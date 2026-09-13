'use strict';

import { buildImportChunk, makeChunk } from '../braceblock.js';

// ─── Python chunker ───────────────────────────────────────────────────────────

function chunkPython(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^(?:import |from )\S/);
  if (importChunk) chunks.push(importChunk);

  // Class context stack: each entry is { name, indent }
  const classStack = [];
  const moduleLevel = [];
  let moduleLevelStart = -1;
  // Decorator lines (@name / @name(...)) immediately preceding a def.
  // We collect only the call lines (not their implementation) so the LLM
  // sees the full annotation context without the decorator body code.
  const pendingDecorators = [];
  let i = 0;

  // Flushes any buffered decorator lines that never attached to a def —
  // a decorator on a class (@dataclass, @final: describes the class, not
  // any one method, so intentionally never prepended to a method chunk),
  // back-to-back decorators where the second line wasn't actually a def,
  // or a decorator on the last line(s) of the file with nothing after it.
  // Without this they were silently discarded the moment
  // pendingDecorators.length was reset to 0, rather than surviving
  // anywhere in the output.
  function flushPendingDecorators(atIndex) {
    if (pendingDecorators.length === 0) return;
    if (moduleLevelStart === -1) moduleLevelStart = atIndex - pendingDecorators.length;
    moduleLevel.push(...pendingDecorators);
    pendingDecorators.length = 0;
  }

  while (i < lines.length) {
    const line     = lines[i];
    const stripped = line.trimStart();
    const indent   = line.length - stripped.length;

    // Pop class stack entries that are no longer in scope
    // (any non-empty, non-comment line at or below the class's indent closes it)
    while (
      classStack.length > 0 &&
      stripped.length > 0 &&
      !stripped.startsWith('#') &&
      indent <= classStack[classStack.length - 1].indent
    ) {
      classStack.pop();
    }

    const currentClass = classStack.length > 0
      ? classStack[classStack.length - 1].name
      : null;

    // Collect decorator call lines — @name or @name(...) or @pkg.name(...)
    // Multi-line decorator argument lists (rare) are intentionally left as a
    // single line here: we capture only the opening call, not its body.
    if (stripped.startsWith('@') && /^@[\w.]/.test(stripped)) {
      pendingDecorators.push(line);
      i++; continue;
    }

    // Detect class definition — decorators on the class itself are flushed
    // to module_code rather than prepended to any one method.
    const classMatch = stripped.match(/^class\s+([A-Za-z_]\w*)\s*[:(]/);
    if (classMatch) {
      flushPendingDecorators(i);
      classStack.push({ name: classMatch[1], indent });
      i++; continue;
    }

    // Detect method inside current class
    if (currentClass) {
      const methodMatch = stripped.match(/^def\s+([A-Za-z_]\w*)\s*\(/);
      if (methodMatch) {
        const name = methodMatch[1];
        // Prepend collected decorator calls then the def body
        const blockStart = i - pendingDecorators.length;
        const blockLines = [...pendingDecorators, line];
        pendingDecorators.length = 0;
        const baseIndent = indent;
        i++;
        while (i < lines.length) {
          const nl = lines[i]; const ns = nl.trimStart(); const ni = nl.length - ns.length;
          if (ns.length === 0 || ns.startsWith('#')) { blockLines.push(nl); i++; continue; }
          if (ni <= baseIndent) break;
          blockLines.push(nl); i++;
        }
        chunks.push(makeChunk(filePath, 'method', currentClass, name, blockLines, blockStart));
        continue;
      }
    }

    // Detect top-level function (indent === 0)
    const funcMatch = stripped.match(/^def\s+([A-Za-z_]\w*)\s*\(/);
    if (funcMatch && indent === 0) {
      const name = funcMatch[1];
      const blockStart = i - pendingDecorators.length;
      const blockLines = [...pendingDecorators, line];
      pendingDecorators.length = 0;
      i++;
      while (i < lines.length) {
        const nl = lines[i]; const ns = nl.trimStart(); const ni = nl.length - ns.length;
        if (ns.length === 0 || ns.startsWith('#')) { blockLines.push(nl); i++; continue; }
        if (ni === 0) break;
        blockLines.push(nl); i++;
      }
      chunks.push(makeChunk(filePath, 'function', null, name, blockLines, blockStart));
      continue;
    }

    // Any non-decorator, non-def line resets the pending buffer — flushed
    // to module_code first so nothing is silently lost.
    flushPendingDecorators(i);

    // Captured regardless of indent — this includes class-body lines that
    // aren't a def (attributes, class docstrings, nested-closure bodies) as
    // well as true top-level statements, so nothing outside an
    // import/function/method chunk is silently dropped.
    if (stripped.length > 0 && !stripped.startsWith('#') &&
        !/^(?:import |from )\S/.test(stripped) &&
        !/^class\s/.test(stripped) && !/^def\s/.test(stripped)) {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    i++;
  }

  // A decorator on the very last line(s) of the file with nothing after it
  // would otherwise never hit any of the flush points above.
  flushPendingDecorators(lines.length);

  if (moduleLevel.length > 0) {
    chunks.push({
      id: `${filePath}:module_code`, type: 'module_code', file: filePath,
      class: null, name: 'module_code',
      startLine: moduleLevelStart + 1,
      endLine:   moduleLevelStart + moduleLevel.length,
      code: moduleLevel.join('\n'),
    });
  }
  return chunks;
}

export { chunkPython };