'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';

// ─── PHP chunker ──────────────────────────────────────────────────────────────

function chunkPHP(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines,
    /^(?:use\s+|require(?:_once)?\s*[\('"]|include(?:_once)?\s*[\('"])/);
  if (importChunk) chunks.push(importChunk);

  const modifiers = '(?:(?:public|protected|private|static|abstract|final|readonly)\\s+)*';
  const classRe   = new RegExp(`^${modifiers}(?:abstract\\s+)?class\\s+([A-Za-z_][\\w]*)`, 'i');
  const funcRe    = new RegExp(`^${modifiers}function\\s+([A-Za-z_][\\w]*)\\s*\\(`);
  const methodRe  = new RegExp(`^(\\s+)${modifiers}function\\s+([A-Za-z_][\\w]*)\\s*\\(`);

  let i = 0;
  let currentClass = null;
  const moduleLevel = [];
  let moduleLevelStart = -1;
  // Pending PHP 8 attribute lines (#[...]) immediately preceding a function.
  // Only the attribute call lines are prepended — not docblocks or comments.
  const pendingAttrs = [];
  // Tracks whether we're inside an unclosed /* ... */ comment, so
  // continuation lines (which carry no '/*' or leading '*' marker of their
  // own) are correctly skipped instead of falling through to the class/
  // function regexes below.
  let inBlockComment = false;

  // Flushes any buffered attribute lines that never attached to a function —
  // an attribute on the class itself (#[Entity], #[ORM\Table(...)]:
  // describes the class, not any one method, so intentionally never
  // prepended to a method chunk), an attribute followed by another
  // non-function line, or an attribute on the last line(s) of the file with
  // nothing after it. Without this they were silently discarded the moment
  // pendingAttrs.length was reset to 0, rather than surviving anywhere in
  // the output.
  function flushPendingAttrs(atIndex) {
    if (pendingAttrs.length === 0) return;
    if (moduleLevelStart === -1) moduleLevelStart = atIndex - pendingAttrs.length;
    moduleLevel.push(...pendingAttrs);
    pendingAttrs.length = 0;
  }

  while (i < lines.length) {
    const line    = lines[i];
    const stripped = line.trim();

    if (inBlockComment) {
      if (stripped.includes('*/')) inBlockComment = false;
      i++; continue;
    }

    if (stripped.startsWith('//') || stripped.startsWith('*') ||
        (stripped.startsWith('#') && !stripped.startsWith('#['))) { i++; continue; }
    if (stripped.startsWith('/*')) {
      if (!stripped.includes('*/')) inBlockComment = true;
      i++; continue;
    }

    // Collect PHP 8 attribute lines: #[Route(...)] #[ORM\Column(...)] etc.
    // Plain # comments are already handled above, so only #[ reaches here.
    if (/^#\[/.test(stripped)) {
      pendingAttrs.push(line);
      i++; continue;
    }

    const classMatch = stripped.match(classRe);
    if (classMatch) { flushPendingAttrs(i); currentClass = classMatch[1]; i++; continue; }
    if (stripped === '}' && currentClass) { currentClass = null; i++; continue; }

    if (currentClass) {
      const mMatch = stripped.match(methodRe) || stripped.match(funcRe);
      if (mMatch) {
        const name = mMatch[2] || mMatch[1];
        const blockStart = i - pendingAttrs.length;
        const block = collectBraceBlock(lines, i);
        chunks.push(makeChunk(filePath, 'method', currentClass, name,
          [...pendingAttrs, ...block.lines], blockStart));
        pendingAttrs.length = 0;
        i = block.nextIndex; continue;
      }
    }

    const funcMatch = stripped.match(funcRe);
    if (funcMatch) {
      const name = funcMatch[1];
      const blockStart = i - pendingAttrs.length;
      const block = collectBraceBlock(lines, i);
      chunks.push(makeChunk(filePath, 'function', null, name,
        [...pendingAttrs, ...block.lines], blockStart));
      pendingAttrs.length = 0;
      i = block.nextIndex; continue;
    }

    // Any other line resets the attribute buffer — flushed to module_code
    // first so nothing is silently lost.
    flushPendingAttrs(i);

    if (stripped.length > 0 && !stripped.startsWith('<?') && !stripped.startsWith('?>') &&
        !classRe.test(stripped) && !funcRe.test(stripped) &&
        !/^(?:use\s+|require|include)/.test(stripped) &&
        stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    i++;
  }

  // An attribute on the very last line(s) of the file with nothing after it
  // would otherwise never hit any of the flush points above.
  flushPendingAttrs(lines.length);

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

export { chunkPHP };