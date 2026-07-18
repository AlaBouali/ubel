'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';

// ─── Kotlin chunker ───────────────────────────────────────────────────────────

function chunkKotlin(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^import\s+/);
  if (importChunk) chunks.push(importChunk);

  const classRe = /^(?:(?:data|sealed|abstract|open|inner|enum|annotation|value)\s+)*(?:class|object|interface)\s+([A-Za-z_]\w*)/;
  const funRe   = /^(\s*)(?:(?:private|protected|public|internal|override|suspend|inline|operator|infix|external|tailrec|actual|expect)\s+)*fun\s+(?:<[^>]+>\s+)?([A-Za-z_]\w*)\s*\(/;

  let i = 0;
  let currentClass = null;
  // Brace depth recorded when entering the current class/object/interface
  // body, so we know when a closing '}' actually ends it rather than some
  // nested block inside it (an `init { ... }` block, a companion object, a
  // property getter/setter spanning multiple lines). Without this, `fun`s
  // declared after that nested block closed were still detected (funRe
  // isn't gated on currentClass), but got silently misattributed — labeled
  // as a top-level 'function' with no owning class instead of a 'method',
  // and the wrong `class` field on the chunk.
  let classBraceDepth = 0;
  let braceDepth = 0;
  // Pending @Annotation lines immediately preceding a fun declaration.
  // Only the call lines are prepended — not any annotation class bodies.
  const pendingAnnotations = [];
  // Tracks whether we're inside an unclosed /* ... */ comment, so
  // continuation lines are correctly skipped instead of falling through
  // to the class/fun regexes below.
  const commentState = { inBlockComment: false };
  // Every top-level (and in-class-but-not-a-fun) survivor — properties,
  // init blocks, companion objects without their own fun match — is
  // collected here instead of being silently dropped.
  const moduleLevel = [];
  let moduleLevelStart = -1;

  while (i < lines.length) {
    const line    = lines[i];
    const stripped = line.trim();

    if (commentState.inBlockComment) {
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    if (stripped.startsWith('//') || stripped.startsWith('*')) { i++; continue; }
    if (stripped.startsWith('/*')) {
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    // Collect annotation calls: @Name or @Name(...) or @pkg.Name(...)
    if (/^@[A-Za-z]/.test(stripped)) {
      pendingAnnotations.push(line);
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    const classMatch = stripped.match(classRe);
    if (classMatch) {
      currentClass = classMatch[1];
      pendingAnnotations.length = 0;
      classBraceDepth = braceDepth; // depth BEFORE this class's own '{' is consumed
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }
    if (currentClass && stripped.startsWith('}') && braceDepth === classBraceDepth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      currentClass = null;
      i++; continue;
    }

    const funMatch = line.match(funRe);
    if (funMatch) {
      const name = funMatch[2];
      const blockStart = i - pendingAnnotations.length;
      const block = collectBraceBlock(lines, i);
      const body  = block.lines.length > 0 ? block.lines : [line];
      // Prepend annotation calls so the LLM sees the full decorator context.
      const blockLines = [...pendingAnnotations, ...body];
      pendingAnnotations.length = 0;
      chunks.push(makeChunk(filePath, currentClass ? 'method' : 'function', currentClass, name, blockLines, blockStart));
      for (const bl of body) braceDepth += computeBraceDelta(bl, commentState);
      i = block.nextIndex; continue;
    }

    if (pendingAnnotations.length > 0) {
      if (moduleLevelStart === -1) moduleLevelStart = i - pendingAnnotations.length;
      moduleLevel.push(...pendingAnnotations);
      pendingAnnotations.length = 0;
    }

    if (stripped.length > 0 && stripped !== '{' && stripped !== '}') {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    braceDepth += computeBraceDelta(line, commentState);
    i++;
  }

  // An annotation on the very last line(s) of the file with nothing after
  // it would otherwise never reach the flush inside the loop above.
  if (pendingAnnotations.length > 0) {
    if (moduleLevelStart === -1) moduleLevelStart = lines.length - pendingAnnotations.length;
    moduleLevel.push(...pendingAnnotations);
  }

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

export { chunkKotlin };