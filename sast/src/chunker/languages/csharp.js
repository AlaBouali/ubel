'use strict';

import { collectBraceBlock, buildImportChunk, makeChunk } from '../braceblock.js';
import { computeBraceDelta } from '../bracedelta.js';

// ─── C# chunker ───────────────────────────────────────────────────────────────

function chunkCSharp(filePath, lines) {
  const chunks = [];
  const importChunk = buildImportChunk(filePath, lines, /^using\s+/);
  if (importChunk) chunks.push(importChunk);

  const modifiers    = '(?:(?:public|private|protected|internal|static|virtual|override|abstract|sealed|async|partial|readonly|extern|unsafe|new)\\s+)*';
  const classRe      = new RegExp(`^${modifiers}(?:class|struct|interface|record|enum)\\s+([A-Za-z_][\\w]*)`, 'i');
  const memberRe     = new RegExp(`^(\\s+)${modifiers}(?:[\\w<>\\[\\].,?*]+\\s+)+([A-Za-z_][\\w]*)\\s*(?:\\(|\\{|=>)`);
  const annotationRe = /^(\s*)\[[A-Za-z]/;

  let i = 0;
  let currentClass = null;
  // Brace depth recorded when entering the current class/struct/interface/
  // record/enum body, so we know when a closing '}' actually ends the type
  // rather than some nested block inside it (a property's { get; set; }
  // block spanning multiple lines, a static constructor, a field
  // initialized with a multi-line lambda). Without this, that nested
  // block's own closing '}' was mistaken for the type ending — which
  // silently dropped every member declared afterward for the rest of the
  // file, since member detection below is gated on currentClass being set.
  let classBraceDepth = 0;
  let braceDepth = 0;
  const pendingAnnotations = [];
  // Tracks whether we're inside an unclosed /* ... */ comment, so
  // continuation lines are correctly skipped instead of falling through
  // to the class/member regexes below. Comment lines never clear
  // pendingAnnotations, matching the existing single-line-comment behavior.
  const commentState = { inBlockComment: false };
  // Every top-level (and in-class-but-not-a-member) survivor — fields,
  // auto-properties, static constructors, top-level statements (C# 9+
  // "Program.cs" style) — is collected here instead of being silently
  // dropped.
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
    if (annotationRe.test(line)) {
      pendingAnnotations.push(line);
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }

    const classMatch = stripped.match(classRe);
    if (classMatch) {
      currentClass = classMatch[1];
      pendingAnnotations.length = 0;
      classBraceDepth = braceDepth; // depth BEFORE this type's own '{' is consumed
      braceDepth += computeBraceDelta(line, commentState);
      i++; continue;
    }
    if (currentClass && stripped.startsWith('}') && braceDepth === classBraceDepth + 1) {
      braceDepth += computeBraceDelta(line, commentState);
      currentClass = null;
      i++; continue;
    }

    if (currentClass) {
      const mMatch = line.match(memberRe);
      if (mMatch) {
        const name = mMatch[2];
        const controlKw = new Set(['if', 'for', 'foreach', 'while', 'switch', 'catch', 'else', 'try', 'lock', 'using', 'return']);
        if (!controlKw.has(name)) {
          const blockLines = [...pendingAnnotations];
          pendingAnnotations.length = 0;
          const blockStart = i - blockLines.length;
          const block = collectBraceBlock(lines, i);
          chunks.push(makeChunk(filePath, 'method', currentClass, name,
            [...blockLines, ...block.lines], blockStart));
          for (const bl of block.lines) braceDepth += computeBraceDelta(bl, commentState);
          i = block.nextIndex; continue;
        }
      }
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

export { chunkCSharp };