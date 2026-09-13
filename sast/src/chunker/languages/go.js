'use strict';

import { collectBraceBlock, makeChunk } from '../braceblock.js';

// ─── Go chunker ───────────────────────────────────────────────────────────────

function chunkGo(filePath, lines) {
  const chunks = [];

  // Collect import block (single or grouped)
  const importLines = [];
  let inImportBlock = false;
  for (const line of lines) {
    const t = line.trim();
    if (t.startsWith('import (')) { inImportBlock = true; importLines.push(line); continue; }
    if (inImportBlock)            { importLines.push(line); if (t === ')') inImportBlock = false; continue; }
    if (t.startsWith('import '))  importLines.push(line);
  }
  if (importLines.length > 0) {
    chunks.push({ id: `${filePath}:imports`, type: 'imports', file: filePath,
      class: null, name: 'imports', startLine: 1, endLine: importLines.length,
      code: importLines.join('\n') });
  }

  const funcRe   = /^func\s+(?:\(\s*\w+\s+\*?(\w+)\s*\)\s+)?([A-Za-z_]\w*)\s*\(/;
  const structRe = /^type\s+([A-Za-z_]\w*)\s+struct\s*\{/;

  let i = 0;
  // Tracks whether we're inside an unclosed /* ... */ comment, so
  // continuation lines are correctly skipped instead of falling through
  // to the struct/func regexes below.
  let inBlockComment = false;
  // Mirrors the prescan above so import lines (single or grouped) walked a
  // second time here are excluded from module_code instead of duplicated
  // into it.
  let inImportBlockWalk = false;
  // Every top-level survivor — package-level var/const, type aliases,
  // non-struct type declarations, interface declarations — is collected
  // here instead of being silently dropped.
  const moduleLevel = [];
  let moduleLevelStart = -1;

  while (i < lines.length) {
    const line    = lines[i];
    const stripped = line.trim();

    if (inBlockComment) {
      if (stripped.includes('*/')) inBlockComment = false;
      i++; continue;
    }

    if (stripped.startsWith('//') || stripped.startsWith('*')) { i++; continue; }
    if (stripped.startsWith('/*')) {
      if (!stripped.includes('*/')) inBlockComment = true;
      i++; continue;
    }

    if (inImportBlockWalk) {
      if (stripped === ')') inImportBlockWalk = false;
      i++; continue;
    }
    if (stripped.startsWith('import (')) { inImportBlockWalk = true; i++; continue; }
    if (stripped.startsWith('import ')) { i++; continue; }

    const structMatch = stripped.match(structRe);
    if (structMatch) {
      const name = structMatch[1]; const blockStart = i;
      const block = collectBraceBlock(lines, i);
      chunks.push(makeChunk(filePath, 'struct', name, name, block.lines, blockStart));
      i = block.nextIndex; continue;
    }

    const funcMatch = stripped.match(funcRe);
    if (funcMatch) {
      const receiver = funcMatch[1] || null;
      const name     = funcMatch[2];
      const blockStart = i;
      const block    = collectBraceBlock(lines, i);
      chunks.push(makeChunk(filePath, receiver ? 'method' : 'function', receiver, name, block.lines, blockStart));
      i = block.nextIndex; continue;
    }

    if (stripped.length > 0 && stripped !== '{' && stripped !== '}' &&
        !stripped.startsWith('package ')) {
      if (moduleLevelStart === -1) moduleLevelStart = i;
      moduleLevel.push(line);
    }
    i++;
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

export { chunkGo };