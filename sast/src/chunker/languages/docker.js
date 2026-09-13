'use strict';

import path from 'path';

import { detectDockerKind } from '../configDetect.js';

// ─── Docker chunker ─────────────────────────────────────────────────────────
//
// Dockerfiles and Compose files are declarative, not code — there is no
// function/block structure to decompose, so the whole file is submitted as a
// single chunk (oversized files still get split by buildChunks.js's
// maxChunkSize guard, same as every other language).

function chunkDocker(filePath, lines) {
  const code = lines.join('\n');
  if (code.trim().length === 0) return [];

  const kind = detectDockerKind(filePath) || 'dockerfile';
  const name = path.basename(filePath);

  return [{
    id:        `${filePath}:all`,
    type:      kind,          // 'dockerfile' | 'compose'
    file:      filePath,
    class:     null,
    name,
    startLine: 1,
    endLine:   lines.length,
    code,
  }];
}

export { chunkDocker };
