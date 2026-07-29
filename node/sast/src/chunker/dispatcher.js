'use strict';

import fs   from 'fs';
import path from 'path';

import { EXT_FAMILY } from './constants.js';
import { detectConfigKind, familyForKind } from './configDetect.js';
import {
  chunkPython, chunkJS, chunkPHP, chunkRuby, chunkGo,
  chunkRust, chunkJava, chunkKotlin, chunkCSharp, chunkC,
  chunkDocker, chunkIac,
} from './languages/index.js';

// ─── Dispatcher ───────────────────────────────────────────────────────────────

function chunkFile(filePath) {
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); }
  catch { return []; }

  if (content.length > 512_000) {
    console.warn(`[skip] ${filePath} — file too large (${(content.length / 1024).toFixed(0)}KB)`);
    return [];
  }

  const lines  = content.split('\n');
  const ext    = path.extname(filePath).toLowerCase();
  let family = EXT_FAMILY[ext];

  // Dockerfile/Compose (no reliable extension) and Kubernetes/CloudFormation/
  // Ansible (share the ambiguous .yaml/.yml/.json extension) aren't in
  // EXT_FAMILY — resolve those via filename/content detection instead.
  // `content` is passed in so the yaml/json sniff reuses what's already read.
  if (!family) {
    const kind = detectConfigKind(filePath, content);
    if (kind) family = familyForKind(kind);
  }

  let chunks;
  switch (family) {
    case 'python': chunks = chunkPython(filePath, lines); break;
    case 'js':     chunks = chunkJS(filePath, lines);     break;
    case 'php':    chunks = chunkPHP(filePath, lines);    break;
    case 'ruby':   chunks = chunkRuby(filePath, lines);   break;
    case 'go':     chunks = chunkGo(filePath, lines);     break;
    case 'rust':   chunks = chunkRust(filePath, lines);   break;
    case 'java':   chunks = chunkJava(filePath, lines);   break;
    case 'kotlin': chunks = chunkKotlin(filePath, lines); break;
    case 'csharp': chunks = chunkCSharp(filePath, lines); break;
    case 'c':      chunks = chunkC(filePath, lines);      break;
    case 'docker': chunks = chunkDocker(filePath, lines); break;
    case 'iac':    chunks = chunkIac(filePath, lines);    break;
    // Kubernetes manifests are mechanically identical to the rest of the IaC
    // formats (declarative YAML, whole-file, no function/brace structure to
    // decompose) — chunkIac already branches on `detectConfigKind`'s result
    // internally, so it's reused here rather than duplicated. What's
    // different is the family this resolves to (see configDetect.js /
    // constants.js), which is what lets `--languages k8s` target Kubernetes
    // manifests specifically instead of the whole iac bucket.
    case 'k8s':    chunks = chunkIac(filePath, lines);    break;
    default:       return [];
  }

  // If the file has exactly one non-import chunk, merge everything
  // (including module_code if present) into that single chunk so the
  // whole file is analyzed in one call rather than split artificially.
  const importChunks    = chunks.filter(c => c.type === 'imports');
  const nonImportChunks = chunks.filter(c => c.type !== 'imports');

  if (nonImportChunks.length === 1) return chunks;   // already one chunk — nothing to do

  // Count real function/method/struct chunks (not module_code glue)
  const funcChunks = nonImportChunks.filter(
    c => c.type === 'function' || c.type === 'method' || c.type === 'struct'
  );

  if (funcChunks.length === 1) {
    // Merge module_code into the single function chunk
    const fn       = funcChunks[0];
    const modCode  = nonImportChunks.filter(c => c.type === 'module_code');
    if (modCode.length === 0) return chunks;   // nothing to merge

    const combined = [fn.code, ...modCode.map(c => c.code)].join('\n\n');
    const merged   = {
      ...fn,
      id:       `${filePath}:all`,
      type:     fn.type,
      name:     fn.name,
      startLine: Math.min(fn.startLine, ...modCode.map(c => c.startLine)),
      endLine:   Math.max(fn.endLine,   ...modCode.map(c => c.endLine)),
      code:     combined,
    };
    return [...importChunks, merged];
  }

  return chunks;
}

export { chunkFile };