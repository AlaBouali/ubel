'use strict';

import fs   from 'fs';
import path from 'path';

import {
  IGNORE_DIRS, EXT_FAMILY, FAMILY_LABELS, LANGUAGE_ALIASES, DEFAULT_LANGUAGES,
} from './constants.js';
import { chunkFile } from './dispatcher.js';

function resolveLanguageSet(languages) {
  const families = new Set();
  for (const raw of languages) {
    const key = raw.toLowerCase().trim();
    const resolved = LANGUAGE_ALIASES[key] || FAMILY_LABELS[key];
    if (resolved) families.add(resolved);
  }
  return families;
}

/**
 * Build semantic chunks from a file or directory.
 *
 * @param {string} [targetPath]  Absolute or relative path to file/directory.
 *                               Defaults to opts.workingDir or process.cwd().
 * @param {object} [opts]
 * @param {boolean} [opts.silent=false]         Suppress console output.
 * @param {string}  [opts.workingDir]           Root directory to scan (default: cwd).
 * @param {number}  [opts.maxChunkSize=12000]   Max chars per chunk (over-size chunks are sub-chunked).
 * @param {number}  [opts.chunksStart=0]        Index of first chunk to return (0-based slice).
 * @param {number}  [opts.maxChunks=1000]       Maximum number of chunks to return.
 * @param {string[]} [opts.skipFolders=[]]      Directory names to skip (in addition to built-in ignores).
 * @param {string[]} [opts.skipFiles=[]]        File names or glob-style basenames to skip.
 * @param {string[]} [opts.languages]           Language families to include (default: all supported).
 * @returns {{ id, type, file, class, name, startLine, endLine, code }[]}
 */
function buildChunks(targetPath, opts) {
  // targetPath is optional — opts may be passed as the first argument
  if (targetPath !== null && typeof targetPath === 'object' && !Array.isArray(targetPath)) {
    opts = targetPath;
    targetPath = null;
  }
  opts = opts || {};

  const {
    silent       = false,
    workingDir   = process.cwd(),
    maxChunkSize = 12_000,
    chunksStart  = 0,
    maxChunks    = 1_000,
    skipFolders  = [],
    skipFiles    = [],
    languages    = DEFAULT_LANGUAGES,
  } = opts;

  const log = silent ? () => {} : (...a) => console.log(...a);

  const root = targetPath
    ? path.resolve(targetPath)
    : path.resolve(workingDir);

  const skipFolderSet = new Set(skipFolders.map(f => f.toLowerCase()));
  const skipFileSet   = new Set(skipFiles.map(f => f.toLowerCase()));
  const langFamilies  = resolveLanguageSet(languages);

  // Walk — honouring extra skip lists and language filter
  function walkFiltered(rootPath) {
    const files = [];
    function recurse(currentPath) {
      let entries;
      try { entries = fs.readdirSync(currentPath, { withFileTypes: true }); }
      catch { return; }
      for (const entry of entries) {
        if (entry.name.startsWith('.') && entry.name !== '.') continue;
        const nameLower = entry.name.toLowerCase();
        const fullPath  = path.join(currentPath, entry.name);
        if (entry.isDirectory()) {
          if (IGNORE_DIRS.has(entry.name) || skipFolderSet.has(nameLower)) continue;
          recurse(fullPath);
        } else if (entry.isFile()) {
          if (skipFileSet.has(nameLower)) continue;
          const ext    = path.extname(entry.name).toLowerCase();
          const family = EXT_FAMILY[ext];
          if (family && langFamilies.has(family)) files.push(fullPath);
        }
      }
    }
    recurse(rootPath);
    return files;
  }

  const stat  = fs.statSync(root);
  const files = stat.isDirectory() ? walkFiltered(root) : [root];

  const byLang = {};
  for (const f of files) {
    const family = EXT_FAMILY[path.extname(f).toLowerCase()] || 'unknown';
    byLang[family] = (byLang[family] || 0) + 1;
  }

  log(`[ubel-sast] Root        : ${root}`);
  log(`[ubel-sast] Found ${files.length} source file(s) to chunk`);
  for (const [lang, count] of Object.entries(byLang)) log(`           ${lang.padEnd(10)} ${count} file(s)`);
  if (skipFolders.length > 0) log(`[ubel-sast] Skip folders: ${skipFolders.join(', ')}`);
  if (skipFiles.length > 0)   log(`[ubel-sast] Skip files  : ${skipFiles.join(', ')}`);
  log('');

  // Use maxChunkSize (chars) instead of the fixed MAX_CHUNK_LINES guard
  function subChunkBySize(chunk) {
    if (chunk.code.length <= maxChunkSize) return [chunk];
    const lines = chunk.code.split('\n');
    const parts = [];
    let partIndex = 0;
    let buf = [];
    let bufLen = 0;
    let bufStart = 0;

    for (let i = 0; i < lines.length; i++) {
      const lineLen = lines[i].length + 1; // +1 for \n
      if (bufLen + lineLen > maxChunkSize && buf.length > 0) {
        partIndex++;
        parts.push({
          ...chunk,
          id:        `${chunk.id}#part${partIndex}`,
          startLine: chunk.startLine + bufStart,
          endLine:   chunk.startLine + bufStart + buf.length - 1,
          code:      buf.join('\n'),
        });
        buf = []; bufLen = 0; bufStart = i;
      }
      buf.push(lines[i]);
      bufLen += lineLen;
    }
    if (buf.length > 0) {
      partIndex++;
      parts.push({
        ...chunk,
        id:        `${chunk.id}#part${partIndex}`,
        startLine: chunk.startLine + bufStart,
        endLine:   chunk.startLine + bufStart + buf.length - 1,
        code:      buf.join('\n'),
      });
    }
    return parts;
  }

  const allChunks = [];
  for (const file of files) {
    const fileChunks = chunkFile(file);
    const expanded   = fileChunks.flatMap(subChunkBySize);
    allChunks.push(...expanded);
    if (expanded.length > 0) log(`  ${file} → ${expanded.length} chunk(s)`);
  }

  log(`\n[ubel-sast] Total chunks : ${allChunks.length}`);

  const sliced = allChunks.slice(chunksStart, chunksStart + maxChunks);
  if (chunksStart > 0 || allChunks.length > chunksStart + maxChunks) {
    log(`[ubel-sast] Returning    : chunks ${chunksStart}–${chunksStart + sliced.length - 1} (${sliced.length} of ${allChunks.length})`);
  }

  return sliced;
}

export { buildChunks, resolveLanguageSet };
