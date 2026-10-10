'use strict';

import fs   from 'fs';
import path from 'path';

import {
  IGNORE_DIRS, EXT_FAMILY, FAMILY_LABELS, LANGUAGE_ALIASES, DEFAULT_LANGUAGES,
} from './constants.js';
import { detectConfigKind, familyForKind } from './configDetect.js';
import { chunkFile } from './dispatcher.js';

// Resolves a file's language family, falling back to filename/content-based
// detection (Dockerfile, Compose, Terraform, Kubernetes, CloudFormation,
// Ansible) for files EXT_FAMILY doesn't cover by extension alone.
function resolveFileFamily(fullPath, ext) {
  const family = EXT_FAMILY[ext];
  if (family) return family;
  const kind = detectConfigKind(fullPath);
  return kind ? familyForKind(kind) : undefined;
}

// Machine-generated Dart (build_runner / codegen output). Never hand-written,
// large, and a source of noise findings — skipped the same way node_modules is.
const GENERATED_DART = /(?:\.g|\.freezed|\.gr|\.mocks|\.chopper)\.dart$|^generated_plugin_registrant\.dart$/;

// TypeScript declaration files hold types only (no executable code, nothing
// for a vulnerability or malware review to find) — always skipped.
const TS_DECLARATION = /\.d\.(?:ts|mts|cts)$/;

// Minified / pre-bundled output. Noise for the vulnerability scan (one giant
// line, no semantic structure), so skipped by default there; the malware scan
// turns it back on (opts.includeMinified) because bundles are exactly where
// planted code hides.
const MINIFIED = /\.min\.(?:js|mjs|cjs)$|\.bundle\.(?:js|mjs|cjs)$/;

// Test code is opt-in to skip (opts.skipTests / --skip-tests): hardcoded
// credentials in fixtures are sometimes real, so it is not dropped silently.
const TEST_DIRS  = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e', '__mocks__', 'fixtures', 'testdata']);
const TEST_FILES = /(?:\.|_)(?:test|spec)\.[a-z0-9]+$|^test_.+\.py$|(?:Test|Tests|IT)\.(?:java|kt|cs|swift)$|_test\.(?:go|py|rb|dart)$/i;

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
 * @param {string[]} [opts.includeFolders=[]]   Folder names to scan even though they are in the built-in
 *                                              ignore set (node_modules, dist, build, vendor, ...) or are
 *                                              dot-directories. The only way to scan a dependency tree
 *                                              from its parent directory.
 * @param {number}  [opts.maxFileSize=512000]   Files larger than this many characters are skipped (and reported).
 * @param {boolean} [opts.includeMinified=false] Scan *.min.js / *.bundle.js (the malware scan sets this).
 * @param {boolean} [opts.skipTests=false]      Skip test directories and test-named files.
 * @returns {{ id, type, file, class, name, startLine, endLine, code }[]}
 *          The array also carries a non-enumerable `info` property (see buildChunksDetailed).
 */
function buildChunks(targetPath, opts) {
  const { chunks, info, all } = buildChunksDetailed(targetPath, opts);
  Object.defineProperty(chunks, 'info', { value: info, enumerable: false, writable: true });
  // Every chunk found, before the --chunks-start / --max-chunks window: used for
  // call-graph resolution so a capped run still sees callers outside the window.
  Object.defineProperty(chunks, 'all',  { value: all,  enumerable: false, writable: true });
  return chunks;
}

/**
 * Same as buildChunks, but returns { chunks, info } explicitly. `info` is the
 * coverage record the reports need to say what was NOT scanned:
 *   total_chunks, chunks_start, max_chunks, chunks_returned,
 *   chunks_dropped_by_cap  (chunks past the --max-chunks window — silently lost before),
 *   chunks_before_start, files_found, files_skipped_too_large[], max_file_size,
 *   files_skipped_generated, files_skipped_tests, chunks_hard_split, truncated
 */
function buildChunksDetailed(targetPath, opts) {
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
    includeFolders  = [],
    maxFileSize     = 512_000,
    includeMinified = false,
    skipTests       = false,
  } = opts;

  const log = silent ? () => {} : (...a) => console.log(...a);

  const root = targetPath
    ? path.resolve(targetPath)
    : path.resolve(workingDir);

  const skipFolderSet = new Set(skipFolders.map(f => f.toLowerCase()));
  const skipFileSet   = new Set(skipFiles.map(f => f.toLowerCase()));
  const includeFolderSet = new Set(includeFolders.map(f => f.toLowerCase()));
  const langFamilies  = resolveLanguageSet(languages);

  const info = {
    total_chunks: 0, chunks_start: chunksStart, max_chunks: maxChunks,
    chunks_returned: 0, chunks_dropped_by_cap: 0, chunks_before_start: 0,
    files_found: 0, files_skipped_too_large: [], max_file_size: maxFileSize,
    files_skipped_generated: 0, files_skipped_tests: 0,
    chunks_hard_split: 0, truncated: false,
  };

  // Walk — honouring extra skip lists and language filter
  function walkFiltered(rootPath) {
    const files = [];
    function recurse(currentPath) {
      let entries;
      try { entries = fs.readdirSync(currentPath, { withFileTypes: true }); }
      catch { return; }
      for (const entry of entries) {
        const nameLower = entry.name.toLowerCase();
        const forced    = includeFolderSet.has(nameLower);
        if (entry.name.startsWith('.') && entry.name !== '.' && !forced) continue;
        const fullPath  = path.join(currentPath, entry.name);
        if (entry.isDirectory()) {
          if (skipFolderSet.has(nameLower)) continue;
          if (IGNORE_DIRS.has(entry.name) && !forced) continue;
          if (skipTests && TEST_DIRS.has(nameLower)) { info.files_skipped_tests++; continue; }
          recurse(fullPath);
        } else if (entry.isFile()) {
          if (skipFileSet.has(nameLower)) continue;
          if (GENERATED_DART.test(nameLower)) continue;
          if (TS_DECLARATION.test(nameLower)) { info.files_skipped_generated++; continue; }
          if (!includeMinified && MINIFIED.test(nameLower)) { info.files_skipped_generated++; continue; }
          if (skipTests && TEST_FILES.test(entry.name)) { info.files_skipped_tests++; continue; }
          const ext    = path.extname(entry.name).toLowerCase();
          const family = resolveFileFamily(fullPath, ext);
          if (family && langFamilies.has(family)) files.push(fullPath);
        }
      }
    }
    recurse(rootPath);
    return files;
  }

  const stat  = fs.statSync(root);
  const files = stat.isDirectory() ? walkFiltered(root) : [root];
  info.files_found = files.length;

  const byLang = {};
  for (const f of files) {
    const family = resolveFileFamily(f, path.extname(f).toLowerCase()) || 'unknown';
    byLang[family] = (byLang[family] || 0) + 1;
  }

  log(`[ubel-sast] Root        : ${root}`);
  log(`[ubel-sast] Found ${files.length} source file(s) to chunk`);
  for (const [lang, count] of Object.entries(byLang)) log(`           ${lang.padEnd(10)} ${count} file(s)`);
  if (skipFolders.length > 0) log(`[ubel-sast] Skip folders: ${skipFolders.join(', ')}`);
  if (skipFiles.length > 0)   log(`[ubel-sast] Skip files  : ${skipFiles.join(', ')}`);
  if (includeFolders.length > 0) log(`[ubel-sast] Include folders (override ignore list): ${includeFolders.join(', ')}`);
  log('');

  // maxChunkSize is a HARD cap on characters per chunk. Whole lines are packed
  // greedily; a single line longer than the cap (minified bundle, generated
  // data blob) is cut into pieces at the nearest statement/space boundary
  // instead of being passed through as one oversized chunk.
  function splitLongLine(line) {
    const pieces = [];
    let rest = line;
    while (rest.length > maxChunkSize) {
      let cut = maxChunkSize;
      const floor = Math.floor(maxChunkSize * 0.8);
      const window = rest.slice(floor, maxChunkSize);
      const m = Math.max(window.lastIndexOf(';'), window.lastIndexOf('}'), window.lastIndexOf(','), window.lastIndexOf(' '));
      if (m >= 0) cut = floor + m + 1;
      pieces.push(rest.slice(0, cut));
      rest = rest.slice(cut);
    }
    if (rest.length > 0) pieces.push(rest);
    return pieces;
  }

  function subChunkBySize(chunk) {
    if (chunk.code.length <= maxChunkSize) return [chunk];
    const lines = chunk.code.split('\n');
    const parts = [];
    let partIndex = 0;
    let buf = [];
    let bufLen = 0;
    let bufStart = 0;

    const emit = (code, startOffset, lineCount) => {
      partIndex++;
      parts.push({
        ...chunk,
        id:        `${chunk.id}#part${partIndex}`,
        startLine: chunk.startLine + startOffset,
        endLine:   chunk.startLine + startOffset + lineCount - 1,
        code,
      });
    };
    const flush = (nextStart) => {
      if (buf.length > 0) emit(buf.join('\n'), bufStart, buf.length);
      buf = []; bufLen = 0; bufStart = nextStart;
    };

    for (let i = 0; i < lines.length; i++) {
      const lineLen = lines[i].length + 1; // +1 for \n
      if (lineLen > maxChunkSize) {
        flush(i);
        for (const piece of splitLongLine(lines[i])) { emit(piece, i, 1); info.chunks_hard_split++; }
        bufStart = i + 1;
        continue;
      }
      if (bufLen + lineLen > maxChunkSize && buf.length > 0) flush(i);
      buf.push(lines[i]);
      bufLen += lineLen;
    }
    flush(lines.length);
    return parts;
  }

  const allChunks = [];
  for (const file of files) {
    const fileChunks = chunkFile(file, {
      maxFileSize,
      onSkipTooLarge: (f, size) => info.files_skipped_too_large.push({ file: f, size }),
    });
    const expanded   = fileChunks.flatMap(subChunkBySize);
    allChunks.push(...expanded);
    if (expanded.length > 0) log(`  ${file} → ${expanded.length} chunk(s)`);
  }

  log(`\n[ubel-sast] Total chunks : ${allChunks.length}`);

  const sliced = allChunks.slice(chunksStart, chunksStart + maxChunks);
  info.total_chunks          = allChunks.length;
  info.chunks_returned       = sliced.length;
  info.chunks_before_start   = Math.min(chunksStart, allChunks.length);
  info.chunks_dropped_by_cap = Math.max(0, allChunks.length - (chunksStart + maxChunks));
  info.truncated             = info.chunks_dropped_by_cap > 0;

  if (chunksStart > 0 || info.truncated) {
    log(`[ubel-sast] Returning    : chunks ${chunksStart}–${chunksStart + sliced.length - 1} (${sliced.length} of ${allChunks.length})`);
  }
  if (info.truncated) {
    log(`[ubel-sast] ⚠  ${info.chunks_dropped_by_cap} chunk(s) beyond --max-chunks ${maxChunks} will NOT be scanned (raise --max-chunks or use --chunks-start to continue).`);
  }
  if (info.files_skipped_too_large.length > 0) {
    log(`[ubel-sast] ⚠  ${info.files_skipped_too_large.length} file(s) larger than ${maxFileSize} chars were skipped (raise --max-file-size to scan them).`);
  }
  if (info.chunks_hard_split > 0) {
    log(`[ubel-sast] Note        : ${info.chunks_hard_split} over-long line(s) were split to honour --max-chunk-size ${maxChunkSize}.`);
  }

  return { chunks: sliced, info, all: allChunks };
}

export { buildChunks, buildChunksDetailed, resolveLanguageSet };
