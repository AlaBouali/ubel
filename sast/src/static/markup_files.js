'use strict';

// ─── HTML / template file discovery for the static engine (--no-llm) ──────────
//
// markup.js knows how to take a template file apart (template-engine tags, inline <script>, on*= handlers, javascript: URLs) and
// rules/markup.js knows what to look for in it — but the engine only analyses the chunks it is handed, and the chunker has no
// entry for .html / .gohtml / .ejs / .vue … (chunker/constants.js lists code and IaC only). Those files therefore never became
// chunks and were silently never scanned: a Go project with templates/*.html reported Go and JS chunks and no markup at all.
//
// analyzeSastStatic() calls discoverMarkupChunks() to close that gap. It walks the scan root with the SAME scope rules as the
// chunker (built-in ignored folders, dot-directories, --include-folders, --skip-folders, --skip-files, --skip-tests,
// --max-file-size) and returns one WHOLE-FILE chunk per markup file the chunker did not already supply. Whole-file, not split at
// --max-chunk-size: the template rules read the raw text and the <script> extraction needs every tag of the page. The engine
// (engine.js → markup.js → expandMarkupChunk) then expands each one into the markup chunk, one JavaScript chunk per inline
// <script> and one for the inline event handlers.
//
// Zero dependencies (fs + path), no child processes, no network.

import fs from 'fs';
import path from 'path';
import { IGNORE_DIRS } from '../chunker/constants.js';
import { MARKUP_ONLY_EXT, MARKUP_CODE_EXT, extOf } from './markup.js';

// Same sets the chunker uses for --skip-tests (buildChunks.js).
const TEST_DIRS  = new Set(['test', 'tests', '__tests__', 'spec', 'specs', 'e2e', '__mocks__', 'fixtures', 'testdata']);
const TEST_FILES = /(?:\.|_)(?:test|spec)\.[a-z0-9]+$/i;

const win = process.platform === 'win32';
/** Comparison key for a file path: absolute, and case-insensitive on Windows. */
export const fileKey = (p) => { const r = path.resolve(String(p || '')); return win ? r.toLowerCase() : r; };

// ── --languages filter ───────────────────────────────────────────────────────
// Markup files belong to no chunker language family, so an explicit filter such as `java,kotlin` means "no templates", while
// `html`, `markup`, `templates` or the extension itself (`ejs`, `vue`, `gohtml` …) lets them through. `null` = no filter.
const GENERIC_NAMES = ['html', 'htm', 'markup', 'template', 'templates'];
function languageAllows(languages, ext) {
  if (!languages || !languages.length) return true;
  const want = new Set(languages.map((l) => String(l).toLowerCase().trim().replace(/^\./, '')));
  return GENERIC_NAMES.some((g) => want.has(g)) || want.has(ext.slice(1));
}

/**
 * Find markup / template files under `scope.root` that are not in `known`.
 *
 * @param {object} scope  { root, includeFolders, skipFolders, skipFiles, skipTests, maxFileSize, languages }
 * @param {Set<string>} known  fileKey()s of files the chunker already produced chunks for
 * @returns {{ chunks: object[], stats: object }}
 *   stats.files_skipped_too_large is in the chunker's shape ({ file, size }) so the report's coverage treats it the same way.
 */
export function discoverMarkupChunks(scope, known = new Set()) {
  const root = path.resolve(scope.root || process.cwd());
  const stats = { found: 0, already_chunked: 0, scanned: 0, files_skipped_too_large: [], skipped_unreadable: 0, skipped_by_filter: 0 };
  const chunks = [];

  const lc = (v) => String(v).toLowerCase();
  const includeSet = new Set((scope.includeFolders || []).map(lc));
  const skipFolderSet = new Set((scope.skipFolders || []).map(lc));
  const skipFileSet = new Set((scope.skipFiles || []).map(lc));
  const maxFileSize = scope.maxFileSize || 512_000;

  const consider = (full, name) => {
    const ext = extOf(name);
    if (!MARKUP_ONLY_EXT.has(ext) && !MARKUP_CODE_EXT.has(ext)) return;
    stats.found++;
    if (known.has(fileKey(full))) { stats.already_chunked++; return; }
    if (!languageAllows(scope.languages, ext)) { stats.skipped_by_filter++; return; }
    let st; try { st = fs.statSync(full); } catch { stats.skipped_unreadable++; return; }
    if (st.size > maxFileSize * 4) { stats.files_skipped_too_large.push({ file: full, size: st.size }); return; }   // > 4 bytes per char: over the limit for certain
    let buf; try { buf = fs.readFileSync(full); } catch { stats.skipped_unreadable++; return; }
    if (buf.subarray(0, 4096).includes(0)) { stats.skipped_unreadable++; return; }                                 // binary
    let text = buf.toString('utf8');
    if (text.charCodeAt(0) === 0xFEFF) text = text.slice(1);
    if (text.length > maxFileSize) { stats.files_skipped_too_large.push({ file: full, size: text.length }); return; }
    if (text.trim() === '') return;
    text = text.replace(/\r\n?/g, '\n');                                   // CRLF (Windows) files: same line numbers, simpler regexes
    chunks.push({
      id: `${full}:all`, file: full, type: 'markup', class: undefined, name: path.basename(full), language: 'HTML',
      startLine: 1, endLine: (text.match(/\n/g) || []).length + 1, code: text,
    });
    stats.scanned++;
  };

  let rootStat;
  try { rootStat = fs.statSync(root); } catch { return { chunks, stats }; }
  if (rootStat.isFile()) { consider(root, path.basename(root)); return { chunks, stats }; }   // a single file given as the target

  const walk = (dir) => {
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    entries.sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
    for (const entry of entries) {
      const nameLower = lc(entry.name);
      const forced = includeSet.has(nameLower);
      if (entry.name.startsWith('.') && !forced) continue;                 // dot-directories (and dot-files) unless --include-folders names them
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        if (skipFolderSet.has(nameLower)) continue;
        if (IGNORE_DIRS.has(entry.name) && !forced) continue;
        if (scope.skipTests && TEST_DIRS.has(nameLower)) continue;
        walk(full);
      } else if (entry.isFile()) {
        if (skipFileSet.has(nameLower)) continue;
        if (scope.skipTests && TEST_FILES.test(entry.name)) continue;
        consider(full, entry.name);
      }
    }
  };
  walk(root);
  return { chunks, stats };
}
