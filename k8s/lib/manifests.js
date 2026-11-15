'use strict';
// manifests.js — loads Kubernetes manifests (YAML / JSON files or directories) for offline auditing.
// Multi-document YAML streams and `kind: List` wrappers are expanded. Helm / Go templates ({{ … }}) are not valid
// YAML until rendered, so such files are skipped and reported (render them first: `helm template … > out.yaml`).

import fs from 'node:fs';
import path from 'node:path';
import { parseYaml } from '../../package/lib/yaml.js';

const EXT = /\.(ya?ml|json)$/i;
const SKIP_DIRS = new Set(['node_modules', '.git', '.terraform', 'vendor']);
const MAX_FILE = 8 * 1024 * 1024;

function collectFiles(p, out, skipped, depth = 0) {
  let st;
  try { st = fs.statSync(p); } catch { skipped.push({ file: p, reason: 'not found' }); return; }
  if (st.isDirectory()) {
    if (depth > 12) return;
    for (const n of fs.readdirSync(p).sort()) {
      if (SKIP_DIRS.has(n)) continue;
      const full = path.join(p, n);
      let s; try { s = fs.statSync(full); } catch { continue; }
      if (s.isDirectory()) collectFiles(full, out, skipped, depth + 1);
      else if (EXT.test(n)) out.push(full);
    }
  } else if (st.isFile()) out.push(p);
}

function expand(doc, file, out) {
  if (!doc || typeof doc !== 'object' || Array.isArray(doc)) return;
  if (typeof doc.kind !== 'string') return;
  if ((doc.kind === 'List' || /List$/.test(doc.kind)) && Array.isArray(doc.items)) {
    for (const it of doc.items) expand(it, file, out);
    return;
  }
  Object.defineProperty(doc, '__file', { value: file, enumerable: false });
  out.push(doc);
}

/** @returns {{docs:object[], files:string[], skipped:{file:string,reason:string}[], documents:number}} */
function loadManifests(paths) {
  const files = [], skipped = [], docs = [];
  for (const p of paths) collectFiles(path.resolve(p), files, skipped);
  const loaded = [];
  for (const f of files) {
    let text;
    try {
      if (fs.statSync(f).size > MAX_FILE) { skipped.push({ file: f, reason: 'larger than 8 MiB' }); continue; }
      text = fs.readFileSync(f, 'utf8');
    } catch (e) { skipped.push({ file: f, reason: e.message }); continue; }
    if (/\{\{[^}]*\}\}/.test(text) && !/\.json$/i.test(f)) { skipped.push({ file: f, reason: 'contains Helm / Go template syntax; render it first (helm template)' }); continue; }
    const before = docs.length;
    try {
      if (/\.json$/i.test(f)) {
        const j = JSON.parse(text);
        for (const d of Array.isArray(j) ? j : [j]) expand(d, f, docs);
      } else {
        for (const chunk of text.split(/^---[ \t]*$/m)) {
          if (!chunk.trim() || /^\s*(#.*\n?)*$/.test(chunk)) continue;
          let d;
          try { d = parseYaml(chunk); } catch (e) { skipped.push({ file: f, reason: `YAML parse error: ${e.message}` }); continue; }
          expand(d, f, docs);
        }
      }
    } catch (e) { skipped.push({ file: f, reason: `parse error: ${e.message}` }); continue; }
    if (docs.length > before) loaded.push(f);
  }
  return { docs, files: loaded, skipped, documents: docs.length };
}

export { loadManifests };
