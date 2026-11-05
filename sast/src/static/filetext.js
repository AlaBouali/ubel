'use strict';

import fs from 'fs';

// Whole-file text, read once per file (rules and the flow engine need file-level context such as
// "is this a web handler file" or "is the XML parser hardened elsewhere in the file").
const cache = new Map();
export function readFileText(file, fallback = '') {
  if (cache.has(file)) return cache.get(file);
  let t;
  try { t = fs.readFileSync(file, 'utf8'); } catch { t = fallback; }
  cache.set(file, t);
  return t;
}
