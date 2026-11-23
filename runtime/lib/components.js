'use strict';
// components.js — what a live Node.js process has loaded, from the script URLs V8 reports (--inspect). Node.js stdlib only, nothing executed.
//   scriptFiles()  the files behind those script URLs, for the code-from-temp and stale-code checks of the inspection area

import { fileURLToPath } from 'node:url';
import path from 'node:path';

function urlToPath(u) {
  if (!u) return null;
  if (u.startsWith('file://')) { try { return fileURLToPath(u); } catch { return null; } }
  return path.posix.isAbsolute(u) ? u : null;
}

/** @returns {{files:string[], builtinCount:number, anonymousCount:number}} */
export function scriptFiles(scripts) {
  const files = new Set();
  let builtin = 0, anonymous = 0;
  for (const s of scripts) {
    const url = s.url || '';
    if (!url) { anonymous++; continue; }
    if (url.startsWith('node:')) { builtin++; continue; }
    const p = urlToPath(url);
    if (!p) { anonymous++; continue; }
    files.add(p);
  }
  return { files: [...files], builtinCount: builtin, anonymousCount: anonymous };
}
