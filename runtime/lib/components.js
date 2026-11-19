'use strict';
// components.js — which software a running process is made of, read from disk (Node.js stdlib only, nothing executed):
//   findProjectRoot()      nearest package.json above a process's script / working directory
//   readInstalledPackages()  every package under node_modules (npm, yarn, pnpm layouts) or, failing that, package-lock.json
//   packagesFromScripts()  which of those packages a live process has actually compiled, from the script URLs V8 reports
// `fsPath` maps a path as the PROCESS sees it to a path this scanner can open: identical for host processes, via
// /proc/<pid>/root for processes in another mount namespace (containers).

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const MAX_PACKAGES = 30000;

const readJson = (file) => { try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; } };
const isFile = (f) => { try { return fs.statSync(f).isFile(); } catch { return false; } };

export function findProjectRoot(starts, fsPath = (x) => x, maxUp = 14) {
  for (const start of starts.filter(Boolean)) {
    let dir = path.posix.dirname(start.endsWith('/') ? start + 'x' : start);
    if (!path.posix.isAbsolute(dir)) continue;
    for (let i = 0; i < maxUp; i++) {
      if (isFile(fsPath(path.posix.join(dir, 'package.json')))) return dir;
      const up = path.posix.dirname(dir);
      if (up === dir) break;
      dir = up;
    }
  }
  return null;
}

/** @returns {{source:'node_modules'|'package-lock.json'|null, packages:Map<string,{name:string,version:string,dirs:string[]}>, truncated:boolean, root:string}} */
export function readInstalledPackages(root, fsPath = (x) => x) {
  const packages = new Map();
  let truncated = false;
  const add = (name, version, dir) => {
    if (typeof name !== 'string' || typeof version !== 'string' || !name || !version) return;
    const k = `${name}@${version}`;
    const e = packages.get(k) || { name, version, dirs: [] };
    if (e.dirs.length < 3) e.dirs.push(dir);
    packages.set(k, e);
  };
  const dirents = (d) => { try { return fs.readdirSync(fsPath(d), { withFileTypes: true }); } catch { return []; } };
  const addPkg = (dir) => {
    if (packages.size >= MAX_PACKAGES) { truncated = true; return; }
    const pj = readJson(fsPath(path.posix.join(dir, 'package.json')));
    if (pj) add(pj.name, pj.version, dir);
    walk(path.posix.join(dir, 'node_modules'), 0);
  };
  const walk = (nm, depth) => {
    if (depth > 40 || packages.size >= MAX_PACKAGES) { if (packages.size >= MAX_PACKAGES) truncated = true; return; }
    for (const e of dirents(nm)) {
      if (e.name === '.pnpm') { for (const s of dirents(path.posix.join(nm, '.pnpm'))) if (s.isDirectory()) walk(path.posix.join(nm, '.pnpm', s.name, 'node_modules'), depth + 1); continue; }
      if (e.name.startsWith('.')) continue;
      if (e.name.startsWith('@') && e.isDirectory()) { for (const s of dirents(path.posix.join(nm, e.name))) if (s.isDirectory()) addPkg(path.posix.join(nm, e.name, s.name)); continue; }
      if (e.isDirectory()) addPkg(path.posix.join(nm, e.name));
    }
  };
  const nm = path.posix.join(root, 'node_modules');
  if (dirents(nm).length) { walk(nm, 0); return { source: 'node_modules', packages, truncated, root }; }

  const lock = readJson(fsPath(path.posix.join(root, 'package-lock.json')));
  if (lock && lock.packages && typeof lock.packages === 'object') {
    for (const [k, v] of Object.entries(lock.packages)) {
      if (!k.includes('node_modules/') || !v || v.link || v.dev) continue;                       // dev dependencies are not part of a running service
      const name = v.name || k.slice(k.lastIndexOf('node_modules/') + 13);
      add(name, v.version, path.posix.join(root, k));
    }
    return { source: 'package-lock.json', packages, truncated, root };
  }
  return { source: null, packages, truncated, root };
}

/** The root package of an application (its own name and version), when the root has a package.json. */
export function readRootPackage(root, fsPath = (x) => x) {
  const pj = readJson(fsPath(path.posix.join(root, 'package.json')));
  return pj ? { name: pj.name || null, version: pj.version || null, main: pj.main || null, scripts: Object.keys(pj.scripts || {}).filter((s) => /^(pre|post)?install$|^prepare$/.test(s)) } : null;
}

function urlToPath(u) {
  if (!u) return null;
  if (u.startsWith('file://')) { try { return fileURLToPath(u); } catch { return null; } }
  return path.posix.isAbsolute(u) ? u : null;
}

/**
 * Maps the script URLs V8 reports to packages. A script inside .../node_modules/<pkg>/... belongs to that package; anything else is
 * the application's own code. Versions are read from the package.json on disk — see the stale-code check for when that can lag
 * behind what is in memory.
 */
export function packagesFromScripts(scripts, fsPath = (x) => x) {
  const packages = new Map();
  const cache = new Map();
  const app = new Set();
  const files = new Set();
  let builtin = 0, anonymous = 0;
  for (const s of scripts) {
    const url = s.url || '';
    if (!url) { anonymous++; continue; }
    if (url.startsWith('node:')) { builtin++; continue; }
    const p = urlToPath(url);
    if (!p) { anonymous++; continue; }
    files.add(p);
    const idx = p.lastIndexOf('/node_modules/');
    if (idx < 0) { app.add(p); continue; }
    const rest = p.slice(idx + 14).split('/');
    const segs = rest[0].startsWith('@') ? 2 : 1;
    if (rest.length < segs) continue;
    const dir = p.slice(0, idx + 14) + rest.slice(0, segs).join('/');
    if (!cache.has(dir)) cache.set(dir, readJson(fsPath(path.posix.join(dir, 'package.json'))));
    const pj = cache.get(dir);
    if (!pj || !pj.name || !pj.version) continue;
    const k = `${pj.name}@${pj.version}`;
    const e = packages.get(k) || { name: pj.name, version: pj.version, files: 0, dir };
    e.files++;
    packages.set(k, e);
  }
  return { packages, appFiles: [...app], files: [...files], builtinCount: builtin, anonymousCount: anonymous };
}
