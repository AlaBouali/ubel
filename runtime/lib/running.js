'use strict';
// running.js — the packages that RUNNING processes use, from the SCA engine's scans (vm/lib/scascan.js).
//
// Operating-system packages: every file a process has mapped (its executable and the libraries it loaded — /proc/<pid>/maps) is
// mapped to the package that owns it by the package database on disk (dpkg / apk / rpm file lists, vm/lib/owners.js); the SCA engine
// scans the same machine — platform mode for the host, docker mode on /proc/<pid>/root for a container — and only the advisories of
// the packages in use are kept. An installed package no running process touches stays with ubel-vm.
// Application packages: the application directory of each running Python, Ruby or PHP process (its virtualenv, script or working
// directory, up to the nearest project marker) is scanned by the SCA health scan, so every ecosystem's installed dependencies there
// — site-packages of the venv, Composer vendor/, Bundler and Cargo lockfiles — are found by the SCA scanners. Node.js applications
// have their own check (the v8 inspector can say which packages are loaded). Go and Rust programs carry their modules inside the
// binary, which the library check reads. Java applications are not read.
// Nothing is executed and nothing in the audited processes' directories is written.

import fs from 'node:fs';
import path from 'node:path';
import { OwnerIndex } from '../../vm/lib/owners.js';
import { scanPlatform, scanDocker, scanTree, mergeResults, pathsOf, isOsPurl } from '../../vm/lib/scascan.js';
import { baseName, scriptOf, procLabel, scopeOf, isNodeExe } from './util.js';

const INTERPRETER = /^(?:python[\d.]*|pypy[\d.]*|ruby[\d.]*|php[\d.]*|perl)$/i;
const MARKERS = ['requirements.txt', 'pyproject.toml', 'Pipfile', 'Pipfile.lock', 'poetry.lock', 'uv.lock', 'setup.py', 'composer.json', 'composer.lock', 'Gemfile', 'Gemfile.lock', 'Cargo.lock', 'go.mod'];
const exists = (p) => { try { fs.accessSync(p); return true; } catch { return false; } };

/** Mount-namespace groups of the processes in scope: the host's, and one per container filesystem. */
function groups(ctx) {
  const g = new Map();
  for (const p of ctx.targets) {
    const mnt = p.ns && p.ns.mnt && ctx.selfMnt && p.ns.mnt !== ctx.selfMnt ? p.ns.mnt : 'host';
    if (!g.has(mnt)) g.set(mnt, { key: mnt, host: mnt === 'host', root: mnt === 'host' ? '/' : ctx.fsPath(p, '/'), scope: scopeOf(p), procs: [] });
    g.get(mnt).procs.push(p);
  }
  return [...g.values()];
}

/** Files a process uses: its executable and every mapped file that is executable code (libraries, native modules). */
function filesOf(ctx, p) {
  const out = new Set();
  if (p.exe && p.exe.startsWith('/')) out.add(p.exe.replace(/ \(deleted\)$/, ''));
  const m = ctx.mapsOf(p);
  if (m) for (const f of m.files) if (!f.deleted && f.exec) out.add(f.path);
  return [...out];
}

/**
 * Operating-system packages in use by running processes, with the SCA advisories that apply to them.
 * @returns {Promise<{scopes:object[], notes:string[]}>}  scopes[]: { scope, label, root, procs, packages:Map<name,{files,procs}>, inventory, vulnerabilities, unowned }
 */
export function runningOsPackages(ctx) {
  return ctx.memo('running-os', async () => {
    const mode = ctx.opts.packages || 'all';
    const notes = [];
    const scopes = [];
    let hostScan = null;
    const maxScopes = ctx.opts.maxPackageScopes || 20;
    let done = 0;
    for (const g of groups(ctx)) {
      if (mode === 'host' && !g.host) continue;
      if (!g.host && done >= maxScopes) { notes.push(`Running packages were read for ${maxScopes} container filesystem(s) (--max-package-scopes); the others were not.`); break; }
      const owners = new OwnerIndex(g.host ? '/' : g.root).load();
      if (!owners.kind) { notes.push(`${g.host ? 'host' : g.scope}: no readable package database${owners.error ? ` (${owners.error})` : ''}: the packages its processes use were not identified.`); continue; }
      const packages = new Map();
      let unowned = 0;
      for (const p of g.procs) {
        for (const f of filesOf(ctx, p)) {
          const name = owners.ownerOf(f);
          if (!name) { unowned++; continue; }
          if (!packages.has(name)) packages.set(name, { files: new Set(), procs: new Set() });
          const e = packages.get(name); e.files.add(f); e.procs.add(procLabel(p));
        }
      }
      if (!packages.size) continue;
      let scan;
      if (g.host) {
        scan = hostScan || (hostScan = await scanPlatform({ workDir: ctx.opts.workDir, threatIntel: ctx.opts.threatIntel, log: ctx.log }));
      } else {
        scan = await scanDocker({ root: g.root, osOnly: true, workDir: ctx.opts.workDir, threatIntel: ctx.opts.threatIntel, log: ctx.log });
      }
      done += g.host ? 0 : 1;
      for (const w of scan.scan_warnings || []) if (!notes.includes(w)) notes.push(w);
      const inventory = scan.inventory.filter((c) => isOsPurl(c.id) && packages.has(c.name));
      const ids = new Set(inventory.map((c) => c.id));
      const merged = mergeResults([scan]);
      scopes.push({ scope: g.host ? 'host' : g.scope, label: g.host ? 'host' : g.scope, host: g.host, root: g.host ? '' : g.root.replace(/\/+$/, ''), procs: g.procs, packages, inventory, unowned,
        vulnerabilities: merged.vulnerabilities.filter((v) => ids.has(v.affected_package_id)), threatIntel: scan.threat_intel });
    }
    return { scopes, notes };
  });
}

// ── application packages ────────────────────────────────────────────────────────────────────────────────────────────

/** Nearest ancestor of `dir` (≤ 8 levels, never "/") that holds a project marker; null when there is none. */
function projectDir(dir, fsPath) {
  let d = dir;
  for (let i = 0; i < 8 && d && d !== '/' && d !== '.'; i++, d = path.posix.dirname(d)) {
    if (MARKERS.some((m) => exists(fsPath(path.posix.join(d, m))))) return d;
  }
  return null;
}

/** Application directories of one Python / Ruby / PHP process (as the process sees them). */
export function appRootsOf(ctx, p) {
  const fsPath = (x) => ctx.fsPath(p, x);
  const roots = new Set();
  const env = ctx.environOf(p);
  const venvs = [];
  const ve = env && env.find(([k]) => k === 'VIRTUAL_ENV');
  if (ve && ve[1].startsWith('/')) venvs.push(ve[1]);
  const c0 = (p.cmdline || [])[0];
  if (c0 && c0.startsWith('/') && /\/bin\/[^/]+$/.test(c0)) venvs.push(path.posix.dirname(path.posix.dirname(c0)));
  let venvFound = false;
  for (const v of venvs) if (exists(fsPath(path.posix.join(v, 'pyvenv.cfg')))) { venvFound = true; const parent = path.posix.dirname(v); if (parent !== '/') roots.add(parent); }
  const script = scriptOf(p);
  for (const start of [script && script.startsWith('/') ? path.posix.dirname(script) : null, p.cwd]) {
    const d = start && projectDir(start, fsPath); if (d) roots.add(d);
  }
  // a Python process on the system interpreter also uses what pip installed system-wide
  if (!venvFound && INTERPRETER.test(baseName(p.exe) || '') && /^python|^pypy/i.test(baseName(p.exe)) && exists(fsPath('/usr/local/lib'))) roots.add('/usr/local/lib');
  // drop a directory that lies inside another one in the list
  return [...roots].filter((r) => ![...roots].some((o) => o !== r && r.startsWith(`${o}/`)));
}

/**
 * Application packages installed under the application directories of running Python / Ruby / PHP processes, with SCA advisories.
 * @returns {Promise<{apps:object[], notes:string[]}>}  apps[]: { root, base, scope, procs, inventory, vulnerabilities }
 */
export function runningAppPackages(ctx) {
  return ctx.memo('running-apps', async () => {
    const notes = [];
    const byKey = new Map();
    for (const p of ctx.targets) {
      if (isNodeExe(p) || !INTERPRETER.test(baseName(p.exe) || '')) continue;
      for (const root of appRootsOf(ctx, p)) {
        const key = `${p.ns && p.ns.mnt || ''}:${root}`;
        if (!byKey.has(key)) byKey.set(key, { root, scope: scopeOf(p), proc: p, procs: [] });
        byKey.get(key).procs.push(p);
      }
    }
    const max = ctx.opts.maxPackageScopes || 20;
    const list = [...byKey.values()];
    if (list.length > max) notes.push(`Application packages were read for ${max} of ${list.length} application directories (--max-package-scopes).`);
    const apps = [];
    for (const a of list.slice(0, max)) {
      const dir = ctx.fsPath(a.proc, a.root);
      const strip = dir !== a.root ? dir.replace(/\/+$/, '') : '';
      const scan = await scanTree({ dir, workDir: ctx.opts.workDir, threatIntel: ctx.opts.threatIntel, log: ctx.log });
      for (const w of scan.scan_warnings || []) if (!notes.includes(w)) notes.push(w);
      const inventory = scan.inventory.map((c) => ({ ...c, paths: pathsOf(c).map((x) => (strip && x.startsWith(strip) ? x.slice(strip.length) || '/' : x)) }));
      apps.push({ root: a.root, base: strip, scope: a.scope, procs: a.procs, inventory, vulnerabilities: scan.vulnerabilities, threatIntel: scan.threat_intel });
    }
    return { apps, notes };
  });
}
