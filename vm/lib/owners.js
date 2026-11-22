'use strict';
// owners.js — which operating-system package owns a file, read from the package database ON DISK (no dpkg / apk / rpm is run):
//   dpkg   /var/lib/dpkg/info/<package>[:<arch>].list     one path per line
//   apk    /lib/apk/db/installed                          F:<dir> / R:<file> records
//   rpm    the rpm database (BDB / sqlite), through sca/rpmdb_reader.js
// Two callers need it:
//   - ubel-vm skips application packages (Python wheels, npm modules …) that the distribution itself installed. Their versions are
//     the distribution's patched builds (Debian keeps the upstream version number and backports the fix), so matching them against
//     the upstream advisories of PyPI / npm would report vulnerabilities that the distribution already fixed. The OS package check
//     covers them with release-scoped advisories instead.
//   - ubel-runtime maps the executables and libraries a running process has mapped to the packages that own them.
// Paths are compared after "usr-merge" normalisation (/bin → /usr/bin, /lib → /usr/lib …): dpkg still lists /lib/x86_64-linux-gnu/…
// while /proc/<pid>/maps shows the resolved /usr/lib/x86_64-linux-gnu/….

import fs from 'node:fs';
import path from 'node:path';
import { findRpmDb, readRpmDb } from '../../sca/rpmdb_reader.js';      // plain fs + path: reads the rpm database file itself

const MERGED = /^\/(?:bin|sbin|lib|lib32|lib64|libx32)(?:\/|$)/;

/** Canonical form of an absolute path: duplicate slashes and a trailing slash removed, usr-merged directories under /usr. */
export function canonPath(p) {
  let s = String(p || '').replace(/\/{2,}/g, '/');
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return MERGED.test(s) ? `/usr${s}` : s;
}

const readText = (file) => { try { return fs.readFileSync(file, 'utf8'); } catch { return null; } };

export class OwnerIndex {
  /** @param {string} [root]  "/" or "" = the running host; otherwise a mounted image / another process's root (/proc/<pid>/root) */
  constructor(root = '/') {
    this.rootDir = !root || root === '/' ? '' : root;
    this.map = new Map();       // canonical path → package name
    this.kind = null;           // 'dpkg' | 'apk' | 'rpm' | null (no readable database)
    this.error = null;          // why a database that exists could not be read
    this.loaded = false;
  }

  /** Reads the database once. Never throws: a missing / unreadable database leaves the index empty and `kind` / `error` say why. */
  load() {
    if (this.loaded) return this;
    this.loaded = true;
    const at = (p) => (this.rootDir ? path.join(this.rootDir, p) : p);
    try {
      if (fs.existsSync(at('/var/lib/dpkg/status'))) { this.kind = 'dpkg'; this._loadDpkg(at('/var/lib/dpkg/info')); return this; }
      if (fs.existsSync(at('/lib/apk/db/installed'))) { this.kind = 'apk'; this._loadApk(at('/lib/apk/db/installed')); return this; }
      this._loadRpm();
    } catch (e) { this.error = e.message; this.map.clear(); }
    return this;
  }

  _loadDpkg(infoDir) {
    let names;
    try { names = fs.readdirSync(infoDir); } catch (e) { throw new Error(`dpkg file lists unreadable (${e.code || e.message})`); }
    for (const f of names) {
      if (!f.endsWith('.list')) continue;
      const pkg = f.slice(0, -5).split(':')[0];
      const text = readText(path.join(infoDir, f));
      if (text === null) continue;
      for (const line of text.split('\n')) { const p = line.trim(); if (p && p !== '/.') this.map.set(canonPath(p), pkg); }
    }
  }

  _loadApk(dbFile) {
    const text = readText(dbFile);
    if (text === null) throw new Error('apk database unreadable');
    let pkg = null, dir = '';
    for (const raw of text.split('\n')) {
      const line = raw.trimEnd();
      if (line.startsWith('P:')) { pkg = line.slice(2).trim(); dir = ''; }
      else if (line.startsWith('F:')) { dir = line.slice(2).trim(); if (pkg && dir) this.map.set(canonPath(`/${dir}`), pkg); }
      else if (line.startsWith('R:') && pkg) this.map.set(canonPath(dir ? `/${dir}/${line.slice(2).trim()}` : `/${line.slice(2).trim()}`), pkg);
    }
  }

  _loadRpm() {
    if (!findRpmDb(this.rootDir)) return;                                   // no package database at all: nothing owns anything
    this.kind = 'rpm';
    for (const p of readRpmDb(this.rootDir)) for (const f of p.files || []) if (f && f.path) this.map.set(canonPath(f.path), p.name);
  }

  /** Package that owns `p` (a path as the owning filesystem sees it), or null. */
  ownerOf(p) { return this.map.get(canonPath(p)) ?? null; }
  owns(p) { return this.map.has(canonPath(p)); }
  get size() { return this.map.size; }
}
