'use strict';
// fsview.js — read-only, root-relative filesystem access for ubel-vm.
//
// Every path a check passes in is an absolute POSIX path *inside the scanned system* (/etc/ssh/sshd_config).
// With the default root "/" that is the live host; with --root <dir> it is a mounted VM disk image / extracted
// root filesystem, and symlinks are resolved INSIDE that root (an absolute link such as /etc/alternatives/x
// never escapes to the scanner's own filesystem). Nothing here writes, and nothing spawns a process.
//
// Error contract (the check engine relies on it):
//   - a missing file/dir is a normal answer: read() → null, readdir() → null, lstat() → null
//   - a permission error is NOT "missing": it throws an Error with code EACCES, so the rule that needed the
//     file is reported as "not assessed" instead of passing on the strength of a file it could not read.

import fs from 'node:fs';
import path from 'node:path';

const MAX_LINKS = 40;
const MAX_READ = 4 * 1024 * 1024;

function posixParts(p) {
  const out = [];
  for (const c of String(p).split('/')) {
    if (!c || c === '.') continue;
    out.push(c);
  }
  return out;
}

class FsView {
  /** @param {string} [root='/'] directory that stands for "/" of the scanned system */
  constructor(root = '/') {
    this.root = path.resolve(root);
    this.live = this.root === path.resolve('/') && process.platform === 'linux';
    this.denied = new Set();            // paths that could not be read (permission), for the coverage note
  }

  /** Maps a rooted path to a path on the scanner's filesystem, resolving symlinks inside the root. */
  host(p, followFinal = true) {
    let queue = posixParts(p);
    let cur = [];
    let links = 0;
    while (queue.length) {
      const comp = queue.shift();
      if (comp === '..') { cur.pop(); continue; }
      const candidate = path.join(this.root, ...cur, comp);
      let st = null;
      try { st = fs.lstatSync(candidate); } catch { st = null; }
      if (st && st.isSymbolicLink() && (queue.length > 0 || followFinal)) {
        if (++links > MAX_LINKS) { const e = new Error(`too many symbolic links: ${p}`); e.code = 'ELOOP'; throw e; }
        let target;
        try { target = fs.readlinkSync(candidate); } catch { cur.push(comp); continue; }
        if (target.startsWith('/')) cur = [];
        queue = posixParts(target).concat(queue);
        continue;
      }
      cur.push(comp);
    }
    return path.join(this.root, ...cur);
  }

  _guard(e, p) {
    if (e && (e.code === 'ENOENT' || e.code === 'ENOTDIR' || e.code === 'ELOOP')) return null;
    if (e && (e.code === 'EACCES' || e.code === 'EPERM')) {
      this.denied.add(p);
      const err = new Error(`permission denied reading ${p}`);
      err.code = 'EACCES'; err.path = p;
      throw err;
    }
    throw e;
  }

  exists(p) { return this.lstat(p) !== null; }

  /** lstat of the final component (symlinks not followed) as { mode, uid, gid, size, mtimeMs, dev, ino, isFile, isDir, isSymlink }. */
  lstat(p) {
    try {
      const st = fs.lstatSync(this.host(p, false));
      return view(st);
    } catch (e) { return this._guard(e, p); }
  }

  /** stat following symlinks. */
  stat(p) {
    try { return view(fs.statSync(this.host(p, true))); } catch (e) { return this._guard(e, p); }
  }

  readlink(p) {
    try { return fs.readlinkSync(this.host(p, false)); } catch (e) { if (e && e.code === 'EINVAL') return null; return this._guard(e, p); }
  }

  /** Whole file as UTF-8 text (capped at 4 MiB), or null when it does not exist. */
  read(p, max = MAX_READ) {
    try {
      const hp = this.host(p, true);
      const st = fs.statSync(hp);
      if (!st.isFile()) return null;
      if (st.size > max) {
        const fd = fs.openSync(hp, 'r');
        try { const b = Buffer.alloc(max); const n = fs.readSync(fd, b, 0, max, 0); return b.toString('utf8', 0, n); } finally { fs.closeSync(fd); }
      }
      return fs.readFileSync(hp, 'utf8');
    } catch (e) { return this._guard(e, p); }
  }

  /** First `n` bytes of a file as a Buffer (for key/ELF sniffing), or null. */
  readHead(p, n = 4096) {
    try {
      const fd = fs.openSync(this.host(p, true), 'r');
      try { const b = Buffer.alloc(n); const got = fs.readSync(fd, b, 0, n, 0); return b.subarray(0, got); } finally { fs.closeSync(fd); }
    } catch (e) { return this._guard(e, p); }
  }

  /** Directory entry names (sorted), or null when it is not a directory. */
  readdir(p) {
    try { return fs.readdirSync(this.host(p, true)).sort(); } catch (e) { return this._guard(e, p); }
  }

  /** Non-empty, non-comment lines (leading/trailing whitespace trimmed); null when the file does not exist. */
  lines(p) {
    const t = this.read(p);
    if (t === null) return null;
    return t.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
  }

  /** Expands a single-level glob in the last path component (dir/*.conf, dir/sshd_config.d/*); no recursion. */
  glob(pattern) {
    const i = pattern.lastIndexOf('/');
    const dir = i <= 0 ? '/' : pattern.slice(0, i);
    const leaf = pattern.slice(i + 1);
    if (!/[*?]/.test(leaf)) return this.exists(pattern) ? [pattern] : [];
    const names = this.readdir(dir) || [];
    const re = new RegExp('^' + leaf.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
    return names.filter((n) => re.test(n)).map((n) => (dir === '/' ? '/' : dir + '/') + n);
  }

  /**
   * Iterative tree walk (no symlink following, never leaves the root).
   * @param {string[]} starts  rooted directories to begin at
   * @param {{skip?: (rootedPath:string)=>boolean, maxEntries?: number, deadline?: number}} opts
   * @param {(rootedPath:string, st:object)=>void} visit
   * @returns {{visited:number, truncated:boolean}}
   */
  walk(starts, opts, visit) {
    const { skip = () => false, maxEntries = 3_000_000, deadline = Infinity } = opts || {};
    const stack = [...starts].reverse();
    let visited = 0, truncated = false;
    while (stack.length) {
      const dir = stack.pop();
      let names, hdir;
      try { hdir = this.host(dir, true); names = fs.readdirSync(hdir); } catch { continue; }   // unreadable subtree: skipped, like find(1)
      for (const name of names) {
        const rp = (dir === '/' ? '' : dir) + '/' + name;
        if (skip(rp)) continue;
        let st;
        try { st = fs.lstatSync(path.join(hdir, name)); } catch { continue; }
        visited++;
        if (visited > maxEntries || Date.now() > deadline) { truncated = true; return { visited, truncated }; }
        const v = view(st);
        visit(rp, v);
        if (v.isDir) stack.push(rp);
      }
    }
    return { visited, truncated };
  }
}

function view(st) {
  return {
    mode: st.mode & 0o7777, uid: st.uid, gid: st.gid, size: st.size, mtimeMs: st.mtimeMs, dev: st.dev, ino: st.ino,
    isFile: st.isFile(), isDir: st.isDirectory(), isSymlink: st.isSymbolicLink(),
  };
}

const octal = (m) => '0' + (m & 0o7777).toString(8).padStart(3, '0');

export { FsView, octal };
