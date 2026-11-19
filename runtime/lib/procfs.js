'use strict';
// procfs.js — what running processes look like from the outside, read from /proc only (Linux; no ps, lsof, ss or netstat,
// no process is started). Everything here is read-only. Whatever cannot be read (other users' processes without root,
// hidepid mounts) is skipped and counted in `denied`, never guessed — the checks that depend on it then report "not assessed".
//
// A ProcFs can point at another directory than /proc (the tests build a fake one), so nothing below hard-codes "/proc".

import fs from 'node:fs';
import path from 'node:path';

export const CAP_NAMES = ['CHOWN', 'DAC_OVERRIDE', 'DAC_READ_SEARCH', 'FOWNER', 'FSETID', 'KILL', 'SETGID', 'SETUID', 'SETPCAP', 'LINUX_IMMUTABLE',
  'NET_BIND_SERVICE', 'NET_BROADCAST', 'NET_ADMIN', 'NET_RAW', 'IPC_LOCK', 'IPC_OWNER', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_CHROOT', 'SYS_PTRACE',
  'SYS_PACCT', 'SYS_ADMIN', 'SYS_BOOT', 'SYS_NICE', 'SYS_RESOURCE', 'SYS_TIME', 'SYS_TTY_CONFIG', 'MKNOD', 'LEASE', 'AUDIT_WRITE', 'AUDIT_CONTROL',
  'SETFCAP', 'MAC_OVERRIDE', 'MAC_ADMIN', 'SYSLOG', 'WAKE_ALARM', 'BLOCK_SUSPEND', 'AUDIT_READ', 'PERFMON', 'BPF', 'CHECKPOINT_RESTORE'];

export function capNames(hex) {
  if (!hex || !/^[0-9a-f]+$/i.test(hex)) return [];
  let v; try { v = BigInt('0x' + hex); } catch { return []; }
  const out = [];
  for (let i = 0; i < CAP_NAMES.length; i++) if ((v >> BigInt(i)) & 1n) out.push(CAP_NAMES[i]);
  return out;
}
/** True when every capability the kernel knows is set (a "privileged" container / root with a full bounding set). */
export const capsFull = (hex) => capNames(hex).length >= 38;

export function signalSet(hex, signal) {                // SigCgt / SigIgn masks: bit (n-1) is signal n
  if (!hex || !/^[0-9a-f]+$/i.test(hex)) return null;
  try { return Boolean((BigInt('0x' + hex) >> BigInt(signal - 1)) & 1n); } catch { return null; }
}

function hexIp(hex) {
  if (hex.length === 8) return [3, 2, 1, 0].map((i) => parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join('.');
  const words = hex.match(/.{8}/g).map((w) => w.match(/../g).reverse().join(''));    // four little-endian 32-bit words
  const g = words.join('').match(/.{4}/g);
  if (g.slice(0, 5).every((x) => x === '0000') && g[5] === 'ffff') return `::ffff:${parseInt(g[6].slice(0, 2), 16)}.${parseInt(g[6].slice(2), 16)}.${parseInt(g[7].slice(0, 2), 16)}.${parseInt(g[7].slice(2), 16)}`;
  return g.map((x) => x.replace(/^0+(?=.)/, '')).join(':').replace(/(?:^|:)0(?::0)+(?::|$)/, '::');
}
export const isAnyAddr = (a) => a === '0.0.0.0' || a === '::' || a === '::ffff:0.0.0.0';
export const isLoopbackAddr = (a) => /^127\./.test(a) || a === '::1' || /^::ffff:127\./.test(a);

/** Container runtime + id from a /proc/<pid>/cgroup file (cgroup v1 and v2, docker / containerd / CRI-O / podman / LXC). */
export function containerFromCgroup(text) {
  if (!text) return null;
  const pats = [
    ['docker', /(?:\/docker\/|docker-)([0-9a-f]{64})/],
    ['containerd', /cri-containerd-([0-9a-f]{64})/],
    ['crio', /crio-([0-9a-f]{64})/],
    ['podman', /libpod-([0-9a-f]{64})/],
    ['kubernetes', /\/kubepods[^\n]*?\/([0-9a-f]{64})/],
  ];
  for (const [runtime, re] of pats) { const m = text.match(re); if (m) return { runtime, id: m[1] }; }
  const lxc = text.match(/\/(?:lxc|machine\.slice\/machine-lxc\\x2d)([^/\n.]+)/);
  if (lxc) return { runtime: 'lxc', id: lxc[1] };
  return null;
}

export class ProcFs {
  /** @param {{root?:string, hostRoot?:string}} [o]  root = the procfs directory (default /proc); hostRoot = where /etc/passwd lives (default /) */
  constructor({ root = '/proc', hostRoot = '/' } = {}) {
    this.root = root; this.hostRoot = hostRoot;
    this.denied = new Set();                         // paths that exist but could not be read (permission)
    this._users = null; this._btime = undefined; this._owners = null;
  }

  p(...a) { return path.join(this.root, ...a.map(String)); }
  _note(e, file) { if (e && (e.code === 'EACCES' || e.code === 'EPERM')) this.denied.add(file); }
  rd(...a) { const f = this.p(...a); try { return fs.readFileSync(f, 'utf8'); } catch (e) { this._note(e, f); return null; } }
  rdBuf(...a) { const f = this.p(...a); try { return fs.readFileSync(f); } catch (e) { this._note(e, f); return null; } }
  link(...a) { const f = this.p(...a); try { return fs.readlinkSync(f); } catch (e) { this._note(e, f); return null; } }
  ls(...a) { const f = this.p(...a); try { return fs.readdirSync(f); } catch (e) { this._note(e, f); return null; } }

  supported() { try { return process.platform === 'linux' && fs.existsSync(this.p('self')) && fs.existsSync(this.p('net', 'tcp')); } catch { return false; } }
  pids() { return (this.ls() || []).filter((x) => /^\d+$/.test(x)).map(Number).sort((a, b) => a - b); }

  bootTimeSec() {
    if (this._btime !== undefined) return this._btime;
    const m = (this.rd('stat') || '').match(/^btime\s+(\d+)/m);
    return (this._btime = m ? Number(m[1]) : null);
  }

  users() {
    if (this._users) return this._users;
    const m = new Map();
    try { for (const l of fs.readFileSync(path.join(this.hostRoot, 'etc/passwd'), 'utf8').split('\n')) { const f = l.split(':'); if (f.length > 3 && !m.has(Number(f[2]))) m.set(Number(f[2]), f[0]); } } catch { /* no passwd: numeric uids only */ }
    return (this._users = m);
  }

  /** One process, or null when it is gone / cannot be identified. Fields that could not be read are null. */
  process(pid) {
    const cmd = this.rd(pid, 'cmdline');
    const stat = this.rd(pid, 'stat');
    if (cmd == null && stat == null) return null;
    const cmdline = (cmd || '').split('\0');
    if (cmdline.length && cmdline[cmdline.length - 1] === '') cmdline.pop();   // arguments are NUL-terminated; keep genuinely empty ones in the middle
    if (cmdline.length === 1 && cmdline[0] === '') cmdline.length = 0;
    const commMatch = (stat || '').match(/^\d+ \((.*)\) [A-Za-z]/s);
    const comm = commMatch ? commMatch[1] : ((this.rd(pid, 'comm') || '').trim() || null);
    const after = stat ? stat.slice(stat.lastIndexOf(')') + 2).split(' ') : [];
    const status = this.rd(pid, 'status') || '';
    const st = (k) => { const m = status.match(new RegExp('^' + k + ':\\s*(.*)$', 'm')); return m ? m[1].trim() : null; };
    const ids = (st('Uid') || '').split(/\s+/).map(Number);
    const gids = (st('Gid') || '').split(/\s+/).map(Number);
    const exeRaw = this.link(pid, 'exe');
    const deleted = !!exeRaw && / \(deleted\)$/.test(exeRaw);
    const exe = exeRaw ? exeRaw.replace(/ \(deleted\)$/, '') : null;
    const ns = (n) => { const l = this.link(pid, 'ns', n); const m = l && l.match(/\[(\d+)\]/); return m ? m[1] : null; };
    const startTicks = Number(after[19]);
    const btime = this.bootTimeSec();
    const ppid = Number(after[1]) || 0;
    const cg = this.rd(pid, 'cgroup');
    const uid = ids.length > 1 ? ids[1] : (ids.length ? ids[0] : null);
    return {
      pid, ppid, comm, state: after[0] || null,
      uid, ruid: ids[0] ?? null, gid: gids.length > 1 ? gids[1] : (gids[0] ?? null),
      user: uid == null ? null : (this.users().get(uid) || String(uid)),
      cmdline, exe, exeDeleted: deleted, exeMemfd: !!exe && /^\/memfd:/.test(exe),
      cwd: this.link(pid, 'cwd'), root: this.link(pid, 'root'),
      kernelThread: !exeRaw && cmd !== null && cmdline.length === 0 && (ppid === 0 || ppid === 2),
      startMs: (btime != null && Number.isFinite(startTicks)) ? (btime + startTicks / 100) * 1000 : null,   // USER_HZ is 100 on every Linux ABI
      caps: { eff: st('CapEff'), prm: st('CapPrm'), bnd: st('CapBnd'), inh: st('CapInh') },
      noNewPrivs: st('NoNewPrivs') == null ? null : st('NoNewPrivs') === '1',
      seccomp: st('Seccomp') == null ? null : Number(st('Seccomp')),          // 0 none, 1 strict, 2 filter
      tracerPid: Number(st('TracerPid')) || 0,
      sigCgt: st('SigCgt'), sigIgn: st('SigIgn'),
      threads: Number(st('Threads')) || null, rssKb: Number((st('VmRSS') || '').split(' ')[0]) || null,
      ns: { mnt: ns('mnt'), pid: ns('pid'), net: ns('net'), user: ns('user') },
      container: containerFromCgroup(cg),
    };
  }

  processes() { return this.pids().map((p) => this.process(p)).filter(Boolean); }

  /** Files mapped into the process: libraries, the executable, native addons. `deleted` = replaced or removed on disk since it was mapped. */
  maps(pid) {
    const text = this.rd(pid, 'maps');
    if (text == null) return null;
    const files = new Map();
    let rwxAnon = 0, rwxFile = 0;
    for (const line of text.split('\n')) {
      const m = line.match(/^[0-9a-f]+-[0-9a-f]+ (\S{4}) [0-9a-f]+ (\S+) (\d+)\s*(.*)$/);
      if (!m) continue;
      const [, perms, dev, inode, rest] = m;
      const name = rest.trim();
      if (perms.startsWith('rwx')) { if (name.startsWith('/')) rwxFile++; else if (!name || name.startsWith('[anon')) rwxAnon++; }
      if (!name.startsWith('/')) continue;
      const deleted = / \(deleted\)$/.test(name);
      const file = deleted ? name.replace(/ \(deleted\)$/, '') : name;
      const e = files.get(file) || { path: file, deleted: false, exec: false, dev, inode: Number(inode) };
      e.deleted = e.deleted || deleted; e.exec = e.exec || perms[2] === 'x';
      files.set(file, e);
    }
    return { files: [...files.values()], rwxAnon, rwxFile };
  }

  /** The process environment as an ordered [name, value] list; null when unreadable (not the same user / root). */
  environ(pid) {
    const buf = this.rdBuf(pid, 'environ');
    if (buf == null) return null;
    return buf.toString('utf8').split('\0').filter(Boolean).map((kv) => { const i = kv.indexOf('='); return i < 0 ? [kv, ''] : [kv.slice(0, i), kv.slice(i + 1)]; });
  }

  /** Open file descriptors: [{ fd, target }]; null when unreadable. */
  fds(pid, limit = 4096) {
    const names = this.ls(pid, 'fd');
    if (names == null) return null;
    return names.slice(0, limit).map((fd) => ({ fd: Number(fd), target: this.link(pid, 'fd', fd) })).filter((f) => f.target);
  }

  _parseTcp(file, want) {
    const text = this.rd(...file);
    if (!text) return [];
    const out = [];
    for (const line of text.split('\n').slice(1)) {
      const f = line.trim().split(/\s+/);
      if (f.length < 10 || f[3] !== want) continue;
      const [lh, lp] = f[1].split(':'), [rh, rp] = f[2].split(':');
      let addr, remote; try { addr = hexIp(lh); remote = hexIp(rh); } catch { continue; }
      out.push({ addr, port: parseInt(lp, 16), remote, remotePort: parseInt(rp, 16), uid: Number(f[7]), inode: f[9] });
    }
    return out;
  }

  /** inode → pid of one process that holds the socket. Built once per instance; bounded. */
  socketOwners(pids, limit = 400000) {
    if (this._owners) return this._owners;
    const map = new Map();
    let n = 0;
    outer: for (const pid of pids || this.pids()) {
      const names = this.ls(pid, 'fd');
      if (!names) continue;
      for (const fd of names) {
        if (++n > limit) break outer;
        const l = this.link(pid, 'fd', fd);
        const m = l && l.match(/^socket:\[(\d+)\]$/);
        if (m && !map.has(m[1])) map.set(m[1], pid);
      }
    }
    return (this._owners = map);
  }

  /**
   * TCP sockets in LISTEN state with the process that owns them, across every network namespace that has a process in it
   * (containers have their own /proc/<pid>/net/tcp).
   * @param {object[]} procs  from processes()
   */
  listeners(procs) {
    const owners = this.socketOwners(procs.map((p) => p.pid));
    const seenNs = new Set(), out = [], seen = new Set();
    const reps = [];
    for (const p of procs) { const k = p.ns.net || 'self'; if (seenNs.has(k)) continue; seenNs.add(k); reps.push(p); }
    if (!reps.length) reps.push({ pid: 'self', ns: { net: 'self' } });
    for (const rep of reps) {
      for (const f of ['tcp', 'tcp6']) {
        for (const l of this._parseTcp([rep.pid, 'net', f], '0A')) {
          if (seen.has(l.inode)) continue; seen.add(l.inode);
          out.push({ ...l, proto: 'tcp', pid: owners.get(l.inode) ?? null, netns: rep.ns.net || null });
        }
      }
    }
    return out;
  }

  /** Listening TCP sockets of one process, read fresh (no cache) — used to watch an inspector port appear. */
  listenersOf(proc) {
    const inodes = new Set();
    for (const fd of this.ls(proc.pid, 'fd') || []) { const m = (this.link(proc.pid, 'fd', fd) || '').match(/^socket:\[(\d+)\]$/); if (m) inodes.add(m[1]); }
    if (!inodes.size) return [];
    return ['tcp', 'tcp6'].flatMap((f) => this._parseTcp([proc.pid, 'net', f], '0A')).filter((c) => inodes.has(c.inode)).map((c) => ({ addr: c.addr, port: c.port, inode: c.inode }));
  }

  /** Established TCP connections of one process. */
  connections(proc) {
    const names = this.ls(proc.pid, 'fd') || [];
    const inodes = new Set();
    for (const fd of names) { const m = (this.link(proc.pid, 'fd', fd) || '').match(/^socket:\[(\d+)\]$/); if (m) inodes.add(m[1]); }
    if (!inodes.size) return [];
    return ['tcp', 'tcp6'].flatMap((f) => this._parseTcp([proc.pid, 'net', f], '01')).filter((c) => inodes.has(c.inode)).map((c) => ({ addr: c.addr, port: c.port, remote: c.remote, remotePort: c.remotePort }));
  }
}
