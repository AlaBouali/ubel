'use strict';
import fs from 'node:fs';
import path from 'node:path';
import { rule, needLive } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';
import { procLabel, scopeOf, inTempDir, baseName } from '../lib/util.js';

const CRITICAL_LIB = /(?:^|\/)(?:libssl|libcrypto|libc|libc-[\d.]+|ld-linux[^/]*|ld-[\d.]+|libgnutls|libz|libpam|libsystemd|libnss_[a-z]+|libgcrypt|libsqlite3)[.-]/;
const WRITABLE_PATH = (p) => !p || p === '.' || p === '' || inTempDir(p.endsWith('/') ? p : p + '/');

export default [
  rule({
    id: 'rt-lib-stale-mapped', area: 'libraries', severity: 'medium', title: 'Process still uses a library that was replaced or deleted on disk',
    description: 'The process has the old version of a shared library mapped in memory although the file on disk was updated or removed — the classic "patched but not restarted" state. The vulnerable code keeps running until the process is restarted.',
    remediation: 'Restart the listed processes (or the services that own them; `needrestart` / `checkrestart` list them on most distributions). Reboot if the library is used by init or the C library.',
    cap: 150,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const groups = new Map();
      let unreadable = 0;
      for (const p of ctx.targets) {
        const m = ctx.mapsOf(p);
        if (!m) { unreadable++; continue; }
        for (const f of m.files) {
          if (!f.deleted || !f.exec) continue;
          if (/^\/(memfd:|dev\/|SYSV|run\/|proc\/)/.test(f.path) || inTempDir(f.path)) continue;       // anonymous memory, shared memory, temp (own check)
          const k = `${f.path}\u0001${scopeOf(p)}`;
          if (!groups.has(k)) groups.set(k, { file: f.path, scope: scopeOf(p), labels: new Set(), pids: [] });
          const g = groups.get(k); g.labels.add(procLabel(p)); if (g.pids.length < 8) g.pids.push(p.pid);
        }
      }
      if (unreadable === ctx.targets.length && ctx.targets.length) return unassessed('/proc/<pid>/maps of every process is unreadable (run as root, or as the owner of the processes)');
      if (unreadable) ctx.notes.push(`${unreadable} process(es) had unreadable memory maps (other users' processes): stale libraries in them were not checked.`);
      return [...groups.values()].map((g) => ({
        resource: `${baseName(g.file)} (${g.file})`, scope: g.scope, severity: CRITICAL_LIB.test(g.file) ? 'high' : 'medium',
        detail: `Used by ${[...g.labels].slice(0, 5).join(', ')}${g.labels.size > 5 ? `, … (${g.labels.size} programs)` : ''}; pids ${g.pids.join(', ')}.`,
      }));
    },
  }),
  rule({
    id: 'rt-lib-from-temp', area: 'libraries', severity: 'high', title: 'Process has loaded native code from a world-writable directory',
    description: 'A shared library or native addon mapped into the process lives in /tmp, /var/tmp or /dev/shm. Anyone who can write there can plant code that this process then runs; it is also where injected payloads are staged.',
    remediation: 'Install libraries and addons in directories only their owner can write. Investigate how the file got there and who started the process if you do not recognise it.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [], seen = new Set();
      for (const p of ctx.targets) {
        const m = ctx.mapsOf(p); if (!m) continue;
        for (const f of m.files) {
          if (!f.exec || !inTempDir(f.path)) continue;
          const k = `${f.path}\u0001${scopeOf(p)}`; if (seen.has(k)) continue; seen.add(k);
          out.push({ resource: f.path, scope: scopeOf(p), detail: `Mapped by ${procLabel(p)} (pid ${p.pid})${f.deleted ? '; the file has been deleted since it was loaded' : ''}.` });
        }
      }
      return out;
    },
  }),
  rule({
    id: 'rt-lib-preload-hijack', area: 'libraries', severity: 'medium', title: 'Library injection through LD_PRELOAD / LD_LIBRARY_PATH or /etc/ld.so.preload',
    description: 'A process runs with LD_PRELOAD set, or an LD_LIBRARY_PATH that contains the working directory, an empty entry or a world-writable directory, or the host has a non-empty /etc/ld.so.preload. All of these make the dynamic linker load someone\'s code into every program — a standard rootkit and hooking technique, occasionally a legitimate profiler or sandbox shim.',
    remediation: 'Confirm that each library is expected and installed by an administrator. Remove unexpected entries and restart the process; treat an unknown /etc/ld.so.preload as a sign of compromise.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [];
      try {
        const pre = fs.readFileSync('/etc/ld.so.preload', 'utf8').split('\n').map((l) => l.replace(/#.*/, '').trim()).filter(Boolean);
        if (pre.length) out.push({ resource: '/etc/ld.so.preload', scope: 'host', severity: 'high', title: 'System-wide library preload is configured', detail: `Every dynamically linked program loads: ${pre.join(', ')}.` });
      } catch { /* absent or unreadable: nothing to report */ }
      let readable = 0;
      const seen = new Set();
      for (const p of ctx.targets) {
        const env = ctx.environOf(p);
        if (!env) continue;
        readable++;
        for (const [k, v] of env) {
          if (k !== 'LD_PRELOAD' && k !== 'LD_LIBRARY_PATH') continue;
          const entries = v.split(/[:\s]+/);
          const risky = k === 'LD_PRELOAD' ? entries.filter(Boolean) : (v.split(':').some((x) => WRITABLE_PATH(x)) ? [v] : []);
          if (!risky.length) continue;
          const key = `${procLabel(p)}\u0001${k}\u0001${v}`; if (seen.has(key)) continue; seen.add(key);
          const temp = entries.some((e) => inTempDir(e));
          out.push({ resource: `${procLabel(p)} ${k}`, scope: scopeOf(p), severity: k === 'LD_PRELOAD' && temp ? 'high' : 'medium', detail: `pid ${p.pid}: ${k}=${short(v, 160)}${temp ? ' (a world-writable directory)' : ''}.` });
        }
      }
      if (!readable && ctx.targets.length && !out.length) return unassessed('the environment of every process is unreadable (run as root, or as the owner of the processes)');
      if (readable < ctx.targets.length) ctx.notes.push(`${ctx.targets.length - readable} process(es) had an unreadable environment: LD_PRELOAD / LD_LIBRARY_PATH were not checked in them.`);
      return out;
    },
  }),
];
