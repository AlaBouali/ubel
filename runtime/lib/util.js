'use strict';
// util.js — small helpers shared by the runtime scanner's modules and checks.

import path from 'node:path';

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const rule = (r) => r;
export const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
export const downgrade = (sev) => ({ critical: 'high', high: 'medium', medium: 'low', low: 'low', info: 'info' }[sev] || sev);
export const worstSeverity = (a, b) => (SEVERITIES.indexOf(a) <= SEVERITIES.indexOf(b) ? a : b);
export const mapSeverity = (s) => ({ critical: 'critical', high: 'high', moderate: 'medium', medium: 'medium', low: 'low' }[String(s || '').toLowerCase()] || 'medium');

/** A value that must never reach a report in clear text: first characters + length. */
export const redact = (v) => { v = String(v ?? ''); return v.length <= 4 ? '****' : `${v.slice(0, 3)}…(${v.length} chars)`; };

export const baseName = (p) => (p ? path.posix.basename(String(p).replace(/ \(deleted\)$/, '')) : '');
const NODE_EXE = /^(node|nodejs)(-?v?\d+(\.\d+)*)?$/i;
export const isNodeExe = (p) => NODE_EXE.test(baseName(p.exe)) || (p.cmdline.length > 0 && NODE_EXE.test(baseName(p.cmdline[0])));

const WORLD_WRITABLE_DIRS = ['/tmp/', '/var/tmp/', '/dev/shm/', '/run/shm/', '/var/crash/'];
export const inTempDir = (p) => !!p && WORLD_WRITABLE_DIRS.some((d) => String(p).startsWith(d));

/** The program a process is running: the script of an interpreter, else the executable. Never throws. */
export function scriptOf(p) {
  const a = p.cmdline || [];
  if (!a.length) return null;
  const exe = baseName(p.exe || a[0]);
  if (isNodeExe(p)) {
    const takesValue = new Set(['-r', '--require', '--import', '--loader', '--experimental-loader', '-C', '--conditions', '--inspect-port', '--title', '--max-old-space-size']);
    for (let i = 1; i < a.length; i++) {
      const x = a[i];
      if (x === '-e' || x === '--eval' || x === '-p' || x === '--print') return '[eval]';
      if (x === '--') continue;
      if (x.startsWith('-')) { if (takesValue.has(x)) i++; continue; }
      return resolveFrom(p.cwd, x);
    }
    return null;
  }
  if (/^(python|python\d(\.\d+)?|ruby|perl|php\d?|bash|sh|dash|zsh)$/.test(exe)) {
    for (let i = 1; i < a.length; i++) { if (a[i] === '-m' && a[i + 1]) return `-m ${a[i + 1]}`; if (a[i] === '-c') return '[inline]'; if (!a[i].startsWith('-')) return resolveFrom(p.cwd, a[i]); }
    return null;
  }
  if (exe === 'java') { const j = a.indexOf('-jar'); if (j >= 0 && a[j + 1]) return resolveFrom(p.cwd, a[j + 1]); }
  return null;
}
function resolveFrom(cwd, x) { try { return path.posix.isAbsolute(x) ? path.posix.normalize(x) : (cwd ? path.posix.join(cwd, x) : x); } catch { return x; } }

/** Stable label of a process across runs (no pid): "node /srv/app/server.js", "nginx". */
export function procLabel(p) {
  const exe = baseName(p.exe) || p.comm || (p.cmdline[0] ? baseName(p.cmdline[0]) : `pid ${p.pid}`);
  const s = scriptOf(p);
  return s ? `${exe} ${s}` : exe;
}
export const scopeOf = (p) => (p.container ? `${p.container.runtime}:${p.container.id.slice(0, 12)}` : 'host');

/** Groups processes that run the same program (cluster workers, forked children) so that one problem is one finding. */
export function groupByLabel(procs) {
  const m = new Map();
  for (const p of procs) {
    const k = `${procLabel(p)}\u0001${scopeOf(p)}`;
    if (!m.has(k)) m.set(k, { label: procLabel(p), scope: scopeOf(p), procs: [] });
    m.get(k).procs.push(p);
  }
  return [...m.values()];
}
export const pidList = (g, n = 6) => `pid ${g.procs.slice(0, n).map((p) => p.pid).join(', ')}${g.procs.length > n ? `, … (${g.procs.length} processes)` : ''}`;

/** Cheap, dependency-free concurrency limiter. */
export async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let next = 0;
  await Promise.all(Array.from({ length: Math.max(1, Math.min(limit, items.length || 1)) }, async () => {
    while (true) { const i = next++; if (i >= items.length) return; try { out[i] = { ok: true, value: await fn(items[i], i) }; } catch (error) { out[i] = { ok: false, error }; } }
  }));
  return out;
}

/** Node.js release lines whose security support has ended (https://github.com/nodejs/release#release-schedule). The table is embedded, so it ages. */
export const NODE_EOL = { 10: '2021-04-30', 11: '2019-06-01', 12: '2022-04-30', 13: '2020-06-01', 14: '2023-04-30', 15: '2021-06-01', 16: '2023-09-11', 17: '2022-06-01', 18: '2025-04-30', 19: '2023-06-01', 20: '2026-04-30', 21: '2024-06-01', 23: '2025-06-01', 25: '2026-06-01' };
export function nodeEol(version, now = Date.now()) {
  const m = String(version || '').match(/^v?(\d+)\./);
  if (!m) return null;
  const date = NODE_EOL[Number(m[1])];
  return date && Date.parse(date) <= now ? { major: Number(m[1]), date } : null;
}
