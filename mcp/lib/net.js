'use strict';
// net.js — address classification shared by the config checks and the remote probe (stdlib only).

import dns from 'node:dns';
import net from 'node:net';

const stripBrackets = h => String(h).replace(/^\[|\]$/g, '');

/** 'loopback' | 'private' | 'public' for an IP literal; null when `host` is not an IP. */
export function classifyIp(host) {
  const h = stripBrackets(host).toLowerCase().split('%')[0];
  const v = net.isIP(h);
  if (!v) return null;
  if (v === 4) return classify4(h);
  const mapped = h.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
  if (mapped) return classify4(mapped[1]);
  if (h === '::1' || h === '::') return 'loopback';
  if (/^f[cd]/.test(h) || /^fe[89ab]/.test(h)) return 'private';       // fc00::/7 unique-local, fe80::/10 link-local
  return 'public';
}
function classify4(h) {
  const [a, b] = h.split('.').map(Number);
  if (a === 127 || a === 0) return 'loopback';
  if (a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 169 && b === 254) || (a === 100 && b >= 64 && b <= 127)) return 'private';
  return 'public';
}

/** Exposure of a host name or IP: 'loopback' | 'private' | 'public' | 'unknown'. Names are resolved; a name with any public address is public. */
export async function hostExposure(host, { timeoutMs = 3000 } = {}) {
  const h = stripBrackets(host).toLowerCase();
  if (h === 'localhost' || h.endsWith('.localhost')) return 'loopback';
  const ip = classifyIp(h);
  if (ip) return ip;
  if (/\.(?:local|internal|lan|home|corp|intranet)$/.test(h) || !h.includes('.')) {
    // a bare or private-suffix name: resolve anyway, fall back to private
    const r = await resolveAll(h, timeoutMs);
    return r.length ? worst(r) : 'private';
  }
  const r = await resolveAll(h, timeoutMs);
  return r.length ? worst(r) : 'unknown';
}
function worst(addrs) {
  const c = addrs.map(a => classifyIp(a) || 'public');
  return c.includes('public') ? 'public' : c.includes('private') ? 'private' : 'loopback';
}
function resolveAll(host, timeoutMs) {
  return new Promise(resolve => {
    const t = setTimeout(() => resolve([]), timeoutMs);
    dns.lookup(host, { all: true }, (err, list) => { clearTimeout(t); resolve(err ? [] : list.map(x => x.address)); });
  });
}

export const isLoopbackHost = host => { const h = stripBrackets(host).toLowerCase(); return h === 'localhost' || h.endsWith('.localhost') || classifyIp(h) === 'loopback'; };
