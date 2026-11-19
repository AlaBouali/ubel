'use strict';
// probe.js — opt-in (--probe) look at what the listening sockets of the scanned processes actually answer, over the loopback
// interface only. A handful of plain GET requests per HTTP port: the front page, and a fixed list of well-known paths whose
// presence is itself a finding (a debug interface, an environment dump, a source-control directory, a profiler). Nothing is
// sent that changes state, no credentials are tried, and nothing leaves this machine. For a deep external scan of a service use ubel-url.

import http from 'node:http';

const PATHS = [
  { id: 'inspector', path: '/json/version', test: (r) => r.status === 200 && /webSocketDebuggerUrl|"Browser"\s*:\s*"node\.js/i.test(r.body) },
  { id: 'env-file', path: '/.env', test: (r) => r.status === 200 && /^[A-Z][A-Z0-9_]{2,}=.+/m.test(r.body) && !/<html/i.test(r.body) },
  { id: 'git-dir', path: '/.git/HEAD', test: (r) => r.status === 200 && /^ref: refs\//.test(r.body) },
  { id: 'actuator-env', path: '/actuator/env', test: (r) => r.status === 200 && /propertySources/.test(r.body) },
  { id: 'actuator-heapdump', path: '/actuator/heapdump', test: (r) => r.status === 200 && /octet-stream/i.test(r.type) },
  { id: 'pprof', path: '/debug/pprof/', test: (r) => r.status === 200 && /Types of profiles available/i.test(r.body) },
  { id: 'server-status', path: '/server-status', test: (r) => r.status === 200 && /Apache Server Status/i.test(r.body) },
  { id: 'metrics', path: '/metrics', test: (r) => r.status === 200 && /^# (HELP|TYPE) /m.test(r.body) },
  { id: 'phpinfo', path: '/phpinfo.php', test: (r) => r.status === 200 && /phpinfo\(\)|PHP Version/i.test(r.body) },
];

function get(host, port, path, timeout) {
  return new Promise((resolve) => {
    let done = false; const fin = (v) => { if (!done) { done = true; resolve(v); } };
    const req = http.request({ host, port, path, method: 'GET', timeout, headers: { Host: `${host}:${port}`, 'User-Agent': 'ubel-runtime/probe', Accept: '*/*', Connection: 'close' } }, (res) => {
      let b = ''; res.setEncoding('utf8');
      res.on('data', (d) => { if (b.length < 16384) b += d; else req.destroy(); });
      res.on('end', () => fin({ ok: true, status: res.statusCode, headers: res.headers, type: String(res.headers['content-type'] || ''), body: b }));
      res.on('close', () => fin({ ok: true, status: res.statusCode, headers: res.headers, type: String(res.headers['content-type'] || ''), body: b }));
    });
    req.on('timeout', () => { req.destroy(); fin({ ok: false, error: 'timeout' }); });
    req.on('error', (e) => fin({ ok: false, error: e.code || e.message }));
    req.end();
  });
}

/** @param {{addr:string,port:number}[]} listeners @returns {Promise<object[]>} one record per distinct port */
export async function probeListeners(listeners, { timeout = 3000, log = () => {} } = {}) {
  const seen = new Set(), out = [];
  for (const l of listeners) {
    if (seen.has(l.port)) continue; seen.add(l.port);
    const host = /:/.test(l.addr) && !/^::ffff:/.test(l.addr) && l.addr !== '::' ? '::1' : '127.0.0.1';
    const front = await get(host, l.port, '/', timeout);
    const rec = { port: l.port, host, http: false, status: null, server: null, powered_by: null, exposed: [] };
    if (front.ok) {
      rec.http = true; rec.status = front.status; rec.server = front.headers.server || null; rec.powered_by = front.headers['x-powered-by'] || null;
      for (const p of PATHS) {
        const r = await get(host, l.port, p.path, timeout);
        if (r.ok && p.test(r)) rec.exposed.push({ id: p.id, path: p.path, status: r.status });
      }
    } else rec.error = front.error;
    log(`  probe ${host}:${l.port}: ${rec.http ? 'HTTP ' + rec.status : 'no HTTP answer (' + rec.error + ')'}${rec.exposed.length ? ' — exposed: ' + rec.exposed.map((e) => e.id).join(', ') : ''}`);
    out.push(rec);
  }
  return out;
}
