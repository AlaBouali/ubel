'use strict';
// http.js — one HTTP(S) request over node:http / node:https. Used instead of fetch() because the probe needs what fetch hides: a Host
// header it chooses, no redirect following, the TLS certificate of the connection, a byte cap, and streaming reads for SSE.

import http from 'node:http';
import https from 'node:https';

/**
 * @param {string} url
 * @param {{method?:string, headers?:object, body?:string|null, timeoutMs?:number, maxBytes?:number, insecure?:boolean,
 *          onChunk?:(text:string, soFar:string)=>boolean|void}} [o]  onChunk returning true ends the request early (SSE).
 * @returns {Promise<{status:number, headers:object, body:string, truncated:boolean, early:boolean, tls:object|null, remoteAddress:string|null}>}
 */
export function request(url, { method = 'GET', headers = {}, body = null, timeoutMs = 8000, maxBytes = 1 << 20, insecure = false, onChunk = null } = {}) {
  return new Promise((resolve, reject) => {
    let u;
    try { u = new URL(url); } catch (e) { reject(Object.assign(new Error(`invalid URL: ${url}`), { code: 'EINVALIDURL' })); return; }
    if (u.protocol !== 'http:' && u.protocol !== 'https:') { reject(Object.assign(new Error(`unsupported protocol ${u.protocol}`), { code: 'EPROTO' })); return; }
    const lib = u.protocol === 'https:' ? https : http;
    const hostname = u.hostname.replace(/^\[|\]$/g, '');
    const h = { ...headers };
    if (body != null && !Object.keys(h).some(k => k.toLowerCase() === 'content-length')) h['Content-Length'] = Buffer.byteLength(body);
    const opts = { method, hostname, port: u.port || undefined, path: `${u.pathname}${u.search}`, headers: h, agent: false };
    if (u.protocol === 'https:') { opts.rejectUnauthorized = !insecure; if (!/^[\d.:]+$/.test(hostname)) opts.servername = hostname; }
    let settled = false;
    const done = (fn, v) => { if (settled) return; settled = true; clearTimeout(timer); fn(v); };
    const timer = setTimeout(() => { req.destroy(Object.assign(new Error(`timed out after ${timeoutMs} ms`), { code: 'ETIMEDOUT' })); }, timeoutMs);
    const req = lib.request(opts, res => {
      let text = '', truncated = false, early = false;
      const sock = res.socket;
      let tls = null;
      if (u.protocol === 'https:' && sock && typeof sock.getPeerCertificate === 'function') {
        const c = sock.getPeerCertificate();
        tls = { authorized: sock.authorized, authError: sock.authorizationError ? String(sock.authorizationError) : null, protocol: sock.getProtocol?.() || null,
          validTo: c && c.valid_to ? Date.parse(c.valid_to) : null, subject: c?.subject?.CN || null, issuer: c?.issuer?.CN || null };
      }
      const finish = () => done(resolve, { status: res.statusCode, headers: res.headers, body: text, truncated, early, tls, remoteAddress: sock?.remoteAddress || null });
      res.setEncoding('utf8');
      res.on('data', chunk => {
        if (settled) return;
        text += chunk;
        if (text.length > maxBytes) { text = text.slice(0, maxBytes); truncated = true; res.destroy(); finish(); return; }
        if (onChunk && onChunk(chunk, text) === true) { early = true; res.destroy(); finish(); }
      });
      res.on('end', finish);
      res.on('close', finish);
      res.on('error', e => (settled ? null : (text ? finish() : done(reject, e))));
    });
    req.on('error', e => done(reject, e));
    if (body != null) req.write(body);
    req.end();
  });
}

/** Incremental text/event-stream parser: feed() chunks, get back complete events {event, data, id}. */
export class SseParser {
  constructor() { this.buf = ''; }
  feed(chunk) {
    this.buf += chunk.replace(/\r\n?/g, '\n');
    const events = [];
    let i;
    while ((i = this.buf.indexOf('\n\n')) >= 0) {
      const block = this.buf.slice(0, i); this.buf = this.buf.slice(i + 2);
      const ev = { event: 'message', data: '', id: null };
      const data = [];
      for (const line of block.split('\n')) {
        if (!line || line.startsWith(':')) continue;
        const c = line.indexOf(':');
        const f = c < 0 ? line : line.slice(0, c);
        const v = c < 0 ? '' : line.slice(c + 1).replace(/^ /, '');
        if (f === 'data') data.push(v); else if (f === 'event') ev.event = v; else if (f === 'id') ev.id = v;
      }
      ev.data = data.join('\n');
      if (data.length || ev.event !== 'message') events.push(ev);
    }
    return events;
  }
}
