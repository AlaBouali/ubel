'use strict';
// session.js — a minimal MCP client over HTTP, written against the transport specification and nothing else.
//   StreamableSession   one POST per JSON-RPC message; the reply is a JSON body or an SSE stream that ends with the reply
//   LegacySseSession    GET opens an event stream whose first event (`endpoint`) names the URL to POST to; replies arrive on the stream
// Both expose call() / notify() / close(). Neither ever calls a tool: the probe only initialises and lists.

import http from 'node:http';
import https from 'node:https';
import { request, SseParser } from './http.js';

export const PROTOCOL_VERSION = '2025-06-18';
const INIT_PARAMS = version => ({ protocolVersion: PROTOCOL_VERSION, capabilities: {}, clientInfo: { name: 'ubel-mcp', version } });

const rpc = (id, method, params) => JSON.stringify({ jsonrpc: '2.0', id, method, ...(params !== undefined ? { params } : {}) });
const notification = (method, params) => JSON.stringify({ jsonrpc: '2.0', method, ...(params !== undefined ? { params } : {}) });
const isRpc = m => m && typeof m === 'object' && m.jsonrpc === '2.0';
const pick = (m, id) => (Array.isArray(m) ? m.find(x => isRpc(x) && x.id === id) : isRpc(m) && m.id === id ? m : null);

/** Parses a response body (JSON or SSE) and returns the JSON-RPC message with `id`, or null. */
export function messageFromBody(body, contentType, id) {
  if (/text\/event-stream/i.test(contentType || '')) {
    const p = new SseParser();
    for (const ev of p.feed(`${body}\n\n`)) { try { const m = pick(JSON.parse(ev.data), id); if (m) return m; } catch { /* not JSON */ } }
    return null;
  }
  try { return pick(JSON.parse(body), id); } catch { return null; }
}

export class StreamableSession {
  constructor(url, o) { this.url = url; this.o = o; this.id = 0; this.sessionId = null; this.protocol = null; this.headers = o.headers || {}; this.last = null; }
  baseHeaders(extra = {}) {
    return { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream', 'User-Agent': `ubel-mcp/${this.o.toolVersion}`,
      ...(this.protocol ? { 'MCP-Protocol-Version': this.protocol } : {}), ...(this.sessionId ? { 'Mcp-Session-Id': this.sessionId } : {}), ...this.headers, ...extra };
  }
  async init() {
    const id = ++this.id;
    const res = await this.send(rpc(id, 'initialize', INIT_PARAMS(this.o.toolVersion)), id);
    const msg = res.status >= 200 && res.status < 300 ? messageFromBody(res.body, res.headers['content-type'], id) : null;
    if (msg?.result && typeof msg.result === 'object') {
      this.protocol = msg.result.protocolVersion || PROTOCOL_VERSION;
      this.sessionId = res.headers['mcp-session-id'] || null;
      return { ok: true, result: msg.result, res };
    }
    return { ok: false, res, msg };
  }
  async send(body, id, extraHeaders = {}) {
    // The reply may be an SSE stream that stays open: stop as soon as the message with our id has arrived (recognised by the stream's framing).
    const res = await request(this.url, { method: 'POST', headers: this.baseHeaders(extraHeaders), body, timeoutMs: this.o.timeoutMs, maxBytes: this.o.maxBytes, insecure: this.o.insecure,
      onChunk: id == null ? null : (_c, soFar) => (/^\s*(?:event:|data:|:)/.test(soFar) ? !!messageFromBody(soFar, 'text/event-stream', id) : false) });
    this.last = res;
    return res;
  }
  async call(method, params) {
    const id = ++this.id;
    const res = await this.send(rpc(id, method, params), id);
    const msg = messageFromBody(res.body, res.headers['content-type'], id);
    if (!msg) throw Object.assign(new Error(`no JSON-RPC reply to ${method} (HTTP ${res.status})`), { code: 'ENORPC', status: res.status });
    return msg.error ? { error: msg.error } : { result: msg.result };
  }
  async notify(method, params) { await this.send(notification(method, params), null); }
  async close() {
    if (!this.sessionId) return;
    try { await request(this.url, { method: 'DELETE', headers: this.baseHeaders(), timeoutMs: 3000, maxBytes: 4096, insecure: this.o.insecure }); } catch { /* best effort */ }
  }
}

export class LegacySseSession {
  constructor(url, o) { this.url = url; this.o = o; this.id = 0; this.pending = new Map(); this.endpoint = null; this.headers = o.headers || {}; this.req = null; this.sessionIdInUrl = false; this.foreignEndpoint = false; this.closed = false; }
  /** Opens the stream and waits for the `endpoint` event. @returns {{ok:boolean, status?:number, res?:object}} */
  open() {
    return new Promise(resolve => {
      const u = new URL(this.url);
      const lib = u.protocol === 'https:' ? https : http;
      const opts = { method: 'GET', hostname: u.hostname.replace(/^\[|\]$/g, ''), port: u.port || undefined, path: `${u.pathname}${u.search}`, agent: false,
        headers: { Accept: 'text/event-stream', 'Cache-Control': 'no-cache', 'User-Agent': `ubel-mcp/${this.o.toolVersion}`, ...this.headers } };
      if (u.protocol === 'https:') { opts.rejectUnauthorized = !this.o.insecure; if (!/^[\d.:]+$/.test(opts.hostname)) opts.servername = opts.hostname; }
      let settled = false;
      const fin = v => { if (settled) return; settled = true; clearTimeout(t); resolve(v); };
      const t = setTimeout(() => { this.req?.destroy(); fin({ ok: false, timeout: true }); }, this.o.timeoutMs);
      const req = this.req = lib.request(opts, res => {
        if (res.statusCode !== 200 || !/text\/event-stream/i.test(res.headers['content-type'] || '')) {
          let b = ''; res.setEncoding('utf8'); res.on('data', c => { if (b.length < 2048) b += c; });
          res.on('end', () => fin({ ok: false, status: res.statusCode, headers: res.headers, body: b })); res.on('error', () => fin({ ok: false, status: res.statusCode, headers: res.headers, body: b }));
          return;
        }
        const parser = new SseParser();
        res.setEncoding('utf8');
        res.on('data', chunk => {
          if (parser.buf.length > 4194304) { req.destroy(); return; }                       // a stream that never completes an event is not an MCP server
          for (const ev of parser.feed(chunk)) {
            if (ev.event === 'endpoint') {
              try {
                const target = new URL(ev.data.trim(), this.url);
                this.endpoint = target.href;
                this.foreignEndpoint = target.origin !== u.origin;
                this.sessionIdInUrl = /[?&](?:session_?id|sessionid|sid)=/i.test(target.search);
                fin({ ok: true, res: { status: 200, headers: res.headers } });
              } catch { /* ignore a malformed endpoint */ }
            } else if (ev.data) {
              try { const m = JSON.parse(ev.data); const p = isRpc(m) && this.pending.get(m.id); if (p) { this.pending.delete(m.id); p(m); } } catch { /* not JSON */ }
            }
          }
        });
        res.on('end', () => { this.closed = true; for (const p of this.pending.values()) p(null); fin({ ok: false, status: 200, headers: res.headers, body: '' }); });
        res.on('error', () => { this.closed = true; });
      });
      req.on('error', e => { if (!settled) fin({ ok: false, error: e }); });
      req.end();
    });
  }
  async send(body) {
    return request(this.endpoint, { method: 'POST', headers: { 'Content-Type': 'application/json', 'User-Agent': `ubel-mcp/${this.o.toolVersion}`, ...this.headers }, body, timeoutMs: this.o.timeoutMs, maxBytes: 65536, insecure: this.o.insecure });
  }
  async rpc(method, params) {
    const id = ++this.id;
    const reply = new Promise(res => { this.pending.set(id, res); setTimeout(() => { if (this.pending.delete(id)) res(null); }, this.o.timeoutMs); });
    const post = await this.send(rpc(id, method, params));
    if (post.status >= 400) { this.pending.delete(id); throw Object.assign(new Error(`HTTP ${post.status} posting ${method}`), { code: 'EHTTP', status: post.status }); }
    const inline = messageFromBody(post.body, post.headers['content-type'], id);   // some servers answer in the POST body
    const msg = inline || await reply;
    if (!msg) throw Object.assign(new Error(`no reply to ${method}`), { code: 'ENORPC' });
    return msg;
  }
  async init() {
    const msg = await this.rpc('initialize', INIT_PARAMS(this.o.toolVersion));
    if (msg.result && typeof msg.result === 'object') return { ok: true, result: msg.result };
    return { ok: false, msg };
  }
  async call(method, params) { const m = await this.rpc(method, params); return m.error ? { error: m.error } : { result: m.result }; }
  async notify(method, params) { await this.send(notification(method, params)); }
  async close() { this.closed = true; try { this.req?.destroy(); } catch { /* ignore */ } }
}
