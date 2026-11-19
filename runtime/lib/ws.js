'use strict';
// ws.js — a minimal RFC 6455 WebSocket client over node:http / node:crypto (Node.js 18 has no global WebSocket), plus a tiny
// Chrome-DevTools-Protocol session on top of it. Only what talking to a local Node.js inspector needs: text frames, ping/pong,
// close, fragmented messages, 16/64-bit lengths, client-side masking.

import http from 'node:http';
import crypto from 'node:crypto';
import { EventEmitter } from 'node:events';

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_MESSAGE = 64 * 1024 * 1024;

class WsClient extends EventEmitter {
  constructor(socket, head) {
    super();
    this.socket = socket; this.buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0); this.frags = []; this.fragBytes = 0; this.closed = false;
    socket.on('data', (d) => { this.buf = Buffer.concat([this.buf, d]); try { this._parse(); } catch (e) { this._fail(e); } });
    socket.on('close', () => this._closed());
    socket.on('error', (e) => this.emit('error', e));
    if (this.buf.length) { try { this._parse(); } catch (e) { this._fail(e); } }
  }
  _fail(e) { this.emit('error', e); this.close(); }
  _closed() { if (!this.closed) { this.closed = true; this.emit('close'); } }
  _parse() {
    for (;;) {
      if (this.buf.length < 2) return;
      const b0 = this.buf[0], b1 = this.buf[1];
      const fin = (b0 & 0x80) !== 0, op = b0 & 0x0f, masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f, off = 2;
      if (len === 126) { if (this.buf.length < 4) return; len = this.buf.readUInt16BE(2); off = 4; }
      else if (len === 127) { if (this.buf.length < 10) return; const big = this.buf.readBigUInt64BE(2); if (big > BigInt(MAX_MESSAGE)) throw new Error('websocket frame too large'); len = Number(big); off = 10; }
      if (len > MAX_MESSAGE) throw new Error('websocket frame too large');
      const need = off + (masked ? 4 : 0) + len;
      if (this.buf.length < need) return;
      let payload = this.buf.subarray(off + (masked ? 4 : 0), need);
      if (masked) { const m = this.buf.subarray(off, off + 4); payload = Buffer.from(payload); for (let i = 0; i < payload.length; i++) payload[i] ^= m[i & 3]; }
      this.buf = this.buf.subarray(need);
      if (op === 0x8) { this.close(); return; }
      if (op === 0x9) { this._frame(0xA, payload); continue; }             // ping → pong
      if (op === 0xA) continue;
      if (op === 0x1 || op === 0x2 || op === 0x0) {
        this.frags.push(payload); this.fragBytes += payload.length;
        if (this.fragBytes > MAX_MESSAGE) throw new Error('websocket message too large');
        if (fin) { const msg = Buffer.concat(this.frags).toString('utf8'); this.frags = []; this.fragBytes = 0; this.emit('message', msg); }
      }
    }
  }
  _frame(op, payload) {
    if (this.closed || this.socket.destroyed) return;
    const len = payload.length;
    const head = len < 126 ? Buffer.alloc(2) : len < 65536 ? Buffer.alloc(4) : Buffer.alloc(10);
    head[0] = 0x80 | op;
    if (len < 126) head[1] = 0x80 | len; else if (len < 65536) { head[1] = 0x80 | 126; head.writeUInt16BE(len, 2); } else { head[1] = 0x80 | 127; head.writeBigUInt64BE(BigInt(len), 2); }
    const mask = crypto.randomBytes(4);
    const body = Buffer.from(payload);
    for (let i = 0; i < body.length; i++) body[i] ^= mask[i & 3];
    this.socket.write(Buffer.concat([head, mask, body]));
  }
  send(text) { this._frame(0x1, Buffer.from(text, 'utf8')); }
  close() { if (this.closed) return; try { this._frame(0x8, Buffer.alloc(0)); } catch { /* already gone */ } this.closed = true; try { this.socket.destroy(); } catch { /* ignore */ } this.emit('close'); }
}

/** @returns {Promise<WsClient>} */
export function wsConnect(url, { timeout = 5000 } = {}) {
  return new Promise((resolve, reject) => {
    let u; try { u = new URL(url); } catch (e) { return reject(e); }
    if (u.protocol !== 'ws:') return reject(new Error('only ws:// URLs are supported (the Node.js inspector does not speak TLS)'));
    const key = crypto.randomBytes(16).toString('base64');
    const req = http.request({
      host: u.hostname, port: u.port || 80, path: u.pathname + u.search, timeout,
      headers: { Connection: 'Upgrade', Upgrade: 'websocket', 'Sec-WebSocket-Key': key, 'Sec-WebSocket-Version': '13', Host: u.host },
    });
    req.on('upgrade', (res, socket, head) => {
      const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
      if (res.headers['sec-websocket-accept'] !== accept) { socket.destroy(); return reject(new Error('websocket handshake rejected (bad Sec-WebSocket-Accept)')); }
      socket.setTimeout(0);
      resolve(new WsClient(socket, head));
    });
    req.on('response', (res) => { res.resume(); reject(new Error(`websocket upgrade refused (HTTP ${res.statusCode})`)); });
    req.on('timeout', () => { req.destroy(new Error('websocket connect timed out')); });
    req.on('error', reject);
    req.end();
  });
}

/** A Chrome-DevTools-Protocol session: call() with a timeout, event subscription. */
export class Cdp {
  constructor(ws) {
    this.ws = ws; this.id = 0; this.pending = new Map(); this.handlers = new Map();
    ws.on('message', (m) => {
      let j; try { j = JSON.parse(m); } catch { return; }
      if (j.id != null && this.pending.has(j.id)) { const p = this.pending.get(j.id); this.pending.delete(j.id); clearTimeout(p.t); j.error ? p.reject(new Error(`${j.error.message || 'protocol error'}`)) : p.resolve(j.result || {}); }
      else if (j.method) for (const h of this.handlers.get(j.method) || []) { try { h(j.params || {}); } catch { /* handler bugs must not break the session */ } }
    });
    const gone = () => { for (const p of this.pending.values()) { clearTimeout(p.t); p.reject(new Error('inspector connection closed')); } this.pending.clear(); };
    ws.on('close', gone); ws.on('error', gone);
  }
  on(method, fn) { if (!this.handlers.has(method)) this.handlers.set(method, []); this.handlers.get(method).push(fn); }
  call(method, params = {}, timeout = 8000) {
    return new Promise((resolve, reject) => {
      const id = ++this.id;
      const t = setTimeout(() => { this.pending.delete(id); reject(new Error(`${method} timed out`)); }, timeout);
      this.pending.set(id, { resolve, reject, t });
      try { this.ws.send(JSON.stringify({ id, method, params })); } catch (e) { clearTimeout(t); this.pending.delete(id); reject(e); }
    });
  }
  close() { this.ws.close(); }
}
