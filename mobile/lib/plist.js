'use strict';
// plist.js — Apple property lists: XML and binary (bplist00) → plain JS values. No external parser.

const MAX_DEPTH = 40;
const MAX_NODES = 500000;

export function parsePlist(buf) {
  if (buf.length >= 8 && buf.toString('latin1', 0, 8) === 'bplist00') return parseBinary(buf);
  return parseXml(buf.toString('utf8').replace(/^\uFEFF/, ''));
}

// ── XML ───────────────────────────────────────────────────────────────────────────────────────────
const ENT = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'" };
const unescapeXml = s => s.replace(/&(#x[0-9a-f]+|#\d+|amp|lt|gt|quot|apos);/gi, (m, e) => {
  if (e[0] === '#') { const c = e[1] === 'x' || e[1] === 'X' ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10); return Number.isFinite(c) && c <= 0x10ffff ? String.fromCodePoint(c) : m; }
  return ENT[e.toLowerCase()] ?? m;
});

function parseXml(text) {
  let i = 0, nodes = 0;
  const len = text.length;
  function skipMisc() {
    for (;;) {
      while (i < len && /\s/.test(text[i])) i++;
      if (text.startsWith('<?', i)) { const e = text.indexOf('?>', i); if (e < 0) throw new Error('bad plist'); i = e + 2; }
      else if (text.startsWith('<!--', i)) { const e = text.indexOf('-->', i); if (e < 0) throw new Error('bad plist'); i = e + 3; }
      else if (text.startsWith('<!', i)) { const e = text.indexOf('>', i); if (e < 0) throw new Error('bad plist'); i = e + 1; }
      else return;
    }
  }
  function readTag() {
    skipMisc();
    if (text[i] !== '<') throw new Error('bad plist: expected tag');
    const e = text.indexOf('>', i);
    if (e < 0) throw new Error('bad plist');
    const raw = text.slice(i + 1, e); i = e + 1;
    const closing = raw[0] === '/', self = raw.endsWith('/');
    const name = raw.replace(/^\//, '').replace(/\/$/, '').trim().split(/\s+/)[0];
    return { name, closing, self };
  }
  function readText(endName) {
    const e = text.indexOf(`</${endName}>`, i);
    if (e < 0) throw new Error('bad plist');
    const t = text.slice(i, e); i = e + endName.length + 3;
    return unescapeXml(t.replace(/^<!\[CDATA\[|\]\]>$/g, ''));
  }
  function value(depth) {
    if (depth > MAX_DEPTH || ++nodes > MAX_NODES) throw new Error('plist too deep or large');
    const t = readTag();
    if (t.closing) throw new Error('bad plist: unexpected closing tag');
    switch (t.name) {
      case 'dict': {
        const o = {};
        if (t.self) return o;
        for (;;) {
          const k = readTag();
          if (k.closing && k.name === 'dict') return o;
          if (k.name !== 'key') throw new Error('bad plist: expected key');
          const key = k.self ? '' : readText('key');
          o[key] = value(depth + 1);
        }
      }
      case 'array': {
        const a = [];
        if (t.self) return a;
        for (;;) {
          skipMisc();
          if (text.startsWith('</array>', i)) { i += 8; return a; }
          a.push(value(depth + 1));
        }
      }
      case 'string': return t.self ? '' : readText('string');
      case 'integer': return t.self ? 0 : Number(readText('integer').trim());
      case 'real': return t.self ? 0 : Number(readText('real').trim());
      case 'true': return true;
      case 'false': return false;
      case 'date': return t.self ? '' : readText('date').trim();
      case 'data': return t.self ? Buffer.alloc(0) : Buffer.from(readText('data').replace(/\s+/g, ''), 'base64');
      default: throw new Error(`bad plist: unknown tag <${t.name}>`);
    }
  }
  skipMisc();
  if (!text.startsWith('<plist', i)) throw new Error('not a plist');
  const e = text.indexOf('>', i);
  if (text[e - 1] === '/') return {};
  i = e + 1;
  return value(0);
}

// ── binary ────────────────────────────────────────────────────────────────────────────────────────
function parseBinary(buf) {
  if (buf.length < 40) throw new Error('bad binary plist');
  const t = buf.length - 32;
  const offSize = buf[t + 6], refSize = buf[t + 7];
  const num = Number(buf.readBigUInt64BE(t + 8));
  const top = Number(buf.readBigUInt64BE(t + 16));
  const tableAt = Number(buf.readBigUInt64BE(t + 24));
  if (!offSize || !refSize || num > MAX_NODES || tableAt + num * offSize > t) throw new Error('bad binary plist trailer');
  const rd = (p, n) => { let v = 0; for (let k = 0; k < n; k++) v = v * 256 + buf[p + k]; return v; };
  const offsetOf = i => rd(tableAt + i * offSize, offSize);
  let visited = 0;
  function obj(i, depth) {
    if (depth > MAX_DEPTH || i >= num || ++visited > MAX_NODES * 2) throw new Error('bad binary plist');
    let p = offsetOf(i);
    if (p >= t) throw new Error('bad binary plist offset');
    const m = buf[p++], hi = m >> 4;
    let lo = m & 0xf;
    const readLen = () => {
      if (lo !== 0xf) return lo;
      const im = buf[p++]; const n = 1 << (im & 0xf);
      const v = rd(p, n); p += n; return v;
    };
    switch (hi) {
      case 0x0: return m === 0x08 ? false : m === 0x09 ? true : null;
      case 0x1: { const n = 1 << lo; return n <= 8 ? rd(p, n) : 0; }
      case 0x2: return lo === 2 ? buf.readFloatBE(p) : buf.readDoubleBE(p);
      case 0x3: return new Date(Date.UTC(2001, 0, 1) + buf.readDoubleBE(p) * 1000).toISOString();
      case 0x4: { const n = readLen(); return Buffer.from(buf.subarray(p, p + n)); }
      case 0x5: { const n = readLen(); return buf.toString('latin1', p, p + n); }
      case 0x6: { const n = readLen(); const b = Buffer.from(buf.subarray(p, p + n * 2)); b.swap16(); return b.toString('utf16le'); }
      case 0x8: return { UID: rd(p, lo + 1) };
      case 0xa: case 0xc: {
        const n = readLen(); const a = [];
        for (let k = 0; k < n; k++) a.push(obj(rd(p + k * refSize, refSize), depth + 1));
        return a;
      }
      case 0xd: {
        const n = readLen(); const o = {};
        for (let k = 0; k < n; k++) {
          const key = obj(rd(p + k * refSize, refSize), depth + 1);
          o[String(key)] = obj(rd(p + (n + k) * refSize, refSize), depth + 1);
        }
        return o;
      }
      default: return null;
    }
  }
  return obj(top, 0);
}

/** Extracts the XML plist embedded in a CMS-signed blob (embedded.mobileprovision) without parsing CMS. */
export function extractEmbeddedPlist(buf) {
  const s = buf.indexOf('<?xml');
  const e = buf.lastIndexOf('</plist>');
  if (s < 0 || e < s) return null;
  return parseXml(buf.toString('utf8', s, e + 8));
}

/** Flattens a parsed plist into `a.b.c = "value"` lines for the secrets engine. */
export function plistToLines(value, prefix = '', out = [], depth = 0) {
  if (depth > 12 || out.length > 50000) return out;
  if (typeof value === 'string') { if (value && prefix) out.push(`${prefix} = "${value.replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"')}"`); }
  else if (Array.isArray(value)) value.forEach((v, i) => plistToLines(v, `${prefix}[${i}]`, out, depth + 1));
  else if (value && typeof value === 'object' && !Buffer.isBuffer(value)) {
    for (const [k, v] of Object.entries(value)) plistToLines(v, prefix ? `${prefix}.${k}` : k, out, depth + 1);
  }
  return out;
}
