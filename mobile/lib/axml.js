'use strict';
// axml.js — Android binary XML (AXML) parser: AndroidManifest.xml and res/xml/*.xml.
// Produces a small element tree: { tag, attrs: {name: value}, children, text }.
// Attribute values are decoded to string / boolean / number; resource references come back as "@0x7f0a0001".

import { StringPool } from './respool.js';

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';

function decodeValue(pool, raw, type, data) {
  switch (type) {
    case 0x03: return pool.get(data);                              // string
    case 0x12: return data !== 0;                                  // boolean
    case 0x10: return data | 0;                                    // int (decimal)
    case 0x11: return data >>> 0;                                  // int (hex) — kept numeric
    case 0x01: return `@0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case 0x02: return `?0x${(data >>> 0).toString(16).padStart(8, '0')}`;
    case 0x04: { const b = Buffer.alloc(4); b.writeUInt32LE(data >>> 0); return b.readFloatLE(0); }
    default:   return raw >= 0 ? pool.get(raw) : (data >>> 0);
  }
}

export function isAxml(buf) { return buf.length > 8 && buf.readUInt16LE(0) === 0x0003 && buf.readUInt16LE(2) === 8; }

export function parseAxml(buf, { maxElements = 200000 } = {}) {
  if (!isAxml(buf)) throw new Error('not Android binary XML');
  let pos = buf.readUInt16LE(2);
  let pool = null;
  const prefixes = new Map();
  const root = { tag: '#document', attrs: {}, children: [], text: '' };
  const stack = [root];
  let count = 0;
  while (pos + 8 <= buf.length) {
    const type = buf.readUInt16LE(pos), size = buf.readUInt32LE(pos + 4);
    if (size < 8 || pos + size > buf.length) break;
    if (type === 0x0001) pool = new StringPool(buf, pos);
    else if (type === 0x0100 && pool) prefixes.set(pool.get(buf.readInt32LE(pos + 20)), pool.get(buf.readInt32LE(pos + 16)));
    else if (type === 0x0102 && pool) {
      if (++count > maxElements) throw new Error('too many XML elements');
      const name = pool.get(buf.readInt32LE(pos + 20));
      const attrStart = buf.readUInt16LE(pos + 24), attrSize = buf.readUInt16LE(pos + 26), attrCount = buf.readUInt16LE(pos + 28);
      const attrs = {};
      for (let i = 0; i < attrCount; i++) {
        const a = pos + 16 + attrStart + i * attrSize;
        if (a + 20 > buf.length) break;
        const ns = buf.readInt32LE(a), an = pool.get(buf.readInt32LE(a + 4));
        const raw = buf.readInt32LE(a + 8), vtype = buf[a + 15], data = buf.readUInt32LE(a + 16);
        const uri = ns >= 0 ? pool.get(ns) : '';
        const key = !uri || uri === ANDROID_NS ? an : `${prefixes.get(uri) || uri}:${an}`;
        attrs[key || `attr_${i}`] = decodeValue(pool, raw, vtype, data);
      }
      const node = { tag: name, attrs, children: [], text: '' };
      stack[stack.length - 1].children.push(node);
      stack.push(node);
    } else if (type === 0x0103) { if (stack.length > 1) stack.pop(); }
    else if (type === 0x0104 && pool) {
      const t = pool.get(buf.readInt32LE(pos + 16));
      if (t && stack.length) stack[stack.length - 1].text += t;
    }
    pos += size;
  }
  return root.children[0] || null;
}

export function walk(node, fn, depth = 0) {
  if (!node) return;
  fn(node, depth);
  for (const c of node.children) walk(c, fn, depth + 1);
}

export function findAll(node, tag) {
  const out = [];
  walk(node, n => { if (n.tag === tag) out.push(n); });
  return out;
}

/** Flattens an element tree into `key = "value"` lines the secrets engine understands. */
export function axmlToLines(root) {
  const lines = [];
  const esc = v => String(v).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"');
  walk(root, n => {
    for (const [k, v] of Object.entries(n.attrs)) {
      if (typeof v === 'string' && v && !v.startsWith('@0x')) lines.push(`${n.tag}.${k} = "${esc(v)}"`);
    }
    const t = n.text.trim();
    if (t) lines.push(`${n.tag} = "${esc(t)}"`);
  });
  return lines;
}
