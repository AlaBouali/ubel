'use strict';
// hermes.js — Hermes bytecode (.hbc, the default JS engine of React Native since 0.70). The JavaScript source is gone, but the
// string table (every string literal and identifier of the bundle) is stored as data. Reading it through its own index gives
// real, separate strings — far better input for the secrets engine than printable runs, which fuse neighbouring strings together.
//
// Layout (verified against bytecode version 94 compiled by hermesc 0.12): u64 magic · u32 version · sha1[20] · header fields (u32 each) ·
// options byte · padding to a multiple of 32; then function headers (16 B each), string kinds, identifier hashes, the small string
// table (u32 each: bit 0 = UTF-16, bits 1-23 = offset, bits 24-31 = length, 255 = "see overflow table"), the overflow table (u32 offset,
// u32 length), and the string storage. Field sets differ between bytecode versions, so several candidate layouts are tried and each
// is accepted only if EVERY string-table entry falls inside the storage area; if none validates, the caller falls back to printable runs.

export const HERMES_MAGIC = 0x1f1903c103bc1fc6n;

export const isHermes = buf => Buffer.isBuffer(buf) && buf.length >= 128 && buf.readBigUInt64LE(0) === HERMES_MAGIC;

const MAX_STRINGS = 3_000_000;

function candidates(version) {
  const out = [];
  const seen = new Set();
  const add = (bigint, funcSource, pad) => { const k = `${bigint}${funcSource}${pad}`; if (!seen.has(k)) { seen.add(k); out.push({ bigint, funcSource, pad }); } };
  const bigint = version >= 87, funcSource = version >= 84;
  for (const pad of [32, 4]) { add(bigint, funcSource, pad); }
  for (const b of [true, false]) for (const f of [true, false]) for (const pad of [32, 4]) add(b, f, pad);
  return out;
}

function tryLayout(buf, version, { bigint, funcSource, pad }) {
  const names = ['fileLength', 'globalCodeIndex', 'functionCount', 'stringKindCount', 'identifierCount', 'stringCount', 'overflowStringCount', 'stringStorageSize'];
  if (bigint) names.push('bigIntCount', 'bigIntStorageSize');
  names.push('regExpCount', 'regExpStorageSize', 'arrayBufferSize', 'objKeyBufferSize', 'objValueBufferSize', 'segmentID', 'cjsModuleCount');
  if (funcSource) names.push('functionSourceCount');
  names.push('debugInfoOffset');
  const h = {};
  let p = 32;
  if (p + names.length * 4 + 1 > buf.length) return null;
  for (const n of names) { h[n] = buf.readUInt32LE(p); p += 4; }
  p += 1;                                                       // options byte
  if (h.stringCount > MAX_STRINGS || h.functionCount > 5_000_000 || h.stringStorageSize > buf.length || h.overflowStringCount > h.stringCount) return null;
  if (h.fileLength && h.fileLength > buf.length + 4096) return null;
  const align = n => (n + pad - 1) & ~(pad - 1);
  const a4 = n => (n + 3) & ~3;
  p = align(p);
  p += h.functionCount * 16; p = a4(p);
  p += h.stringKindCount * 4; p = a4(p);
  p += h.identifierCount * 4; p = a4(p);
  const small = p; p += h.stringCount * 4; p = a4(p);
  const over = p; p += h.overflowStringCount * 8; p = a4(p);
  const storage = p;
  if (storage + h.stringStorageSize > buf.length) return null;
  // validation: every entry must resolve inside the storage area
  for (let i = 0; i < h.stringCount; i++) {
    const e = buf.readUInt32LE(small + i * 4);
    const utf16 = e & 1; let off = (e >>> 1) & 0x7fffff, len = e >>> 24;
    if (len === 0xff) {
      const idx = off;
      if (idx >= h.overflowStringCount) return null;
      off = buf.readUInt32LE(over + idx * 8); len = buf.readUInt32LE(over + idx * 8 + 4);
    }
    if (off + len * (utf16 ? 2 : 1) > h.stringStorageSize) return null;
  }
  return { h, small, over, storage };
}

/**
 * @param {Buffer} buf  a Hermes bytecode file
 * @returns {{version:number, functionCount:number, stringCount:number, strings:string[]|null, fileLength:number}}
 *   `strings` is null when the table could not be validated (unknown layout): use printable runs instead.
 */
export function parseHermes(buf) {
  if (!isHermes(buf)) throw new Error('not Hermes bytecode');
  const version = buf.readUInt32LE(8);
  for (const c of candidates(version)) {
    let lay = null;
    try { lay = tryLayout(buf, version, c); } catch { lay = null; }
    if (!lay) continue;
    const { h, small, over, storage } = lay;
    const strings = [];
    for (let i = 0; i < h.stringCount; i++) {
      const e = buf.readUInt32LE(small + i * 4);
      const utf16 = e & 1; let off = (e >>> 1) & 0x7fffff, len = e >>> 24;
      if (len === 0xff) { const idx = off; off = buf.readUInt32LE(over + idx * 8); len = buf.readUInt32LE(over + idx * 8 + 4); }
      const a = storage + off;
      const s = utf16 ? buf.toString('utf16le', a, a + len * 2) : buf.toString('latin1', a, a + len);
      if (s) strings.push(s);
    }
    return { version, functionCount: h.functionCount, stringCount: h.stringCount, strings, fileLength: h.fileLength };
  }
  return { version, functionCount: 0, stringCount: 0, strings: null, fileLength: buf.readUInt32LE(32) };
}
