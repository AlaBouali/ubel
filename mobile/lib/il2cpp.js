'use strict';
// il2cpp.js — Unity IL2CPP `global-metadata.dat`. IL2CPP turns C# into C++, but every C# string literal and every type / method
// name still lives in this file, in the clear. Reading it through its own tables yields the exact literals (where hardcoded keys
// and endpoints are) and the identifier table (class and method names). Header: u32 sanity 0xFAB11BAF, i32 version (24–31 seen),
// then (offset, size) pairs; the literal table is 8-byte entries { length, dataIndex } into the literal-data block.
// Anything that does not validate (encrypted or custom-packed metadata) returns null so the caller can say so instead of guessing.

export const IL2CPP_SANITY = 0xfab11baf;
export const isIl2cppMetadata = buf => Buffer.isBuffer(buf) && buf.length > 64 && buf.readUInt32LE(0) === IL2CPP_SANITY;

/** @returns {{version:number, literals:string[], identifiers:string[]}|null} */
export function parseIl2cppMetadata(buf, { maxLiterals = 2_000_000 } = {}) {
  if (!isIl2cppMetadata(buf)) return null;
  const version = buf.readInt32LE(4);
  if (version < 16 || version > 40) return null;
  const litOff = buf.readUInt32LE(8), litSize = buf.readUInt32LE(12);
  const dataOff = buf.readUInt32LE(16), dataSize = buf.readUInt32LE(20);
  const strOff = buf.readUInt32LE(24), strSize = buf.readUInt32LE(28);
  const inside = (o, s) => o <= buf.length && s <= buf.length - o;
  if (!inside(litOff, litSize) || !inside(dataOff, dataSize) || !inside(strOff, strSize) || litSize % 8) return null;
  const n = Math.min(litSize / 8, maxLiterals);
  const literals = [];
  for (let i = 0; i < n; i++) {
    const len = buf.readUInt32LE(litOff + i * 8), idx = buf.readUInt32LE(litOff + i * 8 + 4);
    if (idx + len > dataSize) return null;                      // table does not describe this file: not plain metadata
    if (len) literals.push(buf.toString('utf8', dataOff + idx, dataOff + idx + len));
  }
  const identifiers = [];
  const h = buf.subarray(strOff, strOff + strSize);
  for (let a = 0; a < h.length && identifiers.length < 1_000_000;) { let e = h.indexOf(0, a); if (e < 0) e = h.length; if (e > a) identifiers.push(h.toString('utf8', a, e)); a = e + 1; }
  return { version, literals, identifiers };
}
