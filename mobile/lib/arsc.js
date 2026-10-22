'use strict';
// arsc.js — resources.arsc reader. Returns every string resource (name + value) so hardcoded keys in
// res/values/strings.xml (Maps / Firebase / OAuth client ids, …) can be scanned with their resource names.

import { StringPool } from './respool.js';

export function parseArscStrings(buf, { maxEntries = 300000 } = {}) {
  if (buf.length < 12 || buf.readUInt16LE(0) !== 0x0002) throw new Error('not a resources.arsc');
  let pos = buf.readUInt16LE(2);
  let globalPool = null;
  const out = [];
  const tableEnd = Math.min(buf.length, buf.readUInt32LE(4));
  while (pos + 8 <= tableEnd) {
    const type = buf.readUInt16LE(pos), size = buf.readUInt32LE(pos + 4);
    if (size < 8 || pos + size > buf.length) break;
    if (type === 0x0001 && !globalPool) globalPool = new StringPool(buf, pos);
    else if (type === 0x0200 && globalPool) parsePackage(buf, pos, size, globalPool, out, maxEntries);
    pos += size;
  }
  return out;
}

function parsePackage(buf, start, size, globalPool, out, maxEntries) {
  const headerSize = buf.readUInt16LE(start + 2);
  const pkgId = buf.readUInt32LE(start + 8);
  const typeStringsOff = buf.readUInt32LE(start + 268);
  const keyStringsOff = buf.readUInt32LE(start + 276);
  const typePool = typeStringsOff ? new StringPool(buf, start + typeStringsOff) : null;
  const keyPool = keyStringsOff ? new StringPool(buf, start + keyStringsOff) : null;
  if (!typePool || !keyPool) return;
  let pos = start + headerSize;
  const end = start + size;
  while (pos + 8 <= end) {
    const type = buf.readUInt16LE(pos), hs = buf.readUInt16LE(pos + 2), csize = buf.readUInt32LE(pos + 4);
    if (csize < 8 || pos + csize > end) break;
    if (type === 0x0201) {
      const typeId = buf[pos + 8], flags = buf[pos + 9];
      const entryCount = buf.readUInt32LE(pos + 12), entriesStart = buf.readUInt32LE(pos + 16);
      const typeName = typePool.get(typeId - 1);
      if (typeName === 'string') {
        // a config with no qualifiers (all bytes after the 4-byte size are zero) is the default one
        const cfgSize = buf.readUInt32LE(pos + 20);
        let isDefault = true;
        for (let i = 4; i < Math.min(cfgSize, 64) && isDefault; i++) if (buf[pos + 20 + i] !== 0) isDefault = false;
        const offsets = pos + hs;
        const sparse = (flags & 1) !== 0, off16 = (flags & 2) !== 0;
        for (let i = 0; i < entryCount && out.length < maxEntries; i++) {
          let idx = i, off;
          if (sparse) { const v = buf.readUInt32LE(offsets + i * 4); idx = v & 0xffff; off = (v >>> 16) * 4; }
          else if (off16) { const v = buf.readUInt16LE(offsets + i * 2); if (v === 0xffff) continue; off = v * 4; }
          else { off = buf.readUInt32LE(offsets + i * 4); if (off === 0xffffffff) continue; }
          const e = pos + entriesStart + off;
          if (e + 16 > pos + csize) continue;
          const eflags = buf.readUInt16LE(e + 2);
          if (eflags & 0x0001 || eflags & 0x0008) continue;              // complex or compact entries
          const key = buf.readUInt32LE(e + 4);
          const dataType = buf[e + 8 + 3], data = buf.readUInt32LE(e + 8 + 4);
          if (dataType !== 0x03) continue;
          out.push({ id: ((pkgId << 24) | (typeId << 16) | idx) >>> 0, name: keyPool.get(key), value: globalPool.get(data), isDefault });
        }
      }
    }
    pos += csize;
  }
}
