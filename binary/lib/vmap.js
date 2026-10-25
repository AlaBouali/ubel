'use strict';
// vmap.js — virtual address → file offset for ELF, PE and Mach-O (thin or fat). Only what is needed to follow a pointer that a
// compiler wrote into the file (Go's pre-1.18 build-info header holds two of them). Returns null when the headers cannot be read;
// an address outside every mapped range maps to -1.

function elfMap(buf) {
  const is64 = buf[4] === 2, le = buf[5] !== 2;
  const u16 = o => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o));
  const u32 = o => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
  const u64 = o => (le ? u32(o) + u32(o + 4) * 4294967296 : u32(o) * 4294967296 + u32(o + 4));
  const phoff = is64 ? u64(32) : u32(28), phentsize = u16(is64 ? 54 : 42), phnum = u16(is64 ? 56 : 44);
  const segs = [];
  for (let i = 0; i < phnum && i < 256; i++) {
    const o = phoff + i * phentsize;
    if (o + (is64 ? 56 : 32) > buf.length || u32(o) !== 1) continue;           // PT_LOAD
    segs.push(is64 ? { off: u64(o + 8), va: u64(o + 16), size: u64(o + 32) } : { off: u32(o + 4), va: u32(o + 8), size: u32(o + 16) });
  }
  return va => { for (const s of segs) if (va >= s.va && va < s.va + s.size) return s.off + (va - s.va); return -1; };
}

function peMap(buf) {
  const pe = buf.readUInt32LE(0x3c), nsec = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20), opt = pe + 24;
  const is64 = buf.readUInt16LE(opt) === 0x20b;
  const base = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
  const secs = [];
  for (let i = 0, o = opt + optSize; i < nsec && i < 96 && o + 40 <= buf.length; i++, o += 40) {
    secs.push({ va: buf.readUInt32LE(o + 12), vsize: buf.readUInt32LE(o + 8), raw: buf.readUInt32LE(o + 20), rawSize: buf.readUInt32LE(o + 16) });
  }
  return va => { const rva = va - base; for (const s of secs) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) return s.raw + (rva - s.va); return -1; };
}

function machoMap(buf, hint) {
  const slices = [];
  const be = buf.readUInt32BE(0);
  if (be === 0xcafebabe || be === 0xcafebabf) {
    const is64 = be === 0xcafebabf, n = buf.readUInt32BE(4), step = is64 ? 32 : 20;
    for (let i = 0; i < n && i < 16; i++) {
      const o = 8 + i * step;
      if (o + step > buf.length) break;
      slices.push({ base: is64 ? Number(buf.readBigUInt64BE(o + 8)) : buf.readUInt32BE(o + 8), size: is64 ? Number(buf.readBigUInt64BE(o + 16)) : buf.readUInt32BE(o + 12) });
    }
  } else slices.push({ base: 0, size: buf.length });
  const sl = slices.find(s => hint >= s.base && hint < s.base + s.size) || slices[0];
  if (!sl) return null;
  const magic = buf.readUInt32LE(sl.base);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) return null;
  const is64 = magic === 0xfeedfacf, ncmds = buf.readUInt32LE(sl.base + 16);
  const segs = [];
  let p = sl.base + (is64 ? 32 : 28);
  for (let i = 0; i < ncmds && p + 8 <= buf.length; i++) {
    const cmd = buf.readUInt32LE(p), csz = buf.readUInt32LE(p + 4);
    if (csz < 8) break;
    if (cmd === 0x19) segs.push({ va: Number(buf.readBigUInt64LE(p + 24)), vsize: Number(buf.readBigUInt64LE(p + 32)), off: Number(buf.readBigUInt64LE(p + 40)), fsize: Number(buf.readBigUInt64LE(p + 48)) });
    else if (cmd === 0x1) segs.push({ va: buf.readUInt32LE(p + 24), vsize: buf.readUInt32LE(p + 28), off: buf.readUInt32LE(p + 32), fsize: buf.readUInt32LE(p + 36) });
    p += csz;
  }
  return va => { for (const s of segs) if (va >= s.va && va < s.va + Math.min(s.vsize, s.fsize || s.vsize)) return sl.base + s.off + (va - s.va); return -1; };
}

/** @param {Buffer} buf @param {number} [hint] file offset the address belongs to (picks the slice of a fat Mach-O) @returns {((va:number)=>number)|null} */
export function makeVaMap(buf, hint = 0) {
  try {
    if (buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46) return elfMap(buf);
    if (buf[0] === 0x4d && buf[1] === 0x5a) return peMap(buf);
    return machoMap(buf, hint);
  } catch { return null; }
}

/** Offset just past the loader-mapped image (ELF segments and section table, PE sections, Mach-O segments); bytes beyond it are an appended payload. */
export function imageEnd(buf) {
  try {
    if (buf[0] === 0x7f && buf[1] === 0x45) {
      const is64 = buf[4] === 2, le = buf[5] !== 2;
      const u16 = o => (le ? buf.readUInt16LE(o) : buf.readUInt16BE(o)), u32 = o => (le ? buf.readUInt32LE(o) : buf.readUInt32BE(o));
      const u64 = o => (le ? u32(o) + u32(o + 4) * 4294967296 : u32(o) * 4294967296 + u32(o + 4));
      let end = 0;
      const phoff = is64 ? u64(32) : u32(28), phentsize = u16(is64 ? 54 : 42), phnum = u16(is64 ? 56 : 44);
      for (let i = 0; i < phnum && i < 256; i++) {
        const o = phoff + i * phentsize;
        if (o + (is64 ? 56 : 32) > buf.length || u32(o) !== 1) continue;
        end = Math.max(end, (is64 ? u64(o + 8) + u64(o + 32) : u32(o + 4) + u32(o + 16)));
      }
      const shoff = is64 ? u64(40) : u32(32), shentsize = u16(is64 ? 58 : 46), shnum = u16(is64 ? 60 : 48);
      if (shoff && shnum) {
        for (let i = 0; i < shnum && i < 4096; i++) {
          const o = shoff + i * shentsize;
          if (o + shentsize > buf.length) break;
          const type = u32(o + 4);
          if (type !== 8) end = Math.max(end, is64 ? u64(o + 24) + u64(o + 32) : u32(o + 16) + u32(o + 20));   // SHT_NOBITS occupies no file bytes
        }
        end = Math.max(end, shoff + shnum * shentsize);
      }
      return end;
    }
    if (buf[0] === 0x4d && buf[1] === 0x5a) {
      const pe = buf.readUInt32LE(0x3c), nsec = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20), opt = pe + 24;
      let end = buf.readUInt32LE(opt + 60);
      for (let i = 0, o = opt + optSize; i < nsec && i < 96 && o + 40 <= buf.length; i++, o += 40) end = Math.max(end, buf.readUInt32LE(o + 20) + buf.readUInt32LE(o + 16));
      return end;
    }
  } catch { /* unreadable headers: no appended payload is assumed */ }
  return 0;
}
