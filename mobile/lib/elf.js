'use strict';
// elf.js — ELF reader for Android native libraries: hardening flags (NX, RELRO, PIE, canary, text relocations,
// RPATH) and imported symbols. Little-endian only (every Android ABI is).

const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;
const MACHINE = { 0x03: 'x86', 0x3e: 'x86_64', 0x28: 'arm', 0xb7: 'arm64' };

export function isElf(buf) { return buf.length > 64 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46; }

export function parseElf(buf) {
  if (!isElf(buf)) throw new Error('not an ELF file');
  const is64 = buf[4] === 2;
  if (buf[5] !== 1) throw new Error('big-endian ELF not supported');
  const w = (a, b) => (is64 ? a : b);
  const type = buf.readUInt16LE(16), machine = buf.readUInt16LE(18);
  const phoff = is64 ? U64(buf, 32) : buf.readUInt32LE(28), shoff = is64 ? U64(buf, 40) : buf.readUInt32LE(32);
  const phentsize = buf.readUInt16LE(w(54, 42)), phnum = buf.readUInt16LE(w(56, 44));
  const shentsize = buf.readUInt16LE(w(58, 46)), shnum = buf.readUInt16LE(w(60, 48));
  const r = {
    bits: is64 ? 64 : 32, arch: MACHINE[machine] || `machine_${machine}`, type, pie: type === 3,
    execStack: false, hasStackHeader: false, relro: 'none', canary: false, textrel: false,
    rpath: null, needed: [], imports: [],
  };
  let relroHdr = false, bindNow = false, dynamic = null;
  for (let i = 0; i < phnum && i < 256; i++) {
    const o = phoff + i * phentsize;
    if (o + phentsize > buf.length) break;
    const pt = buf.readUInt32LE(o);
    const flags = buf.readUInt32LE(w(o + 4, o + 24));
    if (pt === 0x6474e551) { r.hasStackHeader = true; r.execStack = (flags & 1) !== 0; }
    else if (pt === 0x6474e552) relroHdr = true;
    else if (pt === 2) dynamic = { off: is64 ? U64(buf, o + 8) : buf.readUInt32LE(o + 4), size: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 16) };
  }
  // section headers → .dynsym and its string table
  let dynsym = null, dynstr = null;
  for (let i = 0; i < shnum && i < 4096; i++) {
    const o = shoff + i * shentsize;
    if (o + shentsize > buf.length) break;
    if (buf.readUInt32LE(o + 4) === 11) {
      dynsym = { off: is64 ? U64(buf, o + 24) : buf.readUInt32LE(o + 16), size: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 20), link: buf.readUInt32LE(w(o + 40, o + 24)) };
      const so = shoff + dynsym.link * shentsize;
      if (so + shentsize <= buf.length) dynstr = { off: is64 ? U64(buf, so + 24) : buf.readUInt32LE(so + 16), size: is64 ? U64(buf, so + 32) : buf.readUInt32LE(so + 20) };
      break;
    }
  }
  const str = off => {
    if (!dynstr || off >= dynstr.size) return '';
    const a = dynstr.off + off; const e = buf.indexOf(0, a);
    return buf.latin1Slice(a, e < 0 ? buf.length : Math.min(e, a + 512));
  };
  if (dynamic && dynamic.off + 16 <= buf.length) {
    const esz = is64 ? 16 : 8;
    for (let o = dynamic.off; o + esz <= Math.min(dynamic.off + dynamic.size, buf.length); o += esz) {
      const tag = is64 ? U64(buf, o) : buf.readUInt32LE(o), val = is64 ? U64(buf, o + 8) : buf.readUInt32LE(o + 4);
      if (tag === 0) break;
      if (tag === 1) r.needed.push(str(val));
      else if (tag === 24) bindNow = true;
      else if (tag === 30 && (val & 0x8)) bindNow = true;
      else if (tag === 0x6ffffffb && (val & 0x1)) bindNow = true;
      else if (tag === 22) r.textrel = true;
      else if (tag === 15 || tag === 29) r.rpath = str(val);
    }
  }
  if (relroHdr) r.relro = bindNow ? 'full' : 'partial';
  if (dynsym && dynstr) {
    const esz = is64 ? 24 : 16, n = Math.min(Math.floor(dynsym.size / esz), 200000);
    for (let i = 1; i < n; i++) {
      const o = dynsym.off + i * esz;
      if (o + esz > buf.length) break;
      const shndx = buf.readUInt16LE(w(o + 6, o + 14));
      if (shndx !== 0) continue;
      const name = str(buf.readUInt32LE(o));
      if (name) r.imports.push(name);
    }
    r.canary = r.imports.some(s => s === '__stack_chk_fail' || s === '__stack_chk_guard');
  }
  return r;
}
