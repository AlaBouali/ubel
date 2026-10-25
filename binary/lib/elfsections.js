'use strict';
// elfsections.js — section names of a little-endian ELF (the section table is optional for the loader, so a missing or damaged
// table yields an empty list, never an exception). Used for: symbol table / debug info (stripped?), and named sections that carry
// build metadata (.dep-v0 of cargo-auditable).

const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;

/** @returns {{sections: Array<{name:string,type:number,off:number,size:number}>, hasSymtab:boolean, hasDebug:boolean}} */
export function elfSections(buf) {
  const out = { sections: [], hasSymtab: false, hasDebug: false };
  try {
    if (buf[5] !== 1) return out;
    const is64 = buf[4] === 2;
    const shoff = is64 ? U64(buf, 40) : buf.readUInt32LE(32);
    const shentsize = buf.readUInt16LE(is64 ? 58 : 46), shnum = buf.readUInt16LE(is64 ? 60 : 48), shstrndx = buf.readUInt16LE(is64 ? 62 : 50);
    const min = is64 ? 64 : 40;
    if (!shoff || !shnum || shentsize < min || shoff + shnum * shentsize > buf.length) return out;
    const hdr = i => {
      const o = shoff + i * shentsize;
      return { nameOff: buf.readUInt32LE(o), type: buf.readUInt32LE(o + 4), off: is64 ? U64(buf, o + 24) : buf.readUInt32LE(o + 16), size: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 20) };
    };
    const str = shstrndx < shnum ? hdr(shstrndx) : null;
    for (let i = 0; i < shnum && i < 4096; i++) {
      const h = hdr(i);
      let name = '';
      if (str && str.off + h.nameOff < buf.length) { const a = str.off + h.nameOff; const e = buf.indexOf(0, a); name = buf.latin1Slice(a, Math.min(e < 0 ? buf.length : e, a + 128)); }
      out.sections.push({ name, type: h.type, off: h.off, size: h.size });
      if (h.type === 2) out.hasSymtab = true;                    // SHT_SYMTAB
      if (name.startsWith('.debug_') || name === '.zdebug_info') out.hasDebug = true;
    }
  } catch { /* leave what was read */ }
  return out;
}
