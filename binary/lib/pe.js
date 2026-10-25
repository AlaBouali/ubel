'use strict';
// pe.js — Windows PE/COFF reader: build-hardening flags (ASLR, high-entropy ASLR, DEP/NX, CFG, SafeSEH, /GS cookie, W+X sections,
// Authenticode presence), the import table and the section table. Nothing is executed or loaded.
// Authenticode: the presence of a signature is reported, the signature itself is NOT verified.

const MACHINE = { 0x14c: 'x86', 0x8664: 'x86_64', 0x1c0: 'arm', 0x1c4: 'arm', 0xaa64: 'arm64', 0x200: 'ia64' };
const DLL_HIGH_ENTROPY_VA = 0x20, DLL_DYNAMIC_BASE = 0x40, DLL_FORCE_INTEGRITY = 0x80, DLL_NX_COMPAT = 0x100, DLL_NO_SEH = 0x400, DLL_GUARD_CF = 0x4000;
const FILE_RELOCS_STRIPPED = 0x1, FILE_DLL = 0x2000;
const SCN_EXEC = 0x20000000, SCN_WRITE = 0x80000000;
const MAX_IMPORTS = 20000;

export function isPe(buf) {
  if (buf.length < 0x40 || buf[0] !== 0x4d || buf[1] !== 0x5a) return false;
  const off = buf.readUInt32LE(0x3c);
  return off >= 0x40 && off + 24 <= buf.length && buf.readUInt32LE(off) === 0x00004550;
}

export function parsePe(buf) {
  if (!isPe(buf)) throw new Error('not a PE file');
  const pe = buf.readUInt32LE(0x3c);
  const machine = buf.readUInt16LE(pe + 4), nsec = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20), chars = buf.readUInt16LE(pe + 22);
  const opt = pe + 24;
  if (optSize < 96 || opt + optSize > buf.length) throw new Error('truncated optional header');
  const magic = buf.readUInt16LE(opt);
  if (magic !== 0x10b && magic !== 0x20b) throw new Error(`unknown optional header magic 0x${magic.toString(16)}`);
  const is64 = magic === 0x20b;
  const dll = buf.readUInt16LE(opt + 70);
  const sizeOfHeaders = buf.readUInt32LE(opt + 60);
  const ndir = Math.min(buf.readUInt32LE(opt + (is64 ? 108 : 92)), 16);
  const dirBase = opt + (is64 ? 112 : 96);
  const dir = i => (i < ndir && dirBase + i * 8 + 8 <= opt + optSize ? { rva: buf.readUInt32LE(dirBase + i * 8), size: buf.readUInt32LE(dirBase + i * 8 + 4) } : { rva: 0, size: 0 });

  const sections = [];
  for (let i = 0, o = opt + optSize; i < nsec && i < 96 && o + 40 <= buf.length; i++, o += 40) {
    sections.push({
      name: buf.toString('latin1', o, o + 8).replace(/\0.*$/, ''),
      vsize: buf.readUInt32LE(o + 8), va: buf.readUInt32LE(o + 12), rawSize: buf.readUInt32LE(o + 16), rawPtr: buf.readUInt32LE(o + 20), chars: buf.readUInt32LE(o + 36),
    });
  }
  const rvaToOff = rva => {
    if (rva < sizeOfHeaders && rva < buf.length) return rva;
    for (const s of sections) if (rva >= s.va && rva < s.va + Math.max(s.vsize, s.rawSize)) { const o = s.rawPtr + (rva - s.va); return o < buf.length ? o : -1; }
    return -1;
  };
  const cstr = off => { if (off < 0 || off >= buf.length) return ''; const e = buf.indexOf(0, off); return buf.latin1Slice(off, Math.min(e < 0 ? buf.length : e, off + 512)); };

  const r = {
    bits: is64 ? 64 : 32, arch: MACHINE[machine] || `machine_0x${machine.toString(16)}`, machine,
    kind: (chars & FILE_DLL) ? 'shared' : 'executable', subsystem: buf.readUInt16LE(opt + 68),
    aslr: (dll & DLL_DYNAMIC_BASE) !== 0, highEntropyVa: (dll & DLL_HIGH_ENTROPY_VA) !== 0, nx: (dll & DLL_NX_COMPAT) !== 0,
    cfg: (dll & DLL_GUARD_CF) !== 0, noSeh: (dll & DLL_NO_SEH) !== 0, forceIntegrity: (dll & DLL_FORCE_INTEGRITY) !== 0,
    relocsStripped: (chars & FILE_RELOCS_STRIPPED) !== 0,
    hasRelocDir: dir(5).size > 0,
    managed: dir(14).rva !== 0 && dir(14).size > 0,
    signed: false, signatureBytes: 0,
    loadConfig: false, securityCookie: null, safeSeh: null,
    wxSections: sections.filter(s => (s.chars & SCN_EXEC) && (s.chars & SCN_WRITE)).map(s => s.name),
    sections: sections.map(s => ({ name: s.name, size: s.rawSize, off: s.rawPtr, vsize: s.vsize, chars: s.chars })),
    needed: [], imports: [], importProviders: new Map(), ordinalImports: 0, importsReadable: false,
  };

  // Authenticode: the security directory holds a FILE OFFSET (not an RVA).
  const sec = dir(4);
  if (sec.rva > 0 && sec.size >= 8 && sec.rva + sec.size <= buf.length + 8) { r.signed = true; r.signatureBytes = sec.size; }

  // load configuration: /GS cookie, SafeSEH table
  const lc = dir(10), lo = lc.rva ? rvaToOff(lc.rva) : -1;
  if (lo >= 0 && lo + 4 <= buf.length) {
    const size = buf.readUInt32LE(lo);
    const cookieAt = is64 ? 88 : 60, sehAt = is64 ? 96 : 64, sehCountAt = is64 ? 104 : 68, w = is64 ? 8 : 4;
    const rd = at => (lo + at + w <= buf.length ? (is64 ? Number(buf.readBigUInt64LE(lo + at)) : buf.readUInt32LE(lo + at)) : null);
    r.loadConfig = true;
    if (size >= cookieAt + w) r.securityCookie = rd(cookieAt) !== 0;
    if (!is64 && size >= sehCountAt + 4) r.safeSeh = rd(sehAt) !== 0 && (rd(sehCountAt) || 0) > 0;
  }

  // imports (by name; ordinals are skipped)
  const imp = dir(1), io = imp.rva ? rvaToOff(imp.rva) : -1;
  if (io >= 0) {
    try {
      const names = new Set(), dlls = new Set(), providers = new Map();
      let ordinals = 0;
      for (let o = io, n = 0; o + 20 <= buf.length && n < 2048; o += 20, n++) {
        const oft = buf.readUInt32LE(o), nameRva = buf.readUInt32LE(o + 12), ft = buf.readUInt32LE(o + 16);
        if (!oft && !nameRva && !ft) break;
        const d = cstr(rvaToOff(nameRva)), dll = d ? d.toLowerCase() : null; if (dll) dlls.add(dll);
        let t = rvaToOff(oft || ft); if (t < 0) continue;
        const w = is64 ? 8 : 4;
        for (let k = 0; k < MAX_IMPORTS && t + w <= buf.length; k++, t += w) {
          const v = is64 ? buf.readBigUInt64LE(t) : BigInt(buf.readUInt32LE(t));
          if (v === 0n) break;
          if (v >> BigInt(is64 ? 63 : 31)) { ordinals++; continue; }         // import by ordinal: no name to look at
          const nm = cstr(rvaToOff(Number(v & 0x7fffffffn)) + 2);
          if (nm) { names.add(nm); if (dll && !providers.has(nm)) providers.set(nm, dll); }
        }
      }
      r.needed = [...dlls]; r.imports = [...names]; r.importProviders = providers; r.ordinalImports = ordinals; r.importsReadable = true;
    } catch { r.importsReadable = false; }
  }
  return r;
}
