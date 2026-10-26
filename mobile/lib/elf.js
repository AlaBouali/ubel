'use strict';
// elf.js — ELF reader for Android native libraries: build-hardening properties (PIE, NX, RELRO, stack canary,
// FORTIFY_SOURCE indicators, text relocations, W^X segments, RPATH) and imported symbols. Little-endian only
// (every Android ABI is). Nothing is executed or loaded.
//
// Symbols and strings are located the way the dynamic loader finds them — through the PT_DYNAMIC tags
// (DT_SYMTAB / DT_STRTAB / DT_HASH / DT_GNU_HASH) — and only fall back to the section headers when the dynamic
// segment does not give a usable table. Section headers are optional for the loader, so a library whose section
// table was stripped or zeroed (common for packed or obfuscated builds) must not silently look "unhardened"
// or "clean": the result says which source was used (`symbols`) and whether the table could be read at all
// (`symbolsReadable`).

const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;
const MACHINE = { 0x03: 'x86', 0x3e: 'x86_64', 0x28: 'arm', 0xb7: 'arm64', 0xf3: 'riscv64' };
const KIND = { 1: 'relocatable', 2: 'executable', 3: 'shared', 4: 'core' };

// program header types
const PT_LOAD = 1, PT_DYNAMIC = 2, PT_INTERP = 3, PT_GNU_STACK = 0x6474e551, PT_GNU_RELRO = 0x6474e552;
// dynamic tags
const DT_NEEDED = 1, DT_HASH = 4, DT_STRTAB = 5, DT_SYMTAB = 6, DT_STRSZ = 10, DT_TEXTREL = 22, DT_BIND_NOW = 24, DT_RPATH = 15,
  DT_RUNPATH = 29, DT_FLAGS = 30, DT_GNU_HASH = 0x6ffffef5, DT_FLAGS_1 = 0x6ffffffb;
const DT_VERSYM = 0x6ffffff0, DT_VERNEED = 0x6ffffffe, DT_VERNEEDNUM = 0x6fffffff;
const DF_TEXTREL = 0x4, DF_BIND_NOW = 0x8, DF_1_NOW = 0x1, DF_1_PIE = 0x08000000;
// tags whose value is the address of a table: PLTGOT, HASH, STRTAB, SYMTAB, RELA, INIT, FINI, REL, JMPREL, INIT_ARRAY, FINI_ARRAY, GNU_HASH, VERSYM, VERDEF, VERNEED
const POINTER_TAGS = new Set([3, 4, 5, 6, 7, 12, 13, 17, 23, 25, 26, 0x6ffffef5, 0x6ffffff0, 0x6ffffffc, 0x6ffffffe]);

const MAX_SYMBOLS = 200000;
const MAX_NAME = 512;

export function isElf(buf) { return buf.length > 64 && buf[0] === 0x7f && buf[1] === 0x45 && buf[2] === 0x4c && buf[3] === 0x46; }

// ── FORTIFY_SOURCE indicators ───────────────────────────────────────────────────────────────────────
// With _FORTIFY_SOURCE the compiler redirects bounds-checkable libc calls to checked variants (`memcpy` → `__memcpy_chk`).
// bionic and glibc both export them, so an import of one is direct evidence that part of the code was built fortified.
// It is an indicator, not a proof of absence: the compiler only emits a `_chk` call where it can prove the destination size,
// so a fortified build still imports plain `memcpy` for the rest.
const FORTIFIED = /^(?:__(?!stack_chk)[A-Za-z0-9_]+_chk|__open(?:at)?(?:64)?_2)$/;
export const FORTIFIABLE = new Set([
  'memcpy', 'memmove', 'mempcpy', 'memset', 'stpcpy', 'stpncpy', 'strcpy', 'strncpy', 'strcat', 'strncat', 'strlcpy', 'strlcat',
  'sprintf', 'vsprintf', 'snprintf', 'vsnprintf', 'fgets', 'fread', 'read', 'pread', 'pread64', 'readlink', 'readlinkat', 'getcwd', 'recv', 'recvfrom',
]);

/**
 * @param {Iterable<string>} imports  imported (undefined) dynamic symbol names
 * @returns {{state:'yes'|'partial'|'no'|'n/a', fortified:string[], unfortified:string[]}}
 *   yes      only checked variants are imported
 *   partial  both checked and plain variants are imported (normal for a fortified build)
 *   no       fortifiable functions are imported and no checked variant is
 *   n/a      the library imports no fortifiable function at all
 */
export function fortifyInfo(imports) {
  const fortified = [], unfortified = [];
  for (const s of new Set(imports)) {
    if (FORTIFIED.test(s)) fortified.push(s);
    else if (FORTIFIABLE.has(s)) unfortified.push(s);
  }
  fortified.sort(); unfortified.sort();
  const state = fortified.length ? (unfortified.length ? 'partial' : 'yes') : (unfortified.length ? 'no' : 'n/a');
  return { state, fortified, unfortified };
}

/** True when the library carries the stack-protector runtime hooks (`__stack_chk_fail`, or the guard variable on older ARM/x86 toolchains). */
export function hasCanaryImport(imports) {
  for (const s of imports) if (s === '__stack_chk_fail' || s === '__stack_chk_guard' || s === '__stack_chk_fail_local') return true;
  return false;
}

export function parseElf(buf) {
  if (!isElf(buf)) throw new Error('not an ELF file');
  if (buf[4] !== 1 && buf[4] !== 2) throw new Error('unknown ELF class');
  const is64 = buf[4] === 2;
  if (buf[5] !== 1) throw new Error('big-endian ELF not supported');
  const w = (a, b) => (is64 ? a : b);
  const type = buf.readUInt16LE(16), machine = buf.readUInt16LE(18);
  const phoff = is64 ? U64(buf, 32) : buf.readUInt32LE(28), shoff = is64 ? U64(buf, 40) : buf.readUInt32LE(32);
  const phentsize = buf.readUInt16LE(w(54, 42)), phnum = buf.readUInt16LE(w(56, 44));
  const shentsize = buf.readUInt16LE(w(58, 46)), shnum = buf.readUInt16LE(w(60, 48));
  const r = {
    bits: is64 ? 64 : 32, arch: MACHINE[machine] || `machine_${machine}`, machine, type, kind: KIND[type] || `type_${type}`,
    pie: type === 3,                          // position independent image (ET_DYN); text relocations are reported separately
    interp: false, pieFlag: false, execStack: false, hasStackHeader: false, nx: 'missing', wxSegments: 0,
    relro: 'none', canary: false, textrel: false,
    rpath: null, needed: [], imports: [], importProviders: new Map(),
    symbols: 'none', symbolsReadable: false,
    fortify: { state: 'n/a', fortified: [], unfortified: [] },
  };

  // ── program headers ──
  const minPh = is64 ? 56 : 32;
  const loads = [];
  let relroHdr = false, dynamic = null;
  if (phentsize >= minPh) {
    for (let i = 0; i < phnum && i < 256; i++) {
      const o = phoff + i * phentsize;
      if (o + minPh > buf.length) break;
      const pt = buf.readUInt32LE(o);
      const flags = buf.readUInt32LE(w(o + 4, o + 24));
      if (pt === PT_GNU_STACK) { r.hasStackHeader = true; r.execStack = (flags & 1) !== 0; }
      else if (pt === PT_GNU_RELRO) relroHdr = true;
      else if (pt === PT_INTERP) r.interp = true;
      else if (pt === PT_DYNAMIC) dynamic = { off: is64 ? U64(buf, o + 8) : buf.readUInt32LE(o + 4), size: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 16) };
      else if (pt === PT_LOAD) {
        loads.push({ off: is64 ? U64(buf, o + 8) : buf.readUInt32LE(o + 4), vaddr: is64 ? U64(buf, o + 16) : buf.readUInt32LE(o + 8), filesz: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 16) });
        if ((flags & 1) && (flags & 2)) r.wxSegments++;
      }
    }
  }
  r.nx = !r.hasStackHeader ? 'missing' : r.execStack ? 'disabled' : 'enabled';
  const vaToOff = va => {
    for (const s of loads) if (va >= s.vaddr && va < s.vaddr + s.filesz) return s.off + (va - s.vaddr);
    return -1;
  };

  // ── dynamic section ──
  const dyn = [];
  if (dynamic && dynamic.off + 8 <= buf.length) {
    const esz = is64 ? 16 : 8;
    const end = Math.min(dynamic.off + dynamic.size, buf.length);
    for (let o = dynamic.off; o + esz <= end && dyn.length < 4096; o += esz) {
      const tag = is64 ? U64(buf, o) : buf.readUInt32LE(o), val = is64 ? U64(buf, o + 8) : buf.readUInt32LE(o + 4);
      if (tag === 0) break;
      dyn.push([tag, val]);
    }
  }
  let hasSoname = false, bindNow = false, flags = 0, flags1 = 0, symtabVa = null, strtabVa = null, strsz = 0, hashVa = null, gnuHashVa = null, versymVa = null, vernVa = null, vernNum = 0;
  const tableVas = [];                                   // addresses of the other tables the loader is told about
  for (const [tag, val] of dyn) {
    if (POINTER_TAGS.has(tag) && val > 0) tableVas.push(val);
    switch (tag) {
      case 14: hasSoname = true; break;                // DT_SONAME: only shared objects have one
      case DT_BIND_NOW: bindNow = true; break;
      case DT_TEXTREL: r.textrel = true; break;
      case DT_FLAGS: flags = val; break;
      case DT_FLAGS_1: flags1 = val; break;
      case DT_SYMTAB: symtabVa = val; break;
      case DT_STRTAB: strtabVa = val; break;
      case DT_STRSZ: strsz = val; break;
      case DT_HASH: hashVa = val; break;
      case DT_GNU_HASH: gnuHashVa = val; break;
      case DT_VERSYM: versymVa = val; break;
      case DT_VERNEED: vernVa = val; break;
      case DT_VERNEEDNUM: vernNum = val; break;
      default: break;
    }
  }
  if (flags & DF_BIND_NOW) bindNow = true;
  if (flags1 & DF_1_NOW) bindNow = true;
  if (flags & DF_TEXTREL) r.textrel = true;        // lld/modern ld emit the flag form rather than DT_TEXTREL
  r.pieFlag = (flags1 & DF_1_PIE) !== 0;           // DF_1_PIE: an ET_DYN that is meant to be run (a PIE executable), not dlopen'ed
  if (relroHdr) r.relro = bindNow ? 'full' : 'partial';
  // ET_DYN is either a PIE executable or a shared object. DF_1_PIE marks the former on modern linkers; older linkers set only PT_INTERP.
  // glibc's libc.so.6 also has a PT_INTERP (it can be run), but it carries a DT_SONAME, which no executable has.
  if (type === 3) r.kind = (r.pieFlag || (r.interp && !hasSoname)) ? 'executable' : 'shared';

  // ── section headers (fallback only) ──
  let secSym = null, secStr = null;
  const minSh = is64 ? 64 : 40;
  if (shoff > 0 && shnum > 0 && shentsize >= minSh) {
    for (let i = 0; i < shnum && i < 4096; i++) {
      const o = shoff + i * shentsize;
      if (o + shentsize > buf.length) break;
      if (buf.readUInt32LE(o + 4) !== 11) continue;      // SHT_DYNSYM
      secSym = { off: is64 ? U64(buf, o + 24) : buf.readUInt32LE(o + 16), size: is64 ? U64(buf, o + 32) : buf.readUInt32LE(o + 20), link: buf.readUInt32LE(w(o + 40, o + 24)) };
      const so = shoff + secSym.link * shentsize;
      if (secSym.link > 0 && so + shentsize <= buf.length) secStr = { off: is64 ? U64(buf, so + 24) : buf.readUInt32LE(so + 16), size: is64 ? U64(buf, so + 32) : buf.readUInt32LE(so + 20) };
      break;
    }
  }

  // ── locate the dynamic symbol and string tables ──
  const esz = is64 ? 24 : 16;
  let sym = null, str = null;
  try {
    if (symtabVa !== null && strtabVa !== null) {
      const so = vaToOff(symtabVa), to = vaToOff(strtabVa);
      if (so >= 0 && to >= 0 && so < buf.length && to < buf.length) {
        let count = null;
        if (hashVa !== null) { const h = vaToOff(hashVa); if (h >= 0 && h + 8 <= buf.length) count = buf.readUInt32LE(h + 4); }               // nchain = number of symbols
        if (!count && gnuHashVa !== null) count = gnuSymbolCount(buf, vaToOff(gnuHashVa), is64);
        if (!count && secSym && secSym.off === so) count = Math.floor(secSym.size / esz);
        if (!count) {                                                                                                                       // the table ends where the next one begins
          const next = Math.min(...tableVas.filter(a => a > symtabVa), Infinity);
          if (next !== Infinity) count = Math.floor((next - symtabVa) / esz);
        }
        if (count) { sym = { off: so, count }; str = { off: to, size: strsz || buf.length - to }; r.symbols = 'dynamic'; }
      }
    }
  } catch { sym = null; str = null; }
  if (!sym && secSym && secStr && secSym.off < buf.length && secStr.off < buf.length) {
    sym = { off: secSym.off, count: Math.floor(secSym.size / esz) }; str = secStr; r.symbols = 'sections';
  }

  const readStr = off => {
    if (!str || off < 0 || off >= str.size) return '';
    const a = str.off + off;
    if (a >= buf.length) return '';
    const lim = Math.min(buf.length, a + MAX_NAME);
    let e = a;
    while (e < lim && buf[e] !== 0) e++;
    return buf.latin1Slice(a, e);
  };

  for (const [tag, val] of dyn) {
    if (tag === DT_NEEDED) { const s = readStr(val); if (s) r.needed.push(s); }
    else if (tag === DT_RPATH || tag === DT_RUNPATH) r.rpath = readStr(val) || r.rpath;
  }

  // Symbol versioning tells which library an import comes from: .gnu.version (DT_VERSYM) gives each dynamic symbol a version index, and
  // .gnu.version_r (DT_VERNEED) maps that index to the DT_NEEDED file that defines the version (`libc.so.6` for GLIBC_2.2.5). Only versioned
  // symbols get a provider: musl and bionic libraries do not version their symbols, and an unversioned import has no recorded origin.
  const verFile = new Map();
  let versymOff = -1;
  try {
    const vo = versymVa !== null && vernVa !== null && vernNum > 0 ? vaToOff(vernVa) : -1;
    versymOff = versymVa !== null ? vaToOff(versymVa) : -1;
    if (vo >= 0 && versymOff >= 0) {
      for (let k = 0, at = vo; k < Math.min(vernNum, 256) && at + 16 <= buf.length; k++) {
        const cnt = buf.readUInt16LE(at + 2), file = readStr(buf.readUInt32LE(at + 4)), aux = buf.readUInt32LE(at + 8), next = buf.readUInt32LE(at + 12);
        for (let j = 0, ax = at + aux; j < Math.min(cnt, 512) && ax + 16 <= buf.length; j++) {
          verFile.set(buf.readUInt16LE(ax + 6) & 0x7fff, file);           // vna_other: the version index that .gnu.version uses
          const an = buf.readUInt32LE(ax + 12);
          if (!an) break;
          ax += an;
        }
        if (!next) break;
        at += next;
      }
    }
  } catch { verFile.clear(); }

  if (sym && str) {
    try {
      const n = Math.min(sym.count, MAX_SYMBOLS);
      for (let i = 1; i < n; i++) {
        const o = sym.off + i * esz;
        if (o + esz > buf.length) break;
        const shndx = buf.readUInt16LE(w(o + 6, o + 14));
        if (shndx !== 0) continue;                                   // defined here: not an import
        const name = readStr(buf.readUInt32LE(o));
        if (!name) continue;
        r.imports.push(name);
        if (verFile.size && versymOff >= 0 && versymOff + i * 2 + 2 <= buf.length) {
          const file = verFile.get(buf.readUInt16LE(versymOff + i * 2) & 0x7fff);
          if (file && !r.importProviders.has(name)) r.importProviders.set(name, file);
        }
      }
      r.symbolsReadable = true;
    } catch { r.symbolsReadable = false; }
  }
  if (r.symbolsReadable) {
    r.canary = hasCanaryImport(r.imports);
    r.fortify = fortifyInfo(r.imports);
  }
  return r;
}

/** Number of dynamic symbols according to a DT_GNU_HASH table (highest hashed symbol + 1), or null when the table hashes nothing. */
function gnuSymbolCount(buf, off, is64) {
  if (off < 0 || off + 16 > buf.length) return null;
  const nbuckets = buf.readUInt32LE(off), symoffset = buf.readUInt32LE(off + 4), bloomSize = buf.readUInt32LE(off + 8);
  if (nbuckets > 1 << 22 || bloomSize > 1 << 22) return null;
  const buckets = off + 16 + bloomSize * (is64 ? 8 : 4), chains = buckets + nbuckets * 4;
  if (chains > buf.length) return null;
  let max = 0;
  for (let i = 0; i < nbuckets; i++) max = Math.max(max, buf.readUInt32LE(buckets + i * 4));
  // Nothing is hashed (an executable that exports nothing): GNU ld writes symoffset = 1 here although undefined symbols follow, so
  // the table says nothing about how many symbols there are. The caller bounds .dynsym by the next table instead.
  if (max < symoffset) return null;
  for (let idx = max, steps = 0; steps < MAX_SYMBOLS * 2; idx++, steps++) {
    const p = chains + (idx - symoffset) * 4;
    if (p + 4 > buf.length) return null;
    if (buf.readUInt32LE(p) & 1) return idx + 1;                      // low bit marks the end of a hash chain
  }
  return null;
}
