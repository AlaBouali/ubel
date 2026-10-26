'use strict';
// macho.js — Mach-O reader (thin and fat): header flags, load commands, imported symbols, string sections,
// FairPlay encryption state and the code-signature entitlements. No external tools.

import { parsePlist } from './plist.js';

const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;
const CPU = { 7: 'x86', 0x01000007: 'x86_64', 12: 'arm', 0x0100000c: 'arm64', 0x0200000c: 'arm64_32' };
const ver = v => `${v >>> 16}.${(v >>> 8) & 0xff}.${v & 0xff}`;

export function isMachO(buf) {
  if (buf.length < 8) return false;
  const m = buf.readUInt32LE(0);
  if (m === 0xfeedface || m === 0xfeedfacf) return true;
  if (buf.readUInt32BE(0) === 0xcafebabe || buf.readUInt32BE(0) === 0xcafebabf) {
    const n = buf.readUInt32BE(4); return n > 0 && n < 20;
  }
  return false;
}

export function parseMachO(buf) {
  const slices = [];
  const be = buf.readUInt32BE(0);
  if (be === 0xcafebabe || be === 0xcafebabf) {
    const is64 = be === 0xcafebabf, n = buf.readUInt32BE(4), step = is64 ? 32 : 20;
    for (let i = 0; i < n && i < 16; i++) {
      const o = 8 + i * step;
      if (o + step > buf.length) break;
      const off = is64 ? Number(buf.readBigUInt64BE(o + 8)) : buf.readUInt32BE(o + 8);
      const size = is64 ? Number(buf.readBigUInt64BE(o + 16)) : buf.readUInt32BE(o + 12);
      try { const s = parseSlice(buf, off, size); if (s) slices.push(s); } catch { /* skip unreadable slice */ }
    }
  } else {
    const s = parseSlice(buf, 0, buf.length);
    if (s) slices.push(s);
  }
  if (!slices.length) throw new Error('no readable Mach-O slice');
  const preferred = slices.find(s => s.arch === 'arm64') || slices[slices.length - 1];
  return { slices, preferred };
}

function parseSlice(buf, base, size) {
  const magic = buf.readUInt32LE(base);
  if (magic !== 0xfeedfacf && magic !== 0xfeedface) return null;
  const is64 = magic === 0xfeedfacf;
  const cputype = buf.readUInt32LE(base + 4);
  const filetype = buf.readUInt32LE(base + 12);
  const ncmds = buf.readUInt32LE(base + 16);
  const flags = buf.readUInt32LE(base + 24);
  const s = {
    arch: CPU[cputype] || `cpu_${cputype.toString(16)}`, is64, filetype, flags, base, size,
    pie: (flags & 0x200000) !== 0, allowStackExec: (flags & 0x20000) !== 0,
    encrypted: false, cryptid: 0, signed: false, adhoc: false, cdFlags: null, entitlements: null,
    minOS: null, sdk: null, platform: null, dylibs: [], rpaths: [], imports: new Set(), importProviders: new Map(), exports: new Set(),
    sections: [], strings: [],
  };
  let p = base + (is64 ? 32 : 28);
  let symtab = null, sig = null;
  for (let i = 0; i < ncmds && p + 8 <= base + size; i++) {
    const cmd = buf.readUInt32LE(p), csz = buf.readUInt32LE(p + 4);
    if (csz < 8 || p + csz > buf.length) break;
    switch (cmd) {
      case 0x19: case 0x1: {                                     // LC_SEGMENT_64 / LC_SEGMENT
        const nsects = buf.readUInt32LE(p + (cmd === 0x19 ? 64 : 48));
        let sp = p + (cmd === 0x19 ? 72 : 56);
        const ssz = cmd === 0x19 ? 80 : 68;
        for (let k = 0; k < nsects && sp + ssz <= p + csz; k++, sp += ssz) {
          const name = buf.toString('latin1', sp, sp + 16).replace(/\0.*$/, '');
          const seg = buf.toString('latin1', sp + 16, sp + 32).replace(/\0.*$/, '');
          const ssize = cmd === 0x19 ? U64(buf, sp + 40) : buf.readUInt32LE(sp + 36);
          const off = cmd === 0x19 ? buf.readUInt32LE(sp + 48) : buf.readUInt32LE(sp + 40);
          s.sections.push({ seg, name, off: base + off, size: ssize });
        }
        break;
      }
      case 0x2: symtab = { symoff: buf.readUInt32LE(p + 8), nsyms: buf.readUInt32LE(p + 12), stroff: buf.readUInt32LE(p + 16), strsize: buf.readUInt32LE(p + 20) }; break;
      case 0xc: case 0x20: case 0x80000018: case 0x8000001f: case 0x80000023: {      // LOAD_DYLIB, LAZY_LOAD, LOAD_WEAK, REEXPORT, LOAD_UPWARD: the order is what library ordinals count
        const o = buf.readUInt32LE(p + 8);
        s.dylibs.push(buf.toString('utf8', p + o, p + csz).replace(/\0.*$/, ''));
        break;
      }
      case 0x8000001c: { const o = buf.readUInt32LE(p + 8); s.rpaths.push(buf.toString('utf8', p + o, p + csz).replace(/\0.*$/, '')); break; }
      case 0x21: case 0x2c: s.cryptid = buf.readUInt32LE(p + 16); s.encrypted = s.cryptid !== 0; break;
      case 0x1d: sig = { off: buf.readUInt32LE(p + 8), size: buf.readUInt32LE(p + 12) }; break;
      case 0x32: s.platform = buf.readUInt32LE(p + 8); s.minOS = ver(buf.readUInt32LE(p + 12)); s.sdk = ver(buf.readUInt32LE(p + 16)); break;
      case 0x25: case 0x24: case 0x2f: case 0x30:                                                  // LC_VERSION_MIN_*: the command id names the platform
        if (s.platform === null) s.platform = ({ 0x24: 1, 0x25: 2, 0x2f: 3, 0x30: 4 })[cmd];
        s.minOS = s.minOS || ver(buf.readUInt32LE(p + 8)); break;
      default: break;
    }
    p += csz;
  }
  if (symtab && symtab.nsyms < 3_000_000) readSymbols(buf, base, s, symtab, is64, size);
  if (sig) readSignature(buf, base, s, sig, size);
  return s;
}

function readSymbols(buf, base, s, st, is64, size) {
  const esz = is64 ? 16 : 12;
  const strBase = base + st.stroff, strEnd = Math.min(strBase + st.strsize, buf.length);
  for (let i = 0; i < st.nsyms; i++) {
    const o = base + st.symoff + i * esz;
    if (o + esz > buf.length) break;
    const strx = buf.readUInt32LE(o), type = buf[o + 4];
    if (type & 0xe0) continue;                                    // debugging (stab) entry
    const ext = type & 1, kind = type & 0x0e;
    if (!ext || strx === 0) continue;
    const at = strBase + strx;
    if (at >= strEnd) continue;
    let e = buf.indexOf(0, at); if (e < 0 || e > strEnd) e = strEnd;
    const name = buf.latin1Slice(at, e);
    if (kind === 0) {
      s.imports.add(name);
      // Two-level namespace: the high byte of n_desc is the 1-based ordinal of the dylib that provides the symbol (0 = this image, 0xfe =
      // flat lookup, 0xff = the main executable). Ordinals count the dylib load commands in order.
      if (s.flags & 0x80) {
        const ord = (buf.readUInt16LE(o + 6) >> 8) & 0xff, lib = ord >= 1 && ord <= s.dylibs.length ? s.dylibs[ord - 1] : null;
        if (lib && !s.importProviders.has(name)) s.importProviders.set(name, lib.replace(/^.*\//, ''));
      }
    } else if (kind === 0x0e) s.exports.add(name);
  }
}

function readSignature(buf, base, s, sig, size) {
  const at = base + sig.off;
  if (at + 12 > buf.length || buf.readUInt32BE(at) !== 0xfade0cc0) return;
  s.signed = true;
  const count = Math.min(buf.readUInt32BE(at + 8), 64);
  for (let i = 0; i < count; i++) {
    const idxAt = at + 12 + i * 8;
    if (idxAt + 8 > buf.length) break;
    const off = at + buf.readUInt32BE(idxAt + 4);
    if (off + 8 > buf.length) continue;
    const magic = buf.readUInt32BE(off), len = buf.readUInt32BE(off + 4);
    if (magic === 0xfade0c02 && off + 16 <= buf.length) { s.cdFlags = buf.readUInt32BE(off + 12); s.adhoc = (s.cdFlags & 0x2) !== 0; }
    else if (magic === 0xfade7171 && len > 8 && off + len <= buf.length) {
      try { s.entitlements = parsePlist(buf.subarray(off + 8, off + len)); } catch { /* unparseable entitlements */ }
    }
  }
}

/**
 * Buffers to extract printable strings from: the string-bearing sections of a slice. When the slice has none of them (a Go build keeps its
 * text in `__rodata`, other toolchains use their own section names, a stripped section table has none at all) the whole slice is returned
 * as one part named `__slice`, so a binary is never reported as having no strings just because its layout is unusual.
 */
export function sectionBuffers(buf, slice) {
  const CAP = 64 * 1024 * 1024;
  const want = new Set(['__cstring', '__ustring', '__objc_methname', '__objc_classname', '__swift5_reflstr', '__const', '__oslogstring']);
  const parts = [];
  for (const sec of slice.sections) {
    if (want.has(sec.name) && sec.size > 0 && sec.off + sec.size <= buf.length) parts.push({ name: sec.name, data: buf.subarray(sec.off, sec.off + Math.min(sec.size, CAP)) });
  }
  if (!parts.length) {
    const start = Math.min(slice.base || 0, buf.length), end = Math.min(start + (slice.size || buf.length), buf.length);
    if (end > start) parts.push({ name: '__slice', data: buf.subarray(start, Math.min(end, start + CAP)) });
  }
  return parts;
}
