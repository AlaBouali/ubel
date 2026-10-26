'use strict';
// gosyms.js — the function names of a Go binary, read from its pclntab (the runtime's pc → function table).
//
// A Go linker keeps this table in every binary, also with `strip` and `-ldflags=-s -w` (the runtime needs it for stack traces), and it
// lists the functions that were linked: `os/exec.Command`, `net/http.(*Client).Do`, `golang.org/x/sys/unix.Ptrace`. Imports tell nothing
// about a Go binary (it is static), this table does.
//
// Layout by version (little-endian; the table starts with a 4-byte magic, two zero bytes, `minLC` and the pointer size):
//   go1.2   0xfffffffb  nfunc · functab {entry, funcoff}[ptr-sized] · _func {entry, nameoff:int32 …}; every offset is from the table start
//   go1.16  0xfffffffa  nfunc, nfiles, funcnameOff, cuOff, filetabOff, pctabOff, pclnOff · functab {entry, funcoff}[ptr-sized] at pclnOff
//   go1.18  0xfffffff0  nfunc, nfiles, textStart, funcnameOff, … · functab {entryoff:u32, funcoff:u32}[] at pclnOff · _func {entryoff, nameoff}
//   go1.20  0xfffffff1  same layout as 1.18
// Every offset is relative to the table, so no virtual-address mapping is needed to reach the names.

const MAGICS = [
  { magic: 0xfffffffb, v: '1.2' }, { magic: 0xfffffffa, v: '1.16' }, { magic: 0xfffffff0, v: '1.18' }, { magic: 0xfffffff1, v: '1.20' },
];
const MAX_FUNCS = 600000;
const MAX_NAME = 512;

function header(buf, at, v) {
  const ptr = buf[at + 7], minLC = buf[at + 6];
  if (buf[at + 4] !== 0 || buf[at + 5] !== 0 || ![1, 2, 4].includes(minLC) || (ptr !== 4 && ptr !== 8)) return null;
  const word = o => (at + o + ptr <= buf.length ? (ptr === 8 ? Number(buf.readBigUInt64LE(at + o)) : buf.readUInt32LE(at + o)) : null);
  const nfunc = word(8);
  if (nfunc === null || nfunc < 1 || nfunc > MAX_FUNCS) return null;
  if (v === '1.2') return { ptr, nfunc, tab: at + 8 + ptr, entry: 2 * ptr, nameBase: at, funcBase: at, nameAt: ptr };
  const off = k => word(8 + k * ptr);                                    // k = 0 nfunc, 1 nfiles, then (1.18+) textStart, funcnameOff, cuOff, filetabOff, pctabOff, pclnOff
  const base = v === '1.16' ? 2 : 3;
  const funcname = off(base), pcln = off(base + 4);
  if (funcname === null || pcln === null || at + funcname >= buf.length || at + pcln >= buf.length) return null;
  return v === '1.16'
    ? { ptr, nfunc, tab: at + pcln, entry: 2 * ptr, nameBase: at + funcname, funcBase: at + pcln, nameAt: ptr }
    : { ptr, nfunc, tab: at + pcln, entry: 8, nameBase: at + funcname, funcBase: at + pcln, nameAt: 4 };
}

function readNames(buf, h, v) {
  const out = [];
  const n = Math.min(h.nfunc, MAX_FUNCS);
  const u32 = v === '1.18' || v === '1.20';
  for (let i = 0; i < n; i++) {
    const e = h.tab + i * h.entry;
    if (e + h.entry > buf.length) break;
    // funcoff is the second word of a functab entry: ptr-sized before 1.18, u32 from 1.18
    const funcoff = u32 ? buf.readUInt32LE(e + 4) : (h.ptr === 8 ? Number(buf.readBigUInt64LE(e + h.ptr)) : buf.readUInt32LE(e + h.ptr));
    const f = h.funcBase + funcoff;
    if (f + h.nameAt + 4 > buf.length) continue;
    const nameoff = buf.readInt32LE(f + h.nameAt);
    const a = h.nameBase + nameoff;
    if (nameoff < 0 || a >= buf.length) continue;
    const lim = Math.min(buf.length, a + MAX_NAME);
    let z = a;
    while (z < lim && buf[z] !== 0) z++;
    if (z > a) out.push(buf.latin1Slice(a, z));
  }
  return out;
}

const PLAUSIBLE = /^[\x21-\x7e\u0080-\uffff]+$/;

/**
 * @param {Buffer} buf
 * @returns {{version:string, names:string[]}|null} null when the file carries no readable Go pclntab
 */
export function goFunctionNames(buf) {
  for (const { magic, v } of MAGICS) {
    const needle = Buffer.alloc(4); needle.writeUInt32LE(magic);
    for (let at = buf.indexOf(needle), tries = 0; at >= 0 && tries < 64; at = buf.indexOf(needle, at + 1), tries++) {
      try {
        const h = header(buf, at, v);
        if (!h) continue;
        const names = readNames(buf, h, v);
        // a real table names its first functions (runtime.*, type..*, internal/*); random bytes that look like a header do not
        if (names.length < Math.min(h.nfunc, 8) || !names.slice(0, 8).every(x => PLAUSIBLE.test(x)) || !names.some(x => x.startsWith('runtime.'))) continue;
        return { version: v, names };
      } catch { /* not a table: try the next candidate */ }
    }
  }
  return null;
}

/** `net/http.(*Client).Do.func1` → { pkg: 'net/http', fn: 'Client.Do' } (closures, generic instantiations and wrappers folded onto their function). */
export function splitGoName(name) {
  let n = String(name).replace(/\[\.\.\.\]|\[[^\]]*\]/g, '');
  const slash = n.lastIndexOf('/');
  const dot = n.indexOf('.', slash + 1);
  if (dot <= 0) return null;
  const pkg = n.slice(0, dot);
  let fn = n.slice(dot + 1).replace(/^\(\*?([^)]+)\)\./, '$1.');
  fn = fn.replace(/(?:\.(?:func|gowrap|deferwrap)\d+(?:\.\d+)*|\.\d+)+$/, '').replace(/-fm$/, '');
  if (!fn || /^init(?:\.\d+)?$/.test(fn)) return null;
  return { pkg: pkg.replace(/%2e/gi, '.'), fn };
}
