'use strict';
// callsites.js — call-site counts for imported functions of an ELF or PE file (x86-64 and arm64 only).
//
// An import table says a function is linked. Counting the places that call it needs two steps, both done here without a disassembler:
//   1. resolve how code reaches an import: ELF PLT stubs (`jmp [GOT]` / `adrp+ldr+br`) and GOT slots, PE import-address-table (IAT) slots;
//   2. scan the executable sections for the instructions that call or jump to those stubs and slots.
//
// What this is and is not:
//   - arm64 instructions are fixed width, so `bl` / `b` / `blr` are found exactly.
//   - x86-64 instructions are not. `E8 rel32` (call) and `E9 rel32` (jmp) bytes are only counted when the target is EXACTLY a known stub, and
//     `FF 15` / `FF 25` (call / jmp [rip+disp]) only when the slot is exactly a known GOT / IAT slot. That filters almost everything that
//     merely looks like a call, but without proper disassembly a stray match is possible and data inside code can be misread.
//   - Calls through a function pointer, a vtable or a value resolved with dlsym / GetProcAddress are not seen; stripped or obfuscated code
//     (packers, control-flow flattening) may hide or invent sites. A count is "direct call sites found", never "times called".
//   - ELF i386 / arm and PE for other machines are not supported (the result is null: the caller keeps the presence-only inventory).
//   - Mach-O is not covered.

const MAX_SCAN = 256 * 1024 * 1024;
const JMP_MEM = Buffer.from([0xff, 0x25]);

// ── shared arm64 helpers ───────────────────────────────────────────────────────────────────────────────────────────────────────
const signExt = (v, bits) => (v & (1 << (bits - 1)) ? v - (2 ** bits) : v);
/** `adrp xRd, page` → { rd, page } for the instruction at `pc` (an address), or null. */
function adrp(w, pc) {
  if (((w & 0x9f000000) >>> 0) !== 0x90000000) return null;
  const imm = signExt((((w >>> 5) & 0x7ffff) << 2) | ((w >>> 29) & 3), 21);
  return { rd: w & 31, page: (Math.floor(pc / 4096) + imm) * 4096 };
}
/** `ldr xRt, [xRn, #imm]` (64-bit, unsigned offset) → { rt, rn, imm }, or null. */
function ldrX(w) {
  if (((w & 0xffc00000) >>> 0) !== 0xf9400000) return null;
  return { rt: w & 31, rn: (w >>> 5) & 31, imm: ((w >>> 10) & 0xfff) * 8 };
}

// ── PTRACE_TRACEME: is the first argument of a ptrace call the constant 0? ─────────────────────────────────────────────────
// x86-64: the last write to edi / rdi in the 24 bytes before the call is `xor edi,edi` or `mov edi,0`.
// arm64: the last write to w0 / x0 in the 8 instructions before the call is `mov w0,#0` / `mov x0,xzr`, with no call or branch in between.
function x86ArgZero(buf, p) {
  let best = -1, zero = false;
  const lo = Math.max(0, p - 24);
  for (let i = lo; i < p; i++) {
    const b = buf[i];
    if (b === 0xbf && i + 5 <= p) { best = i; zero = buf.readUInt32LE(i + 1) === 0; }                                                // mov edi, imm32
    else if ((b === 0x31 || b === 0x33) && buf[i + 1] === 0xff && i + 2 <= p) { best = i; zero = true; }                           // xor edi, edi
    else if (b === 0xc7 && buf[i + 1] === 0xc7 && buf[i - 1] === 0x48 && i + 6 <= p) { best = i; zero = buf.readUInt32LE(i + 2) === 0; }   // mov rdi, imm32
  }
  return best >= 0 && zero;
}
function armArgZero(buf, p) {
  for (let k = 1; k <= 8 && p - 4 * k >= 0; k++) {
    const w = buf.readUInt32LE(p - 4 * k);
    if (w >>> 26 === 0x25 || w >>> 26 === 0x05 || w === 0xd65f03c0 || ((w & 0xfffffc1f) >>> 0) === 0xd63f0000) return false;   // bl / b / ret / blr: another function
    if ((w & 31) !== 0) continue;
    if ((w & 0x7f800000) === 0x52800000) return ((w >>> 5) & 0xffff) === 0;                    // movz w0/x0, #imm
    if ((w & 0x7fe0ffe0) === 0x2a0003e0) return ((w >>> 16) & 31) === 31;                      // mov w0/x0, wzr/xzr
    if ((w & 0x7f800000) === 0x12800000) return false;                                         // movn
  }
  return false;
}

class Tally {
  constructor() { this.counts = new Map(); this.traceme = 0; this.sites = 0; }
  hit(name, isTraceme) {
    this.sites++;
    if (name === 'ptrace' && isTraceme) { this.traceme++; return; }
    this.counts.set(name, (this.counts.get(name) || 0) + 1);
  }
  result(extra) { return { counts: this.counts, traceme: this.traceme, sites: this.sites, ...extra }; }
}

/** Scans one executable range for direct calls / jumps to `stubs` (address -> name) and indirect ones through `slots` (address -> name). */
function scanRange(buf, off, size, addr, arch, stubs, slots, tally, adrpSlots) {
  const end = Math.min(buf.length, off + size);
  if (arch === 'x86_64') {
    for (let p = off; p < end - 5; p++) {
      const b = buf[p];
      if (b === 0xe8 || b === 0xe9) {
        const name = stubs.get(addr + (p - off) + 5 + buf.readInt32LE(p + 1));
        if (name) tally.hit(name, name === 'ptrace' && x86ArgZero(buf, p));
      } else if (b === 0xff && (buf[p + 1] === 0x15 || buf[p + 1] === 0x25) && !stubs.has(addr + (p - off))) {          // not the `jmp [slot]` that IS a thunk
        const name = slots.get(addr + (p - off) + 6 + buf.readInt32LE(p + 2));
        if (name) tally.hit(name, name === 'ptrace' && x86ArgZero(buf, p));
      }
    }
  } else {
    for (let p = off & ~3; p + 4 <= end; p += 4) {
      const w = buf.readUInt32LE(p), pc = addr + (p - off);
      const top = w >>> 26;
      if (top === 0x25 || top === 0x05) {                                                           // bl / b imm26
        const name = stubs.get(pc + signExt(w & 0x3ffffff, 26) * 4);
        if (name) tally.hit(name, name === 'ptrace' && armArgZero(buf, p));
      } else if (((w & 0xfffffc1f) >>> 0) === 0xd63f0000 && p - 8 >= off) {                                  // blr xN preceded by `adrp xM` + `ldr xN,[xM,#imm]`
        const l = ldrX(buf.readUInt32LE(p - 4)), a = l && adrp(buf.readUInt32LE(p - 8), pc - 8);
        if (l && a && l.rt === ((w >>> 5) & 31) && a.rd === l.rn) {
          const name = adrpSlots.get(a.page + l.imm);
          if (name) tally.hit(name, name === 'ptrace' && armArgZero(buf, p));
        }
      }
    }
  }
}

// ── ELF ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const ELF_ARCH = { 62: 'x86_64', 183: 'arm64' };
// relocation types that fill a GOT slot with the address of a named symbol
const RELOC = { x86_64: new Set([6, 7]), arm64: new Set([1025, 1026]) };       // GLOB_DAT, JUMP_SLOT

/**
 * @param {Buffer} buf an ELF file (little-endian)
 * @returns {{counts:Map<string,number>, traceme:number, sites:number, arch:string}|null} null when the file cannot be scanned
 */
export function elfCallSites(buf) {
  try {
    if (buf.length < 64 || buf.readUInt32BE(0) !== 0x7f454c46 || buf[5] !== 1) return null;
    const is64 = buf[4] === 2, arch = ELF_ARCH[buf.readUInt16LE(18)];
    if (!arch || !is64) return null;
    const shoff = Number(buf.readBigUInt64LE(0x28)), shent = buf.readUInt16LE(0x3a), shnum = buf.readUInt16LE(0x3c);
    if (!shoff || shent < 64 || !shnum || shoff + shnum * shent > buf.length) return null;
    const sec = [];
    for (let i = 0; i < shnum; i++) {
      const o = shoff + i * shent;
      sec.push({ type: buf.readUInt32LE(o + 4), flags: Number(buf.readBigUInt64LE(o + 8)), addr: Number(buf.readBigUInt64LE(o + 16)), off: Number(buf.readBigUInt64LE(o + 24)),
        size: Number(buf.readBigUInt64LE(o + 32)), link: buf.readUInt32LE(o + 40), nameIdx: buf.readUInt32LE(o) });
    }
    const shstr = sec[buf.readUInt16LE(0x3e)];
    const nameOf = s => { if (!shstr) return ''; let a = shstr.off + s.nameIdx, z = a; while (z < buf.length && buf[z] !== 0 && z - a < 64) z++; return buf.latin1Slice(a, z); };
    sec.forEach(s => { s.name = nameOf(s); });
    const dynsym = sec.find(s => s.type === 11), dynstr = dynsym && sec[dynsym.link];
    if (!dynsym || !dynstr) return null;
    const symName = i => { const a = dynstr.off + buf.readUInt32LE(dynsym.off + i * 24); let z = a; while (z < buf.length && buf[z] !== 0 && z - a < 256) z++; return buf.latin1Slice(a, z); };

    // GOT slot address -> imported symbol name
    const gotSlots = new Map();
    for (const s of sec) {
      if (s.type !== 4 || sec[s.link] !== dynsym) continue;                                       // SHT_RELA against the dynamic symbols
      for (let o = s.off; o + 24 <= Math.min(buf.length, s.off + s.size); o += 24) {
        const info = buf.readBigUInt64LE(o + 8), type = Number(info & 0xffffffffn), sym = Number(info >> 32n);
        if (sym && RELOC[arch].has(type) && !gotSlots.has(Number(buf.readBigUInt64LE(o)))) gotSlots.set(Number(buf.readBigUInt64LE(o)), symName(sym));
      }
    }
    if (!gotSlots.size) return null;

    // stubs: code in the PLT sections that jumps through a GOT slot
    const stubs = new Map(), adrpSlots = new Map();
    for (const s of sec.filter(x => (x.flags & 4) && /^\.(plt|iplt)/.test(x.name) && x.type === 1)) {
      const end = Math.min(buf.length, s.off + s.size);
      if (arch === 'x86_64') {
        for (let p = buf.indexOf(JMP_MEM, s.off); p >= 0 && p + 6 <= end; p = buf.indexOf(JMP_MEM, p + 1)) {
          const name = gotSlots.get(s.addr + (p - s.off) + 6 + buf.readInt32LE(p + 2));
          if (!name) continue;
          let st = p;
          if (buf[st - 1] === 0xf2) st--;                                                          // bnd jmp
          if (st >= s.off + 4 && buf.readUInt32BE(st - 4) === 0xf30f1efa) st -= 4;                  // endbr64
          stubs.set(s.addr + (st - s.off), name);
        }
      } else {
        for (let p = s.off & ~3; p + 8 <= end; p += 4) {
          const a = adrp(buf.readUInt32LE(p), s.addr + (p - s.off)), l = a && ldrX(buf.readUInt32LE(p + 4));
          if (!a || !l || l.rn !== a.rd) continue;
          const name = gotSlots.get(a.page + l.imm);
          if (!name) continue;
          const at = s.addr + (p - s.off);
          stubs.set(at, name);
          if (p >= s.off + 4 && buf.readUInt32LE(p - 4) === 0xd503245f) stubs.set(at - 4, name);     // `bti c` in front of the stub
        }
      }
    }
    // -fno-plt code reaches the GOT directly
    for (const [a, n] of gotSlots) adrpSlots.set(a, n);
    if (!stubs.size && !gotSlots.size) return null;

    const tally = new Tally();
    let scanned = 0;
    for (const s of sec) {
      if (!(s.flags & 4) || s.type !== 1 || /^\.(plt|iplt)/.test(s.name) || !s.size) continue;       // executable code other than the stubs themselves
      if (scanned + s.size > MAX_SCAN || s.off + s.size > buf.length) continue;
      scanned += s.size;
      scanRange(buf, s.off, s.size, s.addr, arch, stubs, gotSlots, tally, adrpSlots);
    }
    return tally.result({ arch, stubs: stubs.size });
  } catch { return null; }
}

// ── PE ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/**
 * @param {Buffer} buf a PE file
 * @returns {{counts:Map<string,number>, traceme:number, sites:number, arch:string}|null}
 */
export function peCallSites(buf) {
  try {
    if (buf.length < 0x100 || buf.readUInt16LE(0) !== 0x5a4d) return null;
    const pe = buf.readUInt32LE(0x3c);
    if (buf.readUInt32LE(pe) !== 0x4550) return null;
    const machine = buf.readUInt16LE(pe + 4), arch = { 0x8664: 'x86_64', 0xaa64: 'arm64', 0x14c: 'x86' }[machine];
    if (!arch) return null;
    const nsec = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20), opt = pe + 24, is64 = buf.readUInt16LE(opt) === 0x20b;
    const imageBase = is64 ? Number(buf.readBigUInt64LE(opt + 24)) : buf.readUInt32LE(opt + 28);
    const dirs = opt + (is64 ? 112 : 96);
    const sec = [];
    for (let i = 0; i < nsec; i++) {
      const o = opt + optSize + i * 40;
      if (o + 40 > buf.length) return null;
      sec.push({ vsize: buf.readUInt32LE(o + 8), rva: buf.readUInt32LE(o + 12), rsize: buf.readUInt32LE(o + 16), off: buf.readUInt32LE(o + 20), ch: buf.readUInt32LE(o + 36) });
    }
    const toOff = rva => { for (const s of sec) if (rva >= s.rva && rva < s.rva + Math.max(s.vsize, s.rsize)) return s.off + (rva - s.rva); return -1; };
    const cstr = o => { if (o < 0) return null; let z = o; while (z < buf.length && buf[z] !== 0 && z - o < 256) z++; return buf.latin1Slice(o, z); };
    const impRva = buf.readUInt32LE(dirs + 8), io = impRva ? toOff(impRva) : -1;
    if (io < 0) return null;
    const w = is64 ? 8 : 4;
    const iat = new Map();                                                                          // IAT slot RVA -> imported name
    for (let o = io, n = 0; o + 20 <= buf.length && n < 2048; o += 20, n++) {
      const oft = buf.readUInt32LE(o), ft = buf.readUInt32LE(o + 16);
      if (!oft && !ft && !buf.readUInt32LE(o + 12)) break;
      let t = toOff(oft || ft);
      if (t < 0 || !ft) continue;
      for (let k = 0; k < 20000 && t + w <= buf.length; k++, t += w) {
        const v = is64 ? buf.readBigUInt64LE(t) : BigInt(buf.readUInt32LE(t));
        if (v === 0n) break;
        if (v >> BigInt(is64 ? 63 : 31)) continue;                                                  // by ordinal
        const nm = cstr(toOff(Number(v & 0x7fffffffn)) + 2);
        if (nm && !iat.has(ft + k * w)) iat.set(ft + k * w, nm);
      }
    }
    if (!iat.size) return null;

    const code = sec.filter(s => (s.ch & 0x20000000) && s.rsize && s.off + s.rsize <= buf.length);
    // slots for the scanner: x64 / arm64 use RVAs directly; 32-bit x86 call [abs32], which is imageBase + RVA
    const slots = new Map(), stubs = new Map();
    const slotKey = rva => (arch === 'x86' ? imageBase + rva : rva);
    for (const [rva, name] of iat) slots.set(slotKey(rva), name);
    // import thunks (`jmp [IAT slot]`) are what `call thunk` reaches in MinGW / Delphi / older MSVC output
    if (arch !== 'arm64') {
      for (const s of code) {
        const end = s.off + s.rsize;
        for (let p = buf.indexOf(JMP_MEM, s.off); p >= 0 && p + 6 <= end; p = buf.indexOf(JMP_MEM, p + 1)) {
          const slot = arch === 'x86' ? buf.readUInt32LE(p + 2) : s.rva + (p - s.off) + 6 + buf.readInt32LE(p + 2);
          const name = slots.get(slot);
          if (name) stubs.set(arch === 'x86' ? imageBase + s.rva + (p - s.off) : s.rva + (p - s.off), name);
        }
      }
    }
    const tally = new Tally();
    let scanned = 0;
    for (const s of code) {
      if (scanned + s.rsize > MAX_SCAN) break;
      scanned += s.rsize;
      if (arch === 'x86') scanX86(buf, s, imageBase, stubs, slots, tally);
      else scanRange(buf, s.off, s.rsize, s.rva, arch, stubs, slots, tally, slots);
    }
    return tally.result({ arch, stubs: stubs.size });
  } catch { return null; }
}

// 32-bit x86: `call [abs32]` (FF 15) and `call rel32` into a thunk. The relative form needs addresses in the same space as the thunks.
function scanX86(buf, s, imageBase, stubs, slots, tally) {
  const end = s.off + s.rsize;
  for (let p = s.off; p < end - 5; p++) {
    const b = buf[p];
    if (b === 0xe8 || b === 0xe9) {
      const name = stubs.get(imageBase + s.rva + (p - s.off) + 5 + buf.readInt32LE(p + 1));
      if (name) tally.hit(name, false);
    } else if (b === 0xff && (buf[p + 1] === 0x15 || buf[p + 1] === 0x25) && p + 6 <= end && !stubs.has(imageBase + s.rva + (p - s.off))) {
      const name = slots.get(buf.readUInt32LE(p + 2));
      if (name) tally.hit(name, false);
    }
  }
}
