'use strict';
// dotnet.js — everything ubel-mobile needs to look inside Xamarin / .NET MAUI / Unity (Mono) apps, Node built-ins only:
//   • parseDotnet(): PE + CLI metadata → the exact user-string literals (#US heap, UTF-16), the identifier heap (#Strings) and the PDB
//     path from the debug directory. C# string literals are where hardcoded keys live; reading the #US heap gives them as separate,
//     complete strings instead of fragments of a UTF-16 byte scan.
//   • xalzDecompress() / lz4Block(): Xamarin.Android compresses assemblies in release builds ("XALZ" + LZ4 block), which made every
//     assembly of such an app unreadable to a plain string scan.
//   • readAssemblyStore(): the "XABA" assembly store (assemblies.blob / libassembly-store.so) that .NET for Android packs assemblies into.

const U32 = (b, o) => b.readUInt32LE(o);

// ── PE / CLI ────────────────────────────────────────────────────────────────────────────────────
export function isPe(buf) { return Buffer.isBuffer(buf) && buf.length > 0x100 && buf[0] === 0x4d && buf[1] === 0x5a; }

function peLayout(buf) {
  if (!isPe(buf)) return null;
  const pe = U32(buf, 0x3c);
  if (pe + 24 > buf.length || U32(buf, pe) !== 0x00004550) return null;
  const nSections = buf.readUInt16LE(pe + 6), optSize = buf.readUInt16LE(pe + 20);
  const opt = pe + 24;
  const magic = buf.readUInt16LE(opt);
  const ddBase = opt + (magic === 0x20b ? 112 : magic === 0x10b ? 96 : -1);
  if (ddBase < opt || ddBase + 16 * 8 > buf.length) return null;
  const secs = [];
  let s = opt + optSize;
  for (let i = 0; i < nSections && i < 96 && s + 40 <= buf.length; i++, s += 40) {
    secs.push({ va: U32(buf, s + 12), vsize: U32(buf, s + 8), raw: U32(buf, s + 20), rsize: U32(buf, s + 16) });
  }
  const rva = r => { for (const x of secs) if (r >= x.va && r < x.va + Math.max(x.vsize, x.rsize)) return x.raw + (r - x.va); return -1; };
  const dir = n => ({ rva: U32(buf, ddBase + n * 8), size: U32(buf, ddBase + n * 8 + 4) });
  return { rva, dir };
}

function usEntries(heap) {
  const out = [];
  let p = 1;                                              // the heap starts with an empty entry
  while (p < heap.length && out.length < 500000) {
    const b = heap[p];
    let len, hdr;
    if ((b & 0x80) === 0) { len = b; hdr = 1; }
    else if ((b & 0xc0) === 0x80) { if (p + 2 > heap.length) break; len = ((b & 0x3f) << 8) | heap[p + 1]; hdr = 2; }
    else if ((b & 0xe0) === 0xc0) { if (p + 4 > heap.length) break; len = ((b & 0x1f) << 24) | (heap[p + 1] << 16) | (heap[p + 2] << 8) | heap[p + 3]; hdr = 4; }
    else break;
    if (len === 0) { p += hdr; continue; }
    if (p + hdr + len > heap.length) break;
    const s = heap.toString('utf16le', p + hdr, p + hdr + ((len - 1) & ~1));   // last byte is a flag, not text
    if (s) out.push(s);
    p += hdr + len;
  }
  return out;
}

/**
 * @param {Buffer} buf
 * @returns {{userStrings:string[], identifiers:Set<string>, pdbPath:string|null}|null} null when `buf` is not a managed assembly
 */
export function parseDotnet(buf) {
  const lay = peLayout(buf);
  if (!lay) return null;
  const cliDir = lay.dir(14);
  const cliOff = cliDir.rva ? lay.rva(cliDir.rva) : -1;
  if (cliOff < 0 || cliOff + 72 > buf.length) return null;
  const mdOff = lay.rva(U32(buf, cliOff + 8));
  if (mdOff < 0 || mdOff + 20 > buf.length || U32(buf, mdOff) !== 0x424a5342) return null;
  const verLen = U32(buf, mdOff + 12);
  let p = mdOff + 16 + verLen;
  p = (p + 3) & ~3;
  const nStreams = buf.readUInt16LE(p + 2);
  p += 4;
  const streams = {};
  for (let i = 0; i < nStreams && i < 16 && p + 8 < buf.length; i++) {
    const off = U32(buf, p), size = U32(buf, p + 4);
    let q = p + 8; while (q < buf.length && buf[q] !== 0) q++;
    const name = buf.toString('latin1', p + 8, q);
    p = (q + 4) & ~3;
    if (mdOff + off + size <= buf.length) streams[name] = buf.subarray(mdOff + off, mdOff + off + size);
  }
  const identifiers = new Set();
  if (streams['#Strings']) {
    let a = 0; const h = streams['#Strings'];
    while (a < h.length && identifiers.size < 400000) { let e = h.indexOf(0, a); if (e < 0) e = h.length; if (e > a) identifiers.add(h.toString('utf8', a, e)); a = e + 1; }
  }
  // CodeView debug entry: RSDS + guid + age + path
  let pdbPath = null;
  try {
    const dbg = lay.dir(6);
    const off = dbg.rva ? lay.rva(dbg.rva) : -1;
    for (let i = 0; off >= 0 && i < Math.min(8, Math.floor(dbg.size / 28)); i++) {
      const e = off + i * 28;
      if (U32(buf, e + 12) !== 2) continue;
      const raw = U32(buf, e + 24), size = U32(buf, e + 16);
      if (raw + 24 < buf.length && buf.toString('latin1', raw, raw + 4) === 'RSDS') {
        const end = buf.indexOf(0, raw + 24); pdbPath = buf.toString('utf8', raw + 24, Math.min(end < 0 ? raw + size : end, raw + 24 + 512));
        break;
      }
    }
  } catch { /* no debug directory */ }
  return { userStrings: streams['#US'] ? usEntries(streams['#US']) : [], identifiers, pdbPath };
}

// ── XALZ (LZ4-compressed assembly) ──────────────────────────────────────────────────────────────
export const isXalz = buf => Buffer.isBuffer(buf) && buf.length > 12 && buf[0] === 0x58 && buf[1] === 0x41 && buf[2] === 0x4c && buf[3] === 0x5a;

/** LZ4 *block* decoder. Throws on malformed input; never writes past `outLen`. */
export function lz4Block(src, outLen) {
  const out = Buffer.allocUnsafe(outLen);
  let ip = 0, op = 0;
  while (ip < src.length) {
    const token = src[ip++];
    let lit = token >> 4;
    if (lit === 15) { let b; do { if (ip >= src.length) throw new Error('lz4: truncated literal length'); b = src[ip++]; lit += b; } while (b === 255); }
    if (ip + lit > src.length || op + lit > outLen) throw new Error('lz4: literal run overruns');
    src.copy(out, op, ip, ip + lit); ip += lit; op += lit;
    if (ip >= src.length) break;
    if (ip + 2 > src.length) throw new Error('lz4: truncated offset');
    const offset = src.readUInt16LE(ip); ip += 2;
    if (offset === 0 || offset > op) throw new Error('lz4: bad match offset');
    let m = token & 15;
    if (m === 15) { let b; do { if (ip >= src.length) throw new Error('lz4: truncated match length'); b = src[ip++]; m += b; } while (b === 255); }
    m += 4;
    if (op + m > outLen) throw new Error('lz4: match overruns');
    for (let i = 0; i < m; i++, op++) out[op] = out[op - offset];
  }
  if (op !== outLen) throw new Error('lz4: size mismatch');
  return out;
}

/** "XALZ" + u32 descriptor index + u32 uncompressed length + LZ4 block → the assembly bytes, or null when not XALZ / invalid. */
export function xalzDecompress(buf, { maxBytes = 256 * 1024 * 1024 } = {}) {
  if (!isXalz(buf)) return null;
  const len = U32(buf, 8);
  if (len < 64 || len > maxBytes) return null;
  try { return lz4Block(buf.subarray(12), len); } catch { return null; }
}

/** Plain or XALZ-compressed assembly bytes → PE bytes, or null. */
export function assemblyBytes(buf) { return isPe(buf) ? buf : (isXalz(buf) ? xalzDecompress(buf) : null); }

// ── XABA assembly store ─────────────────────────────────────────────────────────────────────────
const XABA = 0x41424158;

/**
 * .NET for Android assembly store: header { magic "XABA", version, local_entry_count, global_entry_count, store_id }, then one 24-byte
 * descriptor per local assembly { data_offset, data_size, debug_data_offset, debug_data_size, config_data_offset, config_data_size }.
 * Names are not in the store (only hashes); `names` (from assemblies.manifest) supplies them when available.
 * Every entry is validated (inside the file, starts with MZ or XALZ); a store that does not validate yields null.
 * @param {Buffer} buf  assemblies.blob, or an ELF that embeds a store (libassembly-store.so)
 * @returns {Array<{name:string, data:Buffer}>|null}
 */
export function readAssemblyStore(buf, names = []) {
  const starts = [];
  if (buf.length >= 20 && U32(buf, 0) === XABA) starts.push(0);
  else { let i = -1, guard = 0; while ((i = buf.indexOf(Buffer.from([0x58, 0x41, 0x42, 0x41]), i + 1)) >= 0 && guard++ < 16) starts.push(i); }
  for (const base of starts) {
    if (base + 20 > buf.length) continue;
    const count = U32(buf, base + 8);
    if (!count || count > 20000 || base + 20 + count * 24 > buf.length) continue;
    const out = [];
    let ok = true;
    for (let i = 0; i < count && ok; i++) {
      const d = base + 20 + i * 24;
      const off = base + U32(buf, d), size = U32(buf, d + 4);
      if (!size || off + size > buf.length) { ok = false; break; }
      const head = buf.subarray(off, off + 4);
      if (!(head[0] === 0x4d && head[1] === 0x5a) && head.toString('latin1') !== 'XALZ') { ok = false; break; }
      out.push({ name: names[i] || `assembly_${i}.dll`, data: buf.subarray(off, off + size) });
    }
    if (ok && out.length) return out;
  }
  return null;
}

/** assemblies.manifest lines: "Hash 32 | Hash 64 | Blob ID | Blob idx | Name" → names ordered by blob index. */
export function parseAssemblyManifest(text) {
  const rows = [];
  for (const line of String(text).split(/\r?\n/)) {
    const c = line.split(/\s+/).filter(Boolean);
    if (c.length >= 5 && /^0x[0-9a-f]+$/i.test(c[0]) && /^\d+$/.test(c[3])) rows.push({ idx: Number(c[3]), id: Number(c[2]), name: c.slice(4).join(' ') });
  }
  return rows;
}
