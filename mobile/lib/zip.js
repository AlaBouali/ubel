'use strict';
// zip.js — read-only ZIP reader (APK / IPA / nested packages) on Node's built-in zlib.
// Reads the central directory, then inflates single entries on demand straight from the file
// (positional reads, so a multi-GB IPA is never loaded whole). Defends against zip bombs:
// per-entry and total inflated-size caps, a compression-ratio cap and maxOutputLength on inflate.

import fs from 'fs';
import zlib from 'zlib';

export class ZipError extends Error {}

const EOCD_SIG = 0x06054b50, CEN_SIG = 0x02014b50, LOC_SIG = 0x04034b50;
const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;

export class ZipArchive {
  constructor(source, { maxEntries = 200000, maxEntryBytes = 256 * 1024 * 1024, maxTotalBytes = 2 * 1024 ** 3 } = {}) {
    this.maxEntries = maxEntries;
    this.maxEntryBytes = maxEntryBytes;
    this.maxTotalBytes = maxTotalBytes;
    this.inflated = 0;
    this.buf = null; this.fd = null;
    if (Buffer.isBuffer(source)) { this.buf = source; this.size = source.length; }
    else { this.fd = fs.openSync(source, 'r'); this.size = fs.fstatSync(this.fd).size; }
    try { this._load(); } catch (e) { this.close(); throw e; }
  }

  close() { if (this.fd !== null) { try { fs.closeSync(this.fd); } catch { /* ignore */ } this.fd = null; } }

  _read(off, len) {
    if (!(off >= 0) || !(len >= 0) || off + len > this.size) throw new ZipError('read beyond end of archive');
    if (this.buf) return this.buf.subarray(off, off + len);
    const b = Buffer.allocUnsafe(len);
    let got = 0;
    while (got < len) {
      const n = fs.readSync(this.fd, b, got, len - got, off + got);
      if (!n) throw new ZipError('unexpected end of file');
      got += n;
    }
    return b;
  }

  _load() {
    if (this.size < 22) throw new ZipError('not a ZIP archive (too small)');
    const tailLen = Math.min(this.size, 65557);
    const tailOff = this.size - tailLen;
    const tail = this._read(tailOff, tailLen);
    let e = -1;
    for (let i = tail.length - 22; i >= 0; i--) if (tail.readUInt32LE(i) === EOCD_SIG) { e = i; break; }
    if (e < 0) throw new ZipError('not a ZIP archive (no end-of-central-directory record)');
    let total = tail.readUInt16LE(e + 10);
    let cdSize = tail.readUInt32LE(e + 12);
    let cdOff = tail.readUInt32LE(e + 16);
    if (total === 0xffff || cdSize === 0xffffffff || cdOff === 0xffffffff) {
      const locPos = tailOff + e - 20;
      const loc = locPos >= 0 ? this._read(locPos, 20) : null;
      if (!loc || loc.readUInt32LE(0) !== 0x07064b50) throw new ZipError('ZIP64 locator missing');
      const rec = this._read(U64(loc, 8), 56);
      if (rec.readUInt32LE(0) !== 0x06064b50) throw new ZipError('bad ZIP64 end record');
      total = U64(rec, 32); cdSize = U64(rec, 40); cdOff = U64(rec, 48);
    }
    if (total > this.maxEntries) throw new ZipError(`too many entries (${total})`);
    if (cdSize > 512 * 1024 * 1024) throw new ZipError('central directory too large');
    this.cdOffset = cdOff;
    const cd = this._read(cdOff, cdSize);
    this.entries = [];
    this.byName = new Map();
    this.duplicateNames = [];
    let p = 0;
    for (let n = 0; n < total; n++) {
      if (p + 46 > cd.length || cd.readUInt32LE(p) !== CEN_SIG) throw new ZipError('corrupt central directory');
      const flags = cd.readUInt16LE(p + 8), method = cd.readUInt16LE(p + 10);
      let csize = cd.readUInt32LE(p + 20), usize = cd.readUInt32LE(p + 24);
      const nameLen = cd.readUInt16LE(p + 28), extraLen = cd.readUInt16LE(p + 30), commentLen = cd.readUInt16LE(p + 32);
      let localOffset = cd.readUInt32LE(p + 42);
      const name = cd.toString('utf8', p + 46, p + 46 + nameLen);
      if (usize === 0xffffffff || csize === 0xffffffff || localOffset === 0xffffffff) {
        let q = p + 46 + nameLen; const end = q + extraLen;
        while (q + 4 <= end) {
          const id = cd.readUInt16LE(q), sz = cd.readUInt16LE(q + 2);
          if (id === 0x0001) {
            let r = q + 4;
            if (usize === 0xffffffff) { usize = U64(cd, r); r += 8; }
            if (csize === 0xffffffff) { csize = U64(cd, r); r += 8; }
            if (localOffset === 0xffffffff) { localOffset = U64(cd, r); }
            break;
          }
          q += 4 + sz;
        }
      }
      const entry = { name, method, flags, csize, usize, localOffset, isDir: name.endsWith('/') };
      this.entries.push(entry);
      if (this.byName.has(name)) this.duplicateNames.push(name); else this.byName.set(name, entry);
      p += 46 + nameLen + extraLen + commentLen;
    }
  }

  has(name) { return this.byName.has(name); }
  entry(name) { return this.byName.get(name) || null; }
  find(re) { return this.entries.filter(e => !e.isDir && re.test(e.name)); }

  /** Inflates one entry. Throws ZipError when it is encrypted, oversized, suspicious or corrupt. */
  read(entryOrName, maxBytes = this.maxEntryBytes) {
    const entry = typeof entryOrName === 'string' ? this.byName.get(entryOrName) : entryOrName;
    if (!entry) throw new ZipError(`no such entry: ${entryOrName}`);
    if (entry.flags & 1) throw new ZipError(`${entry.name}: encrypted entry`);
    if (entry.usize > maxBytes) throw new ZipError(`${entry.name}: ${entry.usize} bytes exceeds the ${maxBytes}-byte entry limit`);
    if (this.inflated + entry.usize > this.maxTotalBytes) throw new ZipError('total inflated size limit reached');
    if (entry.usize > 1048576 && entry.usize / Math.max(entry.csize, 1) > 2000) throw new ZipError(`${entry.name}: implausible compression ratio`);
    const lh = this._read(entry.localOffset, 30);
    if (lh.readUInt32LE(0) !== LOC_SIG) throw new ZipError(`${entry.name}: bad local header`);
    const start = entry.localOffset + 30 + lh.readUInt16LE(26) + lh.readUInt16LE(28);
    const raw = this._read(start, entry.csize);
    let out;
    if (entry.method === 0) out = Buffer.from(raw);
    else if (entry.method === 8) {
      try { out = zlib.inflateRawSync(raw, { maxOutputLength: entry.usize + 64 }); }
      catch (e) { throw new ZipError(`${entry.name}: ${e.code === 'ERR_BUFFER_TOO_LARGE' ? 'inflates beyond its declared size' : e.message}`); }
    } else throw new ZipError(`${entry.name}: unsupported compression method ${entry.method}`);
    if (out.length !== entry.usize) throw new ZipError(`${entry.name}: size mismatch`);
    this.inflated += out.length;
    return out;
  }

  /** Reads without throwing: null on any failure. */
  tryRead(entryOrName, maxBytes) {
    try { return this.read(entryOrName, maxBytes); } catch { return null; }
  }
}
