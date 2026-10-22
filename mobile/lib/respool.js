'use strict';
// respool.js — Android ResStringPool (shared by binary XML and resources.arsc).

export class StringPool {
  /** @param {Buffer} buf  @param {number} chunkOffset  start of the RES_STRING_POOL chunk */
  constructor(buf, chunkOffset) {
    if (buf.readUInt16LE(chunkOffset) !== 0x0001) throw new Error('not a string pool');
    this.buf = buf;
    const headerSize = buf.readUInt16LE(chunkOffset + 2);
    this.chunkSize = buf.readUInt32LE(chunkOffset + 4);
    this.count = buf.readUInt32LE(chunkOffset + 8);
    const flags = buf.readUInt32LE(chunkOffset + 16);
    this.utf8 = (flags & 0x100) !== 0;
    const stringsStart = buf.readUInt32LE(chunkOffset + 20);
    this.offsetsAt = chunkOffset + headerSize;
    this.dataAt = chunkOffset + stringsStart;
    this.end = chunkOffset + this.chunkSize;
    if (this.count > 5_000_000 || this.offsetsAt + this.count * 4 > buf.length) throw new Error('corrupt string pool');
    this._cache = new Map();
  }

  get(i) {
    if (i < 0 || i >= this.count) return '';
    const hit = this._cache.get(i);
    if (hit !== undefined) return hit;
    let s = '';
    try { s = this._decode(i); } catch { s = ''; }
    if (this._cache.size < 200000) this._cache.set(i, s);
    return s;
  }

  _decode(i) {
    const buf = this.buf;
    let p = this.dataAt + buf.readUInt32LE(this.offsetsAt + i * 4);
    if (p >= buf.length) return '';
    if (this.utf8) {
      let chars = buf[p++]; if (chars & 0x80) p++;               // UTF-16 length (skipped)
      let bytes = buf[p++]; if (bytes & 0x80) bytes = ((bytes & 0x7f) << 8) | buf[p++];
      return buf.toString('utf8', p, Math.min(p + bytes, buf.length));
    }
    let len = buf.readUInt16LE(p); p += 2;
    if (len & 0x8000) { len = ((len & 0x7fff) << 16) | buf.readUInt16LE(p); p += 2; }
    return buf.toString('utf16le', p, Math.min(p + len * 2, buf.length));
  }
}
