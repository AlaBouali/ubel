'use strict';
// pb.js — minimal protobuf wire-format reader (Node built-ins only). App Bundles (.aab) store the manifest, res/xml files and
// resources.pb in aapt2's protobuf encoding, and BUNDLE-METADATA carries a protobuf dependency list; this is all that is needed to read them.
// Untrusted input: every read is bounds-checked and malformed data throws PbError instead of looping or over-reading.

export class PbError extends Error {}

/** @returns {[number|bigint, number]} [value, next position]. Values past 2^53 come back as BigInt. */
export function readVarint(buf, pos) {
  let result = 0, mul = 1, i = 0;
  let big = null;
  for (;;) {
    if (pos + i >= buf.length) throw new PbError('truncated varint');
    if (i >= 10) throw new PbError('varint too long');
    const b = buf[pos + i];
    if (big === null && i < 7) { result += (b & 0x7f) * mul; mul *= 128; }
    else {
      if (big === null) { big = BigInt(result); mul = 128n ** BigInt(i); }
      big += BigInt(b & 0x7f) * mul; mul *= 128n;
    }
    i++;
    if (!(b & 0x80)) break;
  }
  return [big === null ? result : (big <= BigInt(Number.MAX_SAFE_INTEGER) ? Number(big) : big), pos + i];
}

/**
 * Parses one message into field number → list of values. Varints are numbers, length-delimited fields are Buffers (sub-messages,
 * strings and bytes are not distinguished on the wire), fixed32 is a number, fixed64 a Buffer. Groups are rejected.
 * @param {Buffer} buf
 * @returns {Map<number, Array<number|bigint|Buffer>>}
 */
export function parseMessage(buf) {
  const fields = new Map();
  let pos = 0;
  const push = (f, v) => { const a = fields.get(f); if (a) a.push(v); else fields.set(f, [v]); };
  while (pos < buf.length) {
    let tag;
    [tag, pos] = readVarint(buf, pos);
    if (typeof tag !== 'number') throw new PbError('bad field tag');
    const field = Math.floor(tag / 8), wire = tag % 8;
    if (field < 1) throw new PbError('bad field number');
    if (wire === 0) { let v; [v, pos] = readVarint(buf, pos); push(field, v); }
    else if (wire === 2) {
      let len; [len, pos] = readVarint(buf, pos);
      if (typeof len !== 'number' || pos + len > buf.length) throw new PbError('length-delimited field overruns the message');
      push(field, buf.subarray(pos, pos + len)); pos += len;
    } else if (wire === 5) { if (pos + 4 > buf.length) throw new PbError('truncated fixed32'); push(field, buf.readUInt32LE(pos)); pos += 4; }
    else if (wire === 1) { if (pos + 8 > buf.length) throw new PbError('truncated fixed64'); push(field, buf.subarray(pos, pos + 8)); pos += 8; }
    else throw new PbError(`unsupported wire type ${wire}`);
  }
  return fields;
}

export const first = (m, f) => { const a = m.get(f); return a ? a[0] : undefined; };
export const all = (m, f) => m.get(f) || [];
export const str = (m, f) => { const v = first(m, f); return Buffer.isBuffer(v) ? v.toString('utf8') : undefined; };
export const msg = (m, f) => { const v = first(m, f); return Buffer.isBuffer(v) ? parseMessage(v) : undefined; };
export const msgs = (m, f) => all(m, f).filter(Buffer.isBuffer).map(parseMessage);
