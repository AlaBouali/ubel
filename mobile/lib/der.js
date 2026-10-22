'use strict';
// der.js — just enough ASN.1 (DER/BER) to pull certificates out of a PKCS#7 signature (META-INF/*.RSA) and
// out of the APK Signing Block (v2/v3), then describe them with Node's built-in X509Certificate.

import { X509Certificate } from 'crypto';

const MAX_DEPTH = 24;

export function parseTlv(buf, pos = 0, depth = 0) {
  if (depth > MAX_DEPTH || pos + 2 > buf.length) throw new Error('bad ASN.1');
  const start = pos;
  const tag = buf[pos++];
  let len = buf[pos++];
  let indefinite = false;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0) { indefinite = true; len = 0; }
    else {
      if (n > 4 || pos + n > buf.length) throw new Error('bad ASN.1 length');
      len = 0; for (let i = 0; i < n; i++) len = len * 256 + buf[pos++];
    }
  }
  const constructed = (tag & 0x20) !== 0;
  const node = { tag, constructed, start, valueStart: pos, children: [], end: 0 };
  if (!constructed) {
    if (pos + len > buf.length) throw new Error('bad ASN.1 length');
    node.end = pos + len;
    return node;
  }
  let p = pos;
  const limit = indefinite ? buf.length : pos + len;
  while (p < limit) {
    if (indefinite && buf[p] === 0 && buf[p + 1] === 0) { p += 2; break; }
    const c = parseTlv(buf, p, depth + 1);
    node.children.push(c);
    p = c.end;
  }
  node.end = indefinite ? p : pos + len;
  if (node.end > buf.length) throw new Error('bad ASN.1 length');
  return node;
}

function oid(buf, node) {
  const b = buf.subarray(node.valueStart, node.end);
  if (!b.length) return '';
  const parts = [Math.floor(b[0] / 40), b[0] % 40];
  let v = 0;
  for (let i = 1; i < b.length; i++) { v = v * 128 + (b[i] & 0x7f); if (!(b[i] & 0x80)) { parts.push(v); v = 0; } }
  return parts.join('.');
}

const SIG_ALGS = {
  '1.2.840.113549.1.1.4': 'md5WithRSA', '1.2.840.113549.1.1.5': 'sha1WithRSA', '1.2.840.113549.1.1.11': 'sha256WithRSA',
  '1.2.840.113549.1.1.12': 'sha384WithRSA', '1.2.840.113549.1.1.13': 'sha512WithRSA', '1.2.840.113549.1.1.10': 'rsassa-pss',
  '1.2.840.10045.4.1': 'sha1WithECDSA', '1.2.840.10045.4.3.2': 'sha256WithECDSA', '1.2.840.10045.4.3.3': 'sha384WithECDSA',
  '1.2.840.10045.4.3.4': 'sha512WithECDSA', '1.2.840.10040.4.3': 'sha1WithDSA', '2.16.840.1.101.3.4.3.2': 'sha256WithDSA',
  '1.3.101.112': 'ed25519',
};
export const WEAK_SIG = /^(md2|md4|md5|sha1)/i;

/** Certificates inside a PKCS#7 SignedData blob (DER or BER). Returns DER buffers. */
export function certsFromPkcs7(buf) {
  const root = parseTlv(buf, 0);
  const explicit = root.children.find(c => c.tag === 0xa0);
  const signed = explicit && explicit.children[0];
  const certSet = signed && signed.children.find(c => c.tag === 0xa0);
  if (!certSet) return [];
  return certSet.children.filter(c => c.tag === 0x30).map(c => Buffer.from(buf.subarray(c.start, c.end)));
}

export function describeCert(der) {
  const x = new X509Certificate(der);
  let sigAlg = 'unknown';
  try {
    const n = parseTlv(der, 0);
    sigAlg = SIG_ALGS[oid(der, n.children[1].children[0])] || oid(der, n.children[1].children[0]);
  } catch { /* keep unknown */ }
  const pk = x.publicKey;
  const d = pk.asymmetricKeyDetails || {};
  return {
    subject: x.subject.replace(/\n/g, ', '),
    issuer: x.issuer.replace(/\n/g, ', '),
    valid_from: x.validFrom, valid_to: x.validTo,
    expired: Date.parse(x.validTo) < Date.now(),
    key_type: pk.asymmetricKeyType, key_bits: d.modulusLength || (d.namedCurve ? d.namedCurve : null),
    signature_algorithm: sigAlg,
    sha256: x.fingerprint256.replace(/:/g, '').toLowerCase(),
    self_signed: x.subject === x.issuer,
  };
}

// ── APK Signing Block (schemes v2 / v3 / v3.1) ────────────────────────────────────────────────────
const U64 = (b, o) => b.readUInt32LE(o) + b.readUInt32LE(o + 4) * 4294967296;
const SCHEMES = { 0x7109871a: 'v2', 0xf05368c0: 'v3', 0x1b93ad61: 'v3.1' };

/** @param {(off:number,len:number)=>Buffer} read  @param {number} cdOffset  start of the ZIP central directory */
export function parseApkSigningBlock(read, cdOffset) {
  const res = { schemes: [], certs: [] };
  if (cdOffset < 32) return res;
  const foot = read(cdOffset - 24, 24);
  if (foot.toString('latin1', 8, 24) !== 'APK Sig Block 42') return res;
  const size = U64(foot, 0);
  const blockStart = cdOffset - size - 8;
  if (size < 24 || blockStart < 0 || size > 64 * 1024 * 1024) return res;
  const block = read(blockStart, size + 8);
  let p = 8;
  const end = block.length - 24;
  while (p + 12 <= end) {
    const len = U64(block, p), id = block.readUInt32LE(p + 8);
    if (len < 4 || p + 8 + len > end + 0) break;
    const value = block.subarray(p + 12, p + 8 + len);
    if (SCHEMES[id]) {
      res.schemes.push(SCHEMES[id]);
      try { res.certs.push(...certsFromSignerSequence(value)); } catch { /* unreadable signer block */ }
    }
    p += 8 + len;
  }
  return res;
}

function certsFromSignerSequence(v) {
  const out = [];
  const u32 = (b, o) => b.readUInt32LE(o);
  let p = 4; const signersEnd = 4 + u32(v, 0);
  while (p + 4 <= signersEnd && p + 4 <= v.length) {
    const sLen = u32(v, p); const signer = v.subarray(p + 4, p + 4 + sLen); p += 4 + sLen;
    const sdLen = u32(signer, 0); const sd = signer.subarray(4, 4 + sdLen);
    const digestsLen = u32(sd, 0);
    const certsAt = 4 + digestsLen;
    const certsLen = u32(sd, certsAt);
    let q = certsAt + 4; const cEnd = q + certsLen;
    while (q + 4 <= cEnd) { const l = u32(sd, q); out.push(Buffer.from(sd.subarray(q + 4, q + 4 + l))); q += 4 + l; }
  }
  return out;
}
