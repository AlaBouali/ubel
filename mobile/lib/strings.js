'use strict';
// strings.js — printable-string extraction from binaries (ASCII and UTF-16LE), and small text helpers.

const PRINT = new Uint8Array(256);
for (let i = 0x20; i < 0x7f; i++) PRINT[i] = 1;
PRINT[0x09] = 1;

export function asciiStrings(buf, { min = 6, max = 1024, limit = 300000 } = {}) {
  const out = [];
  let start = -1;
  for (let i = 0; i <= buf.length; i++) {
    const ok = i < buf.length && PRINT[buf[i]] === 1;
    if (ok) { if (start < 0) start = i; continue; }
    if (start >= 0) {
      const len = i - start;
      if (len >= min) {
        // very long runs (base64 blobs, minified JS) are kept, cut at `max` per piece
        for (let s = start; s < i; s += max) out.push(buf.latin1Slice(s, Math.min(i, s + max)));
        if (out.length >= limit) return out;
      }
      start = -1;
    }
  }
  return out;
}

export function utf16Strings(buf, { min = 6, max = 1024, limit = 100000 } = {}) {
  const out = [];
  let i = 0;
  const n = buf.length - 1;
  while (i < n) {
    if (PRINT[buf[i]] === 1 && buf[i + 1] === 0) {
      let j = i; const chars = [];
      while (j < n && PRINT[buf[j]] === 1 && buf[j + 1] === 0 && chars.length < max) { chars.push(buf[j]); j += 2; }
      if (chars.length >= min) { out.push(Buffer.from(chars).toString('latin1')); if (out.length >= limit) return out; }
      i = j > i ? j : i + 1;
    } else i++;
  }
  return out;
}

/** Heuristic: true when the first KiB contains a NUL byte or a lot of non-text bytes. */
export function isLikelyBinary(buf) {
  const n = Math.min(buf.length, 4096);
  let bad = 0;
  for (let i = 0; i < n; i++) {
    const b = buf[i];
    if (b === 0) return true;
    if (b < 9 || (b > 13 && b < 32)) bad++;
  }
  return n > 0 && bad / n > 0.1;
}

export function dedupe(list) { return [...new Set(list)]; }

/** Escapes a value so it survives as one `key = "value"` line for the secrets engine. */
export function oneLine(s) { return String(s).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"'); }
