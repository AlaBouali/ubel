'use strict';
// components.js — what a binary says about the software inside it.
//   • C/C++ libraries: version banners that libraries leave in their own code (OpenSSL 1.1.1k, zlib 1.2.11, libcurl/7.x …) → NVD CPEs
//   • Go: see go.js (module build info, exact module versions → OSV PURLs pkg:golang/…)
//   • Rust: cargo-auditable `.dep-v0` data, or crate paths left in panic messages → OSV PURLs (pkg:cargo/…)
// A version string proves the code is in the file, not that it is reachable: records carry confidence 'medium' (banner) or 'high' (build metadata).

import zlib from 'zlib';
import { cRecord, purlRecord } from './records.js';
export { goBuildInfo, goRecords } from './go.js';                 // Go build info lives in go.js; re-exported so existing imports keep working

// [name, regex (group 1 = version), CPE vendor, CPE product]
const BANNERS = [
  ['OpenSSL',   /\bOpenSSL (\d+\.\d+\.\d+[a-z]?)(?![\w.])/,                                         'openssl', 'openssl'],
  ['LibreSSL',  /\bLibreSSL (\d+\.\d+\.\d+)/,                                                      'openbsd', 'libressl'],
  ['zlib',      /\b(?:deflate|inflate) (1\.\d+(?:\.\d+){1,2}) Copyright 1995-\d{4} (?:Jean-loup Gailly|Mark Adler)/, 'zlib', 'zlib'],
  ['libcurl',   /\blibcurl\/(\d+\.\d+\.\d+)/,                                                       'haxx', 'libcurl'],
  ['SQLite',    /\bSQLite (?:version )?(3\.\d+\.\d+(?:\.\d+)?)\b/,                                  'sqlite', 'sqlite'],
  ['libpng',    /\blibpng version (\d+\.\d+\.\d+)/,                                                 'libpng', 'libpng'],
  ['FFmpeg',    /\bFFmpeg version n?(\d+\.\d+(?:\.\d+)?)/,                                          'ffmpeg', 'ffmpeg'],
  ['expat',     /\bexpat_(\d+\.\d+\.\d+)/,                                                          'libexpat_project', 'libexpat'],
  // `_` is deliberately not a separator: ELF symbol-version tags (LIBXML2_2.4.30) are not banners. "libxml2-2.9.14", "libxml2 2.9.14", "libxml2 version 2.9.14" still match.
  ['libxml2',   /\b(?:libxml2|LIBXML)[ -]?(?:version )?(2\.\d+\.\d+)\b/i,                            'xmlsoft', 'libxml2'],
  ['xz',        /\b(?:XZ Utils|liblzma) (\d+\.\d+\.\d+)/,                                           'tukaani', 'xz'],
  ['bzip2',     /\bbzip2\/libbzip2: version (1\.\d+\.\d+)/,                                         'bzip', 'bzip2'],
  ['BusyBox',   /\bBusyBox v(\d+\.\d+\.\d+)/,                                                       'busybox', 'busybox'],
  ['Lua',       /\$LuaVersion: Lua (5\.\d\.\d+)/,                                                   'lua', 'lua'],
  ['PCRE',      /\b(8\.\d\d) 20\d\d-\d\d-\d\d\b/,                                                   'pcre', 'pcre'],
  ['PCRE2',     /\b(10\.\d\d) 20\d\d-\d\d-\d\d\b/,                                                  'pcre', 'pcre2'],
  ['glibc',     /GNU C Library .*?(?:version|GLIBC) (2\.\d+(?:\.\d+)?)/,                            'gnu', 'glibc'],
  ['mbed TLS',  /\bmbed TLS (\d+\.\d+\.\d+)/,                                                       'arm', 'mbed_tls'],
  ['wolfSSL',   /\bwolfSSL (\d+\.\d+\.\d+)/,                                                        'wolfssl', 'wolfssl'],
  ['libtiff',   /\bLIBTIFF, Version (4\.\d+\.\d+)/,                                                 'libtiff', 'libtiff'],
];
// libcurl's own banner lists the libraries it was built with: "libcurl/7.68.0 OpenSSL/1.1.1f zlib/1.2.11 nghttp2/1.40.0 …"
const CURL_PARTS = { openssl: ['OpenSSL', 'openssl', 'openssl'], zlib: ['zlib', 'zlib', 'zlib'], nghttp2: ['nghttp2', 'nghttp2', 'nghttp2'], libssh2: ['libssh2', 'libssh2', 'libssh2'],
  zstd: ['zstd', 'facebook', 'zstandard'], brotli: ['brotli', 'google', 'brotli'] };

/** Banner scan over printable strings. @param {Iterable<string>} strings @returns component records (deduplicated by name+version) */
export function detectBanners(strings) {
  const found = new Map();
  const add = c => { const k = `${c.name}@${c.version}`; if (!found.has(k)) found.set(k, cRecord(c)); };
  for (const s of strings) {
    if (s.length < 6 || s.length > 8192) continue;
    for (const [name, re, vendor, product] of BANNERS) {
      const m = re.exec(s);
      if (m) add({ name, version: m[1], vendor, product, evidence: s });
    }
    const ci = s.indexOf('libcurl/');
    if (ci >= 0) {
      for (const m of s.slice(ci, ci + 300).matchAll(/\b([A-Za-z0-9]+)\/(\d+\.\d+(?:\.\d+)*[a-z]?)(?![\w.])/g)) {
        const part = CURL_PARTS[m[1].toLowerCase()];
        if (part) add({ name: part[0], version: m[2], vendor: part[1], product: part[2], evidence: s });
      }
    }
  }
  return [...found.values()];
}

// ── Rust ─────────────────────────────────────────────────────────────────────────────────────────
/** cargo-auditable: the `.dep-v0` section is a zlib-compressed JSON dependency list. @returns {{name,version}[]|null} */
export function cargoAuditable(data) {
  try {
    const json = JSON.parse(zlib.inflateSync(data, { maxOutputLength: 32 * 1024 * 1024 }).toString('utf8'));
    return (json.packages || []).filter(p => p && p.name && p.version && (p.source === 'crates.io' || p.source === 'registry') && p.kind !== 'build').map(p => ({ name: p.name, version: p.version }));
  } catch { return null; }
}

/** Crate names/versions that panic messages and debug paths leave in the binary: …/registry/src/<index>/<crate>-<version>/src/… */
export function cratesFromStrings(strings) {
  const out = new Map();
  const re = /\/registry\/src\/[^/]+\/([A-Za-z0-9_.-]+?)-(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.+-]+)?)\//g;
  for (const s of strings) {
    if (s.length > 8192 || !s.includes('/registry/src/')) continue;
    for (const m of s.matchAll(re)) out.set(`${m[1]}@${m[2]}`, { name: m[1], version: m[2] });
  }
  return [...out.values()];
}

export function cargoRecords(list, { exact }) {
  return list.map(c => purlRecord({
    name: c.name, version: c.version, ecosystem: 'crates.io', purl: `pkg:cargo/${encodeURIComponent(c.name)}@${c.version}`,
    source: exact ? 'cargo-auditable dependency data' : 'crate path in embedded strings', sourceType: exact ? 'cargo-auditable' : 'rust panic path', confidence: exact ? 'high' : 'medium',
  }));
}
