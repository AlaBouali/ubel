'use strict';
// components.js — what a binary says about the software inside it.
//   • C/C++ libraries: version banners that libraries leave in their own code (OpenSSL 1.1.1k, zlib 1.2.11, libcurl/7.x …) → NVD CPEs
//   • Go: module build info (`\xff Go buildinf:`), exact module versions → OSV PURLs (pkg:golang/…)
//   • Rust: cargo-auditable `.dep-v0` data, or crate paths left in panic messages → OSV PURLs (pkg:cargo/…)
// A version string proves the code is in the file, not that it is reachable: records carry confidence 'medium' (banner) or 'high' (build metadata).

import zlib from 'zlib';

const C_ECOSYSTEM = 'C/C++ library (version banner)';

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
  ['libxml2',   /\b(?:libxml2|LIBXML)[ _-]?(?:version )?(2\.\d+\.\d+)\b/i,                          'xmlsoft', 'libxml2'],
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

const cpeOf = (vendor, product, version) => `cpe:2.3:a:${vendor}:${product}:${version}:*:*:*:*:*:*:*`;
const specificEnough = v => /^\d+(\.\d+){1,}/.test(String(v || ''));            // same guard as the EASM NVD path: a bare "3" matches every release

function cRecord({ name, version, vendor, product, evidence }) {
  const cpe = cpeOf(vendor, product, version);
  return {
    name, version, ecosystem: C_ECOSYSTEM, purl: null, coordinate: cpe, cpe, platform: 'native',
    sources: ['embedded version string'], source_types: ['binary version string'], confidence: 'medium', identity: null,
    lookup_status: specificEnough(version) ? 'pending' : 'not_queryable',
    lookup_reason: specificEnough(version) ? null : 'The version string is not specific enough for an NVD CPE query.',
    evidence: String(evidence || '').slice(0, 120), vulnerabilities: [], vulnerability_count: 0,
  };
}
function purlRecord({ name, version, ecosystem, purl, source, sourceType, confidence = 'high' }) {
  return {
    name, version, ecosystem, purl, coordinate: null, platform: 'native', sources: [source], source_types: [sourceType], confidence, identity: null,
    lookup_status: 'pending', lookup_reason: null, vulnerabilities: [], vulnerability_count: 0,
  };
}

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

// ── Go ───────────────────────────────────────────────────────────────────────────────────────────
const GO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');

function uvarint(buf, at) {
  let x = 0, s = 0;
  for (let i = 0; i < 10 && at + i < buf.length; i++) {
    const b = buf[at + i];
    if (b < 0x80) return { value: x + b * 2 ** s, next: at + i + 1 };
    x += (b & 0x7f) * 2 ** s; s += 7;
  }
  return null;
}

/** Go build info (Go ≥ 1.18, inline-string format). @returns {{goVersion:string, modules:{path:string,version:string}[]}|{unsupported:string}|null} */
export function goBuildInfo(buf) {
  let at = buf.indexOf(GO_MAGIC);
  while (at >= 0 && at % 16 !== 0) at = buf.indexOf(GO_MAGIC, at + 1);
  if (at < 0) return null;
  const flags = buf[at + 15];
  if (!(flags & 2)) return { unsupported: 'Go build info uses the pre-1.18 pointer format; module versions were not read.' };
  const v = uvarint(buf, at + 32); if (!v || v.next + v.value > buf.length) return { unsupported: 'Go build info is truncated.' };
  const goVersion = buf.toString('latin1', v.next, v.next + v.value).trim();
  const m = uvarint(buf, v.next + v.value); if (!m || m.next + m.value > buf.length) return { goVersion, modules: [] };
  let mod = buf.toString('latin1', m.next, m.next + m.value);
  if (mod.length >= 33 && mod[mod.length - 17] === '\n') mod = mod.slice(16, mod.length - 16);   // strip the 16-byte sentinels
  const modules = [];
  let last = null;
  for (const line of mod.split('\n')) {
    const f = line.split('\t');
    if (f[0] === 'dep' && f[1] && f[2]) { last = { path: f[1], version: f[2] }; modules.push(last); }
    else if (f[0] === '=>' && last) {                                    // replace directive: the replacement is what was compiled in
      if (f[1] && f[2]) { last.path = f[1]; last.version = f[2]; } else modules.splice(modules.indexOf(last), 1);
      last = null;
    } else last = null;
  }
  return { goVersion, modules };
}

export function goRecords(info) {
  if (!info || info.unsupported) return [];
  const out = [];
  const goVer = /^go(\d+\.\d+(?:\.\d+)?)/.exec(info.goVersion || '');
  const src = 'Go build info', type = 'go buildinfo';
  if (goVer) out.push(purlRecord({ name: 'Go standard library', version: goVer[1], ecosystem: 'Go', purl: `pkg:golang/stdlib@${goVer[1]}`, source: src, sourceType: type }));
  for (const m of info.modules) {
    if (!m.version || m.version === '(devel)') continue;
    out.push(purlRecord({ name: m.path, version: m.version, ecosystem: 'Go', purl: `pkg:golang/${m.path.split('/').map(encodeURIComponent).join('/')}@${m.version}`, source: src, sourceType: type }));
  }
  return out;
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
