'use strict';
// npm.js — executables that were built from an npm project: vercel/pkg (and @yao-pkg/pkg), Node.js single-executable applications (SEA)
// and Bun `--compile`. Nothing is executed and nothing is extracted to disk.
//
//   pkg          the virtual filesystem is stored verbatim (optionally per-file gzip/brotli): every dependency's package.json is read, so
//                names and versions are exact (confidence high). Files are also handed to the secret scanner, because compression hides
//                them from a plain strings pass.
//   SEA / Bun    the app is one JavaScript bundle. Packages are recognised from the module path comments bundlers leave
//                (`// node_modules/lodash/lodash.js`, webpack/esbuild module keys), versions from a version embedded in the path
//                (pnpm / Deno layouts), an inlined package.json, or a `VERSION = "x.y.z"` constant inside the package's own code. A package
//                whose version is not recoverable stays in the inventory without a lookup (never reported as clean).
//   runtime      the Node.js release URL compiled into every Node binary gives the runtime version (→ NVD CPE nodejs:node.js).
//
// Only the bytes of the packaged application are inventoried: the Node / Bun runtime embeds a few packages of its own (minimatch,
// undici …) and they are not the application's dependencies.

import zlib from 'zlib';
import { asciiStrings } from '../../mobile/lib/strings.js';
import { cRecord, purlRecord, inventoryRecord, npmPurl } from './records.js';
import { imageEnd } from './vmap.js';

const PKG_PRELUDE = Buffer.from('(function(process, require, console, EXECPATH_FD, PAYLOAD_POSITION, PAYLOAD_SIZE)', 'latin1');
const SEA_FUSE = Buffer.from('NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2:', 'latin1');
const SEA_NOTE = Buffer.from('NODE_SEA_BLOB\0', 'latin1');
const SEA_MAGIC = Buffer.from([0x20, 0xda, 0x43, 0x01]);              // 0x143da20, little endian
const BUN_TRAILER = Buffer.from('\n---- Bun! ----\n', 'latin1');

const NPM_NAME = /^(?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*$/i;
const SEMVER = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const MAX_ENTRY_BYTES = 32 * 1024 * 1024;
const MAX_TOTAL_BYTES = 384 * 1024 * 1024;
const REGION_STRINGS = { min: 4, max: 4096, limit: 4000000 };

// ── runtimes ─────────────────────────────────────────────────────────────────────────────────────
/** Node.js version from the release URLs every Node binary carries. */
export function nodeRuntime(buf) {
  const key = Buffer.from('nodejs.org/download/release/v', 'latin1');
  for (let at = buf.indexOf(key); at >= 0; at = buf.indexOf(key, at + key.length)) {
    const m = /^nodejs\.org\/download\/release\/v(\d+\.\d+\.\d+)\/node-v\1(?:\.tar\.gz|-headers\.tar\.gz)/.exec(buf.latin1Slice(at, Math.min(buf.length, at + 120)));
    if (m) return { name: 'Node.js', version: m[1], evidence: m[0] };
  }
  return null;
}
export function bunRuntime(buf) {
  const key = Buffer.from('Bun v', 'latin1');
  for (let at = buf.indexOf(key); at >= 0; at = buf.indexOf(key, at + key.length)) {
    const m = /^Bun v(\d+\.\d+\.\d+) \(/.exec(buf.latin1Slice(at, Math.min(buf.length, at + 40)));
    if (m) return { name: 'Bun', version: m[1], evidence: m[0] };
  }
  return null;
}

// ── pkg ──────────────────────────────────────────────────────────────────────────────────────────
/** Locates and parses a pkg payload: [node binary][payload][prelude = bootstrap + virtual filesystem JSON]. @returns null | {error} | {…} */
export function pkgPayload(buf) {
  const pre = buf.lastIndexOf(PKG_PRELUDE);
  if (pre < 0) return null;
  const tail = buf.toString('utf8', pre);
  const end = /\n\);\s*\}\)\s*$/.exec(tail);
  if (!end) return { error: 'the pkg prelude has an unexpected ending' };
  const parts = tail.slice(0, end.index).split('\n,\n');
  let compress = 0;
  if (parts.length && /^\d$/.test(parts[parts.length - 1].trim())) compress = Number(parts.pop().trim());
  if (parts.length < 4) return { error: 'the pkg prelude has an unexpected layout' };
  const dictText = parts.pop(); parts.pop(); parts.pop();                  // DICT, then SYMLINKS and DEFAULT_ENTRYPOINT (unused)
  // the virtual filesystem is the last line of what precedes them (JSON.stringify never writes a raw newline)
  const before = parts.pop();
  let vfs;
  try { vfs = JSON.parse(before.slice(before.lastIndexOf('\n') + 1)); } catch { return { error: 'the pkg virtual filesystem could not be parsed' }; }
  if (!vfs || typeof vfs !== 'object') return { error: 'the pkg virtual filesystem is empty' };
  // a compressed build replaces every path segment by a short code ("0/1/2/4/5/6"); DICT maps segment → code
  let dict = {};
  try { dict = JSON.parse(dictText) || {}; } catch { /* no dictionary */ }
  if (Object.keys(dict).length) {
    const back = new Map(Object.entries(dict).map(([seg, code]) => [String(code), seg]));
    const decoded = {};
    for (const [k, v] of Object.entries(vfs)) decoded[k.split('/').map(c => (back.has(c) ? back.get(c) : c)).join('/')] = v;
    vfs = decoded;
  }
  let size = 0;
  for (const e of Object.values(vfs)) for (const v of Object.values(e || {})) if (Array.isArray(v) && v.length === 2) size = Math.max(size, v[0] + v[1]);      // blob, content, links and stat stripes
  const start = pre - size;
  if (start < 0 || compress > 2) return { error: 'the pkg payload could not be located' };
  return { vfs, compress, start, end: buf.length, prelude: pre };
}

function stripe(buf, p, entry, key) {
  const s = entry && entry[key];
  if (!Array.isArray(s) || s[1] <= 0) return null;
  const raw = buf.subarray(p.start + s[0], p.start + s[0] + s[1]);
  if (p.compress === 1) return zlib.gunzipSync(raw, { maxOutputLength: MAX_ENTRY_BYTES });
  if (p.compress === 2) return zlib.brotliDecompressSync(raw, { maxOutputLength: MAX_ENTRY_BYTES });
  return raw;
}


function analyzePkg(buf, p, out, name) {
  const failures = [];
  const found = new Map();                       // name@version → record
  const unversioned = new Set();
  let total = 0, project = null;
  const depPath = /node_modules[\\/]((?:@[^\\/]+[\\/])?[^\\/]+)[\\/]package\.json$/;
  for (const [vpath, entry] of Object.entries(p.vfs)) {
    const isPkgJson = /[\\/]package\.json$/.test(vpath);
    const isDep = /[\\/]node_modules[\\/]/.test(vpath);
    try {
      if (isPkgJson) {
        const b = stripe(buf, p, entry, '1') || stripe(buf, p, entry, '0');
        if (!b) continue;
        let json;
        try { json = JSON.parse(b.toString('utf8')); } catch { failures.push(vpath); continue; }
        const m = depPath.exec(vpath);
        if (m) {
          const pkgName = (json && typeof json.name === 'string' && NPM_NAME.test(json.name)) ? json.name : m[1].replace(/\\/g, '/');
          const version = typeof json?.version === 'string' ? json.version : null;
          if (version && SEMVER.test(version)) {
            const k = `${pkgName}@${version}`;
            if (!found.has(k)) found.set(k, purlRecord({ name: pkgName, version, ecosystem: 'npm', purl: npmPurl(pkgName, version), source: 'pkg virtual filesystem', sourceType: 'pkg package.json', evidence: vpath }));
          } else unversioned.add(pkgName);
        } else if (!isDep && (!project || vpath.length < project.path.length)) project = { path: vpath, name: json?.name || null, version: json?.version || null };
        continue;
      }
      // Source / data files go to the secret scanner. A compressed payload is invisible to a plain strings pass, so it is read here; an
      // uncompressed one is covered by the strings of the file itself, but attributing it to its virtual path is more useful.
      if (!/\.(?:[cm]?js|json|ya?ml|env|txt|cfg|conf|ini|properties|xml|html?)$/i.test(vpath) && !/[\\/]\.env/.test(vpath)) continue;
      for (const key of ['0', '1']) {
        const e = entry && entry[key];
        if (!Array.isArray(e) || e[1] <= 0 || e[1] > MAX_ENTRY_BYTES) continue;
        if (total + e[1] > MAX_TOTAL_BYTES) { failures.push(`${vpath} (payload scan budget reached)`); break; }
        const b = stripe(buf, p, entry, key);
        total += b ? b.length : 0;
        if (!b) continue;                                               // V8 bytecode is not text, but its string constants are still readable
        const lines = asciiStrings(b, { min: 8, max: 2048, limit: 50000 });
        if (lines.length) out.sources.push({ path: `${name}!${vpath}`, lines });
      }
    } catch (err) { failures.push(`${vpath} (${String(err.message || err).slice(0, 60)})`); }
  }
  for (const n of unversioned) if (![...found.values()].some(r => r.name === n)) found.set(`${n}@`, inventoryRecord({ name: n, ecosystem: 'npm', source: 'pkg virtual filesystem', sourceType: 'pkg package.json', reason: 'The package.json bundled in the executable has no usable version.', confidence: 'high' }));
  out.records.push(...found.values());
  out.regions.push({ start: p.start, end: p.end });
  out.info.push({ kind: 'pkg', compression: ['none', 'gzip', 'brotli'][p.compress], files: Object.keys(p.vfs).length, packages: [...found.values()].filter(r => r.version).length, project: project ? { name: project.name, version: project.version } : null,
    source_visibility: 'The application is stored as V8 bytecode unless it was built with --no-bytecode; string constants stay readable, logic does not.' });
  if (failures.length) out.gaps.push(`${name}: ${failures.length} file(s) in the pkg payload could not be read (${failures.slice(0, 3).join('; ')}${failures.length > 3 ? '; …' : ''}); their packages and strings were not checked.`);
}

// ── JavaScript bundles (SEA, Bun) ─────────────────────────────────────────────
/** The package a bundler path refers to: the innermost node_modules/<name>/, and a version if the layout (pnpm, Deno) puts one in the path. */
export function packageFromPath(p) {
  const s = String(p).replace(/\\/g, '/');
  const store = /node_modules\/\.(?:pnpm|deno)\/(?:@[^/@]+\+)?[^/@]+@(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+?)?)(?:_[^/]*)?\/node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(s);
  if (store && NPM_NAME.test(store[2]) && SEMVER.test(store[1])) return { name: store[2], version: store[1], from: 'path' };
  let last = null;
  for (const m of s.matchAll(/node_modules\/((?:@[^/]+\/)?[^/.][^/]*)\//g)) last = m[1];
  return last && NPM_NAME.test(last) ? { name: last, version: null, from: null, isPackageJson: /\/package\.json$/.test(s) } : null;
}

const MARKERS = [
  /^\s*\/\/\s*(\S*node_modules\/\S+)\s*$/,                                              // esbuild, Bun:        // node_modules/lodash/lodash.js
  /["'`]((?:\.{1,2}\/)*(?:[\w@.~+-]+\/)*node_modules\/[^"'`\s]+)["'`]\s*(?:\(|:|,|=>)/,   // module keys:  "node_modules/x/y.js"(exports…)   "./node_modules/x/y.js":
  /!\*\*\*\s+(\S*node_modules\/\S+?)\s+\*\*\*!/,                                        // webpack development banner
];
const VERSION_CONST = /\b(?:VERSION|version|__version__|_version|Version)\b["']?\s*[:=]\s*["'](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']/;
const NAME_KEY = /^\s*["']?name["']?\s*:\s*["']([^"']+)["']/;

/** @param {string[]} lines the bundle's text lines, in file order @returns {{name:string, version:string|null, how:string, evidence:string}[]} */
export function bundleInventory(lines) {
  const pkgs = new Map();                                         // name → {versions: Map(version → how), seen}
  const entry = name => { let e = pkgs.get(name); if (!e) pkgs.set(name, e = { versions: new Map(), evidence: new Map() }); return e; };
  let cur = null;                                                  // { name, isPackageJson, nameOk }
  for (const line of lines) {
    if (line.length <= 600 && line.includes('node_modules/')) {
      let path = null;
      for (const re of MARKERS) { const m = re.exec(line); if (m) { path = m[1]; break; } }
      const pk = path ? packageFromPath(path) : null;
      if (pk) {
        const e = entry(pk.name);
        if (pk.version) { e.versions.set(pk.version, 'bundler path'); e.evidence.set(pk.version, path); }
        cur = { name: pk.name, isPackageJson: Boolean(pk.isPackageJson), nameOk: !pk.isPackageJson };
        continue;
      }
    }
    if (!cur) continue;
    const e = pkgs.get(cur.name);
    if (cur.isPackageJson && !cur.nameOk) { const n = NAME_KEY.exec(line); if (n) cur.nameOk = n[1] === cur.name; }
    if (e.versions.size && !cur.isPackageJson) continue;           // a version is known; only an inlined package.json can add the exact one
    if (line.length > 400) continue;
    const v = VERSION_CONST.exec(line);
    if (v && SEMVER.test(v[1])) {
      if (cur.isPackageJson && cur.nameOk) { e.versions.set(v[1], 'inlined package.json'); e.evidence.set(v[1], line.trim()); cur.isPackageJson = false; }
      else if (!cur.isPackageJson && !e.versions.size) { e.versions.set(v[1], 'version constant'); e.evidence.set(v[1], line.trim()); }
    }
  }
  const out = [];
  for (const [name, e] of pkgs) {
    if (!e.versions.size) out.push({ name, version: null, how: 'path only', evidence: '' });
    for (const [version, how] of e.versions) out.push({ name, version, how, evidence: e.evidence.get(version) || '' });
  }
  return out;
}

function bundleRecords(inv, source) {
  return inv.map(x => {
    if (!x.version) return inventoryRecord({ name: x.name, ecosystem: 'npm', source, sourceType: 'npm bundle path marker', reason: 'The bundle shows that this package is included but does not keep its version, so no advisory lookup was possible.', confidence: 'medium' });
    return purlRecord({ name: x.name, version: x.version, ecosystem: 'npm', purl: npmPurl(x.name, x.version), source: `${source} (${x.how})`, sourceType: x.how === 'version constant' ? 'npm version constant' : x.how === 'bundler path' ? 'npm bundle path marker' : 'npm package.json', confidence: x.how === 'version constant' ? 'medium' : 'high', evidence: x.evidence });
  });
}

function scanRegion(buf, start, end, label, out, name) {
  const region = buf.subarray(start, end);
  const lines = asciiStrings(region, REGION_STRINGS);
  const inv = bundleInventory(lines);
  out.records.push(...bundleRecords(inv, label));
  out.regions.push({ start, end });
  const text = lines.filter(l => l.length >= 8);
  if (text.length) out.sources.push({ path: `${name}!${label}`, lines: text });
  if (lines.length >= REGION_STRINGS.limit) out.gaps.push(`${name}: the ${label} has more than ${REGION_STRINGS.limit} strings; the rest were not inventoried or scanned.`);
  return inv;
}

/** Node SEA: the blob is an ELF note named NODE_SEA_BLOB (postject); other formats keep it in a segment/resource that starts with the blob magic. */
export function seaRegion(buf) {
  let enabled = false;
  for (let at = buf.indexOf(SEA_FUSE); at >= 0; at = buf.indexOf(SEA_FUSE, at + 1)) if (buf[at + SEA_FUSE.length] === 0x31) enabled = true;
  if (!enabled) return null;
  for (let at = buf.indexOf(SEA_NOTE); at >= 12; at = buf.indexOf(SEA_NOTE, at + 1)) {
    if (buf.readUInt32LE(at - 12) !== 14) continue;
    const size = buf.readUInt32LE(at - 8), start = at + 16;
    if (size > 0 && start + size <= buf.length && buf.subarray(start, start + 4).equals(SEA_MAGIC)) return { start, end: start + size, how: 'ELF note' };
  }
  const m = buf.lastIndexOf(SEA_MAGIC);
  return m >= 0 ? { start: m, end: buf.length, how: 'resource' } : { start: -1, end: -1, how: 'unlocated' };
}

/** Bun --compile: the module graph sits before a trailer; the size of the graph is the 8 bytes 32 before the trailer. */
export function bunRegion(buf) {
  const t = buf.lastIndexOf(BUN_TRAILER);
  if (t < 0) return null;
  let start = -1;
  if (t >= 48) {
    const n = Number(buf.readBigUInt64LE(t - 32));
    if (n > 0 && n < t && n < 1024 * 1024 * 1024) start = Math.max(0, t - 48 - n - 4096);
  }
  if (start < 0) { const ie = imageEnd(buf); start = ie > 0 && ie < t ? ie : Math.max(0, t - 256 * 1024 * 1024); }
  return { start, end: buf.length };
}

/**
 * @returns {{records:object[], sources:{path:string,lines:string[]}[], regions:{start:number,end:number}[], gaps:string[], notes:string[], info:object[], runtimes:object[]}}
 * `regions` are byte ranges that were read here (the caller leaves them out of its own string pass); `sources` go to the secret scanner.
 */
export function analyzeNpm(buf, { name = 'binary' } = {}) {
  const out = { records: [], sources: [], regions: [], gaps: [], notes: [], info: [], runtimes: [] };
  const bun = bunRuntime(buf), node = bun ? null : nodeRuntime(buf);
  if (node) {
    out.runtimes.push(node);
    out.records.push(cRecord({ name: node.name, version: node.version, vendor: 'nodejs', product: 'node.js', evidence: node.evidence, source: 'embedded Node.js release URL', sourceType: 'node runtime banner', ecosystem: 'Node.js runtime' }));
  }
  if (bun) out.runtimes.push(bun);

  const pkg = pkgPayload(buf);
  if (pkg && pkg.error) out.gaps.push(`${name}: looks like a pkg executable but ${pkg.error}; bundled npm packages were not read.`);
  else if (pkg) analyzePkg(buf, pkg, out, name);

  if (!pkg) {
    const sea = seaRegion(buf);
    if (sea) {
      if (sea.start < 0) out.gaps.push(`${name}: a Node.js single-executable application, but its blob could not be located; bundled npm packages were not read.`);
      else { const inv = scanRegion(buf, sea.start, sea.end, 'Node SEA blob', out, name); out.info.push({ kind: 'node-sea', blob_bytes: sea.end - sea.start, packages: inv.filter(x => x.version).length, unversioned_packages: inv.filter(x => !x.version).length }); }
    }
    const bn = !sea && bunRegion(buf);
    if (bn) { const inv = scanRegion(buf, bn.start, bn.end, 'Bun module graph', out, name); out.info.push({ kind: 'bun-compile', packages: inv.filter(x => x.version).length, unversioned_packages: inv.filter(x => !x.version).length }); }
  }
  if (out.info.length && node) out.info[0].node_version = node.version;
  if (out.info.some(i => i.unversioned_packages)) out.notes.push(`${name}: some bundled npm packages are only visible by path (the bundler dropped their versions); they are listed in the Dependencies tab but could not be checked against OSV.dev. Build with a bundler setting that keeps package.json versions, or scan the project with ubel-npm.`);
  return out;
}
