'use strict';
// npm.js — executables that were built from an npm project: vercel/pkg (and @yao-pkg/pkg), Node.js single-executable applications (SEA)
// and Bun `--compile`. Nothing is executed and nothing is extracted to disk.
//
//   pkg          the virtual filesystem is stored verbatim (optionally per-file gzip/brotli): every dependency's package.json is read, so
//                names and versions are exact (confidence high). Files are also handed to the secret scanner, because compression hides
//                them from a plain strings pass.
//   SEA / Bun    the app is one JavaScript bundle. Packages are recognised from the module path comments bundlers leave
//                (`// node_modules/lodash/lodash.js`, webpack/esbuild module keys), versions from a version embedded in the path
//                (pnpm / Deno layouts), an inlined package.json, or a `VERSION = "x.y.z"` constant inside the package's own code. When
//                the bundler stripped those too, licence banners, package metadata literals, client identifiers and esbuild's
//                `/*! Bundled license information:` block still name the packages (without versions); those become inventory records.
//                A package whose version is not recoverable stays in the inventory without a lookup (never reported as clean).
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

// Minifiers keep the module paths bundlers use as object keys (esbuild: `__commonJS({"node_modules/ms/index.js"(e,t){…}})`) but drop the
// comments, and put the whole bundle on a handful of lines of megabytes each. Those lines are searched for every key, and the text up to
// the next key is the module's body.
const LONG_KEYS = [
  /["'`]((?:\.{1,2}\/)*(?:[\w@.~+-]+\/)*node_modules\/[^"'`\s]+)["'`]\s*(?:\(|:|,|=>|\[)/g,                // "node_modules/x/y.js"(e,t){  /  "node_modules/x/y.js":
  /\/\*+!?\s*\*{0,3}\s*((?:\S*\/)?node_modules\/[^\s*]+?)\s*\*{0,3}\s*\*\//g,                        // /*** ./node_modules/x/y.js ***/   /* node_modules/x/y.js */
  /\/\/\s*(\S*node_modules\/\S+?)(?=\s|$|["'`])/g,                                              // // node_modules/x/y.js   (kept after a minified statement)
];
const LONG_SEGMENT = 3000;                                      // characters of a module body searched for its version constant
const LONG_VERSION = /\b(?:VERSION|version|__version__|_version|Version)\b["']?\s*[:=]\s*["'](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']/;

/** @param {string[]} lines the bundle's text lines, in file order @returns {{name:string, version:string|null, how:string, evidence:string}[]} */
export function bundleInventory(lines) {
  const pkgs = new Map();                                         // name → {versions: Map(version → how), seen}
  const entry = name => { let e = pkgs.get(name); if (!e) pkgs.set(name, e = { versions: new Map(), evidence: new Map() }); return e; };
  let cur = null;                                                  // { name, isPackageJson, nameOk }

  // a module body (one line, or the stretch of a long line up to the next module key) → its version
  const readBody = (text) => {
    if (!cur) return;
    const e = pkgs.get(cur.name);
    if (cur.isPackageJson && !cur.nameOk) { const n = NAME_KEY.exec(text) || /\bname\s*:\s*["']([^"']+)["']/.exec(text); if (n) cur.nameOk = n[1] === cur.name; }
    if (e.versions.size && !cur.isPackageJson) return;             // a version is known; only an inlined package.json can add the exact one
    const v = LONG_VERSION.exec(text);
    if (v && SEMVER.test(v[1])) {
      if (cur.isPackageJson && cur.nameOk) { e.versions.set(v[1], 'inlined package.json'); e.evidence.set(v[1], text.slice(Math.max(0, v.index - 40), v.index + v[0].length + 20).trim()); cur.isPackageJson = false; }
      else if (!cur.isPackageJson && !e.versions.size) { e.versions.set(v[1], 'version constant'); e.evidence.set(v[1], text.slice(Math.max(0, v.index - 40), v.index + v[0].length + 20).trim()); }
    }
  };
  const open = path => {
    const pk = path ? packageFromPath(path) : null;
    if (!pk) return false;
    const e = entry(pk.name);
    if (pk.version) { e.versions.set(pk.version, 'bundler path'); e.evidence.set(pk.version, path); }
    cur = { name: pk.name, isPackageJson: Boolean(pk.isPackageJson), nameOk: !pk.isPackageJson };
    return true;
  };

  for (const line of lines) {
    if (!line.includes('node_modules/')) { if (cur && line.length <= 400) readBody(line); continue; }
    if (line.length <= 600) {
      let path = null;
      for (const re of MARKERS) { const m = re.exec(line); if (m) { path = m[1]; break; } }
      if (open(path)) continue;
      if (cur && line.length <= 400) readBody(line);
      continue;
    }
    // long line: every module key in it, in order
    const hits = [];
    for (const re of LONG_KEYS) for (const m of line.matchAll(re)) hits.push({ at: m.index, end: m.index + m[0].length, path: m[1] });
    hits.sort((a, b) => a.at - b.at);
    if (cur) readBody(line.slice(0, Math.min(hits.length ? hits[0].at : line.length, LONG_SEGMENT)));
    let last = -1;
    for (let i = 0; i < hits.length; i++) {
      const h = hits[i];
      if (h.at < last) continue;                                   // two patterns matched the same key
      last = h.end;
      if (!open(h.path)) continue;
      readBody(line.slice(h.end, Math.min(i + 1 < hits.length ? hits[i + 1].at : line.length, h.end + LONG_SEGMENT)));
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
    if (!x.version && x.how === 'declared dependency') {
      return inventoryRecord({ name: x.name, ecosystem: 'npm', source, sourceType: 'npm declared dependency', confidence: 'medium',
        reason: `The package.json embedded in the bundle declares this dependency as "${x.range}". A declared range is not the installed version, so no advisory lookup was possible. Confirm the version from the project's lockfile / SBOM.` });
    }
    if (!x.version) {
      const type = x.how === 'licence banner' ? 'npm licence banner' : x.how === 'client identifier' ? 'npm client identifier' : 'npm bundle path marker';
      const reason = x.how === 'licence banner'
        ? `The bundle shows this package is included (its licence banner survived minification), but no version is in the bundle, so no advisory lookup was possible. Confirm the version by inspecting the bundled code, or from the project's lockfile / SBOM.`
        : x.how === 'client identifier'
          ? `The bundle contains a client identifier "${x.name}/…" but nothing to confirm it refers to the npm package, so no advisory lookup was made.`
          : `The bundle shows that this package is included but does not keep its version, so no advisory lookup was possible.`;
      return inventoryRecord({ name: x.name, ecosystem: 'npm', source, sourceType: type, reason, confidence: x.how === 'licence banner' ? 'low' : 'medium' });
    }
    return purlRecord({ name: x.name, version: x.version, ecosystem: 'npm', purl: npmPurl(x.name, x.version), source: `${source} (${x.how})`, sourceType: x.how === 'version constant' ? 'npm version constant' : x.how === 'bundler path' ? 'npm bundle path marker' : x.how === 'licence banner' ? 'npm licence banner' : (x.how === 'metadata literal' || x.how === 'loose metadata literal') ? 'npm package metadata literal' : x.how === 'client identifier' ? 'npm client identifier' : 'npm package.json', confidence: (x.how === 'licence banner' || x.how === 'client identifier' || x.how === 'loose metadata literal') ? 'low' : x.how === 'metadata literal' ? 'medium' : x.how === 'version constant' ? 'medium' : 'high', evidence: x.evidence });
  });
}

// ── bundles whose module paths were stripped ───────────────────────────────────────────────────
// A minified, scope-hoisted bundle has no node_modules/ paths left. What survives is what minifiers are told to keep: licence banners
// (`/*! axios v1.6.0 | MIT */`, `/** @license React v18.2.0`), esbuild's `/*! Bundled license information: … */` block, and the URLs
// inside library error messages. Banners give a name and a version (low confidence: the banner names the project, which is usually but not
// always the npm package); the esbuild block gives a name and a path (no version); URLs only hint at names.
const BANNER = /(?:\/\*[!*]+|\/\/!|@license|@preserve)\s*(?:\*\s*)?(?:@license\s+|@preserve\s+)?(@[a-z0-9][\w.~-]*\/[a-z0-9][\w.~-]*|[A-Za-z][\w.~-]*)\s+v?(\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)(?![\w.])/g;
const BANNER_STOP = new Set(['copyright', 'license', 'licence', 'version', 'mit', 'bsd', 'apache', 'isc', 'released', 'under', 'the', 'this', 'for', 'by', 'v', 'http', 'https', 'node', 'nodejs', 'ecmascript', 'es', 'api', 'sdk']);
const NAME_RE = '((?:@[a-z0-9][\\w.~-]*\\/)?[a-z0-9][\\w.~-]*)', SEMVER_RE = '(\\d+\\.\\d+\\.\\d+(?:-[0-9A-Za-z.-]+)?)';
// a package.json-shaped literal that survived minification: {name:"x",version:"1.2.3"} (either order, quoted or not)
const META_LITERAL = [new RegExp(`["']?name["']?\\s*:\\s*["']${NAME_RE}["']\\s*,\\s*["']?version["']?\\s*:\\s*["']${SEMVER_RE}["']`, 'gi'), new RegExp(`["']?version["']?\\s*:\\s*["']${SEMVER_RE}["']\\s*,\\s*["']?name["']?\\s*:\\s*["']${NAME_RE}["']`, 'gi')];
// the same two fields with other keys in between (description, main, license …), still inside one object literal
const META_LOOSE = [new RegExp(`["']?name["']?\\s*:\\s*["']${NAME_RE}["'][^{}]{1,400}?["']?version["']?\\s*:\\s*["']${SEMVER_RE}["']`, 'gi'), new RegExp(`["']?version["']?\\s*:\\s*["']${SEMVER_RE}["'][^{}]{1,400}?["']?name["']?\\s*:\\s*["']${NAME_RE}["']`, 'gi')];
// a client identifier that is the whole string literal: "axios/1.6.0"
const CLIENT_ID = new RegExp(`["'\`]${NAME_RE}\\/${SEMVER_RE}["'\`]`, 'g');
const ID_STOP = new Set(['node', 'nodejs', 'mozilla', 'chrome', 'chromium', 'safari', 'firefox', 'edge', 'windows', 'linux', 'darwin', 'win32', 'openssl', 'curl', 'http', 'https', 'v8', 'electron', 'bun', 'deno', 'android', 'ios', 'macos']);
// The application's own package.json survives minification as a literal: {name:"app",version:"1.0.0",…,dependencies:{lodash:"^4.18.1",…}}.
// Its `dependencies` are what the bundler pulled in, but they are declared RANGES, not installed versions: names only, never a lookup.
const DEPS_OBJ = /[{,]\s*[\"']?(dependencies|optionalDependencies)[\"']?\s*:\s*\{([^{}]{2,6000})\}/g;
const DEP_ENTRY = new RegExp(`[\"']?${NAME_RE}[\"']?\\s*:\\s*[\"']([^\"']{1,80})[\"']`, 'g');
const DEP_RANGE = /^(?:[\^~<>=vV*xX\d][\w.+\-^~<>=|* ]*|latest|workspace:.*|npm:.*|file:.*|git[+:].*|https?:.*)$/;
function declaredDependencies(line) {
  const deps = []; let self = null;
  for (const m of line.matchAll(DEPS_OBJ)) {
    const entries = [...m[2].matchAll(DEP_ENTRY)];
    if (!entries.length || entries.some(e => !DEP_RANGE.test(e[2]))) continue;           // not a manifest
    let own = null;
    for (const n of line.slice(Math.max(0, m.index - 8000), m.index).matchAll(/[\"']?name[\"']?\s*:\s*[\"']([^\"']+)[\"']\s*,\s*[\"']?version[\"']?\s*:/g)) own = n[1];
    if (own) self = own.toLowerCase();
    for (const e of entries) if (NPM_NAME.test(e[1])) deps.push({ name: e[1].toLowerCase(), range: e[2] });
  }
  return { deps, self };
}
const REPO_URL = /github\.com\/([\w.-]+)\/([\w.-]+)\/(?:wiki|issues|blob|tree|pull|releases|discussions)\b/g;

// esbuild --legal-comments=inline. Two shapes exist in the wild, sometimes in the same bundle:
//   /*! Bundled license information: <path1> */
//   /*! Bundled license information: <path2> */              ← one path per line, everything on the same line as the prefix
// and
//   /*! Bundled license information:
//   <path1>:
//     * (license)
//   */                                                         ← one path per line, prefix on its own line
// Both must be handled: the path can be on the same line as the phrase, or on the line after it. A path may end with a file extension
// (`pkg/lib/index.js`) or be a directory (`pkg/lib/`), or have neither (`pkg/lib`).
const LEGAL_START = /Bundled license information:?/i;
const PKG_INTERNAL_DIRS = new Set(['lib', 'dist', 'src', 'es', 'esm', 'cjs', 'umd', 'build', 'out']);
const APP_DIRS = new Set(['src', 'app', 'apps', 'test', 'tests', 'spec', 'specs', 'example', 'examples', 'docs', 'scripts', 'bin', 'config',
  'components', 'pages', 'routes', 'views', 'layouts', 'hooks', 'utils', 'helpers', 'types', 'server', 'client', 'shared', 'common',
  'fixtures', 'mocks', '__mocks__', '__tests__', 'coverage']);

/** From one path-like token, the package name it belongs to, or null when it is clearly an application file rather than a package. */
function packageFromLegalPath(path) {
  const p = String(path).replace(/\\/g, '/');
  if (p.includes('node_modules/')) {
    const nm = /node_modules\/((?:@[^/]+\/)?[^/]+)\//.exec(p);
    return nm ? nm[1] : null;
  }
  const parts = p.split('/').filter(Boolean);
  if (parts.length < 1) return null;
  if (parts[0].startsWith('@')) return parts.length >= 2 ? `${parts[0]}/${parts[1]}` : null;
  if (parts.length === 1) return null;
  if (APP_DIRS.has(parts[0]) || (parts.length >= 2 && APP_DIRS.has(parts[1]))) return null;
  if (PKG_INTERNAL_DIRS.has(parts[1]) || /\.(?:[cm]?[jt]sx?|json)$/.test(parts[1])) return parts[0];
  return null;
}

// core-js (2.x) and babel-polyfill describe themselves as `module.exports = {version: "X.Y.Z"}`.
// The shape is specific enough to record the version, but not the name — the caller puts these in a note, not a package record.
const SELF_DESC_VERSION = /(?:module\.)?exports?\s*=\s*\{\s*version\s*:\s*["'](\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?)["']\s*\}/g;

// One path-like token inside a legal-comment line: `pkg/lib/index.js`, `pkg/lib/`, `@scope/pkg/dist/x.js`. Group 1 is the candidate
// package name, group 2 the rest of the path (with or without a trailing slash). Deliberately permissive: `packageFromLegalPath` does the
// filtering, so a path without an extension is accepted here and rejected there only if it also names an app directory.
const LEGAL_PATH_TOKEN = /(?<![\w./@-])((?:@[a-z0-9][\w.~-]*\/)?[a-z0-9][\w.~-]*)\/([a-z0-9][\w.~-]*(?:\/[\w.~-]+)*\/?)(?=[\s:*<>"'`]|$)/gi;

function extractPackagePaths(text) {
  const results = [];
  if (!text || text.length < 4) return results;
  for (const m of text.matchAll(LEGAL_PATH_TOKEN)) {
    const full = `${m[1]}/${m[2]}`;
    if (full.length > 200 || full.includes('node_modules/')) continue;
    const name = packageFromLegalPath(full);
    if (name) results.push({ name, path: full });
  }
  return results;
}

/** Merges the path-based and the fallback inventories: same name, prefer the entry with a version, then the higher-ranked source. */
function mergeInventories(pathInv, fallbackPkgs) {
  const rank = { 'metadata literal': 5, 'loose metadata literal': 4, 'bundler path': 4, 'inlined package.json': 4, 'version constant': 3, 'client identifier': 2, 'declared dependency': 2, 'licence banner': 1, 'path only': 0 };
  const by = new Map();
  for (const x of [...pathInv, ...fallbackPkgs]) {
    const key = x.name.toLowerCase();
    const cur = by.get(key);
    if (!cur) { by.set(key, x); continue; }
    if (!cur.version && x.version) { by.set(key, x); continue; }
    if (cur.version && !x.version) continue;
    if ((rank[x.how] || 0) > (rank[cur.how] || 0)) by.set(key, x);
  }
  return [...by.values()];
}

/** @param {string[]} lines @returns {{packages:{name:string, version:string|null, how:string, evidence:string}[], repos:string[], unattributedVersions:string[]}} */
export function fallbackInventory(lines) {
  const packages = new Map(), repos = new Set(), unattributedVersions = new Set();
  let inLegalBlock = false, legalBlockLines = 0;
  const record = (name, path) => {
    if (!packages.has(`${name}@`) && packages.size < 500) packages.set(`${name}@`, { name, version: null, how: 'licence banner', evidence: path });
  };
  for (const line of lines) {
    if (line.length < 4) continue;

    // esbuild legal comment: the phrase may share a line with the path, or stand on its own with paths on the following lines.
    const hasLegal = LEGAL_START.test(line);
    if (hasLegal) {
      // Paths on the SAME line as the phrase (the format this bundle uses, and also `/*! Bundled license information: pkg/lib/x.js */`).
      const after = line.replace(LEGAL_START, '').replace(/\s*\*\/.*$/, '');
      for (const { name, path } of extractPackagePaths(after)) record(name, path);
      inLegalBlock = true;
      legalBlockLines = 0;
    } else if (inLegalBlock) {
      if (++legalBlockLines > 200) inLegalBlock = false;
      // Paths on their own line (the multi-line esbuild format, one path per line, followed by license text).
      else for (const { name, path } of extractPackagePaths(line)) record(name, path);
    }

    if (line.length < 12) continue;

    // self-describing version constants without a name (core-js 2.x, babel-polyfill): reported as a note, never as a package record
    if (line.includes('version')) for (const m of line.matchAll(SELF_DESC_VERSION)) if (unattributedVersions.size < 50) unattributedVersions.add(m[1]);

    if (line.includes('/*') || line.includes('//!') || line.includes('@license') || line.includes('@preserve')) {
      for (const m of line.matchAll(BANNER)) {
        const name = m[1].toLowerCase();
        if (BANNER_STOP.has(name) || !NPM_NAME.test(name) || !SEMVER.test(m[2])) continue;
        const k = `${name}@${m[2]}`;
        if (!packages.has(k)) packages.set(k, { name, version: m[2], how: 'licence banner', evidence: line.slice(Math.max(0, m.index), m.index + 100).trim() });
        if (packages.size >= 500) break;
      }
    }
    if (line.includes('dependencies')) {
      const d = declaredDependencies(line);
      for (const { name, range } of d.deps) {
        const cur = packages.get(`${name}@`);
        if ((!cur || cur.how === 'licence banner') && packages.size < 500) packages.set(`${name}@`, { name, version: null, how: 'declared dependency', range, evidence: `dependencies: ${name}@${range}` });
      }
    }
    if (line.includes('version')) {
      for (const [i, re] of META_LITERAL.entries()) for (const m of line.matchAll(re)) {
        const name = (i === 0 ? m[1] : m[2]).toLowerCase(), version = i === 0 ? m[2] : m[1];
        if (BANNER_STOP.has(name) || ID_STOP.has(name) || !NPM_NAME.test(name) || !SEMVER.test(version) || name.length < 2) continue;
        const k = `${name}@${version}`;
        if (!packages.has(k) && packages.size < 500) packages.set(k, { name, version, how: 'metadata literal', evidence: line.slice(Math.max(0, m.index), m.index + 100) });
      }
    }
    if (line.includes('version')) {
      for (const [i, re] of META_LOOSE.entries()) for (const m of line.matchAll(re)) {
        const name = (i === 0 ? m[1] : m[2]).toLowerCase(), version = i === 0 ? m[2] : m[1];
        if (BANNER_STOP.has(name) || ID_STOP.has(name) || !NPM_NAME.test(name) || !SEMVER.test(version) || name.length < 2) continue;
        const k = `${name}@${version}`;
        if (!packages.has(k) && packages.size < 500) packages.set(k, { name, version, how: 'loose metadata literal', evidence: line.slice(Math.max(0, m.index), m.index + 100) });
      }
    }
    if (line.includes('/')) {
      for (const m of line.matchAll(CLIENT_ID)) {
        const name = m[1].toLowerCase();
        if (ID_STOP.has(name) || BANNER_STOP.has(name) || name.length < 3 || !NPM_NAME.test(name)) continue;
        const k = `${name}@${m[2]}`;
        if (!packages.has(k) && packages.size < 500) packages.set(k, { name, version: m[2], how: 'client identifier', evidence: line.slice(Math.max(0, m.index), m.index + 100) });
      }
    }
    if (repos.size < 200 && line.includes('github.com/')) for (const m of line.matchAll(REPO_URL)) repos.add(`${m[1]}/${m[2].replace(/\.$/, '')}`);
  }
  return { packages: [...packages.values()], repos: [...repos], unattributedVersions: [...unattributedVersions] };
}

function scanRegion(buf, start, end, label, out, name) {
  const region = buf.subarray(start, end);
  const lines = asciiStrings(region, REGION_STRINGS);
  // The inventory reads whole lines: a minified bundle is a few multi-megabyte lines, and cutting them every 4096 characters would split
  // module keys and detach version constants from their module.
  const whole = asciiStrings(region, { min: 4, max: 64 * 1024 * 1024, limit: REGION_STRINGS.limit });

  // Path-based inventory first; banner / metadata / licence-block inventory second; merged, not either-or.
  const pathInv = bundleInventory(whole);
  const fallback = fallbackInventory(whole);
  const inv = mergeInventories(pathInv, fallback.packages);

  out.records.push(...bundleRecords(inv, label));
  out.regions.push({ start, end });
  const text = lines.filter(l => l.length >= 8);
  if (text.length) out.sources.push({ path: `${name}!${label}`, lines: text });
  if (lines.length >= REGION_STRINGS.limit) out.gaps.push(`${name}: the ${label} has more than ${REGION_STRINGS.limit} strings; the rest were not inventoried or scanned.`);

  const kb = Math.round((end - start) / 1024);
  if (!pathInv.length && end - start >= 256 * 1024) {
    if (!fallback.packages.length && !fallback.repos.length) {
      out.notes.push(`${name}: no node_modules module paths were found in the ${label} (${kb} KB), and neither licence banners nor package metadata literals survived minification. The bundled npm packages are not in the inventory. For a complete list, build with module paths kept (esbuild/webpack without path stripping, or a metafile / SBOM) or scan the project with ubel-npm.`);
    } else {
      out.notes.push(`${name}: no node_modules module paths were found in the ${label} (${kb} KB): the bundler minified or hoisted them away, so the bundled npm packages cannot be listed completely. ` +
        `${fallback.packages.length} package(s) were identified from licence banners, package metadata literals and client identifiers that survived minification (${fallback.packages.slice(0, 6).map(p => p.version ? `${p.name}@${p.version}` : p.name).join(', ')}${fallback.packages.length > 6 ? ', …' : ''}); these are name matches on text, so confirm each against the npm package; a metadata literal can also be the application's own manifest rather than a dependency. Packages without a banner are missing from the inventory. ` +
        (fallback.repos.length ? `Repository URLs inside the bundle point to: ${fallback.repos.slice(0, 12).join(', ')}${fallback.repos.length > 12 ? ', …' : ''} (names only, no versions). ` : '') +
        'For a complete list, build with module paths kept (esbuild/webpack without path stripping, or a metafile / SBOM) or scan the project with ubel-npm.');
    }
  } else if (pathInv.length && fallback.packages.length) {
    // Both inventories found something; only surface the additions the path walker missed
    const fromFallback = fallback.packages.filter(p => !pathInv.some(pi => pi.name.toLowerCase() === p.name.toLowerCase()));
    if (fromFallback.length) {
      out.notes.push(`${name}: ${fromFallback.length} additional package(s) were identified from licence banners, package metadata literals and client identifiers that survived minification (${fromFallback.slice(0, 6).map(p => p.version ? `${p.name}@${p.version}` : p.name).join(', ')}${fromFallback.length > 6 ? ', …' : ''}); these are name matches on text, so confirm each against the npm package.`);
    }
  }
  if (fallback.unattributedVersions.length) {
    out.notes.push(`${name}: ${fallback.unattributedVersions.length} self-describing version constant(s) without a package name were found (${fallback.unattributedVersions.slice(0, 8).join(', ')}); these are likely libraries like core-js or babel-polyfill whose name is not in the bundle — confirm what they belong to.`);
  }
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
      else { const inv = scanRegion(buf, sea.start, sea.end, 'Node SEA blob', out, name); out.info.push({ kind: 'node-sea', blob_bytes: sea.end - sea.start, packages: inv.filter(x => x.version).length, unversioned_packages: inv.filter(x => !x.version).length, node_version: node.version }); }
    }
    const bn = !sea && bunRegion(buf);
    if (bn) { const inv = scanRegion(buf, bn.start, bn.end, 'Bun module graph', out, name); out.info.push({ kind: 'bun-compile', packages: inv.filter(x => x.version).length, unversioned_packages: inv.filter(x => !x.version).length }); }
  }
  if (out.info.length && node) out.info[0].node_version = node.version;
  if (out.info.some(i => i.unversioned_packages)) out.notes.push(`${name}: some bundled npm packages are only visible by path (the bundler dropped their versions); they are listed in the Dependencies tab but could not be checked against OSV.dev. Build with a bundler setting that keeps package.json versions, or scan the project with ubel-npm.`);
  return out;
}