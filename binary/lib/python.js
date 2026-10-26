'use strict';
// python.js — executables built from a Python project.
//   PyInstaller (one-file / one-dir bootloader + archive): the archive ("CArchive": entries + a trailer holding the table of contents) is read
//   structurally. Its entries are decompressed in memory (nothing is written to disk) and used for:
//     • embedded shared libraries (libssl, libcrypto, libz, libsqlite3, libpython …): C/C++ version banners → NVD, as for any native file;
//     • dist-info / egg-info metadata bundled as data: exact package names and versions → OSV.dev (PyPI);
//     • the compressed module archive (PYZ): `<package>.__version__`-style modules give a version where no metadata was bundled
//       (confidence medium); every module's string constants go to the secret scanner (a compressed archive hides them from a strings pass);
//     • the interpreter version (table-of-contents header, then the libpython banner) → NVD CPE python:python.
//   Nuitka, cx_Freeze, py2exe, PyOxidizer: recognised by their own markers and reported as not inventoried (their payloads are compressed
//   with codecs this module does not carry, or are not stored inside the executable), which is a coverage gap, never a clean result.
// Encrypted PYZ archives (PyInstaller < 6 with --key) cannot be read and are reported as a gap.

import zlib from 'zlib';
import { asciiStrings } from '../../mobile/lib/strings.js';
import { detectBanners } from './components.js';
import { cRecord, purlRecord, inventoryRecord, pypiPurl, normalisePypi } from './records.js';

const MAGIC = Buffer.from([0x4d, 0x45, 0x49, 0x0c, 0x0b, 0x0a, 0x0b, 0x0e]);
const MAX_ENTRY_BYTES = 64 * 1024 * 1024;
// Marshalled code keeps names (`socket`, `subprocess`, `ctypes`) as short strings; the secret scanner's 8-character minimum would drop them.
const NAME_STRINGS = { min: 4, max: 64, limit: 20000 };
const MAX_TOTAL_BYTES = 512 * 1024 * 1024;
const MAX_TOC_BYTES = 64 * 1024 * 1024;

// Python standard-library top-level modules (3.12): a `__version__` in one of them (json, csv …) is not a PyPI package.
const STDLIB = new Set(('__future__ abc aifc antigravity argparse array ast asynchat asyncio asyncore atexit audioop base64 bdb binascii bisect builtins bz2 cProfile calendar cgi cgitb chunk cmath cmd code codecs codeop collections colorsys compileall concurrent configparser contextlib contextvars copy copyreg crypt csv ctypes curses dataclasses datetime dbm decimal difflib dis distutils doctest email encodings ensurepip enum errno faulthandler fcntl filecmp fileinput fnmatch fractions ftplib functools gc genericpath getopt getpass gettext glob graphlib grp gzip hashlib heapq hmac html http idlelib imaplib imghdr imp importlib inspect io ipaddress itertools json keyword lib2to3 linecache locale logging lzma mailbox mailcap marshal math mimetypes mmap modulefinder msilib msvcrt multiprocessing netrc nis nntplib nt ntpath nturl2path numbers opcode operator optparse os ossaudiodev pathlib pdb pickle pickletools pipes pkgutil platform plistlib poplib posix posixpath pprint profile pstats pty pwd py_compile pyclbr pydoc pydoc_data pyexpat queue quopri random re readline reprlib resource rlcompleter runpy sched secrets select selectors shelve shlex shutil signal site smtpd smtplib sndhdr socket socketserver spwd sqlite3 sre_compile sre_constants sre_parse ssl stat statistics string stringprep struct subprocess sunau symtable sys sysconfig syslog tabnanny tarfile telnetlib tempfile termios textwrap this threading time timeit tkinter token tokenize tomllib trace traceback tracemalloc tty turtle turtledemo types typing unicodedata unittest urllib uu uuid venv warnings wave weakref webbrowser winreg winsound wsgiref xdrlib xml xmlrpc zipapp zipfile zipimport zlib zoneinfo').split(' '));
const PYINSTALLER_INTERNAL = /^(?:PyInstaller|pyimod\d*|pyi_rth|pyiboot)/;

// import name → PyPI distribution, where they differ
const DIST_NAMES = { yaml: 'PyYAML', _yaml: 'PyYAML', PIL: 'Pillow', cv2: 'opencv-python', bs4: 'beautifulsoup4', sklearn: 'scikit-learn', skimage: 'scikit-image', dateutil: 'python-dateutil',
  OpenSSL: 'pyOpenSSL', Crypto: 'pycryptodome', Cryptodome: 'pycryptodomex', jwt: 'PyJWT', attr: 'attrs', docx: 'python-docx', serial: 'pyserial', usb: 'pyusb', zmq: 'pyzmq',
  MySQLdb: 'mysqlclient', magic: 'python-magic', dns: 'dnspython', nacl: 'PyNaCl', socks: 'PySocks', pkg_resources: 'setuptools', markdown: 'Markdown', jinja2: 'Jinja2', flask: 'Flask',
  werkzeug: 'Werkzeug', markupsafe: 'MarkupSafe', itsdangerous: 'itsdangerous', psycopg2: 'psycopg2', lxml: 'lxml', Xlib: 'python-xlib', ldap: 'python-ldap', git: 'GitPython', gi: 'PyGObject' };
const VERSION_MODULES = ['__version__', '_version', 'version', '__about__', '_metadata', '_ver'];

// ── marshal (the subset a PYZ table of contents uses) ────────────────────────────────────────────
function unmarshal(buf, start = 0) {
  let p = start;
  const refs = [];
  const u32 = () => { const v = buf.readUInt32LE(p); p += 4; return v; };
  const read = (depth = 0) => {
    if (depth > 8 || p >= buf.length) throw new Error('marshal: too deep or truncated');
    const code = buf[p++], flag = code & 0x80, t = String.fromCharCode(code & 0x7f);
    let slot = -1;
    if (flag) { slot = refs.length; refs.push(undefined); }
    const put = v => { if (slot >= 0) refs[slot] = v; return v; };
    switch (t) {
      case '0': return null;
      case 'N': return put(null);
      case 'T': return put(true);
      case 'F': return put(false);
      case 'i': { const v = buf.readInt32LE(p); p += 4; return put(v); }
      case 'I': { const v = Number(buf.readBigInt64LE(p)); p += 8; return put(v); }
      case 'l': { const n = buf.readInt32LE(p); p += 4; const cnt = Math.abs(n); let v = 0; for (let i = 0; i < cnt; i++) { v += buf.readUInt16LE(p) * 2 ** (15 * i); p += 2; } return put(n < 0 ? -v : v); }
      case 's': case 'u': case 't': case 'a': case 'A': { const n = u32(); if (p + n > buf.length) throw new Error('marshal: truncated string'); const v = buf.toString(t === 's' ? 'latin1' : 'utf8', p, p + n); p += n; return put(v); }
      case 'z': case 'Z': { const n = buf[p++]; const v = buf.toString('latin1', p, p + n); p += n; return put(v); }
      case ')': { const n = buf[p++]; const v = []; put(v); for (let i = 0; i < n; i++) v.push(read(depth + 1)); return v; }
      case '(': case '[': { const n = u32(); if (n > 5e6) throw new Error('marshal: oversized sequence'); const v = []; put(v); for (let i = 0; i < n; i++) v.push(read(depth + 1)); return v; }
      case '{': { const m = new Map(); put(m); for (;;) { const k = read(depth + 1); if (k === null && buf[p - 1] === 0x30) break; m.set(k, read(depth + 1)); } return m; }
      case 'r': { const i = u32(); return refs[i]; }
      default: throw new Error(`marshal: unsupported type ${t}`);
    }
  };
  return read();
}

// ── CArchive ─────────────────────────────────────────────────────────────────────────────────────
/** @returns null | {start, cookie, end, pyvers, pylib, toc:[{name,pos,len,ulen,cflag,type}]} | {error} */
export function readCArchive(buf) {
  let tried = 0;
  for (let at = buf.lastIndexOf(MAGIC); at >= 0 && tried < 8; at = at > 0 ? buf.lastIndexOf(MAGIC, at - 1) : -1, tried++) {
    for (const size of [88, 24]) {                                  // cookie v2.1 (with the libpython name) and v2.0
      if (at + size > buf.length) continue;
      const pkgLen = buf.readUInt32BE(at + 8), tocPos = buf.readUInt32BE(at + 12), tocLen = buf.readInt32BE(at + 16), pyvers = buf.readInt32BE(at + 20);
      const end = at + size, start = end - pkgLen;
      if (start < 0 || tocLen <= 0 || tocLen > MAX_TOC_BYTES || tocPos + tocLen > pkgLen || pyvers < 20 || pyvers > 999) continue;
      const pylib = size === 88 ? buf.toString('latin1', at + 24, at + 88).replace(/\0.*$/s, '') : '';
      if (size === 88 && pylib && !/^[\w.+-]+$/.test(pylib)) continue;
      const toc = [];
      let p = start + tocPos;
      const limit = p + tocLen;
      while (p + 18 <= limit && toc.length < 200000) {
        const elen = buf.readInt32BE(p);
        if (elen < 18 || p + elen > limit) break;
        const name = buf.toString('utf8', p + 18, p + elen).replace(/\0.*$/s, '');
        toc.push({ name, pos: buf.readUInt32BE(p + 4), len: buf.readUInt32BE(p + 8), ulen: buf.readUInt32BE(p + 12), cflag: buf[p + 16], type: String.fromCharCode(buf[p + 17]) });
        p += elen;
      }
      if (!toc.length) continue;
      return { start, cookie: at, end, pyvers, pylib, toc };
    }
  }
  return null;
}

function entryData(buf, ar, e) {
  if (e.len > MAX_ENTRY_BYTES || e.ulen > MAX_ENTRY_BYTES) return null;
  const a = ar.start + e.pos;
  if (a < 0 || a + e.len > buf.length) return null;
  const raw = buf.subarray(a, a + e.len);
  return e.cflag ? zlib.inflateSync(raw, { maxOutputLength: MAX_ENTRY_BYTES }) : raw;
}

const pyVersionOf = v => (v >= 100 ? `${Math.floor(v / 100)}.${v % 100}` : `${Math.floor(v / 10)}.${v % 10}`);

// ── PYZ ──────────────────────────────────────────────────────────────────────────────────────────
function readPyz(data) {
  if (data.length < 12 || data.toString('latin1', 0, 4) !== 'PYZ\0') return { error: 'not a PYZ archive' };
  const tocAt = data.readUInt32BE(8);
  if (tocAt + 4 > data.length) return { error: 'PYZ table of contents is out of range' };
  let toc;
  try { toc = unmarshal(data, tocAt); } catch (e) { return { error: `PYZ table of contents could not be decoded (${e.message})` }; }
  const out = [];
  const add = (name, v) => { if (typeof name === 'string' && Array.isArray(v) && v.length >= 3) out.push({ name, pkg: v[0] === 1 || v[0] === true, pos: v[1], len: v[2] }); };
  if (toc instanceof Map) for (const [k, v] of toc) add(k, v);
  else if (Array.isArray(toc)) for (const item of toc) if (Array.isArray(item)) add(item[0], item[1]);
  return { entries: out };
}

const VERSION_STR = /[Zz\xda\xfa]([\x03-\x20])(\d+\.\d+(?:\.\d+)*(?:(?:a|b|rc)\d+)?(?:\.(?:post|dev)\d+)*)/g;
/** Version-looking marshalled strings of a module's code: a short ascii string is its type byte (Z, z, or either with the 0x80 reference flag), a length byte and the text. */
function versionStrings(mod) {
  const s = mod.toString('latin1');
  const out = new Set();
  for (const m of s.matchAll(VERSION_STR)) if (m[1].charCodeAt(0) === m[2].length) out.add(m[2]);
  return [...out];
}

// ── dist-info / egg-info metadata ────────────────────────────────────────────────────────────────
function metadataRecord(text, from) {
  const head = text.split(/\r?\n\r?\n/, 1)[0];
  const name = /^Name:\s*(\S+)\s*$/mi.exec(head)?.[1], version = /^Version:\s*(\S+)\s*$/mi.exec(head)?.[1];
  return name && version ? { name, version, from } : null;
}

// ── Python runtime ───────────────────────────────────────────────────────────────────────────────
const PY_PATCH = /(?:^|[^\d.])(3\.\d{1,2}\.\d{1,2})(?:(?:a|b|rc)\d+)?(?![\w.])/;
function pythonPatch(strings, minor) {
  const counts = new Map();
  for (const s of strings) {
    if (s.length > 80) continue;
    const m = PY_PATCH.exec(s);
    if (m && m[1].startsWith(`${minor}.`)) counts.set(m[1], (counts.get(m[1]) || 0) + 1);
  }
  let best = null;
  for (const [v, n] of counts) if (!best || n > best.n || (n === best.n && v > best.v)) best = { v, n };
  return best ? best.v : null;
}

function analyzePyInstaller(buf, ar, out, name) {
  const info = { kind: 'pyinstaller', python: pyVersionOf(ar.pyvers), entries: ar.toc.length, libpython: ar.pylib || null, archive_bytes: ar.end - ar.start };
  out.regions.push({ start: ar.start, end: ar.end });
  let total = 0;
  const failed = [];
  const meta = new Map();                       // normalised name@version → {name, version, from}
  const bannerRecs = [];
  let pyz = null, libpythonStrings = null;
  const budget = n => { total += n; return total <= MAX_TOTAL_BYTES; };

  for (const e of ar.toc) {
    try {
      if (e.type === 'z' || e.type === 'Z') {                                                  // module archive
        if (!pyz) pyz = e;
        continue;
      }
      if (/\.(?:dist-info|egg-info)[\\/](?:METADATA|PKG-INFO)$/i.test(e.name)) {
        const d = entryData(buf, ar, e);
        const r = d && metadataRecord(d.toString('utf8'), e.name);
        if (r) meta.set(`${normalisePypi(r.name)}@${r.version}`, r);
        continue;
      }
      const looksNative = e.type === 'b' || /\.(?:so(?:\.[\d.]+)?|dll|dylib|pyd)$/i.test(e.name);
      if (looksNative && e.ulen <= MAX_ENTRY_BYTES && budget(e.ulen)) {
        const d = entryData(buf, ar, e);
        if (!d) continue;
        const strings = asciiStrings(d, { min: 6, max: 2048, limit: 300000 });
        for (const r of detectBanners(strings)) bannerRecs.push({ r, from: e.name });
        if (/(?:^|[\\/])(?:libpython3[\d.]*\.(?:so|dylib)|python3\d*\.dll|Python)(?:\.[\d.]+)?$/i.test(e.name) && !libpythonStrings) libpythonStrings = strings;
        continue;
      }
      if ((e.type === 's' || e.type === 'x' || e.type === 'm' || e.type === 'M') && e.ulen <= MAX_ENTRY_BYTES && budget(e.ulen) && !PYINSTALLER_INTERNAL.test(e.name)) {
        if (/\.(?:png|jpe?g|gif|ico|icns|ttf|otf|woff2?|mo|pyd|zip|gz|bz2|xz|pkl|npy|bin|dat|db|sqlite3?)$/i.test(e.name)) continue;
        const d = entryData(buf, ar, e);
        const lines = d ? asciiStrings(d, { min: 8, max: 2048, limit: 50000 }) : [];
        const tokens = d ? asciiStrings(d, NAME_STRINGS) : [];                    // module and attribute names of the marshalled code (behavior inventory)
        if (lines.length || tokens.length) out.sources.push({ path: `${name}!${e.name}`, lines, tokens });
      }
    } catch (err) { failed.push(`${e.name} (${String(err.message || err).slice(0, 50)})`); }
  }

  // embedded libraries: one record per name+version, remembering where it was found
  const seen = new Set();
  for (const { r, from } of bannerRecs) {
    const k = `${r.name}@${r.version}`;
    if (seen.has(k)) continue;
    seen.add(k);
    r.sources = [`embedded version string in ${from}`];
    r.source_types = ['pyinstaller bundled library'];
    out.records.push(r);
  }

  // interpreter
  const minor = info.python;
  const patch = libpythonStrings ? pythonPatch(libpythonStrings, minor) : null;
  info.python_version = patch || minor;
  if (patch) out.records.push(cRecord({ name: 'Python', version: patch, vendor: 'python', product: 'python', evidence: `libpython ${patch}`, source: 'embedded libpython version string', sourceType: 'python runtime banner', ecosystem: 'Python runtime' }));
  else out.gaps.push(`${name}: the Python interpreter is ${minor}.x, but its patch release could not be read, so the interpreter was not checked for known vulnerabilities.`);

  // PYZ: module list, versions, strings
  const versions = new Map();                   // top-level package → Set of versions (medium)
  if (pyz) {
    let data = null;
    try { data = entryData(buf, ar, pyz); } catch (err) { failed.push(`${pyz.name} (${String(err.message || err).slice(0, 50)})`); }
    const tab = data ? readPyz(data) : { error: 'PYZ could not be read' };
    if (tab.error) out.gaps.push(`${name}: ${tab.error}; bundled Python modules were not inventoried or scanned.`);
    else {
      info.modules = tab.entries.length;
      const byName = new Map(tab.entries.map(x => [x.name, x]));
      let enc = 0;
      const load = x => {
        try { return zlib.inflateSync(data.subarray(x.pos, x.pos + x.len), { maxOutputLength: MAX_ENTRY_BYTES }); } catch { enc++; return null; }
      };
      const tops = new Set(tab.entries.map(x => x.name.split('.')[0]));
      for (const top of tops) {
        if (STDLIB.has(top) || PYINSTALLER_INTERNAL.test(top) || top.startsWith('_') && !DIST_NAMES[top]) continue;
        const cands = [];
        for (const v of VERSION_MODULES) { const x = byName.get(`${top}.${v}`); if (x) cands.push({ x, strict: false }); }
        const init = byName.get(top); if (init) cands.push({ x: init, strict: true });
        for (const { x, strict } of cands) {
          if (!budget(x.len)) break;
          const m = load(x);
          if (!m) continue;
          const vs = versionStrings(m);
          if (strict && !(m.includes('__version__') && vs.length === 1)) continue;
          if (vs.length) { versions.set(top, new Set([...(versions.get(top) || []), ...vs])); if (!strict) break; }
        }
      }
      // string constants of the application's own and third-party modules → secret scanner
      for (const x of tab.entries) {
        if (PYINSTALLER_INTERNAL.test(x.name) || STDLIB.has(x.name.split('.')[0]) || !budget(x.len)) continue;
        const m = load(x);
        if (!m) continue;
        const lines = asciiStrings(m, { min: 8, max: 2048, limit: 20000 });
        const tokens = asciiStrings(m, NAME_STRINGS);
        if (lines.length || tokens.length) out.sources.push({ path: `${name}!PYZ/${x.name}`, lines, tokens });
      }
      if (enc) out.gaps.push(`${name}: ${enc} module(s) in the PYZ archive could not be decompressed (encrypted with --key, or damaged); their packages and strings were not checked.`);
    }
  }

  // package records: metadata first (exact), then __version__ modules for packages that metadata did not cover
  const covered = new Set();
  for (const r of meta.values()) {
    covered.add(normalisePypi(r.name));
    out.records.push(purlRecord({ name: r.name, version: r.version, ecosystem: 'PyPI', purl: pypiPurl(r.name, r.version), source: `bundled package metadata (${r.from})`, sourceType: 'python dist-info', confidence: 'high' }));
  }
  const names = new Set();
  for (const [top, vs] of versions) {
    const dist = DIST_NAMES[top] || top;
    const n = normalisePypi(dist);
    if (covered.has(n) || names.has(n)) continue;
    names.add(n);
    if (vs.size === 1) {
      const v = [...vs][0];
      out.records.push(purlRecord({ name: dist, version: v, ecosystem: 'PyPI', purl: pypiPurl(dist, v), source: `__version__ in the bundled ${top} module`, sourceType: 'python module version', confidence: 'medium', evidence: `${top}: ${v}` }));
    } else out.records.push(inventoryRecord({ name: dist, ecosystem: 'PyPI', source: `bundled ${top} module`, sourceType: 'python module version', reason: `The bundled module shows several version-like strings (${[...vs].slice(0, 4).join(', ')}), so the installed version could not be decided.` }));
  }
  info.packages = out.records.filter(r => r.ecosystem === 'PyPI' && r.version).length;
  if (failed.length) out.gaps.push(`${name}: ${failed.length} PyInstaller archive entr${failed.length === 1 ? 'y' : 'ies'} could not be read (${failed.slice(0, 3).join('; ')}${failed.length > 3 ? '; …' : ''}).`);
  if (total > MAX_TOTAL_BYTES) out.gaps.push(`${name}: the PyInstaller archive is larger than the ${MAX_TOTAL_BYTES / 1024 / 1024} MB decompression budget; the remaining entries were not read.`);
  out.info.push(info);
}

// ── other Python freezers: recognised, not inventoried ──────────────────────────────────────────
const OTHERS = [
  ['nuitka', Buffer.from('Nuitka', 'latin1'), /(?:__nuitka_version__|nuitka_version|Nuitka[- ]Onefile|NUITKA_ONEFILE)/, 'Nuitka compiles the program to C and keeps its modules and bundled packages inside a compressed payload (or beside the executable)'],
  ['cx_Freeze', Buffer.from('cx_Freeze', 'latin1'), /cx_Freeze/, 'cx_Freeze keeps the bundled packages in a library.zip beside the executable, which is not part of this file'],
  ['py2exe', Buffer.from('PYTHONSCRIPT', 'latin1'), /PYTHONSCRIPT|py2exe/, 'py2exe keeps the bundled packages in a zip resource that this scanner does not read'],
  ['PyOxidizer', Buffer.from('pyembed', 'latin1'), /pyembed|PyOxidizer/, 'PyOxidizer embeds its packed resources in a format this scanner does not read'],
];

export function analyzePython(buf, { name = 'binary' } = {}) {
  const out = { records: [], sources: [], regions: [], gaps: [], notes: [], info: [] };
  const ar = readCArchive(buf);
  if (ar) {
    try { analyzePyInstaller(buf, ar, out, name); }
    catch (err) { out.gaps.push(`${name}: a PyInstaller archive was found but could not be read (${String(err.message || err).slice(0, 80)}); bundled Python packages were not checked.`); }
    return out;
  }
  for (const [kind, needle, re, why] of OTHERS) {
    if (buf.indexOf(needle) < 0) continue;
    const idx = buf.indexOf(needle);
    const around = buf.latin1Slice(Math.max(0, idx - 64), Math.min(buf.length, idx + 64));
    if (!re.test(around)) continue;
    if (kind === 'cx_Freeze' || kind === 'py2exe' || kind === 'PyOxidizer') { if (buf.indexOf(Buffer.from('Py_Initialize', 'latin1')) < 0 && buf.indexOf(Buffer.from('python3', 'latin1')) < 0) continue; }
    out.info.push({ kind: kind.toLowerCase(), inventoried: false });
    out.gaps.push(`${name}: built with ${kind}. ${why}, so its Python packages could not be inventoried. Scan the project (ubel-pip / ubel-poetry / ubel-uv) or the unpacked distribution instead.`);
    break;
  }
  return out;
}
