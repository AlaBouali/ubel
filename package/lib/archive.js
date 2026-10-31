'use strict';
// archive.js — reads a package archive IN MEMORY and never writes a byte of it to disk, so nothing in it can be executed, linked or
// overwrite a file. Formats: tar (plain / gzip), zip (wheel, nupkg, Go module zip, Composer dist) and .gem (a tar of metadata.gz + data.tar.gz).
// Every entry is described, and what a malicious or careless archive can do on extraction is reported as a PROBLEM instead of being acted on:
//   path_traversal  an entry path with `..` segments or an absolute / drive path (writes outside the install directory)
//   symlink_escape  a symlink or hard link whose target leaves the package (`../../.ssh`, `/etc/passwd`)
//   special_file    a device node or FIFO
//   setuid          setuid / setgid bit on a file
//   world_writable  a regular file or directory with the world-write bit
// Limits (zip-bomb defence): compressed input, total unpacked bytes, entry count, per-entry size, compression ratio.

import zlib from 'node:zlib';
import { ZipArchive } from '../../mobile/lib/zip.js';

export class ArchiveError extends Error {}

const LIMITS = { maxEntries: 100000, maxUnpackedBytes: 1024 * 1048576, maxEntryBytes: 256 * 1048576 };

/** Normalised path of an entry (forward slashes, no `./`), and whether it escapes the root. */
export function normalizeEntryPath(raw) {
  let p = String(raw).replace(/\\/g, '/').replace(/\0.*$/, '');
  const absolute = /^(?:\/|[A-Za-z]:\/)/.test(p);
  const out = [];
  let escapes = false;
  for (const seg of p.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { if (out.length) out.pop(); else escapes = true; continue; }
    out.push(seg);
  }
  return { path: out.join('/'), traversal: absolute || escapes || /(?:^|\/)\.\.(?:\/|$)/.test(p.replace(/\\/g, '/')) };
}

/** Where a link points, relative to the package root, or null when it leaves it. */
function linkInside(entryPath, target, hard) {
  const t = String(target).replace(/\\/g, '/');
  if (/^(?:\/|[A-Za-z]:\/)/.test(t)) return null;
  const base = hard ? [] : entryPath.split('/').slice(0, -1);
  const out = base.slice();
  for (const seg of t.split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') { if (!out.length) return null; out.pop(); } else out.push(seg);
  }
  return out.join('/');
}

// ── tar ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const TYPE = { '0': 'file', '\0': 'file', '7': 'file', '1': 'hardlink', '2': 'symlink', '3': 'special', '4': 'special', '5': 'dir', '6': 'special' };

function octal(b, off, len) {
  if (b[off] & 0x80) {                                           // base-256 (GNU): big sizes / ids
    let v = 0;
    for (let i = off + 1; i < off + len; i++) v = v * 256 + b[i];
    return v;
  }
  const s = b.toString('latin1', off, off + len).replace(/\0.*$/, '').trim();
  return s ? parseInt(s, 8) : 0;
}
const cstr = (b, off, len) => b.toString('utf8', off, off + len).replace(/\0.*$/, '');

function paxRecords(data) {
  const out = {};
  let i = 0;
  while (i < data.length) {
    const sp = data.indexOf(0x20, i);
    if (sp < 0) break;
    const len = parseInt(data.toString('latin1', i, sp), 10);
    if (!(len > 0) || i + len > data.length) break;
    const rec = data.toString('utf8', sp + 1, i + len - 1);
    const eq = rec.indexOf('=');
    if (eq > 0) out[rec.slice(0, eq)] = rec.slice(eq + 1);
    i += len;
  }
  return out;
}

/** Parses an uncompressed tar held in `buf`. Entries carry `offset` / `size` into `buf`; nothing is copied. */
export function parseTar(buf, { maxEntries = LIMITS.maxEntries } = {}) {
  const entries = [];
  let pos = 0, longName = null, longLink = null, pax = null, globalPax = {};
  let zeroBlocks = 0, headers = 0;
  while (pos + 512 <= buf.length) {
    const h = buf.subarray(pos, pos + 512);
    if (h.every(x => x === 0)) { if (++zeroBlocks >= 2) break; pos += 512; continue; }
    zeroBlocks = 0;
    // checksum: sum of all header bytes with the checksum field read as spaces
    const stored = octal(h, 148, 8);
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += (i >= 148 && i < 156) ? 32 : h[i];
    if (sum !== stored) {
      let signed = 0;
      for (let i = 0; i < 512; i++) signed += (i >= 148 && i < 156) ? 32 : (h[i] > 127 ? h[i] - 256 : h[i]);
      if (signed !== stored) throw new ArchiveError(headers === 0 ? 'not a tar archive (header checksum mismatch)' : `corrupt tar header at byte ${pos}`);
    }
    headers++;
    const flag = String.fromCharCode(h[156] || 0);
    let size = octal(h, 124, 12);
    const dataStart = pos + 512;
    const next = dataStart + Math.ceil(size / 512) * 512;
    if (flag !== 'x' && flag !== 'g' && flag !== 'L' && flag !== 'K' && dataStart + size > buf.length) throw new ArchiveError(`tar entry at byte ${pos} runs past the end of the archive (truncated)`);
    if (flag === 'L' || flag === 'K' || flag === 'x' || flag === 'g') {
      if (dataStart + size > buf.length) throw new ArchiveError('truncated tar extension header');
      const data = buf.subarray(dataStart, dataStart + size);
      if (flag === 'L') longName = data.toString('utf8').replace(/\0.*$/, '');
      else if (flag === 'K') longLink = data.toString('utf8').replace(/\0.*$/, '');
      else if (flag === 'x') pax = paxRecords(data);
      else globalPax = { ...globalPax, ...paxRecords(data) };
      pos = next;
      continue;
    }
    const meta = { ...globalPax, ...(pax || {}) };
    const magic = h.toString('latin1', 257, 262);
    let name = cstr(h, 0, 100);
    if (magic === 'ustar') { const prefix = cstr(h, 345, 155); if (prefix) name = `${prefix}/${name}`; }
    if (longName != null) name = longName;
    if (meta.path != null) name = meta.path;
    let linkname = cstr(h, 157, 100);
    if (longLink != null) linkname = longLink;
    if (meta.linkpath != null) linkname = meta.linkpath;
    if (meta.size != null && Number.isFinite(Number(meta.size))) size = Number(meta.size);
    entries.push({ rawName: name, type: TYPE[flag] || 'special', typeflag: flag, mode: octal(h, 100, 8) & 0o7777, uid: octal(h, 108, 8), gid: octal(h, 116, 8), size, linkname, offset: dataStart });
    if (entries.length > maxEntries) throw new ArchiveError(`more than ${maxEntries} entries`);
    longName = longLink = pax = null;
    pos = dataStart + Math.ceil(size / 512) * 512;
  }
  if (!headers) throw new ArchiveError('not a tar archive (no entries)');
  return entries;
}

const isGzip = b => b.length > 2 && b[0] === 0x1f && b[1] === 0x8b;
const isZip = b => b.length > 3 && b[0] === 0x50 && b[1] === 0x4b && (b[2] === 3 || b[2] === 5) && (b[3] === 4 || b[3] === 6);
const isBzip2 = b => b.length > 3 && b[0] === 0x42 && b[1] === 0x5a && b[2] === 0x68;
const isXz = b => b.length > 5 && b[0] === 0xfd && b[1] === 0x37 && b[2] === 0x7a && b[3] === 0x58 && b[4] === 0x5a;
const isZstd = b => b.length > 3 && b[0] === 0x28 && b[1] === 0xb5 && b[2] === 0x2f && b[3] === 0xfd;
const looksTar = b => b.length >= 512 && b.toString('latin1', 257, 262) === 'ustar';

export function gunzip(buf, { maxBytes = LIMITS.maxUnpackedBytes } = {}) {
  let out;
  try { out = zlib.gunzipSync(buf, { maxOutputLength: maxBytes }); }
  catch (e) { throw new ArchiveError(e.code === 'ERR_BUFFER_TOO_LARGE' ? `unpacks to more than ${Math.round(maxBytes / 1048576)} MB (zip-bomb guard)` : `gzip: ${e.message}`); }
  if (out.length > 64 * 1048576 && out.length / Math.max(buf.length, 1) > 4000) throw new ArchiveError('implausible compression ratio (zip-bomb guard)');
  return out;
}

/**
 * A package archive as a flat, safe description.
 * @typedef {{path:string, rawPath:string, type:'file'|'dir'|'symlink'|'hardlink'|'special', size:number, mode:number|null, linkname:string|null, read:(max?:number)=>Buffer}} PackageFile
 * @returns {{format:string, files:PackageFile[], problems:{kind:string,path:string,detail:string}[], root:string|null, unpacked:number, compressed:number}}
 */
export function openArchive(input, opts = {}) {
  const limits = { ...LIMITS, ...opts };
  const compressed = input.length;
  let format, entries, readEntry;
  if (isBzip2(input) || isXz(input) || isZstd(input)) {
    throw new ArchiveError(`${isBzip2(input) ? 'bzip2' : isXz(input) ? 'xz' : 'zstd'}-compressed archives are not supported (Node built-ins cannot read them)`);
  }
  if (isGzip(input) || looksTar(input)) {
    const raw = isGzip(input) ? gunzip(input, { maxBytes: limits.maxUnpackedBytes }) : input;
    if (isBzip2(raw) || isXz(raw) || isZstd(raw)) throw new ArchiveError('nested compression is not supported');
    format = isGzip(input) ? 'tar.gz' : 'tar';
    const list = parseTar(raw, limits);
    entries = list.map(e => ({ rawPath: e.rawName, type: e.type, size: e.size, mode: e.mode, linkname: e.type === 'symlink' || e.type === 'hardlink' ? e.linkname : null, _o: e.offset }));
    readEntry = e => raw.subarray(e._o, e._o + e.size);
  } else if (isZip(input)) {
    format = 'zip';
    let zip;
    try { zip = new ZipArchive(input, { maxEntries: limits.maxEntries, maxEntryBytes: limits.maxEntryBytes, maxTotalBytes: limits.maxUnpackedBytes }); }
    catch (e) { throw new ArchiveError(`zip: ${e.message}`); }
    entries = zip.entries.map(e => ({ rawPath: e.name, type: e.isDir ? 'dir' : 'file', size: e.usize, mode: null, linkname: null, _z: e, _zip: zip }));
    readEntry = (e, max) => zip.read(e._z, max ?? limits.maxEntryBytes);
  } else {
    throw new ArchiveError('not a recognised archive (expected tar, tar.gz or zip)');
  }
  return describe({ format, entries, readEntry, compressed, limits });
}

function describe({ format, entries, readEntry, compressed, limits }) {
  const problems = [];
  const files = [];
  let unpacked = 0;
  const seen = new Set();
  const top = new Set();
  for (const e of entries) {
    const { path: p, traversal } = normalizeEntryPath(e.rawPath);
    if (e.rawPath === 'pax_global_header' || (!p && e.type === 'dir')) continue;
    if (traversal) problems.push({ kind: 'path_traversal', path: e.rawPath, detail: 'the entry path leaves the package directory (absolute path or `..` segments), so extracting it would write outside the install location' });
    if (!p) continue;
    if (seen.has(p) && e.type !== 'dir') problems.push({ kind: 'duplicate_entry', path: p, detail: 'the same path appears more than once in the archive; which copy wins depends on the extractor' });
    seen.add(p);
    top.add(p.split('/')[0]);
    if (e.type === 'special') problems.push({ kind: 'special_file', path: p, detail: 'device node or FIFO' });
    if (e.mode != null && (e.mode & 0o6000) && e.type === 'file') problems.push({ kind: 'setuid', path: p, detail: `mode ${(e.mode & 0o7777).toString(8)} sets the ${e.mode & 0o4000 ? 'setuid' : ''}${(e.mode & 0o4000) && (e.mode & 0o2000) ? '/' : ''}${e.mode & 0o2000 ? 'setgid' : ''} bit` });
    if (e.mode != null && (e.mode & 0o002) && (e.type === 'file' || e.type === 'dir') && (e.mode & 0o111 || e.type === 'dir')) problems.push({ kind: 'world_writable', path: p, detail: `mode ${(e.mode & 0o7777).toString(8)} is writable by every user` });
    if ((e.type === 'symlink' || e.type === 'hardlink') && e.linkname) {
      if (linkInside(p, e.linkname, e.type === 'hardlink') === null) problems.push({ kind: 'symlink_escape', path: p, detail: `${e.type} to ${e.linkname}, which is outside the package` });
    }
    unpacked += e.type === 'file' ? e.size : 0;
    files.push({ path: p, rawPath: e.rawPath, type: e.type, size: e.size, mode: e.mode, linkname: e.linkname, read: max => readEntry(e, max) });
  }
  if (files.length > limits.maxEntries) throw new ArchiveError(`more than ${limits.maxEntries} entries`);
  if (unpacked > limits.maxUnpackedBytes) throw new ArchiveError(`${Math.round(unpacked / 1048576)} MB unpacked, over the ${Math.round(limits.maxUnpackedBytes / 1048576)} MB limit`);
  // one common top-level directory (`package/`, `name-1.0/`, `module@v1/`) is the archive's root; paths are reported relative to it
  let root = null;
  // Go module zips: every path starts with `<module path>@<version>/`, and the module path itself contains slashes
  if (files.length) {
    const m = /^(.+@v[^/]+)\//.exec(files[0].path);
    if (m && files.every(f => f.path === m[1] || f.path.startsWith(`${m[1]}/`))) root = m[1];
  }
  if (!root && top.size === 1 && limits.stripRoot !== false) {
    const only = [...top][0];
    if (files.some(f => f.path.includes('/') && f.path.split('/')[0] === only) && !files.some(f => f.path === only && f.type === 'file')) root = only;
  }
  let out = files;
  if (root) {
    out = [];
    for (const f of files) { if (f.path === root) continue; f.path = f.path.slice(root.length + 1); out.push(f); }
    for (const pr of problems) if (pr.path.startsWith(`${root}/`)) pr.path = pr.path.slice(root.length + 1);
  }
  return { format, files: out, problems, root, unpacked, compressed };
}

// ── .gem ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
/** A RubyGems package: a plain tar holding `metadata.gz` (the gemspec as YAML), `data.tar.gz` (the files) and `checksums.yaml.gz`. */
export function openGem(buf, opts = {}) {
  const limits = { ...LIMITS, ...opts };
  let outer;
  try { outer = parseTar(isGzip(buf) ? gunzip(buf, { maxBytes: limits.maxUnpackedBytes }) : buf, limits); }
  catch (e) { throw new ArchiveError(`gem: ${e.message}`); }
  const raw = isGzip(buf) ? gunzip(buf, { maxBytes: limits.maxUnpackedBytes }) : buf;
  const part = name => { const e = outer.find(x => x.rawName.replace(/^\.\//, '') === name); return e ? raw.subarray(e.offset, e.offset + e.size) : null; };
  const metaGz = part('metadata.gz'), dataGz = part('data.tar.gz'), sumsGz = part('checksums.yaml.gz');
  if (!metaGz || !dataGz) throw new ArchiveError('gem: metadata.gz or data.tar.gz is missing');
  const metadata = gunzip(metaGz, { maxBytes: 16 * 1048576 }).toString('utf8');
  const checksums = sumsGz ? gunzip(sumsGz, { maxBytes: 4 * 1048576 }).toString('utf8') : null;
  const archive = openArchive(dataGz, { ...limits, stripRoot: false });      // a gem's data has no wrapper directory: a lone lib/ is content, not a root
  archive.format = 'gem';
  return { archive, metadata, checksums };
}

export { isGzip, isZip, looksTar, LIMITS as ARCHIVE_LIMITS };
