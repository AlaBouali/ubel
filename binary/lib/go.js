'use strict';
// go.js — what a Go binary says about itself.
//   • Go ≥ 1.18: build info is stored inline (`\xff Go buildinf:` header, flag 2): toolchain version + module list as plain text.
//   • Go 1.13 – 1.17: the header only holds two pointers (flag 0) to a version string and to the module list; the pointers are followed
//     through the file's own segment/section table (vmap.js).
//   • Either way the module list sits between two fixed 16-byte sentinels, so it is still found when the header is missing or its
//     pointers cannot be followed (a stripped or repacked file); the toolchain version is then unknown.
// Build info survives `strip` and `-ldflags=-s -w`; only a binary built without modules (GOPATH mode, ≤ 1.17) carries no module list.

import { makeVaMap } from './vmap.js';
import { purlRecord } from './records.js';

const GO_MAGIC = Buffer.from('\xff Go buildinf:', 'latin1');
const MOD_START = Buffer.from('3077af0c9274080241e1c107e6d618e6', 'hex');
const MOD_END = Buffer.from('f932433186182072008242104116d8f2', 'hex');
const MAX_MODINFO = 8 * 1024 * 1024;
const MAX_STRING = 1024 * 1024;

function uvarint(buf, at) {
  let x = 0, s = 0;
  for (let i = 0; i < 10 && at + i < buf.length; i++) {
    const b = buf[at + i];
    if (b < 0x80) return { value: x + b * 2 ** s, next: at + i + 1 };
    x += (b & 0x7f) * 2 ** s; s += 7;
  }
  return null;
}

/** The module list is wrapped in two 16-byte sentinels; the text between them is `path`/`mod`/`dep`/`=>`/`build` lines. */
function unwrap(mod) {
  if (mod.length >= 33 && mod[mod.length - 17] === '\n') return mod.slice(16, mod.length - 16);
  return mod;
}

/** Modules, replacements and build settings out of the module-list text. */
function parseModInfo(text) {
  const modules = [], build = {};
  let path = null, main = null, last = null;
  for (const line of String(text || '').split('\n')) {
    const f = line.split('\t');
    if (f[0] === 'path') { path = f[1] || null; last = null; }
    else if (f[0] === 'mod') { main = { path: f[1] || path, version: f[2] || null }; last = null; }
    else if (f[0] === 'dep' && f[1] && f[2]) { last = { path: f[1], version: f[2] }; modules.push(last); }
    else if (f[0] === '=>' && last) {                                    // replace directive: the replacement is what was compiled in
      if (f[1] && f[2]) { last.path = f[1]; last.version = f[2]; } else modules.splice(modules.indexOf(last), 1);
      last = null;
    } else if (f[0] === 'build' && f[1]) {
      const i = f[1].indexOf('=');
      if (i > 0) build[f[1].slice(0, i)] = f[1].slice(i + 1).replace(/^"(.*)"$/, '$1');
      last = null;
    } else last = null;
  }
  return { path, main, modules, build };
}

function sentinelModinfo(buf) {
  const s = buf.indexOf(MOD_START);
  if (s < 0) return null;
  const e = buf.indexOf(MOD_END, s + 16);
  if (e < 0 || e - s > MAX_MODINFO) return null;
  const text = buf.latin1Slice(s + 16, e);
  return /^(?:path|mod|dep|build)\t/.test(text) || text === '' ? text : null;
}

function inlineFormat(buf, at) {
  const v = uvarint(buf, at + 32); if (!v || v.next + v.value > buf.length) return { unsupported: 'Go build info is truncated.' };
  const goVersion = buf.toString('latin1', v.next, v.next + v.value).trim();
  const m = uvarint(buf, v.next + v.value); if (!m || m.next + m.value > buf.length) return { goVersion, modules: [], build: {}, format: 'inline' };
  return { goVersion, ...parseModInfo(unwrap(buf.toString('latin1', m.next, m.next + m.value))), format: 'inline' };
}

function pointerFormat(buf, at) {
  const ptrSize = buf[at + 14], big = (buf[at + 15] & 1) !== 0;
  let goVersion = null, mod = null;
  const vm = ptrSize === 4 || ptrSize === 8 ? makeVaMap(buf, at) : null;
  if (vm) {
    const ptr = o => (ptrSize === 8 ? Number(big ? buf.readBigUInt64BE(o) : buf.readBigUInt64LE(o)) : (big ? buf.readUInt32BE(o) : buf.readUInt32LE(o)));
    const str = hdrVa => {                                           // a Go string header is {data pointer, length}
      try {
        const ho = vm(hdrVa); if (ho < 0 || ho + 2 * ptrSize > buf.length) return null;
        const len = ptr(ho + ptrSize), so = vm(ptr(ho));
        if (so < 0 || len > MAX_STRING || so + len > buf.length) return null;
        return buf.latin1Slice(so, so + len);
      } catch { return null; }
    };
    try { goVersion = str(ptr(at + 16)); mod = str(ptr(at + 16 + ptrSize)); } catch { /* fall back to the sentinels below */ }
    if (goVersion !== null && !/^go\d/.test(goVersion) && !/^devel/.test(goVersion)) goVersion = null;
  }
  const text = mod !== null ? unwrap(mod) : sentinelModinfo(buf);
  if (text === null && goVersion === null) return { unsupported: 'Go build info uses the pre-1.18 pointer format and its pointers could not be followed; module versions were not read.' };
  return { goVersion, ...parseModInfo(text), format: mod !== null ? 'pointer' : 'sentinel' };
}

/**
 * Go build info of an ELF / Mach-O / PE file.
 * @returns {{goVersion:string|null, path:string|null, main:{path:string,version:string|null}|null, modules:{path:string,version:string}[], build:object, format:string}|{unsupported:string}|null}
 */
export function goBuildInfo(buf) {
  let at = buf.indexOf(GO_MAGIC);
  while (at >= 0 && at % 16 !== 0) at = buf.indexOf(GO_MAGIC, at + 1);
  if (at >= 0) return (buf[at + 15] & 2) ? inlineFormat(buf, at) : pointerFormat(buf, at);
  const text = sentinelModinfo(buf);                                  // no header: a file that was repacked or whose header was removed
  return text === null || text === '' ? null : { goVersion: null, ...parseModInfo(text), format: 'sentinel' };
}

const GO_SOURCE = 'Go build info', GO_TYPE = 'go buildinfo';

export function goRecords(info) {
  if (!info || info.unsupported) return [];
  const out = [];
  const goVer = /^go(\d+\.\d+(?:\.\d+)?)(?![\w.])/.exec(info.goVersion || '');
  if (goVer) {
    const v = goVer[1].split('.').length === 2 ? `${goVer[1]}.0` : goVer[1];          // go1.20 is release 1.20.0
    out.push(purlRecord({ name: 'Go standard library', version: v, ecosystem: 'Go', purl: `pkg:golang/stdlib@${v}`, source: GO_SOURCE, sourceType: GO_TYPE }));
  }
  for (const m of info.modules || []) {
    if (!m.version || m.version === '(devel)') continue;
    out.push(purlRecord({ name: m.path, version: m.version, ecosystem: 'Go', purl: `pkg:golang/${m.path.split('/').map(encodeURIComponent).join('/')}@${m.version}`, source: GO_SOURCE, sourceType: GO_TYPE }));
  }
  return out;
}

/** What the report shows about a Go binary (never the raw -ldflags: they may carry values set with -X). */
export function goSummary(info) {
  if (!info || info.unsupported) return null;
  const b = info.build || {};
  return {
    go_version: info.goVersion || null, build_info_format: info.format, main_module: info.main?.path || info.path || null, main_version: info.main?.version || null,
    modules: (info.modules || []).length, cgo: b.CGO_ENABLED === undefined ? null : b.CGO_ENABLED === '1', goos: b.GOOS || null, goarch: b.GOARCH || null,
    buildmode: b['-buildmode'] || null, trimpath: b['-trimpath'] === 'true', race: b['-race'] === 'true', ldflags: '-ldflags' in b,
    vcs_revision: b['vcs.revision'] || null, vcs_modified: b['vcs.modified'] === undefined ? null : b['vcs.modified'] === 'true',
  };
}

/** Plain analysis notes for the report. */
export function goNotes(info, name) {
  if (!info || info.unsupported) return [];
  const out = [];
  const b = info.build || {};
  if (!info.goVersion) out.push(`${name}: the Go toolchain version could not be read (module versions were); the standard library was not checked.`);
  else if (!/^go\d+\.\d+(?:\.\d+)?(?![\w.])/.test(info.goVersion)) out.push(`${name}: built with ${info.goVersion}, a pre-release or development Go toolchain; the standard library was not checked.`);
  if (b['-race'] === 'true') out.push(`${name}: built with the Go race detector (-race), which is meant for testing, not for release builds.`);
  if (b.CGO_ENABLED === '1') out.push(`${name}: built with cgo, so it links C code that Go module advisories do not cover; C library banners are checked separately.`);
  if (b['vcs.modified'] === 'true') out.push(`${name}: built from a source tree with uncommitted changes (vcs.modified=true).`);
  return out;
}
