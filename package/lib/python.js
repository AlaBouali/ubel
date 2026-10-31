'use strict';
// python.js — everything ubel-package reads about a Python package's dependencies, beyond the PEP 566 metadata that manifests.js reads first:
//
//   setup.py       a small static evaluator of the setup() call: install_requires / setup_requires / tests_require / extras_require given as
//                  literals, as names assigned earlier in the file, as concatenations, or read from a requirements file. Never executed.
//   setup.cfg      [options] install_requires / setup_requires / tests_require, [options.extras_require], `file:` directives
//   pyproject.toml PEP 621 (incl. dynamic = file), PEP 735 dependency-groups, Poetry (groups, dev-dependencies, extras), PDM, uv, Flit, Hatch
//   requirements   requirements*.txt / *.in / constraints*.txt with -r / -c includes, hashes, VCS and URL requirements, index options
//   Pipfile, environment.yml, <name>.egg-info/requires.txt
//   lockfiles      poetry.lock, Pipfile.lock, uv.lock, pdm.lock, pylock.toml (PEP 751), pinned requirements files
//   vendored       copies of other packages inside the archive (pip/_vendor, requests/packages, site-packages, nested dist-info)
//
// Nothing here runs Python or a package manager. What is not statically readable is reported (`notes`), never guessed.

import { parseToml } from './toml.js';
import { parseYaml } from './yaml.js';
import { parsePep508, classifyPypi } from './pinning.js';

const norm = n => String(n).toLowerCase().replace(/[-_.]+/g, '-');
const objectOf = v => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const arr = v => (Array.isArray(v) ? v : v == null ? [] : [v]);
const isHttp = u => /^http:\/\//i.test(u) && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(u);

// ── requirements files ───────────────────────────────────────────────────────────────────────────────────────────────────────────

/** @returns {{name:string, spec:string, extras:string[], marker:string|null, url:string|null, hashes:number, editable:boolean, file:string}} or null */
function requirementLine(line, file) {
  let t = line.trim();
  let editable = false;
  const e = /^(?:-e|--editable)(?:\s+|=)(.+)$/.exec(t);
  if (e) { editable = true; t = e[1].trim(); }
  let hashes = 0;
  t = t.replace(/\s--hash[= ]\S+/g, () => { hashes++; return ''; }).replace(/\s--(?:global-option|install-option|config-settings|no-binary|only-binary)[= ]\S+/g, '').trim();
  if (!t) return null;
  // VCS / URL / path requirements
  if (/^(?:git|hg|svn|bzr)\+|^[a-z][a-z0-9+.-]*:\/\//i.test(t) || /^(?:\.{1,2}\/|\/|~\/|\.$)/.test(t) || /\.(?:whl|tar\.gz|zip|tgz)(?:#.*)?$/i.test(t)) {
    const egg = /[#&]egg=([A-Za-z0-9._-]+)/.exec(t)?.[1];
    const base = t.split(/[#?]/)[0].replace(/\/+$/, '').split('/').pop().replace(/\.git(?:@.*)?$/, '').replace(/@.*$/, '').replace(/-\d[\w.]*(?:-.*)?\.(?:whl|tar\.gz|zip|tgz)$/i, '').replace(/\.(?:whl|tar\.gz|zip|tgz)$/i, '');
    return { name: egg || base || t, spec: `@ ${t.split(/\s+;/)[0]}`, extras: [], marker: /\s;\s*(.+)$/.exec(t)?.[1] || null, url: t.split(/\s+;/)[0], hashes, editable, file };
  }
  const p = parsePep508(t);
  if (!p) return null;
  return { name: p.name, spec: p.spec, extras: p.extras, marker: p.marker, url: p.url, hashes, editable, file };
}

/**
 * Parses a requirements file. `read(path)` returns the text of another file of the archive (or null) for `-r` / `-c`.
 * @returns {{entries:object[], constraints:object[], includes:string[], missing:string[], indexUrls:string[], extraIndexUrls:string[], findLinks:string[], trustedHosts:string[], requireHashes:boolean}}
 */
export function parseRequirementsTxt(text, { file = 'requirements.txt', read = () => null, _seen = new Set(), _depth = 0 } = {}) {
  const out = { entries: [], constraints: [], includes: [], missing: [], indexUrls: [], extraIndexUrls: [], findLinks: [], trustedHosts: [], requireHashes: false };
  if (_seen.has(file) || _depth > 8) return out;
  _seen.add(file);
  const lines = [];
  let buf = '';
  for (const raw of String(text).split(/\r?\n/)) {
    if (/\\\s*$/.test(raw)) { buf += raw.replace(/\\\s*$/, ' '); continue; }
    lines.push(buf + raw); buf = '';
  }
  if (buf) lines.push(buf);
  const dir = file.includes('/') ? file.slice(0, file.lastIndexOf('/') + 1) : '';
  const resolve = p => { const q = p.replace(/^\.\//, ''); return q.startsWith('/') ? q.replace(/^\/+/, '') : `${dir}${q}`.replace(/(^|\/)\.\//g, '$1'); };
  for (const raw of lines) {
    const line = raw.replace(/(^|\s)#.*$/, '').trim();
    if (!line) continue;
    let m;
    if ((m = /^(?:-r|--requirement)(?:\s+|=)(\S+)/.exec(line))) {
      const target = resolve(m[1]);
      out.includes.push(target);
      const t = read(target);
      if (t == null) out.missing.push(target);
      else { const sub = parseRequirementsTxt(t, { file: target, read, _seen, _depth: _depth + 1 }); for (const k of ['entries', 'constraints', 'includes', 'missing', 'indexUrls', 'extraIndexUrls', 'findLinks', 'trustedHosts']) out[k].push(...sub[k]); out.requireHashes ||= sub.requireHashes; }
      continue;
    }
    if ((m = /^(?:-c|--constraint)(?:\s+|=)(\S+)/.exec(line))) {
      const target = resolve(m[1]);
      const t = read(target);
      if (t == null) out.missing.push(target);
      else { const sub = parseRequirementsTxt(t, { file: target, read, _seen, _depth: _depth + 1 }); out.constraints.push(...sub.entries, ...sub.constraints); }
      continue;
    }
    if ((m = /^(?:-i|--index-url)(?:\s+|=)(\S+)/.exec(line))) { out.indexUrls.push(m[1]); continue; }
    if ((m = /^--extra-index-url(?:\s+|=)(\S+)/.exec(line))) { out.extraIndexUrls.push(m[1]); continue; }
    if ((m = /^(?:-f|--find-links)(?:\s+|=)(\S+)/.exec(line))) { out.findLinks.push(m[1]); continue; }
    if ((m = /^--trusted-host(?:\s+|=)(\S+)/.exec(line))) { out.trustedHosts.push(m[1]); continue; }
    if (/^--require-hashes\b/.test(line)) { out.requireHashes = true; continue; }
    if (/^--?[A-Za-z]/.test(line) && !/^-e\b|^--editable\b/.test(line)) continue;        // --no-binary, --prefer-binary, --pre …
    const r = requirementLine(line, file);
    if (r) out.entries.push(r);
  }
  return out;
}

// ── setup.py: a small static evaluator ───────────────────────────────────────────────────────────────────────────────────────────

const UNKNOWN = Symbol('unknown');
class FileRef { constructor(path) { this.path = path; } }

function tokenize(src) {
  const toks = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '#') { while (i < n && src[i] !== '\n') i++; continue; }
    if (c === '\n') { toks.push({ t: 'nl' }); i++; continue; }
    if (c === ' ' || c === '\t' || c === '\r' || c === '\f') { i++; continue; }
    if (c === '\\' && src[i + 1] === '\n') { i += 2; continue; }
    // strings, with an optional prefix
    const sm = /^([rRbBuUfF]{0,2})('''|"""|'|")/.exec(src.slice(i, i + 6));
    if (sm) {
      const prefix = sm[1].toLowerCase(), q = sm[2];
      let j = i + sm[0].length, val = '';
      const raw = prefix.includes('r');
      while (j < n && !src.startsWith(q, j)) {
        if (src[j] === '\\' && !raw && j + 1 < n) { const nx = src[j + 1]; val += nx === 'n' ? '\n' : nx === 't' ? '\t' : nx === '\n' ? '' : nx; j += 2; }
        else if (src[j] === '\\' && raw) { val += src[j] + (src[j + 1] || ''); j += 2; }
        else { val += src[j]; j++; }
        if (q.length === 1 && src[j] === '\n') break;                                     // an unterminated one-line string: stop at the line end
      }
      toks.push({ t: 'str', v: val, f: prefix.includes('f'), b: prefix.includes('b') });
      i = j + (src.startsWith(q, j) ? q.length : 0);
      continue;
    }
    const nm = /^[A-Za-z_][A-Za-z0-9_]*/.exec(src.slice(i, i + 80));
    if (nm) { toks.push({ t: 'name', v: nm[0] }); i += nm[0].length; continue; }
    const num = /^\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(src.slice(i, i + 40));
    if (num) { toks.push({ t: 'num', v: num[0] }); i += num[0].length; continue; }
    const op3 = src.slice(i, i + 3);
    if (op3 === '**=' || op3 === '...' ) { toks.push({ t: 'op', v: op3 }); i += 3; continue; }
    const op2 = src.slice(i, i + 2);
    if (['+=', '-=', '==', '!=', '<=', '>=', '**', '//', '->', ':=', '|=', '%='].includes(op2)) { toks.push({ t: 'op', v: op2 }); i += 2; continue; }
    toks.push({ t: 'op', v: c }); i++;
  }
  return toks;
}

/** Recursive-descent evaluator over the token list; values: string | array | Map (dict) | FileRef | UNKNOWN. */
function makeEvaluator(toks, env) {
  let p = 0;
  const peek = () => toks[p];
  const isOp = v => toks[p] && toks[p].t === 'op' && toks[p].v === v;
  const isName = v => toks[p] && toks[p].t === 'name' && toks[p].v === v;
  const skipNl = () => { while (toks[p] && toks[p].t === 'nl') p++; };

  function skipBalanced(open, close) {              // p is just after `open`
    let d = 1;
    while (p < toks.length && d > 0) { const x = toks[p++]; if (x.t === 'op') { if (x.v === open) d++; else if (x.v === close) d--; } }
  }
  function collectUntilClose(close) {               // raw tokens up to the matching close (p after the opener); leaves p after the closer
    const start = p; skipBalanced({ ')': '(', ']': '[', '}': '{' }[close], close);
    return toks.slice(start, p - 1);
  }

  function atom() {
    const x = peek();
    if (!x) return UNKNOWN;
    if (x.t === 'str') {
      let v = '', unknown = false;
      while (peek() && peek().t === 'str') { const s = toks[p++]; if (s.f && /\{/.test(s.v)) unknown = true; v += s.v; }
      return unknown ? UNKNOWN : v;
    }
    if (x.t === 'num') { p++; return UNKNOWN; }
    if (x.t === 'op' && (x.v === '[' || x.v === '(' || x.v === '{')) {
      const close = { '[': ']', '(': ')', '{': '}' }[x.v];
      p++;
      return display(x.v, close);
    }
    if (x.t === 'name') {
      p++;
      if (x.v === 'None' || x.v === 'True' || x.v === 'False') return UNKNOWN;
      if (x.v === 'lambda') return UNKNOWN;
      if (isOp('(')) { p++; return call(x.v); }
      return env.has(x.v) ? env.get(x.v) : UNKNOWN;
    }
    p++;
    return UNKNOWN;
  }

  function display(open, close) {
    skipNl();
    if (isOp(close)) { p++; return open === '{' ? new Map() : []; }
    const startP = p;
    // comprehension? look for a top-level `for` before the close
    let d = 0, hasFor = false;
    for (let q = p; q < toks.length; q++) {
      const x = toks[q];
      if (x.t === 'op' && '([{'.includes(x.v)) d++;
      else if (x.t === 'op' && ')]}'.includes(x.v)) { if (d === 0) break; d--; }
      else if (d === 0 && x.t === 'name' && x.v === 'for') { hasFor = true; break; }
    }
    if (hasFor) {
      const body = collectUntilClose(close);
      return comprehension(body);
    }
    p = startP;
    const items = [], dict = new Map();
    let isDict = open === '{';
    for (;;) {
      skipNl();
      if (isOp(close)) { p++; break; }
      if (isOp('*') || isOp('**')) { p++; const v = expr(); if (Array.isArray(v)) items.push(...v); else if (v instanceof Map) for (const [k, x] of v) dict.set(k, x); else items.push(UNKNOWN); }
      else {
        const k = expr();
        skipNl();
        if (isOp(':')) { p++; skipNl(); const v = expr(); isDict = true; if (typeof k === 'string') dict.set(k, v); else dict.set(Symbol('k'), v); }
        else items.push(k);
      }
      skipNl();
      if (isOp(',')) { p++; continue; }
      skipNl();
      if (isOp(close)) { p++; break; }
      // unexpected token: skip to the close
      skipBalanced({ ')': '(', ']': '[', '}': '{' }[close], close);
      break;
    }
    if (isDict && (open === '{')) return dict;
    return items;
  }

  function comprehension(body) {
    // `[l.strip() for l in open('requirements.txt')]` and friends: a file read; anything else is not statically known
    for (let q = 0; q < body.length; q++) {
      const x = body[q];
      if (x.t === 'name' && (x.v === 'open' || x.v === 'read_text' || x.v === 'parse_requirements') && body[q + 1]?.v === '(') {
        const s = body[q + 2];
        if (s && s.t === 'str') return new FileRef(s.v);
        return new FileRef(null);
      }
    }
    return UNKNOWN;
  }

  function call(name) {
    // p is just after '('
    const argStart = p;
    const argToks = collectUntilClose(')');
    const sub = argToks.length ? makeEvaluator(argToks.concat([{ t: 'nl' }]), env) : null;
    const first = sub ? sub.exprValue() : UNKNOWN;
    if (name === 'open' || name === 'parse_requirements' || name === 'read_requirements' || name === 'read_file' || name === 'read') {
      if (typeof first === 'string') return new FileRef(first);
      // open(os.path.join(HERE, 'requirements.txt')) : take the last string literal
      const lits = argToks.filter(x => x.t === 'str').map(x => x.v);
      return new FileRef(lits.length ? lits[lits.length - 1] : null);
    }
    if (['list', 'sorted', 'tuple', 'set', 'frozenset', 'reversed'].includes(name)) return first === UNKNOWN ? UNKNOWN : first;
    if (name === 'dict') {
      if (first instanceof Map) return first;
      const m = new Map();
      for (let q = 0; q + 2 < argToks.length; q++) if (argToks[q].t === 'name' && argToks[q + 1].v === '=' ) { const s = makeEvaluator(argToks.slice(q + 2).concat([{ t: 'nl' }]), env); m.set(argToks[q].v, s.exprValue()); }
      return m;
    }
    if (name === 'str' || name === 'Path' || name === 'PurePath') return first;
    void argStart;
    return UNKNOWN;
  }

  function postfix(v) {
    for (;;) {
      if (isOp('.') && toks[p + 1]?.t === 'name') {
        const m = toks[p + 1].v; p += 2;
        if (isOp('(')) {
          p++; const args = collectUntilClose(')');
          if (v instanceof FileRef) { /* .read() / .readlines() / .splitlines() / .strip() / .split() keep the file reference */ continue; }
          if (typeof v === 'string' && ['strip', 'lstrip', 'rstrip', 'lower', 'upper', 'format', 'replace', 'encode', 'decode'].includes(m)) { if (m === 'format' || m === 'replace' || m === 'encode' || m === 'decode') v = UNKNOWN; else v = m === 'strip' ? v.trim() : v; continue; }
          if (typeof v === 'string' && ['split', 'splitlines'].includes(m)) { const sepTok = args[0]; const sep = sepTok && sepTok.t === 'str' ? sepTok.v : null; v = m === 'splitlines' || sep == null ? v.split(/\r?\n/).filter(Boolean) : v.split(sep).filter(Boolean); continue; }
          if (Array.isArray(v) && ['copy'].includes(m)) { v = v.slice(); continue; }
          if (v instanceof Map && m === 'copy') { v = new Map(v); continue; }
          v = UNKNOWN; continue;
        }
        v = UNKNOWN; continue;
      }
      if (isOp('[')) {                                 // subscript / slice
        p++; skipBalanced('[', ']');
        v = v instanceof FileRef ? v : UNKNOWN; continue;
      }
      if (isOp('(') && v === UNKNOWN) { p++; skipBalanced('(', ')'); continue; }
      break;
    }
    return v;
  }

  function term() { return postfix(atom()); }
  function arith() {
    let v = term();
    while (isOp('+') || isOp('|')) {
      const op = toks[p++].v; skipNl();
      const r = term();
      if (op === '+') {
        if (Array.isArray(v) && Array.isArray(r)) v = v.concat(r);
        else if (typeof v === 'string' && typeof r === 'string') v += r;
        else if (v instanceof FileRef && r !== UNKNOWN) v = [v, ...(Array.isArray(r) ? r : [r])];
        else if (Array.isArray(v) && r instanceof FileRef) v = v.concat([r]);
        else v = UNKNOWN;
      } else if (v instanceof Map && r instanceof Map) v = new Map([...v, ...r]); else v = UNKNOWN;
    }
    // a `%` / `*` / `-` etc. makes the value non-literal
    while (peek() && peek().t === 'op' && ['%', '*', '-', '/'].includes(peek().v)) { p++; term(); v = UNKNOWN; }
    return v;
  }
  function expr() {
    let v = arith();
    // ternary: `a if cond else b` → both branches (a requirement list that depends on the platform is still a requirement list)
    while (isName('if')) {
      p++;
      // condition: skip to `else` at depth 0
      let d = 0;
      while (p < toks.length) { const x = toks[p]; if (x.t === 'op' && '([{'.includes(x.v)) d++; else if (x.t === 'op' && ')]}'.includes(x.v)) { if (d === 0) break; d--; } else if (d === 0 && x.t === 'name' && x.v === 'else') break; else if (d === 0 && x.t === 'nl') break; p++; }
      if (isName('else')) { p++; const b = arith(); if (Array.isArray(v) && Array.isArray(b)) v = v.concat(b); else if (v === UNKNOWN) v = b; }
      else v = UNKNOWN;
    }
    // trailing `and` / `or` / comparison: not a literal
    while (peek() && (peek().t === 'name' && ['and', 'or', 'in', 'not', 'is'].includes(peek().v) || (peek().t === 'op' && ['==', '!=', '<', '>', '<=', '>='].includes(peek().v)))) { p++; arith(); v = UNKNOWN; }
    return v;
  }
  return { expr, exprValue: () => { skipNl(); return expr(); }, pos: () => p, setPos: q => { p = q; }, peek, isOp, skipNl, skipBalanced };
}

function flattenRequirements(v, readFile, notes, what) {
  const out = [];
  const files = [];
  const walk = x => {
    if (typeof x === 'string') { for (const l of x.split(/\r?\n/)) if (l.trim()) out.push(l.trim()); }
    else if (Array.isArray(x)) x.forEach(walk);
    else if (x instanceof FileRef) files.push(x.path);
    else if (x === UNKNOWN) notes.add(`${what} is computed when setup.py runs, so it cannot be read statically`);
  };
  walk(v);
  return { lines: out, files };
}

/**
 * Reads setup.py without running it.
 * @returns {{found:boolean, install:{lines:string[],files:(string|null)[]}, setup:{...}, tests:{...}, extras:Map<string,{lines,files}>, dependencyLinks:string[], notes:string[], requirementsFiles:string[]}}
 */
export function parseSetupPy(src) {
  const notes = new Set();
  const res = { found: false, install: { lines: [], files: [] }, setup: { lines: [], files: [] }, tests: { lines: [], files: [] }, extras: new Map(), dependencyLinks: [], notes: [], literalFiles: [] };
  const toks = tokenize(src);
  const env = new Map();
  const ev = makeEvaluator(toks, env);
  // pass 1: statements `NAME = expr`, `NAME += expr`, `NAME.append(x)`, `NAME.extend(x)`; stops at nothing (any indentation counts)
  ev.setPos(0);
  const n = toks.length;
  let i = 0;
  const startsStmt = k => k === 0 || toks[k - 1].t === 'nl' || (toks[k - 1].t === 'op' && [':', ';'].includes(toks[k - 1].v));
  const evalAt = pos => { ev.setPos(pos); return ev.exprValue(); };
  const setupCalls = [];
  while (i < n) {
    const x = toks[i];
    if (x.t === 'name' && startsStmt(i) && toks[i + 1]?.t === 'op' && toks[i + 1].v === '=' && toks[i + 2] && !(toks[i + 2].t === 'op' && toks[i + 2].v === '=')) {
      const v = evalAt(i + 2);
      env.set(x.v, v);
      i = Math.max(ev.pos(), i + 3); continue;
    }
    if (x.t === 'name' && startsStmt(i) && toks[i + 1]?.t === 'op' && toks[i + 1].v === '+=') {
      const v = evalAt(i + 2), cur = env.get(x.v);
      env.set(x.v, Array.isArray(cur) && Array.isArray(v) ? cur.concat(v) : typeof cur === 'string' && typeof v === 'string' ? cur + v : UNKNOWN);
      i = Math.max(ev.pos(), i + 3); continue;
    }
    if (x.t === 'name' && startsStmt(i) && toks[i + 1]?.v === '.' && toks[i + 2]?.t === 'name' && ['append', 'extend', 'insert'].includes(toks[i + 2].v) && toks[i + 3]?.v === '(') {
      const m = toks[i + 2].v;
      let argPos = i + 4;
      if (m === 'insert') { while (argPos < n && !(toks[argPos].t === 'op' && toks[argPos].v === ',')) argPos++; argPos++; }
      const v = evalAt(argPos), cur = env.get(x.v);
      if (Array.isArray(cur)) env.set(x.v, m === 'extend' ? cur.concat(Array.isArray(v) ? v : [v]) : cur.concat([v]));
      i = Math.max(ev.pos(), i + 4); continue;
    }
    if (x.t === 'name' && x.v === 'setup' && toks[i + 1]?.v === '(') { setupCalls.push(i + 2); i += 2; continue; }
    i++;
  }
  // pass 2: the keyword arguments of each setup(...) call
  for (const start of setupCalls) {
    res.found = true;
    ev.setPos(start);
    for (;;) {
      ev.skipNl();
      const t = ev.peek();
      if (!t || ev.isOp(')')) break;
      if (ev.isOp('*') || ev.isOp('**')) { const q = ev.pos() + 1; ev.setPos(q); ev.expr(); if (ev.isOp(',')) ev.setPos(ev.pos() + 1); continue; }
      if (t.t === 'name' && toks[ev.pos() + 1]?.t === 'op' && toks[ev.pos() + 1].v === '=') {
        const key = t.v;
        ev.setPos(ev.pos() + 2);
        const v = (() => { ev.skipNl(); return ev.expr(); })();
        const bucket = key === 'install_requires' ? 'install' : key === 'setup_requires' ? 'setup' : key === 'tests_require' ? 'tests' : null;
        if (bucket) { const f = flattenRequirements(v, null, notes, key); res[bucket].lines.push(...f.lines); res[bucket].files.push(...f.files); }
        else if (key === 'extras_require') {
          if (v instanceof Map) for (const [k, val] of v) { const f = flattenRequirements(val, null, notes, `extras_require[${typeof k === 'string' ? k : '?'}]`); const kk = typeof k === 'string' ? k : '(computed)'; const cur = res.extras.get(kk) || { lines: [], files: [] }; cur.lines.push(...f.lines); cur.files.push(...f.files); res.extras.set(kk, cur); }
          else notes.add('extras_require is computed when setup.py runs, so it cannot be read statically');
        } else if (key === 'dependency_links') { const f = flattenRequirements(v, null, notes, key); res.dependencyLinks.push(...f.lines); }
        if (ev.isOp(',')) ev.setPos(ev.pos() + 1);
        continue;
      }
      // positional argument or something unrecognised: skip it
      ev.expr(); if (ev.isOp(',')) ev.setPos(ev.pos() + 1); else break;
    }
  }
  // any requirements-like file name that setup.py names is a candidate even when the path is computed
  res.literalFiles = [...new Set([...src.matchAll(/['"]([A-Za-z0-9_./-]*requirements[A-Za-z0-9_.-]*\.(?:txt|in))['"]/g)].map(m => m[1]))];
  res.notes = [...notes];
  return res;
}

// ── setup.cfg ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

export function parseIni(text) {
  const out = {};
  let sec = null, key = null;
  for (const raw of String(text).split(/\r?\n/)) {
    if (/^\s*[#;]/.test(raw)) continue;
    const s = /^\[([^\]]+)\]\s*$/.exec(raw);
    if (s) { sec = s[1].trim(); out[sec] = out[sec] || {}; key = null; continue; }
    if (sec == null) continue;
    if (/^\s+\S/.test(raw) && key) { out[sec][key] += `\n${raw.trim()}`; continue; }
    const kv = /^([^=:\s][^=:]*?)\s*[=:]\s*(.*)$/.exec(raw);
    if (kv) { key = kv[1].trim(); out[sec][key] = kv[2].trim(); }
  }
  return out;
}

// ── lockfiles ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

/** A lock entry: {name, version, source:'registry'|'git'|'url'|'path', url, ref, group, hashes, editable} */
const entry = (name, version, extra = {}) => ({ name: String(name), version: version == null ? null : String(version), source: 'registry', url: null, ref: null, group: null, hashes: 0, editable: false, ...extra });

function poetryLock(text) {
  const { data } = parseToml(text);
  const pk = arr(data.package);
  const out = pk.map(p => {
    const s = objectOf(p.source);
    const t = s.type;
    const src = t === 'git' ? 'git' : t === 'directory' || t === 'file' ? 'path' : t === 'url' ? 'url' : 'registry';
    const groups = arr(p.groups);
    return entry(p.name, p.version, { source: src, url: s.url || null, ref: s.resolved_reference || s.reference || null, group: groups.length ? (groups.includes('main') ? 'main' : groups.join(',')) : p.category || null, hashes: arr(p.files).length, optional: Boolean(p.optional), editable: Boolean(s.develop) });
  });
  const md = objectOf(data.metadata);
  return { entries: out, meta: { lockVersion: md['lock-version'] ?? null, contentHash: md['content-hash'] ?? null, python: md['python-versions'] ?? null } };
}

function uvLock(text) {
  const { data } = parseToml(text);
  const out = [];
  for (const p of arr(data.package)) {
    const s = objectOf(p.source);
    if (s.virtual != null || s.editable === '.' || s.directory === '.') continue;           // the project itself
    const src = s.git ? 'git' : s.url ? 'url' : s.path || s.directory || s.editable ? 'path' : 'registry';
    out.push(entry(p.name, p.version, { source: src, url: s.git || s.url || s.registry || s.path || s.directory || s.editable || null, hashes: arr(p.wheels).length + (p.sdist ? 1 : 0), editable: Boolean(s.editable) }));
  }
  return { entries: out, meta: { lockVersion: data.version ?? null, requiresPython: data['requires-python'] ?? null } };
}

function pdmLock(text) {
  const { data } = parseToml(text);
  const out = arr(data.package).map(p => entry(p.name, p.version, { source: p.git ? 'git' : p.url ? 'url' : p.path ? 'path' : 'registry', url: p.git || p.url || p.path || null, ref: p.revision || p.ref || null, group: arr(p.groups).join(',') || null, hashes: arr(p.files).length, editable: Boolean(p.editable) }));
  const md = objectOf(data.metadata);
  return { entries: out, meta: { contentHash: md.content_hash ?? null, strategy: arr(md.strategy).join(',') || null, groups: arr(md.groups) } };
}

function pylock(text) {
  const { data } = parseToml(text);
  const out = arr(data.packages).map(p => {
    const vcs = objectOf(p.vcs), dir = objectOf(p.directory), arch = objectOf(p.archive);
    const src = vcs.url ? 'git' : dir.path ? 'path' : arch.url ? 'url' : 'registry';
    return entry(p.name, p.version, { source: src, url: vcs.url || dir.path || arch.url || null, ref: vcs['commit-id'] || null, hashes: arr(p.wheels).length + (p.sdist ? 1 : 0), editable: Boolean(dir.editable) });
  });
  return { entries: out, meta: { lockVersion: data['lock-version'] ?? null, createdBy: data['created-by'] ?? null, requiresPython: data['requires-python'] ?? null } };
}

function pipfileLock(text) {
  let j; try { j = JSON.parse(text); } catch { return null; }
  const out = [];
  for (const [section, group] of [['default', 'default'], ['develop', 'develop']]) {
    for (const [name, d] of Object.entries(objectOf(j[section]))) {
      const v = typeof d.version === 'string' ? d.version.replace(/^===?/, '') : null;
      out.push(entry(name, v, { source: d.git ? 'git' : d.path || d.file ? 'path' : 'registry', url: d.git || d.path || d.file || null, ref: d.ref || null, group, hashes: arr(d.hashes).length, editable: Boolean(d.editable) }));
    }
  }
  const meta = objectOf(j._meta);
  return { entries: out, meta: { sources: arr(meta.sources).map(s => s.url).filter(Boolean), requires: meta.requires ?? null, sha256: objectOf(meta.hash).sha256 ?? null } };
}

// ── Pipfile / conda / egg-info ───────────────────────────────────────────────────────────────────────────────────────────────

function pipfileDeps(text) {
  const { data } = parseToml(text);
  const out = [];
  const sources = arr(data.source).map(s => objectOf(s));
  for (const [section, kind] of [['packages', 'runtime'], ['dev-packages', 'dev']]) {
    for (const [name, v] of Object.entries(objectOf(data[section]))) {
      if (typeof v === 'string') out.push({ name, spec: v === '*' ? '' : v, kind, url: null });
      else {
        const o = objectOf(v);
        if (o.git || o.path || o.file) out.push({ name, spec: o.git || o.path || o.file, kind, url: o.git || o.path || o.file, ref: o.ref || null, editable: Boolean(o.editable) });
        else out.push({ name, spec: o.version === '*' ? '' : o.version || '', kind, url: null, marker: o.markers || null, extras: arr(o.extras), index: o.index || null });
      }
    }
  }
  return { deps: out, sources, python: objectOf(data.requires).python_version || objectOf(data.requires).python_full_version || null };
}

function condaEnv(text) {
  let y; try { y = parseYaml(text); } catch { return null; }
  if (!y || typeof y !== 'object') return null;
  const conda = [], pip = [];
  for (const d of arr(y.dependencies)) {
    if (typeof d === 'string') conda.push(d);
    else if (d && typeof d === 'object' && Array.isArray(d.pip)) pip.push(...d.pip.filter(x => typeof x === 'string'));
  }
  return { name: y.name || null, channels: arr(y.channels).filter(x => typeof x === 'string'), conda, pip };
}

function eggRequires(text) {
  const lines = [];
  let section = '';
  for (const raw of String(text).split(/\r?\n/)) {
    const l = raw.trim();
    if (!l) continue;
    const s = /^\[([^\]]*)\]$/.exec(l);
    if (s) { section = s[1]; continue; }
    const [extra, marker] = section.split(':');
    const parts = [];
    if (extra) parts.push(`extra == "${extra}"`);
    if (marker) parts.push(`(${marker})`);
    lines.push(parts.length ? `${l}; ${parts.join(' and ')}` : l);
  }
  return lines;
}

// ── vendored packages ────────────────────────────────────────────────────────────────────────────────────────────────────────────

const VENDOR_PARENT_STRONG = /(?:^|\/)(?:_vendor|_vendored|vendor|vendored|third_party|third-party|thirdparty|_extern|extern|externals?)$/i;
const VENDOR_PARENT_WEAK = /(?:^|\/)(?:packages|libs?|deps|external_libs?)$/i;
const ALIAS = { yaml: 'PyYAML', bs4: 'beautifulsoup4', PIL: 'Pillow', dateutil: 'python-dateutil', OpenSSL: 'pyOpenSSL', attr: 'attrs', attrs: 'attrs', jwt: 'PyJWT', jose: 'python-jose', Crypto: 'pycryptodome', sklearn: 'scikit-learn', cv2: 'opencv-python', git: 'GitPython', serial: 'pyserial', usb: 'pyusb', magic: 'python-magic', socks: 'PySocks', zmq: 'pyzmq', pkg_resources: 'setuptools', _pytest: 'pytest', markdown: 'Markdown', pygments: 'Pygments', cachecontrol: 'CacheControl', msgpack: 'msgpack', tomli: 'tomli', idna: 'idna', ruamel: 'ruamel.yaml' };
// names that are certainly third-party libraries when found under an ambiguous parent such as `packages/`
const KNOWN_THIRD_PARTY = new Set(['urllib3', 'chardet', 'charade', 'charset_normalizer', 'idna', 'certifi', 'six', 'requests', 'simplejson', 'yaml', 'jinja2', 'markupsafe', 'docutils', 'pygments', 'packaging', 'pyparsing', 'attr', 'dateutil', 'pytz', 'tornado', 'mock', 'colorama', 'oauthlib', 'cachecontrol', 'msgpack', 'toml', 'tomli', 'lockfile', 'webencodings', 'html5lib', 'ordereddict', 'simplejson', 'typing_extensions', 'markdown', 'future', 'enum', 'ipaddress', 'backports', 'distlib', 'pep517', 'platformdirs', 'resolvelib', 'rich', 'tenacity', 'truststore', 'distro', 'progress', 'bs4', 'lxml']);

const VALID_VERSION = /^v?\d+(?:\.\d+)*(?:[-._]?(?:a|b|c|rc|alpha|beta|pre|post|dev|final)?\d*)*(?:\+[A-Za-z0-9.]+)?$/i;
function versionFromSource(text) {
  const v = versionFromSource0(text);
  return v && VALID_VERSION.test(v.trim()) ? v.trim().replace(/^v(?=\d)/i, '') : null;          // `__version__ = 'dev'` (urllib3 before 1.8) is not a version
}
function versionFromSource0(text) {
  if (!text) return null;
  let m = /^\s*__version__\s*=\s*['"]([^'"\n]+)['"]/m.exec(text) || /^\s*(?:VERSION|version|__VERSION__)\s*=\s*['"]([^'"\n]+)['"]/m.exec(text);
  if (m) return m[1];
  m = /^\s*(?:__version_info__|version_info|VERSION|__version_tuple__)\s*=\s*\(\s*(\d+)\s*,\s*(\d+)(?:\s*,\s*(\d+))?/m.exec(text);
  if (m) return [m[1], m[2], m[3]].filter(x => x != null).join('.');
  return null;
}

/** @param {{all():object[], find(p):object, text(f,max?):string|null}} fx */
export function detectVendored(fx, ownName) {
  const files = fx.all().filter(f => !/(?:^|\/)(?:tests?|testing|test[-_]?data|testdata|fixtures?|examples?|docs?|benchmarks?|e2e)\//i.test(f.path));
  const byPath = new Map(files.map(f => [f.path, f]));
  const out = [], unversioned = [];
  const seen = new Set();
  const own = norm(ownName || '');
  const textOf = p => { const f = byPath.get(p); return f ? fx.text(f, 256 * 1024) : null; };

  // pinned list of a vendor directory (pip's _vendor/vendor.txt)
  const vendorTxt = new Map();
  for (const f of files) if (/(?:^|\/)vendor\.txt$/.test(f.path) && VENDOR_PARENT_STRONG.test(f.path.replace(/\/vendor\.txt$/, ''))) {
    const t = fx.text(f, 64 * 1024) || '';
    const m = new Map();
    for (const l of t.split(/\r?\n/)) { const r = /^([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([^\s;#]+)/.exec(l.trim()); if (r) m.set(norm(r[1]), r[2]); }
    vendorTxt.set(f.path.replace(/\/vendor\.txt$/, ''), m);
  }

  const add = (name, version, path, how) => {
    if (norm(name) === own) return;
    const key = `${norm(name)}|${path}`;
    if (seen.has(key)) return;
    seen.add(key);
    if (version) out.push({ name, version, path, declaredBundled: false, source: how });
    else unversioned.push({ name, path, source: how });
  };

  // 1) nested dist-info / egg-info (a bundled environment, or a vendored wheel's metadata)
  for (const f of files) {
    const m = /^(.+)\/([^/]+)-([^/-]+(?:\.[^/-]+)*)\.dist-info\/METADATA$/.exec(f.path);
    if (m) { add(m[2], m[3], m[1], 'nested dist-info'); continue; }
    const e = /^(.+)\/([^/]+)\.egg-info\/PKG-INFO$/.exec(f.path);
    if (e) { const t = fx.text(f, 64 * 1024) || ''; const nm = /^Name:\s*(.+)$/m.exec(t)?.[1]?.trim(), vv = /^Version:\s*(.+)$/m.exec(t)?.[1]?.trim(); if (nm && vv && !/^[^/]+\.egg-info$/.test(f.path.split('/').slice(-2)[0])) add(nm, vv, e[1], 'nested egg-info'); }
  }

  // 2) packages / modules directly under a vendor directory
  const dirs = new Map();                                    // dir path → {parent, name, files:Set}
  for (const f of files) {
    const parts = f.path.split('/');
    for (let k = 1; k < parts.length; k++) {
      const parent = parts.slice(0, k).join('/');
      const isStrong = VENDOR_PARENT_STRONG.test(parent), isWeak = VENDOR_PARENT_WEAK.test(parent) && parent.includes('/');
      if (!isStrong && !isWeak) continue;
      const name = parts[k];
      if (k === parts.length - 1) {                           // a single-file module: six.py
        if (/\.py$/.test(name) && !/^__init__\.py$/.test(name)) { const mod = name.replace(/\.py$/, ''); const key = `${parent}/${name}`; if (!dirs.has(key)) dirs.set(key, { parent, name: mod, single: f.path, strong: isStrong }); }
      } else {
        const key = `${parent}/${name}`;
        if (!dirs.has(key)) dirs.set(key, { parent, name, single: null, strong: isStrong });
      }
      break;
    }
  }
  for (const [path, d] of dirs) {
    const lower = d.name.toLowerCase();
    if (/^(?:tests?|docs?|__pycache__|examples?|scripts?|bin|data|static|templates|_vendor|vendor)$/.test(lower) || /\.(?:dist|egg)-info$/.test(d.name) || /\.dist-info$/.test(d.name)) continue;
    if (!d.single && !byPath.has(`${path}/__init__.py`)) continue;                     // a Python package has an __init__.py
    const known = KNOWN_THIRD_PARTY.has(lower) || ALIAS[d.name];
    // `packages/`, `libs/` … only count as vendor directories for libraries we recognise, or for a sub-package that carries its own readable version
    if (!d.strong && !known && !(!d.single && versionFromSource(textOf(`${path}/__init__.py`)))) continue;
    if (!d.strong) { if (!byPath.has(`${d.parent}/__init__.py`) && !byPath.has(`${d.parent}/__init__.pyi`)) continue; }
    const pypi = ALIAS[d.name] || d.name.replace(/_/g, '-');
    let version = vendorTxt.get(d.parent)?.get(norm(pypi)) || vendorTxt.get(d.parent)?.get(norm(d.name)) || null;
    let how = version ? 'vendor.txt' : null;
    if (!version) {
      const candidates = d.single ? [d.single] : [`${path}/__init__.py`, `${path}/_version.py`, `${path}/version.py`, `${path}/__version__.py`, `${path}/__about__.py`, `${path}/_metadata.py`, `${path}/about.py`, `${path}/release.py`];
      for (const c of candidates) { const v = versionFromSource(textOf(c)); if (v) { version = v; how = `__version__ in ${c.split('/').pop()}`; break; } }
    }
    if (!version) {                                              // a sibling <name>-<version>.dist-info/METADATA
      for (const f of files) { const m = new RegExp(`^${path.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}-([^/]+)\\.(?:dist-info|egg-info)/`).exec(f.path); if (m) { version = m[1]; how = 'sibling dist-info'; break; } }
    }
    add(pypi, version, path, how ? `vendored Python package (${how})` : 'vendored Python package');
  }
  return { bundled: out, unversioned };
}

// ── the one entry point used by analyzePypi ─────────────────────────────────────────────────────────────────────────────────────

// dependency files that belong to a project's own tests, docs, examples or vendored libraries describe those, not the package
const NOISE_DIR = /(?:^|\/)(?:tests?|testing|test[-_]?data|testdata|fixtures?|examples?|samples?|demos?|docs?|documentation|benchmarks?|e2e|integration|\.github|\.tox|\.venv|venv|node_modules|_vendor|_vendored|vendor|third_party)\//i;
const REQ_FILE = /(?:^|\/)(?:requirements|constraints)[A-Za-z0-9_.-]*\.(?:txt|in)$|(?:^|\/)requirements\/[A-Za-z0-9_.-]+\.(?:txt|in)$/i;
const LOCK_FILES = [
  [/(?:^|\/)poetry\.lock$/, 'poetry.lock', 'Poetry', poetryLock],
  [/(?:^|\/)uv\.lock$/, 'uv.lock', 'uv', uvLock],
  [/(?:^|\/)pdm\.lock$/, 'pdm.lock', 'PDM', pdmLock],
  [/(?:^|\/)pylock(?:\.[A-Za-z0-9_-]+)?\.toml$/, 'pylock.toml', 'PEP 751', pylock],
  [/(?:^|\/)Pipfile\.lock$/, 'Pipfile.lock', 'Pipenv', pipfileLock],
];

/**
 * @param {object} fx archive helper (manifests.js Files)
 * @returns {{
 *   lines: {line:string, kind:string, file:string, extraName?:string}[],       PEP 508 strings (feed them to addDep)
 *   direct: {name, spec, url, kind, file, marker, extras}[],                    requirements that are not plain PEP 508 (VCS / URL / path)
 *   locked: object[], lockfiles: object[], issues: object[], notes: string[], manifestFiles: string[], bundled: object[], unversioned: object[], requirementsFiles: object[] }}
 */
export function collectPython(fx, { pkg, referenced = new Set() } = {}) {
  const out = { lines: [], direct: [], locked: [], lockfiles: [], issues: [], notes: [], manifestFiles: [], bundled: [], unversioned: [], requirementsFiles: [], consumerFiles: new Set() };
  let ignored = 0;
  const notes = new Set();
  const readText = p => { const f = fx.find(p.replace(/^\.\//, '')); return f ? fx.text(f) : null; };
  const reqRefs = new Set();                                   // requirements files that setup.py / setup.cfg / pyproject read for the consumer's dependencies
  const addLines = (lines, kind, file, extraName) => { for (const l of lines) out.lines.push({ line: l, kind, file, extraName }); };

  // ── setup.py ──
  const setupPy = fx.find('setup.py');
  if (setupPy) {
    const t = fx.text(setupPy) || '';
    const sp = parseSetupPy(t);
    out.manifestFiles.push('setup.py');
    const take = (bucket, kind) => {
      addLines(bucket.lines, kind, 'setup.py');
      for (const fp of bucket.files) {
        if (fp == null) { notes.add('setup.py reads its requirements from a file whose path is computed when it runs'); for (const lf of sp.literalFiles) reqRefs.add(lf); continue; }
        reqRefs.add(fp.replace(/^\.\//, ''));
      }
    };
    take(sp.install, 'runtime'); take(sp.setup, 'build'); take(sp.tests, 'dev');
    for (const [k, v] of sp.extras) { addLines(v.lines.map(l => `${l}${/;/.test(l) ? ' and' : ';'} extra == "${k}"`), 'runtime', 'setup.py', k); for (const fp of v.files) if (fp) reqRefs.add(fp.replace(/^\.\//, '')); }
    for (const n of sp.notes) notes.add(n);
    if (sp.dependencyLinks.length) out.issues.push({ rule: 'package.dep.non_registry', key: 'dependency_links', detail: `setup.py sets dependency_links (${sp.dependencyLinks.slice(0, 3).join(', ')}): pip no longer honours it, but older tools fetch dependencies from those URLs instead of the registry`, file: 'setup.py' });
    if (!sp.found) notes.add('setup.py has no setup() call that could be read; its dependencies, if any, are not listed from it');
    else if (!sp.install.lines.length && !sp.install.files.length && /install_requires/.test(t) && !notes.size) notes.add('setup.py names install_requires but its value could not be read statically');
  }

  // ── setup.cfg ──
  const cfgText = fx.textOf('setup.cfg');
  if (cfgText) {
    out.manifestFiles.push('setup.cfg');
    const ini = parseIni(cfgText);
    const opt = ini.options || {};
    const lineList = (v, dest, kind, extraName) => {
      if (!v) return;
      const fm = /^file\s*:\s*(.+)$/im.exec(v);
      if (fm) { for (const fp of fm[1].split(/[,\s]+/).filter(Boolean)) reqRefs.add(fp.replace(/^\.\//, '')); return; }
      if (/^attr\s*:/i.test(v)) { notes.add('setup.cfg takes a requirement list from a Python attribute (attr:), which is not read'); return; }
      addLines(v.split(/\r?\n|;(?=\s*\w+\s*[=<>~!])/).map(s => s.trim()).filter(s => s && !s.startsWith('#')), kind, 'setup.cfg', extraName);
    };
    lineList(opt.install_requires, null, 'runtime');
    lineList(opt.setup_requires, null, 'build');
    lineList(opt.tests_require, null, 'dev');
    for (const [k, v] of Object.entries(ini['options.extras_require'] || {})) {
      const fm = /^file\s*:\s*(.+)$/im.exec(v);
      if (fm) { for (const fp of fm[1].split(/[,\s]+/).filter(Boolean)) reqRefs.add(fp.replace(/^\.\//, '')); continue; }
      addLines(String(v).split(/\r?\n/).map(s => s.trim()).filter(Boolean).map(l => `${l}${/;/.test(l) ? ' and' : ';'} extra == "${k.replace(/:.*$/, '')}"`), 'runtime', 'setup.cfg', k);
    }
    if (opt.dependency_links) out.issues.push({ rule: 'package.dep.non_registry', key: 'cfg-dependency_links', detail: 'setup.cfg sets dependency_links: those URLs replace the registry for the listed dependencies in older tools', file: 'setup.cfg' });
  }

  // ── pyproject.toml extras (the core blocks stay in manifests.js) ──
  const pyp = fx.textOf('pyproject.toml');
  if (pyp) {
    const { data } = parseToml(pyp);
    const project = objectOf(data.project), tool = objectOf(data.tool);
    // PEP 735 dependency groups
    const groups = objectOf(data['dependency-groups']);
    const resolveGroup = (name, seen = new Set()) => {
      if (seen.has(name)) return [];
      seen.add(name);
      const lines = [];
      for (const it of arr(groups[name])) {
        if (typeof it === 'string') lines.push(it);
        else if (it && typeof it === 'object' && it['include-group']) lines.push(...resolveGroup(it['include-group'], seen));
      }
      return lines;
    };
    for (const g of Object.keys(groups)) addLines(resolveGroup(g), 'dev', 'pyproject.toml', `group:${g}`);
    // dynamic = ["dependencies"] with tool.setuptools.dynamic
    const dyn = objectOf(objectOf(tool.setuptools).dynamic);
    for (const key of ['dependencies', 'optional-dependencies']) {
      const d = key === 'dependencies' ? objectOf(dyn.dependencies) : dyn['optional-dependencies'];
      if (key === 'dependencies') for (const fp of arr(d.file)) reqRefs.add(String(fp).replace(/^\.\//, ''));
      else for (const v of Object.values(objectOf(d))) for (const fp of arr(objectOf(v).file)) reqRefs.add(String(fp).replace(/^\.\//, ''));
    }
    if (arr(project.dynamic).includes('dependencies') && !Object.keys(dyn).length && !fx.find('setup.py')) notes.add('pyproject.toml marks dependencies as dynamic, computed by the build backend; they cannot be read statically (the wheel METADATA, when downloaded, lists them)');
    // Poetry
    const poetry = objectOf(tool.poetry);
    const poetryDeps = (tbl, kind, extraName, file = 'pyproject.toml') => {
      for (const [n, v] of Object.entries(objectOf(tbl))) {
        if (n === 'python') continue;
        for (const one of arr(v)) {
          if (typeof one === 'string') out.direct.push({ name: n, spec: one, kind, file, poetry: true, extraName });
          else if (one && typeof one === 'object') {
            if (one.git || one.path || one.url) out.direct.push({ name: n, spec: one.git || one.path || one.url, url: one.git || one.path || one.url, ref: one.rev || one.tag || one.branch || null, kind, file, extraName, source: one.git ? 'git' : one.path ? 'path' : 'url' });
            else out.direct.push({ name: n, spec: typeof one.version === 'string' ? one.version : '', kind: one.optional && kind === 'runtime' ? 'extra' : kind, file, poetry: true, marker: one.markers || one.python || null, extras: arr(one.extras), extraName });
          }
        }
      }
    };
    poetryDeps(poetry['dev-dependencies'], 'dev');
    for (const [g, body] of Object.entries(objectOf(poetry.group))) poetryDeps(objectOf(body).dependencies, g === 'main' ? 'runtime' : 'dev', `group:${g}`);
    // PDM / uv / Hatch / Flit
    const pdm = objectOf(tool.pdm);
    for (const [g, list] of Object.entries(objectOf(pdm['dev-dependencies']))) addLines(arr(list).map(String), 'dev', 'pyproject.toml', `group:${g}`);
    const uv = objectOf(tool.uv);
    addLines(arr(uv['dev-dependencies']).map(String), 'dev', 'pyproject.toml', 'group:dev');
    for (const [n, src] of Object.entries(objectOf(uv.sources))) {
      const s = objectOf(Array.isArray(src) ? src[0] : src);
      if (s.git || s.url || s.path || s.workspace) out.issues.push({ rule: 'package.dep.non_registry', key: `uv-source:${n}`, detail: `pyproject.toml [tool.uv.sources] takes ${n} from ${s.git ? `git ${s.git}` : s.url ? `URL ${s.url}` : s.path ? `path ${s.path}` : 'the workspace'} instead of the registry (uv only; other installers ignore it)`, file: 'pyproject.toml' });
    }
    const flit = objectOf(objectOf(tool.flit).metadata);
    addLines(arr(flit.requires).map(String), 'runtime', 'pyproject.toml');
    for (const [k, list] of Object.entries(objectOf(flit['requires-extra']))) addLines(arr(list).map(l => `${l}; extra == "${k}"`), 'runtime', 'pyproject.toml', k);
    const hatchMeta = objectOf(objectOf(tool.hatch).metadata);
    if (hatchMeta['allow-direct-references']) notes.add('pyproject.toml allows direct references (hatch): a dependency may be a URL or VCS requirement instead of a registry release');
    for (const [name, env] of Object.entries(objectOf(objectOf(tool.hatch).envs))) addLines(arr(objectOf(env).dependencies).map(String), 'dev', 'pyproject.toml', `env:${name}`);
    // tox / nox style test dependencies are not read
  }

  // ── requirements files ──
  const reqSet = new Set(fx.findAll(REQ_FILE).map(f => f.path).filter(p => !NOISE_DIR.test(p) || (ignored++, false)));
  for (const r of reqRefs) { const p = String(r).replace(/^\.\//, ''); if (!reqSet.has(p) && fx.find(p)) reqSet.add(p); }      // a file the build names, whatever it is called
  const reqFiles = [...reqSet].sort();
  const parsedReq = new Map();
  for (const path of reqFiles) {
    const t = readText(path);
    if (t == null) continue;
    parsedReq.set(path, parseRequirementsTxt(t, { file: path, read: readText }));
  }
  const consumerReq = new Set();
  const markConsumer = p => { if (parsedReq.has(p)) consumerReq.add(p); for (const inc of parsedReq.get(p)?.includes || []) markConsumer(inc); };
  for (const r of reqRefs) { const p = r.replace(/^\.\//, ''); if (parsedReq.has(p)) markConsumer(p); else { const alt = [...parsedReq.keys()].find(k => k.endsWith(`/${p}`) || k === p); if (alt) markConsumer(alt); } }
  const covered = new Set();                                   // files already included by another requirements file
  for (const [, pr] of parsedReq) for (const inc of pr.includes) covered.add(inc);
  for (const path of reqFiles) {
    const pr = parsedReq.get(path);
    if (!pr) continue;
    out.manifestFiles.push(path);
    const entries = pr.entries;
    const pinned = entries.filter(e => !e.url && /^===?\s*[^*\s]+$/.test(e.spec.replace(/\s/g, '')) && !e.spec.includes('*'));
    const isLockLike = entries.length >= 3 && pinned.length / entries.length >= 0.8;
    const forConsumer = consumerReq.has(path);
    out.requirementsFiles.push({ file: path, entries: entries.length, pinned: pinned.length, hashes: entries.filter(e => e.hashes).length, includes: pr.includes, constraints: pr.constraints.length, role: forConsumer ? 'dependency list (read by the build)' : isLockLike ? 'pinned list' : 'not read by the build', indexUrls: pr.indexUrls, extraIndexUrls: pr.extraIndexUrls, missing: pr.missing });
    for (const m of pr.missing) notes.add(`${path} includes ${m}, which is not in the archive`);
    for (const u of pr.extraIndexUrls) out.issues.push({ rule: 'package.dep.non_registry', key: `extra-index:${path}:${u}`, detail: `${path} adds an extra package index (${u}): a name that exists on both indexes is taken from whichever has the higher version (dependency confusion)`, file: path });
    for (const u of [...pr.indexUrls, ...pr.extraIndexUrls, ...pr.findLinks]) if (isHttp(u)) out.issues.push({ rule: 'package.config.insecure_registry', key: `http-index:${path}:${u}`, detail: `${path} points at an unencrypted index (${u})`, file: path });
    for (const h of pr.trustedHosts) out.issues.push({ rule: 'package.config.insecure_registry', key: `trusted-host:${path}:${h}`, detail: `${path} marks ${h} as a trusted host, which switches TLS verification off for it`, file: path });
    if (covered.has(path) && !forConsumer) continue;            // listed through the file that includes it
    for (const e of entries) {
      const kind = forConsumer ? 'runtime' : 'dev';
      if (!forConsumer && (isLockLike || /^===?\s*[^*\s]+$/.test(e.spec.replace(/\s/g, ''))) && !e.url) {
        const v = e.spec.replace(/^===?\s*/, '').trim();
        out.locked.push({ name: e.name, version: v, source: 'registry', url: null, ref: null, group: path, hashes: e.hashes, file: path, marker: e.marker });
      } else if (e.url || e.editable) out.direct.push({ name: e.name, spec: e.spec, url: e.url, kind, file: path, marker: e.marker, extras: e.extras, editable: e.editable, source: /^git\+|^hg\+|^svn\+|^bzr\+/.test(e.url || '') ? 'git' : /^file:|^(?:\.{1,2}\/|\/|~\/|\.$)/.test(e.url || '') ? 'path' : 'url' });
      else out.lines.push({ line: `${e.name}${e.extras.length ? `[${e.extras.join(',')}]` : ''}${e.spec ? ` ${e.spec}` : ''}${e.marker ? `; ${e.marker}` : ''}`, kind, file: path });
    }
    if (forConsumer) for (const l of pr.constraints) void l;
  }
  const idx = out.requirementsFiles.filter(r => r.indexUrls.length || r.extraIndexUrls.length);
  void idx;

  // ── Pipfile ──
  const pipfile = fx.textOf('Pipfile');
  if (pipfile) {
    out.manifestFiles.push('Pipfile');
    const pf = pipfileDeps(pipfile);
    for (const d of pf.deps) {
      if (d.url) out.direct.push({ name: d.name, spec: d.spec, url: d.url, ref: d.ref, kind: d.kind === 'dev' ? 'dev' : 'dev', file: 'Pipfile', source: /^git|\.git$|^https?:\/\/(?:github|gitlab|bitbucket)/i.test(d.url) ? 'git' : 'path', editable: d.editable });
      else out.lines.push({ line: `${d.name}${d.extras?.length ? `[${d.extras.join(',')}]` : ''}${d.spec ? ` ${/^[<>=!~]/.test(d.spec) ? d.spec : `==${d.spec}`}` : ''}${d.marker ? `; ${d.marker}` : ''}`, kind: 'dev', file: 'Pipfile' });
    }
    for (const s of pf.sources) if (s.url && (isHttp(s.url) || s.verify_ssl === false)) out.issues.push({ rule: 'package.config.insecure_registry', key: `pipfile-source:${s.url}`, detail: `Pipfile source ${s.url} ${s.verify_ssl === false ? 'has verify_ssl = false (TLS verification is off)' : 'is unencrypted'}`, file: 'Pipfile' });
  }

  // ── environment.yml (conda) ──
  for (const f of fx.findAll(/(?:^|\/)(?:environment|conda|env)[A-Za-z0-9_.-]*\.ya?ml$/i)) {
    if (NOISE_DIR.test(f.path)) { ignored++; continue; }
    const t = fx.text(f); if (!t) continue;
    const env = condaEnv(t);
    if (!env || (!env.conda.length && !env.pip.length)) continue;
    out.manifestFiles.push(f.path);
    for (const l of env.pip) out.lines.push({ line: l.replace(/^-e\s+/, ''), kind: 'dev', file: f.path });
    for (const c of env.conda) out.direct.push({ name: c.split(/[<>=!~ ]/)[0], spec: c.slice(c.split(/[<>=!~ ]/)[0].length).trim(), url: null, kind: 'dev', file: f.path, conda: true });
  }

  // ── egg-info requires.txt (sdists and installed copies) ──
  for (const f of fx.findAll(/^[^/]+\.egg-info\/requires\.txt$/)) { out.manifestFiles.push(f.path); addLines(eggRequires(fx.text(f) || ''), 'runtime', f.path); }

  // ── lockfiles ──
  for (const f of fx.all()) {
    for (const [re, label, tool, fn] of LOCK_FILES) {
      if (!re.test(f.path)) continue;
      if (NOISE_DIR.test(f.path)) { ignored++; break; }
      const t = fx.text(f, 16 * 1048576);
      if (t == null) { notes.add(`${f.path} is larger than the read limit and was not parsed`); break; }
      let r = null;
      try { r = fn(t); } catch { r = null; }
      if (!r) { notes.add(`${f.path} could not be parsed as a ${tool} lockfile`); break; }
      out.manifestFiles.push(f.path);
      const entries = r.entries.filter(e => e.name);
      out.lockfiles.push({ file: f.path, format: label, tool, packages: entries.length, pinned: entries.filter(e => e.version).length, hashes: entries.filter(e => e.hashes).length, non_registry: entries.filter(e => e.source !== 'registry').length, meta: r.meta });
      for (const e of entries) out.locked.push({ ...e, file: f.path });
      break;
    }
  }
  for (const r of out.requirementsFiles) if (r.role === 'pinned list' && !out.lockfiles.some(l => l.file === r.file)) out.lockfiles.push({ file: r.file, format: 'requirements (pinned)', tool: 'pip', packages: r.entries, pinned: r.pinned, hashes: r.hashes, non_registry: 0, meta: {} });

  // ── vendored copies ──
  if (ignored) notes.add(`${ignored} dependency file(s) under tests / docs / examples / fixtures / vendored directories were not treated as dependencies of this package`);
  const v = detectVendored(fx, pkg?.name);
  out.bundled = v.bundled; out.unversioned = v.unversioned;
  out.notes = [...notes];
  out.consumerFiles = consumerReq;
  return out;
}
