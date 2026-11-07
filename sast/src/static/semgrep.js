'use strict';

// ─── Semgrep-syntax rules for the --no-llm engine (zero dependencies) ──────────────────────────────────────────
//
// A language-agnostic, TOKEN-based implementation of the Semgrep rule language. It has no parser / AST per language, so it matches
// what a pattern *looks like* in the code, not what it means:
//
//   supported   pattern · patterns (AND) · pattern-either (OR) · pattern-not · pattern-inside · pattern-not-inside · pattern-regex ·
//               pattern-not-regex · metavariable-regex · metavariable-pattern · metavariable-comparison · focus-metavariable
//               metavariables ($X, $_, $...ARGS) · ellipsis (...) in calls / blocks / strings · "..." and "$X" string patterns ·
//               deep expressions <... P ...> · repeated metavariables must bind the same code · fix · message interpolation
//   NOT         taint mode (pattern-sources / sinks / sanitizers), join / extract mode, typed metavariables ((T $X)), symbolic /
//               constant propagation, type- and import-aware matching, equivalences such as `a.b(c)` ≡ `b(a, c)`.
//               A rule that uses one of these is reported as SKIPPED, never silently run with a weaker meaning.

export class RuleError extends Error { constructor(m) { super(m); this.name = 'RuleError'; } }
export class BudgetError extends Error { constructor() { super('pattern matching step budget exceeded'); this.name = 'BudgetError'; } }

// ── lexer ──────────────────────────────────────────────────────────────────────────────────────────────────────
const OPS = ['>>>=', '...', '===', '!==', '**=', '<<=', '>>=', '>>>', '<=>', '&&=', '||=', '??=', '?.', '??', '=>', '->', '::', '==', '!=', '<=', '>=', '&&', '||',
  '++', '--', '+=', '-=', '*=', '/=', '%=', '&=', '|=', '^=', '<<', '>>', '**', '|>', ':=', '..', '=~', '!~'].sort((a, b) => b.length - a.length);
const PHP_SUPERGLOBALS = /^\$(?:_GET|_POST|_COOKIE|_REQUEST|_SERVER|_FILES|_SESSION|_ENV|GLOBALS)\b/;
const isIdStart = (c) => /[A-Za-z_$\u0080-\uFFFF]/.test(c);
const isIdPart = (c) => /[\w$\u0080-\uFFFF]/.test(c);

function readString(text, i) {
  const q = text[i];
  if ((q === '"' || q === "'") && text.startsWith(q.repeat(3), i)) {
    const end = text.indexOf(q.repeat(3), i + 3);
    return end < 0 ? -1 : end + 3;
  }
  for (let k = i + 1; k < text.length; k++) {
    const c = text[k];
    if (c === '\\') { k++; continue; }
    if (c === q) return k + 1;
    if (c === '\n' && q !== '`') return -1;               // '…' and "…" end at the line; only `…` (JS templates, Go raw strings) spans lines
  }
  return -1;
}

export function lex(text, { pattern = false } = {}) {
  const toks = [];
  let i = 0, line = 1, lineAt = 0;
  const n = text.length;
  const syncLine = (upTo) => { for (; lineAt < upTo; lineAt++) if (text.charCodeAt(lineAt) === 10) line++; };
  while (i < n) {
    const c = text[i];
    if (c === ' ' || c === '\t' || c === '\r' || c === '\n' || c === '\f') { i++; continue; }
    syncLine(i);
    const s = i;
    let t, v;
    if (c === '"' || c === "'" || c === '`') {
      const e = readString(text, i);
      if (e > 0) { t = 'str'; v = text.slice(i, e); i = e; } else { t = 'op'; v = c; i++; }
    } else if (/[0-9]/.test(c)) {
      const m = /^(?:0[xX][0-9a-fA-F_]+|0[bB][01_]+|\d[\d_]*(?:\.\d+)?(?:[eE][+-]?\d+)?)[A-Za-z]*/.exec(text.slice(i, i + 64));
      t = 'num'; v = m[0]; i += v.length;
    } else if (pattern && c === '$' && text.startsWith('$...', i) && /[A-Z_]/.test(text[i + 4] || '')) {
      const m = /^\$\.\.\.[A-Z_][A-Z0-9_]*/.exec(text.slice(i, i + 64));
      t = 'evar'; v = m[0]; i += v.length;
    } else if (pattern && c === '$' && /[A-Z_]/.test(text[i + 1] || '') && !PHP_SUPERGLOBALS.test(text.slice(i, i + 12))) {
      const m = /^\$[A-Z_][A-Z0-9_]*/.exec(text.slice(i, i + 64));
      t = 'mv'; v = m[0]; i += v.length;
    } else if (isIdStart(c)) {
      let e = i + 1;
      while (e < n && isIdPart(text[e])) e++;
      t = 'id'; v = text.slice(i, e); i = e;
    } else {
      v = null;
      for (const op of OPS) if (text.startsWith(op, i)) { v = op; break; }
      if (v === null) v = c;
      t = 'op'; i += v.length;
      if (pattern && v === '...') t = 'ell';
    }
    toks.push({ t, v, s, e: i, line });
  }
  return toks;
}

const OPEN = { '(': ')', '[': ']', '{': '}' };
const CLOSERS = new Set([')', ']', '}']);
function pairs(S) {
  const pair = new Map(), st = [];
  for (let i = 0; i < S.length; i++) {
    const t = S[i];
    if (t.t !== 'op') continue;
    if (OPEN[t.v]) st.push(i);
    else if (CLOSERS.has(t.v)) {
      for (let k = st.length - 1; k >= 0; k--) if (OPEN[S[st[k]].v] === t.v) { pair.set(st[k], i); st.length = k; break; }
    }
  }
  return pair;
}

const innerOf = (v) => (v.length >= 6 && (v.startsWith('"""') || v.startsWith("'''")) ? v.slice(3, -3) : v.slice(1, -1));
const canonTok = (t) => (t.t === 'str' ? 'S:' + innerOf(t.v) : t.v);

// ── pattern compilation ────────────────────────────────────────────────────────────────────────────────────────
function compileStr(inner) {
  if (inner === '...') return { any: true };
  const only = /^\$([A-Z_][A-Z0-9_]*)$/.exec(inner);
  if (only) return { only: only[0] };
  if (!/\.\.\.|\$[A-Z_][A-Z0-9_]*/.test(inner)) return { exact: inner };
  const names = [];
  let re = '^', last = 0;
  const rx = /\.\.\.|\$[A-Z_][A-Z0-9_]*/g;
  let m;
  while ((m = rx.exec(inner)) !== null) {
    re += escapeRe(inner.slice(last, m.index));
    if (m[0] === '...') re += '[\\s\\S]*?';
    else if (m[0] === '$_') re += '[\\s\\S]*?';
    else { re += '([\\s\\S]*?)'; names.push(m[0]); }
    last = m.index + m[0].length;
  }
  re += escapeRe(inner.slice(last)) + '$';
  return { re: new RegExp(re), names };
}
const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

export function compilePattern(text) {
  let toks = lex(String(text).trim(), { pattern: true });
  while (toks.length && toks[toks.length - 1].t === 'op' && toks[toks.length - 1].v === ';') toks.pop();
  if (!toks.length) throw new RuleError('empty pattern');
  // <... P ...>  (deep expression)  →  ... P ...
  for (let i = 0; i < toks.length - 1; i++) {
    if (toks[i].v === '<' && toks[i].t === 'op' && toks[i + 1].t === 'ell') {
      let j = -1;
      for (let k = toks.length - 2; k > i + 1; k--) if (toks[k].t === 'ell' && toks[k + 1].v === '>') { j = k; break; }
      if (j > 0) { toks = [...toks.slice(0, i), ...toks.slice(i + 1, j + 1), ...toks.slice(j + 2)]; break; }
    }
  }
  // typed metavariables `(Type $X)` change the meaning (the type is checked); refuse instead of ignoring the type
  for (let i = 0; i + 3 < toks.length; i++) {
    if (toks[i].v === '(' && toks[i].t === 'op' && toks[i + 1].t === 'id' && toks[i + 2].t === 'mv' && toks[i + 3].v === ')' && toks[i + 3].t === 'op') {
      throw new RuleError('typed metavariables (Type $X) are not supported');
    }
  }
  const pair = pairs(toks);
  for (let i = 0; i < toks.length; i++) {
    const t = toks[i];
    if (t.t === 'op' && OPEN[t.v] && !pair.has(i)) throw new RuleError(`unbalanced "${t.v}" in pattern`);
    if (t.t === 'op' && CLOSERS.has(t.v) && ![...pair.values()].includes(i)) throw new RuleError(`unbalanced "${t.v}" in pattern`);
  }
  const names = new Set();
  const lits = [];
  function build(a, b) {
    const items = [];
    for (let i = a; i < b; i++) {
      const t = toks[i];
      if (t.t === 'op' && OPEN[t.v]) {
        const close = pair.get(i);
        items.push({ k: 'group', open: t.v, close: OPEN[t.v], items: build(i + 1, close) });
        i = close;
      } else if (t.t === 'ell') items.push({ k: 'ell' });
      else if (t.t === 'evar') { names.add(t.v); items.push({ k: 'evar', name: t.v }); }
      else if (t.t === 'mv') { if (t.v !== '$_') names.add(t.v); items.push({ k: 'mv', name: t.v, anon: t.v === '$_' }); }
      else if (t.t === 'str') {
        const inner = innerOf(t.v), str = compileStr(inner);
        if (str.only) names.add(str.only);
        if (str.names) str.names.forEach((x) => names.add(x));
        if (str.exact !== undefined && str.exact.length > 1) lits.push(str.exact);
        items.push({ k: 'str', tok: t, str });
      } else { if (t.t === 'id' && t.v.length > 1) lits.push(t.v); items.push({ k: 'tok', tok: t }); }
    }
    // `f(..., x, ...)`: a comma next to an ellipsis is a separator that goes with it (so `f(x, ...)` also matches `f(x)`)
    for (let i = 0; i < items.length; i++) {
      const it = items[i];
      if (it.k !== 'ell' && it.k !== 'evar') continue;
      const comma = (x) => x && x.k === 'tok' && x.tok.t === 'op' && x.tok.v === ',';
      if (comma(items[i - 1])) { it.cb = true; items.splice(i - 1, 1); i--; }
      if (comma(items[i + 1])) { it.ca = true; items.splice(i + 1, 1); }
    }
    return items;
  }
  const items = build(0, toks.length);
  items.top = true;
  if (items.every((x) => x.k === 'ell')) throw new RuleError('a pattern made only of "..." matches nothing useful');
  return { text: String(text).trim(), items, names, lits: [...new Set(lits)] };
}

// ── matcher ────────────────────────────────────────────────────────────────────────────────────────────────────
export function makeScope(literal, raw = literal, maxSteps = 100000) {
  const S = lex(literal);
  return { text: literal, raw, S, pair: pairs(S), cache: new Map(), steps: 0, maxSteps };
}

const UNARY = new Set(['!', '-', '+', '~', '*', '&', '++', '--', 'await', 'new', 'typeof', 'void', 'delete', 'not', 'yield', 'sizeof', 'async']);
const BINOPS = new Set(['+', '-', '*', '/', '%', '**', '==', '!=', '===', '!==', '<', '>', '<=', '>=', '&&', '||', '??', '&', '|', '^', '<<', '>>', '>>>', '<=>', '=~', '!~',
  'and', 'or', 'in', 'is', 'instanceof']);
const isOp = (t, v) => t && t.t === 'op' && t.v === v;
const isOpener = (t) => t && t.t === 'op' && OPEN[t.v] !== undefined;

// every end index (exclusive) at which an expression starting at `p` can stop, shortest first
function primaryEnds(p, limit, ctx) {
  const { S, pair } = ctx;
  const ends = [];
  let pos = p;
  while (pos < limit && (UNARY.has(S[pos].v) && (S[pos].t === 'op' || S[pos].t === 'id'))) pos++;
  if (pos >= limit) return ends;
  const t = S[pos];
  if (t.t === 'id' && (t.v === 'function' || t.v === 'fn' || t.v === 'func' || t.v === 'def')) {
    let q = pos + 1;
    if (q < limit && S[q].t === 'id') q++;
    if (q < limit && isOp(S[q], '(') && pair.has(q)) q = pair.get(q) + 1; else return ends;
    while (q < limit && !isOpener(S[q]) && !isOp(S[q], ',')) q++;      // return type / `=>`
    if (q < limit && isOp(S[q], '{') && pair.has(q)) q = pair.get(q) + 1;
    if (q <= limit) ends.push(q);
    return ends;
  }
  if (t.t === 'id' && t.v === 'lambda') {
    let q = pos + 1;
    while (q < limit && !isOp(S[q], ',') && !CLOSERS.has(S[q].v)) { q = isOpener(S[q]) && pair.has(q) ? pair.get(q) + 1 : q + 1; }
    ends.push(Math.min(q, limit));
    return ends;
  }
  if (t.t === 'id' || t.t === 'num' || t.t === 'str') pos++;
  else if (isOpener(t) && pair.has(pos) && pair.get(pos) < limit) pos = pair.get(pos) + 1;
  else return ends;
  ends.push(pos);
  for (;;) {
    const n = S[pos];
    if (pos >= limit || !n) break;
    if (n.t === 'op' && (n.v === '.' || n.v === '?.' || n.v === '::' || n.v === '->') && pos + 1 < limit && (S[pos + 1].t === 'id' || S[pos + 1].t === 'num')) { pos += 2; ends.push(pos); continue; }
    if (isOpener(n) && (n.v === '(' || n.v === '[') && pair.has(pos) && pair.get(pos) < limit) { pos = pair.get(pos) + 1; ends.push(pos); continue; }
    if (isOp(n, '=>') && pos + 1 < limit) {
      const q = pos + 1;
      if (isOp(S[q], '{') && pair.has(q)) { pos = pair.get(q) + 1; ends.push(pos); }
      else { const rest = primaryEnds(q, limit, ctx); if (rest.length) { pos = rest[rest.length - 1]; ends.push(pos); } }
      break;
    }
    if (n.t === 'op' && (n.v === '++' || n.v === '--')) { pos++; ends.push(pos); continue; }
    break;
  }
  return ends;
}

function exprEnds(p, limit, ctx) {
  const out = [];
  let ends = primaryEnds(p, limit, ctx);
  if (!ends.length) return out;
  out.push(...ends);
  let pos = ends[ends.length - 1];
  while (pos + 1 < limit && S_isBinop(ctx.S[pos])) {
    ends = primaryEnds(pos + 1, limit, ctx);
    if (!ends.length) break;
    out.push(...ends);
    pos = ends[ends.length - 1];
  }
  return out;
}
const S_isBinop = (t) => t && (t.t === 'op' || t.t === 'id') && BINOPS.has(t.v);

const CONT_PREV = new Set([',', '=', '+', '-', '*', '/', '%', '&&', '||', '??', '?', '.', '?.', '=>', '->', '&', '|', '^', '==', '!=', '===', '!==', '<', '>', '<=', '>=', '+=', '-=', '(', '[', '{', 'and', 'or', 'not']);
const CONT_NEXT = new Set(['.', '?.', '+', '-', '*', '/', '%', '&&', '||', '??', '?', ':', '=', '=>', '->', '&', '|', '^', '==', '!=', '===', '!==', 'and', 'or', ')', ']', '}']);
function stmtEnd(si, limit, ctx) {
  const { S, pair } = ctx;
  let j = si;
  while (j < limit) {
    const t = S[j];
    if (isOp(t, ';')) break;
    if (j > si && t.line > S[j - 1].line && !CONT_PREV.has(S[j - 1].v) && !CONT_NEXT.has(t.v)) break;
    if (isOpener(t) && pair.has(j)) { j = pair.get(j) + 1; continue; }
    j++;
  }
  return Math.min(j, limit);
}

function bind(env, name, s, e, ctx, canonOverride, rawS, rawE) {
  const S = ctx.S;
  const text = canonOverride !== undefined ? canonOverride : S.slice(s, e).map(canonTok).join(' ');
  const prev = env[name];
  if (prev) return prev.text === text ? env : null;
  return { ...env, [name]: { text, s: rawS !== undefined ? rawS : S[s].s, e: rawE !== undefined ? rawE : S[e - 1].e } };
}

function matchStr(it, st, env, ctx, idx) {
  const inner = innerOf(st.v), p = it.str;
  if (p.any) return env;
  if (p.only) { const prev = env[p.only]; const canon = 'S:' + inner; if (prev) return prev.text === canon ? env : null; return { ...env, [p.only]: { text: canon, s: st.s, e: st.e } }; }
  if (p.exact !== undefined) return inner === p.exact ? env : null;
  const m = p.re.exec(inner);
  if (!m) return null;
  let out = env;
  p.names.forEach((name, i) => {
    if (!out) return;
    const canon = 'S:' + m[i + 1], prev = out[name];
    if (prev) { if (prev.text !== canon) out = null; }
    else out = { ...out, [name]: { text: canon, s: st.s, e: st.e } };
  });
  return out;
}

function matchItems(items, ii, si, limit, env, ctx, k) {
  if (++ctx.steps > ctx.maxSteps) throw new BudgetError();
  if (ii === items.length) return k(si, env);
  const it = items[ii], S = ctx.S;
  const skipSemi = (p) => { if (ii > 0) while (p < limit && isOp(S[p], ';')) p++; return p; };
  switch (it.k) {
    case 'tok': {
      const p = it.tok.v === ';' ? si : skipSemi(si);
      if (p >= limit || S[p].t !== it.tok.t || S[p].v !== it.tok.v) return false;
      return matchItems(items, ii + 1, p + 1, limit, env, ctx, k);
    }
    case 'str': {
      const p = skipSemi(si);
      if (p >= limit || S[p].t !== 'str') return false;
      const e2 = matchStr(it, S[p], env, ctx, p);
      return e2 ? matchItems(items, ii + 1, p + 1, limit, e2, ctx, k) : false;
    }
    case 'mv': {
      const p = skipSemi(si);
      if (p >= limit) return false;
      const ends = exprEnds(p, limit, ctx);
      ctx.steps += ends.length;                                 // scanning a long expression is work too
      for (const end of ends) {
        const e2 = it.anon ? env : bind(env, it.name, p, end, ctx);
        if (e2 && matchItems(items, ii + 1, end, limit, e2, ctx, k)) return true;
      }
      return false;
    }
    case 'group': {
      const p = skipSemi(si);
      if (p >= limit || !isOp(S[p], it.open)) return false;
      const close = ctx.pair.get(p);
      if (close === undefined || close >= limit) return false;
      return matchItems(it.items, 0, p + 1, close, env, ctx, (s2, env2) => (s2 === close ? matchItems(items, ii + 1, close + 1, limit, env2, ctx, k) : false));
    }
    case 'ell': case 'evar': {
      const trailing = ii === items.length - 1;
      const tryAt = (e) => {
        // separators: `X, ...` (cb) = nothing, or a comma then anything; `..., X` (ca) = nothing, or anything then a comma;
        // both = a single comma, or a comma … a comma
        if (it.cb && it.ca) { if (!(e > si && isOp(S[si], ',') && isOp(S[e - 1], ','))) return false; }
        else if (it.cb) { if (e > si && !isOp(S[si], ',')) return false; }
        else if (it.ca) { if (e > si && !isOp(S[e - 1], ',')) return false; }
        let env2 = env;
        if (it.k === 'evar') {
          if (e > si) { env2 = bind(env, it.name, si, e, ctx); if (!env2) return false; }
          else { env2 = env[it.name] ? (env[it.name].text === '' ? env : null) : { ...env, [it.name]: { text: '', s: S[si] ? S[si].s : 0, e: S[si] ? S[si].s : 0 } }; if (!env2) return false; }
        }
        return matchItems(items, ii + 1, e, limit, env2, ctx, k);
      };
      if (trailing && items.top) return tryAt(stmtEnd(si, limit, ctx));      // a trailing `...` of a statement pattern runs to the end of that statement
      let e = si;
      for (;;) {
        if (tryAt(e)) return true;
        if (e >= limit) return false;
        e = isOpener(S[e]) && ctx.pair.has(e) ? ctx.pair.get(e) + 1 : e + 1;      // an ellipsis never stops inside a bracket group
        if (e > limit) return false;
      }
    }
    default: return false;
  }
}

export function matchPattern(c, scope) {
  if (scope.cache.has(c)) return scope.cache.get(c);
  const res = [];
  if (!c.lits.every((l) => scope.text.includes(l))) { scope.cache.set(c, res); return res; }
  const { S } = scope, first = c.items[0], seen = new Set();
  for (let st = 0; st < S.length; st++) {
    if (first.k === 'tok' && (S[st].t !== first.tok.t || S[st].v !== first.tok.v)) continue;
    if (first.k === 'str' && S[st].t !== 'str') continue;
    // `foo(...)` is a call of `foo`, not of `x.foo`; `$X.foo()` starts at the beginning of the expression
    if ((first.k === 'tok' && first.tok.t === 'id') || first.k === 'mv') {
      const prev = S[st - 1];
      if (prev && prev.t === 'op' && (prev.v === '.' || prev.v === '?.' || prev.v === '->' || prev.v === '::')) continue;
    }
    let found = null;
    matchItems(c.items, 0, st, S.length, {}, scope, (end, env) => { if (end > st) { found = { end, env }; return true; } return false; });
    if (!found) continue;
    const s = S[st].s, e = S[found.end - 1].e, key = s + ':' + e;
    if (seen.has(key)) continue;
    seen.add(key);
    res.push({ s, e, env: found.env });
    if (res.length >= 5000) break;
  }
  scope.cache.set(c, res);
  return res;
}

// ── regex (PCRE / Python flavour → JavaScript) ─────────────────────────────────────────────────────────────────
export function compileRegex(src, { multiline = false, global = true } = {}) {
  let s = String(src), flags = global ? 'g' : '';
  // PCRE inline flags `(?i)` apply to the rest of the pattern; JavaScript has only whole-regex flags, so they are applied to all of it
  // (exact for the usual `(?i)…` / `^(?i)…` forms)
  s = s.replace(/\(\?([a-z]+)\)/g, (all, fl) => {
    for (const f of fl) {
      if (f === 'i' || f === 's' || f === 'm') { if (!flags.includes(f)) flags += f; }
      else if (f === 'x') throw new RuleError('regex flag (?x) is not supported');
      else throw new RuleError(`regex flag (?${f}) is not supported`);
    }
    return '';
  });
  if (multiline && !flags.includes('m')) flags += 'm';
  s = s.replace(/\(\?P</g, '(?<').replace(/\(\?P=(\w+)\)/g, '\\k<$1>').replace(/\\A/g, '(?<![\\s\\S])').replace(/\\[Zz]/g, '(?![\\s\\S])');
  if (/\(\?>|\(\?[imsx-]+:|[*+?}]\+/.test(s)) throw new RuleError('atomic groups, possessive quantifiers and scoped flags are not supported in regexes');
  try { return new RegExp(s, flags); } catch (e) { throw new RuleError(`invalid regex: ${e.message}`); }
}

// ── metavariable-comparison: a small, safe Python-like expression evaluator ─────────────────────────────────────
const CMP_TOKEN = /\s*(?:(\d+\.\d*|\.\d+|\d+(?:_\d+)*|0[xX][0-9a-fA-F]+)|("(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')|(\$[A-Z_][A-Z0-9_]*)|([A-Za-z_][A-Za-z0-9_.]*)|(<=|>=|==|!=|\/\/|\*\*|[-+*\/%<>()\[\],]))/y;
function cmpTokens(src) {
  const out = []; CMP_TOKEN.lastIndex = 0;
  let m;
  while (CMP_TOKEN.lastIndex < src.length && src.slice(CMP_TOKEN.lastIndex).trim() !== '') {
    m = CMP_TOKEN.exec(src);
    if (!m) throw new RuleError(`metavariable-comparison: cannot parse "${src}"`);
    if (m[1] !== undefined) out.push({ t: 'num', v: /^0[xX]/.test(m[1]) ? parseInt(m[1], 16) : Number(m[1].replace(/_/g, '')) });
    else if (m[2] !== undefined) out.push({ t: 'str', v: m[2].slice(1, -1) });
    else if (m[3] !== undefined) out.push({ t: 'mv', v: m[3] });
    else if (m[4] !== undefined) out.push({ t: 'name', v: m[4] });
    else out.push({ t: 'op', v: m[5] });
  }
  return out;
}
export function compileComparison(src, { strip = false, base = 10 } = {}) {
  const toks = cmpTokens(String(src));
  let p = 0;
  const peek = () => toks[p], eat = () => toks[p++];
  const isName = (v) => peek() && peek().t === 'name' && peek().v === v;
  const FUNCS = { int: (x, b) => (typeof x === 'number' ? Math.trunc(x) : parseInt(String(x), b || base)), float: (x) => Number(x), str: (x) => String(x), len: (x) => String(x).length, abs: Math.abs, min: Math.min, max: Math.max };
  function orE() { let l = andE(); while (isName('or')) { eat(); const r = andE(); const a = l; l = (env) => a(env) || r(env); } return l; }
  function andE() { let l = notE(); while (isName('and')) { eat(); const r = notE(); const a = l; l = (env) => a(env) && r(env); } return l; }
  function notE() { if (isName('not') && !(toks[p + 1] && toks[p + 1].v === 'in')) { eat(); const x = notE(); return (env) => !x(env); } return cmpE(); }
  function cmpE() {
    let l = sumE();
    const parts = [];
    for (;;) {
      const t = peek();
      let op = null;
      if (t && t.t === 'op' && ['<', '<=', '>', '>=', '==', '!='].includes(t.v)) { op = t.v; eat(); }
      else if (isName('in')) { op = 'in'; eat(); }
      else if (isName('not') && toks[p + 1] && toks[p + 1].v === 'in') { op = 'not in'; eat(); eat(); }
      if (!op) break;
      parts.push([op, sumE()]);
    }
    if (!parts.length) return l;
    const first = l;
    return (env) => {
      let a = first(env);
      for (const [op, rf] of parts) {
        const b = rf(env);
        let ok;
        switch (op) {
          case '<': ok = a < b; break; case '<=': ok = a <= b; break; case '>': ok = a > b; break; case '>=': ok = a >= b; break;
          case '==': ok = a === b; break; case '!=': ok = a !== b; break;
          case 'in': ok = Array.isArray(b) ? b.includes(a) : String(b).includes(String(a)); break;
          default: ok = !(Array.isArray(b) ? b.includes(a) : String(b).includes(String(a)));
        }
        if (!ok) return false;
        a = b;
      }
      return true;
    };
  }
  function sumE() { let l = termE(); for (;;) { const t = peek(); if (t && t.t === 'op' && (t.v === '+' || t.v === '-')) { eat(); const r = termE(), a = l, o = t.v; l = (env) => (o === '+' ? a(env) + r(env) : a(env) - r(env)); } else return l; } }
  function termE() { let l = factE(); for (;;) { const t = peek(); if (t && t.t === 'op' && ['*', '/', '%', '//'].includes(t.v)) { eat(); const r = factE(), a = l, o = t.v; l = (env) => { const x = a(env), y = r(env); return o === '*' ? x * y : o === '/' ? x / y : o === '%' ? x % y : Math.floor(x / y); }; } else return l; } }
  function factE() { const t = peek(); if (t && t.t === 'op' && t.v === '-') { eat(); const x = factE(); return (env) => -x(env); } return atomE(); }
  function atomE() {
    const t = eat();
    if (!t) throw new RuleError(`metavariable-comparison: unexpected end of "${src}"`);
    if (t.t === 'num' || t.t === 'str') return () => t.v;
    if (t.t === 'mv') return (env) => {
      const b = env[t.v]; if (!b) throw new Error('unbound');
      let txt = b.raw !== undefined ? b.raw : b.text;
      if (strip) txt = txt.replace(/^(['"`])([\s\S]*)\1$/, '$2');
      const n = /^[-+]?\d[\d_]*(?:\.\d+)?$/.test(txt) ? Number(txt.replace(/_/g, '')) : /^0[xX][0-9a-fA-F]+$/.test(txt) ? parseInt(txt, 16) : base !== 10 && /^[0-9a-zA-Z]+$/.test(txt) && !Number.isNaN(parseInt(txt, base)) ? parseInt(txt, base) : null;
      return n === null ? txt : n;
    };
    if (t.t === 'op' && t.v === '(') { const x = orE(); if (!peek() || peek().v !== ')') throw new RuleError('metavariable-comparison: missing ")"'); eat(); return x; }
    if (t.t === 'op' && t.v === '[') {
      const items = [];
      while (peek() && peek().v !== ']') { items.push(orE()); if (peek() && peek().v === ',') eat(); }
      eat(); return (env) => items.map((f) => f(env));
    }
    if (t.t === 'name') {
      if (t.v === 'True') return () => true;
      if (t.v === 'False') return () => false;
      const fn = FUNCS[t.v];
      if (!fn || !peek() || peek().v !== '(') throw new RuleError(`metavariable-comparison: "${t.v}" is not supported`);
      eat();
      const args = [];
      while (peek() && peek().v !== ')') { args.push(orE()); if (peek() && peek().v === ',') eat(); }
      eat();
      return (env) => fn(...args.map((f) => f(env)));
    }
    throw new RuleError(`metavariable-comparison: unexpected "${t.v}"`);
  }
  const root = orE();
  if (p < toks.length) throw new RuleError(`metavariable-comparison: unexpected "${toks[p].v}"`);
  return (env) => { try { return !!root(env); } catch { return false; } };
}

// ── formulas ───────────────────────────────────────────────────────────────────────────────────────────────────
const POSITIVE = new Set(['pattern', 'patterns', 'pattern-either', 'pattern-regex']);
const UNSUPPORTED_KEYS = {
  'pattern-sources': 'taint mode', 'pattern-sinks': 'taint mode', 'pattern-sanitizers': 'taint mode', 'pattern-propagators': 'taint mode',
  'pattern-where-python': 'pattern-where-python', 'metavariable-analysis': 'metavariable-analysis', 'semgrep-internal-pattern-anywhere': 'internal patterns',
  'r2c-internal-project-depends-on': 'supply-chain (depends-on) rules', 'depends-on-either': 'supply-chain (depends-on) rules',
};
const asText = (v, what) => {
  if (typeof v === 'string') return v;
  if (typeof v === 'number' || typeof v === 'boolean') return String(v);
  throw new RuleError(`${what} must be a string`);
};

export function compileFormula(obj, where = 'rule') {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw new RuleError(`${where}: expected a mapping`);
  for (const key of Object.keys(obj)) if (UNSUPPORTED_KEYS[key]) throw new RuleError(`${UNSUPPORTED_KEYS[key]} is not supported (${key})`);
  const keys = Object.keys(obj).filter((k) => POSITIVE.has(k) || ['pattern-inside', 'pattern-not', 'pattern-not-inside', 'pattern-not-regex'].includes(k));
  if (keys.length !== 1) throw new RuleError(`${where}: expected exactly one of pattern / patterns / pattern-either / pattern-regex (found ${keys.join(', ') || 'none'})`);
  const key = keys[0], v = obj[key];
  switch (key) {
    case 'pattern': return { op: 'pattern', c: compilePattern(asText(v, 'pattern')) };
    case 'pattern-regex': return { op: 'regex', re: compileRegex(asText(v, 'pattern-regex'), { multiline: true }) };
    case 'pattern-either': {
      if (!Array.isArray(v) || !v.length) throw new RuleError('pattern-either must be a non-empty list');
      return { op: 'or', items: v.map((x, i) => compileFormula(x, `pattern-either[${i}]`)) };
    }
    case 'patterns': return compileAnd(v);
    default: return compileAnd([obj]);                       // a lone pattern-inside / pattern-not at the top of a formula
  }
}

function compileAnd(list) {
  if (!Array.isArray(list) || !list.length) throw new RuleError('patterns must be a non-empty list');
  const node = { op: 'and', pos: [], inside: [], notInside: [], not: [], notRegex: [], filters: [], focus: [] };
  list.forEach((entry, i) => {
    if (!entry || typeof entry !== 'object' || Array.isArray(entry)) throw new RuleError(`patterns[${i}]: expected a mapping`);
    for (const key of Object.keys(entry)) {
      if (UNSUPPORTED_KEYS[key]) throw new RuleError(`${UNSUPPORTED_KEYS[key]} is not supported (${key})`);
      const v = entry[key];
      switch (key) {
        case 'pattern': case 'patterns': case 'pattern-either': case 'pattern-regex': node.pos.push(compileFormula({ [key]: v }, `patterns[${i}]`)); break;
        case 'pattern-inside': node.inside.push(typeof v === 'object' && !Array.isArray(v) ? compileFormula(v) : { op: 'pattern', c: compilePattern(asText(v, key)) }); break;
        case 'pattern-not': node.not.push(typeof v === 'object' && !Array.isArray(v) ? compileFormula(v) : { op: 'pattern', c: compilePattern(asText(v, key)) }); break;
        case 'pattern-not-inside': node.notInside.push(typeof v === 'object' && !Array.isArray(v) ? compileFormula(v) : { op: 'pattern', c: compilePattern(asText(v, key)) }); break;
        case 'pattern-not-regex': node.notRegex.push(compileRegex(asText(v, key), { multiline: true })); break;
        case 'metavariable-regex':
          if (!v || !v.metavariable || v.regex === undefined) throw new RuleError('metavariable-regex needs metavariable and regex');
          node.filters.push({ f: 'regex', mv: String(v.metavariable), re: compileRegex(asText(v.regex, 'regex'), { global: false }) }); break;
        case 'metavariable-comparison':
          if (!v || !v.metavariable || v.comparison === undefined) throw new RuleError('metavariable-comparison needs metavariable and comparison');
          node.filters.push({ f: 'cmp', mv: String(v.metavariable), fn: compileComparison(asText(v.comparison, 'comparison'), { strip: !!v.strip, base: Number(v.base) || 10 }) }); break;
        case 'metavariable-pattern': {
          if (!v || !v.metavariable) throw new RuleError('metavariable-pattern needs a metavariable');
          const { metavariable, language, ...rest } = v;
          node.filters.push({ f: 'pat', mv: String(metavariable), formula: compileFormula(rest, 'metavariable-pattern') }); break;
        }
        case 'focus-metavariable': node.focus.push(...[].concat(v).map(String)); break;
        default: throw new RuleError(`unsupported operator "${key}"`);
      }
    }
  });
  if (!node.pos.length && !node.inside.length) throw new RuleError('patterns needs at least one positive pattern');
  return node;
}

const within = (a, b) => b.s <= a.s && a.e <= b.e;
function merge(a, b) {
  for (const k of Object.keys(b)) if (a[k] && a[k].text !== b[k].text) return null;
  return { ...a, ...b };
}
const rawOf = (scope, b) => scope.raw.slice(b.s, b.e);

function matchRegexRanges(re, scope) {
  const out = [], rx = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
  let m, guard = 0;
  while ((m = rx.exec(scope.raw)) !== null && guard++ < 5000) {
    if (m[0] === '') { rx.lastIndex++; continue; }
    const env = {};
    if (m.groups) for (const [name, val] of Object.entries(m.groups)) if (val !== undefined) env['$' + name.toUpperCase()] = { text: val, s: m.index + m[0].indexOf(val), e: m.index + m[0].indexOf(val) + val.length };
    out.push({ s: m.index, e: m.index + m[0].length, env });
  }
  return out;
}

export function evaluate(node, scope) {
  switch (node.op) {
    case 'pattern': return matchPattern(node.c, scope);
    case 'regex': return matchRegexRanges(node.re, scope);
    case 'or': {
      const out = [], seen = new Set();
      for (const it of node.items) for (const r of evaluate(it, scope)) { const key = `${r.s}:${r.e}`; if (!seen.has(key)) { seen.add(key); out.push(r); } }
      return out;
    }
    case 'and': return evalAnd(node, scope);
    default: return [];
  }
}

function evalAnd(node, scope) {
  let cur = null;
  const positives = node.pos.length ? node.pos : [];
  for (const p of positives) {
    const rs = evaluate(p, scope);
    if (cur === null) { cur = rs; continue; }
    const next = [];
    for (const a of cur) for (const b of rs) {
      if (!(within(a, b) || within(b, a))) continue;
      const env = merge(a.env, b.env);
      if (env) { next.push({ s: Math.max(a.s, b.s), e: Math.min(a.e, b.e), env }); break; }
    }
    cur = next;
    if (!cur.length) return [];
  }
  const insides = node.inside;
  if (cur === null) {                                           // only pattern-inside given: it is the positive pattern
    cur = evaluate(insides[0], scope);
    for (const extra of insides.slice(1)) cur = restrictInside(cur, evaluate(extra, scope));
  } else for (const i of insides) cur = restrictInside(cur, evaluate(i, scope));
  if (!cur.length) return [];
  for (const n of node.notInside) {
    const rs = evaluate(n, scope);
    cur = cur.filter((a) => !rs.some((b) => within(a, b) && merge(a.env, b.env)));
  }
  for (const n of node.not) {
    const rs = evaluate(n, scope);
    cur = cur.filter((a) => !rs.some((b) => within(a, b) && merge(a.env, b.env)));
  }
  for (const re of node.notRegex) {
    const rs = matchRegexRanges(re, scope);
    cur = cur.filter((a) => !rs.some((b) => within(a, b)));
  }
  for (const f of node.filters) {
    cur = cur.filter((r) => {
      const b = r.env[f.mv];
      if (!b) return false;
      const txt = rawOf(scope, b);
      if (f.f === 'regex') return f.re.test(txt);
      if (f.f === 'cmp') return f.fn({ ...r.env, [f.mv]: { ...b, raw: txt } });
      const sub = makeScope(txt, txt, scope.maxSteps);
      return evaluate(f.formula, sub).length > 0;
    });
  }
  if (node.focus.length) {
    const out = [];
    for (const r of cur) for (const name of node.focus) { const b = r.env[name]; if (b) out.push({ s: b.s, e: b.e, env: r.env }); }
    cur = out;
  }
  return cur;
}
function restrictInside(cur, rs) {
  const out = [];
  for (const a of cur) for (const b of rs) {
    if (!within(a, b)) continue;
    const env = merge(a.env, b.env);
    if (env) { out.push({ ...a, env }); break; }
  }
  return out;
}

// $X / $...ARGS in a message or fix → the code it matched
export function interpolate(text, env, scope, max = 90) {
  if (typeof text !== 'string' || !text.includes('$')) return text;
  return text.replace(/\$\.\.\.[A-Z_][A-Z0-9_]*|\$[A-Z_][A-Z0-9_]*/g, (name) => {
    const b = env[name];
    if (!b) return name;
    const raw = rawOf(scope, b).replace(/\s+/g, ' ').trim();
    return raw.length > max ? raw.slice(0, max - 1) + '…' : raw;
  });
}
