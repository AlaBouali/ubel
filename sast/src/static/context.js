'use strict';

// ─── Per-chunk analysis context ───────────────────────────────────────────────
//
// prepareChunk() lexes a chunk once and derives everything the rules and the
// taint engine need from the two offset-aligned views (see lexer.js):
//   lines / lineAt()   offsets ↔ line numbers (chunk-relative, 1-based)
//   logical            statements (a call split over several lines is one)
//   calls              every call expression with its callee path and arguments
//   accessPaths()      `a.b.c`-style references inside an expression

import { lex, familyToLexer } from './lexer.js';
import { EXT_FAMILY } from '../chunker/constants.js';
import { detectConfigKind, familyForKind } from '../chunker/configDetect.js';
import path from 'path';

// Words that may stand in front of a real call; any OTHER identifier in front of
// `name(` means a declaration (`String name(`, `int main(`) in C-like languages.
const CALL_LEAD = new Set([
  'return', 'new', 'await', 'throw', 'yield', 'else', 'case', 'in', 'of', 'not', 'and', 'or', 'is', 'typeof',
  'delete', 'void', 'do', 'if', 'unless', 'while', 'until', 'when', 'then', 'elif', 'elsif', 'echo', 'print',
  'puts', 'raise', 'assert', 'with', 'from', 'import', 'async', 'go', 'defer', 'try', 'catch', 'using', 'lock',
  'foreach', 'for', 'match', 'let', 'var', 'val', 'const', 'final', 'static', 'extends', 'implements', 'instanceof',
  'sizeof', 'unsafe', 'move', 'ref', 'out', 'yield', 'emit', 'exec', 'eval', 'include', 'require', 'sync', 'select',
]);
const DECL_KEYWORD = /(?:^|[^\w$])(?:def|function|fun|fn|func|sub|proc|class|struct|interface|enum|trait|impl|namespace|module|macro_rules!?|operator)\s*(?:\*\s*)?$/;
const C_LIKE = new Set(['java', 'csharp', 'c', 'dart', 'kotlin', 'swift', 'go', 'rust']);

const NOT_CALLS = new Set(['if', 'for', 'while', 'switch', 'catch', 'return', 'function', 'foreach', 'using', 'lock', 'sizeof', 'typeof', 'elif', 'when', 'match', 'with', 'fn', 'func', 'fun', 'def', 'await', 'async', 'yield', 'throw', 'new', 'in', 'not', 'and', 'or', 'unless', 'until', 'defined', 'alignof', 'decltype', 'static_assert', 'assert_eq', 'defer', 'go', 'select', 'synchronized', 'do', 'else']);

export function resolveFamily(chunk) {
  const ext = path.extname(chunk.file || '').toLowerCase();
  let family = EXT_FAMILY[ext];
  if (!family) {
    const kind = detectConfigKind(chunk.file || '', chunk.code);
    if (kind) family = familyForKind(kind);
  }
  return family || null;
}

// ── Statements ────────────────────────────────────────────────────────────────
function buildLogicalLines(code, literal, lineStartsRel, family) {
  const out = [];
  const n = code.length;
  const stmtSplit = C_LIKE.has(family) || family === 'js' || family === 'php';
  const braceIsLiteralOnly = family === 'python' || family === 'ruby';
  let depth = 0, start = 0, prevSig = '', i = 0;
  const stack = [];   // open braces: { lit:true } literal/dict, or { lit:false, saved } block whose body is its own statement scope
  const lineAt = (off) => lineStartsRel.lineAt(off);

  const push = (end) => {
    if (end > start) {
      const t = code.slice(start, end);
      if (t.trim() !== '') {
        let s = start; while (s < end && /\s/.test(code[s])) s++;
        out.push({ start: s, end, text: code.slice(s, end), lit: literal.slice(s, end), line: lineAt(s) });
      }
    }
  };

  while (i < n) {
    const ch = code[i];
    if (ch === '\n') {
      if (depth <= 0) {
        // continuation: previous line ends with an operator, or next line starts with one
        const before = code.slice(start, i).replace(/\s+$/, '');
        const nextHead = code.slice(i + 1).trimStart().slice(0, 3);
        const endsOp = /(?:[+\-*/%=&|^<,.?\\]|&&|\|\||\?\?|=>|->|\bin|\bnot|\band|\bor)$/.test(before) && !/(?:\+\+|--|\*\/)$/.test(before) && !(family === 'python' && /:$/.test(before));
        const nextCont = /^[.]|^[?:]\s|^\|\||^&&|^\+(?!\+)|^->/.test(nextHead) && !/^\.\./.test(nextHead);
        const blockOpen = /\{$/.test(before) || (/[:]$/.test(before) && family === 'python');
        if ((endsOp || nextCont) && !blockOpen && before !== '') { i++; continue; }
        push(i); start = i + 1;
      }
      i++; continue;
    }
    if (ch === '(' || ch === '[') depth++;
    else if (ch === ')' || ch === ']') depth = Math.max(0, depth - 1);
    else if (ch === '{') {
      const literalBrace = braceIsLiteralOnly || /[=(,\[:?`]$|\breturn$|\bin$|\b(?:const|let|var|val|final|import|export)$/.test(prevSig) || /=>\s*\($/.test(prevSig);
      if (literalBrace) { stack.push({ lit: true }); depth++; }
      else { push(i + 1); stack.push({ lit: false, saved: depth }); depth = 0; start = i + 1; }
    } else if (ch === '}') {
      const top = stack.pop();
      if (!top) { push(i); start = i + 1; }
      else if (top.lit) depth = Math.max(0, depth - 1);
      else { push(i); depth = top.saved; start = i + 1; }
    } else if (ch === ';' && depth <= 0 && stmtSplit) {
      push(i + 1); start = i + 1;
    }
    if (!/\s/.test(ch)) prevSig = (prevSig + ch).slice(-12);
    i++;
  }
  push(n);
  return out;
}

// ── Calls ─────────────────────────────────────────────────────────────────────
const CALL_RE = /([A-Za-z_$][\w$]*(?:(?:\s*(?:\?\.|\.|::|->)\s*)[A-Za-z_$][\w$]*)*)\s*(!?)\s*\(/g;

function matchParen(code, open) {
  let depth = 0;
  for (let k = open; k < code.length; k++) {
    const c = code[k];
    if (c === '(') depth++;
    else if (c === ')') { depth--; if (depth === 0) return k; }
  }
  return -1;
}

export function splitArgs(code, literal, from, to) {
  const args = [];
  let depth = 0, s = from;
  const flush = (e) => {
    const raw = code.slice(s, e);
    if (raw.trim() === '' && args.length === 0 && e >= to) return;
    let a = s; while (a < e && /\s/.test(code[a])) a++;
    let b = e; while (b > a && /\s/.test(code[b - 1])) b--;
    args.push({ start: a, end: b, text: code.slice(a, b), lit: literal.slice(a, b) });
  };
  for (let k = from; k < to; k++) {
    const c = code[k];
    if (c === '(' || c === '[' || c === '{') depth++;
    else if (c === ')' || c === ']' || c === '}') depth--;
    else if (c === ',' && depth === 0) { flush(k); s = k + 1; }
  }
  flush(to);
  return args;
}

// A call expression. `text` / `lit` (the whole call in each view) are derived on demand: a chunk can hold
// thousands of calls and most rules never read them.
class Call {
  constructor(o, code, literal) { Object.assign(this, o); Object.defineProperty(this, '_v', { value: { code, literal }, enumerable: false }); }
  get text() { return this._v.code.slice(this.start, this.close + 1); }
  get lit() { return this._v.literal.slice(this.start, this.close + 1); }
}

function extractCalls(code, literal, lineAt, family) {
  const calls = [];
  CALL_RE.lastIndex = 0;
  let m;
  while ((m = CALL_RE.exec(code)) !== null) {
    const raw = m[1];
    const callee = raw.replace(/\s+/g, '').replace(/\?\./g, '.').replace(/->/g, '.');
    const first = callee.split(/[.:]+/)[0];
    const start = m.index;
    const open = m.index + m[0].length - 1;
    if (NOT_CALLS.has(callee)) continue;

    // what stands in front of the callee?
    const lead = code.slice(Math.max(0, start - 40), start);
    let pk = start - 1; while (pk >= 0 && /\s/.test(code[pk])) pk--;
    const viaDot = pk >= 0 && (code[pk] === '.' || (code[pk] === '>' && code[pk - 1] === '-') || (code[pk] === ':' && code[pk - 1] === ':')) && !(code[pk] === '.' && code[pk - 1] === '.');
    const before = /([A-Za-z_$][\w$]*)\s*$/.exec(lead);
    const isNew = !!before && before[1] === 'new';
    if (DECL_KEYWORD.test(lead)) continue;
    if (/\bfunc\s*\([^)]*\)\s*$/.test(lead)) continue;                  // Go method declaration
    if (before && C_LIKE.has(family) && !CALL_LEAD.has(before[1]) && !(family === 'rust' || family === 'go' || family === 'swift' || family === 'kotlin')) continue;   // `String name(` declaration
    if (family === 'php' && /\bfunction\s*&?\s*$/.test(lead)) continue;
    if (family === 'kotlin' && /\bfun\s+(?:<[^>]*>\s*)?(?:[\w.]+\.)?$/.test(lead)) continue;

    const close = matchParen(code, open);
    if (close < 0) continue;
    const args = splitArgs(code, literal, open + 1, close);
    calls.push(new Call({
      callee: callee + (m[2] || ''), name: callee.split(/[.:]+/).pop() + (m[2] || ''),
      start, open, close, args, line: lineAt(start), isNew, viaDot, chain: callee + (m[2] || ''),
      first,
    }, code, literal));
  }
  // method chains: `Runtime.getRuntime().exec(` → chain "Runtime.getRuntime().exec"
  const byClose = new Map(calls.map(c => [c.close, c]));
  for (const c of calls) {
    let k = c.start - 1;
    while (k >= 0 && /\s/.test(code[k])) k--;
    if (code[k] === '.' || (code[k] === '>' && code[k - 1] === '-')) {
      let p = code[k] === '.' ? k - 1 : k - 2;
      while (p >= 0 && /\s/.test(code[p])) p--;
      if (code[p] === '?') p--;
      const prev = byClose.get(p);
      if (prev) c.chain = prev.chain + '().' + c.callee;
    }
  }
  return calls;
}

// Ruby / PHP statements that are calls without parentheses.
const BARE_PHP = /\b(include_once|include|require_once|require|echo|print|exit|die)\b[ \t]*(?=[$"'\w(\[<-])/g;
const BARE_RUBY = /(?:^|[;\s(])((?:[a-z_]\w*\.)*(?:system|exec|spawn|eval|instance_eval|class_eval|module_eval|send|public_send|__send__|constantize|safe_constantize|open|redirect_to|redirect_back|render|puts|print|p|pp|require|load|require_relative|send_file|send_data|info|warn|error|debug|fatal|sh|exit|abort|log|popen|popen3|capture2|capture3|capture2e))[ \t]+(?![=!<>]=?|\+\s|-\s|\*\s|\/\s|\?\s|:\s|\.\.|and\b|or\b|if\b|unless\b|while\b|until\b|do\b|then\b|\{)(?=[\w"'`:@$\[%<(-])/g;

function extractBareCalls(code, literal, logical, lineAt, family) {
  const out = [];
  const re = family === 'php' ? BARE_PHP : family === 'ruby' ? BARE_RUBY : null;
  if (!re) return out;
  for (const ll of logical) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(ll.text)) !== null) {
      const name = m[1];
      const nameStart = ll.start + m.index + m[0].indexOf(name);
      const argStart = ll.start + m.index + m[0].length;
      if (code[argStart] === '(' ) continue;      // has parens: handled by CALL_RE
      let argEnd = ll.end; while (argEnd > argStart && /[\s;]/.test(code[argEnd - 1])) argEnd--;
      const args = splitArgs(code, literal, argStart, argEnd);
      out.push(new Call({
        callee: name, name: name.split('.').pop(), start: nameStart, open: argStart - 1, close: argEnd - 1, args,
        line: lineAt(nameStart), isNew: false, viaDot: false, chain: name, first: name.split('.')[0], bare: true,
      }, code, literal));
    }
  }
  return out;
}

// ── Access paths ──────────────────────────────────────────────────────────────
// `a.b[0].c` → { path:'a.b.c', base:'a', start, end }.  Index expressions are dropped
// from the path (a[i] is a read of `a`).
export function accessPaths(text) {
  const out = [];
  const re = /[A-Za-z_$][\w$]*/g;
  let m;
  while ((m = re.exec(text)) !== null) {
    if (/^\d/.test(m[0])) continue;
    // Is this identifier the continuation of a member chain?  `a.b`  `a->b`  `a::b`  `a?.b`  or a chain broken
    // across lines (`a\n  .b`).  A "." with a space on its right-hand side is string concatenation (PHP), not access.
    const before = text.slice(Math.max(0, m.index - 40), m.index);
    if (/(?:->|::|\?\.)[ \t]*$/.test(before) || /(?:[\w$)\]]|^)\.$/.test(before) && !/\.\.$/.test(before) || /(?:[\w$)\]])[ \t]*\n[ \t]*\.$/.test(before)) {
      if (!/(?:^|[^.])\.\.\.$/.test(before)) continue;
    }
    // PHP variable sigil is part of the identifier
    const startIdx = text[m.index - 1] === '$' && !m[0].startsWith('$') ? m.index - 1 : m.index;
    let end = m.index + m[0].length;
    let pathStr = (startIdx < m.index ? '$' : '') + m[0];
    const ends = [end];
    for (;;) {
      const rest = text.slice(end);
      const seg = /^(?:\s*(?:->|::|\?\.)\s*|[ \t]*\n[ \t]*\.|\.)([A-Za-z_$][\w$]*)/.exec(rest);
      if (seg) { pathStr += '.' + seg[1]; end += seg[0].length; ends.push(end); continue; }
      if (rest[0] === '[') {
        let d = 0, k = 0;
        for (; k < rest.length; k++) { if (rest[k] === '[') d++; else if (rest[k] === ']') { d--; if (d === 0) break; } }
        end += k + 1; continue;
      }
      break;
    }
    re.lastIndex = Math.max(re.lastIndex, end);
    out.push({ path: pathStr, base: pathStr.split('.')[0], start: startIdx, end, ends, call: /^\s*\(/.test(text.slice(end)) });
  }
  return out;
}

// ── Public ────────────────────────────────────────────────────────────────────
export function prepareChunk(chunk, family) {
  const lexFamily = familyToLexer(family, chunk.file || '');
  const { literal, code } = lex(chunk.code, lexFamily);

  const starts = [0];
  for (let i = 0; i < chunk.code.length; i++) if (chunk.code[i] === '\n') starts.push(i + 1);
  const lineAt = (off) => {
    let lo = 0, hi = starts.length - 1;
    while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
    return lo + 1;
  };
  const lineHelper = { lineAt };

  const logical = buildLogicalLines(code, literal, lineHelper, family);
  let calls = extractCalls(code, literal, lineAt, family);
  if (family === 'php' || family === 'ruby') calls = calls.concat(extractBareCalls(code, literal, logical, lineAt, family));
  calls.sort((a, b) => a.start - b.start);

  return { chunk, family, literal, code, lineAt, logical, calls, starts };
}

export { matchParen, CALL_LEAD };
