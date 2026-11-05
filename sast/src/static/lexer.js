'use strict';

// ─── Offset-preserving source lexer for the static (--no-llm) engine ──────────
//
// lex(code, family) returns two strings of EXACTLY the same length as `code`
// (so an offset in one is the same offset in the other, and in the original):
//
//   literal  comments blanked, string/char literal text kept.
//            Used by rules that need the text of a literal: secrets, algorithm
//            names ("md5"), URLs, config values.
//   code     comments blanked AND the text of string literals blanked, except
//            interpolated expressions (`${x}`, f"{x}", "#{x}", "$x", "\(x)" …),
//            which are real code and are kept. Used for everything structural:
//            finding calls, matching identifiers, tracking variables. A word
//            that only occurs inside a string or a comment can therefore never
//            be mistaken for code.
//
// Newlines are kept in both views, so line numbers never shift.
//
// It is a lexer, not a parser: it knows each family's comment and string
// syntax (nesting, raw strings, heredocs, interpolation) and nothing else.

import { regexCanFollow, consumeRegexLiteral } from '../chunker/regexliteral.js';

const IDENT_CH = /[A-Za-z0-9_$]/;

// Per-family syntax. `interp` names the interpolation style used by the
// family's double-quoted strings.
const SYNTAX = {
  js:     { line: ['//'], block: [['/*', '*/']], regex: true,  tmpl: true },
  python: { line: ['#'],  block: [], py: true },
  php:    { line: ['//', '#'], block: [['/*', '*/']], php: true },
  ruby:   { line: ['#'],  block: [], ruby: true, regex: true },
  go:     { line: ['//'], block: [['/*', '*/']], go: true },
  rust:   { line: ['//'], block: [['/*', '*/']], nest: true, rust: true },
  java:   { line: ['//'], block: [['/*', '*/']], java: true },
  kotlin: { line: ['//'], block: [['/*', '*/']], nest: true, kotlin: true },
  dart:   { line: ['//'], block: [['/*', '*/']], dart: true },
  swift:  { line: ['//'], block: [['/*', '*/']], nest: true, swift: true },
  csharp: { line: ['//'], block: [['/*', '*/']], cs: true },
  c:      { line: ['//'], block: [['/*', '*/']], c: true },
  hcl:    { line: ['#', '//'], block: [['/*', '*/']], hcl: true },
  hash:   { line: ['#'],  block: [], hash: true },
  docker: { line: [],     block: [], docker: true },
  json:   { line: [],     block: [], json: true },
};

export function familyToLexer(family, filePath = '') {
  if (family === 'iac') return /\.(?:tf|tfvars)$/i.test(filePath) ? 'hcl' : (/\.json$/i.test(filePath) ? 'json' : 'hash');
  if (family === 'k8s') return /\.json$/i.test(filePath) ? 'json' : 'hash';
  if (family === 'docker') return /compose/i.test(filePath) ? 'hash' : 'docker';
  return SYNTAX[family] ? family : 'js';
}

export function lex(code, family) {
  const syn = SYNTAX[family] || SYNTAX.js;
  const n = code.length;
  const lit = new Array(n);
  const cod = new Array(n);
  let i = 0;

  const keep = (k) => { lit[k] = code[k]; cod[k] = code[k]; };
  const blank = (k) => { const c = code[k]; lit[k] = c === '\n' ? '\n' : ' '; cod[k] = lit[k]; };
  const strKeep = (k) => { lit[k] = code[k]; cod[k] = code[k] === '\n' ? '\n' : ' '; };   // string text: literal keeps, code blanks
  const startsWith = (s, at = i) => code.startsWith(s, at);

  let lastToken = null, wordBuf = '';
  const flushWord = () => { if (wordBuf) { lastToken = wordBuf; wordBuf = ''; } };
  const pendingHeredocs = [];   // { id, interp, squiggly }

  // Copies a balanced interpolated expression starting at `from` (the first
  // char AFTER the opener) until the matching closer. Returns the index after it.
  function copyBalanced(from, open, close) {
    let depth = 1, k = from;
    while (k < n && depth > 0) {
      const c = code[k];
      if (c === open) depth++;
      else if (c === close) { depth--; if (depth === 0) break; }
      else if (c === '"' || c === "'" || c === '`') {
        // copy a nested simple string verbatim so a brace inside it does not unbalance us
        let m = k + 1;
        while (m < n && code[m] !== c && code[m] !== '\n') { if (code[m] === '\\') m++; m++; }
        for (; k <= Math.min(m, n - 1); k++) { lit[k] = code[k]; cod[k] = code[k]; }
        continue;
      }
      lit[k] = code[k]; cod[k] = code[k]; k++;
    }
    return k;   // index of the closer (or n)
  }

  // Reads a string whose opening delimiter has ALREADY been consumed up to
  // `from`. `o` = { close, esc, interp, raw, multiline, doubleEscape }.
  // Returns the index just past the closing delimiter.
  function readString(from, o) {
    let k = from;
    while (k < n) {
      const c = code[k];
      if (!o.multiline && c === '\n' && !o.allowNewline) { return k; }   // unterminated: stop at EOL
      if (o.hashes !== undefined) {
        // Rust raw "…"### / Swift #"…"#
        if (c === '"' && code.startsWith('"' + '#'.repeat(o.hashes), k)) {
          for (let m = 0; m < 1 + o.hashes; m++) { keep(k + m); }
          return k + 1 + o.hashes;
        }
        if (o.swiftRawInterp && code.startsWith('\\' + '#'.repeat(o.hashes) + '(', k)) {
          for (let m = 0; m < o.hashes + 1; m++) strKeep(k + m);
          const end = copyBalanced(k + o.hashes + 2, '(', ')');
          lit[k + o.hashes + 1] = '('; cod[k + o.hashes + 1] = '(';
          if (end < n) { lit[end] = ')'; cod[end] = ')'; }
          k = end + 1; continue;
        }
        strKeep(k); k++; continue;
      }
      if (o.close && code.startsWith(o.close, k) && !(o.doubleEscape && code.startsWith(o.close + o.close, k))) {
        for (let m = 0; m < o.close.length; m++) keep(k + m);
        return k + o.close.length;
      }
      if (o.doubleEscape && code.startsWith(o.close + o.close, k)) { strKeep(k); strKeep(k + 1); k += 2; continue; }

      // interpolation
      if (o.interp === 'js' && c === '$' && code[k + 1] === '{') {
        strKeep(k); strKeep(k + 1); lit[k + 1] = '{'; cod[k + 1] = '(';
        const end = copyBalanced(k + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'ruby' && c === '#' && code[k + 1] === '{') {
        strKeep(k); lit[k + 1] = '{'; cod[k + 1] = '(';
        const end = copyBalanced(k + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'py' && c === '{') {
        if (code[k + 1] === '{') { strKeep(k); strKeep(k + 1); k += 2; continue; }
        lit[k] = '{'; cod[k] = '(';
        const end = copyBalanced(k + 1, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'cs' && c === '{') {
        if (code[k + 1] === '{') { strKeep(k); strKeep(k + 1); k += 2; continue; }
        lit[k] = '{'; cod[k] = '(';
        const end = copyBalanced(k + 1, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'swift' && c === '\\' && code[k + 1] === '(') {
        strKeep(k); lit[k + 1] = '('; cod[k + 1] = '(';
        const end = copyBalanced(k + 2, '(', ')'); if (end < n) { lit[end] = ')'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'dollar' && c === '$') {
        if (code[k + 1] === '{') {
          strKeep(k); lit[k + 1] = '{'; cod[k + 1] = '(';
          const end = copyBalanced(k + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
        }
        const m = /^[A-Za-z_]\w*/.exec(code.slice(k + 1, k + 80));
        if (m) { strKeep(k); for (let t = 0; t < m[0].length; t++) keep(k + 1 + t); k += 1 + m[0].length; continue; }
      }
      if (o.interp === 'php' && c === '$') {
        if (code[k + 1] === '{') {
          strKeep(k); lit[k + 1] = '{'; cod[k + 1] = '(';
          const end = copyBalanced(k + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
        }
        const m = /^[A-Za-z_]\w*(?:->\w+|\[[^\]\n]{0,60}\])?/.exec(code.slice(k + 1, k + 120));
        if (m) { keep(k); for (let t = 0; t < m[0].length; t++) keep(k + 1 + t); k += 1 + m[0].length; continue; }
      }
      if (o.interp === 'php' && c === '{' && code[k + 1] === '$') {
        lit[k] = '{'; cod[k] = '(';
        const end = copyBalanced(k + 1, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } k = end + 1; continue;
      }
      if (o.interp === 'rust' && c === '{') {
        if (code[k + 1] === '{') { strKeep(k); strKeep(k + 1); k += 2; continue; }
        const m = /^\{([A-Za-z_]\w*)(?::[^}\n]*)?\}/.exec(code.slice(k, k + 80));
        if (m) {
          strKeep(k);
          for (let t = 0; t < m[1].length; t++) keep(k + 1 + t);
          for (let t = 1 + m[1].length; t < m[0].length; t++) strKeep(k + t);
          k += m[0].length; continue;
        }
      }
      if (o.esc && c === '\\') {
        strKeep(k); if (k + 1 < n) strKeep(k + 1); k += 2; continue;
      }
      strKeep(k); k++;
    }
    return k;
  }

  // Heredoc body after a newline: consume lines until the terminator.
  function readHeredocBody(from, h) {
    let k = from;
    const interp = h.interp;
    while (k < n) {
      let eol = code.indexOf('\n', k); if (eol < 0) eol = n;
      const line = code.slice(k, eol);
      const t = h.squiggly ? line.trim() : line.replace(/\r$/, '');
      if (t === h.id || (h.php && line.trim().replace(/[;,)].*$/, '') === h.id)) {
        for (let m = k; m < eol; m++) keep(m);
        return eol;
      }
      // body line: string text, interpolation handled line-wise
      let p = k;
      while (p < eol) {
        const c = code[p];
        if (interp === 'ruby' && c === '#' && code[p + 1] === '{') {
          strKeep(p); lit[p + 1] = '{'; cod[p + 1] = '(';
          const end = copyBalanced(p + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } p = end + 1; continue;
        }
        if (interp === 'php' && c === '$') {
          const m = /^\$?\{?[A-Za-z_]\w*/.exec(code.slice(p, p + 80));
          if (m) { for (let t = 0; t < m[0].length; t++) keep(p + t); p += m[0].length; continue; }
        }
        if (interp === 'hcl' && c === '$' && code[p + 1] === '{') {
          strKeep(p); lit[p + 1] = '{'; cod[p + 1] = '(';
          const end = copyBalanced(p + 2, '{', '}'); if (end < n) { lit[end] = '}'; cod[end] = ')'; } p = end + 1; continue;
        }
        strKeep(p); p++;
      }
      if (eol < n) { lit[eol] = '\n'; cod[eol] = '\n'; }
      k = eol + 1;
    }
    return k;
  }

  const prefixBefore = (at, max = 3) => {
    let s = '', k = at - 1;
    while (k >= 0 && s.length < max && /[A-Za-z]/.test(code[k])) { s = code[k] + s; k--; }
    if (k >= 0 && IDENT_CH.test(code[k])) return '';   // part of a longer identifier
    return s;
  };

  while (i < n) {
    const ch = code[i];

    // ── newline: flush pending heredocs ──────────────────────────────────
    if (ch === '\n') {
      keep(i); i++;
      while (pendingHeredocs.length) { i = readHeredocBody(i, pendingHeredocs.shift()); }
      flushWord(); continue;
    }

    // ── Dockerfile: `#` is a comment only at the start of a line ─────────
    if (syn.docker) {
      if (ch === '#' && /^\s*$/.test(code.slice(code.lastIndexOf('\n', i - 1) + 1, i))) {
        while (i < n && code[i] !== '\n') { blank(i); i++; }
        continue;
      }
      keep(i); i++; continue;
    }
    if (syn.json) { keep(i); i++; continue; }

    // ── YAML-ish: `#` starts a comment at line start or after whitespace ──
    if (syn.hash) {
      if (ch === '#' && (i === 0 || /\s/.test(code[i - 1]))) {
        while (i < n && code[i] !== '\n') { blank(i); i++; }
        continue;
      }
      if (ch === '"' || ch === "'") {
        // quoted scalar on one line: text is literal-only
        keep(i); i++;
        const q = ch;
        while (i < n && code[i] !== '\n') {
          if (code[i] === '\\' && q === '"') { strKeep(i); if (i + 1 < n && code[i + 1] !== '\n') strKeep(i + 1); i += 2; continue; }
          if (code[i] === q) { if (q === "'" && code[i + 1] === "'") { strKeep(i); strKeep(i + 1); i += 2; continue; } keep(i); i++; break; }
          strKeep(i); i++;
        }
        continue;
      }
      keep(i); i++; continue;
    }

    // ── comments ─────────────────────────────────────────────────────────
    let handled = false;
    for (const lc of syn.line) {
      if (!startsWith(lc)) continue;
      if (syn.php && lc === '#' && code[i + 1] === '[') continue;                // PHP 8 attribute, not a comment
      while (i < n && code[i] !== '\n') { blank(i); i++; }
      handled = true; break;
    }
    if (handled) continue;
    if (syn.ruby && ch === '=' && startsWith('=begin') && (i === 0 || code[i - 1] === '\n')) {
      const e = code.indexOf('\n=end', i);
      const stop = e < 0 ? n : code.indexOf('\n', e + 1) < 0 ? n : code.indexOf('\n', e + 1);
      while (i < stop) { blank(i); i++; }
      continue;
    }
    for (const [bo, bc] of syn.block) {
      if (!startsWith(bo)) continue;
      let depth = 1; blank(i); blank(i + 1); i += 2;
      while (i < n && depth > 0) {
        if (syn.nest && startsWith(bo)) { depth++; blank(i); blank(i + 1); i += 2; continue; }
        if (startsWith(bc)) { depth--; blank(i); blank(i + 1); i += 2; continue; }
        blank(i); i++;
      }
      handled = true; break;
    }
    if (handled) continue;

    // ── strings ──────────────────────────────────────────────────────────
    // Python
    if (syn.py && (ch === '"' || ch === "'")) {
      const pre = prefixBefore(i, 2).toLowerCase();
      const raw = pre.includes('r'), isF = pre.includes('f');
      const tri = startsWith(ch.repeat(3));
      const o = { close: tri ? ch.repeat(3) : ch, esc: !raw, interp: isF ? 'py' : null, multiline: tri };
      const open = tri ? 3 : 1;
      for (let m = 0; m < open; m++) keep(i + m);
      i = readString(i + open, o); lastToken = 'VALUE'; continue;
    }
    // JS / TS
    if (syn.tmpl && (ch === '"' || ch === "'")) {
      keep(i); i = readString(i + 1, { close: ch, esc: true, multiline: false }); lastToken = 'VALUE'; continue;
    }
    if (syn.tmpl && ch === '`') {
      keep(i); i = readString(i + 1, { close: '`', esc: true, interp: 'js', multiline: true }); lastToken = 'VALUE'; continue;
    }
    if (syn.regex && ch === '/' && regexCanFollow(lastToken)) {
      const end = consumeRegexLiteral(code, i);
      if (end !== null) {
        // a regex literal is pattern text: kept in `literal`, blanked in `code`
        keep(i); for (let k = i + 1; k < end - 1; k++) strKeep(k);
        // closing slash + flags
        let k = end - 1; keep(k);
        i = end; lastToken = 'VALUE'; continue;
      }
    }
    // PHP
    if (syn.php) {
      if (ch === "'") { keep(i); i = readString(i + 1, { close: "'", esc: true, multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, interp: 'php', multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === '`') { keep(i); i = readString(i + 1, { close: '`', esc: true, interp: 'php', multiline: true }); lastToken = 'VALUE'; continue; }
      const hm = /^<<<\s*(['"]?)([A-Za-z_]\w*)\1/.exec(code.slice(i, i + 80));
      if (hm) {
        for (let k = 0; k < hm[0].length; k++) keep(i + k);
        pendingHeredocs.push({ id: hm[2], interp: hm[1] === "'" ? null : 'php', squiggly: true, php: true });
        i += hm[0].length; continue;
      }
    }
    // Ruby
    if (syn.ruby) {
      if (ch === "'") { keep(i); i = readString(i + 1, { close: "'", esc: true, multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === '"' || ch === '`') { keep(i); i = readString(i + 1, { close: ch, esc: true, interp: 'ruby', multiline: true }); lastToken = 'VALUE'; continue; }
      const hm = /^<<([~-]?)(['"]?)([A-Z_][A-Z0-9_]*)\2/.exec(code.slice(i, i + 80));
      if (hm && (hm[1] || /[=(,]\s*$/.test(code.slice(Math.max(0, i - 6), i)) || /\b(?:puts|print|exec|system|eval|sh)\s*$/.test(code.slice(Math.max(0, i - 8), i)))) {
        for (let k = 0; k < hm[0].length; k++) keep(i + k);
        pendingHeredocs.push({ id: hm[3], interp: hm[2] === "'" ? null : 'ruby', squiggly: hm[1] !== '' });
        i += hm[0].length; continue;
      }
      const pm = /^%([qQwWiIrx]?)([({[<|!/])/.exec(code.slice(i, i + 3));
      if (pm && regexCanFollow(lastToken) && !(IDENT_CH.test(code[i - 1] || ' '))) {
        const closeMap = { '(': ')', '{': '}', '[': ']', '<': '>' };
        const close = closeMap[pm[2]] || pm[2];
        const interp = pm[1] === '' || /[QWIrx]/.test(pm[1]) ? 'ruby' : null;
        for (let k = 0; k < pm[0].length; k++) keep(i + k);
        i = readString(i + pm[0].length, { close, esc: true, interp, multiline: true }); lastToken = 'VALUE'; continue;
      }
    }
    // Go
    if (syn.go) {
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
      if (ch === '`') { keep(i); i = readString(i + 1, { close: '`', esc: false, multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === "'") { keep(i); i = readString(i + 1, { close: "'", esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // Rust
    if (syn.rust) {
      const rm = /^b?r(#*)"/.exec(code.slice(i, i + 20));
      if (rm && !IDENT_CH.test(code[i - 1] || ' ')) {
        for (let k = 0; k < rm[0].length; k++) keep(i + k);
        i = readString(i + rm[0].length, { hashes: rm[1].length, multiline: true }); lastToken = 'VALUE'; continue;
      }
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, interp: 'rust', multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === "'") {
        // char literal vs lifetime
        const cm = /^'(?:\\(?:x[0-9a-fA-F]{2}|u\{[0-9a-fA-F]+\}|.)|[^\\'])'/.exec(code.slice(i, i + 14));
        if (cm) { for (let k = 0; k < cm[0].length; k++) { k === 0 || k === cm[0].length - 1 ? keep(i + k) : strKeep(i + k); } i += cm[0].length; lastToken = 'VALUE'; continue; }
        keep(i); i++; continue;     // lifetime tick
      }
    }
    // Java
    if (syn.java) {
      if (startsWith('"""')) { for (let k = 0; k < 3; k++) keep(i + k); i = readString(i + 3, { close: '"""', esc: true, multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === '"' || ch === "'") { keep(i); i = readString(i + 1, { close: ch, esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // Kotlin
    if (syn.kotlin) {
      if (startsWith('"""')) { for (let k = 0; k < 3; k++) keep(i + k); i = readString(i + 3, { close: '"""', esc: false, interp: 'dollar', multiline: true }); lastToken = 'VALUE'; continue; }
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, interp: 'dollar', multiline: false }); lastToken = 'VALUE'; continue; }
      if (ch === "'") { keep(i); i = readString(i + 1, { close: "'", esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // Dart
    if (syn.dart && (ch === '"' || ch === "'")) {
      const raw = code[i - 1] === 'r' && !IDENT_CH.test(code[i - 2] || ' ');
      const tri = startsWith(ch.repeat(3));
      const open = tri ? 3 : 1;
      for (let k = 0; k < open; k++) keep(i + k);
      i = readString(i + open, { close: tri ? ch.repeat(3) : ch, esc: !raw, interp: raw ? null : 'dollar', multiline: tri }); lastToken = 'VALUE'; continue;
    }
    // Swift
    if (syn.swift) {
      const hm = /^(#*)"""/.exec(code.slice(i, i + 12));
      if (hm) {
        const hashes = hm[1].length;
        for (let k = 0; k < hm[0].length; k++) keep(i + k);
        i = readString(i + hm[0].length, hashes
          ? { close: '"""' + '#'.repeat(hashes), esc: false, multiline: true }
          : { close: '"""', esc: true, interp: 'swift', multiline: true });
        lastToken = 'VALUE'; continue;
      }
      const hr = /^(#+)"/.exec(code.slice(i, i + 12));
      if (hr) {
        for (let k = 0; k < hr[0].length; k++) keep(i + k);
        i = readString(i + hr[0].length, { hashes: hr[1].length, swiftRawInterp: true, multiline: false }); lastToken = 'VALUE'; continue;
      }
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, interp: 'swift', multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // C#
    if (syn.cs) {
      const m = /^(\$@|@\$|\$|@)?"/.exec(code.slice(i, i + 3));
      if (m && !IDENT_CH.test(code[i - 1] || ' ')) {
        const pre = m[1] || '';
        if (code.startsWith('"""', i + pre.length)) {
          for (let k = 0; k < pre.length + 3; k++) keep(i + k);
          i = readString(i + pre.length + 3, { close: '"""', esc: false, interp: pre.includes('$') ? 'cs' : null, multiline: true }); lastToken = 'VALUE'; continue;
        }
        const verbatim = pre.includes('@'), interp = pre.includes('$');
        for (let k = 0; k < pre.length + 1; k++) keep(i + k);
        i = readString(i + pre.length + 1, { close: '"', esc: !verbatim, interp: interp ? 'cs' : null, multiline: verbatim, doubleEscape: verbatim });
        lastToken = 'VALUE'; continue;
      }
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
      if (ch === "'") { keep(i); i = readString(i + 1, { close: "'", esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // C / C++
    if (syn.c) {
      const rm = /^(?:u8|u|U|L)?R"([^()\\\s]{0,16})\(/.exec(code.slice(i, i + 24));
      if (rm) {
        const close = ')' + rm[1] + '"';
        for (let k = 0; k < rm[0].length; k++) keep(i + k);
        i = readString(i + rm[0].length, { close, esc: false, multiline: true }); lastToken = 'VALUE'; continue;
      }
      if (ch === '#' && /^\s*$/.test(code.slice(code.lastIndexOf('\n', i - 1) + 1, i)) && /^#\s*include\s*[<"]/.test(code.slice(i, i + 40))) {
        // #include <x.h> / "x.h": header names are not code
        while (i < n && code[i] !== '\n') { strKeep(i); i++; }
        continue;
      }
      if (ch === '"' || ch === "'") { keep(i); i = readString(i + 1, { close: ch, esc: true, multiline: false }); lastToken = 'VALUE'; continue; }
    }
    // HCL (Terraform)
    if (syn.hcl) {
      if (ch === '"') { keep(i); i = readString(i + 1, { close: '"', esc: true, interp: 'js', multiline: false }); lastToken = 'VALUE'; continue; }
      const hm = /^<<(-?)([A-Za-z_]\w*)/.exec(code.slice(i, i + 60));
      if (hm) {
        for (let k = 0; k < hm[0].length; k++) keep(i + k);
        pendingHeredocs.push({ id: hm[2], interp: 'hcl', squiggly: true });
        i += hm[0].length; continue;
      }
    }

    // ── plain code ───────────────────────────────────────────────────────
    keep(i);
    if (IDENT_CH.test(ch)) wordBuf += ch;
    else { flushWord(); if (!/\s/.test(ch)) lastToken = ch; }
    i++;
  }

  return { literal: lit.join(''), code: cod.join('') };
}
