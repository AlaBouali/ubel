'use strict';

// ─── minimal YAML parser (zero dependencies) ─────────────────────────────────────────────────────────────────
//
// Just enough YAML for Semgrep-style rule files, so `--rules-dir` works with Node built-ins only:
//
//   block mappings and sequences (including `- key: v` and `- - x`), `key:\n- item` at the same indent,
//   plain / 'single' / "double" quoted scalars (multi-line, with YAML escapes), block scalars  | |- |+ > >- >+ (+ indent digit),
//   flow collections  [a, b]  {k: v}  (nested, multi-line), `#` comments, a leading `---`, null / true / false / numbers.
//
// NOT supported (a clear YamlError, never a silent mis-parse): anchors & aliases (&a *a <<), tags (!!str), `? ` complex keys,
// tab indentation, multiple documents (only the first is read).

export class YamlError extends Error {
  constructor(message, line) { super(line ? `${message} (line ${line})` : message); this.name = 'YamlError'; this.line = line || 0; }
}

const ESC = { n: '\n', t: '\t', r: '\r', '0': '\0', a: '\x07', b: '\b', e: '\x1b', f: '\f', v: '\v', ' ': ' ', '"': '"', '/': '/', '\\': '\\', N: '\x85', _: '\xa0', L: '\u2028', P: '\u2029' };

function unescapeDouble(s, line) {
  let out = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c !== '\\') { out += c; continue; }
    const n = s[++i];
    if (n === undefined) throw new YamlError('dangling backslash in a double-quoted string', line);
    if (n === 'x' || n === 'u' || n === 'U') {
      const len = n === 'x' ? 2 : n === 'u' ? 4 : 8;
      const hex = s.slice(i + 1, i + 1 + len);
      if (!new RegExp(`^[0-9a-fA-F]{${len}}$`).test(hex)) throw new YamlError(`bad \\${n} escape`, line);
      out += String.fromCodePoint(parseInt(hex, 16)); i += len;
    } else if (n === '\n') { /* escaped line break: joined */ }
    else if (n in ESC) out += ESC[n];
    else throw new YamlError(`unknown escape \\${n}`, line);
  }
  return out;
}

function scalarOf(text) {
  const t = text.trim();
  if (t === '' || t === '~' || /^null$/i.test(t)) return null;
  if (/^(?:true|True|TRUE)$/.test(t)) return true;
  if (/^(?:false|False|FALSE)$/.test(t)) return false;
  if (/^[-+]?(?:0|[1-9]\d*)$/.test(t)) return Number(t);
  if (/^[-+]?(?:\d+\.\d*|\.\d+)(?:[eE][-+]?\d+)?$/.test(t)) return Number(t);
  if (/^0x[0-9a-fA-F]+$/.test(t)) return parseInt(t, 16);
  return t;
}

// position of a ` #` comment in a plain scalar (a `#` must follow whitespace)
function plainCommentAt(s) {
  for (let i = 0; i < s.length; i++) if (s[i] === '#' && (i === 0 || /\s/.test(s[i - 1]))) return i;
  return -1;
}

export function parseYaml(src, file = '') {
  const lines = String(src).replace(/^\uFEFF/, '').split(/\r?\n/);
  let i = 0;

  const fail = (msg, at = i) => { throw new YamlError(msg, at + 1); };
  const indentOf = (l) => {
    let n = 0;
    while (n < l.length && l[n] === ' ') n++;
    if (l[n] === '\t' && l.slice(n).trim() !== '' && !l.slice(n).trim().startsWith('#')) throw new YamlError('tabs are not allowed for indentation', lines.indexOf(l) + 1);
    return n;
  };
  const blank = (l) => l.trim() === '' || l.trim().startsWith('#');

  function skipBlank() { while (i < lines.length && blank(lines[i])) i++; }

  // document markers
  skipBlank();
  while (i < lines.length && /^%/.test(lines[i])) { i++; skipBlank(); }
  if (i < lines.length && /^---(?:\s|$)/.test(lines[i])) {
    const rest = lines[i].slice(3).trim();
    if (rest && !rest.startsWith('#')) lines[i] = ' '.repeat(4) + rest; else i++;
  }
  // everything after a second `---` / `...` is another document
  for (let k = i; k < lines.length; k++) if (/^(?:---|\.\.\.)(?:\s|$)/.test(lines[k])) { lines.length = k; break; }

  skipBlank();
  if (i >= lines.length) return null;
  const value = parseBlock(indentOf(lines[i]));
  skipBlank();
  if (i < lines.length) fail('unexpected content (bad indentation?)');
  return value;

  // ── block structures ─────────────────────────────────────────────────────────────────────────────────────
  function parseBlock(ind) {
    skipBlank();
    if (i >= lines.length) return null;
    const line = lines[i];
    const body = line.slice(indentOf(line));
    if (/^-(?:\s|$)/.test(body)) return parseSeq(indentOf(line));
    if (keyOf(body)) return parseMap(indentOf(line));
    return parseScalarLines(indentOf(line), -1);
  }

  function parseSeq(ind) {
    const out = [];
    while (i < lines.length) {
      skipBlank();
      if (i >= lines.length) break;
      const line = lines[i], cur = indentOf(line), body = line.slice(cur);
      if (cur < ind) break;
      if (cur > ind) fail('bad indentation of a sequence entry');
      if (!/^-(?:\s|$)/.test(body)) break;
      const rest = body.slice(1);
      const lead = rest.length - rest.trimStart().length;
      const content = rest.trim();
      if (content === '' || content.startsWith('#')) {
        i++;
        skipBlank();
        if (i < lines.length && indentOf(lines[i]) > ind) out.push(parseBlock(indentOf(lines[i])));
        else out.push(null);
      } else {
        // `- key: v` / `- - x` / `- scalar`: re-read the rest of the line as if it were its own line, indented past the dash
        const col = cur + 1 + lead;
        lines[i] = ' '.repeat(col) + rest.trimStart();
        out.push(parseBlock(col));
      }
    }
    return out;
  }

  // a mapping key at the start of `body`: { key, rest } or null
  function keyOf(body) {
    let m;
    if ((m = /^"((?:[^"\\]|\\.)*)"\s*:(?:\s+(.*)|$)/.exec(body))) return { key: unescapeDouble(m[1], i + 1), rest: m[2] ?? '' };
    if ((m = /^'((?:[^']|'')*)'\s*:(?:\s+(.*)|$)/.exec(body))) return { key: m[1].replace(/''/g, "'"), rest: m[2] ?? '' };
    if (/^[\-?:,\[\]{}#&*!|>'"%@`]/.test(body) && !/^-[^\s]/.test(body)) return null;
    m = /^((?:[^:#\s]|:(?!\s|$)|\s+(?![#\s]))+?)\s*:(?:\s+(.*)|$)/.exec(body);
    if (!m) return null;
    if (/^[\[{]/.test(m[1])) return null;
    return { key: m[1].trim(), rest: m[2] ?? '' };
  }

  function parseMap(ind) {
    const out = {};
    while (i < lines.length) {
      skipBlank();
      if (i >= lines.length) break;
      const line = lines[i], cur = indentOf(line);
      if (cur < ind) break;
      if (cur > ind) fail('bad indentation of a mapping entry');
      const body = line.slice(cur);
      if (/^-(?:\s|$)/.test(body)) break;                      // a sequence at the same indent ends the mapping (`key:\n- a` is handled below)
      const k = keyOf(body);
      if (!k) fail(`expected "key: value", got "${body.slice(0, 40)}"`);
      if (Object.prototype.hasOwnProperty.call(out, k.key)) fail(`duplicate key "${k.key}"`);
      const at = i;
      out[k.key] = parseValue(k.rest, ind);
      if (i === at) i++;                                        // safety: always make progress
    }
    return out;
  }

  // the value after `key:` (rest of the line) for a mapping whose keys are at `ind`
  function parseValue(rest, ind) {
    const r = rest.trim();
    const startLine = i;
    if (r === '' || r.startsWith('#')) {
      i++;
      skipBlank();
      if (i < lines.length) {
        const nl = lines[i], ni = indentOf(nl), nb = nl.slice(ni);
        if (ni > ind) return parseBlock(ni);
        if (ni === ind && /^-(?:\s|$)/.test(nb)) return parseSeq(ni);   // `key:` followed by `- item` at the same indent
      }
      return null;
    }
    if (/^[|>]/.test(r)) { i++; return blockScalar(r, ind, startLine); }
    if (/^[&*!]/.test(r) || /^<<\s*:/.test(r)) fail('YAML anchors, aliases and tags are not supported', startLine);
    if (r[0] === '[' || r[0] === '{') {
      let text = stripFlowComment(r);
      let j = i + 1;
      while (!flowBalanced(text) && j < lines.length) { text += ' ' + stripFlowComment(lines[j].trim()); j++; }
      if (!flowBalanced(text)) fail('unterminated flow collection', startLine);
      i = j;
      return parseFlow(text, startLine);
    }
    if (r[0] === '"' || r[0] === "'") {
      let text = rest.replace(/^\s+/, '');
      let j = i + 1;
      while (!quotedClosed(text) && j < lines.length) { text += '\n' + lines[j]; j++; }
      if (!quotedClosed(text)) fail('unterminated quoted string', startLine);
      i = j;
      return quotedScalar(text, startLine);
    }
    // plain scalar, possibly continued on more-indented lines
    i++;
    let text = r;
    const c = plainCommentAt(text); if (c >= 0) text = text.slice(0, c).trimEnd();
    for (;;) {
      let j = i;
      while (j < lines.length && lines[j].trim() === '') j++;
      if (j >= lines.length || blank(lines[j]) || indentOf(lines[j]) <= ind) break;
      const cont = lines[j].trim();
      if (keyOf(lines[j].slice(indentOf(lines[j]))) && !/^["'(\[{$]/.test(cont)) break;
      const cc = plainCommentAt(cont);
      text += (j > i ? '\n' : ' ') + (cc >= 0 ? cont.slice(0, cc).trimEnd() : cont);
      i = j + 1;
    }
    return scalarOf(text.replace(/\n/g, ' '));
  }

  // a scalar occupying whole lines (a document that is just text)
  function parseScalarLines(ind) {
    const text = lines[i].trim(); i++;
    if (text[0] === '[' || text[0] === '{') return parseFlow(text, i);
    if (text[0] === '"' || text[0] === "'") return quotedScalar(text, i);
    return scalarOf(text);
  }

  // ── block scalars ────────────────────────────────────────────────────────────────────────────────────────
  function blockScalar(header, parentIndent, startLine) {
    const m = /^([|>])([1-9])?([+-])?([1-9])?\s*(?:#.*)?$/.exec(header);
    if (!m) fail(`bad block scalar header "${header}"`, startLine);
    const style = m[1], chomp = m[3] || '', explicit = Number(m[2] || m[4] || 0);
    const raw = [];
    let blockIndent = explicit ? parentIndent + explicit : -1;
    // for a sequence item (`- |`) the parent indent is the column of the dash content, which is what `parentIndent` carries
    while (i < lines.length) {
      const l = lines[i];
      if (l.trim() === '') { raw.push(''); i++; continue; }
      const ind = indentOf(l);
      if (blockIndent < 0) { if (ind <= parentIndent) break; blockIndent = ind; }
      if (ind < blockIndent) break;
      raw.push(l.slice(blockIndent));
      i++;
    }
    while (raw.length && raw[raw.length - 1] === '' && chomp !== '+') raw.pop();
    let trailing = 0;
    if (chomp === '+') { while (raw.length && raw[raw.length - 1] === '') { raw.pop(); trailing++; } }
    let text;
    if (style === '|') text = raw.join('\n');
    else {
      text = '';
      for (let k = 0; k < raw.length; k++) {
        const cur = raw[k], prev = raw[k - 1];
        if (k === 0) { text = cur; continue; }
        if (cur === '') { text += '\n'; continue; }
        if (prev === '' ) { text += cur; continue; }
        text += (/^\s/.test(cur) || /^\s/.test(prev) ? '\n' : ' ') + cur;
      }
    }
    if (raw.length === 0 && chomp !== '+') return '';
    if (chomp === '-') return text;
    return text + '\n' + '\n'.repeat(trailing);
  }

  // ── quoted scalars ───────────────────────────────────────────────────────────────────────────────────────
  function quotedClosed(t) {
    const q = t[0];
    for (let k = 1; k < t.length; k++) {
      if (q === '"' && t[k] === '\\') { k++; continue; }
      if (t[k] === q) { if (q === "'" && t[k + 1] === "'") { k++; continue; } return true; }
    }
    return false;
  }
  function foldQuoted(body) {
    // line folding: a single break becomes a space, a blank line becomes a newline; leading blanks of continuation lines are dropped
    const parts = body.split('\n');
    let out = parts[0].replace(/[ \t]+$/, parts.length > 1 ? '' : '$&');
    for (let k = 1; k < parts.length; k++) {
      const cur = parts[k].trim();
      if (cur === '') { out += '\n'; continue; }
      out += (out.endsWith('\n') ? '' : ' ') + cur;
    }
    return out;
  }
  function quotedScalar(text, at) {
    const q = text[0];
    let k = 1, end = -1;
    for (; k < text.length; k++) {
      if (q === '"' && text[k] === '\\') { k++; continue; }
      if (text[k] === q) { if (q === "'" && text[k + 1] === "'") { k++; continue; } end = k; break; }
    }
    if (end < 0) fail('unterminated quoted string', at - 1);
    const trailing = text.slice(end + 1).trim();
    if (trailing && !trailing.startsWith('#')) fail(`unexpected text after a quoted string: "${trailing.slice(0, 30)}"`, at - 1);
    const body = text.slice(1, end);
    // an escaped line break (`\` at the end of a line) joins the lines with no space; it is resolved before folding
    return q === '"' ? unescapeDouble(foldQuoted(body.replace(/((?:^|[^\\])(?:\\\\)*)\\\n[ \t]*/g, '$1')), at) : foldQuoted(body).replace(/''/g, "'");
  }

  // ── flow collections ─────────────────────────────────────────────────────────────────────────────────────
  function stripFlowComment(s) {
    let q = null;
    for (let k = 0; k < s.length; k++) {
      const c = s[k];
      if (q) { if (c === '\\' && q === '"') k++; else if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '#' && (k === 0 || /\s/.test(s[k - 1]))) return s.slice(0, k).trimEnd();
    }
    return s;
  }
  function flowBalanced(s) {
    let d = 0, q = null;
    for (let k = 0; k < s.length; k++) {
      const c = s[k];
      if (q) { if (c === '\\' && q === '"') k++; else if (c === q) q = null; continue; }
      if (c === '"' || c === "'") q = c;
      else if (c === '[' || c === '{') d++;
      else if (c === ']' || c === '}') d--;
    }
    return d <= 0 && !q;
  }
  function parseFlow(s, at) {
    let p = 0;
    const ws = () => { while (p < s.length && /\s/.test(s[p])) p++; };
    const err = (m) => { throw new YamlError(m, at + 1); };
    function node() {
      ws();
      const c = s[p];
      if (c === '[') {
        p++; const arr = [];
        for (;;) {
          ws();
          if (s[p] === ']') { p++; return arr; }
          arr.push(entryValue());
          ws();
          if (s[p] === ',') { p++; continue; }
          if (s[p] === ']') { p++; return arr; }
          err('expected "," or "]" in a flow sequence');
        }
      }
      if (c === '{') {
        p++; const obj = {};
        for (;;) {
          ws();
          if (s[p] === '}') { p++; return obj; }
          const key = flowScalar(true);
          ws();
          let val = null;
          if (s[p] === ':') { p++; ws(); val = (s[p] === ',' || s[p] === '}') ? null : node(); }
          obj[String(key)] = val;
          ws();
          if (s[p] === ',') { p++; continue; }
          if (s[p] === '}') { p++; return obj; }
          err('expected "," or "}" in a flow mapping');
        }
      }
      return flowScalar(false);
    }
    // `[a: b]` is a single-pair mapping; everything else is a node
    function entryValue() {
      ws();
      if (s[p] === '[' || s[p] === '{') return node();
      const save = p;
      const k = flowScalar(true);
      ws();
      if (s[p] === ':' && (s[p + 1] === ' ' || p + 1 >= s.length)) { p++; ws(); return { [String(k)]: node() }; }
      p = save;
      return flowScalar(false);
    }
    function flowScalar(isKey) {
      ws();
      const c = s[p];
      if (c === '"' || c === "'") {
        let k = p + 1;
        for (; k < s.length; k++) {
          if (c === '"' && s[k] === '\\') { k++; continue; }
          if (s[k] === c) { if (c === "'" && s[k + 1] === "'") { k++; continue; } break; }
        }
        if (k >= s.length) err('unterminated quoted string');
        const body = s.slice(p + 1, k); p = k + 1;
        return c === '"' ? unescapeDouble(body, at + 1) : body.replace(/''/g, "'");
      }
      let k = p;
      while (k < s.length) {
        const ch = s[k];
        if (ch === ',' || ch === ']' || ch === '}') break;
        if (ch === ':' && (isKey || s[k + 1] === ' ' || k + 1 >= s.length)) { if (s[k + 1] === ' ' || k + 1 >= s.length || isKey) break; }
        k++;
      }
      const text = s.slice(p, k).trim(); p = k;
      return scalarOf(text);
    }
    const v = node();
    ws();
    if (p < s.length) err('unexpected text after a flow collection');
    return v;
  }
}
