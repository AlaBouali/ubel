'use strict';

// ─── Structure parsers for config files (no dependencies) ─────────────────────
//
//   parseYamlDocs(literal)  → [{ doc, line }]  a YAML subset sufficient for Kubernetes
//                             manifests, Compose files, CloudFormation and Ansible:
//                             block maps/sequences, scalars, quoted strings, flow
//                             [a, b] / {a: b}, block scalars, multi-document files.
//                             Every map/array carries non-enumerable `$line` (1-based
//                             file line) and `$lines` (key/index → line).
//   parseHclBlocks(code, literal) → Terraform blocks with labels and attribute access.
//
// Both operate on the offset-aligned views from lexer.js, so comments are gone and
// string text is still available (literal view).

const hide = (o, k, v) => Object.defineProperty(o, k, { value: v, enumerable: false, writable: true });

function unquote(s) {
  s = s.trim();
  if ((s.startsWith('"') && s.endsWith('"') && s.length >= 2)) return s.slice(1, -1).replace(/\\(["\\nt])/g, (_, c) => (c === 'n' ? '\n' : c === 't' ? '\t' : c));
  if ((s.startsWith("'") && s.endsWith("'") && s.length >= 2)) return s.slice(1, -1).replace(/''/g, "'");
  return s;
}

function splitFlow(s) {
  const out = []; let depth = 0, cur = '', q = null;
  for (const ch of s) {
    if (q) { cur += ch; if (ch === q) q = null; continue; }
    if (ch === '"' || ch === "'") { q = ch; cur += ch; continue; }
    if (ch === '[' || ch === '{') depth++;
    else if (ch === ']' || ch === '}') depth--;
    if (ch === ',' && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

function parseScalarOrFlow(text, line) {
  const t = text.trim();
  if (t.startsWith('[') && t.endsWith(']')) {
    const arr = splitFlow(t.slice(1, -1)).map(x => parseScalarOrFlow(x, line));
    hide(arr, '$line', line); hide(arr, '$lines', arr.map(() => line));
    return arr;
  }
  if (t.startsWith('{') && t.endsWith('}')) {
    const obj = {}; const lines = {};
    for (const part of splitFlow(t.slice(1, -1))) {
      const i = part.indexOf(':'); if (i < 0) continue;
      const k = unquote(part.slice(0, i)); obj[k] = parseScalarOrFlow(part.slice(i + 1), line); lines[k] = line;
    }
    hide(obj, '$line', line); hide(obj, '$lines', lines);
    return obj;
  }
  if (t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  return unquote(t);
}

function parseYamlDoc(rawLines, firstLine) {
  const lines = [];
  rawLines.forEach((raw, i) => {
    if (/^\s*$/.test(raw) || /^\s*#/.test(raw)) return;
    const indent = raw.match(/^ */)[0].length;
    lines.push({ indent, text: raw.slice(indent).replace(/\s+$/, ''), line: firstLine + i, raw });
  });
  let pos = 0;

  const isSeq = (t) => t === '-' || t.startsWith('- ');
  const KEY = /^((?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^\s"'#\[\]{},&*!|>%@`:][^:]*?|[^\s:"'][^:]*?))\s*:(?:\s+(.*))?$/;

  function blockScalar(parentIndent, style) {
    const buf = [];
    while (pos < lines.length && lines[pos].indent > parentIndent) { buf.push(lines[pos].raw.slice(Math.min(lines[pos].indent, lines[pos].raw.length))); pos++; }
    return style.startsWith('|') ? buf.join('\n') : buf.join(' ');
  }

  function parseValue(rest, indent, line) {
    rest = (rest || '').trim();
    if (rest === '' || rest.startsWith('&') && !rest.includes(' ')) {
      if (pos < lines.length && lines[pos].indent > indent) return parseBlock(lines[pos].indent);
      if (pos < lines.length && lines[pos].indent === indent && isSeq(lines[pos].text)) return parseBlock(indent);
      return '';
    }
    if (/^[|>][+\-0-9]*$/.test(rest)) return blockScalar(indent, rest);
    // continuation of a multi-line plain/quoted scalar
    let val = rest;
    while (pos < lines.length && lines[pos].indent > indent && !KEY.test(lines[pos].text) && !isSeq(lines[pos].text) && !/^[\[{]/.test(val)) { val += ' ' + lines[pos].text; pos++; }
    // multi-line flow collections
    if (/^[\[{]/.test(val)) {
      let open = (val.match(/[\[{]/g) || []).length, close = (val.match(/[\]}]/g) || []).length;
      while (open > close && pos < lines.length) { val += ' ' + lines[pos].text; pos++; open = (val.match(/[\[{]/g) || []).length; close = (val.match(/[\]}]/g) || []).length; }
    }
    return parseScalarOrFlow(val.replace(/^(?:&\S+|!\S+)\s+/, ''), line);
  }

  function parseBlock(indent) {
    if (pos >= lines.length) return null;
    const first = lines[pos];
    if (isSeq(first.text)) {
      const arr = []; const ls = [];
      hide(arr, '$line', first.line);
      while (pos < lines.length && lines[pos].indent === indent && isSeq(lines[pos].text)) {
        const cur = lines[pos];
        const rest = cur.text === '-' ? '' : cur.text.slice(2);
        const restTrim = rest.trimStart();
        const off = cur.text.length - restTrim.length;
        if (restTrim === '') { pos++; arr.push(pos < lines.length && lines[pos].indent > indent ? parseBlock(lines[pos].indent) : null); ls.push(cur.line); continue; }
        if (isSeq(restTrim) || (KEY.test(restTrim) && !/^[\[{"']/.test(restTrim) || KEY.test(restTrim) && /^["'][^"']*["']\s*:/.test(restTrim))) {
          // inline nested block starting on the "- " line: re-indent it as a virtual line
          lines[pos] = { indent: indent + off, text: restTrim, line: cur.line, raw: ' '.repeat(indent + off) + restTrim };
          arr.push(parseBlock(indent + off)); ls.push(cur.line);
        } else {
          pos++; arr.push(parseValue(restTrim, indent, cur.line)); ls.push(cur.line);
        }
      }
      hide(arr, '$lines', ls);
      return arr;
    }
    const obj = {}; const ls = {};
    hide(obj, '$line', first.line);
    while (pos < lines.length && lines[pos].indent === indent && !isSeq(lines[pos].text)) {
      const cur = lines[pos];
      const km = KEY.exec(cur.text);
      if (!km) { pos++; continue; }
      pos++;
      const key = unquote(km[1]);
      obj[key] = parseValue(km[2], indent, cur.line); ls[key] = cur.line;
    }
    hide(obj, '$lines', ls);
    return obj;
  }

  if (!lines.length) return null;
  try { return parseBlock(lines[0].indent); } catch { return null; }
}

export function parseYamlDocs(literal) {
  const all = literal.split('\n');
  const docs = []; let start = 0, cur = [];
  const flush = (firstLine) => {
    if (cur.some(l => l.trim())) { const d = parseYamlDoc(cur, firstLine); if (d && typeof d === 'object') docs.push({ doc: d, line: firstLine }); }
    cur = [];
  };
  let first = 1;
  for (let i = 0; i < all.length; i++) {
    if (/^---(?:\s|$)/.test(all[i]) || /^\.\.\.\s*$/.test(all[i])) { flush(first); first = i + 2; continue; }
    cur.push(all[i]);
  }
  flush(first);
  return docs;
}

// Helpers for walking parsed YAML
export const isMap = (v) => v && typeof v === 'object' && !Array.isArray(v);
export const lineOfKey = (obj, key) => (obj && obj.$lines && obj.$lines[key]) || (obj && obj.$line) || 1;
export const asArray = (v) => (Array.isArray(v) ? v : v === undefined || v === null || v === '' ? [] : [v]);
export const truthy = (v) => /^(?:true|yes|on|y|1)$/i.test(String(v ?? '').trim());
export const falsy = (v) => /^(?:false|no|off|n|0)$/i.test(String(v ?? '').trim());
export function* walk(node, pathKeys = []) {
  yield [node, pathKeys];
  if (Array.isArray(node)) { for (let i = 0; i < node.length; i++) if (node[i] && typeof node[i] === 'object') yield* walk(node[i], [...pathKeys, i]); }
  else if (isMap(node)) { for (const k of Object.keys(node)) if (node[k] && typeof node[k] === 'object') yield* walk(node[k], [...pathKeys, k]); }
}

// ── HCL (Terraform) ───────────────────────────────────────────────────────────
function matchBrace(code, open) {
  let depth = 0;
  for (let k = open; k < code.length; k++) { if (code[k] === '{') depth++; else if (code[k] === '}') { depth--; if (depth === 0) return k; } }
  return -1;
}

// Returns the value text for `name = value` inside a block body (literal view), or undefined.
function hclAttr(bodyLit, bodyCode, name) {
  const re = new RegExp(String.raw`(?:^|\n)[ \t]*${name}[ \t]*=[ \t]*`, 'g');
  const m = re.exec(bodyCode);
  if (!m) return undefined;
  const from = m.index + m[0].length;
  let k = from, depth = 0;
  for (; k < bodyCode.length; k++) {
    const c = bodyCode[k];
    if (c === '[' || c === '{' || c === '(') depth++;
    else if (c === ']' || c === '}' || c === ')') depth--;
    else if (c === '\n' && depth <= 0) break;
  }
  return { text: bodyLit.slice(from, k).trim(), offset: from, line: null };
}

export function parseHclBlocks(code, literal, lineAt) {
  const blocks = [];
  const re = /(^|\n)[ \t]*([A-Za-z_][\w-]*)((?:[ \t]+(?:"[^"\n]*"|[A-Za-z_][\w-]*))*)[ \t]*\{/g;
  let m;
  while ((m = re.exec(code)) !== null) {
    const open = m.index + m[0].length - 1;
    const close = matchBrace(code, open);
    if (close < 0) continue;
    const nameStart = m.index + m[1].length;
    const labels = [...literal.slice(nameStart, open).matchAll(/"([^"\n]*)"|\b([A-Za-z_][\w-]*)\b/g)].slice(1).map(x => x[1] ?? x[2]);
    const kind = m[2];
    const bodyCode = code.slice(open + 1, close), bodyLit = literal.slice(open + 1, close);
    blocks.push(makeBlock(kind, labels, nameStart, open + 1, bodyCode, bodyLit, lineAt));
    // nested blocks are parsed lazily by sub(); continue scanning after this block's opener
  }
  // keep only top-level blocks
  return blocks.filter(b => !blocks.some(o => o !== b && o.bodyStart < b.start && b.start < o.bodyStart + o.bodyCode.length));
}

function makeBlock(kind, labels, start, bodyStart, bodyCode, bodyLit, lineAt) {
  const blk = {
    kind, labels, start, bodyStart, bodyCode, bodyLit, line: lineAt(start),
    type: labels[0], name: labels[1],
    attr(name) { const a = hclAttr(bodyLit, bodyCode, name); return a ? { ...a, line: lineAt(bodyStart + a.offset) } : undefined; },
    val(name) { const a = hclAttr(bodyLit, bodyCode, name); return a ? a.text.replace(/^["']|["']$/g, '') : undefined; },
    sub(name) {
      const out = []; const r = new RegExp(String.raw`(^|\n)[ \t]*${name}((?:[ \t]+(?:"[^"\n]*"|[A-Za-z_][\w-]*))*)[ \t]*\{`, 'g'); let mm;
      while ((mm = r.exec(bodyCode)) !== null) {
        const open = mm.index + mm[0].length - 1; const close = matchBrace(bodyCode, open); if (close < 0) continue;
        const s = mm.index + mm[1].length;
        out.push(makeBlock(name, [...bodyLit.slice(s, open).matchAll(/"([^"\n]*)"/g)].map(x => x[1]), bodyStart + s, bodyStart + open + 1, bodyCode.slice(open + 1, close), bodyLit.slice(open + 1, close), lineAt));
        r.lastIndex = close;
      }
      return out;
    },
  };
  return blk;
}
