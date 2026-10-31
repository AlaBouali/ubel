'use strict';
// yaml.js — a block-YAML reader for the two documents `ubel-package` needs: a RubyGems `metadata.gz` (a Ruby-tagged gemspec dump) and pubspec.yaml.
// Supported: block mappings and sequences (including the compact `- key: v` and `- - x` forms and sequences indented like their key), plain /
// quoted scalars, block scalars (| and > with chomping), flow `[a, b]` / `{a: b}` collections, comments, `---`. Tags (`!ruby/object:…`) and
// anchors are dropped. Every plain scalar stays a STRING except true / false / null, so a version like `1.0` is never turned into the number 1.
// It is not a general YAML parser: aliases, multi-document streams and complex keys are not interpreted.

class Reader {
  constructor(text) {
    this.lines = [];
    const raw = String(text).replace(/^﻿/, '').split(/\r?\n/);
    for (let n = 0; n < raw.length; n++) this.lines.push({ n, raw: raw[n] });
    this.i = 0;
  }
}

const indentOf = l => l.length - l.trimStart().length;
const stripComment = s => {
  let q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { if (c === '\\' && q === '"') i++; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'") { if (i === 0 || /[\s[{,:]/.test(s[i - 1])) q = c; continue; }
    if (c === '#' && (i === 0 || /\s/.test(s[i - 1]))) return s.slice(0, i).trimEnd();
  }
  return s.trimEnd();
};

function unquote(t) {
  if (t.length >= 2 && t[0] === '"' && t.endsWith('"')) {
    return t.slice(1, -1).replace(/\\(u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|.)/g, (m, c) => {
      if (c[0] === 'u' || c[0] === 'x') return String.fromCharCode(parseInt(c.slice(1), 16));
      return ({ n: '\n', t: '\t', r: '\r', '0': '\0', '"': '"', '\\': '\\', '/': '/', ' ': ' ' })[c] ?? m;
    });
  }
  if (t.length >= 2 && t[0] === "'" && t.endsWith("'")) return t.slice(1, -1).replace(/''/g, "'");
  return t;
}

function scalar(t) {
  t = t.trim();
  if (t === '' || t === '~' || t === 'null' || t === 'Null' || t === 'NULL') return null;
  if (t === 'true' || t === 'True') return true;
  if (t === 'false' || t === 'False') return false;
  if (t[0] === '"' || t[0] === "'") return unquote(t);
  return t;
}

function stripTagAnchor(t) {
  return t.replace(/^(?:!\S*|&\S+)\s*/, '').replace(/^(?:!\S*|&\S+)\s*/, '');
}

function flow(t) {
  let i = 0;
  const ws = () => { while (i < t.length && /\s/.test(t[i])) i++; };
  const value = () => {
    ws();
    if (t[i] === '[') {
      i++; const a = [];
      for (;;) { ws(); if (t[i] === ']' || i >= t.length) { i++; return a; } a.push(value()); ws(); if (t[i] === ',') i++; }
    }
    if (t[i] === '{') {
      i++; const o = {};
      for (;;) {
        ws(); if (t[i] === '}' || i >= t.length) { i++; return o; }
        const k = key(); ws(); if (t[i] === ':') i++;
        o[k] = value(); ws(); if (t[i] === ',') i++;
      }
    }
    if (t[i] === '"' || t[i] === "'") {
      const q = t[i]; let j = i + 1;
      while (j < t.length && t[j] !== q) j += t[j] === '\\' && q === '"' ? 2 : 1;
      const s = t.slice(i, j + 1); i = j + 1; return unquote(s);
    }
    let j = i; while (j < t.length && !/[,\]}]/.test(t[j])) j++;
    const s = t.slice(i, j); i = j; return scalar(s);
  };
  const key = () => {
    ws();
    if (t[i] === '"' || t[i] === "'") return value();
    let j = i; while (j < t.length && !/[:,}]/.test(t[j])) j++;
    const s = t.slice(i, j).trim(); i = j; return s;
  };
  return value();
}

function blockScalar(r, head, parentIndent) {
  const style = head[0], chomp = /[-+]/.exec(head)?.[0] || '';
  const body = [];
  let indent = null;
  while (r.i < r.lines.length) {
    const l = r.lines[r.i].raw;
    if (l.trim() === '') { body.push(''); r.i++; continue; }
    const ind = indentOf(l);
    if (ind <= parentIndent) break;
    if (indent === null) indent = ind;
    if (ind < indent) break;
    body.push(l.slice(indent)); r.i++;
  }
  let trailing = 0;
  while (body.length && body[body.length - 1] === '') { body.pop(); trailing++; }
  let text = style === '|' ? body.join('\n') : body.reduce((acc, l, k) => (k === 0 ? l : (l === '' || body[k - 1] === '' ? `${acc}\n${l}` : `${acc} ${l}`)), '');
  if (chomp === '+') text += '\n'.repeat(trailing + 1); else if (chomp !== '-' && body.length) text += '\n';
  return text;
}

function nextContent(r) {
  while (r.i < r.lines.length) {
    const t = stripComment(r.lines[r.i].raw);
    if (t.trim() === '' || /^\s*(?:---|\.\.\.)\s*$/.test(t) || /^%/.test(t)) { r.i++; continue; }
    return r.i;
  }
  return -1;
}

function valueAfter(r, rest, indent, depth) {
  rest = stripTagAnchor(stripComment(rest).trim());
  if (rest === '') {
    const k = nextContent(r);
    if (k < 0) return null;
    const ni = indentOf(r.lines[k].raw), nt = r.lines[k].raw.trim();
    if (ni > indent || (ni === indent && /^-(\s|$)/.test(nt))) return block(r, ni, depth + 1);
    return null;
  }
  if (/^[|>][-+0-9]*$/.test(rest)) return blockScalar(r, rest, indent);
  if (rest[0] === '[' || rest[0] === '{') {
    let t = rest;                                                   // a flow collection may continue on the next lines
    const open = rest[0], close = open === '[' ? ']' : '}';
    const count = s => [...s].filter(c => c === open).length - [...s].filter(c => c === close).length;
    while (count(t) > 0 && r.i < r.lines.length) t += ` ${stripComment(r.lines[r.i++].raw).trim()}`;
    return flow(t);
  }
  return scalar(rest);
}

function block(r, indent, depth = 0) {
  if (depth > 64) throw new Error('nesting too deep');
  const k = nextContent(r);
  if (k < 0) return null;
  const first = r.lines[k].raw;
  const text = first.trim();
  if (/^-(\s|$)/.test(text)) {
    const arr = [];
    for (;;) {
      const j = nextContent(r);
      if (j < 0) break;
      const raw = r.lines[j].raw, ind = indentOf(raw), t = raw.trim();
      if (ind !== indent || !/^-(\s|$)/.test(t)) break;
      const after = t.slice(1);
      const lead = after.length - after.trimStart().length;
      const rest = after.trimStart();
      r.i = j + 1;
      if (rest === '' || /^(?:!\S*|&\S+)\s*(?:#.*)?$/.test(rest)) { arr.push(valueAfter(r, '', indent, depth)); continue; }
      const body = stripTagAnchor(stripComment(rest));
      if (/^-(\s|$)/.test(body) || (/^(?:"[^"]*"|'[^']*'|[^\s"'{}[\],#&*!|>%@`-][^:]*?|[^\s]+):(\s|$)/.test(body) && body[0] !== '{' && body[0] !== '[')) {
        // `- key: v` / `- - x`: the item's content is a block that starts at the column after the dash
        r.lines[j] = { n: r.lines[j].n, raw: ' '.repeat(indent + 1 + lead) + rest };
        r.i = j;
        arr.push(block(r, indent + 1 + lead, depth + 1));
        continue;
      }
      arr.push(valueAfter(r, rest, indent, depth));
    }
    return arr;
  }
  const obj = {};
  for (;;) {
    const j = nextContent(r);
    if (j < 0) break;
    const raw = r.lines[j].raw, ind = indentOf(raw);
    if (ind !== indent) break;
    const t = raw.trim();
    if (/^-(\s|$)/.test(t)) break;
    const m = /^("(?:[^"\\]|\\.)*"|'(?:[^']|'')*'|[^:]+?)\s*:(?:\s+(.*)|\s*)$/.exec(stripComment(raw).trim());
    if (!m) { r.i = j + 1; continue; }                              // a line that is not `key: value` is skipped, never fatal
    r.i = j + 1;
    const key = unquote(m[1].trim());
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') { valueAfter(r, m[2] || '', indent, depth); continue; }
    obj[key] = valueAfter(r, m[2] || '', indent, depth);
  }
  return obj;
}

/** @returns {any} the parsed document, or null for an empty one. Never throws on malformed input beyond very deep nesting. */
export function parseYaml(text) {
  const r = new Reader(text);
  const k = nextContent(r);
  if (k < 0) return null;
  const first = stripTagAnchor(stripComment(r.lines[k].raw).trim().replace(/^---\s*/, ''));
  if (/^---/.test(r.lines[k].raw) && first) { r.lines[k] = { n: r.lines[k].n, raw: first }; }
  else if (/^---/.test(r.lines[k].raw)) r.i = k + 1;
  const j = nextContent(r);
  if (j < 0) return null;
  try { return block(r, indentOf(r.lines[j].raw)); } catch { return null; }
}
