'use strict';
// toml.js — a small TOML reader for Cargo.toml / pyproject.toml (TOML 1.0 subset that real manifests use: tables, arrays of tables, dotted keys,
// inline tables, multi-line arrays, basic / literal / multi-line strings, integers, floats, booleans, datetimes as strings).
// Tolerant: a line it cannot read is skipped and counted in `errors`, because a hostile manifest must not stop the scan.

function parseString(s, i) {
  // s[i] is the opening quote; returns [value, nextIndex]
  const q = s[i];
  const triple = s.startsWith(q + q + q, i);
  if (triple) {
    const end = s.indexOf(q + q + q, i + 3);
    if (end < 0) return [s.slice(i + 3), s.length];
    let j = end; while (s[j + 3] === q) j++;                       // `""""` ends with an escaped quote
    let raw = s.slice(i + 3, j);
    if (raw.startsWith('\r\n')) raw = raw.slice(2); else if (raw.startsWith('\n')) raw = raw.slice(1);
    return [q === '"' ? unescape(raw, true) : raw, j + 3];
  }
  if (q === "'") { const end = s.indexOf("'", i + 1); return end < 0 ? [s.slice(i + 1), s.length] : [s.slice(i + 1, end), end + 1]; }
  let j = i + 1;
  while (j < s.length && s[j] !== '"') j += s[j] === '\\' ? 2 : 1;
  return [unescape(s.slice(i + 1, j), false), j + 1];
}

function unescape(raw, multi) {
  let out = raw;
  if (multi) out = out.replace(/\\[ \t]*\r?\n\s*/g, '');
  return out.replace(/\\(u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8}|.)/g, (m, c) => {
    if (c[0] === 'u' || c[0] === 'U') { try { return String.fromCodePoint(parseInt(c.slice(1), 16)); } catch { return m; } }
    return ({ n: '\n', t: '\t', r: '\r', b: '\b', f: '\f', '"': '"', '\\': '\\' })[c] ?? m;
  });
}

function skipWs(s, i, nl = false) {
  for (;;) {
    while (i < s.length && (s[i] === ' ' || s[i] === '\t' || (nl && (s[i] === '\n' || s[i] === '\r')))) i++;
    if (nl && s[i] === '#') { while (i < s.length && s[i] !== '\n') i++; continue; }
    return i;
  }
}

function parseKey(s, i) {
  const parts = [];
  for (;;) {
    i = skipWs(s, i);
    if (s[i] === '"' || s[i] === "'") { const [v, n] = parseString(s, i); parts.push(v); i = n; }
    else { const m = /^[A-Za-z0-9_-]+/.exec(s.slice(i, i + 256)); if (!m) return null; parts.push(m[0]); i += m[0].length; }
    i = skipWs(s, i);
    if (s[i] === '.') { i++; continue; }
    return [parts, i];
  }
}

function parseValue(s, i) {
  i = skipWs(s, i);
  const c = s[i];
  if (c === '"' || c === "'") return parseString(s, i);
  if (c === '[') {
    const arr = []; i++;
    for (;;) {
      i = skipWs(s, i, true);
      if (s[i] === ']') return [arr, i + 1];
      if (i >= s.length) throw new Error('unterminated array');
      const [v, n] = parseValue(s, i); arr.push(v); i = skipWs(s, n, true);
      if (s[i] === ',') i++;
    }
  }
  if (c === '{') {
    const obj = {}; i++;
    for (;;) {
      i = skipWs(s, i, true);
      if (s[i] === '}') return [obj, i + 1];
      const k = parseKey(s, i); if (!k) throw new Error('bad inline table');
      i = skipWs(s, k[1]); if (s[i] !== '=') throw new Error('bad inline table');
      const [v, n] = parseValue(s, i + 1);
      setPath(obj, k[0], v); i = skipWs(s, n, true);
      if (s[i] === ',') i++;
    }
  }
  const m = /^[^,\]}\n#]*/.exec(s.slice(i, i + 512));
  const tok = m[0].trim(); const n = i + m[0].length;
  if (tok === 'true') return [true, n];
  if (tok === 'false') return [false, n];
  if (/^[+-]?(?:inf|nan)$/.test(tok)) return [Number(tok.replace('inf', 'Infinity')), n];
  if (/^[+-]?\d[\d_]*$/.test(tok)) return [Number(tok.replace(/_/g, '')), n];
  if (/^0x[0-9a-f_]+$/i.test(tok)) return [parseInt(tok.replace(/_/g, ''), 16), n];
  if (/^[+-]?\d[\d_]*(?:\.\d[\d_]*)?(?:[eE][+-]?\d+)?$/.test(tok)) return [Number(tok.replace(/_/g, '')), n];
  return [tok, n];                                                // datetimes and anything unknown stay as text
}

function setPath(obj, path, value) {
  let o = obj;
  for (let k = 0; k < path.length - 1; k++) {
    const key = path[k];
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return;
    o = Array.isArray(o[key]) ? o[key][o[key].length - 1] : (o[key] ??= {});
    if (typeof o !== 'object' || o === null) return;
  }
  const last = path[path.length - 1];
  if (last === '__proto__' || last === 'constructor' || last === 'prototype') return;
  o[last] = value;
}

function tableAt(root, path, arrayLast = true) {
  let o = root;
  for (const key of path) {
    if (key === '__proto__' || key === 'constructor' || key === 'prototype') return {};
    if (Array.isArray(o[key])) o = o[key][o[key].length - 1];
    else o = (o[key] ??= {});
    if (typeof o !== 'object' || o === null) return {};
  }
  return o;
}

/** @returns {{data:object, errors:number}} */
export function parseToml(text) {
  const s = String(text).replace(/^﻿/, '');
  const root = {};
  let cur = root, errors = 0, i = 0;
  while (i < s.length) {
    i = skipWs(s, i, true);
    if (i >= s.length) break;
    try {
      if (s[i] === '[') {
        const arr = s[i + 1] === '[';
        const k = parseKey(s, i + (arr ? 2 : 1));
        if (!k) throw new Error('bad table header');
        let j = skipWs(s, k[1]);
        if (s[j] !== ']') throw new Error('bad table header');
        j += arr ? 2 : 1;
        if (arr) {
          const parent = tableAt(root, k[0].slice(0, -1));
          const last = k[0][k[0].length - 1];
          if (last !== '__proto__' && last !== 'constructor') { (parent[last] = Array.isArray(parent[last]) ? parent[last] : []).push(cur = {}); }
        } else cur = tableAt(root, k[0]);
        i = j;
      } else {
        const k = parseKey(s, i);
        if (!k) throw new Error('bad key');
        let j = skipWs(s, k[1]);
        if (s[j] !== '=') throw new Error('expected =');
        const [v, n] = parseValue(s, j + 1);
        setPath(cur, k[0], v);
        i = n;
      }
    } catch {
      errors++;
      while (i < s.length && s[i] !== '\n') i++;
    }
    while (i < s.length && s[i] !== '\n') { if (s[i] === '#') { while (i < s.length && s[i] !== '\n') i++; break; } if (s[i] !== ' ' && s[i] !== '\t' && s[i] !== '\r') { errors++; while (i < s.length && s[i] !== '\n') i++; break; } i++; }
  }
  return { data: root, errors };
}
