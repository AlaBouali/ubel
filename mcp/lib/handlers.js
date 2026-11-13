'use strict';
// handlers.js — reads the MCP shape out of server source without running it: for every tool, resource and prompt the code registers, its
// name, its description (a Python docstring, a `description:` field, or the second argument of `server.tool(...)`), its parameters and its
// handler body; plus the helper functions of the same file, and a small taint set that says which identifiers carry the handler's arguments.
//
// This is a reader for text, not a parser for the languages: Python by indentation, JavaScript / TypeScript by balanced brackets with strings,
// template literals and comments skipped, Go by a window of lines. What it cannot read it skips; it never guesses.

const MCP_JS = /@modelcontextprotocol|fastmcp|mcp-framework|\bMcpServer\b|\bFastMCP\b/;
const IDENT = /[A-Za-z_$][\w$]*/g;

// ── shared scanners ──────────────────────────────────────────────────────────────────────────────────────────────────────────

/** Index of the bracket that closes the one at `open` (strings, template literals and comments skipped), or -1. Bounded. */
export function balancedClose(text, open, limit = 80000) {
  const pairs = { '(': ')', '[': ']', '{': '}' };
  const want = pairs[text[open]];
  if (!want) return -1;
  const stack = [want];
  const end = Math.min(text.length, open + limit);
  for (let i = open + 1; i < end; i++) {
    const c = text[i];
    if (c === '"' || c === "'" || c === '`') {
      for (i++; i < end && text[i] !== c; i++) if (text[i] === '\\') i++;
      continue;
    }
    if (c === '/' && text[i + 1] === '/') { while (i < end && text[i] !== '\n') i++; continue; }
    if (c === '/' && text[i + 1] === '*') { i = text.indexOf('*/', i + 2); if (i < 0) return -1; i++; continue; }
    if (pairs[c]) stack.push(pairs[c]);
    else if (c === stack[stack.length - 1]) { stack.pop(); if (!stack.length) return i; }
  }
  return -1;
}

const lineOf = (text, index) => { let n = 1; for (let i = text.indexOf('\n'); i >= 0 && i < index; i = text.indexOf('\n', i + 1)) n++; return n; };
const dedent = s => { const ls = s.replace(/\t/g, '    ').split('\n'); const ind = Math.min(...ls.filter((l, i) => i > 0 && l.trim()).map(l => l.match(/^ */)[0].length), Infinity); return ls.map((l, i) => (i === 0 ? l.trim() : l.slice(Number.isFinite(ind) ? ind : 0))).join('\n').trim(); };

/** Splits at top-level commas (brackets and strings respected). */
function splitTop(s) {
  const out = []; let depth = 0, cur = '', q = null;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) { cur += c; if (c === '\\') cur += s[++i] ?? ''; else if (c === q) q = null; continue; }
    if (c === '"' || c === "'" || c === '`') { q = c; cur += c; continue; }
    if ('([{'.includes(c)) depth++; else if (')]}'.includes(c)) depth--;
    if (c === ',' && depth === 0) { out.push(cur); cur = ''; } else cur += c;
  }
  if (cur.trim()) out.push(cur);
  return out;
}

const STR = String.raw`(?:"""([\s\S]*?)"""|'''([\s\S]*?)'''|"((?:\\.|[^"\\])*)"|'((?:\\.|[^'\\])*)')`;
const firstGroup = m => (m ? (m[1] ?? m[2] ?? m[3] ?? m[4] ?? '') : null);

// ── Python ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────

const indentOf = l => l.replace(/\t/g, '    ').match(/^ */)[0].length;

function pyParams(paramsText) {
  const out = [];
  for (const raw of splitTop(paramsText)) {
    const p = raw.trim();
    if (!p || p === '*' || p === '/' || p.startsWith('*')) continue;
    const m = p.match(/^(\w+)\s*(?::\s*([^=]+?))?\s*(?:=\s*([\s\S]+))?$/);
    if (!m) continue;
    const [, name, ann = ''] = m;
    if (name === 'self' || name === 'cls' || /\bContext\b/.test(ann)) continue;
    const type = /\b(?:int|float|number)\b/.test(ann) ? 'number' : /\bbool\b/.test(ann) ? 'boolean' : /\bstr\b/.test(ann) || !ann ? 'string' : undefined;
    out.push({ name, type });
  }
  return out;
}

function pyDocstring(body) {
  const m = body.match(new RegExp(String.raw`^\s*[rRuUbB]?${STR}`));
  return m ? dedent(firstGroup(m)) : '';
}
function docArgs(doc) {
  const out = {};
  const lines = doc.split('\n');
  let inArgs = false;
  for (const l of lines) {
    if (/^\s*(?:Args|Arguments|Parameters|Params)\s*:\s*$/.test(l)) { inArgs = true; continue; }
    if (inArgs && (/^\s*(?:Returns?|Raises?|Yields?|Examples?|Notes?)\s*:/.test(l))) inArgs = false;
    if (!inArgs) continue;
    const m = l.match(/^\s*(\w+)\s*(?:\([^)]*\))?\s*:\s*(.+)$/);
    if (m) out[m[1]] = m[2].trim();
  }
  return out;
}

function pyParse(text) {
  const lines = text.split('\n');
  const units = [], helpers = new Map();
  // decorators, with arguments that may span lines
  const decos = [];
  for (let i = 0; i < lines.length; i++) {
    if (!/^\s*@/.test(lines[i])) continue;
    let j = i, buf = lines[i], depth = 0;
    const count = s => { for (const c of s.replace(/(["'])(?:\\.|(?!\1).)*\1/g, '')) { if (c === '(') depth++; else if (c === ')') depth--; } };
    count(lines[i]);
    while (depth > 0 && j + 1 < lines.length && j - i < 40) { j++; buf += `\n${lines[j]}`; count(lines[j]); }
    decos.push({ start: i, end: j, text: buf.trim() });
    i = j;
  }
  const decoBy = new Map();                       // def line → decorators directly above it
  for (let k = 0; k < decos.length; k++) {
    let end = decos[k].end, chain = [decos[k]], n = k;
    while (decos[n + 1] && decos[n + 1].start === end + 1) { n++; chain.push(decos[n]); end = decos[n].end; }
    if (/^\s*(?:async\s+)?def\s/.test(lines[end + 1] || '')) decoBy.set(end + 1, chain);
    k = n;
  }
  for (let i = 0; i < lines.length; i++) {
    const m = lines[i].match(/^([ \t]*)(?:async\s+)?def\s+(\w+)\s*\(/);
    if (!m) continue;
    const defIndent = indentOf(m[1]);
    // signature: until the parentheses are balanced and the line ends with ':'
    let j = i, sig = lines[i];
    const bal = s => { let d = 0; for (const c of s.replace(/(["'])(?:\\.|(?!\1).)*\1/g, '')) { if (c === '(') d++; else if (c === ')') d--; } return d; };
    while ((bal(sig) > 0 || !/:\s*(?:#.*)?$/.test(sig)) && j + 1 < lines.length && j - i < 30) { j++; sig += `\n${lines[j]}`; }
    const open = sig.indexOf('(');
    let depth = 0, close = -1;
    for (let k = open; k < sig.length; k++) { if (sig[k] === '(') depth++; else if (sig[k] === ')') { depth--; if (!depth) { close = k; break; } } }
    const paramsText = close > open ? sig.slice(open + 1, close) : '';
    const bodyLines = [];
    let k = j + 1;
    for (; k < lines.length; k++) {
      if (lines[k].trim() === '' ) { bodyLines.push(lines[k]); continue; }
      if (indentOf(lines[k]) <= defIndent) break;
      bodyLines.push(lines[k]);
    }
    const body = bodyLines.join('\n');
    const params = pyParams(paramsText);
    const chain = decoBy.get(i);
    const deco = chain && chain.map(d => d.text.match(/^@\s*[\w.]+\.(tool|resource|prompt)\b\s*(?:\(([\s\S]*)\))?\s*$/)).find(Boolean);
    if (!deco) { helpers.set(m[2], { name: m[2], params: params.map(p => p.name), body, line: i + 1 }); continue; }
    const kind = deco[1], args = deco[2] || '';
    const doc = pyDocstring(body);
    const argDocs = docArgs(doc);
    const kwName = firstGroup(args.match(new RegExp(String.raw`\bname\s*=\s*${STR}`)));
    const kwDesc = firstGroup(args.match(new RegExp(String.raw`\bdescription\s*=\s*${STR}`)));
    const firstStr = firstGroup(args.match(new RegExp(String.raw`^\s*${STR}`)));
    units.push({
      kind, name: kind === 'resource' ? (kwName || m[2]) : (kwName || m[2]), uri: kind === 'resource' ? firstStr : undefined, line: i + 1,
      description: kwDesc ?? doc, params: params.map(p => ({ ...p, description: argDocs[p.name] })), body, bodyLine: j + 2,
      taintRoots: params.map(p => p.name), lang: 'py',
    });
  }
  const im = text.match(new RegExp(String.raw`FastMCP\s*\([\s\S]{0,600}?\binstructions\s*=\s*${STR}`));
  return { units, helpers, instructions: im ? firstGroup(im) : null };
}

// ── JavaScript / TypeScript ──────────────────────────────────────────────────────────────────────────────────────────────────

const JS_STR = String.raw`(['"` + '`' + String.raw`])((?:\\.|(?!\1)[^\\])*)\1`;           // groups 1, 2
const JS_STR2 = String.raw`(['"` + '`' + String.raw`])((?:\\.|(?!\3)[^\\])*)\3`;          // groups 3, 4 (a second string in the same pattern)
const jsStr = (re, s) => { const m = s.match(re); return m ? m[2] : null; };

function jsHandlerParams(callText) {
  // the handler is the last argument of the call, or the `execute` / `handler` / `callback` property of an options object
  const args = splitTop(callText.slice(1, -1));
  let fn = args[args.length - 1] || '';
  const prop = fn.match(/\b(?:execute|handler|callback)\s*:\s*([\s\S]*)$/);
  if (prop) fn = prop[1];
  let list = null;
  const arrow = fn.indexOf('=>');
  if (arrow >= 0) { const head = fn.slice(0, arrow).trim().replace(/^async\s*/, ''); list = head.startsWith('(') ? head.slice(1, head.lastIndexOf(')')) : head; }
  else { const m = fn.match(/function\s*[\w$]*\s*\(([^)]*)\)/); list = m ? m[1] : null; }
  if (!list) return { names: [], roots: [] };
  const first = splitTop(list)[0]?.trim() || '';
  if (first.startsWith('{')) {
    const names = splitTop(first.replace(/^\{|\}$/g, '')).map(x => (x.trim().match(/^(?:\.\.\.)?([\w$]+)(?:\s*:\s*([\w$]+))?/) || []).slice(1, 3).filter(Boolean)).flat();
    return { names, roots: names };
  }
  const id = first.match(/^[\w$]+/);
  return { names: [], roots: id ? [id[0]] : [] };
}

function jsParse(text) {
  const units = [], helpers = new Map();
  if (!MCP_JS.test(text)) return { units, helpers, instructions: null };
  const re = /\b[\w$.]+\s*\.\s*(tool|registerTool|addTool|resource|registerResource|prompt|registerPrompt)\s*\(/g;
  for (let m; (m = re.exec(text));) {
    const open = m.index + m[0].length - 1;
    const close = balancedClose(text, open);
    if (close < 0) continue;
    const call = text.slice(open, close + 1);
    const kind = /^(?:tool|registerTool|addTool)$/.test(m[1]) ? 'tool' : /^(?:resource|registerResource)$/.test(m[1]) ? 'resource' : 'prompt';
    const name = jsStr(new RegExp(String.raw`^\(\s*${JS_STR}`), call) ?? jsStr(new RegExp(String.raw`\bname\s*:\s*${JS_STR}`), call);
    if (!name) continue;
    let description = jsStr(new RegExp(String.raw`\bdescription\s*:\s*${JS_STR}`), call);
    if (description == null && kind !== 'resource') { const m2 = call.match(new RegExp(String.raw`^\(\s*${JS_STR}\s*,\s*${JS_STR2}\s*,`)); description = m2 ? m2[4] : ''; }   // server.tool("name", "description", schema, handler)
    if (description == null) description = '';
    // zod parameters: key: z.something(...).describe("…")
    const keys = [...call.matchAll(/(?:^|[{,\s])([\w$]+)\s*:\s*z\s*\./g)].filter(k => !/^(?:parameters|inputSchema|outputSchema|argsSchema|schema|input|properties)$/.test(k[1]));
    const params = keys.map((k, i) => {
      const seg = call.slice(k.index + k[0].length, keys[i + 1]?.index ?? Math.min(call.length, k.index + 600));
      const d = seg.match(new RegExp(String.raw`\.describe\(\s*${JS_STR}`));
      const t = /^\s*(?:number|int|bigint)/.test(seg) ? 'number' : /^\s*boolean/.test(seg) ? 'boolean' : /^\s*(?:string|enum|literal)/.test(seg) ? 'string' : undefined;
      return { name: k[1], type: t, description: d ? d[2] : undefined };
    });
    const hp = jsHandlerParams(call);
    let uri;
    if (kind === 'resource') { const m3 = call.match(new RegExp(String.raw`^\(\s*${JS_STR}\s*,\s*${JS_STR2}`)); uri = (m3 && m3[4]) || jsStr(new RegExp(String.raw`\buri(?:Template)?\s*:\s*${JS_STR}`), call) || undefined; }
    units.push({ kind, name, uri, line: lineOf(text, m.index), description, params, body: call, bodyLine: lineOf(text, open), taintRoots: [...new Set([...hp.roots, ...params.map(p => p.name)])], lang: 'js' });
  }
  const hre = /(?:async\s+)?function\s+([\w$]+)\s*\(([^)]*)\)\s*\{|(?:const|let|var)\s+([\w$]+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>\s*\{/g;
  for (let m; (m = hre.exec(text));) {
    const open = m.index + m[0].length - 1;
    const close = balancedClose(text, open);
    if (close < 0) continue;
    const name = m[1] || m[3];
    helpers.set(name, { name, params: splitTop(m[2] ?? m[4] ?? '').map(p => (p.trim().match(/^[\w$]+/) || [''])[0]).filter(Boolean), body: text.slice(open, close + 1), line: lineOf(text, m.index) });
  }
  const im = text.match(new RegExp(String.raw`\binstructions\s*:\s*${JS_STR}`));
  return { units, helpers, instructions: im ? im[2] : null };
}

// ── Go ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

function goParse(text) {
  const units = [];
  const re = /\b(?:mcp\.)?NewTool\s*\(\s*"([\w.-]+)"/g;
  for (let m; (m = re.exec(text));) {
    const win = text.slice(m.index, m.index + 6000);
    const d = win.match(/WithDescription\s*\(\s*"((?:\\.|[^"\\])*)"/);
    units.push({ kind: 'tool', name: m[1], line: lineOf(text, m.index), description: d ? d[1] : '', params: [], body: win, bodyLine: lineOf(text, m.index), taintRoots: [], lang: 'go' });
  }
  return { units, helpers: new Map(), instructions: null };
}

export function parseUnits(text, lang) {
  if (lang === 'py') return pyParse(text);
  if (lang === 'js') return jsParse(text);
  if (lang === 'go') return goParse(text);
  return { units: [], helpers: new Map(), instructions: null };
}

// ── taint ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

const WORD = new RegExp(IDENT.source, 'g');
export const identsIn = s => new Set(String(s).match(WORD) || []);

/** The identifiers that carry the handler's arguments: the parameters, plus every variable assigned from an expression that uses one (three passes). */
export function taintedIdents(roots, body, lang) {
  const t = new Set(roots);
  if (!t.size) return t;
  const lines = body.split('\n');
  for (let pass = 0; pass < 3; pass++) {
    for (const l of lines) {
      let m;
      if (lang === 'py') m = l.match(/^\s*(\w+)\s*(?:[-+*/|&]|\/\/)?=(?!=)\s*(.+)$/);
      else m = l.match(/(?:\b(?:const|let|var)\s+)?([\w$]+)\s*(?:[-+*/|&]|\|\|)?=(?![=>])\s*(.+)$/) || l.match(/\b(?:const|let|var)\s*\{([^}]*)\}\s*=\s*(.+)$/);
      if (!m) continue;
      const rhs = identsIn(m[2]);
      if (![...t].some(x => rhs.has(x))) continue;
      for (const n of m[1].split(',')) { const id = (n.trim().match(/^(?:\.\.\.)?([\w$]+)/) || [])[1]; if (id) t.add(id); }
    }
  }
  return t;
}
/** The statement around `index`: its line and the next two (a call often continues). */
export function segmentAt(body, index) {
  const start = body.lastIndexOf('\n', index) + 1;
  let end = index;
  for (let n = 0; n < 3 && end >= 0; n++) end = body.indexOf('\n', end + 1);
  return body.slice(start, end < 0 ? body.length : end);
}
export const usesAny = (segment, set) => { const ids = identsIn(segment); for (const x of set) if (ids.has(x)) return true; return false; };
