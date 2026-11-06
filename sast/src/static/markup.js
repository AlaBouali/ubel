'use strict';

// HTML-like and template files carry JavaScript in <script> blocks, inline event handlers and javascript: URLs, and
// server- or client-side template syntax ({{ }}, <% %>, {!! !!}, th:utext, v-html …).
//
// The static engine analyses code per chunk, so a markup file is expanded into
//   1. one 'markup' chunk   (family 'html': the template-engine rules read the raw text),
//   2. one JavaScript chunk per inline <script> (family 'js'),
//   3. one JavaScript chunk holding every inline event handler / javascript: URL (family 'js').
// Every synthetic chunk keeps the file's own line numbers (startLine + code that preserves the original line breaks), so findings
// point at the real line of the .html / .ejs / .vue … file.

import path from 'path';

// Never meaningful as code in any other family: replaced by the expansion.
export const MARKUP_ONLY_EXT = new Set([
  '.html', '.htm', '.xhtml', '.shtml', '.vue', '.svelte', '.astro',
  '.ejs', '.hbs', '.handlebars', '.mustache', '.njk', '.nunjucks', '.twig', '.jinja', '.jinja2', '.j2', '.liquid',
  '.tpl', '.tmpl', '.gohtml', '.ftl', '.latte', '.volt', '.pug', '.jade', '.dust',
]);
// Often already mapped to a code family (Ruby / Java / C# / PHP): that chunk is kept and the markup scan is added to it.
export const MARKUP_CODE_EXT = new Set(['.erb', '.jsp', '.jspx', '.cshtml', '.razor', '.phtml', '.vm']);

export const extOf = (file) => path.extname(file || '').toLowerCase();
export const isMarkupFile = (file) => { const e = extOf(file); return MARKUP_ONLY_EXT.has(e) || MARKUP_CODE_EXT.has(e); };

// ── text helpers ─────────────────────────────────────────────────────────────
export function lineStarts(text) {
  const starts = [0];
  for (let i = 0; i < text.length; i++) if (text[i] === '\n') starts.push(i + 1);
  return starts;
}
export function lineOfOffset(starts, off) {
  let lo = 0, hi = starts.length - 1;
  while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= off) lo = mid; else hi = mid - 1; }
  return lo + 1;                                  // 1-based, relative to the text
}
const blank = (s) => s.replace(/[^\n]/g, ' ');

// Server / client template tags are not JavaScript: swap them for something the JS lexer accepts, keeping every newline.
//   value tags     {{ x }}  {{{ x }}}  <%= x %>  <%- x %>  <?= x ?>  {!! x !!}   ->  `0` + spaces
//   statement tags {% … %}  {# … #}  <% … %>  <?php … ?>                          ->  spaces
const TAG_RE = /\{\{\{[\s\S]*?\}\}\}|\{\{[\s\S]{0,400}?\}\}|\{%[\s\S]*?%\}|\{#[\s\S]*?#\}|<%[\s\S]*?%>|\{!![\s\S]*?!!\}|<\?(?:php|=)?[\s\S]*?\?>/g;
export function neutralizeTags(code) {
  return code.replace(TAG_RE, (t) => {
    const isValue = /^(?:\{\{|\{!!|<%[=-]|<\?=|<\?php\s+(?:echo|print)\b)/.test(t) && !/^\{\{[#\/^>!]/.test(t);
    return isValue ? '0' + blank(t.slice(1)) : blank(t);
  });
}

const ENTITIES = { '&quot;': '"', '&#34;': '"', '&#x22;': '"', '&apos;': "'", '&#39;': "'", '&#x27;': "'", '&lt;': '<', '&gt;': '>', '&amp;': '&', '&#10;': '\n', '&#13;': '\r', '&#9;': '\t', '&nbsp;': ' ' };
const decodeEntities = (s) => s.replace(/&(?:quot|apos|lt|gt|amp|nbsp|#34|#39|#10|#13|#9|#x22|#x27);/gi, (e) => ENTITIES[e.toLowerCase()] ?? e);

// ── <script> blocks ──────────────────────────────────────────────────────────
//   kind: 'js' | 'template' (text/template, text/x-handlebars-template, text/html …) | 'data' (json, importmap) | 'external' (src=)
const BLOCK_RE = /<!--[\s\S]*?-->|<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi;
const JS_TYPE = /^(?:|text\/javascript|application\/javascript|application\/x-javascript|text\/ecmascript|application\/ecmascript|module|text\/babel|text\/jsx|jsx|babel|text\/typescript|ts|tsx)$/i;
const DATA_TYPE = /json|importmap|speculationrules/i;
export function scriptBlocks(text) {
  const out = [];
  let m; BLOCK_RE.lastIndex = 0;
  while ((m = BLOCK_RE.exec(text)) !== null) {
    if (m[0].startsWith('<!--')) continue;
    const attrs = m[1] || '', body = m[2] || '';
    const tm = /\btype\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/i.exec(attrs);
    const type = (tm ? (tm[1] ?? tm[2] ?? tm[3]) : '').trim();
    const lang = (/\blang\s*=\s*["']?([\w-]+)/i.exec(attrs) || [])[1] || '';
    const start = m.index + 7 + attrs.length + 1;            // first char after `<script …>`
    let kind;
    if (/\bsrc\s*=/i.test(attrs) && body.trim() === '') kind = 'external';
    else if (DATA_TYPE.test(type)) kind = 'data';
    else if (JS_TYPE.test(type) && !/^(?:html|pug|jade)$/i.test(lang)) kind = 'js';
    else kind = 'template';
    out.push({ kind, type, attrs, start, end: start + body.length, body, tagStart: m.index });
  }
  return out;
}

// ── inline event handlers and javascript: URLs ───────────────────────────────
const HANDLER_RE = /\son([a-z]{3,25})\s*=\s*(?:"([^"]*)"|'([^']*)')/gi;
const JSURL_RE = /\b(?:href|src|action|formaction|data|xlink:href|poster|background)\s*=\s*(?:"\s*javascript:([^"]*)"|'\s*javascript:([^']*)')/gi;
export function inlineHandlers(text, blocks) {
  // blank the script bodies and comments so attribute-looking text inside them is not picked up
  let t = text.replace(/<!--[\s\S]*?-->/g, blank);
  for (const b of blocks) t = t.slice(0, b.start) + blank(t.slice(b.start, b.end)) + t.slice(b.end);
  const out = [];
  let m;
  HANDLER_RE.lastIndex = 0;
  while ((m = HANDLER_RE.exec(t)) !== null) out.push({ off: m.index + m[0].indexOf(m[2] ?? m[3] ?? ''), name: 'on' + m[1], code: m[2] ?? m[3] ?? '' });
  JSURL_RE.lastIndex = 0;
  while ((m = JSURL_RE.exec(t)) !== null) out.push({ off: m.index, name: 'javascript:', code: m[1] ?? m[2] ?? '' });
  return out.sort((a, b) => a.off - b.off);
}

// ── expansion ────────────────────────────────────────────────────────────────
const CACHE = new Map();
export const clearMarkupCache = () => CACHE.clear();      // the engine calls it per run so scanned pages are not kept in memory

export function expandMarkupChunk(chunk, { keepId = true } = {}) {
  const key = `${chunk.id}|${chunk.file}|${chunk.startLine}|${keepId}`;
  if (CACHE.has(key)) return CACHE.get(key);
  const text = chunk.code || '';
  const base = chunk.startLine || 1;
  const starts = lineStarts(text);
  const out = [];

  out.push({ ...chunk, id: keepId ? chunk.id : `${chunk.id}#markup`, type: 'markup', family: 'html', language: 'html', origin: 'markup', parent: keepId ? undefined : chunk.id });

  const blocks = scriptBlocks(text);
  for (const b of blocks) {
    if (b.kind !== 'js' || b.body.trim() === '') continue;
    const rel = lineOfOffset(starts, b.start);
    const startLine = base + rel - 1;
    const code = neutralizeTags(b.body);
    out.push({
      ...chunk, id: `${chunk.id}#script@${startLine}`, type: 'script', name: `script@${startLine}`, class: undefined,
      code, startLine, endLine: startLine + (code.match(/\n/g) || []).length,
      language: 'javascript', family: 'js', webContext: true, origin: 'markup', parent: chunk.id,
    });
  }

  const hs = inlineHandlers(text, blocks);
  if (hs.length) {
    let code = '', cur = 1;
    for (const h of hs) {
      const rel = lineOfOffset(starts, h.off);
      if (rel > cur) { code += '\n'.repeat(rel - cur); cur = rel; }
      const js = neutralizeTags(decodeEntities(h.code));
      code += js + ';';
      cur += (js.match(/\n/g) || []).length;
    }
    out.push({
      ...chunk, id: `${chunk.id}#handlers`, type: 'script', name: 'inline-event-handlers', class: undefined,
      code, startLine: base, endLine: base + (code.match(/\n/g) || []).length,
      language: 'javascript', family: 'js', webContext: true, origin: 'markup', parent: chunk.id,
    });
  }
  CACHE.set(key, out);
  return out;
}
