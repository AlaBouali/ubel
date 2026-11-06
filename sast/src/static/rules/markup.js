'use strict';

// Template-engine vulnerabilities in HTML and template files (family 'html'; see markup.js for how files are expanded), and
// template-engine misconfiguration in code. The JavaScript inside <script> blocks and inline handlers is scanned by the normal
// JavaScript rules; this file covers what only the markup shows:
//
//   unescaped output                {{{ x }}}  {{& x}}  {{ x|safe }}  {{ x|raw }}  <%- x %>  {!! x !!}  <%== x %>  @Html.Raw(x)  th:utext …
//   server values inside <script>   var id = {{ id }};   var n = '{{ name }}';   var d = <%- JSON.stringify(x) %>
//   server values in on*= handlers  onclick="go('{{ name }}')"      (HTML-escaping is undone before the JS runs)
//   javascript: / scheme-less URLs  <a href="{{ url }}">
//   raw-HTML directives             v-html  {@html}  set:html  x-html  ng-bind-html  data-bind="html:"  <c:out escapeXml="false">
//   client-side template injection  AngularJS ng-app / in-DOM Vue around server-rendered values
//   engine misconfiguration         autoescape off, noEscape, Jinja2 Environment() without autoescape

import { custom, pattern } from './helpers.js';
import { lineStarts, lineOfOffset, scriptBlocks, extOf } from '../markup.js';

const MK = {
  cls: 'XSS / template injection', group: 'html', sev: 'high',
  fix: 'Keep auto-escaping on and print values with the engine\'s escaping tag ({{ x }}, <%= x %> in EJS, {{ x }} in Blade). Put server values into JavaScript with a JSON encoder ({{ x|tojson }}, <%- JSON.stringify(x) %>, wp_json_encode) or in a data-* attribute, never by string concatenation; sanitise rich HTML with an allow-list sanitiser (DOMPurify, bleach, Loofah) before marking it safe.',
};
const html = (d) => custom({ ...MK, langs: ['html'], conf: 'medium', ...d });

// ── analysis shared by the rules (cached per chunk) ─────────────────────────────
const TAG = new RegExp([
  String.raw`(?<cmt><!--[\s\S]*?-->)`,
  String.raw`(?<tri>\{\{\{(?<trib>[\s\S]{0,600}?)\}\}\})`,
  String.raw`(?<blk>\{\{[#\/^>!~][\s\S]{0,600}?\}\})`,
  String.raw`(?<amp>\{\{&(?<ampb>[\s\S]{0,600}?)\}\})`,
  String.raw`(?<out>\{\{-?(?<outb>[\s\S]{0,600}?)-?\}\})`,
  String.raw`(?<stmt>\{%-?(?<stmtb>[\s\S]*?)-?%\})`,
  String.raw`(?<tcmt>\{#[\s\S]*?#\})`,
  String.raw`(?<pct><%(?<pk>==|=|-|#)?(?<pb>[\s\S]*?)-?%>)`,
  String.raw`(?<blade>\{!!(?<bladeb>[\s\S]*?)!!\})`,
  String.raw`(?<phpe><\?=(?<phpeb>[\s\S]*?)\?>)`,
  String.raw`(?<phpecho><\?php\s+(?:echo|print)\b(?<phpechob>[\s\S]*?)\?>)`,
  String.raw`(?<razor>@Html\.Raw\s*\()`,
].join('|'), 'g');

const RAW_FILTER = /\|\s*(?:safe|raw|noescape|unescape|safeHTML|safeHTMLAttr|safeJS|safeCSS|safeURL|html_safe|htmlSafe)\b|\b(?:mark_safe|Markup|raw|safe_join|html_safe)\s*\(|\.html_safe\b/i;
const HTML_SAFE = /\|\s*(?:escape|force_escape|e|h|striptags|sanitize|purify|bleach|clean|strip_tags|urlencode|tojson|escapejs|json_script|int|float|length|count|abs|round)\b|\b(?:esc_html|esc_attr|esc_url|esc_js|htmlspecialchars|htmlentities|escapeHtml|sanitize|DOMPurify|absint|intval|e|h)\s*\(/i;
const JS_SAFE = /\|\s*(?:tojson|escapejs|json_script|json_encode|json|to_json|jsonify|js|e\s*\(\s*['"]js['"]\s*\)|escape\s*\(\s*['"]js['"]\s*\))\b|\b(?:JSON\.stringify|json_encode|wp_json_encode|esc_js|escapeJs|js_escape|encodeURIComponent|Json\.Serialize|Json\.Encode|to_json|tojson|escape_javascript|j|raw_json)\s*\(/i;
const LITERAL = /^\s*(?:'[^']*'|"[^"]*"|-?\d+(?:\.\d+)?|true|false|null|none)\s*(?:\|[^|]*)*$/i;
const URL_HELPER = /\b(?:url_for|route|static|asset|path|reverse|url|admin_url|home_url|site_url|esc_url|get_permalink|base_url|Url\.Action|Url\.Content)\s*\(|\|\s*url\b|\{%\s*url\b|\{%\s*static\b|\bth:href\b/i;

function analyze(flow) {
  if (flow._mk) return flow._mk;
  const text = flow.chunk.code;
  const starts = lineStarts(text);
  const ext = extOf(flow.chunk.file);
  const blocks = scriptBlocks(text);
  const lodash = /_\.template|lodash|underscore|\.template\s*\(/.test(text) || blocks.some((b) => b.kind === 'template');
  const ejs = ext === '.ejs' || /\bejs\b/.test(text);
  const tags = [];
  let m; TAG.lastIndex = 0;
  while ((m = TAG.exec(text)) !== null) {
    const g = m.groups;
    if (g.cmt || g.blk || g.tcmt || (g.pct && g.pk === '#')) continue;
    let kind, body;
    if (g.tri) { kind = 'tri'; body = g.trib; }
    else if (g.amp) { kind = 'amp'; body = g.ampb; }
    else if (g.out) { kind = 'out'; body = g.outb; }
    else if (g.stmt) { kind = 'stmt'; body = g.stmtb; }
    else if (g.pct) { kind = g.pk === '==' ? 'pctraw' : g.pk === '-' ? 'pctdash' : g.pk === '=' ? 'pcteq' : 'pctstmt'; body = g.pb; }
    else if (g.blade) { kind = 'blade'; body = g.bladeb; }
    else if (g.phpe) { kind = 'phpe'; body = g.phpeb; }
    else if (g.phpecho) { kind = 'phpe'; body = g.phpechob; }
    else if (g.razor) { kind = 'razor'; body = argOf(text, m.index + m[0].length - 1); }
    else continue;
    const off = m.index;
    tags.push({ kind, body: (body || '').trim(), off, end: off + m[0].length, line: lineOfOffset(starts, off) });
  }
  // context of each tag: inside a JavaScript <script>, inside a client-template <script>, an attribute, or plain markup
  for (const t of tags) {
    const blk = blocks.find((b) => t.off >= b.start && t.off < b.end);
    t.script = blk && blk.kind === 'js' ? blk : null;
    t.tmpl = blk && blk.kind === 'template' ? blk : null;
    t.attr = t.script || t.tmpl ? null : attrContext(text, t.off);
  }
  return (flow._mk = { text, starts, ext, blocks, tags, lodash, ejs, line: (off) => lineOfOffset(starts, off), raw: text.split('\n') });
}

// text of the (...) argument list whose '(' is at `open`
function argOf(text, open) {
  let d = 0;
  for (let k = open; k < text.length; k++) { if (text[k] === '(') d++; else if (text[k] === ')') { d--; if (d === 0) return text.slice(open + 1, k); } }
  return text.slice(open + 1, open + 200);
}

// attribute (and its value so far) the offset sits in, or null when it is plain markup
function attrContext(text, off) {
  const lt = text.lastIndexOf('<', off), gt = text.lastIndexOf('>', off);
  if (lt < 0 || lt < gt) return null;
  const seg = text.slice(lt, off);
  let mm = /([^\s=<>"'\/]+)\s*=\s*("[^"]*|'[^']*)$/.exec(seg);
  if (mm) return { name: mm[1].toLowerCase(), quote: mm[2][0], before: mm[2].slice(1) };
  mm = /([^\s=<>"'\/]+)\s*=\s*([^\s"'>]*)$/.exec(seg);
  return mm ? { name: mm[1].toLowerCase(), quote: '', before: mm[2] } : null;
}

// quote character the end of `src` is inside (JavaScript string state), or null
function jsStringAt(src) {
  let q = null;
  for (let i = 0; i < src.length; i++) {
    const c = src[i];
    if (q) { if (c === '\\') i++; else if (c === q) q = null; }
    else if (c === '"' || c === "'" || c === '`') q = c;
    else if (c === '/' && src[i + 1] === '/') { const nl = src.indexOf('\n', i); if (nl < 0) return null; i = nl; }
    else if (c === '/' && src[i + 1] === '*') { const e = src.indexOf('*/', i + 2); if (e < 0) return null; i = e + 1; }
  }
  return q;
}

function emitAt(flow, emit, an, line, extra) {
  const raw = (an.raw[line - 1] || '').trim();
  emit(0, { relLine: line, snippet: raw.slice(0, 300), lineNeedle: raw, ...extra });
}
const isVar = (body) => /[A-Za-z_$]/.test(body.replace(/'[^']*'|"[^"]*"/g, '')) && !LITERAL.test(body);

// ── 1. unescaped output ────────────────────────────────────────────────────────
function rawKind(an, t) {
  const b = t.body, ext = an.ext;
  switch (t.kind) {
    case 'tri': return '{{{ }}} (Handlebars / Mustache unescaped)';
    case 'amp': return '{{& }} (Mustache unescaped)';
    case 'blade': return '{!! !!} (Blade unescaped)';
    case 'pctraw': return '<%== %> (unescaped)';
    case 'razor': return '@Html.Raw()';
    case 'out': return RAW_FILTER.test(b) ? '|safe / |raw (auto-escaping switched off for this value)' : null;
    case 'pctdash': return an.lodash && !an.ejs && ext !== '.ejs' ? null : '<%- %> (EJS unescaped)';
    case 'pcteq':
      if (ext === '.jsp' || ext === '.jspx') return /\brequest\s*\.\s*(?:getParameter|getHeader|getQueryString|getRequestURI|getRequestURL|getCookies|getAttribute)\b|\bparam\b/.test(b) ? 'JSP expression <%= %> printing request data' : null;
      if (ext === '.erb') return /\braw\b|\.html_safe\b/.test(b) ? '<%= raw / html_safe %>' : null;
      return an.lodash && !an.ejs ? '<%= %> (Underscore / lodash templates do not escape this tag)' : null;
    case 'phpe': return HTML_SAFE.test(b) ? null : '<?= ?> (PHP prints without escaping)';
    default: return null;
  }
}
const unescapedOutput = html({
  id: 'tpl-unescaped-output',
  run(flow, emit) {
    const an = analyze(flow);
    for (const t of an.tags) {
      if (t.script || t.attr?.name?.startsWith('on') || !isVar(t.body)) continue;     // script / handler contexts have their own rules
      if (HTML_SAFE.test(t.body) && t.kind !== 'tri') continue;
      const how = rawKind(an, t); if (!how) continue;
      emitAt(flow, emit, an, t.line, {
        title: 'Unescaped template output', sev: 'high', conf: 'medium',
        desc: `The template prints \`${t.body.replace(/\s+/g, ' ').slice(0, 80)}\` with ${how}, so the engine does not HTML-encode it. If any part of this value comes from a request, a database row or another user, it is injected into the page as markup (stored / reflected XSS).`,
      });
    }
    // JSP / EL: ${param.x} in template text is not escaped (only <c:out> is)
    if (an.ext === '.jsp' || an.ext === '.jspx') {
      const re = /\$\{\s*([^}]*\b(?:param|paramValues|header|headerValues|cookie|pageContext\.request\.(?:queryString|requestURI|requestURL))\b[^}]*)\}/g; let m;
      while ((m = re.exec(an.text)) !== null) {
        const before = an.text.slice(Math.max(0, m.index - 120), m.index);
        if (/<c:out\b[^>]*value\s*=\s*["']$|fn:escapeXml\s*\(\s*$|<fmt:[^>]*value\s*=\s*["']$/.test(before) || /fn:escapeXml/.test(m[1])) continue;
        emitAt(flow, emit, an, an.line(m.index), {
          title: 'Request data printed by JSP EL without escaping', sev: 'high', conf: 'medium',
          desc: `The expression \`${m[0].slice(0, 80)}\` prints request data into the page. EL in template text is not HTML-escaped (only <c:out> / fn:escapeXml are).`,
          fix: 'Wrap it in <c:out value="${...}"/> or fn:escapeXml(), or print it through a tag library that escapes.',
        });
      }
    }
  },
});

// ── 2. server values inside <script> ─────────────────────────────────────────────
const scriptContext = html({
  id: 'tpl-script-context',
  run(flow, emit) {
    const an = analyze(flow);
    if (['.vue', '.svelte', '.astro'].includes(an.ext)) return;
    for (const t of an.tags) {
      if (!t.script || t.kind === 'stmt' || t.kind === 'pctstmt' || !isVar(t.body) || JS_SAFE.test(t.body)) continue;
      if (t.kind === 'phpe' && HTML_SAFE.test(t.body) && /esc_js|json_encode/.test(t.body)) continue;
      const q = jsStringAt(an.text.slice(t.script.start, t.off));          // from the start of the block: template literals span lines
      const rawTag = ['tri', 'amp', 'blade', 'pctraw', 'razor'].includes(t.kind) || RAW_FILTER.test(t.body) || t.kind === 'pctdash' && !an.lodash;
      // `{{ }}` inside a string that holds an HTML fragment is a client-side template (Vue / Angular / Handlebars template string)
      if (t.kind === 'out' && q) {
        // the neighbouring lines of THIS script body (not the <script> tags themselves)
        const a = Math.max(t.script.start, an.starts[Math.max(0, t.line - 3)]), b = Math.min(t.script.end, an.starts[t.line + 1] ?? an.text.length);
        if (/<\/?[A-Za-z][^>]*>/.test(an.text.slice(a, b))) continue;
      }
      let sev, conf, why;
      if (rawTag) { sev = 'high'; conf = 'medium'; why = 'is printed unescaped'; }
      else if (!q) { sev = 'high'; conf = 'medium'; why = 'is HTML-escaped, which does not make it safe outside a JavaScript string (`1;alert(1)//` passes through)'; }
      else { sev = 'medium'; conf = 'low'; why = 'is HTML-escaped, which is not JavaScript escaping (a trailing backslash or a line break still changes the script)'; }
      emitAt(flow, emit, an, t.line, {
        title: 'Template value interpolated into inline JavaScript', sev, conf,
        desc: `The template value \`${t.body.replace(/\s+/g, ' ').slice(0, 80)}\` ${why} inside a <script> block${q ? ' (inside a ' + (q === '`' ? 'template literal' : 'quoted string') + ')' : ''}. Whoever controls that value controls the script.`,
        fix: 'Serialise it with a JSON encoder ({{ x|tojson }}, <%- JSON.stringify(x) %>, wp_json_encode, json_script) or hand it over in a data-* attribute and read it from JavaScript.',
      });
    }
  },
});

// ── 3. server values inside on*= handlers / javascript: URLs ─────────────────────
const handlerContext = html({
  id: 'tpl-handler-context',
  run(flow, emit) {
    const an = analyze(flow);
    for (const t of an.tags) {
      if (!t.attr || t.kind === 'stmt' || t.kind === 'pctstmt' || !isVar(t.body) || JS_SAFE.test(t.body)) continue;
      const isHandler = t.attr.name.startsWith('on'), isJsUrl = /^\s*javascript:/i.test(t.attr.before);
      if (!isHandler && !isJsUrl) continue;
      emitAt(flow, emit, an, t.line, {
        title: 'Template value interpolated into an event handler', sev: 'high', conf: 'medium',
        desc: `The template value \`${t.body.replace(/\s+/g, ' ').slice(0, 80)}\` is placed inside ${isHandler ? 'the ' + t.attr.name + ' handler' : 'a javascript: URL'}. The browser HTML-decodes an attribute before running it as JavaScript, so HTML escaping (&#39; → ') does not stop the value from closing the string and adding code.`,
        fix: 'Pass the value through a data-* attribute (data-id="{{ id }}") and read it with element.dataset in an addEventListener handler, or JSON-encode it and JS-escape the attribute.',
      });
    }
  },
});

// ── 4. scheme-controlled URL attributes ──────────────────────────────────────────
const urlAttr = html({
  id: 'tpl-url-attr', sev: 'medium', conf: 'low',
  run(flow, emit) {
    const an = analyze(flow);
    for (const t of an.tags) {
      if (!t.attr || t.script || t.tmpl || !['out', 'tri', 'pcteq', 'pctdash', 'blade', 'phpe'].includes(t.kind) || !isVar(t.body)) continue;
      if (!/^(?:href|src|action|formaction|xlink:href|data|poster)$/.test(t.attr.name)) continue;
      if (t.attr.before.trim() !== '' || URL_HELPER.test(t.body)) continue;     // a fixed prefix pins the scheme
      emitAt(flow, emit, an, t.line, {
        title: 'Template value used as a whole URL', sev: 'medium', conf: 'low',
        desc: `\`${t.body.replace(/\s+/g, ' ').slice(0, 80)}\` supplies the whole ${t.attr.name}= URL. HTML escaping does not remove a javascript: or data: scheme, so an attacker-chosen value runs script when the link is followed.`,
        fix: 'Validate the scheme on the server (allow only http, https, mailto, relative paths) or build the URL from a fixed prefix.',
      });
    }
  },
});

// ── 5. raw-HTML directives and escaping switched off ─────────────────────────────
const DIRECTIVES = [
  { re: /\bv-html\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, name: 'v-html (Vue)', conf: 'low', sev: 'medium' },
  { re: /\{@html\s+([^}]+)\}/gi, name: '{@html} (Svelte)', conf: 'low', sev: 'medium' },
  { re: /\bset:html\s*=\s*\{([^}]+)\}/gi, name: 'set:html (Astro)', conf: 'low', sev: 'medium' },
  { re: /\bx-html\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, name: 'x-html (Alpine.js)', conf: 'low', sev: 'medium' },
  { re: /\b(?:data-)?ng-bind-html\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, name: 'ng-bind-html (AngularJS)', conf: 'low', sev: 'medium' },
  { re: /\bdata-bind\s*=\s*(?:"[^"]*\bhtml\s*:\s*([^,"]*)[^"]*"|'[^']*\bhtml\s*:\s*([^,']*)[^']*')/gi, name: 'data-bind="html:" (Knockout)', conf: 'low', sev: 'medium' },
  { re: /\bth:utext\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, name: 'th:utext (Thymeleaf unescaped text)', conf: 'medium', sev: 'high' },
  { re: /\[\(\s*(\$\{[^}]*\})\s*\)\]/g, name: '[(${…})] (Thymeleaf unescaped inline)', conf: 'medium', sev: 'high' },
  { re: /<c:out\b[^>]*value\s*=\s*(?:"([^"]*)"|'([^']*)')[^>]*escapeXml\s*=\s*["']false["']|<c:out\b[^>]*escapeXml\s*=\s*["']false["'][^>]*value\s*=\s*(?:"([^"]*)"|'([^']*)')/gi, name: '<c:out escapeXml="false"> (JSTL)', conf: 'medium', sev: 'high' },
  { re: /<#noescape>|<#noautoesc>/gi, name: '<#noescape> (FreeMarker)', conf: 'medium', sev: 'high', noExpr: true },
  { re: /\$\{[^}]*\?no_esc\s*\}/gi, name: '?no_esc (FreeMarker)', conf: 'medium', sev: 'high', noExpr: true },
  { re: /\{%-?\s*autoescape\s+(?:false|off|'false')\s*-?%\}/gi, name: '{% autoescape off %}', conf: 'medium', sev: 'high', noExpr: true },
  { re: /\{[^{}]*\bnofilter\b[^{}]*\}|\{\$[^}|]*\|\s*noescape\s*\}/gi, name: 'nofilter / |noescape (Smarty / Latte)', conf: 'medium', sev: 'high', noExpr: true },
  { re: /(?:^|\s)!=\s+\S|!\{[^}]+\}/g, name: '!= / !{} (Pug unescaped)', conf: 'medium', sev: 'high', noExpr: true, exts: ['.pug', '.jade'] },
];
const directives = html({
  id: 'tpl-raw-directive',
  run(flow, emit) {
    const an = analyze(flow);
    for (const d of DIRECTIVES) {
      if (d.exts && !d.exts.includes(an.ext)) continue;
      d.re.lastIndex = 0;
      let m;
      while ((m = d.re.exec(an.text)) !== null) {
        if (m[0] === '') { d.re.lastIndex++; continue; }
        const expr = (m.slice(1).find((g) => g !== undefined) || '').trim();
        if (!d.noExpr && (!expr || LITERAL.test(expr) || /^\s*['"`][\s\S]*['"`]\s*$/.test(expr))) continue;      // a constant string is not attacker data
        if (!d.noExpr && /\b(?:DOMPurify|sanitize|sanitizeHtml|purify|\$sce\.trustAsHtml|escapeHtml)\b/i.test(expr)) continue;
        emitAt(flow, emit, an, an.line(m.index), {
          title: `Raw HTML output: ${d.name}`, sev: d.sev, conf: d.conf,
          desc: `${d.name} writes ${expr ? '`' + expr.replace(/\s+/g, ' ').slice(0, 80) + '`' : 'its content'} into the page as HTML, bypassing the engine's escaping. Anything attacker-influenced that reaches it executes as script.`,
        });
      }
    }
  },
});

// ── 6. client-side template injection: server-rendered values inside an AngularJS / Vue template ────
const SERVER_TEMPLATE = /\{%[\s\S]*?%\}|<%[=-]?|<\?(?:php|=)|\{!!|@Html\.|\{\{\s*(?:request|url_for|csrf_token|csrf|user|session|config|form|_\(|gettext)\b|\{\{[^}\n]*\|\s*(?:safe|escape|e|default|length|join|upper|lower|title|date|truncate|striptags|tojson)\b|\{\{\{|\bth:\w+\s*=|<%@\s*page/i;
const csti = html({
  id: 'tpl-csti',
  run(flow, emit) {
    const an = analyze(flow);
    if (!SERVER_TEMPLATE.test(an.text)) return;       // no server-side templating: the {{ }} are client bindings only
    const ng = /\b(?:data-|x-)?ng-app\b/i.exec(an.text);
    if (ng && !/\bng-non-bindable\b/.test(an.text.slice(Math.max(0, ng.index - 5), ng.index + 400))) {
      emitAt(flow, emit, an, an.line(ng.index), {
        title: 'AngularJS template rendered together with server-side templating', sev: 'high', conf: 'low',
        desc: 'This page is an AngularJS application (ng-app) AND is produced by a server-side template engine. Any server-rendered value that reaches the page is evaluated by AngularJS as an expression, and HTML escaping does not touch `{{ }}` — a value such as {{constructor.constructor(\'alert(1)\')()}} runs script (client-side template injection).',
        fix: 'Do not render untrusted values inside an ng-app element: wrap them in ng-non-bindable, emit them through {% raw %} / a JSON data attribute, or move the application to a page that is a static file.',
      });
    }
    const vue = /\bnew\s+Vue\s*\(\s*\{[^}]*\bel\s*:|\bcreateApp\s*\([^)]*\)\s*\.mount\s*\(\s*['"]#/.exec(an.text) || /\bVue\.createApp\s*\([\s\S]{0,300}?\.mount\s*\(\s*['"]#/.exec(an.text);
    if (vue) {
      emitAt(flow, emit, an, an.line(vue.index), {
        title: 'In-DOM Vue template rendered together with server-side templating', sev: 'high', conf: 'low',
        desc: 'Vue compiles the server-rendered page content mounted on this element as a template. A server value containing {{ … }} is evaluated by Vue, and HTML escaping does not remove the braces (client-side template injection).',
        fix: 'Mark the server-rendered region v-pre, or pass data to Vue as JSON and render from a client-side template string that does not contain server output.',
      });
    }
  },
});

// ── 7. template engines configured to skip escaping (code files) ───────────────────
const J2_ENV = /\b(?:jinja2\.)?Environment\s*\(/g;
const engineConfig = [
  pattern({ ...MK, id: 'tpl-autoescape-off-js', langs: ['js'], view: 'code', title: 'Template engine escaping disabled', conf: 'medium',
    re: /\bautoescape\s*:\s*false\b|\bnoEscape\s*:\s*true\b/,
    desc: 'The template engine is configured with autoescape/noEscape off, so every {{ value }} is printed unescaped; any attacker-influenced value becomes XSS.',
    fix: 'Leave autoescape on (the default in nunjucks and Handlebars) and mark individual trusted values safe instead.' }),
  pattern({ ...MK, id: 'tpl-autoescape-off-py', langs: ['python'], view: 'code', title: 'Template engine escaping disabled', conf: 'medium',
    re: /\bautoescape\s*=\s*False\b/,
    desc: 'Jinja2 is configured with autoescape=False, so every {{ value }} is printed unescaped; any attacker-influenced value becomes XSS.',
    fix: 'Use autoescape=select_autoescape() (or True) and mark individual trusted values with |safe / Markup.' }),
  pattern({ ...MK, id: 'tpl-autoescape-default-py', langs: ['python'], view: 'code', title: 'Jinja2 Environment without autoescape', conf: 'medium',
    re: J2_ENV,
    check: (m, flow, text) => {
      const open = m.index + m[0].length - 1; let d = 0, end = text.length;
      for (let k = open; k < text.length; k++) { if (text[k] === '(') d++; else if (text[k] === ')') { d--; if (d === 0) { end = k; break; } } }
      return /\bautoescape\b/.test(text.slice(open, end)) ? false : true;
    },
    desc: 'A Jinja2 Environment is created without autoescape; the default is off, so every {{ value }} is printed unescaped (Bandit B701).',
    fix: 'Pass autoescape=select_autoescape() (or True).' }),
  pattern({ ...MK, id: 'tpl-autoescape-off-php', langs: ['php'], inString: true, title: 'Template engine escaping disabled', conf: 'medium',
    re: /['"]autoescape['"]\s*=>\s*false\b|->\s*escape_html\s*=\s*false\b|->\s*setEscapeHtml\s*\(\s*false\s*\)/,
    desc: 'Twig / Smarty is configured to skip HTML escaping, so every printed value is unescaped; any attacker-influenced value becomes XSS.',
    fix: "Keep Twig 'autoescape' => 'html' and Smarty escape_html on; mark individual trusted values |raw / nofilter." }),
];

engineConfig.push(
  pattern({ ...MK, id: 'tpl-angularjs-sce-off', langs: ['js'], view: 'code', title: 'AngularJS strict contextual escaping disabled', conf: 'high',
    re: /\$sceProvider\s*\.\s*enabled\s*\(\s*false\s*\)|\$sceDelegateProvider\s*\.\s*resourceUrlWhitelist\s*\(\s*\[\s*['"]\*\*?['"]\s*\]\s*\)/,
    desc: 'AngularJS strict contextual escaping ($sce) is disabled, or every resource URL is whitelisted, so ng-bind-html / ng-include / ng-src accept attacker-chosen HTML and URLs.',
    fix: 'Keep $sce enabled, whitelist specific origins, and sanitise HTML with ngSanitize / DOMPurify.' }),
);

export const MARKUP_RULES = [unescapedOutput, scriptContext, handlerContext, urlAttr, directives, csti, ...engineConfig];
