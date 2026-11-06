'use strict';

import { isCleared } from '../taint.js';
import { call, assign, pattern, custom, WEB, JVM, ALLL } from './helpers.js';
import { m, x, notDot, FN_VALUE } from './injection.js';
import { inFile, fileText } from './helpers.js';

const flowOf = (st) => (st.kind === 'src' ? { kind: 'src', origin: st.origin } : { kind: 'param', params: [st] });

// ═══ XSS / template injection ════════════════════════════════════════════════
// The handler declares a body type browsers do not render as HTML (JSON, plain text, CSV, octet-stream, images…).
const goNonHtmlResponse = (cand, flow) => {
  const ct = /Header\(\)\.Set\(\s*"Content-Type"\s*,\s*"([^"]*)"/i.exec(flow.ctx.literal);
  if (ct && !/html|xml|svg|javascript|ecmascript/i.test(ct[1]))
    return { valid: false, reason: `the handler sets Content-Type "${ct[1]}" explicitly, so the body is not rendered as HTML` };
  return null;
};
const XSS = { cls: 'XSS / template injection', group: 'html', sev: 'high', fix: 'Encode output for its context (HTML-escape, or use the framework auto-escaping template), never mark input as "safe"/raw HTML, and never use input as a template source. For rich HTML use a sanitiser with an allowlist (DOMPurify, bleach, Loofah).' };
const xssWhat = 'writes it into an HTML response / DOM without escaping';
const ssti = 'compiles it as a template, so the input can execute template expressions';
const sstiFix = 'Never build template source from input: keep the template fixed and pass the value as a context variable (render_template("page.html", name=name), ejs.render(tpl, { name }), $twig->render("page.twig", [...])). If users must author templates, use a sandboxed engine and treat the template as code.';
// Group 'ssti', not 'html': escaping <>&"' does nothing against {{7*7}} / <%= … %> / ${…}, so html escapers must not clear it.
const STI = { ...XSS, group: 'ssti', sev: 'critical', fix: sstiFix };
const stiFile = 'selects the template file the engine loads, so the input can pick (or traverse to) any template';

// Start offset of the primary expression whose last member is the '.' at `end` (walks back over strings, bracket groups and call chains).
function rubyReceiverStart(text, end) {
  let i = end - 1;
  for (;;) {
    if (i < 0) return 0;
    const c = text[i];
    if (c === ')' || c === ']' || c === '}') {
      let d = 0;
      for (; i >= 0; i--) { const ch = text[i]; if (ch === ')' || ch === ']' || ch === '}') d++; else if (ch === '(' || ch === '[' || ch === '{') { d--; if (d === 0) break; } }
      i--;
      while (i >= 0 && /[\w@$:?!]/.test(text[i])) i--;         // the name the group belongs to:  params[…]  h(…)
    } else if (c === '"' || c === "'" || c === '`') {
      i--; while (i >= 0 && text[i] !== c) i--;
      i--;
    } else if (/[\w@$:?!]/.test(c)) {
      while (i >= 0 && /[\w@$:?!]/.test(text[i])) i--;
    } else return i + 1;
    if (i >= 0 && text[i] === '.') i--;        // continue through a method chain:  a.b(c).d
    else return i + 1;
  }
}

const XSS_RULES = [
  call({ ...XSS, id: 'xss-js-send', langs: ['js'], what: xssWhat, args: [0], chain: true, callee: /^(?:res|response|reply|resp|ctx\.res)(?:\.(?:status|type|set|header|contentType|code)\(\))*\.(?:send|write|end|html)$/, conf: 'medium' }),
  assign({ ...XSS, id: 'xss-js-dom', langs: ['js'], what: xssWhat, lhs: /\.(?:innerHTML|outerHTML|srcdoc)$|^(?:innerHTML|outerHTML)$/ }),
  assign({ ...XSS, id: 'xss-js-ctxbody', langs: ['js'], what: xssWhat, lhs: /^ctx\.body$/, conf: 'low' }),
  call({ ...XSS, id: 'xss-js-dom-call', langs: ['js'], what: xssWhat, args: [1], callee: m('insertAdjacentHTML') }),
  call({ ...XSS, id: 'xss-js-docwrite', langs: ['js'], what: xssWhat, args: 'any', callee: x('document\\.write|document\\.writeln') }),
  call({ ...XSS, id: 'xss-js-jquery', langs: ['js'], what: xssWhat, args: [0], callee: /^(?:\$|jQuery|\$\(\)|jQuery\(\))\.(?:html|append|prepend|after|before|replaceWith|wrap)$|^\$\(\)\.(?:html|append|prepend|after|before|replaceWith)$/, chain: true, argUnless: FN_VALUE }),
  call({ ...XSS, id: 'xss-js-trust', langs: ['js'], what: 'tells the framework to trust it as safe HTML/script/URL', args: [0], callee: m('bypassSecurityTrustHtml|bypassSecurityTrustScript|bypassSecurityTrustUrl|bypassSecurityTrustResourceUrl|bypassSecurityTrustStyle|trustAsHtml|trustAsJs|trustAsResourceUrl') }),
  call({ ...STI, id: 'xss-js-ssti', langs: ['js'], what: ssti, args: [0],
    callee: /^(?:ejs|pug|jade|nunjucks|swig|dust|hogan|Hogan|eta|Eta|doT|dot|Mustache|mustache|twig|Twig|art|artTemplate)\.(?:render|renderString|compile|compileClient|template|twig|renderSource|precompile|compileSource|parse)$|^(?:Handlebars|handlebars|hbs|hbs\.handlebars)\.(?:compile|precompile)$|^(?:_|lodash|underscore)\.template$|^(?:new\s*)?nunjucks\.Template$|^\w+\.parseAndRender(?:Sync)?$/,
    when: (c) => /\./.test(c.callee) }),
  custom({ ...XSS, id: 'xss-js-react', langs: ['js'], what: xssWhat,
    run(flow, emit) {
      const re = /dangerouslySetInnerHTML\s*=\s*\{\{\s*__html\s*:/g; let mm;
      while ((mm = re.exec(flow.ctx.code)) !== null) {
        const from = mm.index + mm[0].length;
        let depth = 2, k = from;
        while (k < flow.ctx.code.length && depth > 0) { const c = flow.ctx.code[k]; if (c === '{') depth++; else if (c === '}') depth--; k++; }
        const expr = flow.ctx.code.slice(from, k - 2);
        const st = flow.state(expr, flow.ctx.literal.slice(from, k - 2), flow.ctx.lineAt(mm.index)).filter(s => !isCleared(s, 'html'));
        if (st.length) emit(mm.index, { desc: `dangerouslySetInnerHTML is given ${st[0].origin || 'parameter "' + st[0].param + '"'}, which React will not escape.`, flowInfo: flowOf(st[0]) });
      }
    } }),

  call({ ...XSS, id: 'xss-py-markup', langs: ['python'], what: 'marks it as safe HTML (no auto-escaping)', args: [0], callee: x('(?:markupsafe\\.|django\\.utils\\.safestring\\.|flask\\.)?(?:Markup|mark_safe|SafeString|SafeText)') }),
  call({ ...XSS, id: 'xss-py-response', langs: ['python'], what: xssWhat, args: [0], callee: x('HttpResponse|HTMLResponse|make_response|self\\.write|self\\.finish|web\\.Response|Response|(?:flask\\.)?Response'),
    when: (c) => !/(?:json|JSON)/.test(c.callee) && !/content_type\s*=\s*['"]application\/json|mimetype\s*=\s*['"]application\/json|media_type\s*=\s*['"](?:application|text\/plain)/.test(c.lit) }),
  call({ ...STI, id: 'xss-py-ssti', langs: ['python'], what: ssti, sev: 'critical', args: [0], callee: x('render_template_string|(?:jinja2\\.|jinja2\\.environment\\.)?Template|\\w+\\.from_string|Environment\\(\\)\\.from_string|mako\\.template\\.Template|Template|tornado\\.template\\.Template|django\\.template\\.Template|Engine\\(\\)\\.from_string'), }),
  call({ ...XSS, id: 'xss-php-echo', langs: ['php'], what: xssWhat, args: 'any', callee: x('echo|print|printf|print_r|var_dump|die|exit|vprintf|fprintf'), conf: 'medium',
    when: (c) => !/^fprintf$/.test(c.callee) || /STDOUT|php:\/\/output/.test(c.lit) }),
  custom({ ...XSS, id: 'xss-php-shorttag', langs: ['php'], what: xssWhat,
    run(flow, emit) {
      // The expression may itself contain '?' (`$a ?? ''`, `$a ?: $b`); strings and comments are blanked in the code
      // view, so the first '?>' really is the end of the tag. The literal view of the same span lets the engine read
      // string-literal callback names such as array_map('absint', …) and wp_kses allow-lists.
      const re = /<\?=\s*([\s\S]+?)\s*\?>/g; let mm;
      while ((mm = re.exec(flow.ctx.code)) !== null) {
        const from = mm.index + /^<\?=\s*/.exec(mm[0])[0].length;
        const st = flow.state(mm[1], flow.ctx.literal.slice(from, from + mm[1].length), flow.ctx.lineAt(mm.index)).filter(s => !isCleared(s, 'html'));
        if (st.length) emit(mm.index, { desc: `<?= echoes ${st[0].origin || 'parameter "' + st[0].param + '"'} without escaping.`, flowInfo: flowOf(st[0]) });
      }
    } }),
  call({ ...XSS, id: 'xss-ruby-raw', langs: ['ruby'], what: 'marks it as safe HTML (no auto-escaping)', args: [0], callee: x('raw|ActionController::Base\\.helpers\\.raw|html_safe|safe_concat') }),
  call({ ...STI, id: 'xss-ruby-ssti', langs: ['ruby'], what: ssti, args: [0], callee: /^(?:ERB\.new|Erubi::Engine\.new|Erubis::Eruby\.new|Haml::Engine\.new|Hamlit::Engine\.new|Slim::Template\.new|Liquid::Template\.parse|Tilt\.new|Tilt::\w+Template\.new|Mustache\.render|Handlebars\.compile)$/ }),
  call({ ...XSS, id: 'xss-ruby-render', langs: ['ruby'], what: xssWhat, args: 'any', callee: x('render'), when: (c) => /\btext\s*:/.test(c.text) }),
  // render inline: compiles its argument as an ERB template; render file: / template: / partial: / action: load a template chosen by the input
  call({ ...STI, id: 'xss-ruby-render-inline', langs: ['ruby'], what: ssti, args: 'any', callee: x('render|render_to_string'), when: (c) => /\binline\s*:/.test(c.text) }),
  call({ ...STI, id: 'xss-ruby-render-file', langs: ['ruby'], what: stiFile, sev: 'high', args: 'any', callee: x('render|render_to_string'), when: (c) => /\b(?:file|template|partial|action|layout)\s*:/.test(c.text) }),
  // Sinatra / Roda style blocks return the value of their LAST expression:  get '/' do … html end
  custom({ ...XSS, id: 'xss-ruby-sinatra', langs: ['ruby'], what: xssWhat, conf: 'medium',
    run(flow, emit) {
      if (!/^\s*(?:get|post|put|delete|patch|any)\s+['"%\/]/m.test(flow.ctx.code)) return;
      const lines = flow.ctx.logical.filter(l => l.text.trim() && !/^\s*(?:end|\})\s*$/.test(l.text));
      const last = lines[lines.length - 1];
      if (!last || /^\s*(?:get|post|put|delete|patch|any|halt|redirect|content_type|status|headers|erb|haml|slim|json)\b/.test(last.text)) return;
      if (!/<\s*[a-zA-Z!\/]/.test(last.lit) && !mentionsHtmlName(flow, last.text)) return;
      const st = flow.state(last.text, last.lit, last.line).filter(s => !isCleared(s, 'html'));
      if (st.length) emit(last.start, { desc: `The block's value (the response body) is HTML built from ${st[0].origin || 'parameter "' + st[0].param + '"'} without escaping it.`, flowInfo: flowOf(st[0]) });
    } }),
  custom({ ...XSS, id: 'xss-ruby-htmlsafe', langs: ['ruby'], what: xssWhat,
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        const mm = /\.html_safe\b/.exec(ll.text); if (!mm) continue;
        // the receiver is the whole primary expression before `.html_safe`: a string literal with #{…} interpolation,
        // a parenthesised expression, or a call chain (`"<b>#{x}</b>".html_safe`, `(a + b).html_safe`, `h(x).html_safe`)
        const from = rubyReceiverStart(ll.text, mm.index);
        const st = flow.state(ll.text.slice(from, mm.index), ll.lit.slice(from, mm.index), ll.line).filter(s => !isCleared(s, 'html'));
        if (st.length) emit(ll.start + mm.index, { desc: `html_safe disables escaping for ${st[0].origin || 'parameter "' + st[0].param + '"'}.`, flowInfo: flowOf(st[0]) });
      }
    } }),
  call({ ...XSS, id: 'xss-go-template', langs: ['go'], what: 'marks it as trusted HTML/JS/URL, bypassing html/template escaping', args: [0], callee: x('template\\.(?:HTML|HTMLAttr|JS|JSStr|CSS|URL|Srcset)|(?:\\w+\\.)?(?:template\\.HTML)') }),
  call({ ...XSS, id: 'xss-go-write', langs: ['go'], what: xssWhat, args: 'any', verify: goNonHtmlResponse, callee: x('fmt\\.(?:Fprintf|Fprint|Fprintln)|io\\.WriteString|(?:w|rw|resp|res|writer|wr)\\.Write|(?:c|ctx)\\.(?:String|Writer\\.Write|Data|HTML)'),
    when: (c) => /^(?:fmt\.F|io\.WriteString)/.test(c.callee) ? /^(?:w|rw|resp|res|writer|wr|c\.Writer|ctx\.Writer)\b/.test(c.args[0]?.text || '') : !/^(?:c|ctx)\.HTML$/.test(c.callee) || c.args.length === 2,   // Gin c.HTML(code, tmpl, data) renders a template; Echo c.HTML(code, html) writes the string
    argsFn: (c) => /^(?:fmt\.F|io\.WriteString)/.test(c.callee) ? c.args.map((_, i) => i).filter(i => i > 0) : /^(?:c|ctx)\.(?:String|Data|HTML)$/.test(c.callee) ? c.args.map((_, i) => i).filter(i => i > 0) : [0] }),
  call({ ...XSS, id: 'xss-rust', langs: ['rust'], what: xssWhat, args: [0], chain: true, callee: /^HttpResponse::\w+\(\)(?:\.\w+\(\))*\.body$|^(?:axum::response::)?Html$|^(?:maud::)?PreEscaped$|^(?:warp::)?reply::html$|^RawHtml$|^content::RawHtml$|^(?:HttpResponse::\w+\(\)\.content_type\(\))\.body$/ }),
  call({ ...XSS, id: 'xss-jvm-writer', langs: JVM, what: xssWhat, args: 'any', chain: true, callee: /^(?:response|resp|res)\.getWriter\(\)\.(?:println|print|write|append|printf|format)$|^(?:response|resp|res)\.(?:writer|outputStream)\.(?:println|print|write|append)$/ }),
  call({ ...XSS, id: 'xss-jvm-out', langs: JVM, what: xssWhat, args: 'any', callee: x('(?:out|writer|pw|printWriter|w)\\.(?:println|print|write|append|printf)'), when: (c, f) => /getWriter\s*\(|HttpServletResponse|response\./.test(f.ctx.code) }),
  call({ ...STI, id: 'xss-jvm-ssti', langs: JVM, what: ssti, sev: 'critical', args: 'any', callee: x('(?:\\w*[tT]emplateEngine|engine|thymeleaf)\\.process|Velocity\\.evaluate|(?:\\w+\\.)?(?:evaluate)|Template|StringTemplateLoader\\.putTemplate|\\w+\\.putTemplate'),
    when: (c, f) => /process|putTemplate/.test(c.callee) || (/Velocity\.evaluate/.test(c.callee)) || (c.isNew && /StringReader/.test(c.text)) }),
  call({ ...XSS, id: 'xss-kotlin-ktor', langs: ['kotlin'], what: xssWhat, args: [0], callee: x('call\\.respondText|call\\.respondHtml|call\\.respondBytes'), when: (c) => /Html|text\/html/.test(c.text) }),
  call({ ...XSS, id: 'xss-csharp', langs: ['csharp'], what: xssWhat, args: [0], callee: x('(?:HttpContext\\.)?Response\\.Write|(?:HttpContext\\.)?Response\\.WriteAsync|(?:Html|@Html)\\.Raw|HtmlString|MvcHtmlString\\.Create|Content|Results\\.Content|ContentResult|Server\\.HtmlDecode|new\\.HtmlString'),
    when: (c) => !/^(?:Content|Results\.Content|ContentResult)$/.test(c.callee) || /text\/html/i.test(c.lit) }),
  assign({ ...XSS, id: 'xss-csharp-inner', langs: ['csharp'], what: xssWhat, lhs: /\.(?:InnerHtml|InnerText|OuterHtml)$/, conf: 'low' }),
  call({ ...XSS, id: 'xss-mobile-html', langs: ['dart', 'swift'], what: 'loads it into a WebView as HTML/JavaScript', args: 'any', sev: 'high',
    callee: x('(?:\\w+\\.)?(?:loadHtmlString|loadHTMLString|loadData|loadHtmlText|evaluateJavascript|runJavaScript|runJavascript|evaluateJavaScript|runJavaScriptReturningResult|addJavaScriptChannel)'),
    argsFn: (c) => c.name === 'loadHTMLString' ? [0] : [0] }),
];

// Names that hold HTML this handler assembled:  html = '<ul>'   html += '<li>' + x   parts.append('<li>' …)   sb.append("<b>")
// A tag only counts when it sits inside a string literal (the code view blanks strings), so generics (List<String>) are ignored.
function htmlBuiltNames(flow) {
  if (flow._htmlNames) return flow._htmlNames;
  const names = new Set();
  const tagInString = (ll) => { const re = /<\s*\/?\s*[a-zA-Z!]/g; let m; while ((m = re.exec(ll.lit)) !== null) if (ll.text[m.index] !== ll.lit[m.index]) return true; return false; };
  for (const ll of flow.ctx.logical) {
    if (!tagInString(ll)) continue;
    const a = flow._parseAssignment(ll.text);
    if (a) for (const n of a.lhs) names.add(n);
    const mu = /^\s*([\w$.]+?)\s*\.\s*(?:append|push|add|write|writeln|concat|extend|insert|AppendLine|Append|AppendFormat|WriteString|push_str|print|println)\s*\(/.exec(ll.text);
    if (mu) names.add(mu[1]);
  }
  return (flow._htmlNames = names);
}
const mentionsHtmlName = (flow, expr) => {
  const names = htmlBuiltNames(flow);
  if (!names.size) return false;
  for (const tok of expr.match(/[\w$.]+/g) || []) if (names.has(tok) || names.has(tok.split('.')[0])) return true;
  return false;
};

// Returning HTML built from input: Flask / Spring / Fastify / Nest / WordPress shortcodes and filters / Laravel controllers.
// The returned expression is HTML when it contains an HTML literal itself or names a variable assembled from HTML literals.
function returnHtmlRule(id, langs, gate, opts = {}) {
  return custom({ ...XSS, id, langs, what: xssWhat, conf: 'medium',
    run(flow, emit) {
      if (gate && !gate(flow)) return;
      for (const ll of flow.ctx.logical) {
        const mm = /^\s*return\b\s*([\s\S]+)$/.exec(ll.text); if (!mm) continue;
        if (opts.unless && opts.unless.test(mm[1])) continue;
        const lit = ll.lit.slice(ll.lit.length - mm[1].length);
        if (!/<\s*[a-zA-Z!\/]/.test(lit) && !mentionsHtmlName(flow, mm[1])) continue;
        const st = flow.state(mm[1], lit, ll.line).filter(s => !isCleared(s, 'html'));
        if (st.length) emit(ll.start, { desc: `A response is built as HTML by concatenating ${st[0].origin || 'parameter "' + st[0].param + '"'} without escaping it.`, flowInfo: flowOf(st[0]) });
      }
    } });
}
XSS_RULES.push(returnHtmlRule('xss-py-return', ['python'], (f) => {
  if (/\bfastapi\b|\bstarlette\b/i.test(fileText(f)) && !/response_class\s*=\s*(?:HTMLResponse|Response)\b|HTMLResponse/.test(f.chunk.code.slice(0, 900))) return false;   // FastAPI returns JSON by default
  return /@\s*[\w.]+\s*\.\s*(?:route|get|post|put|delete|patch)\s*\(|def\s+(?:get|post|put|delete|patch)\b|HttpResponse|View\b/.test(f.chunk.code.slice(0, 900)) || f.routeHandler;
}));
XSS_RULES.push(returnHtmlRule('xss-jvm-return', JVM, (f) => /@ResponseBody|@RestController|produces\s*=\s*["']text\/html/.test(f.chunk.code.slice(0, 1200)) || /@RestController/.test(f.chunk.code)));

// Route handlers in Fastify / Nest / Hapi / Koa that return an HTML string; WordPress shortcodes, filters and Laravel / Symfony
// actions that return one. (Express handlers write with res.send, which xss-js-send covers.)
XSS_RULES.push(returnHtmlRule('xss-js-return', ['js'],
  (f) => /@(?:Get|Post|Put|Delete|Patch|All|Head|Options)\s*\(|\b(?:fastify|server|app|router|api|route)\s*\.\s*(?:get|post|put|delete|patch|route|all)\s*\(|\breply\b|\bh\.response\b|\bctx\b/.test(f.chunk.code),
  { unless: /\.json\s*\(|\.jsonp\s*\(|JSON\.stringify|^\s*[{\[]|\.redirect\s*\(|\.sendStatus\s*\(/ }));
XSS_RULES.push(returnHtmlRule('xss-php-return', ['php'], null,
  { unless: /\b(?:json_encode|wp_json_encode|wp_send_json\w*|rest_ensure_response|WP_REST_Response|WP_Error|JsonResponse)\b|->\s*json\s*\(|\barray\s*\(|^\s*\[/ }));

XSS_RULES.push(
  call({ ...XSS, id: 'xss-php-response', langs: ['php'], what: xssWhat, args: [0], callee: /^(?:response|Response|HtmlResponse)$/, when: (c) => !/application\/json|text\/plain/i.test(c.lit) }),

  // ── server-side template injection: more engines and the template-selection variants ──────────────────────
  call({ ...STI, id: 'xss-js-ssti-file', langs: ['js'], what: stiFile, sev: 'high', args: [0], callee: /^(?:ejs|pug|jade|nunjucks|swig|hogan|dust|hbs|handlebars)\.(?:renderFile|__express)$/ }),
  call({ ...STI, id: 'xss-js-render-view', langs: ['js'], what: stiFile, sev: 'high', args: [0], chain: true,
    callee: /^(?:res|response|reply|resp|ctx|app)(?:\.(?:status|type|set|header)\(\))*\.(?:render|view)$/, when: (c) => /\./.test(c.chain) }),
  call({ ...STI, id: 'xss-js-render-opts', langs: ['js'], conf: 'low', sev: 'high', args: [1], chain: true,
    what: 'receives the whole request object as render options, so the request can set template-engine options (outputFunctionName, layout, …); this is how EJS render options became RCE (CVE-2022-29078)',
    callee: /^(?:res|response|reply|resp|ctx|app)(?:\.(?:status|type|set|header)\(\))*\.(?:render|view)$/,
    when: (c, f) => /^\s*(?:\{\s*\.\.\.\s*)?(?:req|request|ctx\.request|ctx)\.(?:query|body|params)\s*\}?\s*$/.test(c.args[1] ? c.args[1].text : '') && /\bejs\b|view\s*engine/i.test(fileText(f)) }),

  call({ ...STI, id: 'xss-php-ssti', langs: ['php'], what: ssti, args: [0],
    callee: /(?:^|[.:])(?:createTemplate|compileString|renderString|render_string|template_from_string|ArrayLoader|Twig_Loader_Array|Twig_Loader_String|StringLoader)$|^Blade::render$/ }),
  call({ ...STI, id: 'xss-php-ssti-engine', langs: ['php'], what: ssti, args: [0], conf: 'medium',
    callee: /(?:^|[.:])(?:fetch|display|render|renderToString|loadString|isCached)$/,
    fileGate: /\bsmarty\b|mustache|handlebars|latte\\|plates|dwoo|savant|twig/i }),
  call({ ...STI, id: 'xss-php-ssti-view', langs: ['php'], what: stiFile, sev: 'high', conf: 'low', args: [0], callee: /^(?:view|View::make|View::first|Response::view)$/ }),

  call({ ...STI, id: 'xss-go-ssti', langs: ['go'], what: 'compiles it as a template (or loads it as a template file), so the input can execute template actions', args: 'any', chain: true,
    callee: /(?:^|\.)(?:Parse|ParseFiles|ParseGlob|ParseFS)$/,
    when: (c, f) => /["`](?:html|text)\/template["`]/.test(fileText(f)) && /template|tmpl|tpl|\.New\(\)/i.test(c.chain) && !/^(?:url|time|flag|strconv|net|netip|uuid|semver|mail|json|yaml|toml|big|version)\./.test(c.chain) }),
  call({ ...XSS, id: 'xss-go-texttemplate', langs: ['go'], what: 'is executed through text/template into the HTTP response, which does not HTML-escape (use html/template)', verify: goNonHtmlResponse, conf: 'medium',
    callee: /(?:^|\.)(?:Execute|ExecuteTemplate)$/,
    when: (c, f) => /["`]text\/template["`]/.test(fileText(f)) && !/["`]html\/template["`]/.test(fileText(f)) && /^(?:w|rw|resp|res|writer|wr|c\.Writer|ctx\.Writer)\b/.test(c.args[0] ? c.args[0].text : ''),
    argsFn: (c) => /ExecuteTemplate$/.test(c.callee) ? [2] : [1] }),

  call({ ...STI, id: 'xss-csharp-ssti', langs: ['csharp'], what: ssti,
    callee: /(?:^|\.)(?:Razor\.(?:Parse|Compile|RunCompile)|Template\.(?:Parse|ParseLiquid|ParseScriban|Evaluate)|Handlebars\.Compile|\w+\.(?:RunCompile|CompileRenderString|CompileRenderStringAsync|RenderStringAsync|ParseAndRender|ParseAndRenderAsync|CompileTemplateAsync|ParseTemplate))$/,
    argsFn: (c) => /CompileRenderString/.test(c.callee) ? [1] : [0] }),
  call({ ...STI, id: 'xss-csharp-ssti-fluid', langs: ['csharp'], what: ssti, args: [0], callee: /(?:^|\.)(?:Parse|TryParse)$/,
    fileGate: /\bFluid\b|FluidParser|Scriban|DotLiquid|Stubble|Mustachio|Nustache/,
    when: (c) => !/^(?:int|Int32|Int64|long|double|Double|decimal|Decimal|float|Single|short|bool|Boolean|byte|Guid|DateTime|DateTimeOffset|TimeSpan|Enum|Uri|IPAddress|Version|char)\./.test(c.callee) }),

  call({ ...STI, id: 'xss-rust-ssti', langs: ['rust'], what: ssti,
    callee: /(?:^|[.:])(?:one_off|add_raw_template|add_raw_templates|render_template|register_template_string|render_str|render_template_string)$/,
    argsFn: (c) => /(?:add_raw_template|register_template_string)$/.test(c.callee) ? [1] : [0] }),

  call({ ...STI, id: 'xss-jvm-modelview', langs: JVM, sev: 'high', args: [0], what: 'is used as the view name, so the template engine (Thymeleaf, FreeMarker, Velocity) resolves, and may evaluate, it', callee: m('ModelAndView|setViewName') }),
  // Spring MVC: a @Controller method that returns a view name built from input (Thymeleaf evaluates `__${…}__` and fragment expressions in it)
  custom({ ...STI, id: 'xss-jvm-viewname', langs: JVM, sev: 'high', conf: 'medium', what: 'is returned as the view name',
    run(flow, emit) {
      const file = fileText(flow);
      if (!/@Controller\b/.test(file) || /@RestController/.test(file) || /@ResponseBody/.test(flow.chunk.code)) return;
      for (const ll of flow.ctx.logical) {
        const mm = /^\s*return\s+([\s\S]+)$/.exec(ll.text); if (!mm) continue;
        const lit = ll.lit.slice(ll.lit.length - mm[1].length);
        if (/^\s*["']\s*(?:redirect|forward):/.test(lit) || /\b(?:ResponseEntity|ModelAndView|RedirectView|Map\.of|List\.of|null)\b/.test(mm[1])) continue;
        if (!/["']/.test(lit) && !/^[\w.]+$/.test(mm[1].trim())) continue;
        const st = flow.state(mm[1], lit, ll.line).filter(s => !isCleared(s, 'ssti'));
        if (st.length) emit(ll.start, { desc: `${st[0].origin || 'Parameter "' + st[0].param + '"'} is used to build the view name this controller returns, so the template engine can resolve or evaluate attacker-chosen template text.`, flowInfo: flowOf(st[0]) });
      }
    } }),
);

// ═══ Open redirect ═══════════════════════════════════════════════════════════
const REDIR = { cls: 'open redirect', group: 'redirect', sev: 'medium', fix: 'Redirect only to relative paths or to hosts on an explicit allowlist; map user choices to server-side route names, and validate with the framework helper (url_has_allowed_host_and_scheme, LocalRedirect).' };
const redirWhat = 'redirects the browser to a destination taken from the input';
const REDIRECT_RULES = [
  call({ ...REDIR, id: 'redir-js', langs: ['js'], what: redirWhat, args: 'any', chain: true, callee: /^(?:res|response|reply|ctx|resp)(?:\.(?:status|set|header)\(\))*\.(?:redirect|location)$|^(?:NextResponse\.redirect|redirect|permanentRedirect|Response\.redirect)$|^(?:window\.|self\.|top\.)?location\.(?:assign|replace)$|^(?:window\.)?open$/, when: (c) => !c.viaDot || /\./.test(c.callee) }),
  assign({ ...REDIR, id: 'redir-js-assign', langs: ['js'], what: redirWhat, lhs: /(?:^|\.)(?:location|location\.href|top\.location|document\.location)$/ }),
  call({ ...REDIR, id: 'redir-python', langs: ['python'], what: redirWhat, args: [0], callee: x('redirect|flask\\.redirect|HttpResponseRedirect|HttpResponsePermanentRedirect|RedirectResponse|self\\.redirect|web\\.HTTPFound|HTTPFound|HTTPSeeOther|HTTPMovedPermanently|HTTPTemporaryRedirect|django\\.shortcuts\\.redirect') }),
  call({ ...REDIR, id: 'redir-php-header', langs: ['php'], what: redirWhat, args: [0], callee: x('header'), when: (c) => /Location\s*:/i.test(c.lit) }),
  call({ ...REDIR, id: 'redir-php', langs: ['php'], what: redirWhat, args: 'any', chain: true, callee: /^(?:wp_redirect|redirect|Redirect::to|Redirect::away|redirect\(\)\.(?:to|away)|header_remove)$|^Response::redirect\w*$/, when: (c) => c.callee !== 'header_remove' }),
  call({ ...REDIR, id: 'redir-ruby', langs: ['ruby'], what: redirWhat, args: [0], callee: x('redirect_to|redirect'), unless: /allow_other_host\s*:\s*false/ }),
  call({ ...REDIR, id: 'redir-go', langs: ['go'], what: redirWhat, callee: x('http\\.Redirect|(?:c|ctx|e)\\.Redirect|(?:c|ctx)\\.Redirect\\w*'),
    argsFn: (c) => c.callee === 'http.Redirect' ? [2] : c.args.map((_, i) => i).filter(i => i > 0 || c.args.length === 1) }),
  call({ ...REDIR, id: 'redir-rust', langs: ['rust'], what: redirWhat, args: [0], callee: x('Redirect::(?:to|temporary|permanent|found|see_other|moved)') }),
  call({ ...REDIR, id: 'redir-jvm', langs: JVM, what: redirWhat, args: [0], callee: x('(?:\\w+\\.)?(?:sendRedirect|redirect|seeOther|temporaryRedirect|permanentRedirect|respondRedirect)|RedirectView|ModelAndView|(?:call\\.)?respondRedirect'),
    when: (c) => !/ModelAndView/.test(c.callee) || /redirect\s*:/.test(c.lit) }),
  custom({ ...REDIR, id: 'redir-spring-return', langs: JVM, what: redirWhat,
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        const mm = /^\s*return\s+([\s\S]+)$/.exec(ll.text); if (!mm) continue;
        const lit = ll.lit.slice(ll.lit.length - mm[1].length);
        if (!/["']\s*redirect\s*:/.test(lit)) continue;
        const st = flow.state(mm[1], lit, ll.line).filter(s => !isCleared(s, 'redirect'));
        if (st.length) emit(ll.start, { desc: `Spring "redirect:" view built from ${st[0].origin || 'parameter "' + st[0].param + '"'}.`, flowInfo: flowOf(st[0]) });
      }
    } }),
  call({ ...REDIR, id: 'redir-csharp', langs: ['csharp'], what: redirWhat, args: [0], callee: x('(?:this\\.|Controller\\.)?(?:Redirect|RedirectPermanent|RedirectPreserveMethod|RedirectPermanentPreserveMethod)|(?:HttpContext\\.)?Response\\.Redirect|RedirectResult|Results\\.Redirect|TypedResults\\.Redirect') }),
];

// ═══ SSRF ════════════════════════════════════════════════════════════════════
const SSRF = { cls: 'SSRF', group: 'ssrf', sev: 'high', fix: 'Do not fetch URLs supplied by users. If required, parse the URL, allow only https and an explicit host allowlist, resolve the host and block private/loopback/link-local ranges, and disable redirects.' };
const ssrfWhat = 'makes a server-side network request to a destination taken from the input';
// An attacker who controls only the path/query of a fixed https://host/ cannot redirect the request elsewhere.
const FIXED_HOST = /^\s*(?:f|r|b|rb|u)?["'`]?\s*https?:\/\/[^\/"'`{$#?\s]+[\/?]/i;
// Browser-side JS (DOM APIs, no Node/server markers): fetch() runs in the user's own browser, which is not SSRF
// (same-origin policy and the page CSP apply; no internal network is reachable on the server's behalf).
const BROWSER_JS = /\b(?:document\.(?:getElementById|querySelector\w*|createElement|addEventListener|body|cookie)|window\.(?:location|addEventListener|open)|addEventListener\s*\()/;
const SERVER_JS = /\brequire\s*\(|\bfrom\s+['"](?:node:|express|fastify|koa|http|https|fs|path|child_process)\b|\bprocess\.(?:env|argv)\b|\bmodule\.exports\b/;
const isBrowserJs = (flow) => { const t = fileText(flow); return BROWSER_JS.test(t) && !SERVER_JS.test(t); };
const ssrfVerify = (cand, flow) => {
  const a = cand.arg; if (!a) return null;
  if (flow && isBrowserJs(flow)) return { valid: false, reason: 'browser-side code: the request is made by the user\'s own browser (same-origin policy / CSP apply), not by the server, so this is not SSRF' };
  if (FIXED_HOST.test(a.lit.replace(/^\s*[&*]\s*/, '').replace(/^(?:format!|String\.format|sprintf|f)\s*\(/, ''))) return { valid: false, reason: 'the destination host is a fixed literal; the input only affects the path or query string' };
  return null;
};

const SSRF_RULES = [
  call({ ...SSRF, id: 'ssrf-python', langs: ['python'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: x('(?:requests|httpx|aiohttp|urllib3|http_client|session|sess|client|api|http|requests_session|self\\.session|self\\.client)\\.(?:get|post|put|delete|patch|head|options|request|stream|send|urlopen|fetch)|urlopen|urllib\\.request\\.urlopen|urllib\\.request\\.urlretrieve|urlretrieve|urllib\\.request\\.Request|urllib\\.urlopen|socket\\.create_connection|http\\.client\\.HTTPS?Connection|HTTPS?Connection|ftplib\\.FTP|smtplib\\.SMTP(?:_SSL)?|wget\\.download|pycurl\\.\\w+|(?:requests|httpx)\\.(?:Session|AsyncClient)\\(\\)\\.(?:get|post|put|delete|request)'),
    chain: false }),
  call({ ...SSRF, id: 'ssrf-js', langs: ['js'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: x('fetch|axios|got|request|needle|superagent|ky|ofetch|\\$fetch|rp|requestPromise|nodeFetch|undici\\.(?:request|fetch)|(?:http|https)\\.(?:get|request)|axios\\.(?:get|post|put|delete|patch|head|options|request)|got\\.(?:get|post|put|delete|patch|head|stream)|request\\.(?:get|post|put|delete|patch|head)|needle\\.(?:get|post|put|delete|patch|head)|superagent\\.(?:get|post|put|delete|patch|head)|page\\.goto|\\$\\.(?:ajax|get|post|getJSON)|(?:\\w*[cC]lient|instance|api|http)\\.(?:get|post|put|delete|patch|head|request)'),
    when: (c) => !(c.viaDot && !/\./.test(c.callee)) && !/^(?:\w*[cC]lient|instance|api|http)\./.test(c.callee) || /(?:axios|httpClient|apiClient|fetchClient|httpService)/i.test(c.callee) }),
  call({ ...SSRF, id: 'ssrf-js-xhr', langs: ['js'], what: ssrfWhat, args: [1], callee: m('open'), when: (c) => /^(?:GET|POST|PUT|DELETE|PATCH|HEAD)$/i.test(c.args[0]?.lit.replace(/["'`\s]/g, '') || ''), verify: ssrfVerify }),
  call({ ...SSRF, id: 'ssrf-php', langs: ['php'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: x('curl_init|fsockopen|pfsockopen|stream_socket_client|get_headers|wp_remote_get|wp_remote_post|wp_remote_request|Http::(?:get|post|put|delete|patch|head)|SoapClient|simplexml_load_file|getimagesize|exif_read_data|file_get_contents|fopen|readfile|copy|file|\\$(?:client|http|guzzle|httpClient)\\.(?:get|post|put|delete|patch|head|request|send|getAsync|postAsync)|Request::create'),
    argsFn: (c) => /\.(?:request)$/.test(c.callee) ? [1] : [0] }),
  call({ ...SSRF, id: 'ssrf-php-curlopt', langs: ['php'], what: ssrfWhat, args: [2], callee: x('curl_setopt'), when: (c) => /CURLOPT_URL/.test(c.lit), verify: ssrfVerify }),
  call({ ...SSRF, id: 'ssrf-ruby', langs: ['ruby'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: x('Net::HTTP\\.(?:get|get_response|post|post_form|start|new|get_print)|URI\\.open|URI\\(\\)\\.open|HTTParty\\.\\w+|RestClient\\.\\w+|Faraday\\.(?:get|post|put|delete|new|head)|Typhoeus\\.\\w+|Excon\\.\\w+|HTTP\\.(?:get|post|put|delete|head|headers)|Curl::Easy\\.\\w+|open|URI\\.parse|URI|Mechanize\\.new\\.get|Net::HTTP\\.new'),
    when: (c) => !/^(?:URI\.parse|URI)$/.test(c.callee) && (c.callee !== 'open' || /^\s*["']?https?:|http/.test(c.lit)) }),
  call({ ...SSRF, id: 'ssrf-go', langs: ['go'], what: ssrfWhat, verify: ssrfVerify,
    callee: x('http\\.(?:Get|Post|Head|PostForm|NewRequest|NewRequestWithContext)|(?:client|httpClient|hc|cl|http\\.DefaultClient|resty|c)\\.(?:Get|Post|Head|PostForm)|net\\.(?:Dial|DialTimeout|DialTCP)|grpc\\.(?:Dial|NewClient|DialContext)|tls\\.Dial|(?:\\w+\\.)?R\\(\\)\\.(?:Get|Post|Put|Delete|Patch|Head)|websocket\\.Dial|rpc\\.Dial\\w*|smtp\\.Dial'),
    chain: false, argsFn: (c) => c.name === 'NewRequest' ? [1] : c.name === 'NewRequestWithContext' ? [2] : /^(?:Dial|DialTimeout|DialTCP|DialContext)$/.test(c.name) && /^net\.|^tls\./.test(c.callee) ? [1] : [0] }),
  call({ ...SSRF, id: 'ssrf-rust', langs: ['rust'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: x('reqwest::(?:get|blocking::get)|ureq::(?:get|post|put|delete|request|head)|surf::(?:get|post|put|delete|head)|isahc::\\w+|attohttpc::\\w+|minreq::\\w+|TcpStream::connect|(?:client|http_client|http|cli|reqwest_client)\\.(?:get|post|put|delete|patch|head|request)|Url::parse|hyper::Uri::from_str|Uri::from_str') ,
    when: (c) => !/^(?:Url::parse|hyper::Uri::from_str|Uri::from_str)$/.test(c.callee) }),
  call({ ...SSRF, id: 'ssrf-jvm', langs: JVM, what: ssrfWhat, args: [0], verify: ssrfVerify, chain: true,
    callee: /^(?:URI\.create|URL|URI|HttpGet|HttpPost|HttpPut|HttpDelete|HttpHead|HttpPatch|HttpRequest\.newBuilder|Jsoup\.connect|Socket|InetAddress\.getByName|DriverManager\.getConnection|(?:rest|restTemplate|template|webClient|client)\.(?:getForObject|getForEntity|postForObject|postForEntity|exchange|execute|put|delete|headForHeaders|optionsForAllow|uri|get|post)|Request\.Builder\(\)\.url|(?:request|req|builder|newBuilder|Builder)\.url|WebClient\.create|RestClient\.create|Unirest\.(?:get|post|put|delete)|HttpClient\.newHttpClient\(\)\.send)$/,
    when: (c) => !/^(?:URI|URL)$/.test(c.callee) || c.isNew }),
  call({ ...SSRF, id: 'ssrf-csharp', langs: ['csharp'], what: ssrfWhat, args: [0], verify: ssrfVerify,
    callee: /^(?:\w+\.)*(?:_?client|_?httpClient|_?http|_?webClient|_?wc|HttpClient|WebClient|_?restClient|_?httpclient)\.(?:Get\w*Async|Post\w*Async|PutAsync|DeleteAsync|PatchAsync|SendAsync|Download\w+|Open\w*Read\w*|Upload\w+|GetFromJsonAsync|PostAsJsonAsync)$|^(?:WebRequest|HttpWebRequest|FtpWebRequest)\.Create(?:Http)?$|^(?:Uri|HttpRequestMessage|RestClient|RestRequest|TcpClient|WebSocket)$/,
    when: (c) => !/^(?:Uri|HttpRequestMessage|RestClient|RestRequest|TcpClient|WebSocket)$/.test(c.callee) || c.isNew }),
  call({ ...SSRF, id: 'ssrf-dart', langs: ['dart'], what: ssrfWhat, args: [0], verify: ssrfVerify, callee: /^(?:http|dio|client|_client|_dio|Dio\(\)|httpClient|_httpClient|https)\.(?:get|post|put|delete|patch|head|read|readBytes|send|getUrl|postUrl|openUrl|fetch|download|getUri|postUri|requestUri)$/ }),
  call({ ...SSRF, id: 'ssrf-swift', langs: ['swift'], what: ssrfWhat, args: 'any', verify: ssrfVerify,
    callee: /^(?:URLSession\.shared\.(?:dataTask|downloadTask|uploadTask|data|download|upload)|URLRequest|AF\.(?:request|download|upload|streamRequest)|Alamofire\.(?:request|download|upload)|(?:\w*[sS]ession)\.(?:dataTask|downloadTask|uploadTask|data|download|request))$|^(?:Data|String|NSData|NSString|NSURLRequest)$/,
    when: (c) => !/^(?:Data|String|NSData|NSString)$/.test(c.callee) || /contentsOf\s*:/.test(c.text) }),
  call({ ...SSRF, id: 'ssrf-c', langs: ['c'], what: ssrfWhat, args: 'any', callee: x('curl_easy_setopt|curl_url_set|getaddrinfo|gethostbyname|inet_addr|inet_pton|connect|curl_easy_init'), when: (c) => c.callee !== 'curl_easy_setopt' || /CURLOPT_URL/.test(c.text) }),
];

// ═══ XXE ═════════════════════════════════════════════════════════════════════
const XXE = { cls: 'XXE injection', group: 'xml', sev: 'high', fix: 'Disable DTDs and external entity resolution on the XML parser (disallow-doctype-decl, XmlResolver=null / DtdProcessing.Prohibit, resolve_entities=False), or use a hardened library (defusedxml).' };
const xxeWhat = 'parses it as XML with a parser that resolves external entities';
const SAFE_XML = /disallow-doctype-decl|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|ACCESS_EXTERNAL_SCHEMA|ACCESS_EXTERNAL_STYLESHEET|IS_SUPPORTING_EXTERNAL_ENTITIES|external-general-entities|external-parameter-entities|setExpandEntityReferences\s*\(\s*false|setXIncludeAware\s*\(\s*false|defusedxml|resolve_entities\s*=\s*False|forbid_dtd|forbid_entities|DtdProcessing\s*=\s*DtdProcessing\.(?:Prohibit|Ignore)|XmlResolver\s*=\s*null|ProhibitDtd\s*=\s*true|setFeature\s*\(\s*["'][^"']*(?:disallow-doctype|external-general)/;
const xxeVerify = (cand, flow) => (inFile(flow, SAFE_XML) ? { valid: false, reason: 'the XML parser is configured to disable DTDs / external entities elsewhere in this file' } : null);

const XXE_RULES = [
  call({ ...XXE, id: 'xxe-python', langs: ['python'], what: xxeWhat, args: [0], verify: xxeVerify, callee: x('(?:lxml\\.)?etree\\.(?:parse|fromstring|XML|iterparse|fromstringlist|parseid|HTML)|(?:xml\\.)?sax\\.(?:parse|parseString)|xmltodict\\.parse|minidom\\.parse(?:String)?|xml\\.dom\\.minidom\\.parse(?:String)?|pulldom\\.parse(?:String)?|objectify\\.fromstring|objectify\\.parse'), when: (c, f) => /lxml|etree/.test(f.ctx.literal + f.chunk.code) || /minidom|sax|pulldom/.test(c.callee) }),
  call({ ...XXE, id: 'xxe-js', langs: ['js'], what: xxeWhat, args: [0], verify: xxeVerify, callee: x('(?:libxmljs2?\\.)?parseXml(?:String)?|libxmljs\\.parseXmlString|parseXmlString'), when: (c) => /noent\s*:\s*true/.test(c.lit) }),
  call({ ...XXE, id: 'xxe-php', langs: ['php'], what: xxeWhat, args: [0], verify: xxeVerify, callee: x('simplexml_load_string|simplexml_load_file|SimpleXMLElement|\\$\\w+\\.loadXML|\\$\\w+\\.load|xml_parse|DOMDocument\\.loadXML|\\$\\w+\\.xml'), when: (c) => /LIBXML_(?:NOENT|DTDLOAD|DTDATTR|DTDVALID)/.test(c.text) }),
  call({ ...XXE, id: 'xxe-ruby', langs: ['ruby'], what: xxeWhat, args: [0], verify: xxeVerify, callee: x('Nokogiri::XML(?:\\.parse|::Document\\.parse|::Document\\.from_memory)?|Nokogiri\\.XML|LibXML::XML::Document\\.string|Nokogiri::XML::Reader'), when: (c) => /noent|NOENT|dtdload|DTDLOAD/.test(c.text) }),
  call({ ...XXE, id: 'xxe-jvm', langs: JVM, what: xxeWhat, args: 'any', verify: xxeVerify, chain: true,
    callee: /^(?:DocumentBuilderFactory\.newInstance\(\)\.newDocumentBuilder\(\)|\w*[bB]uilder\w*|\w*[pP]arser\w*|\w*[rR]eader\w*|\w*[fF]actory\w*|\w*[uU]nmarshaller\w*|\w*[tT]ransformer\w*|\w*[vV]alidator\w*|SAXBuilder\(\)|SAXReader\(\)|dbf|db)\.(?:parse|unmarshal|build|read|transform|createXMLStreamReader|createXMLEventReader|validate)$/ }),
  call({ ...XXE, id: 'xxe-csharp', langs: ['csharp'], what: xxeWhat, args: [0],
    callee: x('(?:\\w+\\.)?(?:LoadXml|Load)|XmlTextReader|XmlReader\\.Create|XDocument\\.(?:Parse|Load)|\\w+\\.ReadXml'),
    when: (c, f) => /DtdProcessing\s*=\s*DtdProcessing\.Parse|XmlUrlResolver|ProhibitDtd\s*=\s*false|XmlResolver\s*=\s*new\s+XmlUrlResolver/.test(f.ctx.literal) || (c.callee === 'XmlTextReader' && c.isNew && !/DtdProcessing|XmlResolver/.test(f.ctx.literal)) }),
  call({ ...XXE, id: 'xxe-c', langs: ['c'], what: xxeWhat, args: 'any', callee: x('xmlReadMemory|xmlReadFile|xmlParseMemory|xmlParseFile|xmlCtxtReadMemory|xmlCtxtReadFile|xmlReadDoc|xmlParseDoc'), when: (c) => /XML_PARSE_NOENT|XML_PARSE_DTDLOAD|XML_PARSE_DTDATTR/.test(c.text) }),
];

// ═══ NoSQL injection ═════════════════════════════════════════════════════════
const NOSQL = { cls: 'NoSQL injection', group: 'nosql', fileGate: /\b(?:mongo\w*|mongoose|nedb|pouchdb|lowdb|lokijs|couch\w*|firestore|dynamodb|cosmos\w*|rethinkdb|arangojs|redis|BsonDocument|MongoClient|MongoCollection|bson)\b/i, sev: 'high', fix: 'Never pass request objects into query filters. Coerce each value to the expected primitive (String(x), Number(x)), validate with a schema, and reject keys that start with "$"; avoid $where and server-side JS.' };
const nosqlWhat = 'uses it as a NoSQL query filter, so operators such as {"$ne": ...} can be injected';
const NOSQL_RULES = [
  call({ ...NOSQL, id: 'nosql-js', langs: ['js'], what: nosqlWhat, args: [0], argUnless: FN_VALUE,
    callee: m('find|findOne|findOneAndUpdate|findOneAndDelete|findOneAndReplace|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|distinct|replaceOne|findById|exists|where') ,
    when: (c) => !/^(?:Array|arr|array|list|items|rows|results|users\.data|data)\./.test(c.callee) }),
  call({ ...NOSQL, id: 'nosql-python', langs: ['python'], what: nosqlWhat, args: [0],
    callee: /(?:^|\.)(?:find_one|find_one_and_update|find_one_and_delete|find_one_and_replace|update_one|update_many|delete_one|delete_many|count_documents|aggregate|distinct|replace_one)$|(?:collection|col|coll|db|mongo|\w+_collection|\w+_col)\.find$/ }),
  call({ ...NOSQL, id: 'nosql-php', langs: ['php'], what: nosqlWhat, args: [0],
    callee: /(?:^|[.:])(?:findOne|updateOne|updateMany|deleteOne|deleteMany|countDocuments|aggregate|distinct|findOneAndUpdate|replaceOne)$|(?:collection|col|coll)\.find$/ }),
  call({ ...NOSQL, id: 'nosql-jvm', langs: JVM, what: 'builds a MongoDB query/JavaScript ($where) from it', args: 'any',
    callee: x('BasicDBObject|BasicQuery|Document|Filters\\.where|(?:\\w+\\.)?(?:parse)|Query\\.query|BasicDBObjectBuilder\\.start'),
    when: (c) => (/^(?:BasicDBObject|Document)$/.test(c.callee) && /\$where/.test(c.lit)) || /^(?:BasicQuery|Filters\.where)$/.test(c.callee) || (c.callee === 'Document.parse') }),
  call({ ...NOSQL, id: 'nosql-csharp', langs: ['csharp'], what: nosqlWhat, args: [0], callee: x('BsonDocument\\.Parse|BsonSerializer\\.Deserialize|FilterDefinition<[\\w.]+>\\.op_Implicit|new\\.JsonFilterDefinition|JsonFilterDefinition|\\w*\\.Find|\\w*\\.FindSync|\\w*\\.FindAsync|\\w*\\.DeleteOne|\\w*\\.DeleteMany|\\w*\\.UpdateOne|\\w*\\.UpdateMany|\\w*\\.CountDocuments'),
    when: (c) => /BsonDocument\.Parse|BsonSerializer|JsonFilterDefinition/.test(c.callee) || /\$where|\bBson\b/.test(c.lit) }),
  call({ ...NOSQL, id: 'nosql-go', langs: ['go'], what: 'builds a MongoDB filter containing a $where JavaScript expression from it', args: 'any', callee: x('bson\\.(?:M|D|E)'), when: (c) => /\$where/.test(c.lit) }),
];

// ═══ LDAP / XPath injection ═════════════════════════════════════════════════
const LDAP = { cls: 'LDAP / XPath injection', group: 'ldap', fileGate: /ldap|xpath|DirContext|DirectorySearcher|SearchControls|XPathFactory|XPathExpression|SelectNodes|SelectSingleNode|nokogiri|simplexml|DOMXPath|lxml|etree|antchfx|xmlquery|xmldom|libxmljs/i, sev: 'high', fix: 'Escape filter values with the library helper (ldap3 escape_filter_chars, Encode.forLdap, XPath variable binding) or use parameterised XPath; never concatenate input into a filter or expression.' };
const ldapWhat = 'builds an LDAP filter / XPath expression from it';
const LDAP_RULES = [
  call({ ...LDAP, id: 'ldap-python', langs: ['python'], what: ldapWhat, args: 'any', callee: /(?:^|\.)(?:search_s|search_ext_s|search_st|search_ext)$|^(?:ldap\w*|conn\w*|connection|server|client|l)\.search$|(?:^|\.)xpath$|(?:^|\.)XPath$/ }),
  call({ ...LDAP, id: 'ldap-js', langs: ['js'], what: ldapWhat, args: 'any', callee: /^(?:ldap\w*|client|ldapClient|ldapjs)\.(?:search|bind)$|^xpath\.(?:select|select1|evaluate|parse)$|^document\.evaluate$|^(?:\w+\.)?evaluate$/, when: (c, f) => !/^(?:\w+\.)?evaluate$/.test(c.callee) || /xpath|XPath/i.test(c.text + f.ctx.literal.slice(0, 600)) }),
  call({ ...LDAP, id: 'ldap-php', langs: ['php'], what: ldapWhat, args: 'any', callee: x('ldap_search|ldap_list|ldap_read|ldap_bind|\\$\\w*(?:xpath|xp|simplexml|xml)\\w*\\.(?:query|evaluate|xpath)|\\$\\w+\\.xpath') }),
  call({ ...LDAP, id: 'ldap-jvm', langs: JVM, what: ldapWhat, args: 'any', callee: /^(?:ctx|context|dirContext|ldapContext|ldapTemplate|\w*[lL]dap\w*|\w*[dD]irContext\w*)\.(?:search|searchForObject|authenticate|lookup|list)$|^(?:\w*[xX][pP]ath\w*)\.(?:compile|evaluate)$|^(?:LdapQueryBuilder\.query\(\)\.filter|LdapQuery|SearchControls|FilterBuilder\.\w+)$/ }),
  call({ ...LDAP, id: 'ldap-csharp', langs: ['csharp'], what: ldapWhat, args: [0], callee: x('(?:\\w+\\.)?(?:SelectNodes|SelectSingleNode|XPathSelectElements|XPathSelectElement|XPathEvaluate|XPathExpression\\.Compile|DirectorySearcher)') }),
  assign({ ...LDAP, id: 'ldap-csharp-filter', langs: ['csharp'], what: ldapWhat, lhs: /\.Filter$/ }),
  call({ ...LDAP, id: 'ldap-go', langs: ['go'], what: ldapWhat, args: 'any', callee: x('ldap\\.NewSearchRequest|(?:xpath|xmlquery|htmlquery)\\.(?:Compile|MustCompile|Find|FindOne|Query|QueryAll)|ldap\\.EscapeFilter') , when: (c) => !/EscapeFilter/.test(c.callee) }),
  call({ ...LDAP, id: 'ldap-ruby', langs: ['ruby'], what: ldapWhat, args: 'any', callee: x('Net::LDAP::Filter\\.construct|(?:\\w+\\.)?(?:xpath|at_xpath)|(?:ldap|conn)\\.search') }),
  call({ ...LDAP, id: 'ldap-rust', langs: ['rust'], what: ldapWhat, args: 'any', callee: x('(?:sxd_xpath::)?evaluate_xpath|(?:ldap|conn|ldap3)\\.(?:search|streaming_search)') }),
];

// ═══ HTTP header injection ═══════════════════════════════════════════════════
const HDR = { cls: 'HTTP header injection / response splitting', group: 'header', sev: 'medium', conf: 'low', fix: 'Reject CR/LF in any value placed in a header, or encode it; prefer framework APIs that validate header values.' };
const hdrWhat = 'puts it into an HTTP response header, where CR/LF can split the response';
const HEADER_RULES = [
  call({ ...HDR, id: 'hdr-js', langs: ['js'], what: hdrWhat, args: 'any', chain: true, callee: /^(?:res|response|reply|ctx|resp)(?:\.\w+\(\))*\.(?:setHeader|set|header|append|writeHead|setHeaders)$/, argsFn: (c) => c.args.map((_, i) => i).filter(i => i > 0) }),
  assign({ ...HDR, id: 'hdr-py-assign', langs: ['python', 'ruby', 'csharp'], what: hdrWhat, lhs: /(?:headers|Headers|response|resp|res)\s*\[/ }),
  call({ ...HDR, id: 'hdr-py', langs: ['python'], what: hdrWhat, args: 'any', callee: x('(?:\\w+\\.)?headers\\.(?:add|set|setdefault|append|update)|self\\.set_header|self\\.add_header|(?:\\w+\\.)?set_header'), argsFn: (c) => c.args.map((_, i) => i).filter(i => i > 0) }),
  call({ ...HDR, id: 'hdr-php', langs: ['php'], what: hdrWhat, args: [0], callee: x('header'), when: (c) => !/Location\s*:/i.test(c.lit) }),
  call({ ...HDR, id: 'hdr-ruby', langs: ['ruby'], what: hdrWhat, args: [1], callee: m('set_header|add_header|response\\.set_header') }),
  call({ ...HDR, id: 'hdr-go', langs: ['go'], what: hdrWhat, args: [1], chain: true, verify: (cand, flow) => /\bHeader\(\)\s*\.\s*(?:Set|Add)\s*$/.test(flow.ctx.code.slice(Math.max(0, (cand.call?.start ?? 0) - 24), (cand.call?.start ?? 0) + (cand.call?.callee || '').length)) ? { valid: false, reason: 'net/http replaces CR/LF in header values when the response is written, so response splitting is not possible through Header().Set/Add' } : null, callee: /(?:^|\.)Header\(\)\.(?:Set|Add)$|^(?:c|ctx)\.(?:Header|Set|Response\(\)\.Header\(\)\.Set)$|^(?:c|ctx)\.Response\(\)\.Header\(\)\.(?:Set|Add)$/ }),
  call({ ...HDR, id: 'hdr-jvm', langs: JVM, what: hdrWhat, args: [1], callee: m('setHeader|addHeader|header|putSingle') }),
  call({ ...HDR, id: 'hdr-csharp', langs: ['csharp'], what: hdrWhat, args: [1], callee: x('(?:HttpContext\\.)?Response\\.(?:Headers\\.Add|Headers\\.Append|AppendHeader|AddHeader|Headers\\.TryAdd)') }),
  call({ ...HDR, id: 'hdr-rust', langs: ['rust'], what: hdrWhat, args: 'any', callee: m('insert_header|append_header|header'), when: (c) => /\(\s*["'a-zA-Z:_]+/.test(c.text) && !/\.get\b/.test(c.callee) }),
];

// ═══ Log injection ═══════════════════════════════════════════════════════════
const LOG = { cls: 'log injection / forged log entries', group: 'log', sev: 'low', conf: 'low', srcOnly: true, fix: 'Strip or encode CR/LF (and other control characters) from values before logging them, or use structured logging (JSON) so values cannot create new log lines.' };
const logWhat = 'writes it into a log message, where line breaks can forge entries';
const LOG_OBJ = String.raw`(?:logger|log|LOG|LOGGER|_logger|_log|Log|Logger|logging|console|app\.logger|Rails\.logger|self\.logger|self\.log|this\.logger|this\.log|slog|winston|pino|bunyan|fastify\.log|request\.log|req\.log|zap\.S\(\)|sugar|syslog)`;
const LOG_RULES = [
  call({ ...LOG, id: 'log-generic', langs: ['js', 'python', 'ruby', 'java', 'kotlin', 'csharp', 'dart', 'swift'], what: logWhat, args: [0],
    callee: new RegExp(`^(?:${LOG_OBJ}\\.)(?:info|debug|warn|warning|error|critical|fatal|trace|log|notice|exception|information|verbose|Information|Warning|Error|Debug|Critical|Trace|LogInformation|LogWarning|LogError|LogDebug|LogCritical|LogTrace|Log|d|i|w|e|v|wtf)$`),
    when: (c, f) => f.webContext !== false }),
  call({ ...LOG, id: 'log-go', langs: ['go'], what: logWhat, args: 'any', callee: /^(?:log|logger|l|slog|zap\.S\(\)|sugar)\.(?:Print|Println|Printf|Fatal|Fatalf|Fatalln|Panic|Panicf|Panicln|Info|Infof|Infow|Warn|Warnf|Error|Errorf|Debug|Debugf)$/, when: (c) => /^(?:Print|Println|Fatal|Fatalln|Panic|Panicln|Info|Warn|Error|Debug)$/.test(c.name) || /f$/.test(c.name) }),
  call({ ...LOG, id: 'log-php', langs: ['php'], what: logWhat, args: [0], callee: x('error_log|syslog|\\$(?:this\\.)?(?:logger|log)\\.(?:info|debug|warning|error|critical|notice|alert|emergency|log)|Log::(?:info|debug|warning|error|critical|notice|alert|emergency|log)') }),
  call({ ...LOG, id: 'log-rust', langs: ['rust'], what: logWhat, args: [0], callee: x('(?:log::|tracing::)?(?:info|warn|error|debug|trace)!') }),
  call({ ...LOG, id: 'log-c', langs: ['c'], what: logWhat, args: 'any', callee: x('syslog|vsyslog|fprintf|g_warning|g_message|g_critical|g_error'), when: (c) => c.callee !== 'fprintf' || /^(?:stderr|logfile|log|fp_log)\b/.test(c.args[0]?.text || ''), argsFn: (c) => c.callee === 'syslog' ? [1] : c.callee === 'fprintf' ? [1] : [0] }),
];

// ═══ Host header injection ═══════════════════════════════════════════════════
const HOSTSRC = {
  js: /\b(?:req|request)\s*\.\s*(?:hostname|host|get\s*\(\s*['"]host['"]\s*\)|headers\s*\[\s*['"]host['"]\s*\]|headers\s*\.\s*host|headers\s*\[\s*['"]x-forwarded-host['"]\s*\]|header\s*\(\s*['"]host['"]\s*\))/i,
  python: /\brequest\s*\.\s*(?:host|host_url|META\s*\[\s*['"]HTTP_HOST['"]\s*\]|headers\s*\[\s*['"](?:Host|X-Forwarded-Host)['"]\s*\]|headers\s*\.\s*get\s*\(\s*['"](?:Host|X-Forwarded-Host)['"]|get_host\s*\(|build_absolute_uri\s*\()/,
  php: /\$_SERVER\s*\[\s*['"](?:HTTP_HOST|HTTP_X_FORWARDED_HOST|SERVER_NAME)['"]\s*\]/,
  ruby: /\brequest\s*\.\s*(?:host|host_with_port|headers\s*\[\s*['"](?:Host|X-Forwarded-Host)['"]\s*\]|env\s*\[\s*['"]HTTP_HOST['"]\s*\])/,
  go: /\b(?:r|req|request)\s*\.\s*(?:Host|Header\s*\.\s*Get\s*\(\s*["'](?:Host|X-Forwarded-Host)["']\s*\))/,
  rust: /\b(?:req|request)\s*\.\s*(?:connection_info\s*\(\s*\)\s*\.\s*host|headers\s*\(\s*\)\s*\.\s*get\s*\(\s*["'](?:host|x-forwarded-host)["'])/i,
  java: /\b(?:request|req)\s*\.\s*(?:getServerName|getHeader\s*\(\s*["'](?:Host|X-Forwarded-Host)["']\s*\)|getRequestURL)\s*\(/,
  kotlin: /\b(?:request|req|call\.request)\s*\.\s*(?:getServerName|getHeader\s*\(\s*["'](?:Host|X-Forwarded-Host)["']\s*\)|host\s*\(|origin\.host|headers\s*\[\s*["'](?:Host|X-Forwarded-Host)["']\s*\])/,
  csharp: /\bRequest\s*\.\s*(?:Host|Headers\s*\[\s*["'](?:Host|X-Forwarded-Host)["']\s*\]|Url\s*\.\s*(?:Host|Authority))/,
};
const HOST_RULES = [custom({ cls: 'host header injection / cache poisoning', id: 'host-header', langs: Object.keys(HOSTSRC), sev: 'medium', conf: 'low', group: 'host',
  fix: 'Do not build absolute URLs (reset links, redirects, emails) from the Host / X-Forwarded-Host header. Use a configured canonical base URL or an allowlist of trusted hosts.',
  run(flow, emit) {
    const re = HOSTSRC[flow.family]; if (!re) return;
    for (const ll of flow.ctx.logical) {
      const mm = re.exec(ll.lit); if (!mm) continue;
      if (flow.ctx.code[ll.start + mm.index] !== flow.ctx.literal[ll.start + mm.index]) continue;          // inside a string / comment
      if (!/(?:https?:\/\/|\/\/|link|url|href|redirect|location|reset|verify|confirm|mail|callback|base|origin)/i.test(ll.lit)) continue;
      if (/^\s*(?:if|while|assert|unless)\b/.test(ll.text)) continue;
      emit(ll.start + mm.index, { desc: `The ${mm[0].replace(/\s+/g, '')} value (attacker-controlled Host header) is used to build a URL, enabling password-reset poisoning and cache poisoning.`, flowInfo: { kind: 'src', origin: mm[0].replace(/\s+/g, '').slice(0, 60) } });
    }
  } })];

// ═══ EL / SpEL / OGNL injection ═════════════════════════════════════════════
const EL = { cls: 'Expression Language (EL) / SpEL / OGNL injection', group: 'el', sev: 'critical', fix: 'Never parse input as an expression. Use SimpleEvaluationContext (read-only) for SpEL, bind values as variables, and keep user data out of expression strings.' };
const EL_RULES = [
  call({ ...EL, id: 'el-jvm', langs: JVM, what: 'evaluates it as an expression-language expression', args: 'any', chain: true,
    callee: /(?:^|\.)(?:\w*[pP]arser\w*|SpelExpressionParser\(\)|spel)\.parseExpression$|^(?:Ognl|OgnlUtil|ognl\.Ognl)\.(?:getValue|setValue|parseExpression)$|(?:^|\.)createValueExpression$|(?:^|\.)createMethodExpression$|^(?:MVEL|Mvel)\.(?:eval|executeExpression|compileExpression)$|^(?:\w+\.)?(?:evaluateExpression)$|^(?:ExpressionFactory)\.createValueExpression$|^(?:ValueStack|stack)\.(?:findValue|setValue)$|^(?:TextParseUtil)\.translateVariables$/ }),
];

// ═══ LFI / RFI ═══════════════════════════════════════════════════════════════
const LFI = { cls: 'local / remote file inclusion (LFI/RFI)', group: 'path', sev: 'critical', fix: 'Never build include/require paths from input. Map input to an allowlist of known files, or resolve and pin the path to a fixed directory; keep allow_url_include off.' };
const LFI_RULES = [
  call({ ...LFI, id: 'lfi-php', langs: ['php'], what: 'includes and executes the file it names', args: 'any', callee: x('include|include_once|require|require_once') }),
];

// ═══ Unsafe file upload ══════════════════════════════════════════════════════
const UP = { cls: 'unsafe file upload', group: 'path', sev: 'high', fix: 'Do not trust the client file name or type: generate a random server-side name, enforce an extension/MIME allowlist (and verify content), store uploads outside the web root, and never make them executable.' };
const upWhat = 'saves an upload under the client-supplied file name without visible validation';
const FILENAME_PROP = /\.(?:filename|originalname|originalFilename|original_filename|name|Filename|FileName|fileName|getOriginalFilename|getSubmittedFileName|file_name)\b|\[\s*['"]name['"]\s*\]|getOriginalFilename\s*\(|getSubmittedFileName\s*\(|original_filename/;
const UPLOAD_CHECK = /allowed_file|ALLOWED_EXTENSIONS|allowedExtensions|allowed_extensions|whitelist|allowlist|\.endswith\s*\(|\.endsWith\s*\(|\.endswith|extname|mimetype|content_?type|ContentType|getContentType|fileFilter|imghdr|magic|mime_content_type|finfo|guessContentType|Path\.GetExtension|\.Extension\b|getExtension|FilenameUtils/i;
const upVerify = (cand, flow) => (UPLOAD_CHECK.test(flow.ctx.literal) ? { valid: true, conf: 'low' } : null);
const UP_RULES = [
  call({ ...UP, id: 'upload-py', langs: ['python'], what: upWhat, args: [0], callee: m('save'), when: (c) => FILENAME_PROP.test(c.args[0]?.lit || '') || /secure_filename/.test(c.text) === false && /filename/.test(c.args[0]?.lit || ''), verify: upVerify }),
  call({ ...UP, id: 'upload-js', langs: ['js'], what: upWhat, args: 'any', callee: m('mv|writeFile|writeFileSync|createWriteStream|rename|renameSync|copyFile|copyFileSync|pipe'), when: (c) => /\.(?:originalname|originalFilename|name|filename)\b/.test(c.text), verify: upVerify }),
  call({ ...UP, id: 'upload-php', langs: ['php'], what: upWhat, args: [1], callee: x('move_uploaded_file'), when: (c) => /\[\s*['"]name['"]\s*\]/.test(c.lit) || /basename/.test(c.lit) === false, verify: upVerify }),
  call({ ...UP, id: 'upload-ruby', langs: ['ruby'], what: upWhat, args: 'any', callee: x('File\\.(?:open|write|binwrite|new|rename)|FileUtils\\.(?:mv|cp|copy|move)|IO\\.binwrite'), when: (c) => /original_filename|\.filename/.test(c.text), verify: upVerify }),
  call({ ...UP, id: 'upload-jvm', langs: JVM, what: upWhat, args: 'any', callee: x('(?:\\w+\\.)?transferTo|Files\\.(?:copy|write|move)|File|FileOutputStream|Paths\\.get|Path\\.of'), when: (c) => /getOriginalFilename|getSubmittedFileName|originalFilename/.test(c.text), verify: upVerify }),
  call({ ...UP, id: 'upload-go', langs: ['go'], what: upWhat, args: 'any', callee: x('(?:c|ctx|e)\\.SaveUploadedFile|os\\.(?:Create|OpenFile)|ioutil\\.WriteFile|os\\.WriteFile|filepath\\.Join|c\\.FormFile'), when: (c) => /\.Filename\b/.test(c.text) && !/^c\.FormFile$/.test(c.callee), verify: upVerify }),
  call({ ...UP, id: 'upload-csharp', langs: ['csharp'], what: upWhat, args: 'any', callee: x('(?:\\w+\\.)?SaveAs|FileStream|File\\.(?:Create|OpenWrite|WriteAllBytes)|Path\\.Combine'), when: (c) => /\.FileName\b|\.Name\b/.test(c.text) && /Files|FormFile|IFormFile|file\b/i.test(c.text), verify: upVerify }),
  call({ ...UP, id: 'upload-rust', langs: ['rust'], what: upWhat, args: 'any', callee: x('(?:std::)?fs::(?:write|File::create)|File::create|PathBuf::from|Path::new|\\w+\\.join'), when: (c) => /\.file_name\(\)|filename|content_disposition/.test(c.text), verify: upVerify }),
];

// ═══ GraphQL ═════════════════════════════════════════════════════════════════
const GQL = { cls: 'GraphQL injection / query abuse', group: 'gql', fileGate: /graphql|\bgql\b|apollo|\bhasura\b|urql|relay/i, sev: 'medium', fix: 'Pass input only through GraphQL variables, never by concatenating it into the query document; disable introspection/GraphiQL in production and enforce query depth/cost limits.' };
const GQL_RULES = [
  call({ ...GQL, id: 'gql-inject-js', langs: ['js'], what: 'executes a GraphQL document built from it', args: [0], callee: x('graphql|graphqlSync|(?:\\w*[cC]lient|\\w*[aA]pollo\\w*)\\.(?:request|query|mutate|rawRequest)|request|rawRequest|execute') , when: (c) => !c.viaDot || /\./.test(c.callee) }),
  call({ ...GQL, id: 'gql-inject-py', langs: ['python'], what: 'executes a GraphQL document built from it', args: [0], callee: x('graphql_sync|graphql|(?:\\w*schema\\w*|\\w*client\\w*)\\.(?:execute|execute_async|query)') }),
  call({ ...GQL, id: 'gql-inject-go', langs: ['go'], what: 'executes a GraphQL document built from it', args: 'any', callee: x('graphql\\.Do|(?:\\w*client\\w*)\\.(?:Query|Mutate|Exec)'), when: (c) => c.callee === 'graphql.Do' }),
  call({ ...GQL, id: 'gql-inject-jvm', langs: JVM, what: 'executes a GraphQL document built from it', args: [0], callee: m('execute|executeAsync'), when: (c, f) => /graphql|GraphQL/.test(c.callee + f.ctx.literal.slice(0, 1500)) }),
  call({ ...GQL, id: 'gql-inject-csharp', langs: ['csharp'], what: 'executes a GraphQL document built from it', args: 'any', callee: m('SendQueryAsync|SendMutationAsync|ExecuteAsync'), when: (c, f) => /GraphQL/.test(f.ctx.literal.slice(0, 2000)) }),
  call({ ...GQL, id: 'gql-inject-ruby', langs: ['ruby'], what: 'executes a GraphQL document built from it', args: [0], callee: m('execute|query'), when: (c, f) => /Schema|GraphQL/.test(c.callee + f.ctx.literal.slice(0, 1500)) && /Schema\.execute|GraphQL/.test(c.callee + f.ctx.literal) }),
  pattern({ ...GQL, id: 'gql-introspection', langs: ['js'], re: /\b(?:introspection|playground|graphiql)\s*:\s*true\b/, noTaint: true, conf: 'medium', sev: 'low', title: 'GraphQL introspection / playground enabled', what: 'enables GraphQL introspection or an interactive IDE', desc: 'GraphQL introspection / interactive IDE is explicitly enabled, which exposes the full schema to attackers and eases query abuse. Disable it in production.' }),
  pattern({ ...GQL, id: 'gql-graphiql-py', langs: ['python'], re: /\bgraphiql\s*=\s*True\b/, noTaint: true, conf: 'medium', sev: 'low', title: 'GraphQL introspection / playground enabled', desc: 'GraphiQL is enabled, exposing the full schema; disable it in production.' }),
];

// ═══ Prototype pollution (JS) ════════════════════════════════════════════════
const PP = { cls: 'prototype pollution', group: 'proto', sev: 'high', fix: 'Reject "__proto__", "constructor" and "prototype" keys, build merge targets with Object.create(null) or a Map, and use a patched merge library (lodash >= 4.17.21).' };
const PP_RULES = [
  call({ ...PP, id: 'pp-merge', langs: ['js'], what: 'recursively merges it into an object, allowing __proto__ keys to modify Object.prototype', args: 'any',
    callee: x('(?:_|lodash|\\$|jQuery)\\.(?:merge|mergeWith|defaultsDeep|set|setWith|zipObjectDeep|extend|assignDeep)|merge|deepmerge|deepMerge|defaultsDeep|mixin|(?:\\w+\\.)?mergeDeep|(?:\\w+\\.)?deepExtend|(?:\\w+\\.)?deepAssign|(?:\\w+\\.)?extend|setValue|set-value|dset|dot\\.set|objectPath\\.set'),
    when: (c) => !/^(?:\$|jQuery)\.extend$/.test(c.callee) || /^\s*true\b/.test(c.args[0]?.lit || '') }),
  custom({ ...PP, id: 'pp-assign', langs: ['js'],
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        const mm = /^\s*([\w$.\[\]]+?)\[\s*([A-Za-z_$][\w$]*)\s*\](?:\s*\[\s*([A-Za-z_$][\w$]*)\s*\])?\s*=[^=>]/.exec(ll.text);
        if (!mm) continue;
        const key = flow.vars.get(mm[2]); if (!key || !key.contribs.some(c => c.kind === 'src' && !isCleared(c, 'proto'))) continue;
        const rhs = ll.text.slice(ll.text.indexOf('=') + 1);
        if (!/\[|\.|\(/.test(rhs) && !flow.vars.has(rhs.trim().replace(/;$/, ''))) continue;
        emit(ll.start, { desc: `An object property is written with the attacker-controlled key "${mm[2]}" (from ${key.contribs[0].origin}); a key of "__proto__" or "constructor" pollutes Object.prototype.`, flowInfo: { kind: 'src', origin: key.contribs[0].origin } });
      }
    },
    verify: (cand, flow) => (/__proto__|hasOwnProperty|hasOwn\s*\(|Object\.create\(\s*null\s*\)|new\s+Map\b|=== ?['"]constructor['"]|key\s*===?\s*['"]__proto__/.test(flow.ctx.literal) ? { valid: false, reason: 'the key is checked against __proto__/own-property, or the target is a null-prototype object / Map' } : null) }),
];

// ── client-side template engines: browser scripts and the inline <script> blocks of HTML files ───────────────
XSS_RULES.push(
  // AngularJS evaluates a string given to $compile / $parse / $interpolate / $eval / $watch / $apply as an Angular expression or template.
  call({ ...STI, id: 'xss-js-angularjs-eval', langs: ['js'], args: [0], conf: 'medium',
    what: 'evaluates it as an AngularJS expression or template, so the input can run script (client-side template injection)',
    callee: /^\$(?:compile|parse|interpolate)$|(?:^|\.)\$(?:eval|evalAsync|watch|watchCollection|apply|applyAsync)$/ }),
  call({ ...XSS, id: 'xss-js-angularjs-trust', langs: ['js'], args: [0],
    what: 'marks it as trusted HTML / JS / URL, bypassing AngularJS strict contextual escaping',
    callee: /(?:^|\.)\$sce\.trustAs(?:Html|Js|Url|ResourceUrl|Css)?$/ }),
  // jQuery: a string that starts with '<' (or, before 1.9, merely contains one) is parsed as HTML.
  call({ ...XSS, id: 'xss-js-jquery-selector', langs: ['js'], args: [0], conf: 'low', sev: 'medium',
    what: 'is passed to jQuery as a selector, and jQuery parses a string that looks like markup as HTML',
    callee: /^(?:\$|jQuery)$/, when: (c) => !c.viaDot }),
  // Vue: `template:` is compiled at run time (new Vue / createApp / component / extend), so its value is template source.
  custom({ ...STI, id: 'xss-js-vue-template', langs: ['js'], conf: 'medium',
    run(flow, emit) {
      for (const c of flow.ctx.calls) {
        if (!/^(?:Vue|Vue\.extend|Vue\.component|Vue\.createApp|createApp|defineComponent|\w+\.component|\w+\.mixin)$/.test(c.callee)) continue;
        const a = c.args.find((arg) => /\btemplate\s*:/.test(arg.text)); if (!a) continue;
        const mm = /\btemplate\s*:\s*([\s\S]*?)\s*(?:,\s*[A-Za-z_$][\w$]*\s*:|\}\s*$)/.exec(a.text); if (!mm || !mm[1]) continue;
        const from = a.text.indexOf(mm[1], mm.index);
        const st = flow.state(mm[1], a.lit.slice(from, from + mm[1].length), c.line).filter((s) => !isCleared(s, 'ssti'));
        if (st.length) emit(c.start, { desc: `${st[0].origin || 'Parameter "' + st[0].param + '"'} is used as the Vue template of ${c.callee}(), so the input can execute template expressions (client-side template injection).`, flowInfo: flowOf(st[0]) });
      }
    } }),
  call({ ...STI, id: 'xss-js-vue-compile', langs: ['js'], args: [0], what: ssti, callee: /^(?:Vue\.compile|compileToFunctions|Vue\.compileToFunctions)$/ }),
);

export const INJECTION2_RULES = [
  ...XSS_RULES, ...REDIRECT_RULES, ...SSRF_RULES, ...XXE_RULES, ...NOSQL_RULES, ...LDAP_RULES, ...HEADER_RULES,
  ...LOG_RULES, ...HOST_RULES, ...EL_RULES, ...LFI_RULES, ...UP_RULES, ...GQL_RULES, ...PP_RULES,
];
export { flowOf };
