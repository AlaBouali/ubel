'use strict';
// source.js — reads the SOURCE of a local MCP server (or of an app that embeds an MCP client) without running it.
//   • UBEL's behaviour analyser (package/lib/sourcebehavior.js): shells, downloads, obfuscation, secret collection, persistence …
//   • the secrets engine (sca/secrets.js): hardcoded credentials
//   • MCP-specific reading (handlers.js): every tool, resource and prompt the code registers — its description (docstring or `description:`),
//     its parameters and its handler — then
//       - the descriptions go through the SAME definition analysis as a live server's (defs.js): poisoning, hidden characters, look-alike
//         names, command-running tools, parameters that let the caller act as another user;
//       - handlers are checked for shell / eval / SQL / file-path / URL sinks, following the arguments through assignments and through helper
//         functions of the same file (a handler that calls `_run_shell(cmd)` is a shell sink when `_run_shell` runs its argument in a shell);
//       - handlers are checked for secrets in what they return; the file for weak JWT handling, bind-all, wildcard CORS, DNS rebinding.
//
// The handler checks are HEURISTICS on text, not a data-flow engine. An argument that provably reaches a sink through the handler's own
// assignments is reported with medium confidence; a non-literal that merely appears there with low confidence, which the shared Findings
// class turns into one level less severity. Findings are per file, so a tree of servers is not reported as a single issue.

import fs from 'node:fs';
import path from 'node:path';
import { detectLang, analyzeSource, snip } from '../../package/lib/sourcebehavior.js';
import { scanText } from '../../sca/secrets.js';
import { mask } from '../../mobile/lib/findings.js';
import { parseUnits, taintedIdents, segmentAt, usesAny } from './handlers.js';
import { analyzeDefinitions } from './defs.js';
import { isPlaceholder } from './config_checks.js';

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', '.venv', 'venv', 'env', '__pycache__', 'site-packages', '.tox', '.mypy_cache', '.pytest_cache', '.next', '.nuxt', 'target', 'vendor', '.idea', '.vscode']);
const ROOT_MARKERS = ['package.json', 'pyproject.toml', 'setup.py', 'setup.cfg', 'go.mod', 'Cargo.toml'];
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|mocks?)\//i;
const PER_RULE_CAP = 40;                 // findings of one rule listed individually; the rest are summarised in one

// risk id (from analyzeSource) → [severity, headline]
const RISK = {
  reverse_shell: ['critical', 'opens a reverse shell'], crypto_mining: ['critical', 'refers to a cryptocurrency miner'], download_exec: ['high', 'downloads and runs code'],
  exfiltration: ['high', 'collects secrets and has network access in the same file'], obfuscated: ['medium', 'contains obfuscated or encoded code'],
  credential_access: ['medium', 'reads credentials or secret-named environment variables'], persistence: ['medium', 'refers to autostart or scheduler locations'],
  destructive: ['medium', 'contains a destructive command'], insecure_tls: ['medium', 'turns TLS certificate verification off'],
};

/** The nearest directory above `file` (within 4 levels, never the home directory or the filesystem root) that has a project marker; null when there is none. */
export function findProjectRoot(file, home) {
  let dir = path.dirname(file);
  for (let i = 0; i < 4; i++) {
    if (dir === home || dir === path.parse(dir).root) return null;
    if (ROOT_MARKERS.some(m => fs.existsSync(path.join(dir, m)))) return dir;
    dir = path.dirname(dir);
  }
  return null;
}

function* walk(root, limits) {
  const stack = [root]; let files = 0;
  while (stack.length) {
    const dir = stack.pop();
    let ents; try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { continue; }
    for (const e of ents) {
      if (e.isSymbolicLink()) continue;                                   // never follow links out of the tree
      const p = path.join(dir, e.name);
      if (e.isDirectory()) { if (!SKIP_DIRS.has(e.name)) stack.push(p); }
      else if (e.isFile()) { if (++files > limits.maxFiles) { limits.truncated = true; return; } yield p; }
    }
  }
}

// ── sinks ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// [kind, regex, containment / allow-list hint that makes the hit less likely, headline]
const SINKS = {
  js: [
    ['command_injection', /\b(?:exec|execSync)\s*\(\s*(?:`[^`]*\$\{|[A-Za-z_$][\w$.]*\s*[,)]|['"][^'"]*['"]\s*\+)|\b(?:spawn|spawnSync|execFile|execFileSync)\s*\([^)]*shell\s*:\s*true|\beval\s*\(|new\s+Function\s*\(|\bvm\.(?:runInNewContext|runInThisContext|Script)\b/, null, 'runs a shell command or evaluates code built from a non-literal'],
    ['sql_injection', /\.(?:query|execute|run|all|get|exec|raw)\s*\(\s*(?:`[^`]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE)\b[^`]*\$\{|['"][^'"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'"]*['"]\s*\+)/i, null, 'builds an SQL statement by concatenation'],
    ['path_traversal', /\b(?:readFile|readFileSync|writeFile|writeFileSync|createReadStream|createWriteStream|readdir|readdirSync|unlink|unlinkSync|rm|rmSync|appendFile|appendFileSync|copyFile|rename)\s*\(\s*(?!['"`][^'"`$]*['"`]\s*[,)])[A-Za-z_$`]/, /startsWith\s*\(|path\.relative|realpath|isAbsolute|allowed(?:Dir|Path|Root)|ALLOWED_|\.includes\(\s*['"]\.\.['"]/, 'uses a file path that is not a literal'],
    ['ssrf', /\b(?:fetch|axios(?:\.\w+)?|got(?:\.\w+)?|request|http\.get|https\.get|undici\.request)\s*\(\s*(?!['"`][^'"`$]*['"`]\s*[,)])[A-Za-z_$`]/, /allow(?:ed)?[_-]?(?:hosts?|domains?|list|urls?)|isPrivate|isInternal|blocklist|blockedHosts|new URL\([^)]*\)\.(?:hostname|host|origin)/i, 'requests a URL that is not a literal'],
  ],
  py: [
    ['command_injection', /\bos\.(?:system|popen)\s*\(\s*(?:f['"]|[A-Za-z_]\w*\s*[,)]|['"][^'"]*['"]\s*(?:%|\+|\.format))|\bsubprocess\.(?:run|call|check_output|check_call|Popen)\s*\([^)]*shell\s*=\s*True|(?<![\w.])(?:eval|exec)\s*\(/, null, 'runs a shell command or evaluates code built from a non-literal'],
    ['sql_injection', /\.execute(?:many)?\s*\(\s*(?:f['"]|['"][^'"]*['"]\s*(?:%|\+|\.format))/, null, 'builds an SQL statement by formatting'],
    ['path_traversal', /\bopen\s*\(\s*(?!['"][^'"]*['"]\s*[,)])[A-Za-z_f]|\bPath\s*\([^)]*\)\s*\.(?:read_text|write_text|read_bytes|write_bytes|unlink)|\bos\.(?:remove|unlink|rename|listdir)\s*\(\s*[A-Za-z_]/, /is_relative_to|commonpath|\.resolve\(\)|realpath|abspath|startswith\s*\(|ALLOWED_|allowed_(?:dir|path|root)/, 'uses a file path that is not a literal'],
    ['ssrf', /\b(?:requests\.(?:get|post|put|request|head)|httpx\.(?:get|post|put|request)|urllib\.request\.urlopen|session\.(?:get|post))\s*\(\s*(?!['"][^'"]*['"]\s*[,)])[A-Za-z_f]/, /allow(?:ed)?_?(?:hosts?|domains?|list|urls?)|is_private|ipaddress\.|blocklist/i, 'requests a URL that is not a literal'],
  ],
  go: [
    ['command_injection', /\bexec\.Command\s*\(\s*"(?:sh|bash|cmd)"\s*,\s*"-?[cC]"\s*,\s*(?:fmt\.Sprintf|[A-Za-z_]\w*\s*\+|"[^"]*"\s*\+)/, null, 'runs a shell command built by formatting'],
    ['sql_injection', /\.(?:Query|Exec|QueryRow)(?:Context)?\s*\([^)]*fmt\.Sprintf\s*\(\s*"[^"]*\b(?:SELECT|INSERT|UPDATE|DELETE)\b/i, null, 'builds an SQL statement by formatting'],
  ],
};
const global = re => new RegExp(re.source, re.flags.replace('g', '') + 'g');
const literalFirstArg = (seg, name) => new RegExp(String.raw`\b${name}\s*\(\s*(?:f?r?["'\`][^"'\`$\{]*["'\`])\s*[,)]`).test(seg);     // helper("ls -la") is not a sink

// ── secrets in what a handler returns ──────────────────────────────────────────────────────────────────────────────────────────
const SECRET_WORD = String.raw`(?:token|secret|passw(?:or)?d|passwd|api[_-]?key|apikey|credential|private[_-]?key|jwt|session[_-]?id|auth[_-]?key)`;
const OUT = [
  ['interpolates a secret-named value into the text it returns', 'low', new RegExp(String.raw`f["'][^"'\n]*\{[^}\n]*${SECRET_WORD}[^}\n]*\}|\$\{[^}\n]*${SECRET_WORD}[^}\n]*\}`, 'i')],
  ['puts a secret-named value into a structure it returns', 'low', new RegExp(String.raw`["']\w*${SECRET_WORD}\w*["']\s*:\s*(?!["'\d\[{]|None\b|null\b|true\b|false\b|True\b|False\b)[A-Za-z_]`, 'i')],
  ['returns the whole process environment', 'medium', /\bdict\s*\(\s*os\.environ\s*\)|os\.environ\.copy\s*\(\)|json\.dumps\s*\(\s*(?:dict\s*\(\s*)?os\.environ|JSON\.stringify\s*\(\s*process\.env|\.\.\.\s*process\.env/],
  ['returns a module-level credential', 'medium', /\breturn\b[^\n]*\b_?[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIALS?|PRIVATE_KEY)[A-Z0-9_]*\b/],
];
const LOG_LINE = /^\s*(?:#|\/\/)|\b(?:logger|logging|log|console)\s*\.\s*\w+\s*\(|\bprint\s*\(/;

// ── JWT ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const JWT_FILE = /\bjwt\b|jsonwebtoken|\bjose\b|\bHS(?:256|384|512)\b/i;
const JWT_BAD = [
  ['switches signature verification off', /verify_signature["']?\s*[:=]\s*(?:False|false)|\bverify\s*=\s*False\b|["']verify_(?:exp|aud|iss)["']\s*:\s*False/],
  ['accepts the "none" algorithm', /algorithms?\s*[:=]\s*\[?[^\]\n]*["']none["']|algorithm\s*=\s*["']none["']/i],
  ['ignores token expiry', /ignoreExpiration\s*:\s*true/],
];
const JWT_SECRET_NAME = /(?:jwt|token|signing|hmac|auth)[_-]?(?:secret|key)|^secret(?:[_-]?key)?$/i;

// ── other file-level patterns ──────────────────────────────────────────────────────────────────────────────────────────────────
const FILE_PATTERNS = [
  ['bind_all', 'mcp.source.bind_all', /(?:host(?:name)?|listen)\s*[:=(]\s*['"`](?:0\.0\.0\.0|::)['"`]|\.listen\s*\(\s*\d+\s*,\s*['"`]0\.0\.0\.0['"`]|--host[ =]0\.0\.0\.0|host\s*=\s*['"]0\.0\.0\.0['"]|ListenAndServe\s*\(\s*":\d+"/g, 'binds to all network interfaces'],
  ['cors_wildcard', 'mcp.source.cors_wildcard', /\bcors\s*\(\s*\)|origin\s*:\s*['"`]\*['"`]|allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[,:]\s*['"`]\*['"`]|AllowedOrigins\s*:\s*\[\]string\{\s*"\*"/g, 'allows cross-origin requests from any origin'],
  ['auto_approve', 'mcp.source.auto_approve', /(?:autoApprove|auto_approve|alwaysAllow|requireApproval|require_approval|approval_mode)\s*[:=]\s*(?:true|['"`](?:never|always|auto)['"`]|\[\s*['"`]\*['"`]\s*\])|dangerously[-_]?skip[-_]?permissions|bypassPermissions|permission[_-]?mode\s*[:=]\s*['"`]bypass/gi, 'approves tool calls without asking'],
];
const HTTP_TRANSPORT = /StreamableHTTPServerTransport|SSEServerTransport|streamableHttp|streamable_http|sse_app|run_sse_async|run_streamable_http|transport\s*=\s*["'](?:sse|streamable-http)["']/;
const REBIND_GUARD = /enableDnsRebindingProtection\s*:\s*true|allowedHosts|allowedOrigins|allowed_hosts|allowed_origins|validateOrigin|checkOrigin|hostHeaderValidation|TransportSecuritySettings|enable_dns_rebinding_protection\s*=\s*True|headers\[['"]origin['"]\]|headers\.origin|\.get\(['"]origin['"]\)/i;

/** Findings are emitted per file; one rule lists at most PER_RULE_CAP of them and summarises the rest. */
function makeEmitter(findings, app, label) {
  const counts = new Map(), overflow = new Map();
  return {
    emit(rule, { file, key, ...f }) {
      const n = (counts.get(rule) || 0) + 1; counts.set(rule, n);
      if (n > PER_RULE_CAP) { const o = overflow.get(rule) || overflow.set(rule, { files: new Set(), first: f }).get(rule); o.files.add(file); return; }
      findings.add(rule, { app, origin: 'app', artifact: `${label} → ${file}`, key: `${key}:${file}`, ...f });
    },
    flush() {
      for (const [rule, o] of overflow) findings.add(rule, { app, origin: 'app', artifact: label, key: `overflow:${rule}`, severity: o.first.severity, confidence: o.first.confidence, title: o.first.title, description: `${o.files.size} more file(s) in ${label} have the same finding as the ${PER_RULE_CAP} listed above.`, evidence: [...o.files].slice(0, 20) });
    },
  };
}

/**
 * @param {string} root  directory or single file
 * @param {{findings:object, app:string, label:string, focus?:'server'|'client'|'all', maxFiles?:number, maxFileKb?:number}} o
 *   focus 'server' reads the code as an MCP server; 'client' as an app that embeds an MCP client (auto-approval). Both always run the behaviour
 *   analysis and the secrets engine.
 * @returns {{files:number, analysed:number, tools:{name:string,file:string,line:number}[], truncated:boolean, root:string}}
 */
export function analyzeLocalSource(root, o) {
  const { findings, app, label } = o;
  const serverSide = o.focus !== 'client', clientSide = o.focus !== 'server';
  const limits = { maxFiles: o.maxFiles ?? 800, truncated: false };
  const maxBytes = (o.maxFileKb ?? 768) * 1024;
  const out = { files: 0, analysed: 0, tools: [], truncated: false, root };
  const stat = (() => { try { return fs.statSync(root); } catch { return null; } })();
  if (!stat) return out;
  const base = stat.isDirectory() ? root : path.dirname(root);
  const list = stat.isDirectory() ? walk(root, limits) : [root][Symbol.iterator]();
  const { emit, flush } = makeEmitter(findings, app, label);

  for (const file of list) {
    out.files++;
    const rel = path.relative(base, file).split(path.sep).join('/');
    let fst; try { fst = fs.statSync(file); } catch { continue; }
    if (fst.size > maxBytes || fst.size === 0) continue;
    let buf; try { buf = fs.readFileSync(file); } catch { continue; }
    if (buf.includes(0)) continue;                                        // binary
    const text = buf.toString('utf8');
    const lang = detectLang(rel, text.slice(0, 200));
    if (!lang) continue;
    out.analysed++;
    const lines = text.split(/\r?\n/);
    const lineAt = idx => text.slice(0, idx).split('\n').length;

    // behaviour of the code
    try {
      const a = analyzeSource(text, lang);
      for (const r of a.risks) {
        if (!RISK[r.id]) continue;
        const [sev, headline] = RISK[r.id];
        emit('mcp.source.risky_code', { file: rel, key: `risk:${r.id}`, severity: sev, confidence: r.confidence || 'medium', title: `Server source ${headline}`, description: `${rel} ${headline}.`, evidence: [`${rel}${r.line ? `:${r.line}` : ''} ${r.label}${r.snippet ? ` — ${r.snippet}` : ''}`] });
      }
    } catch { /* an unparsable file is skipped, not fatal */ }

    // secrets (not in tests, examples or docs)
    if (!TEST_PATH.test(rel)) {
      try {
        const seen = new Set();
        for (const h of scanText(lines, rel)) {
          const k = h.fingerprint || `${h.line}`; if (seen.has(k) || seen.size >= 10) continue; seen.add(k);
          emit('mcp.source.hardcoded_secret', { file: rel, key: `secret:${k}`, line: h.line, title: `Hardcoded secret in server source: ${h.title}`, confidence: /^generic/.test(h.id) ? 'low' : 'high', description: `${h.title} in ${rel} (line ${h.line}).`, evidence: [h.match_preview || mask('x')] });
        }
      } catch { /* best-effort */ }
    }

    // MCP shape: tools, resources, prompts
    if (serverSide && (lang === 'js' || lang === 'py' || lang === 'go')) {
      const { units, helpers, instructions } = parseUnits(text, lang);
      for (const u of units) if (u.kind === 'tool') out.tools.push({ name: u.name, file: rel, line: u.line });

      // 1. the descriptions go through the definition analysis a live server's would
      if (units.length || instructions) {
        const before = findings.list.length;
        analyzeDefinitions({
          server: { id: `${app}|${rel}`, name: label, client: 'source' }, static: true, exposure: 'loopback', unauthenticated: false, instructions: instructions || undefined,
          tools: units.filter(u => u.kind === 'tool').map(u => ({ name: u.name, description: u.description, inputSchema: { type: 'object', properties: Object.fromEntries(u.params.map(p => [p.name, { ...(p.type ? { type: p.type } : {}), ...(p.description ? { description: p.description } : {}) }])) } })),
          resources: units.filter(u => u.kind === 'resource').map(u => ({ uri: u.uri || '', name: u.name, description: u.description })),
          prompts: units.filter(u => u.kind === 'prompt').map(u => ({ name: u.name, description: u.description })),
        }, { findings });
        for (const f of findings.list.slice(before)) { f.artifact = `${label} → ${rel} → ${f.artifact}`; }
      }

      // 2. handler sinks: direct, and through helper functions of the same file
      if (SINKS[lang] && units.length) {
        const helperSinks = new Map();                                    // helper name → Set(kind)
        for (const h of helpers.values()) {
          if (!h.params.length) continue;
          const ht = taintedIdents(h.params, h.body, lang);
          for (const [kind, re] of SINKS[lang]) {
            for (const m of h.body.matchAll(global(re))) if (usesAny(segmentAt(h.body, m.index), ht)) { (helperSinks.get(h.name) || helperSinks.set(h.name, new Set()).get(h.name)).add(kind); break; }
          }
        }
        for (let pass = 0; pass < 2; pass++) {                            // a helper that passes its argument to a sink helper is a sink helper
          for (const h of helpers.values()) {
            if (!h.params.length) continue;
            const ht = taintedIdents(h.params, h.body, lang);
            for (const [name, kinds] of [...helperSinks]) {
              if (name === h.name) continue;
              for (const m of h.body.matchAll(new RegExp(String.raw`\b${name}\s*\(`, 'g'))) if (usesAny(segmentAt(h.body, m.index), ht)) { const s = helperSinks.get(h.name) || helperSinks.set(h.name, new Set()).get(h.name); for (const k of kinds) s.add(k); }
            }
          }
        }
        const perKind = new Map();                                        // kind → {headline, conf, ev[] (argument reaches the sink), weak[] (a non-literal only)}
        const record = (kind, headline, conf, ev) => {
          const e = perKind.get(kind) || perKind.set(kind, { headline, conf: 'low', ev: [], weak: [] }).get(kind);
          const list = conf === 'medium' ? e.ev : e.weak;
          if (conf === 'medium') e.conf = 'medium';
          if (list.length < 8) list.push(ev);
        };
        for (const u of units) {
          const tainted = taintedIdents(u.taintRoots, u.body, lang);
          const at = idx => u.bodyLine + u.body.slice(0, idx).split('\n').length - 1;
          for (const [kind, re, hint, headline] of SINKS[lang]) {
            for (const hit of u.body.matchAll(global(re))) {
              if (hint && hint.test(text)) break;
              const seg = segmentAt(u.body, hit.index);
              const t = tainted.size > 0 && usesAny(seg, tainted);
              record(kind, headline, t ? 'medium' : 'low', `${u.kind} "${u.name}" (${rel}:${at(hit.index)}) — ${snip(hit[0])}${t ? ' [argument reaches it]' : ''}`);
              break;
            }
          }
          for (const [name, kinds] of helperSinks) {
            for (const hit of u.body.matchAll(new RegExp(String.raw`\b${name}\s*\(`, 'g'))) {
              const seg = segmentAt(u.body, hit.index);
              if (literalFirstArg(seg, name)) continue;
              const t = tainted.size > 0 && usesAny(seg, tainted);
              for (const kind of kinds) {
                const [, , hint, headline] = SINKS[lang].find(s => s[0] === kind);
                if (hint && hint.test(text)) continue;
                record(kind, headline, t ? 'medium' : 'low', `${u.kind} "${u.name}" (${rel}:${at(hit.index)}) — calls ${name}(…), which ${headline}${t ? ' [argument reaches it]' : ''}`);
              }
              break;
            }
          }
        }
        for (const [kind, e] of perKind) emit(`mcp.source.tool_${kind}`, { file: rel, key: `sink:${kind}`, confidence: e.conf, description: `Handler(s) in ${rel} ${e.headline}.${e.conf === 'medium' ? ' A parameter of the handler reaches the call through the handler\'s own assignments.' : ' This is a text-level heuristic that could not follow a parameter to the call, so read the handler before concluding anything.'}`, evidence: e.ev.length ? e.ev : e.weak });
      }

      // 3. secrets in what a handler returns
      if (lang === 'py' || lang === 'js') {
        const hits = new Map();
        for (const u of units) {
          u.body.split('\n').forEach((l, i) => {
            if (LOG_LINE.test(l)) return;
            for (const [what, conf, re] of OUT) if (re.test(l)) { const e = hits.get(what) || hits.set(what, { conf, ev: [] }).get(what); if (e.ev.length < 6) e.ev.push(`${u.kind} "${u.name}" (${rel}:${u.bodyLine + i}) — ${snip(l.trim())}`); }
          });
        }
        if (hits.size) emit('mcp.source.tool_secret_exposure', { file: rel, key: 'secret_out', confidence: [...hits.values()].some(h => h.conf === 'medium') ? 'medium' : 'low', description: `Handler(s) in ${rel}: ${[...hits.keys()].join('; ')}. Whatever a tool or resource returns goes into the model's context.`, evidence: [...hits.values()].flatMap(h => h.ev).slice(0, 8) });
      }

      // 4. file-level: HTTP transport without Origin / Host validation
      if (HTTP_TRANSPORT.test(text) && !REBIND_GUARD.test(text) && lang !== 'go') emit('mcp.source.dns_rebinding', { file: rel, key: 'dns_rebinding', confidence: 'low', description: `${rel} serves MCP over HTTP with no Origin or Host validation that this scan can see.`, evidence: [rel] });
    }

    // 5. JWT
    if ((lang === 'py' || lang === 'js') && JWT_FILE.test(text) && !TEST_PATH.test(rel)) {
      const ev = [];
      for (const [what, re] of JWT_BAD) { const m = re.exec(text); if (m) ev.push(`${rel}:${lineAt(m.index)} ${what} — ${snip(m[0])}`); }
      if (lang === 'js' && /\bjwt\.decode\s*\(/.test(text) && !/\bjwt\.verify\s*\(/.test(text)) ev.push(`${rel} decodes a token with jwt.decode and never calls jwt.verify`);
      lines.forEach((l, i) => {
        const m = l.match(/^\s*(?:export\s+)?(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::[^=]+)?=\s*b?["']([^"'\n]{1,31})["']\s*;?\s*(?:#.*|\/\/.*)?$/);
        if (m && JWT_SECRET_NAME.test(m[1]) && !isPlaceholder(m[2])) ev.push(`${rel}:${i + 1} ${m[1]} is a ${m[2].length}-character literal (${mask(m[2])}); HS256 needs at least 32 random bytes`);
      });
      if (ev.length) emit('mcp.source.jwt_weak', { file: rel, key: 'jwt', confidence: 'medium', description: `${rel} handles tokens in a way that lets them be forged or guessed.`, evidence: ev.slice(0, 8) });
    }

    // 6. bind / CORS / auto-approval
    for (const [id, rule, re, headline] of FILE_PATTERNS) {
      if (id === 'auto_approve' ? !clientSide : !serverSide) continue;
      re.lastIndex = 0;
      const ev = []; let m;
      while ((m = re.exec(text)) && ev.length < 3) ev.push(`${rel}:${lineAt(m.index)} — ${snip(m[0])}`);
      if (ev.length) emit(rule, { file: rel, key: rule, confidence: 'medium', description: `${rel} ${headline}.`, evidence: ev });
    }
  }
  out.truncated = limits.truncated;
  flush();
  return out;
}
