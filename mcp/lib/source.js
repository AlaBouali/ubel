'use strict';
// source.js — reads the SOURCE of a local MCP server (or of an app that embeds an MCP client) without running it.
//   • UBEL's own behaviour analyser (package/lib/sourcebehavior.js) for shells, downloads, obfuscation, secret collection, persistence …
//   • the secrets engine (sca/secrets.js) for hardcoded credentials
//   • MCP-specific reading: which tools the code registers, and what each tool handler does with its arguments
//
// The tool-handler checks are HEURISTICS on text, not data-flow analysis: they look at the lines after a tool registration for a shell call,
// an SQL string, a file path or a URL built from something that is not a literal. Every such finding carries low confidence, which the
// shared Findings class turns into one level less severity. They point at where to read; they do not prove an injection.

import fs from 'node:fs';
import path from 'node:path';
import { detectLang, analyzeSource, snip } from '../../package/lib/sourcebehavior.js';
import { scanText } from '../../sca/secrets.js';
import { mask } from '../../mobile/lib/findings.js';

const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', '.venv', 'venv', 'env', '__pycache__', 'site-packages', '.tox', '.mypy_cache', '.pytest_cache', '.next', '.nuxt', 'target', 'vendor', '.idea', '.vscode']);
const ROOT_MARKERS = ['package.json', 'pyproject.toml', 'setup.py', 'setup.cfg', 'go.mod', 'Cargo.toml'];
const TEST_PATH = /(?:^|\/)(?:tests?|__tests__|spec|fixtures?|examples?|docs?|mocks?)\//i;

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

// ── tool registration ─────────────────────────────────────────────────────────────────────────────────────────────────────────
const REG = {
  js: [/\b(?:server|mcp|app|this|srv)\s*\.\s*(?:tool|registerTool|addTool)\s*\(\s*(?:\{\s*name\s*:\s*)?['"`]([\w.-]{1,128})['"`]/g],
  py: [/^[ \t]*@\s*\w+(?:\.\w+)*\.tool\s*\(([^)]*)\)[ \t]*\r?\n(?:[ \t]*@[^\n]*\r?\n)*[ \t]*(?:async\s+)?def\s+(\w+)/gm],
  go: [/\b(?:mcp\.NewTool|NewTool)\s*\(\s*"([\w.-]+)"/g],
};
function registrations(text, lang) {
  const out = [];
  for (const re of REG[lang] || []) {
    re.lastIndex = 0;
    for (let m; (m = re.exec(text));) {
      const line = text.slice(0, m.index).split('\n').length;
      let name = m[1];
      if (lang === 'py') { const explicit = (m[1] || '').match(/name\s*=\s*['"]([\w.-]+)['"]/); name = explicit ? explicit[1] : m[2]; }
      out.push({ name, line, index: m.index });
    }
  }
  return out.sort((a, b) => a.index - b.index);
}

// handler-window checks: [kind, regex, containment/allow-list hint that makes the hit less likely, headline]
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
const WINDOW = 90;

const FILE_PATTERNS = [
  ['bind_all', 'mcp.source.bind_all', /(?:host(?:name)?|listen)\s*[:=(]\s*['"`](?:0\.0\.0\.0|::)['"`]|\.listen\s*\(\s*\d+\s*,\s*['"`]0\.0\.0\.0['"`]|--host[ =]0\.0\.0\.0|host\s*=\s*['"]0\.0\.0\.0['"]|ListenAndServe\s*\(\s*":\d+"/g, 'binds to all network interfaces'],
  ['cors_wildcard', 'mcp.source.cors_wildcard', /\bcors\s*\(\s*\)|origin\s*:\s*['"`]\*['"`]|allow_origins\s*=\s*\[\s*['"]\*['"]|Access-Control-Allow-Origin['"]?\s*[,:]\s*['"`]\*['"`]|AllowedOrigins\s*:\s*\[\]string\{\s*"\*"/g, 'allows cross-origin requests from any origin'],
  ['auto_approve', 'mcp.source.auto_approve', /(?:autoApprove|auto_approve|alwaysAllow|requireApproval|require_approval|approval_mode)\s*[:=]\s*(?:true|['"`](?:never|always|auto)['"`]|\[\s*['"`]\*['"`]\s*\])|dangerously[-_]?skip[-_]?permissions|bypassPermissions|permission[_-]?mode\s*[:=]\s*['"`]bypass/gi, 'approves tool calls without asking'],
];
const HTTP_TRANSPORT = /StreamableHTTPServerTransport|SSEServerTransport|streamableHttp|streamable_http|sse_app|run_sse_async|run_streamable_http/;
const REBIND_GUARD = /enableDnsRebindingProtection\s*:\s*true|allowedHosts|allowedOrigins|allowed_hosts|allowed_origins|validateOrigin|checkOrigin|hostHeaderValidation|TransportSecuritySettings|enable_dns_rebinding_protection\s*=\s*True|headers\[['"]origin['"]\]|headers\.origin|\.get\(['"]origin['"]\)/i;

/**
 * @param {string} root  directory or single file
 * @param {{findings:object, app:string, label:string, focus?:'server'|'client'|'all', maxFiles?:number, maxFileKb?:number, notes?:object}} o
 *   focus 'server' reads the code as an MCP server (tool handlers, bind / CORS / DNS-rebinding); 'client' as an app that embeds an MCP client (auto-approval);
 *   both always run the behaviour analysis and the secrets engine.
 * @returns {{files:number, analysed:number, tools:{name:string,file:string,line:number}[], truncated:boolean}}
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
  const riskHits = new Map();
  const sinkHits = new Map();
  const fileHits = new Map();
  const secretHits = [];

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

    // behaviour of the code
    try {
      const a = analyzeSource(text, lang);
      for (const r of a.risks) {
        if (!RISK[r.id]) continue;
        const e = riskHits.get(r.id) || riskHits.set(r.id, { conf: new Set(), ev: [] }).get(r.id);
        e.conf.add(r.confidence);
        if (e.ev.length < 8) e.ev.push(`${rel}${r.line ? `:${r.line}` : ''} ${r.label}${r.snippet ? ` — ${r.snippet}` : ''}`);
      }
    } catch { /* an unparsable file is skipped, not fatal */ }

    // secrets (not in tests, examples or docs)
    if (!TEST_PATH.test(rel)) {
      try { for (const h of scanText(lines, rel)) if (secretHits.length < 20) secretHits.push({ rel, h }); } catch { /* best-effort */ }
    }

    // MCP shape
    if (serverSide && (lang === 'js' || lang === 'py' || lang === 'go')) {
      const regs = registrations(text, lang);
      for (const r of regs) out.tools.push({ name: r.name, file: rel, line: r.line });
      const lineStarts = []; let off = 0; for (const l of text.split('\n')) { lineStarts.push(off); off += l.length + 1; }
      const guarded = {};
      regs.forEach((r, i) => {
        const end = Math.min(regs[i + 1]?.index ?? Infinity, r.index + 12000, lineStarts[Math.min(r.line - 1 + WINDOW, lineStarts.length - 1)] ?? text.length);
        const win = text.slice(r.index, end);
        for (const [kind, re, hint, headline] of SINKS[lang] || []) {
          const m = win.match(re);
          if (!m) continue;
          if (hint && hint.test(text)) { guarded[kind] = true; continue; }
          const e = sinkHits.get(kind) || sinkHits.set(kind, { headline, ev: [] }).get(kind);
          if (e.ev.length < 8) e.ev.push(`tool "${r.name}" (${rel}:${r.line}) — ${snip(m[0])}`);
        }
      });
      if (HTTP_TRANSPORT.test(text) && !REBIND_GUARD.test(text) && lang !== 'go') {
        const e = fileHits.get('dns_rebinding') || fileHits.set('dns_rebinding', { rule: 'mcp.source.dns_rebinding', headline: 'serves MCP over HTTP with no Origin or Host validation that this scan can see', ev: [] }).get('dns_rebinding');
        if (e.ev.length < 6) e.ev.push(rel);
      }
    }
    for (const [id, rule, re, headline] of FILE_PATTERNS) {
      if (id === 'auto_approve' ? !clientSide : !serverSide) continue;
      re.lastIndex = 0;
      let m, n = 0;
      while ((m = re.exec(text)) && n < 3) {
        n++;
        const line = text.slice(0, m.index).split('\n').length;
        const e = fileHits.get(id) || fileHits.set(id, { rule, headline, ev: [] }).get(id);
        if (e.ev.length < 6) e.ev.push(`${rel}:${line} — ${snip(m[0])}`);
      }
    }
  }
  out.truncated = limits.truncated;

  const add = (rule, f) => findings.add(rule, { app, origin: 'app', ...f });
  for (const [id, e] of riskHits) {
    const [sev, headline] = RISK[id];
    add('mcp.source.risky_code', { artifact: label, key: `risk:${id}`, severity: sev, confidence: e.conf.has('high') ? 'high' : e.conf.has('medium') ? 'medium' : 'low', title: `Server source ${headline}`, description: `The source of ${label} ${headline}.`, evidence: e.ev });
  }
  const seenSecret = new Set();
  for (const { rel, h } of secretHits) {
    const k = `${rel}:${h.fingerprint || h.line}`; if (seenSecret.has(k)) continue; seenSecret.add(k);
    add('mcp.source.hardcoded_secret', { artifact: `${label} → ${rel}`, line: h.line, key: h.fingerprint || k, title: `Hardcoded secret in server source: ${h.title}`, confidence: /^generic/.test(h.id) ? 'low' : 'high', description: `${h.title} in ${rel} (line ${h.line}).`, evidence: [h.match_preview || mask('x')] });
  }
  for (const [kind, e] of sinkHits) add(`mcp.source.tool_${kind}`, { artifact: label, key: `sink:${kind}`, confidence: 'low', description: `At least one tool handler in ${label} ${e.headline}. This is a text-level heuristic (it does not follow the value from the tool's arguments to the call), so read the handler before concluding anything.`, evidence: e.ev });
  for (const [, e] of fileHits) add(e.rule, { artifact: label, key: e.rule, confidence: e.rule === 'mcp.source.dns_rebinding' ? 'low' : 'medium', description: `The source of ${label} ${e.headline}.`, evidence: e.ev });
  return out;
}
