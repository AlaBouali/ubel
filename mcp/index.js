'use strict';
// mcp/index.js — the engine behind the two MCP scanners. It has no command line of its own; the entry points are
//   mcp/client.js  →  ubel-mcp-client   how MCP CLIENTS are set up: configuration files, credentials, auto-approval, project trust,
//                                        launch commands. Static and offline: reads files, contacts nothing, starts nothing.
//   mcp/server.js  →  ubel-mcp-server   the MCP SERVERS themselves: live HTTP / SSE probing (initialize + list only), tool / resource / prompt
//                                        definitions, launcher packages (through ubel-package), local server source, running processes (Linux /proc).
//
// Standard library only: no third-party package, no external binary, no process of its own. Never starts a server, never calls a tool.
// Reuses UBEL's rule table, findings, --fail-on gate, report id, asset identity and history zip.

import fs from 'node:fs';
import os from 'node:os';
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import './lib/rules.js';
import { SEVERITY_RANK, SEVERITIES } from '../mobile/lib/rules.js';
import { Findings } from '../mobile/lib/findings.js';
import { Notes, gap } from '../mobile/lib/coverage.js';
import { parseFailOn, evaluateGate } from '../mobile/index.js';
import { provisionAssetAt } from '../sca/report_naming.js';
import { clientSources, readClientConfigs } from './lib/clients.js';
import { describeLaunch, parsePackageSpec } from './lib/launcher.js';
import { checkServerConfig, displayTarget, redactUrl } from './lib/config_checks.js';
import { probeRemote } from './lib/remote.js';
import { shadowing } from './lib/defs.js';
import { analyzeLocalSource, findProjectRoot } from './lib/source.js';
import { analysePackages, adopt } from './lib/packages.js';
import { hostExposure } from './lib/net.js';
import { allProcesses, candidateEndpoints, describeProcess, matchProcesses, procSupported, DEFAULT_PORTS } from './lib/observe.js';
import { listeners } from './lib/procfs.js';
import { loadBaseline, buildPayload, writeReports } from './lib/report.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;
const VALID_SEVERITIES = new Set(SEVERITIES);

export const MODES = {
  client: { tool: 'ubel-mcp-client', tag: 'mcp_client', groups: new Set(['config', 'launch', 'url']), focus: 'client' },
  server: { tool: 'ubel-mcp-server', tag: 'mcp_server', groups: new Set(['url']), focus: 'server' },
};

const OUTPUT_HELP = `
Output
  --working-dir <dir>       where .ubel/reports is written (default: the current directory)
  --min-severity <s>        hide findings below this severity in the report (${SEVERITIES.join(' | ')}; default info)
  --fail-on <s>             exit 2 when a finding at or above this severity exists: none | ${SEVERITIES.join(' | ')} | <count>:<severity> (default critical)
  --allow-partial           exit 0 even when part of the analysis could not be done (otherwise exit 3)
  --quiet / --verbose

Exit codes: 0 ok · 1 error · 2 gate tripped · 3 analysis incomplete
`;

export const HELP = {
  client: `
ubel-mcp-client — security scan of how MCP clients are set up (Node standard library only; static: reads files, contacts nothing, starts nothing)

Usage: ubel-mcp-client [options]

What is scanned
  (default)                 every MCP client configuration of this user (Claude Desktop / Code, Cursor, VS Code, Windsurf, Cline, Zed, Gemini CLI,
                            Codex, Amazon Q, LM Studio …) and the project files of the working directory (.mcp.json, .cursor/, .vscode/ …)
  --config <file>           another client configuration file (JSON, JSONC or TOML); repeatable
  --project <dir>           look for project-scoped configuration in this directory; repeatable (default: the working directory)
  --home <dir>              locate user-level configuration under this directory (default: the current user's home)
  --no-configs              read only the files given with --config
  --source <dir|file>       source of an app that embeds an MCP client (auto-approval of tool calls, secrets, risky behaviour); repeatable

Reported: credentials in plain text, tool calls approved without asking, project servers trusted automatically, configuration files other
users can read, and how each local server is launched (download-and-run, shells, unpinned packages, container flags, filesystem scope).
Probing the declared servers, their packages, their source and their processes is ubel-mcp-server --from-config.
${OUTPUT_HELP}`,
  server: `
ubel-mcp-server — security scan of MCP servers (Node standard library only; initialize + list only, never calls a tool, never starts a server)

Usage: ubel-mcp-server [options] [url ...]

What is scanned (at least one is required)
  url ...  /  --url <url>   an MCP endpoint (Streamable HTTP or legacy SSE) to probe; repeatable
  --from-config             the servers declared by this user's MCP client configurations and the working directory's project files
  --config <file>           the servers declared in another configuration file (JSON, JSONC or TOML); repeatable
  --project <dir>           the servers declared by project files in this directory; repeatable
  --home <dir>              locate user-level configuration under this directory (default: the current user's home)
  --discover                servers that are running now and not declared: Linux reads /proc (listening sockets owned by something that looks like
                            an MCP server); elsewhere ports are tried on 127.0.0.1
  --ports <list>            extra ports for --discover, e.g. 3000,8000-8100
  --source <dir|file>       source of a local MCP server (tool handlers, secrets, risky behaviour, bind / CORS / DNS rebinding); repeatable
  --package <spec>          a server package to download from its registry and analyse with ubel-package: npm:name[@version] or pypi:name[==version]; repeatable

Live probing (initialize + list only)
  --use-config-headers      send the headers a configuration declares to that server's own URL (default: probe without credentials)
  --header "Name: value"    header for the url targets; repeatable
  --token <token>           bearer token for the url targets (or UBEL_MCP_TOKEN)
  --trust-project           also probe project-scoped servers that point at a loopback or private address (default: skipped, because a repository
                            you did not write could otherwise make this scan contact internal hosts)
  --insecure                continue when a server's TLS certificate does not validate (the invalid certificate is still reported)
  --timeout <ms>            per-request timeout (default 8000)
  --static-only             do not contact any server and do not read /proc

Packages and source of declared servers
  --no-packages             do not download the packages npx / uvx / pipx would run (and --package ones) for analysis
  --max-packages <n>        packages to analyse (default 20)
  --no-source               do not read the source of declared local servers
  --offline                 no registry or advisory lookups (implies --no-packages)
${OUTPUT_HELP}`,
};

const COMMON = ['--help', '-h', '--working-dir', '--min-severity', '--fail-on', '--allow-partial', '--verbose', '--quiet'];
const ALLOWED = {
  client: new Set([...COMMON, '--config', '--project', '--home', '--no-configs', '--source']),
  server: new Set([...COMMON, '--url', '--config', '--project', '--home', '--from-config', '--discover', '--ports', '--use-config-headers', '--trust-project', '--header', '--token', '--insecure', '--timeout', '--static-only', '--no-packages', '--max-packages', '--no-source', '--offline', '--source', '--package']),
};

export function parseArgs(argv, mode) {
  const { tool } = MODES[mode];
  const args = { mode, urls: [], configs: [], projects: [], sources: [], packageSpecs: [], headers: {}, minSeverity: 'info', failOn: 'critical', verbose: false, quiet: false, allowPartial: false,
    offline: false, insecure: false, timeoutMs: 8000, maxPackages: 20, noConfigs: false, fromConfig: false, trustProject: false, noSource: false, noPackages: false, staticOnly: false,
    discover: false, useConfigHeaders: false, ports: [], token: process.env.UBEL_MCP_TOKEN || null };
  const bad = msg => { console.error(`${msg}\n`); console.log(HELP[mode]); process.exit(2); };
  const value = (flag, i) => { const v = argv[i + 1]; if (v === undefined || (v.startsWith('--') && v.length > 2)) bad(`${flag} requires a value`); return v; };
  const num = (flag, i, min, max) => { const n = Number(value(flag, i)); if (!Number.isFinite(n) || n < min || n > max) bad(`${flag} must be a number between ${min} and ${max}`); return n; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a.startsWith('-') && !ALLOWED[mode].has(a)) bad(`Unknown argument for ${tool}: ${a}`);
    if (a === '--help' || a === '-h') { console.log(HELP[mode]); process.exit(0); }
    else if (a === '--url') args.urls.push(value(a, i++));
    else if (a === '--config') args.configs.push(value(a, i++));
    else if (a === '--project') args.projects.push(value(a, i++));
    else if (a === '--home') args.home = value(a, i++);
    else if (a === '--no-configs') args.noConfigs = true;
    else if (a === '--from-config') args.fromConfig = true;
    else if (a === '--source') args.sources.push(value(a, i++));
    else if (a === '--package') { const v = value(a, i++); if (!parsePackageSpec(v)) bad('--package must look like npm:name[@version] or pypi:name[==version]'); args.packageSpecs.push(v); }
    else if (a === '--discover') args.discover = true;
    else if (a === '--ports') args.ports.push(...parsePorts(value(a, i++), bad));
    else if (a === '--use-config-headers') args.useConfigHeaders = true;
    else if (a === '--trust-project') args.trustProject = true;
    else if (a === '--header') { const h = value(a, i++); const k = h.indexOf(':'); if (k < 1) bad('--header must look like "Name: value"'); args.headers[h.slice(0, k).trim()] = h.slice(k + 1).trim(); }
    else if (a === '--token') args.token = value(a, i++);
    else if (a === '--insecure') args.insecure = true;
    else if (a === '--timeout') args.timeoutMs = num(a, i++, 500, 120000);
    else if (a === '--static-only') args.staticOnly = true;
    else if (a === '--no-packages') args.noPackages = true;
    else if (a === '--max-packages') args.maxPackages = num(a, i++, 0, 200);
    else if (a === '--no-source') args.noSource = true;
    else if (a === '--offline') args.offline = true;
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') args.failOn = value(a, i++);
    else if (a === '--allow-partial') args.allowPartial = true;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (/^https?:\/\//i.test(a) && mode === 'server') args.urls.push(a);
    else bad(`Unexpected argument: ${a}${mode === 'server' ? ' (a target is an http:// or https:// URL; use --config or --source for files)' : ' (ubel-mcp-client takes options only)'}`);
  }
  if (!VALID_SEVERITIES.has(args.minSeverity)) bad(`--min-severity must be one of: ${SEVERITIES.join(', ')}`);
  args.failOnParsed = parseFailOn(args.failOn);
  if (!args.failOnParsed) bad(`--fail-on must be "none", one of: ${SEVERITIES.join(', ')}, or "<count>:<severity>" (got "${args.failOn}")`);
  if (args.token) args.headers.Authorization = `Bearer ${args.token}`;
  if (args.offline) args.noPackages = true;
  if (mode === 'server' && !(args.urls.length || args.fromConfig || args.configs.length || args.projects.length || args.discover || args.sources.length || args.packageSpecs.length)) {
    bad('Nothing to scan: give an endpoint URL, or one of --from-config, --config, --project, --discover, --source, --package');
  }
  return args;
}
function parsePorts(s, bad) {
  const out = [];
  for (const part of s.split(',')) {
    const m = part.trim().match(/^(\d{1,5})(?:-(\d{1,5}))?$/);
    if (!m) bad(`--ports: "${part}" is not a port or a range`);
    const a = Number(m[1]), b = Number(m[2] ?? m[1]);
    if (a < 1 || b > 65535 || b < a || b - a > 2000) bad(`--ports: "${part}" is out of range (1-65535, at most 2000 ports per range)`);
    for (let p = a; p <= b; p++) out.push(p);
  }
  return out;
}

// Names and URLs come from files and servers we do not control: no control character (an ANSI escape, say) reaches the terminal.
const clean = s => String(s ?? '').replace(/[\u0000-\u001F\u007F-\u009F\u200B-\u200F\u202A-\u202E\u2066-\u2069\uFEFF]/g, '·');

const tcpProbe = (host, port, ms) => new Promise(resolve => {
  const s = net.connect({ host: host.replace(/^\[|\]$/g, ''), port });
  const done = ok => { s.destroy(); resolve(ok); };
  s.setTimeout(ms, () => done(false)); s.once('connect', () => done(true)); s.once('error', () => done(false));
});
async function pool(items, n, fn) {
  const q = [...items];
  await Promise.all(Array.from({ length: Math.min(n, q.length) }, async () => { while (q.length) await fn(q.shift()); }));
}

/** Runs the whole scan and returns everything the report needs; writes nothing. Exported for use as a library. */
export async function scanMcp(args, { log = () => {} } = {}) {
  const mode = args.mode;
  const client = mode === 'client';
  const M = MODES[mode];
  const notes = new Notes();
  const findings = new Findings();
  const home = args.home ? path.resolve(args.home) : os.homedir();
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  const baseline = client ? new Map() : loadBaseline(workingDir, M.tag);
  const records = [];                                  // what the report says about each server
  const probes = [];                                   // {rec (report record), server (normalised), url, headers, explicit}
  const toolSets = [];
  const allPackages = [];
  const analysedRoots = new Set();
  const scanned = { packages: 0, processes: 0 };
  let nonProbeable = 0;

  // ── 1. client configurations ────────────────────────────────────────────────────────────────────────────────────────────────
  const useConfigs = client || args.fromConfig || args.configs.length > 0 || args.projects.length > 0;
  let cfg = { servers: [], flags: [], files: [], gaps: [] };
  if (useConfigs) {
    const all = clientSources({ home, projects: args.projects.length ? args.projects : [workingDir], extra: args.configs });
    cfg = readClientConfigs(args.noConfigs ? all.filter(s => s.client === 'custom') : all);
    for (const g of cfg.gaps) gap(notes, g);
    log(`Client configurations: ${cfg.files.length} file(s), ${cfg.servers.length} server(s).`);
  }
  if (client) for (const f of cfg.flags) findings.add('mcp.config.trust_project_servers', { app: `${f.client}:${f.scope}:settings`, origin: 'app', artifact: f.file, key: 'trust_project', description: `${f.file} sets enableAllProjectMcpServers, so every MCP server declared by a project's .mcp.json is enabled without asking. A cloned repository can start a command on this machine.`, evidence: ['enableAllProjectMcpServers: true'] });

  // ── 2. declared servers ─────────────────────────────────────────────────────────────────────────────────────────────────────
  for (const server of cfg.servers) {
    const launch = server.transport === 'stdio' ? describeLaunch(server) : null;
    checkServerConfig(server, launch, { findings, home, groups: M.groups });
    const rec = {
      id: server.id, key: server.key, name: server.name, client: server.client, scope: server.scope, file: server.file, transport: server.transport, disabled: server.disabled || undefined,
      target: displayTarget(server),
      ...(launch ? { launch: { kind: launch.kind, runner: launch.runner, shell_wrapper: launch.wrapper?.kind, packages: launch.packages.map(p => ({ ecosystem: p.ecosystem, name: p.name, version: p.version, spec: p.spec, pin: p.pinClass, source: p.source })), image: launch.image ? { image: launch.image.image, tag: launch.image.tag, digest: launch.image.digest, privileged: launch.image.privileged } : undefined, script: launch.script ? { path: launch.script.path, module: launch.script.module, interpreter: launch.script.interpreter } : undefined } } : {}),
    };
    records.push(rec);
    if (client) continue;
    if (launch) {
      allPackages.push(...launch.packages);
      if (launch.kind === 'image' || launch.kind === 'binary') nonProbeable++;
      const script = server.resolvedScript;
      if (script && !args.noSource) {
        let root = script;
        try { if (fs.statSync(script).isFile()) root = findProjectRoot(script, home) || script; } catch { root = null; }
        if (root && !analysedRoots.has(root)) {
          analysedRoots.add(root);
          const r = analyzeLocalSource(root, { findings, app: server.id, label: `${server.name} (${path.basename(root)})`, focus: M.focus });
          rec.source = { root, files: r.files, analysed: r.analysed, tools: r.tools.slice(0, 100) };
          if (r.truncated) gap(notes, `The source of "${server.name}" has more files than the scan limit; only the first ${r.files - 1} were read.`);
        }
      } else if (launch.script?.path && !script && !args.noSource) notes.push(`Server "${server.name}" runs ${launch.script.path}, a relative path with no working directory in the configuration; its source was not read.`);
    }
    if (server.url && !server.disabled && !args.staticOnly) probes.push({ rec, server, url: server.url, headers: args.useConfigHeaders ? server.headers : {}, explicit: false });
  }

  // ── 3. targets given on the command line ────────────────────────────────────────────────────────────────────────────────────
  for (const dir of args.sources) {
    const root = path.resolve(dir);
    let st = null; try { st = fs.statSync(root); } catch { /* reported below */ }
    if (!st) { gap(notes, `--source ${dir}: no such file or directory.`); continue; }
    const rec = { id: `source:${root}`, key: `source|${root}`, name: root, client: 'cli', scope: 'target', file: null, transport: 'source', target: root };
    const r = analyzeLocalSource(root, { findings, app: rec.id, label: path.basename(root) || root, focus: M.focus });
    rec.source = { root, files: r.files, analysed: r.analysed, tools: r.tools.slice(0, 100) };
    if (r.truncated) gap(notes, `${root} has more files than the scan limit; only the first ${r.files - 1} were read.`);
    if (!r.analysed) notes.push(`${root}: no JavaScript, TypeScript, Python or Go source was found to analyse.`);
    records.push(rec);
  }
  if (!client) {
    for (const spec of args.packageSpecs) {
      const p = parsePackageSpec(spec);
      allPackages.push(p);
      records.push({ id: `package:${spec}`, key: `package|${spec}`, name: spec, client: 'cli', scope: 'target', file: null, transport: 'package', target: spec, launch: { kind: 'package', packages: [{ ecosystem: p.ecosystem, name: p.name, version: p.version, spec: p.spec, pin: p.pinClass, source: p.source }] } });
    }
    for (const url of args.urls) {
      const server = { id: `url:${redactUrl(url)}`, key: `url|${redactUrl(url)}`, name: redactUrl(url), client: 'cli', scope: 'target', transport: 'remote', url, headers: args.headers };
      checkServerConfig(server, null, { findings, home, groups: new Set(['url']) });        // plain-HTTP targets
      const rec = { id: server.id, key: server.key, name: server.name, client: 'cli', scope: 'target', file: null, transport: 'remote', target: redactUrl(url) };
      records.push(rec);
      if (!args.staticOnly) probes.push({ rec, server, url, headers: args.headers, explicit: true });
      else notes.push(`--static-only: ${rec.target} was not contacted.`);
    }
  }

  // ── 4. running processes and undeclared local servers (server scan) ─────────────────────────────────────────────────────────
  let procs = null;
  if (!client && !args.staticOnly) {
    if (procSupported()) procs = allProcesses();
    else if (args.discover) notes.push('Process observation is Linux-only; on this platform --discover only tries ports on 127.0.0.1.');
  }
  if (procs && cfg.servers.length) {
    const listenAll = listeners();
    for (const rec of records) {
      const server = cfg.servers.find(s => s.id === rec.id);
      if (!server || server.transport !== 'stdio' || server.disabled) continue;
      const found = matchProcesses(server, describeLaunch(server), procs);
      if (found.length) { rec.observed = found.map(p => describeProcess(server, p, procs, listenAll, findings)); scanned.processes += found.length; }
    }
  }
  if (!client && args.discover && !args.staticOnly) {
    const ports = [...new Set([...args.ports, ...DEFAULT_PORTS])];
    const cands = await candidateEndpoints({ ports, procs: procs || new Map(), tcpProbe });
    log(`Discovery: ${cands.length} local endpoint(s) to try.`);
    const declared = new Set(probes.map(p => p.url));
    for (const c of cands) {
      const base = `http://${c.host}:${c.port}`;
      const server = { id: `discovered:${c.host}:${c.port}`, key: `discovered|${c.host}:${c.port}`, name: `${c.host}:${c.port}`, client: 'discovered', scope: 'local', transport: 'remote', url: base };
      const rec = { id: server.id, key: server.key, name: server.name, client: 'discovered', scope: 'local', file: null, transport: 'remote', target: base, ...(c.process ? { process: c.process } : {}) };
      probes.push({ rec, server, url: base, paths: ['/mcp', '/sse', '/'], headers: {}, explicit: false, discovered: true, skip: [...declared].some(u => { try { return new URL(u).port === String(c.port) && /^(?:127\.0\.0\.1|localhost|\[::1\])$/.test(new URL(u).hostname); } catch { return false; } }) });
    }
  }

  // ── 5. probe ────────────────────────────────────────────────────────────────────────────────────────────────────────────────
  const popts = { timeoutMs: args.timeoutMs, maxBytes: 1 << 20, insecure: args.insecure, toolVersion: TOOL_VERSION, log: args.verbose ? log : () => {} };
  await pool(probes.filter(p => !p.skip), 4, async p => {
    if (p.server.scope === 'project' && !args.trustProject) {                       // a repository decides this URL, not the person scanning it
      let host = null; try { host = new URL(p.url).hostname; } catch { /* invalid URL: probeRemote reports it */ }
      const exp = host ? await hostExposure(host) : 'unknown';
      if (exp === 'loopback' || exp === 'private') { p.rec.remote = { skipped: `project-scoped and ${exp}` }; notes.push(`${p.rec.name}: declared by a project file and pointing at a ${exp} address; not probed (--trust-project probes it).`); return; }
    }
    const paths = p.paths || [null];
    let rec = null;
    for (const sub of paths) {
      const url = sub ? new URL(sub, p.url).href : p.url;
      rec = await probeRemote(url, { ...popts, headers: p.headers, previous: baseline.get(p.server.key) }, { findings, server: p.server });
      if (rec.mcp || !rec.reachable) break;
    }
    if (p.discovered && !rec.mcp) { p.rec.dropped = true; return; }                 // something else is listening there: not our business
    if (!rec.mcp && rec.error && p.explicit) gap(notes, `${p.rec.target}: not reachable (${rec.error}).`);
    else if (!rec.mcp && rec.error) notes.push(`${p.rec.name}: not reachable (${rec.error}); a declared server that is not running cannot be probed.`);
    else if (!rec.mcp && p.explicit) gap(notes, `${p.rec.target}: answered, but not as an MCP server (${rec.notes.join(' ') || 'no JSON-RPC reply'}).`);
    for (const n of rec.notes) if (rec.mcp) notes.push(`${p.rec.name}: ${n}`);
    const { tools, resources, resourceTemplates, prompts, definitions, ...slim } = rec;
    p.rec.remote = { ...slim, counts: { tools: tools.length, resources: resources.length, prompts: prompts.length } };
    if (definitions?.summary.truncated?.budgetExhausted) gap(notes, `${p.rec.name}: the definitions are larger than the scan budget; part of them was not checked for instructions to the model.`);
    if (definitions) { p.rec.definitions = { tools: definitions.tools, summary: definitions.summary }; toolSets.push({ server: p.server, names: tools.map(t => String(t?.name ?? '')) }); }
    if (rec.initialize) p.rec.server_info = { name: rec.initialize.serverInfo?.name, version: rec.initialize.serverInfo?.version, protocol: rec.initialize.protocolVersion, instructions: rec.initialize.instructions ? `${rec.initialize.instructions.slice(0, 500)}${rec.initialize.instructions.length > 500 ? '…' : ''}` : undefined };
  });
  const finalRecords = records.concat(probes.filter(p => p.discovered && !p.rec.dropped && !p.skip).map(p => p.rec)).filter((r, i, a) => !r.dropped && a.indexOf(r) === i);
  shadowing(toolSets, findings);

  // ── 6. packages (server scan) ───────────────────────────────────────────────────────────────────────────────────────────────
  const registryPkgs = allPackages.filter(p => p.source === 'registry' && !p.unsupported && /^(?:npm|pypi)$/.test(p.ecosystem));
  if (registryPkgs.length) {
    if (args.noPackages) notes.push(`${new Set(registryPkgs.map(p => `${p.ecosystem}:${p.name}`)).size} package(s) were not downloaded for analysis (${args.offline ? '--offline' : '--no-packages'}); run ubel-package on them.`);
    else {
      const { results, keyOf } = await analysePackages(registryPkgs, { offline: args.offline, notes, log, max: args.maxPackages });
      for (const [, r] of results) { if (r.resolved) scanned.packages++; adopt(findings, r.findings); }
      for (const rec of finalRecords) for (const p of rec.launch?.packages || []) {
        const r = results.get(keyOf({ ecosystem: p.ecosystem, name: p.name, version: p.version }));
        if (r) p.analysis = r.error ? { error: r.error } : { analysed_version: r.resolved.version, findings: r.findings.length };
      }
    }
  }
  if (nonProbeable) notes.push(`${nonProbeable} server(s) run a container image or a native binary; their contents were not analysed here (see ubel-docker and ubel-binary).`);
  if (client) notes.push('Static scan of the configuration: nothing was contacted or started. ubel-mcp-server --from-config probes the declared servers, analyses their packages and source, and observes their processes.');
  else if (!finalRecords.length) notes.push('Nothing was found to scan: no declared server, endpoint, source or package.');
  if (client && !cfg.files.length && !args.sources.length) notes.push('No MCP client configuration was found. Use --config <file> or --project <dir>.');
  if (args.staticOnly) notes.push('--static-only: no server was contacted and /proc was not read.');
  // the same package behind two servers produces the same gap twice: say it once
  const uniq = a => [...new Set(a)];
  const keptGaps = uniq(notes.gaps || []), keptNotes = uniq([...notes]);
  notes.length = 0; notes.push(...keptNotes); notes.gaps.length = 0; notes.gaps.push(...keptGaps);      // `gaps` is read-only on Notes: change it in place
  return { servers: finalRecords, findings, notes, files: cfg.files.map(f => ({ client: f.client, file: f.file, scope: f.scope, servers: f.servers })), scanned };
}

/** The command line behind both binaries. */
export async function runCli(mode) {
  const M = MODES[mode];
  const args = parseArgs(process.argv.slice(2), mode);
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  provisionAssetAt(workingDir);
  const log = args.quiet ? () => {} : m => console.log(m);
  let scan;
  try { scan = await scanMcp(args, { log }); }
  catch (e) { console.error(`[${M.tool}] ${e.message}`); process.exitCode = 1; return; }

  const rank = SEVERITY_RANK[args.minSeverity];
  const everything = scan.findings.list.slice();
  const shown = everything.filter(f => (SEVERITY_RANK[f.severity] ?? 4) <= rank);
  const gate = evaluateGate({ failOn: args.failOnParsed, findings: everything, dependencies: [], gaps: scan.notes.gaps || [], allowPartial: args.allowPartial });
  const payload = writeReports({
    tag: M.tag,
    payloadMeta: { schema: 'ubel-mcp/1', tool: M.tool, generated_at: new Date().toISOString(), tool_version: TOOL_VERSION, min_severity: args.minSeverity, hidden_by_filter: everything.length - shown.length, gate },
    build: meta => buildPayload({ meta, servers: scan.servers, findings: shown, notes: scan.notes, files: scan.files, scanned: scan.scanned }),
    workingDir, quiet: args.quiet,
  });

  if (!args.quiet) {
    const c = payload.summary.counts;
    console.log(`\n=== MCP ${mode} security scan: ${payload.summary.servers} entr${payload.summary.servers === 1 ? 'y' : 'ies'}${payload.target.clients.length ? ` · ${payload.target.clients.join(', ')}` : ''} ===`);
    console.log(`Issues: ${payload.summary.total}  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info})`);
    if (!mode.startsWith('c')) console.log(`Probed live: ${payload.summary.servers_probed} (${payload.summary.servers_unauthenticated} without authentication) · tools read: ${payload.summary.tools} · packages analysed: ${payload.summary.packages_analysed} · running processes matched: ${payload.summary.processes_observed}`);
    for (const f of payload.findings.filter(x => x.severity !== 'info').slice(0, 40)) console.log(`  [${f.severity.toUpperCase()}] ${clean(f.title)} -- ${clean(f.artifact)}`);
    for (const n of payload.analysis_notes) console.log(`  note: ${clean(n)}`);
  }
  if (gate.exit_code === 2) console.error(`[${M.tool}] gate FAILED: ${gate.hits} issue(s) at or above ${args.failOnParsed.severity}${gate.tolerated ? ` (${gate.tolerated} tolerated)` : ''} (--fail-on ${gate.fail_on}).`);
  else if (gate.exit_code === 3) console.error(`[${M.tool}] gate INCOMPLETE: nothing tripped --fail-on ${gate.fail_on}, but ${gate.gaps} part(s) could not be analysed, so a clean result is not proof that everything is clean (exit 3; --allow-partial accepts this).`);
  process.exitCode = gate.exit_code;
}
