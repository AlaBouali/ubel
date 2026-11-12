'use strict';
// config_checks.js — static checks of one declared server: what its configuration says (credentials, auto-approval, project trust) and,
// for a local (stdio) server, how it is launched (command line, package pinning, container flags, the files it runs). Nothing is started.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { analyzeCommand } from '../../package/lib/installscripts.js';
import { scanText } from '../../sca/secrets.js';
import { mask } from '../../mobile/lib/findings.js';
import { isLoopbackHost } from './net.js';

const SECRET_NAME = /(?:token|secret|passw(?:or)?d|passwd|pwd|api[_-]?key|apikey|auth|bearer|credential|private[_-]?key|access[_-]?key|session|cookie|signature)/i;
const NOT_SECRET_NAME = /(?:^|[_-])(?:url|uri|host|hostname|path|file|dir|endpoint|region|user(?:name)?|id|type|mode|method|scheme|version|enabled|name|port|timeout)$/i;
const PLACEHOLDER = /\$\{[^}]*\}|\$\([^)]*\)|(?:^|\s)\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|\{\{[^}]*\}\}|<[^>\s]+>|^(?:your|my|insert|put|replace|example|changeme|change-me|xxx+|\*{3,}|todo|none|null|undefined|true|false)[-_ a-z0-9]*$|^\.{3,}$/i;

export const isPlaceholder = v => { const s = String(v ?? '').trim(); return !s || PLACEHOLDER.test(s.replace(/^(?:Bearer|Basic|Token)\s+/i, '')); };
export function entropy(s) {
  const f = new Map(); for (const c of s) f.set(c, (f.get(c) || 0) + 1);
  let h = 0; for (const n of f.values()) { const p = n / s.length; h -= p * Math.log2(p); }
  return h;
}
const expand = (p, home) => String(p).replace(/^~(?=$|[\\/])/, home).replace(/^\$\{?HOME\}?(?=$|[\\/])/, home);
const snippet = s => { const t = String(s).replace(/\s+/g, ' ').trim(); return t.length > 200 ? `${t.slice(0, 197)}…` : t; };

/** Is this literal value a credential? Returns {title, evidence, vendor:boolean} or null. Never returns the value itself. */
export function literalCredential(name, value) {
  const v = String(value ?? '');
  if (isPlaceholder(v) || v.length < 8) return null;
  let hit = null;
  try { hit = scanText([`${name}=${v}`], 'mcp-config.env')[0] || null; } catch { /* the engine is best-effort here */ }
  if (hit) return { title: hit.title, evidence: hit.match_preview || mask(v), vendor: true };
  if (SECRET_NAME.test(name) && !NOT_SECRET_NAME.test(name) && v.length >= 12 && entropy(v) >= 3.2 && !/^[./~]|^[a-z]+:\/\//i.test(v)) return { title: `${name} (literal value)`, evidence: `${name}=${mask(v)}`, vendor: false };
  return null;
}

/** Credentials in a URL: user:password@host, or a secret-named query parameter with a literal value. */
export function urlCredentials(url) {
  let u; try { u = new URL(url); } catch { return []; }
  const out = [];
  if (u.password && !isPlaceholder(decodeURIComponent(u.password))) out.push(`userinfo ${u.username}:${mask(u.password)}`);
  for (const [k, v] of u.searchParams) if (SECRET_NAME.test(k) && !NOT_SECRET_NAME.test(k) && v.length >= 8 && !isPlaceholder(v)) out.push(`?${k}=${mask(v)}`);
  return out;
}

const DOCKER_SENSITIVE = /^(?:\/|\/etc|\/root|\/home|\/Users|\/var\/run\/docker\.sock|\/run\/docker\.sock|\/proc|\/sys|\/dev|\/boot|\/var|\/usr)(?:\/?$|\/)|(?:^|[\\/])\.(?:ssh|aws|gnupg|kube|docker|config|azure|npmrc|netrc|git-credentials)(?:[\\/]|$)|docker\.sock$|^[A-Za-z]:[\\/]?$/;
const SAFE_SUBPATH = /^\/(?:home|Users)\/[^/]+\/(?!\.)[^/]+/;      // /home/u/project is a project dir, /home/u itself is not
function sensitiveMount(src, home) {
  const s = expand(src, home).replace(/\\/g, '/').replace(/\/+$/, '') || '/';
  if (!s.startsWith('/') && !/^[A-Za-z]:\//.test(s)) return null;      // a named volume
  if (s === home.replace(/\\/g, '/')) return 'the home directory';
  if (/\/\.(?:ssh|aws|gnupg|kube|docker|azure|config|npmrc|netrc|git-credentials)(?:\/|$)/.test(s)) return 'a credential directory';
  if (/docker\.sock$/.test(s)) return 'the Docker socket (root on the host)';
  if (s === '/' ) return 'the whole filesystem';
  if (/^\/(?:etc|root|proc|sys|dev|boot|var|usr)(?:\/|$)/.test(s) && !SAFE_SUBPATH.test(s)) return 'a system directory';
  if (/^\/(?:home|Users)$/.test(s)) return 'every user\'s home';
  return null;
}
export const isBroadPath = (p, home) => {
  const s = expand(p, home).replace(/\\/g, '/').replace(/\/+$/, '') || '/';
  return s === '/' || s === home.replace(/\\/g, '/') || /^\/(?:home|Users)$/.test(s) || /^[A-Za-z]:$/.test(s) || /^[A-Za-z]:\/(?:Users)?$/.test(s) || p === '~' || /^\$\{?HOME\}?$/.test(p);
};

/** @param {object} ctx {findings, notes, home, log} */
export function checkServerConfig(server, launch, ctx) {
  const { findings, home = os.homedir(), groups = null } = ctx;
  // groups: 'config' (credentials, approval), 'url' (how a remote server is declared), 'launch' (the command and what it runs). Default: all.
  // `server.resolvedScript` is always worked out, because process matching and source analysis need it whichever groups run.
  const on = g => !groups || groups.has(g);
  const app = server.id;
  const add = (rule, f) => findings.add(rule, { app, origin: 'app', ...f });
  const where = `${server.file} → ${server.name}`;

  if (on('config')) {
    // ── credentials written in the file ────────────────────────────────────────────────────────────────────────────────────────
    let secretCount = 0;
    const cred = (kind, name, value) => {
      const c = literalCredential(name, value);
      if (!c) return;
      secretCount++;
      add('mcp.config.hardcoded_secret', {
        title: `Credential written in plain text in an MCP configuration: ${c.title}`, artifact: where, key: `${kind}:${name}`,
        confidence: c.vendor ? 'high' : 'medium',
        description: `The ${kind} ${name} of the server "${server.name}" holds a literal credential in ${server.file}. Anyone who can read the file, a backup of it, or a repository it is committed to has the credential.${server.scope === 'project' ? ' This is a project-scoped file, so it is probably committed.' : ''}`,
        evidence: [c.evidence],
      });
    };
    for (const [k, v] of Object.entries(server.env)) cred('environment variable', k, v);
    for (const [k, v] of Object.entries(server.headers)) cred('header', k, v);
    for (let i = 0; i < server.args.length; i++) {
      const a = server.args[i];
      const kv = a.match(/^(?:--?)?([A-Za-z][\w.-]*)=(.+)$/s);                      // --api-key=…, -e KEY=…, KEY=…
      if (kv) cred('argument', kv[1], kv[2]);
      else if (/^--?[A-Za-z][\w-]*$/.test(a) && SECRET_NAME.test(a) && !NOT_SECRET_NAME.test(a) && i + 1 < server.args.length && !server.args[i + 1].startsWith('-')) cred('argument', a.replace(/^-+/, ''), server.args[i + 1]);
    }
    if (server.url) {
      const found = urlCredentials(server.url);
      if (found.length) { secretCount++; add('mcp.config.secret_in_url', { artifact: where, key: 'url', description: `The URL of the server "${server.name}" carries a credential (${found.length} found). ${server.url.split('?')[0]}`, evidence: found }); }
    }
    if (secretCount && server.fileMode != null && (server.fileMode & 0o044) && server.scope !== 'project') {
      findings.add('mcp.config.file_permissions', { app: `file:${server.file}`, origin: 'app', artifact: server.file, key: `mode:${server.file}`, severity: (server.fileMode & 0o004) ? 'medium' : 'low', description: `${server.file} holds literal credentials (for example in the server "${server.name}") and has mode ${server.fileMode.toString(8).padStart(3, '0')}: it can be read by ${(server.fileMode & 0o004) ? 'every user on the machine' : 'the owner\'s group'}.`, evidence: [`mode ${server.fileMode.toString(8).padStart(3, '0')}`] });
    }

    // ── approval ──────────────────────────────────────────────────────────────────────────────────────────────────────────────
    if (server.autoApprove || server.trust) {
      const list = Array.isArray(server.autoApprove) ? server.autoApprove.map(String) : [];
      const wildcard = server.autoApprove === true || server.trust || list.some(t => t === '*' || t === 'all');
      const risky = list.filter(t => /exec|shell|bash|command|run|eval|write|delete|remove|edit|move|create|sql|query/i.test(t));
      add('mcp.config.auto_approve', {
        artifact: where, key: 'auto_approve', severity: wildcard || risky.length ? 'high' : 'medium',
        description: wildcard ? `The server "${server.name}" is configured so that every tool call is approved without asking (${server.trust ? 'trust: true' : 'wildcard auto-approve'}).` : `${list.length} tool(s) of the server "${server.name}" are approved without asking${risky.length ? `, including ones that look like they run commands or change data (${risky.slice(0, 5).join(', ')})` : ''}.`,
        evidence: wildcard ? [server.trust ? 'trust: true' : 'auto-approve: *'] : list.slice(0, 20),
      });
    }
  }

  if (server.transport !== 'stdio') {
    // ── remote declaration ───────────────────────────────────────────────────────────────────────────────────────────────────
    if (on('url') && server.url) {
      let u; try { u = new URL(server.url); } catch { u = null; }
      if (u && u.protocol === 'http:' && !isLoopbackHost(u.hostname)) {
        const authed = Object.keys(server.headers).some(h => /^(?:authorization|x-api-key|api-key|cookie)$/i.test(h));
        add('mcp.remote.cleartext', { artifact: server.url, key: `cleartext:${server.url}`, severity: authed ? 'critical' : 'high', description: `The server "${server.name}" is declared with the plain-HTTP URL ${u.origin}${u.pathname}.${authed ? ' The configuration also sends credentials in its headers, so they cross the network unencrypted.' : ''}`, evidence: [`${u.protocol}//${u.host}`] });
      }
    }
    return;
  }

  if (on('launch')) {
    // ── launch command ────────────────────────────────────────────────────────────────────────────────────────────────────────
    const line = launch.wrapper ? launch.wrapper.inner : launch.commandLine;
    const analysis = analyzeCommand(launch.commandLine);
    const sig = id => analysis.signals.get(id);
    if (sig('download_exec')) add('mcp.launch.download_exec', { artifact: where, key: 'download_exec', description: `The command that starts the server "${server.name}" ${sig('download_exec').detail}. Whatever the remote host serves at that moment runs with the client's privileges, and nothing about it is pinned or reviewed.`, evidence: sig('download_exec').commands });
    if (sig('obfuscated_inline')) add('mcp.launch.obfuscated', { artifact: where, key: 'obfuscated', description: `The command that starts the server "${server.name}" ${sig('obfuscated_inline').detail}.`, evidence: sig('obfuscated_inline').commands });
    for (const [id, sev] of [['reverse_shell', 'critical'], ['crypto_mining', 'critical'], ['persistence', 'high'], ['destructive', 'high'], ['credential_access', 'medium'], ['privilege', 'medium']]) {
      const s = sig(id);
      if (s) add('mcp.launch.suspicious_command', { artifact: where, key: id, severity: sev, title: `Server command ${s.detail}`, description: `The command that starts the server "${server.name}" ${s.detail}.`, evidence: s.commands });
    }
    if (launch.privilegedPrefix && !sig('privilege')) add('mcp.launch.suspicious_command', { artifact: where, key: 'sudo', severity: 'medium', title: 'Server is started with elevated privileges', description: `The server "${server.name}" is started through sudo/doas, so a tool call that is steered by a poisoned prompt runs as root.`, evidence: [snippet(launch.commandLine)] });
    if (launch.wrapper) {
      add('mcp.launch.shell_wrapper', {
        artifact: where, key: 'shell_wrapper', severity: launch.wrapper.complex ? 'medium' : 'low',
        description: `The server "${server.name}" is started through ${launch.wrapper.kind}.${launch.wrapper.complex ? ' The string contains shell syntax (pipes, substitutions, variables or command separators), so what runs depends on how the shell expands it.' : ' The string is a plain command; on Windows this wrapper is common for launchers such as npx.'}`,
        evidence: [snippet(launch.wrapper.inner)],
      });
    }

    // ── packages fetched by a runner ──────────────────────────────────────────────────────────────────────────────────────────
    for (const p of launch.packages) {
      if (p.unsupported) continue;
      const label = `${p.ecosystem === 'npm' ? 'npm' : 'PyPI'} package ${p.name}`;
      if (p.source === 'registry' && p.pinClass !== 'exact') {
        add('mcp.launch.unpinned', {
          artifact: where, key: `unpinned:${p.name}`, severity: p.pinClass === 'range' ? 'low' : 'medium',
          description: `${launch.runner} fetches the ${label}${p.pinClass === 'range' ? ` within the range "${p.spec}"` : p.pinClass === 'tag' ? ` by the moving tag in "${p.spec}"` : ' with no version'} when the server "${server.name}" starts${p.autoInstall ? ' (and installs it without asking)' : ''}, so a new or compromised release is run on the next start.`,
          evidence: [p.spec],
        });
      } else if (p.source === 'git' || p.source === 'url') {
        if (p.pinClass !== 'commit' || p.insecure) add('mcp.launch.non_registry', {
          artifact: where, key: `non_registry:${p.spec}`, severity: p.insecure ? 'high' : 'medium',
          description: `The server "${server.name}" runs a package from ${p.source === 'git' ? 'a git repository' : 'a URL'}${p.pinClass === 'commit' ? '' : ' that is not pinned to a commit'}${p.insecure ? ' over an unencrypted connection' : ''}.`,
          evidence: [snippet(p.spec)],
        });
      }
    }

    // ── container ─────────────────────────────────────────────────────────────────────────────────────────────────────────────
    const img = launch.image;
    if (img) {
      if (!img.digest) add('mcp.launch.docker_unpinned', { artifact: where, key: `image:${img.image}`, severity: !img.tag || img.tag === 'latest' ? 'medium' : 'low', description: `The server "${server.name}" runs the image ${img.image}${!img.tag ? ' (no tag, so :latest)' : ''} by a tag, which its publisher can move to different content.`, evidence: [img.image] });
      const bad = [];
      if (img.privileged) bad.push('--privileged');
      for (const c of img.capAdd) if (/^(?:ALL|SYS_ADMIN|SYS_PTRACE|NET_ADMIN|SYS_MODULE|DAC_READ_SEARCH)$/i.test(c)) bad.push(`--cap-add ${c}`);
      for (const o of img.securityOpt) if (/unconfined|systempaths=unconfined/i.test(o)) bad.push(`--security-opt ${o}`);
      for (const d of img.devices) bad.push(`--device ${d}`);
      if (img.user === 'root' || img.user === '0') bad.push('--user root');
      if (bad.length) add('mcp.launch.docker_privileged', { artifact: where, key: 'docker_privileged', severity: img.privileged || bad.some(b => /ALL|SYS_ADMIN|unconfined|--device/.test(b)) ? 'high' : 'medium', description: `The container of the server "${server.name}" is started with ${bad.join(', ')}.`, evidence: bad });
      const mounts = img.volumes.map(v => ({ v, why: v.source ? sensitiveMount(v.source, home) : null })).filter(m => m.why);
      if (mounts.length) add('mcp.launch.docker_host_mount', { artifact: where, key: 'docker_mount', severity: mounts.some(m => /whole filesystem|Docker socket|credential/.test(m.why)) ? 'high' : 'medium', description: `The container of the server "${server.name}" mounts ${mounts.map(m => m.why).join(', ')} from the host${mounts.every(m => m.v.readonly) ? ' (read-only)' : ' read-write'}.`, evidence: mounts.map(m => m.v.spec) });
      const ns = [['--network', img.network, 'host'], ['--pid', img.pid, 'host'], ['--ipc', img.ipc, 'host'], ['--uts', img.uts, 'host']].filter(([, v, want]) => v === want).map(([f, v]) => `${f} ${v}`);
      if (ns.length) add('mcp.launch.docker_host_namespace', { artifact: where, key: 'docker_ns', description: `The container of the server "${server.name}" shares the host's ${ns.map(n => n.split(' ')[0].slice(2)).join(', ')} namespace.`, evidence: ns });
    }

    // ── filesystem server scope ───────────────────────────────────────────────────────────────────────────────────────────────
    if (launch.packages.some(p => /server-filesystem/.test(p.name)) || (img && /server-filesystem|mcp[-/]filesystem/.test(img.image))) {
      const dirs = (img ? img.containerArgs : launch.restArgs).filter(a => !a.startsWith('-'));
      const broad = dirs.filter(d => isBroadPath(d, home));
      if (broad.length) add('mcp.launch.broad_filesystem', { artifact: where, key: 'broad_fs', description: `The filesystem server "${server.name}" is given ${broad.map(d => `"${d}"`).join(', ')}, which covers the whole disk or the home directory (SSH keys, cloud credentials, browser profiles, other projects). The model, and anything that can steer it, can read and write all of it.`, evidence: broad });
    }
  }

  // ── local files the server runs ───────────────────────────────────────────────────────────────────────────────────────────
  const scriptPath = launch.script?.path || (launch.kind === 'binary' && launch.argv[0] && /[\\/]/.test(launch.argv[0]) ? launch.argv[0] : null);
  if (scriptPath) {
    const baseDir = server.cwd ? path.resolve(expand(server.cwd, home)) : server.projectDir || null;
    const abs = path.isAbsolute(expand(scriptPath, home)) ? expand(scriptPath, home) : baseDir ? path.resolve(baseDir, scriptPath) : null;
    server.resolvedScript = abs;
    if (abs && on('launch') && process.platform !== 'win32') {
      try {
        const st = fs.statSync(abs), dir = path.dirname(abs), ds = fs.statSync(dir);
        const problems = [];
        if (st.mode & 0o002) problems.push(`${abs} is world-writable (mode ${(st.mode & 0o777).toString(8)})`);
        if ((ds.mode & 0o002) && !(ds.mode & 0o1000)) problems.push(`${dir} is world-writable without the sticky bit`);
        if (/^\/(?:tmp|var\/tmp|dev\/shm)(?:\/|$)/.test(abs)) problems.push(`${abs} is in a directory that every user can write to`);
        if (problems.length) add('mcp.launch.writable_target', { artifact: where, key: `writable:${abs}`, description: `The server "${server.name}" runs ${abs}, which another user can replace: ${problems.join('; ')}.`, evidence: problems });
      } catch { /* a missing file is not a finding */ }
    }
    if (on('launch') && server.scope === 'project' && server.projectDir) {
      const inside = abs && (abs === server.projectDir || abs.startsWith(server.projectDir + path.sep));
      if (inside || launch.wrapper || /^\.{1,2}[\\/]/.test(scriptPath)) add('mcp.config.project_runs_repo_code', { artifact: where, key: 'project_code', description: `The project-scoped file ${server.file} starts the server "${server.name}" from ${launch.wrapper ? 'a shell string' : `${scriptPath}, which is part of the repository`}. Opening this project in an MCP-enabled client runs that code once the server is approved — or immediately, where the client trusts project servers.`, evidence: [snippet(launch.commandLine)] });
    }
  } else if (on('launch') && server.scope === 'project' && launch.wrapper?.complex) {
    add('mcp.config.project_runs_repo_code', { artifact: where, key: 'project_shell', description: `The project-scoped file ${server.file} starts the server "${server.name}" through a shell string.`, evidence: [snippet(launch.wrapper.inner)] });
  }
}

// ── what the report may show of a command line or URL (never a literal credential) ─────────────────────────────────────────────

export function redactArgs(args) {
  const out = [];
  for (let i = 0; i < args.length; i++) {
    const a = String(args[i]);
    const kv = a.match(/^(--?)?([A-Za-z][\w.-]*)=(.+)$/s);
    if (kv && literalCredential(kv[2], kv[3])) { out.push(`${kv[1] || ''}${kv[2]}=${mask(kv[3])}`); continue; }
    if (/^--?[A-Za-z][\w-]*$/.test(a) && SECRET_NAME.test(a) && !NOT_SECRET_NAME.test(a) && i + 1 < args.length && !String(args[i + 1]).startsWith('-') && literalCredential(a.replace(/^-+/, ''), args[i + 1])) { out.push(a, mask(args[i + 1])); i++; continue; }
    out.push(/^[a-z][a-z0-9+.-]*:\/\//i.test(a) ? redactUrl(a) : a);
  }
  return out;
}
export function redactUrl(url) {
  try {
    const u = new URL(url);
    if (u.password) u.password = '***';
    for (const [k, v] of [...u.searchParams]) if (SECRET_NAME.test(k) && !NOT_SECRET_NAME.test(k) && v && !isPlaceholder(v)) u.searchParams.set(k, mask(v));
    return u.href;
  } catch { return String(url); }
}
export const displayTarget = server => (server.transport === 'stdio' ? [server.command, ...redactArgs(server.args)].filter(Boolean).join(' ') : redactUrl(server.url || ''));
