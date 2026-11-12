'use strict';
// clients.js — finds the MCP client configuration files on this machine (and in project directories) and reads the servers they declare.
// Pure fs + JSON / JSONC / TOML parsing. Nothing is started and nothing is contacted. A file that does not exist is skipped silently;
// a file that exists but cannot be read or parsed is reported as an analysis gap.
//
// The locations below are the ones the clients document or are known to use. They change between client versions, so --config <file>
// reads any file with the same shapes, and --project <dir> looks for the project-scoped files in another directory.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { parseJsonc } from './jsonc.js';
import { parseToml } from '../../package/lib/toml.js';

const MAX_CONFIG_BYTES = 5 * 1024 * 1024;

function roots(home, platform = process.platform) {
  const appData = process.env.APPDATA || path.join(home, 'AppData', 'Roaming');
  const vsUser = name => platform === 'darwin' ? path.join(home, 'Library', 'Application Support', name, 'User')
    : platform === 'win32' ? path.join(appData, name, 'User') : path.join(home, '.config', name, 'User');
  const claudeDir = platform === 'darwin' ? path.join(home, 'Library', 'Application Support', 'Claude')
    : platform === 'win32' ? path.join(appData, 'Claude') : path.join(home, '.config', 'Claude');
  const zed = platform === 'win32' ? path.join(appData, 'Zed', 'settings.json') : path.join(home, '.config', 'zed', 'settings.json');
  const managed = platform === 'darwin' ? '/Library/Application Support/ClaudeCode/managed-mcp.json'
    : platform === 'win32' ? 'C:\\Program Files\\ClaudeCode\\managed-mcp.json' : '/etc/claude-code/managed-mcp.json';
  return { vsUser, claudeDir, zed, managed };
}

/** The files to read: [{client, file, scope, keys, format, flags?}]. `keys` says where in the file the server table lives. */
export function clientSources({ home = os.homedir(), projects = [], extra = [], platform = process.platform } = {}) {
  const r = roots(home, platform);
  const S = [];
  const add = (client, file, scope, keys, format = 'jsonc', extraProps = {}) => S.push({ client, file, scope, keys, format, ...extraProps });
  add('claude-desktop', path.join(r.claudeDir, 'claude_desktop_config.json'), 'user', ['mcpServers']);
  add('claude-code', path.join(home, '.claude.json'), 'user', ['mcpServers', 'projects.*.mcpServers']);
  add('claude-code', r.managed, 'managed', ['mcpServers']);
  add('claude-code', path.join(home, '.claude', 'settings.json'), 'user', [], 'jsonc', { settings: true });
  add('cursor', path.join(home, '.cursor', 'mcp.json'), 'user', ['mcpServers']);
  for (const [label, dir] of [['vscode', 'Code'], ['vscode-insiders', 'Code - Insiders'], ['vscodium', 'VSCodium']]) {
    add(label, path.join(r.vsUser(dir), 'mcp.json'), 'user', ['servers']);
    add(label, path.join(r.vsUser(dir), 'settings.json'), 'user', ['mcp.servers']);
    add(`${label}:cline`, path.join(r.vsUser(dir), 'globalStorage', 'saoudrizwan.claude-dev', 'settings', 'cline_mcp_settings.json'), 'user', ['mcpServers']);
    add(`${label}:roo`, path.join(r.vsUser(dir), 'globalStorage', 'rooveterinaryinc.roo-cline', 'settings', 'mcp_settings.json'), 'user', ['mcpServers']);
  }
  add('windsurf', path.join(home, '.codeium', 'windsurf', 'mcp_config.json'), 'user', ['mcpServers']);
  add('zed', r.zed, 'user', ['context_servers']);
  add('gemini-cli', path.join(home, '.gemini', 'settings.json'), 'user', ['mcpServers']);
  add('codex', path.join(process.env.CODEX_HOME || path.join(home, '.codex'), 'config.toml'), 'user', ['mcp_servers'], 'toml');
  add('amazon-q', path.join(home, '.aws', 'amazonq', 'mcp.json'), 'user', ['mcpServers']);
  add('lm-studio', path.join(home, '.lmstudio', 'mcp.json'), 'user', ['mcpServers']);
  for (const dir of projects) {
    const d = path.resolve(dir);
    add('claude-code', path.join(d, '.mcp.json'), 'project', ['mcpServers'], 'jsonc', { projectDir: d });
    add('claude-code', path.join(d, '.claude', 'settings.json'), 'project', [], 'jsonc', { settings: true, projectDir: d });
    add('claude-code', path.join(d, '.claude', 'settings.local.json'), 'project', [], 'jsonc', { settings: true, projectDir: d });
    add('cursor', path.join(d, '.cursor', 'mcp.json'), 'project', ['mcpServers'], 'jsonc', { projectDir: d });
    add('vscode', path.join(d, '.vscode', 'mcp.json'), 'project', ['servers'], 'jsonc', { projectDir: d });
    add('gemini-cli', path.join(d, '.gemini', 'settings.json'), 'project', ['mcpServers'], 'jsonc', { projectDir: d });
    add('amazon-q', path.join(d, '.amazonq', 'mcp.json'), 'project', ['mcpServers'], 'jsonc', { projectDir: d });
    add('roo', path.join(d, '.roo', 'mcp.json'), 'project', ['mcpServers'], 'jsonc', { projectDir: d });
    add('zed', path.join(d, '.zed', 'settings.json'), 'project', ['context_servers'], 'jsonc', { projectDir: d });
  }
  for (const f of extra) add('custom', path.resolve(f), 'custom', ['mcpServers', 'servers', 'context_servers', 'mcp_servers', 'mcp.servers', 'projects.*.mcpServers'], f.endsWith('.toml') ? 'toml' : 'jsonc');
  return S;
}

const isObj = v => v && typeof v === 'object' && !Array.isArray(v);
const get = (o, dotted) => dotted.split('.').reduce((a, k) => (isObj(a) ? a[k] : undefined), o);

/** [{table, scopeSuffix}] for a `keys` spec; `projects.*.mcpServers` fans out over the per-project tables of ~/.claude.json. */
function tables(data, keys) {
  const out = [];
  for (const k of keys) {
    if (k.includes('*')) {
      const [head, tail] = k.split('.*.');
      const parent = get(data, head);
      if (isObj(parent)) for (const [p, v] of Object.entries(parent)) if (isObj(v) && isObj(v[tail])) out.push({ table: v[tail], scopeSuffix: `local:${p}` });
    } else {
      const t = get(data, k);
      if (isObj(t)) out.push({ table: t, scopeSuffix: '' });
    }
  }
  return out;
}

const str = v => (typeof v === 'string' ? v : undefined);
const strMap = o => (isObj(o) ? Object.fromEntries(Object.entries(o).map(([k, v]) => [k, v == null ? '' : String(v)])) : {});

/** One server entry → the normalized record every later step works from. */
export function normalizeServer(name, raw, src, scopeSuffix = '') {
  if (!isObj(raw)) return null;
  let command = raw.command, args = raw.args, env = raw.env ?? raw.environment, cwd = raw.cwd;
  if (isObj(command)) { env = env ?? command.env; args = command.args ?? args; command = command.path ?? command.command; }   // Zed: command: {path, args, env}
  if (Array.isArray(command)) { args = command.slice(1); command = command[0]; }                                            // OpenCode-style array form
  const url = str(raw.url) ?? str(raw.serverUrl) ?? str(raw.httpUrl) ?? str(raw.endpoint);
  const type = String(raw.type ?? raw.transport ?? '').toLowerCase();
  let transport = null;
  if (/^(?:http|streamable[-_]?http|streamablehttp)$/.test(type)) transport = 'http';
  else if (type === 'sse') transport = 'sse';
  else if (type === 'stdio') transport = 'stdio';
  else if (url) transport = raw.httpUrl ? 'http' : 'remote';          // type unknown: try Streamable HTTP, then legacy SSE
  else if (command) transport = 'stdio';
  if (!transport) return null;
  const auto = raw.autoApprove ?? raw.alwaysAllow ?? raw.auto_approve ?? raw.alwaysAllowTools;
  const scope = scopeSuffix ? scopeSuffix : src.scope;
  const target = transport === 'stdio' ? [command, ...(Array.isArray(args) ? args : [])].join(' ') : url;
  return {
    id: `${src.client}:${scope}:${name}`, key: `${name}|${target}`, name, client: src.client, scope, file: src.file, projectDir: src.projectDir || null,
    transport, command: str(command), args: Array.isArray(args) ? args.map(String) : [], env: strMap(env), cwd: str(cwd),
    url, headers: strMap(raw.headers ?? raw.http_headers), disabled: raw.disabled === true || raw.enabled === false,
    autoApprove: auto === true || (Array.isArray(auto) && auto.length) ? auto : null,
    trust: raw.trust === true,
  };
}

/** @returns {{servers:object[], flags:object[], files:object[], notes:string[], gaps:string[]}} */
export function readClientConfigs(sources) {
  const servers = [], flags = [], files = [], notes = [], gaps = [];
  const seen = new Set();
  for (const src of sources) {
    let st;
    try { st = fs.statSync(src.file); } catch { continue; }
    if (!st.isFile()) continue;
    const dedupe = `${src.file}|${src.keys.join(',')}|${src.settings ? 's' : ''}`;
    if (seen.has(dedupe)) continue;
    seen.add(dedupe);
    if (st.size > MAX_CONFIG_BYTES) { gaps.push(`${src.file}: not read, ${Math.round(st.size / 1048576)} MB is over the ${MAX_CONFIG_BYTES / 1048576} MB limit.`); continue; }
    let data;
    try {
      const text = fs.readFileSync(src.file, 'utf8');
      data = src.format === 'toml' ? parseToml(text).data : parseJsonc(text);
    } catch (e) { gaps.push(`${src.file}: could not be parsed (${e.message}); the servers it declares were not analysed.`); continue; }
    if (!isObj(data)) continue;
    const fileInfo = { client: src.client, file: src.file, scope: src.scope, mode: process.platform === 'win32' ? null : st.mode & 0o777, uid: st.uid ?? null, servers: 0 };
    if (src.settings) {
      if (data.enableAllProjectMcpServers === true) flags.push({ id: 'trust_project_servers', client: src.client, file: src.file, scope: src.scope });
      files.push(fileInfo);
      continue;
    }
    for (const { table, scopeSuffix } of tables(data, src.keys)) {
      for (const [name, raw] of Object.entries(table)) {
        const s = normalizeServer(name, raw, src, scopeSuffix);
        if (s) { s.fileMode = fileInfo.mode; s.fileUid = fileInfo.uid; servers.push(s); fileInfo.servers++; }
      }
    }
    files.push(fileInfo);
  }
  return { servers, flags, files, notes, gaps };
}
