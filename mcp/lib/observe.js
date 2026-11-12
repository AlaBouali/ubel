'use strict';
// observe.js — ties MCP servers to the processes and sockets that exist right now (Linux /proc), and finds local servers that nobody declared.
// Nothing here talks to a server; probing the endpoints it finds is remote.js's job.

import path from 'node:path';
import { allProcesses, children, connections, listeners, looksLikeMcp, processInfo, isAnyAddr, isLoopbackAddr, supported } from './procfs.js';
import { redactArgs } from './config_checks.js';

export const DEFAULT_PORTS = [3000, 3001, 6277, 8000, 8080, 8081, 8765, 8931, 9000];
const NET_TOOLS = new Set(['nc', 'ncat', 'netcat', 'socat', 'curl', 'wget', 'ssh', 'scp', 'telnet', 'ftp', 'tftp']);
const SHELLS = new Set(['sh', 'bash', 'dash', 'zsh', 'fish', 'ash']);

export const procSupported = supported;
export { allProcesses };

/** What identifies a declared server in a command line: its package name, its absolute script path, its module or its image. Bare file names are not used. */
function needles(server, launch) {
  const out = [];
  for (const p of launch?.packages || []) if (p.source === 'registry' && p.name.length >= 4) out.push(p.name);
  if (server.resolvedScript && path.isAbsolute(server.resolvedScript)) out.push(server.resolvedScript);
  if (launch?.script?.module && launch.script.module.length >= 4) out.push(launch.script.module);
  if (launch?.image?.imageName) out.push(launch.image.imageName);
  return out.filter(n => n && n.length >= 4);
}

/** This process and everything that started it (the shell, a CI runner …) is the scanner's own, never a server. */
function ownChain(procs) {
  const own = new Set([process.pid]);
  for (let pid = process.pid, i = 0; i < 20; i++) { const p = procs.get(pid); if (!p?.ppid || own.has(p.ppid)) break; own.add(p.ppid); pid = p.ppid; }
  return own;
}

export function matchProcesses(server, launch, procs) {
  const ns = needles(server, launch);
  if (!ns.length) return [];
  const own = ownChain(procs);
  const out = [];
  for (const p of procs.values()) {
    if (own.has(p.pid) || !p.cmdline.length) continue;
    const line = p.cmdline.join(' ');
    if (ns.some(n => line.includes(n))) out.push(p);
  }
  return out.slice(0, 8);
}

/** Findings and an `observed` record for one running process of a server. */
export function describeProcess(server, p, procs, listenAll, findings) {
  const add = (rule, f) => findings.add(rule, { app: server.id, origin: 'app', ...f });
  const label = `pid ${p.pid} (${p.comm || '?'})`;
  const cmd = [p.cmdline[0], ...redactArgs(p.cmdline.slice(1))].join(' ').slice(0, 300);
  if (p.uid === 0 && !/^(?:docker|dockerd|containerd|podman)/.test(p.comm || '')) {
    add('mcp.process.root', { artifact: label, key: `root:${p.pid}`, description: `The process of the server "${server.name}" runs as root (${label}).`, evidence: [cmd] });
  }
  if (p.deleted) add('mcp.process.deleted_binary', { artifact: label, key: `deleted:${p.pid}`, description: `The executable of ${label}, ${p.exe}, was deleted while the process runs.`, evidence: [p.exe] });
  const kids = children(p.pid, procs);
  const sus = kids.filter(k => NET_TOOLS.has(k.comm) || SHELLS.has(k.comm));
  const net = sus.filter(k => NET_TOOLS.has(k.comm));
  if (sus.length) add('mcp.process.suspicious_child', {
    artifact: label, key: `children:${p.pid}`, severity: net.some(k => /^(?:nc|ncat|netcat|socat)$/.test(k.comm)) ? 'high' : net.length ? 'medium' : 'low',
    description: `${label} has ${sus.length} descendant process(es) that are ${net.length ? 'network tools' : 'shells'}: ${sus.slice(0, 5).map(k => k.comm).join(', ')}. A tool server normally starts neither, unless one of its tools is meant to run commands.`,
    evidence: sus.slice(0, 5).map(k => `pid ${k.pid} ${k.comm}: ${[k.cmdline[0], ...redactArgs(k.cmdline.slice(1))].join(' ').slice(0, 200)}`),
  });
  const mine = listenAll.filter(l => l.pid === p.pid || kids.some(k => k.pid === l.pid));
  for (const l of mine) {
    if (isAnyAddr(l.addr)) add('mcp.remote.network_exposed', { artifact: `http://127.0.0.1:${l.port}`, key: `bind:${l.port}`, description: `${label} listens on ${l.addr}:${l.port}, that is on every network interface, not only on loopback.`, evidence: [`${l.addr}:${l.port}`] });
  }
  return {
    pid: p.pid, ppid: p.ppid, uid: p.uid, comm: p.comm, cmdline: cmd, cwd: p.cwd, deleted: p.deleted || undefined,
    listening: mine.map(l => ({ addr: l.addr, port: l.port, any: isAnyAddr(l.addr), loopback: isLoopbackAddr(l.addr) })),
    connections: connections(p.pid).filter(c => !isLoopbackAddr(c.remote)).slice(0, 10).map(c => `${c.remote}:${c.remotePort}`),
    children: kids.slice(0, 10).map(k => k.comm),
  };
}

/**
 * Local endpoints worth probing. Linux: listening sockets owned by something that looks like an MCP server, plus listed/default ports.
 * Elsewhere (or without /proc): the listed/default ports on loopback, found by a connect attempt.
 * @returns {{host:string, port:number, process?:object}[]}
 */
export function candidateEndpoints({ ports, procs, tcpProbe }) {
  const want = new Set(ports);
  const out = [];
  if (supported()) {
    const seen = new Set();
    for (const l of listeners()) {
      const proc = l.pid ? (procs.get(l.pid) || processInfo(l.pid)) : null;
      const mcp = proc && looksLikeMcp(proc.cmdline.join(' '));
      if (!mcp && !want.has(l.port)) continue;
      const host = isAnyAddr(l.addr) || isLoopbackAddr(l.addr) ? (l.addr.includes(':') && l.addr !== '::' && !/^::ffff:/.test(l.addr) ? '[::1]' : '127.0.0.1') : l.addr;
      if (/^::/.test(l.addr) && !isAnyAddr(l.addr) && !isLoopbackAddr(l.addr)) continue;
      const k = `${host}:${l.port}`; if (seen.has(k)) continue; seen.add(k);
      out.push({ host, port: l.port, process: proc ? { pid: proc.pid, cmdline: proc.cmdline.slice(0, 6).join(' ').slice(0, 200) } : null });
    }
    return Promise.resolve(out);
  }
  return Promise.all([...want].map(async port => ((await tcpProbe('127.0.0.1', port, 300)) ? { host: '127.0.0.1', port, process: null } : null))).then(r => r.filter(Boolean));
}
