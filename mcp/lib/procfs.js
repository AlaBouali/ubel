'use strict';
// procfs.js — what a running MCP server looks like from the outside, read from /proc (Linux only; no ps, lsof, ss or netstat).
//   listeners()        TCP sockets in LISTEN state with the process that owns them
//   connections(pid)   established TCP connections of one process
//   processInfo(pid)   command line, working directory, executable, owner, parent
//   children(pid)      descendants of a process
// Other users' processes are readable only as root; whatever cannot be read is skipped, never guessed.

import fs from 'node:fs';

export const supported = () => process.platform === 'linux' && fs.existsSync('/proc/net/tcp');
const rd = p => { try { return fs.readFileSync(p, 'utf8'); } catch { return null; } };
const link = p => { try { return fs.readlinkSync(p); } catch { return null; } };

function hexIp(hex) {
  if (hex.length === 8) return [3, 2, 1, 0].map(i => parseInt(hex.slice(i * 2, i * 2 + 2), 16)).join('.');
  const words = hex.match(/.{8}/g).map(w => w.match(/../g).reverse().join(''));      // four little-endian 32-bit words
  const g = words.join('').match(/.{4}/g);
  if (g.slice(0, 5).every(x => x === '0000') && g[5] === 'ffff') return `::ffff:${parseInt(g[6].slice(0, 2), 16)}.${parseInt(g[6].slice(2), 16)}.${parseInt(g[7].slice(0, 2), 16)}.${parseInt(g[7].slice(2), 16)}`;
  return g.map(x => x.replace(/^0+(?=.)/, '')).join(':').replace(/(?:^|:)0(?::0)+(?::|$)/, '::');
}
export const isAnyAddr = a => a === '0.0.0.0' || a === '::' || a === '::ffff:0.0.0.0';
export const isLoopbackAddr = a => /^127\./.test(a) || a === '::1' || /^::ffff:127\./.test(a);

function parseTcp(file, wantState) {
  const text = rd(file); if (!text) return [];
  const out = [];
  for (const line of text.split('\n').slice(1)) {
    const f = line.trim().split(/\s+/);
    if (f.length < 10 || f[3] !== wantState) continue;
    const [lh, lp] = f[1].split(':'), [rh, rp] = f[2].split(':');
    out.push({ addr: hexIp(lh), port: parseInt(lp, 16), remote: hexIp(rh), remotePort: parseInt(rp, 16), inode: f[9] });
  }
  return out;
}

/** inode → pid for every socket the caller may inspect. */
function socketOwners(limit = 20000) {
  const map = new Map();
  let n = 0;
  let pids = [];
  try { pids = fs.readdirSync('/proc').filter(x => /^\d+$/.test(x)); } catch { return map; }
  for (const pid of pids) {
    let fds; try { fds = fs.readdirSync(`/proc/${pid}/fd`); } catch { continue; }
    for (const fd of fds) {
      if (++n > limit) return map;
      const l = link(`/proc/${pid}/fd/${fd}`);
      const m = l && l.match(/^socket:\[(\d+)\]$/);
      if (m && !map.has(m[1])) map.set(m[1], Number(pid));
    }
  }
  return map;
}

export function listeners() {
  const owners = socketOwners();
  const all = [...parseTcp('/proc/net/tcp', '0A'), ...parseTcp('/proc/net/tcp6', '0A')];
  return all.map(l => ({ ...l, pid: owners.get(l.inode) ?? null }));
}
export function connections(pid) {
  const owners = new Set();
  let fds = []; try { fds = fs.readdirSync(`/proc/${pid}/fd`); } catch { return []; }
  for (const fd of fds) { const m = (link(`/proc/${pid}/fd/${fd}`) || '').match(/^socket:\[(\d+)\]$/); if (m) owners.add(m[1]); }
  return [...parseTcp('/proc/net/tcp', '01'), ...parseTcp('/proc/net/tcp6', '01')].filter(c => owners.has(c.inode)).map(c => ({ addr: c.addr, port: c.port, remote: c.remote, remotePort: c.remotePort }));
}

export function processInfo(pid) {
  const cmd = rd(`/proc/${pid}/cmdline`);
  if (cmd == null) return null;
  const stat = rd(`/proc/${pid}/stat`) || '';
  const after = stat.slice(stat.lastIndexOf(')') + 2).split(' ');
  const status = rd(`/proc/${pid}/status`) || '';
  const exe = link(`/proc/${pid}/exe`);
  return {
    pid: Number(pid), ppid: Number(after[1]) || null, uid: Number((status.match(/^Uid:\s+(\d+)/m) || [])[1] ?? -1),
    comm: (stat.match(/\(([^)]*)\)/) || [])[1] || null,
    cmdline: cmd.split('\0').filter(Boolean), cwd: link(`/proc/${pid}/cwd`), exe, deleted: !!exe && / \(deleted\)$/.test(exe),
  };
}

export function allProcesses(limit = 6000) {
  const out = new Map();
  let pids = []; try { pids = fs.readdirSync('/proc').filter(x => /^\d+$/.test(x)); } catch { return out; }
  for (const pid of pids.slice(0, limit)) { const p = processInfo(pid); if (p) out.set(p.pid, p); }
  return out;
}
export function children(pid, procs, depth = 3) {
  const by = new Map();
  for (const p of procs.values()) (by.get(p.ppid) || by.set(p.ppid, []).get(p.ppid)).push(p);
  const out = []; let layer = [pid];
  for (let d = 0; d < depth && layer.length; d++) { const next = []; for (const x of layer) for (const c of by.get(x) || []) { out.push(c); next.push(c.pid); } layer = next; }
  return out;
}

/** Does this command line look like an MCP server or an MCP bridge? */
export const looksLikeMcp = cmdline => /@modelcontextprotocol\/|\bmcp[-_]?(?:server|remote|proxy|bridge|gateway|inspector)\b|\bserver-(?:filesystem|github|memory|puppeteer|slack|postgres|sqlite|fetch|everything|brave-search|gdrive|git|time|sequential-thinking)\b|\bfastmcp\b|\bsupergateway\b|\bplaywright\/mcp\b|(?:^|[\s/\\])mcp[-_.][\w.-]*(?:\.(?:js|mjs|py|ts))?(?:\s|$)|[\w-]+-mcp(?:@|\s|$|\/)/i.test(cmdline);
