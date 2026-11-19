'use strict';
// docker.js — read-only view of the containers that are running, from the Docker / Podman Engine API over its unix socket
// (node:http with socketPath; no `docker` CLI). Only GET requests are ever sent: container list and container inspect.
// Environment variables of a container are returned by the API; they are inspected for secrets but never copied into a report.

import fs from 'node:fs';
import http from 'node:http';

const SOCKETS = ['/var/run/docker.sock', '/run/docker.sock', '/run/podman/podman.sock'];

export function socketCandidates(env = process.env) {
  const list = [];
  const dh = env.DOCKER_HOST || '';
  if (dh.startsWith('unix://')) list.push(dh.slice(7));
  if (typeof process.getuid === 'function') list.push(`/run/user/${process.getuid()}/podman/podman.sock`, `/run/user/${process.getuid()}/docker.sock`);
  list.push(...SOCKETS);
  return [...new Set(list)];
}

function get(socketPath, path, timeout = 5000) {
  return new Promise((resolve, reject) => {
    const req = http.request({ socketPath, path, method: 'GET', timeout, headers: { Host: 'localhost' } }, (res) => {
      let b = ''; res.setEncoding('utf8');
      res.on('data', (d) => { b += d; if (b.length > 32 * 1024 * 1024) req.destroy(new Error('response too large')); });
      res.on('end', () => { if (res.statusCode !== 200) return reject(Object.assign(new Error(`HTTP ${res.statusCode}`), { status: res.statusCode })); try { resolve(JSON.parse(b)); } catch { reject(new Error('invalid JSON from the container engine')); } });
    });
    req.on('timeout', () => req.destroy(Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' })));
    req.on('error', reject);
    req.end();
  });
}

/**
 * @returns {Promise<{status:'ok', socket:string, containers:object[]} | {status:'unavailable', reason:string} | {status:'denied', reason:string, socket:string} | {status:'error', reason:string, socket:string}>}
 * unavailable = no engine socket on this machine (the container checks are not applicable); denied / error = one exists but could not be read (not assessed).
 */
export async function listContainers({ env = process.env, sockets } = {}) {
  const found = (sockets || socketCandidates(env)).filter((s) => { try { return fs.statSync(s).isSocket(); } catch { return false; } });
  if (!found.length) return { status: 'unavailable', reason: 'no Docker / Podman engine socket on this machine' };
  let last = null;
  for (const socket of found) {
    try {
      const list = await get(socket, '/containers/json');
      const out = [];
      for (const c of list) {
        let d; try { d = await get(socket, `/containers/${encodeURIComponent(c.Id)}/json`); } catch (e) { out.push({ id: c.Id, name: (c.Names || [])[0] || c.Id.slice(0, 12), image: c.Image, error: e.message }); continue; }
        out.push(summarise(d));
      }
      return { status: 'ok', socket, containers: out };
    } catch (e) {
      last = e.code === 'EACCES' || e.code === 'EPERM'
        ? { status: 'denied', socket, reason: `permission denied on ${socket} (run as root, or as a user in the engine's group)` }
        : { status: 'error', socket, reason: `${socket}: ${e.message}` };
      if (last.status === 'denied') continue;
    }
  }
  return last;
}

const DANGEROUS_CAPS = new Set(['SYS_ADMIN', 'SYS_PTRACE', 'SYS_MODULE', 'SYS_RAWIO', 'DAC_READ_SEARCH', 'NET_ADMIN', 'SYS_BOOT', 'MAC_ADMIN', 'BPF', 'SYS_TIME', 'ALL']);
const SENSITIVE_HOST_PATHS = [/^\/$/, /^\/etc(\/|$)/, /^\/proc(\/|$)/, /^\/sys(\/|$)/, /^\/root(\/|$)/, /^\/boot(\/|$)/, /^\/dev(\/|$)/, /^\/var\/lib\/(docker|kubelet|containerd)(\/|$)/, /^\/(var\/)?run\/(docker|containerd|podman)[^/]*\.sock$/, /\/(docker|containerd|crio|podman)\.sock$/];

function summarise(d) {
  const h = d.HostConfig || {}, c = d.Config || {};
  const ports = [];
  for (const [k, v] of Object.entries(h.PortBindings || {})) for (const b of v || []) ports.push({ container: k, host_ip: b.HostIp || '0.0.0.0', host_port: Number(b.HostPort) || null });
  const mounts = (d.Mounts || []).map((m) => ({ type: m.Type, source: m.Source, destination: m.Destination, rw: m.RW !== false }));
  const capAdd = (h.CapAdd || []).map((x) => String(x).replace(/^CAP_/, '').toUpperCase());
  return {
    id: d.Id, name: String(d.Name || '').replace(/^\//, '') || String(d.Id).slice(0, 12), image: c.Image || d.Image, image_id: d.Image, created: d.Created, pid: d.State && d.State.Pid ? d.State.Pid : null,
    user: c.User || '', env: c.Env || [], labels: c.Labels || {},
    privileged: !!h.Privileged, pid_mode: h.PidMode || '', network_mode: h.NetworkMode || '', ipc_mode: h.IpcMode || '', userns_mode: h.UsernsMode || '',
    cap_add: capAdd, dangerous_caps: capAdd.filter((x) => DANGEROUS_CAPS.has(x)), cap_drop: (h.CapDrop || []).map((x) => String(x).replace(/^CAP_/, '').toUpperCase()),
    security_opt: h.SecurityOpt || [], readonly_rootfs: !!h.ReadonlyRootfs, memory_limit: h.Memory || 0, pids_limit: h.PidsLimit || 0, devices: (h.Devices || []).map((x) => x.PathOnHost),
    mounts, sensitive_mounts: mounts.filter((m) => m.source && SENSITIVE_HOST_PATHS.some((re) => re.test(m.source))),
    ports, restart_policy: (h.RestartPolicy && h.RestartPolicy.Name) || '',
  };
}
