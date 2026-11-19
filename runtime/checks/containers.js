'use strict';
import path from 'node:path';
import { rule, vulnSeverity, cveOf, short, vulnFacts, sortVulns } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';

const RISKY_PORTS = { 2375: ['Docker API', 'critical'], 2379: ['etcd', 'high'], 3306: ['MySQL/MariaDB', 'medium'], 5432: ['PostgreSQL', 'medium'], 6379: ['Redis', 'high'], 9200: ['Elasticsearch', 'high'], 11211: ['Memcached', 'high'], 27017: ['MongoDB', 'high'], 9229: ['Node.js inspector', 'critical'] };
const ENGINE_SOCKET = /\/(?:docker|containerd|podman|crio)\.sock$/;

/** Resolves the engine answer once: returns { na } / { unassessed } / { list }. */
async function engine(ctx) {
  const r = await ctx.containers();
  if (r.status === 'unavailable') return { skip: na(r.reason) };
  if (r.status !== 'ok') return { skip: unassessed(r.reason) };
  return { list: r.containers.filter((c) => !c.error), failed: r.containers.filter((c) => c.error), socket: r.socket };
}
const res = (c) => `container ${c.name} (${String(c.image || '').slice(0, 60)})`;

export default [
  rule({
    id: 'rt-ctr-privileged', area: 'containers', severity: 'critical', title: 'Container runs in privileged mode',
    description: 'A privileged container has every capability, access to all host devices and no seccomp or AppArmor confinement: root inside it is effectively root on the host, and escaping is trivial.',
    remediation: 'Remove --privileged / privileged: true. Grant only the specific capabilities or devices the workload needs.',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => c.privileged).map((c) => ({ resource: res(c), scope: '', detail: 'HostConfig.Privileged is true.' })); },
  }),
  rule({
    id: 'rt-ctr-host-namespaces', area: 'containers', severity: 'high', title: 'Container shares a namespace with the host',
    description: 'The container uses the host\'s PID, IPC, user or network namespace, which removes the isolation between the container and the host (it can see and signal host processes, reach host-only network services, or share its memory).',
    remediation: 'Run the container in its own namespaces. Use published ports instead of host networking, and avoid --pid=host / --ipc=host.',
    cap: 100,
    async evaluate(ctx) {
      const e = await engine(ctx); if (e.skip) return e.skip;
      const out = [];
      for (const c of e.list) {
        const shared = [['pid', c.pid_mode === 'host', 'high'], ['ipc', c.ipc_mode === 'host', 'high'], ['user', c.userns_mode === 'host', 'medium'], ['network', c.network_mode === 'host', 'medium']].filter((x) => x[1]);
        if (shared.length) out.push({ resource: res(c), scope: '', severity: shared.some((x) => x[2] === 'high') ? 'high' : 'medium', detail: `Shares the host ${shared.map((x) => x[0]).join(', ')} namespace${shared.length > 1 ? 's' : ''}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-ctr-sensitive-mounts', area: 'containers', severity: 'high', title: 'Container mounts a sensitive part of the host',
    description: 'A host path such as /, /etc, /proc, /root, /dev, the container engine\'s data directory or its control socket is mounted into the container. Mounting the engine socket gives the container full control of the engine and therefore of the host.',
    remediation: 'Mount only the specific directories the workload needs, read-only where possible, and never the engine socket (use a socket proxy with an allow-list if a tool needs the API).',
    cap: 100,
    async evaluate(ctx) {
      const e = await engine(ctx); if (e.skip) return e.skip;
      const out = [];
      for (const c of e.list) for (const m of c.sensitive_mounts) {
        const sock = ENGINE_SOCKET.test(m.source), root = m.source === '/';
        out.push({ resource: `${res(c)} → ${m.source}`, scope: '', severity: sock || (root && m.rw) ? 'critical' : (m.rw ? 'high' : 'medium'), title: sock ? 'Container has the container engine socket mounted' : undefined,
          detail: `${m.source} is mounted at ${m.destination} (${m.rw ? 'read-write' : 'read-only'}).` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-ctr-dangerous-capabilities', area: 'containers', severity: 'high', title: 'Container was granted dangerous Linux capabilities',
    description: 'The container was started with capabilities such as SYS_ADMIN, SYS_PTRACE, SYS_MODULE, SYS_RAWIO, DAC_READ_SEARCH, NET_ADMIN or BPF (or ALL). These are the standard building blocks of container escapes.',
    remediation: '--cap-drop ALL and add back only what is needed; most services need none.',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => c.dangerous_caps.length && !c.privileged).map((c) => ({ resource: res(c), scope: '', detail: `CapAdd: ${c.dangerous_caps.join(', ')}.` })); },
  }),
  rule({
    id: 'rt-ctr-confinement-disabled', area: 'containers', severity: 'high', title: 'Container runs without seccomp / AppArmor / SELinux confinement',
    description: 'The container\'s security options switch off the default seccomp profile, AppArmor or SELinux label separation, leaving the kernel\'s full syscall surface available to it.',
    remediation: 'Remove seccomp=unconfined, apparmor=unconfined and label=disable from --security-opt.',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => !c.privileged && c.security_opt.some((o) => /(?:seccomp|apparmor)[=:]unconfined|label[=:]disable/.test(o))).map((c) => ({ resource: res(c), scope: '', detail: `SecurityOpt: ${c.security_opt.join(', ')}.` })); },
  }),
  rule({
    id: 'rt-ctr-env-secrets', area: 'containers', severity: 'medium', title: 'Container configuration carries a credential in its environment',
    description: 'A recognisable credential is part of the container\'s configured environment. It is readable by anyone who can run `docker inspect` (every member of the docker group) and stays in the engine\'s metadata after the container is gone.',
    remediation: 'Use Docker / Kubernetes secrets mounted as files or a secrets manager, and rotate the exposed credential.',
    cap: 100,
    async evaluate(ctx) {
      const e = await engine(ctx); if (e.skip) return e.skip;
      const { scanText } = await import('../../sca/secrets.js');
      const out = [];
      for (const c of e.list) {
        let hits; try { hits = scanText(c.env, 'container-env'); } catch { continue; }
        for (const h of hits) {
          const name = String(c.env[h.line - 1] || '').split('=')[0];
          out.push({ resource: `${res(c)} env ${name}`, scope: '', severity: /^generic-/.test(h.id) ? 'low' : 'medium', title: `${h.title} in a container's environment`, detail: `Variable ${name} holds ${h.title} (${h.match_preview}).` });
        }
      }
      return out;
    },
  }),
  rule({
    id: 'rt-ctr-published-ports', area: 'containers', severity: 'medium', title: 'Container publishes a sensitive port on all host interfaces',
    description: 'A database, cache, orchestration or debug port of a container is published on 0.0.0.0 / ::, making it reachable from every network the host is on (Docker\'s published ports also bypass most host firewall rules).',
    remediation: 'Publish on 127.0.0.1 (-p 127.0.0.1:6379:6379) or on a private network only, or do not publish it at all and let other containers reach it over a user-defined network.',
    cap: 100,
    async evaluate(ctx) {
      const e = await engine(ctx); if (e.skip) return e.skip;
      const out = [];
      for (const c of e.list) for (const p of c.ports) {
        const cp = Number(String(p.container).split('/')[0]); const r = RISKY_PORTS[cp];
        if (!r || /^127\.|^::1$/.test(p.host_ip)) continue;
        out.push({ resource: `${res(c)} :${p.host_port || cp}`, scope: '', severity: r[1], title: `${r[0]} port is published on all interfaces`, detail: `Container port ${p.container} is published on ${p.host_ip}:${p.host_port}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-ctr-run-as-root', area: 'containers', severity: 'low', title: 'Container runs as root',
    description: 'No unprivileged user is configured for the container (USER is empty, root or 0) and user-namespace remapping is not in use, so a flaw in the application gives root inside the container — the starting point of most escapes.',
    remediation: 'Set USER in the image or --user <uid>:<gid> at run time, and drop capabilities.',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => (!c.user || /^(root|0)(:|$)/.test(c.user)) && !c.userns_mode).map((c) => ({ resource: res(c), scope: '', detail: `Configured user: ${c.user || '(none — root)'}.` })); },
  }),
  rule({
    id: 'rt-ctr-no-resource-limits', area: 'containers', severity: 'low', title: 'Container has no memory or process limit',
    description: 'Without a memory limit one container can exhaust the host\'s RAM, and without a PIDs limit a fork bomb inside it can exhaust the host\'s process table — a cheap denial of service for everything else on the machine.',
    remediation: 'Set --memory and --pids-limit (Kubernetes: resources.limits.memory).',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => !c.memory_limit || !c.pids_limit).map((c) => ({ resource: res(c), scope: '', detail: `${!c.memory_limit ? 'No memory limit. ' : ''}${!c.pids_limit ? 'No PIDs limit.' : ''}`.trim() })); },
  }),
  rule({
    id: 'rt-ctr-mutable-image', area: 'containers', severity: 'low', title: 'Container was started from a mutable image tag',
    description: 'The image reference has no tag, or uses :latest, and is not pinned by digest. What runs after the next pull is not what was reviewed, and a compromised registry tag silently changes the workload.',
    remediation: 'Pin images by digest (image@sha256:…) or at least by an exact version tag, and update them deliberately.',
    cap: 100,
    async evaluate(ctx) { const e = await engine(ctx); if (e.skip) return e.skip; return e.list.filter((c) => c.image && !/@sha256:/.test(c.image) && (!/:[^/]+$/.test(c.image) || /:latest$/.test(c.image))).map((c) => ({ resource: res(c), scope: '', detail: `Image reference: ${c.image}.` })); },
  }),
  rule({
    id: 'rt-ctr-packages-vulnerable', area: 'containers', severity: 'high', title: 'Package installed in a running container has a known vulnerability',
    description: 'The package database of a running container (read through /proc/<pid>/root; no engine command is run) lists a package with an OSV.dev advisory for that container\'s distribution release. Opt-in because it queries OSV.dev for every container (--container-packages).',
    remediation: 'Rebuild the image from an updated base image, redeploy, and restart the container.',
    cap: 250,
    async evaluate(ctx) {
      if (!ctx.opts.containerPackages) return na('container package scan not requested (--container-packages)');
      if (ctx.opts.noLookups) return na('advisory lookups disabled (--no-lookups)');
      const e = await engine(ctx); if (e.skip) return e.skip;
      const { scanInstalledPackages, PackageScanUnsupported } = await import('../../vm/lib/pkgvulns.js');
      const out = [], errors = [];
      let scanned = 0;
      for (const c of e.list) {
        if (!c.pid) continue;
        const root = path.join(ctx.procs.root, String(c.pid), 'root');
        let r;
        try { r = await scanInstalledPackages({ root, threatIntel: ctx.opts.threatIntel, log: ctx.log }); } catch (x) { if (x instanceof PackageScanUnsupported) { ctx.notes.push(`${c.name}: no supported package database (${x.message}).`); continue; } errors.push(`${c.name}: ${x.message}`); continue; }
        scanned++;
        for (const v of r.vulnerabilities) {
          const fixed = (v.fixed_versions || [])[0];
          out.push({ resource: `${c.name}: ${v.affected_dependency}@${v.affected_dependency_version}: ${cveOf(v)}`, scope: '', severity: vulnSeverity(v), kev: v.is_kev === true,
            title: `${v.affected_dependency}: ${cveOf(v)}${v.summary ? ' — ' + short(v.summary) : ''}`,
            detail: `Container ${c.name} (${r.distro || r.ecosystem}) has ${v.affected_dependency} ${v.affected_dependency_version}. ${vulnFacts(v)}`,
            remediation: fixed ? `Rebuild ${c.image} with ${v.affected_dependency} ${fixed} or later and redeploy.` : `No fix is published yet: restrict exposure of ${c.name} and track ${v.url || v.id}.` });
        }
      }
      if (errors.length && !scanned) return unassessed(errors.slice(0, 3).join('; '));
      if (errors.length) ctx.notes.push(`Package scan failed for ${errors.length} container(s): ${errors.slice(0, 3).join('; ')}.`);
      return out.sort(sortVulns);
    },
  }),
];
