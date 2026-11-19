'use strict';
import { rule, needLive } from './util.js';
import { groupByLabel, pidList, procLabel, scopeOf, inTempDir, scriptOf, baseName } from '../lib/util.js';
import { capNames, capsFull, isLoopbackAddr } from '../lib/procfs.js';
import { explicitInspector } from '../lib/inspector.js';

// Daemons that legitimately run as root and listen on the network (they drop privileges for their workers, or are the host's own plumbing).
const ROOT_DAEMONS = /^(sshd|systemd.*|init|dockerd|containerd.*|kubelet|nginx|apache2|httpd|haproxy|master|cupsd|rpcbind|chronyd|ntpd|named|dnsmasq|smbd|nmbd|avahi-daemon|cron|crond|rsyslogd|polkitd|NetworkManager|snapd|tailscaled|sssd.*|rpc\..*|nfsd|mysqld_safe|unbound|crio|kube-.*|etcd|runc|python3?-?unattended.*)$/;
const DANGEROUS = new Set(['SYS_ADMIN', 'SYS_MODULE', 'SYS_RAWIO', 'SYS_PTRACE', 'DAC_READ_SEARCH', 'BPF', 'SYS_BOOT']);

export default [
  rule({
    id: 'rt-proc-deleted-exe', area: 'processes', severity: 'medium', title: 'Process runs a program file that was deleted or replaced on disk',
    description: 'The executable of this process was removed or replaced after the process started. Either an update was installed without restarting the process (the old, possibly vulnerable code keeps running), or the file was deleted to hide it.',
    remediation: 'Restart the process (or service) so that it runs the file that is on disk now. If you did not update this program, treat the process as suspicious and find out how it was started.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      return groupByLabel(ctx.targets.filter((p) => p.exeDeleted && !p.exeMemfd)).map((g) => ({ resource: g.label, scope: g.scope, detail: `${pidList(g)}; deleted file: ${g.procs[0].exe}.` }));
    },
  }),
  rule({
    id: 'rt-proc-memfd-exec', area: 'processes', severity: 'high', title: 'Process runs from an anonymous memory file (fileless execution)',
    description: 'The executable of this process lives in a memfd (an in-memory file with no path on disk). Fileless execution is how malware avoids leaving a binary behind; container runtimes use it too for their own helper, which is excluded here.',
    remediation: 'Identify the parent process and how this was started. If it is not a container runtime or a tool you recognise, isolate the host and investigate.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      return groupByLabel(ctx.targets.filter((p) => p.exeMemfd && !/^\/memfd:(runc|crun|youki)/.test(p.exe))).map((g) => ({ resource: g.label, scope: g.scope, detail: `${pidList(g)}; executable ${g.procs[0].exe}.` }));
    },
  }),
  rule({
    id: 'rt-proc-code-in-temp', area: 'processes', severity: 'high', title: 'Process runs a program or script from a world-writable directory',
    description: 'The executable or the script of this process is located in /tmp, /var/tmp or /dev/shm. Any local user can write there, and dropped payloads are usually run from there.',
    remediation: 'Install the program in a directory only its owner can write (for example /opt/<app> or /usr/local/bin). If you do not recognise it, treat it as a possible compromise.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      return groupByLabel(ctx.targets.filter((p) => inTempDir(p.exe) || inTempDir(scriptOf(p)))).map((g) => ({ resource: g.label, scope: g.scope, detail: `${pidList(g)}; ${inTempDir(g.procs[0].exe) ? 'executable ' + g.procs[0].exe : 'script ' + scriptOf(g.procs[0])}.` }));
    },
  }),
  rule({
    id: 'rt-proc-root-network-service', area: 'processes', severity: 'medium', title: 'Network service runs as root',
    description: 'A process running as root accepts connections on a non-loopback address. A flaw in the service gives an attacker root straight away. Well-known daemons that drop privileges for their workers (sshd, nginx, dockerd …) are not listed.',
    remediation: 'Run the service as a dedicated unprivileged user (bind low ports with CAP_NET_BIND_SERVICE or a reverse proxy), and in containers set a non-root USER.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [];
      const seen = new Set();
      for (const l of ctx.targetListeners) {
        if (isLoopbackAddr(l.addr)) continue;
        const p = ctx.byPid(l.pid);
        if (!p || p.uid !== 0 || ROOT_DAEMONS.test(p.comm || '') || ROOT_DAEMONS.test(baseName(p.exe))) continue;
        const k = `${procLabel(p)}:${l.port}:${scopeOf(p)}`;
        if (seen.has(k)) continue; seen.add(k);
        out.push({ resource: `${procLabel(p)} :${l.port}`, scope: scopeOf(p), severity: p.container ? 'low' : 'medium', detail: `pid ${p.pid} (uid 0) listens on ${l.addr}:${l.port}.${p.container ? ' Inside a container root is the default, but it is still root of that container.' : ''}` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-proc-excess-capabilities', area: 'processes', severity: 'high', title: 'Process holds dangerous Linux capabilities',
    description: 'A containerised process, or a non-root process, holds capabilities that allow it to escape or tamper with the host (SYS_ADMIN, SYS_MODULE, SYS_PTRACE, SYS_RAWIO, DAC_READ_SEARCH, BPF, SYS_BOOT), or a container has the complete capability set (a privileged container).',
    remediation: 'Drop all capabilities and add back only what the workload needs (docker: --cap-drop ALL --cap-add …; Kubernetes: securityContext.capabilities.drop: [ALL]). Never run a container with --privileged.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [];
      for (const g of groupByLabel(ctx.targets.filter((p) => p.caps.eff && (p.container || p.uid !== 0)))) {
        const p = g.procs[0];
        const eff = capNames(p.caps.eff);
        if (p.container && capsFull(p.caps.eff)) { out.push({ resource: g.label, scope: g.scope, severity: 'critical', title: 'Container process has the complete capability set (privileged container)', detail: `${pidList(g)}; all ${eff.length} capabilities are effective.` }); continue; }
        const bad = eff.filter((c) => DANGEROUS.has(c));
        if (bad.length) out.push({ resource: g.label, scope: g.scope, detail: `${pidList(g)}; effective: ${bad.join(', ')}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-proc-traced', area: 'processes', severity: 'medium', title: 'Process is being traced by another process',
    description: 'Another process is attached to this one with ptrace (TracerPid is set). That is what debuggers do, and also what credential stealers and code injectors do.',
    remediation: 'Check what the tracer is. Detach debuggers from production processes; if the tracer is unknown, investigate.',
    cap: 50,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      return ctx.targets.filter((p) => p.tracerPid > 0).map((p) => { const t = ctx.byPid(p.tracerPid); return { resource: `${procLabel(p)} (pid ${p.pid})`, scope: scopeOf(p), detail: `traced by pid ${p.tracerPid}${t ? ` (${procLabel(t)})` : ''}.` }; });
    },
  }),
  rule({
    id: 'rt-proc-debug-interface-exposed', area: 'processes', severity: 'high', title: 'Debugger interface is enabled on a running service',
    description: 'A Node.js process was started with --inspect, or a JVM with the JDWP agent. These interfaces have no authentication and allow arbitrary code execution in the process for anyone who can connect.',
    remediation: 'Remove --inspect / -agentlib:jdwp from production start-up (NODE_OPTIONS included). If a debugger is needed, bind it to 127.0.0.1 and reach it through an SSH tunnel.',
    cap: 50,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [];
      for (const p of ctx.targets) {
        const insp = ctx.inspectionOf(p);
        const ex = explicitInspector(p, ctx.environOf(p));
        const jdwp = p.cmdline.join(' ').match(/(?:-agentlib:jdwp|-Xrunjdwp)[^ ]*?address=(?:[^,: ]*:)?(\*?:?\d+)/);
        const jdwpHost = p.cmdline.join(' ').match(/jdwp[^ ]*address=([^,: ]+):\d+/);
        const ls = ctx.targetListeners.filter((l) => l.pid === p.pid && (ex ? l.port === ex.port : jdwp ? String(jdwp[1]).replace(/\D/g, '') === String(l.port) : false));
        if (insp && insp.ok && insp.opened && ex == null) continue;                       // the inspector WE opened is reported by rt-insp-left-open, if it was left open
        if (!ex && !jdwp) continue;
        const exposed = ls.some((l) => !isLoopbackAddr(l.addr)) || (ex && ex.wildcard) || (jdwp && (!jdwpHost || /^(\*|0\.0\.0\.0)$/.test(jdwpHost[1])));
        out.push({ resource: procLabel(p), scope: scopeOf(p), severity: exposed ? 'critical' : 'medium', title: exposed ? 'Debugger interface is listening on a non-loopback address' : undefined,
          detail: `pid ${p.pid}: ${ex ? `${ex.flag} (port ${ex.port})` : 'JDWP agent'}${exposed ? ' is reachable from other hosts — unauthenticated remote code execution.' : ' is bound to loopback only: any local user can still attach.'}` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-proc-no-sandbox', area: 'processes', severity: 'low', title: 'Network-facing process has no seccomp filter and no_new_privs',
    description: 'A process that accepts connections from other hosts runs without a seccomp syscall filter and without no_new_privs, so a compromise of it has the full kernel attack surface to work with. systemd units can add SystemCallFilter= and NoNewPrivileges=, containers get a default seccomp profile.',
    remediation: 'Apply a seccomp profile (container runtime default, or SystemCallFilter=@system-service in the unit) and set NoNewPrivileges=true / allowPrivilegeEscalation: false.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const pids = new Set(ctx.targetListeners.filter((l) => !isLoopbackAddr(l.addr)).map((l) => l.pid));
      return groupByLabel(ctx.targets.filter((p) => pids.has(p.pid) && p.seccomp === 0 && p.noNewPrivs === false)).map((g) => ({ resource: g.label, scope: g.scope, detail: pidList(g) + '.' }));
    },
  }),
];
