'use strict';
// ubel-runtime — stdlib-only security scan of the applications running on a Linux machine.
//
// Reads /proc (processes, sockets, mapped files, environments)
// and — only when asked — the local container engine socket (read-only GETs), a loopback HTTP probe (--probe) and the V8 inspector
// of Node.js processes (--inspect). Node.js built-ins only: no third-party packages and no external programs are executed.

import os from 'node:os';
import { pathToFileURL } from 'node:url';
import { runCli, UsageError } from '../vm/lib/runner.js';
import { RuntimeContext } from './lib/context.js';
import { rules } from './checks/index.js';
import { RUNTIME_PROFILE } from './profile.js';
import { generateHtmlReport, buildReportPayload } from './lib/html_report.js';
import { groupByLabel, procLabel, scopeOf, isNodeExe } from './lib/util.js';
import { capNames } from './lib/procfs.js';
import { getComplianceForRuntimeCheck, getFrameworkIdsForRuntimeCheck } from '../sca/compliance_mappings.js';

const HELP = `
runtime-scanner — stdlib-only security scan of the applications running on this Linux machine

Usage:
  ubel-runtime [--pid <n,..>] [--name <text|/regex/>] [--node-only] [--include-self]
               [--libs app|all|none] [--max-libs <n>]
               [--inspect] [--inspect-max <n>] [--probe] [--no-lookups]
               [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>]
               [--only <checks|areas>] [--skip <checks|areas>] [--allow-partial] [--verbose] [--quiet]

Assesses what is running now: how each process is confined (root, capabilities, seccomp, tracing, debug interfaces, programs run from
deleted files, memory or temporary directories), what it listens on, the native libraries it has mapped (stale, injected, vulnerable),
the Node.js release it is made of (checked against NVD), credentials in process environments and command
lines, and — when a Docker / Podman socket is readable — the configuration of the running containers. It reads /proc and files only; the
two optional active steps below are opt-in.

Run it as root for a complete result: other users' environments, mapped files and sockets are unreadable otherwise, and the checks that
need them are reported as "not assessed" (exit 3 unless --allow-partial). Linux only.

Scope:
  --pid <n,..>             Only these process ids
  --name <text|/regex/>    Only processes whose name, executable or command line matches (repeatable)
  --node-only              Only Node.js processes
  --include-self           Also assess this scanner's own process (excluded by default)

Software:
  --libs app|all|none      Which mapped native files are read for embedded component versions: "app" = everything outside the
                           system library directories (default), "all" = system libraries too, "none" = skip
  --max-libs <n>           Read at most n distinct executables / libraries (default 150)
  --no-lookups             Do not query OSV.dev / NVD (the checks that need them become not applicable)

Opt-in active steps:
  --inspect                Look inside Node.js processes. For each one the scanner sends SIGUSR1 (only if the process handles it, otherwise it
                           would be killed), connects to the inspector that opens on loopback, reads the list of scripts V8 has compiled and
                           runs ONE read-only expression (process.versions), then closes the inspector again. The target process prints
                           "Debugger listening on ws://127.0.0.1:…" to its stderr. Needs the same user as the target, or root.
  --inspect-max <n>        Inspect at most n Node.js processes (default 25)
  --probe                  Send a few GET requests to the loopback ports the processes listen on (/, /.env, /.git/HEAD, actuator, metrics,
                           pprof, … ) to see what answers without authentication. Loopback only; never leaves this machine.
`;

const spec = {
  cli: 'ubel-runtime',
  tag: 'runtime',
  profile: RUNTIME_PROFILE,
  heading: 'Runtime Scan Summary',
  help: HELP,
  report: { generateHtmlReport, buildReportPayload },
  flags: {
    '--pid': { key: 'pids', value: true, list: true },
    '--name': { key: 'names', value: true, list: true },
    '--node-only': { key: 'nodeOnly', value: false },
    '--include-self': { key: 'includeSelf', value: false },
    '--libs': { key: 'libs', value: true, default: 'app' },
    '--max-libs': { key: 'maxLibs', value: true, number: true },
    '--inspect': { key: 'inspect', value: false },
    '--inspect-max': { key: 'inspectMax', value: true, number: true },
    '--probe': { key: 'probe', value: false },
    '--no-lookups': { key: 'noLookups', value: false },
  },
  async catalogue() { return { rules }; },

  async prepare(args, log) {
    if (process.platform !== 'linux') throw new UsageError(`ubel-runtime needs Linux and /proc (this is ${process.platform}).`);
    if (!['app', 'all', 'none'].includes(args.libs)) throw new UsageError(`--libs must be app, all or none (got "${args.libs}")`);
    let pids;
    if (args.pids) {
      pids = args.pids.map(Number);
      if (pids.some((n) => !Number.isInteger(n) || n <= 0)) throw new UsageError('--pid takes a comma-separated list of process ids');
    }
    const ctx = new RuntimeContext({
      pids, names: args.names, nodeOnly: !!args.nodeOnly, includeSelf: !!args.includeSelf, libs: args.libs,
      ...(args.maxLibs ? { maxLibs: args.maxLibs } : {}), inspect: !!args.inspect, ...(args.inspectMax ? { inspectMax: args.inspectMax } : {}),
      probe: !!args.probe, noLookups: !!args.noLookups, log,
    });
    if (!ctx.live) throw new UsageError('/proc is not available on this machine; ubel-runtime cannot see any process.');
    const targets = ctx.targets;
    log(`Assessing ${targets.length} process(es)`);
    if (!targets.length) ctx.notes.push('No process matched the selection; nothing was assessed.');

    if (args.inspect) await ctx.runInspections();

    const hostname = os.hostname();
    const target = { subject: hostname, hostname, os: `${os.type()} ${os.release()}`, arch: os.arch(), mode: 'live', processes_assessed: targets.length };
    const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    if (!isRoot) ctx.notes.push('ubel-runtime ran without root privileges; other users\' processes (environment, mapped files, sockets) were not readable and the checks that need them were limited to what could be read.');
    if (args.noLookups) ctx.notes.push('--no-lookups: OSV.dev / NVD were not queried; vulnerability checks were not applied.');

    return {
      ctx, rules, target,
      options: {
        scope: { ...(pids ? { pids } : {}), ...(args.names ? { names: args.names } : {}), ...(args.nodeOnly ? { node_only: true } : {}) },
        libs: args.libs, inspect: !!args.inspect, probe: !!args.probe, lookups: !args.noLookups,
      },
      notes: () => {
        const n = [...ctx.notes];
        if (ctx.procs.denied && ctx.procs.denied.size) n.push(`${ctx.procs.denied.size} /proc entr${ctx.procs.denied.size === 1 ? 'y was' : 'ies were'} unreadable (permission denied).`);
        const orphan = ctx.orphanListeners.length;
        if (orphan) n.push(`${orphan} listening socket(s) belong to processes that could not be identified (other users' processes): they are not attributed to any program.`);
        return n;
      },
      sameTarget: (prev) => !prev.target || !prev.target.hostname || prev.target.hostname === hostname,
      deps: { complianceFor: getComplianceForRuntimeCheck, frameworksFor: getFrameworkIdsForRuntimeCheck },
      meta: async () => ({ runtime: await buildRuntimeData(ctx) }),
    };
  },
};

/** What the report's Processes / Containers / Live data tabs show. No environment values, no pids in labels (pids are listed separately). */
async function buildRuntimeData(ctx) {
  const targets = ctx.targets;
  const listeners = ctx.targetListeners;
  const portsOf = new Map();
  for (const l of listeners) { if (!portsOf.has(l.pid)) portsOf.set(l.pid, []); portsOf.get(l.pid).push(`${l.addr}:${l.port}`); }
  const processes = groupByLabel(targets).map((g) => {
    const p = g.procs[0];
    const ports = [...new Set(g.procs.flatMap((x) => portsOf.get(x.pid) || []))];
    const insp = isNodeExe(p) ? g.procs.map((x) => ctx.inspectionOf(x)).find(Boolean) : null;
    return {
      label: g.label, scope: g.scope, count: g.procs.length, pids: g.procs.slice(0, 12).map((x) => x.pid), user: p.user || String(p.uid),
      root: p.uid === 0, exe: p.exe || null, deleted_exe: !!p.exeDeleted, started: p.startMs ? new Date(p.startMs).toISOString() : null,
      capabilities: capNames(p.caps && p.caps.eff).slice(0, 40), no_new_privs: !!p.noNewPrivs, seccomp: p.seccomp ?? null, listening: ports.slice(0, 20),
      node: isNodeExe(p), inspected: insp ? (insp.ok ? 'yes' : 'failed') : (isNodeExe(p) && ctx.opts.inspect ? 'no' : null),
    };
  }).sort((a, b) => (b.listening.length - a.listening.length) || a.label.localeCompare(b.label));

  const byPid = new Map(ctx.allProcesses.map((p) => [p.pid, p]));
  const listenerRows = listeners.map((l) => { const p = byPid.get(l.pid); return { address: l.addr, port: l.port, program: p ? procLabel(p) : null, scope: p ? scopeOf(p) : 'host' }; })
    .sort((a, b) => a.port - b.port).slice(0, 500);

  return { processes, listeners: listenerRows, containers: await buildContainers(ctx), inspections: buildInspections(ctx), summary: {
    processes: targets.length, programs: processes.length, node_processes: ctx.nodeTargets.length, listeners: listeners.length, inspected: [...ctx.inspections.values()].filter((i) => i.ok).length,
  } };
}

/** Container engine result, only when a check already asked for it (--only can leave the engine untouched). Environment values are never copied. */
async function buildContainers(ctx) {
  if (!ctx._memo.has('containers')) return null;
  const r = await ctx.containers();
  if (r.status !== 'ok') return { status: r.status, reason: r.reason };
  return {
    status: 'ok', socket: r.socket,
    items: r.containers.filter((c) => !c.error).map((c) => ({
      name: c.name, id: String(c.id).slice(0, 12), image: c.image, user: c.user || 'root (default)', privileged: c.privileged, network_mode: c.network_mode, pid_mode: c.pid_mode,
      dangerous_caps: c.dangerous_caps, sensitive_mounts: c.sensitive_mounts.map((m) => m.source), published_ports: c.ports.map((x) => `${x.host_ip}:${x.host_port} -> ${x.container}`),
      memory_limit: c.memory_limit, pids_limit: c.pids_limit,
    })).slice(0, 300),
  };
}

function buildInspections(ctx) {
  const out = [];
  for (const p of ctx.nodeTargets) {
    const r = ctx.inspectionOf(p); if (!r) continue;
    if (!r.ok) { out.push({ label: procLabel(p), scope: scopeOf(p), ok: false, reason: r.reason }); continue; }
    const loaded = ctx.loadedOf(p);
    out.push({
      label: procLabel(p), scope: scopeOf(p), ok: true, node_version: r.node && r.node.versions ? r.node.versions.node : null, opened_by_scanner: !!r.opened, left_open: !!r.leftOpen,
      scripts: r.scripts.length, loaded_files: loaded ? loaded.files.length : 0,
    });
  }
  return out;
}

async function main(argv) { return runCli(spec, argv); }

export { main, spec, buildRuntimeData };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
