'use strict';
// ubel-vm — stdlib-only hardening audit of a Linux virtual machine / server.
//
// Reads configuration files, /proc and /sys of the machine it runs on (or of a mounted disk image given with
// --root) and evaluates a baseline of checks: OS support status, SSH, accounts, PAM / sudo, file permissions,
// kernel parameters, network exposure, services, logging and stored credentials. Node.js built-ins only: no
// third-party packages and no external programs are executed.

import fs from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { runCli, UsageError } from './lib/runner.js';
import { VmContext } from './lib/context.js';
import { rules } from './checks/index.js';
import { VM_PROFILE } from './profile.js';
import { getComplianceForVmCheck, getFrameworkIdsForVmCheck } from '../sca/compliance_mappings.js';

const HELP = `
vm-scanner — stdlib-only Linux VM / server hardening audit

Usage:
  ubel-vm [--root <dir>] [--host-proc] [--skip-fs-walk] [--fs-max-entries <n>] [--fs-timeout <seconds>] [--skip-packages] [--no-threat-intel]
          [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>]
          [--only <checks|areas>] [--skip <checks|areas>] [--allow-partial] [--verbose] [--quiet]

Audits the machine ubel-vm runs on: operating-system support status, SSH, accounts / PAM / sudo, file permissions
(world-writable files, set-uid programs, cron, systemd units), kernel parameters, listening network services,
firewall, legacy services, Docker exposure, logging, time sync and credentials left in plain text — and the installed
packages are checked against OSV.dev for known vulnerabilities (the same package-database read and OSV lookup as
ubel-docker; set UBEL_OSV_ENDPOINT for an internal mirror). It reads files, /proc and /sys only — it never executes a
command and never changes anything.

Run it as root for a complete result: /etc/shadow, /etc/sudoers and other users' home directories are unreadable
otherwise, and the checks that need them are reported as "not assessed" (exit 3 unless --allow-partial).

VM options:
  --root <dir>             Audit a mounted disk image / extracted root filesystem instead of the running host.
                           Checks that need a live kernel (sysctl values, listening sockets, CPU mitigations,
                           running processes) are reported as not applicable. Works from any operating system.
  --host-proc              With --root: the root is a HOST filesystem mounted into this process (a pod with hostPID/hostNetwork);
                           /proc and /sys are then read from this process's own view, which is the host's kernel — so live checks
                           (sysctl, listening ports, kubelet flags) work.
  --skip-packages          Do not look up the installed packages in OSV.dev (the package check becomes not applicable)
  --no-threat-intel        Do not fetch CISA KEV / FIRST EPSS data for the vulnerabilities found
  --skip-fs-walk           Skip the one-pass filesystem walk (world-writable files/dirs, set-uid programs)
  --fs-max-entries <n>     Stop the filesystem walk after n entries (default 3000000)
  --fs-timeout <seconds>   Stop the filesystem walk after this many seconds (default 90)
`;

const spec = {
  cli: 'ubel-vm',
  tag: 'vm',
  profile: VM_PROFILE,
  heading: 'VM Hardening Scan Summary',
  help: HELP,
  flags: {
    '--root': { key: 'root', value: true },
    '--host-proc': { key: 'hostProc', value: false },
    '--skip-packages': { key: 'skipPackages', value: false },
    '--no-threat-intel': { key: 'noThreatIntel', value: false },
    '--skip-fs-walk': { key: 'skipFsWalk', value: false },
    '--fs-max-entries': { key: 'fsMaxEntries', value: true, number: true },
    '--fs-timeout': { key: 'fsTimeout', value: true, number: true },
  },
  async catalogue() { return { rules }; },
  async prepare(args, log) {
    const root = args.root ? path.resolve(args.root) : '/';
    if (!args.root && process.platform !== 'linux') {
      throw new UsageError(`Live auditing needs Linux (this is ${process.platform}). To audit a Linux machine's disk image from here, mount it and pass --root <dir>.`);
    }
    let st;
    try { st = fs.statSync(root); } catch { throw new UsageError(`--root ${root} does not exist`); }
    if (!st.isDirectory()) throw new UsageError(`--root ${root} is not a directory`);

    if (args.hostProc && (!args.root || process.platform !== 'linux')) throw new UsageError('--host-proc needs --root <dir> (the mounted host filesystem) and a Linux scanner process');
    const target = {};
    const ctx = new VmContext({
      root, skipFsWalk: !!args.skipFsWalk, hostProc: !!args.hostProc, skipPackages: !!args.skipPackages, threatIntel: !args.noThreatIntel,
      onPackageScan: (r) => {
        const vulnerablePackages = new Set(r.vulnerabilities.map((v) => v.affected_package_id));
        target.packages = { installed: r.packageCount, ecosystem: r.ecosystem, distro: r.distro, advisories: r.vulnerabilities.length, vulnerable_packages: vulnerablePackages.size,
          actively_exploited: r.vulnerabilities.filter((v) => v.is_kev === true).length, advisories_for_other_releases_dropped: r.advisoriesDropped, threat_intel: { kev: r.intel.kev.status, epss: r.intel.epss.status } };
      },
      ...(args.fsMaxEntries ? { fsMaxEntries: args.fsMaxEntries } : {}),
      ...(args.fsTimeout ? { fsTimeoutMs: args.fsTimeout * 1000 } : {}),
    });
    if (!ctx.osRelease && !fs.existsSync(path.join(root, 'etc'))) {
      throw new UsageError(`${root} does not look like a Linux root filesystem (no /etc)`);
    }
    if (args.hostProc) {
      // /proc only describes the node when this process shares the host's PID namespace (hostPID: true): PID 1's root is then the host's, not ours.
      try {
        const a = fs.statSync('/proc/1/root/'), b = fs.statSync('/');
        if (a.ino === b.ino && a.dev === b.dev) ctx.notes.push('--host-proc was given but PID 1 shares this process\'s filesystem: the pod is not running with hostPID, so /proc describes the container, not the node. Run it with hostPID: true and hostNetwork: true.');
      } catch { ctx.notes.push('Could not confirm that /proc describes the host (reading /proc/1/root was denied): the pod needs hostPID: true and the SYS_PTRACE capability.'); }
    }
    log(`Auditing ${ctx.live ? (ctx.hostProc ? 'the host mounted at ' + root : 'the running host') : 'root filesystem ' + root}`);
    const env = ctx.environment;
    Object.assign(target, { subject: env.hostname || path.basename(root), ...env });
    if (ctx.live && typeof process.getuid === 'function' && process.getuid() !== 0) {
      ctx.notes.push('ubel-vm ran without root privileges; files readable only by root were skipped (those checks are listed as not assessed).');
    }
    return {
      ctx, rules, target,
      options: { root, ...(args.hostProc ? { host_proc: true } : {}), skip_fs_walk: !!args.skipFsWalk, ...(args.skipPackages ? { packages: 'skipped' } : {}) },
      notes: () => {
        const n = [...ctx.notes];
        if (ctx.fs.denied.size) n.push(`${ctx.fs.denied.size} file(s) could not be read (permission denied), e.g. ${[...ctx.fs.denied].slice(0, 3).join(', ')}.`);
        return n;
      },
      sameTarget: (prev) => !prev.target || !prev.target.hostname || !target.hostname || prev.target.hostname === target.hostname,
      deps: { complianceFor: getComplianceForVmCheck, frameworksFor: getFrameworkIdsForVmCheck },
    };
  },
};

async function main(argv) { return runCli(spec, argv); }

export { main, spec };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
