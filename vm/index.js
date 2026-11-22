'use strict';
// ubel-vm — stdlib-only hardening audit of a Linux virtual machine / server.
//
// Reads configuration files, /proc and /sys of the machine it runs on (or of a mounted disk image given with
// --root) and evaluates a baseline of checks: SSH, accounts, PAM / sudo, file permissions,
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
  ubel-vm [--root <dir>] [--host-proc] [--skip-fs-walk] [--fs-max-entries <n>] [--fs-timeout <seconds>] [--skip-packages] [--skip-app-packages] [--app-roots <dirs>] [--no-threat-intel]
          [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>]
          [--only <checks|areas>] [--skip <checks|areas>] [--allow-partial] [--verbose] [--quiet]

Audits the machine ubel-vm runs on: operating-system support status, SSH, accounts / PAM / sudo, file permissions
(world-writable files, set-uid programs, cron, systemd units), kernel parameters, listening network services,
firewall, legacy services, Docker exposure, logging, time sync and credentials left in plain text — and the software installed
on it is checked for known vulnerabilities by the SCA engine (OSV.dev; set UBEL_OSV_ENDPOINT for an internal mirror): the
operating-system packages through its platform mode (docker mode for a --root image), and the application packages (npm,
Python, Composer, Bundler, Cargo, Go, NuGet, Maven, pub, SwiftPM) found under the application directories. Findings are
SCA vulnerabilities (sc_vuln / sc_infection) and open in the SCA vulnerability view. It reads files, /proc and /sys only — it
never executes a command and never changes anything.

Run it as root for a complete result: /etc/shadow, /etc/sudoers and other users' home directories are unreadable
otherwise, and the checks that need them are reported as "not assessed" (exit 3 unless --allow-partial).

VM options:
  --root <dir>             Audit a mounted disk image / extracted root filesystem instead of the running host.
                           Checks that need a live kernel (sysctl values, listening sockets, CPU mitigations,
                           running processes) are reported as not applicable. Works from any operating system.
  --host-proc              With --root: the root is a HOST filesystem mounted into this process (a pod with hostPID/hostNetwork);
                           /proc and /sys are then read from this process's own view, which is the host's kernel — so live checks
                           (sysctl, listening ports, kubelet flags) work.
  --skip-packages          Do not scan the installed packages (the package checks become not applicable)
  --skip-app-packages      Scan the operating-system packages only, not the application packages
  --app-roots <a,b>        Directories to scan for application packages in addition to the defaults
                           (/opt, /srv, /var/www, /app, /usr/src, /usr/local, /home, /root); with --root, paths are inside the root
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
    '--skip-app-packages': { key: 'skipAppPackages', value: false },
    '--app-roots': { key: 'appRoots', value: true, list: true },
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
      root, skipFsWalk: !!args.skipFsWalk, hostProc: !!args.hostProc, skipPackages: !!args.skipPackages, skipAppPackages: !!args.skipAppPackages, appRoots: args.appRoots || [],
      threatIntel: !args.noThreatIntel, workDir: args.workingDir, log,
      onPackageScan: (r) => {
        const vulnerablePackages = new Set(r.vulnerabilities.map((v) => v.affected_package_id));
        const ti = r.threatIntel || {};
        target.packages = {
          installed: r.os.installed, ecosystem: r.os.ecosystem, distro: r.os.distro, scan_mode: r.mode,
          advisories: r.osVulnerabilities.length, vulnerable_packages: new Set(r.osVulnerabilities.map((v) => v.affected_package_id)).size,
          ...(r.apps.scanned ? { application_packages: r.apps.installed, application_advisories: r.appVulnerabilities.length, application_vulnerable_packages: new Set(r.appVulnerabilities.map((v) => v.affected_package_id)).size, application_locations: r.apps.roots, application_packages_installed_by_the_distribution_skipped: r.apps.osInstalledSkipped } : {}),
          actively_exploited: r.vulnerabilities.filter((v) => v.is_kev === true).length, total_vulnerable_packages: vulnerablePackages.size,
          threat_intel: { kev: (ti.kev && ti.kev.status) || 'unknown', epss: (ti.epss && ti.epss.status) || 'unknown' },
          lookup: r.os.error || r.apps.error ? 'incomplete' : 'complete',
        };
        for (const n of r.notes) ctx.notes.push(n);
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
      options: { root, ...(args.hostProc ? { host_proc: true } : {}), skip_fs_walk: !!args.skipFsWalk, ...(args.skipPackages ? { packages: 'skipped' } : {}), ...(args.skipAppPackages ? { application_packages: 'skipped' } : {}), ...(args.appRoots ? { app_roots: args.appRoots } : {}) },
      // the installed-package list (operating-system and application packages) travels in the report: the canonical inventory is built from it
      meta: async () => {
        if (!ctx.pkgScanRan) return {};                  // no package check was evaluated (--skip / --only): do not start a scan for the report
        try { const r = await ctx.packageScan(); return r && Array.isArray(r.packages) && r.packages.length ? { package_inventory: r.packages } : {}; } catch { return {}; }
      },
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
