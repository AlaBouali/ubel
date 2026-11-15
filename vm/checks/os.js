'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';
import { eolFor } from '../lib/eol.js';

function aptSources(ctx) {
  const files = ['/etc/apt/sources.list', ...ctx.fs.glob('/etc/apt/sources.list.d/*.list'), ...ctx.fs.glob('/etc/apt/sources.list.d/*.sources')];
  return files.filter((f) => ctx.fs.exists(f)).map((f) => ({ file: f, text: ctx.fs.read(f) || '' }));
}

export default [
  rule({
    id: 'vm-os-end-of-life', area: 'os', severity: 'high', title: 'Operating system release is past (or near) the end of vendor support',
    description: 'A release that no longer receives security updates accumulates unpatched vulnerabilities. The date comes from a table embedded in this tool version and covers the vendor\'s standard support only.',
    remediation: 'Upgrade to a supported release (or move the workload to a new image); where a paid extended-support programme is in place, record that decision.',
    evaluate(ctx) {
      const o = ctx.osRelease;
      if (!o) return na('no /etc/os-release');
      const e = eolFor({ id: o.id, versionId: o.versionId, name: o.name }, ctx.now);
      if (!e) return na(`${o.prettyName || o.id} is not in the embedded support-date table`);
      const label = `${e.product} ${e.version}`;
      if (e.ended) return [{ resource: `os:${o.id}-${o.versionId}`, detail: `${label} reached end of standard support on ${e.end} (${-e.daysLeft} days ago).${e.extended ? ' Note: ' + e.extended + '.' : ''}` }];
      if (e.daysLeft <= 90) return [{ resource: `os:${o.id}-${o.versionId}`, severity: 'low', detail: `${label} reaches end of standard support on ${e.end} (in ${e.daysLeft} days).` }];
      return [];
    },
  }),

  rule({
    id: 'vm-pkg-repo-integrity', area: 'os', severity: 'high', title: 'Package signature verification is disabled',
    description: 'The package manager is configured to install software without verifying its signature (gpgcheck=0, [trusted=yes], AllowUnauthenticated). A tampered mirror or on-path attacker can then supply malicious packages.',
    remediation: 'Remove the override: set gpgcheck=1 for the repository, drop [trusted=yes] / Trusted: yes, and delete AllowUnauthenticated / AllowInsecureRepositories settings; import the vendor signing key.',
    evaluate(ctx) {
      const out = [];
      for (const f of [...ctx.fs.glob('/etc/yum.repos.d/*.repo'), '/etc/yum.conf', '/etc/dnf/dnf.conf']) {
        const t = ctx.fs.read(f);
        if (!t) continue;
        let section = null, enabled = true;
        const flush = () => {};
        for (const l of t.split(/\r?\n/).map((x) => x.trim())) {
          const s = l.match(/^\[(.+)\]$/);
          if (s) { section = s[1]; enabled = true; flush(); continue; }
          if (/^enabled\s*=\s*0/i.test(l)) enabled = false;
          if (/^gpgcheck\s*=\s*0/i.test(l)) out.push({ resource: `${f}${section ? ' [' + section + ']' : ''}`, severity: enabled ? 'high' : 'low', detail: `gpgcheck=0${enabled ? '' : ' (repository disabled)'}.` });
        }
      }
      for (const { file, text } of aptSources(ctx)) {
        if (/^\s*deb(?:-src)?\s+\[[^\]]*trusted\s*=\s*yes/im.test(text) || /^\s*Trusted:\s*yes/im.test(text)) out.push({ resource: file, detail: 'Repository is marked trusted=yes, so its signatures are not checked.' });
      }
      for (const f of ['/etc/apt/apt.conf', ...ctx.fs.glob('/etc/apt/apt.conf.d/*')]) {
        const t = ctx.fs.read(f);
        if (t && /(AllowUnauthenticated|AllowInsecureRepositories|AllowDowngradeToInsecureRepositories)\s+"?(true|1|yes)/i.test(t)) out.push({ resource: f, detail: 'APT is configured to accept unauthenticated or insecure repositories.' });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-os-auto-updates', area: 'os', severity: 'low', title: 'Automatic security updates are not configured',
    description: 'Hosts that are not patched automatically (or by a patch-management system) fall behind quickly. Skip this finding if patching is handled by an external tool.',
    remediation: 'Debian/Ubuntu: install unattended-upgrades and set APT::Periodic::Unattended-Upgrade "1". RHEL family: enable dnf-automatic (apply_updates=yes) or yum-cron.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; the image is patched by rebuilding');
      if (ctx.family === 'debian') {
        const conf = ['/etc/apt/apt.conf.d/20auto-upgrades', '/etc/apt/apt.conf.d/10periodic'].map((f) => ctx.fs.read(f) || '').join('\n');
        const on = /Unattended-Upgrade\s+"?1"?/.test(conf);
        const pkg = ctx.hasPackage('unattended-upgrades');
        return on && pkg !== false ? [] : [{ resource: 'unattended-upgrades', detail: !pkg ? 'unattended-upgrades is not installed.' : 'APT::Periodic::Unattended-Upgrade is not enabled.' }];
      }
      if (ctx.family === 'rhel') {
        const w = ctx._unitIndex().wanted;
        const timer = [...w].some((u) => /^dnf-automatic.*\.timer$/.test(u)) || ctx.fs.exists('/etc/yum/yum-cron.conf') && ctx.serviceState('yum-cron').enabled;
        return timer ? [] : [{ resource: 'dnf-automatic', detail: 'No enabled dnf-automatic timer or yum-cron service.' }];
      }
      return na(`not evaluated for the ${ctx.family} family`);
    },
  }),

  rule({
    id: 'vm-os-reboot-required', area: 'os', severity: 'low', title: 'A reboot is pending to apply updates',
    description: 'Updated packages (often the kernel or libc) are installed but not yet in use, so known vulnerabilities may still be exploitable.',
    remediation: 'Schedule a reboot (and review which packages require it: cat /var/run/reboot-required.pkgs).',
    evaluate(ctx) {
      if (!ctx.live) return na('needs a live host');
      return ctx.fs.exists('/var/run/reboot-required') || ctx.fs.exists('/run/reboot-required') ? [{ resource: '/var/run/reboot-required' }] : [];
    },
  }),
];
