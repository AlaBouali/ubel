'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';

export default [
  rule({
    id: 'vm-log-auditd', area: 'logging', severity: 'medium', title: 'The Linux audit daemon is not installed or not enabled',
    description: 'auditd records security-relevant system calls, logins and file changes. Without it there is little evidence to investigate an incident, and several standards (PCI DSS Req. 10, NIST AU) expect it.',
    remediation: 'Install auditd (apt install auditd / dnf install audit) and enable it: systemctl enable --now auditd.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; auditing belongs to the host');
      const st = ctx.serviceState('auditd');
      const installed = st.installed || ctx.fs.exists('/etc/audit/auditd.conf') || ctx.hasPackage('auditd') === true || ctx.hasPackage('audit') === true;
      if (!installed) return [{ resource: 'auditd', detail: 'auditd is not installed.' }];
      if (!st.enabled && !st.running) return [{ resource: 'auditd', detail: 'auditd is installed but not enabled at boot' + (ctx.live ? ' and not running.' : '.') }];
      return [];
    },
  }),

  rule({
    id: 'vm-log-audit-rules', area: 'logging', severity: 'low', title: 'The audit daemon has no rules loaded from configuration',
    description: 'auditd is installed but no -w / -a rule is configured, so it records almost nothing useful.',
    remediation: 'Add rules under /etc/audit/rules.d/ (identity files, sudoers, logins, privileged commands, time changes) and run augenrules --load.',
    evaluate(ctx) {
      if (!ctx.fs.exists('/etc/audit/auditd.conf')) return na('auditd is not installed');
      const files = [...ctx.fs.glob('/etc/audit/rules.d/*.rules'), '/etc/audit/audit.rules'];
      const n = files.reduce((a, f) => a + (ctx.fs.lines(f) || []).filter((l) => /^-(w|a)\s/.test(l)).length, 0);
      return n ? [] : [{ resource: '/etc/audit/rules.d', detail: 'No -w or -a audit rule found.' }];
    },
  }),

  rule({
    id: 'vm-log-syslog', area: 'logging', severity: 'medium', title: 'No persistent system logging is configured',
    description: 'Neither a syslog daemon nor a persistent systemd journal was found, so logs may be lost at reboot or not kept at all.',
    remediation: 'Install and enable rsyslog (or syslog-ng), or set Storage=persistent in /etc/systemd/journald.conf and create /var/log/journal.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; logging belongs to the host');
      const syslog = ctx.serviceState('rsyslog', 'syslog-ng', 'syslogd', 'rsyslogd', 'syslog');
      if (syslog.enabled || syslog.running) return [];
      let persistent = ctx.fs.exists('/var/log/journal');
      for (const f of ['/etc/systemd/journald.conf', ...ctx.fs.glob('/etc/systemd/journald.conf.d/*.conf')]) {
        for (const l of ctx.fs.lines(f) || []) { const m = l.match(/^Storage\s*=\s*(\w+)/i); if (m) persistent = /persistent/i.test(m[1]); }
      }
      return persistent ? [] : [{ resource: 'logging', detail: 'No syslog daemon is enabled and the journal is not persistent.' }];
    },
  }),

  rule({
    id: 'vm-time-sync', area: 'logging', severity: 'low', title: 'No time-synchronisation service is enabled',
    description: 'Accurate clocks are needed to correlate logs, validate certificates and Kerberos tickets, and meet audit requirements.',
    remediation: 'Enable chrony or systemd-timesyncd (systemctl enable --now chronyd) with at least two reliable time sources.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; the host keeps time');
      const st = ctx.serviceState('chronyd', 'chrony', 'ntpd', 'ntp', 'ntpsec', 'openntpd', 'systemd-timesyncd', 'timesyncd');
      if (st.enabled || st.running) return [];
      const hyperv = ctx.fs.exists('/etc/chrony.conf') || ctx.fs.exists('/etc/ntp.conf');
      return [{ resource: 'time-sync', detail: hyperv ? 'A time-sync configuration exists but no service is enabled.' : 'No chrony, ntpd or systemd-timesyncd service is enabled.' }];
    },
  }),
];
