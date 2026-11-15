'use strict';
import { rule, fmtMode } from './util.js';
import { na } from '../lib/engine.js';

const NOLOGIN = /(nologin|false)$/;
const SYSTEM_OK = new Set(['root', 'sync', 'shutdown', 'halt']);

function pamFiles(ctx) {
  return ctx._memo('pam', () => {
    const names = ctx.fs.readdir('/etc/pam.d');
    if (!names) return null;
    return names.map((n) => ({ file: `/etc/pam.d/${n}`, lines: ctx.fs.lines(`/etc/pam.d/${n}`) || [] }));
  });
}

function sudoers(ctx) {
  return ctx._memo('sudoers', () => {
    const files = [];
    if (ctx.fs.exists('/etc/sudoers')) files.push('/etc/sudoers');
    for (const n of ctx.fs.readdir('/etc/sudoers.d') || []) if (!/[.~]/.test(n)) files.push(`/etc/sudoers.d/${n}`);
    return files.map((f) => ({ file: f, lines: ctx.fs.lines(f) || [] }));
  });
}

export default [
  rule({
    id: 'vm-account-empty-password', area: 'accounts', severity: 'critical', title: 'Account has an empty password',
    description: 'An account with no password can be logged into without any secret (local console, su, and SSH if PermitEmptyPasswords or nullok allow it).',
    remediation: 'Set a password or lock the account: passwd -l <user>',
    evaluate(ctx) {
      const sh = ctx.shadow();
      if (sh === null) return na('/etc/shadow does not exist');
      const out = [];
      for (const [name, e] of sh) if (e.hash === '') out.push({ resource: `user:${name}`, detail: `Account "${name}" has an empty password field in /etc/shadow.` });
      for (const u of ctx.passwd() || []) if (u.pw === '') out.push({ resource: `user:${u.name}`, detail: `Account "${u.name}" has an empty password field in /etc/passwd.` });
      return out;
    },
  }),

  rule({
    id: 'vm-account-uid0-nonroot', area: 'accounts', severity: 'critical', title: 'A non-root account has UID 0',
    description: 'Any account with UID 0 is a second root: it has full control and is easy to overlook, which makes it a classic persistence mechanism.',
    remediation: 'Remove the account or give it a normal UID: usermod -u <new> <user> (or userdel).',
    evaluate(ctx) {
      const pw = ctx.passwd();
      if (!pw) return na('/etc/passwd does not exist');
      return pw.filter((u) => u.uid === 0 && u.name !== 'root').map((u) => ({ resource: `user:${u.name}`, detail: `"${u.name}" has UID 0.` }));
    },
  }),

  rule({
    id: 'vm-account-passwd-hash', area: 'accounts', severity: 'high', title: 'Password hash stored in /etc/passwd',
    description: '/etc/passwd is world-readable; a password hash kept there is exposed to offline cracking by every local user.',
    remediation: 'Move hashes to /etc/shadow with pwconv.',
    evaluate(ctx) {
      const pw = ctx.passwd();
      if (!pw) return na('/etc/passwd does not exist');
      return pw.filter((u) => u.pw && !['x', '*', '!', '!!'].includes(u.pw)).map((u) => ({ resource: `user:${u.name}`, detail: `Account "${u.name}" keeps its password hash in /etc/passwd.` }));
    },
  }),

  rule({
    id: 'vm-account-weak-hash', area: 'accounts', severity: 'medium', title: 'Account password uses a weak hash algorithm',
    description: 'Passwords hashed with DES or MD5 crypt can be cracked quickly offline.',
    remediation: 'Set ENCRYPT_METHOD to SHA512 (or YESCRYPT) in /etc/login.defs and have the user change their password.',
    evaluate(ctx) {
      const sh = ctx.shadow();
      if (sh === null) return na('/etc/shadow does not exist');
      const out = [];
      for (const [name, e] of sh) {
        const h = (e.hash || '').replace(/^!+/, '');
        if (!h || h === '*' || h === 'x') continue;
        if (h.startsWith('$1$')) out.push({ resource: `user:${name}`, detail: `"${name}" uses MD5-crypt ($1$).` });
        else if (!h.startsWith('$') && h.length === 13) out.push({ resource: `user:${name}`, severity: 'high', detail: `"${name}" uses legacy DES crypt.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-account-system-shell', area: 'accounts', severity: 'medium', title: 'System account has an interactive login shell',
    description: 'Service accounts should not be able to start an interactive shell; if the service is compromised the attacker gets one for free.',
    remediation: 'usermod -s /usr/sbin/nologin <user>',
    evaluate(ctx) {
      const pw = ctx.passwd();
      if (!pw) return na('/etc/passwd does not exist');
      const min = Number(ctx.loginDefs().get('UID_MIN')) || 1000;
      const shells = ctx.validShells();
      return pw.filter((u) => u.uid > 0 && u.uid < min && !SYSTEM_OK.has(u.name) && u.shell && !NOLOGIN.test(u.shell) && shells.has(u.shell))
        .map((u) => ({ resource: `user:${u.name}`, detail: `"${u.name}" (uid ${u.uid}) has shell ${u.shell}.` }));
    },
  }),

  rule({
    id: 'vm-account-duplicate-uid', area: 'accounts', severity: 'low', title: 'Two accounts share the same UID',
    description: 'Accounts sharing a UID are indistinguishable to the kernel and to file permissions, which defeats accountability.',
    remediation: 'Give each account a unique UID (usermod -u) and re-own its files.',
    evaluate(ctx) {
      const pw = ctx.passwd();
      if (!pw) return na('/etc/passwd does not exist');
      const by = new Map();
      for (const u of pw) by.set(u.uid, [...(by.get(u.uid) || []), u.name]);
      return [...by].filter(([, n]) => n.length > 1).map(([uid, n]) => ({ resource: `uid:${uid}`, detail: `UID ${uid} is shared by ${n.join(', ')}.` }));
    },
  }),

  rule({
    id: 'vm-account-password-aging', area: 'accounts', severity: 'low', title: 'Password ageing is not configured',
    description: 'PASS_MAX_DAYS is unset or very long, so passwords never have to be changed. Several standards (for example PCI DSS where passwords are the only factor) require a maximum password lifetime.',
    remediation: 'Set PASS_MAX_DAYS (for example 365 or the value your policy requires) in /etc/login.defs; use chage for existing accounts.',
    evaluate(ctx) {
      if (!ctx.fs.exists('/etc/login.defs')) return na('/etc/login.defs does not exist');
      const v = Number(ctx.loginDefs().get('PASS_MAX_DAYS'));
      return !Number.isFinite(v) || v === 0 || v > 365 ? [{ resource: '/etc/login.defs', detail: `PASS_MAX_DAYS is ${ctx.loginDefs().get('PASS_MAX_DAYS') ?? 'unset (default 99999)'}.` }] : [];
    },
  }),

  rule({
    id: 'vm-account-encrypt-method', area: 'accounts', severity: 'medium', title: 'login.defs hashes new passwords with a weak algorithm',
    description: 'ENCRYPT_METHOD selects DES or MD5 for newly set passwords.',
    remediation: 'Set ENCRYPT_METHOD SHA512 (or YESCRYPT) in /etc/login.defs.',
    evaluate(ctx) {
      if (!ctx.fs.exists('/etc/login.defs')) return na('/etc/login.defs does not exist');
      const v = (ctx.loginDefs().get('ENCRYPT_METHOD') || '').toUpperCase();
      return v === 'DES' || v === 'MD5' ? [{ resource: '/etc/login.defs', detail: `ENCRYPT_METHOD is ${v}.` }] : [];
    },
  }),

  rule({
    id: 'vm-account-umask', area: 'accounts', severity: 'low', title: 'Default umask is more permissive than 027',
    description: 'New files are created readable by every local user when the default umask is 022.',
    remediation: 'Set UMASK 027 in /etc/login.defs (and in /etc/profile or /etc/bashrc if they override it).',
    evaluate(ctx) {
      if (!ctx.fs.exists('/etc/login.defs')) return na('/etc/login.defs does not exist');
      const raw = ctx.loginDefs().get('UMASK');
      const v = raw === undefined ? 0o022 : parseInt(raw, 8);
      return Number.isNaN(v) || (v & 0o027) !== 0o027 ? [{ resource: '/etc/login.defs', detail: `UMASK is ${raw ?? 'unset (default 022)'}.` }] : [];
    },
  }),

  rule({
    id: 'vm-account-home-permissions', area: 'accounts', severity: 'medium', title: 'A home directory is writable by other users',
    description: 'If anyone can write into a user\'s home directory they can plant shell start-up files and run code as that user.',
    remediation: 'chmod go-w <home> (750 or 700 is typical).',
    evaluate(ctx) {
      const out = [];
      for (const u of ctx.interactiveUsers()) {
        if (!u.home || u.home === '/') continue;
        const st = ctx.fs.stat(u.home);
        if (st && st.isDir && (st.mode & 0o002)) out.push({ resource: u.home, detail: `${fmtMode(st)} (user ${u.name}).` });
        else if (st && st.isDir && (st.mode & 0o020) && u.uid !== 0) out.push({ resource: u.home, severity: 'low', detail: `Group-writable: ${fmtMode(st)} (user ${u.name}).` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-account-trust-files', area: 'accounts', severity: 'high', title: 'Legacy remote-trust files (.rhosts / hosts.equiv) exist',
    description: 'rhosts-style trust lets remote hosts log in without a password; the mechanism is obsolete and easily abused.',
    remediation: 'Delete the file(s) and make sure no rsh/rlogin service is installed.',
    evaluate(ctx) {
      const out = [];
      for (const f of ['/etc/hosts.equiv', '/etc/shosts.equiv']) if (ctx.fs.exists(f)) out.push({ resource: f });
      for (const u of ctx.passwd() || []) {
        if (!u.home || u.home === '/' || !/^\//.test(u.home)) continue;
        for (const n of ['.rhosts', '.shosts']) if (ctx.fs.exists(`${u.home}/${n}`)) out.push({ resource: `${u.home}/${n}`, detail: `(user ${u.name})` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-sudo-nopasswd', area: 'accounts', severity: 'medium', title: 'sudo allows commands without a password',
    description: 'NOPASSWD (or !authenticate) lets anyone who gets a session as that user run privileged commands with no further proof of identity.',
    remediation: 'Remove NOPASSWD / !authenticate from the sudoers entry, or limit it to the specific commands that need it.',
    evaluate(ctx) {
      const files = sudoers(ctx);
      if (!files.length) return na('sudo is not configured (no /etc/sudoers)');
      const out = [];
      for (const { file, lines } of files) {
        for (const l of lines) {
          if (/^Defaults/.test(l) && /!authenticate/.test(l)) out.push({ resource: file, detail: `"${l}"` });
          else if (/NOPASSWD\s*:/.test(l) && !/^(Defaults|#)/.test(l)) out.push({ resource: file, severity: /NOPASSWD\s*:\s*ALL\b/.test(l) ? 'medium' : 'low', detail: `"${l.replace(/\s+/g, ' ')}"` });
        }
      }
      return out;
    },
  }),

  rule({
    id: 'vm-pam-nullok', area: 'accounts', severity: 'high', title: 'PAM allows logins with empty passwords (nullok)',
    description: 'pam_unix with the nullok option accepts accounts that have no password.',
    remediation: 'Remove "nullok" from the pam_unix.so lines (e.g. /etc/pam.d/common-auth or system-auth / password-auth).',
    evaluate(ctx) {
      const files = pamFiles(ctx);
      if (!files) return na('/etc/pam.d does not exist');
      const out = [];
      for (const { file, lines } of files) for (const l of lines) if (/^-?auth\b/.test(l) && /pam_unix\.so/.test(l) && /\bnullok/.test(l)) out.push({ resource: file, detail: `"${l.replace(/\s+/g, ' ')}"` });
      return out;
    },
  }),

  rule({
    id: 'vm-pam-password-quality', area: 'accounts', severity: 'low', title: 'No password-quality enforcement in PAM',
    description: 'None of pam_pwquality, pam_passwdqc or pam_cracklib is configured, so weak passwords are accepted.',
    remediation: 'Install libpam-pwquality (Debian/Ubuntu) or use authselect / system-auth with pam_pwquality (RHEL) and set minlen/dcredit… in /etc/security/pwquality.conf.',
    evaluate(ctx) {
      const files = pamFiles(ctx);
      if (!files) return na('/etc/pam.d does not exist');
      const has = files.some((f) => f.lines.some((l) => /pam_(pwquality|passwdqc|cracklib)\.so/.test(l)));
      return has ? [] : [{ resource: '/etc/pam.d', detail: 'No password-quality module found in any PAM service file.' }];
    },
  }),

  rule({
    id: 'vm-pam-lockout', area: 'accounts', severity: 'low', title: 'No failed-login lockout in PAM',
    description: 'Without pam_faillock / pam_tally2, repeated wrong passwords on local or SSH logins never lock the account or slow the attacker.',
    remediation: 'Configure pam_faillock (deny=5, unlock_time=900) in the auth stack.',
    evaluate(ctx) {
      const files = pamFiles(ctx);
      if (!files) return na('/etc/pam.d does not exist');
      const has = files.some((f) => f.lines.some((l) => /pam_(faillock|tally2|tally)\.so/.test(l)));
      return has ? [] : [{ resource: '/etc/pam.d', detail: 'No account-lockout module found in any PAM service file.' }];
    },
  }),
];
