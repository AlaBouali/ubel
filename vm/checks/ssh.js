'use strict';
import { rule, SSHD, bad, fmtMode, homes } from './util.js';
import { na } from '../lib/engine.js';

const noSshd = () => na('OpenSSH server is not installed (no /etc/ssh/sshd_config)');
const REM = (line) => `Set "${line}" in ${SSHD} (or a drop-in under /etc/ssh/sshd_config.d/ that is included before any other setting of the same keyword), then validate and reload sshd.`;

const WEAK_CIPHER_HIGH = /^(3des-cbc|arcfour\d*|blowfish-cbc|cast128-cbc|des-cbc|rijndael-cbc@lysator\.liu\.se)$/;
const WEAK_CIPHER_MED = /^aes(128|192|256)-cbc$/;
const WEAK_MAC_MED = /^(hmac-md5(-96)?|hmac-sha1-96|hmac-ripemd160|umac-64)(-etm)?(@openssh\.com)?$/;
const WEAK_MAC_LOW = /^hmac-sha1(-etm@openssh\.com)?$/;
const WEAK_KEX = /^(diffie-hellman-group1-sha1|diffie-hellman-group-exchange-sha1|diffie-hellman-group14-sha1)$/;

const simple = (id, severity, title, description, line, test) => rule({
  id, area: 'ssh', severity, title, description, remediation: REM(line),
  evaluate(ctx) {
    const s = ctx.sshd();
    if (!s) return noSshd();
    const v = test(s);
    return v ? [{ resource: SSHD, detail: v }] : [];
  },
});

export default [
  simple('vm-ssh-root-login', 'high', 'SSH permits direct root login', 'sshd allows logging in as root over SSH, so one stolen or guessed root credential is a full compromise and logins are not attributable to a person.', 'PermitRootLogin no',
    (s) => (/^yes$/i.test(s.get('permitrootlogin') || '') ? 'PermitRootLogin is "yes".' : null)),
  simple('vm-ssh-empty-passwords', 'critical', 'SSH permits empty passwords', 'Accounts with an empty password can log in over SSH without any secret.', 'PermitEmptyPasswords no',
    (s) => (/^yes$/i.test(s.get('permitemptypasswords') || '') ? 'PermitEmptyPasswords is "yes".' : null)),
  simple('vm-ssh-protocol-1', 'critical', 'SSH protocol version 1 is enabled', 'SSH protocol 1 has known cryptographic weaknesses and must not be offered.', 'Protocol 2',
    (s) => (/(^|,)1(,|$)/.test(s.get('protocol') || '') ? `Protocol is "${s.get('protocol')}".` : null)),
  simple('vm-ssh-password-auth', 'medium', 'SSH accepts password authentication', 'Password logins over SSH are exposed to guessing and credential-stuffing; key-based (or certificate / MFA) authentication is much harder to attack.', 'PasswordAuthentication no',
    (s) => { const v = (s.get('passwordauthentication') || '').toLowerCase(); return v === 'no' ? null : (v ? `PasswordAuthentication is "${v}".` : 'PasswordAuthentication is not set; the OpenSSH default is "yes".'); }),
  simple('vm-ssh-x11-forwarding', 'low', 'SSH X11 forwarding is enabled', 'X11 forwarding widens the attack surface of an SSH session and is rarely needed on a server.', 'X11Forwarding no',
    (s) => (/^yes$/i.test(s.get('x11forwarding') || '') ? 'X11Forwarding is "yes".' : null)),
  simple('vm-ssh-max-auth-tries', 'low', 'SSH allows many authentication attempts per connection', 'A high MaxAuthTries makes online password guessing cheaper per connection.', 'MaxAuthTries 4',
    (s) => { const n = Number(s.get('maxauthtries')); return n > 6 ? `MaxAuthTries is ${n}.` : null; }),
  simple('vm-ssh-permit-user-environment', 'medium', 'SSH lets users set environment variables', 'PermitUserEnvironment can let a user bypass restricted shells or alter the environment of forced commands.', 'PermitUserEnvironment no',
    (s) => (/^yes$/i.test(s.get('permituserenvironment') || '') ? 'PermitUserEnvironment is "yes".' : null)),
  simple('vm-ssh-hostbased-auth', 'medium', 'SSH host-based authentication is enabled', 'Host-based authentication trusts a remote machine instead of a user credential.', 'HostbasedAuthentication no',
    (s) => (/^yes$/i.test(s.get('hostbasedauthentication') || '') ? 'HostbasedAuthentication is "yes".' : null)),
  simple('vm-ssh-ignore-rhosts', 'medium', 'SSH honours .rhosts files', 'With IgnoreRhosts set to "no", legacy .rhosts / .shosts trust files are consulted.', 'IgnoreRhosts yes',
    (s) => (/^no$/i.test(s.get('ignorerhosts') || '') ? 'IgnoreRhosts is "no".' : null)),
  simple('vm-ssh-gateway-ports', 'medium', 'SSH allows remote hosts to use forwarded ports', 'GatewayPorts lets SSH port forwards listen on all interfaces, which can expose internal services.', 'GatewayPorts no',
    (s) => (/^yes$/i.test(s.get('gatewayports') || '') ? 'GatewayPorts is "yes".' : null)),
  simple('vm-ssh-no-idle-timeout', 'low', 'SSH sessions have no idle timeout', 'Without ClientAliveInterval / ClientAliveCountMax, abandoned sessions stay open indefinitely.', 'ClientAliveInterval 300 and ClientAliveCountMax 2',
    (s) => (Number(s.get('clientaliveinterval') || 0) === 0 ? 'ClientAliveInterval is unset or 0.' : null)),
  simple('vm-ssh-no-access-restriction', 'low', 'SSH is not limited to named users or groups', 'Without AllowUsers / AllowGroups (or Deny equivalents) every local account that can authenticate can log in over SSH.', 'AllowGroups <group>',
    (s) => (['allowusers', 'allowgroups', 'denyusers', 'denygroups'].some((k) => s.all(k).length) ? null : 'No AllowUsers/AllowGroups/DenyUsers/DenyGroups is configured.')),
  simple('vm-ssh-loglevel', 'low', 'SSH logging is turned down too far', 'LogLevel QUIET or FATAL hides authentication events needed for investigations.', 'LogLevel VERBOSE (or INFO)',
    (s) => (/^(quiet|fatal)$/i.test(s.get('loglevel') || '') ? `LogLevel is "${s.get('loglevel')}".` : null)),

  rule({
    id: 'vm-ssh-weak-crypto', area: 'ssh', severity: 'medium', title: 'SSH is configured with weak cryptographic algorithms',
    description: 'sshd explicitly offers algorithms that are broken or deprecated.',
    remediation: 'Remove the weak entries from Ciphers / MACs / KexAlgorithms in sshd_config (or drop the override and use the OpenSSH defaults).',
    evaluate(ctx) {
      const s = ctx.sshd();
      if (!s) return noSshd();
      const out = [];
      const items = (k) => (s.get(k) || '').split(',').map((x) => x.trim()).filter((x) => x && !x.startsWith('-')).map((x) => x.replace(/^[+^]/, ''));
      const ci = items('ciphers'), ma = items('macs'), kx = items('kexalgorithms');
      const hi = ci.filter((c) => WEAK_CIPHER_HIGH.test(c)), cm = ci.filter((c) => WEAK_CIPHER_MED.test(c));
      if (hi.length) out.push({ resource: 'sshd_config: Ciphers', severity: 'high', detail: `Broken ciphers offered: ${hi.join(', ')}.` });
      else if (cm.length) out.push({ resource: 'sshd_config: Ciphers', detail: `CBC-mode ciphers offered: ${cm.join(', ')}.` });
      const mm = ma.filter((m) => WEAK_MAC_MED.test(m)), ml = ma.filter((m) => WEAK_MAC_LOW.test(m));
      if (mm.length) out.push({ resource: 'sshd_config: MACs', detail: `Weak MACs offered: ${mm.join(', ')}.` });
      else if (ml.length) out.push({ resource: 'sshd_config: MACs', severity: 'low', detail: `SHA-1 MACs offered: ${ml.join(', ')}.` });
      const kk = kx.filter((k) => WEAK_KEX.test(k));
      if (kk.length) out.push({ resource: 'sshd_config: KexAlgorithms', severity: kk.includes('diffie-hellman-group1-sha1') ? 'high' : 'medium', detail: `Weak key exchange offered: ${kk.join(', ')}.` });
      return out;
    },
  }),

  rule({
    id: 'vm-ssh-config-permissions', area: 'ssh', severity: 'medium', title: 'sshd_config is writable by someone other than root',
    description: 'Whoever can edit sshd_config can change how the server authenticates.',
    remediation: 'chown root:root /etc/ssh/sshd_config && chmod 600 /etc/ssh/sshd_config',
    evaluate(ctx) {
      const s = ctx.sshd();
      if (!s) return noSshd();
      const out = [];
      for (const f of s.files) {
        const st = ctx.fs.stat(f);
        if (st && (st.uid !== 0 || (st.mode & 0o022))) out.push({ resource: f, detail: `${fmtMode(st)}.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-ssh-host-key-permissions', area: 'ssh', severity: 'high', title: 'SSH host private key is readable by other users',
    description: 'A host private key that group or others can read lets them impersonate this server.',
    remediation: 'chown root:root /etc/ssh/ssh_host_*_key && chmod 600 /etc/ssh/ssh_host_*_key',
    evaluate(ctx) {
      if (!ctx.sshd()) return noSshd();
      const out = [];
      for (const f of ctx.fs.glob('/etc/ssh/ssh_host_*_key')) {
        const st = ctx.fs.stat(f);
        if (st && st.isFile && (st.uid !== 0 || bad(st.mode, 0o640) || (st.mode & 0o047))) out.push({ resource: f, detail: `${fmtMode(st)}.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-ssh-dsa-host-key', area: 'ssh', severity: 'medium', title: 'SSH offers a DSA host key',
    description: 'DSA host keys are limited to 1024 bits and have been disabled upstream.',
    remediation: 'Remove /etc/ssh/ssh_host_dsa_key* and any HostKey line that points to it.',
    evaluate(ctx) {
      const s = ctx.sshd();
      if (!s) return noSshd();
      const out = [];
      if (ctx.fs.exists('/etc/ssh/ssh_host_dsa_key')) out.push({ resource: '/etc/ssh/ssh_host_dsa_key' });
      for (const k of s.all('hostkey')) if (/dsa/i.test(k) && !/ecdsa/i.test(k)) out.push({ resource: `sshd_config: HostKey ${k}` });
      return out;
    },
  }),

  rule({
    id: 'vm-ssh-root-authorized-keys', area: 'ssh', severity: 'low', title: 'root has SSH authorized keys without a forced command',
    description: 'Keys in root\'s authorized_keys give direct root access to whoever holds the private key.',
    remediation: 'Remove unneeded keys from /root/.ssh/authorized_keys, or restrict them with command="…" and from="…" options; prefer named accounts plus sudo.',
    evaluate(ctx) {
      if (!ctx.sshd()) return noSshd();
      if (/^no$/i.test(ctx.sshd().get('permitrootlogin') || '')) return [];
      const lines = ctx.fs.lines('/root/.ssh/authorized_keys');
      if (!lines) return [];
      const open = lines.filter((l) => !/^(?:[^ ]*[, ])?command=/.test(l) && /(ssh-|ecdsa-|sk-)/.test(l));
      return open.length ? [{ resource: '/root/.ssh/authorized_keys', detail: `${open.length} key(s) allow an unrestricted root login.` }] : [];
    },
  }),

  rule({
    id: 'vm-ssh-authorized-keys-permissions', area: 'ssh', severity: 'medium', title: 'A user\'s SSH directory or authorized_keys can be modified by others',
    description: 'If group or others can write to ~/.ssh or authorized_keys they can add their own key and log in as that user.',
    remediation: 'chmod 700 ~/.ssh && chmod 600 ~/.ssh/authorized_keys (owned by the user).',
    evaluate(ctx) {
      if (!ctx.sshd()) return noSshd();
      const out = [];
      for (const u of homes(ctx)) {
        for (const p of [`${u.home}/.ssh`, `${u.home}/.ssh/authorized_keys`]) {
          const st = ctx.fs.stat(p);
          if (st && (st.mode & 0o022)) out.push({ resource: p, detail: `${fmtMode(st)} (user ${u.name}).` });
        }
      }
      return out;
    },
  }),
];
