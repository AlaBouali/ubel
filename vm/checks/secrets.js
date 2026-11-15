'use strict';
import { rule, fmtMode, homes } from './util.js';
import { na } from '../lib/engine.js';

/** Returns 'encrypted' | 'unencrypted' | null (not a private key) from the first bytes of a key file. Never returns key material. */
function keyState(buf) {
  if (!buf) return null;
  const s = buf.toString('latin1');
  if (/-----BEGIN OPENSSH PRIVATE KEY-----/.test(s)) {
    const b64 = s.split('\n').slice(1).join('').replace(/-----.*$/s, '').replace(/[^A-Za-z0-9+/]/g, '');
    try {
      const raw = Buffer.from(b64.slice(0, b64.length - (b64.length % 4)), 'base64');
      if (raw.subarray(0, 15).toString('latin1') !== 'openssh-key-v1\0') return null;
      const n = raw.readUInt32BE(15);
      return raw.subarray(19, 19 + n).toString('latin1') === 'none' ? 'unencrypted' : 'encrypted';
    } catch { return null; }
  }
  if (/-----BEGIN ENCRYPTED PRIVATE KEY-----/.test(s)) return 'encrypted';
  if (/-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----/.test(s)) return /Proc-Type:\s*4,ENCRYPTED/.test(s) ? 'encrypted' : 'unencrypted';
  return null;
}

// [relative path, content regex (null = the file's existence is the finding), description]
const CREDENTIAL_FILES = [
  ['.aws/credentials', /aws_(secret_)?access_key_id/i, 'AWS access keys'],
  ['.git-credentials', /:\/\/[^/\s]+:[^@\s]+@/, 'Git credentials in clear text'],
  ['.netrc', /\bpassword\b/i, 'FTP/HTTP credentials in clear text'],
  ['.pgpass', /:.*:.*:.*:.+/, 'PostgreSQL passwords'],
  ['.my.cnf', /^\s*password\s*=/im, 'MySQL password'],
  ['.docker/config.json', /"auth"\s*:\s*"[^"]+"/, 'Docker registry credentials'],
  ['.kube/config', /(token|client-key-data|password)\s*:/i, 'Kubernetes cluster credentials'],
  ['.npmrc', /_authToken\s*=|_password\s*=/i, 'npm registry token'],
  ['.pypirc', /^\s*password\s*[:=]/im, 'PyPI password / token'],
  ['.config/gcloud/application_default_credentials.json', /"(refresh_token|private_key)"/, 'Google Cloud credentials'],
  ['.azure/accessTokens.json', /accessToken/i, 'Azure access tokens'],
  ['.vault-token', /./, 'HashiCorp Vault token'],
  ['.s3cfg', /(secret_key|access_key)\s*=\s*\S+/i, 'S3 access keys'],
  ['.config/rclone/rclone.conf', /^\s*(pass|secret_access_key|token)\s*=/im, 'rclone remote credentials'],
  ['.config/gh/hosts.yml', /oauth_token:/, 'GitHub CLI token'],
  ['.terraform.d/credentials.tfrc.json', /"token"/, 'Terraform Cloud token'],
];

export default [
  rule({
    id: 'vm-secrets-ssh-private-keys', area: 'secrets', severity: 'medium', title: 'SSH private key stored without a passphrase, or readable by others',
    description: 'A private key without a passphrase gives whoever copies the file immediate access to every system that trusts it; one readable by group/others is exposed to every local user.',
    remediation: 'Protect the key with a passphrase (ssh-keygen -p -f <key>) or replace it with short-lived credentials; chmod 600 <key>. Remove keys that are no longer used.',
    cap: 100,
    evaluate(ctx) {
      const out = [];
      for (const u of homes(ctx)) {
        const dir = `${u.home}/.ssh`;
        for (const n of ctx.fs.readdir(dir) || []) {
          if (/\.pub$|^known_hosts|^authorized_keys|^config$|^environment$|^rc$/.test(n)) continue;
          const p = `${dir}/${n}`;
          const st = ctx.fs.stat(p);
          if (!st || !st.isFile || st.size > 20000) continue;
          const state = keyState(ctx.fs.readHead(p, 1200));
          if (!state) continue;
          const loose = (st.mode & 0o077) !== 0;
          if (state === 'unencrypted' || loose) {
            out.push({ resource: p, severity: loose ? 'high' : 'medium', detail: `${state === 'unencrypted' ? 'Key has no passphrase' : 'Key is passphrase-protected'}${loose ? ' and is ' + fmtMode(st) : ''} (user ${u.name}).` });
          }
        }
      }
      return out;
    },
  }),

  rule({
    id: 'vm-secrets-credential-files', area: 'secrets', severity: 'medium', title: 'Credentials are stored in plain text in a user\'s home directory',
    description: 'Long-lived cloud, registry or database credentials sitting in dotfiles are the first thing an attacker (or malware) harvests after getting a shell. The file contents are never shown in this report.',
    remediation: 'Use short-lived credentials / instance roles / credential helpers instead, rotate the exposed secret, and make the file readable by its owner only (chmod 600).',
    cap: 100,
    evaluate(ctx) {
      const out = [];
      for (const u of homes(ctx)) {
        for (const [rel, re, label] of CREDENTIAL_FILES) {
          const p = `${u.home}/${rel}`;
          const st = ctx.fs.stat(p);
          if (!st || !st.isFile || st.size === 0) continue;
          const text = ctx.fs.read(p, 65536) || '';
          if (!re.test(text)) continue;
          const loose = (st.mode & 0o044) !== 0;
          out.push({ resource: p, severity: loose ? 'high' : 'medium', detail: `Contains ${label} (${fmtMode(st)}; user ${u.name}; contents not shown).` });
        }
      }
      return out;
    },
  }),
];
