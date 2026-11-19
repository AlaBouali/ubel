'use strict';
import { rule, needLive } from './util.js';
import { unassessed } from '../../vm/lib/engine.js';
import { procLabel, scopeOf, redact } from '../lib/util.js';

// Credentials that are visible to other users: /proc/<pid>/cmdline is world-readable, /proc/<pid>/environ is readable by the owner and root.
const CMD_PATTERNS = [
  [/(?:^|\s)--?(?:password|passwd|pass|pwd|secret|token|api[-_]?key|access[-_]?key|auth[-_]?token|client[-_]?secret)(?:=|\s+)(?!\*\*\*)(\S{4,})/i, 'a credential passed as a command-line option'],
  [/(?:^|\s)-p(\S{4,})(?:\s|$)/, 'a password attached to -p (mysql-style)'],
  [/[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:([^\s@/]{3,})@/i, 'a URL with an embedded password'],
  [/(?:authorization|bearer)\s*[:=]?\s*(?:bearer\s+)?([A-Za-z0-9._~+/=-]{16,})/i, 'an authorization token'],
  [/\b(AKIA|ASIA)[0-9A-Z]{16}\b/, 'an AWS access key id'],
  [/\bgh[pousr]_[A-Za-z0-9]{30,}\b/, 'a GitHub token'],
];

export default [
  rule({
    id: 'rt-secret-env', area: 'secrets', severity: 'medium', title: 'Credential in the environment of a running process',
    description: 'The environment of this process contains a value that UBEL\'s secret rules recognise as a credential. Anyone who can read /proc/<pid>/environ (the same user, root, and anything that can run code as the process) gets it; it is also inherited by every child process, shown in crash dumps and copied by `docker inspect`. Environment variables are a normal way to configure services, so this is rated medium (low for generic name-based matches, high for private keys).',
    remediation: 'Prefer a secrets manager or a file readable only by the service (systemd LoadCredential=, Docker/Kubernetes secrets mounted as files) and rotate any credential that was exposed more widely than intended.',
    cap: 100,
    async evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const { scanText } = await import('../../sca/secrets.js');
      const out = [], seen = new Set();
      let readable = 0;
      for (const p of ctx.targets) {
        const env = ctx.environOf(p);
        if (!env) continue;
        readable++;
        const lines = env.map(([k, v]) => `${k}=${v}`);
        let hits; try { hits = scanText(lines, 'environ'); } catch { continue; }
        for (const h of hits) {
          const name = env[h.line - 1] ? env[h.line - 1][0] : '?';
          const generic = /^generic-/.test(h.id);
          const sev = /private-key/i.test(h.id) ? 'high' : generic ? 'low' : 'medium';
          const k = `${procLabel(p)}\u0001${name}\u0001${h.id}`; if (seen.has(k)) continue; seen.add(k);
          out.push({ resource: `${procLabel(p)} env ${name}`, scope: scopeOf(p), severity: sev, title: `${h.title} in the environment of a running process`,
            detail: `pid ${p.pid}: variable ${name} holds ${h.title} (${h.match_preview}).${generic ? ' This rule matches on the variable name or on entropy; confirm that the value is a real credential.' : ''}` });
        }
      }
      if (!readable && ctx.targets.length) return unassessed('the environment of every process is unreadable (run as root, or as the owner of the processes)');
      if (readable < ctx.targets.length) ctx.notes.push(`${ctx.targets.length - readable} process(es) had an unreadable environment (other users' processes): their secrets were not checked.`);
      return out;
    },
  }),
  rule({
    id: 'rt-secret-cmdline', area: 'secrets', severity: 'high', title: 'Credential on the command line of a running process',
    description: 'The command line of this process contains a password, token or key. /proc/<pid>/cmdline and `ps` show it to every user on the machine, and it ends up in shell history, audit logs and process-accounting records.',
    remediation: 'Pass the secret through a file or a protected environment instead (--password-file, a config file with mode 0600, a secrets manager) and rotate the credential that was exposed.',
    cap: 100,
    evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      const out = [], seen = new Set();
      for (const p of ctx.targets) {
        const line = p.cmdline.join(' ');
        for (const [re, what] of CMD_PATTERNS) {
          const m = line.match(re); if (!m) continue;
          const k = `${procLabel(p)}\u0001${what}`; if (seen.has(k)) continue; seen.add(k);
          out.push({ resource: procLabel(p), scope: scopeOf(p), detail: `pid ${p.pid}: ${what} (${redact(m[1] || m[0])}).` });
          break;
        }
      }
      return out;
    },
  }),
];
