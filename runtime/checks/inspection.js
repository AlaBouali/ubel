'use strict';
import fs from 'node:fs';
import { rule, needLive } from './util.js';
import { na } from '../../vm/lib/engine.js';
import { procLabel, scopeOf, inTempDir } from '../lib/util.js';

const MAX_STAT = 5000;
const gate = (ctx) => needLive(ctx) || (ctx.opts.inspect ? null : na('live inspection not requested (--inspect)'));

export default [
  rule({
    id: 'rt-insp-coverage', area: 'inspection', severity: 'info', title: 'Node.js process could not be inspected',
    description: 'Live inspection of this Node.js process did not complete, so what it has loaded is unknown and the checks that depend on it (code loaded from temporary directories, stale code) were not applied to it.',
    remediation: 'Run ubel-runtime as the process\'s owner or as root; start the application with --inspect=127.0.0.1:9229 if its SIGUSR1 handling prevents the signal route.',
    cap: 100,
    evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      if (!ctx.nodeTargets.length) return na('no Node.js process in scope');
      return ctx.nodeTargets.map((p) => [p, ctx.inspectionOf(p)]).filter(([, r]) => !r || !r.ok).map(([p, r]) => ({ resource: procLabel(p), scope: scopeOf(p), detail: `pid ${p.pid}: ${r ? r.reason : 'not inspected (over the --inspect-max limit)'}.` }));
    },
  }),
  rule({
    id: 'rt-insp-left-open', area: 'inspection', severity: 'high', title: 'The inspector opened for this scan is still listening',
    description: 'ubel-runtime opened the Node.js inspector of this process with SIGUSR1 and could not close it again afterwards. The inspector has no authentication: until the process restarts, any local user can run code inside it.',
    remediation: 'Restart the process, or close the inspector from inside it (process._debugEnd()).',
    cap: 50,
    evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      return ctx.nodeTargets.map((p) => [p, ctx.inspectionOf(p)]).filter(([, r]) => r && r.ok && r.leftOpen).map(([p, r]) => ({ resource: procLabel(p), scope: scopeOf(p), detail: `pid ${p.pid}: port ${r.port} is still open.` }));
    },
  }),
  rule({
    id: 'rt-insp-code-from-temp', area: 'inspection', severity: 'high', title: 'Running process has loaded JavaScript from a world-writable directory',
    description: 'V8 reports a script compiled from /tmp, /var/tmp or /dev/shm. Anyone who can write there can change code this process runs; droppers and in-memory loaders stage their payloads there.',
    remediation: 'Load code only from directories its owner controls. If you do not recognise the file, treat the process as compromised: preserve the file, then investigate how it got there.',
    cap: 100,
    evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      const out = [];
      for (const p of ctx.nodeTargets) {
        const loaded = ctx.loadedOf(p); if (!loaded) continue;
        const bad = loaded.files.filter(inTempDir);
        if (bad.length) out.push({ resource: procLabel(p), scope: scopeOf(p), detail: `pid ${p.pid} loaded ${bad.length} script(s) from a temporary directory, e.g. ${bad.slice(0, 3).join(', ')}.` });
      }
      return out;
    },
  }),
  rule({
    id: 'rt-insp-stale-code', area: 'inspection', severity: 'medium', title: 'Application files changed on disk after the process started',
    description: 'Files this process loaded were modified after it started, so the code in memory is not the code on disk (a deployment or `npm install` without a restart). Vulnerabilities fixed on disk are still exploitable in memory.',
    remediation: 'Restart the process so that memory and disk agree, and make deployments restart the service.',
    cap: 100,
    evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      const out = [];
      for (const p of ctx.nodeTargets) {
        const loaded = ctx.loadedOf(p); if (!loaded || p.startMs == null) continue;
        let newer = [], statted = 0;
        for (const f of loaded.files.slice(0, MAX_STAT)) {
          statted++;
          try { if (fs.statSync(ctx.fsPath(p, f)).mtimeMs > p.startMs + 2000) newer.push(f); } catch { /* file gone */ }
        }
        if (newer.length) out.push({ resource: procLabel(p), scope: scopeOf(p), detail: `pid ${p.pid} (started ${new Date(p.startMs).toISOString()}): ${newer.length} of ${statted} loaded file(s) changed since, e.g. ${newer.slice(0, 3).join(', ')}.` });
      }
      return out;
    },
  }),
];
