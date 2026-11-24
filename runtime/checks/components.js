'use strict';
import { rule, needLive } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';
import { procLabel, scopeOf, nodeEol } from '../lib/util.js';

/** The Node.js release a process runs: what it reported about itself (--inspect) or the release string compiled into its executable. */
async function nodeVersion(ctx, proc) {
  const insp = ctx.inspectionOf(proc);
  if (insp && insp.ok && insp.node && insp.node.version) return { version: insp.node.version, from: 'process.version (live inspection)' };
  if (ctx.opts.libs === 'none') return null;
  const native = await ctx.nativeComponents();
  const f = native.files.find((x) => x.path === proc.exe);
  const r = f && f.records.find((x) => x.name === 'Node.js');
  return r ? { version: r.version, from: 'release string in the executable' } : null;
}

export default [
  rule({
    id: 'rt-comp-node-eol', area: 'components', severity: 'high', title: 'Node.js release line is past its end of life',
    description: 'The process runs a Node.js release line that no longer receives security fixes, so every newly found vulnerability in Node.js or its bundled libraries stays open. The end-of-life dates are embedded in the tool (from the Node.js release schedule), so they age; a release line that is not in the table is not judged.',
    remediation: 'Move to a Node.js line that is in Active LTS or Maintenance LTS, test, redeploy and restart.',
    cap: 100,
    async evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      if (!ctx.nodeTargets.length) return na('no Node.js process in scope');
      const out = [];
      let unknown = 0;
      const seen = new Set();
      for (const p of ctx.nodeTargets) {
        const v = await nodeVersion(ctx, p);
        if (!v) { unknown++; continue; }
        const eol = nodeEol(v.version);
        if (!eol) continue;
        const k = `${procLabel(p)}\u0001${scopeOf(p)}\u0001${v.version}`; if (seen.has(k)) continue; seen.add(k);
        out.push({ resource: `${procLabel(p)} (Node.js ${String(v.version).replace(/^v/, '')})`, scope: scopeOf(p), detail: `pid ${p.pid} runs Node.js ${String(v.version).replace(/^v/, '')} (${v.from}); the ${eol.major}.x line reached end of life on ${eol.date}.` });
      }
      if (unknown === ctx.nodeTargets.length) return unassessed('the Node.js release of no process could be determined (executables not read, or built without the release string); use --inspect');
      if (unknown) ctx.notes.push(`The Node.js release of ${unknown} process(es) could not be determined: the end-of-life check skipped them.`);
      return out;
    },
  }),
];
