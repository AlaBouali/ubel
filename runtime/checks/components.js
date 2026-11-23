'use strict';
import { rule, needLive, vulnSeverity, cveOf, short, vulnFacts, sortVulns } from './util.js';
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
    id: 'rt-comp-node-runtime-vulnerable', area: 'components', severity: 'high', title: 'Node.js runtime (or a library it bundles) has a known vulnerability',
    description: 'NVD lists a CVE whose CPE range covers the Node.js release a running process uses, or a library bundled in it (OpenSSL, zlib, nghttp2, c-ares). The release is read from the executable and, with --inspect, from process.versions of the live process.',
    remediation: 'Upgrade Node.js to the latest patch release of a supported line and restart the process. If Node.js comes from a distribution package, install the distribution\'s update.',
    cap: 200,
    async evaluate(ctx) {
      const n = needLive(ctx); if (n) return n;
      if (!ctx.nodeTargets.length) return na('no Node.js process in scope');
      if (ctx.opts.noLookups) return na('advisory lookups disabled (--no-lookups)');
      if (ctx.opts.libs === 'none' && !ctx.opts.inspect) return na('needs executables to be read (--libs app) or --inspect');
      const r = await ctx.componentAdvisories();
      const out = [];
      for (const dep of r.dependencies) {
        if (dep.ecosystem !== 'Node.js runtime' || !dep.vulnerabilities || !dep.vulnerabilities.length) continue;
        const src = (r.byKey.get(dep.cpe) || { sources: [] }).sources;
        const pids = [...new Set(src.flatMap((s) => s.pids))];
        for (const v of dep.vulnerabilities) {
          out.push({ resource: `${dep.name} ${dep.version}: ${cveOf(v)}`, scope: 'host', severity: vulnSeverity(v), kev: v.is_kev === true,
            title: `${dep.name} ${dep.version}: ${cveOf(v)}${v.summary ? ' — ' + short(v.summary) : ''}`,
            detail: `Used by pid ${pids.slice(0, 6).join(', ')}${pids.length > 6 ? ', …' : ''}. ${vulnFacts(v)}` });
        }
      }
      return out.sort(sortVulns);
    },
  }),
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
