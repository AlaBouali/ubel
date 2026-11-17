'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';
import { PackageScanUnsupported } from '../lib/pkgvulns.js';

const RANK = { critical: 0, high: 1, medium: 2, low: 3 };
const SEV = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low', unknown: 'medium' };
const upgradeHint = (eco, dep) => (eco === 'alpine' ? `apk upgrade ${dep}` : (['debian', 'ubuntu'].includes(eco) ? `apt-get update && apt-get install --only-upgrade ${dep}` : `dnf upgrade ${dep}`));

export default [
  rule({
    id: 'vm-pkg-vulnerabilities', area: 'packages', severity: 'high', title: 'Installed package has a known vulnerability',
    description: 'OSV.dev lists a security advisory that applies to this package version on this operating-system release.',
    remediation: 'Update the package to a fixed version and restart the services that use it; where no fix exists yet, apply the vendor\'s mitigation or restrict exposure.',
    cap: 250,
    async evaluate(ctx) {
      const r = await ctx.packageScan();
      if (r === null) return na(ctx.opts.skipPackages ? 'package scan skipped (--skip-packages)' : 'package scan not run');
      if (r instanceof PackageScanUnsupported) return na(`no supported package database: ${r.message}`);
      const kev = (v) => v.is_kev === true;
      const list = r.vulnerabilities.map((v) => {
        let sev = SEV[String(v.severity || 'unknown').toLowerCase()] || 'medium';
        if (kev(v) && RANK[sev] > RANK.high) sev = 'high';                   // actively exploited: never below high
        return { v, sev };
      }).sort((a, b) => RANK[a.sev] - RANK[b.sev] || (kev(b.v) - kev(a.v)) || ((b.v.epss_score || 0) - (a.v.epss_score || 0)) || String(a.v.affected_dependency).localeCompare(String(b.v.affected_dependency)));
      return list.map(({ v, sev }) => {
        const cve = (v.aliases || []).find((a) => /^CVE-/.test(a)) || v.id;
        const fixed = (v.fixed_versions || [])[0];
        const sum = String(v.summary || '').replace(/\s+/g, ' ').slice(0, 90);
        return {
          resource: `${v.affected_dependency}@${v.affected_dependency_version}: ${cve}`,
          severity: sev,
          title: `${v.affected_dependency}: ${cve}${sum ? ' — ' + sum : ''}`,
          detail: `Installed ${v.affected_dependency_version}. ${fixed ? `Fixed in ${fixed}.` : 'No fixed version is published for this release yet.'}` +
            `${kev(v) ? ' Listed in the CISA Known Exploited Vulnerabilities catalogue (exploited in the wild).' : ''}` +
            `${typeof v.epss_score === 'number' ? ` EPSS ${(v.epss_score * 100).toFixed(1)}%.` : ''}` +
            `${v.release_confidence && v.release_confidence !== 'high' ? ` Release match: ${v.release_confidence_reason}` : ''} ${v.url || ''}`.trimEnd(),
          remediation: fixed ? `Update ${v.affected_dependency} to ${fixed} or later (${upgradeHint(r.ecosystem, v.affected_dependency)}) and restart the services that use it.` : `No fixed version is available yet: apply the vendor's mitigation or restrict exposure of ${v.affected_dependency}; track ${v.url || v.id}.`,
        };
      });
    },
  }),
];
