'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';
import { PackageScanUnsupported } from '../lib/pkgvulns.js';
import { scViolation, sortViolations } from '../lib/scfinding.js';
import { pathsOf, purlType } from '../lib/scascan.js';

export default [
  rule({
    id: 'vm-pkg-vulnerabilities', area: 'packages', severity: 'high', title: 'Installed operating-system package has a known vulnerability',
    description: 'The SCA engine (platform mode on a live host, docker mode on a --root image) found a security advisory that applies to an operating-system package version installed on this machine, for its release (OSV.dev).',
    remediation: 'Update the package to a fixed version and restart the services that use it; where no fix exists yet, apply the vendor\'s mitigation or restrict exposure.',
    cap: 250,
    async evaluate(ctx) {
      const r = await ctx.packageScan();
      if (r === null) return na('package scan skipped (--skip-packages)');
      if (r instanceof PackageScanUnsupported) return na(`no supported package database: ${r.message}`);
      if (!r.os.supported) return na(`no supported operating-system package database: ${r.os.reason}`);
      return r.osVulnerabilities.map((v) => scViolation(v)).sort(sortViolations);
    },
  }),
  rule({
    id: 'vm-app-pkg-vulnerabilities', area: 'packages', severity: 'high', title: 'Installed application package has a known vulnerability',
    description: 'The SCA engine found a security advisory (OSV.dev) for a package that applications on this machine are built from: an npm module, Python distribution, Composer, Bundler, Cargo, Go, NuGet, Maven, pub or SwiftPM dependency found on disk outside the distribution\'s own package database. Malicious-package advisories are reported as infections.',
    remediation: 'Update the package to a fixed version (or the dependency that brings it in), redeploy and restart the application; where no fix exists yet, remove or replace the package or restrict exposure of the application.',
    cap: 250,
    async evaluate(ctx) {
      const r = await ctx.packageScan();
      if (r === null) return na('package scan skipped (--skip-packages)');
      if (r instanceof PackageScanUnsupported) return na(`nothing to read: ${r.message}`);
      if (!r.apps.scanned) return na('application package scan skipped (--skip-app-packages)');
      if (!r.apps.installed) return na(`no application packages found${r.apps.roots.length ? ` under ${r.apps.roots.join(', ')}` : ' (none of the standard application directories exists; add directories with --app-roots)'}`);
      const comp = new Map(r.inventory.map((c) => [c.id, c]));
      return r.appVulnerabilities.map((v) => {
        const c = comp.get(v.affected_package_id);
        const at = c ? pathsOf(c) : [];
        const dev = c && Array.isArray(c.scopes) && c.scopes.length && !c.scopes.includes('prod');
        return scViolation(v, { prefix: purlType(v.affected_package_id), where: `${at.length ? `at ${at[0]}${at.length > 1 ? ` (+${at.length - 1} more)` : ''}` : ''}${dev ? ' (development dependency)' : ''}`.trim() });
      }).sort(sortViolations);
    },
  }),
];
