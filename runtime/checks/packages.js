'use strict';
import { rule, needLive, vulnSeverity, cveOf, sortVulns } from './util.js';
import { na, unassessed } from '../../vm/lib/engine.js';
import { runningOsPackages, runningAppPackages } from '../lib/running.js';
import { scViolation } from '../../vm/lib/scfinding.js';
import { purlType } from '../../vm/lib/scascan.js';
import { pathsOf } from '../../vm/lib/scascan.js';

const list = (set, n = 3) => { const a = [...set]; return `${a.slice(0, n).join(', ')}${a.length > n ? ` and ${a.length - n} more` : ''}`; };
const gate = (ctx) => needLive(ctx) || (ctx.opts.noLookups ? na('advisory lookups disabled (--no-lookups)') : ctx.opts.packages === 'none' ? na('package scan disabled (--packages none)') : null);
const addNotes = (ctx, notes) => { for (const n of notes) if (!ctx.notes.includes(n)) ctx.notes.push(n); };

export default [
  rule({
    id: 'rt-pkg-os-vulnerable', area: 'packages', severity: 'high', title: 'Operating-system package used by a running process has a known vulnerability',
    description: 'The executable or a library that a running process has mapped belongs to an operating-system package (dpkg / apk / rpm file lists read from disk) for which the SCA engine finds an OSV.dev advisory that applies to the release — on the host (platform mode) or inside a container (docker mode on /proc/<pid>/root). Only packages in use are reported; ubel-vm reports every installed one.',
    remediation: 'Update the package to a fixed version and restart the processes that use it (an upgrade does not replace the code already loaded in a running process); in a container, rebuild the image from an updated base image and redeploy.',
    cap: 250,
    async evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      if (!ctx.targets.length) return na('no process in scope');
      const r = await runningOsPackages(ctx);
      addNotes(ctx, r.notes);
      if (!r.scopes.length) return r.notes.length ? unassessed(r.notes[0]) : na('no running program belongs to an operating-system package that could be identified');
      const out = [];
      for (const s of r.scopes) {
        const inv = new Map(s.inventory.map((c) => [c.id, c]));
        for (const v of s.vulnerabilities) {
          const used = s.packages.get(v.affected_dependency) || (inv.get(v.affected_package_id) && s.packages.get(inv.get(v.affected_package_id).name));
          out.push(scViolation(v, {
            resource: `${v.affected_dependency}@${v.affected_dependency_version}: ${cveOf(v)} (${used ? list(used.procs, 2) : s.label})`, scope: s.scope,
            where: `is used by ${used ? list(used.procs) : 'a running process'}${used ? ` (${list(used.files, 2)})` : ''} on ${s.label === 'host' ? 'the host' : `container ${s.label}`}`,
          }));
        }
      }
      return out.sort(sortVulns);
    },
  }),
  rule({
    id: 'rt-pkg-app-vulnerable', area: 'packages', severity: 'high', title: 'Package of a running Python, Ruby or PHP application has a known vulnerability',
    description: 'The SCA engine reads the packages installed under the application directory of a running Python, Ruby or PHP process (its virtualenv, working directory or script directory; system-wide pip installs for the system interpreter) and finds an OSV.dev advisory for one of them. Malicious-package advisories are reported as infections. Node.js applications are covered by rt-comp-vulnerable-package.',
    remediation: 'Update the package to a fixed version (pip install --upgrade / bundle update / composer update), redeploy, and restart the process so the fixed code is the code that runs.',
    cap: 250,
    async evaluate(ctx) {
      const g = gate(ctx); if (g) return g;
      const r = await runningAppPackages(ctx);
      addNotes(ctx, r.notes);
      if (!r.apps.length) return na('no running Python, Ruby or PHP process with an application directory in scope');
      const out = [];
      let packages = 0;
      for (const a of r.apps) {
        const inv = new Map(a.inventory.map((c) => [c.id, c]));
        packages += a.inventory.length;
        for (const v of a.vulnerabilities) {
          const c = inv.get(v.affected_package_id); const at = c ? pathsOf(c) : [];
          out.push(scViolation(v, {
            prefix: purlType(v.affected_package_id), resource: `${purlType(v.affected_package_id)}:${v.affected_dependency}@${v.affected_dependency_version}: ${cveOf(v)} (${a.root})`, scope: a.scope,
            where: `in ${a.root}${at.length ? ` at ${at[0]}` : ''} (used by ${list(new Set(a.procs.map((p) => p.pid)), 3).replace(/^/, 'pid ')})`,
          }));
        }
      }
      ctx.notes.push(`${packages} application package(s) in ${r.apps.length} application director${r.apps.length === 1 ? 'y' : 'ies'} of running processes were checked by the SCA engine.`);
      return out.sort(sortVulns);
    },
  }),
];
