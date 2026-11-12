'use strict';
// packages.js — runs the packages that a launcher (npx, uvx, pipx …) would fetch through ubel-package: the release is downloaded from its
// registry, checked against the registry's own digest and READ, never installed or run, and its install hooks, source behaviour, secrets,
// bundled binaries and known advisories (OSV.dev / NVD) are reported. An unpinned spec is analysed at the version the registry serves now,
// which is what the next start of the server would run.

import { scanPackage } from '../../package/index.js';
import { resolveAdvisories, DEFAULTS } from '../../package/lib/scan.js';
import { gap } from '../../mobile/lib/coverage.js';

const key = p => `${p.ecosystem}:${p.name}@${p.version || 'latest'}`;

/**
 * @param {object[]} pkgs   launch.packages entries (registry packages only)
 * @param {{offline:boolean, notes:object, log:Function, max:number, registry?:object}} o
 * @returns {Promise<{results:Map<string,{findings:object[], resolved:object|null, error:string|null}>}>}
 */
export async function analysePackages(pkgs, o) {
  const results = new Map();
  const todo = [...new Map(pkgs.filter(p => p.source === 'registry' && !p.unsupported && /^(?:npm|pypi)$/.test(p.ecosystem)).map(p => [key(p), p])).values()];
  if (todo.length > o.max) gap(o.notes, `${todo.length} launcher packages were found; only the first ${o.max} were analysed (--max-packages).`);
  for (const p of todo.slice(0, o.max)) {
    const k = key(p);
    o.log(`  analysing ${p.ecosystem} package ${p.name}@${p.version || 'latest'} …`);
    try {
      const scan = await scanPackage({ ecosystem: p.ecosystem, name: p.name, version: p.version || 'latest', quiet: true, verbose: false, maxSizeMb: 64, maxWheels: 1, artifact: 'all', ...DEFAULTS, headers: {}, authHeaders: {} });
      const analysed = scan.findings.list.slice();
      let advisories = [];
      if (!o.offline) {
        try { advisories = await resolveAdvisories(scan, { log: () => {} }); }
        catch (e) { gap(o.notes, `Advisory lookup for ${p.name} failed: ${e.message}`); }
      } else gap(o.notes, `Advisories for ${p.name} were not checked (--offline).`);
      for (const n of scan.notes?.gaps || []) gap(o.notes, `${p.name}@${scan.package.version}: ${String(n).replace(/;?\s*see the Dependencies tab\.?/i, '.')}`);
      results.set(k, { findings: analysed.concat(advisories), resolved: scan.package, error: null });
    } catch (e) {
      gap(o.notes, `${p.ecosystem} package ${p.name}${p.version ? `@${p.version}` : ''} could not be fetched for analysis: ${e.message}`);
      results.set(k, { findings: [], resolved: null, error: e.message });
    }
  }
  return { results, keyOf: key };
}

/** Adds findings produced by ubel-package to this scan's list once each (the same release behind two servers is reported once). */
export function adopt(findings, list) {
  let n = 0;
  for (const f of list) {
    if (findings.list.some(x => x.fingerprint === f.fingerprint)) continue;
    findings.list.push(f); n++;
  }
  return n;
}
