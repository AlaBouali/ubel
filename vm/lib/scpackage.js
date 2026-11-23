'use strict';
// scpackage.js — an SCA inventory item as the vm / runtime / k8s reports carry it: trimmed to what the SCA package modal shows
// (canonical/client/scvuln.js), with `state` taken from the advisories that apply to it.

import { buildPackageInfo } from './pkginfo.js';

/**
 * @param {object} c            SCA inventory item
 * @param {Map<string,object[]>} vulns  advisories by package id (decides `state`)
 * @param {(c:object)=>boolean} unassessed  true when the package's lookup could not be completed (state "unknown", never "safe")
 * @param {string} [base]       mount point the item's paths are read under ('' on the live host)
 */
export function compactPackage(c, vulns, unassessed, base = '') {
  const cap = (a, n) => (Array.isArray(a) ? a.slice(0, n) : []);
  const mine = vulns.get(c.id) || [];
  return {
    id: c.id, name: c.name, version: c.version, type: c.type || 'library', ecosystem: c.ecosystem || '', ...(c.distro ? { distro: c.distro } : {}),
    ...(c.source_name ? { source_name: c.source_name, source_version: c.source_version || c.version } : {}),
    ...(() => { try { const pi = buildPackageInfo(c, base); return pi && Object.keys(pi).length ? { package_info: pi } : {}; } catch { return {}; } })(),   // what the package is (modal details); never fails the scan
    license: c.license ?? null, ...(c.license_info ? { license_info: c.license_info } : {}),
    state: mine.some((v) => v.is_infection) ? 'infected' : mine.length ? 'vulnerable' : unassessed(c) ? 'unknown' : 'safe',   // 'unknown': its lookup could not be completed, never "safe"
    scopes: cap(c.scopes, 5), paths: cap(c.paths, 5), dependencies: cap(c.dependencies, 25), introduced_by: cap(c.introduced_by, 10), parents: cap(c.parents, 25),
    is_direct: c.is_direct ?? null, is_policy_violation: false, vulnerable_transitive_dependencies: [], policy_violations: [], suggested_fixes: c.suggested_fixes || { fixes: [], unfixed: [] },
  };
}
