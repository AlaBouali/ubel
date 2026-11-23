'use strict';
// scfinding.js — turns a vulnerability record of the SCA engine into a finding of a check rule (ubel-vm, ubel-runtime, ubel-k8s).
// The record travels UNCHANGED in `vuln` and the finding's `type` is sc_vuln (sc_infection for a malicious-package advisory), which is
// what makes every report open it in the SCA vulnerability modal (canonical/client/scvuln.js). The rest — resource, title, detail,
// remediation — is the plain-language line the check lists.
// A check that has the package's SCA inventory item hands it over (`comp`): the violation then carries it (`package`) so the report can list
// the package in its inventory with the SCA package modal's data; the report builder moves it out of the finding (vm/lib/html_report.js).

import { compactPackage } from './scpackage.js';

export const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low', unknown: 'medium' };

/** Severity of an advisory: its own rating; critical for a malicious-package advisory; never below high when exploited in the wild (CISA KEV). */
export function severityOf(v) {
  if (v.is_infection) return 'critical';
  let sev = SEV[String(v.severity || 'unknown').toLowerCase()] || 'medium';
  if (v.is_kev === true && RANK[sev] > RANK.high) sev = 'high';
  return sev;
}

export const cveOf = (v) => (v.aliases || []).find((a) => /^CVE-/.test(a)) || v.id;
export const typeOf = (v) => (v.is_infection ? 'sc_infection' : 'sc_vuln');
const short = (s, n = 90) => String(s || '').replace(/\s+/g, ' ').slice(0, n);

/** Package-URL type ("pkg:pypi/flask@2.0" → "pypi"). */
export const purlType = (purl) => { const m = /^pkg:([^/]+)\//.exec(String(purl || '')); return m ? m[1] : ''; };

const UPGRADE = {
  npm: (n, f) => `npm install ${n}@${f} in the application directory (or update the dependency that brings it in)`,
  pypi: (n, f) => `pip install --upgrade "${n}>=${f}" in the environment that holds it`,
  composer: (n) => `composer update ${n}`,
  gem: (n) => `bundle update ${n}`,
  cargo: (n) => `cargo update -p ${n}`,
  golang: (n, f) => `go get ${n}@v${String(f).replace(/^v/, '')}`,
  nuget: (n, f) => `update the ${n} PackageReference to ${f}`,
  maven: (n, f) => `raise the ${n} version to ${f} in pom.xml`,
  pub: (n) => `dart pub upgrade ${n}`,
  deb: (n) => `apt-get update && apt-get install --only-upgrade ${n}`,
  apk: (n) => `apk upgrade ${n}`,
  rpm: (n) => `dnf upgrade ${n}`,
};

/** How to move a package to its fixed version, by package type. */
export function upgradeHint(v) {
  const fixed = (v.fixed_versions || [])[0];
  const f = UPGRADE[purlType(v.affected_package_id)];
  return fixed && f ? f(v.affected_dependency, fixed) : '';
}

/** KEV / EPSS / release-match sentence of an advisory. */
export function facts(v) {
  const fixed = (v.fixed_versions || [])[0];
  return `${v.is_infection ? 'This is a malicious-package advisory. ' : ''}${fixed ? `Fixed in ${fixed}.` : 'No fixed version is published for this release yet.'}` +
    `${v.is_kev === true ? ' Listed in the CISA Known Exploited Vulnerabilities catalogue (exploited in the wild).' : ''}` +
    `${typeof v.epss_score === 'number' ? ` EPSS ${(v.epss_score * 100).toFixed(1)}%.` : ''}` +
    `${v.release_confidence && v.release_confidence !== 'high' && v.release_confidence_reason ? ` Release match: ${v.release_confidence_reason}` : ''} ${v.url || ''}`.trimEnd();
}

/**
 * One advisory on one package → a rule violation.
 * @param {object} v   SCA vulnerability record
 * @param {{resource?:string, scope?:string, where?:string, prefix?:string, remediation?:string}} [o]
 *   where: what to say after "<package> <version>" (a location, "in container x" …); prefix: label before the package in the resource
 *   comp: the package's SCA inventory item; base: the mount point its paths are read under ('' on the live host)
 */
export function scViolation(v, { resource, scope, where = '', prefix = '', remediation, comp, base = '' } = {}) {
  const cve = cveOf(v);
  const fixed = (v.fixed_versions || [])[0];
  const hint = upgradeHint(v);
  return {
    resource: resource || `${prefix ? `${prefix}:` : ''}${v.affected_dependency}@${v.affected_dependency_version}: ${cve}`,
    ...(scope ? { scope } : {}),
    severity: severityOf(v),
    kev: v.is_kev === true,
    type: typeOf(v),
    vuln: v,
    ...(comp && comp.id ? { package: compactPackage(comp, new Map([[comp.id, [v]]]), () => false, base) } : {}),
    title: `${v.affected_dependency}: ${cve}${v.summary ? ' — ' + short(v.summary) : ''}`,
    detail: `${v.affected_dependency} ${v.affected_dependency_version}${where ? ` ${where}` : ''}. ${facts(v)}`,
    remediation: remediation || (fixed
      ? `Update ${v.affected_dependency} to ${fixed} or later${hint ? ` (${hint})` : ''} and restart the services that use it.`
      : `No fixed version is available yet: apply the vendor's mitigation or restrict exposure of ${v.affected_dependency}; track ${v.url || v.id}.`),
  };
}

export const sortViolations = (a, b) =>
  (RANK[a.severity] ?? 9) - (RANK[b.severity] ?? 9) || ((b.kev === true) - (a.kev === true)) || ((b.vuln?.epss_score || 0) - (a.vuln?.epss_score || 0)) || String(a.resource).localeCompare(String(b.resource));
