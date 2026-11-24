'use strict';
// deps.js — advisory lookup for the components found inside a binary, shaped exactly like ubel-mobile's dependency block.
//   PURL records (Go modules, Rust crates)  → OSV.dev through the same code ubel-mobile uses (scanMobileDependencies)
//   CPE records (C/C++ banners, Node.js / Python runtimes) → NVD through the shared SCA engine (submitToNvd), version-verified
//   inventory records (package seen, version unknown)       → listed as not queryable, no lookup
// A lookup that fails is reported as a failure of that component, never as "clean".

import { submitToNvd, getFix, scoreToSeverity } from '../../sca/engine.js';
import { processVulnerability } from '../../sca/cvss_parser.js';
import { scanMobileDependencies, settleLookupStatuses, summarise, advisoryRecord } from '../../mobile/lib/dependencies.js';
import { enrichAdvisories } from '../../mobile/lib/threatintel.js';

// Same post-processing the SCA engine and the EASM module apply to an NVD item (processVulnerability expects OSV's severity shape and resets the NVD score).
function finishNvd(v) {
  const score = v.severity_score, vector = v.severity_vector;
  processVulnerability(v);
  if (v.severity_score == null) v.severity_score = score;
  if (v.severity_vector == null) v.severity_vector = vector;
  v.severity = scoreToSeverity(v.severity_score);
  getFix(v);
}

/**
 * `threatIntel`: also add CISA KEV / FIRST EPSS to every advisory (is_kev, kev_added, kev_deadline, epss_score, epss_percentile, as the SCA report has them)
 * and the feeds' status to `summary.threat_intel`. Off by default: ubel-binary, ubel-package and ubel-mobile ask for it.
 * @returns {Promise<{dependencies:object[], summary:object, lookup_error:string|null}>}
 */
export async function scanBinaryDependencies(records, { log = () => {}, threatIntel = false } = {}) {
  const purlRecs = records.filter(r => r.purl);
  const cpeRecs = records.filter(r => !r.purl && r.cpe).map(r => ({ ...r, vulnerabilities: [], vulnerability_count: 0 }));
  // Inventory-only records (a package that is in the file but whose version could not be recovered): shown, never looked up, never "clean".
  const inventory = records.filter(r => !r.purl && !r.cpe).map(r => ({ ...r, lookup_status: 'not_queryable', vulnerabilities: [], vulnerability_count: 0 }));
  const first = purlRecs.length ? await scanMobileDependencies(purlRecs, { log, includeNative: true }) : { dependencies: [], lookup_error: null };
  let lookupError = first.lookup_error || null;

  const pending = cpeRecs.filter(r => r.lookup_status === 'pending');
  if (pending.length) {
    log(`[*] Querying NVD for ${pending.length} CPE id(s) (rate-limited; this can take a while)...`);
    const byCpe = new Map(pending.map(r => [r.cpe, r]));
    try {
      const vulns = await submitToNvd(pending.map(r => ({ id: r.cpe, name: r.name, version: r.version, ecosystem: 'native' })), { dropUnboundedMatches: true });
      for (const v of vulns) {
        finishNvd(v);
        const dep = byCpe.get(v.affected_package_id);
        if (dep && !dep.vulnerabilities.some(x => x.id === v.id)) dep.vulnerabilities.push(advisoryRecord({ ...v, url: v.url || (v.id ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}` : null), is_infection: false }));
      }
    } catch (err) {
      const msg = String(err?.message || err).slice(0, 500);
      lookupError ||= msg;
      for (const dep of pending) { dep.lookup_status = 'lookup_error'; dep.lookup_error = msg; dep.lookup_reason = 'The component could not be conclusively checked against NVD during this scan.'; }
    }
  }
  const dependencies = [...first.dependencies, ...cpeRecs, ...inventory];
  for (const dep of cpeRecs) if (dep.lookup_status === 'pending') dep.lookup_reason = null;
  settleLookupStatuses(dependencies.filter(d => d.lookup_status === 'pending'));
  for (const dep of cpeRecs) if (dep.lookup_status === 'clean') dep.lookup_reason = 'NVD returned no CVE whose CPE ranges cover this exact version at scan time.';
  for (const dep of dependencies) { dep.vulnerability_count = dep.vulnerabilities.length; }
  const summary = summarise(dependencies);
  summary.queryable += cpeRecs.filter(d => d.lookup_status !== 'not_queryable').length;     // summarise() counts PURLs only
  if (threatIntel) { const intel = await enrichAdvisories(dependencies, { log }); if (intel) summary.threat_intel = intel; }
  return { dependencies, summary, lookup_error: lookupError };
}
