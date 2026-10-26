'use strict';
// deps.js — advisory lookup for the components found inside a binary, shaped exactly like ubel-mobile's dependency block.
//   PURL records (Go modules, Rust crates)  → OSV.dev through the same code ubel-mobile uses (scanMobileDependencies)
//   CPE records (C/C++ banners, Node.js / Python runtimes) → NVD through the shared SCA engine (submitToNvd), version-verified
//   inventory records (package seen, version unknown)       → listed as not queryable, no lookup
// A lookup that fails is reported as a failure of that component, never as "clean".

import { submitToNvd, getFix, scoreToSeverity } from '../../sca/engine.js';
import { processVulnerability } from '../../sca/cvss_parser.js';
import { scanMobileDependencies, settleLookupStatuses, summarise } from '../../mobile/lib/dependencies.js';

function minimal(v) {
  return {
    id: v.id || v.vulnerability_id || 'Unknown advisory', summary: v.summary || v.title || '', details: v.description || v.details || '',   // processVulnerability() moves `details` into `description` aliases: Array.isArray(v.aliases) ? v.aliases : [],
    severity: String(v.severity || 'unknown').toLowerCase(), severity_score: v.severity_score == null ? null : Number(v.severity_score), severity_vector: v.severity_vector || null,
    cwes: Array.isArray(v.cwes) ? v.cwes : [],
    published: v.published || null, modified: v.modified || null, url: v.url || (v.id ? `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(v.id)}` : null),
    fixed_versions: Array.isArray(v.fixed_versions) ? v.fixed_versions : [], has_fix: Boolean(v.has_fix),
    affected_package_id: v.affected_package_id || null, affected_dependency_version: v.affected_dependency_version || null, is_infection: false,
  };
}

// Same post-processing the SCA engine and the EASM module apply to an NVD item (processVulnerability expects OSV's severity shape and resets the NVD score).
function finishNvd(v) {
  const score = v.severity_score, vector = v.severity_vector;
  processVulnerability(v);
  if (v.severity_score == null) v.severity_score = score;
  if (v.severity_vector == null) v.severity_vector = vector;
  v.severity = scoreToSeverity(v.severity_score);
  getFix(v);
}

/** @returns {Promise<{dependencies:object[], summary:object, lookup_error:string|null}>} */
export async function scanBinaryDependencies(records, { log = () => {} } = {}) {
  const purlRecs = records.filter(r => r.purl);
  const cpeRecs = records.filter(r => !r.purl && r.cpe).map(r => ({ ...r, vulnerabilities: [], vulnerability_count: 0 }));
  // Inventory-only records (a package that is in the file but whose version could not be recovered): shown, never looked up, never "clean".
  const inventory = records.filter(r => !r.purl && !r.cpe).map(r => ({ ...r, lookup_status: 'not_queryable', vulnerabilities: [], vulnerability_count: 0 }));
  const first = purlRecs.length ? await scanMobileDependencies(purlRecs, { log }) : { dependencies: [], lookup_error: null };
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
        if (dep && !dep.vulnerabilities.some(x => x.id === v.id)) dep.vulnerabilities.push(minimal(v));
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
  return { dependencies, summary, lookup_error: lookupError };
}
