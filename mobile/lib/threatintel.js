'use strict';
// threatintel.js — exploit intelligence (CISA KEV + FIRST EPSS) for the advisories found on the components of a mobile app, a native binary or a
// package, exactly as the SCA report has it: the same engine call (enrichWithThreatIntel in sca/engine.js), so every advisory gets
//   is_kev (true | false | null = unknown), kev_added, kev_deadline, epss_score, epss_percentile
// and the canonical report's vulnerability modal (canonical/client/scvuln.js) shows them in its "Known Exploited / KEV Added / KEV Deadline /
// EPSS Score / EPSS Percentile" block.
//
// Neither feed can fail a scan (same contract as SCA): when one is unreachable the fields stay null — unknown, never "not exploited" — and
// the returned status says which feed was unavailable. CVE ids come from the advisory id and its aliases (GHSA / OSV ids carry their CVE as an alias).
// Nothing is requested when there is no advisory at all, or when none of them has a CVE id.

import { enrichWithThreatIntel } from '../../sca/engine.js';

/**
 * Adds the KEV / EPSS fields to every advisory of `dependencies` (each `dep.vulnerabilities[]` entry, once).
 * @param {object[]} dependencies  dependency records with a `vulnerabilities` list
 * @param {{log?:(m:string)=>void}} [opts]
 * @returns {Promise<object|null>} `{ kev: {status, …}, epss: {status, …}, warnings: string[], kev_listed: number }`, or null when there was no advisory
 */
export async function enrichAdvisories(dependencies, { log = () => {} } = {}) {
  const vulns = [];
  const seen = new Set();
  for (const dep of dependencies || []) {
    for (const v of dep.vulnerabilities || []) {
      if (!v || typeof v !== 'object' || seen.has(v)) continue;
      seen.add(v);
      vulns.push(v);
    }
  }
  if (!vulns.length) return null;

  log(`[*] Checking ${vulns.length} advisor${vulns.length === 1 ? 'y' : 'ies'} against the CISA KEV catalog and FIRST EPSS...`);
  let intel;
  try {
    intel = await enrichWithThreatIntel(vulns);
  } catch (e) {                                              // enrichWithThreatIntel does not throw; this keeps the contract if that ever changes
    const error = String(e?.message || e).slice(0, 500);
    for (const v of vulns) { v.is_kev = null; v.kev_added = null; v.kev_deadline = null; v.epss_score = null; v.epss_percentile = null; }
    intel = {
      kev: { status: 'unavailable', error }, epss: { status: 'unavailable', error },
      warnings: [`CISA KEV / FIRST EPSS lookup failed (${error}): KEV status and EPSS scores are unknown.`],
    };
  }
  for (const w of intel.warnings || []) log(`[!] ${w}`);
  return { ...intel, kev_listed: vulns.filter((v) => v.is_kev === true).length };
}
