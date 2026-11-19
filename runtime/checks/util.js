'use strict';
import { na } from '../../vm/lib/engine.js';
export { rule } from '../lib/util.js';

/** Every rule needs /proc; on anything else the whole catalogue is "not applicable", never "clean". */
export const needLive = (ctx) => (ctx.live ? null : na(`needs a live Linux host with /proc (this is ${process.platform}${process.platform === 'linux' ? ', /proc is not readable' : ''})`));

const RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const SEV = { critical: 'critical', high: 'high', medium: 'medium', moderate: 'medium', low: 'low', unknown: 'medium' };

/** Severity of an advisory: its own rating, never below high when it is exploited in the wild (CISA KEV) or a malicious-package advisory. */
export function vulnSeverity(v) {
  if (v.is_infection) return 'critical';
  let sev = SEV[String(v.severity || 'unknown').toLowerCase()] || 'medium';
  if (v.is_kev === true && RANK[sev] > RANK.high) sev = 'high';
  return sev;
}
export const cveOf = (v) => (v.aliases || []).find((a) => /^CVE-/.test(a)) || v.id;
export const short = (s, n = 90) => String(s || '').replace(/\s+/g, ' ').slice(0, n);
export const vulnFacts = (v) =>
  `${v.is_infection ? 'This is a malicious-package advisory. ' : ''}${(v.fixed_versions || [])[0] ? `Fixed in ${v.fixed_versions[0]}.` : 'No fixed version is published for this release yet.'}` +
  `${v.is_kev === true ? ' Listed in the CISA Known Exploited Vulnerabilities catalogue (exploited in the wild).' : ''}` +
  `${typeof v.epss_score === 'number' ? ` EPSS ${(v.epss_score * 100).toFixed(1)}%.` : ''} ${v.url || ''}`.trimEnd();
export const sortVulns = (a, b) => RANK[a.severity] - RANK[b.severity] || ((b.kev === true) - (a.kev === true)) || String(a.resource).localeCompare(String(b.resource));
export { RANK };
