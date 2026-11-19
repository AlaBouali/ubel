'use strict';
// lookups.js — advisory lookups for what a runtime scan finds, through UBEL's own engine (OSV.dev for package URLs, NVD for CPEs):
// the same code and the same fail-closed contract as ubel-vm and ubel-binary. A lookup that cannot be completed THROWS, and the
// check that needed it is then "not assessed" — never "clean". Set UBEL_OSV_ENDPOINT / UBEL_NVD_ENDPOINT for internal mirrors.
// The SCA engine is loaded lazily, only when a lookup runs.

import { mapLimit } from './util.js';
import { cRecord, npmPurl } from '../../binary/lib/records.js';

export { npmPurl };

/** @param {{name:string,version:string}[]} pkgs @returns {Promise<{vulnerabilities:object[], intel:object, queried:number}>} */
export async function lookupNpm(pkgs, { threatIntel = true, log = () => {} } = {}) {
  const engine = await import('../../sca/engine.js');
  const purls = [...new Set(pkgs.map((p) => npmPurl(p.name, p.version)))].filter((p) => !engine.UNVERIFIED_SOURCE_RE.test(p));
  if (!purls.length) return { vulnerabilities: [], intel: { kev: { status: 'skipped' }, epss: { status: 'skipped' } }, queried: 0 };
  log(`  querying OSV.dev for ${purls.length} npm package(s)`);
  const refs = await engine.submitToOsv(purls);
  const results = await mapLimit(refs, 40, (r) => engine.getVulnById(r));
  const failed = results.filter((r) => !r.ok);
  if (failed.length) throw new engine.VulnLookupError(`${failed.length} OSV advisor${failed.length === 1 ? 'y' : 'ies'} could not be fetched (${failed[0].error && failed[0].error.message}) — vulnerability lookup is incomplete.`, { source: 'osv-vuln', cause: failed[0].error });
  let vulnerabilities = engine.deduplicateVulnerabilitiesByAlias(results.map((r) => r.value).filter(Boolean));
  let intel = { kev: { status: 'skipped' }, epss: { status: 'skipped' } };
  if (threatIntel && vulnerabilities.length) {
    try { intel = await engine.enrichWithThreatIntel(vulnerabilities); } catch (e) {
      intel = { kev: { status: 'unavailable', error: e.message }, epss: { status: 'unavailable', error: e.message } };
      for (const v of vulnerabilities) { v.is_kev = null; v.epss_score = null; }
    }
  }
  return { vulnerabilities, intel, queried: purls.length };
}

/** CPE / PURL component records (from ubel-binary's readers or built here) → advisories. Same shape as ubel-binary's dependency block. */
export async function lookupComponents(records, { log = () => {} } = {}) {
  const { scanBinaryDependencies } = await import('../../binary/lib/deps.js');
  const r = await scanBinaryDependencies(records, { log });
  if (r.lookup_error) throw new Error(`component lookup incomplete: ${r.lookup_error}`);
  return r;
}

/** Component records for the runtime a Node.js process reports about itself (process.versions): the Node.js release and the libraries it bundles. */
export function nodeRuntimeRecords(versions) {
  const v = versions || {};
  const clean = (x) => String(x || '').replace(/-.*$/, '');
  const mk = (name, ver, vendor, product) => (ver ? cRecord({ name, version: ver, vendor, product, evidence: `process.versions: ${name} ${ver}`, source: 'process.versions (live inspection)', sourceType: 'node runtime report', ecosystem: 'Node.js runtime' }) : null);
  return [
    mk('Node.js', clean(v.node), 'nodejs', 'node.js'),
    mk('OpenSSL', clean(v.openssl), 'openssl', 'openssl'),
    mk('zlib', String(v.zlib || '').match(/^\d+(?:\.\d+)+/)?.[0], 'zlib', 'zlib'),
    mk('nghttp2', clean(v.nghttp2), 'nghttp2', 'nghttp2'),
    mk('c-ares', clean(v.ares), 'c-ares_project', 'c-ares'),
  ].filter(Boolean);
}
