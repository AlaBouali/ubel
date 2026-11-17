'use strict';
// pkgvulns.js — known vulnerabilities in the packages installed on a machine (or in a mounted image root).
//
// This is the package scan of `ubel-docker`, pointed at the machine instead of an extracted image:
//   1. LinuxHostScanner (sca/linux_runner.js) reads the dpkg / apk / rpm database FROM DISK — no dpkg, apk or rpm binary —
//      and tags every package with its release ("ubuntu-22.04");
//   2. submitToOsv() asks OSV.dev about every package URL with that distro qualifier (batched, paginated);
//   3. getVulnById() fetches each advisory, drops those written for another release or whose fixed version is already
//      installed, and attaches fixed versions and the release-confidence of the match;
//   4. duplicates by alias are merged and CISA KEV / FIRST EPSS are attached (never aborting the scan).
// A lookup that cannot be completed throws (fail closed): the check is then reported as "not assessed", never as clean.
//
// The SCA modules are loaded lazily, only when this scan runs. They also contain the package-manager firewall (apt / dnf
// dry-runs) that does start processes; none of that code is used here — only the file readers and the HTTPS lookups above
// (tests/vm.test.js proves, by making every process-spawning API throw, that a complete scan starts none).
// Set UBEL_OSV_ENDPOINT to use an internal OSV mirror (air-gapped networks).

class PackageScanUnsupported extends Error {}

const hasVersion = (p) => {
  const body = String(p).split('?')[0].split('#')[0];
  const at = body.lastIndexOf('@');
  return at > body.lastIndexOf('/') && at < body.length - 1;
};

/**
 * @param {{root?:string, threatIntel?:boolean, log?:(m:string)=>void}} opts  root "/" (or "") = the running host
 * @returns {Promise<{ecosystem:string, distro:string, packageCount:number, advisoriesDropped:number, vulnerabilities:object[], intel:object}>}
 * @throws {PackageScanUnsupported} no supported package database here
 * @throws {Error} a lookup failed (OSV unreachable, advisory not fetchable …) — the caller reports "not assessed"
 */
async function scanInstalledPackages({ root = '/', threatIntel = true, log = () => {} } = {}) {
  const { LinuxHostScanner } = await import('../../sca/linux_runner.js');
  const engine = await import('../../sca/engine.js');

  const scanner = new LinuxHostScanner(root === '/' ? '' : root);
  let purls;
  try { purls = scanner.getInstalled(); } catch (e) {
    if (/Cannot detect OS|Unsupported OS ecosystem|No scanner implemented|status file not found|not found at|no .* database/i.test(e.message)) throw new PackageScanUnsupported(e.message);
    throw e;
  }
  const inventory = scanner.inventoryData || [];
  if (!inventory.length) throw new PackageScanUnsupported('the package database lists no installed packages');
  log(`  ${inventory.length} installed package(s) read from the package database`);

  const distroByPurl = new Map(inventory.filter((c) => c && typeof c.id === 'string' && c.distro).map((c) => [c.id, c.distro]));
  const queryPurls = [...new Set(purls.filter((p) => p.startsWith('pkg:') && hasVersion(p) && !engine.UNVERIFIED_SOURCE_RE.test(p)))];

  // OSV batch query (distro-qualified), then advisory details with release scoping — the same sequence as the SCA engine.
  const refs = await engine.submitToOsv(queryPurls, { distroByPurl });
  let vulnerabilities = [];
  let dropped = 0;
  const CONCURRENCY = 40;
  for (let i = 0; i < refs.length; i += CONCURRENCY) {
    const results = await Promise.allSettled(refs.slice(i, i + CONCURRENCY).map(engine.getVulnById));
    const failed = results.filter((r) => r.status === 'rejected');
    if (failed.length) {
      throw new engine.VulnLookupError(`${failed.length} OSV advisor${failed.length === 1 ? 'y' : 'ies'} could not be fetched (${failed[0].reason && failed[0].reason.message}) — vulnerability lookup is incomplete.`, { source: 'osv-vuln', cause: failed[0].reason });
    }
    for (const r of results) { if (r.value) vulnerabilities.push(r.value); else dropped++; }
  }
  vulnerabilities = engine.deduplicateVulnerabilitiesByAlias(vulnerabilities);

  let intel = { kev: { status: 'skipped' }, epss: { status: 'skipped' }, warnings: [] };
  if (threatIntel && vulnerabilities.length) {
    try { intel = await engine.enrichWithThreatIntel(vulnerabilities); } catch (e) {
      intel = { kev: { status: 'unavailable', error: e.message }, epss: { status: 'unavailable', error: e.message }, warnings: [`Threat-intel enrichment failed (${e.message}): KEV / EPSS data is unavailable.`] };
      for (const v of vulnerabilities) { v.is_kev = null; v.epss_score = null; }
    }
  }
  const sample = inventory[0] || {};
  return { ecosystem: sample.ecosystem || '', distro: sample.distro || '', packageCount: inventory.length, advisoriesDropped: dropped, vulnerabilities, intel };
}

export { scanInstalledPackages, PackageScanUnsupported };
