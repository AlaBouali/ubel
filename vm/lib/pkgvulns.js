'use strict';
// pkgvulns.js — known vulnerabilities in the software installed on a machine (or in a mounted root filesystem), from the SCA engine.
//
// ubel-vm does not read package databases or query OSV.dev itself: it runs the SCA engine's own scans (scascan.js) and keeps what they
// return — the SCA vulnerability records, unchanged — so the findings carry type sc_vuln / sc_infection and open in the SCA modal.
//   live host        "platform" mode (bin/platform.js): the operating-system packages (dpkg / apk / rpm read from disk), then the SCA
//                    health scan (full stack) of the application directories below — npm modules, venvs and site-packages, Composer,
//                    Bundler, Cargo, Go, NuGet, Maven, pub, SwiftPM — wherever the SCA scanners find them;
//   --root / --host-proc  "docker" mode on the mounted root: operating-system packages and every ecosystem's dependencies in one scan.
// Application packages that the distribution's own package manager installed (dpkg / apk / rpm owns their files) are dropped: their
// versions are the distribution's patched builds (Debian keeps the upstream version number and backports the fix), so an upstream
// PyPI / npm advisory would report a vulnerability the distribution already fixed. The operating-system check judges them instead,
// with release-scoped advisories.
// A lookup that cannot be completed makes the SCA engine throw (fail closed): the checks are then "not assessed", never clean.
// The SCA modules are loaded lazily, only when this scan runs; none of the SCA package-manager firewall code (apt / dnf dry-runs) is
// reached — only file readers and the HTTPS lookups. Set UBEL_OSV_ENDPOINT to use an internal OSV mirror (air-gapped networks).

import fs from 'node:fs';
import path from 'node:path';
import { OwnerIndex } from './owners.js';
import { scanPlatform, scanDocker, scanTree, mergeResults, isOsPurl, pathsOf } from './scascan.js';

class PackageScanUnsupported extends Error {}

/** SCA / linux_runner messages that mean "this machine has no package database the engine can read" — not a failed lookup. */
const UNSUPPORTED_OS = /Cannot detect OS|Unsupported OS ecosystem|No scanner implemented|status file not found|database not found|rpmdb: no rpm database|NDB database|no packages decoded/i;

/** Directory trees the SCA application scan walks on a live host (add more with --app-roots). */
export const DEFAULT_APP_ROOTS = ['/opt', '/srv', '/var/www', '/app', '/usr/src', '/usr/local', '/home', '/root'];

const isDir = (p) => { try { return fs.statSync(p).isDirectory(); } catch { return false; } };

/** True when every location of a component belongs to an operating-system package (see the header). */
function installedByDistro(owners, base, comp) {
  if (!owners || !owners.kind || !owners.size) return false;
  const paths = pathsOf(comp);
  if (!paths.length) return false;
  return paths.every((p) => {
    const lp = base && p.startsWith(base) ? (p.slice(base.length) || '/') : p;
    return owners.owns(lp) || ['package.json', 'METADATA', 'PKG-INFO', 'RECORD'].some((f) => owners.owns(`${lp}/${f}`));
  });
}

/**
 * The package list as the report carries it: the SCA inventory item of every installed package (operating-system and application),
 * trimmed to what the SCA package modal shows, with `state` taken from the advisories that were kept.
 */
function compactPackage(c, vulns, unassessed) {
  const cap = (a, n) => (Array.isArray(a) ? a.slice(0, n) : []);
  const mine = vulns.get(c.id) || [];
  return {
    id: c.id, name: c.name, version: c.version, type: c.type || 'library', ecosystem: c.ecosystem || '', ...(c.distro ? { distro: c.distro } : {}),
    license: c.license ?? null, ...(c.license_info ? { license_info: c.license_info } : {}),
    state: mine.some((v) => v.is_infection) ? 'infected' : mine.length ? 'vulnerable' : unassessed(c) ? 'unknown' : 'safe',   // 'unknown': its lookup could not be completed, never "safe"
    scopes: cap(c.scopes, 5), paths: cap(c.paths, 5), dependencies: cap(c.dependencies, 25), introduced_by: cap(c.introduced_by, 10), parents: cap(c.parents, 25),
    is_direct: c.is_direct ?? null, is_policy_violation: false, vulnerable_transitive_dependencies: [], policy_violations: [], suggested_fixes: c.suggested_fixes || { fixes: [], unfixed: [] },
  };
}

/**
 * Runs one SCA scan with its vulnerability lookup; when the lookup cannot be completed the same scan is repeated WITHOUT it, so the
 * package list is still read (it is local) and the failure is returned for the checks to report as "not assessed".
 * @returns {Promise<{result:object|null, error:Error|null}>}
 * @throws the engine's "no package database" errors (the caller decides what they mean)
 */
async function guarded(run) {
  try { return { result: await run(true), error: null }; } catch (e) {
    if (UNSUPPORTED_OS.test(e.message)) throw e;
    try { return { result: await run(false), error: e }; } catch (e2) { if (UNSUPPORTED_OS.test(e2.message)) throw e2; return { result: null, error: e }; }
  }
}

/**
 * @param {{root?:string, live?:boolean, extraRoots?:string[], skipApps?:boolean, workDir?:string, threatIntel?:boolean, log?:(m:string)=>void}} [opts]
 *   root: "/" or a mounted root; live: scan the running host (platform mode) instead of a mounted root (docker mode)
 * @returns {Promise<{mode:'platform'|'docker', os:{supported:boolean, reason:string|null, ecosystem:string, distro:string, installed:number, error:Error|null},
 *   apps:{scanned:boolean, roots:string[], installed:number, osInstalledSkipped:number, error:Error|null}, inventory:object[], packages:object[],
 *   vulnerabilities:object[], osVulnerabilities:object[], appVulnerabilities:object[], threatIntel:object|null, notes:string[]}>}
 *   os.error / apps.error: the vulnerability lookup of that part could not be completed (the package list is still there; the check must be "not assessed")
 * @throws {PackageScanUnsupported} the machine has neither a readable package database nor any application package location
 */
async function scanMachinePackages({ root = '/', live = true, extraRoots = [], skipApps = false, workDir, threatIntel = true, log = () => {} } = {}) {
  const base = !root || root === '/' ? '' : root.replace(/\/+$/, '');
  const notes = [];
  const parts = [];
  const os = { supported: true, reason: null, ecosystem: '', distro: '', installed: 0, error: null };
  const apps = { scanned: false, roots: [], installed: 0, osInstalledSkipped: 0, error: null };
  let mode;

  if (live) {
    mode = 'platform';
    try {
      const g = await guarded((vulns) => scanPlatform({ workDir, threatIntel, vulns, log }));
      if (g.result) parts.push(g.result);
      if (g.error) os.error = g.error;
    } catch (e) { os.supported = false; os.reason = e.message; }
    if (!skipApps) {
      const dirs = [...new Set([...DEFAULT_APP_ROOTS, ...extraRoots].map((d) => path.posix.normalize(d)))].filter((d) => isDir(d));
      for (const dir of dirs) {
        let g;
        try { g = await guarded((vulns) => scanTree({ dir, workDir, threatIntel, vulns, log })); } catch (e) { notes.push(`${dir}: could not be read (${e.message}).`); continue; }
        if (g.result) { parts.push(g.result); apps.roots.push(dir); }
        if (g.error && !apps.error) apps.error = new Error(`application scan of ${dir}: ${g.error.message}`);
      }
      apps.scanned = true;
    }
  } else {
    mode = 'docker';
    let g;
    try { g = await guarded((vulns) => scanDocker({ root: base || '/', workDir, threatIntel, vulns, scanOs: true, log })); } catch (e) {
      os.supported = false; os.reason = e.message;
      if (!skipApps) g = await guarded((vulns) => scanDocker({ root: base || '/', workDir, threatIntel, vulns, scanOs: false, log }));
    }
    if (g && g.result) parts.push(g.result);                           // one docker-mode scan holds both halves
    if (g && g.error) { if (os.supported) os.error = g.error; apps.error = g.error; }
    apps.scanned = !skipApps; if (!skipApps) apps.roots.push('/');
  }

  const merged = mergeResults(parts);
  if (!parts.length && !os.error && !apps.error) throw new PackageScanUnsupported(os.reason || 'no package database and no application location to read');
  if (!os.supported) notes.push(`The operating-system package list could not be read: ${os.reason}`);
  if (os.error) notes.push(`The vulnerability lookup for the operating-system packages could not be completed (${os.error.message}); the package list is reported without advisories.`);
  if (apps.error) notes.push(`The vulnerability lookup for the application packages could not be completed (${apps.error.message}); the package list is reported without advisories.`);

  // application packages the distribution itself installed are the operating-system check's business
  const owners = new OwnerIndex(base || '/').load();
  if (owners.error) notes.push(`The distribution's file lists could not be read (${owners.error}): application packages installed by the package manager were not told apart.`);
  const skippedIds = new Set();
  const inventory = [];
  for (const c of merged.inventory) {
    if (!isOsPurl(c.id) && installedByDistro(owners, base, c)) { skippedIds.add(c.id); continue; }
    inventory.push(c);
  }
  apps.osInstalledSkipped = skippedIds.size;
  const vulnerabilities = merged.vulnerabilities.filter((v) => !skippedIds.has(v.affected_package_id));
  const osInv = inventory.filter((c) => isOsPurl(c.id));
  os.installed = osInv.length;
  if (osInv.length) { os.ecosystem = osInv[0].ecosystem || ''; os.distro = osInv[0].distro || ''; }
  apps.installed = inventory.length - osInv.length;
  for (const w of merged.scan_warnings) notes.push(w);

  const byPkg = new Map();
  for (const v of vulnerabilities) { if (!byPkg.has(v.affected_package_id)) byPkg.set(v.affected_package_id, []); byPkg.get(v.affected_package_id).push(v); }
  return {
    mode, os, apps, inventory, packages: inventory.map((c) => compactPackage(c, byPkg, (c) => (isOsPurl(c.id) ? !!os.error : !!apps.error))), vulnerabilities, threatIntel: merged.threat_intel, notes,
    osVulnerabilities: vulnerabilities.filter((v) => isOsPurl(v.affected_package_id)),
    appVulnerabilities: vulnerabilities.filter((v) => !isOsPurl(v.affected_package_id)),
  };
}

export { scanMachinePackages, PackageScanUnsupported };
