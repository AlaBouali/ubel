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
 * @param {{root?:string, live?:boolean, extraRoots?:string[], skipApps?:boolean, workDir?:string, threatIntel?:boolean, log?:(m:string)=>void}} [opts]
 *   root: "/" or a mounted root; live: scan the running host (platform mode) instead of a mounted root (docker mode)
 * @returns {Promise<{mode:'platform'|'docker', os:{supported:boolean, reason:string|null, ecosystem:string, distro:string, installed:number},
 *   apps:{scanned:boolean, roots:string[], installed:number, osInstalledSkipped:number}, inventory:object[], vulnerabilities:object[],
 *   osVulnerabilities:object[], appVulnerabilities:object[], threatIntel:object|null, notes:string[]}>}
 * @throws {PackageScanUnsupported} the machine has neither a readable package database nor any application package location
 * @throws {Error} a scan or lookup failed (OSV unreachable, an advisory not fetchable …) — the caller reports "not assessed"
 */
async function scanMachinePackages({ root = '/', live = true, extraRoots = [], skipApps = false, workDir, threatIntel = true, log = () => {} } = {}) {
  const base = !root || root === '/' ? '' : root.replace(/\/+$/, '');
  const notes = [];
  const parts = [];
  const os = { supported: true, reason: null, ecosystem: '', distro: '', installed: 0 };
  const apps = { scanned: false, roots: [], installed: 0, osInstalledSkipped: 0 };
  let mode;

  if (live) {
    mode = 'platform';
    try { parts.push(await scanPlatform({ workDir, threatIntel, log })); } catch (e) {
      if (!UNSUPPORTED_OS.test(e.message)) throw e;
      os.supported = false; os.reason = e.message;
    }
    if (!skipApps) {
      const dirs = [...new Set([...DEFAULT_APP_ROOTS, ...extraRoots].map((d) => path.posix.normalize(d)))].filter((d) => isDir(d));
      for (const dir of dirs) {
        try { parts.push(await scanTree({ dir, workDir, threatIntel, log })); apps.roots.push(dir); } catch (e) { throw new Error(`application scan of ${dir}: ${e.message}`); }
      }
      apps.scanned = true;
    }
  } else {
    mode = 'docker';
    try { parts.push(await scanDocker({ root: base || '/', workDir, threatIntel, scanOs: true, log })); } catch (e) {
      if (!UNSUPPORTED_OS.test(e.message)) throw e;
      os.supported = false; os.reason = e.message;
      if (!skipApps) parts.push(await scanDocker({ root: base || '/', workDir, threatIntel, scanOs: false, log }));
    }
    apps.scanned = !skipApps; if (!skipApps) apps.roots.push('/');
  }

  const merged = mergeResults(parts);
  if (!parts.length || (!merged.inventory.length && !os.supported && !apps.scanned)) throw new PackageScanUnsupported(os.reason || 'no package database and no application location to read');

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

  return {
    mode, os, apps, inventory, vulnerabilities, threatIntel: merged.threat_intel, notes,
    osVulnerabilities: vulnerabilities.filter((v) => isOsPurl(v.affected_package_id)),
    appVulnerabilities: vulnerabilities.filter((v) => !isOsPurl(v.affected_package_id)),
  };
}

export { scanMachinePackages, PackageScanUnsupported };
