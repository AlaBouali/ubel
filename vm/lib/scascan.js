'use strict';
// scascan.js — the SCA engine's own scans (sca/main.js), run IN MEMORY, for the modules that audit a machine, its running software or a
// cluster. ubel-vm, ubel-runtime and ubel-k8s do not re-implement package scanning: they ask the SCA engine, and what comes back is the
// SCA payload — the vulnerability records with CVSS, KEV / EPSS, fix-version ranking, reachability, dependency sequences and compliance
// mapping — which their findings carry unchanged (type sc_vuln / sc_infection), so every report opens them in the SCA vulnerability modal.
//
//   scanPlatform()   "platform" mode (bin/platform.js): the packages the operating system installed on THIS host (dpkg / apk / rpm read
//                    from disk) — scan_scope developer_platform, scan_os, no project tree.
//   scanDocker()     "docker" mode (dockerScan() in sca/main.js) on a directory that already is a root filesystem — a mounted disk
//                    image (--root), a host mounted into a pod (--host-proc) or a running container's /proc/<pid>/root: the OS packages
//                    plus (unless osOnly) every ecosystem's application dependencies found in it (scan_scope container-image, full_stack).
//   scanTree()       the SCA health scan (full_stack, no OS) of one application directory: node_modules, venvs / site-packages,
//                    Composer, Bundler, Cargo, Go, NuGet, Maven, pub, SwiftPM.
//   scanComponents() the SCA pipeline on a plain list of package URLs through `resbom` (ubel-resbom): no project, no package manager.
// Nothing is written to the scanned directories and no report files are saved: is_script + save_reports:false makes the engine return the
// payload before anything is serialised, and asset_ubel_dir moves the policy file it keeps to the scanner's own .ubel folder. The SCA
// package-manager firewall code lives in the same modules and is never reached. `vulns: false` reads the package list only (no OSV / KEV / EPSS request): the
// VM uses it to still report what is installed when the vulnerability lookup could not be completed. Network: OSV.dev / NVD / CISA / FIRST (UBEL_OSV_ENDPOINT
// and UBEL_NVD_ENDPOINT select internal mirrors). A lookup that cannot be completed makes the engine throw: the check that asked is then
// "not assessed", never clean.

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/**
 * Silences the engine's console output while `fn` runs. Progress (log / info) is dropped; warnings and errors (the engine reports an
 * unreachable CISA / FIRST feed that way) are collected into `sink` so the caller can show them as coverage notes instead.
 */
export async function quiet(fn, sink = []) {
  const saved = { log: console.log, info: console.info, warn: console.warn, error: console.error };
  const grab = (...a) => { const t = a.map((x) => (typeof x === 'string' ? x : (x && x.message) || String(x))).join(' ').replace(/^\[[!~+]\]\s*/, '').trim(); if (t) sink.push(t); };
  console.log = () => {}; console.info = () => {}; console.warn = grab; console.error = grab;
  try { return await fn(); } finally { console.log = saved.log; console.info = saved.info; console.warn = saved.warn; console.error = saved.error; }
}

const ubelDirOf = (workDir) => path.join(path.resolve(workDir || process.cwd()), '.ubel');
const sca = () => import('../../sca/main.js');

/** The options every in-memory scan shares. */
const base = (workDir, threatIntel = true, vulns = true) => ({ engine: 'npm', mode: 'health', is_script: true, save_reports: false, scan_secrets: false, scan_vulns: vulns !== false, threat_intel: threatIntel !== false, asset_ubel_dir: ubelDirOf(workDir) });

/** @returns {Promise<object>} the SCA payload (vulnerabilities[], inventory[], scan_info, threat_intel, …) plus `scan_warnings` (what the engine reported on the console) */
async function run(opts, log, what) {
  log(`  SCA ${what}`);
  const { SCA_scan } = await sca();
  const warnings = [];
  const r = await quiet(() => SCA_scan(opts), warnings);
  if (!r || typeof r !== 'object' || !Array.isArray(r.vulnerabilities)) throw new Error(`the SCA scan (${what}) returned no result`);
  r.scan_warnings = warnings;
  return r;
}

/** SCA platform mode: the operating-system packages installed on this host. */
export async function scanPlatform({ workDir, threatIntel = true, vulns = true, log = () => {} } = {}) {
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ubel-platform-'));
  try {
    return await run({ ...base(workDir, threatIntel, vulns), projectRoot: scratch, full_stack: false, scan_os: true, scan_node: false, scan_scope: 'developer_platform' }, log, 'platform scan (operating-system packages)');
  } finally { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}

/** SCA docker mode on a directory that is a root filesystem: OS packages plus every ecosystem's application dependencies. */
export async function scanDocker({ root, workDir, threatIntel = true, vulns = true, scanOs = true, osOnly = false, log = () => {} } = {}) {
  const what = `docker-mode scan of ${root}${osOnly ? ' (operating-system packages)' : scanOs ? '' : ' (application packages only)'}`;
  return run({ ...base(workDir, threatIntel, vulns), engine: 'docker', projectRoot: root, full_stack: !osOnly, scan_os: scanOs || osOnly, scan_node: !osOnly, scan_scope: 'container-image' }, log, what);
}

/** SCA health scan (full stack, no OS packages) of an application directory. */
export async function scanTree({ dir, workDir, threatIntel = true, vulns = true, log = () => {} } = {}) {
  return run({ ...base(workDir, threatIntel, vulns), projectRoot: dir, full_stack: true, scan_os: false, scan_node: true, scan_scope: 'developer_platform' }, log, `application scan of ${dir}`);
}

/**
 * The SCA pipeline on a list of components, through resbom (the engine behind ubel-resbom).
 * @param {{purl:string, name?:string, version?:string}[]} components
 */
export async function scanComponents({ components, workDir, threatIntel = true, log = () => {} } = {}) {
  const sbom = {
    bomFormat: 'CycloneDX', specVersion: '1.5', version: 1,
    components: components.map((c) => ({ type: 'library', 'bom-ref': c.purl, purl: c.purl, name: c.name || c.purl, version: c.version || '' })),
    dependencies: [],
  };
  log(`  SCA component scan (${components.length} component(s))`);
  const scratch = fs.mkdtempSync(path.join(os.tmpdir(), 'ubel-components-'));
  try {
    const { resbomScan } = await sca();
    const warnings = [];
    const r = await quiet(() => resbomScan({ sbom, projectRoot: scratch, is_script: true, save_reports: false, threat_intel: threatIntel !== false, asset_ubel_dir: ubelDirOf(workDir) }), warnings);
    if (!r || !Array.isArray(r.vulnerabilities)) throw new Error('the SCA component scan returned no result');
    r.scan_warnings = warnings;
    return r;
  } finally { try { fs.rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ } }
}

// ── reading the payload ────────────────────────────────────────────────────────────────────────────────────────────

/** Package-URL type of an id ("pkg:pypi/flask@2.0" → "pypi"). */
export const purlType = (purl) => { const m = /^pkg:([^/]+)\//.exec(String(purl || '')); return m ? m[1] : ''; };
/** Operating-system package URL types (the engine's OS_PURL_RE). */
export const isOsPurl = (purl) => ['deb', 'apk', 'rpm'].includes(purlType(purl));
/** A component's locations as plain strings (the engine stores { type, text } objects). */
export const pathsOf = (c) => (c && Array.isArray(c.paths) ? c.paths : []).map((p) => (typeof p === 'string' ? p : (p && p.text) || '')).filter(Boolean);

/** Several SCA payloads → one: vulnerabilities de-duplicated per (advisory, package), inventory per package, warnings and feed status kept. */
export function mergeResults(list) {
  const vulns = new Map(), inv = new Map(), warnings = new Set(), seqs = new Map();
  let intel = null;
  for (const r of list.filter(Boolean)) {
    for (const v of r.vulnerabilities || []) {
      const k = `${v.affected_package_id}\u0001${v.id}`;
      if (vulns.has(k)) continue;
      const fs_ = r.findings_summary && r.findings_summary[v.affected_dependency];
      const sq = fs_ && (fs_.version == null || fs_.version === v.affected_dependency_version) && Array.isArray(fs_.affected_dependency_sequences) ? fs_.affected_dependency_sequences : null;
      vulns.set(k, sq && !v.affected_dependency_sequences ? { ...v, affected_dependency_sequences: sq } : v);
    }
    for (const c of r.inventory || []) {
      const e = inv.get(c.id);
      if (!e) { inv.set(c.id, { ...c, paths: [...(c.paths || [])] }); continue; }
      const have = new Set(pathsOf(e));
      for (const p of c.paths || []) { const t = typeof p === 'string' ? p : p && p.text; if (t && !have.has(t)) { e.paths.push(p); have.add(t); } }
    }
    for (const w of r.scan_warnings || []) warnings.add(w);
    if (!intel && r.threat_intel) intel = r.threat_intel;
  }
  return { vulnerabilities: [...vulns.values()], inventory: [...inv.values()], threat_intel: intel, scan_warnings: [...warnings] };
}
