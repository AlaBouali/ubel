#!/usr/bin/env node
'use strict';
// ubel-mobile — static security scan of an Android .apk or iOS .ipa (also .xapk/.apks/.apkm split bundles).
// Hardcoded secrets, insecure storage / data handling and misconfigurations, mapped to OWASP MASVS.
// Pure Node built-ins: no third-party libraries and no external binaries (no aapt, apktool, jadx, otool …).

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath, pathToFileURL } from 'url';
import { ZipArchive } from './lib/zip.js';
import { analyzeApk } from './lib/android.js';
import { analyzeIpa, findAppDir } from './lib/ios.js';
import { SecretScanner } from './lib/secrets.js';
import { extractMobileDependencies, scanMobileDependencies } from './lib/dependencies.js';
export { extractMobileDependencies, scanMobileDependencies };
import { Findings } from './lib/findings.js';
import { SEVERITY_RANK, SEVERITIES } from './lib/rules.js';
import { buildPayload, buildHtml, complianceForMobileFinding, isMisconfigurationFinding, isSecretFinding, isVulnerabilityFinding, flattenFindings } from './lib/report.js';
import { loadPreviousReport } from '../cloud/lib/previous_report.js';
import { buildZip } from '../sca/zip_writer.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId, provisionAssetAt } from '../sca/report_naming.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;
const TAG = 'mobile';

const HELP = `
ubel-mobile — static security scan of a mobile app package (no third-party libraries, no external tools)

Usage:
  ubel-mobile <app.apk | app.ipa | app.xapk | app.apks> [--working-dir <path>]
              [--min-severity critical|high|medium|low|info]
              [--fail-on critical|high|medium|low|info|none|<count>:<severity>]
              [--max-entry-mb <n>] [--verbose] [--quiet]

Looks for:
  • hardcoded secrets (API keys, tokens, private keys …) in code, resources, plists, bundled files and native libraries
  • insecure storage and data handling (backups, world-readable files, weak crypto, constant keys/IVs, bundled keystores/databases)
  • misconfigurations (debuggable builds, cleartext traffic, ATS exceptions, exported components, WebView settings,
    TLS validation bypasses, weak signing, missing binary hardening)

Nothing is executed. The app package is never uploaded; when exact dependency identities and versions can be extracted, UBEL sends only their package URLs/versions to OSV.dev through the shared SCA engine.

Every run writes report.mobile.json + report.mobile.html into a timestamped zip under
$HOME/.ubel/history/<asset_id>/<timestamp>.mobile.zip and always-overwritten copies to
.ubel/reports/latest.mobile.json and .ubel/reports/latest.mobile.html.

Options:
  --working-dir <path>   Directory whose .ubel/ folder receives the reports (default: cwd)
  --min-severity <s>     Drop findings below this severity from the report (default: info)
  --fail-on <s>          Exit 2 when findings at/above <s> exist; "none" disables; "5:high" tolerates 5 (default: critical)
  --max-entry-mb <n>     Largest single file inside the package that is inflated and scanned (default: 256)
  --verbose / --quiet    More / less console output
Exit codes: 0 ok · 1 scan failed (unreadable or unsupported package) · 2 --fail-on gate tripped or bad arguments
`;

const VALID_SEVERITIES = new Set(SEVERITIES);

export function parseArgs(argv) {
  const args = { minSeverity: 'info', failOn: 'critical', verbose: false, quiet: false, maxEntryMb: 256, file: null };
  const bad = msg => { console.error(`${msg}\n`); console.log(HELP); process.exit(2); };
  const value = (flag, i) => { const v = argv[i + 1]; if (v === undefined || v.startsWith('--')) bad(`${flag} requires a value`); return v; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { console.log(HELP); process.exit(0); }
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') args.failOn = value(a, i++);
    else if (a === '--max-entry-mb') args.maxEntryMb = Number(value(a, i++));
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a.startsWith('--')) bad(`Unknown argument: ${a}`);
    else if (args.file === null) args.file = a;
    else bad(`Unexpected extra argument: ${a}`);
  }
  if (!args.file) bad('A package to scan is required (.apk, .ipa, .xapk, .apks)');
  if (!VALID_SEVERITIES.has(args.minSeverity)) bad(`--min-severity must be one of: ${SEVERITIES.join(', ')}`);
  if (!Number.isFinite(args.maxEntryMb) || args.maxEntryMb < 1 || args.maxEntryMb > 1024) bad('--max-entry-mb must be a number between 1 and 1024');
  args.failOnParsed = parseFailOn(args.failOn);
  if (!args.failOnParsed) bad(`--fail-on must be "none", one of: ${SEVERITIES.join(', ')}, or "<count>:<severity>" (got "${args.failOn}")`);
  return args;
}

function severityRank(value) {
  const severity = String(value || '').toLowerCase();
  return SEVERITY_RANK[severity === 'moderate' ? 'medium' : severity] ?? 4;
}

function parseFailOn(v) {
  if (v === 'none') return { mode: 'none' };
  if (v.includes(':')) {
    const [c, s] = v.split(':'); const count = Number(c);
    return Number.isInteger(count) && count >= 0 && VALID_SEVERITIES.has(s) ? { mode: 'threshold', count, severity: s } : null;
  }
  return VALID_SEVERITIES.has(v) ? { mode: 'severity', severity: v } : null;
}

function sha256File(file) {
  const h = crypto.createHash('sha256');
  const fd = fs.openSync(file, 'r');
  try {
    const buf = Buffer.allocUnsafe(4 * 1024 * 1024);
    let n;
    while ((n = fs.readSync(fd, buf, 0, buf.length, null)) > 0) h.update(buf.subarray(0, n));
  } finally { fs.closeSync(fd); }
  return h.digest('hex');
}

/**
 * Scans one package and returns { findings, apps, dependencies, notes, target }. Never writes files.
 * @param {string} file
 * @param {{maxEntryMb?:number, log?:(m:string)=>void}} [opts]
 */
export function scanPackage(file, opts = {}) {
  const log = opts.log || (() => {});
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`${file} is not a file`);
  const limits = {};
  const zipOpts = { maxEntryBytes: (opts.maxEntryMb || 256) * 1024 * 1024 };
  const findings = new Findings();
  const notes = [];
  const apps = [];
  const dependencies = [];
  const newScanner = base => new SecretScanner(findings, base);
  let kind;
  const zip = new ZipArchive(file, zipOpts);
  try {
    if (zip.duplicateNames.length) notes.push(`The archive contains ${zip.duplicateNames.length} duplicate entry name(s) (e.g. ${zip.duplicateNames[0]}); only the first of each was analysed. Duplicate names are a known package-tampering trick.`);
    if (zip.has('AndroidManifest.xml')) {
      kind = 'apk'; log('Android package detected');
      const app = analyzeApk(zip, { findings, notes, newScanner, limits });
      apps.push(app);
      dependencies.push(...extractMobileDependencies(zip, { platform: 'android', appSummary: app }));
      delete app._detected_dependencies;
    } else if (findAppDir(zip)) {
      kind = 'ipa'; log('iOS package detected');
      const app = analyzeIpa(zip, { findings, notes, newScanner, limits });
      apps.push(app);
      dependencies.push(...extractMobileDependencies(zip, { platform: 'ios', appSummary: app }));
    } else {
      const nested = zip.find(/\.apk$/i).filter(e => !/\//.test(e.name) || /^(splits|config)\//i.test(e.name) || true).slice(0, 20);
      if (!nested.length) throw new Error('not an Android (.apk) or iOS (.ipa) package: no AndroidManifest.xml, no Payload/*.app and no nested .apk found');
      kind = 'apk-bundle';
      for (const e of nested) {
        log(`Nested APK: ${e.name}`);
        try {
          const inner = new ZipArchive(zip.read(e, 1024 * 1024 * 1024), zipOpts);
          if (!inner.has('AndroidManifest.xml')) { notes.push(`${e.name}: no AndroidManifest.xml (resource-only split).`); continue; }
          const app = analyzeApk(inner, { findings, notes, newScanner, prefix: `${e.name}!`, limits });
          apps.push(app);
          dependencies.push(...extractMobileDependencies(inner, { platform: 'android', prefix: `${e.name}!`, appSummary: app }));
          delete app._detected_dependencies;
        } catch (err) { notes.push(`${e.name}: not analysed (${err.message}).`); }
      }
      if (!apps.length) throw new Error('no analysable APK inside the bundle');
    }
  } finally { zip.close(); }
  return { findings, apps, dependencies, notes, target: { file: path.basename(file), kind, size_bytes: st.size, sha256: sha256File(file) } };
}

/**
 * Every issue of an earlier report as one flat list. Reports written before the vulnerabilities / secrets / misconfigurations
 * split carry a single `findings` array (which already held all three kinds); newer ones carry the three disjoint lists.
 * Returns null when the report has neither.
 */
function previousIssues(report) {
  if (Array.isArray(report?.findings)) return report.findings;
  if (['vulnerabilities', 'secrets', 'misconfigurations'].some(k => Array.isArray(report?.[k]))) return flattenFindings(report);
  return null;
}

export function diffReports(prev, current) {
  const previousList = prev && previousIssues(prev.report);
  if (!previousList) return null;
  const ids = r => (r.apps || []).map(a => a.package || a.bundle_id).sort().join(',');
  if (ids(prev.report) !== ids(current)) return null;

  const keyOf = f => String(f.fingerprint || [f.rule || '', f.artifact || '', f.line || '', f.title || ''].join('|'));
  const normalize = f => ({
    ...f,
    compliance: f.compliance && Array.isArray(f.compliance.frameworks)
      ? f.compliance
      : complianceForMobileFinding(f),
  });
  const previousFindings = previousList.map(normalize);
  const currentFindings = flattenFindings(current).map(normalize);
  const brief = f => ({
    fingerprint: keyOf(f), rule: f.rule, severity: f.severity, title: f.title,
    artifact: f.artifact, line: f.line, app: f.app,
    masvs: f.masvs, cwe: f.cwe,
  });
  const compare = (before, after) => {
    const beforeMap = new Map(before.map(f => [keyOf(f), f]));
    const afterMap = new Map(after.map(f => [keyOf(f), f]));
    return {
      new: after.filter(f => !beforeMap.has(keyOf(f))).map(brief),
      unchanged: after.filter(f => beforeMap.has(keyOf(f))).map(brief),
      removed: before.filter(f => !afterMap.has(keyOf(f))).map(brief),
    };
  };
  // Three disjoint groups, matching the report's Vulnerabilities / Secrets / Misconfigurations tabs: an issue is in exactly one.
  // Classification is by rule id (not a stored field) so reports from before the split diff correctly too.
  const vulnerabilities = compare(previousFindings.filter(isVulnerabilityFinding), currentFindings.filter(isVulnerabilityFinding));
  const secrets = compare(previousFindings.filter(isSecretFinding), currentFindings.filter(isSecretFinding));
  const misconfigs = compare(previousFindings.filter(isMisconfigurationFinding), currentFindings.filter(isMisconfigurationFinding));

  // Build the same per-framework New / Existing / Resolved comparison used by
  // SCA. A framework entry contains the mapped finding and the control IDs.
  const complianceByFramework = list => {
    const frameworks = new Map();
    for (const finding of list) {
      for (const fw of finding.compliance?.frameworks || []) {
        if (!frameworks.has(fw.name)) frameworks.set(fw.name, { name: fw.name, version: fw.version || null, items: new Map() });
        const entry = frameworks.get(fw.name);
        const key = keyOf(finding);
        const controls = [...new Set((fw.controls || []).map(c => c.id).filter(Boolean))].sort();
        const item = {
          kind: isSecretFinding(finding) ? 'secret' : isMisconfigurationFinding(finding) ? 'misconfig' : 'vulnerability',
          id: finding.rule || key, severity: finding.severity, title: finding.title,
          where: (finding.artifact || '') + (finding.line ? ':' + finding.line : ''),
          controls: controls.join(', '),
        };
        if (entry.items.has(key)) {
          const prior = entry.items.get(key);
          item.controls = [...new Set([...(prior.controls ? prior.controls.split(', ') : []), ...controls])].sort().join(', ');
        }
        entry.items.set(key, item);
      }
    }
    return frameworks;
  };
  const beforeCompliance = complianceByFramework(previousFindings);
  const afterCompliance = complianceByFramework(currentFindings);
  const frameworkNames = new Set([...beforeCompliance.keys(), ...afterCompliance.keys()]);
  const complianceFrameworks = [...frameworkNames].sort().map(name => {
    const beforeFw = beforeCompliance.get(name);
    const afterFw = afterCompliance.get(name);
    const before = beforeFw ? beforeFw.items : new Map();
    const after = afterFw ? afterFw.items : new Map();
    return {
      name,
      version: (afterFw && afterFw.version) || (beforeFw && beforeFw.version) || null,
      new: [...after.entries()].filter(([key]) => !before.has(key)).map(([, value]) => value),
      unchanged: [...after.entries()].filter(([key]) => before.has(key)).map(([, value]) => value),
      removed: [...before.entries()].filter(([key]) => !after.has(key)).map(([, value]) => value),
    };
  });

  const counts = {
    new_vulnerabilities: vulnerabilities.new.length, unchanged_vulnerabilities: vulnerabilities.unchanged.length, fixed_vulnerabilities: vulnerabilities.removed.length,
    new_secrets: secrets.new.length, unchanged_secrets: secrets.unchanged.length, removed_secrets: secrets.removed.length,
    new_misconfigs: misconfigs.new.length, unchanged_misconfigs: misconfigs.unchanged.length, fixed_misconfigs: misconfigs.removed.length,
  };
  return {
    enabled: true,
    previous: {
      file: prev.file || null,
      report_id: prev.report.report_id || null,
      generated_at: prev.report.generated_at || null,
    },
    previous_file: prev.file || null,
    previous_report_id: prev.report.report_id || null,
    previous_generated_at: prev.report.generated_at || null,
    vulnerabilities, secrets, misconfigs, counts,
    compliance: { frameworks: complianceFrameworks, includes_secrets: true },
  };
}

/** Writes report.mobile.json / .html: latest copies under .ubel/reports and a timestamped bundle in the history. */
async function writeReports(meta, scan, notes, args) {
  const dependencyScan = await scanMobileDependencies(scan.dependencies || [], { log: args.quiet ? () => {} : m => console.log(m) });
  scan.dependencies = dependencyScan.dependencies;
  scan.dependencySummary = dependencyScan.summary;
  if (dependencyScan.lookup_error) notes.push(`Mobile dependency OSV lookup was incomplete: ${dependencyScan.lookup_error}`);
  if (dependencyScan.summary.lookup_errors) notes.push(`${dependencyScan.summary.lookup_errors} mobile dependency record(s) could not be fully checked against OSV.dev; see the Dependencies tab.`);
  const ts = reportTimestamp(new Date());
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const asset = assetFor(TAG, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, TAG, asset.asset_id);
  const jsonName = reportFileName('report', TAG, 'json'), htmlName = reportFileName('report', TAG, 'html');

  const base = {
    generated_at: new Date().toISOString(), tool_version: TOOL_VERSION, min_severity: args.minSeverity, hidden_by_filter: meta.hidden,
    report_id: generateReportId(TAG, asset.asset_id), asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id,
  };
  let payload = buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, dependencies: scan.dependencies, dependencySummary: scan.dependencySummary, notes, diffs: null });
  payload = buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, dependencies: scan.dependencies, dependencySummary: scan.dependencySummary, notes, diffs: diffReports(loadPreviousReport(zipPath, TAG, jsonName), payload) });

  const json = JSON.stringify(payload, null, 2);
  const html = await buildHtml(payload);
  const latestJson = path.join(latestDir, reportFileName('latest', TAG, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', TAG, 'html'));
  atomicWriteFile(latestJson, json);
  atomicWriteFile(latestHtml, html);
  atomicWriteFile(zipPath, buildZip([{ name: jsonName, data: json }, { name: htmlName, data: html }]));
  updateLatestReportZip(zipPath, TAG);
  console.log(`\n[ubel-mobile] JSON report : ${latestJson}`);
  console.log(`[ubel-mobile] HTML report : ${latestHtml}`);
  console.log(`[ubel-mobile] Bundle      : ${zipPath}`);
  return payload;
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  const file = path.resolve(args.file);
  if (!fs.existsSync(file)) { console.error(`File not found: ${file}`); process.exitCode = 1; return; }
  provisionAssetAt(args.workingDir);
  const log = args.verbose ? m => console.log(m) : () => {};
  let scan;
  try { scan = scanPackage(file, { maxEntryMb: args.maxEntryMb, log }); }
  catch (e) { console.error(`[ubel-mobile] ${e.message}`); process.exitCode = 1; return; }

  const rank = SEVERITY_RANK[args.minSeverity];
  const before = scan.findings.list.length;
  scan.findings.list = scan.findings.list.filter(f => (SEVERITY_RANK[f.severity] ?? 4) <= rank);
  const payload = await writeReports({ hidden: before - scan.findings.list.length }, scan, scan.notes, args);

  if (!args.quiet) {
    const c = payload.summary.counts;
    console.log(`\n=== Mobile security scan: ${payload.apps.map(a => a.package || a.bundle_id).join(', ')} ===`);
    const bc = payload.summary.by_category;
    console.log(`Issues: ${payload.summary.total}  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info})`);
    console.log(`  Vulnerabilities: ${bc.vulnerabilities}  ·  Secrets: ${bc.secrets}  ·  Misconfigurations: ${bc.misconfigurations}`);
    const ds = payload.dependency_summary || {};
    console.log(`Dependencies: ${ds.total || 0} detected, ${ds.queryable || 0} queried, ${ds.vulnerable_dependencies || 0} with known vulnerabilities (${ds.vulnerabilities || 0} advisory matches)`);
    const issues = flattenFindings(payload);
    for (const f of issues.filter(x => x.severity !== 'info').slice(0, 40)) console.log(`  [${f.severity.toUpperCase()}] ${f.title} — ${f.artifact}`);
    for (const n of payload.analysis_notes) console.log(`  note: ${n}`);
  }
  const f = args.failOnParsed;
  if (f.mode === 'none') process.exitCode = 0;
  else {
    const limit = SEVERITY_RANK[f.severity];
    const staticHits = flattenFindings(payload).filter(x => (SEVERITY_RANK[x.severity] ?? 4) <= limit).length;
    const dependencyHits = (payload.dependencies || []).reduce((n, dep) => n + (dep.vulnerabilities || []).filter(v => severityRank(v.severity) <= limit).length, 0);
    const hits = staticHits + dependencyHits;  // vulnerabilities + secrets + misconfigurations + dependency advisories
    process.exitCode = f.mode === 'threshold' ? (hits > f.count ? 2 : 0) : (hits > 0 ? 2 : 0);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
