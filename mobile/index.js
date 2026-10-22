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
import { Findings } from './lib/findings.js';
import { SEVERITY_RANK, SEVERITIES } from './lib/rules.js';
import { buildPayload, buildHtml } from './lib/report.js';
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

Nothing is executed and nothing is sent anywhere; the package is only read.

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
 * Scans one package and returns { findings, apps, notes, target }. Never writes files.
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
  const newScanner = base => new SecretScanner(findings, base);
  let kind;
  const zip = new ZipArchive(file, zipOpts);
  try {
    if (zip.duplicateNames.length) notes.push(`The archive contains ${zip.duplicateNames.length} duplicate entry name(s) (e.g. ${zip.duplicateNames[0]}); only the first of each was analysed. Duplicate names are a known package-tampering trick.`);
    if (zip.has('AndroidManifest.xml')) {
      kind = 'apk'; log('Android package detected');
      apps.push(analyzeApk(zip, { findings, notes, newScanner, limits }));
    } else if (findAppDir(zip)) {
      kind = 'ipa'; log('iOS package detected');
      apps.push(analyzeIpa(zip, { findings, notes, newScanner, limits }));
    } else {
      const nested = zip.find(/\.apk$/i).filter(e => !/\//.test(e.name) || /^(splits|config)\//i.test(e.name) || true).slice(0, 20);
      if (!nested.length) throw new Error('not an Android (.apk) or iOS (.ipa) package: no AndroidManifest.xml, no Payload/*.app and no nested .apk found');
      kind = 'apk-bundle';
      for (const e of nested) {
        log(`Nested APK: ${e.name}`);
        try {
          const inner = new ZipArchive(zip.read(e, 1024 * 1024 * 1024), zipOpts);
          if (!inner.has('AndroidManifest.xml')) { notes.push(`${e.name}: no AndroidManifest.xml (resource-only split).`); continue; }
          apps.push(analyzeApk(inner, { findings, notes, newScanner, prefix: `${e.name}!`, limits }));
        } catch (err) { notes.push(`${e.name}: not analysed (${err.message}).`); }
      }
      if (!apps.length) throw new Error('no analysable APK inside the bundle');
    }
  } finally { zip.close(); }
  return { findings, apps, notes, target: { file: path.basename(file), kind, size_bytes: st.size, sha256: sha256File(file) } };
}

function diffReports(prev, current) {
  if (!prev || !Array.isArray(prev.report?.findings)) return null;
  const ids = r => (r.apps || []).map(a => a.package || a.bundle_id).sort().join(',');
  if (ids(prev.report) !== ids(current)) return null;
  const before = new Map(prev.report.findings.map(f => [f.fingerprint, f]));
  const after = new Map(current.findings.map(f => [f.fingerprint, f]));
  const brief = f => ({ rule: f.rule, severity: f.severity, title: f.title, artifact: f.artifact });
  return {
    previous_file: prev.file, previous_report_id: prev.report.report_id || null, previous_generated_at: prev.report.generated_at || null,
    new: current.findings.filter(f => !before.has(f.fingerprint)).map(brief),
    fixed: prev.report.findings.filter(f => !after.has(f.fingerprint)).map(brief),
    unchanged: current.findings.filter(f => before.has(f.fingerprint)).length,
  };
}

/** Writes report.mobile.json / .html: latest copies under .ubel/reports and a timestamped bundle in the history. */
function writeReports(meta, scan, notes, args) {
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
  let payload = buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, notes, diffs: null });
  payload = buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, notes, diffs: diffReports(loadPreviousReport(zipPath, TAG, jsonName), payload) });

  const json = JSON.stringify(payload, null, 2);
  const html = buildHtml(payload);
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
  const payload = writeReports({ hidden: before - scan.findings.list.length }, scan, scan.notes, args);

  if (!args.quiet) {
    const c = payload.summary.counts;
    console.log(`\n=== Mobile security scan: ${payload.apps.map(a => a.package || a.bundle_id).join(', ')} ===`);
    console.log(`Findings: ${payload.summary.total}  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info})`);
    for (const f of payload.findings.filter(x => x.severity !== 'info').slice(0, 40)) console.log(`  [${f.severity.toUpperCase()}] ${f.title} — ${f.artifact}`);
    for (const n of payload.analysis_notes) console.log(`  note: ${n}`);
  }
  const f = args.failOnParsed;
  if (f.mode === 'none') process.exitCode = 0;
  else {
    const limit = SEVERITY_RANK[f.severity];
    const hits = payload.findings.filter(x => (SEVERITY_RANK[x.severity] ?? 4) <= limit).length;
    process.exitCode = f.mode === 'threshold' ? (hits > f.count ? 2 : 0) : (hits > 0 ? 2 : 0);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
