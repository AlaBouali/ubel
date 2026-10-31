#!/usr/bin/env node
'use strict';
// ubel-package — static security analysis of ONE dependency release, straight from its registry: `ubel-package <name> <version> <ecosystem>`.
// Downloads the archive (npm tarball, PyPI sdist + wheels, crate, Go module zip, gem, nupkg, Composer dist, pub archive), checks it against the
// digest the registry published, and reads it without installing, building or running anything: install / build / import-time hooks, source
// behavior, pinned versions of its dependencies, remote hosts, hardcoded secrets, bundled components, native binaries, archive integrity.
// Reuses UBEL's findings, secret scanner, binary analyzer, report and --fail-on gate (the report is report.package.json + report.package.html).

import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fetchPackage } from './lib/registry.js';
import { ECOSYSTEMS, UNSUPPORTED, resolveEcosystem, ecosystemNames } from './lib/ecosystems.js';
import { analyzePackage, resolveAdvisories, DEFAULTS } from './lib/scan.js';
import './lib/rules.js';
import { SEVERITY_RANK, SEVERITIES } from '../mobile/lib/rules.js';
import { buildPayload, buildHtml, flattenFindings } from '../mobile/lib/report.js';
import { parseFailOn, evaluateGate, diffReports, reportIdentity } from '../mobile/index.js';
import { gap } from '../mobile/lib/coverage.js';
import { loadPreviousReport } from '../cloud/lib/previous_report.js';
import { buildZip } from '../sca/zip_writer.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId, provisionAssetAt } from '../sca/report_naming.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;
const TAG = 'package';
const MB = 1024 * 1024;

const HELP = `
ubel-package — static security analysis of a dependency release, downloaded from its registry (no third-party libraries, nothing is installed or run)

Usage:
  ubel-package <name> <version> <ecosystem> [--registry <url>]
  ubel-package <name>@<version> <ecosystem>            (version "latest" or omitted = the registry's latest release)
  ubel-package <name> <version> --ecosystem <ecosystem> --file <archive>     (analyse a local archive instead of downloading)

  Ecosystems: ${[...new Set(Object.values(ECOSYSTEMS).map(e => e.id))].join(', ')}
              (package-manager names work too: pip, pnpm, yarn, bun, uv, poetry, bundler, dotnet, flutter, dart …)

Options:
  --registry <url>           registry / mirror / private index to download from (default: the public registry of the ecosystem).
                             npm: registry base · PyPI: site base (the JSON API, else the Simple API, is used) · crates.io: sparse index ·
                             Go: GOPROXY · RubyGems / Packagist / pub: site base · NuGet: service index (v3/index.json)
  --token <token>            sends "Authorization: Bearer <token>" to the registry (env UBEL_PACKAGE_TOKEN); never sent to any other host
  --header "Name: value"     extra header for the registry, repeatable (same rule: only the registry's own host receives it)
  --file <archive>           analyse this local archive (tar.gz / tgz / zip / .gem / .nupkg / .whl / .crate); name, version and ecosystem are still required
  --artifact sdist|wheel|all PyPI only: which distribution(s) to download (default: all) · --max-wheels <n> wheels of different platforms (default 2)
  --allow-insecure           allow an http:// registry link that the registry itself returns (an http:// --registry is always allowed)
  --offline                  do not look anything up on OSV.dev / NVD (advisory checks are skipped and reported as an analysis gap)
  --max-size-mb <n>          largest archive to download (default 256) · --max-text-kb <n> largest text file read (default ${DEFAULTS.maxTextKb})
  --max-binary-mb <n>        largest native file analysed (default ${DEFAULTS.maxBinaryMb}) · --max-binaries <n> most native files analysed (default ${DEFAULTS.maxBinaries})
  --working-dir <path>       where .ubel/ (reports, asset id) is written (default: the current directory)
  --min-severity critical|high|medium|low|info
  --fail-on critical|high|medium|low|info|none|<count>:<severity>     (default: critical)
  --allow-partial            exit 0 even if part of the package could not be analysed
  --verbose | --quiet

Looks for:
  • install-time, build-time and import-time code: npm lifecycle scripts (and implicit node-gyp), setup.py / build backends / .pth files /
    sitecustomize, build.rs and proc-macros, gem extensions (extconf.rb) and rubygems_plugin.rb, MSBuild targets / install.ps1 / analyzers,
    Composer plugins and autoload files, pub build hooks and plugin build scripts, cgo — and what those commands do (download-and-run,
    package installs, credential reads, persistence, encoded payloads, privilege changes)
  • what the source can do (process, network, file, dynamic code, credentials, persistence, obfuscation) and malware patterns
    (reverse shells, miners, exfiltration, encoded payloads, disabled TLS verification)
  • declared dependencies with their pin class (pinned / minimum / range / unbounded / not from the registry), looked up on OSV.dev (known
    vulnerabilities and known-malicious MAL- advisories) by exact version; bundled copies of other packages
  • remote hosts named in the files (flagging paste sites, callback services, tunnels, bare IPs, clear text) · hardcoded secrets
  • native binaries inside the package (ELF / Mach-O / PE): scanned like ubel-binary
  • integrity: the archive against the registry's digest, the registry's manifest against the tarball's (npm manifest confusion), archive
    tricks (path traversal, links, setuid), disguised binaries, yanked / deprecated releases

Not covered: conda, SwiftPM / Carthage, Maven and OS packages (apt / dnf / yum); bzip2 / xz / zstd archives; dependencies are looked up, not downloaded.

Every run writes report.package.json + report.package.html into a timestamped zip under $HOME/.ubel/history/<asset_id>/<timestamp>.package.zip
and always-overwritten copies to .ubel/reports/latest.package.json and .ubel/reports/latest.package.html.

Exit codes: 0 gate passed and analysis complete · 1 the package could not be fetched or read · 2 --fail-on tripped ·
3 analysis incomplete (part of the package could not be analysed; --allow-partial accepts this) · 2 on bad arguments.
`;

const VALID_SEVERITIES = new Set(SEVERITIES);

export function parseArgs(argv) {
  const args = { minSeverity: 'info', failOn: 'critical', verbose: false, quiet: false, allowPartial: false, offline: false, allowInsecure: false, maxSizeMb: 256, maxTextKb: DEFAULTS.maxTextKb, maxBinaryMb: DEFAULTS.maxBinaryMb, maxBinaries: DEFAULTS.maxBinaries, artifact: 'all', maxWheels: 2, headers: {}, positional: [], ecosystem: null, registry: null, file: null, token: process.env.UBEL_PACKAGE_TOKEN || null };
  const bad = msg => { console.error(`${msg}\n`); console.log(HELP); process.exit(2); };
  const value = (flag, i) => { const v = argv[i + 1]; if (v === undefined || (v.startsWith('--') && v.length > 2)) bad(`${flag} requires a value`); return v; };
  const num = (flag, i, min, max) => { const n = Number(value(flag, i)); if (!Number.isFinite(n) || n < min || n > max) bad(`${flag} must be a number between ${min} and ${max}`); return n; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { console.log(HELP); process.exit(0); }
    else if (a === '--ecosystem' || a === '-e') args.ecosystem = value(a, i++);
    else if (a === '--registry') args.registry = value(a, i++);
    else if (a === '--token') args.token = value(a, i++);
    else if (a === '--header') { const h = value(a, i++); const k = h.indexOf(':'); if (k < 1) bad('--header must look like "Name: value"'); args.headers[h.slice(0, k).trim()] = h.slice(k + 1).trim(); }
    else if (a === '--file') args.file = value(a, i++);
    else if (a === '--artifact') { args.artifact = value(a, i++); if (!['sdist', 'wheel', 'all'].includes(args.artifact)) bad('--artifact must be sdist, wheel or all'); }
    else if (a === '--max-wheels') args.maxWheels = num(a, i++, 0, 12);
    else if (a === '--max-size-mb') args.maxSizeMb = num(a, i++, 1, 2048);
    else if (a === '--max-text-kb') args.maxTextKb = num(a, i++, 16, 65536);
    else if (a === '--max-binary-mb') args.maxBinaryMb = num(a, i++, 1, 1024);
    else if (a === '--max-binaries') args.maxBinaries = num(a, i++, 0, 500);
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') args.failOn = value(a, i++);
    else if (a === '--allow-insecure') args.allowInsecure = true;
    else if (a === '--offline') args.offline = true;
    else if (a === '--allow-partial') args.allowPartial = true;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a.startsWith('--')) bad(`Unknown argument: ${a}`);
    else args.positional.push(a);
  }
  const pos = [...args.positional];
  // ecosystem: a --ecosystem flag, else the last positional when it names one
  let eco = args.ecosystem ? resolveEcosystem(args.ecosystem) : null;
  if (args.ecosystem && !eco) {
    const why = UNSUPPORTED[String(args.ecosystem).toLowerCase()];
    bad(why ? `Ecosystem "${args.ecosystem}" is not supported: ${why}` : `Unknown ecosystem "${args.ecosystem}". Supported: ${ecosystemNames().join(', ')}`);
  }
  if (!eco && pos.length >= 2) {
    const last = pos[pos.length - 1];
    const r = resolveEcosystem(last);
    if (r) { eco = r; pos.pop(); }
    else if (UNSUPPORTED[last.toLowerCase()]) bad(`Ecosystem "${last}" is not supported: ${UNSUPPORTED[last.toLowerCase()]}`);
  }
  if (!eco) bad(`An ecosystem is required (one of: ${[...new Set(Object.values(ECOSYSTEMS).map(e => e.id))].join(', ')}), for example: ubel-package left-pad 1.3.0 npm`);
  args.ecosystem = eco;
  let [name, version] = pos;
  if (!name) bad('A package name is required');
  if (pos.length > 2) bad(`Unexpected extra argument: ${pos[2]}`);
  if (version === undefined) { const at = name.lastIndexOf('@'); if (at > 0) { version = name.slice(at + 1); name = name.slice(0, at); } }
  if (!version) version = 'latest';
  if (args.file && version === 'latest') bad('--file needs the exact version of the archive');
  Object.assign(args, { name, version });
  if (!VALID_SEVERITIES.has(args.minSeverity)) bad(`--min-severity must be one of: ${SEVERITIES.join(', ')}`);
  args.failOnParsed = parseFailOn(args.failOn);
  if (!args.failOnParsed) bad(`--fail-on must be "none", one of: ${SEVERITIES.join(', ')}, or "<count>:<severity>" (got "${args.failOn}")`);
  return args;
}

/** A local archive wrapped like a registry download. */
function localPackage(args) {
  const file = path.resolve(args.file);
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`${file} is not a file`);
  if (st.size > args.maxSizeMb * MB) throw new Error(`file is ${Math.round(st.size / MB)} MB, over the ${args.maxSizeMb} MB limit (--max-size-mb)`);
  const buf = fs.readFileSync(file);
  return {
    ecosystem: args.ecosystem, name: args.name, version: args.version, registry: null, meta: {}, notes: [`Analysed a local archive (${path.basename(file)}); no registry was contacted and the archive was not verified against a published digest.`],
    artifacts: [{ kind: 'local', filename: path.basename(file), url: pathToFileURL(file).href, buf, size: buf.length, sha256: crypto.createHash('sha256').update(buf).digest('hex'), goSum: false, integrity: { state: 'unverified', algo: null, expected: null, actual: null, source: null } }],
  };
}

async function writeReports(meta, scan, notes, args) {
  const ts = reportTimestamp(new Date());
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const asset = assetFor(TAG, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, TAG, asset.asset_id);
  const jsonName = reportFileName('report', TAG, 'json'), htmlName = reportFileName('report', TAG, 'html');
  const base = {
    schema: 'ubel-package/1', tool: 'ubel-package',
    generated_at: new Date().toISOString(), tool_version: TOOL_VERSION, min_severity: args.minSeverity, hidden_by_filter: meta.hidden, gate: meta.gate,
    report_id: generateReportId(TAG, asset.asset_id), asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id,
  };
  const build = diffs => buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, dependencies: scan.dependencies, dependencySummary: scan.dependencySummary, notes, diffs });
  let payload = build(null);
  payload = build(diffReports(loadPreviousReport(zipPath, TAG, jsonName, r => reportIdentity(r) === reportIdentity(payload)), payload));
  const json = JSON.stringify(payload, null, 2);
  const html = await buildHtml(payload);
  const latestJson = path.join(latestDir, reportFileName('latest', TAG, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', TAG, 'html'));
  atomicWriteFile(latestJson, json);
  atomicWriteFile(latestHtml, html);
  atomicWriteFile(zipPath, buildZip([{ name: jsonName, data: json }, { name: htmlName, data: html }]));
  updateLatestReportZip(zipPath, TAG);
  if (!args.quiet) {
    console.log(`\n[ubel-package] JSON report : ${latestJson}`);
    console.log(`[ubel-package] HTML report : ${latestHtml}`);
    console.log(`[ubel-package] Bundle      : ${zipPath}`);
  }
  return payload;
}

/** Downloads (or reads) and analyses a package; returns the scan without writing anything. Exported for tests and for use as a library. */
export async function scanPackage(opts) {
  const log = opts.quiet ? () => {} : m => console.log(m);
  const pkg = opts.file
    ? localPackage(opts)
    : await fetchPackage({
      ecosystem: opts.ecosystem, name: opts.name, version: opts.version, registry: opts.registry || undefined, headers: opts.headers || {},
      authHeaders: { ...(opts.token ? { Authorization: `Bearer ${opts.token}` } : {}), ...(opts.authHeaders || {}) }, allowHttp: Boolean(opts.allowInsecure),
      maxBytes: (opts.maxSizeMb || 256) * MB, artifact: opts.artifact || 'all', maxWheels: opts.maxWheels ?? 2, sumdb: opts.sumdb, log: opts.verbose ? log : undefined,
    });
  if (opts.verbose) log(`[ubel-package] ${pkg.ecosystem} ${pkg.name}@${pkg.version}: ${pkg.artifacts.map(a => `${a.filename} (${a.size} bytes, digest ${a.integrity.state})`).join('; ')}`);
  const scan = await analyzePackage(pkg, { maxTextKb: opts.maxTextKb, maxBinaryMb: opts.maxBinaryMb, maxBinaries: opts.maxBinaries, local: Boolean(opts.file), log: opts.verbose ? log : undefined });
  scan.package = { ecosystem: pkg.ecosystem, name: pkg.name, version: pkg.version };
  return scan;
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  provisionAssetAt(args.workingDir);
  let scan;
  try { scan = await scanPackage(args); }
  catch (e) { console.error(`[ubel-package] ${e.message}`); process.exitCode = 1; return; }

  const rank = SEVERITY_RANK[args.minSeverity];
  const analysed = scan.findings.list.slice();
  let advisoryFindings = [];
  if (args.offline) {
    gap(scan.notes, 'Advisory lookups were skipped (--offline): known vulnerabilities and known-malicious packages were not checked.');
    scan.dependencies = scan.dependencies.map(d => ({ ...d, lookup_status: 'not_queryable', lookup_reason: 'Skipped (--offline).', vulnerabilities: [], vulnerability_count: 0 }));
  } else {
    try { advisoryFindings = await resolveAdvisories(scan, { log: args.quiet ? () => {} : m => console.log(m) }); }
    catch (e) { gap(scan.notes, `Advisory lookup failed: ${e.message}`); }
  }
  // the gate counts dependency advisories from scan.dependencies itself, so it is given only the findings of the analysis (not the advisory findings) to avoid counting each twice
  const everything = analysed;
  scan.findings.list = analysed.concat(advisoryFindings).filter(f => (SEVERITY_RANK[f.severity] ?? 4) <= rank);
  const hidden = analysed.length + advisoryFindings.length - scan.findings.list.length;
  const gate = evaluateGate({ failOn: args.failOnParsed, findings: everything, dependencies: scan.dependencies, gaps: scan.notes.gaps || [], allowPartial: args.allowPartial });
  const payload = await writeReports({ hidden: Math.max(0, hidden), gate }, scan, scan.notes, args);

  if (!args.quiet) {
    const c = payload.summary.counts, bc = payload.summary.by_category;
    console.log(`\n=== Package security scan: ${scan.target.file} (${ECOSYSTEMS[args.ecosystem].label}) ===`);
    console.log(`Issues: ${payload.summary.total}  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info})`);
    console.log(`  Vulnerabilities: ${bc.vulnerabilities}  ·  Secrets: ${bc.secrets}  ·  Misconfigurations: ${bc.misconfigurations}`);
    const ds = payload.dependency_summary || {};
    const pk = scan.apps[0].package;
    console.log(`Hooks reaching consumers: ${pk.hooks.filter(h => h.consumer !== false).length} · Dependencies declared: ${pk.dependency_total} (${Object.entries(pk.pin_summary).map(([k, v]) => `${v} ${k}`).join(', ') || 'none'}) · Components checked: ${ds.queryable || 0}, with advisories: ${ds.vulnerable_dependencies || 0}`);
    for (const f of flattenFindings(payload).filter(x => x.severity !== 'info').slice(0, 40)) console.log(`  [${f.severity.toUpperCase()}] ${f.title} -- ${f.artifact}`);
    for (const n of payload.analysis_notes) console.log(`  note: ${n}`);
  }
  if (gate.exit_code === 2) console.error(`[ubel-package] gate FAILED: ${gate.hits} issue(s) at or above ${args.failOnParsed.severity}${gate.tolerated ? ` (${gate.tolerated} tolerated)` : ''} (--fail-on ${gate.fail_on}).`);
  else if (gate.exit_code === 3) console.error(`[ubel-package] gate INCOMPLETE: nothing tripped --fail-on ${gate.fail_on}, but ${gate.gaps} part(s) could not be analysed, so a clean result is not proof of a clean package (exit 3; --allow-partial accepts this).`);
  process.exitCode = gate.exit_code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
