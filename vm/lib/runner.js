'use strict';
// runner.js — the command-line plumbing shared by ubel-vm and ubel-k8s: argument parsing, asset identity, the
// scan loop, report writing (JSON + HTML bundled into a history zip, plus "latest" copies), console summary and
// exit codes. It mirrors cloud/index.js, so the three scanners behave the same way in CI.
//
// Exit codes:  0 = completed, nothing at/above --fail-on   2 = a --fail-on finding exists (or bad usage)
//              3 = the assessment is incomplete (checks that apply could not be evaluated) and no finding
//                  already failed the run — "no findings" is not "passed"; use --allow-partial to accept
//              1 = fatal error

import fs from 'node:fs';
import path from 'node:path';
import { TOOL_VERSION } from '../../sca/info.js';
import { buildZip } from '../../sca/zip_writer.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId, provisionAssetAt } from '../../sca/report_naming.js';
import { loadPreviousReport } from '../../cloud/lib/previous_report.js';
import { Reporter, runRules, SEVERITY_RANK } from './engine.js';
import { generateHtmlReport, buildReportPayload } from './html_report.js';

const VALID_SEVERITIES = new Set(Object.keys(SEVERITY_RANK));

class UsageError extends Error {}

function parseFailOn(value) {
  if (value === 'none') return { mode: 'none' };
  if (value.includes(':')) {
    const [countStr, severity] = value.split(':');
    const count = Number(countStr);
    if (!Number.isInteger(count) || count < 0 || !VALID_SEVERITIES.has(severity)) return null;
    return { mode: 'threshold', count, severity };
  }
  if (!VALID_SEVERITIES.has(value)) return null;
  return { mode: 'severity', severity: value };
}

const COMMON_HELP = `
Common options:
  --working-dir <path>   Directory the .ubel asset folder and reports are written under (default: cwd)
  --min-severity <sev>   Only report findings at or above this severity: critical|high|medium|low|info (default: info)
  --fail-on <sev|none|N:sev>
                         Non-zero exit if a finding at or above <sev> exists (default: critical). "none" always
                         exits 0. "N:sev" fails only once MORE than N findings at or above <sev> exist.
  --only <a,b>           Run only these checks / areas (a check id, an area name, or a prefix ending in *)
  --skip <a,b>           Do not run these checks / areas
  --list-checks          Print the check catalogue (id, area, severity, title) and exit
  --allow-partial        Accept an incomplete assessment. Without it, checks that apply but could not be
                         evaluated make the run exit 3 (when no --fail-on finding already failed it).
  --verbose              Print per-check progress
  --quiet                Suppress the console findings summary (reports are still written)
  --help, -h             Show this help

Every run bundles report.<tag>.json + report.<tag>.html into a timestamped zip under
$HOME/.ubel/history/<asset_id>/<timestamp>.<tag>.zip and writes plain, always-overwritten "latest" copies to
.ubel/reports/latest.<tag>.json and .ubel/reports/latest.<tag>.html.

Asset commands (run instead of a scan):
  <cli> asset-id [folder] [--json]    Print this folder's asset id
  <cli> set-asset-id <id> [folder]    Link this folder to an existing asset id
  <cli> version [--json]              Print the UBEL version
Asset option (any command; the id is 32 hex characters):
  --asset-id <id>                     Use this asset id for this run (nothing is saved to disk)

Exit codes: 0 ok, 2 a --fail-on finding exists (or bad usage), 3 incomplete assessment, 1 fatal error.
`;

/**
 * @param {object} spec
 * @param {string} spec.cli        "ubel-vm"
 * @param {string} spec.tag        report tag / history mode: "vm" | "k8s"
 * @param {object} spec.profile    labels (vm/profile.js)
 * @param {string} spec.help       tool-specific help text (usage + options)
 * @param {Record<string,{key:string,value:boolean,list?:boolean}>} spec.flags  tool-specific flags
 * @param {(args:object, log:Function)=>Promise<{ctx:object, rules:object[], target:object, notes?:()=>string[], options?:object, sameTarget:(prev:object)=>boolean, deps:object, close?:Function}>} spec.prepare
 * @param {string} spec.heading    console summary heading
 */
async function runCli(spec, argv = process.argv.slice(2)) {
  let args;
  try { args = parseArgs(spec, argv); } catch (e) {
    if (e instanceof UsageError) { console.error(e.message + '\n'); console.log(spec.help + COMMON_HELP); process.exitCode = 2; return; }
    throw e;
  }
  if (args.help) { console.log(spec.help + COMMON_HELP); return; }

  if (args.listChecks) {
    const { rules } = await spec.catalogue();
    for (const r of rules) console.log(`${r.id.padEnd(46)} ${String(r.area).padEnd(12)} ${r.severity.padEnd(8)} ${r.title}`);
    return;
  }

  provisionAssetAt(args.workingDir);
  const log = args.verbose ? (m) => console.log(m) : () => {};

  let prepared;
  try { prepared = await spec.prepare(args, log); } catch (e) {
    if (e instanceof UsageError) { console.error(e.message + '\n'); process.exitCode = 2; return; }
    console.error(`[${spec.cli}] ${e.message}`);
    if (process.env.DEBUG) console.error(e.stack);
    process.exitCode = 1;
    return;
  }

  const reporter = new Reporter(prepared.deps);
  try {
    await runRules(prepared.rules, prepared.ctx, reporter, { only: args.only, skip: args.skip, log });
  } finally {
    if (prepared.close) { try { prepared.close(); } catch { /* best effort */ } }
  }

  const minRank = SEVERITY_RANK[args.minSeverity];
  const total = reporter.findings.length;
  reporter.findings = reporter.findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 4) <= minRank);
  const hidden = total - reporter.findings.length;

  if (!args.quiet) reporter.printSummary(spec.heading);

  const notes = [...(prepared.notes ? prepared.notes() : [])];
  if (reporter.suppressed) notes.push(`${reporter.suppressed} further finding(s) were not listed (per-check cap); the first ones of each check are shown.`);
  const options = { ...(prepared.options || {}), ...(args.only.length ? { only: args.only } : {}), ...(args.skip.length ? { skip: args.skip } : {}) };

  await writeReports(spec, reporter, {
    profile: spec.profile, target: prepared.target, notes, options, min_severity: args.minSeverity, hidden_by_filter: hidden,
    generated_at: new Date().toISOString(), tool_version: TOOL_VERSION,
  }, args, prepared.sameTarget);

  // exit code
  const fo = args.failOn;
  let exitCode;
  if (fo.mode === 'none') exitCode = 0;
  else if (fo.mode === 'threshold') {
    const r = SEVERITY_RANK[fo.severity];
    exitCode = reporter.findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 4) <= r).length > fo.count ? 2 : 0;
  } else {
    const r = SEVERITY_RANK[fo.severity];
    exitCode = reporter.findings.some((f) => (SEVERITY_RANK[f.severity] ?? 4) <= r) ? 2 : 0;
  }

  const un = reporter.checks.filter((c) => c.status === 'unassessed');
  if (un.length) {
    const list = un.slice(0, 5).map((c) => `${c.check} (${c.reason})`).join('; ') + (un.length > 5 ? `; … ${un.length - 5} more` : '');
    if (fo.mode === 'none') console.log(`\n[${spec.cli}] Warning: the assessment is incomplete — ${un.length} check(s) could not be evaluated: ${list}.`);
    else if (args.allowPartial) console.log(`\n[${spec.cli}] Warning: the assessment is incomplete — ${un.length} check(s) could not be evaluated: ${list}. Accepted via --allow-partial.`);
    else {
      console.log(`\n[${spec.cli}] The assessment is incomplete — ${un.length} check(s) that apply could not be evaluated: ${list}. ` +
        'Absence of findings there is not evidence of a clean result. Fix the cause (for example run with the needed access), narrow the run with --only/--skip, or pass --allow-partial.');
      if (exitCode === 0) exitCode = 3;
    }
  }
  process.exitCode = exitCode;
}

function parseArgs(spec, argv) {
  const args = { workingDir: undefined, minSeverity: 'info', failOn: parseFailOn('critical'), only: [], skip: [], allowPartial: false, verbose: false, quiet: false, help: false, listChecks: false };
  for (const f of Object.values(spec.flags)) if (f.default !== undefined) args[f.key] = f.default;
  const value = (flag, i) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) throw new UsageError(`${flag} requires a value`);
    return v;
  };
  const list = (s) => s.split(',').map((x) => x.trim()).filter(Boolean);
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') args.help = true;
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') { const raw = value(a, i++); args.failOn = parseFailOn(raw); if (!args.failOn) throw new UsageError(`--fail-on must be "none", one of: ${[...VALID_SEVERITIES].join(', ')}, or "<count>:<severity>" (got "${raw}")`); }
    else if (a === '--only') args.only.push(...list(value(a, i++)).map((s) => s.toLowerCase()));
    else if (a === '--skip') args.skip.push(...list(value(a, i++)).map((s) => s.toLowerCase()));
    else if (a === '--allow-partial') args.allowPartial = true;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--list-checks') args.listChecks = true;
    else if (spec.flags[a]) {
      const f = spec.flags[a];
      if (f.value) { const v = value(a, i++); if (f.list) args[f.key] = [...(args[f.key] || []), ...list(v)]; else args[f.key] = f.number ? Number(v) : v; if (f.number && !Number.isFinite(args[f.key])) throw new UsageError(`${a} must be a number`); }
      else args[f.key] = true;
    } else throw new UsageError(`Unknown argument: ${a}`);
  }
  if (!VALID_SEVERITIES.has(args.minSeverity)) throw new UsageError(`--min-severity must be one of: ${[...VALID_SEVERITIES].join(', ')} (got "${args.minSeverity}")`);
  return args;
}

async function writeReports(spec, reporter, meta, args, sameTarget) {
  const tag = spec.tag;
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const ts = reportTimestamp(new Date());
  const asset = assetFor(tag, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, tag, asset.asset_id);
  const latestJson = path.join(latestDir, reportFileName('latest', tag, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', tag, 'html'));

  // The asset folder can hold reports of several targets (hosts, clusters): only a report of the SAME target is a baseline.
  const prev = loadPreviousReport(zipPath, tag, reportFileName('report', tag, 'json'), (r) => (sameTarget ? sameTarget(r) : true));

  const payload = buildReportPayload(reporter, {
    ...meta,
    report_id: generateReportId(tag, asset.asset_id),
    asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id,
    previous_report: prev,
  });

  const entries = [];
  const json = JSON.stringify(payload, null, 2);
  atomicWriteFile(latestJson, json);
  entries.push({ name: reportFileName('report', tag, 'json'), data: json });
  console.log(`\n[${spec.cli}] JSON  report : ${latestJson}`);
  try {
    const html = await generateHtmlReport(payload);
    atomicWriteFile(latestHtml, html);
    entries.push({ name: reportFileName('report', tag, 'html'), data: html });
    console.log(`[${spec.cli}] HTML  report : ${latestHtml}`);
  } catch (e) {
    console.warn(`[${spec.cli}] HTML report failed: ${e.message}`);
  }
  atomicWriteFile(zipPath, buildZip(entries));
  updateLatestReportZip(zipPath, tag);
  console.log(`\n[${spec.cli}] Timestamped bundle : ${zipPath}`);
  console.log(`[${spec.cli}] Latest reports      : ${latestDir}`);
  return { zipPath, payload };
}

export { runCli, UsageError, TOOL_VERSION, COMMON_HELP };
