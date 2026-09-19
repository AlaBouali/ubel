// easm/lib/report_output.js
//
// Everything ubel-url (index.js) and ubel-domain (domain.js) do identically
// once they each have a reportPayload in hand — severity filtering/gating
// and writing the JSON+HTML report pair to disk — lives here once instead
// of being copy-pasted between the two entry points. `reportType`/`cliLabel`
// parameters are what let them share this without colliding on each
// other's report folder, latest-pointer filenames, or console prefix.

import fs from "fs";
import path from "path";
import { generateHtmlReport } from "./html_report.js";
import { buildZip } from "../../sca/zip_writer.js";
import { getGitMetadata } from "../../sca/git_info.js";
import { getOSMetadata } from "../../sca/os_metadata.js";

export const SEVERITY_RANK = { infection: -1, critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
export const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "unknown"]);

export function vulnSeverityKey(v) {
  return v.is_infection ? "infection" : (v.severity || "unknown").toLowerCase();
}

// "<count>:<severity>" is the same baseline-tolerant gate shape as
// ubel-cloud's --fail-on (see cloud/index.js's own parseFailOn) — that copy
// stays separate deliberately, to avoid a cross-module dependency between
// cloud/ and easm/; within easm/ itself, ubel-url and ubel-domain sharing
// this one copy is the same logic either way, so there's no equivalent
// reason to duplicate it a third time here.
export function parseFailOn(value) {
  if (value === "none") return { mode: "none" };
  if (value.includes(":")) {
    const [countStr, severity] = value.split(":");
    const count = Number(countStr);
    if (!Number.isInteger(count) || count < 0 || !VALID_SEVERITIES.has(severity)) return null;
    return { mode: "threshold", count, severity };
  }
  if (!VALID_SEVERITIES.has(value)) return null;
  return { mode: "severity", severity: value };
}

/** Applies --min-severity: component inventory and per-component counts
 *  are left untouched (they always reflect the full scan) — only the
 *  Vulnerabilities list itself is filtered. */
export function filterByMinSeverity(vulnerabilities, minSeverity) {
  const minRank = SEVERITY_RANK[minSeverity];
  return vulnerabilities.filter((v) => (SEVERITY_RANK[vulnSeverityKey(v)] ?? 4) <= minRank);
}

/** @returns {number} process exit code (0 or 2) for a resolved --fail-on gate */
export function failOnExitCode(vulnerabilities, failOn) {
  if (failOn.mode === "none") return 0;
  if (failOn.mode === "threshold") {
    const failRank = SEVERITY_RANK[failOn.severity];
    const matchCount = vulnerabilities.filter((v) => (SEVERITY_RANK[vulnSeverityKey(v)] ?? 4) <= failRank).length;
    return matchCount > failOn.count ? 2 : 0;
  }
  const failRank = SEVERITY_RANK[failOn.severity];
  const shouldFail = vulnerabilities.some((v) => (SEVERITY_RANK[vulnSeverityKey(v)] ?? 4) <= failRank);
  return shouldFail ? 2 : 0;
}

function atomicWrite(filePath, content) {
  const tmp = filePath + ".tmp";
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, filePath);
}

/**
 * Host/runtime provenance for the report, mirroring the SAST module's
 * collectMetadata() (see sast/main.js) so an EASM report carries the same
 * "what machine produced this, from what checkout" trail every other UBEL
 * report does. Both lookups are best-effort and non-fatal: a scan run from
 * outside a git repo, or on a platform os_metadata can't introspect, still
 * produces a complete report — it just omits those blocks.
 *
 * @param {{workingDir?: string}} opts
 */
export async function collectScanMetadata(opts = {}) {
  let gitMetadata = {};
  let osMetadata = {};
  try { gitMetadata = getGitMetadata(); } catch { /* non-fatal */ }
  try { osMetadata = await getOSMetadata(); } catch { /* non-fatal */ }
  return {
    platform: process.platform,
    arch: process.arch,
    runtime_version: process.version.replace(/^v/, ""),
    workingDir: opts.workingDir ? path.resolve(opts.workingDir) : process.cwd(),
    gitMetadata,
    osMetadata,
  };
}

/**
 * Writes the scan's reports, following the same flow the SAST/malware
 * scanners use (see writeAnalyzeReports in sast/main.js):
 *
 *   - the timestamped per-run copies are bundled into ONE .zip under
 *     .ubel/local/reports/<reportType>/<date>/ rather than written out as
 *     loose files, to keep file count and storage down as runs accumulate
 *   - the always-current "latest" copies under .ubel/reports/ stay as
 *     plain, unzipped files, so anything watching them (a CI step, a
 *     dashboard, a browser tab on latest.*.html) needs no unpacking step
 *   - each piece only makes it into the bundle if it generated
 *     successfully; a failed HTML render warns and still leaves a complete
 *     JSON report behind rather than losing the whole run
 *
 * JSON and HTML are the only formats here — no SBOM, no SARIF (see
 * ../README.md for why neither applies to a remote-fingerprint scan).
 *
 * @param {object} reportPayload
 * @param {{workingDir?: string}} opts
 * @param {{reportType: string, cliLabel: string}} labels  e.g.
 *   {reportType: "easm", cliLabel: "[ubel-url]"} or
 *   {reportType: "easm-domain", cliLabel: "[ubel-domain]"}
 */
export async function writeEasmReports(reportPayload, opts, { reportType, cliLabel }) {
  reportType = reportType.replace("-", "_");
  const now      = new Date();
  const pad      = n => String(n).padStart(2, "0");
  const ts       = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}`
                 + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
  const datePath = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;

  const workingDir = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();

  const reportDir = path.join(workingDir, ".ubel", "local", "reports", reportType, datePath);
  fs.mkdirSync(reportDir, { recursive: true });

  const latestDir = path.join(workingDir, ".ubel", "reports");
  fs.mkdirSync(latestDir, { recursive: true });

  const baseName = `${reportType}__${ts}`;
  const zipPath = path.join(reportDir, `${baseName}.zip`);

  const latestJson = path.join(latestDir, `latest.${reportType}.json`);
  const latestHtml = path.join(latestDir, `latest.${reportType}.html`);

  const bundleEntries = [];

  const jsonPayload = JSON.stringify(reportPayload, null, 2);
  atomicWrite(latestJson, jsonPayload);
  bundleEntries.push({ name: "report.json", data: jsonPayload });
  console.log(`\n${cliLabel} JSON report : bundled in ${zipPath}`);

  try {
    const htmlReport = await generateHtmlReport(reportPayload);
    atomicWrite(latestHtml, htmlReport);
    bundleEntries.push({ name: "report.html", data: htmlReport });
    console.log(`${cliLabel} HTML report : bundled in ${zipPath}`);
  } catch (e) {
    console.warn(`${cliLabel} HTML report failed: ${e.message}`);
  }

  atomicWrite(zipPath, buildZip(bundleEntries));

  console.log(`\n${cliLabel} Timestamped bundle : ${zipPath}`);
  console.log(`${cliLabel} Latest reports     : ${latestDir}`);
  console.log(`${cliLabel}   - JSON : ${latestJson}`);
  console.log(`${cliLabel}   - HTML : ${latestHtml}`);
  console.log("");

  return { zipPath, latestJson, latestHtml };
}

export function printScanSummary(reportPayload, headerLabel) {
  const s = reportPayload.stats;
  const res = s.resolution || { total: 0, resolved: 0, dead: 0 };
  console.log(`\n=== ${headerLabel} ===`);
  console.log(`Targets: ${reportPayload.targets.length}  Components: ${s.component_count}  Vulnerabilities: ${s.total_vulnerabilities}`);
  console.log(`  resolved: ${res.resolved}  dead (no DNS): ${res.dead}`);
  const sec = s.secrets || { total: 0 };
  if (sec.total) {
    console.log(`  exposed secrets in client-side JS: ${sec.total} across ${sec.affected_urls || 0} URL(s)`);
  }
  console.log(
    `  infections: ${s.infections}  critical: ${s.severity.critical}  high: ${s.severity.high}  ` +
    `medium: ${s.severity.medium}  low: ${s.severity.low}  unknown: ${s.severity.unknown}`
  );
  console.log("");
  for (const v of reportPayload.vulnerabilities) {
    const item = reportPayload.inventory.find(i => i.id === v.affected_package_id);
    const label = item ? `${item.name}@${item.version || "unknown"}` : v.affected_package_id;
    console.log(`[${v.is_infection ? "INFECTION" : v.severity.toUpperCase()}] ${v.id}  (${label})`);
    for (const fix of (v.fixes || [])) console.log(`  fix: ${fix}`);
  }
  console.log("");
}
