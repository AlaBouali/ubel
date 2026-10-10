// ─────────────────────────────────────────────────────────────────────────────
// Shared report-file naming for every UBEL scanner (SCA, firewall, licenses,
// secrets, SAST/malware, EASM url/domain/host/easm, cloud).
//
// One rule everywhere: a scan-type tag sits between the file name and its
// real extension —
//
//     <file_name>.<tag>.<extension>
//
// The tag identifies WHAT produced the file, so reports from different
// scanners never collide on disk and can be told apart without opening them:
//
//     sca                 .sca              (health scan of a project/host)
//     sca / os firewall   .sca_<engine>     (check / install — npm, pip, apt, …)
//     licenses            .licenses
//     secrets             .secrets
//     sast                .sast             (malware scanner: .malware)
//     easm / domain / url / host   .easm  .domain  .url  .host
//     cloud               .cloud
//
// Compound extensions keep their own suffix after the tag:
//     latest.sca.json   latest.sca.html   latest.sca.cdx.json   latest.sca.sarif.json
//
// History: every timestamped zip, from every scanner and every project, is
// kept in one place — $HOME/.ubel/history/<mode>/ — where <mode> is
//
//     sca  firewall  os  licenses  secrets  sast  malware  cloud  easm  host  domain  url
//
// ("firewall" = check/install for npm/pnpm/bun/yarn/composer/pip/pipx/uv/conda/
// cargo; "os" = check/install for apt/dnf/yum). The "latest" copies stay
// per-project under <project>/.ubel/reports/.
//
// Where the tag is used:
//   • "latest" copies   .ubel/reports/latest.<tag>.<ext>
//   • timestamped zip   $HOME/.ubel/history/<mode>/<timestamp>.<tag>.zip
//   • entries in a zip  report.<tag>.<ext>  (always "report", never the
//                       timestamp or "latest")
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import os from "os";
import path from "path";

const pad = (n) => String(n).padStart(2, "0");

/**
 * UTC timestamp used as the zip file name: YYYY_MM_DD__HH_MM_SS.
 * @param {Date} [now]
 */
export function reportTimestamp(now = new Date()) {
  return `${now.getUTCFullYear()}_${pad(now.getUTCMonth() + 1)}_${pad(now.getUTCDate())}`
       + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
}

/**
 * Make a tag safe to embed in a file name: hyphens become underscores and
 * anything outside [A-Za-z0-9_] is dropped, so a tag can never introduce a
 * path separator or an extra ".".
 * @param {string} tag
 */
export function sanitizeReportTag(tag) {
  const clean = String(tag ?? "").replace(/-/g, "_").replace(/[^A-Za-z0-9_]/g, "");
  if (!clean) throw new Error("report tag must not be empty");
  return clean;
}

/**
 * <stem>.<tag>.<ext> — `ext` may be compound ("sarif.json", "cdx.json").
 * @param {string} stem  "latest", "report", or a timestamp
 * @param {string} tag   e.g. "sca", "sca_npm", "cloud"
 * @param {string} ext   extension without the leading dot
 */
export function reportFileName(stem, tag, ext) {
  return `${stem}.${sanitizeReportTag(tag)}.${String(ext).replace(/^\./, "")}`;
}

/**
 * Tag for a run of the SCA engine (sca/engine.js).
 *
 *   scan_scope "license"          → licenses
 *   scan_scope "secrets"          → secrets
 *   check / install (firewall)    → sca_<engine>   (npm, pnpm, pip, apt, dnf, …)
 *   anything else (health)        → sca
 *
 * @param {{checkMode: string, engine: string, scanScope?: string}} p
 */
export function scaReportTag({ checkMode, engine, scanScope }) {
  if (scanScope === "license") return "licenses";
  if (scanScope === "secrets") return "secrets";
  if (checkMode === "check" || checkMode === "install") {
    return sanitizeReportTag(`sca_${engine || "unknown"}`);
  }
  return "sca";
}

/**
 * Mode folder under $HOME/.ubel/history for a run of the SCA engine.
 *
 *   scan_scope "license"                    → licenses
 *   scan_scope "secrets"                    → secrets
 *   check / install on apt/dnf/yum (linux)  → os
 *   check / install on every other engine   → firewall
 *   anything else (health)                  → sca
 *
 * @param {{checkMode: string, systemType: string, scanScope?: string}} p
 */
export function scaHistoryMode({ checkMode, systemType, scanScope }) {
  if (scanScope === "license") return "licenses";
  if (scanScope === "secrets") return "secrets";
  if (checkMode === "check" || checkMode === "install") {
    return systemType === "linux" ? "os" : "firewall";
  }
  return "sca";
}

/** $HOME/.ubel/history — one folder for every scanner's zips. */
export function historyRoot() {
  return path.join(os.homedir(), ".ubel", "history");
}

/**
 * Path for a new history zip: $HOME/.ubel/history/<mode>/<timestamp>.<tag>.zip.
 * Creates the folder. The history folder is shared by every project on the
 * machine, so if two runs land in the same second the later one gets
 * "<timestamp>_2.<tag>.zip" rather than overwriting the first.
 *
 * @param {string} mode       history sub-folder, e.g. "sca", "os", "url"
 * @param {string} timestamp  from reportTimestamp()
 * @param {string} tag        file-name tag, e.g. "sca", "sca_apt", "url"
 * @returns {string}
 */
export function historyZipPath(mode, timestamp, tag) {
  const dir = path.join(historyRoot(), sanitizeReportTag(mode));
  fs.mkdirSync(dir, { recursive: true });
  let candidate = path.join(dir, reportFileName(timestamp, tag, "zip"));
  for (let n = 2; fs.existsSync(candidate); n++) {
    candidate = path.join(dir, reportFileName(`${timestamp}_${n}`, tag, "zip"));
  }
  return candidate;
}
