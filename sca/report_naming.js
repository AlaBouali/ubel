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
// Project identity: every .ubel/ folder a scan writes into holds a
// ubel_project.json ({ "project_id": "<uuid>", "project_name": "<readable>",
// "created_at": "<iso>" }), created on first use; the id never changes. Zips are
// filed under the project's id — history/<mode>/<project_id>/ — so projects
// sharing one history folder stay apart, and the id and name are written into
// each report's own metadata so a zip that is moved or renamed still says where
// it came from. Every scanner gets one — SCA, SAST/malware, secrets, licenses,
// docker, cloud, EASM. The one exception is the OS firewall (apt/dnf/yum): it
// has no project, so it uses $HOME/.ubel/ubel_project.json as a tag for the
// machine itself (the same file a host-platform scan of $HOME uses).
//
// Where the tag is used:
//   • "latest" copies   .ubel/reports/latest.<tag>.<ext>
//   • timestamped zip   $HOME/.ubel/history/<mode>/<project_id>/<timestamp>.<tag>.zip
//   • entries in a zip  report.<tag>.<ext>  (always "report", never the
//                       timestamp or "latest")
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import os from "os";
import path from "path";
import { randomUUID } from "crypto";
import { execFileSync } from "child_process";

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

// ── Project identity (ubel_project.json) ─────────────────────────────────────

/** Name of the per-project (or per-machine) identity file inside a .ubel/ folder. */
export const PROJECT_FILE_NAME = "ubel_project.json";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

/** $HOME/.ubel — holds the machine tag (and the OS firewall's reports). */
export function machineUbelDir() {
  return path.join(os.homedir(), ".ubel");
}

/**
 * Readable name for a project, used only when ubel_project.json is first
 * written (or backfilled): the repository name from `origin` when the folder
 * is a git checkout (credentials in the URL are never read — only the last path
 * segment), else the folder's own name. The machine tag is named after the host.
 */
function deriveProjectName(ubelDir) {
  if (path.resolve(ubelDir) === path.resolve(machineUbelDir())) return os.hostname();
  const dir = path.dirname(path.resolve(ubelDir));
  try {
    const url = execFileSync("git", ["-C", dir, "remote", "get-url", "origin"], {
      stdio: ["ignore", "pipe", "ignore"], timeout: 3000, encoding: "utf-8",
    }).trim();
    const repo = url.replace(/[\\/]+$/, "").split(/[\\/:]/).pop().replace(/\.git$/i, "");
    if (repo) return repo.slice(0, 200);
  } catch { /* not a git checkout, no origin, or git missing */ }
  return path.basename(dir) || os.hostname();
}

function readProjectFile(file) {
  try {
    const j = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (!j || typeof j !== "object" || typeof j.project_id !== "string" || !UUID_RE.test(j.project_id)) return null;
    return { ...j, project_id: j.project_id.toLowerCase() };
  } catch {
    return null; // missing, unreadable, or not valid JSON
  }
}

function writeAtomic(file, body) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, body);
  fs.renameSync(tmp, file);
}

/**
 * Return { project_id, project_name } from <ubelDir>/ubel_project.json,
 * creating the folder and the file (fresh UUID + derived name) if they don't
 * exist yet.
 *
 *   • An existing valid id is never changed.
 *   • An existing project_name (including one edited by hand) is never changed;
 *     a file that has an id but no name gets one added.
 *   • A file that holds no valid UUID (corrupt, hand-edited wrongly) is replaced.
 *
 * Safe against two scans starting in the same folder at once: the file is
 * created exclusively, and the loser of the race reads the winner's id.
 *
 * Never throws — a scan must not fail because this file can't be written
 * (read-only folder, …). On failure it warns on stderr and returns null; the
 * history zip then lands directly in history/<mode>/ without a project folder.
 *
 * @param {string} ubelDir  the .ubel folder (not the project root)
 * @returns {{project_id: string, project_name: string}|null}
 */
export function ensureProject(ubelDir) {
  const file = path.join(ubelDir, PROJECT_FILE_NAME);
  const pick = (j) => ({ project_id: j.project_id, project_name: j.project_name });
  try {
    let existing = readProjectFile(file);
    if (existing) {
      if (typeof existing.project_name === "string" && existing.project_name.trim()) return pick(existing);
      existing.project_name = deriveProjectName(ubelDir); // backfill: id untouched
      writeAtomic(file, JSON.stringify(existing, null, 2) + "\n");
      return pick(existing);
    }

    fs.mkdirSync(ubelDir, { recursive: true });
    const fresh = {
      project_id:   randomUUID(),
      project_name: deriveProjectName(ubelDir),
      created_at:   new Date().toISOString(),
    };
    const body = JSON.stringify(fresh, null, 2) + "\n";

    try {
      fs.writeFileSync(file, body, { flag: "wx" });
      return pick(fresh);
    } catch (e) {
      if (e.code !== "EEXIST") throw e;
    }

    // Lost a race, or the file exists but held no valid id.
    const winner = readProjectFile(file);
    if (winner && typeof winner.project_name === "string" && winner.project_name.trim()) return pick(winner);
    if (winner) return ensureProject(ubelDir); // id present, name still missing → backfill path
    writeAtomic(file, body);
    return pick(fresh);
  } catch (e) {
    console.warn(`[ubel] could not write ${file}: ${e.message} — history zip will not be filed under a project id`);
    return null;
  }
}

/**
 * Project identity for a scan that writes history under `mode`.
 *
 *   mode "os" (apt/dnf/yum)   → machine tag, $HOME/.ubel/ubel_project.json
 *   everything else           → <ubelDir>/ubel_project.json
 *
 * @param {string} mode      history mode (see historyZipPath)
 * @param {string} ubelDir   the .ubel folder this scan writes its reports into
 * @returns {{project_id: string, project_name: string}|null}
 */
export function projectFor(mode, ubelDir) {
  return ensureProject(mode === "os" ? machineUbelDir() : ubelDir);
}

/**
 * Path for a new history zip:
 *   $HOME/.ubel/history/<mode>/<project_id>/<timestamp>.<tag>.zip
 * (history/<mode>/<timestamp>.<tag>.zip when no project id is available).
 * Creates the folders. If two runs of the same project land in the same second
 * the later one gets "<timestamp>_2.<tag>.zip" rather than overwriting the first.
 *
 * @param {string} mode        history sub-folder, e.g. "sca", "os", "url"
 * @param {string} timestamp   from reportTimestamp()
 * @param {string} tag         file-name tag, e.g. "sca", "sca_apt", "url"
 * @param {string|null} [projectId]  project_id from projectFor(); omitted/null = no project folder
 * @returns {string}
 */
export function historyZipPath(mode, timestamp, tag, projectId = null) {
  if (projectId != null && !UUID_RE.test(projectId)) {
    throw new Error(`invalid project id: ${projectId}`);
  }
  let dir = path.join(historyRoot(), sanitizeReportTag(mode));
  if (projectId) dir = path.join(dir, projectId);
  fs.mkdirSync(dir, { recursive: true });
  let candidate = path.join(dir, reportFileName(timestamp, tag, "zip"));
  for (let n = 2; fs.existsSync(candidate); n++) {
    candidate = path.join(dir, reportFileName(`${timestamp}_${n}`, tag, "zip"));
  }
  return candidate;
}
