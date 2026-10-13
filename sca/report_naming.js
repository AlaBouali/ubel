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
//     sca                 .sca              (health scan of an asset: folder/host)
//     docker health       .sca_docker       (ubel-docker health)
//     firewall / os fw    .firewall_<engine> (check / install — npm, pip, apt, …;
//                                             docker check / install → .firewall_docker)
//     licenses            .licenses
//     secrets             .secrets
//     sast                .sast             (malware scanner: .malware)
//     easm / domain / url / host   .easm  .domain  .url  .host
//     cloud               .cloud
//
// Compound extensions keep their own suffix after the tag:
//     latest.sca.json   latest.sca.html   latest.sca.cdx.json   latest.sca.sarif.json
//
// History: every timestamped zip, from every scanner and every asset, is
// kept in one place — $HOME/.ubel/history/<mode>/ — where <mode> is
//
//     sca  firewall  os  licenses  secrets  sast  malware  cloud  easm  host  domain  url
//
// ("firewall" = check/install for npm/pnpm/bun/yarn/composer/pip/pipx/uv/conda/
// cargo; "os" = check/install for apt/dnf/yum). The "latest" copies stay
// per-asset under <asset folder>/.ubel/reports/.
//
// The newest zip of each tag is also kept, apart from the history, in
// $HOME/.ubel/latest_reports/<mode>/<asset_id>/latest.<tag>.zip — the same
// <mode>/<asset_id> layout as history, in a folder of its own. It is
// refreshed after every scan, so it always holds the most recent scan of that
// tag for the asset, and history/ holds nothing but timestamped zips.
//
// Every report file — latest.<tag>.*, the history zip, the latest_reports copy —
// is written with atomicWriteFile() below: temp file in the same folder, then an
// atomic rename, so a reader never sees a half-written report.
//
// Asset identity: every .ubel/ folder a scan writes into holds a
// ubel_asset.json ({ "asset_id": "<32 hex>", "asset_name": "<readable>",
// "created_at": "<iso>" }), created when a CLI starts (every ubel-* CLI creates it if it
// doesn't exist; `ubel-* init` does so explicitly and prints it) — see provisionAsset(); the id never changes. An id is
// a random UUID v4 without hyphens (32 hex characters). Zips are filed under the asset's
// id — history/<mode>/<asset_id>/ — so assets sharing one history folder stay
// apart, and the id, name and type are written into each report's own metadata
// (and into the SBOM / SARIF output) so a zip that is moved or renamed still says
// where it came from. Every scanner gets one — SCA, SAST/malware, secrets,
// licenses, docker, cloud, EASM. The one exception is the OS firewall
// (apt/dnf/yum): it has no folder, so it uses $HOME/.ubel/ubel_asset.json as a tag
// for the machine itself (the same file a host-platform scan of $HOME uses).
//
// Run-time override: every CLI accepts `--asset-id <id>`. For that run it replaces
// the id from ubel_asset.json (nothing on disk is created or changed), so the
// report, SBOM, SARIF and the history zip all carry the id you passed.
//
// Asset type: the history mode the scan files under (see above) — sca, firewall,
// os, licenses, secrets, sast, malware, cloud, easm, host, domain, url.
//
// Where the tag is used:
//   • "latest" copies   .ubel/reports/latest.<tag>.<ext>
//   • timestamped zip   $HOME/.ubel/history/<mode>/<asset_id>/<timestamp>.<tag>.zip
//   • latest zip        $HOME/.ubel/latest_reports/<mode>/<asset_id>/latest.<tag>.zip
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
 * @param {string} tag   e.g. "sca", "firewall_npm", "cloud"
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
 *   scan_scope "container-image"  → firewall_docker (docker check / install)
 *                                   sca_docker      (docker health)
 *   check / install (firewall)    → firewall_<engine>   (npm, pnpm, pip, apt, dnf, …)
 *   anything else (health)        → sca
 *
 * A docker scan always runs the health pipeline (checkMode "health"); the CLI
 * mode it was invoked with arrives as `dockerMode`.
 *
 * @param {{checkMode: string, engine: string, scanScope?: string, dockerMode?: string}} p
 */
export function scaReportTag({ checkMode, engine, scanScope, dockerMode }) {
  if (scanScope === "license") return "licenses";
  if (scanScope === "secrets") return "secrets";
  if (scanScope === "container-image") {
    return dockerMode === "check" || dockerMode === "install" ? "firewall_docker" : "sca_docker";
  }
  if (checkMode === "check" || checkMode === "install") {
    return sanitizeReportTag(`firewall_${engine || "unknown"}`);
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

// ── Asset identity (ubel_asset.json) ─────────────────────────────────────

/** Name of the per-asset (or per-machine) identity file inside a .ubel/ folder. */
export const ASSET_FILE_NAME = "ubel_asset.json";

const UUID_PART = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}";

const HEX32 = "[0-9a-f]{32}";

/**
 * An asset id is a UUID v4 without hyphens (32 hex characters). The hyphenated forms
 * written by older versions (<uuid> and <uuid>-<uuid>) are still accepted, so existing
 * ubel_asset.json files keep their id.
 */
const ASSET_ID_PART = `${HEX32}|${UUID_PART}(?:-${UUID_PART})?`;
const ASSET_ID_RE = new RegExp(`^(?:${ASSET_ID_PART})$`, "i");

/** Example id shown in help and error messages. */
export const ASSET_ID_EXAMPLE = "3f6c2a9e1b7d4c589a426e0d8b5f7a13";

/** A fresh asset id: a UUID v4 without hyphens (Python: uuid.uuid4().hex). */
export function generateAssetId() {
  return randomUUID().replace(/-/g, "");
}

/** $HOME/.ubel — holds the machine tag (and the OS firewall's reports). */
export function machineUbelDir() {
  return path.join(os.homedir(), ".ubel");
}

/**
 * Readable name for an asset, used only when ubel_asset.json is first
 * written (or backfilled): the repository name from `origin` when the folder
 * is a git checkout (credentials in the URL are never read — only the last path
 * segment), else the folder's own name. The machine tag is named after the host.
 */
function deriveAssetName(ubelDir) {
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

function readAssetFile(file) {
  try {
    const j = JSON.parse(fs.readFileSync(file, "utf-8"));
    if (!j || typeof j !== "object" || typeof j.asset_id !== "string" || !ASSET_ID_RE.test(j.asset_id)) return null;
    return { ...j, asset_id: j.asset_id.toLowerCase() };
  } catch {
    return null; // missing, unreadable, or not valid JSON
  }
}

/**
 * Write `content` to `filePath` so that a reader (another process, a CI step, a
 * dashboard watching latest.<tag>.html) only ever sees the complete old file or
 * the complete new one — never a half-written file:
 *
 *   1. write everything to a temp file in the SAME folder (same filesystem, so
 *      the rename below is atomic),
 *   2. rename it over `filePath` in one step.
 *
 * The temp name carries the pid and a random suffix, so two scans writing the
 * same target at once never share (and corrupt) one temp file — the last rename
 * wins, and each outcome is still a complete file. If the write or the rename
 * fails, the temp file is removed, `filePath` is left exactly as it was, and
 * the error is rethrown (a report that could not be saved must not look saved).
 *
 * Used for every report UBEL writes: latest.<tag>.* files, history zips, and
 * the latest_reports/ copy.
 *
 * @param {string} filePath
 * @param {string|Buffer|Uint8Array} content
 */
export function atomicWriteFile(filePath, content) {
  const tmp = `${filePath}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
  try {
    fs.writeFileSync(tmp, content);
    fs.renameSync(tmp, filePath);
  } catch (e) {
    try { fs.unlinkSync(tmp); } catch { /* temp file never created, or already gone */ }
    throw e;
  }
}

const writeAtomic = atomicWriteFile;

/**
 * Return { asset_id, asset_name } from <ubelDir>/ubel_asset.json,
 * creating the folder and the file (fresh UUID + derived name) if they don't
 * exist yet.
 *
 *   • An existing valid id is never changed.
 *   • An existing asset_name (including one edited by hand) is never changed;
 *     a file that has an id but no name gets one added.
 *   • A file that holds no valid UUID (corrupt, hand-edited wrongly) is replaced.
 *
 * Safe against two scans starting in the same folder at once: the file is
 * created exclusively, and the loser of the race reads the winner's id.
 *
 * Never throws — a scan must not fail because this file can't be written
 * (read-only folder, …). On failure it warns on stderr and returns null; the
 * history zip then lands directly in history/<mode>/ without an asset folder.
 *
 * @param {string} ubelDir  the .ubel folder (not the folder root)
 * @returns {{asset_id: string, asset_name: string}|null}
 */
export function ensureAsset(ubelDir) {
  const file = path.join(ubelDir, ASSET_FILE_NAME);
  const pick = (j) => ({ asset_id: j.asset_id, asset_name: j.asset_name });
  try {
    let existing = readAssetFile(file);
    if (existing) {
      if (typeof existing.asset_name === "string" && existing.asset_name.trim()) return pick(existing);
      existing.asset_name = deriveAssetName(ubelDir); // backfill: id untouched
      writeAtomic(file, JSON.stringify(existing, null, 2) + "\n");
      return pick(existing);
    }

    fs.mkdirSync(ubelDir, { recursive: true });
    const fresh = {
      asset_id:   generateAssetId(),
      asset_name: deriveAssetName(ubelDir),
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
    const winner = readAssetFile(file);
    if (winner && typeof winner.asset_name === "string" && winner.asset_name.trim()) return pick(winner);
    if (winner) return ensureAsset(ubelDir); // id present, name still missing → backfill path
    writeAtomic(file, body);
    return pick(fresh);
  } catch (e) {
    console.warn(`[ubel] could not write ${file}: ${e.message} — history zip will not be filed under an asset id`);
    return null;
  }
}

/** True when `id` is a well-formed asset id (32 hex; legacy hyphenated forms also accepted). */
export function isValidAssetId(id) {
  return typeof id === "string" && ASSET_ID_RE.test(id.trim());
}

/**
 * Make sure <ubelDir>/ubel_asset.json exists — the "create one if not exists" step every
 * ubel-* CLI runs at startup, and what `init` runs and reports. ensureAsset() does the
 * work (existing id never changed); this adds whether the file was just created and
 * honours --asset-id.
 *
 *   • --asset-id given (setRuntimeAssetId) → nothing is created or changed on disk;
 *     returns { asset_id: <that id>, runtime: true, created: false }.
 *   • otherwise → { asset_id, asset_name, created, runtime: false }, `created` true only
 *     when this call minted the id.
 *   • null when the file could not be written (read-only folder, …) — ensureAsset()
 *     already warned; the caller carries on, like a scan always has.
 *
 * @param {string} ubelDir  the .ubel folder (not the folder root)
 * @returns {{asset_id: string, asset_name: string|null, created: boolean, runtime: boolean}|null}
 */
export function provisionAsset(ubelDir) {
  if (runtimeAssetId) {
    return { asset_id: runtimeAssetId, asset_name: null, created: false, runtime: true };
  }
  const existed = readAssetFile(path.join(ubelDir, ASSET_FILE_NAME)) !== null;
  const asset = ensureAsset(ubelDir);
  return asset ? { ...asset, created: !existed, runtime: false } : null;
}

/**
 * One-line, stderr-only notice for a freshly created asset id, so a CLI whose stdout
 * is machine-read (JSON) is never polluted. Silent when the id already existed, was
 * given with --asset-id, or could not be written.
 *
 * @param {ReturnType<typeof provisionAsset>} asset
 * @param {string} ubelDir
 */
export function announceNewAsset(asset, ubelDir) {
  if (!asset || !asset.created) return;
  console.error(`[+] New asset id created: ${asset.asset_id}  (${asset.asset_name})  → ${path.join(ubelDir, ASSET_FILE_NAME)}`);
}

/**
 * provisionAsset() + announceNewAsset() for a scan folder: creates
 * <workingDir>/.ubel/ubel_asset.json if it doesn't exist (the cwd when `workingDir` is
 * omitted). The one call the non-SCA CLIs (ubel-sast / -mal / -chunk, ubel-cloud, the EASM
 * binaries) make at startup, with the same working directory they later report into.
 *
 * @param {string} [workingDir]
 * @returns {ReturnType<typeof provisionAsset>}
 */
export function provisionAssetAt(workingDir) {
  const ubelDir = path.join(path.resolve(workingDir || process.cwd()), ".ubel");
  const asset   = provisionAsset(ubelDir);
  announceNewAsset(asset, ubelDir);
  return asset;
}

/**
 * Read-only lookup of <ubelDir>/ubel_asset.json. Unlike ensureAsset() this
 * never creates or repairs anything — it is what `set-asset-id` and the history
 * lookups use, where minting an id as a side effect would be wrong.
 *
 * @param {string} ubelDir  the .ubel folder (not the folder root)
 * @returns {{asset_id: string, asset_name?: string, created_at?: string}|null}
 *          null when the file is missing, unreadable, or holds no valid UUID
 */
export function readAsset(ubelDir) {
  return readAssetFile(path.join(ubelDir, ASSET_FILE_NAME));
}

/**
 * History modes under $HOME/.ubel/history that already hold zips for an asset
 * id (i.e. the id was used by earlier scans on this machine). Used to tell the
 * user whether an id they are linking a folder to is one UBEL has seen here.
 *
 * @param {string} assetId
 * @returns {{mode: string, zips: number}[]}
 */
export function historyForAsset(assetId) {
  const id = String(assetId).toLowerCase();
  const out = [];
  let modes = [];
  try { modes = fs.readdirSync(historyRoot(), { withFileTypes: true }); } catch { return out; }
  for (const m of modes) {
    if (!m.isDirectory()) continue;
    try {
      const zips = fs.readdirSync(path.join(historyRoot(), m.name, id)).filter((f) => f.endsWith(".zip")).length;
      if (zips > 0) out.push({ mode: m.name, zips });
    } catch { /* no folder for this id under this mode */ }
  }
  return out;
}

/**
 * Point <ubelDir>/ubel_asset.json at an existing asset id — the way to
 * reconnect a folder to an asset it was previously scanned as (a fresh clone,
 * a deleted .ubel/, a second checkout of the same repo), so new scans file
 * their history zips next to the old ones instead of starting a new asset.
 *
 *   • Only the id is replaced. created_at, asset_name and any other field
 *     already in the file are kept; `name`, when given, replaces asset_name.
 *   • A missing, corrupt, or id-less file is (re)created with the id, `name`
 *     (else a derived name) and a fresh created_at.
 *   • Unlike ensureAsset() this THROWS on failure: the user asked for the
 *     change explicitly, so a silent no-op would be wrong.
 *
 * @param {string} ubelDir
 * @param {string} assetId  32 hex (case-insensitive; stored lowercase)
 * @param {{name?: string}} [opts]
 * @returns {{asset_id: string, asset_name: string, previous_id: string|null, changed: boolean}}
 */
export function setAssetId(ubelDir, assetId, opts = {}) {
  if (!isValidAssetId(assetId)) {
    throw new Error(`not a valid asset id (expected 32 hex characters, like ${ASSET_ID_EXAMPLE}): ${assetId}`);
  }
  const id = assetId.trim().toLowerCase();
  const file = path.join(ubelDir, ASSET_FILE_NAME);
  const existing = readAssetFile(file);
  const name = typeof opts.name === "string" && opts.name.trim()
    ? opts.name.trim().slice(0, 200)
    : (typeof existing?.asset_name === "string" && existing.asset_name.trim()
        ? existing.asset_name
        : deriveAssetName(ubelDir));

  const next = {
    ...(existing || {}),
    asset_id:   id,
    asset_name: name,
    created_at:   existing?.created_at || new Date().toISOString(),
  };
  fs.mkdirSync(ubelDir, { recursive: true });
  writeAtomic(file, JSON.stringify(next, null, 2) + "\n");
  return {
    asset_id:  id,
    asset_name: name,
    previous_id: existing ? existing.asset_id : null,
    changed:     !existing || existing.asset_id !== id,
  };
}

// ── Run-time asset id (--asset-id) ───────────────────────────────────────────

let runtimeAssetId = null;

/**
 * Use `id` as the asset id for every scan in this process, instead of the one in
 * ubel_asset.json. Set by the `--asset-id <id>` flag (see asset_cli.js). Nothing
 * on disk is created or changed. Pass null to clear it.
 *
 * @param {string|null} id  32 hex; THROWS when it is not a valid asset id
 */
export function setRuntimeAssetId(id) {
  if (id == null) { runtimeAssetId = null; return; }
  if (!isValidAssetId(id)) {
    throw new Error(`not a valid asset id (expected 32 hex characters, like ${ASSET_ID_EXAMPLE}): ${id}`);
  }
  runtimeAssetId = id.trim().toLowerCase();
}

/** The id set by --asset-id for this run, or null. */
export function getRuntimeAssetId() {
  return runtimeAssetId;
}

// ── Report id ───────────────────────────────────────────────────────────────
// Every report (JSON, HTML, SBOM, SARIF — they share it) carries one id:
//
//   UBEL-<tag>-<asset_id>-<report_uuid>
//
//   <tag>          the report's file tag (sca, firewall_npm, licenses, secrets, sast,
//                  malware, cloud, url, domain, host, easm) — see reportFileName()
//   <asset_id>     the scan's asset id, embedded whole (32 hex, no hyphens); 32 zeros
//                  when the scan has no asset id
//   <report_uuid>  a fresh random UUID v4 without hyphens (32 hex), unique to this report
//
// Generated once per scan, where the asset is resolved, and then carried through.

export const REPORT_ID_PREFIX = "UBEL";
export const NIL_ASSET_ID = "0".repeat(32);

/**
 * A fresh report id: UBEL-<tag>-<asset_id>-<report_uuid>, the asset id embedded whole.
 * @param {string} tag      the report's file tag (hyphens become "_", like in file names)
 * @param {string|null} assetId  the scan's asset id, or null when the scan has no asset
 */
export function generateReportId(tag, assetId) {
  const asset = assetId ? String(assetId).trim().toLowerCase() : NIL_ASSET_ID;
  return `${REPORT_ID_PREFIX}-${sanitizeReportTag(tag)}-${asset}-${randomUUID().replace(/-/g, "")}`;
}

const REPORT_ID_PARTS_RE = new RegExp(
  `^${REPORT_ID_PREFIX}-([A-Za-z0-9_]+)-(${ASSET_ID_PART})-(${HEX32})$`, "i");

/** True when `id` is a well-formed report id. */
export function isValidReportId(id) {
  return typeof id === "string" && REPORT_ID_PARTS_RE.test(id);
}

/**
 * Split a report id into its parts, or null when it is not one.
 * @returns {{tag: string, asset_id: string, uuid: string}|null}
 */
export function parseReportId(id) {
  if (typeof id !== "string") return null;
  const m = id.match(REPORT_ID_PARTS_RE);
  if (!m) return null;
  return { tag: m[1], asset_id: m[2].toLowerCase(), uuid: m[3].toLowerCase() };
}

/** The only values `asset_type` can take. */
export const ASSET_TYPES = Object.freeze(["codebase", "cloud", "easm", "machine", "agent", "editor", "docker"]);

// scan_scope values that are about a machine rather than a repository.
const MACHINE_SCOPES = new Set(["developer_platform", "cli_tool", "linux_machine"]);

/**
 * Asset type of a scan — one of ASSET_TYPES:
 *
 *   scan_scope "agent"                                  → agent
 *   scan_scope "editor_extension"                       → editor
 *   scan_scope "container-image" (ubel-docker)          → docker
 *   scan_scope developer_platform / cli_tool /
 *              linux_machine, or mode "os"              → machine
 *   mode cloud                                          → cloud
 *   mode easm (and the EASM modes host / domain / url)  → easm
 *   everything else: modes sca, firewall, sast, malware
 *   (and licenses, secrets, scope cicd)                 → codebase
 *
 * The scope wins over the mode, so `ubel-agent` (history mode "sca") is an agent
 * and `ubel-platform` is a machine.
 *
 * @param {string} mode         history mode (see historyZipPath)
 * @param {string} [scanScope]  scan_scope of an SCA run, when there is one
 * @returns {"codebase"|"cloud"|"easm"|"machine"|"agent"|"editor"|"docker"}
 */
export function assetTypeFor(mode, scanScope) {
  if (scanScope === "agent") return "agent";
  if (scanScope === "editor_extension") return "editor";
  if (scanScope === "container-image") return "docker";
  if (MACHINE_SCOPES.has(scanScope)) return "machine";
  switch (sanitizeReportTag(mode)) {
    case "os":                                      return "machine";
    case "cloud":                                   return "cloud";
    case "easm": case "host": case "domain": case "url": return "easm";
    default:                                        return "codebase";
  }
}

/**
 * Asset identity for a scan that writes history under `mode`.
 *
 *   mode "os" (apt/dnf/yum)   → machine tag, $HOME/.ubel/ubel_asset.json
 *   everything else           → <ubelDir>/ubel_asset.json
 *
 * When --asset-id was given (setRuntimeAssetId) that id is used instead of the
 * stored one and the file is left untouched; the name is the stored one when it
 * belongs to the same id, else derived.
 *
 * asset_id / asset_name are null when the identity file could not be written
 * (see ensureAsset); asset_type is always set.
 *
 * @param {string} mode        history mode (see historyZipPath)
 * @param {string} ubelDir     the .ubel folder this scan writes its reports into
 * @param {string} [scanScope] scan_scope of an SCA run; decides agent / machine (see assetTypeFor)
 * @returns {{asset_id: string|null, asset_name: string|null, asset_type: string}}
 */
export function assetFor(mode, ubelDir, scanScope) {
  const asset_type = assetTypeFor(mode, scanScope);
  const dir = mode === "os" ? machineUbelDir() : ubelDir;

  if (runtimeAssetId) {
    const stored = readAssetFile(path.join(dir, ASSET_FILE_NAME));
    const asset_name = stored && stored.asset_id === runtimeAssetId
      && typeof stored.asset_name === "string" && stored.asset_name.trim()
      ? stored.asset_name
      : deriveAssetName(dir);
    return { asset_id: runtimeAssetId, asset_name, asset_type };
  }

  const asset = ensureAsset(dir);
  return { asset_id: asset?.asset_id ?? null, asset_name: asset?.asset_name ?? null, asset_type };
}

/**
 * Path for a new history zip:
 *   $HOME/.ubel/history/<mode>/<asset_id>/<timestamp>.<tag>.zip
 * (history/<mode>/<timestamp>.<tag>.zip when no asset id is available).
 * Creates the folders. If two runs of the same asset land in the same second
 * the later one gets "<timestamp>_2.<tag>.zip" rather than overwriting the first.
 *
 * @param {string} mode        history sub-folder, e.g. "sca", "os", "url"
 * @param {string} timestamp   from reportTimestamp()
 * @param {string} tag         file-name tag, e.g. "sca", "firewall_apt", "url"
 * @param {string|null} [assetId]  asset_id from assetFor(); omitted/null = no asset folder
 * @returns {string}
 */
export function historyZipPath(mode, timestamp, tag, assetId = null) {
  if (assetId != null && !ASSET_ID_RE.test(assetId)) {
    throw new Error(`invalid asset id: ${assetId}`);
  }
  let dir = path.join(historyRoot(), sanitizeReportTag(mode));
  if (assetId) dir = path.join(dir, assetId);
  fs.mkdirSync(dir, { recursive: true });
  let candidate = path.join(dir, reportFileName(timestamp, tag, "zip"));
  for (let n = 2; fs.existsSync(candidate); n++) {
    candidate = path.join(dir, reportFileName(`${timestamp}_${n}`, tag, "zip"));
  }
  return candidate;
}

/** $HOME/.ubel/latest_reports — the newest zip of every tag, per mode and asset. */
export function latestReportsRoot() {
  return path.join(os.homedir(), ".ubel", "latest_reports");
}

/**
 * Keep the newest scan of a tag in latest_reports/, apart from the history:
 *
 *   history/<mode>/<asset_id>/<timestamp>.<tag>.zip   (just written)
 *   latest_reports/<mode>/<asset_id>/latest.<tag>.zip (this copy)
 *
 * The <mode>/<asset_id> part is taken from where the history zip was filed,
 * so the two trees always line up (and a zip filed without a asset id lands
 * in latest_reports/<mode>/). The copy goes to a temp file first and is renamed
 * over the old one, so a reader never sees a half-written latest zip and a
 * failed copy leaves the previous latest in place. Best effort: a scan must not
 * fail because this convenience copy couldn't be written, so errors are warned
 * about, not thrown.
 *
 * Call it after the timestamped zip has been written.
 *
 * @param {string} zipPath  path returned by historyZipPath(), already written
 * @param {string} tag      same tag the zip was named with
 * @returns {string|null}   path of latest.<tag>.zip, or null if it couldn't be written
 */
export function updateLatestReportZip(zipPath, tag) {
  let latest = null;
  let tmp = null;
  try {
    const rel = path.relative(historyRoot(), path.dirname(path.resolve(zipPath)));
    if (rel.startsWith("..") || path.isAbsolute(rel)) {
      throw new Error(`${zipPath} is not inside ${historyRoot()}`);
    }
    const dir = path.join(latestReportsRoot(), rel);
    fs.mkdirSync(dir, { recursive: true });
    latest = path.join(dir, reportFileName("latest", tag, "zip"));
    // Same temp-then-rename swap as atomicWriteFile(), with a copy as the first step.
    tmp = `${latest}.${process.pid}.${randomUUID().slice(0, 8)}.tmp`;
    fs.copyFileSync(zipPath, tmp);
    fs.renameSync(tmp, latest);
    return latest;
  } catch (e) {
    if (tmp) { try { fs.unlinkSync(tmp); } catch { /* nothing to clean up */ } }
    console.warn(`[ubel] could not update latest report zip (${latest ?? "latest_reports"}): ${e.message}`);
    return null;
  }
}