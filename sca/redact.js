// redact.js — optional removal of machine-specific absolute paths from report text.
//
// Enabled by --redact-paths (any UBEL CLI) or UBEL_REDACT_PATHS=1. Reports otherwise record
// absolute paths (the scan's cwd, each package's install path), which include the local
// user and folder names — fine for local use, unwanted in an SBOM that is shared.
//
// Works on the serialized text of each report (JSON, HTML, SBOM, SARIF), so it also catches
// paths inside JSON-in-JSON values, where every backslash is escaped two or three times.

import os from "os";
import path from "path";

const escapeRe = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const SEP = "(?:\\\\+|/)";           // "/" or a run of (possibly escaped) backslashes

/** RegExp matching `dir` written with any separator style and any amount of escaping. */
function dirRegex(dir) {
  const abs = path.resolve(dir);
  const segs = abs.split(/[\\/]+/).filter(Boolean);
  if (!segs.length) return null;
  const lead = abs.startsWith("/") ? "/" : "";
  const flags = process.platform === "win32" ? "gi" : "g";
  return new RegExp(lead + segs.map(escapeRe).join(SEP) + "(?![\\w.-])", flags);
}

/** True when path redaction was requested for this run. */
export function redactionEnabled() {
  return process.env.UBEL_REDACT_PATHS === "1";
}

/**
 * Replace the scanned project's absolute path with "<project>" and the home directory with
 * "~" (project first: it is usually inside the home directory).
 *
 * @param {string} text         serialized report
 * @param {string} projectRoot  the scanned folder
 */
export function redactPaths(text, projectRoot) {
  if (typeof text !== "string" || !text) return text;
  let out = text;
  const root = projectRoot ? dirRegex(projectRoot) : null;
  if (root) out = out.replace(root, "<project>");
  const home = dirRegex(os.homedir());
  if (home) out = out.replace(home, "~");
  return out;
}
