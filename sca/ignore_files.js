/**
 * ignore_files.js — keep ubel's own files out of git and docker contexts.
 *
 * Original code (not ported from Trivy).
 *
 * ensureUbelIgnoreEntries(dir) makes sure `.gitignore` and `.dockerignore` in
 * `dir` ignore:
 *   .ubel/        reports, policy, extracted images, dependency scratch space
 *   .ubelignore   the local suppression / baseline file
 * and creates either file if it does not exist.
 *
 * Properties:
 *   - Idempotent. An entry is "already covered" if any equivalent pattern is
 *     present (`.ubel`, `/.ubel/`, `.ubel/*`, `.ubel*`, ...), so it never
 *     duplicates one the user wrote by hand.
 *   - Appends only. Existing content, ordering and line endings (LF/CRLF) are
 *     preserved.
 *   - Respects an explicit opt-out: a negation such as `!.ubelignore` means the
 *     user wants that entry tracked, so it is NOT re-added. This is how you keep
 *     a shared baseline in git while the rest stays ignored.
 *   - Never throws. A read-only checkout or a permissions problem is reported in
 *     the result's `error` field; it must not fail a scan.
 *   - Checked once per directory per process.
 *   - Kill switch: UBEL_NO_IGNORE_FILES=1.
 *
 * Called from main.js only (ensureUbelIgnoreFiles, at every entry point, before
 * anything else runs) — never from the secrets scanner, CLI or hook modules.
 * Callers pass the directory that actually contains `.ubel/` — never a
 * container-image rootfs or the $HOME redirect used by ubel-apt/dnf/yum.
 */

import fs from "node:fs";
import path from "node:path";

export const UBEL_IGNORE_ENTRIES = [".ubel/", ".ubelignore"];
export const IGNORE_FILES = [".gitignore", ".dockerignore"];

const MARKER = "# ubel: reports directory and local suppression file";

// Patterns that already cover each entry (all spellings git and docker accept).
const EQUIVALENT = {
  ".ubel/": [
    ".ubel", ".ubel/", "/.ubel", "/.ubel/",
    ".ubel/*", ".ubel/**", "/.ubel/*", "/.ubel/**",
    ".ubel*", "/.ubel*", ".ubel*/", "/.ubel*/",
  ],
  ".ubelignore": [".ubelignore", "/.ubelignore", ".ubel*", "/.ubel*"],
};

const checked = new Set();

function parseLines(text) {
  const set = new Set();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line && !line.startsWith("#")) set.add(line);
  }
  return set;
}

function updateOne(file) {
  let existing = null;
  try {
    existing = fs.readFileSync(file, "utf8");
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }

  const lines = parseLines(existing ?? "");
  const added = [];
  const kept = []; // entries the user explicitly un-ignored with `!`
  for (const entry of UBEL_IGNORE_ENTRIES) {
    const variants = EQUIVALENT[entry];
    if (variants.some(v => lines.has(`!${v}`))) kept.push(entry);
    else if (!variants.some(v => lines.has(v))) added.push(entry);
  }

  const result = { file, created: existing === null && added.length > 0, added, tracked: kept };
  if (!added.length) return result;

  const eol = existing && existing.includes("\r\n") ? "\r\n" : "\n";
  const hasMarker = existing !== null && existing.includes(MARKER);
  let prefix = "";
  if (existing && existing.length) {
    if (!/\r?\n$/.test(existing)) prefix += eol;
    if (!hasMarker) prefix += eol; // blank line before our block
  }
  const block = prefix + (hasMarker ? "" : MARKER + eol) + added.join(eol) + eol;
  fs.appendFileSync(file, block);
  return result;
}

/**
 * @param {string} dir
 * @param {object}  [opts]
 * @param {boolean} [opts.notify=false]  Print one line per changed file to stderr.
 * @param {boolean} [opts.force=false]   Re-check even if `dir` was already checked.
 * @returns {{root: string, files: object[], disabled?: boolean, cached?: boolean, error?: string}}
 */
export function ensureUbelIgnoreEntries(dir, { notify = false, force = false } = {}) {
  const root = path.resolve(dir || process.cwd());
  if (process.env.UBEL_NO_IGNORE_FILES === "1") return { root, files: [], disabled: true };
  if (!force && checked.has(root)) return { root, files: [], cached: true };

  try {
    if (!fs.statSync(root).isDirectory()) return { root, files: [], error: "not a directory" };
  } catch (e) {
    return { root, files: [], error: e.message };
  }
  checked.add(root);

  const files = [];
  let error;
  for (const name of IGNORE_FILES) {
    const file = path.join(root, name);
    try {
      const r = updateOne(file);
      files.push(r);
      if (notify && r.added.length) {
        process.stderr.write(`[ubel] ${r.created ? "Created" : "Updated"} ${name}: added ${r.added.join(", ")}\n`);
      }
    } catch (e) {
      error = `${name}: ${e.message}`;
      if (process.env.DEBUG) process.stderr.write(`[ubel] could not update ${file}: ${e.message}\n`);
    }
  }
  return error ? { root, files, error } : { root, files };
}

export default ensureUbelIgnoreEntries;