#!/usr/bin/env node
/**
 * main.js — entry point for all ubel-node engines.
 *
 * Usage (called by bin/* wrappers):
 *   node src/main.js <engine> <mode> [...extra_args]
 *
 * engine    : npm | pnpm | bun
 * mode      : check | install | health | init | threshold | block-unknown
 *
 * Policy configuration modes:
 *   threshold <level>          — set severity_threshold (low|medium|high|critical)
 *   block-unknown <true|false> — set block_unknown_vulnerabilities
 *
 * check/install support matrix:
 *   npm  — yes  (--package-lock-only dry-run)
 *   pnpm — yes  (--lockfile-only dry-run)
 *   bun  — yes  (--lockfile-only dry-run, node_modules untouched)
 *   yarn — no   (no lockfile-only equivalent; yarn add always writes node_modules)
 */

import { UbelEngine, PolicyViolationError } from "./engine.js";
import { banner }            from "./info.js";
import { loadEnvironment }   from "./utils.js";

const VALID_MODES      = ["check", "install", "health", "init", "threshold", "block-unknown"];
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical", "none"]);

async function main() {
  const [, , engine, mode, ...extraArgs] = process.argv;

  if (!engine) {
    console.error("Usage: ubel-<engine> <mode> [args...]");
    process.exit(1);
  }

  // Configure engine
  UbelEngine.engine     = engine;
  UbelEngine.systemType = "npm";

  // Init policy dirs
  UbelEngine.initiateLocalPolicy();

  // Print banner
  console.log(banner);
  console.log(`Reports location: ${UbelEngine.reportsLocation}`);
  console.log();
  console.log(`Policy location: ${UbelEngine.policyDir}`);
  console.log();

  const effectiveMode = VALID_MODES.includes(mode) ? mode : "health";
  UbelEngine.checkMode = effectiveMode;

  // ── init ──────────────────────────────────────────────────────────────────
  if (effectiveMode === "init") {
    process.exit(0);
  }

  // ── threshold <level> ─────────────────────────────────────────────────────
  if (effectiveMode === "threshold") {
    const level = (extraArgs[0] || "").toLowerCase();
    if (!level || !VALID_SEVERITIES.has(level)) {
      console.error("[!] Provide a valid severity level: low | medium | high | critical | none");
      console.error("[!] Example: ubel-npm threshold high");
      process.exit(1);
    }
    UbelEngine.setPolicyField("severity_threshold", level);
    console.log(`[+] Policy updated: severity_threshold = ${level}`);
    console.log("[i] Infections are always blocked regardless of this setting.");
    process.exit(0);
  }

  // ── block-unknown <true|false> ────────────────────────────────────────────
  if (effectiveMode === "block-unknown") {
    const raw = (extraArgs[0] || "").toLowerCase();
    if (raw !== "true" && raw !== "false") {
      console.error("[!] Provide true or false");
      console.error("[!] Example: ubel-npm block-unknown true");
      process.exit(1);
    }
    const value = raw === "true";
    UbelEngine.setPolicyField("block_unknown_vulnerabilities", value);
    console.log(`[+] Policy updated: block_unknown_vulnerabilities = ${value}`);
    process.exit(0);
  }

  // ── check/install require lockfile-only dry-run support ───────────────────
  const CHECK_INSTALL_ENGINES = new Set(["npm", "pnpm", "bun"]);
  if (!CHECK_INSTALL_ENGINES.has(engine)) {
    console.error(`[!] '${engine}' is not supported.`);
    console.error("[!] Supported engines: npm, pnpm, bun");
    process.exit(1);
  }

  // ── validate package specifiers early ────────────────────────────────────
  const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'"<>]+)?$/i;
  let pkgArgs = extraArgs;
  if (pkgArgs.length) {
    const bad = pkgArgs.filter(a => !PKG_ARG_RE.test(a));
    if (bad.length) {
      console.error(`[!] Rejected unsafe or malformed package argument(s): ${bad.join(", ")}`);
      console.error("[!] Expected format: name, name@version, or @scope/name@version");
      process.exit(1);
    }
  }
  if (!pkgArgs.length && (effectiveMode === "check" || effectiveMode === "install")) {
    pkgArgs = [];
  }

  // ── remote mode guard ─────────────────────────────────────────────────────
  const { apiKey, assetId } = loadEnvironment();
  if (apiKey && assetId) {
    console.error("[!] Remote mode (UBEL_API_KEY + UBEL_ASSET_ID) is not yet implemented in the Node CLI.");
    process.exit(1);
  }

  // ── scan ──────────────────────────────────────────────────────────────────
  try {
    await UbelEngine.scan(pkgArgs, {
      is_script:    false,
      save_reports: true,
      os_scan:      false,
      full_stack:   true,
    });
  } catch (err) {
    if (err instanceof PolicyViolationError) {
      process.exit(1);
    }
    console.error("[!] Scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

/**
 * scan_project — called by the VS Code extension (and any other script consumer).
 *
 * Fixes vs. the inline CLI path:
 *   1. Sets UbelEngine.engine + UbelEngine.systemType before scanning —
 *      the CLI does this in main() but scan_project previously skipped it.
 *   2. Forces checkMode to "health" so the scan() path never reaches the
 *      process.exit(0) calls that live in the "check" / "install" branches —
 *      those would kill the VS Code host process.
 *   3. Resets was_successful_scan so a second call in the same process gets
 *      a clean slate (static class, single process lifetime).
 *
 * @param {string} [projectRoot] - Absolute path to scan. Defaults to cwd().
 * @returns {Promise<object>}    - The finalJson report object.
 */
export async function scan_project(projectRoot, options={
      is_script:    true,
      save_reports: true,
      os_scan:      false,
      full_stack:   true,
    }) {
  // ── change cwd so all relative paths (.ubel/, node_modules/, …) resolve
  //    inside the target project, not inside the extension's install dir.
  const original_cwd = process.cwd();
  if (projectRoot && projectRoot !== original_cwd) {
    process.chdir(projectRoot);
  }

  try {
    // ── Engine state must be initialised before scan() ────────────────────
    UbelEngine.engine            = "npm";
    UbelEngine.systemType        = "npm";
    UbelEngine.checkMode         = "health";   // avoids the process.exit() branches
    UbelEngine.was_successful_scan = false;    // reset for re-runs in same process
    UbelEngine.vulns_ids_found   = new Set();  // reset accumulated vuln ids

    UbelEngine.initiateLocalPolicy();

    return await UbelEngine.scan([], options);
  } finally {
    // Always restore the original cwd, even if the scan throws.
    if (projectRoot && projectRoot !== original_cwd) {
      process.chdir(original_cwd);
    }
  }
}


// main() must run when:
//   • executed directly via node src/main.js
//   • loaded by a bin wrapper via import("../src/main.js")
//     (in that case process.argv[1] is npm.js/pnpm.js/bun.js — NOT main.js,
//      so any argv[1] check is wrong)
//
// main() must NOT run when:
//   • bundled by esbuild for the VS Code extension.
//     esbuild compiles away import.meta, so typeof import.meta === "undefined"
//     inside the CJS bundle — that is the only safe distinguishing signal.

if (typeof import.meta !== "undefined") {
  main();
}