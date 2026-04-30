#!/usr/bin/env node
/**
 * main.js — entry point for all ubel-node engines.
 *
 * ── CLI usage (called by bin/* wrappers) ──────────────────────────────────────
 *   node src/main.js <engine> <mode> [...extra_args]
 *
 *   engine    : npm | pnpm | bun
 *   mode      : check | install | health | init | threshold | block-unknown
 *
 *   Policy configuration modes:
 *     threshold <level>          — set severity_threshold (low|medium|high|critical|none)
 *     block-unknown <true|false> — set block_unknown_vulnerabilities
 *
 * ── Programmatic usage (agent, platform, VS Code extension) ──────────────────
 *   import { main } from "./main.js";
 *
 *   await main({
 *     projectRoot : "/abs/path",   // cwd() when omitted
 *     engine      : "npm",         // default "npm"
 *     mode        : "health",      // default "health"
 *     // any scan() option:
 *     is_script           : true,
 *     save_reports        : true,
 *     scan_os             : true,
 *     full_stack          : true,
 *     scan_node           : false,
 *     is_vscanned_project : false,
 *   });
 *
 * ── check/install support matrix ─────────────────────────────────────────────
 *   npm  — yes  (--package-lock-only dry-run)
 *   pnpm — yes  (--lockfile-only dry-run)
 *   bun  — yes  (--lockfile-only dry-run, node_modules untouched)
 *   yarn — no   (no lockfile-only equivalent; yarn add always writes node_modules)
 */

import { UbelEngine, PolicyViolationError } from "./engine.js";
import { NodeManager }    from "./node_runner.js";
import { banner }         from "./info.js";
import { loadEnvironment } from "./utils.js";

const VALID_MODES      = ["check", "install", "health", "init", "threshold", "block-unknown"];
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical", "none"]);

// ── Engines that support lockfile-only dry-runs ───────────────────────────────
const CHECK_INSTALL_ENGINES = new Set(["npm", "pnpm", "bun"]);

// ── Package-specifier allow-list (same pattern used before) ──────────────────
const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'"<>]+)?$/i;

/**
 * main() — unified entry point for CLI callers AND programmatic callers.
 *
 * Behaviour is determined by how it is called:
 *
 *   • No arguments (or called by a bin/* shim):
 *       Reads engine / mode / extra args from process.argv, prints the banner,
 *       handles policy-config modes (threshold / block-unknown / init), validates
 *       package args, then runs a scan.  This is the legacy CLI path — identical
 *       to the old main() behaviour.
 *
 *   • Called with a plain-object argument:
 *       Skips argv parsing, banner, and CLI-specific exits.  Sets engine state,
 *       chdirs into projectRoot, runs the scan, then restores cwd.  Returns the
 *       finalJson report object (same contract as the old scan_project()).
 *       This replaces scan_project() for agent, platform, and the VS Code extension.
 *
 * @param {object|undefined} programmaticOptions
 * @param {string}  [programmaticOptions.projectRoot]          Absolute path to scan.
 * @param {string}  [programmaticOptions.engine="npm"]         Package manager engine.
 * @param {string}  [programmaticOptions.mode="health"]        Scan mode.
 * @param {boolean} [programmaticOptions.is_script=true]
 * @param {boolean} [programmaticOptions.save_reports=true]
 * @param {boolean} [programmaticOptions.scan_os=false]
 * @param {boolean} [programmaticOptions.full_stack=false]
 * @param {boolean} [programmaticOptions.scan_node=true]
 * @param {boolean} [programmaticOptions.is_vscanned_project=false]
 * @param {string}  [programmaticOptions.scan_scope="repository"]  Scan context: repository | agent | developer_platform | vs_code_extension
 * @returns {Promise<object|void>}  Report object when called programmatically; void for CLI.
 */
export async function main(programmaticOptions) {

  // ════════════════════════════════════════════════════════════════════════════
  // PROGRAMMATIC PATH
  // Called by: agent.js, platform.js, extension.js
  // ════════════════════════════════════════════════════════════════════════════
  if (programmaticOptions !== undefined && typeof programmaticOptions === "object") {

    const {
      projectRoot,
      engine             = "npm",
      mode               = "health",
      is_script          = true,
      save_reports       = true,
      scan_os            = false,
      full_stack         = false,
      scan_node          = true,
      is_vscanned_project = false,
      scan_scope         = "repository",
      ...rest                       // forward any extra options the caller passes
    } = programmaticOptions;

    const original_cwd = process.cwd();
    if (projectRoot && projectRoot !== original_cwd) {
      process.chdir(projectRoot);
    }

    try {
      // Reset all static engine state so re-runs in the same process are clean.
      UbelEngine.engine              = engine;
      UbelEngine.systemType          = engine;
      UbelEngine.checkMode           = mode;
      UbelEngine.vulns_ids_found     = new Set();

      NodeManager.inventoryData      = [];

      UbelEngine.initiateLocalPolicy();

      return await UbelEngine.scan([], {
        current_dir: projectRoot || original_cwd,
        is_script,
        save_reports,
        scan_os,
        full_stack,
        scan_node,
        is_vscanned_project,
        scan_scope,
        ...rest,
      });

    } finally {
      if (projectRoot && projectRoot !== original_cwd) {
        process.chdir(original_cwd);
      }
    }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CLI PATH
  // Called by: bin/npm.js, bin/pnpm.js, bin/bun.js, bin/yarn.js
  // ════════════════════════════════════════════════════════════════════════════

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

  // ── init ────────────────────────────────────────────────────────────────────
  if (effectiveMode === "init") {
    process.exit(0);
  }

  // ── threshold <level> ───────────────────────────────────────────────────────
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

  // ── block-unknown <true|false> ───────────────────────────────────────────────
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

  // ── check/install require lockfile-only dry-run support ─────────────────────
  if (!CHECK_INSTALL_ENGINES.has(engine)) {
    console.error(`[!] '${engine}' is not supported.`);
    console.error("[!] Supported engines: npm, pnpm, bun");
    process.exit(1);
  }

  // ── validate package specifiers early ───────────────────────────────────────
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

  // ── remote mode guard ────────────────────────────────────────────────────────
  const { apiKey, assetId } = loadEnvironment();
  if (apiKey && assetId) {
    console.error("[!] Remote mode (UBEL_API_KEY + UBEL_ASSET_ID) is not yet implemented in the Node CLI.");
    process.exit(1);
  }

  // ── scan ─────────────────────────────────────────────────────────────────────
  try {
    await UbelEngine.scan(pkgArgs, {
      is_script:    false,
      save_reports: true,
      scan_os:      false,
      full_stack:   true,
      scan_scope:   "repository",
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
 * @deprecated Use main({ projectRoot, ...options }) instead.
 *
 * Kept as a zero-cost shim so any existing callers that haven't been updated
 * yet continue to work without modification.
 */
export async function scan_project(projectRoot, options = {}) {
  return main({ projectRoot, ...options });
}