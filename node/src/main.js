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
 *     packages    : ["express@4.18.0", "lodash"],  // check/install only
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

import path from "path";
import { UbelEngineInstance, PolicyViolationError } from "./engine.js";
import { NodeManagerInstance }  from "./node_runner.js";
import { banner }               from "./info.js";
import { loadEnvironment }       from "./utils.js";

import fs from 'node:fs/promises';

async function createTargetPath(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    console.log('Path created successfully!');
  } catch (err) {
    console.error('Error creating path:', err);
  }
}

const VALID_MODES      = ["check", "install", "health", "init", "threshold", "block-unknown"];
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical", "none"]);

// ── Engines that support lockfile-only dry-runs ───────────────────────────────
const CHECK_INSTALL_ENGINES = new Set(["npm", "pnpm", "bun"]);

/**
 * main() — unified entry point for CLI callers AND programmatic callers.
 *
 * A fresh NodeManagerInstance + UbelEngineInstance is constructed for every
 * invocation, so there is no shared mutable state between calls.  No
 * process.chdir() is performed; projectRoot is resolved to an absolute path
 * and threaded through the engine explicitly.
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
 * @param {string[]} [programmaticOptions.packages=[]]
 * @param {string}  [programmaticOptions.scan_scope="repository"]
 * @returns {Promise<object|void>}  Report object when called programmatically; void for CLI.
 */
export async function main(programmaticOptions) {

  // ════════════════════════════════════════════════════════════════════════════
  // PROGRAMMATIC PATH
  // Called by: agent.js, platform.js, extension.js, MCP server
  // ════════════════════════════════════════════════════════════════════════════
  if (programmaticOptions !== undefined && typeof programmaticOptions === "object") {

    const {
      projectRoot,
      engine             = "npm",
      mode               = "health",
      packages           = [],
      is_script          = true,
      save_reports       = true,
      scan_os            = false,
      full_stack         = false,
      scan_node          = true,
      is_vscanned_project = false,
      scan_scope         = "repository",
      ...rest
    } = programmaticOptions;

    // Resolve projectRoot to an absolute path.  When omitted, fall back to
    // the current working directory.  This is the ONLY place cwd() is called
    // in the programmatic path — the resolved absolute path is then passed
    // explicitly everywhere so no chdir is ever needed.
    const resolvedRoot = projectRoot
      ? path.resolve(projectRoot)
      : path.resolve(process.cwd());

    await createTargetPath(resolvedRoot)

    // Construct fresh, isolated instances for this invocation.
    const manager = new NodeManagerInstance();
    const eng     = new UbelEngineInstance(manager, resolvedRoot);

    eng.engine     = engine;
    eng.systemType = engine;
    eng.checkMode  = mode;

    eng.initiateLocalPolicy();

    return await eng.scan(packages, {
      is_script,
      save_reports,
      scan_os,
      full_stack,
      scan_node,
      is_vscanned_project,
      scan_scope,
      ...rest,
    });
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

  // The CLI always operates in the current working directory.
  const resolvedRoot = path.resolve(process.cwd());

  // Construct fresh instances for this CLI invocation.
  const manager = new NodeManagerInstance();
  const eng     = new UbelEngineInstance(manager, resolvedRoot);

  eng.engine     = engine;
  eng.systemType = "npm";

  eng.initiateLocalPolicy();

  console.log(banner);
  console.log(`Reports location: ${eng.reportsLocation}`);
  console.log();
  console.log(`Policy location: ${eng.policyDir}`);
  console.log();

  const effectiveMode = VALID_MODES.includes(mode) ? mode : "health";
  eng.checkMode = effectiveMode;

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
    eng.setPolicyField("severity_threshold", level);
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
    eng.setPolicyField("block_unknown_vulnerabilities", value);
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
    await eng.scan(pkgArgs, {
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
 */
export async function scan_project(projectRoot, options = {}) {
  return main({ projectRoot, ...options });
}