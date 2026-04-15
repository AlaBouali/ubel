#!/usr/bin/env node
/**
 * main.js — entry point for all ubel-node engines.
 *
 * Usage (called by bin/* wrappers):
 *   node src/main.js <engine> <mode> [...extra_args]
 *
 * engine  : npm | pnpm | bun | yarn
 * mode    : check | install | health | init | allow | block
 * extra   : package names for check/install, or severity names for allow/block
 *
 * check/install support matrix:
 *   npm  — yes  (--package-lock-only dry-run)
 *   pnpm — yes  (--lockfile-only dry-run)
 *   bun  — yes  (--lockfile-only dry-run, node_modules untouched)
 *   yarn — no   (no lockfile-only equivalent; yarn add always writes node_modules)
 */

import { UbelEngine, PolicyViolationError } from "./engine.js";
import { banner }     from "./info.js";
import { loadEnvironment } from "./utils.js";

const VALID_MODES = ["check", "install", "health", "init", "allow", "block"];

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

  if (effectiveMode === "init") {
    process.exit(0);
  }

  if (effectiveMode === "allow" || effectiveMode === "block") {
    if (!extraArgs.length) {
      console.error("[!] Provide severity levels: critical high medium low unknown");
      process.exit(1);
    }
    const VALID_SEVERITIES = new Set(["critical", "high", "medium", "low", "unknown"]);
    const invalid = extraArgs.filter(a => !VALID_SEVERITIES.has(a.toLowerCase()));
    if (invalid.length) {
      console.error(`[!] Unrecognised severity level(s): ${invalid.join(", ")}`);
      console.error("[!] Valid values: critical high medium low unknown");
      process.exit(1);
    }
    UbelEngine.setPolicyRules(effectiveMode, extraArgs.map(a => a.toLowerCase()));
    console.log(`[+] Updated policy: ${effectiveMode} → ${extraArgs.join(", ")}`);
    process.exit(0);
  }

  // check/install require a lockfile-only dry-run capability.
  // yarn has no equivalent flag and always writes node_modules — unsupported.
  const CHECK_INSTALL_ENGINES = new Set(["npm", "pnpm", "bun"]);
  if (!CHECK_INSTALL_ENGINES.has(engine)) {
    console.error(`[!] '${engine}' is not supported.`);
    console.error("[!] Supported engines: npm, pnpm, bun");
    process.exit(1);
  }
  if ((effectiveMode === "check" || effectiveMode === "install") && !CHECK_INSTALL_ENGINES.has(engine)) {
    console.error(`[!] '${engine}' does not support check/install mode.`);
    console.error("[!] Supported engines for check/install: npm, pnpm, bun");
    console.error("[!] Use 'health' mode to scan already-installed packages with any engine.");
    process.exit(1);
  }

  // For check/install: validate package specifier format before they reach
  // spawnSync.  The regex mirrors the one in NodeManager.runDryRun so the
  // error surfaces early with a clear message rather than deep inside npm.
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
    // Pass empty array — dry-run will use existing package.json
    pkgArgs = [];
  }

  const { apiKey, assetId } = loadEnvironment();
  if (apiKey && assetId) {
    console.error("[!] Remote mode (UBEL_API_KEY + UBEL_ASSET_ID) is not yet implemented in the Node CLI.");
    process.exit(1);
  }

  try {
    await UbelEngine.scan(pkgArgs);
  } catch (err) {
    if (err instanceof PolicyViolationError) {
      // Messages were already printed inside scan() — just exit.
      process.exit(1);
    }
    console.error("[!] Scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

main();