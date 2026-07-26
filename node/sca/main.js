#!/usr/bin/env node
/**
 * main.js — entry point for all ubel-node engines.
 *
 * ── CLI usage (called by bin/* wrappers) ──────────────────────────────────────
 *   node src/main.js <engine> <mode> [...extra_args]
 *
 *   engine    : npm | pnpm | bun | docker
 *   mode      : check | install | health | init | threshold | block-unknown
 *
 *   Policy configuration modes:
 *     threshold <level>          — set severity_threshold (low|medium|high|critical|none)
 *     block-unknown <true|false> — set block_unknown_vulnerabilities
 *
 *   Docker mode (`docker` engine supports `health`, `check`, and `install`):
 *     node src/main.js docker <health|check|install> <image|tar-path> [--no-pull] [--keep]
 *
 *     Pulls (or reuses a local) image, creates a stopped container — never
 *     runs its ENTRYPOINT/CMD — exports its filesystem to a temp dir, and
 *     scans that dir exactly like any other project root: OS packages via
 *     LinuxHostScanner (scan_os) plus every ecosystem's app dependencies
 *     (full_stack). Safe to point at an unvetted base image pre-deploy.
 *     `--no-pull` scans an image that only exists locally (e.g. right after
 *     `docker build`, before it's pushed). `--keep` skips cleanup of the
 *     extracted rootfs for debugging.
 *
 *     The scan pipeline itself is identical across modes — mode only
 *     controls what happens to the image afterward:
 *       health  — scan only, image left exactly as found.
 *       check   — scan, then always remove the image afterward.
 *       install — scan, then remove the image only if the scan results in
 *                 a policy block; a clean scan leaves it in place.
 *
 *     In place of an image reference, <image|tar-path> also accepts a path
 *     to a local, uncompressed .tar file (e.g. from a prior `docker save`/
 *     `docker export`, or a CI artifact) — detected automatically by a
 *     `.tar` extension that resolves to an existing file. That skips
 *     `docker pull`/`docker create`/`docker export` entirely and extracts
 *     the given tar directly; `--no-pull` is a no-op in that case, and
 *     `check`/`install` won't attempt `docker rmi` since there's no pulled
 *     image to remove. Compressed tarballs (.tar.gz/.tgz) aren't supported
 *     — decompress first.
 *
 * ── Programmatic usage (agent, platform, VS Code extension) ──────────────────
 *   import { main, dockerScan } from "./main.js";
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
 *   await dockerScan({ image: "node:20-alpine" });
 *   await dockerScan({ image: "/path/to/rootfs.tar" });  // local tar file, same API
 *
 * ── check/install support matrix ─────────────────────────────────────────────
 *   npm    — yes  (--package-lock-only dry-run)
 *   pnpm   — yes  (--lockfile-only dry-run)
 *   bun    — yes  (--lockfile-only dry-run, node_modules untouched)
 *   yarn   — no   (no lockfile-only equivalent; yarn add always writes node_modules)
 *   docker — yes  (health/check/install all supported; see Docker mode above)
 */

import path from "path";
import { UbelEngineInstance, PolicyViolationError } from "./engine.js";
import { NodeManagerInstance }  from "./node_runner.js";
import { banner }               from "./info.js";
import { loadEnvironment }       from "./utils.js";
import { DockerImageScanner }    from "./docker_runner.js";

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
async function main(programmaticOptions) {

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
      severity_threshold = undefined,
      block_unknown_vulnerabilities = undefined,
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
    // Apply policy overrides if provided
    if (severity_threshold !== undefined) {
      const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical", "none"]);
      if (!VALID_SEVERITIES.has(severity_threshold)) {
        throw new Error(`Invalid severity_threshold: ${severity_threshold}. Must be one of: low, medium, high, critical, none`);
      }
      eng.setPolicyField("severity_threshold", severity_threshold);
    }

    if (block_unknown_vulnerabilities !== undefined) {
      if (typeof block_unknown_vulnerabilities !== "boolean") {
        throw new Error(`block_unknown_vulnerabilities must be a boolean, got ${typeof block_unknown_vulnerabilities}`);
      }
      eng.setPolicyField("block_unknown_vulnerabilities", block_unknown_vulnerabilities);
    }

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

  // ════════════════════════════════════════════════════════════════════════════
  // DOCKER ENGINE
  // Called by: bin/docker.js
  // Scans an image's extracted filesystem rather than the CLI's cwd, so it
  // branches out here before resolvedRoot/manager/eng get built against cwd.
  // ════════════════════════════════════════════════════════════════════════════
  if (engine === "docker") {
    if (mode !== "health" && mode !== "check" && mode !== "install") {
      console.error(`[!] Invalid mode '${mode}' for the docker engine. Supported: health | check | install.`);
      console.error("[!] Usage: ubel-docker <health|check|install> <image|tar-path> [--no-pull] [--keep]");
      process.exit(1);
    }

    const [image, ...flags] = extraArgs;
    if (!image) {
      console.error("Usage: ubel-docker <health|check|install> <image|tar-path> [--no-pull] [--keep]");
      console.error("  e.g. ubel-docker health node:20-alpine");
      console.error("  e.g. ubel-docker check  node:20-alpine   # pull, scan, always remove the image after");
      console.error("  e.g. ubel-docker install node:20-alpine  # pull, scan, remove the image only if policy blocks it");
      console.error("  e.g. ubel-docker health /path/to/rootfs.tar  # scan a local tar directly, no docker pull/create/export");
      process.exit(1);
    }

    try {
      await dockerScan({
        image,
        mode,
        pull: !flags.includes("--no-pull"),
        keep: flags.includes("--keep"),
      });
    } catch (err) {
      if (err instanceof PolicyViolationError) {
        process.exit(1);
      }
      console.error("[!] Docker scan failed:", err.message);
      if (process.env.DEBUG) console.error(err.stack);
      process.exit(1);
    }
    return;
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

/**
 * dockerScan() — pulls (or reuses a local) image, extracts its filesystem to
 * a temp dir, and recurses into main()'s own programmatic path against that
 * dir with scan_os + full_stack forced on — same eng.scan() pipeline every
 * other engine goes through, just with an image's rootfs as projectRoot
 * instead of a repo checkout or the live host.
 *
 * `docker create` never runs the image's ENTRYPOINT/CMD, so this is safe to
 * point at an unvetted base image before it's pushed or deployed anywhere.
 *
 * The scan itself is identical across modes — mode only changes what happens
 * to the *pulled image* afterward, mirroring the npm/pnpm/bun health-check-
 * install split but adapted to "pull an image" having no dry-run equivalent
 * (there's nothing to resolve-without-writing the way a lockfile install
 * does — the image is either on the machine or it isn't):
 *   - health  — scan only. The image is left exactly as it was found.
 *   - check   — scan, then always `docker rmi` the image afterward,
 *               regardless of the policy decision. Nothing persists locally
 *               beyond the report.
 *   - install — scan, then `docker rmi` the image only if the scan resulted
 *               in a policy block. A clean scan leaves the image in place.
 *
 * @param {object}  opts
 * @param {string}  opts.image           Anything `docker pull`/`docker create` accepts,
 *                                       OR a path to a local, uncompressed .tar file
 *                                       (auto-detected — see DockerImageScanner). In the
 *                                       latter case `pull`/`--no-pull` has no effect and
 *                                       `check`/`install` skip image removal (nothing was
 *                                       pulled).
 * @param {boolean} [opts.pull=true]     Run `docker pull` first. Set false to scan an
 *                                       image that only exists locally (e.g. right
 *                                       after `docker build`, before it's pushed).
 * @param {boolean} [opts.keep=false]    Skip cleanup of the extracted rootfs, and skip
 *                                       any image removal check/install would otherwise
 *                                       do (debugging).
 * @param {"health"|"check"|"install"} [opts.mode="health"]
 * @returns {Promise<object>} same report shape main()/eng.scan() already returns.
 */
export async function dockerScan({ image, pull = true, keep = false, mode = "health", ...rest }) {
  if (!image) throw new Error("dockerScan requires an `image` reference");

  const scanner = new DockerImageScanner(image);
  let report;
  let violated = false;

  try {
    const rootDir = await scanner.extract({ pull });

    try {
      report = await main({
        projectRoot:  rootDir,
        engine:       "docker",
        mode:         "health", // the scan pipeline itself is the same regardless of CLI mode; only image retention differs below
        is_script:    false,
        save_reports: true,
        scan_os:      true,
        full_stack:   true,
        scan_scope:   "container-image",
        ...rest,
      });
    } catch (err) {
      if (err instanceof PolicyViolationError) violated = true;
      throw err; // still propagate so the CLI's own exit-code handling fires
    }
  } finally {
    if (keep) {
      console.log(`[docker] --keep set, leaving extracted rootfs at ${scanner.rootDir}`);
    } else {
      scanner.cleanup();
    }

    if (!keep) {
      if (mode === "check") {
        scanner.removeImage();
      } else if (mode === "install" && violated) {
        console.log("[docker] policy violation — removing image");
        scanner.removeImage();
      }
      // health, or install with no violation: image stays on the machine.
    }
  }

  return report;
}

export { main as SCA_scan };