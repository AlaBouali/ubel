#!/usr/bin/env node
/**
 * main.js — entry point for all ubel-node engines.
 *
 * ── CLI usage (called by bin/* wrappers) ──────────────────────────────────────
 *   node src/main.js <engine> <mode> [...extra_args]
 *
 *   engine    : npm | pnpm | bun | composer | docker | pip | pipx | uv | conda | cargo | apt | dnf | yum
 *   mode      : check | install | health | init | threshold | block-unknown | license-risk | license-block-unknown | install-hook | uninstall-hook
 *     license-risk and license-block-unknown are npm-family only — pip/pipx/uv/
 *     conda/cargo/apt/dnf/yum fall back to `health` for either (see PIP_LINUX_VALID_MODES).
 *     install-hook / uninstall-hook install/remove the git pre-commit hook that
 *     runs `<engine> health` (dependency scan only — no OS scan) on every
 *     commit that stages a dependency manifest/lockfile. Supported on every
 *     engine except docker and apt/dnf/yum.
 *
 *   Policy configuration modes:
 *     threshold <level>          — set severity_threshold (low|medium|high|critical|none)
 *     block-unknown <true|false> — set block_unknown_vulnerabilities
 *     license-risk <level>       — set license_risk_threshold (none|low|medium|high)
 *       Only ever enforced against `health`-mode scans (see engine.js /
 *       policy.js) — license risk is a compliance concern over software
 *       already installed on the machine, not an install-time security
 *       gate, so this has no effect on `check`/`install` scans regardless
 *       of the level set here. Defaults to "none" (not enforced).
 *     license-block-unknown <true|false> — set block_unknown_license_risk
 *       Separate from license-risk above: blocks packages whose license
 *       couldn't be classified at all, rather than a specific risk level.
 *       Same health-mode-only scope. Defaults to false.
 *
 *   Per-run policy flags (health | check | install, any engine except docker):
 *     --threshold <level>          — override severity_threshold for this run
 *     --block-unknown [true|false] — override block_unknown_vulnerabilities (bare = true)
 *     --license-risk <level>       — override license_risk_threshold   (npm-family only)
 *     --license-block-unknown [true|false] — override block_unknown_license_risk (npm-family only)
 *     --block-kev [true|false]     — override block_kev: block CISA KEV vulnerabilities (bare = true)
 *     --epss-threshold <value>     — override epss_threshold: block EPSS >= value. Accepts a
 *                                    fraction (0.1), a percentage (10%), or "none" to disable.
 *                                    A bare number above 1 is rejected (ambiguous: 10 vs 10%).
 *       `--flag value` and `--flag=value` both work, anywhere among the
 *       package args. Unlike the modes above, these are NOT saved: the policy
 *       file is snapshotted and restored on exit, so the persisted policy is
 *       identical before and after. e.g.
 *         node src/main.js npm check --threshold critical lodash
 *
 *   install-hook / uninstall-hook (any engine except docker and apt/dnf/yum):
 *     node src/main.js <engine> install-hook [--force]
 *     node src/main.js <engine> uninstall-hook
 *
 *     install-hook writes THE ubel git pre-commit hook (one hook, shared with
 *     `ubel-secrets --install-hook`; see precommit_hook.js). On every commit it
 *     runs `ubel-secrets --staged` and `<engine> health` (UBEL_HOOK_SCA=auto
 *     limits the latter to commits staging a package manifest or lockfile) — a dependency scan
 *     only (scan_os stays false, full_stack per engine defaults), never the OS
 *     scanner. Installing from either side keeps the other's step, in any
 *     order. uninstall-hook removes the hook. `--force` moves an existing
 *     foreign hook to pre-commit.local instead of refusing, and chains to it
 *     after the scans pass.
 *
 *     Bypass once with `git commit --no-verify`. Set UBEL_HOOK_STRICT=1 to make
 *     a missing ubel binary block the commit instead of warning and continuing.
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
 *   Pip/pipx/uv/conda/apt/dnf/yum mode (each gets its own dedicated bin/*.js —
 *   ubel-pip, ubel-pipx, ubel-uv, ubel-conda, ubel-apt, ubel-dnf, ubel-yum; no
 *   auto-detection between them, same one-binary-per-tool shape as
 *   npm/pnpm/bun):
 *     node src/main.js <pip|uv|conda> <health|check|install|init|threshold|block-unknown|install-hook|uninstall-hook> [packages...]
 *     node src/main.js cargo   <health|check|install|threshold|block-unknown|install-hook|uninstall-hook> [crate[@req]...]   (no init)
 *     node src/main.js pipx    <health|check|install|init|threshold|block-unknown|install-hook|uninstall-hook> <package>
 *     node src/main.js <apt|dnf|yum> <health|check|install|init|threshold|block-unknown> [packages...]                       (no hook modes)
 *
 *     `init` provisions a venv regardless of which of these six engines
 *     it's called on (mirrors __main__.py's _run_mode(), which does the
 *     same unconditionally) — uv gets its own project bootstrap (`uv init
 *     --bare` + `uv venv`); every other engine here, apt/dnf/yum included,
 *     still gets a stdlib `python -m venv`. That's a real Python venv
 *     getting created even for `ubel-apt init`/`ubel-dnf init`/`ubel-yum
 *     init` — ported as-is from the Python original's unconditional
 *     behavior, not something reconsidered here.
 *
 *     `install-hook`/`uninstall-hook` install the single ubel git pre-commit
 *     hook: secrets scan on every commit, plus `<engine> health` (dependency
 *     scan, no OS scan) on every commit. Not
 *     supported on apt/dnf/yum, which scan the host, not a repo.
 *
 *     pip/uv check/install with no package args fall back to
 *     ./requirements.txt, then ./pyproject.toml's [project] dependencies
 *     (see resolveDefaultPackages() in pypi_runner.js — installer-agnostic,
 *     works identically for both). apt/dnf/yum have no such fallback.
 *
 *     A real (non-dry-run) `install` — pip and uv alike — also syncs any
 *     requirements.txt/pyproject.toml already sitting in the project
 *     directory to reflect what's now actually installed, by re-running the
 *     same getInstalled() scan health mode uses and filtering to Python
 *     packages (see _syncDependencyFiles() in pypi_runner.js). Only updates
 *     files that already exist — never creates either one — and a sync
 *     failure is logged, not thrown, since the install itself already
 *     succeeded by that point.
 *
 *     pipx is CLI-tool isolation, not a shared project venv — each
 *     package gets its own venv under ~/.ubel/tools (or the platform
 *     equivalent) plus a global shim, via dryRunCli()/installCli() in
 *     pypi_runner.js rather than the initVenv()/runDryRun()/
 *     runRealInstall() path pip and uv use. No "uvx" equivalent is
 *     implemented — pipx always uses the pip-based isolation methods
 *     regardless of what else is installed.
 *
 *     conda (conda_runner.js) — `check`/`install` resolve with `conda create
 *     --dry-run --json` against a scratch prefix that never exists, so `check`
 *     creates nothing. A clean `install` then runs `conda create|install
 *     --no-deps --file <exact-pinned specs>` into <projectRoot>/conda-env (never
 *     `create` against an existing env). With no package args it falls back to
 *     ./environment.yml / ./environment.yaml; `init` creates an empty env there.
 *
 *     apt/dnf/yum write reports/policy under $HOME (~/.ubel/local/...) rather
 *     than the project-relative default, so invoking them never requires sudo —
 *     only the real `apt/dnf/yum install` itself is escalated, and only for
 *     `install` mode.
 *
 * ── Ubel's own files stay out of git and docker contexts ─────────────────────
 *   Before anything else runs — policy init, dry-runs, report writes, docker
 *   extraction — main.js makes sure `.gitignore` and `.dockerignore` in the
 *   working directory ignore `.ubel/` and `.ubelignore` (creating either file
 *   if missing). This lives HERE, at the entry point, and nowhere in the
 *   scanners: secrets.js / secrets_cli.js / secrets_git.js / secrets_hook.js
 *   never touch those files. See ignore_files.js for the exact rules
 *   (idempotent, append-only, honours `!.ubelignore`, never throws).
 *
 *     CLI           the cwd, for every engine except apt/dnf/yum — those keep
 *                   their reports and policy under $HOME/.ubel, not in the
 *                   project. docker is covered: its `.ubel/<uuid>` scratch
 *                   space is created in the cwd.
 *     programmatic  `projectRoot`, except for docker (projectRoot is the
 *                   extracted image rootfs — dockerScan() ensures the cwd
 *                   instead) and the `container-image` / `developer_platform`
 *                   scopes (the latter targets $HOME).
 *     ubel-secrets  ensureUbelIgnoreFilesForSecrets(argv), exported below, is
 *                   meant to be called by bin/secrets.js BEFORE
 *                   handleSecretsCli(): that path never reaches main().
 *   Opt out with UBEL_NO_IGNORE_FILES=1.
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
 *     scan_secrets        : true,   // default true
 *     scan_vulns          : true,   // default true; false skips all OSV/NVD lookups (ubel-license)
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
 *   composer — yes (`composer require/update --no-install --no-scripts` dry-run; vendor/ untouched)
 *   flutter/dart — no  (pub's dry-run prints a plan, not an installable candidate lockfile, so the scanned set can't be installed exactly)
 *   swift  — no   (SwiftPM has no dry-run: resolving clones the repo and evaluates its Package.swift, i.e. runs code)
 *   docker — yes  (health/check/install all supported; see Docker mode above)
 *   pip    — yes  (`pip install --dry-run --report`; real install syncs requirements.txt/pyproject.toml after)
 *   uv     — yes  (`uv pip install --dry-run`; same post-install manifest sync as pip)
 *   pipx   — yes  (isolated per-tool venv via dryRunCli()/installCli(), not the shared project venv)
 *   conda  — yes  (`conda create --dry-run --json` against a scratch prefix; exact-pinned `--no-deps` real install)
 *   cargo  — yes  (`cargo add` + `cargo update --workspace` in a scratch copy of the project; `cargo fetch --locked` real install)
 *   apt/dnf/yum — yes (native OS package-manager dry-run; each engine bound to exactly one manager)
 */

import path from "path";
import os from "os";
import { UbelEngineInstance, PolicyViolationError } from "./engine.js";
import { NodeManagerInstance }  from "./node_runner.js";
import { PhpComposerScanner }   from "./php_runner.js";
import { PypiManagerInstance }  from "./pypi_runner.js";
import { CondaManagerInstance } from "./conda_runner.js";
import { CargoManagerInstance } from "./cargo_runner.js";
import { LinuxManagerInstance } from "./linux_runner.js";
import { banner }               from "./info.js";
import { loadEnvironment }       from "./utils.js";
import { DockerImageScanner }    from "./docker_runner.js";
import { ensureUbelIgnoreEntries } from "./ignore_files.js";
import { installHook as installScaHook, uninstallHook as uninstallScaHook } from "./sca_hook.js";

import fs from 'node:fs/promises';
import { readFileSync, writeFileSync } from "node:fs";

async function createTargetPath(dirPath) {
  try {
    await fs.mkdir(dirPath, { recursive: true });
    console.log('Path created successfully!');
  } catch (err) {
    console.error('Error creating path:', err);
  }
}

// ── .gitignore / .dockerignore guard ──────────────────────────────────────────
// Scopes whose projectRoot is NOT a directory that holds (or should hold) a
// `.ubel/` of its own: an extracted image rootfs, and the developer's $HOME.
const NO_IGNORE_FILE_SCOPES = new Set(["container-image", "developer_platform"]);

/**
 * Make sure `.gitignore` and `.dockerignore` in `dir` ignore `.ubel/` and
 * `.ubelignore`. Called once, first thing, by every entry point in this file.
 * Never throws; cached per directory per process (see ignore_files.js).
 *
 * @param {string} dir
 * @param {{notify?: boolean}} [opts]  notify: print one stderr line per changed file.
 */
export function ensureUbelIgnoreFiles(dir, { notify = false } = {}) {
  return ensureUbelIgnoreEntries(dir, { notify });
}

/**
 * Same guard for the `ubel-secrets` CLI, whose extra flags (--history,
 * --staged, --install-hook, ...) are handled by handleSecretsCli() without
 * ever reaching main(). bin/secrets.js should call this with process.argv.slice(2)
 * before handleSecretsCli(argv).
 *
 * Skipped for `--staged` (runs inside `git commit`; mutating the tree there
 * would be surprising — --install-hook already did it) and `--uninstall-hook`.
 * `--json` keeps stderr quiet.
 *
 * @param {string[]} [argv=process.argv.slice(2)]
 */
export function ensureUbelIgnoreFilesForSecrets(argv = process.argv.slice(2)) {
  const flags = new Set(argv.filter(a => a.startsWith("-")).map(a => a.split("=")[0]));
  if (flags.has("--staged") || flags.has("--uninstall-hook")) return null;
  const target = argv.find(a => !a.startsWith("-")) || process.cwd();
  return ensureUbelIgnoreFiles(target, { notify: !flags.has("--json") });
}

const VALID_MODES      = [
  "check", "install", "health", "init",
  "threshold", "block-unknown", "license-risk", "license-block-unknown",
  "install-hook", "uninstall-hook",
];
const VALID_SEVERITIES = new Set(["low", "medium", "high", "critical", "none"]);
const VALID_LICENSE_RISKS = new Set(["none", "low", "medium", "high"]);

// ── Engines that support lockfile-only dry-runs ───────────────────────────────
// composer joins this set via `--no-install`, composer's own equivalent of
// npm's `--package-lock-only` — see php_runner.js's ENGINE_CONFIG.
const CHECK_INSTALL_ENGINES = new Set(["npm", "pnpm", "bun", "composer"]);

// pip/pipx/uv/apt/dnf/yum are dispatched through their own dedicated CLI
// branch below (mirroring __main__.py's _run_mode), not through the
// npm-family path, so they're intentionally NOT added to
// CHECK_INSTALL_ENGINES above.
const PYPI_ENGINES  = new Set(["pip", "pipx", "uv", "conda"]);
// Each of ubel-apt/ubel-dnf/ubel-yum targets exactly one native package
// manager — no auto-detection across the three, same as ubel-npm never
// guesses whether you meant pnpm.
const LINUX_ENGINES = new Set(["apt", "dnf", "yum"]);

// Engines that can install a git pre-commit hook. Excludes docker (no repo
// checkout to scan) and apt/dnf/yum (they scan the host, not a repo). The
// hook runs `<engine> health`, which for all of these is a dependency scan
// with scan_os forced off — never the OS scanner.
const HOOK_ENGINES = new Set([
  "npm", "pnpm", "bun", "yarn", "composer",
  "pip", "pipx", "uv", "conda",
  "cargo",
]);

// ── Per-run policy flags ──────────────────────────────────────────────────────
// `--threshold high`, `--block-unknown`, etc. override a policy field for the
// current invocation ONLY. Unlike the `threshold`/`block-unknown`/... modes,
// nothing is left behind in the policy file afterwards.
// `license` fields are npm-family only, mirroring the license-risk /
// license-block-unknown modes.
const POLICY_FLAGS = {
  "--threshold":             { field: "severity_threshold",            type: "severity" },
  "--block-unknown":         { field: "block_unknown_vulnerabilities", type: "boolean"  },
  "--license-risk":          { field: "license_risk_threshold",        type: "license",  license: true },
  "--license-block-unknown": { field: "block_unknown_license_risk",    type: "boolean",  license: true },
  "--block-kev":             { field: "block_kev",                       type: "boolean"  },
  "--epss-threshold":        { field: "epss_threshold",                  type: "epss"     },
};

/**
 * Parse an EPSS threshold into the stored form: a fraction in (0, 1], or "none".
 * `0.1` and `10%` both mean 10%. Returns undefined when invalid.
 */
function parseEpssThresholdArg(raw) {
  if (raw === "none") return "none";
  const m = /^(\d*\.?\d+)(%?)$/.exec(raw);
  if (!m) return undefined;
  const n = m[2] ? parseFloat(m[1]) / 100 : parseFloat(m[1]);
  return (n > 0 && n <= 1) ? n : undefined;
}

/**
 * Pull policy flags out of the CLI args, leaving package specifiers (and any
 * flag we don't recognise) untouched. Accepts `--flag value` and `--flag=value`;
 * boolean flags may also be bare (`--block-unknown` === `--block-unknown true`).
 * Exits 1 on an invalid or unsupported flag/value.
 *
 * @returns {{ rest: string[], overrides: Object<string, string|boolean> }}
 */
function parsePolicyFlags(args, { license }) {
  const rest = [];
  const overrides = {};
  const die = (msg) => { console.error(`[!] ${msg}`); process.exit(1); };

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const eq   = arg.startsWith("--") ? arg.indexOf("=") : -1;
    const name = eq === -1 ? arg : arg.slice(0, eq);
    const def  = POLICY_FLAGS[name];
    if (!def) { rest.push(arg); continue; }

    if (def.license && !license) {
      die(`${name} is only available on npm/pnpm/bun/yarn/composer.`);
    }

    let raw = eq === -1 ? undefined : arg.slice(eq + 1);
    if (raw === undefined) {
      const next = args[i + 1];
      if (def.type === "boolean") {
        if (next !== undefined && /^(true|false)$/i.test(next)) { raw = next; i++; }
        else raw = "true";
      } else {
        raw = next;
        i++;
      }
    }
    raw = (raw ?? "").toLowerCase();

    if (def.type === "severity") {
      if (!VALID_SEVERITIES.has(raw)) die(`${name} requires: low | medium | high | critical | none`);
      overrides[def.field] = raw;
    } else if (def.type === "license") {
      if (!VALID_LICENSE_RISKS.has(raw)) die(`${name} requires: none | low | medium | high`);
      overrides[def.field] = raw;
    } else if (def.type === "epss") {
      const v = parseEpssThresholdArg(raw);
      if (v === undefined) die(`${name} requires: a fraction in (0, 1] (e.g. 0.1), a percentage (e.g. 10%), or none`);
      overrides[def.field] = v;
    } else {
      if (raw !== "true" && raw !== "false") die(`${name} requires: true | false`);
      overrides[def.field] = raw === "true";
    }
  }
  return { rest, overrides };
}

/**
 * Apply per-run policy overrides without leaving them behind. The policy file
 * is snapshotted, the overrides applied through the normal setPolicyField()
 * path (so the engine sees them exactly as it would a saved policy), and the
 * original bytes are written back on process exit — which covers a clean
 * finish, a policy-violation exit(1), a scan failure, and Ctrl-C alike.
 */
function applyPolicyOverrides(eng, overrides) {
  const entries = Object.entries(overrides);
  if (!entries.length) return;

  const policyFile = path.join(eng.policyDir, "config.json");
  let original;
  try {
    original = readFileSync(policyFile);
  } catch (err) {
    // Refuse rather than risk silently persisting an override we can't undo.
    console.error(`[!] Can't apply policy flags: unable to read ${policyFile} (${err.message}).`);
    process.exit(1);
  }

  let restored = false;
  const restore = () => {
    if (restored) return;
    restored = true;
    try { writeFileSync(policyFile, original); }
    catch (err) { console.error(`[!] Failed to restore policy file ${policyFile}: ${err.message}`); }
  };
  process.on("exit", restore);
  process.on("SIGINT",  () => process.exit(130));
  process.on("SIGTERM", () => process.exit(143));

  for (const [field, value] of entries) eng.setPolicyField(field, value);
  console.log(`[i] Policy overrides for this run only (saved policy unchanged): ${entries.map(([k, v]) => `${k} = ${v}`).join(", ")}`);
  console.log();
}

/**
 * Resolve the right manager instance + systemType grouping for an engine
 * name. Keeps "systemType" meaning one of exactly three ecosystem buckets
 * ("npm" | "pypi" | "linux") everywhere engine.js reads it, regardless of
 * which specific package manager (npm/pnpm/bun, pip/pipx/uv, or
 * apt/dnf/yum) is actually in play.
 */
function resolveManager(engine) {
  if (engine === "cargo") {
    // Own systemType bucket: the cargo firewall resolves in a scratch copy of
    // the project (no lockfile backup/revert like npm, no venv like pypi) —
    // see cargo_runner.js.
    return { manager: new CargoManagerInstance(), systemType: "cargo" };
  }
  if (engine === "conda") {
    // conda shares the "pypi" systemType bucket (engine.js's dry-run → scan →
    // gated-install branch for the Python family) but is its own manager
    // class — see conda_runner.js for why it isn't another PypiManagerInstance
    // installer mode.
    return { manager: new CondaManagerInstance(), systemType: "pypi" };
  }
  if (PYPI_ENGINES.has(engine)) {
    // pipx has no "uvx" equivalent implemented here — its CLI-isolation
    // methods (dryRunCli/installCli) are pip-only regardless of engine, so
    // it always gets the "pip" installer; "uv" gets its own installer mode,
    // and "pip" is PypiManagerInstance's own default.
    const installer = engine === "uv" ? "uv" : "pip";
    return { manager: new PypiManagerInstance(installer), systemType: "pypi" };
  }
  if (LINUX_ENGINES.has(engine)) {
    return { manager: new LinuxManagerInstance(engine), systemType: "linux" };
  }
  if (engine === "composer") {
    // PhpComposerScanner implements the same runDryRun/revert_lock_to_
    // original/runRealInstall/saveCandidateLockfile/cleanupLockfileBackup
    // contract as NodeManagerInstance, so it shares the "npm" systemType
    // bucket (engine.js's lockfile-based dry-run/verify/revert/install
    // path) rather than getting a fourth bucket of its own.
    return { manager: new PhpComposerScanner(), systemType: "npm" };
  }
  return { manager: new NodeManagerInstance(), systemType: "npm" };
}

/**
 * Handle `install-hook` / `uninstall-hook`. Installs / removes a git
 * pre-commit hook that runs `<engine> health` — a dependency scan only,
 * never the OS scanner (the health-mode CLI path forces scan_os: false).
 * Exits the process.
 *
 * @param {string}   engine
 * @param {"install-hook"|"uninstall-hook"} mode
 * @param {string[]} extraArgs
 */
async function handleHookMode(engine, mode, extraArgs) {
  const resolvedRoot = path.resolve(process.cwd());
  const binName      = `ubel-${engine}`;

  try {
    if (mode === "install-hook") {
      const force = extraArgs.includes("--force");
      const r = await installScaHook(resolvedRoot, {
        force,
        binPath: process.argv[1],
        nodePath: process.execPath,
        binName,
      });
      console.log(`${r.replaced ? "Updated" : "Installed"} pre-commit hook: ${r.hookFile}`);
      if (r.migrated) console.log("Merged an older ubel hook (pre-commit.local) into this one and removed it.");
      if (r.chained) {
        console.log(`Your existing hook was moved to ${r.localFile}; it still runs after the ubel scans.`);
      }
      if (r.portable) {
        console.log(
          `This hooks directory is outside .git (core.hooksPath), so the hook finds \`${binName}\` on PATH\n` +
          "instead of embedding this machine's paths. Every contributor needs it installed."
        );
      }
      console.log();
      console.log("One hook, two scans. On every commit it runs `ubel-secrets --staged` and");
      console.log(`\`${binName} health\` (dependency scan only — no OS scan).`);
      console.log("UBEL_HOOK_SCA=auto|off limits it to commits staging a manifest/lockfile, or disables it.");
      console.log("Skip once with `git commit --no-verify`; hooks are local, so also run the scan in CI.");
    } else {
      const r = await uninstallScaHook(resolvedRoot);
      console.log(r.removed
        ? `Removed ${r.hookFile}${r.restored ? " and restored your previous hook." : "."}`
        : `No pre-commit hook at ${r.hookFile}; nothing to remove.`);
    }
  } catch (err) {
    console.error(`[!] ${err.message}`);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
  process.exit(0);
}

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
 * @param {string}  [programmaticOptions.engine="npm"]         "npm"|"pnpm"|"bun"|"yarn"|"composer"|"docker"|"pip"|"pipx"|"uv"|"conda"|"cargo"|"apt"|"dnf"|"yum".
 * @param {string}  [programmaticOptions.mode="health"]        Scan mode.
 * @param {boolean} [programmaticOptions.is_script=true]
 * @param {boolean} [programmaticOptions.save_reports=true]
 * @param {boolean} [programmaticOptions.scan_os=false]
 * @param {boolean} [programmaticOptions.full_stack=false]
 * @param {boolean} [programmaticOptions.scan_node=true]
 * @param {string}  [programmaticOptions.venvDir]              engine:"pip"|"uv"|"pipx"|"conda" only — overrides the default
 *   `<projectRoot>/venv` (`<projectRoot>/conda-env` for conda) used for check/install dry-run and real install
 *   (engine.js's systemType==="pypi" branch). Also read by `init` mode for ANY of pip/pipx/uv/apt/dnf/yum (see the CLI usage note above) —
 *   though only pip/uv/pipx's `init` actually provisions a Python venv there.
 * @param {string[]} [programmaticOptions.packages=[]]
 * @param {string}  [programmaticOptions.scan_scope="repository"]
 * @param {boolean} [programmaticOptions.scan_secrets=true]
 * @param {boolean} [programmaticOptions.scan_vulns=true]      When false, skips OSV/NVD entirely —
 *   no vulnerability network calls are made and `vulnerabilities` stays empty. Inventory and
 *   license classification are unaffected. Used by `ubel-license` for an inventory/license-only scan.
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
      scan_secrets        = true,
      scan_vulns          = true,
      venvDir             = undefined,
      severity_threshold = undefined,
      block_unknown_vulnerabilities = undefined,
      license_risk_threshold = undefined,
      block_unknown_license_risk = undefined,
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

    // Before the manager/engine are even built: keep .ubel/ and .ubelignore out
    // of git and docker contexts. docker's projectRoot is the extracted rootfs —
    // dockerScan() has already handled the cwd that actually holds .ubel/<uuid>.
    if (engine !== "docker" && !NO_IGNORE_FILE_SCOPES.has(scan_scope)) {
      ensureUbelIgnoreFiles(resolvedRoot);
    }

    // Construct fresh, isolated instances for this invocation.
    const { manager, systemType } = resolveManager(engine);
    const eng     = new UbelEngineInstance(manager, resolvedRoot);

    eng.engine     = engine;
    eng.systemType = systemType;
    eng.checkMode  = mode;
    // Only meaningful for engine: "pip" — overrides the default
    // `<projectRoot>/venv` venv location. Harmless no-op for every other
    // engine, since only the pypi collect/install branches read it.
    if (venvDir !== undefined) eng.venvDir = venvDir;

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

    if (license_risk_threshold !== undefined) {
      const level = String(license_risk_threshold).toLowerCase();
      if (!VALID_LICENSE_RISKS.has(level)) {
        throw new Error(`Invalid license_risk_threshold: ${license_risk_threshold}. Must be one of: none, low, medium, high`);
      }
      eng.setPolicyField("license_risk_threshold", level);
    }

    if (block_unknown_license_risk !== undefined) {
      if (typeof block_unknown_license_risk !== "boolean") {
        throw new Error(`block_unknown_license_risk must be a boolean, got ${typeof block_unknown_license_risk}`);
      }
      eng.setPolicyField("block_unknown_license_risk", block_unknown_license_risk);
    }

    return await eng.scan(packages, {
      is_script,
      save_reports,
      scan_os,
      full_stack,
      scan_node,
      is_vscanned_project,
      scan_scope,
      scan_secrets,
      scan_vulns,
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

  // Before anything else — policy init, dry-runs, report writes, docker
  // extraction: keep .ubel/ and .ubelignore out of git and docker contexts.
  // apt/dnf/yum are the exception: their reports and policy live under
  // $HOME/.ubel/local, so the cwd gets no .ubel/ from them. docker is NOT an
  // exception — its `.ubel/<uuid>` scratch space is created in the cwd.
  if (!LINUX_ENGINES.has(engine)) {
    ensureUbelIgnoreFiles(process.cwd(), { notify: true });
  }

  // ════════════════════════════════════════════════════════════════════════════
  // install-hook / uninstall-hook — git pre-commit hook for dependency scanning
  // Handled before the engine-specific branches below, since the hook runs
  // `<engine> health` (a dependency scan only — scan_os stays off) regardless
  // of which ecosystem the engine belongs to. Not applicable to docker (no
  // repo checkout) or apt/dnf/yum (they scan the host, not a repo).
  // ════════════════════════════════════════════════════════════════════════════
  if (mode === "install-hook" || mode === "uninstall-hook") {
    if (!HOOK_ENGINES.has(engine)) {
      console.error(`[!] ${mode} is not supported for the '${engine}' engine.`);
      console.error("[!] Supported engines: npm, pnpm, bun, yarn, composer, pip, pipx, uv, conda, cargo");
      process.exit(1);
    }
    await handleHookMode(engine, mode, extraArgs);
    return;
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

  // ════════════════════════════════════════════════════════════════════════════
  // PYPI (pip / pipx / uv) AND LINUX (apt / dnf / yum) ENGINES
  // Called by: bin/pip.js, bin/pipx.js, bin/uv.js, bin/apt.js, bin/dnf.js, bin/yum.js
  // Mirrors __main__.py's _run_mode() — a deliberately separate dispatch
  // path from the npm-family branch below rather than folded into it, since
  // these ecosystems differ in several specific ways: no license-risk /
  // license-block-unknown modes, `init` provisions a venv instead of being a
  // no-op, pip/uv fall back to ./requirements.txt (then ./pyproject.toml)
  // when no packages are given, apt/dnf/yum write reports/policy under
  // $HOME to avoid needing sudo, and full_stack/scan_os default to OFF (vs.
  // npm's health scan, which defaults full_stack to ON). apt/dnf/yum are
  // three separate engines here, each bound to exactly one native package
  // manager — same one-binary-per-tool shape as ubel-npm/ubel-pnpm/ubel-bun,
  // no auto-detection between them. uv is the fourth pypi-family engine:
  // same six modes, same requirements.txt/pyproject.toml fallback, same
  // real-install-via-generated-requirements-file behavior as pip — only the
  // dry-run mechanism differs internally (see pypi_runner.js).
  // ════════════════════════════════════════════════════════════════════════════
  if (PYPI_ENGINES.has(engine) || LINUX_ENGINES.has(engine) || engine === "cargo") {
    const PIP_LINUX_VALID_MODES = ["check", "install", "health", "init", "threshold", "block-unknown"];
    const scanScope =
      (engine === "pip" || engine === "uv" || engine === "conda" || engine === "cargo") ? "repository" :
      engine === "pipx" ? "cli_tool"   :
      "linux_machine"; // apt | dnf | yum

    const resolvedRoot = path.resolve(process.cwd());
    const { manager, systemType } = resolveManager(engine);
    const eng = new UbelEngineInstance(manager, resolvedRoot);

    // Same convention as npm/pnpm/bun: the binary's own name is the engine
    // identity. (engine.js still substitutes TOOL_NAME for `health` mode,
    // and the resolved apt/dnf/yum version for `check`/`install`, exactly
    // as it already does for npm/pnpm/bun — no special-casing needed here.)
    eng.engine     = engine;
    eng.systemType = systemType;

    if (LINUX_ENGINES.has(engine)) {
      // Reports & policy live under $HOME so ubel-apt/ubel-dnf/ubel-yum
      // never need sudo just to write their own output — only the real
      // `apt/dnf/yum install` itself is escalated. Must happen BEFORE
      // initiateLocalPolicy().
      eng.reportsLocation = path.join(os.homedir(), ".ubel", "local", "reports");
      eng.policyDir       = path.join(os.homedir(), ".ubel", "local", "policy");
    }

    eng.initiateLocalPolicy();

    console.log(banner);
    console.log(`Reports location: ${eng.reportsLocation}`);
    console.log();
    console.log(`Policy location: ${eng.policyDir}`);
    console.log();

    // cargo has no environment to provision, so `init` is rejected outright
    // instead of silently falling back to a health scan.
    if (engine === "cargo" && mode === "init") {
      console.error("[!] ubel-cargo has no init mode — there is no environment to create. Use check | install | health.");
      process.exit(1);
    }

    const effectiveMode = PIP_LINUX_VALID_MODES.includes(mode) ? mode : "health";
    eng.checkMode = effectiveMode;

    // ── init — provisions a venv regardless of engine, matching
    //    __main__.py's _run_mode(), which does the same unconditionally.
    //    uv gets its own project bootstrap (`uv init` + `uv venv`); every
    //    other pypi/linux-family engine still gets the stdlib venv. ──
    if (effectiveMode === "init") {
      const venvDir = eng.venvDir || path.join(resolvedRoot, engine === "conda" ? "conda-env" : "venv");
      if (engine === "conda") {
        new CondaManagerInstance().initCondaEnv(venvDir);
      } else if (engine === "uv") {
        new PypiManagerInstance("uv").initUvVenv(venvDir);
      } else {
        new PypiManagerInstance().initVenv(venvDir);
      }
      process.exit(0);
    }

    // ── threshold <level> ─────────────────────────────────────────────────
    if (effectiveMode === "threshold") {
      const level = (extraArgs[0] || "").toLowerCase();
      if (!level || !VALID_SEVERITIES.has(level)) {
        console.error("[!] Provide a valid severity level: low | medium | high | critical | none");
        console.error(`[!] Example: ubel-${engine} threshold high`);
        process.exit(1);
      }
      eng.setPolicyField("severity_threshold", level);
      console.log(`[+] Policy updated: severity_threshold = ${level}`);
      console.log("[i] Infections are always blocked regardless of this setting.");
      process.exit(0);
    }

    // ── block-unknown <true|false> ────────────────────────────────────────
    if (effectiveMode === "block-unknown") {
      const raw = (extraArgs[0] || "").toLowerCase();
      if (raw !== "true" && raw !== "false") {
        console.error("[!] Provide true or false");
        console.error(`[!] Example: ubel-${engine} block-unknown true`);
        process.exit(1);
      }
      const value = raw === "true";
      eng.setPolicyField("block_unknown_vulnerabilities", value);
      console.log(`[+] Policy updated: block_unknown_vulnerabilities = ${value}`);
      process.exit(0);
    }

    // ── collect package args ────────────────────────────────────────────────
    // Per-run policy flags (--threshold, --block-unknown) are peeled off first
    // so they're never mistaken for package specifiers.
    const { rest: pkgArgsRaw, overrides: policyOverrides } = parsePolicyFlags(extraArgs, { license: false });
    applyPolicyOverrides(eng, policyOverrides);
    let pkgArgs = pkgArgsRaw;

    // pip/uv check/install with no args → fall back to ./requirements.txt,
    // then ./pyproject.toml's [project] dependencies (manager owns both —
    // see resolveDefaultPackages() in pypi_runner.js; it's installer-
    // agnostic, so this works identically for pip and uv).
    if (!pkgArgs.length && (engine === "pip" || engine === "uv" || engine === "conda") && (effectiveMode === "check" || effectiveMode === "install")) {
      const resolved = manager.resolveDefaultPackages(resolvedRoot);
      if (!resolved) {
        console.error(engine === "conda"
          ? "[!] No package arguments, and no environment.yml or environment.yaml found."
          : "[!] No package arguments, and no requirements.txt or pyproject.toml found.");
        process.exit(1);
      }
      pkgArgs = resolved;
    }

    // ── remote mode guard ────────────────────────────────────────────────────
    const { apiKey, assetId } = loadEnvironment();
    if (apiKey && assetId) {
      console.error("[!] Remote mode (UBEL_API_KEY + UBEL_ASSET_ID) is not yet implemented in the Node CLI.");
      process.exit(1);
    }

    // ── scan ─────────────────────────────────────────────────────────────────
    try {
      await eng.scan(pkgArgs, {
        is_script:    false,
        save_reports: true,
        scan_os:      false,
        full_stack:   false,
        scan_venv:    true,
        scan_scope:   scanScope,
      });
    } catch (err) {
      if (err instanceof PolicyViolationError) {
        process.exit(1);
      }
      console.error("[!] Scan failed:", err.message);
      if (process.env.DEBUG) console.error(err.stack);
      process.exit(2); // 1 = policy violation, 2 = the scan did not complete (the pre-commit hook relies on this)
    }
    return;
  }

  // The CLI always operates in the current working directory.
  const resolvedRoot = path.resolve(process.cwd());

  // Construct fresh instances for this CLI invocation.
  const { manager, systemType } = resolveManager(engine);
  const eng     = new UbelEngineInstance(manager, resolvedRoot);

  eng.engine     = engine;
  eng.systemType = systemType;

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

  // ── license-risk <level> ─────────────────────────────────────────────────────
  if (effectiveMode === "license-risk") {
    const level = (extraArgs[0] || "").toLowerCase();
    if (!level || !VALID_LICENSE_RISKS.has(level)) {
      console.error("[!] Provide a valid license risk level: none | low | medium | high");
      console.error("[!] Example: ubel-npm license-risk high");
      process.exit(1);
    }
    eng.setPolicyField("license_risk_threshold", level);
    console.log(`[+] Policy updated: license_risk_threshold = ${level}`);
    console.log("[i] Only enforced against `health`-mode scans — installed-software audits, not check/install gating.");
    process.exit(0);
  }

  // ── license-block-unknown <true|false> ───────────────────────────────────────
  if (effectiveMode === "license-block-unknown") {
    const raw = (extraArgs[0] || "").toLowerCase();
    if (raw !== "true" && raw !== "false") {
      console.error("[!] Provide true or false");
      console.error("[!] Example: ubel-npm license-block-unknown true");
      process.exit(1);
    }
    const value = raw === "true";
    eng.setPolicyField("block_unknown_license_risk", value);
    console.log(`[+] Policy updated: block_unknown_license_risk = ${value}`);
    console.log("[i] Only enforced against `health`-mode scans, and separate from license-risk — this blocks packages whose license couldn't be classified at all, not a specific risk level.");
    process.exit(0);
  }

  // ── check/install require lockfile-only dry-run support ─────────────────────
  if (!CHECK_INSTALL_ENGINES.has(engine) && (effectiveMode === "check" || effectiveMode === "install")) {
    console.error(`[!] '${engine}' is not supported.`);
    console.error("[!] Supported engines: npm, pnpm, bun, composer");
    process.exit(1);
  }

  // ── validate package specifiers early ───────────────────────────────────────
  // Per-run policy flags are peeled off first so they're never mistaken for
  // package specifiers, and applied without touching the saved policy.
  const { rest: pkgArgsRaw, overrides: policyOverrides } = parsePolicyFlags(extraArgs, { license: true });
  applyPolicyOverrides(eng, policyOverrides);
  let pkgArgs = pkgArgsRaw;
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
    process.exit(2); // 1 = policy violation, 2 = the scan did not complete (the pre-commit hook relies on this)
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

  // The extracted rootfs lives at <cwd>/.ubel/<uuid> (see DockerImageScanner),
  // so it is the cwd — not the rootfs main() is pointed at — that needs the
  // ignore entries, and they must exist before anything is pulled or extracted.
  // No-op when the CLI branch already did it (cached per directory).
  ensureUbelIgnoreFiles(process.cwd());

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
        // The rootfs (and the .ubel inside it) is thrown away after the scan,
        // so the project id lives in the cwd's .ubel, next to <uuid>/ scratch.
        project_ubel_dir: path.join(process.cwd(), ".ubel"),
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