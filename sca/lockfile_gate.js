// lockfile_gate.js
//
// "Lockfile required" firewall rules for the ecosystems that have no dry-run
// resolution UBEL can safely drive (yarn, Bundler, Go, .NET, Dart, Flutter,
// SwiftPM). Where npm/pnpm/bun/composer/pip/cargo/... resolve a candidate
// lockfile first and scan that, these engines refuse to guess:
//
//   check    the lockfile MUST already exist. Its pinned packages are read
//            (exactly the lockfile parsers `health` uses), looked up and run
//            through the policy. Nothing is installed or written.
//   install  same scan, and only if the policy passes the pinned set is
//            installed — by the ecosystem's frozen/locked install command, so
//            the installer cannot resolve anything that wasn't scanned.
//
// No lockfile (or an empty one, or no manifest to install from) → the
// installation is refused before any package manager runs. Package arguments
// are refused too: adding a package means resolving, which is exactly what is
// not gated here. Add it with your package manager, review and commit the
// lockfile, then run `ubel-<engine> check|install` with no arguments.
//
// Ecosystems NOT covered, on purpose:
//   Maven   has no lockfile at all.
//   Gradle  dependency locking is opt-in and Gradle has no install step
//           separate from a build, so there is no frozen "install" to gate.
//   CocoaPods / Carthage are not gated (SwiftPM's Package.resolved is).
//
// This module has no imports besides fs/path so engine.js, node_runner.js,
// main.js and lockfile_runner.js can all depend on it without a cycle.

import fs   from "fs";
import path from "path";

export class LockfileGateError extends Error {
  constructor(message, { engine, problems = [] } = {}) {
    super(message);
    this.name     = "LockfileGateError";
    this.engine   = engine;
    this.problems = problems;
  }
}

const DOTNET_PROJECT_RE = /\.(cs|fs|vb)proj$|\.slnx?$|\.proj$/i;

/**
 * One entry per gated engine.
 *
 *   label      human name used in messages
 *   binary     the real package-manager binary the install runs
 *   lockfiles  files that ALL must exist (and be non-empty) — the pinned set
 *   manifest   { names: [...] } or { pattern: RegExp } — what the install
 *              reads next to the lockfile; at least one must exist
 *   create     how the lockfile is normally created (shown when it is missing)
 *   family     "node" → scanned/installed by NodeManagerInstance (node_runner.js)
 *              "lockfile" → scanned/installed by LockfileGateManager (lockfile_runner.js)
 */
export const LOCKFILE_GATE = Object.freeze({
  yarn: {
    label: "Yarn", binary: "yarn", family: "node",
    lockfiles: ["yarn.lock"],
    manifest:  { names: ["package.json"] },
    create:    "yarn install (Yarn 2+: yarn install --mode=update-lockfile)",
  },
  bundle: {
    label: "Bundler", binary: "bundle", family: "lockfile",
    lockfiles: ["Gemfile.lock"],
    manifest:  { names: ["Gemfile"] },
    create:    "bundle lock",
  },
  go: {
    label: "Go modules", binary: "go", family: "lockfile",
    lockfiles: ["go.sum"],
    manifest:  { names: ["go.mod"] },
    create:    "go mod tidy",
  },
  dotnet: {
    label: ".NET / NuGet", binary: "dotnet", family: "lockfile",
    lockfiles: ["packages.lock.json"],
    manifest:  { pattern: DOTNET_PROJECT_RE },
    create:    "dotnet restore --use-lock-file",
  },
  dart: {
    label: "Dart (pub)", binary: "dart", family: "lockfile",
    lockfiles: ["pubspec.lock"],
    manifest:  { names: ["pubspec.yaml"] },
    create:    "dart pub get",
  },
  flutter: {
    label: "Flutter (pub)", binary: "flutter", family: "lockfile",
    lockfiles: ["pubspec.lock"],
    manifest:  { names: ["pubspec.yaml"] },
    create:    "flutter pub get",
  },
  swift: {
    label: "SwiftPM", binary: "swift", family: "lockfile",
    lockfiles: ["Package.resolved"],
    manifest:  { names: ["Package.swift"] },
    create:    "swift package resolve",
  },
});

/** Engines whose check/install requires a lockfile (yarn included). */
export const LOCKFILE_GATED_ENGINES = new Set(Object.keys(LOCKFILE_GATE));

/** Gated engines handled by LockfileGateManager (everything except yarn). */
export const LOCKFILE_MANAGER_ENGINES = new Set(
  Object.entries(LOCKFILE_GATE).filter(([, c]) => c.family === "lockfile").map(([e]) => e)
);

export const isLockfileGated = (engine) => LOCKFILE_GATED_ENGINES.has(engine);

function isNonEmptyFile(file) {
  try {
    const st = fs.statSync(file);
    return st.isFile() && st.size > 0;
  } catch {
    return false;
  }
}

/** Absolute paths of the manifest file(s) the install reads in `root`. */
export function findManifests(engine, root) {
  const cfg = LOCKFILE_GATE[engine];
  if (!cfg) return [];
  if (cfg.manifest.names) {
    return cfg.manifest.names.map(n => path.join(root, n)).filter(f => fs.existsSync(f));
  }
  let entries = [];
  try { entries = fs.readdirSync(root, { withFileTypes: true }); } catch { /* unreadable */ }
  return entries
    .filter(e => e.isFile() && cfg.manifest.pattern.test(e.name))
    .map(e => path.join(root, e.name))
    .sort();
}

/**
 * Inspect `root` against the gate for `engine`. Never throws.
 *
 * @returns {{ ok: boolean, problems: string[], lockfiles: string[], manifests: string[] }}
 */
export function checkLockfileGate(engine, root, args = []) {
  const cfg = LOCKFILE_GATE[engine];
  if (!cfg) {
    return { ok: false, problems: [`'${engine}' is not a lockfile-gated engine.`], lockfiles: [], manifests: [] };
  }

  const problems = [];
  const abs = path.resolve(root);

  const extra = (args || []).filter(a => a !== "--");
  if (extra.length) {
    problems.push(
      `package argument(s) not allowed (${extra.join(", ")}): ubel-${engine} only installs what ${cfg.lockfiles.join(" + ")} ` +
      `already pins, because resolving a new package is not something it can gate. Add the package with ` +
      `${cfg.binary}, review and commit the updated lockfile, then run ubel-${engine} again without arguments.`
    );
  }

  const manifests = findManifests(engine, abs);
  if (!manifests.length) {
    const want = cfg.manifest.names ? cfg.manifest.names.join(" or ") : "a .NET project or solution file";
    problems.push(`no ${want} found in ${abs} — there is nothing to install here.`);
  }

  const lockfiles = [];
  for (const name of cfg.lockfiles) {
    const file = path.join(abs, name);
    if (isNonEmptyFile(file)) {
      lockfiles.push(file);
    } else if (fs.existsSync(file)) {
      problems.push(`${name} exists in ${abs} but is empty or not a regular file.`);
    } else {
      problems.push(
        `${name} not found in ${abs}. The ${cfg.label} firewall only installs from a lockfile, so the exact ` +
        `packages are known and scanned before anything is installed. Create it in a trusted environment ` +
        `(${cfg.create}), review it, commit it, then run ubel-${engine} again.`
      );
    }
  }

  return { ok: problems.length === 0, problems, lockfiles, manifests };
}

/**
 * Package arguments are never accepted by a lockfile-gated engine, in ANY scan mode
 * (check, install, or health): they would mean "resolve and add this package", which is not
 * something these engines can gate. A bare `--` separator is ignored.
 * @throws {LockfileGateError}
 */
export function assertNoPackageArgs(engine, args = []) {
  const cfg   = LOCKFILE_GATE[engine];
  const extra = (args || []).filter(a => a !== "--");
  if (!cfg || !extra.length) return;
  const msg =
    `package argument(s) not allowed (${extra.join(", ")}): ubel-${engine} works on the project in the current ` +
    `directory and takes no package names. Add the package with ${cfg.binary}, review and commit the updated ` +
    `lockfile, then run ubel-${engine} again without arguments.`;
  throw new LockfileGateError(`Refused (${cfg.label}): ${msg}`, { engine, problems: [msg] });
}

/**
 * Throwing form of checkLockfileGate().
 * @throws {LockfileGateError}
 */
export function assertLockfileGate(engine, root, args = []) {
  const r = checkLockfileGate(engine, root, args);
  if (!r.ok) {
    throw new LockfileGateError(
      `Installation refused (${LOCKFILE_GATE[engine]?.label ?? engine}): ${r.problems.join(" ")}`,
      { engine, problems: r.problems }
    );
  }
  return r;
}
