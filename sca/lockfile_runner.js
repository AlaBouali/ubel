// lockfile_runner.js
//
// Lockfile-required firewall for `ubel-bundle`, `ubel-go`, `ubel-dotnet`,
// `ubel-dart`, `ubel-flutter` and `ubel-swift` — the ecosystems that have no
// dry-run resolution UBEL can safely drive (see lockfile_gate.js for the rules
// and for what is deliberately not covered). Built on the ecosystem scanners
// that `health` already uses, so lockfile parsing, scopes and PURLs are shared:
//
//   runDryRun(args, root, {install})  → refuses unless the lockfile exists,
//                                       then reads exactly the packages it pins
//                                       (the "health" scan of the lockfile) and
//                                       fingerprints lockfile + manifest
//   runRealInstall(root)              → re-checks the fingerprints, then runs the
//                                       ecosystem's frozen / locked install
//   getInstalled(startDir)            → `health` mode (the scanner's own walk)
//
// Why "frozen" installs: the scanned lockfile IS what gets installed. Each
// command below fails instead of resolving something that wasn't scanned, and
// none of them is allowed to rewrite the lockfile — if one does anyway, the
// original bytes are put back and the install is reported as failed.
//
//   bundle    BUNDLE_FROZEN=true bundle install
//   go        GOFLAGS=-mod=readonly go mod download      (verifies against go.sum)
//   dotnet    dotnet restore --locked-mode
//   dart      dart pub get --enforce-lockfile
//   flutter   flutter pub get --enforce-lockfile
//   swift     swift package resolve --force-resolved-versions
//
// What this does NOT stop (be honest about it):
//   * Only the scan runs before the install. Installers that execute package
//     code at install time (Bundler native extensions, SwiftPM manifests, MSBuild
//     targets shipped in NuGet packages) do so after the scan has passed — the
//     scan is what protects you, not a sandbox. yarn is the one that can skip
//     lifecycle scripts, and does (see node_runner.js).
//   * Packages that aren't from the ecosystem's default registry (git / path /
//     URL sources) cannot be matched against OSV; they surface as "undetermined"
//     and block under the default block_undetermined policy.
//
// Zero third-party runtime dependencies (Node stdlib only).

import fs     from "fs";
import path   from "path";
import crypto from "crypto";
import { spawnSync } from "child_process";

import { RubyBundlerScanner } from "./ruby_runner.js";
import { GoModScanner }       from "./go_runner.js";
import { CSharpNuGetScanner } from "./csharp_runner.js";
import { FlutterPubScanner }  from "./flutter_runner.js";
import { SwiftScanner }       from "./swift_runner.js";
import { PypiManagerInstance } from "./pypi_runner.js";
import {
  LOCKFILE_GATE,
  LockfileGateError,
  assertLockfileGate,
} from "./lockfile_gate.js";

const SUBPROCESS_TIMEOUT = 30 * 60_000; // ms — a cold install can be slow

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function readOrNull(file) {
  try { return fs.readFileSync(file); } catch { return null; }
}

// How each installer is invoked. `env` entries are layered over process.env.
// All arguments are static strings — package arguments are refused by the gate,
// so nothing user-supplied ever reaches these command lines.
const INSTALLERS = {
  bundle:  { cmd: ["install"],                                 env: () => ({ BUNDLE_FROZEN: "true" }) },
  go:      { cmd: ["mod", "download"],                         env: () => ({ GOFLAGS: `${process.env.GOFLAGS || ""} -mod=readonly`.trim() }) },
  dotnet:  { cmd: ["restore", "--locked-mode"],                env: () => ({}) },
  dart:    { cmd: ["pub", "get", "--enforce-lockfile"],        env: () => ({}) },
  flutter: { cmd: ["pub", "get", "--enforce-lockfile"],        env: () => ({}) },
  swift:   { cmd: ["package", "resolve", "--force-resolved-versions"], env: () => ({}) },
};

// `<binary> <versionArgs>` and how to read the version out of it.
const VERSION_PROBES = {
  bundle:  { args: ["--version"], re: /(\d+\.\d+(?:\.\d+)?\S*)/ },
  go:      { args: ["version"],   re: /go version go(\d+\.\d+(?:\.\d+)?\S*)/ },
  dotnet:  { args: ["--version"], re: /^(\d+\.\d+\.\d+\S*)/m },
  dart:    { args: ["--version"], re: /Dart SDK version:\s*(\S+)/ },
  flutter: { args: ["--version"], re: /Flutter\s+(\d+\.\d+\.\d+\S*)/ },
  swift:   { args: ["--version"], re: /Swift version\s+(\d+\.\d+(?:\.\d+)?\S*)/ },
};

const SCANNERS = {
  bundle:  () => new RubyBundlerScanner(),
  go:      () => new GoModScanner(),
  dotnet:  () => new CSharpNuGetScanner(),
  dart:    () => new FlutterPubScanner(),
  flutter: () => new FlutterPubScanner(),
  swift:   () => new SwiftScanner(),
};

export class LockfileGateManager {

  /** @param {"bundle"|"go"|"dotnet"|"dart"|"flutter"|"swift"} engine */
  constructor(engine) {
    const cfg = LOCKFILE_GATE[engine];
    if (!cfg || cfg.family !== "lockfile") {
      throw new Error(`LockfileGateManager does not handle engine '${engine}'.`);
    }
    this.engine        = engine;
    this.cfg           = cfg;
    this.engineVersion = null;
    this.inventoryData = [];
    this._state        = null;   // fingerprints recorded by runDryRun()
  }

  // Graph helpers are ecosystem-agnostic (see pypi_runner.js) and engine.js
  // calls them on whichever manager it was given.
  buildDependencySequences(inv) { return PypiManagerInstance.prototype.buildDependencySequences.call(this, inv); }
  buildIntroducedBy(inv)        { return PypiManagerInstance.prototype.buildIntroducedBy.call(this, inv); }
  buildParents(inv)             { return PypiManagerInstance.prototype.buildParents.call(this, inv); }

  // ── tool probing ────────────────────────────────────────────────────────────

  _spawnOpts(extra = {}) {
    // .cmd / .bat shims (yarn, bundle, dart, flutter on Windows) need a shell.
    // Safe: every argument is a static string, never user input.
    return { shell: process.platform === "win32", ...extra };
  }

  /** Version string of the package manager, or null when it isn't runnable. */
  _probeVersion() {
    const probe = VERSION_PROBES[this.engine];
    try {
      const r = spawnSync(this.cfg.binary, probe.args, this._spawnOpts({ encoding: "utf8", timeout: 60_000 }));
      if (r.error || r.status !== 0) return null;
      // dart (older SDKs) prints its version on stderr.
      const text = `${r.stdout || ""}\n${r.stderr || ""}`;
      const m = probe.re.exec(text);
      if (m) return m[1];
      const first = text.split("\n").map(s => s.trim()).find(Boolean);
      return first || null;
    } catch {
      return null;
    }
  }

  // engine.js calls this for every non-health scan. `check` only reads the
  // lockfile, so a missing binary is not an error here (runDryRun decides).
  _captureEngineVersion() {
    this.engineVersion = this._probeVersion();
  }

  // ── health ──────────────────────────────────────────────────────────────────

  /** `health` mode — the ecosystem scanner's own walk of startDir. */
  async getInstalled(startDir) {
    const scanner = SCANNERS[this.engine]();
    const ids = await scanner.getInstalled(startDir);
    this.inventoryData = scanner.inventoryData;
    return ids;
  }

  // ── lockfile scan (check / install) ─────────────────────────────────────────

  /** Components pinned by THIS project's lockfile only (no sub-project walk). */
  _scanLockfile(root) {
    const s = SCANNERS[this.engine]();
    let comps;

    switch (this.engine) {
      case "bundle":
        comps = s._scanProject(root);
        break;
      case "go":
        // go.sum only — go.mod's require/replace/indirect are not merged in (health mode still does).
        comps = s._scanLockfileOnly(root);
        break;
      case "dart":
      case "flutter":
        // pubspec.lock only — _scanProject() can fall back to .dart_tool/package_config.json.
        comps = s._componentsFromLock(path.join(root, "pubspec.lock"), root);
        break;
      case "dotnet":
        // _scanProject() falls back to obj/project.assets.json when there is no
        // packages.lock.json; this firewall's contract is the lockfile, so it must exist.
        if (!s._readPackagesLock(root)) {
          throw new Error("packages.lock.json could not be read — refusing to fall back to obj/project.assets.json.");
        }
        comps = s._scanProject(root);
        break;
      case "swift":
        // Package.resolved only: _scanDir() would also fall back to .build/workspace-state.json
        // and Carthage's Cartfile.resolved, neither of which swift package resolve installs from.
        comps = s._swiftComponents(s._parsePackageResolved(path.join(root, "Package.resolved")), root);
        break;
      default:
        throw new Error(`Unsupported engine '${this.engine}'.`);
    }

    const merged = s.mergeInventoryByPurl(comps);
    s._assignScopes(merged);
    for (const c of merged) {
      c.paths = [];
      delete c.project_root;
      delete c._indirect;
      delete c._nugetType;
    }
    return merged;
  }

  _fingerprint(files) {
    const out = {};
    for (const f of files) {
      const buf = readOrNull(f);
      out[f] = buf ? { sha: sha256(buf), buf } : null;
    }
    return out;
  }

  /**
   * Require the lockfile, read what it pins, and remember what was scanned.
   * Returns the PURL ids; the full records land in this.inventoryData.
   *
   * @param {string[]} args           must be empty (see lockfile_gate.js)
   * @param {string}   projectRoot
   * @param {{install?: boolean}} [opts]  install: also require the package manager to be runnable
   */
  runDryRun(args, projectRoot, { install = false } = {}) {
    const root = path.resolve(projectRoot);
    // check reads the lockfile only; install also needs the manifest the frozen install reads.
    const gate = assertLockfileGate(this.engine, root, args, { requireManifest: install });   // throws LockfileGateError

    // engine.js usually captured it already (_captureEngineVersion); probe again only if that found nothing.
    if (!this.engineVersion) this.engineVersion = this._probeVersion();
    if (install && !this.engineVersion) {
      throw new Error(
        `'${this.cfg.binary}' was not found or did not run (tried '${this.cfg.binary} ${VERSION_PROBES[this.engine].args.join(" ")}'). ` +
        `Install it and make sure it is on your PATH, or use \`check\` to only scan the lockfile.`
      );
    }

    const components = this._scanLockfile(root);
    if (!components.length) {
      // Fail closed: "read nothing" must never look like "nothing to block".
      throw new LockfileGateError(
        `Installation refused (${this.cfg.label}): ${this.cfg.lockfiles.join(" + ")} yielded no packages — ` +
        `it is empty, in an unsupported format, or out of sync, so nothing could be scanned.`,
        { engine: this.engine, problems: ["lockfile yielded no packages"] }
      );
    }

    this.inventoryData = this.buildDependencySequences(components);

    // check fingerprints the lockfile only (the manifest is not read); install also watches the
    // manifest the frozen install reads.
    const watched = install ? [...gate.lockfiles, ...gate.manifests] : [...gate.lockfiles];
    this._state = {
      root,
      lockfiles: gate.lockfiles,
      watched,
      scanned: this._fingerprint(watched),
    };

    return this.inventoryData.map(c => c.id);
  }

  // ── TOCTOU ──────────────────────────────────────────────────────────────────

  /** basenames of the watched files whose bytes differ from what was fingerprinted at scan time. */
  _changedSinceScan() {
    const s = this._state;
    const changed = [];
    for (const f of s.watched) {
      const now  = readOrNull(f);
      const then = s.scanned[f];
      if ((now ? sha256(now) : null) !== (then ? then.sha : null)) changed.push(path.basename(f));
    }
    return changed;
  }

  /**
   * TOCTOU guard for `check`: the lockfile must still be byte-for-byte what was scanned. The scan
   * spends time on network lookups, and the verdict is only meaningful for the file it was made on
   * — whoever installs from this lockfile afterwards relies on that. Call it once the verdict is
   * final. Returns { "<lockfile>": "<sha256>" } of what was scanned (surface it so a CI step can
   * compare it with the lockfile it later installs from).
   * @throws {Error} when a scanned file changed or is gone.
   */
  verifyScanned(projectRoot) {
    const s = this._state;
    if (!s) throw new Error("No scanned lockfile to verify — runDryRun() must run first.");
    if (path.resolve(projectRoot) !== s.root) throw new Error("Refusing to verify a different project than the one that was scanned.");
    const changed = this._changedSinceScan();
    if (changed.length) {
      throw new Error(
        `${changed.join(", ")} changed while it was being scanned — the result does not describe what is on disk. ` +
        `Nothing was installed; re-run.`
      );
    }
    return Object.fromEntries(s.lockfiles.map(f => [path.basename(f), s.scanned[f].sha]));
  }

  // ── real install ────────────────────────────────────────────────────────────

  _writeAtomic(file, buf) {
    const tmp = `${file}.ubel-tmp`;
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, file);
  }

  /**
   * Run the frozen install for exactly the lockfile that was scanned.
   * Throws on any failure; the lockfile is guaranteed to be left as scanned.
   */
  runRealInstall(projectRoot) {
    const s = this._state;
    if (!s) throw new Error("No scanned lockfile to install — runDryRun() must run first.");
    const root = path.resolve(projectRoot);
    if (root !== s.root) throw new Error("Refusing to install into a different project than the one that was scanned.");

    // TOCTOU: the lockfile (and manifest) must still be byte-for-byte what was scanned.
    const changed = this._changedSinceScan();
    if (changed.length) {
      console.error(`Scanned lockfile integrity check FAILED — ${changed[0]} changed after scanning.`);
      throw new Error(`${changed[0]} changed between scan and install — install aborted; re-run.`);
    }

    const inst = INSTALLERS[this.engine];
    const r = spawnSync(this.cfg.binary, inst.cmd, this._spawnOpts({
      cwd:     root,
      stdio:   "inherit",
      timeout: SUBPROCESS_TIMEOUT,
      env:     { ...process.env, ...inst.env() },
    }));

    // No frozen installer may rewrite what was scanned. If one did, undo it.
    const tampered = [];
    for (const f of s.lockfiles) {
      const now  = readOrNull(f);
      const then = s.scanned[f];
      if (then && (!now || sha256(now) !== then.sha)) {
        try { this._writeAtomic(f, then.buf); } catch (err) {
          console.error(`[!] Failed to restore ${f}: ${err.message}`);
        }
        tampered.push(path.basename(f));
      }
    }
    if (tampered.length) {
      throw new Error(
        `${this.cfg.binary} modified ${tampered.join(", ")} during the install — the original was restored, ` +
        `but what was installed may differ from what was scanned. Treat this install as untrusted.`
      );
    }

    if (r.error || r.status !== 0) {
      const why = r.error ? r.error.message : `exit ${r.status}`;
      console.error(`[!] ${this.cfg.binary} ${inst.cmd.join(" ")} failed (${why}).`);
      throw new Error(`${this.cfg.binary} ${inst.cmd.join(" ")} failed (${why}) — ${path.basename(s.lockfiles[0])} was left untouched.`);
    }
    return r;
  }

  cleanup() { /* nothing is copied or backed up: the project is never modified */ }
}