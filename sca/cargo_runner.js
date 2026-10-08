// cargo_runner.js
//
// Cargo firewall for `ubel-cargo` — dry-run → scan → gated real install, the
// same shape as the pip/uv/conda firewalls, built on RustCargoScanner so the
// Cargo.lock parsing, scope assignment and `health` scan are shared with the
// existing Rust support:
//
//   runDryRun(args, projectRoot)   → resolves in a SCRATCH COPY of the project:
//                                      cargo add <specs>         (only if args)
//                                      cargo update --workspace  (lockfile only)
//   runRealInstall(projectRoot)    → writes the scanned Cargo.toml/Cargo.lock
//                                    into the project, then `cargo fetch --locked`
//   cleanup()                      → removes the scratch copy
//   getInstalled(...)              → inherited (health mode, RustCargoScanner)
//
// Why a scratch copy (instead of editing the project and reverting, as npm and
// composer do):
//   * `check` never touches the project tree — nothing to revert, even if the
//     process is killed mid-scan.
//   * `cargo add` rewrites Cargo.toml in place; doing that on a copy means the
//     user's manifest is only ever written after the scan has passed.
//
// What the dry-run does and doesn't do:
//   `cargo add` and `cargo update` resolve against the registry INDEX only —
//   they don't download crate sources and never run build.rs or proc-macros.
//   Git dependencies are the exception: resolving one clones the repository
//   (no code from it is executed, but the content is fetched).
//
// Why the real install is `cargo fetch --locked`:
//   The scanned lockfile is the installed lockfile. --locked makes cargo fail
//   rather than resolve anything that wasn't scanned. `fetch` populates cargo's
//   registry cache only; nothing is compiled, so build scripts still don't run.
//
// Vulnerability matching:
//   Only crates from crates.io are put in the inventory and matched (OSV maps
//   pkg:cargo/ to crates.io). Workspace members and path dependencies are your
//   own code and are left out; git dependencies and alternative registries are
//   reported in a warning and are NOT scanned.
//
// Zero third-party runtime dependencies (Node stdlib only).

import fs     from "fs";
import os     from "os";
import path   from "path";
import crypto from "crypto";
import { spawnSync } from "child_process";

import { RustCargoScanner }   from "./rust_runner.js";
import { PypiManagerInstance } from "./pypi_runner.js";

const SUBPROCESS_TIMEOUT = 300_000; // ms — index updates can be slow

// `name` or `name@requirement`. Option-shaped, path-shaped, URL-shaped and
// whitespace-containing arguments never match, so a specifier can't smuggle in
// --git/--path/--registry or a feature flag.
export const CARGO_SPEC_RE = /^[A-Za-z_][A-Za-z0-9_-]*(@[0-9A-Za-z.^~=<>*+!,-]+)?$/;

// Cargo.lock `source` values for crates.io (git index / sparse index).
const CRATES_IO_SOURCES = new Set([
  "registry+https://github.com/rust-lang/crates.io-index",
  "sparse+https://index.crates.io/",
]);

// Not copied into the scratch tree: build output, VCS data, and UBEL's own state.
const COPY_EXCLUDES = new Set(["target", ".git", "node_modules", ".ubel"]);

const sha256 = (buf) => crypto.createHash("sha256").update(buf).digest("hex");

function readOrNull(file) {
  try { return fs.readFileSync(file); } catch { return null; }
}

function versionAtLeast(version, min) {
  const parts = String(version).split(/[.-]/).slice(0, 3).map(n => parseInt(n, 10) || 0);
  for (let i = 0; i < 3; i++) {
    if ((parts[i] ?? 0) > min[i]) return true;
    if ((parts[i] ?? 0) < min[i]) return false;
  }
  return true;
}

export class CargoManagerInstance extends RustCargoScanner {

  constructor() {
    super();
    this.installer     = "cargo";
    this.engineVersion = null;
    this._cargoBinPath = null;   // cached by _resolveCargoBin()
    this._scratch      = null;   // scratch project dir, set by runDryRun()
    this._exitHooked   = false;
    this._state        = null;   // hashes/originals recorded by runDryRun()
  }

  // Version is probed inside runDryRun(); nothing to capture up front.
  _captureEngineVersion() {}

  // Graph helpers are ecosystem-agnostic (see pypi_runner.js) and engine.js
  // calls them on whichever manager it was given.
  buildDependencySequences(inv) { return PypiManagerInstance.prototype.buildDependencySequences.call(this, inv); }
  buildIntroducedBy(inv)        { return PypiManagerInstance.prototype.buildIntroducedBy.call(this, inv); }
  buildParents(inv)             { return PypiManagerInstance.prototype.buildParents.call(this, inv); }

  // ── cargo binary resolution ─────────────────────────────────────────────────
  // rustup installs cargo to ~/.cargo/bin and only edits shell rc files to put
  // it on PATH, which spawnSync never sources — so PATH is tried first, then
  // $CARGO_HOME/bin, then ~/.cargo/bin.

  _probeCargoVersion(bin) {
    try {
      const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 30_000 });
      if (r.status !== 0) return null;
      const m = /^cargo\s+(\d+\.\d+\.\d+\S*)/m.exec(r.stdout || "");
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  _resolveCargoBin() {
    if (this._cargoBinPath) return this._cargoBinPath;

    const exe = process.platform === "win32" ? "cargo.exe" : "cargo";
    const candidates = ["cargo"]; // bare command, resolved via PATH
    if (process.env.CARGO_HOME) candidates.push(path.join(process.env.CARGO_HOME, "bin", exe));
    candidates.push(path.join(os.homedir(), ".cargo", "bin", exe));

    for (const candidate of candidates) {
      if (candidate !== "cargo" && !fs.existsSync(candidate)) continue;
      if (this._probeCargoVersion(candidate)) {
        this._cargoBinPath = candidate;
        return candidate;
      }
    }
    return null;
  }

  assertCargoAvailable() {
    if (!this._resolveCargoBin()) {
      throw new Error(
        `'cargo' was not found on PATH, in $CARGO_HOME/bin, or in ~/.cargo/bin — ubel-cargo requires ` +
        `the Rust toolchain to be installed, the same way ubel-pnpm requires pnpm. If you just ` +
        `installed it, open a new terminal (or 'source' your shell rc file) so PATH picks it up.`
      );
    }
  }

  getCargoVersion() {
    const bin = this._resolveCargoBin();
    return bin ? this._probeCargoVersion(bin) : null;
  }

  // ── project checks ──────────────────────────────────────────────────────────

  /**
   * The dry-run copies projectRoot alone, so it must be a standalone package
   * or a workspace root. A member of a parent workspace would resolve against
   * a different lockfile in the copy than in place, so it's refused rather
   * than scanned wrongly.
   */
  _assertResolvableRoot(root) {
    const manifest = path.join(root, "Cargo.toml");
    if (!fs.existsSync(manifest)) {
      throw new Error(`No Cargo.toml found in ${root} — run ubel-cargo from the project (or workspace) root.`);
    }
    const hasWorkspace = (file) => /^\s*\[workspace[\].]/m.test(fs.readFileSync(file, "utf8"));
    if (hasWorkspace(manifest)) return;

    let dir = path.dirname(root);
    for (;;) {
      const parent = path.join(dir, "Cargo.toml");
      if (fs.existsSync(parent) && hasWorkspace(parent)) {
        throw new Error(
          `${root} looks like a member of the workspace rooted at ${dir}. ` +
          `Run ubel-cargo from the workspace root so the scanned lockfile is the one cargo actually uses.`
        );
      }
      const up = path.dirname(dir);
      if (up === dir) break;
      dir = up;
    }
  }

  _copyProject(src, dest) {
    fs.cpSync(src, dest, {
      recursive: true,
      filter: (s) => s === src || !COPY_EXCLUDES.has(path.basename(s)),
    });
  }

  _run(cargoBin, args, cwd) {
    const r = spawnSync(cargoBin, args, {
      cwd,
      encoding: "utf8",
      timeout: SUBPROCESS_TIMEOUT,
      maxBuffer: 64 * 1024 * 1024,
      env: { ...process.env, CARGO_TERM_COLOR: "never" },
    });
    if (r.error || r.status !== 0) {
      throw new Error(
        `cargo dry-run failed:\n` +
        `CMD: ${cargoBin} ${args.join(" ")}\n` +
        `${(r.stderr || "").trim() || r.error?.message || "(no output)"}`
      );
    }
    return r;
  }

  // ── dry-run ─────────────────────────────────────────────────────────────────

  /**
   * Resolve the project's dependencies (plus any `args` crates) in a scratch
   * copy and return the PURL ids of the scanned crates; full records land in
   * this.inventoryData. The project itself is not modified.
   *
   * args: `name` or `name@requirement`. With no args the scanned set is the
   * project's current Cargo.lock (generated in the copy if there isn't one).
   */
  runDryRun(initialArgs, projectRoot) {
    this.assertCargoAvailable();
    const cargoBin = this._resolveCargoBin();

    const cargoVersion = this.getCargoVersion();
    if (cargoVersion === null) throw new Error("Failed to determine cargo version (`cargo --version` did not succeed)");
    this.engineVersion = cargoVersion;

    const args = initialArgs.filter(a => a !== "--");
    // engine.js already rejects these; re-checked so this class is safe to call directly.
    const bad = args.find(a => !CARGO_SPEC_RE.test(a));
    if (bad) throw new Error(`Refusing unsafe or malformed crate specifier: ${bad}`);
    if (args.length && !versionAtLeast(cargoVersion, [1, 62, 0])) {
      throw new Error(`ubel-cargo needs cargo >= 1.62 (for \`cargo add\`) to add packages; found ${cargoVersion}.`);
    }

    const root = path.resolve(projectRoot);
    this._assertResolvableRoot(root);

    const origManifest = readOrNull(path.join(root, "Cargo.toml"));
    const origLock     = readOrNull(path.join(root, "Cargo.lock"));

    this.cleanup();
    const scratch = fs.mkdtempSync(path.join(os.tmpdir(), "ubel-cargo-dryrun-"));
    this._scratch = scratch;
    if (!this._exitHooked) {
      this._exitHooked = true;
      process.once("exit", () => this.cleanup());
    }

    this._copyProject(root, scratch);
    const scratchManifest = path.join(scratch, "Cargo.toml");
    const scratchLock     = path.join(scratch, "Cargo.lock");

    if (args.length) {
      this._run(cargoBin, ["add", "--manifest-path", scratchManifest, ...args], scratch);
    }
    // --workspace: keep every already-locked crate where it is and only resolve
    // what the lockfile is missing, so the scanned set is the project's own
    // plus exactly what was added. Index-only; downloads no crate sources.
    this._run(cargoBin, ["update", "--workspace", "--manifest-path", scratchManifest], scratch);

    const lockBuf = readOrNull(scratchLock);
    if (!lockBuf) throw new Error("cargo dry-run did not produce a Cargo.lock.");

    // ── components ──
    const all = this._scanProject(scratch);   // reads <scratch>/Cargo.lock
    const registry = all.filter(c => CRATES_IO_SOURCES.has(c._source));
    const skipped  = all.filter(c => c._source !== "local" && !CRATES_IO_SOURCES.has(c._source));

    if (skipped.length) {
      const names = [...new Set(skipped.map(c => c.name))].sort();
      console.warn(
        `[!] ${names.length} dependenc${names.length === 1 ? "y" : "ies"} from git or non-crates.io registries ` +
        `are NOT covered by this scan: ${names.join(", ")}`
      );
    }
    if (!registry.length) {
      // Fail closed: "resolved nothing" must never read as "nothing to block".
      throw new Error("cargo dry-run resolved no crates.io dependencies to scan.");
    }

    const merged = this.mergeInventoryByPurl(registry);
    this._assignScopes(merged);   // reads the scratch Cargo.toml (includes any added crate)
    for (const c of merged) {
      c.paths = [];
      delete c._source;
      delete c.project_root;
    }

    this.inventoryData = this.buildDependencySequences(merged);

    this._state = {
      root,
      added:        args.length > 0,
      origManifest, origLock,
      origManifestSha: origManifest ? sha256(origManifest) : null,
      origLockSha:     origLock     ? sha256(origLock)     : null,
      scannedManifest: args.length ? fs.readFileSync(scratchManifest) : null,
      scannedLock:     lockBuf,
      scannedLockSha:  sha256(lockBuf),
      scannedManifestSha: args.length ? sha256(fs.readFileSync(scratchManifest)) : null,
    };

    return this.inventoryData.map(c => c.id);
  }

  // ── real install ────────────────────────────────────────────────────────────

  _writeAtomic(file, buf) {
    const tmp = `${file}.ubel-tmp`;
    fs.writeFileSync(tmp, buf);
    fs.renameSync(tmp, file);
  }

  _restoreOriginals(root, s) {
    try {
      if (s.added && s.origManifest) this._writeAtomic(path.join(root, "Cargo.toml"), s.origManifest);
      if (s.origLock) this._writeAtomic(path.join(root, "Cargo.lock"), s.origLock);
      else fs.rmSync(path.join(root, "Cargo.lock"), { force: true });
    } catch (err) {
      console.error(`[!] Failed to restore the original Cargo.toml/Cargo.lock: ${err.message}`);
    }
  }

  /**
   * Write the scanned Cargo.toml (only if packages were added) and Cargo.lock
   * into the project, then `cargo fetch --locked`. If the fetch fails the
   * project's original files are put back.
   */
  runRealInstall(projectRoot) {
    const s = this._state;
    if (!s || !this._scratch) throw new Error("No scanned resolution to install — runDryRun() must run first.");
    const root = path.resolve(projectRoot);
    if (root !== s.root) throw new Error("Refusing to install into a different project than the one that was scanned.");

    this.assertCargoAvailable();
    const cargoBin = this._resolveCargoBin();

    // The scratch files are what was scanned; they must not have changed.
    const scratchLockNow = readOrNull(path.join(this._scratch, "Cargo.lock"));
    const scratchManNow  = s.added ? readOrNull(path.join(this._scratch, "Cargo.toml")) : null;
    if (!scratchLockNow || sha256(scratchLockNow) !== s.scannedLockSha ||
        (s.added && (!scratchManNow || sha256(scratchManNow) !== s.scannedManifestSha))) {
      console.error("Scanned resolution integrity check FAILED — the files were modified after scanning.");
      throw new Error("cargo resolution changed between scan and install — install aborted.");
    }

    // The project's own files must not have changed while we were scanning.
    const manNow  = readOrNull(path.join(root, "Cargo.toml"));
    const lockNow = readOrNull(path.join(root, "Cargo.lock"));
    if ((manNow  ? sha256(manNow)  : null) !== s.origManifestSha ||
        (lockNow ? sha256(lockNow) : null) !== s.origLockSha) {
      throw new Error("Cargo.toml/Cargo.lock changed in the project while it was being scanned — install aborted; re-run.");
    }

    if (s.added) this._writeAtomic(path.join(root, "Cargo.toml"), s.scannedManifest);
    this._writeAtomic(path.join(root, "Cargo.lock"), s.scannedLock);

    const cmd = ["fetch", "--locked", "--manifest-path", path.join(root, "Cargo.toml")];
    const r = spawnSync(cargoBin, cmd, { cwd: root, stdio: "inherit", env: { ...process.env, CARGO_TERM_COLOR: "never" } });
    if (r.status !== 0) {
      console.error(`[!] Package fetch failed (exit ${r.status}): ${cargoBin} ${cmd.join(" ")}`);
      this._restoreOriginals(root, s);
      throw new Error(`cargo fetch failed (exit ${r.status}) — Cargo.toml/Cargo.lock were restored.`);
    }
    return r;
  }

  cleanup() {
    if (this._scratch) {
      try { fs.rmSync(this._scratch, { recursive: true, force: true }); } catch { /* ignore */ }
      this._scratch = null;
    }
  }
}

export default CargoManagerInstance;