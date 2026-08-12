// pypi_runner.js
//
// JS port of Pypi_Manager (python_runner.py) — the firewall-relevant subset.
// PythonVenvScanner (python_runner.js) already covers pure inventory scanning
// (health mode); this file adds the pre-install firewall mechanics so
// `ubel-pip`/`ubel-uv`/`ubel-pipx` can gate an install the same way
// `ubel-npm` gates `npm ci`:
//
//   initVenv(venvDir)               → create a venv at venvDir (idempotent)
//   initUvVenv(venvDir)             → uv-native venv (`uv init --bare` + `uv venv`, idempotent)
//   getPipVersion(python)           → pip version installed in the venv
//   getUvVersion()                  → uv version on PATH (resolved via _resolveUvBin())
//   runDryRun(initialArgs, venvDir) → dry-run resolution, branches on
//                                      this.installer ("pip" → `pip install
//                                      --dry-run --report`; "uv" → `uv pip
//                                      install --dry-run`, see below) — same
//                                      returned component structure either way
//   runRealInstall(fileName, engine, venvDir) → `pip install -r` / `uv pip
//                                      install -r` inside the venv, then
//                                      syncs requirements.txt/pyproject.toml
//                                      (see _syncDependencyFiles() below)
//   dryRunCli(packageSpec)          → dry-run for a CLI package in an isolated venv (pip only)
//   installCli(packageSpec)         → install a CLI package + expose global shims (pip only)
//   getInstalled(startDir, opts)    → health-mode scan (delegates to PythonVenvScanner);
//                                      also what runRealInstall() reuses post-install to
//                                      learn what's actually now in the venv
//
// pip vs uv, and why they're NOT just "the same command, different binary":
// pip's `--dry-run --report <path>` produces a JSON install plan with each
// package's declared `requires_dist`, so the resulting dependency graph
// (who depends on whom) comes straight from the report. uv has no direct
// equivalent — `uv pip install --dry-run` is the closest, but (confirmed by
// testing directly against uv 0.11.7) writes a flat `+ name==version` list
// to **stderr**, with no dependency relationships, and it only reports what
// would *change* — a fully-satisfied install prints nothing at all, same
// limitation pip's own dry-run --report has. runDryRun() uses it anyway for
// the "uv" installer (see the comment above _runDryRunUv() for the
// resulting trade-off: uv-sourced components all come back as flat roots,
// no introduced_by/parents/dependency_sequences the way pip's report-driven
// branch gets). Neither pip nor uv can resolve a source-only package's
// metadata without potentially building an sdist — see the caveat in
// _runDryRunUv()/the pip branch below.
//
// Zero third-party runtime dependencies (Node stdlib only) — matches UBEL's
// existing zero-dependency positioning.

import fs   from "fs";
import os   from "os";
import path from "path";
import { spawnSync } from "child_process";

import { PythonVenvScanner } from "./python_runner.js";
import { LinuxHostScanner }  from "./linux_runner.js";

const SUBPROCESS_TIMEOUT = 300_000; // ms — resolution can be slow

export class PypiManagerInstance {

  /**
   * @param {"pip"|"uv"} [installer="pip"] — which installer runDryRun()/
   *   runRealInstall() drive. Defaults to "pip" so existing callers
   *   (including the pipx CLI-isolation methods, which are pip-only —
   *   there's no "uvx" equivalent requested/implemented here) are
   *   unaffected. ubel-uv's CLI dispatch constructs
   *   `new PypiManagerInstance("uv")` explicitly.
   */
  constructor(installer = "pip") {
    if (!["pip", "uv"].includes(installer)) {
      throw new Error(`PypiManagerInstance requires installer "pip" or "uv", got: ${JSON.stringify(installer)}`);
    }
    this.installer      = installer;
    this.inventoryData  = [];
    this.engineVersion  = null; // set by getPipVersion()/getUvVersion() during runDryRun/install
    this._uvBinPath     = null; // cached by _resolveUvBin() — "uv" if reachable as-is, else a resolved absolute path
  }

  // ── Engine version capture (no-op) ──────────────────────────────────────────
  // Mirrors LinuxManagerInstance — the version is only knowable once a venv
  // exists (pip) or by probing `uv --version` (uv), so it's captured inline
  // inside runDryRun()/getInstalled(), not via a generic pre-collect probe.
  _captureEngineVersion() {}

  // ── PURL helpers ──────────────────────────────────────────────────────────────

  _purl(name, version) {
    return `pkg:pypi/${name.toLowerCase()}@${version ?? ""}`;
  }

  _resolveDepPurl(rawDepName, nameToPurl) {
    const key = rawDepName.toLowerCase().replace(/-/g, "_");
    return nameToPurl.get(key) || `pkg:pypi/${rawDepName.toLowerCase()}@`;
  }

  mergeInventoryByPurl(components) {
    const map = new Map();
    for (const comp of components) {
      if (!map.has(comp.id)) {
        map.set(comp.id, { ...comp, paths: [...(comp.paths || [])] });
        continue;
      }
      const existing = map.get(comp.id);
      for (const p of (comp.paths || [])) {
        if (p && !existing.paths.includes(p)) existing.paths.push(p);
      }
    }
    return [...map.values()];
  }

  // ── Dependency sequences (identical algorithm to NodeManagerInstance /
  //    LinuxManagerInstance — kept ecosystem-agnostic on purpose so engine.js
  //    can call it the same way regardless of systemType). ──────────────────

  buildDependencySequences(inventory) {
    const byId = new Map();
    for (const comp of inventory) byId.set(comp.id, comp);

    // Deduplicate each component's dependency list first (extras/markers may
    // repeat the same package under different conditions).
    for (const comp of inventory) {
      const seen = new Set();
      const deduped = [];
      for (const dep of (comp.dependencies || [])) {
        if (!seen.has(dep)) { deduped.push(dep); seen.add(dep); }
      }
      comp.dependencies = deduped;
    }

    const depended = new Set();
    for (const comp of inventory) {
      for (const dep of (comp.dependencies || [])) {
        if (byId.has(dep)) depended.add(dep);
      }
    }

    const roots     = inventory.map(c => c.id).filter(id => !depended.has(id));
    const sequences = new Map();

    function dfs(node, pathSoFar, visitedInTree) {
      if (visitedInTree.has(node)) return;
      visitedInTree.add(node);
      const nextPath = [...pathSoFar, node];
      if (!sequences.has(node)) sequences.set(node, []);
      sequences.get(node).push(nextPath);
      for (const dep of (byId.get(node)?.dependencies || [])) {
        if (!pathSoFar.includes(dep) && byId.has(dep)) dfs(dep, nextPath, visitedInTree);
      }
    }

    for (const root of roots) dfs(root, [], new Set());
    for (const comp of inventory) comp.dependency_sequences = sequences.get(comp.id) || [];

    return inventory;
  }

  buildIntroducedBy(inventory) {
    const reverse = new Map();
    for (const pkg of inventory) reverse.set(pkg.id, []);
    for (const pkg of inventory) {
      for (const dep of pkg.dependencies || []) {
        if (!reverse.has(dep)) reverse.set(dep, []);
        reverse.get(dep).push(pkg.id);
      }
    }
    for (const pkg of inventory) pkg.introduced_by = reverse.get(pkg.id) || [];
    return inventory;
  }

  buildParents(inventory) {
    const parents = new Map(inventory.map(c => [c.id, []]));
    for (const comp of inventory) {
      for (const depId of (comp.dependencies || [])) {
        if (parents.has(depId)) parents.get(depId).push(comp.id);
      }
    }
    for (const comp of inventory) comp.parents = (parents.get(comp.id) || []).sort();
    return inventory;
  }

  // ── Venv helpers ──────────────────────────────────────────────────────────────

  _venvPython(venvDir) {
    const unix = path.join(venvDir, "bin", "python");
    if (fs.existsSync(unix)) return unix;
    const win = path.join(venvDir, "Scripts", "python.exe");
    if (fs.existsSync(win)) return win;
    throw new Error(`Cannot locate Python interpreter inside venv: ${venvDir}`);
  }

  getPipVersion(python) {
    try {
      const r = spawnSync(python, ["-m", "pip", "--version"], { encoding: "utf8" });
      if (r.status !== 0) return null;
      const output = (r.stdout || "").trim();
      if (output.startsWith("pip ")) return output.split(/\s+/)[1];
    } catch { /* fall through */ }
    return null;
  }

  // ── init_venv ─────────────────────────────────────────────────────────────────

  /**
   * Create a Python virtual environment at venvDir if one doesn't already
   * exist there. Idempotent — safe to call on an existing venv. Requires a
   * `python3`/`python` interpreter on PATH (Node itself cannot create venvs).
   *
   * Returns the absolute path to the venv's Python interpreter.
   */
  initVenv(venvDir) {
    const venvPath = path.resolve(venvDir);

    if (!fs.existsSync(path.join(venvPath, "pyvenv.cfg"))) {
      fs.mkdirSync(path.dirname(venvPath), { recursive: true });
      const pythonBin = this._systemPython();
      const r = spawnSync(pythonBin, ["-m", "venv", venvPath], { stdio: "inherit" });
      if (r.status !== 0) {
        throw new Error(`Failed to create venv at ${venvPath} (exit ${r.status})`);
      }
    }

    return this._venvPython(venvPath);
  }

  _systemPython() {
    for (const candidate of ["python3", "python"]) {
      const r = spawnSync(candidate, ["--version"], { encoding: "utf8" });
      if (r.status === 0) return candidate;
    }
    throw new Error("No system Python interpreter (python3/python) found on PATH — required to create a venv.");
  }

  // ── run_dry_run ───────────────────────────────────────────────────────────────

  /**
   * Dry-run resolution for initialArgs inside venvDir. Branches on
   * this.installer — "pip" (default) uses `pip install --dry-run --report`;
   * "uv" uses `uv pip install --dry-run` (see the comment above
   * _runDryRunUv() for the resulting trade-off: no dependency-graph
   * provenance the way pip's --report gives). Either way: the venv must
   * already exist first (initVenv() for pip, initUvVenv() for uv), and
   * this returns a list of PURL id strings, with full records landing in
   * this.inventoryData.
   */
  runDryRun(initialArgs, venvDir) {
    if (this.installer === "uv") return this._runDryRunUv(initialArgs, venvDir);
    return this._runDryRunPip(initialArgs, venvDir);
  }

  _runDryRunPip(initialArgs, venvDir) {
    let python = this._venvPython(venvDir);

    let pipVersion = this.getPipVersion(python);
    if (pipVersion === null) {
      // Mirrors the Python fallback: if pip can't be found, re-create the venv once.
      fs.rmSync(venvDir, { recursive: true, force: true });
      python = this.initVenv(venvDir);
      pipVersion = this.getPipVersion(python);
      if (pipVersion === null) {
        throw new Error(`pip is not installed in the venv at ${venvDir} after re-creation`);
      }
    }
    this.engineVersion = pipVersion;

    const args = initialArgs.filter(a => a !== "--");

    const reportPath = path.join(
      os.tmpdir(),
      `ubel-pip-dryrun-${process.pid}-${Date.now()}.json`
    );

    const cmd = ["-m", "pip", "install", "--dry-run", "--report", reportPath, ...args];
    const result = spawnSync(python, cmd, { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, maxBuffer: 32 * 1024 * 1024 });

    if (result.status !== 0) {
      try { fs.unlinkSync(reportPath); } catch { /* ignore */ }
      throw new Error(
        `pip dry-run failed:\n` +
        `CMD: ${python} ${cmd.join(" ")}\n` +
        `stdout: ${result.stdout || ""}\n` +
        `stderr: ${result.stderr || ""}`
      );
    }

    const data = JSON.parse(fs.readFileSync(reportPath, "utf8"));
    try { fs.unlinkSync(reportPath); } catch { /* ignore */ }

    // ── Build name→purl map from the dry-run report ────────────────────────────
    const nameToPurl = new Map();
    for (const pkg of (data.install || [])) {
      const meta = pkg.metadata || {};
      const n = meta.name, v = meta.version;
      if (n && v) {
        const key = n.toLowerCase().replace(/-/g, "_");
        if (!nameToPurl.has(key)) nameToPurl.set(key, this._purl(n, v));
      }
    }

    // ── Build components ────────────────────────────────────────────────────────
    let components = [];
    for (const pkg of (data.install || [])) {
      const meta    = pkg.metadata || {};
      const name    = meta.name;
      const version = meta.version;
      if (!name || !version) continue;

      const deps = [];
      for (const r of (meta.requires_dist || [])) {
        const depName = r.split(/\s+/)[0].replace(/;$/, "");
        deps.push(this._resolveDepPurl(depName, nameToPurl));
      }

      components.push({
        id: this._purl(name, version),
        name: name.toLowerCase(),
        version,
        type: "library",
        license: meta.license || "unknown",
        dependencies: deps,
        paths: [],
        ecosystem: "python",
        scopes: ["prod"],
        state: "undetermined",
      });
    }

    components.push({
      id: `pkg:pypi/pip@${pipVersion}`,
      name: "pip",
      version: pipVersion,
      type: "tool",
      license: "MIT",
      dependencies: [],
      paths: [],
      ecosystem: "python",
      scopes: ["dev", "env", "prod"],
      state: "undetermined",
    });

    components = this.mergeInventoryByPurl(components);
    components = this.buildDependencySequences(components);

    this.inventoryData = components;
    return components.map(c => c.id);
  }

  // ── uv binary resolution ─────────────────────────────────────────────────────
  //
  // `spawnSync` inherits process.env.PATH exactly as this process saw it at
  // startup — it does NOT re-source .bashrc/.zshrc/.profile the way an
  // interactive login shell does. The official https://astral.sh/uv install
  // script drops the binary in ~/.local/bin and makes it reachable by
  // appending to PATH from an rc file, not system-wide — so a plain
  // `spawnSync("uv", ...)` (or a `which uv` subprocess, which has the same
  // PATH-inheritance problem, plus isn't even present on Windows) can fail
  // to find a uv that works fine in the user's actual terminal. That's the
  // "uv is installed globally but this code can't find it" failure mode.
  // Resolve once, cache the working invocation, and fall back through uv's
  // documented default install locations before giving up.
  _resolveUvBin() {
    if (this._uvBinPath) return this._uvBinPath;

    const direct = spawnSync("uv", ["--version"], { encoding: "utf8" });
    if (direct.status === 0) {
      this._uvBinPath = "uv";
      return this._uvBinPath;
    }

    const home = os.homedir();
    const candidates = process.platform === "win32"
      ? [
          path.join(home, ".local", "bin", "uv.exe"),
          path.join(home, ".cargo", "bin", "uv.exe"),
          path.join(process.env.LOCALAPPDATA || "", "Programs", "uv", "uv.exe"),
        ]
      : [
          path.join(home, ".local", "bin", "uv"), // official astral.sh installer default
          path.join(home, ".cargo", "bin", "uv"), // `cargo install uv`
          "/opt/homebrew/bin/uv",                 // Homebrew, Apple Silicon
          "/usr/local/bin/uv",                    // Homebrew, Intel / manual install
          "/usr/bin/uv",
        ];

    for (const candidate of candidates) {
      if (!fs.existsSync(candidate)) continue;
      const probe = spawnSync(candidate, ["--version"], { encoding: "utf8" });
      if (probe.status === 0) {
        this._uvBinPath = candidate;
        return this._uvBinPath;
      }
    }

    return null;
  }

  assertUvAvailable() {
    if (!this._resolveUvBin()) {
      throw new Error(
        `'uv' was not found on PATH or in any known install location ` +
        `(~/.local/bin, ~/.cargo/bin, Homebrew) — ubel-uv requires uv to be ` +
        `installed, the same way ubel-pnpm requires pnpm. If you just ` +
        `installed it, open a new terminal (or 'source' your shell rc file) ` +
        `so PATH picks it up.`
      );
    }
  }

  getUvVersion() {
    const uvBin = this._resolveUvBin();
    if (!uvBin) return null;
    try {
      const r = spawnSync(uvBin, ["--version"], { encoding: "utf8" });
      if (r.status !== 0) return null;
      // "uv 0.11.7 (x86_64-unknown-linux-gnu)" → "0.11.7"
      const m = /^uv\s+(\S+)/.exec((r.stdout || "").trim());
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  // ── uv-native venv creation (init_uv_venv) ──────────────────────────────────
  //
  // Mirrors initVenv()'s contract (idempotent, returns the venv's absolute
  // python path) but drives it through uv's own project bootstrap — `uv
  // init` then `uv venv` — instead of the stdlib `venv` module. A
  // uv-managed install always goes through this rather than initVenv(), so
  // the environment is one uv itself recognizes as belonging to a real
  // project (pyproject.toml + .python-version present), not just a bare
  // interpreter uv happens to be pointed at via --python.
  //
  // Both steps are skipped if already done — `uv init` errors on a project
  // that's already initialized, same idempotency contract as initVenv()
  // checking for pyvenv.cfg first.
  initUvVenv(venvDir) {
    this.assertUvAvailable();
    const uvBin      = this._resolveUvBin();
    const venvPath    = path.resolve(venvDir);
    const projectDir  = path.dirname(venvPath);

    fs.mkdirSync(projectDir, { recursive: true });

    if (!fs.existsSync(path.join(projectDir, "pyproject.toml"))) {
      // --no-workspace: always bootstrap this directory as its own
      // standalone project, regardless of whether a parent directory
      // happens to be (or look like) a uv workspace root.
      // --bare: projectDir is very often the caller's real project root
      // (see the two call sites — engine.js's check/install dispatch and
      // main.js's `init` mode both pass a venvDir under projectRoot/resolvedRoot),
      // so a plain `uv init` scaffolding README.md/main.py/.python-version
      // and running `git init` there — confirmed via direct testing — would
      // be an unwelcome surprise for a firewall/dry-run tool to leave
      // behind. `--bare` writes only the minimal pyproject.toml uv needs to
      // recognize the directory as a project, nothing else.
      const initResult = spawnSync(uvBin, ["init", "--bare", "--no-workspace"], {
        cwd: projectDir,
        encoding: "utf8",
      });
      if (initResult.status !== 0) {
        throw new Error(
          `'uv init' failed in ${projectDir} (exit ${initResult.status}):\n` +
          (initResult.stderr || initResult.stdout || "")
        );
      }
    }

    if (!fs.existsSync(path.join(venvPath, "pyvenv.cfg"))) {
      const venvResult = spawnSync(uvBin, ["venv", venvPath], {
        cwd: projectDir,
        encoding: "utf8",
      });
      if (venvResult.status !== 0) {
        throw new Error(
          `'uv venv' failed to create ${venvPath} (exit ${venvResult.status}):\n` +
          (venvResult.stderr || venvResult.stdout || "")
        );
      }
    }

    return this._venvPython(venvPath);
  }

  // ── uv dry-run ────────────────────────────────────────────────────────────────
  //
  // Uses `uv pip install <specs> --dry-run` — the same command shape as the
  // pip branch above (`pip install --dry-run`), just routed through uv —
  // rather than `uv pip compile`. That symmetry is deliberate but it does
  // cost real information versus `compile`, confirmed by direct testing
  // against uv 0.11.7:
  //   - Output is a flat `+ name==version` / `- name==version` list on
  //     STDERR (the opposite stream from `pip compile`, which writes its
  //     pinned list to stdout) — no `# via <parent>` provenance, so unlike
  //     the old compile-based branch, every returned component here has an
  //     empty `dependencies` list; buildDependencySequences() below treats
  //     each one as its own root rather than reconstructing a real tree.
  //   - It only reports what would *change* — on an already-satisfied
  //     target it prints nothing at all (same limitation pip's own
  //     --dry-run --report has). This is a non-issue in practice because
  //     runDryRun() is only ever called against a venv initUvVenv() just
  //     created (fresh/empty), so every requested package and its
  //     transitive deps show up as "+" lines — see _parseUvInstallDryRun().
  //
  // One honesty note, same as pip: resolving a source-only package's
  // metadata can require building an sdist, which can run arbitrary
  // setup.py/build-backend code — this is inherent to how Python packaging
  // resolution works, not something either pip's or uv's implementation
  // can avoid. A wheel-only install doesn't have this gap.

  _runDryRunUv(initialArgs, venvDir) {
    this.assertUvAvailable();
    const uvBin  = this._resolveUvBin();
    const python = this._venvPython(venvDir);

    const uvVersion = this.getUvVersion();
    if (uvVersion === null) throw new Error("Failed to determine uv version (`uv --version` did not succeed)");
    this.engineVersion = uvVersion;

    const args = initialArgs.filter(a => a !== "--");

    const cmd = ["pip", "install", ...args, "--dry-run", "--python", python, "--color", "never"];
    const result = spawnSync(uvBin, cmd, {
      encoding: "utf8",
      timeout: SUBPROCESS_TIMEOUT,
      maxBuffer: 32 * 1024 * 1024,
    });

    if (result.status !== 0) {
      throw new Error(
        `uv pip install --dry-run failed:\n` +
        `CMD: ${uvBin} ${cmd.join(" ")}\n` +
        `stdout: ${result.stdout || ""}\n` +
        `stderr: ${result.stderr || ""}`
      );
    }

    // The "+ name==version" plan is on stderr; stdout carries nothing
    // useful for this command — confirmed by direct testing, and the
    // opposite of where `uv pip compile` writes.
    const packages = this._parseUvInstallDryRun(result.stderr || "");

    let components = [];
    for (const [norm, pkg] of packages) {
      components.push({
        id: pkg.purl,
        name: norm,
        version: pkg.version,
        type: "library",
        license: "unknown", // `install --dry-run` exposes no metadata beyond name==version
        dependencies: [],   // flat list only — no "# via" provenance in this output, see _parseUvInstallDryRun()
        paths: [],
        ecosystem: "python",
        scopes: ["prod"],
        state: "undetermined",
      });
    }

    components.push({
      id: `pkg:pypi/uv@${uvVersion}`,
      name: "uv",
      version: uvVersion,
      type: "tool",
      license: "Apache-2.0 OR MIT",
      dependencies: [],
      paths: [],
      ecosystem: "python",
      scopes: ["dev", "env", "prod"],
      state: "undetermined",
    });

    components = this.mergeInventoryByPurl(components);
    components = this.buildDependencySequences(components);

    this.inventoryData = components;
    return components.map(c => c.id);
  }

  /**
   * Parses `uv pip install --dry-run`'s stderr into a name→{name,version,purl}
   * map. uv writes one line per package whose state would change, each
   * prefixed with a symbol, e.g.:
   *   Resolved 31 packages in 1.53s
   *   Would download 1 package
   *   Would install 31 packages
   *    + annotated-doc==0.0.5
   *    + annotated-types==0.8.0
   *    ...
   * "+" marks a package that would be installed; "-" marks one that would
   * be removed. Only "+" lines are kept — runDryRun() always targets a venv
   * initUvVenv() just created (see the comment above _runDryRunUv()), so in
   * practice nothing is ever already installed to remove or upgrade, but
   * "-" is still matched (and skipped) here rather than silently
   * mis-parsed, in case that assumption is ever violated by a caller
   * reusing a pre-populated venv. Header/summary lines ("Resolved N
   * packages...", "Would install N packages") don't match the pin pattern
   * and are ignored.
   */
  _parseUvInstallDryRun(stderrText) {
    const packages = new Map(); // normalizedName -> { name, version, purl }
    const pinRe = /^\s*([+-])\s+([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)\s*$/;

    for (const line of stderrText.split("\n")) {
      const m = pinRe.exec(line);
      if (!m) continue;

      const [, sign, rawName, version] = m;
      if (sign === "-") continue; // would-remove — not part of the resulting install set

      const norm = rawName.toLowerCase();
      packages.set(norm, { name: rawName, version, purl: this._purl(rawName, version) });
    }

    return packages;
  }

  // ── run_real_install ─────────────────────────────────────────────────────────

  /**
   * Install packages from fileName (a requirements file — always the
   * generated, exact-pinned file from _generateRequirementsFile() in
   * engine.js, regardless of whether the dry-run source was CLI args,
   * requirements.txt, or pyproject.toml) into venvDir. Supports
   * engine="pip" or engine="uv" — the venv must already exist first
   * (initVenv() for pip, initUvVenv() for uv). On success, also syncs any
   * requirements.txt/pyproject.toml already present in venvDir's project
   * directory to reflect what's now actually installed — see
   * _syncDependencyFiles() below.
   */
  runRealInstall(fileName, engine, venvDir) {
    const python = this._venvPython(venvDir);

    if (engine === "pip") {
      const cmd = [python, "-m", "pip", "install", "-r", fileName];
      const r = spawnSync(cmd[0], cmd.slice(1), { stdio: "inherit" });
      if (r.status !== 0) {
        console.error(`[!] Package install failed (exit ${r.status}): ${cmd.join(" ")}`);
        throw new Error(`pip install failed (exit ${r.status})`);
      }
      this._trySyncDependencyFiles(venvDir);
      return r;
    }

    if (engine === "uv") {
      this.assertUvAvailable();
      const uvBin = this._resolveUvBin();
      const cmd = ["pip", "install", "--python", python, "-r", fileName];
      const r = spawnSync(uvBin, cmd, { stdio: "inherit" });
      if (r.status !== 0) {
        console.error(`[!] Package install failed (exit ${r.status}): ${uvBin} ${cmd.join(" ")}`);
        throw new Error(`uv pip install failed (exit ${r.status})`);
      }
      this._trySyncDependencyFiles(venvDir);
      return r;
    }

    throw new Error(`Unsupported engine: ${engine}`);
  }

  // ── post-install manifest sync ───────────────────────────────────────────────
  //
  // After a REAL (non-dry-run) install, refreshes any requirements.txt /
  // pyproject.toml already sitting in the venv's project directory to
  // reflect what's now actually installed. Reuses getInstalled() — the same
  // PythonVenvScanner .dist-info scan `ubel-pip health` already relies on —
  // rather than shelling out to a separate `pip freeze`/`uv pip freeze`, so
  // this is exactly the same "what's installed" answer health mode would
  // give right after this install.
  //
  // Deliberately does NOT create either file if it doesn't already exist —
  // "update any EXISTING requirements.txt or toml file", not scaffold new
  // ones. And a failure here is logged, never thrown, via
  // _trySyncDependencyFiles() — the install itself already succeeded by the
  // time this runs, so a manifest-sync hiccup shouldn't be surfaced as an
  // install failure.
  //
  // Scope note: this pulls the FULL installed set — every transitive
  // package, not just what was directly requested on the command line —
  // into both files alike. That's normal for requirements.txt, which is
  // routinely used as a full `pip freeze`-style lock of the exact
  // environment. It's a real departure from PEP 621 convention for
  // pyproject.toml's [project].dependencies, though, which is meant to
  // list direct dependencies only (see the scope note above
  // parsePyprojectDependencies()) — the transitive closure is normally
  // uv.lock's job, not something hand-declared there. Implemented this way
  // because that's what was asked for; flagging the tension here in case
  // direct-deps-only semantics for the toml file are wanted later.
  _trySyncDependencyFiles(venvDir) {
    try {
      this._syncDependencyFiles(venvDir);
    } catch (err) {
      console.error(`[!] Failed to sync requirements.txt/pyproject.toml after install: ${err.message}`);
    }
  }

  _syncDependencyFiles(venvDir) {
    const projectDir = path.dirname(path.resolve(venvDir));

    // Re-scan rather than trust this.inventoryData from a preceding
    // runDryRun() — dry-run reflects what WOULD be installed, this needs
    // what actually now IS. scanOs: false — health mode's OS-package sweep
    // is irrelevant to a Python requirements/pyproject sync.
    this.getInstalled(projectDir, { scanVenv: true, scanOs: false });
    const pythonPkgs = this.inventoryData.filter(c => c.ecosystem === "python");
    if (!pythonPkgs.length) return;

    // Component names off PythonVenvScanner are already normalized
    // (lowercase, underscores→dashes — see _scanVenv() in python_runner.js),
    // matching the normalization requirements.txt/pyproject.toml lines get
    // below, so lookups by name just work without re-normalizing here.
    const installedByName = new Map(pythonPkgs.map(c => [c.name, { name: c.name, version: c.version }]));

    const pyprojectSynced = this._syncPyprojectToml(projectDir, installedByName);
    if (pyprojectSynced) return;
    fs.writeFileSync(path.join(projectDir, "requirements.txt"), "", { flag: "a" });
    this._syncRequirementsTxt(projectDir, installedByName);
  }

  // Extracts the leading `name[extras]` portion of a requirement/PEP 508
  // spec string — same char class _assignScopes()'s parseReqs() and
  // _readDistInfo() already split on elsewhere in this codebase, for
  // consistency. Returns null for a line that doesn't start with a name.
  _splitReqNameExtras(spec) {
    const m = /^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?/.exec(spec.trim());
    if (!m) return null;
    return { norm: m[1].toLowerCase().replace(/_/g, "-"), extras: m[2] || "" };
  }

  /**
   * Updates an existing requirements.txt in place: any line whose package
   * name matches something in installedByName gets its version pin
   * rewritten to `name[extras]==<installed version>`; anything installed
   * but not yet listed is appended as a new `name==version` line.
   * Comments, blank lines, and directive lines (-r/-c/-e/--index-url/etc.)
   * are left untouched — same "not a requirement line" filter
   * _assignScopes()'s parseReqs() already uses. Lines for packages that
   * *aren't* actually installed (failed install, platform-specific marker
   * that didn't match this platform) are also left untouched — there's no
   * installed version to pin them to.
   */
  _syncRequirementsTxt(projectDir, installedByName) {
    const reqPath = path.join(projectDir, "requirements.txt");
    if (!fs.existsSync(reqPath)) return;

    const original = fs.readFileSync(reqPath, "utf8");
    const hadTrailingNewline = original.endsWith("\n");
    const lines = original.split("\n");
    if (hadTrailingNewline && lines[lines.length - 1] === "") lines.pop();

    const seen = new Set();
    const updated = lines.map(line => {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("-")) return line;

      const parsed = this._splitReqNameExtras(trimmed);
      const pkg = parsed && installedByName.get(parsed.norm);
      if (!parsed || !pkg) return line;

      seen.add(parsed.norm);
      return `${pkg.name}${parsed.extras}==${pkg.version}`;
    });

    const additions = [];
    for (const [norm, pkg] of installedByName) {
      if (!seen.has(norm)) additions.push(`${pkg.name}==${pkg.version}`);
    }
    additions.sort();

    const finalLines = [...updated, ...additions];
    fs.writeFileSync(reqPath, finalLines.join("\n") + "\n");
  }

  /**
   * Updates an existing pyproject.toml's [project].dependencies array in
   * place, same rewrite/append rule as _syncRequirementsTxt(). Everything
   * outside the array's line range is left byte-for-byte untouched; the
   * array itself is always rewritten in a canonical one-entry-per-line
   * form (matching what `uv add`/most build backends already produce)
   * rather than trying to preserve the original's exact formatting —
   * simpler and safer than reconstructing arbitrary single-line/multi-line
   * array styles.
   *
   * No-ops (leaves the file untouched) if there's no [project] table or no
   * dependencies array to find — same scope boundary
   * parsePyprojectDependencies() already documents (no Poetry legacy
   * table, no speculative insertion of a dependencies array that isn't
   * there).
   */
  _syncPyprojectToml(projectDir, installedByName) {
    const tomlPath = path.join(projectDir, "pyproject.toml");
    if (!fs.existsSync(tomlPath)) return false;

    const raw = fs.readFileSync(tomlPath, "utf8");
    const lines = raw.split("\n");

    let currentTable = null;
    let inArray = false;
    let arrayStart = -1, arrayEnd = -1;

    for (let i = 0; i < lines.length; i++) {
      const line = this._stripTomlComment(lines[i]).trim();
      if (!line) continue;

      if (inArray) {
        if (line.includes("]")) { arrayEnd = i; break; }
        continue;
      }

      const tableMatch = /^\[([^\]]+)\]$/.exec(line);
      if (tableMatch) { currentTable = tableMatch[1].trim(); continue; }

      if (currentTable === "project") {
        const depMatch = /^dependencies\s*=\s*(.*)$/.exec(line);
        if (depMatch) {
          arrayStart = i;
          if (depMatch[1].includes("]")) { arrayEnd = i; break; }
          inArray = true;
        }
      }
    }

    if (arrayStart === -1 || arrayEnd === -1) return false; // no [project].dependencies array — nothing to update

    const existingDeps = this.parsePyprojectDependencies(tomlPath);
    const seen = new Set();
    const finalSpecs = [];

    for (const spec of existingDeps) {
      const parsed = this._splitReqNameExtras(spec);
      const pkg = parsed && installedByName.get(parsed.norm);
      if (!parsed || !pkg) { finalSpecs.push(spec); continue; }

      seen.add(parsed.norm);
      finalSpecs.push(`${pkg.name}${parsed.extras}==${pkg.version}`);
    }

    const additions = [];
    for (const [norm, pkg] of installedByName) {
      if (!seen.has(norm)) additions.push(`${pkg.name}==${pkg.version}`);
    }
    additions.sort();
    finalSpecs.push(...additions);

    const newBlock = [
      "dependencies = [",
      ...finalSpecs.map(s => `    "${s.replace(/\\/g, "\\\\").replace(/"/g, '\\"')}",`),
      "]",
    ];

    const newLines = [...lines.slice(0, arrayStart), ...newBlock, ...lines.slice(arrayEnd + 1)];
    fs.writeFileSync(tomlPath, newLines.join("\n"));
    return true;
  }

  // ── pyproject.toml dependency extraction (PEP 621 [project] table) ──────────
  //
  // Not a general TOML parser — Node has no built-in TOML support, and
  // pulling in a third-party one would break UBEL's zero-runtime-dependency
  // design (see python_runner.js/os_metadata.js for the same hand-rolled
  // approach to METADATA/os-release parsing). This reads just enough
  // structure to find the `[project]` table's `dependencies = [...]` array
  // of PEP 508 requirement strings — the standardized location every modern
  // build backend (setuptools, hatchling, poetry-core in PEP 621 mode, pdm,
  // flit) writes to. **Not supported:** Poetry's legacy
  // `[tool.poetry.dependencies]` table — that's a different, non-PEP-508
  // syntax entirely (`requests = "^2.31"` rather than a list of strings),
  // needing its own translator rather than a tweak to this parser — and
  // `[project.optional-dependencies]` (extras) — deliberately out of scope
  // here since a firewall gating "what would `pip install <project>` pull
  // in" should reflect the same deps `pip install .` resolves by default,
  // not every optional extra a project happens to declare.

  _stripTomlComment(line) {
    // Removes a trailing `# comment`, but not a `#` that appears inside a
    // quoted string (e.g. a git+https URL with `#egg=name`). Quote state is
    // tracked per line, not across lines — a PEP 508 string split across
    // multiple TOML lines (unusual, but legal TOML) can defeat this; keeping
    // each dependency on one line, as virtually every real pyproject.toml
    // does, avoids the edge case entirely.
    let inSingle = false, inDouble = false;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (ch === "'" && !inDouble) inSingle = !inSingle;
      else if (ch === '"' && !inSingle) inDouble = !inDouble;
      else if (ch === "#" && !inSingle && !inDouble) return line.slice(0, i);
    }
    return line;
  }

  parsePyprojectDependencies(tomlPath) {
    const raw = fs.readFileSync(tomlPath, "utf8");
    const lines = raw.split("\n");

    let currentTable = null;
    let inDependenciesArray = false;
    let arrayBuffer = "";
    const deps = [];

    const flushArray = () => {
      // Every double- or single-quoted token in the buffer is a dependency
      // string — this works whether the array was written on one line
      // (`dependencies = ["a", "b"]`) or spread across several, since we
      // accumulate raw text until the closing `]` regardless of line breaks.
      const items = arrayBuffer.match(/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'/g) || [];
      for (const item of items) {
        const unquoted = item.slice(1, -1).replace(/\\(.)/g, "$1").trim();
        if (unquoted) deps.push(unquoted);
      }
      arrayBuffer = "";
      inDependenciesArray = false;
    };

    for (const rawLine of lines) {
      const line = this._stripTomlComment(rawLine).trim();
      if (!line) continue;

      if (inDependenciesArray) {
        arrayBuffer += " " + line;
        if (line.includes("]")) flushArray();
        continue;
      }

      const tableMatch = /^\[([^\]]+)\]$/.exec(line);
      if (tableMatch) {
        currentTable = tableMatch[1].trim();
        continue;
      }

      if (currentTable === "project") {
        const depMatch = /^dependencies\s*=\s*(.*)$/.exec(line);
        if (depMatch) {
          arrayBuffer = depMatch[1];
          if (arrayBuffer.includes("]")) flushArray();
          else inDependenciesArray = true;
        }
      }
    }

    return deps;
  }

  // ── Default package-source resolution ────────────────────────────────────────
  // Used when `check`/`install` get no CLI package arguments. Checked in
  // order: ./requirements.txt, then ./pyproject.toml's [project] deps.
  // Either source just produces a flat list of PEP 508 specifier strings
  // fed into the normal runDryRun() pipeline below — a pyproject.toml isn't
  // treated any differently from a requirements.txt or CLI args once
  // parsed, and in particular this never runs `pip install .`/`-e .`
  // against the project itself. The real install always ends up going
  // through _generateRequirementsFile() (see engine.js) and `pip install -r
  // <generated file>` against the fully-resolved, exact-pinned set — same
  // as every other input source, toml included.
  //
  // Returns an array of specifier strings, or null if neither source exists
  // (or a pyproject.toml exists but declares no [project] dependencies).

  resolveDefaultPackages(projectRoot) {
    const reqPath = path.join(projectRoot, "requirements.txt");
    if (fs.existsSync(reqPath)) {
      return fs.readFileSync(reqPath, "utf8")
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#"));
    }

    const tomlPath = path.join(projectRoot, "pyproject.toml");
    if (fs.existsSync(tomlPath)) {
      const deps = this.parsePyprojectDependencies(tomlPath);
      if (deps.length || deps.length===0) return deps;
    }

    return null;
  }

  // ── get_installed (health mode) ──────────────────────────────────────────────

  /**
   * Scan installed packages rooted at startDir.
   *
   * @param {string}  startDir
   * @param {object}  opts
   * @param {boolean} [opts.scanVenv=true]  Include Python venvs. Default true.
   * @param {boolean} [opts.scanOs=false]   Include host OS packages (LinuxHostScanner).
   *
   * Note: unlike Pypi_Manager.get_installed()'s `full_stack` option, this
   * port does not re-aggregate every other language ecosystem here — that
   * aggregation already exists on the Node side via NodeManagerInstance's own
   * full_stack scan (`ubel-npm health --full-stack`), which already includes
   * Python venvs. `full_stack` is accepted for interface parity but only
   * affects OS packages here; use ubel-npm for the full multi-ecosystem sweep.
   */
  getInstalled(startDir, opts = {}) {
    const { scanVenv = true, scanOs = false } = opts;

    const allComponents = [];

    if (scanVenv) {
      const scanner = new PythonVenvScanner();
      scanner.getInstalled(path.resolve(startDir));
      allComponents.push(...scanner.inventoryData);
    }

    if (scanOs) {
      try {
        const linuxScanner = new LinuxHostScanner();
        linuxScanner.getInstalled();
        allComponents.push(...linuxScanner.inventoryData);
      } catch { /* one failing ecosystem must not block the others */ }
    }

    const merged = this.mergeInventoryByPurl(allComponents);
    this.inventoryData = merged;
    return merged.map(c => c.id);
  }

  // ── CLI isolation helpers (ubel-pipx) ────────────────────────────────────────

  _toolDirs(packageSpec, baseDir) {
    let rawName = packageSpec.split("[")[0].split("@")[0];
    for (const op of ["==", "!=", ">=", "<=", ">", "<", "~="]) {
      rawName = rawName.split(op)[0];
    }
    const normName = rawName.trim().toLowerCase().replace(/-/g, "_");

    const toolDir = path.join(path.resolve(baseDir), normName);
    const venvDir = path.join(toolDir, ".venv");
    return { toolDir, venvDir };
  }

  _ubelBinDir() {
    if (process.platform === "win32") {
      const appdata = process.env.APPDATA || path.join(os.homedir(), "AppData", "Roaming");
      return path.join(appdata, "ubel", "bin");
    }
    return path.join(os.homedir(), ".ubel", "bin");
  }

  _ensureBinInPath(binDir) {
    // Linux/macOS: append an export line to the first rc file found.
    // Windows PATH persistence (registry) is intentionally out of scope here —
    // Node has no first-class registry API without a native addon; document
    // the manual step instead.
    if (process.platform === "win32") {
      console.error(
        `[ubel] Add this to your user PATH manually via System Properties → Environment Variables:\n` +
        `       ${binDir}`
      );
      return;
    }

    const rcCandidates = [".bashrc", ".zshrc", ".profile"].map(f => path.join(os.homedir(), f));
    const rcFile = rcCandidates.find(f => fs.existsSync(f)) || path.join(os.homedir(), ".profile");

    const exportLine = `\nexport PATH="${binDir}:$PATH"  # added by ubel\n`;
    const existing = fs.existsSync(rcFile) ? fs.readFileSync(rcFile, "utf8") : "";

    if (!existing.includes(binDir)) {
      fs.appendFileSync(rcFile, exportLine);
      console.error(
        `[ubel] Added ${binDir} to PATH in ${rcFile}.\n` +
        `       Run:  source ${rcFile}  (or open a new terminal).`
      );
    }
  }

  _writeShim(shimPath, target) {
    if (process.platform === "win32") {
      fs.writeFileSync(`${shimPath}.cmd`, `@echo off\r\n"${target}" %*\r\n`);
      fs.writeFileSync(
        `${shimPath}.py`,
        `import subprocess, sys, os\nsys.exit(subprocess.call([${JSON.stringify(String(target))}] + sys.argv[1:]))\n`
      );
      return;
    }
    fs.writeFileSync(shimPath, `#!/bin/sh\nexec "${target}" "$@"\n`);
    fs.chmodSync(shimPath, 0o755);
  }

  _detectEntryPoints(packageSpec, venvDir) {
    const python = this._venvPython(venvDir);
    const binDir = path.join(venvDir, process.platform === "win32" ? "Scripts" : "bin");

    let rawName = packageSpec.split("[")[0].split("@")[0];
    for (const op of ["==", "!=", ">=", "<=", ">", "<", "~="]) {
      rawName = rawName.split(op)[0];
    }
    const distName = rawName.trim();

    let entryNames = [];
    const probe =
      `import json, importlib.metadata as m; ` +
      `eps = m.entry_points(group='console_scripts', package=${JSON.stringify(distName)}); ` +
      `print(json.dumps([ep.name for ep in eps]))`;

    try {
      const r = spawnSync(python, ["-c", probe], { encoding: "utf8" });
      if (r.status === 0) entryNames = JSON.parse((r.stdout || "[]").trim());
    } catch { /* fall through to directory diff below */ }

    const baselinePrefixes = ["python", "pip", "wheel", "activate", "deactivate", "easy_install"];
    if (entryNames.length === 0 && fs.existsSync(binDir)) {
      for (const name of fs.readdirSync(binDir)) {
        const stem = process.platform === "win32" ? name.replace(/\.[^.]+$/, "") : name;
        if (baselinePrefixes.some(pfx => stem.startsWith(pfx))) continue;
        const full = path.join(binDir, name);
        const st = fs.statSync(full);
        if (process.platform !== "win32" && (st.mode & 0o111)) {
          entryNames.push(name);
        } else if (process.platform === "win32" && /\.(exe|cmd)$/i.test(name)) {
          entryNames.push(stem);
        }
      }
    }

    const resultMap = new Map();
    for (const name of entryNames) {
      const candidates = [path.join(binDir, name)];
      if (process.platform === "win32") {
        candidates.push(path.join(binDir, `${name}.exe`), path.join(binDir, `${name}.cmd`));
      }
      for (const candidate of candidates) {
        if (fs.existsSync(candidate)) { resultMap.set(name, candidate); break; }
      }
    }
    return resultMap;
  }

  // ── dry_run_cli ───────────────────────────────────────────────────────────────

  dryRunCli(packageSpec, baseDir = path.join(os.homedir(), ".ubel", "tools", "python")) {
    const { venvDir } = this._toolDirs(packageSpec, baseDir);
    this.initVenv(venvDir);
    return this.runDryRun([packageSpec], venvDir);
  }

  // ── install_cli ───────────────────────────────────────────────────────────────

  installCli(packageSpec, baseDir = path.join(os.homedir(), ".ubel", "tools", "python"), binDir = null) {
    const { toolDir, venvDir } = this._toolDirs(packageSpec, baseDir);

    if (fs.existsSync(toolDir)) fs.rmSync(toolDir, { recursive: true, force: true });
    fs.mkdirSync(toolDir, { recursive: true });

    const resolvedBin = binDir ? path.resolve(binDir) : this._ubelBinDir();
    fs.mkdirSync(resolvedBin, { recursive: true });
    this._ensureBinInPath(resolvedBin);

    this.initVenv(venvDir);
    const python = this._venvPython(venvDir);

    const cmd = [python, "-m", "pip", "install", "--quiet", packageSpec];
    const r = spawnSync(cmd[0], cmd.slice(1));
    if (r.status !== 0) {
      throw new Error(`pip install failed (exit ${r.status}): ${cmd.join(" ")}`);
    }

    const entryPoints = this._detectEntryPoints(packageSpec, venvDir);
    if (entryPoints.size === 0) {
      console.error(
        `[ubel] No console-script entry-points found for '${packageSpec}'.\n` +
        `       The package was installed at ${venvDir} but no global\n` +
        `       shim was created. You can invoke it directly via:\n` +
        `         ${python}`
      );
    }

    const shims = [];
    for (const [scriptName, venvBin] of entryPoints) {
      const shimPath = path.join(resolvedBin, scriptName);
      this._writeShim(shimPath, venvBin);
      shims.push(shimPath);
    }

    const metadata = {
      package_spec: packageSpec,
      venv_dir: venvDir,
      bin_dir: resolvedBin,
      entry_points: Object.fromEntries(entryPoints),
      shims,
    };
    fs.writeFileSync(path.join(toolDir, "metadata.json"), JSON.stringify(metadata, null, 2));

    return { toolDir, venvDir, entryPoints: Object.fromEntries(entryPoints), shims, binDir: resolvedBin };
  }
}

export default PypiManagerInstance;