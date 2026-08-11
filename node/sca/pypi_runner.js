// pypi_runner.js
//
// JS port of Pypi_Manager (python_runner.py) — the firewall-relevant subset.
// PythonVenvScanner (python_runner.js) already covers pure inventory scanning
// (health mode); this file adds the pre-install firewall mechanics so
// `ubel-pip`/`ubel-uv`/`ubel-pipx` can gate an install the same way
// `ubel-npm` gates `npm ci`:
//
//   initVenv(venvDir)               → create a venv at venvDir (idempotent)
//   getPipVersion(python)           → pip version installed in the venv
//   getUvVersion()                  → uv version on PATH
//   runDryRun(initialArgs, venvDir) → dry-run resolution, branches on
//                                      this.installer ("pip" → `pip install
//                                      --dry-run --report`; "uv" → `uv pip
//                                      compile`, see below) — same returned
//                                      component structure either way
//   runRealInstall(fileName, engine, venvDir) → `pip install -r` / `uv pip
//                                      install -r` inside the venv
//   dryRunCli(packageSpec)          → dry-run for a CLI package in an isolated venv (pip only)
//   installCli(packageSpec)         → install a CLI package + expose global shims (pip only)
//   getInstalled(startDir, opts)    → health-mode scan (delegates to PythonVenvScanner)
//
// pip vs uv, and why they're NOT just "the same command, different binary":
// pip's `--dry-run --report <path>` produces a JSON install plan with each
// package's declared `requires_dist`, so the resulting dependency graph
// (who depends on whom) comes straight from the report. uv has no
// equivalent for `pip install` — `uv pip install --dry-run` exists, but
// (confirmed by testing directly against uv 0.11.7) writes a flat
// `+ name==version` list to **stderr**, with no dependency relationships,
// and it only reports what would *change* — a fully-satisfied install
// prints nothing at all, same limitation pip's own dry-run --report has.
// `uv pip compile -` (piping specifiers via stdin) instead gives a full
// resolution every time, on **stdout**, annotated with `# via <parent>`
// per package — that's what runDryRun uses for the "uv" installer, and how
// dependency provenance (introduced_by/parents/dependency_sequences) is
// reconstructed for uv-sourced scans. Neither pip nor uv can resolve a
// source-only package's metadata without potentially building an sdist —
// see the caveat in _runDryRunUv()/the pip branch below.
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
   * "uv" uses `uv pip compile`. Either way: the venv must already exist
   * (call initVenv() first), and returns a list of PURL id strings, with
   * full records landing in this.inventoryData.
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

  // ── uv dry-run ────────────────────────────────────────────────────────────────
  //
  // Uses `uv pip compile -` (specifiers piped via stdin) rather than
  // `uv pip install --dry-run`. Confirmed by direct testing against uv
  // 0.11.7 — the two behave quite differently and `compile` is the better
  // fit here:
  //   - `pip install --dry-run` only reports what would *change*: on an
  //     already-satisfied target it prints nothing at all (same limitation
  //     pip's own --dry-run --report has — not a uv-specific gap), and its
  //     output has no dependency relationships between packages.
  //   - `pip compile -` always resolves the FULL graph regardless of
  //     what's already installed, is unaffected by the target venv's
  //     current state, and annotates every non-root package with
  //     `# via <parent(s)>` — which is what lets uv-sourced scans get real
  //     introduced_by/parents/dependency_sequences data, not just a flat
  //     package list.
  //
  // One honesty note, same as pip: resolving a source-only package's
  // metadata can require building an sdist, which can run arbitrary
  // setup.py/build-backend code — this is inherent to how Python packaging
  // resolution works, not something either pip's or uv's implementation
  // can avoid. A wheel-only install doesn't have this gap.

  assertUvAvailable() {
    const r = spawnSync("which", ["uv"], { encoding: "utf8" });
    if (r.status !== 0 || !r.stdout.trim()) {
      throw new Error(
        `'uv' was not found on PATH — ubel-uv requires uv to be installed ` +
        `and on PATH, the same way ubel-pnpm requires pnpm.`
      );
    }
  }

  getUvVersion() {
    try {
      const r = spawnSync("uv", ["--version"], { encoding: "utf8" });
      if (r.status !== 0) return null;
      // "uv 0.11.7 (x86_64-unknown-linux-gnu)" → "0.11.7"
      const m = /^uv\s+(\S+)/.exec((r.stdout || "").trim());
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  _runDryRunUv(initialArgs, venvDir) {
    this.assertUvAvailable();
    const python = this._venvPython(venvDir);

    const uvVersion = this.getUvVersion();
    if (uvVersion === null) throw new Error("Failed to determine uv version (`uv --version` did not succeed)");
    this.engineVersion = uvVersion;

    const args = initialArgs.filter(a => a !== "--");
    const stdinInput = args.join("\n") + "\n";

    const cmd = ["pip", "compile", "-", "--python", python, "--color", "never"];
    const result = spawnSync("uv", cmd, {
      input: stdinInput,
      encoding: "utf8",
      timeout: SUBPROCESS_TIMEOUT,
      maxBuffer: 32 * 1024 * 1024,
    });

    if (result.status !== 0) {
      throw new Error(
        `uv pip compile failed:\n` +
        `CMD: uv ${cmd.join(" ")}\n` +
        `stdout: ${result.stdout || ""}\n` +
        `stderr: ${result.stderr || ""}`
      );
    }

    // The pinned list + "# via" provenance is on stdout; progress/timing
    // ("Resolved N packages in Xms") goes to stderr — confirmed by direct
    // testing, and the opposite of where `uv pip install --dry-run` writes.
    const { packages, requiredBy } = this._parseUvCompileOutput(result.stdout || "");

    let components = [];
    for (const [norm, pkg] of packages) {
      components.push({
        id: pkg.purl,
        name: norm,
        version: pkg.version,
        type: "library",
        license: "unknown", // uv's compile output doesn't expose license metadata
        dependencies: [],   // filled in below, inverted from the parsed "via" (required-by) map
        paths: [],
        ecosystem: "python",
        scopes: ["prod"],
        state: "undetermined",
      });
    }

    const byName = new Map(components.map(c => [c.name, c]));
    for (const [childNorm, parents] of requiredBy) {
      const child = byName.get(childNorm);
      if (!child) continue;
      for (const parentNorm of parents) {
        const parent = byName.get(parentNorm);
        if (parent && !parent.dependencies.includes(child.id)) parent.dependencies.push(child.id);
      }
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
   * Parses `uv pip compile`'s stdout into a name→{name,version,purl} map
   * plus a child→Set(parents) "required by" map built from `# via <parent>`
   * annotations. Handles both forms uv emits:
   *   pkg==1.2.3
   *       # via other-pkg              (single parent, inline)
   *   pkg==1.2.3
   *       # via
   *       #   parent-a
   *       #   parent-b                 (multiple parents, one per line)
   * A package with no "# via" at all is a root (directly requested) — uv
   * confirmed to omit the annotation entirely for root packages when
   * specifiers are piped via stdin, so no "-r <file>" marker parsing is
   * needed the way a file-based compile would need.
   */
  _parseUvCompileOutput(stdout) {
    const packages   = new Map(); // normalizedName -> { name, version, purl }
    const requiredBy = new Map(); // normalizedName -> Set(parent normalizedNames)

    let current = null;
    let collectingVia = false;

    const recordVia = (childNorm, parentRaw) => {
      const parentNorm = parentRaw.trim().toLowerCase();
      if (!parentNorm || parentNorm.startsWith("-r ") || parentNorm.startsWith("-c ")) return;
      if (!requiredBy.has(childNorm)) requiredBy.set(childNorm, new Set());
      requiredBy.get(childNorm).add(parentNorm);
    };

    for (const line of stdout.split("\n")) {
      if (!line.trim()) { collectingVia = false; continue; }

      // Unindented "#" lines are header comments (e.g. "# This file was
      // autogenerated..."), never a via-continuation (those are indented).
      if (/^#/.test(line)) { collectingVia = false; continue; }

      const pinMatch = /^([A-Za-z0-9][A-Za-z0-9._-]*)==(\S+)\s*$/.exec(line);
      if (pinMatch) {
        const [, rawName, version] = pinMatch;
        const norm = rawName.toLowerCase();
        packages.set(norm, { name: norm, version, purl: this._purl(rawName, version) });
        current = norm;
        collectingVia = false;
        continue;
      }

      const viaInline = /^\s+#\s*via\s+(.+)$/.exec(line);
      if (viaInline && current) {
        recordVia(current, viaInline[1]);
        collectingVia = false;
        continue;
      }

      const viaBare = /^\s+#\s*via\s*$/.exec(line);
      if (viaBare && current) {
        collectingVia = true;
        continue;
      }

      const viaContinuation = /^\s+#\s+(\S.*)$/.exec(line);
      if (collectingVia && viaContinuation && current) {
        recordVia(current, viaContinuation[1]);
        continue;
      }

      collectingVia = false;
    }

    return { packages, requiredBy };
  }

  // ── run_real_install ─────────────────────────────────────────────────────────

  /**
   * Install packages from fileName (a requirements file — always the
   * generated, exact-pinned file from _generateRequirementsFile() in
   * engine.js, regardless of whether the dry-run source was CLI args,
   * requirements.txt, or pyproject.toml) into venvDir. Supports
   * engine="pip" or engine="uv". The venv must already exist.
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
      return r;
    }

    if (engine === "uv") {
      this.assertUvAvailable();
      const cmd = ["uv", "pip", "install", "--python", python, "-r", fileName];
      const r = spawnSync(cmd[0], cmd.slice(1), { stdio: "inherit" });
      if (r.status !== 0) {
        console.error(`[!] Package install failed (exit ${r.status}): ${cmd.join(" ")}`);
        throw new Error(`uv pip install failed (exit ${r.status})`);
      }
      return r;
    }

    throw new Error(`Unsupported engine: ${engine}`);
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
      if (deps.length) return deps;
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