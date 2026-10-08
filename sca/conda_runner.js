// conda_runner.js
//
// conda firewall for `ubel-conda` — same shape as the pip/uv firewall in
// pypi_runner.js (dry-run → scan → gated real install), implemented as a
// subclass so the pip/uv/pipx code paths are untouched:
//
//   runDryRun(initialArgs, envDir)       → `conda create --dry-run --json` against
//                                           a SCRATCH prefix that never exists
//   writeCondaSpecFile(purls, root)      → exact-pinned spec file for the scanned set
//   runRealInstall(specFile, "conda", envDir)
//                                        → `conda create|install --no-deps --file`
//   initCondaEnv(envDir)                 → empty env (idempotent), for `ubel-conda init`
//   resolveDefaultPackages(projectRoot)  → ./environment.yml / environment.yaml fallback
//   getInstalled(...)                    → inherited (health mode via PythonVenvScanner)
//
// Why a scratch prefix for the dry-run (instead of the real env, as pip does):
//   * `check` leaves nothing behind — no env directory is created.
//   * The dry-run always reports the FULL resolved closure, not just what
//     would change in an existing env (pip/uv's dry-run only report changes,
//     so a fully-satisfied target reports nothing).
//   * `conda create --yes` against an existing environment REMOVES it first.
//     Pointing a dry-run at a path that provably doesn't exist rules out
//     any chance of that, regardless of how conda treats --dry-run there.
//
// Why the real install is `--no-deps` + exact pins:
//   The dry-run output is the scanned set. Every package in it is written as
//   `channel::name==version=build`, and `--no-deps` stops the solver from
//   adding anything that wasn't scanned. If a pin can't be satisfied the
//   install fails instead of quietly installing something else.
//
// Vulnerability matching — the honest limitation:
//   OSV has no conda ecosystem. Conda packages that are Python distributions
//   (detected from conda-forge/defaults build-string conventions, see
//   _isPythonBuild()) are reported as `pkg:pypi/...` so OSV can match them.
//   Everything else (openssl, libxml2, ...) is inventoried as
//   `pkg:conda/<name>@<version>` and is NOT matched against any database.
//   engine.js leaves those components in the "undetermined" state rather
//   than "safe".
//
// Zero third-party runtime dependencies (Node stdlib only).

import fs     from "fs";
import os     from "os";
import path   from "path";
import crypto from "crypto";
import { spawnSync } from "child_process";

import { PypiManagerInstance } from "./pypi_runner.js";

const SUBPROCESS_TIMEOUT = 300_000; // ms — solving can be slow

// Fields that end up in a spec-file line or a PURL come out of conda's own
// JSON, but they're still validated before being written anywhere: a newline
// or option-looking token in a "version" must never become a spec-file line.
const SAFE_TOKEN   = /^[A-Za-z0-9._+!-]+$/;          // name / version / build
const SAFE_CHANNEL = /^[A-Za-z0-9._@+:/-]+$/;        // channel name or URL

// conda package name → PyPI name, for the common cases where they differ.
// Best-effort and deliberately short: a missing entry only costs a missed
// OSV match (the name is used as-is), never a wrong one.
const CONDA_TO_PYPI_NAME = {
  "pytorch":          "torch",
  "msgpack-python":   "msgpack",
  "py-xgboost":       "xgboost",
  "matplotlib-base":  "matplotlib",
  "pytables":         "tables",
};

export class CondaManagerInstance extends PypiManagerInstance {

  constructor() {
    super("pip");              // base class only accepts pip|uv; overridden next line
    this.installer       = "conda";
    this._condaBinPath   = null;   // cached by _resolveCondaBin()
    this._condaPlan      = [];     // [{ purl, spec }] from the last dry-run
    this._specFilePath   = null;   // set by writeCondaSpecFile()
    this._specFileSha256 = null;   // integrity digest of the file as written
  }

  // ── conda binary resolution ─────────────────────────────────────────────────
  //
  // Same problem as uv (see _resolveUvBin() in pypi_runner.js): `conda` is
  // usually a shell function installed by `conda init` in an rc file that
  // spawnSync never sources. CONDA_EXE — exported by conda's own shell hook —
  // points at the real executable, so it's tried first.

  _probeCondaVersion(bin) {
    try {
      const r = spawnSync(bin, ["--version"], { encoding: "utf8", timeout: 30_000 });
      if (r.status !== 0) return null;
      // "conda 24.5.0" — older conda versions print this on stderr.
      const m = /(?:^|\n)conda\s+(\d\S*)/.exec(`${r.stdout || ""}\n${r.stderr || ""}`);
      return m ? m[1] : null;
    } catch {
      return null;
    }
  }

  _resolveCondaBin() {
    if (this._condaBinPath) return this._condaBinPath;

    const home = os.homedir();
    const candidates = [];

    if (process.env.CONDA_EXE) candidates.push(process.env.CONDA_EXE);
    candidates.push("conda"); // bare command, resolved via PATH

    const roots = ["miniconda3", "anaconda3", "miniforge3", "mambaforge", "miniconda", "anaconda"];
    if (process.platform === "win32") {
      for (const r of roots) candidates.push(path.join(home, r, "Scripts", "conda.exe"));
      const pd = process.env.ProgramData || "C:\\ProgramData";
      for (const r of ["miniconda3", "anaconda3", "miniforge3"]) {
        candidates.push(path.join(pd, r, "Scripts", "conda.exe"));
      }
    } else {
      for (const r of roots) candidates.push(path.join(home, r, "bin", "conda"));
      candidates.push(
        "/opt/conda/bin/conda",
        "/opt/miniconda3/bin/conda",
        "/opt/anaconda3/bin/conda",
        "/opt/homebrew/Caskroom/miniconda/base/bin/conda",
        "/usr/local/Caskroom/miniconda/base/bin/conda",
        "/usr/local/miniconda3/bin/conda",
      );
    }

    for (const candidate of candidates) {
      const isBare = candidate === "conda";
      if (!isBare && !fs.existsSync(candidate)) continue;
      if (this._probeCondaVersion(candidate)) {
        this._condaBinPath = candidate;
        return candidate;
      }
    }
    return null;
  }

  assertCondaAvailable() {
    if (!this._resolveCondaBin()) {
      throw new Error(
        `'conda' was not found on PATH, via $CONDA_EXE, or in any known install location ` +
        `(~/miniconda3, ~/anaconda3, ~/miniforge3, /opt/conda, ...) — ubel-conda requires ` +
        `conda to be installed, the same way ubel-pnpm requires pnpm. If you just installed ` +
        `it, open a new terminal (or 'source' your shell rc file) so PATH picks it up.`
      );
    }
  }

  getCondaVersion() {
    const bin = this._resolveCondaBin();
    return bin ? this._probeCondaVersion(bin) : null;
  }

  // ── environment helpers ─────────────────────────────────────────────────────

  _isCondaEnv(envPath) {
    return fs.existsSync(path.join(envPath, "conda-meta"));
  }

  /**
   * Refuses (with our own message) to hand conda a path it could mistake for
   * something to overwrite: an existing directory that is non-empty and is
   * NOT a conda environment.
   */
  _assertUsableEnvPath(envPath) {
    if (this._isCondaEnv(envPath)) return;
    if (fs.existsSync(envPath)) {
      const st = fs.statSync(envPath);
      if (!st.isDirectory() || fs.readdirSync(envPath).length) {
        throw new Error(
          `${envPath} exists but is not a conda environment (no conda-meta/) and is not an ` +
          `empty directory — refusing to let conda create an environment there.`
        );
      }
    }
  }

  /**
   * Create an empty conda environment at envDir if one doesn't already exist
   * there. Idempotent. Returns the absolute env path.
   */
  initCondaEnv(envDir) {
    this.assertCondaAvailable();
    const condaBin = this._resolveCondaBin();
    const envPath  = path.resolve(envDir);

    if (this._isCondaEnv(envPath)) return envPath;
    this._assertUsableEnvPath(envPath);

    fs.mkdirSync(path.dirname(envPath), { recursive: true });
    const r = spawnSync(condaBin, ["create", "--yes", "--prefix", envPath], { stdio: "inherit" });
    if (r.status !== 0) {
      throw new Error(`'conda create' failed to create ${envPath} (exit ${r.status})`);
    }
    return envPath;
  }

  // ── dry-run ─────────────────────────────────────────────────────────────────

  /**
   * Resolve initialArgs with `conda create --dry-run --json` against a scratch
   * prefix and return the resulting PURL ids; full records land in
   * this.inventoryData and the exact install plan in this._condaPlan.
   *
   * envDir is accepted for interface parity with PypiManagerInstance.runDryRun()
   * but is deliberately not used — see the header comment.
   *
   * The dry-run only fetches repodata and runs the solver. It never downloads
   * or links a package, so — unlike pip/uv resolving a source-only package —
   * there is no build-backend execution to worry about.
   */
  runDryRun(initialArgs, envDir) { // eslint-disable-line no-unused-vars
    this.assertCondaAvailable();
    const condaBin = this._resolveCondaBin();

    const condaVersion = this.getCondaVersion();
    if (condaVersion === null) throw new Error("Failed to determine conda version (`conda --version` did not succeed)");
    this.engineVersion = condaVersion;

    const args = initialArgs.filter(a => a !== "--");
    if (!args.length) throw new Error("conda dry-run needs at least one package spec");
    // engine.js already rejects these; re-checked here so this class is safe
    // to call directly. An option-shaped "package" could add a channel or a
    // local file to the resolution.
    const optionLike = args.find(a => a.startsWith("-"));
    if (optionLike) throw new Error(`Refusing option-like package argument: ${optionLike}`);

    const scratchPrefix = path.join(os.tmpdir(), `ubel-conda-dryrun-${process.pid}-${Date.now()}`);
    if (fs.existsSync(scratchPrefix)) throw new Error(`Scratch prefix unexpectedly exists: ${scratchPrefix}`);

    const cmd = ["create", "--dry-run", "--json", "--yes", "--prefix", scratchPrefix, ...args];
    const result = spawnSync(condaBin, cmd, {
      encoding: "utf8",
      timeout: SUBPROCESS_TIMEOUT,
      maxBuffer: 64 * 1024 * 1024,
    });

    // A dry-run must leave nothing behind. Only ever removes the path we named above.
    try { if (fs.existsSync(scratchPrefix)) fs.rmSync(scratchPrefix, { recursive: true, force: true }); } catch { /* ignore */ }

    const data = this._parseCondaJson(result.stdout);

    if (result.error || result.status !== 0 || data?.success === false || data?.error) {
      const detail = data?.message || data?.error || result.error?.message || (result.stderr || "").trim() || "(no output)";
      throw new Error(
        `conda dry-run failed:\n` +
        `CMD: ${condaBin} ${cmd.join(" ")}\n` +
        `${detail}`
      );
    }
    if (data === null) {
      throw new Error(`conda dry-run did not return JSON:\nCMD: ${condaBin} ${cmd.join(" ")}\nstdout: ${result.stdout || ""}`);
    }

    const { components, plan } = this._buildFromLinkRecords(this._linkRecords(data));
    if (!components.length) {
      // Fail closed: "resolved nothing" must never read as "nothing to block".
      throw new Error(`conda dry-run resolved no packages for: ${args.join(" ")}`);
    }

    this._condaPlan = plan;
    this.inventoryData = this.buildDependencySequences(this.mergeInventoryByPurl(components));
    return this.inventoryData.map(c => c.id);
  }

  _parseCondaJson(stdout) {
    const text = (stdout || "").trim();
    if (!text) return null;
    try { return JSON.parse(text); } catch { /* fall through */ }
    // Tolerate stray non-JSON lines (e.g. a plugin banner) before the object.
    const start = text.indexOf("{");
    if (start > 0) { try { return JSON.parse(text.slice(start)); } catch { /* fall through */ } }
    return null;
  }

  /** actions.LINK is an array in current conda; older versions nested it in a list. */
  _linkRecords(data) {
    const a = data?.actions;
    const out = [];
    if (Array.isArray(a)) {
      for (const entry of a) if (Array.isArray(entry?.LINK)) out.push(...entry.LINK);
    } else if (a && Array.isArray(a.LINK)) {
      out.push(...a.LINK);
    }
    return out;
  }

  /**
   * Python distribution? conda-forge and defaults both put a `py` token in the
   * build string of every package that depends on Python:
   *   py311h459d7ec_0   pyhd8ed1ab_0   py_0   cpu_generic_py311h2b6f4c3_0   py3.11_cuda12.1_0
   * Matched per `_`-separated token so prefixes like `cpu_`/`cuda120_` don't hide it.
   */
  _isPythonBuild(build) {
    return build.split("_").some(tok => /^py(?:\d+(?:\.\d+)*)?(?:h[0-9a-f]+)?$/.test(tok));
  }

  _condaPurl(name, version, build) {
    if (this._isPythonBuild(build)) {
      const pypiName = (CONDA_TO_PYPI_NAME[name] ?? name).toLowerCase().replace(/_/g, "-");
      return { purl: `pkg:pypi/${encodeURIComponent(pypiName)}@${version}`, pypiName, python: true };
    }
    return { purl: `pkg:conda/${encodeURIComponent(name)}@${version}`, pypiName: null, python: false };
  }

  _buildFromLinkRecords(records) {
    const seen       = new Set();
    const components = [];
    const plan       = [];

    for (const rec of records) {
      const name    = rec?.name;
      const version = rec?.version;
      const build   = rec?.build_string ?? rec?.build;
      const subdir  = rec?.platform ?? "";
      let   channel = rec?.channel ?? "";

      if (![name, version, build].every(v => typeof v === "string" && SAFE_TOKEN.test(v))) {
        // Can't pin it exactly → can't safely install exactly what was scanned.
        throw new Error(`conda returned a package record that can't be pinned: ${JSON.stringify({ name, version, build })}`);
      }
      if (!channel || channel === "<unknown>") channel = "";
      if (channel && (!SAFE_CHANNEL.test(channel) || channel.includes("::"))) {
        throw new Error(`conda returned an unusable channel for ${name}: ${JSON.stringify(channel)}`);
      }

      const key = `${name}==${version}=${build}`;
      if (seen.has(key)) continue;
      seen.add(key);

      const { purl, pypiName, python } = this._condaPurl(name, version, build);
      plan.push({ purl, spec: `${channel ? `${channel}::` : ""}${name}==${version}=${build}` });

      components.push({
        id: purl,
        name: python ? pypiName : name.toLowerCase(),
        version,
        type: "library",
        license: "unknown",   // dry-run exposes no metadata beyond name/version/build
        dependencies: [],     // conda's dry-run JSON carries no dependency edges — every component is a root
        paths: [],
        ecosystem: python ? "python" : "conda",
        scopes: ["prod"],
        state: "undetermined",
        conda: { name, version, build, channel, subdir },
      });
    }

    return { components, plan };
  }

  // ── spec file (the exact set that was scanned) ─────────────────────────────

  /**
   * Writes the exact-pinned spec file for the dry-run's plan to
   * <projectRoot>/.ubel/dependencies/conda-specs.txt and remembers its SHA-256
   * so runRealInstall() can detect tampering between here and the install.
   * `purls` is the scanned set engine.js ended up with; if it doesn't cover
   * the plan, the scan and the install have diverged and this throws.
   */
  writeCondaSpecFile(purls, projectRoot) {
    if (!this._condaPlan.length) throw new Error("No conda plan to install — runDryRun() must run first.");

    const scanned = new Set(purls);
    const lines   = [];
    for (const entry of this._condaPlan) {
      if (!scanned.has(entry.purl)) {
        throw new Error(`Scanned set does not include ${entry.purl} from the resolved plan — refusing to install an unscanned package.`);
      }
      lines.push(entry.spec);
    }

    const content = [...new Set(lines)].sort().join("\n") + "\n";
    const depsDir = path.join(projectRoot, ".ubel", "dependencies");
    fs.mkdirSync(depsDir, { recursive: true });
    const specFile = path.join(depsDir, "conda-specs.txt");
    fs.writeFileSync(specFile, content);

    this._specFilePath   = path.resolve(specFile);
    this._specFileSha256 = crypto.createHash("sha256").update(content).digest("hex");
    return specFile;
  }

  _verifySpecFile(fileName) {
    const resolved = path.resolve(fileName);
    if (!this._specFileSha256 || resolved !== this._specFilePath) {
      throw new Error("Refusing to install from a spec file UBEL did not generate for this scan.");
    }
    const actual = crypto.createHash("sha256").update(fs.readFileSync(resolved)).digest("hex");
    if (actual !== this._specFileSha256) {
      console.error("Spec file integrity check FAILED — the file was modified after scanning.");
      console.error(`  Expected : ${this._specFileSha256}`);
      console.error(`  Got      : ${actual}`);
      console.error(`  File     : ${resolved}`);
      throw new Error("conda spec file changed between scan and install — install aborted.");
    }
  }

  // ── real install ────────────────────────────────────────────────────────────

  /**
   * Install exactly what writeCondaSpecFile() produced into envDir.
   * Signature matches PypiManagerInstance.runRealInstall(fileName, engine, venvDir).
   *
   *   envDir has conda-meta/ → `conda install --no-deps --file`
   *   envDir absent / empty  → `conda create  --no-deps --no-default-packages --file`
   *
   * `create` is NEVER run against an existing conda environment (`create --yes`
   * would remove it first). Conda runs each package's own post-link scripts on
   * a real install; conda has no flag UBEL could pass to suppress them.
   *
   * Unlike pip/uv, no requirements.txt/pyproject.toml sync happens afterwards —
   * a conda env's package set isn't a pip requirements list.
   */
  runRealInstall(fileName, engine, envDir) {
    if (engine !== "conda") throw new Error(`Unsupported engine: ${engine}`);

    this.assertCondaAvailable();
    const condaBin = this._resolveCondaBin();
    this._verifySpecFile(fileName);

    const envPath = path.resolve(envDir);
    this._assertUsableEnvPath(envPath);

    const cmd = this._isCondaEnv(envPath)
      ? ["install", "--yes", "--prefix", envPath, "--no-deps", "--file", fileName]
      : ["create",  "--yes", "--prefix", envPath, "--no-deps", "--no-default-packages", "--file", fileName];

    if (cmd[0] === "create") fs.mkdirSync(path.dirname(envPath), { recursive: true });

    const r = spawnSync(condaBin, cmd, { stdio: "inherit" });
    if (r.status !== 0) {
      console.error(`[!] Package install failed (exit ${r.status}): ${condaBin} ${cmd.join(" ")}`);
      throw new Error(`conda ${cmd[0]} failed (exit ${r.status})`);
    }
    return r;
  }

  // ── default package source (no CLI args) ────────────────────────────────────

  /**
   * ./environment.yml, then ./environment.yaml — the `dependencies:` entries
   * as match specs. Returns null if neither file exists.
   *
   * Not a YAML parser (zero-dependency, same approach as parsePyprojectDependencies):
   * it reads the flat `dependencies:` list. Two things are deliberately NOT
   * honoured and are reported when present: a nested `- pip:` block (those
   * packages are installed by pip, outside this firewall — use ubel-pip for
   * them) and `channels:` (conda's own configured channels apply, so what
   * gets scanned is exactly what conda resolves on this machine).
   */
  resolveDefaultPackages(projectRoot) {
    for (const f of ["environment.yml", "environment.yaml"]) {
      const p = path.join(projectRoot, f);
      if (fs.existsSync(p)) return this.parseEnvironmentYaml(p);
    }
    return null;
  }

  parseEnvironmentYaml(file) {
    const specs    = [];
    const channels = [];
    let section    = null;
    let inPip      = false;
    let pipIndent  = -1;
    let pipSkipped = 0;

    for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
      const line = raw.replace(/(^|\s)#.*$/, "");
      if (!line.trim()) continue;

      const indent  = line.length - line.trimStart().length;
      const trimmed = line.trim();

      if (indent === 0 && !trimmed.startsWith("-")) {
        const m = /^([A-Za-z_][\w-]*)\s*:/.exec(trimmed);
        section = m ? m[1] : null;
        inPip = false;
        continue;
      }
      if (!trimmed.startsWith("-")) continue;

      const item = trimmed.slice(1).trim().replace(/^(['"])(.*)\1$/, "$2");
      if (!item) continue;

      if (section === "channels") { channels.push(item); continue; }
      if (section !== "dependencies") continue;

      if (inPip && indent > pipIndent) { pipSkipped++; continue; }
      inPip = false;

      if (/^pip\s*:\s*$/.test(item)) { inPip = true; pipIndent = indent; continue; }
      specs.push(item);
    }

    if (pipSkipped) {
      console.log(`[i] ${path.basename(file)}: ${pipSkipped} package(s) under \`- pip:\` are not covered by ubel-conda — scan them with ubel-pip.`);
    }
    if (channels.length) {
      console.log(`[i] ${path.basename(file)}: channels (${channels.join(", ")}) are ignored — conda's configured channels apply.`);
    }
    return specs;
  }
}

export default CondaManagerInstance;