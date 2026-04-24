import fs   from "fs";
import path  from "path";
import { spawnSync }    from "child_process";
import { fileURLToPath } from "url";

import { LockfileParser } from "./lockfiles_parser.js";
import { TOOL_NAME, TOOL_VERSION, TOOL_LICENSE} from "./info.js";
import { PythonVenvScanner } from "./python_runner.js";
import {PhpComposerScanner} from "./php_runner.js";
import { RustCargoScanner} from "./rust_runner.js";
import {GoModScanner} from "./go_runner.js";
import {CSharpNuGetScanner} from "./csharp_runner.js";
import { JavaMavenScanner} from "./java_runner.js";
import { RubyBundlerScanner} from "./ruby_runner.js";
import {LinuxHostScanner} from "./linux_runner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────────────
// Engine configuration table
//
// Each entry describes how to interact with one package manager:
//   lockfile     — filename produced / read by this engine
//   dryRunCmd    — function(pkgArgs) → argv[] for a lockfile-only dry run
//   installCmd   — argv[] for a clean / frozen install (real install)
//   binary       — executable name (for PATH checks and spawnSync)
// ─────────────────────────────────────────────────────────────────────────────

const ENGINE_CONFIG = {

  npm: {
    lockfile:   "package-lock.json",
    binary:     "npm",
    dryRunCmd:  (args) => [
      "install",
      "--package-lock-only",
      "--ignore-scripts",
      "--no-audit",
      "--no-fund",
      "--omit=optional",
      ...args,
    ],
    // `npm ci` performs a clean install from the lockfile without modifying it.
    installCmd: ["ci", "--ignore-scripts"],
  },

  yarn: {
    lockfile:   "yarn.lock",
    binary:     "yarn",
    // Yarn classic (v1):  `yarn install --frozen-lockfile` reads/updates yarn.lock
    // but has no --package-lock-only analogue.  The closest safe equivalent is
    // `yarn add --frozen-lockfile` which updates yarn.lock in-place without
    // installing into node_modules when NODE_ENV=production is set with
    // --ignore-scripts.  In practice we stage the mutation, read yarn.lock,
    // then revert — which is the same pattern we use for all engines.
    dryRunCmd:  (args) => [
      "add",
      "--ignore-scripts",
      "--no-progress",
      ...args,
    ],
    // Frozen install: installs exactly what yarn.lock specifies.
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

  pnpm: {
    lockfile:   "pnpm-lock.yaml",
    binary:     "pnpm",
    // pnpm supports --lockfile-only which mirrors npm's --package-lock-only.
    dryRunCmd:  (args) => args.length
      ? ["add",     "--lockfile-only", "--ignore-scripts", "--no-optional", ...args]
      : ["install", "--lockfile-only", "--ignore-scripts", "--no-optional"],
    // Frozen install via --frozen-lockfile.
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

  bun: {
    lockfile:   "bun.lock",
    binary:     "bun",
    // Lockfile-only dry run — node_modules is never written.
    // `--ignore-scripts` suppresses pre/post-install lifecycle hooks.
    // Note: bun populates its global registry cache during this step.
    //
    // Two subcommands are needed because `bun install` does not accept package
    // name arguments — it only reads package.json.  `bun add` does accept them.
    //   • args present  → `bun add --lockfile-only`     (add new packages)
    //   • args empty    → `bun install --lockfile-only` (resolve existing deps)
    dryRunCmd: (args) => args.length
      ? ["add",     "--lockfile-only", "--ignore-scripts", ...args]
      : ["install", "--lockfile-only", "--ignore-scripts"],
    // Frozen install: installs exactly what bun.lock specifies.
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

};

// ─────────────────────────────────────────────────────────────────────────────
// NodeModulesScanner
// Walks node_modules on disk, resolves deps via Node's own resolution
// algorithm (climb to root), and produces the flat package list that
// NodeManager._scannerToTree() wraps into the nested tree shape.
// ─────────────────────────────────────────────────────────────────────────────

class NodeModulesScanner {
  constructor(rootDir = process.cwd()) {
    this.rootDir          = rootDir;
    this.nodeModulesPath  = path.join(rootDir, "node_modules");
    this.packages         = new Map();
    this.visitedPaths     = new Set();
    
  }

  scan() {
    if (!fs.existsSync(this.nodeModulesPath)) return [];

    this._walk(this.nodeModulesPath);

    const packages = Array.from(this.packages.values());

    for (const pkg of packages) {
      pkg.dependencies = this._resolveDeps(pkg);
      delete pkg._rawPkgJson;
    }

    return packages;
  }

  _walk(dir) {
    let realDir;
    try { realDir = fs.realpathSync(dir); }
    catch { return; }

    if (this.visitedPaths.has(realDir)) return;
    this.visitedPaths.add(realDir);

    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.name === ".pnpm") { this._walk(fullPath); continue; }

      if (entry.isSymbolicLink()) {
        let resolved;
        try { resolved = fs.realpathSync(fullPath); }
        catch { continue; }
        this._handlePackage(resolved);
        this._walk(resolved);
        continue;
      }

      if (!entry.isDirectory()) continue;

      if (entry.name.startsWith("@")) { this._walk(fullPath); continue; }

      this._handlePackage(fullPath);
      this._walk(fullPath);
    }
  }

  _handlePackage(pkgPath) {
    const packageJsonPath = path.join(pkgPath, "package.json");
    if (!fs.existsSync(packageJsonPath)) return;

    let pkgJson;
    try { pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8")); }
    catch { return; }

    const name    = pkgJson.name;
    const version = pkgJson.version;
    if (!name || !version) return;

    // Skip subpath-export stubs (pnpm materialises these as nested dirs)
    const parentDir         = path.dirname(pkgPath);
    const parentPkgJsonPath = path.join(parentDir, "package.json");
    if (fs.existsSync(parentPkgJsonPath)) {
      try {
        const parentPkg = JSON.parse(fs.readFileSync(parentPkgJsonPath, "utf-8"));
        if (parentPkg.name && parentPkg.name !== name && parentPkg.version) return;
      } catch {}
    }

    const key = `${name}@${version}`;
    if (this.packages.has(key)) return;

    const license =
      pkgJson.license ||
      (Array.isArray(pkgJson.licenses)
        ? pkgJson.licenses.map(l => l.type).join(", ")
        : "unknown");

    this.packages.set(key, {
      purl:        NodeManager._npmPurl(name, version),
      name,
      version,
      license,
      path:        pkgPath,
      dependencies: [],
      _rawPkgJson: pkgJson,
    });
  }

  _resolveDeps(pkg) {
    const pkgJson = pkg._rawPkgJson;
    if (!pkgJson) return [];

    const deps = new Set();

    for (const field of ["dependencies", "optionalDependencies", "peerDependencies"]) {
      if (!pkgJson[field]) continue;
      for (const depName of Object.keys(pkgJson[field])) {
        const resolved = this._findInstalledPackage(pkg.path, depName);
        deps.add(
          resolved
            ? NodeManager._npmPurl(resolved.name, resolved.version)
            : NodeManager._npmPurl(depName, "")
        );
      }
    }

    return Array.from(deps);
  }

  _findInstalledPackage(startDir, depName) {
    let current = startDir;

    while (true) {
      const nm = path.join(current, "node_modules");

      let targetPath;
      if (depName.startsWith("@")) {
        const [scope, name] = depName.split("/");
        targetPath = path.join(nm, scope, name);
      } else {
        targetPath = path.join(nm, depName);
      }

      const pkgJsonPath = path.join(targetPath, "package.json");
      if (fs.existsSync(pkgJsonPath)) {
        try {
          const pj = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
          return { name: pj.name, version: pj.version };
        } catch {}
      }

      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }

    return null;
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// NodeManager
// ─────────────────────────────────────────────────────────────────────────────

export class NodeManager {

  static inventoryData = [];
  static currentLockFileContent = null;

  static _original_package_json  = null;
  static _original_lockfile      = null;
  static _lockfileBackupDir      = null;
  static engineVersion = null;

  /**
   * Candidate lockfile content produced by the last runDryRun call.
   * Shape: parsed lockfile object (type depends on engine), or null.
   */
  static candidate_lockfile_content = null;

  /**
   * SHA-256 hex digest of the raw candidate lockfile bytes written to disk
   * by runDryRun.  Used by verifyCandidateLockfileHash() to detect any
   * on-disk mutation between the dry-run scan and the real install.
   */
  static _candidateLockfileHash = null;

  static _captureEngineVersion(binary) {
    try {
      const r = spawnSync(binary, ["--version"], { encoding: "utf8", shell: true });
      if (r.status === 0 && r.stdout) {
        NodeManager.engineVersion = r.stdout.trim().replace(/^v/, "");
      } else {
        NodeManager.engineVersion = null;
      }
    } catch {
      NodeManager.engineVersion = null;
    }
  }

  // ─────────────────────────────
  // Safe iterable helpers
  // ─────────────────────────────

  static _safeArray(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v;
    if (typeof v.values === "function") return [...v.values()];
    return [];
  }

  static _safeObjectEntries(v) {
    if (!v || typeof v !== "object") return [];
    return Object.entries(v);
  }

  // ─────────────────────────────
  // PURL construction
  // Delegates to LockfileParser.purl so there is a single canonical impl.
  // ─────────────────────────────

  static _npmPurl(name, version) {
    return LockfileParser.purl(name, version);
  }

  // ─────────────────────────────
  // Scanner → component tree
  // ─────────────────────────────

  static tree_data = null;

  static _scannerToTree(rootDir) {
    const scanner = new NodeModulesScanner(rootDir);
    const pkgs    = scanner.scan();

    const nodes = pkgs.map(pkg => ({
      id:           pkg.purl,
      base_id:      pkg.purl,
      name:         pkg.name,
      version:      pkg.version,
      path:         pkg.path,
      paths:        [pkg.path],
      license:      pkg.license ?? null,
      ecosystem:    "npm",
      state:        "undetermined",
      dependencies: pkg.dependencies,
    }));

    return {
      id:           NodeManager._npmPurl("", ""),
      base_id:      NodeManager._npmPurl("", ""),
      name:         "",
      version:      "",
      path:         rootDir,
      paths:        [rootDir],
      license:      null,
      ecosystem:    "npm",
      state:        "undetermined",
      dependencies: nodes,
    };
  }

  // ─────────────────────────────
  // Lockfile → component list
  //
  // Delegates entirely to LockfileParser — the single source of truth for
  // all lockfile parsing across every supported engine.
  // ─────────────────────────────

  static scanLockfile(filename, content) {
    return LockfileParser.parse(filename, content);
  }

  /**
   * Legacy shim — callers that used scanPackageLock() directly still work.
   * Internally delegates to LockfileParser.parseNpmLock.
   */
  static scanPackageLock(content) {
    return LockfileParser.parseNpmLock(content);
  }

  // ─────────────────────────────
  // Validate package arg safety
  // ─────────────────────────────

  static _validatePackageArgs(args) {
    const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'"<>]+)?$/i;
    for (const arg of args) {
      if (!PKG_ARG_RE.test(arg)) {
        throw new Error(
          `Rejected unsafe package argument: '${arg}'. ` +
          `Only package specifiers (name, name@version, @scope/name@version) are allowed.`
        );
      }
    }
  }

  // ─────────────────────────────
  // Fast dry run  (all engines)
  //
  // HOW IT WORKS:
  //   1. Reset shared static state.
  //   2. Back up relevant files (package.json + lockfile) to memory + disk.
  //   3. Validate package args against an allowlist regex.
  //   4. Run the engine's lockfile-only command so only the lockfile is
  //      mutated — node_modules is never touched.
  //   5. Parse the candidate lockfile via LockfileParser.
  //   6. Diff against the original lockfile to isolate net-new packages.
  //   7. Normalise through mergeInventoryByPurl.
  //
  // The output shape is IDENTICAL regardless of which engine is used.
  // ─────────────────────────────

  static async runDryRun(engine, initialArgs) {

    // ── 0. Reset static state ────────────────────────────────────────────

    NodeManager.inventoryData              = [];
    NodeManager._original_package_json     = null;
    NodeManager._original_lockfile         = null;
    NodeManager._lockfileBackupDir         = null;
    NodeManager.candidate_lockfile_content = null;
    NodeManager._candidateLockfileHash     = null;

    // ── 1. Validate engine ───────────────────────────────────────────────

    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      throw new Error(
        `Invalid engine '${engine}'. Must be one of: ${Object.keys(ENGINE_CONFIG).join(", ")}`
      );
    }

    if (!NodeManager.engineVersion) {
      throw new Error(
        `Failed to determine version of '${engine}' (tried '${cfg.binary} --version'). ` +
        `Make sure '${cfg.binary}' is installed and on your PATH.`
      );
    } 

    const projectPath     = process.cwd();
    const packageJsonPath = path.join(projectPath, "package.json");
    const lockPath        = path.join(projectPath, cfg.lockfile);

    // ── 2. Backup originals ───────────────────────────────────────────────

    NodeManager._original_package_json = fs.existsSync(packageJsonPath)
      ? fs.readFileSync(packageJsonPath, "utf8")
      : null;

    NodeManager._original_lockfile = fs.existsSync(lockPath)
      ? fs.readFileSync(lockPath, "utf8")
      : null;

    const now = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    const ts  = `${now.getUTCFullYear()}${pad(now.getUTCMonth()+1)}${pad(now.getUTCDate())}`
              + `_${pad(now.getUTCHours())}${pad(now.getUTCMinutes())}${pad(now.getUTCSeconds())}`;
    const tmpDir = path.join(projectPath, ".ubel", "lockfiles", ts);
    fs.mkdirSync(tmpDir, { recursive: true });

    if (NodeManager._original_package_json !== null) {
      fs.writeFileSync(path.join(tmpDir, "package.json"), NodeManager._original_package_json, "utf8");
    }
    if (NodeManager._original_lockfile !== null) {
      fs.writeFileSync(path.join(tmpDir, cfg.lockfile), NodeManager._original_lockfile, "utf8");
    }

    NodeManager._lockfileBackupDir = tmpDir;

    // ── 3. Validate package args ─────────────────────────────────────────

    NodeManager._validatePackageArgs(initialArgs);

    // ── 4. Generate candidate lockfile ───────────────────────────────────

    const argv   = cfg.dryRunCmd(initialArgs);
    const result = spawnSync(cfg.binary, argv, {
      cwd:   projectPath,
      stdio: "inherit",
      shell: true,
    });

    if (result.status !== 0) {
      throw new Error(`${engine} failed to generate lockfile (exit ${result.status})`);
    }

    if (!fs.existsSync(lockPath)) {
      throw new Error(`${engine} did not produce a lockfile at ${lockPath}`);
    }

    // ── 5. Parse candidate lockfile via LockfileParser ───────────────────

    const candidateRaw = fs.readFileSync(lockPath, "utf8");
    NodeManager.candidate_lockfile_content = candidateRaw;

    // Hash the raw bytes so we can verify the file has not been tampered with
    // between the dry-run scan and the real install (TOCTOU guard).
    {
      const { createHash } = await import("crypto");
      NodeManager._candidateLockfileHash = createHash("sha256")
        .update(candidateRaw, "utf8")
        .digest("hex");
    }

    const allCandidateComponents = LockfileParser.parse(cfg.lockfile, candidateRaw);

    // ── 6. Diff: isolate net-new packages ─────────────────────────────────

    const originalPurls = new Set();
    if (NodeManager._original_lockfile) {
      try {
        for (const comp of LockfileParser.parse(cfg.lockfile, NodeManager._original_lockfile)) {
          originalPurls.add(comp.id);
        }
      } catch {
        // Original lockfile unparseable → treat all candidates as new
      }
    }

    const newComponents = allCandidateComponents.filter(c => !originalPurls.has(c.id));

    // ── 7. Normalise ──────────────────────────────────────────────────────

    const merged = NodeManager.mergeInventoryByPurl(newComponents);
    NodeManager.inventoryData = merged;
    if (NodeManager.engineVersion) {
      let engine_license = "MIT";
      if (["yarn"].includes(engine)) {
        engine_license = "BSD 2-Clause";
      }
               NodeManager.inventoryData.push({
                id: `pkg:npm/${engine}@${NodeManager.engineVersion}`,
                name: engine,
                version: NodeManager.engineVersion,
                license: engine_license,
                ecosystem: "npm",
                state: "undetermined",
                scopes: ["env"],
                dependencies: [],
                type: "library",
                paths: [],
              },
              {
                id: `pkg:npm/${TOOL_NAME}@${TOOL_VERSION}`,
                name: TOOL_NAME,
                version: TOOL_VERSION,
                license: TOOL_LICENSE,
                ecosystem: "npm",
                state: "undetermined",
                scopes: ["env", "prod", "dev"],
                dependencies: [],
                type: "library",
                paths: [],
              }
              );
            }

    // ── 8. Assign scopes ──────────────────────────────────────────────────
    // BFS scope propagation must run against the FULL candidate graph so it
    // can traverse already-present transitive deps when diffing against an
    // existing lockfile (e.g. pnpm install with a pre-existing pnpm-lock.yaml
    // produces a near-empty newComponents diff, leaving the BFS with no graph
    // to walk and all scopes empty).
    //
    // Strategy:
    //   1. Run _assignScopes on allCandidateComponents (full graph).
    //   2. Build a purl→scopes map from the result.
    //   3. Copy computed scopes back onto inventoryData (new packages only).
    //   Engine/tool entries already carry scopes: ["env"] and are left alone.

    NodeManager._assignScopes(allCandidateComponents, packageJsonPath);

    const scopeMap = new Map(allCandidateComponents.map(c => [c.id, c.scopes]));
    for (const comp of NodeManager.inventoryData) {
      if (!Array.isArray(comp.scopes) || comp.scopes.length === 0) {
        comp.scopes = scopeMap.get(comp.id) ?? [];
      }
    }

    return merged.map(c => c.id);
  }

  // ─────────────────────────────
  // Revert lockfile + package.json to originals
  // ─────────────────────────────

  static revert_lock_to_original(engine = "npm", projectPath = ".") {
    // Revert logic is intentionally identical for npm, pnpm, and bun:
    //   - npm  : restores package-lock.json + package.json
    //   - pnpm : restores pnpm-lock.yaml    + package.json
    //   - bun  : restores bun.lock          + package.json
    // All three engines mutate both files during a dry-run (npm install
    // --package-lock-only, pnpm add --lockfile-only, bun add --lockfile-only),
    // so both must be reverted.  ENGINE_CONFIG supplies the correct lockfile
    // name per engine; no per-engine special-casing is needed here.

    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      return {
        reverted:  false,
        reason:    `Unknown engine '${engine}' — cannot determine lockfile name`,
        backupDir: NodeManager._lockfileBackupDir,
      };
    }

    const packageJsonPath = path.join(projectPath, "package.json");
    const lockPath        = path.join(projectPath, cfg.lockfile);
    const tmpDir          = NodeManager._lockfileBackupDir;

    try {
      // Restore package.json — primary source is in-memory; disk backup is the
      // safety net (e.g. after a process restart or if memory was cleared).
      let pkgContent = NodeManager._original_package_json;
      if (pkgContent === null && tmpDir) {
        const disk = path.join(tmpDir, "package.json");
        if (fs.existsSync(disk)) pkgContent = fs.readFileSync(disk, "utf8");
      }
      if (pkgContent !== null) {
        fs.writeFileSync(packageJsonPath, pkgContent, "utf8");
      } else if (fs.existsSync(packageJsonPath)) {
        // No original existed before the dry-run — remove the engine-created
        // file so the project is left exactly as it was found.
        fs.unlinkSync(packageJsonPath);
      }

      // Restore lockfile — same two-tier strategy as package.json above.
      let lockContent = NodeManager._original_lockfile;
      if (lockContent === null && tmpDir) {
        const disk = path.join(tmpDir, cfg.lockfile);
        if (fs.existsSync(disk)) lockContent = fs.readFileSync(disk, "utf8");
      }
      if (lockContent !== null) {
        fs.writeFileSync(lockPath, lockContent, "utf8");
      } else if (fs.existsSync(lockPath)) {
        // No lockfile existed before the dry-run — remove the generated one.
        fs.unlinkSync(lockPath);
      }

      return { reverted: true, backupDir: tmpDir };

    } catch (err) {
      return { reverted: false, reason: err.message, backupDir: tmpDir };
    }
  }

  // ─────────────────────────────
  // Delete the tmp backup dir
  // ─────────────────────────────

  static cleanupLockfileBackup() {
    const tmpDir = NodeManager._lockfileBackupDir;
    if (!tmpDir) return { cleaned: false, reason: "no backup dir recorded" };

    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      NodeManager._lockfileBackupDir = null;
      return { cleaned: true };
    } catch (err) {
      return { cleaned: false, reason: err.message };
    }
  }

  // ─────────────────────────────
  // Save candidate lockfile
  // For npm: also regenerates package.json with exact pinned versions.
  // For other engines: only writes back the raw lockfile text.
  // ─────────────────────────────

  static saveCandidateLockfile(engine = "npm", projectPath = process.cwd()) {

    const cfg          = ENGINE_CONFIG[engine] || ENGINE_CONFIG.npm;
    const lockfilePath = path.join(projectPath, cfg.lockfile);

    if (!NodeManager.candidate_lockfile_content) {
      return {
        written:  false,
        filePath: lockfilePath,
        reason:   "candidate_lockfile_content is null — run runDryRun() first",
      };
    }

    try {
      // ── Write candidate lockfile ────────────────────────────────────────
      if (engine === "npm") {
        // npm: content was stored as a parsed object → serialise
        const parsed = typeof NodeManager.candidate_lockfile_content === "string"
          ? JSON.parse(NodeManager.candidate_lockfile_content)
          : NodeManager.candidate_lockfile_content;

        fs.writeFileSync(lockfilePath, JSON.stringify(parsed, null, 2), "utf8");

        // Regenerate package.json with exact pinned versions from the lockfile
        const packageJsonPath = path.join(projectPath, "package.json");
        const packages        = parsed.packages || {};
        const rootMeta        = packages[""] || {};

        let pkgJson = {};
        if (fs.existsSync(packageJsonPath)) {
          try { pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf8")); }
          catch { pkgJson = {}; }
        }

        const exactDeps    = {};
        const exactDevDeps = {};

        for (const [name] of Object.entries(rootMeta.dependencies || {})) {
          const meta = packages[`node_modules/${name}`];
          if (meta?.version) exactDeps[name] = meta.version;
        }
        for (const [name] of Object.entries(rootMeta.devDependencies || {})) {
          const meta = packages[`node_modules/${name}`];
          if (meta?.version) exactDevDeps[name] = meta.version;
        }

        pkgJson.dependencies = exactDeps;
        if (Object.keys(exactDevDeps).length) pkgJson.devDependencies = exactDevDeps;

        fs.writeFileSync(packageJsonPath, JSON.stringify(pkgJson, null, 2), "utf8");

        return { written: true, filePath: lockfilePath, packageJsonPath };

      } else {
        // pnpm / bun / yarn: write raw lockfile text back verbatim.
        //
        // Unlike npm, these engines update package.json in-place during the
        // dry-run (pnpm add / bun add both write exact resolved versions back).
        // The on-disk package.json is therefore already in candidate state after
        // runDryRun completes.  We read it here, write it back explicitly (so
        // the operation is atomic and the return value is consistent with the
        // npm branch), then persist the lockfile.
        const raw = typeof NodeManager.candidate_lockfile_content === "string"
          ? NodeManager.candidate_lockfile_content
          : JSON.stringify(NodeManager.candidate_lockfile_content, null, 2);

        const packageJsonPath = path.join(projectPath, "package.json");

        // Read the candidate package.json that the dry-run already wrote.
        // Fall back to the in-memory original if the file is unexpectedly absent
        // (e.g. the project never had one before the dry-run).
        let pkgJsonRaw = null;
        if (fs.existsSync(packageJsonPath)) {
          pkgJsonRaw = fs.readFileSync(packageJsonPath, "utf8");
        } else if (NodeManager._original_package_json !== null) {
          pkgJsonRaw = NodeManager._original_package_json;
        }

        fs.writeFileSync(lockfilePath, raw, "utf8");

        if (pkgJsonRaw !== null) {
          fs.writeFileSync(packageJsonPath, pkgJsonRaw, "utf8");
        }

        return { written: true, filePath: lockfilePath, packageJsonPath };
      }

    } catch (err) {
      return { written: false, filePath: lockfilePath, reason: err.message };
    }
  }

  // ─────────────────────────────
  // Export installed dependencies
  // (disk scan via NodeModulesScanner)
  // ─────────────────────────────

  static exportNpmDependencies(projectPath) {
    return Promise.resolve(NodeManager._scannerToTree(projectPath));
  }

  // ─────────────────────────────
  // Recursive project scanner
  // ─────────────────────────────

  static async getInstalled(startDir = process.cwd(), full_stack = false, os_scan = false) {

    const visited = new Set();
    const results = [];

    NodeManager.inventoryData = []; // reset shared inventory state before scan

    async function walk(dir) {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
      catch { return; }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;

        const fullPath = path.join(dir, entry.name);

        if (entry.name === "node_modules") {
          const projectRoot = dir;
          const key = path.resolve(projectRoot);
          if (visited.has(key)) continue;
          visited.add(key);

          try {
            const tree       = await NodeManager.exportNpmDependencies(projectRoot);
            const components = NodeManager.getInstalledFromTree(tree);
            NodeManager.inventoryData.push(...components);
            results.push(...components.map(c => c.id));
          } catch {}

          continue;
        }

        if (entry.name.startsWith(".")) continue;
        await walk(fullPath);
      }
    }

    await walk(startDir);

    if (full_stack) {

    await PythonVenvScanner.getInstalled();
    await PhpComposerScanner.getInstalled();
    await RustCargoScanner.getInstalled();
    await GoModScanner.getInstalled();
    await CSharpNuGetScanner.getInstalled();
    await JavaMavenScanner.getInstalled();
    await RubyBundlerScanner.getInstalled();
    NodeManager.inventoryData.push(...PythonVenvScanner.inventoryData);
    NodeManager.inventoryData.push(...PhpComposerScanner.inventoryData);
    NodeManager.inventoryData.push(...RustCargoScanner.inventoryData);
    NodeManager.inventoryData.push(...GoModScanner.inventoryData);
    NodeManager.inventoryData.push(...CSharpNuGetScanner.inventoryData);
    NodeManager.inventoryData.push(...JavaMavenScanner.inventoryData);
    NodeManager.inventoryData.push(...RubyBundlerScanner.inventoryData);
    }
    if (os_scan) {
      await LinuxHostScanner.getInstalled();
      NodeManager.inventoryData.push(...LinuxHostScanner.inventoryData);
    }

    const merged = NodeManager.mergeInventoryByPurl(NodeManager.inventoryData);
    NodeManager.inventoryData = merged;

    // Assign pro/dev/env scopes from the project's package.json.
    const pkgJsonPath = path.join(startDir, 'package.json');
    NodeManager._assignScopes(NodeManager.inventoryData, pkgJsonPath);

    return merged.map(c => c.id);
  }

  // ─────────────────────────────
  // Flatten dependency tree
  // ─────────────────────────────

  static getInstalledFromTree(tree) {
    const map = new Map();

    function walk(node) {
      if (node?.name && node?.version) {
        const id           = NodeManager._npmPurl(node.name, node.version);
        const pathLocation = node.path || null;

        if (!map.has(id)) {
          map.set(id, {
            id,
            name:         node.name,
            version:      node.version,
            type:         "library",
            license:      node.license ?? "unknown",
            ecosystem:    "npm",
            state:        "undetermined",
            scopes:       [],
            dependencies: [],
            paths:        node.paths || [],
          });
        }

        const comp = map.get(id);
        if (pathLocation && !comp.paths.includes(pathLocation)) comp.paths.push(pathLocation);

        const deps = NodeManager._safeArray(node.dependencies);
        comp.dependencies = deps.map(d => d.base_id || d.id || d);
      }

      for (const child of NodeManager._safeArray(node?.dependencies)) {
        walk(child);
      }
    }

    walk(tree);
    return [...map.values()];
  }

  // ─────────────────────────────
  // Scope assignment
  //
  // Reads package.json at pkgJsonPath to identify direct dev/pro roots, then
  // walks the dependency graph propagating scopes transitively.
  //
  // Rules:
  //   • listed in dependencies     → pro  (and all transitives)
  //   • listed in devDependencies  → dev  (and all transitives)
  //   • reachable from both roots  → both pro + dev
  //   • engine binary entries      → env only (already set at creation)
  //   • unreachable from any root  → scopes stays [] (unlisted transitive)
  // ─────────────────────────────

  static _assignScopes(inventory, pkgJsonPath) {
    // Build a PURL→component index for fast lookup.
    const byId = new Map();
    for (const comp of inventory) byId.set(comp.id, comp);

    // Initialise scopes array on every component that does not have one yet.
    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
    }

    // Read package.json — if missing, nothing to do (scopes stay []).
    let pkgJson = null;
    try {
      if (fs.existsSync(pkgJsonPath)) {
        pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, 'utf8'));
      }
    } catch { /* unparseable package.json — skip */ }

    if (!pkgJson) return;

    const proDirect = new Set(Object.keys(pkgJson.dependencies    || {}));
    const devDirect = new Set(Object.keys(pkgJson.devDependencies || {}));

    // Name index: name → comp[].  Needed because lockfile-resolved versions
    // can differ from the range specifiers in package.json.
    const nameIndex = new Map();
    for (const comp of inventory) {
      if (!nameIndex.has(comp.name)) nameIndex.set(comp.name, []);
      nameIndex.get(comp.name).push(comp);
    }

    // BFS: starting from each direct dep, tag every reachable node with scope.
    function propagate(directNames, scope) {
      const queue = [];
      for (const name of directNames) {
        for (const comp of (nameIndex.get(name) || [])) queue.push(comp);
      }
      const visited = new Set();
      while (queue.length) {
        const comp = queue.shift();
        if (visited.has(comp.id)) continue;
        visited.add(comp.id);
        if (!comp.scopes.includes(scope)) comp.scopes.push(scope);
        for (const depPurl of (comp.dependencies || [])) {
          const depComp = byId.get(depPurl);
          if (depComp) {
            if (!visited.has(depComp.id)) queue.push(depComp);
          } else {
            // Versionless PURL (pkg:npm/name@ or pkg:npm/%40scope/name@) —
            // extract the package name and resolve via nameIndex.
            const plain  = depPurl.match(/^pkg:npm\/([^%@][^@/]*)@/);
            const scoped = depPurl.match(/^pkg:npm\/%40([^@/]+)\/([^@]+)@/);
            const depName = scoped
              ? '@' + scoped[1] + '/' + scoped[2]
              : plain ? plain[1] : null;
            if (depName) {
              for (const c of (nameIndex.get(depName) || [])) {
                if (!visited.has(c.id)) queue.push(c);
              }
            }
          }
        }
      }
    }

    propagate(proDirect, 'prod');
    propagate(devDirect, 'dev');
  }

  // ─────────────────────────────
  // Merge inventory by PURL
  // ─────────────────────────────

  static mergeInventoryByPurl(components) {
    components = NodeManager._safeArray(components);
    const map  = new Map();

    for (const comp of components) {
      const id = comp.id;

      if (!map.has(id)) {
        const clone  = { ...comp };
        clone.paths  = NodeManager._safeArray(clone.paths);
        if (clone.path && !clone.paths.includes(clone.path)) clone.paths.push(clone.path);
        delete clone.path;
        map.set(id, clone);
        continue;
      }

      const existing = map.get(id);
      if (comp.path && !existing.paths.includes(comp.path)) existing.paths.push(comp.path);
      if (Array.isArray(comp.paths)) {
        for (const p of comp.paths) {
          if (p && !existing.paths.includes(p)) existing.paths.push(p);
        }
      }
      // Union-merge scopes — a package listed in both dev and prod gets both.
      if (Array.isArray(comp.scopes)) {
        if (!Array.isArray(existing.scopes)) existing.scopes = [];
        for (const s of comp.scopes) {
          if (!existing.scopes.includes(s)) existing.scopes.push(s);
        }
      }
    }

    return [...map.values()];
  }

  // ─────────────────────────────
  // Lockfile integrity check  (TOCTOU guard)
  //
  // Re-hashes the on-disk lockfile and compares it against the SHA-256
  // digest captured at the end of runDryRun.  Must be called immediately
  // before runRealInstall so that any mutation of the lockfile between the
  // dry-run scan and the real install is detected and the install is aborted.
  //
  // Returns { ok: true } on success, or
  //         { ok: false, reason: string } on any failure.
  // ─────────────────────────────

  static async verifyCandidateLockfileHash(engine = "npm", projectPath = process.cwd()) {
    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      return { ok: false, reason: `Unknown engine '${engine}'` };
    }

    if (!NodeManager._candidateLockfileHash) {
      return { ok: false, reason: "No candidate lockfile hash recorded — runDryRun() must be called first" };
    }

    const lockPath = path.join(projectPath, cfg.lockfile);

    let currentContent;
    try {
      currentContent = fs.readFileSync(lockPath, "utf8");
    } catch (err) {
      return { ok: false, reason: `Could not read lockfile for verification: ${err.message}` };
    }

    const { createHash } = await import("crypto");
    const currentHash = createHash("sha256").update(currentContent, "utf8").digest("hex");

    if (currentHash !== NodeManager._candidateLockfileHash) {
      return {
        ok:       false,
        reason:   `Lockfile integrity check FAILED — the lockfile was modified after scanning.\n` +
                  `  Expected : ${NodeManager._candidateLockfileHash}\n` +
                  `  Got      : ${currentHash}\n` +
                  `  File     : ${lockPath}`,
      };
    }

    return { ok: true };
  }

  // ─────────────────────────────
  // Real install  (engine-aware)
  //
  // Runs the engine's frozen/clean install command so that node_modules
  // exactly matches the committed lockfile.  Never modifies the lockfile.
  // ─────────────────────────────

  static runRealInstall(engine) {
    NodeManager.verifyCandidateLockfileHash(engine).then(result => {
      if (!result.ok) {
        throw new Error(`Lockfile verification failed: ${result.reason}`);
      }
    });
    
    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      throw new Error(
        `Invalid engine '${engine}'. Must be one of: ${Object.keys(ENGINE_CONFIG).join(", ")}`
      );
    }

    return spawnSync(cfg.binary, cfg.installCmd, {
      shell: true,
      stdio: "inherit",
    });
  }

  // ─────────────────────────────
  // Graph comparison
  // ─────────────────────────────

  static compareGraphs(expectedPurls, actualPurls) {
    const expected = new Set(expectedPurls);
    const actual   = new Set(actualPurls);

    const missing = [];
    const extra   = [];

    for (const p of expected) { if (!actual.has(p)) missing.push(p); }
    for (const p of actual)   { if (!expected.has(p)) extra.push(p); }

    return { match: missing.length === 0 && extra.length === 0, missing, extra };
  }

  // ─────────────────────────────
  // Dependency sequences
  // ─────────────────────────────

  static buildDependencySequences(inventory) {
    if (!Array.isArray(inventory)) inventory = Object.values(inventory || {});

    const byId    = new Map();
    const reverse = new Map();

    for (const comp of inventory) {
      byId.set(comp.id, comp);
      reverse.set(comp.id, []);
    }

    for (const comp of inventory) {
      for (const dep of (comp.dependencies || [])) {
        if (!reverse.has(dep)) reverse.set(dep, []);
        reverse.get(dep).push(comp.id);
      }
    }

    const depended = new Set();
    for (const comp of inventory) {
      for (const dep of (comp.dependencies || [])) depended.add(dep);
    }

    const roots     = inventory.map(c => c.id).filter(id => !depended.has(id));
    const sequences = new Map();

    function dfs(node, path) {
      const nextPath = [...path, node];
      if (!sequences.has(node)) sequences.set(node, []);
      sequences.get(node).push(nextPath);

      for (const dep of (byId.get(node)?.dependencies || [])) {
        if (!path.includes(dep)) dfs(dep, nextPath);
      }
    }

    for (const root of roots) dfs(root, []);

    for (const comp of inventory) comp.dependency_sequences = sequences.get(comp.id) || [];

    return inventory;
  }

  static buildDependencyTree(inventory) {
  const map = new Map(inventory.map(p => [p.id, p.dependencies || []]));
  const memo = new Map();

  function expand(id, path = new Set()) {
    if (path.has(id)) return {};

    if (memo.has(id)) return memo.get(id);

    const nextPath = new Set(path);
    nextPath.add(id);

    const deps = map.get(id) || {};
    const node = {};

    for (const dep of deps) {
      node[dep] = expand(dep, nextPath);
    }

    memo.set(id, node);
    return node;
  }

  const result = {};
  for (const pkg of inventory) {
    result[pkg.id] = expand(pkg.id);
  }

  return result;
}

static buildIntroducedBy(inventory) {
  const reverse = new Map();

  for (const pkg of inventory) {
    reverse.set(pkg.id, []);
  }

  for (const pkg of inventory) {
    for (const dep of pkg.dependencies || []) {
      if (!reverse.has(dep)) reverse.set(dep, []);
      reverse.get(dep).push(pkg.id);
    }
  }

  for (const pkg of inventory) {
    pkg.introduced_by = reverse.get(pkg.id) || [];
  }

  return inventory;
}

}

export default NodeManager;