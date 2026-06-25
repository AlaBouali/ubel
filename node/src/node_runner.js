import fs from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { fileURLToPath } from "url";
import { createHash } from "crypto";

import { LockfileParser } from "./lockfiles_parser.js";
import { TOOL_NAME, TOOL_VERSION, TOOL_LICENSE } from "./info.js";
import { PythonVenvScanner } from "./python_runner.js";
import { PhpComposerScanner } from "./php_runner.js";
import { RustCargoScanner } from "./rust_runner.js";
import { GoModScanner } from "./go_runner.js";
import { CSharpNuGetScanner } from "./csharp_runner.js";
import { JavaMavenScanner } from "./java_runner.js";
import { RubyBundlerScanner } from "./ruby_runner.js";
import { LinuxHostScanner } from "./linux_runner.js";
import { WindowsHostScanner } from "./windows_runner.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ─────────────────────────────────────────────────────────────────────────────
// Engine configuration table
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
    installCmd: ["ci", "--ignore-scripts"],
  },

  yarn: {
    lockfile:   "yarn.lock",
    binary:     "yarn",
    dryRunCmd:  (args) => [
      "add",
      "--ignore-scripts",
      "--no-progress",
      ...args,
    ],
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

  pnpm: {
    lockfile:   "pnpm-lock.yaml",
    binary:     "pnpm",
    dryRunCmd:  (args) => args.length
      ? ["add",     "--lockfile-only", "--ignore-scripts", "--no-optional", ...args]
      : ["install", "--lockfile-only", "--ignore-scripts", "--no-optional"],
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

  bun: {
    lockfile:   "bun.lock",
    binary:     "bun",
    dryRunCmd: (args) => args.length
      ? ["add",     "--lockfile-only", "--ignore-scripts", ...args]
      : ["install", "--lockfile-only", "--ignore-scripts"],
    installCmd: ["install", "--frozen-lockfile", "--ignore-scripts"],
  },

};

// ─────────────────────────────────────────────────────────────────────────────
// NodeModulesScanner  (already instance-based — unchanged)
// ─────────────────────────────────────────────────────────────────────────────

class NodeModulesScanner {
  constructor(rootDir) {
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
      purl:        NodeManagerInstance._npmPurl(name, version),
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
            ? NodeManagerInstance._npmPurl(resolved.name, resolved.version)
            : NodeManagerInstance._npmPurl(depName, "")
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
// NodeManagerInstance
//
// All state that was previously on static fields of NodeManager is now held
// on instance fields.  One instance is created per scan invocation so there
// is no shared mutable state between concurrent or sequential scans.
// ─────────────────────────────────────────────────────────────────────────────

export class NodeManagerInstance {

  constructor() {
    this.inventoryData               = [];
    this.currentLockFileContent      = null;

    this._original_package_json      = null;
    this._original_lockfile          = null;
    this._lockfileBackupDir          = null;

    this._original_package_json_hash = null;
    this._original_lockfile_hash     = null;

    this.engineVersion               = null;

    this.candidate_lockfile_content  = null;
    this._candidateLockfileHash      = null;
    this._candidatePackageJsonHash   = null;

  }

  // ─────────────────────────────
  // Static helpers (pure functions — no state, safe to keep static)
  // ─────────────────────────────

  static _npmPurl(name, version) {
    return LockfileParser.purl(name, version);
  }

  _safeArray(v) {
    if (!v) return [];
    if (Array.isArray(v)) return v;
    if (typeof v.values === "function") return [...v.values()];
    return [];
  }

  _safeObjectEntries(v) {
    if (!v || typeof v !== "object") return [];
    return Object.entries(v);
  }

  // ─────────────────────────────
  // Engine version capture
  // ─────────────────────────────

  _captureEngineVersion(binary) {
    try {
      const r = spawnSync(binary, ["--version"], { encoding: "utf8", shell: true });
      if (r.status === 0 && r.stdout) {
        this.engineVersion = r.stdout.trim().replace(/^v/, "");
      } else {
        this.engineVersion = null;
      }
    } catch {
      this.engineVersion = null;
    }
  }

  // ─────────────────────────────
  // Scanner → component tree
  // ─────────────────────────────

  _scannerToTree(rootDir) {
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
      id:           NodeManagerInstance._npmPurl("", ""),
      base_id:      NodeManagerInstance._npmPurl("", ""),
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
  // Lockfile parsing
  // ─────────────────────────────

  scanLockfile(filename, content) {
    return LockfileParser.parse(filename, content);
  }

  scanPackageLock(content) {
    return LockfileParser.parseNpmLock(content);
  }

  // ─────────────────────────────
  // Validate package arg safety
  // ─────────────────────────────

  _validatePackageArgs(args) {
    const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'\"<>]+)?$/i;
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
  // ─────────────────────────────

  /**
   * @param {string} engine       - Package manager name ("npm", "pnpm", "bun")
   * @param {string[]} initialArgs - Package specifiers for check/install mode
   * @param {string} projectRoot  - Absolute path of the project being scanned.
   *                                Passed explicitly so no process.chdir() is needed.
   */
  async runDryRun(engine, initialArgs, projectRoot) {

  // ── 0. Reset instance state ──────────────────────────────────────────
  this.inventoryData               = [];
  this._original_package_json      = null;
  this._original_lockfile          = null;
  this._lockfileBackupDir          = null;
  this.candidate_lockfile_content  = null;
  this._candidateLockfileHash      = null;
  this._candidatePackageJsonHash   = null;
  this._original_package_json_hash = null;
  this._original_lockfile_hash     = null;

  // ── 1. Validate engine ───────────────────────────────────────────────
  const cfg = ENGINE_CONFIG[engine];
  if (!cfg) {
    throw new Error(
      `Invalid engine '${engine}'. Must be one of: ${Object.keys(ENGINE_CONFIG).join(", ")}`
    );
  }

  if (!this.engineVersion) {
    throw new Error(
      `Failed to determine version of '${engine}' (tried '${cfg.binary} --version'). ` +
      `Make sure '${cfg.binary}' is installed and on your PATH.`
    );
  }

  const projectPath     = path.resolve(projectRoot);
  const packageJsonPath = path.join(projectPath, "package.json");
  const lockPath        = path.join(projectPath, cfg.lockfile);
  const nodeModulesPath = path.join(projectPath, "node_modules");

  // ── 2. Determine if we can skip the dry‑run shell command ──────────
  const lockfileAlreadyPresent = fs.existsSync(lockPath);
  const skipDryRun = initialArgs.length === 0 && lockfileAlreadyPresent;

  // ── 3. Ensure a package.json exists (if missing, run npm init) ────
  if (!fs.existsSync(packageJsonPath)) {
    console.log(`No package.json found. Running 'npm init -y' in ${projectPath}`);
    const initResult = spawnSync("npm", ["init", "-y"], {
      cwd:   projectPath,
      stdio: "inherit",
      shell: true,
    });
    if (initResult.status !== 0) {
      throw new Error(`npm init -y failed (exit ${initResult.status})`);
    }
  }

  // ── 4. Backup originals ─────────────────────────────────────────────
  this._original_package_json = fs.existsSync(packageJsonPath)
    ? fs.readFileSync(packageJsonPath, "utf8")
    : null;

  this._original_lockfile = fs.existsSync(lockPath)
    ? fs.readFileSync(lockPath, "utf8")
    : null;

  if (this._original_package_json !== null) {
    this._original_package_json_hash = createHash("sha256")
      .update(this._original_package_json, "utf8")
      .digest("hex");
  } else {
    this._original_package_json_hash = "absent";
  }

  if (this._original_lockfile !== null) {
    this._original_lockfile_hash = createHash("sha256")
      .update(this._original_lockfile, "utf8")
      .digest("hex");
  } else {
    this._original_lockfile_hash = "absent";
  }

  const backupParent = path.join(projectPath, ".ubel", "lockfiles");
  fs.mkdirSync(backupParent, { recursive: true });
  const tmpDir = fs.mkdtempSync(path.join(backupParent, "backup-"));

  if (this._original_package_json !== null) {
    fs.writeFileSync(path.join(tmpDir, "package.json"), this._original_package_json, "utf8");
  }
  if (this._original_lockfile !== null) {
    fs.writeFileSync(path.join(tmpDir, cfg.lockfile), this._original_lockfile, "utf8");
  }

  this._lockfileBackupDir = tmpDir;

  // ── 5. Validate package args ─────────────────────────────────────────
  this._validatePackageArgs(initialArgs);

  // ── 6. Generate candidate lockfile (only if NOT skipping) ───────────
  if (skipDryRun) {
    console.log(`Skipping dry-run shell-out: no arguments supplied and lockfile already exists at ${lockPath}`);
  } else {
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
  }

  // ── 7. Hash candidate package.json (TOCTOU guard) ──────────────────
  if (fs.existsSync(packageJsonPath)) {
    const pkgRaw = fs.readFileSync(packageJsonPath, "utf8");
    this._candidatePackageJsonHash = createHash("sha256")
      .update(pkgRaw, "utf8")
      .digest("hex");
  } else {
    this._candidatePackageJsonHash = "absent";
  }

  // ── 8. Parse candidate lockfile via LockfileParser ─────────────────
  const candidateRaw = fs.readFileSync(lockPath, "utf8");
  this.candidate_lockfile_content = candidateRaw;

  this._candidateLockfileHash = createHash("sha256")
    .update(candidateRaw, "utf8")
    .digest("hex");

  const allCandidateComponents = LockfileParser.parse(cfg.lockfile, candidateRaw);

  // ── 9. Diff: isolate net‑new packages ──────────────────────────────
  const originalPurls = new Set();
  if (this._original_lockfile) {
    try {
      for (const comp of LockfileParser.parse(cfg.lockfile, this._original_lockfile)) {
        originalPurls.add(comp.id);
      }
    } catch {
      // Original lockfile unparseable → treat all candidates as new
    }
  }

  const newComponents = allCandidateComponents.filter(c => !originalPurls.has(c.id));

  // ── 10. Normalise ─────────────────────────────────────────────────────
  const merged = this.mergeInventoryByPurl(newComponents);
  this.inventoryData = merged;

  if (this.engineVersion) {
    let engine_license = "MIT";
    if (["yarn"].includes(engine)) {
      engine_license = "BSD 2-Clause";
    }
    this.inventoryData.push(
      {
        id:        `pkg:npm/${engine}@${this.engineVersion}`,
        name:      engine,
        version:   this.engineVersion,
        license:   engine_license,
        ecosystem: "npm",
        state:     "undetermined",
        scopes:    ["env"],
        dependencies: [],
        type:      "library",
        paths:     [],
      },
      {
        id:        `pkg:npm/${TOOL_NAME}@${TOOL_VERSION}`,
        name:      TOOL_NAME,
        version:   TOOL_VERSION,
        license:   TOOL_LICENSE,
        ecosystem: "npm",
        state:     "undetermined",
        scopes:    ["env"],
        dependencies: [],
        type:      "library",
        paths:     [],
      }
    );
  }

  // ── 11. Assign scopes ─────────────────────────────────────────────────
  this._assignScopes(allCandidateComponents, packageJsonPath);

  const scopeMap = new Map(allCandidateComponents.map(c => [c.id, c.scopes]));
  for (const comp of this.inventoryData) {
    if (!Array.isArray(comp.scopes) || comp.scopes.length === 0) {
      comp.scopes = scopeMap.get(comp.id) ?? [];
    }
  }

  return merged.map(c => c.id);
}

  // ─────────────────────────────
  // Revert lockfile + package.json to originals
  // ─────────────────────────────

  revert_lock_to_original(engine = "npm", projectPath) {
    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      return {
        reverted:  false,
        reason:    `Unknown engine '${engine}' — cannot determine lockfile name`,
        backupDir: this._lockfileBackupDir,
      };
    }

    const packageJsonPath = path.join(projectPath, "package.json");
    const lockPath        = path.join(projectPath, cfg.lockfile);
    const tmpDir          = this._lockfileBackupDir;

    const verifyFile = (filePath, expectedHash, fileLabel) => {
      const fileExists = fs.existsSync(filePath);
      if (expectedHash === "absent") {
        if (fileExists) {
          return { ok: false, reason: `${fileLabel} exists on disk but was originally absent` };
        }
        return { ok: true };
      }
      if (!fileExists) {
        return { ok: false, reason: `${fileLabel} is missing on disk but was originally present` };
      }
      let currentContent;
      try {
        currentContent = fs.readFileSync(filePath, "utf8");
      } catch (err) {
        return { ok: false, reason: `Cannot read ${fileLabel}: ${err.message}` };
      }
      const currentHash = createHash("sha256").update(currentContent, "utf8").digest("hex");
      if (currentHash !== expectedHash) {
        return {
          ok:     false,
          reason: `${fileLabel} hash mismatch (expected ${expectedHash}, got ${currentHash})`,
        };
      }
      return { ok: true };
    };

    const pkgExpectedHash  = this._candidatePackageJsonHash ?? this._original_package_json_hash;
    const pkgCheck         = verifyFile(packageJsonPath, pkgExpectedHash, "package.json");
    if (!pkgCheck.ok) {
      return { reverted: false, reason: pkgCheck.reason, backupDir: tmpDir };
    }

    const lockExpectedHash = this._candidateLockfileHash ?? this._original_lockfile_hash;
    const lockCheck        = verifyFile(lockPath, lockExpectedHash, cfg.lockfile);
    if (!lockCheck.ok) {
      return { reverted: false, reason: lockCheck.reason, backupDir: tmpDir };
    }

    try {
      let pkgContent = this._original_package_json;
      if (pkgContent === null && tmpDir) {
        const disk = path.join(tmpDir, "package.json");
        if (fs.existsSync(disk)) pkgContent = fs.readFileSync(disk, "utf8");
      }
      if (pkgContent !== null) {
        fs.writeFileSync(packageJsonPath, pkgContent, "utf8");
      } else if (fs.existsSync(packageJsonPath)) {
        fs.unlinkSync(packageJsonPath);
      }

      let lockContent = this._original_lockfile;
      if (lockContent === null && tmpDir) {
        const disk = path.join(tmpDir, cfg.lockfile);
        if (fs.existsSync(disk)) lockContent = fs.readFileSync(disk, "utf8");
      }
      if (lockContent !== null) {
        fs.writeFileSync(lockPath, lockContent, "utf8");
      } else if (fs.existsSync(lockPath)) {
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

  cleanupLockfileBackup() {
    const tmpDir = this._lockfileBackupDir;
    if (!tmpDir) return { cleaned: false, reason: "no backup dir recorded" };

    try {
      fs.rmSync(tmpDir, { recursive: true, force: true });
      this._lockfileBackupDir = null;
      return { cleaned: true };
    } catch (err) {
      return { cleaned: false, reason: err.message };
    }
  }

  // ─────────────────────────────
  // Save candidate lockfile
  // ─────────────────────────────

  async saveCandidateLockfile(engine = "npm", projectPath) {

    const cfg          = ENGINE_CONFIG[engine] || ENGINE_CONFIG.npm;
    const lockfilePath = path.join(projectPath, cfg.lockfile);

    if (!this.candidate_lockfile_content) {
      return {
        written:  false,
        filePath: lockfilePath,
        reason:   "candidate_lockfile_content is null — run runDryRun() first",
      };
    }

    try {
      if (engine === "npm") {
        const raw = typeof this.candidate_lockfile_content === "string"
          ? this.candidate_lockfile_content
          : JSON.stringify(this.candidate_lockfile_content, null, 2);
        fs.writeFileSync(lockfilePath, raw, "utf8");

        const parsed = typeof this.candidate_lockfile_content === "string"
          ? JSON.parse(this.candidate_lockfile_content)
          : this.candidate_lockfile_content;

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

        {
          const written = fs.readFileSync(packageJsonPath, "utf8");
          this._candidatePackageJsonHash = createHash("sha256")
            .update(written, "utf8")
            .digest("hex");
        }

        return { written: true, filePath: lockfilePath, packageJsonPath };

      } else {
        const raw = typeof this.candidate_lockfile_content === "string"
          ? this.candidate_lockfile_content
          : JSON.stringify(this.candidate_lockfile_content, null, 2);

        const packageJsonPath = path.join(projectPath, "package.json");

        if (this._candidatePackageJsonHash &&
            this._candidatePackageJsonHash !== "absent") {
          if (!fs.existsSync(packageJsonPath)) {
            return {
              written:  false,
              filePath: lockfilePath,
              reason:   "package.json integrity check FAILED — file was removed after scanning",
            };
          }
          const onDisk     = fs.readFileSync(packageJsonPath, "utf8");
          const onDiskHash = createHash("sha256").update(onDisk, "utf8").digest("hex");
          if (onDiskHash !== this._candidatePackageJsonHash) {
            return {
              written:  false,
              filePath: lockfilePath,
              reason:   `package.json integrity check FAILED — file was modified after scanning.\n` +
                        `  Expected : ${this._candidatePackageJsonHash}\n` +
                        `  Got      : ${onDiskHash}\n` +
                        `  File     : ${packageJsonPath}`,
            };
          }
        }

        let pkgJsonRaw = null;
        if (fs.existsSync(packageJsonPath)) {
          pkgJsonRaw = fs.readFileSync(packageJsonPath, "utf8");
        } else if (this._original_package_json !== null) {
          pkgJsonRaw = this._original_package_json;
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
  // ─────────────────────────────

  exportNpmDependencies(projectPath) {
    return this._scannerToTree(projectPath);
  }

  // ─────────────────────────────
  // Recursive project scanner
  // ─────────────────────────────

  async getInstalled(startDir, options = { full_stack: false, scan_os: false, scan_node: true }) {

  // ── Helper: scan Node.js projects ──────────────────────────────────────────
  const scanNodeProjects = () => {
    const inventory = [];
    const projectRoots = [];
    const visitedPaths = new Set();

    if (!options.scan_node) {
      return { inventory, projectRoots };
    }

    console.log(`Scanning for Node.js projects in ${startDir}...`);

    const walk = (dir) => {
      let entries;
      try { entries = fs.readdirSync(dir, { withFileTypes: true }); }
      catch { return; }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (entry.name.startsWith(".")) continue;

        const fullPath = path.join(dir, entry.name);

        if (entry.name === "node_modules") {
          const projectRoot = dir;
          const key = path.resolve(projectRoot);
          if (visitedPaths.has(key)) continue;
          visitedPaths.add(key);

          try {
            const scanner    = new NodeModulesScanner(projectRoot);
            const pkgs       = scanner.scan();

            const components = pkgs.map(pkg => ({
              id:           NodeManagerInstance._npmPurl(pkg.name, pkg.version),
              name:         pkg.name,
              version:      pkg.version,
              type:         "library",
              license:      pkg.license ?? "unknown",
              ecosystem:    "npm",
              state:        "undetermined",
              scopes:       [],
              dependencies: pkg.dependencies,
              paths:        [pkg.path],
            }));

            inventory.push(...components);
            projectRoots.push(projectRoot);
          } catch (err) { console.log(err) }

          continue;
        }

        walk(fullPath);
      }
    };

    walk(startDir);
    return { inventory, projectRoots };
  };

  // ── Main logic ────────────────────────────────────────────────────────────────
  this.inventoryData = [];

  if (!options.full_stack) {
    // Non‑full‑stack: run Node.js scan synchronously
    const result = scanNodeProjects();
    this.inventoryData = result.inventory;
    const nodeProjectRoots = result.projectRoots;

    // Merge by PURL
    const merged = this.mergeInventoryByPurl(this.inventoryData);
    this.inventoryData = merged;

    // Assign scopes
    const roots = nodeProjectRoots.length ? nodeProjectRoots : [startDir];
    for (const root of roots) {
      const pkgJsonPath = path.join(root, "package.json");
      this._assignScopes(this.inventoryData, pkgJsonPath);
    }

    // OS scan if requested
    if (options.scan_os) {
      if (process.platform === "win32") {
        const winScanner = new WindowsHostScanner();
        await winScanner.getInstalled();
        this.inventoryData.push(...winScanner.inventoryData);
      } else {
        const linuxScanner = new LinuxHostScanner();
        linuxScanner.getInstalled();
        this.inventoryData.push(...linuxScanner.inventoryData);
      }
      // Re‑merge after OS scan
      const finalMerged = this.mergeInventoryByPurl(this.inventoryData);
      this.inventoryData = finalMerged;
    }

    return merged.map(c => c.id);
  }

  // ── Full‑stack: run ALL scanners in parallel ──────────────────────────────
  console.log(`Scanning for projects in ${startDir}...`);

  const pythonScanner  = new PythonVenvScanner();
  const phpScanner     = new PhpComposerScanner();
  const rustScanner    = new RustCargoScanner();
  const goScanner      = new GoModScanner();
  const csharpScanner  = new CSharpNuGetScanner();
  const javaScanner    = new JavaMavenScanner();
  const rubyScanner    = new RubyBundlerScanner();

  // Node.js scan as a promise
  const nodePromise = (async () => {
    const result = scanNodeProjects();
    return { inventory: result.inventory, projectRoots: result.projectRoots };
  })();

  // Other language scanners as promises
  const otherPromises = [
    (async () => {
      console.log(`Scanning for Python projects in ${startDir}...`);
      await pythonScanner.getInstalled(startDir);
      return { inventory: pythonScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for PHP projects in ${startDir}...`);
      await phpScanner.getInstalled(startDir);
      return { inventory: phpScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for Rust projects in ${startDir}...`);
      await rustScanner.getInstalled(startDir);
      return { inventory: rustScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for Go projects in ${startDir}...`);
      await goScanner.getInstalled(startDir);
      return { inventory: goScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for C# projects in ${startDir}...`);
      await csharpScanner.getInstalled(startDir);
      return { inventory: csharpScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for Java projects in ${startDir}...`);
      await javaScanner.getInstalled(startDir);
      return { inventory: javaScanner.inventoryData, projectRoots: [] };
    })(),
    (async () => {
      console.log(`Scanning for Ruby projects in ${startDir}...`);
      await rubyScanner.getInstalled(startDir);
      return { inventory: rubyScanner.inventoryData, projectRoots: [] };
    })(),
  ];

  // Run all in parallel
  const results = await Promise.all([nodePromise, ...otherPromises]);

  // Merge all inventories
  let allInventory = [];
  let allProjectRoots = [];
  for (const res of results) {
    allInventory.push(...res.inventory);
    if (res.projectRoots) {
      allProjectRoots.push(...res.projectRoots);
    }
  }

  this.inventoryData = allInventory;

  // ── OS scan if requested ──────────────────────────────────────────────────
  if (options.scan_os) {
    if (process.platform === "win32") {
      const winScanner = new WindowsHostScanner();
      await winScanner.getInstalled();
      this.inventoryData.push(...winScanner.inventoryData);
    } else {
      const linuxScanner = new LinuxHostScanner();
      linuxScanner.getInstalled();
      this.inventoryData.push(...linuxScanner.inventoryData);
    }
  }

  // ── Merge by PURL ──────────────────────────────────────────────────────────
  const finalMerged = this.mergeInventoryByPurl(this.inventoryData);
  this.inventoryData = finalMerged;

  // ── Assign scopes per project root ────────────────────────────────────────
  const roots = allProjectRoots.length ? allProjectRoots : [startDir];
  for (const root of roots) {
    const pkgJsonPath = path.join(root, "package.json");
    this._assignScopes(this.inventoryData, pkgJsonPath);
  }

  return finalMerged.map(c => c.id);
}

  // ─────────────────────────────
  // Flatten dependency tree
  // ─────────────────────────────

  getInstalledFromTree(tree) {
    const map = new Map();

    const walk = (node) => {
      if (node?.name && node?.version) {
        const id           = NodeManagerInstance._npmPurl(node.name, node.version);
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

        const deps = this._safeArray(node.dependencies);
        comp.dependencies = deps.map(d => d.base_id || d.id || d);
      }

      for (const child of this._safeArray(node?.dependencies)) {
        walk(child);
      }
    };

    walk(tree);
    return [...map.values()];
  }

  // ─────────────────────────────
  // Scope assignment
  // ─────────────────────────────

  _assignScopes(inventory, pkgJsonPath) {
    const byId = new Map();
    for (const comp of inventory) byId.set(comp.id, comp);

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
    }

    let pkgJson = null;
    try {
      if (fs.existsSync(pkgJsonPath)) {
        pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf8"));
      }
    } catch { /* unparseable package.json — skip */ }

    if (!pkgJson) return;

    const proDirect = new Set(Object.keys(pkgJson.dependencies    || {}));
    const devDirect = new Set(Object.keys(pkgJson.devDependencies || {}));

    const nameIndex = new Map();
    for (const comp of inventory) {
      if (!nameIndex.has(comp.name)) nameIndex.set(comp.name, []);
      nameIndex.get(comp.name).push(comp);
    }

    const propagate = (directNames, scope) => {
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
            const plain  = depPurl.match(/^pkg:npm\/([^%@][^@/]*)@/);
            const scoped = depPurl.match(/^pkg:npm\/%40([^@/]+)\/([^@]+)@/);
            const depName = scoped
              ? "@" + scoped[1] + "/" + scoped[2]
              : plain ? plain[1] : null;
            if (depName) {
              for (const c of (nameIndex.get(depName) || [])) {
                if (!visited.has(c.id)) queue.push(c);
              }
            }
          }
        }
      }
    };

    propagate(proDirect, "prod");
    propagate(devDirect, "dev");
  }

  // ─────────────────────────────
  // Merge inventory by PURL
  // ─────────────────────────────

  mergeInventoryByPurl(components) {
    components = this._safeArray(components);
    const map  = new Map();

    for (const comp of components) {
      const id = comp.id;

      if (!map.has(id)) {
        const clone  = { ...comp };
        clone.paths  = this._safeArray(clone.paths);
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
  // Lockfile integrity check
  // ─────────────────────────────

  async verifyCandidateLockfileHash(engine = "npm", projectPath) {
    console.log(`Verifying lockfile integrity for engine '${engine}'...`);
    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      return { ok: false, reason: `Unknown engine '${engine}'` };
    }

    if (!this._candidateLockfileHash) {
      return { ok: false, reason: "No candidate lockfile hash recorded — runDryRun() must be called first" };
    }

    const lockPath = path.join(projectPath, cfg.lockfile);

    let currentContent;
    try {
      currentContent = fs.readFileSync(lockPath, "utf8");
    } catch (err) {
      return { ok: false, reason: `Could not read lockfile for verification: ${err.message}` };
    }

    const currentHash = createHash("sha256").update(currentContent, "utf8").digest("hex");
    if (currentHash !== this._candidateLockfileHash) {
      return {
        ok:     false,
        reason: `Lockfile integrity check FAILED — the lockfile was modified after scanning.\n` +
                `  Expected : ${this._candidateLockfileHash}\n` +
                `  Got      : ${currentHash}\n` +
                `  File     : ${lockPath}`,
      };
    }

    return { ok: true };
  }

  // ─────────────────────────────
  // package.json integrity check
  // ─────────────────────────────

  async verifyPackageJsonHash(projectPath) {
    if (!this._candidatePackageJsonHash) {
      return {
        ok:     false,
        reason: "No candidate package.json hash recorded — runDryRun() must be called first",
      };
    }

    const pkgPath = path.join(projectPath, "package.json");

    if (this._candidatePackageJsonHash === "absent") {
      if (fs.existsSync(pkgPath)) {
        return {
          ok:     false,
          reason: `package.json integrity check FAILED — file was created after scanning.\n` +
                  `  Expected : <absent>\n` +
                  `  File     : ${pkgPath}`,
        };
      }
      return { ok: true };
    }

    let currentContent;
    try {
      currentContent = fs.readFileSync(pkgPath, "utf8");
    } catch (err) {
      return {
        ok:     false,
        reason: `Could not read package.json for verification: ${err.message}`,
      };
    }

    const currentHash = createHash("sha256").update(currentContent, "utf8").digest("hex");

    if (currentHash !== this._candidatePackageJsonHash) {
      return {
        ok:     false,
        reason: `package.json integrity check FAILED — the file was modified after scanning.\n` +
                `  Expected : ${this._candidatePackageJsonHash}\n` +
                `  Got      : ${currentHash}\n` +
                `  File     : ${pkgPath}`,
      };
    }

    return { ok: true };
  }

  // ─────────────────────────────
  // Real install
  // ─────────────────────────────

  async runRealInstall(engine, projectPath) {
    const lockfileCheck = await this.verifyCandidateLockfileHash(engine, projectPath);
    if (!lockfileCheck.ok) {
      throw new Error(`Lockfile integrity check failed: ${lockfileCheck.reason}`);
    }

    const pkgJsonCheck = await this.verifyPackageJsonHash(projectPath);
    if (!pkgJsonCheck.ok) {
      throw new Error(`package.json integrity check failed: ${pkgJsonCheck.reason}`);
    }

    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      throw new Error(
        `Invalid engine '${engine}'. Must be one of: ${Object.keys(ENGINE_CONFIG).join(", ")}`
      );
    }

    return spawnSync(cfg.binary, cfg.installCmd, {
      cwd:   projectPath,
      shell: true,
      stdio: "inherit",
    });
  }

  // ─────────────────────────────
  // Graph utilities
  // ─────────────────────────────

  compareGraphs(expectedPurls, actualPurls) {
    const expected = new Set(expectedPurls);
    const actual   = new Set(actualPurls);

    const missing = [];
    const extra   = [];

    for (const p of expected) { if (!actual.has(p)) missing.push(p); }
    for (const p of actual)   { if (!expected.has(p)) extra.push(p); }

    return { match: missing.length === 0 && extra.length === 0, missing, extra };
  }

  buildDependencySequences(inventory) {
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

  buildDependencyTree(inventory) {
    const map  = new Map(inventory.map(p => [p.id, p.dependencies || []]));
    const memo = new Map();

    function expand(id, visited = new Set()) {
      if (visited.has(id)) return {};
      if (memo.has(id)) return memo.get(id);

      const next = new Set(visited);
      next.add(id);

      const deps = map.get(id) || [];
      const node = {};

      for (const dep of deps) {
        node[dep] = expand(dep, next);
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

  buildIntroducedBy(inventory) {
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

  buildParents(inventory) {
  const parents = new Map(inventory.map(c => [c.id, []]));
  for (const comp of inventory) {
    for (const depId of (comp.dependencies || [])) {
      if (parents.has(depId)) {
        parents.get(depId).push(comp.id);
      }
    }
  }
  for (const comp of inventory) {
    comp.parents = (parents.get(comp.id) || []).sort();
  }
  return inventory;
};
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy alias
//
// Code that still imports { NodeManager } continues to work.  Each property
// access on the alias creates a fresh instance implicitly — callers that rely
// on shared static state should migrate to NodeManagerInstance directly.
// ─────────────────────────────────────────────────────────────────────────────

export { NodeManagerInstance as NodeManager };
export default NodeManagerInstance;