// php_composer_scanner.js
import fs   from "fs";
import path from "path";
import { spawnSync } from "child_process";
import { createHash } from "crypto";

import { TOOL_NAME, TOOL_VERSION, TOOL_LICENSE } from "./info.js";

// ─────────────────────────────────────────────────────────────────────────────
// Engine configuration table
//
// Composer only has one binary, but this stays a table (rather than a
// handful of top-level constants) so it lines up with node_runner.js's
// ENGINE_CONFIG and the rest of the codebase can keep treating "engine" as
// a lookup key instead of a special case.
//
//   --no-install : resolve + write composer.json/composer.lock without
//                  touching vendor/ — the composer equivalent of npm's
//                  --package-lock-only. Nothing gets extracted or
//                  autoloaded, so this is safe to run against untrusted
//                  requirements.
//   --no-scripts : never run composer.json "scripts" hooks (pre/post-
//                  install, pre/post-update, etc.) — those are arbitrary
//                  shell commands and are exactly what a firewall dry-run
//                  must not execute.
// ─────────────────────────────────────────────────────────────────────────────

const ENGINE_CONFIG = {

  composer: {
    lockfile:   "composer.lock",
    manifest:   "composer.json",
    binary:     "composer",
    dryRunCmd:  (args) => args.length
      ? ["require", "--no-install", "--no-scripts", "--no-interaction", "--no-ansi", ...args]
      : ["update",  "--no-install", "--no-scripts", "--no-interaction", "--no-ansi"],
    installCmd: ["install", "--no-scripts", "--no-interaction", "--no-ansi"],
  },

};

export class PhpComposerScanner {

  constructor() {
    this.inventoryData          = [];
    this.currentLockFileContent = null;

    // ── Firewall / dry-run state ──────────────────────────────────────
    this._original_composer_json      = null;
    this._original_lockfile           = null;
    this._lockfileBackupDir           = null;

    this._original_composer_json_hash = null;
    this._original_lockfile_hash      = null;

    this.engineVersion                = null;

    this.candidate_lockfile_content   = null;
    this._candidateLockfileHash       = null;
    this._candidateComposerJsonHash   = null;
  }

  // ─────────────────────────────
  // Engine version capture
  // ─────────────────────────────
  //
  // `composer --version` prints a sentence ("Composer version 2.7.1
  // 2024-03-11 15:30:14"), not a bare "vX.Y.Z" the way `node --version`
  // does, so this pulls the semver-shaped token out of it rather than
  // just trimming.
  _captureEngineVersion(binary) {
    try {
      const r = spawnSync(binary, ["--version", "--no-ansi"], { encoding: "utf8", shell: true });
      if (r.status === 0 && r.stdout) {
        const match = r.stdout.trim().match(/(\d+\.\d+\.\d+(?:[.-][0-9A-Za-z.]+)*)/);
        this.engineVersion = match ? match[1] : r.stdout.trim();
      } else {
        this.engineVersion = null;
      }
    } catch {
      this.engineVersion = null;
    }
  }

  // ─────────────────────────────
  // Validate package arg safety
  // ─────────────────────────────
  //
  // Composer specifiers are always "vendor/package", optionally followed
  // by a ":constraint" (e.g. "monolog/monolog:^3.0"). Anything else —
  // shell metacharacters, missing "/", etc. — is rejected before it ever
  // reaches spawnSync.
  _validatePackageArgs(args) {
    const PKG_ARG_RE = /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9]([_.-]?[a-z0-9]+)*(:[^\s;&|`$(){}\\'"<>]+)?$/i;
    for (const arg of args) {
      if (!PKG_ARG_RE.test(arg)) {
        throw new Error(
          `Rejected unsafe package argument: '${arg}'. ` +
          `Only Composer package specifiers (vendor/package or vendor/package:constraint) are allowed.`
        );
      }
    }
  }

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  _composerPurl(name, version) {
    // Composer package names are vendor/package, already lowercase by convention.
    // PURL spec: pkg:composer/vendor/package@version
    const clean = name.toLowerCase();
    return `pkg:composer/${clean}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Read installed packages from
  // vendor/composer/installed.json  (Composer v1 & v2)
  // ─────────────────────────────
  _readInstalledJson(vendorDir) {
    const installedPath = path.join(vendorDir, "composer", "installed.json");
    if (!fs.existsSync(installedPath)) return [];

    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(installedPath, "utf8"));
    } catch {
      return [];
    }

    // Composer v2 wraps the array under { "packages": [...] }
    // Composer v1 is a bare array
    return Array.isArray(raw) ? raw : (raw.packages ?? []);
  }

  // ─────────────────────────────
  // Normalise a version string
  // strips Composer's leading "v" or "V"
  // ─────────────────────────────
  _normaliseVersion(v) {
    if (!v) return "";
    return v.replace(/^v/i, "");
  }

  // ─────────────────────────────
  // Extract license from package
  // metadata (field is an array or
  // a plain string depending on version)
  // ─────────────────────────────
  _extractLicense(pkg) {
    const lic = pkg.license ?? pkg.licence ?? "unknown";
    if (Array.isArray(lic)) return lic.join(" OR ") || "unknown";
    return lic || "unknown";
  }

  // ─────────────────────────────
  // Scan a single composer project
  // using installed.json (if present)
  // ─────────────────────────────
  _scanProject(projectRoot) {
    const vendorDir = path.join(projectRoot, "vendor");
    const packages  = this._readInstalledJson(vendorDir);
    if (!packages.length) return [];

    // First pass – build name index for dependency resolution
    const nameIndex = new Map();   // lowercase name → { name, version, pkg }

    for (const pkg of packages) {
      const rawName = pkg.name;
      if (!rawName) continue;
      const norm    = rawName.toLowerCase();
      const version = this._normaliseVersion(pkg.version ?? pkg.version_normalized ?? "");
      nameIndex.set(norm, { name: rawName, version, pkg });
    }

    // Second pass – build components
    const components = [];

    for (const [norm, { name, version, pkg }] of nameIndex.entries()) {
      const id      = this._composerPurl(name, version);
      const license = this._extractLicense(pkg);

      // Direct require-list for this package (runtime deps)
      const requireMap = pkg.require ?? {};
      const dependencies = Object.keys(requireMap)
        .map(dep => dep.toLowerCase())
        .filter(dep => dep !== "php" && !dep.startsWith("ext-"))   // skip PHP/ext pseudo-deps
        .map(dep => {
          const resolved = nameIndex.get(dep);
          return resolved
            ? this._composerPurl(resolved.name, resolved.version)
            : this._composerPurl(dep, "");
        });

      // Physical install path inside vendor/
      const installPath = path.join(vendorDir, ...name.split("/"));

      components.push({
        id,
        name: norm,
        version,
        type:         "library",
        license,
        ecosystem:    "php",
        state:        "undetermined",
        scopes:       [],
        dependencies,
        paths:        [installPath],
        project_root: projectRoot,
        dev:          pkg["dev-requirements"] === true || pkg.dev === true  // set by Composer v2
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Parse a composer.lock file and
  // return components for all packages
  // ─────────────────────────────
  parseComposerLock(lockPath, projectRoot) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    } catch {
      return [];
    }

    const packages     = data.packages || [];
    const devPackages  = data["packages-dev"] || [];
    const allPackages  = [...packages, ...devPackages];

    // Build name index for dependency resolution
    const nameIndex = new Map();
    for (const pkg of allPackages) {
      const name = pkg.name;
      if (!name) continue;
      const norm = name.toLowerCase();
      const version = this._normaliseVersion(pkg.version || "");
      nameIndex.set(norm, { name, version, pkg });
    }

    const components = [];

    const processSection = (pkgList, isDev) => {
      for (const pkg of pkgList) {
        const name = pkg.name;
        if (!name) continue;
        const norm = name.toLowerCase();
        const version = this._normaliseVersion(pkg.version || "");
        const id = this._composerPurl(name, version);
        const license = this._extractLicense(pkg);

        const requireMap = pkg.require || {};
        const dependencies = Object.keys(requireMap)
          .filter(dep => dep !== "php" && !dep.startsWith("ext-"))
          .map(dep => {
            const resolved = nameIndex.get(dep.toLowerCase());
            return resolved
              ? this._composerPurl(resolved.name, resolved.version)
              : this._composerPurl(dep, "");
          });

        const installPath = path.join(projectRoot, "vendor", ...name.split("/"));

        components.push({
          id,
          name: norm,
          version,
          type: "library",
          license,
          ecosystem: "php",
          state: "undetermined",
          scopes: isDev ? ["dev"] : ["prod"],   // initial scopes
          dependencies,
          paths: [installPath],
          project_root: projectRoot,
          dev: isDev,                           // used by _assignScopes
        });
      }
    };

    processSection(packages, false);
    processSection(devPackages, true);

    return components;
  }

  // ─────────────────────────────
  // Assign scopes from root
  // composer.json  require / require-dev
  // ─────────────────────────────
  _assignScopes(inventory) {
    const byId    = new Map(inventory.map(c => [c.id, c]));
    const nameIdx = new Map();

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      const key = comp.name;
      if (!nameIdx.has(key)) nameIdx.set(key, []);
      nameIdx.get(key).push(comp);
    }

    // Group by project root
    const projectGroups = new Map();
    for (const comp of inventory) {
      const root = comp.project_root;
      if (!projectGroups.has(root)) projectGroups.set(root, []);
      projectGroups.get(root).push(comp);
    }

    for (const [projectRoot, comps] of projectGroups.entries()) {
      let rootManifest = {};
      try {
        rootManifest = JSON.parse(
          fs.readFileSync(path.join(projectRoot, "composer.json"), "utf8")
        );
      } catch { /* no manifest – fall back below */ }

      const prod = new Set(
        Object.keys(rootManifest.require ?? {}).map(k => k.toLowerCase())
      );
      const dev  = new Set(
        Object.keys(rootManifest["require-dev"] ?? {}).map(k => k.toLowerCase())
      );

      // Also honour the per-package `dev` flag written by Composer v2
      for (const comp of comps) {
        if (comp.dev) dev.add(comp.name);
      }

      const propagate = (names, scope) => {
        const queue = [];

        for (const n of names) {
          for (const c of (nameIdx.get(n) ?? [])) {
            if (c.project_root === projectRoot) queue.push(c);
          }
        }

        const visited = new Set();

        while (queue.length) {
          const c = queue.shift();
          if (visited.has(c.id)) continue;
          visited.add(c.id);

          if (!c.scopes.includes(scope)) c.scopes.push(scope);

          for (const dep of c.dependencies) {
            const d = byId.get(dep);
            if (d && d.project_root === projectRoot) queue.push(d);
          }
        }
      };

      propagate(prod, "prod");
      propagate(dev,  "dev");

      // Fallback – only for components that have no scopes at all
      if (prod.size === 0 && dev.size === 0) {
        for (const c of comps) {
          if (c.scopes.length === 0) c.scopes.push("prod");
        }
      }
    }
  }

  // ─────────────────────────────
  // Merge duplicates by PURL
  // ─────────────────────────────
  mergeInventoryByPurl(components) {
    const map = new Map();

    for (const comp of components) {
      if (!map.has(comp.id)) {
        map.set(comp.id, { ...comp, paths: [...comp.paths] });
        continue;
      }

      const existing = map.get(comp.id);

      for (const p of comp.paths) {
        if (!existing.paths.includes(p)) existing.paths.push(p);
      }

      for (const s of comp.scopes) {
        if (!existing.scopes.includes(s)) existing.scopes.push(s);
      }
    }

    return [...map.values()];
  }

  // ─────────────────────────────────────────────────────────────────────────
  // Fast dry run  (composer)
  //
  // Mirrors NodeManagerInstance.runDryRun() in node_runner.js: resolve the
  // requested change(s) with `--no-install`/`--no-scripts` so nothing from
  // vendor/ is ever extracted or executed, hash both composer.json and
  // composer.lock as soon as they're produced (a TOCTOU guard used later by
  // verifyCandidateLockfileHash()/verifyComposerJsonHash()), and report only
  // the packages that are net-new versus what was on disk before the dry
  // run — not the whole resolved graph — so policy is evaluated against the
  // change being made, not the entire dependency tree every time.
  // ─────────────────────────────────────────────────────────────────────────

  /**
   * @param {string} engine       - Package manager name ("composer")
   * @param {string[]} initialArgs - Package specifiers for check/install mode
   * @param {string} projectRoot  - Absolute path of the project being scanned.
   *                                Passed explicitly so no process.chdir() is needed.
   */
  async runDryRun(engine, initialArgs, projectRoot) {

    // ── 0. Reset instance state ────────────────────────────────────────
    this.inventoryData                = [];
    this._original_composer_json      = null;
    this._original_lockfile           = null;
    this._lockfileBackupDir           = null;
    this.candidate_lockfile_content   = null;
    this._candidateLockfileHash       = null;
    this._candidateComposerJsonHash   = null;
    this._original_composer_json_hash = null;
    this._original_lockfile_hash      = null;

    // ── 1. Validate engine ─────────────────────────────────────────────
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

    const projectPath      = path.resolve(projectRoot);
    const composerJsonPath = path.join(projectPath, cfg.manifest);
    const lockPath         = path.join(projectPath, cfg.lockfile);

    // ── 2. Determine if we can skip the dry-run shell command ──────────
    const lockfileAlreadyPresent = fs.existsSync(lockPath);
    const skipDryRun = initialArgs.length === 0 && lockfileAlreadyPresent;

    // ── 3. Ensure a composer.json exists ────────────────────────────────
    // Written directly rather than shelling out to `composer init`, since
    // non-interactive `init` behavior (required fields, prompts skipped)
    // varies across Composer versions — a minimal manifest is deterministic
    // and is all `require`/`update --no-install` need to work from.
    if (!fs.existsSync(composerJsonPath)) {
      console.log(`No composer.json found. Creating a minimal one at ${composerJsonPath}`);
      fs.writeFileSync(
        composerJsonPath,
        JSON.stringify({ name: "ubel/scan-temp", type: "project" }, null, 4) + "\n",
        "utf8"
      );
    }

    // ── 4. Backup originals ───────────────────────────────────────────
    this._original_composer_json = fs.existsSync(composerJsonPath)
      ? fs.readFileSync(composerJsonPath, "utf8")
      : null;

    this._original_lockfile = fs.existsSync(lockPath)
      ? fs.readFileSync(lockPath, "utf8")
      : null;

    this._original_composer_json_hash = this._original_composer_json !== null
      ? createHash("sha256").update(this._original_composer_json, "utf8").digest("hex")
      : "absent";

    this._original_lockfile_hash = this._original_lockfile !== null
      ? createHash("sha256").update(this._original_lockfile, "utf8").digest("hex")
      : "absent";

    const backupParent = path.join(projectPath, ".ubel", "lockfiles");
    fs.mkdirSync(backupParent, { recursive: true });
    const tmpDir = fs.mkdtempSync(path.join(backupParent, "backup-"));

    if (this._original_composer_json !== null) {
      fs.writeFileSync(path.join(tmpDir, cfg.manifest), this._original_composer_json, "utf8");
    }
    if (this._original_lockfile !== null) {
      fs.writeFileSync(path.join(tmpDir, cfg.lockfile), this._original_lockfile, "utf8");
    }

    this._lockfileBackupDir = tmpDir;

    // ── 5. Validate package args ────────────────────────────────────────
    this._validatePackageArgs(initialArgs);

    // ── 6. Generate candidate lockfile (only if NOT skipping) ──────────
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

    // ── 7. Hash candidate composer.json (TOCTOU guard) ─────────────────
    if (fs.existsSync(composerJsonPath)) {
      const manifestRaw = fs.readFileSync(composerJsonPath, "utf8");
      this._candidateComposerJsonHash = createHash("sha256")
        .update(manifestRaw, "utf8")
        .digest("hex");
    } else {
      this._candidateComposerJsonHash = "absent";
    }

    // ── 8. Parse candidate lockfile ─────────────────────────────────────
    const candidateRaw = fs.readFileSync(lockPath, "utf8");
    this.candidate_lockfile_content = candidateRaw;
    this.currentLockFileContent     = candidateRaw;

    this._candidateLockfileHash = createHash("sha256")
      .update(candidateRaw, "utf8")
      .digest("hex");

    const allCandidateComponents = this.parseComposerLock(lockPath, projectPath);

    // ── 9. Diff: isolate net-new packages ───────────────────────────────
    //
    // Same reasoning as node_runner.js's runDryRun(): when skipDryRun is
    // true the lockfile was never regenerated, so the "before" and "after"
    // are literally the same file — diffing them would (incorrectly) yield
    // zero new components. In that mode there is no before/after to diff:
    // the whole existing lockfile IS the inventory being reported on.
    let componentsForInventory;

    if (skipDryRun) {
      componentsForInventory = allCandidateComponents;
    } else {
      const originalPurls = new Set();
      if (this._original_lockfile) {
        try {
          const origData = JSON.parse(this._original_lockfile);
          const origPackages = [...(origData.packages || []), ...(origData["packages-dev"] || [])];
          for (const pkg of origPackages) {
            if (!pkg.name) continue;
            const version = this._normaliseVersion(pkg.version || "");
            originalPurls.add(this._composerPurl(pkg.name, version));
          }
        } catch {
          // Original lockfile unparseable → treat all candidates as new
        }
      }

      componentsForInventory = allCandidateComponents.filter(c => !originalPurls.has(c.id));
    }

    // ── 10. Normalise ─────────────────────────────────────────────────
    const merged = this.mergeInventoryByPurl(componentsForInventory);
    this.inventoryData = merged;

    if (this.engineVersion) {
      this.inventoryData.push(
        {
          id:        `pkg:composer/composer@${this.engineVersion}`,
          name:      "composer",
          version:   this.engineVersion,
          license:   "MIT",
          ecosystem: "php",
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

    // ── 11. Assign scopes ────────────────────────────────────────────
    // Scopes need the FULL candidate graph to propagate prod/dev correctly
    // (a transitive dep of a dev-only package must inherit "dev" even
    // though it isn't itself in composer.json's require-dev), so scoping
    // runs against allCandidateComponents and is then copied onto the
    // diffed/merged inventory that's actually reported.
    this._assignScopes(allCandidateComponents);

    const scopeMap = new Map(allCandidateComponents.map(c => [c.id, c.scopes]));
    for (const comp of this.inventoryData) {
      if (!Array.isArray(comp.scopes) || comp.scopes.length === 0) {
        comp.scopes = scopeMap.get(comp.id) ?? [];
      }
    }

    return merged.map(c => c.id);
  }

  // ─────────────────────────────
  // Revert composer.json + composer.lock to originals
  // ─────────────────────────────
  revert_lock_to_original(engine = "composer", projectPath) {
    const cfg = ENGINE_CONFIG[engine];
    if (!cfg) {
      return {
        reverted:  false,
        reason:    `Unknown engine '${engine}' — cannot determine lockfile name`,
        backupDir: this._lockfileBackupDir,
      };
    }

    const composerJsonPath = path.join(projectPath, cfg.manifest);
    const lockPath         = path.join(projectPath, cfg.lockfile);
    const tmpDir           = this._lockfileBackupDir;

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

    const composerExpectedHash = this._candidateComposerJsonHash ?? this._original_composer_json_hash;
    const composerCheck        = verifyFile(composerJsonPath, composerExpectedHash, cfg.manifest);
    if (!composerCheck.ok) {
      return { reverted: false, reason: composerCheck.reason, backupDir: tmpDir };
    }

    const lockExpectedHash = this._candidateLockfileHash ?? this._original_lockfile_hash;
    const lockCheck        = verifyFile(lockPath, lockExpectedHash, cfg.lockfile);
    if (!lockCheck.ok) {
      return { reverted: false, reason: lockCheck.reason, backupDir: tmpDir };
    }

    try {
      let composerContent = this._original_composer_json;
      if (composerContent === null && tmpDir) {
        const disk = path.join(tmpDir, cfg.manifest);
        if (fs.existsSync(disk)) composerContent = fs.readFileSync(disk, "utf8");
      }
      if (composerContent !== null) {
        fs.writeFileSync(composerJsonPath, composerContent, "utf8");
      } else if (fs.existsSync(composerJsonPath)) {
        fs.unlinkSync(composerJsonPath);
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
  //
  // Unlike npm (where `--package-lock-only <pkg>` only bumps a semver
  // range in package.json, so Node's saveCandidateLockfile has to
  // reconcile exact pinned versions back into it from the lockfile),
  // `composer require --no-install` already writes the resolved
  // constraint into composer.json directly — so this step is mainly a
  // second integrity check plus re-affirming the candidate lockfile
  // content on disk before the real install runs.
  async saveCandidateLockfile(engine = "composer", projectPath) {
    const cfg              = ENGINE_CONFIG[engine] || ENGINE_CONFIG.composer;
    const lockfilePath     = path.join(projectPath, cfg.lockfile);
    const composerJsonPath = path.join(projectPath, cfg.manifest);

    if (!this.candidate_lockfile_content) {
      return {
        written:  false,
        filePath: lockfilePath,
        reason:   "candidate_lockfile_content is null — run runDryRun() first",
      };
    }

    try {
      if (this._candidateComposerJsonHash && this._candidateComposerJsonHash !== "absent") {
        if (!fs.existsSync(composerJsonPath)) {
          return {
            written:  false,
            filePath: lockfilePath,
            reason:   "composer.json integrity check FAILED — file was removed after scanning",
          };
        }
        const onDisk     = fs.readFileSync(composerJsonPath, "utf8");
        const onDiskHash = createHash("sha256").update(onDisk, "utf8").digest("hex");
        if (onDiskHash !== this._candidateComposerJsonHash) {
          return {
            written:  false,
            filePath: lockfilePath,
            reason:   `composer.json integrity check FAILED — the file was modified after scanning.\n` +
                      `  Expected : ${this._candidateComposerJsonHash}\n` +
                      `  Got      : ${onDiskHash}\n` +
                      `  File     : ${composerJsonPath}`,
          };
        }
      }

      const raw = typeof this.candidate_lockfile_content === "string"
        ? this.candidate_lockfile_content
        : JSON.stringify(this.candidate_lockfile_content, null, 4);

      fs.writeFileSync(lockfilePath, raw, "utf8");

      return { written: true, filePath: lockfilePath, composerJsonPath };

    } catch (err) {
      return { written: false, filePath: lockfilePath, reason: err.message };
    }
  }

  // ─────────────────────────────
  // Lockfile integrity check
  // ─────────────────────────────
  async verifyCandidateLockfileHash(engine = "composer", projectPath) {
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
  // composer.json integrity check
  // ─────────────────────────────
  async verifyComposerJsonHash(projectPath) {
    if (!this._candidateComposerJsonHash) {
      return {
        ok:     false,
        reason: "No candidate composer.json hash recorded — runDryRun() must be called first",
      };
    }

    const manifestPath = path.join(projectPath, "composer.json");

    if (this._candidateComposerJsonHash === "absent") {
      if (fs.existsSync(manifestPath)) {
        return {
          ok:     false,
          reason: `composer.json integrity check FAILED — file was created after scanning.\n` +
                  `  Expected : <absent>\n` +
                  `  File     : ${manifestPath}`,
        };
      }
      return { ok: true };
    }

    let currentContent;
    try {
      currentContent = fs.readFileSync(manifestPath, "utf8");
    } catch (err) {
      return {
        ok:     false,
        reason: `Could not read composer.json for verification: ${err.message}`,
      };
    }

    const currentHash = createHash("sha256").update(currentContent, "utf8").digest("hex");

    if (currentHash !== this._candidateComposerJsonHash) {
      return {
        ok:     false,
        reason: `composer.json integrity check FAILED — the file was modified after scanning.\n` +
                `  Expected : ${this._candidateComposerJsonHash}\n` +
                `  Got      : ${currentHash}\n` +
                `  File     : ${manifestPath}`,
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

    const composerJsonCheck = await this.verifyComposerJsonHash(projectPath);
    if (!composerJsonCheck.ok) {
      throw new Error(`composer.json integrity check failed: ${composerJsonCheck.reason}`);
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
  //
  // Pure, ecosystem-agnostic helpers operating only on each component's
  // `id`/`dependencies` fields — engine.js's scan() pipeline calls these
  // generically on whichever manager is active (npm/pypi/linux/composer),
  // so they're carried over unchanged from NodeManagerInstance rather than
  // reimplemented.
  // ─────────────────────────────

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
  }

  // ─────────────────────────────
  // ENTRY
  // ─────────────────────────────
  async getInstalled(startDir) {

    this.inventoryData = [];

    const visited = new Set();
    const raw     = [];

    const collectComponents = (dir) => {
      const comps = [];
      const hasComposerJson = fs.existsSync(path.join(dir, "composer.json"));
      const hasComposerLock = fs.existsSync(path.join(dir, "composer.lock"));

      if (hasComposerJson) {
        // _scanProject reads installed.json if present, otherwise returns []
        comps.push(...this._scanProject(dir));
      }
      if (hasComposerLock) {
        comps.push(...this.parseComposerLock(path.join(dir, "composer.lock"), dir));
      }
      return comps;
    };

    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (["node_modules", ".git", ".ubel", "vendor"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        // Check if this directory is a composer project (has composer.json or .lock)
        const hasComposerJson = fs.existsSync(path.join(full, "composer.json"));
        const hasComposerLock = fs.existsSync(path.join(full, "composer.lock"));
        if (hasComposerJson || hasComposerLock) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...collectComponents(full));
          }
        }

        // Descend into subdirectories
        walk(full);
      }
    };

    // Check startDir itself
    const startHasJson = fs.existsSync(path.join(startDir, "composer.json"));
    const startHasLock = fs.existsSync(path.join(startDir, "composer.lock"));
    if (startHasJson || startHasLock) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...collectComponents(startDir));
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    // Strip internal-only flag before exposing
    for (const c of merged) delete c.dev;

    this.inventoryData = merged;

    return merged.map(c => c.id);
  }
}

export default PhpComposerScanner;