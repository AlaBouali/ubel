// php_composer_scanner.js
import fs   from "fs";
import path from "path";

export class PhpComposerScanner {

  constructor() {
    this.inventoryData = [];
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