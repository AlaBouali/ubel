// RustCargoScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Rust / Cargo projects for installed crates.
 *
 * Detection strategy:
 *   1.  A directory is a Cargo project root when it contains Cargo.toml
 *       AND Cargo.lock (lock file = installed state).
 *   2.  Installed packages are read from Cargo.lock (the only reliable
 *       source of fully-resolved crate graph with exact versions).
 *   3.  Workspace support: if the root Cargo.toml contains [workspace],
 *       member paths are scanned recursively.
 *   4.  PURL: pkg:cargo/<name>@<version>
 *
 * Cargo.lock format (v1/v2/v3 are all handled):
 *   [[package]]
 *   name    = "foo"
 *   version = "1.2.3"
 *   source  = "registry+..."
 *   checksum = "..."
 *   dependencies = [ "bar 0.4.0", "baz 1.0.0 (...)" ]
 */
export class RustCargoScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _cargoPurl(name, version) {
    return `pkg:cargo/${name.toLowerCase()}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect Cargo project root
  // ─────────────────────────────
  static _isCargoRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "Cargo.toml")) &&
      fs.existsSync(path.join(dir, "Cargo.lock"))
    );
  }

  // ─────────────────────────────
  // Minimal TOML block parser for Cargo.lock
  // Returns array of { name, version, source, dependencies[] }
  // ─────────────────────────────
  static _parseCargoLock(lockPath) {
    let content;
    try {
      content = fs.readFileSync(lockPath, "utf8");
    } catch {
      return [];
    }

    const packages = [];
    // Split on [[package]] sections
    const blocks = content.split(/^\[\[package\]\]/m).slice(1);

    for (const block of blocks) {
      const getName    = block.match(/^name\s*=\s*"([^"]+)"/m);
      const getVer     = block.match(/^version\s*=\s*"([^"]+)"/m);
      const getSrc     = block.match(/^source\s*=\s*"([^"]+)"/m);

      if (!getName || !getVer) continue;

      const name    = getName[1];
      const version = getVer[1];
      const source  = getSrc ? getSrc[1] : "local";

      // dependencies block – single-line array or multi-line array
      // e.g.:  dependencies = [\n "bar 0.4.0",\n "baz 1.0.0 (registry+...)"\n]
      const deps = [];
      const depsMatch = block.match(/^dependencies\s*=\s*\[([^\]]*)\]/ms);
      if (depsMatch) {
        const inner = depsMatch[1];
        // Each dep is a quoted string like "name version" or "name version (source)"
        const depRe = /"([^"]+)"/g;
        let dm;
        while ((dm = depRe.exec(inner)) !== null) {
          const parts = dm[1].split(" ");
          deps.push({ name: parts[0], version: parts[1] ?? "" });
        }
      }

      packages.push({ name, version, source, dependencies: deps });
    }

    return packages;
  }

  // ─────────────────────────────
  // Read [dependencies] / [dev-dependencies] / [build-dependencies]
  // from a Cargo.toml file.
  // Returns { prod: Set<string>, dev: Set<string>, build: Set<string> }
  // (all lowercase crate names)
  // ─────────────────────────────
  static _readCargoTomlDeps(tomlPath) {
    const prod  = new Set();
    const dev   = new Set();
    const build = new Set();

    let content;
    try {
      content = fs.readFileSync(tomlPath, "utf8");
    } catch {
      return { prod, dev, build };
    }

    // We do minimal section-aware line scanning (no full TOML parser needed).
    let section = "";
    for (const line of content.split("\n")) {
      const trimmed = line.trim();

      // Section header
      const secMatch = trimmed.match(/^\[([^\]]+)\]/);
      if (secMatch) {
        section = secMatch[1].trim();
        continue;
      }

      // Key = value lines inside dependency sections
      if (
        section === "dependencies"       ||
        section === "dev-dependencies"   ||
        section === "build-dependencies" ||
        // target-scoped: [target.'cfg(...)'.dependencies]
        section.endsWith(".dependencies")
      ) {
        const kvMatch = trimmed.match(/^([A-Za-z0-9_-]+)\s*[=.]/);
        if (kvMatch) {
          const name = kvMatch[1].toLowerCase().replace(/-/g, "_"); // Cargo normalises - → _
          if (section === "dev-dependencies") dev.add(name);
          else if (section === "build-dependencies") build.add(name);
          else prod.add(name);
        }
      }
    }

    return { prod, dev, build };
  }

  // ─────────────────────────────
  // Scan a single Cargo project
  // ─────────────────────────────
  static _scanProject(projectRoot) {
    const lockPath = path.join(projectRoot, "Cargo.lock");
    const packages = this._parseCargoLock(lockPath);
    if (!packages.length) return [];

    // Build lookup index: "<name>@<version>" → package entry
    const index = new Map();
    for (const pkg of packages) {
      const key = `${pkg.name.toLowerCase()}@${pkg.version}`;
      if (!index.has(key)) index.set(key, pkg);
    }

    // Also a name-only index (latest version wins if dupes) for dep resolution
    const nameIndex = new Map();
    for (const pkg of packages) {
      const norm = pkg.name.toLowerCase().replace(/-/g, "_");
      nameIndex.set(norm, pkg);
    }

    const components = [];

    for (const pkg of packages) {
      const name    = pkg.name.toLowerCase().replace(/-/g, "_");
      const id      = this._cargoPurl(pkg.name, pkg.version);
      const isLocal = pkg.source === "local" || !pkg.source.startsWith("registry");

      const dependencies = pkg.dependencies.map(dep => {
        const depName = dep.name.toLowerCase().replace(/-/g, "_");
        const depKey  = `${depName}@${dep.version}`;
        const resolved = index.get(depKey) ?? nameIndex.get(depName);
        return resolved
          ? this._cargoPurl(resolved.name, resolved.version)
          : this._cargoPurl(dep.name, dep.version);
      });

      components.push({
        id,
        name,
        version:      pkg.version,
        type:         "library",
        license:      "unknown",
        ecosystem:    "rust",
        state:        "undetermined",
        scopes:       [],
        dependencies,
        paths:        [isLocal ? projectRoot : pkg.source],
        project_root: projectRoot,
        _source:      pkg.source
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (prod / dev / build)
  // ─────────────────────────────
  static _assignScopes(inventory) {
    const byId    = new Map(inventory.map(c => [c.id, c]));
    const nameIdx = new Map();

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      const key   = comp.name;
      const comps = nameIdx.get(key) ?? [];
      comps.push(comp);
      nameIdx.set(key, comps);
    }

    const projectGroups = new Map();
    for (const comp of inventory) {
      const root = comp.project_root;
      if (!projectGroups.has(root)) projectGroups.set(root, []);
      projectGroups.get(root).push(comp);
    }

    for (const [projectRoot, comps] of projectGroups.entries()) {
      const { prod, dev, build } = this._readCargoTomlDeps(
        path.join(projectRoot, "Cargo.toml")
      );

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

      propagate(prod,  "prod");
      propagate(dev,   "dev");
      propagate(build, "build");

      // Fallback
      for (const c of comps) {
        if (c.scopes.length === 0) c.scopes.push("prod");
      }
    }
  }

  // ─────────────────────────────
  // Merge duplicates by PURL
  // ─────────────────────────────
  static mergeInventoryByPurl(components) {
    const map = new Map();

    for (const comp of components) {
      if (!map.has(comp.id)) {
        map.set(comp.id, { ...comp, paths: [...comp.paths] });
        continue;
      }
      const existing = map.get(comp.id);
      for (const p of comp.paths)  { if (!existing.paths.includes(p))  existing.paths.push(p); }
      for (const s of comp.scopes) { if (!existing.scopes.includes(s)) existing.scopes.push(s); }
    }

    return [...map.values()];
  }

  // ─────────────────────────────
  // ENTRY
  // ─────────────────────────────
  static async getInstalled(startDir = process.cwd()) {
    this.inventoryData = [];

    const visited = new Set();
    const raw     = [];

    function walk(dir) {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (["node_modules", ".git", ".ubel", "target"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (RustCargoScanner._isCargoRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...RustCargoScanner._scanProject(full));
          }
          // Still descend – workspaces have nested member crates
          // BUT skip target/ which is handled above
        }

        walk(full);
      }
    }

    if (RustCargoScanner._isCargoRoot(startDir)) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...RustCargoScanner._scanProject(startDir));
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    for (const c of merged) delete c._source;

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default RustCargoScanner;