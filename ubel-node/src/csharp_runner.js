// CSharpNuGetScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans C# / .NET projects for installed NuGet packages.
 *
 * Detection strategy:
 *   1.  A directory is a NuGet project root when it contains at least one
 *       *.csproj / *.fsproj / *.vbproj file.
 *   2.  Installed packages are read from:
 *         • packages.lock.json   (NuGet lock file, preferred)
 *         • project.assets.json  (obj/project.assets.json, MSBuild restore)
 *   3.  PURL: pkg:nuget/<name>@<version>
 */
export class CSharpNuGetScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _nugetPurl(name, version) {
    // NuGet IDs are case-insensitive; normalise to lowercase for PURL.
    return `pkg:nuget/${name.toLowerCase()}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect .NET project root
  // ─────────────────────────────
  static _isDotnetRoot(dir) {
    try {
      return fs.readdirSync(dir).some(f =>
        /\.(cs|fs|vb)proj$/.test(f)
      );
    } catch {
      return false;
    }
  }

  // ─────────────────────────────
  // Parse packages.lock.json
  // Returns Map<lowercaseName, { name, version, resolved, dependencies[] }>
  // ─────────────────────────────
  static _readPackagesLock(projectRoot) {
    const lockPath = path.join(projectRoot, "packages.lock.json");
    if (!fs.existsSync(lockPath)) return null;

    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(lockPath, "utf8"));
    } catch {
      return null;
    }

    // packages.lock.json structure:
    // { "version": 1, "dependencies": { "<TFM>": { "<PkgId>": { "type": "...", "resolved": "x.y.z", "dependencies": {} } } } }
    const index = new Map();   // lowercase id → entry

    for (const tfmDeps of Object.values(raw.dependencies ?? {})) {
      for (const [pkgId, meta] of Object.entries(tfmDeps)) {
        const key     = pkgId.toLowerCase();
        const version = meta.resolved ?? meta.requested ?? "";
        if (!index.has(key)) {
          index.set(key, {
            name:         pkgId,
            version,
            type:         (meta.type ?? "direct").toLowerCase(),   // "direct" | "transitive"
            dependencies: Object.keys(meta.dependencies ?? {}).map(d => d.toLowerCase())
          });
        }
      }
    }

    return index;
  }

  // ─────────────────────────────
  // Parse obj/project.assets.json
  // Fallback when packages.lock.json absent.
  // ─────────────────────────────
  static _readProjectAssets(projectRoot) {
    const assetPath = path.join(projectRoot, "obj", "project.assets.json");
    if (!fs.existsSync(assetPath)) return null;

    let raw;
    try {
      raw = JSON.parse(fs.readFileSync(assetPath, "utf8"));
    } catch {
      return null;
    }

    // libraries section: { "<Name>/<Version>": { type, dependencies: { ... } } }
    const index = new Map();

    for (const [libKey, meta] of Object.entries(raw.libraries ?? {})) {
      const slash   = libKey.lastIndexOf("/");
      const name    = slash >= 0 ? libKey.slice(0, slash)  : libKey;
      const version = slash >= 0 ? libKey.slice(slash + 1) : "";
      const key     = name.toLowerCase();

      if (!index.has(key)) {
        index.set(key, {
          name,
          version,
          type:         (meta.type ?? "package").toLowerCase(),
          dependencies: Object.keys(meta.dependencies ?? {}).map(d => d.toLowerCase())
        });
      }
    }

    return index.size ? index : null;
  }

  // ─────────────────────────────
  // Read direct deps from .csproj
  // Returns { prod: Set<string>, dev: Set<string> } (all lowercase names)
  // ─────────────────────────────
  static _readCsprojDeps(projectRoot) {
    const prod = new Set();
    const dev  = new Set();

    let projFile;
    try {
      projFile = fs.readdirSync(projectRoot).find(f => /\.(cs|fs|vb)proj$/.test(f));
    } catch {
      return { prod, dev };
    }
    if (!projFile) return { prod, dev };

    let xml;
    try {
      xml = fs.readFileSync(path.join(projectRoot, projFile), "utf8");
    } catch {
      return { prod, dev };
    }

    // Minimal regex parse – no full XML parser needed for UBEL's purposes.
    // <PackageReference Include="Foo.Bar" Version="1.2.3" />
    // <PackageReference Include="Foo.Bar" Condition="'$(Configuration)' == 'Debug'" ...>
    const re = /<PackageReference\s+[^>]*Include=["']([^"']+)["'][^>]*(Condition=[^>]*)?/gi;
    let m;
    while ((m = re.exec(xml)) !== null) {
      const name      = m[1].toLowerCase();
      const condition = (m[2] ?? "").toLowerCase();
      // Heuristic: conditions containing "debug" or "test" → dev scope
      if (condition && (condition.includes("debug") || condition.includes("test"))) {
        dev.add(name);
      } else {
        prod.add(name);
      }
    }

    return { prod, dev };
  }

  // ─────────────────────────────
  // Scan a single .NET project
  // ─────────────────────────────
  static _scanProject(projectRoot) {
    const index =
      this._readPackagesLock(projectRoot) ??
      this._readProjectAssets(projectRoot);

    if (!index) return [];

    const components = [];

    for (const [key, { name, version, type, dependencies }] of index.entries()) {
      const id = this._nugetPurl(name, version);

      const resolvedDeps = dependencies.map(dep => {
        const resolved = index.get(dep);
        return resolved
          ? this._nugetPurl(resolved.name, resolved.version)
          : this._nugetPurl(dep, "");
      });

      components.push({
        id,
        name:         key,
        version,
        type:         "library",
        license:      "unknown",    // NuGet lock files don't carry license info
        ecosystem:    "csharp",
        state:        "undetermined",
        scopes:       [],
        dependencies: resolvedDeps,
        paths:        [projectRoot],
        project_root: projectRoot,
        _nugetType:   type          // "direct" | "transitive" – used for scope seeding
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (prod / dev)
  // via BFS from direct deps declared in .csproj
  // ─────────────────────────────
  static _assignScopes(inventory) {
    const byId    = new Map(inventory.map(c => [c.id, c]));
    const nameIdx = new Map();

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      const comps = nameIdx.get(comp.name) ?? [];
      comps.push(comp);
      nameIdx.set(comp.name, comps);
    }

    const projectGroups = new Map();
    for (const comp of inventory) {
      const root = comp.project_root;
      if (!projectGroups.has(root)) projectGroups.set(root, []);
      projectGroups.get(root).push(comp);
    }

    for (const [projectRoot, comps] of projectGroups.entries()) {
      const { prod, dev } = this._readCsprojDeps(projectRoot);

      // Seed from _nugetType === "direct" if csproj parse found nothing
      if (prod.size === 0 && dev.size === 0) {
        for (const c of comps) {
          if (c._nugetType === "direct") prod.add(c.name);
        }
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

      // Fallback – unscoped packages default to prod
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
      for (const p of comp.paths)   { if (!existing.paths.includes(p))   existing.paths.push(p); }
      for (const s of comp.scopes)  { if (!existing.scopes.includes(s))  existing.scopes.push(s); }
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
        if (["node_modules", ".git", ".ubel", "obj", "bin", "packages"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (CSharpNuGetScanner._isDotnetRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...CSharpNuGetScanner._scanProject(full));
          }
          continue;
        }

        walk(full);
      }
    }

    if (CSharpNuGetScanner._isDotnetRoot(startDir)) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...CSharpNuGetScanner._scanProject(startDir));
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    for (const c of merged) delete c._nugetType;

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default CSharpNuGetScanner;