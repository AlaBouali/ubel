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
 *         • obj/project.assets.json  (MSBuild restore fallback)
 *   3.  Central Package Management: Directory.Packages.props is walked up
 *       from the project root to resolve versions missing from the .csproj.
 *   4.  Multi-target projects: the highest resolved version across TFMs is used.
 *   5.  PURL: pkg:nuget/<name>@<version>
 *            (no @ when version is unknown)
 */
export class CSharpNuGetScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // Omits @<version> when version is blank to avoid silent PURL collisions.
  // ─────────────────────────────
  static _nugetPurl(name, version) {
    const base = `pkg:nuget/${name.toLowerCase()}`;
    return version ? `${base}@${version}` : base;
  }

  // ─────────────────────────────
  // Detect .NET project root
  // ─────────────────────────────
  static _isDotnetRoot(dir) {
    try {
      return fs.readdirSync(dir).some(f => /\.(cs|fs|vb)proj$/.test(f));
    } catch {
      return false;
    }
  }

  // ─────────────────────────────
  // Walk ancestors for Directory.Packages.props (Central Package Management).
  // Returns Map<lowercaseName, version> or empty Map.
  // ─────────────────────────────
  static _readCentralPackageProps(startDir) {
    const versions = new Map();
    let dir = startDir;

    for (let i = 0; i < 8; i++) {                 // cap ancestor search depth
      const candidate = path.join(dir, "Directory.Packages.props");
      if (fs.existsSync(candidate)) {
        let xml;
        try { xml = fs.readFileSync(candidate, "utf8"); } catch { break; }
        // <PackageVersion Include="Foo.Bar" Version="1.2.3" />
        const re = /<PackageVersion[\s\S]*?Include=["']([^"']+)["'][\s\S]*?Version=["']([^"']+)["']/gi;
        let m;
        while ((m = re.exec(xml)) !== null) {
          versions.set(m[1].toLowerCase(), m[2]);
        }
        break;                                    // stop at first props file found
      }
      const parent = path.dirname(dir);
      if (parent === dir) break;                  // filesystem root
      dir = parent;
    }

    return versions;
  }

  // ─────────────────────────────
  // Parse packages.lock.json (preferred).
  // Merges all TFMs, keeping the highest version when the same package appears
  // under multiple target frameworks.
  // Returns Map<lowercaseName, { name, version, type, dependencies[] }> or null.
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

    const index = new Map();

    for (const tfmDeps of Object.values(raw.dependencies ?? {})) {
      for (const [pkgId, meta] of Object.entries(tfmDeps)) {
        const key     = pkgId.toLowerCase();
        const version = meta.resolved ?? meta.requested ?? "";
        if (!version) continue;                   // skip malformed entries

        if (!index.has(key)) {
          index.set(key, {
            name:         pkgId,
            version,
            type:         (meta.type ?? "direct").toLowerCase(),
            dependencies: Object.keys(meta.dependencies ?? {}).map(d => d.toLowerCase())
          });
        } else {
          // Keep the highest version seen across TFMs
          const existing = index.get(key);
          if (this._versionGt(version, existing.version)) {
            existing.version = version;
          }
        }
      }
    }

    return index.size ? index : null;
  }

  // ─────────────────────────────
  // Simple semver-ish "greater than" for version tie-breaking across TFMs.
  // Falls back to lexicographic comparison for non-semver strings.
  // ─────────────────────────────
  static _versionGt(a, b) {
    const parse = v => v.split(/[.\-]/).map(p => parseInt(p, 10) || 0);
    const pa = parse(a), pb = parse(b);
    for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
      const diff = (pa[i] ?? 0) - (pb[i] ?? 0);
      if (diff !== 0) return diff > 0;
    }
    return false;
  }

  // ─────────────────────────────
  // Parse obj/project.assets.json (fallback).
  // Returns Map<lowercaseName, { name, version, type, dependencies[] }> or null.
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

    const index = new Map();

    for (const [libKey, meta] of Object.entries(raw.libraries ?? {})) {
      const slash   = libKey.lastIndexOf("/");
      const name    = slash >= 0 ? libKey.slice(0, slash)  : libKey;
      const version = slash >= 0 ? libKey.slice(slash + 1) : "";
      if (!version) continue;                     // skip malformed entries
      const key = name.toLowerCase();

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
  // Read direct deps from .csproj.
  // Handles both single-line and multi-line PackageReference elements.
  // Returns { prod: Set<string>, dev: Set<string> } (lowercase names).
  // Falls back to Directory.Packages.props for version resolution when needed.
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

    // Match both single-line and multi-line PackageReference elements.
    // [\s\S]*? spans newlines; stops at the first closing > or />
    const re = /<PackageReference\b([\s\S]*?)(?:\/>|>[\s\S]*?<\/PackageReference>)/gi;
    let m;
    while ((m = re.exec(xml)) !== null) {
      const attrs     = m[1];
      const nameMatch = attrs.match(/\bInclude=["']([^"']+)["']/i);
      if (!nameMatch) continue;

      const name      = nameMatch[1].toLowerCase();
      const condition = (attrs.match(/\bCondition=["']([^"']+)["']/i)?.[1] ?? "").toLowerCase();

      if (condition && (condition.includes("debug") || condition.includes("test"))) {
        dev.add(name);
      } else {
        prod.add(name);
      }
    }

    return { prod, dev };
  }

  // ─────────────────────────────
  // Scan a single .NET project directory.
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
        license:      "unknown",
        ecosystem:    "csharp",
        state:        version ? "undetermined" : "version_unknown",
        scopes:       [],
        dependencies: resolvedDeps,
        paths:        [projectRoot],
        project_root: projectRoot,
        _nugetType:   type          // "direct" | "transitive" — used for scope seeding
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (prod / dev) via BFS from direct deps declared in .csproj.
  //
  // Key fix: nameIdx is built PER PROJECT inside the loop, so BFS can never
  // escape into a different project's components.
  // ─────────────────────────────
  static _assignScopes(inventory) {
    const byId = new Map(inventory.map(c => [c.id, c]));

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
    }

    // Group components by project root
    const projectGroups = new Map();
    for (const comp of inventory) {
      const root = comp.project_root;
      if (!projectGroups.has(root)) projectGroups.set(root, []);
      projectGroups.get(root).push(comp);
    }

    for (const [projectRoot, comps] of projectGroups.entries()) {

      // Build a name index scoped ONLY to this project's components
      const nameIdx = new Map();
      for (const c of comps) {
        const existing = nameIdx.get(c.name) ?? [];
        existing.push(c);
        nameIdx.set(c.name, existing);
      }

      const { prod, dev } = this._readCsprojDeps(projectRoot);

      // Fallback: seed from _nugetType === "direct" only when the csproj file
      // could not be read (both sets empty AND no csproj found), not merely
      // when the csproj parsed to zero PackageReferences.
      if (prod.size === 0 && dev.size === 0) {
        let csprojExists = false;
        try {
          csprojExists = fs.readdirSync(projectRoot).some(f => /\.(cs|fs|vb)proj$/.test(f));
        } catch { /* ignore */ }

        if (!csprojExists) {
          for (const c of comps) {
            if (c._nugetType === "direct") prod.add(c.name);
          }
        }
      }

      const propagate = (names, scope) => {
        const queue = [];
        for (const n of names) {
          for (const c of (nameIdx.get(n) ?? [])) queue.push(c);
        }

        const visited = new Set();
        while (queue.length) {
          const c = queue.shift();
          if (visited.has(c.id)) continue;
          visited.add(c.id);

          if (!c.scopes.includes(scope)) c.scopes.push(scope);

          for (const depId of c.dependencies) {
            const d = byId.get(depId);
            // Only follow edges within this project
            if (d && d.project_root === projectRoot) queue.push(d);
          }
        }
      };

      propagate(prod, "prod");
      propagate(dev,  "dev");

      // Fallback — any component still unscoped defaults to prod
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
  // Walks startDir (and subdirs) for .NET project roots, then scans each.
  // ─────────────────────────────
  static async getInstalled(startDir = process.cwd()) {
    this.inventoryData = [];

    const visited = new Set();
    const raw     = [];

    // Scan startDir itself if it is a .NET root
    if (CSharpNuGetScanner._isDotnetRoot(startDir)) {
      const key = path.resolve(startDir);
      visited.add(key);
      raw.push(...CSharpNuGetScanner._scanProject(startDir));
    }

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
        const key  = path.resolve(full);

        if (CSharpNuGetScanner._isDotnetRoot(full)) {
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...CSharpNuGetScanner._scanProject(full));
          }
          continue;
        }

        walk(full);
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    // Remove internal field before exposing inventory
    for (const c of merged) delete c._nugetType;

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default CSharpNuGetScanner;