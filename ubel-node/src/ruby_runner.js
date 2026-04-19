// RubyBundlerScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Ruby / Bundler projects for installed gems.
 *
 * Detection strategy:
 *   1.  A directory is a Bundler project root when it contains a Gemfile
 *       AND a Gemfile.lock (the locked, installed state).
 *   2.  Installed gems are read exclusively from Gemfile.lock (the resolved graph).
 *       Gemfile is parsed only for group classification (dev / test / prod).
 *   3.  PURL: pkg:gem/<name>@<version>
 *
 * Gemfile.lock structure:
 *   GEM
 *     remote: https://rubygems.org/
 *     specs:
 *       activesupport (7.0.4)
 *         concurrent-ruby (~> 1.0, >= 1.0.2)
 *         ...
 *   PLATFORMS
 *     ...
 *   DEPENDENCIES
 *     rails (~> 7.0)
 *     rspec-rails (>= 0, development)
 *
 * Gemfile group syntax:
 *   gem 'rails'
 *   gem 'rspec', group: :test
 *   group :development, :test do
 *     gem 'byebug'
 *   end
 */
export class RubyBundlerScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _gemPurl(name, version) {
    return `pkg:gem/${name.toLowerCase()}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect Bundler project root
  // ─────────────────────────────
  static _isBundlerRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "Gemfile")) &&
      fs.existsSync(path.join(dir, "Gemfile.lock"))
    );
  }

  // ─────────────────────────────
  // Parse Gemfile.lock
  // Returns Map<lowercaseName, { name, version, dependencies[] }>
  // ─────────────────────────────
  static _parseGemfileLock(lockPath) {
    let content;
    try {
      content = fs.readFileSync(lockPath, "utf8");
    } catch {
      return new Map();
    }

    const index = new Map();   // lowercase name → entry

    // Sections are separated by blank lines with uppercase headers.
    // We only care about the GEM / PATH / GIT specs sections.
    let inSpecs = false;

    // Track current gem being parsed (for dependency lines)
    let currentGem = null;

    for (const rawLine of content.split("\n")) {
      const line = rawLine;

      // Section headers
      if (/^(GEM|PATH|GIT)$/.test(line.trim())) {
        inSpecs = false;
        currentGem = null;
        continue;
      }
      if (line.trim() === "specs:") {
        inSpecs = true;
        currentGem = null;
        continue;
      }
      // Exit specs block on next section header or PLATFORMS/DEPENDENCIES/BUNDLED WITH
      if (/^[A-Z]/.test(line) && line.trim() !== "specs:") {
        inSpecs = false;
        currentGem = null;
        continue;
      }

      if (!inSpecs) continue;

      // Indentation tells us structure:
      //   4 spaces  = top-level gem:  "    activesupport (7.0.4)"
      //   6 spaces  = dependency of current gem: "      concurrent-ruby (~> 1.0)"
      const indent = line.match(/^(\s*)/)[1].length;
      const trimmed = line.trim();
      if (!trimmed) continue;

      if (indent === 4) {
        // Top-level gem line: "name (version)"
        const m = trimmed.match(/^([A-Za-z0-9_.-]+)\s+\(([^)]+)\)/);
        if (!m) { currentGem = null; continue; }

        const name    = m[1];
        const version = m[2].split(", ")[0];  // take first version if multiple
        const key     = name.toLowerCase();

        currentGem = { name, version, dependencies: [] };
        index.set(key, currentGem);

      } else if (indent >= 6 && currentGem) {
        // Dependency line: "dep-name (constraint)"  or just "dep-name"
        const m = trimmed.match(/^([A-Za-z0-9_.-]+)/);
        if (m) currentGem.dependencies.push(m[1].toLowerCase());
      }
    }

    return index;
  }

  // ─────────────────────────────
  // Parse Gemfile for group info
  // Returns { prod: Set<string>, dev: Set<string> }
  // (lowercase gem names)
  // ─────────────────────────────
  static _parseGemfileGroups(gemfilePath) {
    const prod = new Set();
    const dev  = new Set();

    let content;
    try {
      content = fs.readFileSync(gemfilePath, "utf8");
    } catch {
      return { prod, dev };
    }

    const DEV_GROUPS = new Set(["development", "test", "staging"]);

    let currentGroups = [];   // groups active for the current block

    for (const rawLine of content.split("\n")) {
      const line    = rawLine.trim();
      if (!line || line.startsWith("#")) continue;

      // group :development, :test do
      const groupBlock = line.match(/^group\s+(.*?)\s+do$/);
      if (groupBlock) {
        currentGroups = groupBlock[1]
          .split(",")
          .map(g => g.trim().replace(/^:/, "").toLowerCase());
        continue;
      }

      // end  – close group block
      if (line === "end") {
        currentGroups = [];
        continue;
      }

      // gem 'name', ...
      // gem "name", group: :test
      // gem "name", groups: [:development, :test]
      const gemLine = line.match(/^gem\s+['"]([^'"]+)['"](.*)/);
      if (!gemLine) continue;

      const gemName = gemLine[1].toLowerCase();
      const rest    = gemLine[2] ?? "";

      // Inline group: group: :test  OR  groups: [:development, :test]
      const inlineGroup = rest.match(/groups?:\s*(\[?[^,\]]+\]?)/);
      let groups = [...currentGroups];

      if (inlineGroup) {
        const gStr   = inlineGroup[1].replace(/[\[\]]/g, "");
        const extras = gStr.split(",").map(g => g.trim().replace(/^:/, "").toLowerCase());
        groups = [...new Set([...groups, ...extras])];
      }

      const isDev = groups.some(g => DEV_GROUPS.has(g));
      if (isDev) dev.add(gemName);
      else       prod.add(gemName);
    }

    return { prod, dev };
  }

  // ─────────────────────────────
  // Scan a single Bundler project
  // ─────────────────────────────
  static _scanProject(projectRoot) {
    const index = this._parseGemfileLock(path.join(projectRoot, "Gemfile.lock"));
    if (!index.size) return [];

    const components = [];

    for (const [key, { name, version, dependencies }] of index.entries()) {
      const id = this._gemPurl(name, version);

      const resolvedDeps = dependencies.map(dep => {
        const resolved = index.get(dep);
        return resolved
          ? this._gemPurl(resolved.name, resolved.version)
          : this._gemPurl(dep, "");
      });

      components.push({
        id,
        name:         key,
        version,
        type:         "library",
        license:      "unknown",
        ecosystem:    "ruby",
        state:        "undetermined",
        scopes:       [],
        dependencies: resolvedDeps,
        paths:        [projectRoot],
        project_root: projectRoot
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (prod / dev)
  // via BFS from Gemfile group declarations
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
      const { prod, dev } = this._parseGemfileGroups(
        path.join(projectRoot, "Gemfile")
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

      propagate(prod, "prod");
      propagate(dev,  "dev");

      // Fallback – unscoped gems default to prod
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
        if (["node_modules", ".git", ".ubel", "vendor", ".bundle"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (RubyBundlerScanner._isBundlerRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...RubyBundlerScanner._scanProject(full));
          }
          continue;
        }

        walk(full);
      }
    }

    if (RubyBundlerScanner._isBundlerRoot(startDir)) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...RubyBundlerScanner._scanProject(startDir));
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default RubyBundlerScanner;