// GoModScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Go modules projects for installed dependencies.
 *
 * Detection strategy:
 *   1.  A directory is a Go module root when it contains go.mod AND go.sum.
 *   2.  Installed packages are read from go.sum (the resolved/verified set)
 *       cross-referenced with go.mod for direct vs indirect classification.
 *   3.  PURL: pkg:golang/<module-path>@<version>
 *
 * go.mod format:
 *   module github.com/org/repo
 *   require (
 *     github.com/foo/bar v1.2.3
 *     github.com/baz/qux v0.4.0 // indirect
 *   )
 *
 * go.sum format:
 *   github.com/foo/bar v1.2.3 h1:<hash>=
 *   github.com/foo/bar v1.2.3/go.mod h1:<hash>=
 */
export class GoModScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _goPurl(modulePath, version) {
    // Strip leading "v" from semver tags for consistency; keep pseudo-versions as-is.
    const v = version ? version.replace(/^v/, "") : "";
    return `pkg:golang/${modulePath.toLowerCase()}@${v}`;
  }

  // ─────────────────────────────
  // Detect Go module root
  // ─────────────────────────────
  static _isGoRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "go.mod")) &&
      fs.existsSync(path.join(dir, "go.sum"))
    );
  }

  // ─────────────────────────────
  // Parse go.mod
  // Returns {
  //   moduleName: string,
  //   requires: Map<lowercasePath, { path, version, indirect }>,
  //   replaces: Map<lowercasePath, { original, replacement, version }>
  // }
  // ─────────────────────────────
  static _parseGoMod(modPath) {
    const requires = new Map();
    const replaces = new Map();
    let moduleName = "";

    let content;
    try {
      content = fs.readFileSync(modPath, "utf8");
    } catch {
      return { moduleName, requires, replaces };
    }

    const lines = content.split("\n");
    let inRequire = false;
    let inReplace = false;

    for (const rawLine of lines) {
      const line = rawLine.trim();

      if (!line || line.startsWith("//")) continue;

      // module declaration
      if (line.startsWith("module ")) {
        moduleName = line.slice(7).trim().split(/\s/)[0];
        continue;
      }

      // Block openers
      if (line === "require (") { inRequire = true;  continue; }
      if (line === "replace (") { inReplace = true;  continue; }
      if (line === ")")          { inRequire = false; inReplace = false; continue; }

      // Inline single-line directives
      const singleRequire = line.match(/^require\s+(\S+)\s+(\S+)(\s*\/\/ indirect)?/);
      if (singleRequire) {
        const mp       = singleRequire[1];
        const ver      = singleRequire[2];
        const indirect = !!singleRequire[3];
        requires.set(mp.toLowerCase(), { path: mp, version: ver, indirect });
        continue;
      }

      if (inRequire) {
        // "github.com/foo/bar v1.2.3 // indirect"
        const m = line.match(/^(\S+)\s+(\S+)(\s*\/\/ indirect)?/);
        if (m) {
          const mp       = m[1];
          const ver      = m[2];
          const indirect = !!m[3];
          requires.set(mp.toLowerCase(), { path: mp, version: ver, indirect });
        }
        continue;
      }

      if (inReplace) {
        // "github.com/old/pkg => github.com/new/pkg v1.0.0"
        const m = line.match(/^(\S+)(?:\s+\S+)?\s+=>\s+(\S+)\s+(\S+)/);
        if (m) {
          replaces.set(m[1].toLowerCase(), {
            original:    m[1],
            replacement: m[2],
            version:     m[3]
          });
        }
        continue;
      }
    }

    return { moduleName, requires, replaces };
  }

  // ─────────────────────────────
  // Parse go.sum → Set of "<module>@<version>"
  // Only /go.mod lines give version presence; h1: lines confirm download.
  // We want the source-code hash lines (not /go.mod lines) to get the
  // actually-used modules.
  // ─────────────────────────────
  static _parseGoSum(sumPath) {
    const installed = new Map();   // lowercase path → { path, version }

    let content;
    try {
      content = fs.readFileSync(sumPath, "utf8");
    } catch {
      return installed;
    }

    for (const rawLine of content.split("\n")) {
      const line = rawLine.trim();
      if (!line) continue;

      const parts = line.split(" ");
      if (parts.length < 2) continue;

      const [modVer] = parts;
      // Skip go.mod-only entries
      if (modVer.endsWith("/go.mod")) continue;

      const atIdx  = modVer.lastIndexOf("@");
      if (atIdx < 0) continue;

      const modPath = modVer.slice(0, atIdx);
      const version = modVer.slice(atIdx + 1);
      const key     = modPath.toLowerCase();

      if (!installed.has(key)) {
        installed.set(key, { path: modPath, version });
      }
    }

    return installed;
  }

  // ─────────────────────────────
  // Scan a single Go module root
  // ─────────────────────────────
  static _scanProject(projectRoot) {
    const { moduleName, requires, replaces } = this._parseGoMod(
      path.join(projectRoot, "go.mod")
    );

    const sumEntries = this._parseGoSum(path.join(projectRoot, "go.sum"));

    if (!sumEntries.size && !requires.size) return [];

    // Build full index: prefer go.sum versions (actual downloaded); fall back
    // to go.mod requires (for local replace directives that don't appear in go.sum)
    const index = new Map();   // lowercase path → { path, version, indirect }

    for (const [key, { path: mp, version }] of sumEntries.entries()) {
      const req = requires.get(key);
      index.set(key, {
        path:     mp,
        version,
        indirect: req ? req.indirect : true
      });
    }

    // Include require-only entries (local modules / replace targets not in go.sum)
    for (const [key, { path: mp, version, indirect }] of requires.entries()) {
      if (!index.has(key)) {
        index.set(key, { path: mp, version, indirect });
      }
    }

    // Apply replace directives – update resolved path/version
    for (const [origKey, { replacement, version }] of replaces.entries()) {
      const entry = index.get(origKey);
      if (entry) {
        entry.path    = replacement;
        entry.version = version;
      }
    }

    const components = [];

    for (const [, { path: mp, version, indirect }] of index.entries()) {
      const id = this._goPurl(mp, version);

      components.push({
        id,
        name:         mp.toLowerCase(),
        version:      version.replace(/^v/, ""),
        type:         "library",
        license:      "unknown",
        ecosystem:    "golang",
        state:        "undetermined",
        scopes:       [],
        dependencies: [],   // go.sum doesn't encode the dep graph; populated below
        paths:        [projectRoot],
        project_root: projectRoot,
        _indirect:    indirect
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes
  // Go doesn't have a native dev-dep concept in go.mod; the only reliable
  // signal is whether a module is "indirect" (transitive) or direct.
  // UBEL maps: direct → prod, indirect → prod (transitive)
  // Test-only packages (ending in /testing, /testutil, etc.) → dev heuristic.
  // ─────────────────────────────
  static _assignScopes(inventory) {
    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      if (comp.scopes.length > 0) continue;

      const isTestHeuristic =
        comp.name.includes("/testing") ||
        comp.name.includes("/testutil") ||
        comp.name.includes("/mock")     ||
        comp.name.endsWith("test")      ||
        comp.name.includes("gomock")    ||
        comp.name.includes("testify");

      comp.scopes.push(isTestHeuristic ? "dev" : "prod");
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
        if (["node_modules", ".git", ".ubel", "vendor"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (GoModScanner._isGoRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...GoModScanner._scanProject(full));
          }
          // Descend – Go workspaces (go.work) can nest multiple modules
        }

        walk(full);
      }
    }

    if (GoModScanner._isGoRoot(startDir)) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...GoModScanner._scanProject(startDir));
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    for (const c of merged) delete c._indirect;

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default GoModScanner;