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

  constructor() {
    this.inventoryData = [];
  }

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  _cargoPurl(name, version) {
    return `pkg:cargo/${name.toLowerCase()}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect Cargo project root
  // ─────────────────────────────
  _isCargoRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "Cargo.toml")) &&
      fs.existsSync(path.join(dir, "Cargo.lock"))
    );
  }

  // ─────────────────────────────
  // Minimal TOML block parser for Cargo.lock
  // Returns array of { name, version, source, dependencies[] }
  // ─────────────────────────────
  _parseCargoLock(lockPath) {
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
  // Minimal TOML helpers for Cargo.toml scope detection.
  // Not a full TOML parser: statements are `key = value` pairs (a value may
  // span several lines while any [ { is still open) and `[section]` headers.
  // Strings are tracked so a `#`, bracket or dot inside quotes is never
  // mistaken for syntax.
  // ─────────────────────────────

  // Drop a trailing `# comment`, ignoring any `#` inside a string.
  _stripTomlComment(line) {
    let quote = null;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (quote) {
        if (ch === "\\" && quote === '"') i++;
        else if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === "#") {
        return line.slice(0, i);
      }
    }
    return line;
  }

  // Net change in [ { nesting for a line, ignoring brackets inside strings.
  _tomlDepthDelta(line) {
    let quote = null, delta = 0;
    for (let i = 0; i < line.length; i++) {
      const ch = line[i];
      if (quote) {
        if (ch === "\\" && quote === '"') i++;
        else if (ch === quote) quote = null;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === "[" || ch === "{") {
        delta++;
      } else if (ch === "]" || ch === "}") {
        delta--;
      }
    }
    return delta;
  }

  // Split a dotted table name (`target.'cfg(unix)'.dev-dependencies.foo`) on
  // the dots that are outside quotes; quotes are removed from each segment.
  _splitTomlPath(header) {
    const parts = [];
    let cur = "", quote = null;
    for (const ch of header) {
      if (quote) {
        if (ch === quote) quote = null; else cur += ch;
      } else if (ch === '"' || ch === "'") {
        quote = ch;
      } else if (ch === ".") {
        parts.push(cur.trim()); cur = "";
      } else {
        cur += ch;
      }
    }
    parts.push(cur.trim());
    return parts;
  }

  // Yield { header } for each [section] and { key, value } for each
  // key = value statement (multi-line values joined into one string).
  _tomlStatements(content) {
    const out = [];
    let buf = "", depth = 0;
    for (const raw of content.split(/\r?\n/)) {
      const line = this._stripTomlComment(raw).trim();
      if (!line && depth === 0) continue;

      if (depth === 0) {
        const sec = line.match(/^\[\[?\s*([^\[\]]+?)\s*\]\]?$/);
        if (sec) { out.push({ header: sec[1] }); continue; }
        buf = line;
      } else {
        buf += " " + line;
      }
      depth += this._tomlDepthDelta(line);
      if (depth > 0) continue;
      depth = 0;

      const kv = buf.match(/^("[^"]+"|'[^']+'|[A-Za-z0-9_.\- ]+?)\s*=\s*([\s\S]*)$/);
      if (kv) out.push({ key: kv[1].replace(/^["']|["']$/g, "").trim(), value: kv[2] });
      buf = "";
    }
    return out;
  }

  // ─────────────────────────────
  // Read [dependencies] / [dev-dependencies] / [build-dependencies] from one
  // Cargo.toml. Returns { prod: Set<string>, dev: Set<string>, build: Set<string> }
  // (lowercase crate names, `-` normalised to `_`).
  //
  // Handles: inline and dotted forms (`foo = "1"`, `foo.version = "1"`),
  // table form (`[dev-dependencies.foo]`), target-scoped sections
  // (`[target.'cfg(unix)'.dependencies]`), values spanning several lines, and
  // renames (`alias = { package = "real-name" }` is recorded as `real_name`).
  // `[workspace.dependencies]` is only a declaration list — what a member
  // actually uses is declared in its own manifest — so it is skipped.
  // ─────────────────────────────
  _readCargoTomlDeps(tomlPath) {
    const sets = { prod: new Set(), dev: new Set(), build: new Set() };

    let content;
    try {
      content = fs.readFileSync(tomlPath, "utf8");
    } catch {
      return sets;
    }

    const norm = (n) => n.toLowerCase().replace(/-/g, "_");
    const KINDS = {
      "dependencies": "prod",       "dev-dependencies": "dev",       "build-dependencies": "build",
      "dev_dependencies": "dev",    "build_dependencies": "build",
    };
    const packageRename = (value) => {
      const m = value.match(/\bpackage\s*=\s*(?:"([^"]+)"|'([^']+)')/);
      return m ? (m[1] ?? m[2]) : null;
    };

    let mode  = null;   // null | { kind, table: null | { name } }
    const flush = () => {
      if (mode?.table) sets[mode.kind].add(norm(mode.table.name));
      mode = null;
    };

    for (const st of this._tomlStatements(content)) {
      if (st.header !== undefined) {
        flush();
        const segs = this._splitTomlPath(st.header);
        if (segs[0] === "workspace") continue;
        const idx = segs.findIndex(s => KINDS[s]);
        if (idx === -1) continue;
        const kind = KINDS[segs[idx]];
        if (idx === segs.length - 1)      mode = { kind, table: null };                          // [dependencies]
        else if (idx === segs.length - 2) mode = { kind, table: { name: segs[idx + 1] } };       // [dependencies.foo]
        continue;
      }

      if (!mode) continue;

      if (mode.table) {
        // Body of [dependencies.foo]: only `package = "..."` matters.
        if (st.key === "package") {
          const m = st.value.match(/^(?:"([^"]+)"|'([^']+)')/);
          if (m) mode.table.name = m[1] ?? m[2];
        }
        continue;
      }

      // key = value / dotted key inside a dependencies section.
      const crate = st.key.split(".")[0].trim();
      if (!/^[A-Za-z0-9_-]+$/.test(crate)) continue;
      const real = st.key.includes(".") ? null : packageRename(st.value);
      sets[mode.kind].add(norm(real ?? crate));
    }
    flush();

    return sets;
  }

  // ─────────────────────────────
  // Workspace member manifests (absolute paths) declared by the root
  // Cargo.toml's `[workspace] members = [...]` minus `exclude`. Supports
  // literal paths and `*` / `?` wildcards within a path segment. Returns []
  // when the root isn't a workspace.
  // ─────────────────────────────
  _workspaceMemberManifests(projectRoot) {
    let content;
    try {
      content = fs.readFileSync(path.join(projectRoot, "Cargo.toml"), "utf8");
    } catch {
      return [];
    }

    let inWorkspace = false;
    const lists = { members: [], exclude: [] };
    for (const st of this._tomlStatements(content)) {
      if (st.header !== undefined) { inWorkspace = st.header.trim() === "workspace"; continue; }
      if (inWorkspace && (st.key === "members" || st.key === "exclude")) {
        for (const m of st.value.matchAll(/"([^"]+)"|'([^']+)'/g)) lists[st.key].push(m[1] ?? m[2]);
      }
    }
    if (!lists.members.length) return [];

    const expand = (pattern) => {
      let dirs = [path.resolve(projectRoot)];
      for (const seg of pattern.split("/").filter(s => s && s !== ".")) {
        const next = [];
        for (const d of dirs) {
          if (/[*?]/.test(seg)) {
            const re = new RegExp(
              "^" + seg.replace(/[.+^${}()|[\]\\]/g, "\\$&").replace(/\*/g, ".*").replace(/\?/g, ".") + "$"
            );
            let ents;
            try { ents = fs.readdirSync(d, { withFileTypes: true }); } catch { continue; }
            for (const e of ents) if (e.isDirectory() && re.test(e.name)) next.push(path.join(d, e.name));
          } else {
            next.push(path.join(d, seg));
          }
        }
        dirs = next;
      }
      return dirs;
    };

    const excluded = new Set(lists.exclude.flatMap(expand).map(d => path.resolve(d)));
    const manifests = [];
    for (const dir of lists.members.flatMap(expand)) {
      const abs = path.resolve(dir);
      if (excluded.has(abs)) continue;
      const manifest = path.join(abs, "Cargo.toml");
      if (fs.existsSync(manifest) && !manifests.includes(manifest)) manifests.push(manifest);
    }
    return manifests;
  }

  // Root manifest plus every workspace member manifest, merged.
  _readProjectDeps(projectRoot) {
    const merged = this._readCargoTomlDeps(path.join(projectRoot, "Cargo.toml"));
    for (const manifest of this._workspaceMemberManifests(projectRoot)) {
      const m = this._readCargoTomlDeps(manifest);
      for (const k of ["prod", "dev", "build"]) for (const n of m[k]) merged[k].add(n);
    }
    return merged;
  }

  // ─────────────────────────────
  // Scan a single Cargo project
  // ─────────────────────────────
  _scanProject(projectRoot) {
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
        paths:        [ projectRoot],
        project_root: projectRoot,
        _source:      pkg.source
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (prod / dev / build)
  // ─────────────────────────────
  _assignScopes(inventory) {
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
      const { prod, dev, build } = this._readProjectDeps(projectRoot);

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
  mergeInventoryByPurl(components) {
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
  async getInstalled(startDir) {
    this.inventoryData = [];

    const visited = new Set();
    const raw     = [];

    const walk = (dir) => {
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

        if (this._isCargoRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...this._scanProject(full));
          }
          // Still descend – workspaces have nested member crates
          // BUT skip target/ which is handled above
        }

        walk(full);
      }
    }

    if (this._isCargoRoot(startDir)) {
      const key = path.resolve(startDir);
      if (!visited.has(key)) {
        visited.add(key);
        raw.push(...this._scanProject(startDir));
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