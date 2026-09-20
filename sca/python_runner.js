// python_venv_scanner.js
import fs   from "fs";
import path from "path";

export class PythonVenvScanner {

  constructor() {
    this.inventoryData = [];
  }

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  _pypiPurl(name, version) {
    const normalised = name.toLowerCase().replace(/_/g, "-");
    return `pkg:pypi/${encodeURIComponent(normalised)}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect venv (robust)
  // ─────────────────────────────
  _isVenvRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "pyvenv.cfg")) ||
      fs.existsSync(path.join(dir, "bin", "activate")) ||
      fs.existsSync(path.join(dir, "Scripts", "activate")) //||
      //fs.existsSync(path.join(dir, "Lib", "distutils")) ||
      //fs.existsSync(path.join(dir, "lib")) ||
      //fs.existsSync(path.join(dir, "Lib"))
    );
  }

  // ─────────────────────────────
  // site-packages
  // ─────────────────────────────
  _sitePackagesDirs(venvRoot) {
    const results = [];

    const libDir = path.join(venvRoot, "lib");
    if (fs.existsSync(libDir)) {
      for (const entry of fs.readdirSync(libDir)) {
        const sp = path.join(libDir, entry, "site-packages");
        if (fs.existsSync(sp)) results.push(sp);
      }
    }

    const winSp = path.join(venvRoot, "Lib", "site-packages");
    if (fs.existsSync(winSp)) results.push(winSp);

    const distPackagesDir = path.join(venvRoot, "lib", "dist-packages");
    if (fs.existsSync(distPackagesDir)) results.push(distPackagesDir);

    const rootdistpkgs = path.join(venvRoot, "dist-packages");
    if (fs.existsSync(rootdistpkgs)) {
      results.push(rootdistpkgs);
    }
    const rootsitepkg = path.join(venvRoot, "site-packages");
    if (fs.existsSync(rootsitepkg)) {
      results.push(rootsitepkg);
    }

    return results;
  }

  // ─────────────────────────────
  // Package metadata dir naming: wheel-style ".dist-info" vs
  // legacy setuptools ".egg-info" (used by most system/apt-installed
  // packages, e.g. /usr/lib/python3/dist-packages/Pillow-8.1.2.egg-info)
  // ─────────────────────────────
  _parsePackageMetaDirName(entryName) {
    if (entryName.endsWith(".dist-info")) {
      const base = entryName.slice(0, -".dist-info".length);
      const idx = base.lastIndexOf("-");
      if (idx === -1) return null;
      return { name: base.slice(0, idx), version: base.slice(idx + 1), format: "dist-info" };
    }

    if (entryName.endsWith(".egg-info")) {
      // some egg-info dirs carry a trailing interpreter/platform tag,
      // e.g. "Pillow-8.1.2-py3.9-linux-x86_64.egg-info"
      let base = entryName
        .slice(0, -".egg-info".length)
        .replace(/-py\d+\.\d+(-[\w.]+)?$/, "");

      const idx = base.lastIndexOf("-");
      if (idx === -1) return { name: base, version: "", format: "egg-info" };
      return { name: base.slice(0, idx), version: base.slice(idx + 1), format: "egg-info" };
    }

    return null;
  }

  // ─────────────────────────────
  // Read metadata
  // dist-info: METADATA (fallback PKG-INFO), deps from "Requires-Dist:"
  // egg-info:  PKG-INFO, deps from sibling "requires.txt"
  // ─────────────────────────────
  _readDistInfo(metaDir, format = "dist-info") {
    let raw = "";
    try {
      const metaPath = fs.existsSync(path.join(metaDir, "METADATA"))
        ? path.join(metaDir, "METADATA")
        : path.join(metaDir, "PKG-INFO");
      raw = fs.readFileSync(metaPath, "utf8");
    } catch {
      return { license: "unknown", requires: [] };
    }

    let license = "unknown";
    const requires = [];

    for (const line of raw.split("\n")) {
      const lower = line.toLowerCase();

      if (lower.startsWith("license:")) {
        license = line.slice("license:".length).trim() || "unknown";
      }
      if (lower.startsWith("classifier: license ")){
        license = line.split("::").slice(2).join("::").trim().replace("License", "") || "unknown";
      }
      if (line.startsWith("License-Expression:")) {
        license = line.slice("License-Expression:".length).trim() || "unknown";
      }

      // wheel/dist-info metadata declares deps inline
      if (format !== "egg-info" && lower.startsWith("requires-dist:")) {
        const dep = line
          .slice("requires-dist:".length)
          .trim()
          .split(/[\s(;[!<>=]/)[0]
          .toLowerCase()
          .replace(/_/g, "-");

        if (dep) requires.push(dep);
      }
    }

    // egg-info doesn't put Requires-Dist in PKG-INFO — deps live in a
    // sibling requires.txt (plain reqs, then optional "[extra]" sections)
    if (format === "egg-info") {
      const requiresTxt = path.join(metaDir, "requires.txt");
      if (fs.existsSync(requiresTxt)) {
        for (const line of fs.readFileSync(requiresTxt, "utf8").split("\n")) {
          const trimmed = line.trim();
          if (!trimmed || trimmed.startsWith("#")) continue;
          if (trimmed.startsWith("[")) break; // stop before extras sections
          const dep = trimmed.split(/[\s(;[!<>=]/)[0].toLowerCase().replace(/_/g, "-");
          if (dep) requires.push(dep);
        }
      }
    }

    return { license: license.trim(), requires };
  }

  // ─────────────────────────────
  // Scan a set of site-packages/dist-packages dirs into components.
  // rootLabel groups them for scope assignment: a venv root for venv
  // scans, or the directory itself for a bare system install.
  // ─────────────────────────────
  _scanPackageDirs(sitePackagesDirs, rootLabel) {
    if (!sitePackagesDirs.length) return [];

    const nameIndex = new Map();

    // Pass 1
    for (const sp of sitePackagesDirs) {
      let entries;
      try {
        entries = fs.readdirSync(sp, { withFileTypes: true });
      } catch {
        continue;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;

        const parsed = this._parsePackageMetaDirName(entry.name);
        if (!parsed) continue;

        const norm = parsed.name.toLowerCase().replace(/_/g, "-");

        nameIndex.set(norm, {
          name: parsed.name,
          version: parsed.version,
          format: parsed.format,
          metaDir: path.join(sp, entry.name)
        });
      }
    }

    // Pass 2
    const components = [];

    for (const { name, version, metaDir, format } of nameIndex.values()) {
      const norm = name.toLowerCase().replace(/_/g, "-");
      const id = this._pypiPurl(name, version);

      const { license, requires } = this._readDistInfo(metaDir, format);

      const dependencies = requires.map(dep => {
        const resolved = nameIndex.get(dep);
        return resolved
          ? this._pypiPurl(resolved.name, resolved.version)
          : this._pypiPurl(dep, "");
      });

      components.push({
        id,
        name: norm,
        version,
        type: "library",
        license,
        ecosystem: "python",
        state: "undetermined",
        scopes: [],
        dependencies,
        paths: [metaDir],
        venv_root: rootLabel
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Scan venv
  // ─────────────────────────────
  _scanVenv(venvRoot) {
    return this._scanPackageDirs(this._sitePackagesDirs(venvRoot), venvRoot);
  }

  // ─────────────────────────────
  // Scan a bare system-wide site-packages/dist-packages dir that
  // isn't inside a venv at all (e.g. /usr/lib/python3/dist-packages)
  // ─────────────────────────────
  _scanSitePackagesDir(dir) {
    return this._scanPackageDirs([dir], dir);
  }

  // ─────────────────────────────
  // Assign scopes (FIXED)
  // ─────────────────────────────
  _assignScopes(inventory) {
    const byId = new Map(inventory.map(c => [c.id, c]));
    const nameIndex = new Map();

    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      if (!nameIndex.has(comp.name)) nameIndex.set(comp.name, []);
      nameIndex.get(comp.name).push(comp);
    }

    function parseReqs(filePath) {
      if (!fs.existsSync(filePath)) return [];
      return fs.readFileSync(filePath, "utf8")
        .split("\n")
        .map(l => l.trim())
        .filter(l => l && !l.startsWith("#") && !l.startsWith("-"))
        .map(l => l.split(/[>=<!;\s[]/)[0].toLowerCase().replace(/_/g, "-"));
    }

    const venvGroups = new Map();

    for (const comp of inventory) {
      const root = comp.venv_root;
      if (!venvGroups.has(root)) venvGroups.set(root, []);
      venvGroups.get(root).push(comp);
    }

    for (const [venvRoot, comps] of venvGroups.entries()) {

      const projectDir = path.dirname(venvRoot);

      const prod = new Set([
        ...parseReqs(path.join(projectDir, "requirements.txt")),
        ...parseReqs(path.join(projectDir, "requirements/base.txt")),
        ...parseReqs(path.join(projectDir, "requirements/prod.txt")),
      ]);

      const dev = new Set([
        ...parseReqs(path.join(projectDir, "requirements-dev.txt")),
        ...parseReqs(path.join(projectDir, "requirements_dev.txt")),
        ...parseReqs(path.join(projectDir, "requirements/dev.txt")),
      ]);

      const propagate = (names, scope) => {
        const queue = [];
        const reached = new Set();

        for (const n of names) {
          for (const c of (nameIndex.get(n) || [])) {
            if (c.venv_root === venvRoot) queue.push(c);
          }
        }

        const visited = new Set();

        while (queue.length) {
          const c = queue.shift();
          if (visited.has(c.id)) continue;
          visited.add(c.id);
          reached.add(c.id);

          if (!c.scopes.includes(scope)) c.scopes.push(scope);

          for (const dep of c.dependencies) {
            const d = byId.get(dep);
            if (d && d.venv_root === venvRoot) queue.push(d);
          }
        }

        return reached;
      };

      // Prod is seeded and propagated first so we know, below, which
      // packages it legitimately reaches before dev gets a chance to
      // touch them.
      const prodReached = propagate(prod, "prod");
      const devReached = propagate(dev, "dev");

      // A package reachable from BOTH the prod graph and the dev graph
      // (e.g. starlette: not pinned directly in requirements.txt, but
      // pulled in transitively via fastapi, while also appearing in
      // requirements-dev.txt for pinning/testing) is a real prod
      // dependency first and foremost. Drop the spurious "dev" tag in
      // that case so it isn't reported as dev-only.
      for (const id of devReached) {
        if (prodReached.has(id)) {
          const c = byId.get(id);
          const i = c.scopes.indexOf("dev");
          if (i !== -1) c.scopes.splice(i, 1);
        }
      }

      // 🔥 FALLBACK (critical)
      // Only apply per-venv when NEITHER requirement-file family was
      // found at all. If only one family exists (e.g. a project that
      // only has requirements-dev.txt with no prod requirements.txt),
      // we should NOT blanket-tag everything "prod" — packages that
      // never appear in any requirement file and were never reached by
      // propagation are genuinely undetermined, not implicitly prod.
      // For a bare system dist-packages/site-packages scan (rootLabel
      // is the dir itself, not a project with a venv), this is also
      // exactly the branch that fires, since there's no requirements
      // file family to find — everything gets tagged "prod" by default.
      if (prod.size === 0 && dev.size === 0) {
        for (const c of comps) {
          if (c.scopes.length === 0) c.scopes.push("prod");
        }
      }
    }
  }

  // ─────────────────────────────
  // Merge
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
    const raw = [];

    // ✅ arrow function – preserves `this`
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (["node_modules", ".git", ".ubel"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (this._isVenvRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...this._scanVenv(full));
          }
          continue;
        }

        // System-wide installs (e.g. /usr/lib/python3/dist-packages,
        // /usr/lib/python3/site-packages) aren't inside a venv at all —
        // scan a bare site-packages/dist-packages dir the moment we
        // walk into one, rather than only looking for these inside a
        // detected venv root.
        if (entry.name === "site-packages" || entry.name === "dist-packages") {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...this._scanSitePackagesDir(full));
          }
          continue;
        }

        walk(full);
      }
    };

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);
    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default PythonVenvScanner;