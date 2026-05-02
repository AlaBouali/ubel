// python_venv_scanner.js
import fs   from "fs";
import path from "path";

export class PythonVenvScanner {

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _pypiPurl(name, version) {
    const normalised = name.toLowerCase().replace(/_/g, "-");
    return `pkg:pypi/${encodeURIComponent(normalised)}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect venv (robust)
  // ─────────────────────────────
  static _isVenvRoot(dir) {
    return (
      fs.existsSync(path.join(dir, "pyvenv.cfg")) ||
      fs.existsSync(path.join(dir, "bin", "activate")) ||
      fs.existsSync(path.join(dir, "Scripts", "activate")) //||
      //fs.existsSync(path.join(dir, "lib")) ||
      //fs.existsSync(path.join(dir, "Lib"))
    );
  }

  // ─────────────────────────────
  // site-packages
  // ─────────────────────────────
  static _sitePackagesDirs(venvRoot) {
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

    return results;
  }

  // ─────────────────────────────
  // Read metadata
  // ─────────────────────────────
  static _readDistInfo(metaDir) {
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

      if (lower.startsWith("requires-dist:")) {
        const dep = line
          .slice("requires-dist:".length)
          .trim()
          .split(/[\s(;[!<>=]/)[0]
          .toLowerCase()
          .replace(/_/g, "-");

        if (dep) requires.push(dep);
      }
    }

    return { license: license.trim(), requires };
  }

  // ─────────────────────────────
  // Scan venv
  // ─────────────────────────────
  static _scanVenv(venvRoot) {
    const sitePackagesDirs = this._sitePackagesDirs(venvRoot);
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
        if (!entry.name.endsWith(".dist-info")) continue;

        const base = entry.name.replace(/\.dist-info$/, "");
        const idx = base.lastIndexOf("-");
        if (idx === -1) continue;

        const name = base.slice(0, idx);
        const version = base.slice(idx + 1);
        const norm = name.toLowerCase().replace(/_/g, "-");

        nameIndex.set(norm, {
          name,
          version,
          metaDir: path.join(sp, entry.name)
        });
      }
    }

    // Pass 2
    const components = [];

    for (const { name, version, metaDir } of nameIndex.values()) {
      const norm = name.toLowerCase().replace(/_/g, "-");
      const id = this._pypiPurl(name, version);

      const { license, requires } = this._readDistInfo(metaDir);

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
        venv_root: venvRoot
      });
    }

    return components;
  }

  // ─────────────────────────────
  // Assign scopes (FIXED)
  // ─────────────────────────────
  static _assignScopes(inventory) {
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

          if (!c.scopes.includes(scope)) c.scopes.push(scope);

          for (const dep of c.dependencies) {
            const d = byId.get(dep);
            if (d && d.venv_root === venvRoot) queue.push(d);
          }
        }
      };

      propagate(prod, "prod");
      propagate(dev, "dev");

      // 🔥 FALLBACK (critical)
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
  static mergeInventoryByPurl(components) {
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
  static async getInstalled(startDir = process.cwd()) {

    this.inventoryData = [];

    const visited = new Set();
    const raw = [];

    function walk(dir) {
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

        if (PythonVenvScanner._isVenvRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            visited.add(key);
            raw.push(...PythonVenvScanner._scanVenv(full));
          }
          continue;
        }

        walk(full);
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);

    this._assignScopes(merged);

    this.inventoryData = merged;

    return merged.map(c => c.id);
  }
}

export default PythonVenvScanner;