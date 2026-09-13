import fs from "fs";
import path from "path";

export class NodeModulesScanner {
  constructor(rootDir = process.cwd()) {
    this.rootDir = rootDir;
    this.nodeModulesPath = path.join(rootDir, "node_modules");
    this.packages = new Map();
    this.visitedPaths = new Set();
  }

  scan() {
    if (!fs.existsSync(this.nodeModulesPath)) {
      return [];
    }

    this._walk(this.nodeModulesPath);

    const packages = Array.from(this.packages.values());

    // resolve deps per package using filesystem
    for (const pkg of packages) {
      pkg.dependencies = this._resolveDeps(pkg);
      delete pkg._rawPkgJson;
    }

    return packages;
  }

  _walk(dir) {
    let realDir;
    try {
      realDir = fs.realpathSync(dir);
    } catch {
      return;
    }

    if (this.visitedPaths.has(realDir)) return;
    this.visitedPaths.add(realDir);

    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);

      if (entry.name === ".pnpm") {
        this._walk(fullPath);
        continue;
      }

      if (entry.isSymbolicLink()) {
        let resolved;
        try {
          resolved = fs.realpathSync(fullPath);
        } catch {
          continue;
        }
        this._handlePackage(resolved);
        this._walk(resolved);
        continue;
      }

      if (!entry.isDirectory()) continue;

      if (entry.name.startsWith("@")) {
        this._walk(fullPath);
        continue;
      }

      this._handlePackage(fullPath);
      this._walk(fullPath);
    }
  }

  _handlePackage(pkgPath) {
    const packageJsonPath = path.join(pkgPath, "package.json");
    if (!fs.existsSync(packageJsonPath)) return;

    let pkgJson;
    try {
      pkgJson = JSON.parse(fs.readFileSync(packageJsonPath, "utf-8"));
    } catch {
      return;
    }

    const name = pkgJson.name;
    const version = pkgJson.version;

    if (!name || !version) return;

    const key = `${name}@${version}`;
    if (this.packages.has(key)) return;

    const license =
      pkgJson.license ||
      (Array.isArray(pkgJson.licenses)
        ? pkgJson.licenses.map(l => l.type).join(", ")
        : "unknown");

    this.packages.set(key, {
      purl: `pkg:npm/${this._encodeName(name)}@${version}`,
      name,
      version,
      license,
      path: pkgPath,
      dependencies: [],
      _rawPkgJson: pkgJson
    });
  }

  _resolveDeps(pkg) {
    const pkgJson = pkg._rawPkgJson;
    if (!pkgJson) return [];

    const deps = new Set();
    const baseDir = pkg.path;

    for (const field of [
      "dependencies",
      "optionalDependencies",
      "peerDependencies",
        //"devDependencies"
    ]) {
      if (!pkgJson[field]) continue;

      for (const depName of Object.keys(pkgJson[field])) {
        const resolved = this._findInstalledPackage(baseDir, depName);

        if (resolved) {
          deps.add(`pkg:npm/${this._encodeName(resolved.name)}@${resolved.version}`);
        } else {
          deps.add(`pkg:npm/${this._encodeName(depName)}@`);
        }
      }
    }

    return Array.from(deps);
  }

  _encodeName(name) {
  return name.startsWith("@") ? "%40" + name.slice(1) : name;
}

  _findInstalledPackage(startDir, depName) {
    let current = startDir;

    while (true) {
      const nm = path.join(current, "node_modules");

      let targetPath;

      if (depName.startsWith("@")) {
        const [scope, name] = depName.split("/");
        targetPath = path.join(nm, scope, name);
      } else {
        targetPath = path.join(nm, depName);
      }

      const pkgJsonPath = path.join(targetPath, "package.json");

      if (fs.existsSync(pkgJsonPath)) {
        try {
          const pkgJson = JSON.parse(fs.readFileSync(pkgJsonPath, "utf-8"));
          return {
            name: pkgJson.name,
            version: pkgJson.version
          };
        } catch {}
      }

      const parent = path.dirname(current);
      if (parent === current) break;
      current = parent;
    }

    return null;
  }
}

export default NodeModulesScanner;