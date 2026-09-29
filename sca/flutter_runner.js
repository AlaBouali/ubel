// FlutterPubScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Flutter / Dart projects (pub) for installed dependencies.
 *
 * Detection strategy:
 *   1.  A directory is scanned when it contains pubspec.lock, or — for projects that
 *       don't commit their lockfile (packages and libraries usually gitignore it) —
 *       .dart_tool/package_config.json, which `dart pub get` / `flutter pub get` writes.
 *   2.  pubspec.lock is preferred. Each entry under `packages:` carries its version,
 *       source (hosted | git | path | sdk) and dependency kind.
 *   3.  package_config.json is the fallback. Hosted packages are recognised from their
 *       pub-cache location (…/hosted/<host>/<name>-<version>).
 *   4.  PURL: pkg:pub/<name>@<version>
 *              pkg:pub/<name>@<version>?repository_url=<url>   (hosted on a non-pub.dev registry)
 *              pkg:pub/<name>@<version>?vcs_url=<url>          (git dependency)
 *
 * Skipped: `sdk` sources (flutter, flutter_test, …) and `path` sources — first-party or
 * toolchain code, not installed third-party packages.
 *
 * Scopes (pubspec.lock only):
 *   "direct main" / "direct overridden" → prod
 *   "direct dev"                        → dev
 *   "transitive"                        → prod  (the lockfile doesn't record whether a
 *                                          transitive dep is reached from dev or main,
 *                                          so the conservative default is used)
 *
 * The lockfile has no dependency graph, so `dependencies` stays empty.
 *
 * Limitation: OSV matches on package name. A package from a private registry or a git
 * repo that shares its name with a pub.dev package can be matched against that package's
 * advisories; the repository_url / vcs_url qualifier keeps the identity distinct in the
 * inventory but does not stop the OSV lookup.
 *
 * pubspec.lock format:
 *   packages:
 *     async:
 *       dependency: transitive
 *       description:
 *         name: async
 *         sha256: "…"
 *         url: "https://pub.dev"
 *       source: hosted
 *       version: "2.11.0"
 */

const ECOSYSTEM_LABEL = "dart";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".ubel",
  ".dart_tool", ".pub-cache", ".symlinks", "build", ".gradle", "Pods", "vendor"
]);

// Registry hosts that are the default pub.dev registry (pub.dartlang.org is its legacy name).
const DEFAULT_HOSTS = new Set(["pub.dev", "pub.dartlang.org"]);

export class FlutterPubScanner {

  constructor() {
    this.inventoryData = [];
  }

  // ─────────────────────────────
  // PURL
  // Qualifier values are percent-encoded so no raw "@" or "/" appears after
  // the "?" — engine/report code splits PURLs on "@" and "/".
  // ─────────────────────────────
  _pubPurl(name, version, qualifiers = {}) {
    const base = `pkg:pub/${name.toLowerCase()}@${version}`;
    const q = Object.entries(qualifiers)
      .filter(([, v]) => v)
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join("&");
    return q ? `${base}?${q}` : base;
  }

  _isDefaultHost(url) {
    if (!url) return true;
    const host = String(url).trim().replace(/^[a-z][a-z0-9+.-]*:\/\//i, "").split("/")[0].toLowerCase();
    return DEFAULT_HOSTS.has(host);
  }

  // ─────────────────────────────
  // pubspec.lock — minimal indentation-based reader (no YAML dependency).
  // Returns [{ name, version, source, dependency, url, ref }]
  // ─────────────────────────────
  _parsePubspecLock(file) {
    let content;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      return [];
    }

    const unquote = (s) => s.trim().replace(/^(["'])(.*)\1$/, "$2");

    const pkgs = [];
    let inPackages = false;
    let inDesc     = false;
    let cur        = null;

    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;

      const indent = rawLine.length - rawLine.trimStart().length;

      if (indent === 0) {
        inPackages = line === "packages:";
        cur    = null;
        inDesc = false;
        continue;
      }
      if (!inPackages) continue;

      // package name
      if (indent === 2) {
        const m = line.match(/^["']?([^"':]+)["']?:\s*$/);
        if (m) {
          cur = { name: m[1], version: "", source: "", dependency: "", url: "", ref: "" };
          pkgs.push(cur);
        } else {
          cur = null;
        }
        inDesc = false;
        continue;
      }
      if (!cur) continue;

      // package fields
      if (indent === 4) {
        const m = line.match(/^([\w-]+):\s*(.*)$/);
        if (!m) continue;
        const [, key, rawVal] = m;
        inDesc = key === "description";
        const val = unquote(rawVal);
        if (key === "version")         cur.version    = val;
        else if (key === "source")     cur.source     = val;
        else if (key === "dependency") cur.dependency = val;
        continue;
      }

      // description sub-map (hosted: url · git: url / resolved-ref)
      if (indent >= 6 && inDesc) {
        const m = line.match(/^([\w-]+):\s*(.*)$/);
        if (!m) continue;
        const val = unquote(m[2]);
        if (m[1] === "url")               cur.url = val;
        else if (m[1] === "resolved-ref") cur.ref = val;
      }
    }

    return pkgs;
  }

  // ─────────────────────────────
  // Map pubspec.lock `dependency:` → UBEL scope
  // ─────────────────────────────
  _lockDependencyToScope(dep) {
    return dep === "direct dev" ? "dev" : "prod";
  }

  _componentsFromLock(file, projectRoot) {
    const components = [];

    for (const p of this._parsePubspecLock(file)) {
      if (p.source === "sdk" || p.source === "path") continue;
      if (!p.name) continue;

      let qualifiers = {};
      if (p.source === "git") {
        if (!p.url) continue;
        qualifiers = { vcs_url: `git+${p.url}${p.ref ? `@${p.ref}` : ""}` };
      } else if (p.source === "hosted" && !this._isDefaultHost(p.url)) {
        qualifiers = { repository_url: p.url };
      }

      components.push(this._component({
        id:      this._pubPurl(p.name, p.version, qualifiers),
        name:    p.name.toLowerCase(),
        version: p.version,
        scopes:  [this._lockDependencyToScope(p.dependency)],
        projectRoot
      }));
    }

    return components;
  }

  // ─────────────────────────────
  // .dart_tool/package_config.json fallback
  //   { "packages": [ { "name": "async",
  //                     "rootUri": "file:///home/u/.pub-cache/hosted/pub.dev/async-2.11.0", … } ] }
  // Only hosted packages carry a version (in the cache directory name); git checkouts,
  // SDK packages and relative-path packages are skipped.
  // ─────────────────────────────
  _componentsFromPackageConfig(file, projectRoot) {
    let data;
    try {
      data = JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      return [];
    }
    if (!Array.isArray(data?.packages)) return [];

    const components = [];

    for (const pkg of data.packages) {
      const name    = pkg?.name;
      const rootUri = pkg?.rootUri;
      if (!name || typeof rootUri !== "string") continue;

      let decoded;
      try {
        decoded = decodeURIComponent(rootUri);
      } catch {
        decoded = rootUri;
      }

      const m = decoded.replace(/\/+$/, "").match(/\/hosted\/([^/]+)\/([^/]+)$/);
      if (!m) continue;

      const host    = m[1];
      const dirName = m[2];
      if (!dirName.startsWith(`${name}-`)) continue;

      const version = dirName.slice(name.length + 1);
      if (!version) continue;

      const qualifiers = this._isDefaultHost(host) ? {} : { repository_url: `https://${host}` };

      components.push(this._component({
        id:      this._pubPurl(name, version, qualifiers),
        name:    name.toLowerCase(),
        version,
        scopes:  [],        // package_config.json doesn't record dev vs main
        projectRoot
      }));
    }

    return components;
  }

  // ─────────────────────────────
  // Component builder
  // ─────────────────────────────
  _component({ id, name, version, scopes, projectRoot }) {
    return {
      id,
      name,
      version,
      type:         "library",
      license:      "unknown",
      ecosystem:    ECOSYSTEM_LABEL,
      state:        "undetermined",
      scopes:       scopes ?? [],
      dependencies: [],
      paths:        [projectRoot],
      project_root: projectRoot
    };
  }

  // ─────────────────────────────
  // Scan a single directory — pubspec.lock wins over package_config.json
  // ─────────────────────────────
  _scanProject(dir) {
    const lock = path.join(dir, "pubspec.lock");
    if (fs.existsSync(lock)) return this._componentsFromLock(lock, dir);

    const pkgConfig = path.join(dir, ".dart_tool", "package_config.json");
    if (fs.existsSync(pkgConfig)) return this._componentsFromPackageConfig(pkgConfig, dir);

    return [];
  }

  // ─────────────────────────────
  // Scopes — anything without an explicit signal is prod
  // ─────────────────────────────
  _assignScopes(inventory) {
    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      if (comp.scopes.length === 0) comp.scopes.push("prod");
    }
  }

  // ─────────────────────────────
  // Merge duplicates by PURL
  // ─────────────────────────────
  mergeInventoryByPurl(components) {
    const map = new Map();

    for (const comp of components) {
      if (!map.has(comp.id)) {
        map.set(comp.id, { ...comp, paths: [...comp.paths], scopes: [...comp.scopes] });
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

    const visit = (dir) => {
      const key = path.resolve(dir);
      if (visited.has(key)) return;
      visited.add(key);

      raw.push(...this._scanProject(dir));

      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (SKIP_DIRS.has(entry.name)) continue;
        visit(path.join(dir, entry.name));
      }
    };

    visit(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this._assignScopes(merged);

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default FlutterPubScanner;