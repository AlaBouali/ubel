// SwiftScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Swift / Apple-platform projects for installed dependencies.
 *
 * Two package managers are covered, both reported under ecosystem "swift":
 *
 *   SwiftPM     Package.resolved
 *                 - <dir>/Package.resolved                                   (SwiftPM package or Xcode-managed root)
 *                 - <X>.xcworkspace/xcshareddata/swiftpm/Package.resolved    (Xcode workspace)
 *                 - <X>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/  (Xcode project; reached because the
 *                                                                             walk descends into .xcodeproj)
 *                 - fallback: <dir>/.build/workspace-state.json when a Package.swift exists but no Package.resolved
 *                   was committed (common for libraries that gitignore it)
 *               formats: v1 ({object:{pins:[…]}}), v2 / v3 ({pins:[…]})
 *
 *   Carthage    Cartfile.resolved
 *               `binary` entries are skipped (no repository identity).
 *
 * PURL: pkg:swift/<host>/<owner>/<repo>@<version>     (OSV ecosystem "SwiftURL")
 *
 * CocoaPods (Podfile.lock) is intentionally not scanned: OSV has no CocoaPods ecosystem,
 * so those packages could never match an advisory.
 *
 * Not reported: local packages (SwiftPM `fileSystem` / `localSourceControl`).
 *
 * Pins that resolve to a branch or revision instead of a release tag get an empty version
 * (PURL ends in "@"), same convention as java_runner.js — inventoried, but the engine drops them from
 * OSV queries because a commit hash is not a version OSV can range-match.
 *
 * Scopes: none of these lockfiles distinguish dev from prod, so everything is "prod".
 */

const ECOSYSTEM_LABEL = "swift";

const SKIP_DIRS = new Set([
  "node_modules", ".git", ".ubel",
  ".build", ".swiftpm", "Pods", "Carthage", "DerivedData", "build",
  "vendor", ".symlinks", ".dart_tool"
]);

// Local pin kinds in Package.resolved v2+ — first-party code, not installed dependencies.
const LOCAL_PIN_KINDS = new Set(["fileSystem", "localSourceControl"]);

export class SwiftScanner {

  constructor() {
    this.inventoryData = [];
  }

  // ─────────────────────────────
  // PURL helpers
  // ─────────────────────────────
  _encodePath(p) {
    return p.split("/").map(encodeURIComponent).join("/");
  }

  _swiftPurl(hostPath, version) {
    return `pkg:swift/${this._encodePath(hostPath)}@${version}`;
  }

  // Strip a leading "v" from tags ("v1.2.3" → "1.2.3"); a bare commit SHA is not a version.
  _cleanVersion(v) {
    if (!v) return "";
    const s = String(v).trim();
    if (/^[0-9a-f]{40}$/i.test(s)) return "";
    return s.replace(/^[vV](?=\d)/, "");
  }

  // ─────────────────────────────
  // Repository URL → "host/owner/repo"
  //   https://github.com/apple/swift-nio.git          → github.com/apple/swift-nio
  //   git@github.com:apple/swift-nio.git              → github.com/apple/swift-nio
  //   ssh://git@host:22/owner/repo.git                → host/owner/repo
  // Returns null for local paths / anything without a host+path.
  // ─────────────────────────────
  _repoHostPath(url) {
    if (!url) return null;
    let u = String(url).trim();
    if (!u) return null;

    // Local paths
    if (/^(file:|\/|\.{1,2}\/|~)/.test(u) || /^[a-zA-Z]:[\\/]/.test(u)) return null;

    const scp = u.match(/^(?:[\w.-]+@)?([\w.-]+):(?!\/\/)(.+)$/);
    if (scp && !/^[a-z][a-z0-9+.-]*:\/\//i.test(u)) {
      u = `${scp[1]}/${scp[2]}`;
    } else {
      u = u.replace(/^[a-z][a-z0-9+.-]*:\/\//i, "");   // scheme
      u = u.replace(/^[^@/]+@/, "");                   // userinfo
      u = u.replace(/^([^/:]+):\d+\//, "$1/");         // port
    }

    u = u.replace(/\/+$/, "").replace(/\.git$/i, "");
    const slash = u.indexOf("/");
    if (slash <= 0 || slash === u.length - 1) return null;

    return u.slice(0, slash).toLowerCase() + u.slice(slash);
  }

  // ─────────────────────────────
  // Package.resolved (v1 / v2 / v3) and .build/workspace-state.json
  // Returns [{ hostPath, version }]
  // ─────────────────────────────
  _readJson(file) {
    try {
      return JSON.parse(fs.readFileSync(file, "utf8"));
    } catch {
      return null;
    }
  }

  _pinToEntry({ kind, url, identity, version }) {
    if (LOCAL_PIN_KINDS.has(kind)) return null;

    let hostPath;
    if (kind === "registry") {
      // identity is "<scope>.<name>"
      const [scope, ...rest] = String(identity || "").split(".");
      if (!scope || !rest.length) return null;
      hostPath = `${scope}/${rest.join(".")}`;
    } else {
      hostPath = this._repoHostPath(url);
    }
    if (!hostPath) return null;

    return { hostPath, version: this._cleanVersion(version) };
  }

  _parsePackageResolved(file) {
    const data = this._readJson(file);
    if (!data) return [];

    const out = [];

    if (data.object && Array.isArray(data.object.pins)) {
      // v1
      for (const pin of data.object.pins) {
        const e = this._pinToEntry({
          kind:    "remoteSourceControl",
          url:     pin.repositoryURL,
          version: pin.state?.version
        });
        if (e) out.push(e);
      }
    } else if (Array.isArray(data.pins)) {
      // v2 / v3
      for (const pin of data.pins) {
        const e = this._pinToEntry({
          kind:     pin.kind,
          url:      pin.location,
          identity: pin.identity,
          version:  pin.state?.version
        });
        if (e) out.push(e);
      }
    }

    return out;
  }

  _parseWorkspaceState(file) {
    const data = this._readJson(file);
    if (!data) return [];

    const deps = data.object?.dependencies ?? data.dependencies ?? [];
    if (!Array.isArray(deps)) return [];

    const out = [];
    for (const d of deps) {
      const ref = d.packageRef;
      if (!ref) continue;
      const e = this._pinToEntry({
        kind:     ref.kind,
        url:      ref.location,
        identity: ref.identity,
        version:  d.state?.checkoutState?.version
      });
      if (e) out.push(e);
    }
    return out;
  }

  // ─────────────────────────────
  // Cartfile.resolved
  //   github "Alamofire/Alamofire" "5.4.3"
  //   github "https://ghe.example.com/org/repo" "1.0.0"
  //   git "https://gitlab.com/org/repo.git" "1.0.0"
  //   binary "https://…/spec.json" "1.0.0"        (skipped)
  // ─────────────────────────────
  _parseCartfileResolved(file) {
    let content;
    try {
      content = fs.readFileSync(file, "utf8");
    } catch {
      return [];
    }

    const out = [];
    for (const rawLine of content.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#")) continue;

      const m = line.match(/^(github|git|binary)\s+"([^"]+)"\s+"([^"]+)"/);
      if (!m) continue;

      const [, kind, origin, ref] = m;
      if (kind === "binary") continue;

      let hostPath;
      if (kind === "github" && !/[:@]/.test(origin)) {
        hostPath = `github.com/${origin.replace(/\/+$/, "")}`;   // "owner/repo" shorthand
      } else {
        hostPath = this._repoHostPath(origin);
      }
      if (!hostPath) continue;

      out.push({ hostPath, version: this._cleanVersion(ref) });
    }
    return out;
  }

  // ─────────────────────────────
  // Component builder
  // ─────────────────────────────
  _component({ id, name, version, projectRoot }) {
    return {
      id,
      name,
      version,
      type:         "library",
      license:      "unknown",
      ecosystem:    ECOSYSTEM_LABEL,
      state:        "undetermined",
      scopes:       [],
      dependencies: [],
      paths:        [projectRoot],
      project_root: projectRoot
    };
  }

  _swiftComponents(entries, projectRoot) {
    return entries.map(e => this._component({
      id:          this._swiftPurl(e.hostPath, e.version),
      name:        e.hostPath,
      version:     e.version,
      projectRoot
    }));
  }

  // ─────────────────────────────
  // Xcode keeps Package.resolved inside the workspace bundle. The project
  // root is the directory that contains the .xcodeproj / .xcworkspace.
  //   Foo/Foo.xcworkspace/…                              → Foo
  //   Foo/Foo.xcodeproj/project.xcworkspace/…            → Foo
  // ─────────────────────────────
  _xcodeProjectRoot(workspaceDir) {
    const parent = path.dirname(workspaceDir);
    if (parent.endsWith(".xcodeproj")) return path.dirname(parent);
    return parent;
  }

  // ─────────────────────────────
  // Scan one directory for every lockfile we understand.
  // seenFiles keeps a lockfile from being parsed twice.
  // ─────────────────────────────
  _scanDir(dir, seenFiles) {
    const found = [];
    const base  = path.basename(dir);

    const take = (file, parser, projectRoot, build) => {
      if (!fs.existsSync(file)) return false;
      const key = path.resolve(file);
      if (seenFiles.has(key)) return true;
      seenFiles.add(key);
      found.push(...build(parser.call(this, file), projectRoot));
      return true;
    };

    const asSwift = (entries, root) => this._swiftComponents(entries, root);

    // SwiftPM — package root / Xcode-managed root
    const hasResolved = take(path.join(dir, "Package.resolved"), this._parsePackageResolved, dir, asSwift);

    // SwiftPM — Xcode workspace bundle
    if (base.endsWith(".xcworkspace")) {
      take(
        path.join(dir, "xcshareddata", "swiftpm", "Package.resolved"),
        this._parsePackageResolved,
        this._xcodeProjectRoot(dir),
        asSwift
      );
    }

    // SwiftPM — no committed Package.resolved: fall back to what `swift build` checked out
    if (!hasResolved && fs.existsSync(path.join(dir, "Package.swift"))) {
      take(path.join(dir, ".build", "workspace-state.json"), this._parseWorkspaceState, dir, asSwift);
    }

    // Carthage
    take(path.join(dir, "Cartfile.resolved"), this._parseCartfileResolved, dir, asSwift);

    return found;
  }

  // ─────────────────────────────
  // Scopes — nothing here encodes dev vs prod.
  // ─────────────────────────────
  _assignScopes(inventory) {
    for (const comp of inventory) {
      if (!Array.isArray(comp.scopes)) comp.scopes = [];
      if (comp.scopes.length === 0) comp.scopes.push("prod");
    }
  }

  // ─────────────────────────────
  // Merge duplicates by PURL (case-insensitive: repo URLs differ in casing
  // across lockfiles for the same package)
  // ─────────────────────────────
  mergeInventoryByPurl(components) {
    const map = new Map();

    for (const comp of components) {
      const key = comp.id.toLowerCase();
      if (!map.has(key)) {
        map.set(key, { ...comp, paths: [...comp.paths], scopes: [...comp.scopes] });
        continue;
      }
      const existing = map.get(key);
      for (const p of comp.paths)        { if (!existing.paths.includes(p))        existing.paths.push(p); }
      for (const s of comp.scopes)       { if (!existing.scopes.includes(s))       existing.scopes.push(s); }
    }

    return [...map.values()];
  }

  // ─────────────────────────────
  // ENTRY
  // ─────────────────────────────
  async getInstalled(startDir) {
    this.inventoryData = [];

    const seenFiles = new Set();
    const visited   = new Set();
    const raw       = [];

    const visit = (dir) => {
      const key = path.resolve(dir);
      if (visited.has(key)) return;
      visited.add(key);

      raw.push(...this._scanDir(dir, seenFiles));

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

export default SwiftScanner;