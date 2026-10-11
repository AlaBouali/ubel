// JavaMavenScanner.js
import fs   from "fs";
import path from "path";

/**
 * Scans Java / Maven projects for installed dependencies.
 *
 * Detection strategy:
 *   1.  A directory is a Maven project root when it contains pom.xml.
 *   2.  Installed packages are read from the Maven local repository cache
 *       (~/.m2/repository) cross-referenced with pom.xml dependency declarations.
 *       If the effective dependency tree file (.ubel/maven-deps.txt) exists it
 *       is preferred (generated via: mvn dependency:tree -DoutputFile=.ubel/maven-deps.txt)
 *   3.  Multi-module projects: parent pom.xml <modules> entries are followed.
 *   4.  PURL: pkg:maven/<groupId>/<artifactId>@<version>
 *            (no @  when version is unknown)
 *
 * pom.xml dependency format:
 *   <dependency>
 *     <groupId>org.springframework</groupId>
 *     <artifactId>spring-core</artifactId>
 *     <version>5.3.21</version>
 *     <scope>test</scope>   <!-- compile|provided|runtime|test|system -->
 *   </dependency>
 */
export class JavaMavenScanner {

  constructor() {
    this.inventoryData = [];
    this._ctxCache = new Map();   // pom path → effective-POM context (see _pomContext)
  }

  // ─────────────────────────────
  // PURL
  // Omits @<version> when the version is unknown. A trailing "@" is not a valid purl, and the
  // engine never sends versionless purls to OSV (it would answer with every advisory ever filed
  // for the artifact), so such components stay in the inventory but are not vulnerability-matched.
  // ─────────────────────────────
  _mavenPurl(groupId, artifactId, version) {
    const base = `pkg:maven/${groupId.toLowerCase()}/${artifactId.toLowerCase()}`;
    return version ? `${base}@${version}` : base;
  }

  // ─────────────────────────────
  // Detect Maven project root
  // ─────────────────────────────
  _isMavenRoot(dir) {
    return fs.existsSync(path.join(dir, "pom.xml"));
  }

  // ─────────────────────────────
  // Minimal XML tag extractor
  // Returns all text values for a given tag name within a block of XML text.
  // ─────────────────────────────
  _extractTag(xml, tag) {
    const results = [];
    const re = new RegExp(`<${tag}[^>]*>([^<]*)<\\/${tag}>`, "gi");
    let m;
    while ((m = re.exec(xml)) !== null) results.push(m[1].trim());
    return results;
  }

  // ─────────────────────────────
  // Extract all <dependency> blocks from pom.xml text.
  // Returns array of { groupId, artifactId, version, scope, optional }
  // ─────────────────────────────
  _parsePomDeps(xml) {
    const deps = [];
    // Capture each <dependency>...</dependency> block
    const blockRe = /<dependency>([\s\S]*?)<\/dependency>/gi;
    let m;
    while ((m = blockRe.exec(xml)) !== null) {
      const block      = m[1];
      const groupId    = this._extractTag(block, "groupId")[0]    ?? "";
      const artifactId = this._extractTag(block, "artifactId")[0] ?? "";
      const version    = this._extractTag(block, "version")[0]    ?? "";
      const scope      = this._extractTag(block, "scope")[0]      ?? "compile";
      // optional deps: skip by default — they are not installed transitively
      const optional   = (this._extractTag(block, "optional")[0] ?? "false") === "true";

      if (groupId && artifactId && !optional) {
        deps.push({ groupId, artifactId, version, scope: scope.toLowerCase() });
      }
    }
    return deps;
  }

  // ─────────────────────────────
  // Extract <properties> block for variable interpolation
  // Returns Map<varName, value>
  // ─────────────────────────────
  _parsePomProperties(xml) {
    const props = new Map();
    const propsMatch = xml.match(/<properties>([\s\S]*?)<\/properties>/i);
    if (!propsMatch) return props;

    const block  = propsMatch[1];
    const propRe = /<([A-Za-z0-9._-]+)>([^<]*)<\/[A-Za-z0-9._-]+>/g;
    let m;
    while ((m = propRe.exec(block)) !== null) props.set(m[1], m[2].trim());
    return props;
  }

  // ─────────────────────────────
  // Resolve ${...} property references (single-pass).
  // Returns empty string if version is blank.
  // Flags with "UNRESOLVED:" prefix if a ${ref} survives after substitution so
  // callers can detect broken versions instead of emitting garbage PURLs.
  // ─────────────────────────────
  _interpolate(value, props) {
    let out = String(value ?? "");
    // Several passes: a property may itself reference another (${a} → ${b}.1 → 2.1).
    for (let i = 0; i < 10 && out.includes("${"); i++) {
      const next = out.replace(/\$\{([^}]+)\}/g, (m, key) => (props.has(key) ? props.get(key) : m));
      if (next === out) break;
      out = next;
    }
    return out;
  }

  // Unknown placeholders are left in place (not replaced by "", which used to turn "${x}.1"
  // into ".1"), so a version that cannot be fully resolved is reported as unknown ("").
  _resolveVersion(version, props) {
    if (!version) return "";
    const resolved = this._interpolate(version, props).trim();
    return resolved.includes("${") ? "" : resolved;
  }

  // ─────────────────────────────
  // Effective-POM context: properties, <dependencyManagement> versions and the project's own
  // coordinates, inherited through the <parent> chain when the parent pom is on disk (default
  // ../pom.xml or <relativePath>). Parents that only exist in a remote repository cannot be
  // read, so versions they manage stay unresolved.
  // ─────────────────────────────
  _readPom(pomFile) {
    try {
      return fs.readFileSync(pomFile, "utf8").replace(/<!--[\s\S]*?-->/g, "");
    } catch {
      return null;
    }
  }

  _parentBlock(xml) {
    const m = xml.match(/<parent>([\s\S]*?)<\/parent>/i);
    if (!m) return null;
    const block = m[1];
    const one = (tag) => this._extractTag(block, tag)[0] ?? "";
    let relativePath = "../pom.xml";                        // Maven's default
    if (/<relativePath\s*\/>/i.test(block)) relativePath = ""; // explicitly "look in the repository"
    else if (this._extractTag(block, "relativePath").length) relativePath = this._extractTag(block, "relativePath")[0];
    return { groupId: one("groupId"), artifactId: one("artifactId"), version: one("version"), relativePath };
  }

  // The project's own groupId / artifactId / version (falling back to the parent's, as Maven does).
  _pomCoords(xml, parent) {
    let own = xml;
    for (const tag of ["parent", "dependencyManagement", "dependencies", "build", "profiles",
                       "reporting", "properties", "repositories", "pluginRepositories", "distributionManagement"]) {
      own = own.replace(new RegExp(`<${tag}[\\s>][\\s\\S]*?<\\/${tag}>`, "gi"), "");
    }
    const one = (tag) => this._extractTag(own, tag)[0] ?? "";
    return {
      groupId:    one("groupId")    || parent?.groupId || "",
      artifactId: one("artifactId"),
      version:    one("version")    || parent?.version || "",
    };
  }

  // <dependencyManagement><dependencies><dependency> entries → [{ groupId, artifactId, version }]
  _parseManagedDeps(xml) {
    const out = [];
    const mgmt = xml.match(/<dependencyManagement>([\s\S]*?)<\/dependencyManagement>/i);
    if (!mgmt) return out;
    const blockRe = /<dependency>([\s\S]*?)<\/dependency>/gi;
    let m;
    while ((m = blockRe.exec(mgmt[1])) !== null) {
      const g = this._extractTag(m[1], "groupId")[0] ?? "";
      const a = this._extractTag(m[1], "artifactId")[0] ?? "";
      const v = this._extractTag(m[1], "version")[0] ?? "";
      if (g && a && v) out.push({ groupId: g, artifactId: a, version: v });
    }
    return out;
  }

  _emptyContext(coords = {}) {
    return { props: new Map(), managed: new Map(), coords };
  }

  _pomContext(pomFile, seen = new Set()) {
    const key = path.resolve(pomFile);
    if (this._ctxCache.has(key)) return this._ctxCache.get(key);
    if (seen.has(key) || seen.size > 10) return this._emptyContext();   // cyclic / absurdly deep chain
    seen.add(key);

    const xml = this._readPom(key);
    if (xml == null) return this._emptyContext();

    // Parent first, so the child's own properties and managed versions override it.
    const par = this._parentBlock(xml);
    let parentCtx = this._emptyContext(par ? { groupId: par.groupId, version: par.version } : {});
    if (par && par.relativePath !== "") {
      let target = path.resolve(path.dirname(key), par.relativePath);
      try { if (fs.statSync(target).isDirectory()) target = path.join(target, "pom.xml"); } catch { /* missing */ }
      if (fs.existsSync(target) && path.resolve(target) !== key) {
        const ctx = this._pomContext(target, seen);
        if (!par.artifactId || ctx.coords.artifactId === par.artifactId) parentCtx = ctx;
      }
    }

    const props = new Map(parentCtx.props);
    for (const [k, v] of this._parsePomProperties(xml)) props.set(k, v);

    const coords = this._pomCoords(xml, parentCtx.coords);
    for (const [name, val] of [
      ["project.groupId", coords.groupId], ["pom.groupId", coords.groupId],
      ["project.artifactId", coords.artifactId], ["pom.artifactId", coords.artifactId],
      ["project.version", coords.version], ["pom.version", coords.version], ["version", coords.version],
      ["project.parent.version", par?.version], ["project.parent.groupId", par?.groupId],
    ]) {
      if (val && !props.has(name)) props.set(name, val);
    }

    // Raw (uninterpolated) managed versions: they are resolved against the *requesting* project's
    // properties, so a child that overrides ${foo.version} changes what the parent manages.
    const managed = new Map(parentCtx.managed);
    for (const d of this._parseManagedDeps(xml)) {
      managed.set(`${this._interpolate(d.groupId, props)}:${this._interpolate(d.artifactId, props)}`, d.version);
    }

    const ctx = { props, managed, coords };
    this._ctxCache.set(key, ctx);
    return ctx;
  }

  // ─────────────────────────────
  // Parse mvn dependency:tree output file (.ubel/maven-deps.txt)
  // Format:
  //   [INFO] com.example:my-app:jar:1.0
  //   [INFO] +- org.springframework:spring-core:jar:5.3.21:compile
  //   [INFO] |  \- org.springframework:spring-jcl:jar:5.3.21:compile
  // Returns array of { groupId, artifactId, version, scope }
  // Note: the root artifact line (no scope field) is intentionally skipped —
  // it represents the project itself, not a dependency.
  // ─────────────────────────────
  _parseDepsTree(filePath) {
    const deps = [];
    let content;
    try {
      content = fs.readFileSync(filePath, "utf8");
    } catch {
      return deps;
    }

    for (const rawLine of content.split("\n")) {
      // Strip [INFO] prefix and tree characters
      const line = rawLine
        .replace(/^\[INFO\]\s*/,  "")
        .replace(/^[|\s\\+\-]+/, "")
        .trim();

      // groupId:artifactId:packaging:version:scope (root line has no :scope → skipped)
      const m = line.match(/^([^:]+):([^:]+):[^:]+:([^:]+):([^:\s]+)/);
      if (!m) continue;

      deps.push({
        groupId:    m[1],
        artifactId: m[2],
        version:    m[3],
        scope:      m[4].toLowerCase()
      });
    }

    return deps;
  }

  // ─────────────────────────────
  // Read <modules> from pom.xml
  // Returns array of relative module paths
  // ─────────────────────────────
  _parseModules(xml) {
    const mods = [];
    const modulesMatch = xml.match(/<modules>([\s\S]*?)<\/modules>/i);
    if (!modulesMatch) return mods;
    const re = /<module>([^<]+)<\/module>/gi;
    let m;
    while ((m = re.exec(modulesMatch[1])) !== null) mods.push(m[1].trim());
    return mods;
  }

  // ─────────────────────────────
  // Map Maven scope → UBEL scope
  // ─────────────────────────────
  _mavenScopeToUbel(mvnScope) {
    switch (mvnScope) {
      case "test":     return "dev";
      case "provided": return "prod";   // present at compile, provided by runtime
      case "runtime":  return "prod";
      case "system":   return "prod";
      default:         return "prod";   // compile (default)
    }
  }

  // ─────────────────────────────
  // Scan a single Maven project.
  // visited  – shared Set<resolvedPath> across the entire getInstalled() call,
  //            prevents both the outer walk and multi-module recursion from
  //            processing the same directory twice.
  // ─────────────────────────────
  _scanProject(projectRoot, visited) {
    const key = path.resolve(projectRoot);
    if (visited.has(key)) return [];
    visited.add(key);

    const pomPath = path.join(projectRoot, "pom.xml");
    let xml;
    try {
      xml = fs.readFileSync(pomPath, "utf8");
    } catch {
      return [];
    }

    // Remove XML comments to avoid false matches
    xml = xml.replace(/<!--[\s\S]*?-->/g, "");

    // Properties + managed versions, including those inherited from on-disk parent poms.
    const ctx        = this._pomContext(pomPath);
    const props      = ctx.props;
    const components = [];

    // Prefer pre-generated dependency tree if available
    const treeFile = path.join(projectRoot, ".ubel", "maven-deps.txt");
    const treeDeps = this._parseDepsTree(treeFile);

    let deps;
    if (treeDeps.length) {
      deps = treeDeps;
    } else {
      deps = this._parsePomDeps(xml).map(d => {
        const groupId    = this._interpolate(d.groupId, props).trim();
        const artifactId = this._interpolate(d.artifactId, props).trim();
        // No <version> of its own → the one <dependencyManagement> (here or in a parent) assigns.
        const raw        = d.version || ctx.managed.get(`${groupId}:${artifactId}`) || "";
        return { ...d, groupId, artifactId, version: this._resolveVersion(raw, props) };
      }).filter(d => !d.groupId.includes("${") && !d.artifactId.includes("${"));
    }

    for (const dep of deps) {
      if (!dep.groupId || !dep.artifactId) continue;

      let version = dep.version ?? "";
      if (version === "unknown") version = "";
      const id    = this._mavenPurl(dep.groupId, dep.artifactId, version);
      const scope = this._mavenScopeToUbel(dep.scope ?? "compile");


      components.push({
        id,
        name:         `${dep.groupId.toLowerCase()}:${dep.artifactId.toLowerCase()}`,
        version,
        type:         "library",
        license:      "unknown",
        ecosystem:    "java",
        state:        "undetermined",
        scopes:       [scope],
        dependencies: [],
        paths:        [projectRoot],
        project_root: projectRoot
      });
    }

    // Recurse into <modules> — pass the same visited set so no dir is double-scanned
    for (const mod of this._parseModules(xml)) {
      const modRoot = path.join(projectRoot, mod);
      components.push(...this._scanProject(modRoot, visited));
    }

    return components;
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
  // Walks startDir (and subdirs) for Maven project roots, then scans each.
  // A single shared `visited` set prevents any directory from being processed
  // more than once, regardless of whether it was found by the walk or by
  // multi-module recursion inside _scanProject.
  // ─────────────────────────────
  async getInstalled(startDir) {
    this.inventoryData = [];
    this._ctxCache = new Map();

    const visited = new Set();
    const raw     = [];

    // Scan startDir itself if it is a Maven root
    if (this._isMavenRoot(startDir)) {
      raw.push(...this._scanProject(startDir, visited));
    }

    // Walk subdirectories for additional Maven roots
    const walk = (dir) => {
      let entries;
      try {
        entries = fs.readdirSync(dir, { withFileTypes: true });
      } catch {
        return;
      }

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        // Skip dirs that cannot contain user project files
        if (["node_modules", ".git", ".ubel", "target", ".m2"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (this._isMavenRoot(full)) {
          // _scanProject will add full to visited on first call;
          // multi-module recursion reuses the same set so no double-scan.
          raw.push(...this._scanProject(full, visited));
          // Still descend — <modules> covers declared multi-module
          // aggregation, but monorepos also commonly contain independent
          // Maven projects nested in the tree with no aggregator pom at
          // all. `visited` (checked at the top of _scanProject) prevents
          // any project already picked up via <modules> from being
          // scanned again here.
        }

        walk(full);
      }
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);
    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default JavaMavenScanner;