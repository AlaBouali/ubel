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

  static inventoryData = [];

  // ─────────────────────────────
  // PURL
  // ─────────────────────────────
  static _mavenPurl(groupId, artifactId, version) {
    return `pkg:maven/${groupId.toLowerCase()}/${artifactId.toLowerCase()}@${version ?? ""}`;
  }

  // ─────────────────────────────
  // Detect Maven project root
  // ─────────────────────────────
  static _isMavenRoot(dir) {
    return fs.existsSync(path.join(dir, "pom.xml"));
  }

  // ─────────────────────────────
  // Minimal XML tag extractor
  // Returns all text values for a given tag name within a block of XML text.
  // ─────────────────────────────
  static _extractTag(xml, tag) {
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
  static _parsePomDeps(xml) {
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
      const optional   = (this._extractTag(block, "optional")[0] ?? "false") === "true";

      if (groupId && artifactId) {
        deps.push({ groupId, artifactId, version, scope: scope.toLowerCase(), optional });
      }
    }
    return deps;
  }

  // ─────────────────────────────
  // Extract <properties> block for variable interpolation
  // Returns Map<"project.X" | varName, value>
  // ─────────────────────────────
  static _parsePomProperties(xml) {
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
  // Resolve ${...} property references
  // ─────────────────────────────
  static _resolveVersion(version, props) {
    if (!version) return "";
    return version.replace(/\$\{([^}]+)\}/g, (_, key) => props.get(key) ?? "");
  }

  // ─────────────────────────────
  // Parse mvn dependency:tree output file (.ubel/maven-deps.txt)
  // Format:
  //   [INFO] com.example:my-app:jar:1.0
  //   [INFO] +- org.springframework:spring-core:jar:5.3.21:compile
  //   [INFO] |  \- org.springframework:spring-jcl:jar:5.3.21:compile
  // Returns array of { groupId, artifactId, version, scope, depth }
  // ─────────────────────────────
  static _parseDepsTree(filePath) {
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

      // groupId:artifactId:packaging:version:scope
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
  static _parseModules(xml) {
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
  static _mavenScopeToUbel(mvnScope) {
    switch (mvnScope) {
      case "test":     return "dev";
      case "provided": return "prod";   // present at compile, provided by runtime
      case "runtime":  return "prod";
      case "system":   return "prod";
      default:         return "prod";   // compile (default)
    }
  }

  // ─────────────────────────────
  // Scan a single Maven project
  // ─────────────────────────────
  static _scanProject(projectRoot, visited = new Set()) {
    const pomPath = path.join(projectRoot, "pom.xml");
    const key     = path.resolve(projectRoot);
    if (visited.has(key)) return [];
    visited.add(key);

    let xml;
    try {
      xml = fs.readFileSync(pomPath, "utf8");
    } catch {
      return [];
    }

    // Remove XML comments to avoid false matches
    xml = xml.replace(/<!--[\s\S]*?-->/g, "");

    const props    = this._parsePomProperties(xml);
    const components = [];

    // Prefer pre-generated dependency tree if available
    const treeFile = path.join(projectRoot, ".ubel", "maven-deps.txt");
    const treeDeps = this._parseDepsTree(treeFile);

    let deps;
    if (treeDeps.length) {
      deps = treeDeps;
    } else {
      deps = this._parsePomDeps(xml).map(d => ({
        ...d,
        version: this._resolveVersion(d.version, props)
      }));
    }

    // Build name index for dep-graph resolution within this project
    const nameIndex = new Map();
    for (const dep of deps) {
      const k = `${dep.groupId.toLowerCase()}:${dep.artifactId.toLowerCase()}`;
      if (!nameIndex.has(k)) nameIndex.set(k, dep);
    }

    for (const dep of deps) {
      if (!dep.groupId || !dep.artifactId) continue;

      const id    = this._mavenPurl(dep.groupId, dep.artifactId, dep.version);
      const scope = this._mavenScopeToUbel(dep.scope ?? "compile");

      components.push({
        id,
        name:         `${dep.groupId.toLowerCase()}:${dep.artifactId.toLowerCase()}`,
        version:      dep.version ?? "",
        type:         "library",
        license:      "unknown",
        ecosystem:    "maven",
        state:        "undetermined",
        scopes:       [scope],
        dependencies: [],   // tree file gives depth but not explicit edges; left empty
        paths:        [projectRoot],
        project_root: projectRoot
      });
    }

    // Recurse into <modules>
    for (const mod of this._parseModules(xml)) {
      const modRoot = path.join(projectRoot, mod);
      components.push(...this._scanProject(modRoot, visited));
    }

    return components;
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
        if (["node_modules", ".git", ".ubel", "target", ".m2"].includes(entry.name)) continue;

        const full = path.join(dir, entry.name);

        if (JavaMavenScanner._isMavenRoot(full)) {
          const key = path.resolve(full);
          if (!visited.has(key)) {
            // _scanProject handles its own visited set for multi-module recursion
            raw.push(...JavaMavenScanner._scanProject(full, visited));
          }
          continue;
        }

        walk(full);
      }
    }

    if (JavaMavenScanner._isMavenRoot(startDir)) {
      raw.push(...JavaMavenScanner._scanProject(startDir, visited));
    }

    walk(startDir);

    const merged = this.mergeInventoryByPurl(raw);

    this.inventoryData = merged;
    return merged.map(c => c.id);
  }
}

export default JavaMavenScanner;