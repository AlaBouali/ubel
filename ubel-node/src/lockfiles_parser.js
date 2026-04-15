import path from "path";

// ─────────────────────────────────────────────────────────────────────────────
// LockfileParser
//
// Parses lockfiles from all supported package managers and returns a flat,
// normalised component array with a consistent shape:
//
//   {
//     id:           "pkg:npm/name@version",
//     name:         string,
//     version:      string,
//     type:         "library",
//     license:      string,
//     ecosystem:    "npm",
//     state:        "undetermined",
//     dependencies: string[],   // PURL strings (version may be empty)
//     path:         string,
//     paths:        string[],
//   }
//
// Supported formats
// ─────────────────
//   npm   — package-lock.json  (v1 / v2 / v3)
//   yarn  — yarn.lock          (classic v1, berry v2/v3)
//   pnpm  — pnpm-lock.yaml     (v5 / v6 / v9)
//   bun   — bun.lock / bun.lockb (JSONC text format)
// ─────────────────────────────────────────────────────────────────────────────

export class LockfileParser {

  // ── PURL helpers ─────────────────────────────────────────────────────────

  /**
   * Build a pkg:npm PURL.
   * Scoped packages (@scope/name) get the "@" percent-encoded so that
   * OSV batch query endpoints parse them correctly.
   */
  static purl(name, version) {
    if (!name) return `pkg:npm/@${version ?? ""}`;
    const enc = name.startsWith("@")
      ? "%40" + name.slice(1)
      : name;
    return version
      ? `pkg:npm/${enc}@${version}`
      : `pkg:npm/${enc}@`;
  }

  // ── Dispatcher ───────────────────────────────────────────────────────────

  /**
   * Auto-detect lockfile type from filename and parse it.
   *
   * @param {string} filename  Basename, e.g. "package-lock.json"
   * @param {string} content   Raw file contents as a string
   * @returns {object[]}       Flat component array
   */
  static parse(filename, content) {
    switch (filename) {
      case "package-lock.json":
        return LockfileParser.parseNpmLock(content);

      case "yarn.lock":
        return LockfileParser.parseYarnLock(content);

      case "pnpm-lock.yaml":
        return LockfileParser.parsePnpmLock(content);

      case "bun.lock":
      case "bun.lockb":
        return LockfileParser.parseBunLock(content);

      default:
        throw new Error(`Unknown lockfile: ${filename}`);
    }
  }

  // ══════════════════════════════════════════════════════════════════════════
  // npm — package-lock.json  (v1 / v2 / v3)
  // ══════════════════════════════════════════════════════════════════════════

  static parseNpmLock(content) {
    let data = content;
    if (typeof content === "string") {
      try { data = JSON.parse(content); }
      catch { return []; }
    }

    // ── v2 / v3: packages map ─────────────────────────────────────────────
    if (data?.packages) {
      const components = [];

      for (const [pkgPath, meta] of Object.entries(data.packages)) {
        if (pkgPath === "" || typeof meta !== "object") continue;

        // Derive name from the lockfile path key when not explicit.
        // e.g. "node_modules/@babel/core" → "@babel/core"
        //      "node_modules/.pnpm/@babel+core@7.x/node_modules/@babel/core" → "@babel/core"
        let name = meta.name;
        if (!name) {
          const parts = pkgPath.split("node_modules/");
          name = parts[parts.length - 1];
        }
        if (!name) continue;

        const version = meta.version;
        if (!version) continue;

        const license      = meta.license || "unknown";
        const dependencies = Object.keys(meta.dependencies || {}).map(
          d => LockfileParser.purl(d, null)
        );

        components.push({
          id:           LockfileParser.purl(name, version),
          name,
          version,
          type:         "library",
          license,
          ecosystem:    "npm",
          state:        "undetermined",
          dependencies,
          path:         path.join(".", pkgPath),
          paths:        [path.join(".", pkgPath)],
        });
      }

      return components;
    }

    // ── v1: dependencies map ──────────────────────────────────────────────
    if (data?.dependencies) {
      const components = [];

      function walk(deps, parentPath = "node_modules") {
        for (const [name, meta] of Object.entries(deps)) {
          if (typeof meta !== "object") continue;

          const version = meta.version;
          if (!version) continue;

          const license      = meta.license || "unknown";
          const dependencies = Object.keys(meta.dependencies || {}).map(
            d => LockfileParser.purl(d, null)
          );
          const pkgPath = path.join(".", parentPath, name);

          components.push({
            id:           LockfileParser.purl(name, version),
            name,
            version,
            type:         "library",
            license,
            ecosystem:    "npm",
            state:        "undetermined",
            dependencies,
            path:         pkgPath,
            paths:        [pkgPath],
          });

          if (meta.dependencies) {
            walk(meta.dependencies, path.join(parentPath, name, "node_modules"));
          }
        }
      }

      walk(data.dependencies);
      return components;
    }

    return [];
  }

  // ══════════════════════════════════════════════════════════════════════════
  // yarn — yarn.lock  (classic v1  AND  berry v2/v3)
  //
  // Classic format is a custom DSL; Berry format is a superset (same DSL but
  // with a "__metadata" block at the top).  Neither is JSON or YAML.
  //
  // Structure of each stanza:
  //
  //   "name@^1.0.0", "name@~1.0.0":    ← one or more descriptor keys
  //     version: "1.2.3"
  //     resolution: "name@npm:1.2.3"
  //     dependencies:
  //       dep-a: ^2.0.0
  //       dep-b: ~3.1.0
  //     ...
  //
  // ══════════════════════════════════════════════════════════════════════════

  static parseYarnLock(content) {
    if (typeof content !== "string") return [];

    const components = [];
    // Map from "name@version" → component for deduplication
    const seen = new Map();

    const lines = content.split("\n");
    let i = 0;

    function skipBlanksAndComments() {
      while (i < lines.length) {
        const l = lines[i].trimEnd();
        if (l === "" || l.startsWith("#")) { i++; continue; }
        break;
      }
    }

    // Parse indented key:value block (2-space indent for top-level fields,
    // 4-space for sub-objects like `dependencies:`).
    function parseBlock(indent) {
      const fields = {};
      while (i < lines.length) {
        const raw = lines[i];
        const trimmed = raw.trimEnd();
        if (trimmed === "") { i++; continue; }

        // How many leading spaces?
        const spaces = raw.length - raw.trimStart().length;

        // Back out if this line belongs to a parent block
        if (spaces < indent) break;

        // Sub-object header (ends with ":")
        if (/^\s+\w[\w-]*:\s*$/.test(raw) || /^\s+"[^"]+":?\s*$/.test(raw)) {
          const key = trimmed.replace(/:$/, "").replace(/"/g, "").trim();
          i++;
          fields[key] = parseBlock(spaces + 2);
          continue;
        }

        // key: "value"  or  key: value
        const kv = trimmed.match(/^([\w.-]+|"[^"]+")\s*:\s*(.*)$/);
        if (kv) {
          const key = kv[1].replace(/"/g, "");
          const val = kv[2].replace(/^"|"$/g, "").trim();
          fields[key] = val;
          i++;
          continue;
        }

        break;
      }
      return fields;
    }

    while (i < lines.length) {
      skipBlanksAndComments();
      if (i >= lines.length) break;

      const headerLine = lines[i].trimEnd();

      // Skip __metadata block (Berry)
      if (headerLine === "__metadata:") {
        i++;
        parseBlock(2);
        continue;
      }

      // A stanza header: one or more quoted descriptors followed by ":"
      // "pkg@^1.0", "pkg@~2.0":
      if (!headerLine.endsWith(":")) { i++; continue; }

      // Collect all descriptors on this header line (may span multiple lines
      // in classic format — though in practice they're on one line).
      const descriptorLine = headerLine.slice(0, -1); // strip trailing ":"
      i++;

      // Parse the body at 2-space indent
      const fields = parseBlock(2);

      const version = (fields.version || "").replace(/^"|"$/g, "");
      if (!version) continue;

      // Extract name from first descriptor
      // Descriptor examples:
      //   "react@^18.0.0"     → name="react"
      //   "@babel/core@^7.0"  → name="@babel/core"
      //   react@npm:^18.0.0   (berry)
      const firstDescriptor = descriptorLine
        .split(",")[0]
        .replace(/"/g, "")
        .trim();

      let name = "";
      if (firstDescriptor.startsWith("@")) {
        // scoped: @scope/pkg@specifier
        const atIdx = firstDescriptor.indexOf("@", 1);
        name = atIdx > 0 ? firstDescriptor.slice(0, atIdx) : firstDescriptor;
      } else {
        name = firstDescriptor.split("@")[0];
      }

      // Berry sometimes uses "pkg@npm:specifier" — strip the npm: registry
      // prefix from the name if it crept in.
      name = name.replace(/@npm$/, "");
      if (!name) continue;

      const key = `${name}@${version}`;
      if (seen.has(key)) continue;

      // Collect dep PURLs from the "dependencies" sub-object
      const rawDeps = fields.dependencies || {};
      const dependencies = Object.keys(rawDeps).map(d => LockfileParser.purl(d, null));

      const comp = {
        id:           LockfileParser.purl(name, version),
        name,
        version,
        type:         "library",
        license:      "unknown",
        ecosystem:    "npm",
        state:        "undetermined",
        dependencies,
        path:         path.join(".", "node_modules", ...name.split("/")),
        paths:        [path.join(".", "node_modules", ...name.split("/"))],
      };

      seen.set(key, comp);
      components.push(comp);
    }

    return components;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // pnpm — pnpm-lock.yaml  (v5 / v6 / v9)
  //
  // We intentionally avoid pulling in a YAML library so this is a purpose-
  // built minimal YAML parser that handles only the subset used by pnpm
  // lockfiles.  Key structural differences between versions:
  //
  //   v5/v6  —  top-level "packages:" map keyed by "/name/version"
  //   v9     —  top-level "packages:" map keyed by "name@version"
  //             (snapshots section is separate but we use packages only)
  //
  // ══════════════════════════════════════════════════════════════════════════

  static parsePnpmLock(content) {
    if (typeof content !== "string") return [];

    // ── Minimal YAML block parser ─────────────────────────────────────────
    // Returns an object where each key maps to either a string value or a
    // nested object (for indented sub-maps).  We only need two levels deep
    // for pnpm lockfiles.

    function parseYamlBlock(lines, startIndent) {
      const result = {};
      let i = 0;

      while (i < lines.length) {
        const raw   = lines[i];
        if (raw.trim() === "" || raw.trimStart().startsWith("#")) { i++; continue; }

        const spaces = raw.length - raw.trimStart().length;
        if (spaces < startIndent) break;

        const trimmed = raw.trim();

        // key: value
        const kv = trimmed.match(/^([^:]+):\s*(.*)$/);
        if (!kv) { i++; continue; }

        const key = kv[1].trim().replace(/^['"]|['"]$/g, "");
        const val = kv[2].trim().replace(/^['"]|['"]$/g, "");

        if (val === "" || val === "|" || val === ">") {
          // Sub-map: collect remaining lines at deeper indent
          const sub = [];
          i++;
          while (i < lines.length) {
            const nextRaw    = lines[i];
            const nextSpaces = nextRaw.length - nextRaw.trimStart().length;
            if (nextRaw.trim() === "" || nextSpaces > spaces) {
              sub.push(nextRaw.slice(spaces + 2));
              i++;
            } else {
              break;
            }
          }
          result[key] = parseYamlBlock(sub, 0);
        } else {
          result[key] = val;
          i++;
        }
      }

      return result;
    }

    // ── Split the file into top-level sections ───────────────────────────
    // pnpm lockfiles use top-level keys like "lockfileVersion:", "packages:",
    // "snapshots:", etc.  We grab the raw lines under "packages:" AND
    // "snapshots:".
    //
    // In pnpm v9 the "packages:" section only holds resolution metadata
    // (integrity, engines, peerDependencies) — NO runtime dependencies.
    // The actual resolved dependency graph is in "snapshots:".
    // In pnpm v5/v6 "packages:" holds everything including dependencies.
    // We parse both sections and merge: snapshots deps win when present.

    const allLines = content.split("\n");
    let inPackages  = false;
    let inSnapshots = false;
    const packageLines  = [];
    const snapshotLines = [];
    let packageIndent = 2;

    for (const line of allLines) {
      if (/^packages:\s*$/.test(line))  { inPackages = true;  inSnapshots = false; continue; }
      if (/^snapshots:\s*$/.test(line)) { inSnapshots = true; inPackages  = false; continue; }

      if (inPackages) {
        if (/^[a-zA-Z_]/.test(line)) { inPackages = false; continue; }
        packageLines.push(line);
      } else if (inSnapshots) {
        if (/^[a-zA-Z_]/.test(line)) { inSnapshots = false; continue; }
        snapshotLines.push(line);
      }
    }

    if (packageLines.length === 0 && snapshotLines.length === 0) return [];

    // ── Helper: parse a section's lines into a map of key → fields ──────
    function parseSectionLines(sectionLines) {
      const map = new Map();
      let j = 0;
      while (j < sectionLines.length) {
        const raw = sectionLines[j];
        if (raw.trim() === "" || raw.trimStart().startsWith("#")) { j++; continue; }

        const spaces = raw.length - raw.trimStart().length;
        if (spaces === packageIndent && raw.trimEnd().endsWith(":")) {
          const entryKey = raw.trim().replace(/:$/, "").replace(/^['"]|['"]$/g, "");
          const bodyLines = [];
          j++;
          while (j < sectionLines.length) {
            const bodyRaw    = sectionLines[j];
            const bodySpaces = bodyRaw.length - bodyRaw.trimStart().length;
            if (bodyRaw.trim() === "" || bodySpaces > packageIndent) {
              bodyLines.push(bodyRaw.slice(packageIndent + 2));
              j++;
            } else {
              break;
            }
          }
          map.set(entryKey, parseYamlBlock(bodyLines, 0));
          continue;
        }
        j++;
      }
      return map;
    }

    // ── Parse both sections into key→fields maps ────────────────────────
    const packagesMap  = parseSectionLines(packageLines);
    const snapshotsMap = parseSectionLines(snapshotLines);

    // Build a unified key set (packages section is authoritative for
    // resolution; snapshots section provides the dependency graph in v9).
    //
    // IMPORTANT: sort so that snapshot entries with peer-dep suffixes
    // (e.g. "@vitejs/plugin-react@5.2.0(@babel/core@7.29.0)(vite@6.4.2)")
    // are processed BEFORE the bare packages-section entry for the same
    // name@version ("@vitejs/plugin-react@5.2.0").  Both resolve to the same
    // seen-map key; whichever is processed first wins.  Snapshot entries carry
    // the actual dependency graph, so they must win — otherwise the packages
    // entry (which has no dependencies block) is stored and the snapshot entry
    // is silently skipped, leaving all transitive deps unscoped.
    const allKeys = [
      ...new Set([...snapshotsMap.keys(), ...packagesMap.keys()])
    ].sort((a, b) => {
      // Entries with '(' have peer-dep suffixes → snapshot entries → sort first
      const aHasSuffix = a.includes('(');
      const bHasSuffix = b.includes('(');
      if (aHasSuffix && !bHasSuffix) return -1;
      if (!aHasSuffix && bHasSuffix) return  1;
      return 0;
    });

    const components = [];
    const seen       = new Map();

    for (const entryKey of allKeys) {
        // Merge: start from packages fields, overlay snapshot fields so that
        // the snapshot's "dependencies" block wins (v9 pattern).
        const pkgFields  = packagesMap.get(entryKey)  || {};
        const snapFields = snapshotsMap.get(entryKey) || {};
        const fields = { ...pkgFields, ...snapFields };

        // ── Derive name + version from entry key ─────────────────────────
        // v5/v6 key: /name/version  or  /@scope/name/version
        //      e.g.  /react/18.2.0          /@babel/core/7.21.0
        // v9   key:  name@version  or  @scope/name@version
        //      e.g.  react@18.2.0           @babel/core@7.21.0

        let name, version;

        if (entryKey.startsWith("/")) {
          // v5/v6: strip leading slash, last segment is version
          const stripped = entryKey.slice(1);           // "react/18.2.0"
          const lastSlash = stripped.lastIndexOf("/");
          name    = stripped.slice(0, lastSlash);       // "react"
          version = stripped.slice(lastSlash + 1);      // "18.2.0"
          // Strip peer-dep suffix like "_react@18.2.0"
          version = version.split("_")[0];
        } else {
          // v9: key may have peer-dep suffix: "pkg@1.2.3(peer@4.0.0)"
          // Strip the parenthesised suffix first.
          const cleanKey = entryKey.replace(/\(.*$/, "");
          const atIdx = cleanKey.indexOf("@", cleanKey.startsWith("@") ? 1 : 0);
          if (atIdx === -1) { continue; }
          name    = cleanKey.slice(0, atIdx);
          version = cleanKey.slice(atIdx + 1);
        }

        // fields.version overrides if present (more reliable for v5/v6)
        if (fields.version) version = fields.version;

        if (!name || !version) continue;

        const key = `${name}@${version}`;
        if (seen.has(key)) continue;
        seen.set(key, true);

        const license = fields.license || "unknown";

        const rawDeps = fields.dependencies || {};
        const dependencies = Object.keys(rawDeps).map(d => LockfileParser.purl(d, null));

        components.push({
          id:           LockfileParser.purl(name, version),
          name,
          version,
          type:         "library",
          license,
          ecosystem:    "npm",
          state:        "undetermined",
          dependencies,
          path:         "",
          paths:        [],
        });

    }

    return components;
  }

  // ══════════════════════════════════════════════════════════════════════════
  // bun — bun.lock / bun.lockb
  //
  // bun.lock is a JSONC file (JSON with // comments and trailing commas).
  // bun.lockb is a binary format — we cannot parse it without the bun binary
  // so we shell out to `bun bun.lock` to get the text representation.
  //
  // Two tuple layouts exist depending on lockfileVersion:
  //
  //   v0 (lockfileVersion: 0):
  //     "react": ["react@18.2.0", {...registryInfo}, "MIT", { deps }]
  //     tuple:    [0: resolution,  1: meta,           2: license, 3: deps]
  //
  //   v1 (lockfileVersion: 1, bun >= 1.2):
  //     "react": ["react@18.2.0", "", { dependencies: {...}, peerDependencies: {...} }, "sha512-..."]
  //     tuple:    [0: resolution,  1: registryURL, 2: meta-object-with-deps, 3: integrity]
  //
  // Detection: if entry[2] is a plain object (not a string), we're in v1.
  // ══════════════════════════════════════════════════════════════════════════

  static parseBunLock(content) {
    if (typeof content !== "string") return [];

    // ── Strip JSONC comments and trailing commas ──────────────────────────
    const json = LockfileParser._stripJsonc(content);

    let data;
    try { data = JSON.parse(json); }
    catch { return []; }

    const packages = data?.packages;
    if (!packages || typeof packages !== "object") return [];

    const components = [];

    for (const [pkgName, entry] of Object.entries(packages)) {
      if (!Array.isArray(entry) || entry.length < 1) continue;

      // entry[0] is always "name@version" (the resolved specifier)
      const resolution = String(entry[0] || "");

      let name, version;

      // Scoped: "@scope/name@ver"
      const scopedMatch = resolution.match(/^(@[^@/]+\/[^@]+)@(.+)$/);
      if (scopedMatch) {
        name    = scopedMatch[1];
        version = scopedMatch[2];
      } else {
        const atIdx = resolution.lastIndexOf("@");
        if (atIdx <= 0) continue;
        name    = resolution.slice(0, atIdx);
        version = resolution.slice(atIdx + 1);
      }

      if (!name || !version) continue;

      // Strip npm: registry prefix that bun sometimes includes
      version = version.replace(/^npm:/, "");

      // ── Detect tuple layout ────────────────────────────────────────────
      // v1: entry[2] is a plain object  → deps at entry[2].dependencies
      // v0: entry[2] is a string        → license, deps at entry[3]
      let license = "unknown";
      let depsRaw = null;

      if (entry[2] !== null && typeof entry[2] === "object" && !Array.isArray(entry[2])) {
        // v1 layout: ["resolution", "registryURL", { dependencies, peerDependencies, ... }, "integrity"]
        depsRaw = entry[2].dependencies || null;
      } else {
        // v0 layout: ["resolution", { meta }, "license", { deps } | deps[]]
        license = typeof entry[2] === "string" && entry[2] ? entry[2] : "unknown";
        depsRaw = entry[3] ?? null;
      }

      // Normalise depsRaw → array of dep names
      let depNames = [];
      if (depsRaw && typeof depsRaw === "object" && !Array.isArray(depsRaw)) {
        depNames = Object.keys(depsRaw);
      } else if (Array.isArray(depsRaw)) {
        depNames = depsRaw.map(d => {
          if (typeof d !== "string") return String(d);
          const idx = d.lastIndexOf("@");
          return idx > 0 ? d.slice(0, idx) : d;
        });
      }
      const dependencies = depNames.map(d => LockfileParser.purl(d, null));

      components.push({
        id:           LockfileParser.purl(name, version),
        name,
        version,
        type:         "library",
        license,
        ecosystem:    "npm",
        state:        "undetermined",
        dependencies,
        path:         "",
        paths:        [],
      });
    }

    return components;
  }

  // ── JSONC stripper ────────────────────────────────────────────────────────
  // Single-pass scanner that removes // line comments and /* block comments */
  // and trailing commas before ] or }.
  // ─────────────────────────────────────────────────────────────────────────

  static _stripJsonc(src) {
    let out    = "";
    let i      = 0;
    let inStr  = false;
    let escape = false;

    while (i < src.length) {
      const ch  = src[i];
      const ch2 = src[i + 1];

      if (escape) {
        out   += ch;
        escape = false;
        i++;
        continue;
      }

      if (inStr) {
        if (ch === "\\") { escape = true; out += ch; i++; continue; }
        if (ch === '"')    inStr  = false;
        out += ch;
        i++;
        continue;
      }

      // Block comment
      if (ch === "/" && ch2 === "*") {
        i += 2;
        while (i < src.length && !(src[i] === "*" && src[i + 1] === "/")) i++;
        i += 2;
        continue;
      }

      // Line comment
      if (ch === "/" && ch2 === "/") {
        while (i < src.length && src[i] !== "\n") i++;
        continue;
      }

      if (ch === '"') { inStr = true; out += ch; i++; continue; }

      out += ch;
      i++;
    }

    // Remove trailing commas: ,  followed by optional whitespace then ] or }
    return out.replace(/,(\s*[}\]])/g, "$1");
  }
}

export default LockfileParser;