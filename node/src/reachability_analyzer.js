/**
 * reachability_analyzer.js — UBEL Reachability Analyzer (Node.js)
 * ================================================================
 * 1:1 port of reachability_analyzer.py.
 *
 * Analyzes a UBEL JSON report and annotates each vulnerability with a
 * reachability assessment derived from:
 *
 *   - dependency_graph   → orphan-tool detection (no dependents)
 *   - inventory          → depth, scope, introduced_by, pkg type
 *   - findings_summary   → affected_dependency_sequences (shortest path)
 *   - vulnerabilities    → severity_vector (AV extraction)
 *   - project source     → import/require scan (optional, 8 ecosystems)
 *
 * Zero external dependencies. Zero new data collection.
 *
 * Usage (programmatic):
 *   import { analyzeReachability, enrichReport } from "./reachability_analyzer.js";
 *   const results = analyzeReachability(reportJson, projectRoot);
 *   const enriched = enrichReport(reportJson, projectRoot);
 *
 * Usage (CLI):
 *   node reachability_analyzer.js report.json [--project-root /path] [--enrich]
 */

import fs   from "fs";
import path from "path";

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Package types that are NOT pure libraries. Any vuln in these is "critical". */
const NON_LIBRARY_TYPES = new Set([
  "application", "app",
  "framework",
  "plugin",
  "container",
  "device",
  "firmware",
  "operating-system", "operating_system", "os",
  "service",
  "binary",
  "executable",
  "deb", "rpm", "apk", "snap", "flatpak",
]);

/** Source file extensions per canonical ecosystem key. */
const ECOSYSTEM_EXTENSIONS = {
  python:   new Set([".py"]),
  npm:      new Set([".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"]),
  maven:    new Set([".java", ".kt", ".groovy", ".scala"]),
  nuget:    new Set([".cs", ".vb", ".fs", ".fsx"]),
  php:      new Set([".php"]),
  go:       new Set([".go"]),
  cargo:    new Set([".rs"]),
  rubygems: new Set([".rb"]),
};

/** PURL ecosystem type → canonical key used in ECOSYSTEM_EXTENSIONS. */
const ECOSYSTEM_ALIASES = {
  pypi:        "python",
  python:      "python",
  npm:         "npm",
  node:        "npm",
  maven:       "maven",
  gradle:      "maven",
  nuget:       "nuget",
  dotnet:      "nuget",
  packagist:   "php",
  composer:    "php",
  php:         "php",
  golang:      "go",
  go:          "go",
  cargo:       "cargo",
  rust:        "cargo",
  gem:         "rubygems",
  rubygems:    "rubygems",
  ruby:        "rubygems",
};

/**
 * Distribution package name → actual import name.
 * Keys are lowercase distribution names as they appear in PURLs/lockfiles.
 */
const IMPORT_NAME_OVERRIDES = {
  // Python
  "beautifulsoup4":             "bs4",
  "pyyaml":                     "yaml",
  "pillow":                     "PIL",
  "scikit-learn":               "sklearn",
  "scikit-image":               "skimage",
  "opencv-python":              "cv2",
  "opencv-python-headless":     "cv2",
  "python-dateutil":            "dateutil",
  "python-dotenv":              "dotenv",
  "python-jose":                "jose",
  "python-multipart":           "multipart",
  "python-slugify":             "slugify",
  "email-validator":            "email_validator",
  "typing-extensions":          "typing_extensions",
  "attrs":                      "attr",
  "pyzmq":                      "zmq",
  "pyjwt":                      "jwt",
  "mysqlclient":                "MySQLdb",
  "psycopg2-binary":            "psycopg2",
  "google-auth":                "google.auth",
  "google-cloud-storage":       "google.cloud.storage",
  "grpcio":                     "grpc",
  "protobuf":                   "google.protobuf",
  "pyopenssl":                  "OpenSSL",
  "werkzeug":                   "werkzeug",
  "markupsafe":                 "markupsafe",
  "itsdangerous":               "itsdangerous",
  "jinja2":                     "jinja2",
  // Node.js
  "lodash.merge":               "lodash",
  // Ruby
  "activesupport":              "active_support",
  // .NET
  "newtonsoft.json":            "Newtonsoft.Json",
  "microsoft.extensions.logging": "Microsoft.Extensions.Logging",
};

/** Directories to skip during source scan. */
const SKIP_DIRS = new Set([
  "node_modules", ".git", "__pycache__", ".tox", "venv", ".venv",
  "env", ".env", "dist", "build", "target", "vendor",
  ".idea", ".vscode", "coverage", ".mypy_cache", ".pytest_cache",
]);

/** Max file size to scan (bytes). */
const MAX_FILE_SIZE = 512 * 1024;

// ---------------------------------------------------------------------------
// PURL helpers
// ---------------------------------------------------------------------------

/**
 * Minimal PURL parser.
 * @param {string} purl
 * @returns {{ ecosystem: string, name: string, namespace: string, version: string }}
 */
function parsePurl(purl) {
  const result = { ecosystem: "", name: "", namespace: "", version: "" };
  if (!purl || !purl.startsWith("pkg:")) return result;

  const body = purl.slice(4);
  const slashIdx = body.indexOf("/");
  if (slashIdx === -1) return result;

  result.ecosystem = body.slice(0, slashIdx).toLowerCase();
  let rest = body.slice(slashIdx + 1).split("?")[0].split("#")[0];

  // version
  const atIdx = rest.lastIndexOf("@");
  if (atIdx > 0) {
    result.version = rest.slice(atIdx + 1);
    rest = rest.slice(0, atIdx);
  }

  // decode
  rest = decodeURIComponent(rest);

  // namespace / name
  const lastSlash = rest.lastIndexOf("/");
  if (lastSlash !== -1) {
    result.namespace = rest.slice(0, lastSlash);
    result.name      = rest.slice(lastSlash + 1);
  } else {
    result.name = rest;
  }

  return result;
}

// ---------------------------------------------------------------------------
// CVSS vector parser
// ---------------------------------------------------------------------------

/**
 * Extracts AV field from a CVSS vector string.
 * @param {string} severityVector
 * @returns {"N"|"L"|"P"|"unknown"}
 */
function extractAttackVector(severityVector) {
  if (!severityVector) return "unknown";
  const m = severityVector.match(/\/AV:([NLP])/);
  return m ? m[1] : "unknown";
}

// ---------------------------------------------------------------------------
// Import pattern builders (per ecosystem)
// ---------------------------------------------------------------------------

/**
 * Normalizes a package name for use in a regex pattern.
 * @param {string} name
 * @param {string} eco
 * @returns {string}
 */
function normalizePkgName(name, eco) {
  if (eco === "python" || eco === "cargo") {
    return name.replace(/[-_]/g, "[-_]");
  }
  return name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/**
 * Builds an array of RegExp patterns for detecting imports of a package
 * in source files, based on ecosystem.
 *
 * @param {{ ecosystem: string, name: string, namespace: string }} purlInfo
 * @returns {RegExp[]}
 */
function buildImportPatterns(purlInfo) {
  const { ecosystem: eco, name, namespace: ns } = purlInfo;
  const patterns = [];

  if (eco === "python") {
    const n = normalizePkgName(name, "python");
    patterns.push(
      new RegExp(`^\\s*import\\s+${n}(\\s|$|\\.)`, "m"),
      new RegExp(`^\\s*from\\s+${n}(\\s|\\.|$)`, "m"),
    );
  }

  else if (eco === "npm") {
    const full = ns ? `${ns}/${name}` : name;
    const esc  = full.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(
      new RegExp(`require\\s*\\(\\s*['"\`]${esc}(/[^'"\`]*)?['"\`]\\s*\\)`, "m"),
      new RegExp(`from\\s+['"\`]${esc}(/[^'"\`]*)?['"\`]`, "m"),
      new RegExp(`import\\s*\\(\\s*['"\`]${esc}(/[^'"\`]*)?['"\`]\\s*\\)`, "m"),
    );
  }

  else if (eco === "maven") {
    const group    = ns ? ns.replace(/\//g, ".") : "";
    const artifact = name.replace(/[-_]/g, ".");
    const prefix   = group ? `${group}.${artifact}` : artifact;
    const pEsc     = prefix.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(new RegExp(`^\\s*import\\s+${pEsc}\\.`, "m"));
    if (group) {
      const gEsc = group.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      patterns.push(new RegExp(`^\\s*import\\s+${gEsc}\\.`, "m"));
    }
  }

  else if (eco === "nuget") {
    const nEsc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(new RegExp(`^\\s*using\\s+${nEsc}(\\.|;|\\s)`, "m"));
  }

  else if (eco === "php") {
    const vendor = ns ? ns.replace(/\//g, "\\\\") : "";
    const nEsc   = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    if (vendor) {
      const vEsc = vendor.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      patterns.push(new RegExp(`^\\s*use\\s+${vEsc}\\\\`, "m"));
    }
    const fullComposer = ns ? `${ns}/${name}` : name;
    const fcEsc = fullComposer.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(
      new RegExp(`require[_once]*\\s*['"]${fcEsc}`, "m"),
      new RegExp(`^\\s*use\\s+.*${nEsc}`, "m"),
    );
  }

  else if (eco === "go") {
    const full = ns ? `${ns}/${name}` : name;
    const esc  = full.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(new RegExp(`["'\`]${esc}(/[^"'\`]*)?["'\`]`, "m"));
  }

  else if (eco === "cargo") {
    const n = normalizePkgName(name, "cargo");
    patterns.push(
      new RegExp(`^\\s*use\\s+${n}(::|;|\\s)`, "m"),
      new RegExp(`^\\s*extern\\s+crate\\s+${n}(\\s|;)`, "m"),
    );
  }

  else if (eco === "rubygems") {
    const nEsc = name.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    patterns.push(
      new RegExp(`require\\s+['"]${nEsc}['"]`, "m"),
      new RegExp(`require_relative\\s+['"]${nEsc}['"]`, "m"),
    );
  }

  return patterns;
}

// ---------------------------------------------------------------------------
// Source file walker
// ---------------------------------------------------------------------------

/**
 * Recursively walks a directory and returns source files matching `extensions`.
 * @param {string} dir
 * @param {Set<string>} extensions
 * @returns {string[]}
 */
function collectSourceFiles(dir, extensions) {
  const files = [];
  if (!fs.existsSync(dir)) return files;

  function walk(current) {
    let entries;
    try { entries = fs.readdirSync(current, { withFileTypes: true }); }
    catch { return; }

    for (const entry of entries) {
      if (entry.isDirectory()) {
        if (!SKIP_DIRS.has(entry.name)) walk(path.join(current, entry.name));
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!extensions.has(ext)) continue;
        const full = path.join(current, entry.name);
        try {
          if (fs.statSync(full).size <= MAX_FILE_SIZE) files.push(full);
        } catch { /* skip */ }
      }
    }
  }

  walk(dir);
  return files;
}

// ---------------------------------------------------------------------------
// Import scan
// ---------------------------------------------------------------------------

/**
 * Scans source files under projectRoot for imports of the given package.
 *
 * @param {string}  importName  - The resolved import name (may differ from dist name)
 * @param {{ ecosystem: string, name: string, namespace: string }} purlInfo
 * @param {string|null} projectRoot
 * @returns {{ searched: boolean, found: boolean, matchedFiles: string[],
 *             patternsUsed: string[], filesScanned: number,
 *             skippedNoSource: boolean, parentScans: Object }}
 */
function scanImports(importName, purlInfo, projectRoot) {
  const NULL = {
    searched: false, found: false, matchedFiles: [],
    patternsUsed: [], filesScanned: 0, skippedNoSource: false, parentScans: {},
  };
  if (!projectRoot) return NULL;

  const rawEco = purlInfo.ecosystem;
  const eco    = ECOSYSTEM_ALIASES[rawEco] ?? rawEco;
  const resolvedInfo = { ...purlInfo, ecosystem: eco };

  const extensions = ECOSYSTEM_EXTENSIONS[eco];
  if (!extensions) return NULL;

  const patterns = buildImportPatterns(resolvedInfo);
  if (!patterns.length) return NULL;

  const sourceFiles = collectSourceFiles(projectRoot, extensions);
  if (!sourceFiles.length) {
    return {
      searched: true, found: false, matchedFiles: [],
      patternsUsed: patterns.map(p => p.source),
      filesScanned: 0, skippedNoSource: true, parentScans: {},
    };
  }

  const matchedFiles = [];
  for (const fpath of sourceFiles) {
    let content;
    try { content = fs.readFileSync(fpath, "utf8"); }
    catch { continue; }

    for (const pat of patterns) {
      if (pat.test(content)) {
        const rel = path.relative(projectRoot, fpath);
        if (!matchedFiles.includes(rel)) matchedFiles.push(rel);
        break;
      }
    }
  }

  return {
    searched: true,
    found: matchedFiles.length > 0,
    matchedFiles,
    patternsUsed: patterns.map(p => p.source),
    filesScanned: sourceFiles.length,
    skippedNoSource: false,
    parentScans: {},
  };
}

// ---------------------------------------------------------------------------
// Transitive parent import scan
// ---------------------------------------------------------------------------

/**
 * For transitive vulns where the direct import wasn't found, scans each
 * package in introducedBy for imports. If a parent is imported, the
 * vulnerable package is reachable through it.
 *
 * @param {string[]} introducedBy     - Array of parent PURLs
 * @param {{ ecosystem: string }} purlInfo
 * @param {string} projectRoot
 * @returns {Object}  parentPurl → importScanResult
 */
function scanParentImports(introducedBy, purlInfo, projectRoot) {
  const results = {};
  const eco = ECOSYSTEM_ALIASES[purlInfo.ecosystem] ?? purlInfo.ecosystem;

  for (const parentPurl of introducedBy) {
    const parentInfo    = parsePurl(parentPurl);
    const parentEco     = ECOSYSTEM_ALIASES[parentInfo.ecosystem] ?? parentInfo.ecosystem;
    if (parentEco !== eco) continue;

    const distName      = parentInfo.name;
    const importName    = IMPORT_NAME_OVERRIDES[distName.toLowerCase()] ?? distName;
    const parentScanInfo = { ...parentInfo, ecosystem: parentEco, name: importName };
    results[parentPurl]  = scanImports(importName, parentScanInfo, projectRoot);
  }

  return results;
}

// ---------------------------------------------------------------------------
// Graph helpers
// ---------------------------------------------------------------------------

/**
 * Walks the full dependency_graph and collects every package PURL that
 * appears as a child (depended upon by at least one other package).
 * @param {Object} graph
 * @returns {Set<string>}
 */
function collectAllDependents(graph) {
  const dependents = new Set();
  function walk(node) {
    for (const [childPurl, subtree] of Object.entries(node || {})) {
      dependents.add(childPurl);
      if (subtree && typeof subtree === "object") walk(subtree);
    }
  }
  walk(graph);
  return dependents;
}

// ---------------------------------------------------------------------------
// Inventory helpers
// ---------------------------------------------------------------------------

function buildInventoryIndex(inventory) {
  const idx = new Map();
  for (const item of inventory) idx.set(item.id, item);
  return idx;
}

function getScope(inventoryItem) {
  if (!inventoryItem) return "unknown";
  const scopes = inventoryItem.scopes || [];
  if (!scopes.length) return "unknown";
  const s = scopes[0].toLowerCase();
  if (s === "dev" || s === "development") return "dev";
  if (s === "test" || s === "testing")    return "test";
  return "prod";
}

/** Returns true if any of the inventory item's scopes equals "env" (case-insensitive). */
function hasEnvScope(inventoryItem) {
  if (!inventoryItem) return false;
  return (inventoryItem.scopes || []).some(s => s.toLowerCase() === "env");
}

function getPkgType(inventoryItem) {
  if (!inventoryItem) return "unknown";
  return (inventoryItem.type || "unknown").toLowerCase().trim();
}

function getMinDepth(pkgPurl, findingsSummary) {
  for (const finding of Object.values(findingsSummary)) {
    const sequences = finding.affected_dependency_sequences || [];
    const matching  = sequences.filter(s => s && s[s.length - 1] === pkgPurl);
    if (matching.length) return Math.min(...matching.map(s => s.length - 1));
  }
  return 0;
}

function getIntroducedBy(pkgPurl, inventoryIndex) {
  const item = inventoryIndex.get(pkgPurl);
  if (!item) return [];
  return [...new Set(item.introduced_by || [])];
}

function getNumPaths(pkgPurl, findingsSummary) {
  for (const finding of Object.values(findingsSummary)) {
    const sequences = finding.affected_dependency_sequences || [];
    const matching  = sequences.filter(s => s && s[s.length - 1] === pkgPurl);
    if (matching.length) return matching.length;
  }
  return 0;
}

// ---------------------------------------------------------------------------
// Core decision logic
// ---------------------------------------------------------------------------

/**
 * Returns { reachable, level, confidence, rationale, tags }.
 *
 * Priority ladder:
 *   0a. MAL- vuln ID              → total / high (malware record)
 *   0b. env scope in scopes list  → total / high (environment-level exposure)
 *   1. Non-library type           → total / high
 *   2. Dev / test scope           → low  / high
 *   3. Import scan confirmed      → high or medium / HIGH
 *   4a. Direct absent, parent found → medium / medium
 *   4b. Neither found             → low  / medium
 *   5. Orphan tool                → low  / medium
 *   6. Depth + AV heuristics      → varies / LOW
 */
function computeReachability(signals) {
  const { depth, attackVector: av, isOrphanTool, scope,
          numPaths, pkgType, isNonLibrary, isMalware,
          hasEnvScope: envScope, importScan } = signals;
  const imp  = importScan;
  const tags = [];

  // ── 0a: malware record (vuln ID starts with "MAL-")
  if (isMalware) {
    tags.push("malware");
    return {
      reachable: true, level: "critical", confidence: "high", tags,
      rationale: "Vulnerability ID carries the MAL- prefix — this is a malware record "
               + "representing an active supply-chain infection. "
               + "Reachability is unconditional.",
    };
  }

  // ── 0b: env scope — package is part of the runtime environment
  if (envScope) {
    tags.push("env_scope");
    return {
      reachable: true, level: "critical", confidence: "high", tags,
      rationale: "Package scope includes 'env' — this component is part of the execution "
               + "environment itself (OS package, system library, runtime, or container layer). "
               + "Reachability is unconditional.",
    };
  }

  // ── 1: non-library type
  if (isNonLibrary) {
    tags.push("non_library_type", `type:${pkgType}`);
    return {
      reachable: true, level: "critical", confidence: "high", tags,
      rationale: `Package type is '${pkgType}' — not a passive library. `
               + `The vulnerable component IS the executable/framework/service being run; `
               + `reachability is unconditional.`,
    };
  }

  // ── 2: dev/test scope
  if (scope === "dev" || scope === "test") {
    tags.push("dev_scope");
    return {
      reachable: false, level: "low", confidence: "high", tags,
      rationale: `Package is scoped to '${scope}' — not reachable from production code paths.`,
    };
  }

  // ── 3: import scan found a direct match
  if (imp.searched && imp.found) {
    tags.push("import_confirmed");
    tags.push(av === "N" ? "network_av" : `av_${av.toLowerCase()}`);
    const level = (depth === 0 || av === "N") ? "high" : "medium";
    const filesNote = imp.matchedFiles.length
      ? `Found in ${imp.matchedFiles.length} source file(s): `
        + imp.matchedFiles.slice(0, 3).join(", ")
        + (imp.matchedFiles.length > 3 ? " …" : "")
      : "";
    return {
      reachable: true, level, confidence: "high", tags,
      rationale: `Import of this package was found in project source code. `
               + `${filesNote}. Depth=${depth}, AV=${av}.`,
    };
  }

  // ── 4a: direct absent — check parent scans (transitive)
  if (imp.searched && !imp.found && !imp.skippedNoSource) {
    if (depth >= 1 && imp.parentScans && Object.keys(imp.parentScans).length) {
      const foundParents = Object.entries(imp.parentScans)
        .filter(([, scan]) => scan.searched && scan.found);

      if (foundParents.length) {
        tags.push("transitive_via_parent");
        tags.push(av === "N" ? "network_av" : `av_${av.toLowerCase()}`);
        const parentNames = foundParents.slice(0, 3)
          .map(([purl]) => parsePurl(purl).name);
        const filesVia = foundParents.slice(0, 2)
          .flatMap(([, scan]) => scan.matchedFiles.slice(0, 2));
        const filesStr = filesVia.slice(0, 4).join(", ") + (filesVia.length > 4 ? " …" : "");
        const level = av === "N" ? "medium" : "low";
        return {
          reachable: true, level, confidence: "medium", tags,
          rationale: `Direct import not found, but parent package(s) `
                   + `${parentNames.join(", ")} — which depend on this package — `
                   + `are imported in: ${filesStr}. `
                   + `Vulnerable code is reachable if the parent exercises the affected function. `
                   + `Depth=${depth}, AV=${av}.`,
        };
      }
    }

    // ── 4b: no direct or parent import found
    tags.push("import_absent");
    return {
      reachable: false, level: "low", confidence: "medium", tags,
      rationale: `No import of this package was found across ${imp.filesScanned} `
               + `source file(s) scanned, and no importing parent package was found. `
               + `Package appears installed but unused in project code.`,
    };
  }

  // ── 5: orphan tool (no import scan available)
  if (isOrphanTool) {
    tags.push("orphan_tool");
    return {
      reachable: false, level: "low", confidence: "medium", tags,
      rationale: "Root package with no dependents in the dependency graph. "
               + "Standalone tool — not importable by application code.",
    };
  }

  // ── 6: heuristics only
  if (depth === 0 && av === "N") {
    tags.push("root_package", "network_av");
    return {
      reachable: true, level: "high", confidence: "low", tags,
      rationale: "Root-level dependency with network attack vector. No source scan performed — heuristic only.",
    };
  }
  if (depth === 0 && (av === "L" || av === "P")) {
    tags.push("root_package", av === "L" ? "local_av" : "physical_av");
    return {
      reachable: true, level: "medium", confidence: "low", tags,
      rationale: `Root-level dependency with ${av === "L" ? "local" : "physical"} attack vector. No source scan performed — heuristic only.`,
    };
  }
  if (depth >= 1 && av === "N") {
    tags.push("transitive", "network_av");
    const pathsNote = numPaths > 0
      ? `Reachable via ${numPaths} path(s), shortest at depth ${depth}.`
      : `Transitive at depth ${depth}.`;
    return {
      reachable: true, level: "medium", confidence: "low", tags,
      rationale: `Transitive dependency with network attack vector. ${pathsNote} No source scan performed — heuristic only.`,
    };
  }
  if (depth >= 1 && (av === "L" || av === "P")) {
    tags.push("transitive", av === "L" ? "local_av" : "physical_av");
    return {
      reachable: false, level: "low", confidence: "low", tags,
      rationale: `Transitive dependency (depth ${depth}) with ${av === "L" ? "local" : "physical"} attack vector. No source scan performed — heuristic only.`,
    };
  }

  // ── Fallback
  tags.push("unknown_av");
  return {
    reachable: true, level: "medium", confidence: "low", tags,
    rationale: `Attack vector undetermined. Depth=${depth}. Defaulting to reachable with low confidence — heuristic only.`,
  };
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Main entry point. Analyzes a UBEL JSON report.
 *
 * @param {Object}      report       - Parsed UBEL JSON report.
 * @param {string|null} projectRoot  - Optional path to project source root.
 * @returns {Array<{
 *   vulnId: string, affectedPackageId: string,
 *   reachable: boolean, level: string, confidence: string,
 *   signals: Object, rationale: string, tags: string[]
 * }>}
 */
export function analyzeReachability(report, projectRoot = null) {
  const vulnerabilities  = report.vulnerabilities  || [];
  const findingsSummary  = report.findings_summary  || {};
  const inventory        = report.inventory        || [];
  const dependencyGraph  = report.dependency_graph  || {};

  const inventoryIndex   = buildInventoryIndex(inventory);
  const allDependents    = collectAllDependents(dependencyGraph);
  const graphRoots       = new Set(Object.keys(dependencyGraph));

  return vulnerabilities.map(vuln => {
    const vulnId         = vuln.id || "unknown";
    const pkgPurl        = vuln.affected_package_id || "";
    const severityVector = vuln.severity_vector || "";

    const purlInfo       = parsePurl(pkgPurl);
    const av             = extractAttackVector(severityVector);
    const inventoryItem  = inventoryIndex.get(pkgPurl);
    const scope          = getScope(inventoryItem);
    const pkgType        = getPkgType(inventoryItem);
    const isNonLibrary   = NON_LIBRARY_TYPES.has(pkgType);
    const isMalware      = vulnId.startsWith("MAL-");
    const envScope       = hasEnvScope(inventoryItem);
    const introducedBy   = getIntroducedBy(pkgPurl, inventoryIndex);
    const depth          = getMinDepth(pkgPurl, findingsSummary);
    const numPaths       = getNumPaths(pkgPurl, findingsSummary);
    const isOrphanTool   = graphRoots.has(pkgPurl) && !allDependents.has(pkgPurl);

    // Import scan — skip if non-library (already total), malware (already total),
    // env-scoped (already total), or dev/test (already low)
    const runImportScan  = projectRoot !== null && !isNonLibrary
                           && !isMalware && !envScope
                           && scope !== "dev" && scope !== "test";

    let importScan;
    if (runImportScan) {
      const rawEco     = purlInfo.ecosystem;
      const eco        = ECOSYSTEM_ALIASES[rawEco] ?? rawEco;
      const distName   = purlInfo.name;
      const importName = IMPORT_NAME_OVERRIDES[distName.toLowerCase()] ?? distName;
      const resolvedInfo = { ...purlInfo, ecosystem: eco, name: importName };

      importScan = scanImports(importName, resolvedInfo, projectRoot);

      // Transitive: direct not found → check parents
      if (
        importScan.searched && !importScan.found &&
        !importScan.skippedNoSource && depth >= 1 && introducedBy.length
      ) {
        const resolvedInfoForParent = { ...purlInfo, ecosystem: eco };
        importScan.parentScans = scanParentImports(
          introducedBy, resolvedInfoForParent, projectRoot
        );
      }
    } else {
      importScan = {
        searched: false, found: false, matchedFiles: [],
        patternsUsed: [], filesScanned: 0, skippedNoSource: false, parentScans: {},
      };
    }

    const signals = {
      depth, attackVector: av, isOrphanTool, scope, numPaths,
      introducedByCount: introducedBy.length, pkgType, isNonLibrary,
      isMalware, hasEnvScope: envScope,
      importScan, introducedBy,
    };

    const { reachable, level, confidence, rationale, tags } =
      computeReachability(signals);

    return { vulnId, affectedPackageId: pkgPurl, reachable, level, confidence, signals, rationale, tags };
  });
}

/**
 * Annotates each vulnerability in report.vulnerabilities with a
 * "reachability" block. Mutates and returns the report.
 *
 * @param {Object}      report
 * @param {string|null} projectRoot
 * @returns {Object}
 */
export function enrichReport(report, projectRoot = null) {
  const results   = analyzeReachability(report, projectRoot);
  const resultMap = new Map(results.map(r => [r.vulnId, r]));

  for (const vuln of (report.vulnerabilities || [])) {
    const r = resultMap.get(vuln.id);
    if (!r) continue;
    const imp = r.signals.importScan;
    vuln.reachability = {
      reachable:  r.reachable,
      level:      r.level,
      confidence: r.confidence,
      rationale:  r.rationale,
      tags:       r.tags,
      signals: {
        depth:                r.signals.depth,
        attack_vector:        r.signals.attackVector,
        is_orphan_tool:       r.signals.isOrphanTool,
        scope:                r.signals.scope,
        num_paths:            r.signals.numPaths,
        introduced_by_count:  r.signals.introducedByCount,
        pkg_type:             r.signals.pkgType,
        is_non_library:       r.signals.isNonLibrary,
        is_malware:           r.signals.isMalware,
        has_env_scope:        r.signals.hasEnvScope,
        import_scan: {
          searched:        imp.searched,
          found:           imp.found,
          matched_files:   imp.matchedFiles,
          files_scanned:   imp.filesScanned,
          skipped_no_source: imp.skippedNoSource,
          parent_scans: Object.fromEntries(
            Object.entries(imp.parentScans || {}).map(([purl, s]) => [purl, {
              found: s.found, matched_files: s.matchedFiles, files_scanned: s.filesScanned,
            }])
          ),
        },
      },
    };
  }
  return report;
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

function printSummary(results) {
  const RESET   = "\x1b[0m";
  const RED     = "\x1b[91m";
  const YELLOW  = "\x1b[93m";
  const GREEN   = "\x1b[92m";
  const CYAN    = "\x1b[96m";
  const MAGENTA = "\x1b[95m";
  const BOLD    = "\x1b[1m";
  const DIM     = "\x1b[2m";

  const levelColor  = { total: MAGENTA, high: RED, medium: YELLOW, low: GREEN };
  const confColor   = { high: GREEN, medium: YELLOW, low: DIM };

  console.log(`\n${BOLD}${"─".repeat(76)}${RESET}`);
  console.log(`${BOLD}  UBEL Reachability Analysis${RESET}`);
  console.log(`${BOLD}${"─".repeat(76)}${RESET}\n`);

  for (const r of results) {
    const reachLabel = r.reachable
      ? `${RED}● REACHABLE${RESET}` : `${GREEN}○ UNREACHABLE${RESET}`;
    const lc = levelColor[r.level] || "";
    const cc = confColor[r.confidence] || "";
    const imp = r.signals.importScan;

    console.log(`  ${BOLD}${r.vulnId}${RESET}`);
    console.log(`  Package    : ${CYAN}${r.affectedPackageId}${RESET}  [type: ${r.signals.pkgType}]`);
    console.log(`  Status     : ${reachLabel}`);
    console.log(`  Level      : ${lc}${r.level.toUpperCase()}${RESET}   Confidence: ${cc}${r.confidence.toUpperCase()}${RESET}`);
    console.log(`  Signals    : depth=${r.signals.depth}  AV=${r.signals.attackVector}  orphan=${r.signals.isOrphanTool}  scope=${r.signals.scope}  paths=${r.signals.numPaths}  non_lib=${r.signals.isNonLibrary}  malware=${r.signals.isMalware}  env_scope=${r.signals.hasEnvScope}`);

    if (imp.searched) {
      if (imp.skippedNoSource) {
        console.log(`  Import scan: ${DIM}no source files found${RESET}`);
      } else if (imp.found) {
        const fileStr = imp.matchedFiles.slice(0, 2).join(", ")
          + (imp.matchedFiles.length > 2 ? " …" : "");
        console.log(`  Import scan: ${GREEN}FOUND${RESET} in ${imp.matchedFiles.length} file(s) [scanned ${imp.filesScanned}] → ${DIM}${fileStr}${RESET}`);
      } else {
        console.log(`  Import scan: ${YELLOW}NOT FOUND${RESET} [scanned ${imp.filesScanned} files]`);
      }
    } else {
      console.log(`  Import scan: ${DIM}not performed${RESET}`);
    }

    console.log(`  Tags       : ${r.tags.length ? r.tags.join(", ") : "—"}`);
    console.log(`  Rationale  : ${DIM}${r.rationale}${RESET}`);
    console.log();
  }

  const reachableCount   = results.filter(r => r.reachable).length;
  const unreachableCount = results.length - reachableCount;
  const totalCount       = results.filter(r => r.level === "critical").length;

  console.log(`${BOLD}${"─".repeat(76)}${RESET}`);
  console.log(`  Total vulns : ${results.length}  │  ${MAGENTA}Total: ${totalCount}${RESET}  │  ${RED}Reachable: ${reachableCount}${RESET}  │  ${GREEN}Unreachable: ${unreachableCount}${RESET}`);
  console.log(`${BOLD}${"─".repeat(76)}${RESET}\n`);
}

// Run as CLI if invoked directly
if (process.argv[1] && path.resolve(process.argv[1]) === path.resolve(new URL(import.meta.url).pathname)) {
  const args        = process.argv.slice(2);
  const reportPath  = args.find(a => !a.startsWith("--"));
  const enrichMode  = args.includes("--enrich");
  const rootIdx     = args.indexOf("--project-root");
  const projectRoot = rootIdx !== -1 ? args[rootIdx + 1] : null;

  if (!reportPath) {
    console.error("Usage: node reachability_analyzer.js <report.json> [--project-root <path>] [--enrich]");
    process.exit(1);
  }

  const report  = JSON.parse(fs.readFileSync(reportPath, "utf8"));
  const results = analyzeReachability(report, projectRoot);
  printSummary(results);

  if (enrichMode) {
    const enriched = enrichReport(report, projectRoot);
    const outPath  = reportPath.replace(/\.json$/, ".enriched.json");
    fs.writeFileSync(outPath, JSON.stringify(enriched, null, 2));
    console.log(`  Enriched report written to: ${outPath}\n`);
  }
}