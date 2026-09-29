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
 *   - project source     → import/require scan (optional, 10 ecosystems:
 *                          python, npm, maven, nuget, php, go, cargo, rubygems,
 *                          dart/flutter (pub), swift (SwiftPM + Carthage))
 *
 * Import scanning is batched: every source file under projectRoot is read
 * exactly once. Files are bucketed by ecosystem (via extension), and each
 * file is tested against the import patterns of every vulnerable component
 * (and every candidate transitive parent) that shares its ecosystem — not
 * re-walked/re-read once per vulnerability. The resulting component→
 * reachability-signal map is then used to classify each vulnerability
 * through the same priority ladder as before.
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
  dart:     new Set([".dart"]),
  // Objective-C sources are included because Carthage/SwiftPM frameworks are
  // routinely consumed from ObjC via `@import Module;` / `#import <Module/…>`.
  swift:    new Set([".swift", ".m", ".mm", ".h"]),
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
  pub:         "dart",      // flutter_runner.js emits pkg:pub/… (ecosystem label "dart")
  dart:        "dart",
  flutter:     "dart",
  swift:       "swift",     // swift_runner.js emits pkg:swift/<host>/<owner>/<repo>
};

/**
 * Ecosystems whose import name is NOT derived from IMPORT_NAME_OVERRIDES.
 * That table is keyed by bare package name and holds PyPI/npm/Ruby/.NET
 * distribution→module mappings; applying it here would corrupt lookups
 * (e.g. the pub.dev package `protobuf` would be rewritten to the Python
 * import name `google.protobuf`). Dart imports use the package name verbatim,
 * and Swift resolves module names through SWIFT_MODULE_OVERRIDES instead.
 */
const NO_NAME_OVERRIDE_ECOSYSTEMS = new Set(["dart", "swift"]);

/**
 * Swift: repository name (lowercase, no ".git") → module names it exports.
 *
 * A SwiftPM package is identified by its repository, but source files import
 * *modules* (library products), and the two rarely match (swift-log → Logging).
 * When an entry exists it is used INSTEAD of the name heuristics in
 * swiftModuleCandidates(). A trailing "*" means "any module with this prefix"
 * (e.g. "Firebase*" → FirebaseCore, FirebaseAuth, …). Matching is
 * case-insensitive. This is a seed list of packages whose module names can't
 * be derived from the repo name — anything not listed falls back to the
 * heuristics.
 */
const SWIFT_MODULE_OVERRIDES = {
  "swift-nio":              ["NIO*"],
  "swift-log":              ["Logging"],
  "swift-metrics":          ["Metrics", "CoreMetrics"],
  "swift-crypto":           ["Crypto", "_CryptoExtras"],
  "swift-certificates":     ["X509"],
  "swift-collections":      ["Collections", "DequeModule", "OrderedCollections",
                             "HeapModule", "BitCollections", "HashTreeCollections"],
  "swift-numerics":         ["Numerics", "RealModule", "ComplexModule"],
  "swift-system":           ["SystemPackage"],
  "swift-http-types":       ["HTTPTypes", "HTTPTypesFoundation"],
  "swift-foundation":       ["FoundationEssentials", "FoundationInternationalization"],
  "swift-syntax":           ["SwiftSyntax*", "SwiftParser*", "SwiftDiagnostics",
                             "SwiftOperators", "SwiftBasicFormat", "SwiftCompilerPlugin"],
  "grpc-swift":             ["GRPC*"],
  "firebase-ios-sdk":       ["Firebase*"],
  "rxswift":                ["RxSwift", "RxCocoa", "RxRelay", "RxBlocking", "RxTest"],
  "moya":                   ["Moya", "RxMoya", "ReactiveMoya", "CombineMoya"],
  "sentry-cocoa":           ["Sentry*"],
  "stripe-ios":             ["Stripe*"],
  "facebook-ios-sdk":       ["FBSDK*", "Facebook*"],
  "googlesignin-ios":       ["GoogleSignIn*"],
  "charts":                 ["Charts", "DGCharts"],
  "ohhttpstubs":            ["OHHTTPStubs", "OHHTTPStubsSwift"],
};

/**
 * Swift: heuristic module names that would collide with modules shipped in the
 * toolchain / SDK. `import Foundation` must never count as evidence for a
 * package that merely has "foundation" in its repo name.
 */
const SWIFT_SYSTEM_MODULES = new Set([
  "swift", "foundation", "dispatch", "darwin", "glibc", "os", "uikit", "appkit",
  "swiftui", "combine", "xctest", "coredata", "cryptokit", "coregraphics",
]);

/**
 * Dart/Flutter: federated-plugin platform packages (url_launcher_android,
 * path_provider_foundation, …). Apps never import these directly — the
 * endorsed implementation is linked in automatically by the app-facing
 * package — so without this an installed, actively-running platform
 * implementation would always be reported "imported nowhere". The capture
 * group is the app-facing package whose import is treated as evidence.
 */
const DART_PLATFORM_IMPL_RE =
  /^(.+?)_(?:android(?:_camerax)?|ios|linux|macos|windows|web|for_web|darwin|foundation|avfoundation|storekit|platform_interface)$/;

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
  // Dart / Flutter: generated tool state and the pub cache
  ".dart_tool", ".pub-cache", ".symlinks",
  // Swift / Apple: SwiftPM checkouts (.build/checkouts holds every dependency's
  // own source, which would make each package "import itself"), Xcode & Carthage
  ".build", ".swiftpm", "Pods", "Carthage", "DerivedData", ".gradle",
]);

/** Max file size to scan (bytes). */
const MAX_FILE_SIZE = 512 * 1024;

/** Shared shape for "no scan performed / nothing found" results. */
function nullImportScan(overrides = {}) {
  return {
    searched: false, found: false, matchedFiles: [],
    patternsUsed: [], filesScanned: 0, skippedNoSource: false,
    parentScans: {},
    ...overrides,
  };
}

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

  else if (eco === "dart") {
    // Dart imports are always `package:<pubspec name>/…` — no name mapping.
    // A federated platform implementation is also evidenced by its
    // app-facing package (see DART_PLATFORM_IMPL_RE).
    const names = [name];
    const impl  = name.match(DART_PLATFORM_IMPL_RE);
    if (impl) names.push(impl[1]);

    for (const n of names) {
      const nEsc = n.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      patterns.push(
        // import 'package:x/x.dart' [as y | show … | hide …];  export 'package:x/…';
        new RegExp(`^\\s*(?:import|export)\\s+['"]package:${nEsc}/`, "m"),
        // conditional-import continuation lines:  if (dart.library.io) 'package:x/io.dart'
        new RegExp(`^\\s*if\\s*\\([^)]*\\)\\s*['"]package:${nEsc}/`, "m"),
      );
    }
  }

  else if (eco === "swift") {
    const mods = swiftModuleCandidates(name);
    if (mods.length) {
      const alt = mods.map(swiftModuleRegexSource).join("|");
      patterns.push(
        // import Mod · @testable import Mod · @_exported import Mod
        // public/package/internal import Mod (Swift 6) · import struct Mod.Type · import Mod.Sub
        new RegExp(
          `^\\s*(?:@\\w+(?:\\([^)]*\\))?\\s+)*`
          + `(?:(?:public|package|internal|fileprivate|private|open)\\s+)?`
          + `import\\s+(?:(?:typealias|struct|class|enum|protocol|let|var|func)\\s+)?`
          + `(?:${alt})(?![A-Za-z0-9_])`,
          "mi",
        ),
        // Objective-C:  @import Mod;   #import <Mod/Header.h>   #include "Mod/Header.h"
        new RegExp(`^\\s*@import\\s+(?:${alt})(?![A-Za-z0-9_])`, "mi"),
        new RegExp(`^\\s*#\\s*(?:import|include)\\s+[<"](?:${alt})/`, "mi"),
      );
    }
  }

  return patterns;
}

/**
 * Swift: the module names a package's source files would import.
 *
 * SWIFT_MODULE_OVERRIDES wins outright when it has the repo. Otherwise the
 * candidates are derived from the repository name — the separators dropped
 * (swift-argument-parser → "swiftargumentparser"), the same with the
 * conventional "swift-" / "-swift" / "-ios" / "-cocoa" affixes removed
 * (→ "argumentparser"), and the underscore form SwiftPM uses when a target
 * name contains "-" or "." (→ "swift_argument_parser"). Matching is
 * case-insensitive, so "argumentparser" matches `import ArgumentParser`.
 *
 * @param {string} repoName  Last path segment of the PURL (repo name).
 * @returns {string[]}       Module names; a trailing "*" marks a prefix match.
 */
function swiftModuleCandidates(repoName) {
  const key = String(repoName || "").toLowerCase().replace(/\.git$/, "");
  if (!key) return [];
  if (SWIFT_MODULE_OVERRIDES[key]) return SWIFT_MODULE_OVERRIDES[key];

  const flat     = (s) => s.replace(/[^a-z0-9]/g, "");
  const under    = (s) => s.replace(/[-.]/g, "_");
  const stripped = key
    .replace(/^swift[-_.]/, "")
    .replace(/[-_.](?:swift|ios|ios[-_]sdk|macos|cocoa|apple)$/, "");

  const out = new Set();
  for (const c of [flat(key), flat(stripped), under(key), under(stripped)]) {
    if (c.length >= 2 && !SWIFT_SYSTEM_MODULES.has(c)) out.add(c);
  }
  return [...out];
}

/** Regex source for one Swift module candidate ("*" suffix → identifier-char run). */
function swiftModuleRegexSource(mod) {
  const prefix = mod.endsWith("*");
  const esc    = (prefix ? mod.slice(0, -1) : mod).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  return prefix ? `${esc}[A-Za-z0-9_]*` : esc;
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
// Component scan registry — decide WHAT needs scanning, ecosystem-agnostic
// ---------------------------------------------------------------------------

/**
 * Resolves a purl to its scannable form: canonical ecosystem, resolved
 * import name (post-override), and pre-built regex patterns. Returns null
 * if the purl's ecosystem has no known source extensions (unsupported).
 *
 * @param {string} purl
 * @returns {{ ecosystem: string, patterns: RegExp[] }|null}
 */
function resolveScanTarget(purl) {
  const info = parsePurl(purl);
  const eco  = ECOSYSTEM_ALIASES[info.ecosystem] ?? info.ecosystem;
  if (!ECOSYSTEM_EXTENSIONS[eco]) return null;

  const importName   = NO_NAME_OVERRIDE_ECOSYSTEMS.has(eco)
    ? info.name
    : (IMPORT_NAME_OVERRIDES[info.name.toLowerCase()] ?? info.name);
  const resolvedInfo = { ...info, ecosystem: eco, name: importName };
  const patterns      = buildImportPatterns(resolvedInfo);
  if (!patterns.length) return null;

  return { ecosystem: eco, patterns };
}

/**
 * Determines whether a vulnerability's package is even eligible for an
 * import scan (mirrors the ladder's early short-circuits: non-library,
 * malware, env-scoped, and dev/test packages are decided without one).
 */
function isEligibleForImportScan(vuln, inventoryIndex) {
  const pkgPurl       = vuln.affected_package_id || "";
  const inventoryItem = inventoryIndex.get(pkgPurl);
  const scope         = getScope(inventoryItem);
  const pkgType       = getPkgType(inventoryItem);
  const isNonLibrary  = NON_LIBRARY_TYPES.has(pkgType);
  const isMalware     = (vuln.id || "").startsWith("MAL-");
  const envScope      = hasEnvScope(inventoryItem);

  return !isNonLibrary && !isMalware && !envScope
      && scope !== "dev" && scope !== "test";
}

/**
 * Walks every vulnerability once and builds the set of component purls
 * that need an import scan — the vulnerable package itself, plus every
 * introduced_by parent (candidate transitive carriers) — so the file walk
 * below can check every file against every needed component in one pass.
 *
 * @param {Object} report
 * @param {Map}    inventoryIndex
 * @returns {Map<string, {ecosystem: string, patterns: RegExp[]}|null>}
 */
function buildScanRegistry(report, inventoryIndex) {
  const vulnerabilities = report.vulnerabilities || [];
  const registry = new Map(); // purl -> resolveScanTarget() result

  const register = (purl) => {
    if (!purl || registry.has(purl)) return;
    registry.set(purl, resolveScanTarget(purl));
  };

  for (const vuln of vulnerabilities) {
    if (!isEligibleForImportScan(vuln, inventoryIndex)) continue;

    const pkgPurl = vuln.affected_package_id || "";
    register(pkgPurl);
    for (const parentPurl of getIntroducedBy(pkgPurl, inventoryIndex)) {
      register(parentPurl);
    }
  }

  return registry;
}

// ---------------------------------------------------------------------------
// Single-pass batched scan — every file read once, checked against every
// registered component sharing its ecosystem
// ---------------------------------------------------------------------------

/**
 * Runs the registry against the project source tree in one pass per
 * ecosystem: each file belonging to that ecosystem is read exactly once
 * and tested against every registered component's patterns.
 *
 * @param {Map}    registry     - from buildScanRegistry()
 * @param {string|null} projectRoot
 * @returns {Map<string, Object>}  purl → import-scan result
 */
function runBatchedScan(registry, projectRoot) {
  const results = new Map();

  if (!projectRoot) {
    for (const purl of registry.keys()) results.set(purl, nullImportScan());
    return results;
  }

  // Bucket registered components by ecosystem so each ecosystem's file set
  // is walked exactly once, regardless of how many components share it.
  const byEcosystem = new Map(); // ecosystem -> [purl, ...]
  for (const [purl, target] of registry.entries()) {
    if (!target) {
      results.set(purl, nullImportScan()); // unsupported ecosystem
      continue;
    }
    if (!byEcosystem.has(target.ecosystem)) byEcosystem.set(target.ecosystem, []);
    byEcosystem.get(target.ecosystem).push(purl);
  }

  for (const [eco, purls] of byEcosystem.entries()) {
    const extensions = ECOSYSTEM_EXTENSIONS[eco];
    const files       = collectSourceFiles(projectRoot, extensions);

    for (const purl of purls) {
      results.set(purl, nullImportScan({
        searched:        true,
        patternsUsed:    registry.get(purl).patterns.map(p => p.source),
        filesScanned:    files.length,
        skippedNoSource: files.length === 0,
      }));
    }
    if (!files.length) continue;

    // Each file is read once and checked against every component
    // registered for this ecosystem.
    for (const fpath of files) {
      let content;
      try { content = fs.readFileSync(fpath, "utf8"); }
      catch { continue; }
      const rel = path.relative(projectRoot, fpath);

      for (const purl of purls) {
        const target = registry.get(purl);
        const result = results.get(purl);
        for (const pat of target.patterns) {
          if (pat.test(content)) {
            if (!result.matchedFiles.includes(rel)) result.matchedFiles.push(rel);
            result.found = true;
            break;
          }
        }
      }
    }
  }

  return results;
}

/**
 * Builds the parentScans map for a single vulnerable component, from the
 * already-batched scan results — no re-scanning. Mirrors the original
 * same-ecosystem-only filter.
 *
 * @param {string[]} introducedBy
 * @param {string}   pkgEcosystem  - canonical ecosystem of the vulnerable pkg
 * @param {Map}      scanResults
 * @returns {Object}
 */
function buildParentScans(introducedBy, pkgEcosystem, scanResults) {
  const results = {};
  for (const parentPurl of introducedBy) {
    const parentInfo = parsePurl(parentPurl);
    const parentEco  = ECOSYSTEM_ALIASES[parentInfo.ecosystem] ?? parentInfo.ecosystem;
    if (parentEco !== pkgEcosystem) continue;
    results[parentPurl] = scanResults.get(parentPurl) || nullImportScan();
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
// Core decision logic — priority ladder (unchanged)
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
 * Import scanning happens once for the whole report: every vulnerable
 * component (and every candidate transitive parent) is registered up
 * front, the project source tree is walked once per ecosystem involved,
 * and each file is checked against every registered component in that
 * ecosystem. The cached per-component results are then combined with
 * each vulnerability's own signals (AV, malware-ID) and run through the
 * unchanged priority ladder.
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

  // ── Batched, single-pass import scan across every component up front ──
  const scanRegistry = buildScanRegistry(report, inventoryIndex);
  const scanResults   = runBatchedScan(scanRegistry, projectRoot);

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

    const runImportScan  = projectRoot !== null && !isNonLibrary
                           && !isMalware && !envScope
                           && scope !== "dev" && scope !== "test";

    let importScan;
    if (runImportScan) {
      const cached = scanResults.get(pkgPurl) || nullImportScan();
      const target = scanRegistry.get(pkgPurl); // { ecosystem, patterns } or null

      // Transitive: direct not found → attach cached parent scans (no re-scan)
      let parentScans = {};
      if (
        cached.searched && !cached.found && !cached.skippedNoSource &&
        depth >= 1 && introducedBy.length && target
      ) {
        parentScans = buildParentScans(introducedBy, target.ecosystem, scanResults);
      }
      importScan = { ...cached, parentScans };
    } else {
      importScan = nullImportScan();
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