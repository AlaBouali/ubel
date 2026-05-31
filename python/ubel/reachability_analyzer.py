"""
UBEL Reachability Analyzer
===========================
Analyzes a UBEL JSON report and annotates each vulnerability with a
reachability assessment derived from existing report fields plus an
optional import scan over the project's source files.

Signals used (in priority order):
  1. Package type != "library"  → total reachability (executable/plugin/framework)
  2. scope = dev/test           → unreachable
  3. Import scan (optional)     → confirmed reachable or confirmed absent
  4. Orphan tool pattern        → unreachable
  5. Depth + Attack Vector      → heuristic level

Import scan coverage:
  Python   (.py)           → import <pkg> / from <pkg>
  Node.js  (.js .ts .mjs)  → require('<pkg>') / from '<pkg>'
  Maven    (.java .kt)     → import <group>.<artifact>
  NuGet    (.cs .vb .fs)   → using <Namespace>
  PHP      (.php)          → use <Vendor>\\ / require '<pkg>'
  Go       (.go)           → "<module-path>"
  Rust     (.rs)           → use <crate>:: / extern crate <crate>
  Ruby     (.rb)           → require '<gem>'

Zero external dependencies.
"""

import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# Package types that are NOT pure libraries — the vulnerable code is the
# product itself (a binary, framework, plugin, application, OS package, etc.)
# Any vuln in these is "critical" — the whole thing is the attack surface.
NON_LIBRARY_TYPES = {
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
    # OS-level package managers
    "deb", "rpm", "apk", "snap", "flatpak",
}

# Source file extensions per ecosystem
ECOSYSTEM_EXTENSIONS = {
    "python":  {".py"},
    "npm":     {".js", ".ts", ".mjs", ".cjs", ".jsx", ".tsx"},
    "maven":   {".java", ".kt", ".groovy", ".scala"},
    "nuget":   {".cs", ".vb", ".fs", ".fsx"},
    "php":     {".php"},
    "go":      {".go"},
    "cargo":   {".rs"},
    "rubygems":{".rb"},
}

# PURL type → canonical ecosystem key used in ECOSYSTEM_EXTENSIONS and pattern builders.
# UBEL report "ecosystem" field and PURL type don't always match the keys above.
ECOSYSTEM_ALIASES = {
    # Python
    "pypi":        "python",
    "python":      "python",
    # Node / JS
    "npm":         "npm",
    "node":        "npm",
    # JVM
    "maven":       "maven",
    "gradle":      "maven",
    # .NET
    "nuget":       "nuget",
    "dotnet":      "nuget",
    # PHP
    "packagist":   "php",
    "composer":    "php",
    "php":         "php",
    # Go
    "golang":      "go",
    "go":          "go",
    # Rust
    "cargo":       "cargo",
    "rust":        "cargo",
    # Ruby
    "gem":         "rubygems",
    "rubygems":    "rubygems",
    "ruby":        "rubygems",
}

# Some packages are imported under a different name than their distribution name.
# Keys are lowercase distribution names (as they appear in PURL / lockfiles).
# Values are the actual Python/JS/etc. module names used in import statements.
IMPORT_NAME_OVERRIDES = {
    # Python
    "beautifulsoup4":       "bs4",
    "pyyaml":               "yaml",
    "pillow":               "PIL",
    "scikit-learn":         "sklearn",
    "scikit-image":         "skimage",
    "opencv-python":        "cv2",
    "opencv-python-headless": "cv2",
    "python-dateutil":      "dateutil",
    "python-dotenv":        "dotenv",
    "python-jose":          "jose",
    "python-multipart":     "multipart",
    "python-slugify":       "slugify",
    "email-validator":      "email_validator",
    "typing-extensions":    "typing_extensions",
    "attrs":                "attr",
    "pyzmq":                "zmq",
    "pyjwt":                "jwt",
    "mysqlclient":          "MySQLdb",
    "psycopg2-binary":      "psycopg2",
    "psycopg2":             "psycopg2",
    "google-auth":          "google.auth",
    "google-cloud-storage": "google.cloud.storage",
    "grpcio":               "grpc",
    "protobuf":             "google.protobuf",
    "cryptography":         "cryptography",
    "pyopenssl":            "OpenSSL",
    "httpx":                "httpx",
    "aiohttp":              "aiohttp",
    "werkzeug":             "werkzeug",
    "markupsafe":           "markupsafe",
    "itsdangerous":         "itsdangerous",
    "jinja2":               "jinja2",
    "flask":                "flask",
    "django":               "django",
    "fastapi":              "fastapi",
    "starlette":            "starlette",
    "sqlalchemy":           "sqlalchemy",
    "alembic":              "alembic",
    "celery":               "celery",
    "redis":                "redis",
    "pymongo":              "pymongo",
    "boto3":                "boto3",
    "botocore":             "botocore",
    "paramiko":             "paramiko",
    "requests":             "requests",
    "urllib3":              "urllib3",
    "certifi":              "certifi",
    "charset-normalizer":   "charset_normalizer",
    # Node.js  (package name → require name, mostly identical but aliased cases)
    "@babel/core":          "@babel/core",
    "lodash.merge":         "lodash",
    "moment":               "moment",
    # Ruby
    "nokogiri":             "nokogiri",
    "activesupport":        "active_support",
    # .NET
    "newtonsoft.json":      "Newtonsoft.Json",
    "microsoft.extensions.logging": "Microsoft.Extensions.Logging",
}

# Directories to always skip during source scan
SKIP_DIRS = {
    "node_modules", ".git", "__pycache__", ".tox", "venv", ".venv",
    "env", ".env", "dist", "build", "target", "vendor",
    ".idea", ".vscode", "coverage", ".mypy_cache", ".pytest_cache",
}

# Max file size to scan (bytes) — skip huge generated files
MAX_FILE_SIZE = 512 * 1024  # 512 KB


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ImportScanResult:
    searched: bool          # was a scan attempted?
    found: bool             # was an import of this pkg found?
    matched_files: list     # list of relative file paths where found
    patterns_used: list     # regex patterns that were tried
    files_scanned: int      # total source files examined
    skipped_no_source: bool # True if project_root had no relevant source files
    # Transitive parent scan results (populated only when direct scan found nothing)
    # Maps parent_purl → ImportScanResult for each parent that was scanned
    parent_scans: dict = None

    def __post_init__(self):
        if self.parent_scans is None:
            self.parent_scans = {}


@dataclass
class ReachabilitySignals:
    depth: int
    attack_vector: str
    is_orphan_tool: bool
    scope: str
    num_paths: int
    introduced_by_count: int
    pkg_type: str
    is_non_library: bool
    is_malware: bool         # True when vuln_id starts with "MAL-"
    has_env_scope: bool      # True when inventory item's scopes list contains "env"
    import_scan: ImportScanResult
    introduced_by: list = None   # raw list of parent PURLs (for transitive scan)

    def __post_init__(self):
        if self.introduced_by is None:
            self.introduced_by = []


@dataclass
class ReachabilityResult:
    vuln_id: str
    affected_package_id: str
    reachable: bool
    level: str              # total / high / medium / low
    confidence: str         # high / medium / low
    signals: ReachabilitySignals
    rationale: str
    tags: list = field(default_factory=list)


# ---------------------------------------------------------------------------
# PURL helpers
# ---------------------------------------------------------------------------

def _parse_purl(purl: str) -> dict:
    """
    Minimal PURL parser. Returns dict with keys:
      ecosystem, name, namespace, version
    e.g. pkg:pypi/idna@3.13
         pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1
         pkg:npm/%40scope/pkg@1.0.0
    """
    result = {"ecosystem": "", "name": "", "namespace": "", "version": ""}
    if not purl or not purl.startswith("pkg:"):
        return result
    body = purl[4:]  # strip "pkg:"
    eco, _, rest = body.partition("/")
    result["ecosystem"] = eco.lower()
    # version
    if "@" in rest:
        path, _, version = rest.rpartition("@")
        result["version"] = version
    else:
        path = rest
    # namespace / name
    path = path.replace("%40", "@").replace("%2F", "/")
    if "/" in path:
        ns, _, name = path.rpartition("/")
        result["namespace"] = ns
        result["name"] = name
    else:
        result["name"] = path
    return result


# ---------------------------------------------------------------------------
# Import pattern builders  (per ecosystem)
# ---------------------------------------------------------------------------

def _normalize_pkg_name(name: str, ecosystem: str) -> str:
    """Normalize package name for pattern matching."""
    if ecosystem in ("python", "pypi"):
        # pip normalizes - and _ interchangeably
        return name.replace("-", "[-_]").replace("_", "[-_]")
    if ecosystem in ("cargo", "rust"):
        return name.replace("-", "[-_]").replace("_", "[-_]")
    return re.escape(name)


def _build_import_patterns(purl_info: dict) -> list:
    """
    Returns a list of compiled regex patterns for detecting imports of
    this package in source files, based on ecosystem.
    """
    eco   = purl_info["ecosystem"]
    name  = purl_info["name"]
    ns    = purl_info["namespace"]   # e.g. org.apache.logging.log4j for maven
    patterns = []

    if eco in ("pypi", "python"):
        n = _normalize_pkg_name(name, "python")
        # import idna
        # from idna import ...
        # import idna.core
        patterns += [
            re.compile(rf"^\s*import\s+{n}(\s|$|\.)", re.MULTILINE | re.IGNORECASE),
            re.compile(rf"^\s*from\s+{n}(\s|\.|$)", re.MULTILINE | re.IGNORECASE),
        ]

    elif eco == "npm":
        # require('idna') / require("idna")
        # from 'idna' / from "idna"
        # Scoped: @scope/pkg
        full = f"{ns}/{name}" if ns else name
        full_esc = re.escape(full)
        # also match prefix: require('idna/something')
        patterns += [
            re.compile(rf"""require\s*\(\s*['"`]{full_esc}(/[^'"`]*)?\s*['"`]\s*\)""", re.MULTILINE),
            re.compile(rf"""from\s+['"`]{full_esc}(/[^'"`]*)?\s*['"`]""", re.MULTILINE),
            re.compile(rf"""import\s*\(\s*['"`]{full_esc}(/[^'"`]*)?\s*['"`]\s*\)""", re.MULTILINE),
        ]

    elif eco == "maven":
        # import org.apache.logging.log4j.LogManager;
        # Maven group = namespace, artifact = name
        # Build a prefix from groupId + artifactId
        group = ns.replace("/", ".") if ns else ""
        artifact = name.replace("-", ".").replace("_", ".")
        prefix = f"{group}.{artifact}" if group else artifact
        prefix_esc = re.escape(prefix)
        patterns += [
            re.compile(rf"^\s*import\s+{prefix_esc}\.", re.MULTILINE),
            re.compile(rf"^\s*import\s+{re.escape(group)}\.", re.MULTILINE) if group else None,
        ]
        patterns = [p for p in patterns if p]

    elif eco == "nuget":
        # using Newtonsoft.Json;
        # using Newtonsoft.Json.Linq;
        # NuGet package name is often the root namespace
        n_esc = re.escape(name)
        patterns += [
            re.compile(rf"^\s*using\s+{n_esc}(\.|;|\s)", re.MULTILINE),
        ]

    elif eco == "packagist":  # PHP
        # use Vendor\Package\Class;
        # require 'vendor/package'
        # Composer: namespace = vendor, name = package
        vendor = ns.replace("/", "\\\\") if ns else ""
        pkg_esc = re.escape(name)
        vendor_esc = re.escape(vendor) if vendor else ""
        patterns += [
            re.compile(rf"^\s*use\s+{vendor_esc}\\\\", re.MULTILINE) if vendor else None,
            re.compile(rf"""require[_once]*\s*['\"]{re.escape(ns + '/' + name if ns else name)}""", re.MULTILINE),
            re.compile(rf"^\s*use\s+.*{pkg_esc}", re.MULTILINE),
        ]
        patterns = [p for p in patterns if p]

    elif eco == "golang":
        # import "github.com/some/pkg"
        # import alias "github.com/some/pkg"
        # Full module path is namespace/name
        full = f"{ns}/{name}" if ns else name
        full_esc = re.escape(full)
        patterns += [
            re.compile(rf"""["'`]{full_esc}(/[^"'`]*)?["'`]""", re.MULTILINE),
        ]

    elif eco == "cargo":
        # use serde::Serialize;
        # extern crate serde;
        # Cargo.toml use is already captured via lockfile; here we check .rs
        n = _normalize_pkg_name(name, "cargo")
        patterns += [
            re.compile(rf"^\s*use\s+{n}(::|;|\s)", re.MULTILINE),
            re.compile(rf"^\s*extern\s+crate\s+{n}(\s|;)", re.MULTILINE),
        ]

    elif eco == "rubygems":
        # require 'nokogiri'
        # require "nokogiri"
        n_esc = re.escape(name)
        patterns += [
            re.compile(rf"""require\s+['\"]{n_esc}['\"]""", re.MULTILINE),
            re.compile(rf"""require_relative\s+['\"]{n_esc}['\"]""", re.MULTILINE),
        ]

    return patterns


# ---------------------------------------------------------------------------
# Source file walker
# ---------------------------------------------------------------------------

def _collect_source_files(project_root: str, extensions: set) -> list:
    """
    Walk project_root and return all source files matching `extensions`,
    skipping SKIP_DIRS and files larger than MAX_FILE_SIZE.
    """
    files = []
    root = Path(project_root)
    if not root.is_dir():
        return files
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            fpath = Path(dirpath) / fname
            if fpath.suffix.lower() in extensions:
                try:
                    if fpath.stat().st_size <= MAX_FILE_SIZE:
                        files.append(fpath)
                except OSError:
                    pass
    return files


def _scan_imports(
    pkg_name: str,
    purl_info: dict,
    project_root: Optional[str],
) -> ImportScanResult:
    """
    Scan source files under project_root for imports of the given package.
    Returns an ImportScanResult.
    """
    null_result = ImportScanResult(
        searched=False, found=False, matched_files=[],
        patterns_used=[], files_scanned=0, skipped_no_source=False,
    )

    if not project_root:
        return null_result

    raw_eco = purl_info["ecosystem"]
    eco = ECOSYSTEM_ALIASES.get(raw_eco, raw_eco)
    # Apply import name override if distribution name differs from import name
    dist_name = purl_info.get("name", "")
    import_name = IMPORT_NAME_OVERRIDES.get(dist_name.lower(), dist_name)
    # Give pattern builder the canonical key and resolved import name
    purl_info = dict(purl_info, ecosystem=eco, name=import_name)

    extensions = ECOSYSTEM_EXTENSIONS.get(eco)
    if not extensions:
        return null_result

    patterns = _build_import_patterns(purl_info)
    if not patterns:
        return null_result

    source_files = _collect_source_files(project_root, extensions)
    if not source_files:
        return ImportScanResult(
            searched=True, found=False, matched_files=[],
            patterns_used=[p.pattern for p in patterns],
            files_scanned=0, skipped_no_source=True,
        )

    matched_files = []
    root_path = Path(project_root)

    for fpath in source_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for pattern in patterns:
            if pattern.search(content):
                try:
                    rel = str(fpath.relative_to(root_path))
                except ValueError:
                    rel = str(fpath)
                if rel not in matched_files:
                    matched_files.append(rel)
                break  # one match per file is enough

    return ImportScanResult(
        searched=True,
        found=bool(matched_files),
        matched_files=matched_files,
        patterns_used=[p.pattern for p in patterns],
        files_scanned=len(source_files),
        skipped_no_source=False,
    )


# ---------------------------------------------------------------------------
# CVSS vector parser
# ---------------------------------------------------------------------------

def _extract_attack_vector(severity_vector: str) -> str:
    if not severity_vector:
        return "unknown"
    m = re.search(r"/AV:([NLP])", severity_vector)
    return m.group(1) if m else "unknown"


# ---------------------------------------------------------------------------
# Graph helpers
# ---------------------------------------------------------------------------

def _collect_all_dependents(graph: dict) -> set:
    dependents: set = set()
    def _walk(node: dict):
        for child_purl, subtree in node.items():
            dependents.add(child_purl)
            if subtree:
                _walk(subtree)
    _walk(graph)
    return dependents


def _graph_root_keys(graph: dict) -> set:
    return set(graph.keys())


# ---------------------------------------------------------------------------
# Inventory helpers
# ---------------------------------------------------------------------------

def _build_inventory_index(inventory: list) -> dict:
    return {item["id"]: item for item in inventory}


def _get_scope(inventory_item: Optional[dict]) -> str:
    if not inventory_item:
        return "unknown"
    scopes = inventory_item.get("scopes", [])
    if not scopes:
        return "unknown"
    s = scopes[0].lower()
    if s in ("dev", "development"):
        return "dev"
    if s in ("test", "testing"):
        return "test"
    return "prod"


def _has_env_scope(inventory_item: Optional[dict]) -> bool:
    """Returns True if any of the inventory item's scopes equals 'env' (case-insensitive)."""
    if not inventory_item:
        return False
    return any(s.lower() == "env" for s in inventory_item.get("scopes", []))


def _get_pkg_type(inventory_item: Optional[dict]) -> str:
    if not inventory_item:
        return "unknown"
    return (inventory_item.get("type") or "unknown").lower().strip()


def _get_min_depth(pkg_purl: str, findings_summary: dict) -> int:
    for _pkg_name, finding in findings_summary.items():
        sequences = finding.get("affected_dependency_sequences", [])
        if not sequences:
            continue
        matching = [s for s in sequences if s and s[-1] == pkg_purl]
        if matching:
            depths = [len(s) - 1 for s in matching]
            return min(depths)
    return 0


def _get_introduced_by(pkg_purl: str, inventory_index: dict) -> list:
    item = inventory_index.get(pkg_purl)
    if not item:
        return []
    return list(set(item.get("introduced_by", [])))


def _get_num_paths(pkg_purl: str, findings_summary: dict) -> int:
    for _pkg_name, finding in findings_summary.items():
        sequences = finding.get("affected_dependency_sequences", [])
        matching = [s for s in sequences if s and s[-1] == pkg_purl]
        if matching:
            return len(matching)
    return 0


# ---------------------------------------------------------------------------
# Core decision logic
# ---------------------------------------------------------------------------

def _compute_reachability(
    signals: ReachabilitySignals,
) -> tuple:
    """
    Returns (reachable, level, confidence, rationale, tags).

    Priority ladder:
      0a. MAL- vuln ID               → total (malware, unconditional)
      0b. env scope in scopes list   → total (environment-level exposure)
      1. Non-library type            → total (highest confidence)
      2. Dev / test scope            → unreachable
      3. Import scan confirmed       → reachable (confirmed by source)
      4. Import scan absent          → unreachable (confirmed absent)
      5. Orphan tool                 → unreachable (heuristic)
      6. Depth + AV heuristics       → medium/low (weakest)
    """
    tags = []
    av    = signals.attack_vector
    depth = signals.depth
    imp   = signals.import_scan

    # ── Priority 0a: malware record (vuln ID starts with "MAL-")
    if signals.is_malware:
        tags.append("malware")
        return (
            True, "critical", "high",
            "Vulnerability ID carries the MAL- prefix — this is a malware record "
            "representing an active supply-chain infection. "
            "Reachability is unconditional.",
            tags,
        )

    # ── Priority 0b: env scope — package is part of the runtime environment
    if signals.has_env_scope:
        tags.append("env_scope")
        return (
            True, "critical", "high",
            "Package scope includes 'env' — this component is part of the execution "
            "environment itself (OS package, system library, runtime, or container layer). "
            "Reachability is unconditional.",
            tags,
        )

    # ── Priority 1: non-library type (framework, app, plugin, OS pkg …)
    if signals.is_non_library:
        tags.append("non_library_type")
        tags.append(f"type:{signals.pkg_type}")
        return (
            True, "critical", "high",
            f"Package type is '{signals.pkg_type}' — not a passive library. "
            "The vulnerable component IS the executable/framework/service being run; "
            "reachability is unconditional.",
            tags,
        )

    # ── Priority 2: dev / test scope
    if signals.scope in ("dev", "test"):
        tags.append("dev_scope")
        return (
            False, "low", "high",
            f"Package is scoped to '{signals.scope}' — "
            "not reachable from production code paths.",
            tags,
        )

    # ── Priority 3: import scan found a match
    if imp.searched and imp.found:
        tags.append("import_confirmed")
        files_note = (
            f"Found in {len(imp.matched_files)} source file(s): "
            + ", ".join(imp.matched_files[:3])
            + (" …" if len(imp.matched_files) > 3 else "")
        )
        level = "high" if (depth == 0 or av == "N") else "medium"
        tags.append("network_av" if av == "N" else f"av_{av.lower()}")
        return (
            True, level, "high",
            f"Import of this package was found in project source code. {files_note}. "
            f"Depth={depth}, AV={av}.",
            tags,
        )

    # ── Priority 4a: direct import absent — check parent imports for transitive deps
    if imp.searched and not imp.found and not imp.skipped_no_source:
        if depth >= 1 and imp.parent_scans:
            # Find parents whose import WAS found in source
            found_parents = [
                (purl, scan)
                for purl, scan in imp.parent_scans.items()
                if scan.searched and scan.found
            ]
            if found_parents:
                tags.append("transitive_via_parent")
                tags.append("network_av" if av == "N" else f"av_{av.lower()}")
                parent_names = [_parse_purl(p).get("name", p) for p, _ in found_parents[:3]]
                files_via = []
                for _, scan in found_parents[:2]:
                    files_via.extend(scan.matched_files[:2])
                files_str = ", ".join(files_via[:4]) + (" …" if len(files_via) > 4 else "")
                level = "medium" if av == "N" else "low"
                return (
                    True, level, "medium",
                    f"Direct import not found, but parent package(s) "
                    f"{', '.join(parent_names)} — which depend on this package — "
                    f"are imported in: {files_str}. "
                    f"Vulnerable code is reachable if the parent exercises the affected function. "
                    f"Depth={depth}, AV={av}.",
                    tags,
                )

        # ── Priority 4b: no direct import, no parent import found either
        tags.append("import_absent")
        return (
            False, "low", "medium",
            f"No import of this package was found across {imp.files_scanned} "
            f"source file(s) scanned, and no importing parent package was found. "
            f"Package appears installed but unused in project code.",
            tags,
        )

    # ── Priority 5: orphan tool (no import scan available)
    if signals.is_orphan_tool:
        tags.append("orphan_tool")
        return (
            False, "low", "medium",
            "Root package with no dependents in the dependency graph. "
            "Standalone tool — not importable by application code.",
            tags,
        )

    # ── Priority 6: heuristics only (no source scan performed)
    if depth == 0 and av == "N":
        tags += ["root_package", "network_av"]
        return (
            True, "high", "low",
            "Root-level dependency with network attack vector. "
            "No source scan performed — heuristic only.",
            tags,
        )
    if depth == 0 and av in ("L", "P"):
        tags += ["root_package", f"{'local' if av == 'L' else 'physical'}_av"]
        return (
            True, "medium", "low",
            f"Root-level dependency with {'local' if av == 'L' else 'physical'} "
            "attack vector. No source scan performed — heuristic only.",
            tags,
        )
    if depth >= 1 and av == "N":
        tags += ["transitive", "network_av"]
        paths_note = (
            f"Reachable via {signals.num_paths} path(s), shortest at depth {depth}."
            if signals.num_paths > 0 else f"Transitive at depth {depth}."
        )
        return (
            True, "medium", "low",
            f"Transitive dependency with network attack vector. {paths_note} "
            "No source scan performed — heuristic only.",
            tags,
        )
    if depth >= 1 and av in ("L", "P"):
        tags += ["transitive", f"{'local' if av == 'L' else 'physical'}_av"]
        return (
            False, "low", "low",
            f"Transitive dependency (depth {depth}) with "
            f"{'local' if av == 'L' else 'physical'} attack vector. "
            "No source scan performed — heuristic only.",
            tags,
        )

    # ── Fallback
    tags.append("unknown_av")
    return (
        True, "medium", "low",
        f"Attack vector undetermined. Depth={depth}. "
        "Defaulting to reachable with low confidence — heuristic only.",
        tags,
    )


# ---------------------------------------------------------------------------
# Transitive parent import scan
# ---------------------------------------------------------------------------

def _scan_parent_imports(
    introduced_by: list,
    purl_info: dict,
    inventory_index: dict,
    project_root: str,
) -> dict:
    """
    For transitive vulnerabilities where the direct package import was not found,
    scan for imports of each parent package in introduced_by.

    If any parent is imported, the vulnerable package is reachable via that parent
    (the parent calls the vulnerable code internally).

    Returns a dict mapping parent_purl → ImportScanResult.
    Only scans parents that share the same ecosystem as the vulnerable package.
    """
    results = {}
    eco = ECOSYSTEM_ALIASES.get(purl_info["ecosystem"], purl_info["ecosystem"])  # resolve alias

    for parent_purl in introduced_by:
        parent_info = _parse_purl(parent_purl)
        parent_eco_raw = parent_info["ecosystem"]
        parent_eco = ECOSYSTEM_ALIASES.get(parent_eco_raw, parent_eco_raw)

        # Only scan if parent is in the same ecosystem (cross-ecosystem parents
        # don't share source files in a meaningful way)
        if parent_eco != eco:
            continue

        parent_dist_name = parent_info["name"]
        parent_import_name = IMPORT_NAME_OVERRIDES.get(
            parent_dist_name.lower(), parent_dist_name
        )
        parent_scan_info = dict(parent_info, ecosystem=parent_eco, name=parent_import_name)
        scan = _scan_imports(parent_import_name, parent_scan_info, project_root)
        results[parent_purl] = scan

    return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def analyze_reachability(
    report: dict,
    project_root: Optional[str] = None,
) -> list[ReachabilityResult]:
    """
    Main entry point.

    Args:
        report:       Parsed UBEL JSON report dict.
        project_root: Optional path to the project's source root directory.
                      When supplied, import scanning is performed for each
                      vulnerable package in a supported ecosystem.

    Returns:
        List of ReachabilityResult, one per vulnerability entry.
    """
    vulnerabilities  = report.get("vulnerabilities", [])
    findings_summary = report.get("findings_summary", {})
    inventory        = report.get("inventory", [])
    dependency_graph = report.get("dependency_graph", {})

    inventory_index  = _build_inventory_index(inventory)
    all_dependents   = _collect_all_dependents(dependency_graph)
    graph_roots      = _graph_root_keys(dependency_graph)

    results: list[ReachabilityResult] = []

    for vuln in vulnerabilities:
        vuln_id         = vuln.get("id", "unknown")
        pkg_purl        = vuln.get("affected_package_id", "")
        severity_vector = vuln.get("severity_vector", "")

        purl_info       = _parse_purl(pkg_purl)
        av              = _extract_attack_vector(severity_vector)
        inventory_item  = inventory_index.get(pkg_purl)
        scope           = _get_scope(inventory_item)
        pkg_type        = _get_pkg_type(inventory_item)
        is_non_library  = pkg_type in NON_LIBRARY_TYPES
        is_malware      = vuln_id.startswith("MAL-")
        has_env_scope   = _has_env_scope(inventory_item)
        introduced_by   = _get_introduced_by(pkg_purl, inventory_index)
        depth           = _get_min_depth(pkg_purl, findings_summary)
        num_paths       = _get_num_paths(pkg_purl, findings_summary)

        is_graph_root   = pkg_purl in graph_roots
        is_dependent    = pkg_purl in all_dependents
        is_orphan_tool  = is_graph_root and not is_dependent

        # Import scan — skip if non-library (already total), malware (already total),
        # env-scoped (already total), or dev/test (already low)
        run_import_scan = (
            project_root is not None
            and not is_non_library
            and not is_malware
            and not has_env_scope
            and scope not in ("dev", "test")
        )
        if run_import_scan:
            import_scan = _scan_imports(purl_info["name"], purl_info, project_root)
            # Transitive case: direct import not found → check if any parent is imported.
            # If a parent package is imported, the vulnerable transitive dep is reachable
            # through it (the parent calls the vulnerable function internally).
            if (
                import_scan.searched
                and not import_scan.found
                and not import_scan.skipped_no_source
                and depth >= 1
                and introduced_by
            ):
                parent_scans = _scan_parent_imports(
                    introduced_by, purl_info, inventory_index, project_root
                )
                import_scan.parent_scans = parent_scans
        else:
            import_scan = ImportScanResult(
                searched=False, found=False, matched_files=[],
                patterns_used=[], files_scanned=0, skipped_no_source=False,
            )

        signals = ReachabilitySignals(
            depth=depth,
            attack_vector=av,
            is_orphan_tool=is_orphan_tool,
            scope=scope,
            num_paths=num_paths,
            introduced_by_count=len(introduced_by),
            pkg_type=pkg_type,
            is_non_library=is_non_library,
            is_malware=is_malware,
            has_env_scope=has_env_scope,
            import_scan=import_scan,
            introduced_by=introduced_by,
        )

        reachable, level, confidence, rationale, tags = _compute_reachability(signals)

        results.append(ReachabilityResult(
            vuln_id=vuln_id,
            affected_package_id=pkg_purl,
            reachable=reachable,
            level=level,
            confidence=confidence,
            signals=signals,
            rationale=rationale,
            tags=tags,
        ))

    return results


def enrich_report(report: dict, project_root: Optional[str] = None) -> dict:
    """
    Annotates each vulnerability in report["vulnerabilities"] with a
    "reachability" block. Returns the mutated report dict.
    """
    results = analyze_reachability(report, project_root=project_root)
    result_index = {r.vuln_id: r for r in results}

    for vuln in report.get("vulnerabilities", []):
        r = result_index.get(vuln["id"])
        if not r:
            continue
        imp = r.signals.import_scan
        vuln["reachability"] = {
            "reachable": r.reachable,
            "level": r.level,
            "confidence": r.confidence,
            "rationale": r.rationale,
            "tags": r.tags,
            "signals": {
                "depth": r.signals.depth,
                "attack_vector": r.signals.attack_vector,
                "is_orphan_tool": r.signals.is_orphan_tool,
                "scope": r.signals.scope,
                "num_paths": r.signals.num_paths,
                "introduced_by_count": r.signals.introduced_by_count,
                "pkg_type": r.signals.pkg_type,
                "is_non_library": r.signals.is_non_library,
                "is_malware": r.signals.is_malware,
                "has_env_scope": r.signals.has_env_scope,
                "import_scan": {
                    "searched": imp.searched,
                    "found": imp.found,
                    "matched_files": imp.matched_files,
                    "files_scanned": imp.files_scanned,
                    "skipped_no_source": imp.skipped_no_source,
                    "parent_scans": {
                        purl: {
                            "found": ps.found,
                            "matched_files": ps.matched_files,
                            "files_scanned": ps.files_scanned,
                        }
                        for purl, ps in (imp.parent_scans or {}).items()
                    },
                },
            },
        }

    return report


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _print_summary(results: list[ReachabilityResult]) -> None:
    RESET  = "\033[0m"
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    CYAN   = "\033[96m"
    MAGENTA= "\033[95m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"

    level_color = {
        "critical":  MAGENTA,
        "high":   RED,
        "medium": YELLOW,
        "low":    GREEN,
    }
    conf_color = {"high": GREEN, "medium": YELLOW, "low": DIM}

    print(f"\n{BOLD}{'─' * 76}{RESET}")
    print(f"{BOLD}  UBEL Reachability Analysis{RESET}")
    print(f"{BOLD}{'─' * 76}{RESET}\n")

    for r in results:
        reach_label = (
            f"{RED}● REACHABLE{RESET}"   if r.reachable
            else f"{GREEN}○ UNREACHABLE{RESET}"
        )
        lc = level_color.get(r.level, "")
        cc = conf_color.get(r.confidence, "")
        imp = r.signals.import_scan

        print(f"  {BOLD}{r.vuln_id}{RESET}")
        print(f"  Package    : {CYAN}{r.affected_package_id}{RESET}  "
              f"[type: {r.signals.pkg_type}]")
        print(f"  Status     : {reach_label}")
        print(f"  Level      : {lc}{r.level.upper()}{RESET}   "
              f"Confidence: {cc}{r.confidence.upper()}{RESET}")
        print(f"  Signals    : depth={r.signals.depth}  "
              f"AV={r.signals.attack_vector}  "
              f"orphan={r.signals.is_orphan_tool}  "
              f"scope={r.signals.scope}  "
              f"paths={r.signals.num_paths}  "
              f"non_lib={r.signals.is_non_library}  "
              f"malware={r.signals.is_malware}  "
              f"env_scope={r.signals.has_env_scope}")

        if imp.searched:
            if imp.skipped_no_source:
                print(f"  Import scan: {DIM}no source files found{RESET}")
            elif imp.found:
                print(f"  Import scan: {GREEN}FOUND{RESET} in "
                      f"{len(imp.matched_files)} file(s) "
                      f"[scanned {imp.files_scanned}] → "
                      f"{DIM}{', '.join(imp.matched_files[:2])}"
                      f"{'…' if len(imp.matched_files) > 2 else ''}{RESET}")
            else:
                print(f"  Import scan: {YELLOW}NOT FOUND{RESET} "
                      f"[scanned {imp.files_scanned} files]")
        else:
            print(f"  Import scan: {DIM}not performed{RESET}")

        print(f"  Tags       : {', '.join(r.tags) if r.tags else '—'}")
        print(f"  Rationale  : {DIM}{r.rationale}{RESET}")
        print()

    reachable_count   = sum(1 for r in results if r.reachable)
    unreachable_count = len(results) - reachable_count
    total_count       = sum(1 for r in results if r.level == "critical")

    print(f"{BOLD}{'─' * 76}{RESET}")
    print(f"  Total vulns : {len(results)}  │  "
          f"{MAGENTA}Total: {total_count}{RESET}  │  "
          f"{RED}Reachable: {reachable_count}{RESET}  │  "
          f"{GREEN}Unreachable: {unreachable_count}{RESET}")
    print(f"{BOLD}{'─' * 76}{RESET}\n")


def main():
    args = sys.argv[1:]
    if not args or args[0] in ("-h", "--help"):
        print("Usage: python reachability_analyzer.py <report.json> "
              "[--project-root <path>] [--enrich]")
        sys.exit(0 if args else 1)

    report_path  = args[0]
    project_root = None
    enrich_mode  = "--enrich" in args

    if "--project-root" in args:
        idx = args.index("--project-root")
        if idx + 1 < len(args):
            project_root = args[idx + 1]

    with open(report_path, "r", encoding="utf-8") as f:
        report = json.load(f)

    results = analyze_reachability(report, project_root=project_root)
    _print_summary(results)

    if enrich_mode:
        enriched = enrich_report(report, project_root=project_root)
        out_path = report_path.replace(".json", ".enriched.json")
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(enriched, f, indent=2)
        print(f"  Enriched report written to: {out_path}\n")


if __name__ == "__main__":
    main()