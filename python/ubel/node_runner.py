"""
node_modules_scanner.py — Node.js installed-package scanner.

Pure-Python port of the NodeModulesScanner + NodeManager.getInstalled()
capability from node_runner.js.

Walks a directory tree recursively, finds every ``node_modules`` directory,
reads each package's ``package.json``, resolves intra-tree dependencies via
Node's standard resolution algorithm (climb-to-root), then propagates
prod/dev scopes from the nearest ``package.json`` manifest.

Zero external dependencies.

Usage
-----
    from node_modules_scanner import NodeModulesScanner

    ids = NodeModulesScanner.get_installed("/path/to/project")
    for rec in NodeModulesScanner.inventory_data:
        print(rec["id"], rec["scopes"])
"""

from __future__ import annotations

import json
import os
import re
from typing import Dict, List, Optional, Set, Union
from urllib.parse import quote


# ---------------------------------------------------------------------------
# WorkspaceResolver
#
# Pure utility — no I/O.  Mirrors WorkspaceResolver in lockfiles_parser.js.
# ---------------------------------------------------------------------------

class WorkspaceResolver:

    @staticmethod
    def globs(pkg_json: Optional[Dict], pnpm_ws_yaml: Optional[str] = None) -> List[str]:
        """
        Extract workspace glob patterns from a parsed package.json and/or a
        raw pnpm-workspace.yaml string.

        Supports:
          • npm/yarn:  "workspaces": ["packages/*"]
          • npm/yarn:  "workspaces": { "packages": ["packages/*"] }
          • pnpm:      pnpm-workspace.yaml  packages: list
        """
        patterns: List[str] = []

        if pkg_json:
            ws = pkg_json.get("workspaces")
            if isinstance(ws, list):
                patterns.extend(ws)
            elif isinstance(ws, dict) and isinstance(ws.get("packages"), list):
                patterns.extend(ws["packages"])

        if pnpm_ws_yaml and isinstance(pnpm_ws_yaml, str):
            in_packages = False
            for raw_line in pnpm_ws_yaml.splitlines():
                line = raw_line.rstrip()
                if re.match(r"^packages\s*:", line):
                    in_packages = True
                    continue
                if in_packages:
                    if line and line[0].isalpha():
                        in_packages = False
                        continue
                    m = re.match(r"^\s*-\s*['\"]?(.+?)['\"]?\s*$", line)
                    if m:
                        patterns.append(m.group(1))

        seen: Set[str] = set()
        result: List[str] = []
        for p in patterns:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result

    @staticmethod
    def match(patterns: List[str], dirs: List[str]) -> List[str]:
        """
        Return the subset of *dirs* that match at least one glob pattern.
        Supports ``*`` (single path segment) and ``**`` (any depth).
        """
        return [d for d in dirs if any(WorkspaceResolver._glob_match(p, d) for p in patterns)]

    @staticmethod
    def _glob_match(pattern: str, s: str) -> bool:
        pattern = pattern.replace("\\", "/").rstrip("/")
        s       = s.replace("\\", "/").rstrip("/")
        parts   = pattern.split("/")
        re_parts = []
        for seg in parts:
            if seg == "**":
                re_parts.append(".*")
            else:
                re_parts.append(re.escape(seg).replace(r"\*", "[^/]*"))
        rx = "^" + "/".join(re_parts) + "$"
        return bool(re.match(rx, s))

    @staticmethod
    def resolve_workspace_dirs(root_dir: str) -> List[str]:
        """
        Read package.json and pnpm-workspace.yaml at *root_dir*, expand
        workspace globs against the directory tree, and return a list of
        absolute paths to workspace package directories.

        Returns an empty list for non-monorepo projects.
        """
        pkg_json   = _parse_pkg_json(os.path.join(root_dir, "package.json"))
        pnpm_yaml  = None
        pnpm_path  = os.path.join(root_dir, "pnpm-workspace.yaml")
        if os.path.isfile(pnpm_path):
            try:
                with open(pnpm_path, "r", encoding="utf-8", errors="replace") as fh:
                    pnpm_yaml = fh.read()
            except OSError:
                pass

        globs = WorkspaceResolver.globs(pkg_json, pnpm_yaml)
        if not globs:
            return []

        # Collect candidate relative paths up to 3 levels deep
        candidates: List[str] = []

        def _scan(directory: str, prefix: str, depth: int) -> None:
            if depth > 3:
                return
            try:
                entries = list(os.scandir(directory))
            except OSError:
                return
            for entry in entries:
                if not entry.is_dir():
                    continue
                if entry.name.startswith(".") or entry.name == "node_modules":
                    continue
                rel = f"{prefix}/{entry.name}" if prefix else entry.name
                candidates.append(rel)
                _scan(entry.path, rel, depth + 1)

        _scan(root_dir, "", 0)

        matched = WorkspaceResolver.match(globs, candidates)
        return [os.path.join(root_dir, rel) for rel in matched]


# ---------------------------------------------------------------------------
# PURL
# ---------------------------------------------------------------------------

def _npm_purl(name: str, version: str) -> str:
    """
    Build a Package-URL for an npm package.

    Scoped packages (@scope/name) are percent-encoded per the PURL spec:
      pkg:npm/%40scope%2Fname@version
    """
    if name.startswith("@"):
        # @scope/name → %40scope%2Fname
        encoded = quote(name, safe="")
    else:
        encoded = name
    return f"pkg:npm/{encoded}@{version}"


# ---------------------------------------------------------------------------
# NodeModulesScanner
#
# Mirrors the JS class exactly:
#   • _walk()            — BFS/DFS over node_modules, follows symlinks safely
#   • _handle_package()  — reads package.json, deduplicates by name@version
#   • _resolve_deps()    — climb-to-root resolution for each declared dep
# ---------------------------------------------------------------------------

class _NodeModulesScanner:
    """
    Walk a single ``node_modules`` tree and return flat package records.
    One instance per project root (mirrors the JS constructor).
    """

    def __init__(self, root_dir: str) -> None:
        self.root_dir          = root_dir
        self.node_modules_path = os.path.join(root_dir, "node_modules")
        # name@version → record
        self.packages:      Dict[str, Dict] = {}
        # real-path set to break symlink cycles
        self.visited_paths: Set[str] = set()

    # ── public ──────────────────────────────────────────────────────────────

    def scan(self) -> List[Dict]:
        if not os.path.isdir(self.node_modules_path):
            return []

        self._walk(self.node_modules_path)

        packages = list(self.packages.values())
        for pkg in packages:
            pkg["dependencies"] = self._resolve_deps(pkg)
            pkg.pop("_raw_pkg_json", None)

        return packages

    # ── private ─────────────────────────────────────────────────────────────

    def _walk(self, directory: str) -> None:
        try:
            real_dir = os.path.realpath(directory)
        except OSError:
            return

        if real_dir in self.visited_paths:
            return
        self.visited_paths.add(real_dir)

        try:
            entries = list(os.scandir(directory))
        except OSError:
            return

        for entry in entries:
            full_path = entry.path

            # .pnpm virtual store — recurse into it (mirrors JS behaviour)
            if entry.name == ".pnpm":
                self._walk(full_path)
                continue

            # Symbolic link — resolve and handle + recurse
            if entry.is_symlink():
                try:
                    resolved = os.path.realpath(full_path)
                except OSError:
                    continue
                self._handle_package(resolved)
                self._walk(resolved)
                continue

            if not entry.is_dir():
                continue

            # Scoped namespace directory (@scope) — just recurse, don't handle
            if entry.name.startswith("@"):
                self._walk(full_path)
                continue

            self._handle_package(full_path)
            self._walk(full_path)

    def _handle_package(self, pkg_path: str) -> None:
        pkg_json_path = os.path.join(pkg_path, "package.json")
        if not os.path.isfile(pkg_json_path):
            return

        try:
            with open(pkg_json_path, "r", encoding="utf-8", errors="replace") as fh:
                pkg_json = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return

        name    = pkg_json.get("name")
        version = pkg_json.get("version")
        if not name or not version:
            return

        # Skip subpath-export stubs (pnpm materialises nested dirs for these)
        parent_dir          = os.path.dirname(pkg_path)
        parent_pkg_json_path = os.path.join(parent_dir, "package.json")
        if os.path.isfile(parent_pkg_json_path):
            try:
                with open(parent_pkg_json_path, "r", encoding="utf-8", errors="replace") as fh:
                    parent_pkg = json.load(fh)
                parent_name = parent_pkg.get("name")
                if parent_name and parent_name != name and parent_pkg.get("version"):
                    return
            except (OSError, json.JSONDecodeError):
                pass

        key = f"{name}@{version}"
        if key in self.packages:
            return

        license_val = pkg_json.get("license")
        if not license_val:
            licenses = pkg_json.get("licenses")
            if isinstance(licenses, list):
                license_val = ", ".join(
                    lic.get("type", "") for lic in licenses if isinstance(lic, dict)
                )
        if not license_val:
            license_val = "unknown"

        self.packages[key] = {
            "purl":         _npm_purl(name, version),
            "name":         name,
            "version":      version,
            "license":      license_val,
            "path":         pkg_path,
            "dependencies": [],          # filled in after scan()
            "_raw_pkg_json": pkg_json,
        }

    def _resolve_deps(self, pkg: Dict) -> List[str]:
        pkg_json = pkg.get("_raw_pkg_json")
        if not pkg_json:
            return []

        deps: Set[str] = set()

        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            declared = pkg_json.get(field)
            if not isinstance(declared, dict):
                continue
            for dep_name in declared:
                resolved = self._find_installed_package(pkg["path"], dep_name)
                if resolved:
                    deps.add(_npm_purl(resolved["name"], resolved["version"]))
                else:
                    deps.add(_npm_purl(dep_name, ""))

        return list(deps)

    def _find_installed_package(
        self, start_dir: str, dep_name: str
    ) -> Optional[Dict[str, str]]:
        """
        Climb the directory tree from *start_dir* looking for
        ``node_modules/<dep_name>/package.json`` — mirrors Node's resolution.
        """
        current = start_dir

        while True:
            nm = os.path.join(current, "node_modules")

            if dep_name.startswith("@"):
                parts = dep_name.split("/", 1)
                if len(parts) == 2:
                    target_path = os.path.join(nm, parts[0], parts[1])
                else:
                    target_path = os.path.join(nm, dep_name)
            else:
                target_path = os.path.join(nm, dep_name)

            pj_path = os.path.join(target_path, "package.json")
            if os.path.isfile(pj_path):
                try:
                    with open(pj_path, "r", encoding="utf-8", errors="replace") as fh:
                        pj = json.load(fh)
                    n = pj.get("name")
                    v = pj.get("version")
                    if n and v:
                        return {"name": n, "version": v}
                except (OSError, json.JSONDecodeError):
                    pass

            parent = os.path.dirname(current)
            if parent == current:
                break
            current = parent

        return None


# ---------------------------------------------------------------------------
# Scope helpers
# ---------------------------------------------------------------------------

def _parse_pkg_json(pkg_json_path: str) -> Optional[Dict]:
    """Return parsed package.json or None on any error."""
    if not os.path.isfile(pkg_json_path):
        return None
    try:
        with open(pkg_json_path, "r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)
    except (OSError, json.JSONDecodeError):
        return None


def _assign_scopes(
    inventory: List[Dict],
    pkg_json_path: Union[str, List[str]],
) -> None:
    """
    BFS scope propagation from package.json direct dependencies.

    *pkg_json_path* may be a single path string or a list of paths (for
    monorepos).  When multiple paths are supplied, ``dependencies`` and
    ``devDependencies`` are unioned across all supplied package.json files
    before propagation — so a package that is a prod dep in any workspace
    gets the "prod" scope, and likewise for "dev".

    Rules (mirrors NodeManager._assignScopes):
      • listed in ``dependencies``    → prod (and all transitives)
      • listed in ``devDependencies`` → dev  (and all transitives)
      • reachable from both roots     → prod + dev
      • engine / tool entries         → env  (pre-set at creation, not touched)
      • unreachable from any root     → scopes stays []
    """
    by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

    for comp in inventory:
        if not isinstance(comp.get("scopes"), list):
            comp["scopes"] = []

    # Normalise to list
    paths = [pkg_json_path] if isinstance(pkg_json_path, str) else list(pkg_json_path)

    pro_direct: Set[str] = set()
    dev_direct: Set[str] = set()

    for path in paths:
        pkg_json = _parse_pkg_json(path)
        if not pkg_json:
            continue
        pro_direct.update(pkg_json.get("dependencies",    {}).keys())
        dev_direct.update(pkg_json.get("devDependencies", {}).keys())

    # name → [comp, …]  (a name can have multiple version entries)
    name_index: Dict[str, List[Dict]] = {}
    for comp in inventory:
        name_index.setdefault(comp["name"], []).append(comp)

    _PLAIN_RE  = re.compile(r"^pkg:npm/([^%@][^@/]*)@")
    _SCOPED_RE = re.compile(r"^pkg:npm/%40([^@/]+)/([^@]+)@")

    def propagate(direct_names: Set[str], scope: str) -> None:
        queue: List[Dict] = []
        for name in direct_names:
            queue.extend(name_index.get(name, []))

        visited: Set[str] = set()
        while queue:
            comp = queue.pop(0)
            cid  = comp["id"]
            if cid in visited:
                continue
            visited.add(cid)

            if scope not in comp["scopes"]:
                comp["scopes"].append(scope)

            for dep_purl in (comp.get("dependencies") or []):
                dep_comp = by_id.get(dep_purl)
                if dep_comp:
                    if dep_comp["id"] not in visited:
                        queue.append(dep_comp)
                else:
                    # Versionless PURL — resolve via name index
                    m = _SCOPED_RE.match(dep_purl)
                    if m:
                        dep_name = f"@{m.group(1)}/{m.group(2)}"
                    else:
                        m = _PLAIN_RE.match(dep_purl)
                        dep_name = m.group(1) if m else None

                    if dep_name:
                        for c in name_index.get(dep_name, []):
                            if c["id"] not in visited:
                                queue.append(c)

    propagate(pro_direct, "prod")
    propagate(dev_direct,  "dev")


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _merge_inventory_by_purl(components: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}

    for comp in components:
        cid = comp["id"]

        if cid not in merged:
            clone          = dict(comp)
            clone["paths"] = list(clone.get("paths", []))
            p = clone.pop("path", None)
            if p and p not in clone["paths"]:
                clone["paths"].append(p)
            # Collect workspace attributions as a set during merge
            ws = clone.get("workspace")
            clone["_workspaces"] = {ws} if ws else set()
            merged[cid] = clone
            continue

        existing = merged[cid]
        p = comp.get("path")
        if p and p not in existing["paths"]:
            existing["paths"].append(p)
        for p in comp.get("paths", []):
            if p and p not in existing["paths"]:
                existing["paths"].append(p)
        # Union-merge scopes
        for s in (comp.get("scopes") or []):
            if s not in existing["scopes"]:
                existing["scopes"].append(s)
        # Union-merge workspace attributions
        ws = comp.get("workspace")
        if ws:
            existing["_workspaces"].add(ws)

    # Flatten _workspaces → workspace
    for comp in merged.values():
        ws_set = comp.pop("_workspaces", set())
        ws_list = list(ws_set)
        if len(ws_list) == 0:
            comp["workspace"] = None
        elif len(ws_list) == 1:
            comp["workspace"] = ws_list[0]
        else:
            comp["workspace"] = ws_list  # shared by multiple workspaces

    return list(merged.values())


# ---------------------------------------------------------------------------
# NodeModulesScanner  (public API — mirrors PythonVenvScanner shape)
# ---------------------------------------------------------------------------

class NodeModulesScanner:
    """
    Walk a directory tree recursively, find every ``node_modules`` directory,
    enumerate installed packages, resolve intra-tree dependencies, and
    propagate prod/dev scopes from the nearest ``package.json``.

    API mirrors ``PythonVenvScanner`` so it can be dropped into
    ``Pypi_Manager.get_installed()`` alongside the other ecosystem scanners.
    """

    inventory_data: List[Dict] = []

    @classmethod
    def get_installed(
        cls,
        start_dir: str = ".",
        is_recursive: bool = True,
    ) -> List[str]:
        """
        Entry-point.  Returns a list of PURL id strings.
        Full component records are stored in ``NodeModulesScanner.inventory_data``.

        Parameters
        ----------
        start_dir : str
            Root directory to begin scanning from.
        is_recursive : bool
            When True (default) the scanner walks the entire subtree under
            ``start_dir``.  When False only the immediate children of
            ``start_dir`` are inspected.
        """
        return cls.scan(start_dir, is_recursive=is_recursive)

    @classmethod
    def scan(
        cls,
        start_dir: str = ".",
        is_recursive: bool = True,
    ) -> List[str]:
        """Synchronous scan. Returns a list of PURL id strings."""
        cls.inventory_data = []

        start_dir = os.path.abspath(start_dir)

        # project roots whose node_modules we have already processed
        visited_roots: Set[str] = set()
        all_components: List[Dict] = []

        skip_names = {".git", ".ubel"}

        def walk(directory: str, depth: int = 0) -> None:
            try:
                entries = list(os.scandir(directory))
            except OSError:
                return

            for entry in entries:
                if not entry.is_dir():
                    continue

                name = entry.name

                # Hidden dirs (except first-level) and known noise dirs
                if name.startswith(".") or name in skip_names:
                    continue

                full_path = entry.path

                if name == "node_modules":
                    project_root = os.path.realpath(directory)
                    if project_root in visited_roots:
                        continue
                    visited_roots.add(project_root)

                    print(f"[i] Found node_modules: {full_path}")
                    try:
                        scanner  = _NodeModulesScanner(directory)
                        raw_pkgs = scanner.scan()

                        components = _pkgs_to_components(raw_pkgs)

                        # Collect package.json paths: project root + all
                        # workspace sub-package directories (if any).
                        pkg_json_paths: List[str] = []
                        root_pj = os.path.join(directory, "package.json")
                        if os.path.isfile(root_pj):
                            pkg_json_paths.append(root_pj)

                        for ws_dir in WorkspaceResolver.resolve_workspace_dirs(directory):
                            ws_pj = os.path.join(ws_dir, "package.json")
                            if os.path.isfile(ws_pj):
                                pkg_json_paths.append(ws_pj)

                        _assign_scopes(components, pkg_json_paths)
                        all_components.extend(components)
                    except Exception:
                        pass

                    # Never descend into node_modules itself
                    continue

                # Depth-control: only recurse deeper when is_recursive=True.
                # At depth 0 we enumerate start_dir's direct children,
                # so we always take one step in.
                if is_recursive or depth == 0:
                    walk(full_path, depth + 1)

        walk(start_dir)

        merged = _merge_inventory_by_purl(all_components)
        cls.inventory_data = merged
        return [c["id"] for c in merged]


# ---------------------------------------------------------------------------
# Conversion helper
# ---------------------------------------------------------------------------

def _pkgs_to_components(raw_pkgs: List[Dict]) -> List[Dict]:
    """
    Convert the flat list produced by _NodeModulesScanner.scan() into the
    canonical UBEL component shape (mirrors NodeManager.getInstalledFromTree).
    """
    by_purl: Dict[str, Dict] = {}

    for pkg in raw_pkgs:
        cid = pkg["purl"]
        if cid in by_purl:
            existing = by_purl[cid]
            p = pkg.get("path")
            if p and p not in existing["paths"]:
                existing["paths"].append(p)
            continue

        by_purl[cid] = {
            "id":           cid,
            "name":         pkg["name"],
            "version":      pkg["version"],
            "type":         "library",
            "license":      pkg.get("license") or "unknown",
            "ecosystem":    "npm",
            "state":        "undetermined",
            "scopes":       [],
            "dependencies": pkg.get("dependencies", []),
            "paths":        [pkg["path"]] if pkg.get("path") else [],
            "workspace":    None,
        }

    return list(by_purl.values())