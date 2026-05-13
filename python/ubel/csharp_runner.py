"""
csharp_scanner.py — C# / NuGet scanner (getInstalled only).

Mirrors the JS CSharpNuGetScanner:
  - Detects .NET project roots (*.csproj / *.fsproj / *.vbproj)
  - Reads packages.lock.json (preferred) or obj/project.assets.json
  - Assigns prod/dev scopes via BFS from .csproj PackageReference declarations
  - Merges duplicate PURLs across multi-project repos
  - PURL: pkg:nuget/<name>@<version>
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class CSharpNuGetScanner:

    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    def _nuget_purl(self,name: str, version: str) -> str:
        base = f"pkg:nuget/{name.lower()}"
        return f"{base}@{version}" if version else base

    # ------------------------------------------------------------------ #
    # Detect .NET root                                                     #
    # ------------------------------------------------------------------ #

    def _is_dotnet_root(directory: str) -> bool:
        try:
            return any(
                re.search(r"\.(cs|fs|vb)proj$", f)
                for f in os.listdir(directory)
            )
        except OSError:
            return False

    # ------------------------------------------------------------------ #
    # Central Package Management (Directory.Packages.props)               #
    # ------------------------------------------------------------------ #

    def _read_central_package_props(start_dir: str) -> Dict[str, str]:
        versions: Dict[str, str] = {}
        directory = start_dir
        for _ in range(8):
            candidate = os.path.join(directory, "Directory.Packages.props")
            if os.path.exists(candidate):
                try:
                    xml = Path(candidate).read_text(encoding="utf-8")
                except OSError:
                    break
                pattern = re.compile(
                    r'<PackageVersion[\s\S]*?Include=["\']([^"\']+)["\'][\s\S]*?Version=["\']([^"\']+)["\']',
                    re.IGNORECASE,
                )
                for m in pattern.finditer(xml):
                    versions[m.group(1).lower()] = m.group(2)
                break
            parent = os.path.dirname(directory)
            if parent == directory:
                break
            directory = parent
        return versions

    # ------------------------------------------------------------------ #
    # Version comparison                                                   #
    # ------------------------------------------------------------------ #

    def _version_gt(a: str, b: str) -> bool:
        def parse(v: str) -> List[int]:
            return [int(p) if p.isdigit() else 0 for p in re.split(r"[.\-]", v)]
        pa, pb = parse(a), parse(b)
        for i in range(max(len(pa), len(pb))):
            ai = pa[i] if i < len(pa) else 0
            bi = pb[i] if i < len(pb) else 0
            if ai != bi:
                return ai > bi
        return False

    # ------------------------------------------------------------------ #
    # packages.lock.json                                                   #
    # ------------------------------------------------------------------ #

    def _read_packages_lock(self,project_root: str) -> Optional[Dict[str, Any]]:
        lock_path = os.path.join(project_root, "packages.lock.json")
        if not os.path.exists(lock_path):
            return None
        try:
            raw = json.loads(Path(lock_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        index: Dict[str, Any] = {}
        for tfm_deps in raw.get("dependencies", {}).values():
            for pkg_id, meta in tfm_deps.items():
                key = pkg_id.lower()
                version = meta.get("resolved") or meta.get("requested") or ""
                if not version:
                    continue
                if key not in index:
                    index[key] = {
                        "name": pkg_id,
                        "version": version,
                        "type": (meta.get("type") or "direct").lower(),
                        "dependencies": [d.lower() for d in meta.get("dependencies", {})],
                    }
                else:
                    if self._version_gt(version, index[key]["version"]):
                        index[key]["version"] = version

        return index if index else None

    # ------------------------------------------------------------------ #
    # obj/project.assets.json                                              #
    # ------------------------------------------------------------------ #

    def _read_project_assets(project_root: str) -> Optional[Dict[str, Any]]:
        asset_path = os.path.join(project_root, "obj", "project.assets.json")
        if not os.path.exists(asset_path):
            return None
        try:
            raw = json.loads(Path(asset_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None

        index: Dict[str, Any] = {}
        for lib_key, meta in raw.get("libraries", {}).items():
            slash = lib_key.rfind("/")
            name    = lib_key[:slash]  if slash >= 0 else lib_key
            version = lib_key[slash+1:] if slash >= 0 else ""
            if not version:
                continue
            key = name.lower()
            if key not in index:
                index[key] = {
                    "name": name,
                    "version": version,
                    "type": (meta.get("type") or "package").lower(),
                    "dependencies": [d.lower() for d in meta.get("dependencies", {})],
                }

        return index if index else None

    # ------------------------------------------------------------------ #
    # .csproj direct deps                                                  #
    # ------------------------------------------------------------------ #

    def _read_csproj_deps(self,project_root: str) -> Tuple[Set[str], Set[str]]:
        prod: Set[str] = set()
        dev:  Set[str] = set()

        try:
            proj_file = next(
                (f for f in os.listdir(project_root) if re.search(r"\.(cs|fs|vb)proj$", f)),
                None,
            )
        except OSError:
            return prod, dev

        if not proj_file:
            return prod, dev

        try:
            xml = Path(os.path.join(project_root, proj_file)).read_text(encoding="utf-8")
        except OSError:
            return prod, dev

        pattern = re.compile(
            r"<PackageReference\b([\s\S]*?)(?:/>|>[\s\S]*?</PackageReference>)",
            re.IGNORECASE,
        )
        for m in pattern.finditer(xml):
            attrs = m.group(1)
            name_m = re.search(r'\bInclude=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            if not name_m:
                continue
            name = name_m.group(1).lower()
            cond_m = re.search(r'\bCondition=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
            condition = (cond_m.group(1) if cond_m else "").lower()
            if condition and ("debug" in condition or "test" in condition):
                dev.add(name)
            else:
                prod.add(name)

        return prod, dev

    # ------------------------------------------------------------------ #
    # Scan one project                                                     #
    # ------------------------------------------------------------------ #

    def _scan_project(self,project_root: str) -> List[Dict[str, Any]]:
        index = (
            self._read_packages_lock(project_root)
            or self._read_project_assets(project_root)
        )
        if not index:
            return []

        components: List[Dict[str, Any]] = []

        for key, entry in index.items():
            name    = entry["name"]
            version = entry["version"]
            cid     = self._nuget_purl(name, version)

            resolved_deps: List[str] = []
            for dep in entry["dependencies"]:
                if dep in index:
                    d = index[dep]
                    resolved_deps.append(self._nuget_purl(d["name"], d["version"]))
                else:
                    resolved_deps.append(self._nuget_purl(dep, ""))

            components.append({
                "id":           cid,
                "name":         key,
                "version":      version,
                "type":         "library",
                "license":      "unknown",
                "ecosystem":    "csharp",
                "state":        "undetermined" if version else "version_unknown",
                "scopes":       [],
                "dependencies": resolved_deps,
                "paths":        [project_root],
                "project_root": project_root,
                "_nuget_type":  entry["type"],
            })

        return components

    # ------------------------------------------------------------------ #
    # BFS scope propagation                                                #
    # ------------------------------------------------------------------ #

    def _assign_scopes(self,inventory: List[Dict[str, Any]]) -> None:
        by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

        for comp in inventory:
            if not isinstance(comp.get("scopes"), list):
                comp["scopes"] = []

        # Group by project root
        project_groups: Dict[str, List[Dict]] = {}
        for comp in inventory:
            root = comp["project_root"]
            project_groups.setdefault(root, []).append(comp)

        for project_root, comps in project_groups.items():
            name_idx: Dict[str, List[Dict]] = {}
            for c in comps:
                name_idx.setdefault(c["name"], []).append(c)

            prod, dev = self._read_csproj_deps(project_root)

            if not prod and not dev:
                csproj_exists = False
                try:
                    csproj_exists = any(
                        re.search(r"\.(cs|fs|vb)proj$", f)
                        for f in os.listdir(project_root)
                    )
                except OSError:
                    pass
                if not csproj_exists:
                    for c in comps:
                        if c.get("_nuget_type") == "direct":
                            prod.add(c["name"])

            def propagate(names: Set[str], scope: str) -> None:
                queue = [c for n in names for c in name_idx.get(n, [])]
                visited: Set[str] = set()
                while queue:
                    c = queue.pop(0)
                    if c["id"] in visited:
                        continue
                    visited.add(c["id"])
                    if scope not in c["scopes"]:
                        c["scopes"].append(scope)
                    for dep_id in c["dependencies"]:
                        d = by_id.get(dep_id)
                        if d and d.get("project_root") == project_root:
                            queue.append(d)

            propagate(prod, "prod")
            propagate(dev,  "dev")

            for c in comps:
                if not c["scopes"]:
                    c["scopes"].append("prod")

    # ------------------------------------------------------------------ #
    # Merge by PURL                                                        #
    # ------------------------------------------------------------------ #

    def merge_inventory_by_purl(self,components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged: Dict[str, Dict] = {}
        for comp in components:
            cid = comp["id"]
            if cid not in merged:
                clone = dict(comp)
                clone["paths"]  = list(comp.get("paths", []))
                clone["scopes"] = list(comp.get("scopes", []))
                merged[cid] = clone
                continue
            existing = merged[cid]
            for p in comp.get("paths", []):
                if p not in existing["paths"]:
                    existing["paths"].append(p)
            for s in comp.get("scopes", []):
                if s not in existing["scopes"]:
                    existing["scopes"].append(s)
        return list(merged.values())

    # ------------------------------------------------------------------ #
    # ENTRY                                                                #
    # ------------------------------------------------------------------ #

    def get_installed(self, start_dir: str = ".") -> List[str]:
        self.inventory_data = []
        start_dir = os.path.abspath(start_dir)

        visited: Set[str] = set()
        raw: List[Dict[str, Any]] = []

        if self._is_dotnet_root(start_dir):
            visited.add(start_dir)
            raw.extend(self._scan_project(start_dir))

        skip = {"node_modules", ".git", ".ubel", "obj", "bin", "packages"}

        def walk(directory: str) -> None:
            try:
                entries = os.scandir(directory)
            except OSError:
                return
            with entries as it:
                for entry in it:
                    if not entry.is_dir(follow_symlinks=False):
                        continue
                    if entry.name in skip:
                        continue
                    full = entry.path
                    key  = os.path.realpath(full)
                    if self._is_dotnet_root(full):
                        if key not in visited:
                            visited.add(key)
                            raw.extend(self._scan_project(full))
                        continue
                    walk(full)

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self._assign_scopes(merged)

        for c in merged:
            c.pop("_nuget_type", None)

        self.inventory_data = merged
        return [c["id"] for c in merged]