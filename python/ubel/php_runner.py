"""
php_scanner.py — PHP / Composer scanner (getInstalled only).

Mirrors the JS PhpComposerScanner:
  - Detects Composer roots (composer.json + vendor/)
  - Reads vendor/composer/installed.json (v1 bare array, v2 { packages: [...] })
  - Assigns prod/dev scopes via BFS from root composer.json require / require-dev
  - Respects per-package "dev" flag written by Composer v2
  - Merges duplicate PURLs
  - PURL: pkg:composer/<vendor>/<package>@<version>
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Set


class PhpComposerScanner:

    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    
    def _composer_purl(self,name: str, version: str) -> str:
        clean = name.lower()
        return f"pkg:composer/{clean}@{version or ''}"

    # ------------------------------------------------------------------ #
    # Detect Composer root                                                 #
    # ------------------------------------------------------------------ #

    
    def _is_composer_root(self,directory: str) -> bool:
        return (
            os.path.exists(os.path.join(directory, "composer.json")) and
            os.path.exists(os.path.join(directory, "vendor"))
        )

    # ------------------------------------------------------------------ #
    # Read installed.json                                                  #
    # ------------------------------------------------------------------ #

    
    def _read_installed_json(self,vendor_dir: str) -> List[Dict[str, Any]]:
        installed_path = os.path.join(vendor_dir, "composer", "installed.json")
        if not os.path.exists(installed_path):
            return []
        try:
            raw = json.loads(Path(installed_path).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        # v2 wraps under { "packages": [...] }; v1 is a bare array
        return raw if isinstance(raw, list) else raw.get("packages", [])

    # ------------------------------------------------------------------ #
    # Normalize version                                                    #
    # ------------------------------------------------------------------ #

    
    def _normalise_version(self,v: str) -> str:
        if not v:
            return ""
        return v.lstrip("vV")

    # ------------------------------------------------------------------ #
    # Extract license                                                      #
    # ------------------------------------------------------------------ #

    
    def _extract_license(self,pkg: Dict[str, Any]) -> str:
        lic = pkg.get("license") or pkg.get("licence") or "unknown"
        if isinstance(lic, list):
            return " OR ".join(lic) or "unknown"
        return lic or "unknown"

    # ------------------------------------------------------------------ #
    # Scan one Composer project                                            #
    # ------------------------------------------------------------------ #

    
    def _scan_project(self,project_root: str) -> List[Dict[str, Any]]:
        vendor_dir = os.path.join(project_root, "vendor")
        packages   = self._read_installed_json(vendor_dir)
        if not packages:
            return []

        # Pass 1 – build name index
        name_index: Dict[str, Any] = {}
        for pkg in packages:
            raw_name = pkg.get("name")
            if not raw_name:
                continue
            norm    = raw_name.lower()
            version = self._normalise_version(
                pkg.get("version") or pkg.get("version_normalized") or ""
            )
            name_index[norm] = {"name": raw_name, "version": version, "pkg": pkg}

        # Pass 2 – build components
        components: List[Dict[str, Any]] = []

        for norm, entry in name_index.items():
            name    = entry["name"]
            version = entry["version"]
            pkg     = entry["pkg"]
            cid     = self._composer_purl(name, version)
            license_ = self._extract_license(pkg)

            require_map = pkg.get("require") or {}
            dependencies: List[str] = []
            for dep in require_map:
                dep_lower = dep.lower()
                if dep_lower == "php" or dep_lower.startswith("ext-"):
                    continue
                resolved = name_index.get(dep_lower)
                if resolved:
                    dependencies.append(
                        self._composer_purl(resolved["name"], resolved["version"])
                    )
                else:
                    dependencies.append(self._composer_purl(dep_lower, ""))

            install_path = os.path.join(vendor_dir, *name.split("/"))

            is_dev = (
                pkg.get("dev-requirements") is True or
                pkg.get("dev") is True
            )

            components.append({
                "id":           cid,
                "name":         norm,
                "version":      version,
                "type":         "library",
                "license":      license_,
                "ecosystem":    "php",
                "state":        "undetermined",
                "scopes":       [],
                "dependencies": dependencies,
                "paths":        [install_path],
                "project_root": project_root,
                "dev":          is_dev,
            })

        return components

    # ------------------------------------------------------------------ #
    # Assign scopes                                                        #
    # ------------------------------------------------------------------ #

    
    def _assign_scopes(self,inventory: List[Dict[str, Any]]) -> None:
        by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}
        name_idx: Dict[str, List[Dict]] = {}

        for comp in inventory:
            if not isinstance(comp.get("scopes"), list):
                comp["scopes"] = []
            name_idx.setdefault(comp["name"], []).append(comp)

        project_groups: Dict[str, List[Dict]] = {}
        for comp in inventory:
            project_groups.setdefault(comp["project_root"], []).append(comp)

        for project_root, comps in project_groups.items():
            try:
                root_manifest = json.loads(
                    Path(os.path.join(project_root, "composer.json")).read_text(encoding="utf-8")
                )
            except (OSError, json.JSONDecodeError):
                root_manifest = {}

            prod = {k.lower() for k in root_manifest.get("require", {})}
            dev  = {k.lower() for k in root_manifest.get("require-dev", {})}

            # Also honour per-package dev flag from Composer v2
            for comp in comps:
                if comp.get("dev"):
                    dev.add(comp["name"])

            def propagate(names: Set[str], scope: str) -> None:
                queue = [
                    c for n in names
                    for c in name_idx.get(n, [])
                    if c["project_root"] == project_root
                ]
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

            if not prod and not dev:
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

        skip = {"node_modules", ".git", ".ubel", "vendor"}

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
                    if self._is_composer_root(full):
                        key = os.path.realpath(full)
                        if key not in visited:
                            visited.add(key)
                            raw.extend(self._scan_project(full))
                        continue
                    walk(full)

        if self._is_composer_root(start_dir):
            key = os.path.realpath(start_dir)
            if key not in visited:
                visited.add(key)
                raw.extend(self._scan_project(start_dir))

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self._assign_scopes(merged)

        for c in merged:
            c.pop("dev", None)

        self.inventory_data = merged
        return [c["id"] for c in merged]