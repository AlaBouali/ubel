"""
rust_scanner.py — Rust / Cargo scanner (getInstalled only).

Mirrors the JS RustCargoScanner:
  - Detects Cargo project roots (Cargo.toml + Cargo.lock)
  - Parses Cargo.lock (v1/v2/v3 [[package]] format) for fully-resolved crates
  - Reads Cargo.toml [dependencies] / [dev-dependencies] / [build-dependencies]
    for scope seeding; BFS propagates through the dep graph
  - Descends into workspace member crates
  - Merges duplicate PURLs
  - PURL: pkg:cargo/<name>@<version>
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set


class RustCargoScanner:

    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    
    def _cargo_purl(self,name: str, version: str) -> str:
        return f"pkg:cargo/{name.lower()}@{version or ''}"

    # ------------------------------------------------------------------ #
    # Detect Cargo root                                                    #
    # ------------------------------------------------------------------ #

    
    def _is_cargo_root(self,directory: str) -> bool:
        return (
            os.path.exists(os.path.join(directory, "Cargo.toml")) and
            os.path.exists(os.path.join(directory, "Cargo.lock"))
        )

    # ------------------------------------------------------------------ #
    # Parse Cargo.lock                                                     #
    # ------------------------------------------------------------------ #

    
    def _parse_cargo_lock(self,lock_path: str) -> List[Dict[str, Any]]:
        try:
            content = Path(lock_path).read_text(encoding="utf-8")
        except OSError:
            return []

        packages: List[Dict[str, Any]] = []
        # Split on [[package]] sections
        blocks = re.split(r"^\[\[package\]\]", content, flags=re.MULTILINE)[1:]

        for block in blocks:
            name_m = re.search(r'^name\s*=\s*"([^"]+)"',    block, re.MULTILINE)
            ver_m  = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
            src_m  = re.search(r'^source\s*=\s*"([^"]+)"',  block, re.MULTILINE)

            if not name_m or not ver_m:
                continue

            name    = name_m.group(1)
            version = ver_m.group(1)
            source  = src_m.group(1) if src_m else "local"

            # dependencies = [ "bar 0.4.0", "baz 1.0.0 (...)" ]
            deps: List[Dict[str, str]] = []
            deps_m = re.search(
                r"^dependencies\s*=\s*\[([^\]]*)\]", block, re.MULTILINE | re.DOTALL
            )
            if deps_m:
                for dm in re.finditer(r'"([^"]+)"', deps_m.group(1)):
                    parts = dm.group(1).split()
                    deps.append({"name": parts[0], "version": parts[1] if len(parts) > 1 else ""})

            packages.append({"name": name, "version": version, "source": source, "dependencies": deps})

        return packages

    # ------------------------------------------------------------------ #
    # Read Cargo.toml dep sections                                         #
    # ------------------------------------------------------------------ #

    
    def _read_cargo_toml_deps(self,toml_path: str) -> tuple:
        """Returns (prod: Set[str], dev: Set[str], build: Set[str])"""
        prod:  Set[str] = set()
        dev:   Set[str] = set()
        build: Set[str] = set()

        try:
            content = Path(toml_path).read_text(encoding="utf-8")
        except OSError:
            return prod, dev, build

        section = ""
        for line in content.splitlines():
            trimmed = line.strip()

            sec_m = re.match(r"^\[([^\]]+)\]", trimmed)
            if sec_m:
                section = sec_m.group(1).strip()
                continue

            is_dep_section = (
                section == "dependencies" or
                section == "dev-dependencies" or
                section == "build-dependencies" or
                section.endswith(".dependencies")
            )
            if not is_dep_section:
                continue

            kv_m = re.match(r"^([A-Za-z0-9_-]+)\s*[=.]", trimmed)
            if kv_m:
                # Cargo normalises hyphens to underscores in crate names
                name = kv_m.group(1).lower().replace("-", "_")
                if section == "dev-dependencies":
                    dev.add(name)
                elif section == "build-dependencies":
                    build.add(name)
                else:
                    prod.add(name)

        return prod, dev, build

    # ------------------------------------------------------------------ #
    # Scan one Cargo project                                               #
    # ------------------------------------------------------------------ #

    
    def _scan_project(self,project_root: str) -> List[Dict[str, Any]]:
        packages = self._parse_cargo_lock(
            os.path.join(project_root, "Cargo.lock")
        )
        if not packages:
            return []

        # Build lookup indexes
        full_index: Dict[str, Any] = {}    # "name@version" → package
        name_index: Dict[str, Any] = {}    # "normalized_name" → package (last wins)

        for pkg in packages:
            key       = f"{pkg['name'].lower()}@{pkg['version']}"
            norm_name = pkg["name"].lower().replace("-", "_")
            if key not in full_index:
                full_index[key] = pkg
            name_index[norm_name] = pkg

        components: List[Dict[str, Any]] = []

        for pkg in packages:
            name    = pkg["name"].lower().replace("-", "_")
            cid     = self._cargo_purl(pkg["name"], pkg["version"])
            is_local = pkg["source"] == "local" or not pkg["source"].startswith("registry")

            dependencies: List[str] = []
            for dep in pkg["dependencies"]:
                dep_name = dep["name"].lower().replace("-", "_")
                dep_key  = f"{dep_name}@{dep['version']}"
                resolved = full_index.get(dep_key) or name_index.get(dep_name)
                if resolved:
                    dependencies.append(
                        self._cargo_purl(resolved["name"], resolved["version"])
                    )
                else:
                    dependencies.append(self._cargo_purl(dep["name"], dep["version"]))

            components.append({
                "id":           cid,
                "name":         name,
                "version":      pkg["version"],
                "type":         "library",
                "license":      "unknown",
                "ecosystem":    "rust",
                "state":        "undetermined",
                "scopes":       [],
                "dependencies": dependencies,
                "paths":        [project_root if is_local else pkg["source"]],
                "project_root": project_root,
                "_source":      pkg["source"],
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
            prod, dev, build = self._read_cargo_toml_deps(
                os.path.join(project_root, "Cargo.toml")
            )

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

            propagate(prod,  "prod")
            propagate(dev,   "dev")
            propagate(build, "build")

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

        skip = {"node_modules", ".git", ".ubel", "target"}

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
                    if self._is_cargo_root(full):
                        key = os.path.realpath(full)
                        if key not in visited:
                            visited.add(key)
                            raw.extend(self._scan_project(full))
                        # Still descend – workspace member crates live inside
                    walk(full)

        if self._is_cargo_root(start_dir):
            key = os.path.realpath(start_dir)
            if key not in visited:
                visited.add(key)
                raw.extend(self._scan_project(start_dir))

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self._assign_scopes(merged)

        for c in merged:
            c.pop("_source", None)

        self.inventory_data = merged
        return [c["id"] for c in merged]