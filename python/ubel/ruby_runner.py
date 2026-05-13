"""
ruby_scanner.py — Ruby / Bundler scanner (getInstalled only).

Mirrors the JS RubyBundlerScanner:
  - Detects Bundler roots (Gemfile + Gemfile.lock)
  - Reads Gemfile.lock for the full resolved gem graph
  - Reads Gemfile for group classifications (dev/test → dev, else → prod)
  - Assigns scopes via BFS from Gemfile groups
  - Merges duplicate PURLs
  - PURL: pkg:gem/<name>@<version>
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Set


class RubyBundlerScanner:

    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    
    def _gem_purl(self,name: str, version: str) -> str:
        return f"pkg:gem/{name.lower()}@{version or ''}"

    # ------------------------------------------------------------------ #
    # Detect Bundler root                                                  #
    # ------------------------------------------------------------------ #

    
    def _is_bundler_root(self,directory: str) -> bool:
        return (
            os.path.exists(os.path.join(directory, "Gemfile")) and
            os.path.exists(os.path.join(directory, "Gemfile.lock"))
        )

    # ------------------------------------------------------------------ #
    # Parse Gemfile.lock                                                   #
    # ------------------------------------------------------------------ #

    
    def _parse_gemfile_lock(self,lock_path: str) -> Dict[str, Any]:
        """Returns lowercase_name → { name, version, dependencies: [lowercase names] }"""
        try:
            content = Path(lock_path).read_text(encoding="utf-8")
        except OSError:
            return {}

        index: Dict[str, Any] = {}
        in_specs   = False
        current_gem = None

        for raw_line in content.splitlines():
            line    = raw_line
            trimmed = line.strip()

            # Section header detection
            if re.match(r"^(GEM|PATH|GIT)$", trimmed):
                in_specs    = False
                current_gem = None
                continue

            if trimmed == "specs:":
                in_specs    = True
                current_gem = None
                continue

            # Exit on new uppercase section (PLATFORMS, DEPENDENCIES, etc.)
            if re.match(r"^[A-Z]", line) and trimmed != "specs:":
                in_specs    = False
                current_gem = None
                continue

            if not in_specs:
                continue

            indent  = len(line) - len(line.lstrip())
            if not trimmed:
                continue

            if indent == 4:
                # Top-level gem: "    name (version)"
                m = re.match(r"^([A-Za-z0-9_.\-]+)\s+\(([^)]+)\)", trimmed)
                if not m:
                    current_gem = None
                    continue
                name    = m.group(1)
                version = m.group(2).split(", ")[0]
                key     = name.lower()
                current_gem = {"name": name, "version": version, "dependencies": []}
                index[key]  = current_gem

            elif indent >= 6 and current_gem is not None:
                # Dependency of current gem
                m = re.match(r"^([A-Za-z0-9_.\-]+)", trimmed)
                if m:
                    current_gem["dependencies"].append(m.group(1).lower())

        return index

    # ------------------------------------------------------------------ #
    # Parse Gemfile for group classification                               #
    # ------------------------------------------------------------------ #

    
    def _parse_gemfile_groups(self,gemfile_path: str) -> tuple:
        """Returns (prod: Set[str], dev: Set[str])"""
        prod: Set[str] = set()
        dev:  Set[str] = set()

        try:
            content = Path(gemfile_path).read_text(encoding="utf-8")
        except OSError:
            return prod, dev

        DEV_GROUPS = {"development", "test", "staging"}
        current_groups: List[str] = []

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue

            # group :development, :test do
            group_block = re.match(r"^group\s+(.*?)\s+do$", line)
            if group_block:
                current_groups = [
                    g.strip().lstrip(":").lower()
                    for g in group_block.group(1).split(",")
                ]
                continue

            if line == "end":
                current_groups = []
                continue

            # gem 'name', ...
            gem_line = re.match(r'^gem\s+[\'"]([^\'"]+)[\'\"](.*)', line)
            if not gem_line:
                continue

            gem_name = gem_line.group(1).lower()
            rest     = gem_line.group(2) or ""

            # Inline group: group: :test  OR  groups: [:development, :test]
            inline_group = re.search(r"groups?:\s*(\[?[^,\]]+\]?)", rest)
            groups = list(current_groups)
            if inline_group:
                g_str  = re.sub(r"[\[\]]", "", inline_group.group(1))
                extras = [g.strip().lstrip(":").lower() for g in g_str.split(",")]
                groups = list(set(groups + extras))

            if any(g in DEV_GROUPS for g in groups):
                dev.add(gem_name)
            else:
                prod.add(gem_name)

        return prod, dev

    # ------------------------------------------------------------------ #
    # Scan one Bundler project                                             #
    # ------------------------------------------------------------------ #

    
    def _scan_project(self,project_root: str) -> List[Dict[str, Any]]:
        index = self._parse_gemfile_lock(
            os.path.join(project_root, "Gemfile.lock")
        )
        if not index:
            return []

        components: List[Dict[str, Any]] = []

        for key, entry in index.items():
            name    = entry["name"]
            version = entry["version"]
            cid     = self._gem_purl(name, version)

            resolved_deps: List[str] = []
            for dep in entry["dependencies"]:
                resolved = index.get(dep)
                if resolved:
                    resolved_deps.append(
                        self._gem_purl(resolved["name"], resolved["version"])
                    )
                else:
                    resolved_deps.append(self._gem_purl(dep, ""))

            components.append({
                "id":           cid,
                "name":         key,
                "version":      version,
                "type":         "library",
                "license":      "unknown",
                "ecosystem":    "ruby",
                "state":        "undetermined",
                "scopes":       [],
                "dependencies": resolved_deps,
                "paths":        [project_root],
                "project_root": project_root,
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
            prod, dev = self._parse_gemfile_groups(
                os.path.join(project_root, "Gemfile")
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

            propagate(prod, "prod")
            propagate(dev,  "dev")

            # Fallback
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

        skip = {"node_modules", ".git", ".ubel", "vendor", ".bundle"}

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
                    if self._is_bundler_root(full):
                        key = os.path.realpath(full)
                        if key not in visited:
                            visited.add(key)
                            raw.extend(self._scan_project(full))
                        continue
                    walk(full)

        if self._is_bundler_root(start_dir):
            key = os.path.realpath(start_dir)
            if key not in visited:
                visited.add(key)
                raw.extend(self._scan_project(start_dir))

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self._assign_scopes(merged)

        self.inventory_data = merged
        return [c["id"] for c in merged]