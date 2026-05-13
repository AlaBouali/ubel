"""
go_scanner.py — Go / go.mod scanner (getInstalled only).

Mirrors the JS GoModScanner:
  - Detects Go module roots (go.mod + go.sum)
  - Reads go.sum for resolved deps, go.mod for direct/indirect classification
  - Applies replace directives
  - Assigns scopes via test-path heuristics (no native dev-dep concept in Go)
  - Merges duplicate PURLs
  - PURL: pkg:golang/<module-path>@<version>  (leading "v" stripped)
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple


class GoModScanner:


    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    
    def _go_purl(self,module_path: str, version: str) -> str:
        v = version.lstrip("v") if version else ""
        return f"pkg:golang/{module_path.lower()}@{v}"

    # ------------------------------------------------------------------ #
    # Detect Go module root                                                #
    # ------------------------------------------------------------------ #

    
    def _is_go_root(self,directory: str) -> bool:
        return (
            os.path.exists(os.path.join(directory, "go.mod")) and
            os.path.exists(os.path.join(directory, "go.sum"))
        )

    # ------------------------------------------------------------------ #
    # Parse go.mod                                                         #
    # ------------------------------------------------------------------ #

    
    def _parse_go_mod(self,mod_path: str) -> Tuple[str, Dict[str, Any], Dict[str, Any]]:
        """
        Returns (module_name, requires, replaces).
        requires: lowercase_path → { path, version, indirect }
        replaces: lowercase_path → { original, replacement, version }
        """
        requires: Dict[str, Any] = {}
        replaces: Dict[str, Any] = {}
        module_name = ""

        try:
            content = Path(mod_path).read_text(encoding="utf-8")
        except OSError:
            return module_name, requires, replaces

        in_require = False
        in_replace = False

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("//"):
                continue

            if line.startswith("module "):
                module_name = line[7:].strip().split()[0]
                continue

            if line == "require (":
                in_require = True;  continue
            if line == "replace (":
                in_replace = True;  continue
            if line == ")":
                in_require = False; in_replace = False; continue

            # Inline single-line require
            m = re.match(r"^require\s+(\S+)\s+(\S+)(.*//\s*indirect)?", line)
            if m:
                mp, ver, ind = m.group(1), m.group(2), bool(m.group(3))
                requires[mp.lower()] = {"path": mp, "version": ver, "indirect": ind}
                continue

            if in_require:
                m = re.match(r"^(\S+)\s+(\S+)(.*//\s*indirect)?", line)
                if m:
                    mp, ver, ind = m.group(1), m.group(2), bool(m.group(3))
                    requires[mp.lower()] = {"path": mp, "version": ver, "indirect": ind}
                continue

            if in_replace:
                # "github.com/old/pkg => github.com/new/pkg v1.0.0"
                m = re.match(r"^(\S+)(?:\s+\S+)?\s+=>\s+(\S+)\s+(\S+)", line)
                if m:
                    replaces[m.group(1).lower()] = {
                        "original":    m.group(1),
                        "replacement": m.group(2),
                        "version":     m.group(3),
                    }
                continue

        return module_name, requires, replaces

    # ------------------------------------------------------------------ #
    # Parse go.sum                                                         #
    # ------------------------------------------------------------------ #

    
    def _parse_go_sum(self,sum_path: str) -> Dict[str, Any]:
        """Returns lowercase_path → { path, version }"""
        installed: Dict[str, Any] = {}

        try:
            content = Path(sum_path).read_text(encoding="utf-8")
        except OSError:
            return installed

        for raw_line in content.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            parts = line.split()
            if len(parts) < 2:
                continue
            mod_ver = parts[0]
            if mod_ver.endswith("/go.mod"):
                continue
            at_idx = mod_ver.rfind("@")
            if at_idx < 0:
                continue
            mod_path = mod_ver[:at_idx]
            version  = mod_ver[at_idx + 1:]
            key = mod_path.lower()
            if key not in installed:
                installed[key] = {"path": mod_path, "version": version}

        return installed

    # ------------------------------------------------------------------ #
    # Scan one Go module root                                              #
    # ------------------------------------------------------------------ #

    
    def _scan_project(self,project_root: str) -> List[Dict[str, Any]]:
        _, requires, replaces = self._parse_go_mod(
            os.path.join(project_root, "go.mod")
        )
        sum_entries = self._parse_go_sum(
            os.path.join(project_root, "go.sum")
        )

        if not sum_entries and not requires:
            return []

        # Prefer go.sum versions (actually downloaded); fallback to go.mod
        index: Dict[str, Any] = {}
        for key, entry in sum_entries.items():
            req = requires.get(key)
            index[key] = {
                "path":     entry["path"],
                "version":  entry["version"],
                "indirect": req["indirect"] if req else True,
            }
        for key, entry in requires.items():
            if key not in index:
                index[key] = {
                    "path":     entry["path"],
                    "version":  entry["version"],
                    "indirect": entry["indirect"],
                }

        # Apply replace directives
        for orig_key, rep in replaces.items():
            if orig_key in index:
                index[orig_key]["path"]    = rep["replacement"]
                index[orig_key]["version"] = rep["version"]

        components: List[Dict[str, Any]] = []
        for entry in index.values():
            mp      = entry["path"]
            version = entry["version"]
            cid     = self._go_purl(mp, version)

            components.append({
                "id":           cid,
                "name":         mp.lower(),
                "version":      version.lstrip("v"),
                "type":         "library",
                "license":      "unknown",
                "ecosystem":    "golang",
                "state":        "undetermined",
                "scopes":       [],
                "dependencies": [],
                "paths":        [project_root],
                "project_root": project_root,
                "_indirect":    entry["indirect"],
            })

        return components

    # ------------------------------------------------------------------ #
    # Assign scopes                                                        #
    # ------------------------------------------------------------------ #

    
    def _assign_scopes(inventory: List[Dict[str, Any]]) -> None:
        test_patterns = [
            "/testing", "/testutil", "/mock", "test", "gomock", "testify"
        ]
        for comp in inventory:
            if not isinstance(comp.get("scopes"), list):
                comp["scopes"] = []
            if comp["scopes"]:
                continue
            name = comp["name"]
            is_test = any(p in name for p in test_patterns)
            comp["scopes"].append("dev" if is_test else "prod")

    # ------------------------------------------------------------------ #
    # Merge by PURL                                                        #
    # ------------------------------------------------------------------ #

    
    def merge_inventory_by_purl(components: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
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
                    if self._is_go_root(full):
                        key = os.path.realpath(full)
                        if key not in visited:
                            visited.add(key)
                            raw.extend(self._scan_project(full))
                    walk(full)

        if self._is_go_root(start_dir):
            key = os.path.realpath(start_dir)
            if key not in visited:
                visited.add(key)
                raw.extend(self._scan_project(start_dir))

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self._assign_scopes(merged)

        for c in merged:
            c.pop("_indirect", None)

        self.inventory_data = merged
        return [c["id"] for c in merged]