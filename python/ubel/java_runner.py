"""
java_scanner.py — Java / Maven scanner (getInstalled only).

Mirrors the JS JavaMavenScanner:
  - Detects Maven project roots (pom.xml)
  - Reads .ubel/maven-deps.txt (mvn dependency:tree output) if present,
    otherwise parses pom.xml <dependency> blocks
  - Resolves ${property} version references from <properties>
  - Follows <modules> for multi-module builds (shared visited set)
  - Maps Maven scope → UBEL scope  (test → dev, rest → prod)
  - Merges duplicate PURLs
  - PURL: pkg:maven/<groupId>/<artifactId>@<version>
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Set


class JavaMavenScanner:

    # ------------------------------------------------------------------ #
    # PURL                                                                 #
    # ------------------------------------------------------------------ #

    
    def _maven_purl(self,group_id: str, artifact_id: str, version: str) -> str:
        base = f"pkg:maven/{group_id.lower()}/{artifact_id.lower()}"
        return f"{base}@{version}" if version else f"{base}@"

    # ------------------------------------------------------------------ #
    # Detect Maven root                                                    #
    # ------------------------------------------------------------------ #

    
    def _is_maven_root(self,directory: str) -> bool:
        return os.path.exists(os.path.join(directory, "pom.xml"))

    # ------------------------------------------------------------------ #
    # Minimal XML tag extractor                                            #
    # ------------------------------------------------------------------ #

    
    def _extract_tag(self,xml: str, tag: str) -> List[str]:
        return re.findall(
            rf"<{re.escape(tag)}[^>]*>([^<]*)</{re.escape(tag)}>",
            xml,
            re.IGNORECASE,
        )

    # ------------------------------------------------------------------ #
    # Parse <dependency> blocks from pom.xml                              #
    # ------------------------------------------------------------------ #

    
    def _parse_pom_deps(self,xml: str) -> List[Dict[str, str]]:
        deps: List[Dict[str, str]] = []
        for block_m in re.finditer(r"<dependency>([\s\S]*?)</dependency>", xml, re.IGNORECASE):
            block = block_m.group(1)
            group_id    = (self._extract_tag(block, "groupId")    or [""])[0]
            artifact_id = (self._extract_tag(block, "artifactId") or [""])[0]
            version     = (self._extract_tag(block, "version")    or [""])[0]
            scope       = (self._extract_tag(block, "scope")      or ["compile"])[0]
            optional    = (self._extract_tag(block, "optional")   or ["false"])[0]
            if group_id and artifact_id and optional.strip().lower() != "true":
                deps.append({
                    "groupId":    group_id.strip(),
                    "artifactId": artifact_id.strip(),
                    "version":    version.strip(),
                    "scope":      scope.strip().lower(),
                })
        return deps

    # ------------------------------------------------------------------ #
    # Parse <properties>                                                   #
    # ------------------------------------------------------------------ #

    
    def _parse_pom_properties(self,xml: str) -> Dict[str, str]:
        props: Dict[str, str] = {}
        props_m = re.search(r"<properties>([\s\S]*?)</properties>", xml, re.IGNORECASE)
        if not props_m:
            return props
        block = props_m.group(1)
        for m in re.finditer(r"<([A-Za-z0-9._-]+)>([^<]*)</[A-Za-z0-9._-]+>", block):
            props[m.group(1)] = m.group(2).strip()
        return props

    # ------------------------------------------------------------------ #
    # Resolve ${...} property refs                                         #
    # ------------------------------------------------------------------ #

    
    def _resolve_version(self,version: str, props: Dict[str, str]) -> str:
        if not version:
            return ""
        resolved = re.sub(
            r"\$\{([^}]+)\}",
            lambda m: props.get(m.group(1), ""),
            version,
        )
        return "" if "${" in resolved else resolved

    # ------------------------------------------------------------------ #
    # Parse mvn dependency:tree output                                     #
    # ------------------------------------------------------------------ #

    
    def _parse_deps_tree(self,file_path: str) -> List[Dict[str, str]]:
        deps: List[Dict[str, str]] = []
        try:
            content = Path(file_path).read_text(encoding="utf-8")
        except OSError:
            return deps

        for raw_line in content.splitlines():
            line = re.sub(r"^\[INFO\]\s*", "", raw_line)
            line = re.sub(r"^[|\s\\+\-]+", "", line).strip()
            # groupId:artifactId:packaging:version:scope
            m = re.match(r"^([^:]+):([^:]+):[^:]+:([^:]+):([^:\s]+)", line)
            if m:
                deps.append({
                    "groupId":    m.group(1),
                    "artifactId": m.group(2),
                    "version":    m.group(3),
                    "scope":      m.group(4).lower(),
                })
        return deps

    # ------------------------------------------------------------------ #
    # Parse <modules>                                                      #
    # ------------------------------------------------------------------ #

    
    def _parse_modules(self,xml: str) -> List[str]:
        mods: List[str] = []
        mods_m = re.search(r"<modules>([\s\S]*?)</modules>", xml, re.IGNORECASE)
        if not mods_m:
            return mods
        for m in re.finditer(r"<module>([^<]+)</module>", mods_m.group(1), re.IGNORECASE):
            mods.append(m.group(1).strip())
        return mods

    # ------------------------------------------------------------------ #
    # Maven scope → UBEL scope                                             #
    # ------------------------------------------------------------------ #

    
    def _maven_scope_to_ubel(self,mvn_scope: str) -> str:
        return "dev" if mvn_scope == "test" else "prod"

    # ------------------------------------------------------------------ #
    # Scan one Maven project                                               #
    # ------------------------------------------------------------------ #

    def _scan_project(self, project_root: str, visited: Set[str]) -> List[Dict[str, Any]]:
        key = os.path.realpath(project_root)
        if key in visited:
            return []
        visited.add(key)

        pom_path = os.path.join(project_root, "pom.xml")
        try:
            xml = Path(pom_path).read_text(encoding="utf-8")
        except OSError:
            return []

        # Strip XML comments
        xml = re.sub(r"<!--[\s\S]*?-->", "", xml)

        props      = self._parse_pom_properties(xml)
        components: List[Dict[str, Any]] = []

        # Prefer pre-generated dependency tree
        tree_file = os.path.join(project_root, ".ubel", "maven-deps.txt")
        tree_deps = self._parse_deps_tree(tree_file)

        if tree_deps:
            deps = tree_deps
        else:
            deps = [
                {**d, "version": self._resolve_version(d["version"], props)}
                for d in self._parse_pom_deps(xml)
            ]

        for dep in deps:
            if not dep.get("groupId") or not dep.get("artifactId"):
                continue
            version = dep.get("version") or ""
            if version == "unknown":
                version = ""
            cid   = self._maven_purl(dep["groupId"], dep["artifactId"], version)
            scope = self._maven_scope_to_ubel(dep.get("scope") or "compile")

            components.append({
                "id":           cid,
                "name":         f"{dep['groupId'].lower()}:{dep['artifactId'].lower()}",
                "version":      version,
                "type":         "library",
                "license":      "unknown",
                "ecosystem":    "java",
                "state":        "undetermined",
                "scopes":       [scope],
                "dependencies": [],
                "paths":        [project_root],
                "project_root": project_root,
            })

        # Recurse into <modules>
        for mod in self._parse_modules(xml):
            mod_root = os.path.join(project_root, mod)
            components.extend(self._scan_project(mod_root, visited))

        return components

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

        if self._is_maven_root(start_dir):
            raw.extend(self._scan_project(start_dir, visited))

        skip = {"node_modules", ".git", ".ubel", "target", ".m2"}

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
                    if self._is_maven_root(full):
                        raw.extend(self._scan_project(full, visited))
                        # Don't descend further — _scan_project follows <modules>
                        continue
                    walk(full)

        walk(start_dir)

        merged = self.merge_inventory_by_purl(raw)
        self.inventory_data = merged
        return [c["id"] for c in merged]