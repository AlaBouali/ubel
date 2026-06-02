"""
self.py — Linux host package manager.

Pure-Python, zero external dependencies.
  - OS detection via /etc/os-release (stdlib only, no `distro` package)
  - Package inventory delegated to LinuxHostScanner (linux_host_scanner.py)
  - All other methods (resolve, real install, PURL building, dep sequences)
    preserved 1:1 from the original.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from .os_health import LinuxHostScanner


class Linux_Manager:

    inventory_data: List[Dict[str, Any]] = []

    pkg_manager: Optional[str] = None
    pkg_manager_version: Optional[str] = None

    # ------------------------------------------------------------------ #
    # Dependency sequences                                                 #
    # ------------------------------------------------------------------ #

    
    def build_dependency_sequences(self,inventory: List[Dict]) -> List[Dict]:
        by_id = {c["id"]: c for c in inventory}

        depended: set = set()
        for comp in inventory:
            for dep in comp.get("dependencies", []):
                depended.add(dep)

        roots = [c["id"] for c in inventory if c["id"] not in depended]

        sequences: Dict[str, List] = {}

        def dfs(node: str, path: List[str]) -> None:
            next_path = path + [node]
            sequences.setdefault(node, []).append(next_path)
            for dep in by_id.get(node, {}).get("dependencies", []):
                if dep not in path and dep in by_id:
                    dfs(dep, next_path)

        for root in roots:
            dfs(root, [])

        for comp in inventory:
            comp["dependency_sequences"] = sequences.get(comp["id"], [])

        return inventory

    # ------------------------------------------------------------------ #
    # Merge                                                                #
    # ------------------------------------------------------------------ #

    
    def merge_inventory_by_purl(self,components: List[Dict]) -> List[Dict]:
        merged: Dict[str, Dict] = {}
        for comp in components:
            cid = comp["id"]
            if cid not in merged:
                clone = dict(comp)
                clone["paths"] = list(clone.get("paths", []))
                merged[cid] = clone
                continue
            existing = merged[cid]
            for p in comp.get("paths", []):
                if p and p not in existing["paths"]:
                    existing["paths"].append(p)
        return list(merged.values())

    # ------------------------------------------------------------------ #
    # Shell helpers                                                        #
    # ------------------------------------------------------------------ #

    
    def command_exists(self,cmd: str) -> bool:
        return shutil.which(cmd) is not None

    
    def run_command(self,cmd: List[str]) -> str:
        try:
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError as exc:
            print(f"[!] Command failed: {' '.join(cmd)}", file=sys.stderr)
            print(exc.stderr, file=sys.stderr)
            return ""

    # ------------------------------------------------------------------ #
    # OS detection  (stdlib only — no `distro` package)                   #
    # ------------------------------------------------------------------ #

    
    def _parse_os_release(self) -> Dict[str, str]:
        """Parse /etc/os-release (or /usr/lib/os-release) into a plain dict."""
        data: Dict[str, str] = {}
        for candidate in ("/etc/os-release", "/usr/lib/os-release"):
            try:
                with open(candidate, "r", encoding="utf-8", errors="replace") as fh:
                    for raw in fh:
                        line = raw.strip()
                        if not line or line.startswith("#") or "=" not in line:
                            continue
                        eq  = line.index("=")
                        key = line[:eq].strip().lower()
                        val = line[eq + 1:].strip().strip('"').strip("'")
                        data[key] = val
                return data
            except OSError:
                continue
        return data

    
    def get_os_info(self) -> Dict[str, str]:
        """
        Return an OS information dict that mirrors the shape previously
        produced by the `distro` library, extended with raw os-release keys.

        Keys guaranteed to be present:
            id, name, version, like, package_manager
        All raw /etc/os-release keys are also included (lowercased).
        """
        raw = self._parse_os_release()

        os_id   = raw.get("id", "").replace(" ", "")
        name    = raw.get("pretty_name") or raw.get("name", os_id)
        version = raw.get("version_id", raw.get("version", ""))
        like    = raw.get("id_like", "")

        info: Dict[str, str] = {
            "id":              os_id,
            "name":            name,
            "version":         version,
            "like":            like,
            "package_manager": self.get_pkg_manager(),
        }
        # Merge all raw os-release keys so callers that read e.g. info["id_like"]
        # directly continue to work.
        info.update(raw)
        return info

    # ------------------------------------------------------------------ #
    # Package manager detection                                            #
    # ------------------------------------------------------------------ #

    
    def get_pkg_manager(self) -> Optional[str]:
        for pm in ("apt", "apt-get", "dnf", "yum"):
            if self.command_exists(pm):
                return pm
        return None

    
    def get_pkg_manager_version(self) -> str:
        """
        Return the installed version of the active package manager, or "unknown".

        Probes in priority order:
          apt      → apt --version   → "apt 2.4.12 (amd64)"          → "2.4.12"
          apt-get  → apt-get --version → "apt 2.4.12 ..."            → "2.4.12"
          dnf      → dnf --version   → "4.14.0\n  ..."               → "4.14.0"
          yum      → yum --version   → "4.14.0\nLoaded plugins:..."  → "4.14.0"
        """
        pm = self.get_pkg_manager()
        if pm is None:
            return "unknown"
        try:
            result = subprocess.run(
                [pm, "--version"],
                capture_output=True,
                text=True,
            )
            first_line = (result.stdout or result.stderr or "").splitlines()[0].strip()
            # apt / apt-get: "apt 2.4.12 (amd64)"
            # dnf / yum:     "4.14.0"
            parts = first_line.split()
            for part in parts:
                # Take first token that looks like a version number
                if re.match(r"^\d+\.\d+", part):
                    return part
        except Exception:
            pass
        return "unknown"

    # ------------------------------------------------------------------ #
    # PURL builder                                                         #
    # ------------------------------------------------------------------ #

    
    def package_to_purl(self,os_info: Dict[str, str], package: str, version: str) -> str:
        os_id      = os_info.get("id", "").replace(" ", "").lower()
        like       = os_info.get("like", "").lower()
        pkg_manager = os_info.get("package_manager", "")

        if pkg_manager in ("apt", "apt-get"):
            if "ubuntu" in os_id or "ubuntu" in like:
                return f"pkg:deb/ubuntu/{package}@{version}"
            return f"pkg:deb/debian/{package}@{version}"
        if "almalinux" in os_id:
            return f"pkg:rpm/almalinux/{package}@{version}"
        if "redhat" in os_id or "rhel" in os_id:
            return f"pkg:rpm/redhat/{package}@{version}"
        if "alpaquita" in os_id:
            return f"pkg:apk/alpaquita/{package}@{version}"
        if "rocky" in os_id:
            return f"pkg:rpm/rocky-linux/{package}@{version}"
        if "alpine" in os_id:
            return f"pkg:apk/alpine/{package}@{version}"
        raise RuntimeError(
            f"Unsupported Linux distribution: id={os_id!r} like={like!r}"
        )

    # ------------------------------------------------------------------ #
    # get_linux_packages  (delegates scanning to LinuxHostScanner)        #
    # ------------------------------------------------------------------ #

    
    def get_linux_packages(self) -> List[str]:
        """
        Inventory all installed system packages via LinuxHostScanner,
        annotate with dependency sequences, append the running kernel
        component (on apt-based systems), and return a list of PURL strings.

        Full records are stored in self.inventory_data.
        """
        system_info = self.get_os_info()

        # LinuxHostScanner.scan() is synchronous; no event loop needed here.
        LinuxHostScannerInstance = LinuxHostScanner()
        LinuxHostScannerInstance.get_installed()
        raw_packages = LinuxHostScannerInstance.inventory_data

        components: List[Dict] = []
        for pkg in raw_packages:
            components.append({
                "id":           pkg["id"],
                "name":         pkg["name"],
                "version":      pkg["version"],
                "type":         "application",
                "scopes":       ["prod"],
                "license":      pkg.get("license") or pkg.get("licence") or "unknown",
                "dependencies": pkg.get("dependencies", []),
                "paths":        pkg.get("paths", []),
                "ecosystem":    pkg["ecosystem"],
                "state":        "undetermined",
            })

        components = self.merge_inventory_by_purl(components)
        components = self.build_dependency_sequences(components)

        self.inventory_data = components
        purls = [c["id"] for c in components]

        # Kernel component (apt-based distros only, matching original behaviour)
        pkg_manager = system_info.get("package_manager")
        if pkg_manager in ("apt", "apt-get"):
            kernel_version = os.uname().release
            kernel_purl = self.package_to_purl(
                system_info, "linux", kernel_version
            )
            kernel_component = {
                "id":                   kernel_purl,
                "name":                 "linux",
                "version":              kernel_version,
                "type":                 "application",
                "license":              "unknown",
                "paths":                [],
                "dependencies":         [],
                "ecosystem":            system_info["id"],
                "state":                "undetermined",
                "dependency_sequences": [],
            }
            components.append(kernel_component)
            purls.append(kernel_purl)

        return purls

    # ------------------------------------------------------------------ #
    # resolve_packages  (dry-run via the native package manager)          #
    # ------------------------------------------------------------------ #

    
    def resolve_packages(self,packages: Any) -> List[Dict]:
        """
        Simulate dependency resolution and return a list of package dicts:
            [{"name": "...", "version": "...", ...}, ...]
        """
        if isinstance(packages, str):
            packages = [packages]

        os_info = self.get_os_info()
        pm      = self.get_pkg_manager()

        self.pkg_manager = pm  # Store for later use in real install
        self.pkg_manager_version = self.get_pkg_manager_version()  # Probe version now while we have the PM detected
        resolved: List[Dict] = []

        # ── APT (Debian / Ubuntu) ─────────────────────────────────────────
        if pm in ("apt", "apt-get"):
            cmd    = ["apt-get", "-s", "--no-install-recommends", "install"] + packages
            output = self.run_command(cmd)
            # e.g. "Inst curl (7.88.1-10ubuntu1 Ubuntu:22.04/jammy [amd64])"
            pattern = re.compile(r"^Inst\s+(\S+)\s+\(([^ ]+)")
            for line in output.splitlines():
                m = pattern.search(line.strip())
                if m:
                    resolved.append({
                        "name":         m.group(1),
                        "version":      m.group(2),
                        "type":         "application",
                        "ecosystem":    os_info["id"],
                        "license":      "unknown",
                        "paths":        [],
                        "dependencies": [],
                    })
            return resolved

        # ── DNF (RHEL 8+, AlmaLinux, Rocky) ──────────────────────────────
        if pm == "dnf":
            cmd    = ["dnf", "install", "--assumeno"] + packages
            output = self.run_command(cmd)
            capture = False
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Installing:"):
                    capture = True
                    continue
                if capture:
                    if not line:
                        break
                    parts = line.split()
                    if len(parts) >= 2:
                        resolved.append({
                            "name":         parts[0].split(".")[0],
                            "version":      parts[1],
                            "type":         "application",
                            "license":      "unknown",
                            "paths":        [],
                            "dependencies": [],
                            "ecosystem":    os_info["id"],
                        })
            return resolved

        # ── YUM (RHEL 7) ──────────────────────────────────────────────────
        if pm == "yum":
            cmd    = ["yum", "install", "--assumeno"] + packages
            output = self.run_command(cmd)
            capture = False
            for line in output.splitlines():
                line = line.strip()
                if line.startswith("Installing:"):
                    capture = True
                    continue
                if capture:
                    if not line:
                        break
                    parts = line.split()
                    if len(parts) >= 2:
                        resolved.append({
                            "name":         parts[0].split(".")[0],
                            "version":      parts[1],
                            "type":         "application",
                            "ecosystem":    os_info["id"],
                            "license":      "unknown",
                            "paths":        [],
                            "dependencies": [],
                        })
            return resolved

        raise RuntimeError(f"Unsupported package manager for resolution: {pm!r}")

    # ------------------------------------------------------------------ #
    # get_packages_purls                                                   #
    # ------------------------------------------------------------------ #

    
    def get_packages_purls(self,packages: Any) -> List[str]:
        packages    = self.resolve_packages(packages)
        system_info = self.get_os_info()
        identified  = [
            {"id": self.package_to_purl(system_info, pkg["name"], pkg["version"])}
            for pkg in packages
        ]
        self.inventory_data = identified
        return [pkg["id"] for pkg in identified]

    # ------------------------------------------------------------------ #
    # run_real_install                                                     #
    # ------------------------------------------------------------------ #

    
    def run_real_install(self,packages_list: List[Any]) -> subprocess.CompletedProcess:
        pm = self.get_os_info()["package_manager"]
        if pm in ("apt", "apt-get"):
            pkgs = [f"{item[0]}={item[1]}" for item in packages_list]
        else:
            pkgs = [f"{item[0]}-{item[1]}" for item in packages_list]
        cmd = ["sudo", pm, "install", "-y"] + pkgs
        try:
            return subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            print(f"[!] Package install failed (exit {exc.returncode}): {' '.join(cmd)}", file=sys.stderr)
            raise