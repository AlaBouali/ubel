"""
pypi_manager.py — PyPI package manager with local venv support.

Static methods:
    init_venv(venv_dir)              → create a venv at venv_dir (idempotent)
    run_dry_run(initial_args,        → pip dry-run inside the venv, returns
               venv_dir)               same component structure as before
    run_real_install(file_name,      → pip install -r inside the venv
                     engine,
                     venv_dir)
    build_dependency_sequences(inv)  → annotate inventory with dep sequences
    merge_inventory_by_purl(comps)   → deduplicate by PURL
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Any, Dict, List, Optional
from .venv_scanner import PythonVenvScanner


class Pypi_Manager:

    inventory_data: List[Dict[str, Any]] = []

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _purl(name: str, version: str) -> str:
        return f"pkg:pypi/{name.lower()}@{version}"

    @staticmethod
    def merge_inventory_by_purl(components: List[Dict]) -> List[Dict]:
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
    # Dependency sequences                                                 #
    # ------------------------------------------------------------------ #

    @staticmethod
    def build_dependency_sequences(inventory: List[Dict]) -> List[Dict]:
        by_id = {c["id"]: c for c in inventory}

        # Deduplicate each component's dependency list (extras/markers may
        # repeat the same package under different conditions).
        for comp in inventory:
            seen: set = set()
            deduped: List[str] = []
            for dep in comp.get("dependencies", []):
                if dep not in seen:
                    deduped.append(dep)
                    seen.add(dep)
            comp["dependencies"] = deduped

        # Only mark a node as depended-upon when it actually exists in by_id.
        depended: set = set()
        for comp in inventory:
            for dep in comp.get("dependencies", []):
                if dep in by_id:
                    depended.add(dep)

        roots = [c["id"] for c in inventory if c["id"] not in depended]

        sequences: Dict[str, List] = {}

        def dfs(node: str, path: List[str], visited_in_tree: set) -> None:
            if node in visited_in_tree:
                return
            visited_in_tree.add(node)
            next_path = path + [node]
            sequences.setdefault(node, []).append(next_path)
            for dep in by_id.get(node, {}).get("dependencies", []):
                if dep not in path and dep in by_id:
                    dfs(dep, next_path, visited_in_tree)

        for root in roots:
            dfs(root, [], set())

        for comp in inventory:
            comp["dependency_sequences"] = sequences.get(comp["id"], [])

        return inventory

    # ------------------------------------------------------------------ #
    # Venv helpers                                                         #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _venv_python(venv_dir: str) -> str:
        """Return the absolute path to the venv's Python interpreter."""
        venv_path = Path(venv_dir)
        # Unix
        unix = venv_path / "bin" / "python"
        if unix.exists():
            return str(unix)
        # Windows
        win = venv_path / "Scripts" / "python.exe"
        if win.exists():
            return str(win)
        raise RuntimeError(
            f"Cannot locate Python interpreter inside venv: {venv_dir}"
        )
    
    @staticmethod
    def get_pip_version(python: str) -> Optional[str]:
        """Return the version of pip installed in the venv, or None if not found."""
        try:
            result = subprocess.run(
                [python, "-m", "pip", "--version"],
                capture_output=True,
                text=True,
                check=True,
            )
            output = result.stdout.strip()
            if output.startswith("pip "):
                return output.split()[1]
        except (subprocess.CalledProcessError, IndexError):
            pass
        return None

    @staticmethod
    def _resolve_dep_purl(raw_dep_name: str, name_to_purl: Dict[str, str]) -> str:
        key = raw_dep_name.lower().replace("-", "_")
        return name_to_purl.get(key, f"pkg:pypi/{raw_dep_name.lower()}@")

    # ------------------------------------------------------------------ #
    # init_venv                                                            #
    # ------------------------------------------------------------------ #

    @staticmethod
    def init_venv(venv_dir: str) -> str:
        """
        Create a Python virtual environment at *venv_dir* if one does not
        already exist there.  Idempotent — safe to call on an existing venv.

        Returns the absolute path to the venv's Python interpreter.
        """
        venv_path = Path(venv_dir).resolve()

        # Detect an already-initialised venv (pyvenv.cfg is the canonical marker)
        if not (venv_path / "pyvenv.cfg").exists():
            builder = venv.EnvBuilder(
                system_site_packages=False,
                clear=False,
                symlinks=(os.name != "nt"),   # symlinks on POSIX, copies on Windows
                with_pip=True,
            )
            builder.create(str(venv_path))

        return Pypi_Manager._venv_python(str(venv_path))
    
    @staticmethod
    def get_installed(venv_dir: str) -> List[Dict[str, Any]]:
        """
        Scan the given venv for installed packages and return them in the same
        format as the dry-run inventory (with "id", "name", "version", etc.).
        """
        return PythonVenvScanner.get_installed(venv_dir)

    # ------------------------------------------------------------------ #
    # run_dry_run                                                          #
    # ------------------------------------------------------------------ #

    @staticmethod
    def run_dry_run(initial_args: List[str], venv_dir: str) -> List[str]:
        """
        Run ``pip install --dry-run`` for *initial_args* inside *venv_dir*.

        The venv must already exist (call ``init_venv`` first).

        Returns a list of PURL id strings.
        Full records are stored in ``Pypi_Manager.inventory_data``.
        """
        python = Pypi_Manager._venv_python(venv_dir)

        pip_version = Pypi_Manager.get_pip_version(python)
        if pip_version is None:
            raise RuntimeError(f"pip is not installed in the venv at {venv_dir}")
        args   = [a for a in initial_args if a != "--"]

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            report_path = Path(tmp.name)

        cmd = [
            python, "-m", "pip",
            "install",
            "--dry-run",
            "--report", str(report_path),
        ] + args

        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            report_path.unlink(missing_ok=True)
            raise RuntimeError(
                f"pip dry-run failed:\n"
                f"CMD: {' '.join(cmd)}\n"
                f"stdout: {result.stdout.decode(errors='replace')}\n"
                f"stderr: {result.stderr.decode(errors='replace')}"
            )

        with open(report_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)

        report_path.unlink(missing_ok=True)

        # ── Build name→purl map from the dry-run report ──────────────────
        # (we have no installed env to query; everything we know comes from
        # what pip resolved for us in the report itself)
        name_to_purl: Dict[str, str] = {}
        for pkg in data.get("install", []):
            meta = pkg.get("metadata", {})
            n = meta.get("name")
            v = meta.get("version")
            if n and v:
                key = n.lower().replace("-", "_")
                name_to_purl.setdefault(key, Pypi_Manager._purl(n, v))

        # ── Build components ──────────────────────────────────────────────
        components: List[Dict] = []

        for pkg in data.get("install", []):
            meta    = pkg.get("metadata", {})
            name    = meta.get("name")
            version = meta.get("version")

            if not name or not version:
                continue

            deps: List[str] = []
            for r in meta.get("requires_dist") or []:
                dep_name = r.split()[0].rstrip(";")
                deps.append(Pypi_Manager._resolve_dep_purl(dep_name, name_to_purl))

            components.append({
                "id":           Pypi_Manager._purl(name, version),
                "name":         name.lower(),
                "version":      version,
                "type":         "library",
                "license":      meta.get("license", "unknown"),
                "dependencies": deps,
                "paths":        [],
                "ecosystem":    "python",
                "scopes":       ["prod"],
                "state":        "undetermined",
            })
        
        components.append(
            {
                "id": f"pkg:pypi/pip@{pip_version}",
                "name": "pip",
                "version": pip_version,
                "type": "tool",
                "license": "MIT",
                "dependencies": [],
                "paths": [],
                "ecosystem": "python",
                "scopes": ["dev", "env", "prod"],
                "state": "undetermined",
            }
        )

        components = Pypi_Manager.merge_inventory_by_purl(components)
        components = Pypi_Manager.build_dependency_sequences(components)

        Pypi_Manager.inventory_data = components
        return [c["id"] for c in components]

    # ------------------------------------------------------------------ #
    # run_real_install                                                     #
    # ------------------------------------------------------------------ #

    @staticmethod
    def run_real_install(
        file_name: str,
        engine: str,
        venv_dir: str,
    ) -> subprocess.CompletedProcess:
        """
        Install packages from *file_name* into *venv_dir*.

        Currently only ``engine="pip"`` is supported.
        The venv must already exist (call ``init_venv`` first).
        """
        python = Pypi_Manager._venv_python(venv_dir)

        if engine == "pip":
            cmd = [python, "-m", "pip", "install", "-r", file_name]
            return subprocess.run(cmd)

        raise ValueError(f"Unsupported engine: {engine!r}")