"""
python_venv_scanner.py — Python virtualenv inventory scanner.

Pure-Python port of python_venv_scanner.js.
Zero external dependencies.

Walks a directory tree, finds every virtualenv, reads the installed
packages from .dist-info / .egg-info metadata, and returns PURL id strings.

Usage
-----
    from python_venv_scanner import PythonVenvScanner
    import asyncio

    ids = asyncio.run(PythonVenvScanner.get_installed("/path/to/project"))
    for rec in PythonVenvScanner.inventory_data:
        print(rec)
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional


# ---------------------------------------------------------------------------
# PURL
# ---------------------------------------------------------------------------

def _pypi_purl(name: str, version: str) -> str:
    normalised = name.lower().replace("_", "-")
    from urllib.parse import quote
    return f"pkg:pypi/{quote(normalised, safe='')}@{version or ''}"


# ---------------------------------------------------------------------------
# Venv detection
# ---------------------------------------------------------------------------

def _is_venv_root(directory: str) -> bool:
    return (
        os.path.exists(os.path.join(directory, "pyvenv.cfg"))
        or os.path.exists(os.path.join(directory, "bin", "activate"))
        or os.path.exists(os.path.join(directory, "Scripts", "activate"))
    )


# ---------------------------------------------------------------------------
# site-packages
# ---------------------------------------------------------------------------

def _site_packages_dirs(venv_root: str) -> List[str]:
    results: List[str] = []

    lib_dir = os.path.join(venv_root, "lib")
    if os.path.exists(lib_dir):
        for entry in os.listdir(lib_dir):
            sp = os.path.join(lib_dir, entry, "site-packages")
            if os.path.exists(sp):
                results.append(sp)

    win_sp = os.path.join(venv_root, "Lib", "site-packages")
    if os.path.exists(win_sp):
        results.append(win_sp)

    return results


# ---------------------------------------------------------------------------
# Metadata reader
# ---------------------------------------------------------------------------

def _read_dist_info(meta_dir: str) -> Dict:
    raw = ""
    meta_path = os.path.join(meta_dir, "METADATA")
    pkg_info  = os.path.join(meta_dir, "PKG-INFO")

    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            pass
    elif os.path.exists(pkg_info):
        try:
            with open(pkg_info, "r", encoding="utf-8", errors="replace") as fh:
                raw = fh.read()
        except OSError:
            pass

    if not raw:
        return {"license": "unknown", "requires": []}

    license_ = "unknown"
    requires: List[str] = []

    for line in raw.splitlines():
        lower = line.lower()

        if lower.startswith("license:"):
            license_ = line[len("license:"):].strip() or "unknown"

        elif lower.startswith("requires-dist:"):
            dep_raw = line[len("requires-dist:"):].strip()
            # grab the package name only (stop at version spec, extras, env marker)
            dep = dep_raw.split(" ")[0].split("(")[0].split(";")[0]
            dep = dep.split("[")[0].split("!")[0].split("<")[0].split(">")[0].split("=")[0]
            dep = dep.strip().lower().replace("_", "-")
            if dep:
                requires.append(dep)
        elif lower.startswith("classifier: license "):
            license_ = line.split("::")[2].strip().replace("License", "") or "unknown"
        elif line.startswith("License-Expression:"):
            license_ = line[len("License-Expression:"):].strip() or "unknown"

    return {"license": license_.strip(), "requires": requires}


# ---------------------------------------------------------------------------
# Scan a single venv
# ---------------------------------------------------------------------------

def _scan_venv(venv_root: str) -> List[Dict]:
    sp_dirs = _site_packages_dirs(venv_root)
    if not sp_dirs:
        return []

    # Pass 1 — build name index from .dist-info directories
    name_index: Dict[str, Dict] = {}

    for sp in sp_dirs:
        try:
            entries = os.scandir(sp)
        except OSError:
            continue

        for entry in entries:
            if not entry.is_dir():
                continue
            if not entry.name.endswith(".dist-info"):
                continue

            base = entry.name[: -len(".dist-info")]
            idx  = base.rfind("-")
            if idx == -1:
                continue

            pkg_name = base[:idx]
            version  = base[idx + 1:]
            norm     = pkg_name.lower().replace("_", "-")

            name_index[norm] = {
                "name":     pkg_name,
                "version":  version,
                "meta_dir": os.path.join(sp, entry.name),
            }

    # Pass 2 — build component list
    components: List[Dict] = []

    for info in name_index.values():
        name     = info["name"]
        version  = info["version"]
        meta_dir = info["meta_dir"]
        norm     = name.lower().replace("_", "-")
        id_      = _pypi_purl(name, version)

        meta = _read_dist_info(meta_dir)

        dependencies: List[str] = []
        for dep in meta["requires"]:
            resolved = name_index.get(dep)
            if resolved:
                dependencies.append(_pypi_purl(resolved["name"], resolved["version"]))
            else:
                dependencies.append(_pypi_purl(dep, ""))

        components.append({
            "id":           id_,
            "name":         norm,
            "version":      version,
            "type":         "library",
            "license":      meta["license"],
            "ecosystem":    "python",
            "state":        "undetermined",
            "scopes":       [],
            "dependencies": dependencies,
            "paths":        [meta_dir],
            "venv_root":    venv_root,
        })

    return components


# ---------------------------------------------------------------------------
# Scope assignment
# ---------------------------------------------------------------------------

def _parse_reqs(file_path: str) -> List[str]:
    if not os.path.exists(file_path):
        return []
    result: List[str] = []
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as fh:
            for raw in fh:
                line = raw.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                import re
                name = re.split(r"[><=!;\s\[]", line)[0].lower().replace("_", "-")
                if name:
                    result.append(name)
    except OSError:
        pass
    return result


def _assign_scopes(inventory: List[Dict]) -> None:
    by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

    name_index: Dict[str, List[Dict]] = {}
    for comp in inventory:
        if not isinstance(comp.get("scopes"), list):
            comp["scopes"] = []
        name_index.setdefault(comp["name"], []).append(comp)

    # Group by venv root
    venv_groups: Dict[str, List[Dict]] = {}
    for comp in inventory:
        root = comp["venv_root"]
        venv_groups.setdefault(root, []).append(comp)

    for venv_root, comps in venv_groups.items():
        project_dir = os.path.dirname(venv_root)

        prod_names = set(
            _parse_reqs(os.path.join(project_dir, "requirements.txt"))
            + _parse_reqs(os.path.join(project_dir, "requirements", "base.txt"))
            + _parse_reqs(os.path.join(project_dir, "requirements", "prod.txt"))
        )
        dev_names = set(
            _parse_reqs(os.path.join(project_dir, "requirements-dev.txt"))
            + _parse_reqs(os.path.join(project_dir, "requirements_dev.txt"))
            + _parse_reqs(os.path.join(project_dir, "requirements", "dev.txt"))
        )

        def propagate(names: set, scope: str) -> None:
            queue: List[Dict] = []
            for n in names:
                for c in name_index.get(n, []):
                    if c["venv_root"] == venv_root:
                        queue.append(c)

            visited: set = set()
            while queue:
                c = queue.pop(0)
                if c["id"] in visited:
                    continue
                visited.add(c["id"])
                if scope not in c["scopes"]:
                    c["scopes"].append(scope)
                for dep_id in c["dependencies"]:
                    d = by_id.get(dep_id)
                    if d and d["venv_root"] == venv_root:
                        queue.append(d)

        propagate(prod_names, "prod")
        propagate(dev_names,  "dev")

        # Fallback — no requirements files found
        if not prod_names and not dev_names:
            for c in comps:
                if not c["scopes"]:
                    c["scopes"].append("prod")


# ---------------------------------------------------------------------------
# Merge
# ---------------------------------------------------------------------------

def _merge_inventory_by_purl(components: List[Dict]) -> List[Dict]:
    merged: Dict[str, Dict] = {}
    for comp in components:
        purl = comp["id"]
        if purl not in merged:
            merged[purl] = {**comp, "paths": list(comp["paths"])}
            continue
        existing = merged[purl]
        for p in comp["paths"]:
            if p not in existing["paths"]:
                existing["paths"].append(p)
        for s in comp["scopes"]:
            if s not in existing["scopes"]:
                existing["scopes"].append(s)
    return list(merged.values())


# ---------------------------------------------------------------------------
# PythonVenvScanner
# ---------------------------------------------------------------------------

class PythonVenvScanner:
    """
    Walk a directory tree, find all Python virtualenvs, and enumerate their
    installed packages.
    """

    inventory_data: List[Dict] = []

    @classmethod
    def get_installed(cls, start_dir: str = ".", is_recursive: bool = True) -> List[str]:
        """
        Entry-point that mirrors the JS API.  Returns a list of PURL id strings.
        Full records are available on PythonVenvScanner.inventory_data.

        Parameters
        ----------
        start_dir : str
            Root directory to begin scanning from.
        is_recursive : bool
            When True (default) the scanner walks the entire subtree under
            ``start_dir``.  When False only the immediate children of
            ``start_dir`` are inspected — no further descent is performed.
        """
        return cls.scan(start_dir, is_recursive=is_recursive)

    @classmethod
    def scan(cls, start_dir: str = ".", is_recursive: bool = True) -> List[str]:
        """Synchronous scan. Returns a list of PURL id strings."""
        cls.inventory_data = []

        visited: set = set()
        raw: List[Dict] = []

        skip_dirs = {"node_modules", ".git", ".ubel"}

        def walk(directory: str, depth: int = 0) -> None:
            try:
                entries = os.scandir(directory)
            except OSError:
                return

            for entry in entries:
                if not entry.is_dir():
                    continue
                if entry.name in skip_dirs:
                    continue

                full = entry.path

                if _is_venv_root(full):
                    print(f"[i] Found virtualenv: {full}")
                    key = os.path.realpath(full)
                    if key not in visited:
                        visited.add(key)
                        raw.extend(_scan_venv(full))
                    # A confirmed venv — never descend into it regardless of
                    # is_recursive (venvs don't nest meaningfully).
                    continue

                # Only recurse deeper when is_recursive=True.  At depth 0 we
                # are still enumerating start_dir's direct children, so we
                # always take one step in; the flag controls everything beyond.
                if is_recursive or depth == 0:
                    walk(full, depth + 1)

        walk(start_dir)

        merged = _merge_inventory_by_purl(raw)
        _assign_scopes(merged)

        cls.inventory_data = merged
        return [c["id"] for c in merged]