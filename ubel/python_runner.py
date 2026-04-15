import subprocess
import sys
import tempfile
import json
from pathlib import Path
from importlib.metadata import distributions, packages_distributions


class Pypi_Manager:

    inventory_data = []

    # ---------------------------------------------------
    # Helpers
    # ---------------------------------------------------

    @staticmethod
    def _purl(name, version):
        return f"pkg:pypi/{name.lower()}@{version}"

    @staticmethod
    def merge_inventory_by_purl(components):

        merged = {}

        for comp in components:

            cid = comp["id"]

            if cid not in merged:
                clone = dict(comp)
                clone["paths"] = clone.get("paths", [])
                merged[cid] = clone
                continue

            existing = merged[cid]

            for p in comp.get("paths", []):
                if p and p not in existing["paths"]:
                    existing["paths"].append(p)

        return list(merged.values())

    # ---------------------------------------------------
    # Dependency sequences
    # ---------------------------------------------------

    @staticmethod
    def build_dependency_sequences(inventory):

        by_id = {c["id"]: c for c in inventory}

        # Deduplicate each component's dependency list before DFS.
        # dist.requires lists the same package multiple times for different
        # extras/markers; all resolve to the same purl, causing duplicate paths.
        for comp in inventory:
            seen_set = set()
            deduped = []
            for dep in comp.get("dependencies", []):
                if dep not in seen_set:
                    deduped.append(dep)
                    seen_set.add(dep)
            comp["dependencies"] = deduped

        # Only mark a node as depended-upon when it actually exists in by_id.
        # Version-less stub purls are not in by_id and must not suppress roots.
        depended = set()
        for comp in inventory:
            for dep in comp.get("dependencies", []):
                if dep in by_id:
                    depended.add(dep)

        roots = [c["id"] for c in inventory if c["id"] not in depended]

        sequences = {}

        def dfs(node, path, visited_in_tree):
            # Each node is visited at most once per root tree.
            # This matches the Node/arborist behaviour: a shared dependency
            # (e.g. more-itertools required by both jaraco.classes and
            # jaraco.functools) gets exactly one path per root — the first
            # (shortest / most direct) path found — instead of one entry per
            # unique route through the graph.
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


    # ---------------------------------------------------
    # Installed packages
    # ---------------------------------------------------

    @staticmethod
    def _build_name_to_purl_map():
        """Return {normalised_name: full_purl} for every installed distribution."""
        mapping = {}
        for dist in distributions():
            name = dist.metadata["Name"]
            if name:
                mapping[name.lower().replace("-", "_")] = Pypi_Manager._purl(name, dist.version)
        return mapping

    @staticmethod
    def _resolve_dep_purl(raw_dep_name, name_to_purl):
        """
        Turn a raw dependency token (e.g. 'Requests', 'typing-extensions')
        into a full versioned purl when the package is installed,
        or a version-less stub otherwise.
        """
        key = raw_dep_name.lower().replace("-", "_")
        return name_to_purl.get(key, f"pkg:pypi/{raw_dep_name.lower()}@")

    @staticmethod
    def _dist_path(dist):
        """
        Return the real on-disk path for a distribution.
        Prefers the direct_url.json location, then the dist-info dir,
        then the site-packages root — mirroring what Node stores as node.path.
        """
        # dist._path is the *.dist-info / *.egg-info directory (Python 3.9+)
        try:
            p = dist._path
            if p and p.exists():
                return p.as_posix()
        except AttributeError:
            pass
        # Fallback: site-packages root (original behaviour, less precise)
        return dist.locate_file("").as_posix()

    @staticmethod
    def get_installed():

        name_to_purl = Pypi_Manager._build_name_to_purl_map()

        components = []

        for dist in distributions():

            name = dist.metadata["Name"]
            if not name:
                continue
            version = dist.version

            deps = []

            for r in dist.requires or []:
                # Strip environment markers: "requests ; python_version>='3'"  -> "requests"
                dep_name = r.split()[0].rstrip(";")
                deps.append(Pypi_Manager._resolve_dep_purl(dep_name, name_to_purl))

            component = {
                "id": Pypi_Manager._purl(name, version),
                "name": name.lower(),
                "version": version,
                "type": "library",
                "license": dist.metadata.get("License", "unknown"),
                "dependencies": deps,
                "paths": [Pypi_Manager._dist_path(dist)],
                "ecosystem": "pypi",
                "state": "undetermined"
            }

            components.append(component)

        components = Pypi_Manager.merge_inventory_by_purl(components)

        components = Pypi_Manager.build_dependency_sequences(components)

        Pypi_Manager.inventory_data = components

        return [c["id"] for c in components]

    # ---------------------------------------------------
    # Installed inventory (full metadata)
    # ---------------------------------------------------

    @staticmethod
    def get_installed_inventory():

        if not Pypi_Manager.inventory_data:
            Pypi_Manager.get_installed()

        return Pypi_Manager.inventory_data

    # ---------------------------------------------------
    # Dry run
    # ---------------------------------------------------

    @staticmethod
    def run_dry_run(initial_args):

        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            report_path = Path(tmp.name)

        args = [a for a in initial_args if a != "--"]

        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--report",
            str(report_path),
        ] + args

        result = subprocess.run(cmd, capture_output=True)

        if result.returncode != 0:
            raise RuntimeError(
                f"pip dry-run failed:\nCMD: {' '.join(cmd)}\nOutput:{result.stdout}\nError:{result.stderr}"
            )

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        report_path.unlink(missing_ok=True)

        components = []

        # Build a name->purl map from the *currently installed* environment so
        # that dependencies resolved by the dry-run get full versioned purls
        # matching what get_installed() produces.
        name_to_purl = Pypi_Manager._build_name_to_purl_map()

        # Also enrich from the dry-run result itself (newly-to-be-installed pkgs)
        for pkg in data.get("install", []):
            meta = pkg.get("metadata", {})
            n = meta.get("name")
            v = meta.get("version")
            if n and v:
                key = n.lower().replace("-", "_")
                name_to_purl.setdefault(key, Pypi_Manager._purl(n, v))

        for pkg in data.get("install", []):

            meta = pkg.get("metadata", {})

            name = meta.get("name")
            version = meta.get("version")

            deps = []

            for r in meta.get("requires_dist", []) or []:
                dep_name = r.split()[0].rstrip(";")
                deps.append(Pypi_Manager._resolve_dep_purl(dep_name, name_to_purl))

            component = {
                "id": Pypi_Manager._purl(name, version),
                "name": name.lower(),
                "version": version,
                "type": "library",
                "license": meta.get("license", "unknown"),
                "dependencies": deps,
                "paths": [],
                "ecosystem": "pypi",
                "state": "undetermined"
            }

            components.append(component)

        components = Pypi_Manager.merge_inventory_by_purl(components)

        components = Pypi_Manager.build_dependency_sequences(components)

        Pypi_Manager.inventory_data = components

        return [c["id"] for c in components]

    # ---------------------------------------------------
    # Real install
    # ---------------------------------------------------

    @staticmethod
    def run_real_install(file_name, engine):

        if engine == "pip":
            cmd = [sys.executable, "-m", "pip", "install", "-r", file_name]
            return subprocess.run(cmd)