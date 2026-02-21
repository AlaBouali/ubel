import json,os
import re,subprocess
from pathlib import Path

class Node_Manager:

    dependency_file = "package.json"

    current_lock_file_content = None

    DEP_KEYS = [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies"
    ]

    LOCKFILES = [
        "package-lock.json",
        "npm-shrinkwrap.json",
        "yarn.lock",
        "pnpm-lock.yaml"
    ]

    # ============================================================
    # Main dispatch
    # ============================================================
    @staticmethod
    def scan(filename, content: str):
        if filename == "package.json":
            return Node_Manager.scan_package_json(content)

        if filename in ("package-lock.json", "npm-shrinkwrap.json"):
            return Node_Manager.scan_package_lock(content)

        if filename == "yarn.lock":
            return Node_Manager.scan_yarn_lock(content)

        if filename == "pnpm-lock.yaml":
            return Node_Manager.scan_pnpm_lock(content)

        return []

    # ============================================================
    # package.json
    # ============================================================
    @staticmethod
    def scan_package_json(content):
        try:
            data = json.loads(content)
        except Exception:
            return []

        components = []

        for key in Node_Manager.DEP_KEYS:
            deps = data.get(key, {})
            if not isinstance(deps, dict):
                continue

            for pkg, version in deps.items():
                comps = Node_Manager.process_component(pkg, version)
                # no dependencies info in package.json level
                for c in comps:
                    c["dependencies"] = []
                components += comps

        return components

        # ============================================================
        # Full, fixed, correct parser for package-lock.json v1 / v2 / v3
        # ============================================================
    @staticmethod
    def scan_package_lock(content):
        try:
            if isinstance(content, str):
                content = json.loads(content)
            data = content
        except Exception:
            return []

        components = []

        # ============================================================
        # CASE 1 — lockfile v2/v3 (packages: {path → meta})
        # ============================================================
        if "packages" in data:
            packages = data["packages"]

            for path, meta in packages.items():
                # skip root package entry
                if path == "" or not isinstance(meta, dict):
                    continue

                # derive name
                name = meta.get("name")
                if not name:
                    # derive from path: node_modules/abc or node_modules/@scope/abc
                    if path.startswith("node_modules/"):
                        name = path.split("node_modules/")[-1]
                    else:
                        # fallback for unusual entries
                        name = path.split("/")[-1]

                version = meta.get("version")
                if not version:
                    continue

                purl = f"pkg:npm/{name}@{version}"

                components.append({
                    "id": purl,
                    "name": name,
                    "version": version,
                    "type": "library",
                    "ecosystem": "npm",
                })

            return components

        # ============================================================
        # CASE 2 — legacy lockfile v1
        # ============================================================
        elif "dependencies" in data:
            def walk(deps):
                for name, meta in deps.items():
                    if not isinstance(meta, dict):
                        continue
                    version = meta.get("version")
                    if not version:
                        continue
                    purl = f"pkg:npm/{name}@{version}"

                    components.append({
                        "id": purl,
                        "name": name,
                        "version": version,
                        "type": "library",
                        "ecosystem": "npm",
                    })

                    if "dependencies" in meta:
                        walk(meta["dependencies"])

            walk(data["dependencies"])
            return components

        # no valid lockfile structure
        return components

    # ============================================================
    # yarn.lock
    # ============================================================
    @staticmethod
    def scan_yarn_lock(content):
        components = []
        depgraph = {}

        # Yarn v1 format:
        #   pkg@range:
        #     version "1.2.3"
        #     dependencies:
        #        left-pad "^1.3.0"
        entry_re = re.compile(
            r'([^\s]+):\s*\n\s+version\s+"([^"]+)"(?:\n\s+dependencies:\s*\n((?:\s+[^\s]+.+\n)+))?',
            re.MULTILINE
        )

        for pkg_expr, version, deps_block in entry_re.findall(content):
            pkg = pkg_expr.split("@", 1)[0]
            purl = f"pkg:npm/{pkg}@{version}"

            depgraph[purl] = []

            if deps_block:
                for line in deps_block.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if ":" not in line:
                        continue
                    dep, ver = line.split(" ", 1)
                    ver = ver.strip().strip('"')
                    depgraph[purl].append(f"pkg:npm/{dep}@{ver}")

            comps = Node_Manager.process_component(pkg, version)
            components += comps

        for c in components:
            c["dependencies"] = depgraph.get(c["purl"], [])

        return components

    # ============================================================
    # pnpm-lock.yaml (supports v6–v9)
    # ============================================================
    @staticmethod
    def scan_pnpm_lock(content):
        components = []
        detected_purls={}
        depgraph = {}

        # ----------------------------------------------------
        # Method 1: old pnpm format (/pkg/version:)
        # ----------------------------------------------------
        package_line = re.compile(r'^\s{2}(/[^:]+):\s*$', re.MULTILINE)
        matched_old = package_line.findall(content)

        if matched_old:
            for entry in matched_old:
                parts = entry.strip("/").split("/")
                if len(parts) != 2:
                    continue
                pkg, version = parts
                purl = f"pkg:npm/{pkg}@{version}"
                depgraph[purl] = []
                new_components = Node_Manager.process_component(pkg, version)
                for item in new_components:
                    if detected_purls.get(item["id"])==None:
                        item["components"]=[]
                        components.append(item)
                        detected_purls[item["id"]]=""

        # ----------------------------------------------------
        # Method 2: pnpm v9 format ('package@version(...):')
        # ----------------------------------------------------
        pattern = re.compile(
            r"^\s*['\"]?([^'\":]+?)@([^'\":\(\)]+)",
            re.MULTILINE
        )

        for pkg, version in pattern.findall(content):
            if " " in pkg:
                continue
            purl = f"pkg:npm/{pkg}@{version}"
            if purl not in depgraph:
                depgraph[purl] = []
            new_components = Node_Manager.process_component(pkg, version)
            for item in new_components:
                if detected_purls.get(item["id"])==None:
                    item["components"]=[]
                    components.append(item)
                    detected_purls[item["id"]]=""

        """# ----------------------------------------------------
        # Extract dependencies for pnpm v9:
        #   dependencies:
        #       depA: 1.2.3
        #       depB: 4.5.6
        # ----------------------------------------------------
        block_re = re.compile(
            r"^(['\"]?([^'\":]+?)@([^'\":\(\)]+)['\"]?):\s*\n(.*?)\n(?=\S|\Z)",
            re.MULTILINE | re.DOTALL
        )

        for fullkey, pkg, version, block in block_re.findall(content):
            purl = f"pkg:npm/{pkg}@{version}"
            if purl not in depgraph:
                depgraph[purl] = []

            dep_section = re.search(r"dependencies:\s*\n(.*?)(?=\n\S|\Z)", block, re.DOTALL)
            if dep_section:
                body = dep_section.group(1)
                for line in body.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    if ":" not in line:
                        continue
                    dep, ver = line.split(":", 1)
                    ver = ver.strip().strip('"').strip("'")
                    depgraph[purl].append(f"pkg:npm/{dep}@{ver}")

        # inject dependency lists
        for c in components:
            c["dependencies"] = depgraph.get(c["purl"], [])"""

        return components

    # ============================================================
    # Helpers
    # ============================================================
    @staticmethod
    def is_valid_file(content: str) -> bool:
        return True

    @staticmethod
    def is_valid_dependency_file(filename: str) -> bool:
        return (
            filename.lower() == Node_Manager.dependency_file.lower() or
            filename.lower() in [x.lower() for x in Node_Manager.LOCKFILES]
        )

    @staticmethod
    def process_component(pkg, version):
        components = []

        if "|" in version and "||" not in version:
            versions = [v.strip() for v in version.split("|")]
        elif "||" in version:
            versions = [v.strip() for v in version.split("||")]
        else:
            versions = [version]

        for ver in versions:
            while True:
                if ver.startswith(("v", "V", "^", "~", "@", ">", "<", "=")):
                    ver = ver[1:]
                else:
                    break

            purl = f"pkg:npm/{pkg}@{ver}" if ver else f"pkg:npm/{pkg}"

            components.append({
                "id": purl,
                "name": pkg,
                "version": ver,
                "type": "library",
                "ecosystem": "npm",
                })

        return components

    @staticmethod
    def run_dry_run(initial_args):

        old_data=None
        if os.path.exists("package-lock.json"):
            with open("package-lock.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
        cmd = [
            "npm",
            "install",
            "--package-lock-only"
            ] + initial_args

        result = subprocess.run(cmd,capture_output=True, shell=True)

        if result.returncode != 0:
            raise RuntimeError(f"npm dry-run failed:\nCMD: {' '.join(cmd)}\nOutput:{result.stdout}\nError:{result.stderr}")

        with open("package-lock.json", "r", encoding="utf-8") as lockfile:
            new_data = json.load(lockfile)


        with open("package-lock.json", "w", encoding="utf-8") as lock_file:
            json.dump(old_data, lock_file, indent=2)
            lock_file.close()
        

        old_components = Node_Manager.scan_package_lock(old_data)
        new_components = Node_Manager.scan_package_lock(new_data)
        Node_Manager.current_lock_file_content = new_data
        components=[]
        for new_c in new_components:
            found = False
            for old_c in old_components:
                if new_c["id"]==old_c["id"]:
                    found = True
                    break
            if not found:
                components.append(new_c)
        return [comp["id"] for comp in components]
    
    @staticmethod
    def get_installed(engine):
        if engine=="npm":
            if not os.path.exists("package-lock.json"):
                cmd = [
                        "npm",
                        "list",
                        "--json",
                        "--all",
                        ">package-lock.json"
                    ]
                
                result = subprocess.run(cmd,capture_output=True,shell=True)

                #if result.returncode != 0:
                    #raise RuntimeError(f"npm list failed:\nCMD: {' '.join(cmd)}\nOutput:{result.stdout}\nError:{result.stderr}")
            
            with open("package-lock.json", "r", encoding="utf-8") as lockfile: 
                data = json.load(lockfile)
        else:
            raise RuntimeError(f"Unsupported engine: {engine}")
        purls = [comp["id"] for comp in Node_Manager.scan_package_lock(data)]
        if not purls:
            raise RuntimeError(f"Failed to retrieve installed npm packages. Please ensure you have a valid package-lock.json or try running with elevated permissions.")
        return purls
    
    @staticmethod
    def run_real_install(engine,components):
        if engine=="npm":
            cmd = ["npm", "install"]
            for c in components:
                cmd.append(f"{c['name']}@{c['version']}")
            return subprocess.run(cmd,shell=True)