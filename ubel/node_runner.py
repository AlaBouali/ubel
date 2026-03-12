import json,os
import re,subprocess,uuid
from pathlib import Path

class Node_Manager:

    dependency_file = "package.json"

    inventory_data=[]

    current_lock_file_content = None


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
                pkg_license = meta.get("license", "unknown")
                dependencies_list=[ ]
                for item in meta.get("dependencies", {}).keys():
                    dependencies_list.append(f"pkg:npm/{item}@")
                if not version:
                    continue

                purl = f"pkg:npm/{name}@{version}"

                components.append({
                    "id": purl,
                    "name": name,
                    "version": version,
                    "type": "library",
                    "license": pkg_license,
                    "dependencies": dependencies_list,
                    "path": os.path.join(os.getcwd(), path),
                    "ecosystem": "npm",
                    "state":"undetermined",
                })
            Node_Manager.inventory_data+=components
            return components

        # ============================================================
        # CASE 2 — legacy lockfile v1
        # ============================================================
        elif "dependencies" in data:

            def walk(deps, parent_path="node_modules"):
                for name, meta in deps.items():
                    if not isinstance(meta, dict):
                        continue

                    version = meta.get("version")
                    if not version:
                        continue

                    pkg_license = meta.get("license", "unknown")

                    dependencies_list = []
                    for dep in meta.get("dependencies", {}).keys():
                        dependencies_list.append(f"pkg:npm/{dep}@")

                    purl = f"pkg:npm/{name}@{version}"

                    pkg_path = os.path.abspath(
                        os.path.join(os.getcwd(), parent_path, name)
                    )

                    components.append({
                        "id": purl,
                        "name": name,
                        "version": version,
                        "type": "library",
                        "license": pkg_license,
                        "dependencies": dependencies_list,
                        "path": pkg_path,
                        "ecosystem": "npm",
                        "state": "undetermined",
                    })

                    # recurse into nested dependencies
                    if "dependencies" in meta:
                        walk(meta["dependencies"], os.path.join(parent_path, name, "node_modules"))

            walk(data["dependencies"])

            Node_Manager.inventory_data += components
            return components


    @staticmethod
    def run_dry_run(initial_args):

        old_data=None
        old_pkgs=None
        if os.path.exists("package-lock.json"):
            with open("package-lock.json", "r", encoding="utf-8") as f:
                old_data = json.load(f)
        if os.path.exists("package.json"):
            with open("package.json", "r", encoding="utf-8") as f:
                old_pkgs = json.load(f)
        cmd = [
            "npm",
            "install",
            "--package-lock-only",
            "--ignore-scripts",
             "--no-audit", 
             "--no-fund"
            ] + initial_args

        result = subprocess.run(cmd,capture_output=True, shell=True)

        if result.returncode != 0:
            raise RuntimeError(f"npm dry-run failed:\nCMD: {' '.join(cmd)}\nOutput:{result.stdout}\nError:{result.stderr}")

        with open("package-lock.json", "r", encoding="utf-8") as lockfile:
            new_data = json.load(lockfile)
        """os.remove("package-lock.json")
        if old_data :
            with open("package-lock.json", "w", encoding="utf-8") as lock_file:
                json.dump(old_data, lock_file, indent=2)
                lock_file.close()"""
        
        if old_data and new_data:
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
        else:
            components=Node_Manager.scan_package_lock(new_data)
        if old_data:
            with open("package-lock.json", "w", encoding="utf-8") as lock_file:
                json.dump(old_data, lock_file, indent=2)
                lock_file.close()
        if old_pkgs:
            with open("package.json", "w", encoding="utf-8") as pkg_file:
                json.dump(old_pkgs, pkg_file, indent=2)
                pkg_file.close()
        return [comp["id"] for comp in components]
    
    @staticmethod
    def ensure_arborist(project_path):
        subprocess.run(
            ["npm", "install", "@npmcli/arborist", "--no-save"],
            cwd=project_path,
            check=True,
            shell=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

    @staticmethod
    def export_npm_dependencies(project_path):
        NODE_SCRIPT = r"""
import fs from "fs"

async function loadArborist() {
    try {
        const mod = await import("@npmcli/arborist")
        return mod.default || mod
    } catch (e) {
        const mod = await import(await import.meta.resolve("@npmcli/arborist"))
        return mod.default || mod
    }
}

function buildTree(node) {
    let name = node.name || ""

    if (name.startsWith(".")) {
        name = name.slice(1)
    }

    const children = [...node.children.values()]

    // PNPM virtual store flattening
    const deps = []
    for (const child of children) {
        if (child.name === ".pnpm") {
            //deps.push(...[...child.children.values()].map(buildTree))
        } else {
            deps.push(buildTree(child))
        }
    }
    //const dependencies_list = deps.map(d => d.base_id)
    return {
        id: `pkg:npm/${name}@${node.version}`,
        base_id: `pkg:npm/${name}@${node.version}`,
        name: name,
        version: node.version,
        path: node.path,
        dependencies: deps,
        license: node.package && node.package.license ? node.package.license : null,
        //dev: node.dev || false,
        //optional: node.optional || false,
        //peer: node.peer || false,
    }
}

async function run() {
    const Arborist = await loadArborist()

    const arb = new Arborist({
        path: process.cwd()
    })

    const tree = await arb.loadActual()

    const result = buildTree(tree)

    fs.writeFileSync(
        "dependencies.json",
        JSON.stringify(result, null, 2)
    )
}

run()
"""
        script_path = os.path.join(project_path, f"_arb_{uuid.uuid4().hex}.mjs")

        with open(script_path, "w", encoding="utf-8") as f:
            f.write(NODE_SCRIPT)

        try:
            subprocess.run(
                ["node", script_path],
                cwd=project_path,
                check=True,
            )
        finally:
            if os.path.exists(script_path):
                os.remove(script_path)

    @staticmethod
    def get_installed():
        if not os.path.exists("node_modules"):
            raise FileNotFoundError("node_modules directory not found. Please run 'install' first.")
        Node_Manager.ensure_arborist(os.getcwd())
        Node_Manager.export_npm_dependencies(os.getcwd())
        with open("dependencies.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        components = Node_Manager.get_installed_from_tree(data)
        Node_Manager.inventory_data+=components
        return [comp["id"] for comp in components]
    
    @staticmethod
    def get_installed_from_tree(tree):
        components = []
        def walk(node):
            if node["name"] and node["version"]:
                components.append(node)
            for child in node.get("dependencies", []):
                walk(child)
        walk(tree)
        for c in components:
            c["dependencies"] = [d["base_id"] for d in c.get("dependencies", [])]
        return components
    
    @staticmethod
    def run_real_install(engine,components):
        if engine=="npm":
            cmd = ["npm", "install"]
            for c in components:
                cmd.append(f"{c['name']}@{c['version']}")
            return subprocess.run(cmd,shell=True)
        elif engine=="yarn":
            cmd = ["yarn", "add"]
            for c in components:
                cmd.append(f"{c['name']}@{c['version']}")
            return subprocess.run(cmd,shell=True)
        elif engine=="pnpm":
            cmd = ["pnpm", "add"]
            for c in components:
                cmd.append(f"{c['name']}@{c['version']}")
            return subprocess.run(cmd,shell=True)
        elif engine=="bun":
            cmd = ["bun", "add"]
            for c in components:
                cmd.append(f"{c['name']}@{c['version']}")
            return subprocess.run(cmd,shell=True)