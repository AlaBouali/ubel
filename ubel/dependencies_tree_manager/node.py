import json
from pathlib import Path


class NPMDependencyTreeBuilder:

    @staticmethod
    def _resolve_npm_dependency_path(packages, parent_path, dep_name):
        """
        Resolve dependency according to npm hoisting rules.
        """
        current = parent_path

        while True:
            candidate = (current + "/node_modules/" + dep_name).strip("/")

            if candidate in packages:
                return candidate

            if current == "":
                break

            current = current.rsplit("/node_modules/", 1)[0] if "/node_modules/" in current else ""

        candidate = f"node_modules/{dep_name}"
        if candidate in packages:
            return candidate

        return None

    @staticmethod
    def extract_npm_dependency_graph(artifact_path: str):
        """
        Build a dependency graph keyed by package path.
        """
        with open(artifact_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        packages = data.get("packages", {})

        graph = {}

        for pkg_path, meta in packages.items():
            if pkg_path == "":
                continue

            name = meta.get("name") or pkg_path.split("/")[-1]

            graph[pkg_path] = {
                "name": name,
                "version": meta.get("version"),
                "dependencies": []
            }

        # resolve dependency edges
        for pkg_path, meta in packages.items():
            if pkg_path == "":
                continue

            deps = meta.get("dependencies", {})

            for dep_name in deps:
                resolved = NPMDependencyTreeBuilder._resolve_npm_dependency_path(
                    packages, pkg_path, dep_name
                )

                if resolved:
                    graph[pkg_path]["dependencies"].append(resolved)

        return graph

    @staticmethod
    def find_component_dependency_paths(graph: dict, components: list) -> dict:
        """
        Return all dependency branches leading to target components.
        """

        targets = {(c["name"], c.get("version")) for c in components}
        results = {}

        def dfs(node_path, path):
            node = graph[node_path]
            name = node["name"]
            version = node["version"]

            new_path = path + [f"{name}@{version}"]

            if (name, version) in targets:
                key = f"{name}@{version}"
                results.setdefault(key, []).append(new_path)

            for dep in node["dependencies"]:
                dfs(dep, new_path)

        # start traversal from top-level dependencies
        roots = [
            p for p in graph
            if p.count("node_modules") == 1
        ]

        for r in roots:
            dfs(r, [])

        return results

    @staticmethod
    def npm_vulnerable_components_tracer(artifact_path: str, vulnerable_components: list):
        graph = NPMDependencyTreeBuilder.extract_npm_dependency_graph(artifact_path)

        paths = NPMDependencyTreeBuilder.find_component_dependency_paths(
            graph, vulnerable_components
        )

        filtered = {}

        for comp, comp_paths in paths.items():
            # sort longest → shortest
            comp_paths = sorted(comp_paths, key=len, reverse=True)

            unique = []

            for p in comp_paths:
                is_suffix = False

                for existing in unique:
                    if len(existing) >= len(p) and existing[-len(p):] == p:
                        is_suffix = True
                        break

                if not is_suffix:
                    unique.append(p)

            filtered[comp] = unique

        return filtered