import subprocess
import sys
import tempfile
import json
from pathlib import Path
from importlib.metadata import distributions


class Pypi_Manager:

    @staticmethod
    def get_installed():
        return  [
        f'pkg:pypi/{dist.metadata["Name"].lower()}@{dist.version}'
        for dist in distributions()
    ]

    @staticmethod
    def get_installed_inventory():
        components_list = []

        for dist in distributions():
            meta = dist.metadata

            # Convert EntryPoints to a serializable structure
            entry_points = [
                {
                    "name": ep.name,
                    "group": ep.group,
                    "value": ep.value
                }
                for ep in dist.entry_points
            ]

            # Convert files to serializable form with full paths
            files = []
            if dist.files:
                for f in dist.files:
                    files.append({
                        "path": str(f),
                        "full_path": str(dist.locate_file(f)),
                        "hash": getattr(f, "hash", None).__dict__ if getattr(f, "hash", None) else None,
                        "size": None  # could populate by os.stat if needed
                    })

            # Try reading optional metadata fields safely
            def m(key, empty=""):
                return meta.get(key) or empty

            dist_info = {
                "name": dist.metadata["Name"],
                "version": dist.version,
                "metadata": meta.json,  # full metadata JSON

                # Common metadata fields
                "summary": m("Summary"),
                "license": m("License"),
                "author": m("Author"),
                "author_email": m("Author-email"),
                "home_page": m("Home-page"),
                "requires_python": m("Requires-Python"),

                # Dependencies
                "requires": dist.requires or [],

                # Entry points (console scripts, plugins…)
                "entry_points": entry_points,

                # Installation info
                "location": dist.locate_file("").as_posix(),
                "origin": dist._path.as_posix() if hasattr(dist, "_path") else None,

                # Files
                "files": files,

                # Additional metadata fields
                "platform": m("Platform"),
                "installer": m("Installer"),
                "python_version": m("Requires-Python"),
                "keywords": m("Keywords"),
                "classifiers": meta.get_all("Classifier") or [],

                # Top-level modules/packages
                "packages": meta.get_all("Top-Level") or []
            }

            components_list.append(dist_info)

        return components_list

    @staticmethod
    def run_dry_run(initial_args):
        with tempfile.NamedTemporaryFile(delete=False, suffix=".json") as tmp:
            report_path = Path(tmp.name)
        args=[]
        for item in initial_args:
            if item!="--":
                args.append(item)

        cmd = [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--dry-run",
            "--report",
            str(report_path),
        ] + args

        result = subprocess.run(cmd,capture_output=True)

        if result.returncode != 0:
            raise RuntimeError(f"pip dry-run failed:\nCMD: {' '.join(cmd)}\nOutput:{result.stdout}\nError:{result.stderr}")

        with open(report_path, "r", encoding="utf-8") as f:
            data = json.load(f)

        report_path.unlink(missing_ok=True)
        return data


    @staticmethod
    def run_real_install(file_name,engine):
        if engine=="pip":
            cmd = [sys.executable, "-m", "pip" , "install","-r",file_name]
            return subprocess.run(cmd)