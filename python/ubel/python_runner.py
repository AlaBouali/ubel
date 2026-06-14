"""
self.py — PyPI package manager with local venv support.

Static methods:
    init_venv(venv_dir)              → create a venv at venv_dir (idempotent)
    run_dry_run(initial_args,        → pip dry-run inside the venv, returns
               venv_dir)               same component structure as before
    run_real_install(file_name,      → pip install -r inside the venv
                     engine,
                     venv_dir)
    build_dependency_sequences(inv)  → annotate inventory with dep sequences
    merge_inventory_by_purl(comps)   → deduplicate by PURL
    get_installed(start_dir)         → aggregate scan across ALL ecosystems
                                       (Python venvs, Node.js, C#, Go, Java,
                                        PHP, Ruby, Rust).  Returns list of
                                       PURL ids; full records in
                                       self.inventory_data.
    dry_run_cli(package_spec,        → pip dry-run for a CLI package inside a
                base_dir)              throw-away isolated venv; returns the
                                       same PURL list / inventory_data as
                                       run_dry_run without touching the real
                                       install location.
    install_cli(package_spec,        → create an isolated venv under base_dir,
                base_dir,              install the package into it, detect its
                bin_dir)               console-script entry-points, and write
                                       platform-appropriate shims into bin_dir
                                       so the CLI is available globally.
                                       Returns a dict with keys:
                                         tool_dir, venv_dir, shims, entry_points
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
import json
import os
import subprocess
import sys
import tempfile
import venv
from pathlib import Path
from typing import Any, Dict, List, Optional
from .venv_scanner          import PythonVenvScanner
from .node_runner  import NodeModulesScanner
from .csharp_runner         import CSharpNuGetScanner
from .go_runner             import GoModScanner
from .java_runner           import JavaMavenScanner
from .php_runner            import PhpComposerScanner
from .ruby_runner           import RubyBundlerScanner
from .rust_runner           import RustCargoScanner


class Pypi_Manager:

    # ------------------------------------------------------------------ #
    # Helpers                                                              #
    # ------------------------------------------------------------------ #

    package_manager = "pip"

    
    def _purl(self,name: str, version: str) -> str:
        return f"pkg:pypi/{name.lower()}@{version}"

    
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
    # Dependency sequences                                                 #
    # ------------------------------------------------------------------ #

    
    def build_dependency_sequences(self,inventory: List[Dict]) -> List[Dict]:
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

    
    def _venv_python(self,venv_dir: str) -> str:
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
    
    
    def get_pip_version(self,python: str) -> Optional[str]:
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

    
    def _resolve_dep_purl(self,raw_dep_name: str, name_to_purl: Dict[str, str]) -> str:
        key = raw_dep_name.lower().replace("-", "_")
        return name_to_purl.get(key, f"pkg:pypi/{raw_dep_name.lower()}@")

    # ------------------------------------------------------------------ #
    # init_venv                                                            #
    # ------------------------------------------------------------------ #

    
    def init_venv(self,venv_dir: str) -> str:
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

        return self._venv_python(str(venv_path))
    
    def get_installed(
        self,
        start_dir:  str  = ".",
        full_stack: bool = False,
        scan_venv:  bool = True,
        scan_os:    bool = False,
    ) -> List[str]:
        """
        Scan installed packages rooted at *start_dir*.

        Parameters
        ----------
        full_stack : When True, scan all supported ecosystems (Node.js, C#,
                     Go, Java, PHP, Ruby, Rust) in addition to Python venvs.
                     When False (default), scan Python venvs only.
        scan_venv  : Include Python venvs (PythonVenvScanner).  Default True.
                     Set False to skip Python venvs entirely (e.g. when you
                     only want the other ecosystems from a full_stack run).
        scan_os    : Include the host OS packages (Linux_Manager) after the
                     package-ecosystem sweep.  Default False.

        Returns a list of PURL id strings.
        Full component records are stored in ``self.inventory_data``.
        """
        start_dir = os.path.abspath(start_dir)

        scanners = []

        if scan_venv:
            scanners.append(PythonVenvScanner)

        if full_stack:
            scanners += [
                NodeModulesScanner,
                CSharpNuGetScanner,
                GoModScanner,
                JavaMavenScanner,
                PhpComposerScanner,
                RubyBundlerScanner,
                RustCargoScanner,
            ]

        all_components: List[Dict[str, Any]] = []

        with ThreadPoolExecutor(max_workers=len(scanners)) as executor:
        # Submit all scan tasks
            future_to_scanner = {
                executor.submit(lambda sc=sc: sc().get_installed(start_dir)): sc
                for sc in scanners
            }

            for future in as_completed(future_to_scanner):
                scanner_class = future_to_scanner[future]
                try:
                    scanner = scanner_class()
                    # The synchronous get_installed method populates scanner.inventory_data
                    future.result()  # re‑raise any exception inside the thread
                    all_components.extend(scanner.inventory_data)
                except Exception:
                    # One failing ecosystem must not block the others
                    pass
        if scan_os:
            try:
                from .os_health import LinuxHostScanner
                linux_scanner = LinuxHostScanner()
                linux_scanner.get_installed(start_dir)
                all_components.extend(linux_scanner.inventory_data)
            except Exception:
                pass

        merged = self.merge_inventory_by_purl(all_components)
        self.inventory_data = merged
        return [c["id"] for c in merged]

    # ------------------------------------------------------------------ #
    # run_dry_run                                                          #
    # ------------------------------------------------------------------ #

    
    def run_dry_run(self,initial_args: List[str], venv_dir: str) -> List[str]:
        """
        Run ``pip install --dry-run`` for *initial_args* inside *venv_dir*.

        The venv must already exist (call ``init_venv`` first).

        Returns a list of PURL id strings.
        Full records are stored in ``self.inventory_data``.
        """
        python = self._venv_python(venv_dir)

        pip_version = self.get_pip_version(python)
        if pip_version is None:
            if os.path.exists(venv_dir):
                os.remove(venv_dir)
                python = self._venv_python(venv_dir)

                pip_version = self.get_pip_version(python)
                if pip_version is None:
                    raise RuntimeError(f"pip is not installed in the venv at {venv_dir} after re-creation")
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
                name_to_purl.setdefault(key, self._purl(n, v))

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
                deps.append(self._resolve_dep_purl(dep_name, name_to_purl))

            components.append({
                "id":           self._purl(name, version),
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

        components = self.merge_inventory_by_purl(components)
        components = self.build_dependency_sequences(components)

        self.inventory_data = components
        return [c["id"] for c in components]

    # ------------------------------------------------------------------ #
    # run_real_install                                                     #
    # ------------------------------------------------------------------ #

    
    def run_real_install(
            self,
        file_name: str,
        engine: str,
        venv_dir: str,
    ) -> subprocess.CompletedProcess:
        """
        Install packages from *file_name* into *venv_dir*.

        Currently only ``engine="pip"`` is supported.
        The venv must already exist (call ``init_venv`` first).
        """
        python = self._venv_python(venv_dir)

        if engine == "pip":
            cmd = [python, "-m", "pip", "install", "-r", file_name]
            try:
                return subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as exc:
                print(f"[!] Package install failed (exit {exc.returncode}): {' '.join(cmd)}", file=sys.stderr)
                raise

        raise ValueError(f"Unsupported engine: {engine!r}")

    # ------------------------------------------------------------------ #
    # CLI isolation helpers                                                #
    # ------------------------------------------------------------------ #

    def _tool_dirs(self, package_spec: str, base_dir: str) -> tuple[Path, Path]:
        """
        Return (tool_dir, venv_dir) for *package_spec* rooted at *base_dir*.

        The package name is normalised (lowercased, hyphens → underscores) so
        that ``Black``, ``black``, and ``black[d]`` all land in the same slot.
        The version pin, extras, and URL markers are stripped before the name
        is used as a directory component.
        """
        # Strip extras [foo], version pins (==, >=, …), and URL markers (@)
        raw_name = package_spec.split("[")[0].split("@")[0]
        for op in ("==", "!=", ">=", "<=", ">", "<", "~="):
            raw_name = raw_name.split(op)[0]
        norm_name = raw_name.strip().lower().replace("-", "_")

        tool_dir = Path(base_dir).expanduser().resolve() / norm_name
        venv_dir = tool_dir / ".venv"
        return tool_dir, venv_dir

    # ------------------------------------------------------------------ #
    # PATH persistence                                                     #
    # ------------------------------------------------------------------ #

    def _ubel_bin_dir(self) -> Path:
        """
        Return the canonical UBEL bin directory for the current platform.

        Linux/macOS : ~/.ubel/bin
        Windows     : %APPDATA%\\ubel\\bin
        """
        if os.name == "nt":
            appdata = os.environ.get("APPDATA", str(Path.home() / "AppData" / "Roaming"))
            return Path(appdata) / "ubel" / "bin"
        return Path.home() / ".ubel" / "bin"

    def _ensure_bin_in_path(self, bin_dir: Path) -> None:
        """
        Persistently add *bin_dir* to the user PATH so every new terminal
        session picks it up automatically.  Idempotent — does nothing if the
        directory is already registered.

        Windows : writes to HKCU\\Environment via the registry and broadcasts
                  WM_SETTINGCHANGE so running Explorer/shells notice without a
                  reboot.
        Linux   : appends an export line to the first rc file found among
                  ~/.bashrc, ~/.zshrc, ~/.profile.  Falls back to ~/.profile.
        """
        bin_str = str(bin_dir)

        if os.name == "nt":
            # ── Windows: persist via user registry ───────────────────────
            try:
                import winreg  # only available on Windows
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    r"Environment",
                    0,
                    winreg.KEY_READ | winreg.KEY_WRITE,
                )
                try:
                    current, reg_type = winreg.QueryValueEx(key, "PATH")
                except FileNotFoundError:
                    current, reg_type = ("", winreg.REG_EXPAND_SZ)

                entries = [e for e in current.split(os.pathsep) if e]
                if bin_str not in entries:
                    entries.append(bin_str)
                    new_value = os.pathsep.join(entries)
                    winreg.SetValueEx(key, "PATH", 0, reg_type, new_value)
                    winreg.CloseKey(key)

                    # Broadcast the change so new cmd/PowerShell windows
                    # inherit the updated PATH without a logoff/reboot.
                    try:
                        import ctypes
                        HWND_BROADCAST   = 0xFFFF
                        WM_SETTINGCHANGE = 0x001A
                        ctypes.windll.user32.SendMessageTimeoutW(
                            HWND_BROADCAST, WM_SETTINGCHANGE, 0,
                            "Environment", 0, 1000, None,
                        )
                    except Exception:
                        pass  # broadcast is best-effort

                    print(
                        f"[ubel] Added {bin_str} to your user PATH (registry).\n"
                        f"       Open a new terminal for the change to take effect.",
                        file=sys.stderr,
                    )
                else:
                    winreg.CloseKey(key)

            except Exception as exc:
                print(
                    f"[ubel] Could not update the registry PATH automatically: {exc}\n"
                    f"       Add this manually via System Properties → Environment Variables:\n"
                    f"         {bin_str}",
                    file=sys.stderr,
                )

        else:
            # ── Linux / macOS: append export to shell rc file ─────────────
            rc_candidates = [
                Path.home() / ".bashrc",
                Path.home() / ".zshrc",
                Path.home() / ".profile",
            ]
            # Pick the first rc file that already exists; fall back to ~/.profile.
            rc_file = next((p for p in rc_candidates if p.exists()), Path.home() / ".profile")

            export_line = f'\nexport PATH="{bin_str}:$PATH"  # added by ubel\n'

            # Check whether it's already there (avoid duplicates across runs).
            existing = rc_file.read_text(encoding="utf-8") if rc_file.exists() else ""
            if bin_str not in existing:
                with rc_file.open("a", encoding="utf-8") as fh:
                    fh.write(export_line)
                print(
                    f"[ubel] Added {bin_str} to PATH in {rc_file}.\n"
                    f"       Run:  source {rc_file}  (or open a new terminal).",
                    file=sys.stderr,
                )

    def _detect_entry_points(self, package_spec: str, venv_dir: Path) -> Dict[str, Path]:
        """
        Return a mapping of ``{script_name: absolute_path}`` for every
        console-script entry-point that belongs to *package_spec*.

        Strategy
        --------
        1. Ask ``importlib.metadata`` (via the venv's Python) for the
           distribution's entry-points in the ``console_scripts`` group.
        2. Fall back to diffing the venv's bin/Scripts directory against a
           known baseline of always-present files if step 1 yields nothing.
        """
        python = self._venv_python(str(venv_dir))
        bin_dir = venv_dir / ("Scripts" if os.name == "nt" else "bin")

        # Normalise to bare distribution name (no extras / pins)
        raw_name = package_spec.split("[")[0].split("@")[0]
        for op in ("==", "!=", ">=", "<=", ">", "<", "~="):
            raw_name = raw_name.split(op)[0]
        dist_name = raw_name.strip()

        # ── 1. importlib.metadata query ──────────────────────────────────
        # entry_points(group=..., package=...) filters by distribution directly.
        # dist_name is passed as a repr'd string literal so it is always valid
        # Python inside the one-liner regardless of the package name.
        probe = (
            "import json, importlib.metadata as m; "
            f"eps = m.entry_points(group='console_scripts', package={dist_name!r}); "
            "print(json.dumps([ep.name for ep in eps]))"
        )
        entry_names: List[str] = []
        try:
            result = subprocess.run(
                [python, "-c", probe],
                capture_output=True, text=True, check=True,
            )
            entry_names = json.loads(result.stdout.strip())
        except Exception:
            pass

        # ── 2. Fallback: diff the bin dir ─────────────────────────────────
        # Exclude anything that starts with a known venv-baseline prefix so
        # that versioned variants (pip3.11, wheel3, python3.12, activate.fish,
        # easy_install-3.x, …) are all caught without enumerating them.
        _VENV_BASELINE_PREFIXES = (
            "python", "pip", "wheel", "activate", "deactivate", "easy_install",
        )
        if not entry_names and bin_dir.is_dir():
            for p in bin_dir.iterdir():
                stem = p.stem if os.name == "nt" else p.name
                if any(stem.startswith(pfx) for pfx in _VENV_BASELINE_PREFIXES):
                    continue
                if os.name != "nt" and p.stat().st_mode & 0o111:
                    entry_names.append(p.name)
                elif os.name == "nt" and p.suffix.lower() in (".exe", ".cmd", ""):
                    entry_names.append(stem)

        # Build the final map: name → absolute Path inside the venv
        result_map: Dict[str, Path] = {}
        for name in entry_names:
            candidates = [bin_dir / name]
            if os.name == "nt":
                candidates += [bin_dir / f"{name}.exe", bin_dir / f"{name}.cmd"]
            for candidate in candidates:
                if candidate.exists():
                    result_map[name] = candidate
                    break

        return result_map

    def _write_shim(self, shim_path: Path, target: Path) -> None:
        """
        Write a thin wrapper at *shim_path* that exec-delegates to *target*.

        On POSIX a shell shim is used (fastest, no extra process).
        On Windows a .cmd wrapper is written alongside a .py launcher as
        fallback because .cmd files are first-class on the PATH.
        """
        if os.name == "nt":
            # .cmd shim — works from cmd.exe and PowerShell
            cmd_path = shim_path.with_suffix(".cmd")
            cmd_path.write_text(
                f'@echo off\r\n"{target}" %*\r\n',
                encoding="utf-8",
            )
            # Also write a .py shim as a universal fallback
            shim_path.with_suffix(".py").write_text(
                f"import subprocess, sys, os\n"
                f"sys.exit(subprocess.call(\n"
                f"    [{str(target)!r}] + sys.argv[1:]\n"
                f"))\n",
                encoding="utf-8",
            )
        else:
            shim_path.write_text(
                f"#!/bin/sh\nexec {str(target)!r} \"$@\"\n",
                encoding="utf-8",
            )
            shim_path.chmod(shim_path.stat().st_mode | 0o111)  # +x

    # ------------------------------------------------------------------ #
    # dry_run_cli                                                          #
    # ------------------------------------------------------------------ #

    def dry_run_cli(
        self,
        package_spec: str,
        base_dir: str = f"{Path.home()}/.ubel/tools/python",
    ) -> List[str]:
        """
        Perform a pip dry-run for *package_spec* inside a throw-away isolated
        venv located at ``<base_dir>/<normalised_name>/.venv``.

        The venv is created if it does not exist yet (idempotent), but nothing
        is actually installed — this is a pure resolution / inventory step.

        Parameters
        ----------
        package_spec : Anything ``pip install`` accepts: bare name, name with
                       version pin, name with extras, or a PEP 440 URL.
                       Examples: ``"black"``, ``"black==24.3.0"``,
                       ``"black[d]>=24"``.
        base_dir     : Root directory under which per-tool folders are created.
                       Defaults to ``~/.ubel/tools/python``.

        Returns
        -------
        List of PURL id strings (same shape as ``run_dry_run``).
        Full component records are stored in ``self.inventory_data``.
        """
        _, venv_dir = self._tool_dirs(package_spec, base_dir)
        self.init_venv(str(venv_dir))
        return self.run_dry_run([package_spec], str(venv_dir))

    # ------------------------------------------------------------------ #
    # install_cli                                                          #
    # ------------------------------------------------------------------ #

    def install_cli(
        self,
        package_spec: str,
        base_dir: str = f"{Path.home()}/.ubel/tools/python",
        bin_dir: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Install *package_spec* into an isolated venv and expose its
        console-script entry-points as global shims.

        Layout
        ------
        ``~/.ubel/tools/python/<normalised_name>/``   (Linux)
        ``%APPDATA%\\ubel\\tools\\python\\<name>\\``  (Windows)
            ``metadata.json``          ← install record written by this method
            ``.venv/``                 ← isolated virtual environment

        ``~/.ubel/bin/<entry-point>``           (Linux)
        ``%APPDATA%\\ubel\\bin\\<entry-point>`` (Windows)
            ← thin shim(s) pointing into the venv

        The ubel bin directory is registered in the user PATH automatically
        on first use (registry on Windows, rc file on Linux/macOS) so shims
        are immediately callable from any new terminal without manual setup.

        Parameters
        ----------
        package_spec : Anything ``pip install`` accepts.
        base_dir     : Root for per-tool folders.
                       Default: ``~/.ubel/tools`` (Linux) /
                                ``%APPDATA%\\ubel\\tools`` (Windows).
        bin_dir      : Directory where shims are written.  Must be on the
                       user's PATH.  Defaults to the ubel-owned bin dir:
                         Linux/macOS → ``~/.ubel/bin``
                         Windows     → ``%APPDATA%\\ubel\\bin``

        Returns
        -------
        A dict with keys:
            ``tool_dir``     – absolute Path of the tool's home directory
            ``venv_dir``     – absolute Path of the isolated venv
            ``entry_points`` – mapping of ``{script_name: venv_binary_path}``
            ``shims``        – list of absolute Paths of written shim files
            ``bin_dir``      – resolved Path where shims were placed
        """
        # ── Resolve directories ───────────────────────────────────────────
        tool_dir, venv_dir = self._tool_dirs(package_spec, base_dir)

        # Remove any previous installation unconditionally so stale venv
        # state, old entry-points, or version mismatches can never persist.
        if tool_dir.exists():
            import shutil
            shutil.rmtree(tool_dir)

        tool_dir.mkdir(parents=True, exist_ok=True)

        if bin_dir is None:
            resolved_bin = self._ubel_bin_dir()
        else:
            resolved_bin = Path(bin_dir).expanduser().resolve()

        resolved_bin.mkdir(parents=True, exist_ok=True)

        # ── Ensure ubel bin dir is on the persistent user PATH ────────────
        self._ensure_bin_in_path(resolved_bin)

        # ── Create venv and install ───────────────────────────────────────
        self.init_venv(str(venv_dir))
        python = self._venv_python(str(venv_dir))

        cmd = [python, "-m", "pip", "install", "--quiet", package_spec]
        try:
            subprocess.run(cmd, check=True)
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(
                f"pip install failed (exit {exc.returncode}): {' '.join(cmd)}"
            ) from exc

        # ── Detect entry-points ───────────────────────────────────────────
        entry_points = self._detect_entry_points(package_spec, venv_dir)

        if not entry_points:
            print(
                f"[ubel] No console-script entry-points found for {package_spec!r}.\n"
                f"       The package was installed at {venv_dir} but no global\n"
                f"       shim was created.  You can invoke it directly via:\n"
                f"         {python}",
                file=sys.stderr,
            )

        # ── Write shims ───────────────────────────────────────────────────
        shims: List[Path] = []
        for script_name, venv_bin in entry_points.items():
            shim_path = resolved_bin / script_name
            self._write_shim(shim_path, venv_bin)
            shims.append(shim_path)

        # ── Persist a metadata record inside the tool dir ─────────────────
        # Useful for UBEL's own uninstall / list / upgrade commands later.
        metadata: Dict[str, Any] = {
            "package_spec": package_spec,
            "venv_dir":     str(venv_dir),
            "bin_dir":      str(resolved_bin),
            "entry_points": {k: str(v) for k, v in entry_points.items()},
            "shims":        [str(s) for s in shims],
        }
        (tool_dir / "metadata.json").write_text(
            json.dumps(metadata, indent=2), encoding="utf-8"
        )

        return {
            "tool_dir":     tool_dir,
            "venv_dir":     venv_dir,
            "entry_points": entry_points,
            "shims":        shims,
            "bin_dir":      resolved_bin,
        }