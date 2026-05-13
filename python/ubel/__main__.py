"""
__main__.py — UBEL Python CLI entry-point.

Mirrors the Node.js main.js exactly:
  ubel-pip  <mode> [args...]
  ubel-linux <mode> [args...]

Modes:
  health          scan installed packages
  check           dry-run scan against new packages / requirements
  install         scan then install if policy passes
  init            initialise policy file and exit
  threshold       <low|medium|high|critical|none>  set severity_threshold
  block-unknown   <true|false>                     set block_unknown_vulnerabilities

Zero external dependencies (no dotenv, no requests, no packaging).
"""

from __future__ import annotations

import argparse
import os
import re
import sys
import json
from pathlib import Path

from .ubel_engine import UbelEngine as UbelEngine_Class, PolicyViolationError, _initiate_local_policy
from .python_runner import Pypi_Manager
from .info import banner                         # from the existing info module

try:
    from .info import __version__, __tool_name__, __tool_license__
except ImportError:
    __version__ = "0.0.0"
    __tool_name__ = "ubel-pip"
    __tool_license__ = "AGPL-3.0-only"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

VALID_MODES      = {"check", "install", "health", "init", "threshold", "block-unknown"}
VALID_SEVERITIES = {"low", "medium", "high", "critical", "none"}

# Same regex as the JS PKG_ARG_RE used to validate pypi/npm package args
PKG_ARG_RE = re.compile(
    r'^(@[a-z0-9_.+-]+/)?[a-z0-9_.+-]+(@[^\s;&|`$(){}\\\'\"<>]+)?$',
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# .env loader  (stdlib only — mirrors utils.js loadEnvironment)
# ---------------------------------------------------------------------------

def load_environment():
    env_path = Path(os.getcwd()) / ".env"
    if env_path.exists():
        try:
            for raw in env_path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = raw.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                eq  = line.index("=")
                key = line[:eq].strip()
                val = line[eq + 1:].strip().strip('"').strip("'")
                if key not in os.environ:
                    os.environ[key] = val
        except OSError:
            pass

    return (
        os.environ.get("UBEL_API_KEY"),
        os.environ.get("UBEL_ASSET_ID"),
        os.environ.get("UBEL_ENDPOINT"),
    )


# ---------------------------------------------------------------------------
# Banner / header
# ---------------------------------------------------------------------------

def _print_header(UbelEngine: UbelEngine_Class) -> None:
    print(banner)
    print()
    print(f"Reports location: {UbelEngine.reports_location}")
    print()
    print(f"Policy location:  {UbelEngine.policy_dir}")
    print()


# ---------------------------------------------------------------------------
# Policy configuration helpers  (mirrors JS threshold / block-unknown modes)
# ---------------------------------------------------------------------------

def _cmd_threshold(UbelEngine: UbelEngine_Class,level: str) -> None:
    level = level.lower()
    if level not in VALID_SEVERITIES:
        print(
            "[!] Provide a valid severity level: low | medium | high | critical | none",
            file=sys.stderr,
        )
        print("[!] Example: ubel-pip threshold high", file=sys.stderr)
        sys.exit(1)
    UbelEngine.set_policy_field("severity_threshold", level)
    print(f"[+] Policy updated: severity_threshold = {level}")
    print("[i] Infections are always blocked regardless of this setting.")


def _cmd_block_unknown(UbelEngine: UbelEngine_Class,raw: str) -> None:
    raw = raw.lower()
    if raw not in ("true", "false"):
        print("[!] Provide true or false", file=sys.stderr)
        print("[!] Example: ubel-pip block-unknown true", file=sys.stderr)
        sys.exit(1)
    value = raw == "true"
    UbelEngine.set_policy_field("block_unknown_vulnerabilities", value)
    print(f"[+] Policy updated: block_unknown_vulnerabilities = {value}")


# ---------------------------------------------------------------------------
# Argument validation
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Shared mode runner
# ---------------------------------------------------------------------------

def _run_mode(
    UbelEngine: UbelEngine_Class,
    engine:    str,
    ecosystem: str,
    description: str,
    extra_argv: list[str] | None = None,
    scan_scope: str = "repository",
    is_script:    bool = False,
    save_reports: bool = True,
    scan_os:      bool = False,
    full_stack:   bool = False,
    scan_venv:    bool = True,
    current_dir:  str | None = None,
) -> None:
    _print_header(UbelEngine)

    parser = argparse.ArgumentParser(description=description)
    parser.add_argument(
        "mode",
        choices=sorted(VALID_MODES),
        help="Execution mode",
    )
    parser.add_argument(
        "extra_args",
        nargs="*",
        help="Package arguments or sub-command arguments",
    )

    # Allow callers to inject argv (useful when the entry-point already
    # consumed sys.argv[0]).
    argv = extra_argv if extra_argv is not None else sys.argv[1:]
    args = parser.parse_args(argv)

    # Configure engine
    UbelEngine.engine      = engine
    UbelEngine.system_type = ecosystem
    _initiate_local_policy(
        UbelEngine.policy_dir,
        UbelEngine.policy_filename,
    )

    mode       = args.mode
    extra_args = args.extra_args or []

    # ── init ────────────────────────────────────────────────────────────────
    if mode == "init":
        Pypi_Manager().init_venv(venv_dir = UbelEngine.venv_dir or "./venv")
        sys.exit(0)

    # ── threshold ────────────────────────────────────────────────────────────
    if mode == "threshold":
        level = extra_args[0] if extra_args else ""
        _cmd_threshold(UbelEngine,level)
        sys.exit(0)

    # ── block-unknown ────────────────────────────────────────────────────────
    if mode == "block-unknown":
        raw = extra_args[0] if extra_args else ""
        _cmd_block_unknown(UbelEngine,raw)
        sys.exit(0)

    # ── collect package args ─────────────────────────────────────────────────
    pkg_args = extra_args

    # pip check/install with no args → fall back to requirements.txt
    if not pkg_args and engine == "pip" and mode in ("check", "install"):
        req = Path("requirements.txt")
        if not req.exists():
            print("[!] No package arguments and no requirements.txt found.", file=sys.stderr)
            sys.exit(1)
        pkg_args = [
            line.strip()
            for line in req.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.startswith("#")
        ]


    # ── scan ─────────────────────────────────────────────────────────────────
    UbelEngine.check_mode = mode
    try:
        UbelEngine.scan(
            pkg_args,
            scan_scope=scan_scope,
            is_script=is_script,
            save_reports=save_reports,
            scan_os=scan_os,
            full_stack=full_stack,
            scan_venv=scan_venv,
            current_dir=current_dir,
        )
    except PolicyViolationError:
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        if os.environ.get("DEBUG"):
            import traceback; traceback.print_exc()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Programmatic entry point  (mirrors JS main(programmaticOptions))
# ---------------------------------------------------------------------------

def main(programmatic_options: dict | None = None) -> dict | None:
    """
    Unified entry point for CLI callers AND programmatic callers.

    Programmatic usage (agent, platform, CI tool)::

        from ubel.__main__ import main

        report = main({
            "project_root": "/abs/path",
            "engine":       "pip",        # default "pip"
            "mode":         "health",     # default "health"
            "packages":     ["requests==2.31.0", "flask"],  # check/install only
            "is_script":    True,
            "save_reports": True,
            "scan_os":      False,
            "full_stack":   False,
            "scan_venv":    True,
            "scan_scope":   "repository",
        })

    When called with a dict, this function:
      - does NOT print the banner
      - does NOT call sys.exit()
      - returns the final_json report dict

    When called with no argument (or None) it falls through to the CLI
    dispatch based on sys.argv, identical to the old behaviour.

    Parameters
    ----------
    project_root : str        Absolute path to scan (cwd() when omitted).
    engine       : str        "pip" or the linux tool name.  default "pip".
    mode         : str        "health" | "check" | "install".  default "health".
    packages     : list[str]  Package specifiers for check/install mode
                              (e.g. ["requests==2.31.0", "flask"]).
                              Ignored in health mode.  Defaults to [].
    is_script    : bool       Suppress console output; never call sys.exit().
    save_reports : bool       Write reports to disk.  Set False to skip all I/O.
    scan_os      : bool       Include OS packages (Linux/Windows host).
    full_stack   : bool       Scan all ecosystems, not just Python venvs.
    scan_venv    : bool       Include Python venvs (set False to skip them).
    scan_scope   : str        Label written into scan_info.scan_scope.
    """
    UbelEngine=UbelEngine_Class()
    if programmatic_options is not None and isinstance(programmatic_options, dict):
        opts = programmatic_options

        project_root  = opts.get("project_root")
        engine        = opts.get("engine",       "pip")
        mode          = opts.get("mode",         "health")
        packages      = opts.get("packages",     [])
        is_script     = opts.get("is_script",    True)
        save_reports  = opts.get("save_reports", True)
        scan_os_opt   = opts.get("scan_os",      False)
        full_stack    = opts.get("full_stack",   False)
        scan_venv     = opts.get("scan_venv",    True)
        scan_scope    = opts.get("scan_scope",   "repository")

        original_cwd = os.getcwd()
        if project_root and project_root != original_cwd:
            os.chdir(project_root)

        try:
            UbelEngine.engine      = engine
            UbelEngine.system_type = "pypi" if engine == "pip" else engine
            UbelEngine.check_mode  = mode
            UbelEngine._vuln_ids_found = set()

            _initiate_local_policy(UbelEngine.policy_dir, UbelEngine.policy_filename)

            return UbelEngine.scan(
                packages,
                scan_scope=scan_scope,
                current_dir=project_root or original_cwd,
                is_script=is_script,
                save_reports=save_reports,
                scan_os=scan_os_opt,
                full_stack=full_stack,
                scan_venv=scan_venv,
            )
        finally:
            if project_root and project_root != original_cwd:
                os.chdir(original_cwd)

    # CLI fallback — dispatch via sys.argv (legacy path)
    argv = sys.argv[1:]
    if not argv:
        print("Usage: python -m ubel <engine> <mode> [args...]", file=sys.stderr)
        print("Engines: pip, linux", file=sys.stderr)
        sys.exit(1)

    engine_arg = argv[0].lower()
    rest       = argv[1:]

    dispatch = {
        "pip":   pip_mode,
        "linux": linux_mode,
    }

    if engine_arg not in dispatch:
        print(f"[!] Unknown engine: {engine_arg!r}. Choose from: {', '.join(dispatch)}", file=sys.stderr)
        sys.exit(1)

    sys.argv = [sys.argv[0]] + rest
    dispatch[engine_arg]()
    return None


# ---------------------------------------------------------------------------
# Per-ecosystem entry-points  (mirror the JS bin/* wrappers)
# ---------------------------------------------------------------------------

def pip_mode() -> None:
    UbelEngine=UbelEngine_Class()
    _run_mode(UbelEngine,"pip", "pypi", "Safe Python policy-driven supply-chain firewall", scan_scope="repository")
    
    


def linux_mode() -> None:
    # Linux reports & policy live under $HOME to avoid requiring sudo for writes.
    # These MUST be set before _run_mode() is called because _run_mode() calls
    # _initiate_local_policy(UbelEngine.policy_dir, …) as one of its first steps.
    home = Path.home()
    UbelEngine=UbelEngine_Class()
    UbelEngine.reports_location = str(home / ".ubel" / "local" / "reports")
    UbelEngine.policy_dir       = str(home / ".ubel" / "local" / "policy")
    UbelEngine.system_type      = "linux"
    _run_mode(UbelEngine,__tool_name__, "linux", "Safe Linux policy-driven supply-chain firewall", scan_scope="linux_machine")


# ---------------------------------------------------------------------------
# __main__ dispatch  (python -m ubel <engine> <mode> [args...])
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    main()