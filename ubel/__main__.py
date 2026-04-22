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

from .ubel_engine import UbelEngine, PolicyViolationError, _initiate_local_policy, Pypi_Manager
from .info import banner                         # from the existing info module

try:
    from .info import __version__, __tool_name__, __tool_license__
except ImportError:
    __version__ = "0.0.0"
    __tool_name__ = "ubel-pip"
    __tool_license__ = "Apache 2.0"


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

def _print_header() -> None:
    print(banner)
    print()
    print(f"Reports location: {UbelEngine.reports_location}")
    print()
    print(f"Policy location:  {UbelEngine.policy_dir}")
    print()


# ---------------------------------------------------------------------------
# Policy configuration helpers  (mirrors JS threshold / block-unknown modes)
# ---------------------------------------------------------------------------

def _cmd_threshold(level: str) -> None:
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


def _cmd_block_unknown(raw: str) -> None:
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

def _validate_pkg_args(pkg_args: list[str]) -> None:
    bad = [] #[a for a in pkg_args if not PKG_ARG_RE.match(a)]
    accepted_non_alphanumeric_characters ="=._+-@/~"
    for arg in pkg_args:
        pkg=arg.strip()
        for char in accepted_non_alphanumeric_characters:
            pkg=pkg.replace(char,"")
        if not pkg.isalnum():
            bad.append(arg)
    if bad:
        print(
            f"[!] Rejected unsafe or malformed package argument(s): {', '.join(bad)}",
            file=sys.stderr,
        )
        print(
            "[!] Expected format: name, name==version, or @scope/name@version",
            file=sys.stderr,
        )
        sys.exit(1)


# ---------------------------------------------------------------------------
# Shared mode runner
# ---------------------------------------------------------------------------

def _run_mode(
    engine:    str,
    ecosystem: str,
    description: str,
    extra_argv: list[str] | None = None,
) -> None:
    _print_header()

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
        Pypi_Manager.init_venv(venv_dir = UbelEngine.venv_dir or "./venv")
        sys.exit(0)

    # ── threshold ────────────────────────────────────────────────────────────
    if mode == "threshold":
        level = extra_args[0] if extra_args else ""
        _cmd_threshold(level)
        sys.exit(0)

    # ── block-unknown ────────────────────────────────────────────────────────
    if mode == "block-unknown":
        raw = extra_args[0] if extra_args else ""
        _cmd_block_unknown(raw)
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

    if pkg_args:
        _validate_pkg_args(pkg_args)


    # ── scan ─────────────────────────────────────────────────────────────────
    UbelEngine.check_mode = mode
    try:
        UbelEngine.scan(pkg_args)
    except PolicyViolationError:
        sys.exit(1)
    except Exception as exc:
        print(f"[!] Scan failed: {exc}", file=sys.stderr)
        if os.environ.get("DEBUG"):
            import traceback; traceback.print_exc()
        sys.exit(1)


# ---------------------------------------------------------------------------
# Per-ecosystem entry-points  (mirror the JS bin/* wrappers)
# ---------------------------------------------------------------------------

def pip_mode() -> None:
    _run_mode("pip", "pypi", "Safe Python policy-driven supply-chain firewall")
    
    


def linux_mode() -> None:
    # Linux reports & policy live under $HOME to avoid requiring sudo for writes
    home = Path.home()
    UbelEngine.reports_location = str(home / UbelEngine.reports_location.lstrip("./"))
    UbelEngine.policy_dir       = str(home / UbelEngine.policy_dir.lstrip("./"))
    UbelEngine.system_type      = "linux"
    _run_mode(__tool_name__, "linux", "Safe Linux policy-driven supply-chain firewall")


# ---------------------------------------------------------------------------
# __main__ dispatch  (python -m ubel <engine> <mode> [args...])
# ---------------------------------------------------------------------------

def main() -> None:
    """
    Dispatch: python -m ubel pip health
                             pip check requests flask
                             pip threshold high
                             linux health
    """
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

    # Inject the remaining argv so each mode's argparse sees mode + extra_args
    sys.argv = [sys.argv[0]] + rest
    dispatch[engine_arg]()


if __name__ == "__main__":
    main()