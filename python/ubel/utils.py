"""
utils.py — UBEL Python utilities.

Python port of utils.js + git_info.js.
Zero external dependencies (no dotenv, no requests).

Public API
----------
load_environment()          → (api_key, asset_id, endpoint)
create_output_dir(base)     → Path
download_file(url, dest)    → None
dict_to_str(data, ...)      → str
get_git_metadata()          → dict
"""

from __future__ import annotations

import os
import subprocess
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Environment  (mirrors utils.js loadEnvironment)
# ---------------------------------------------------------------------------

def load_environment() -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """
    Load UBEL_API_KEY, UBEL_ASSET_ID, UBEL_ENDPOINT from .env or process env.
    Minimal dotenv — reads .env in cwd if it exists, then falls back to
    the real environment.  Does NOT overwrite already-set env vars.
    """
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
        os.environ.get("UBEL_API_KEY")  or None,
        os.environ.get("UBEL_ASSET_ID") or None,
        os.environ.get("UBEL_ENDPOINT") or None,
    )


# ---------------------------------------------------------------------------
# Output directory  (mirrors utils.js createOutputDir)
# ---------------------------------------------------------------------------

def create_output_dir(base: str = "./") -> Path:
    """
    Create and return a timestamped output directory under
    <base>/.ubel/reports/remote/<YYYY>/<MM>/<DD>/
    """
    now       = datetime.now(timezone.utc)
    date_path = now.strftime("%Y/%m/%d")
    directory = Path(base) / ".ubel" / "reports" / "remote" / date_path
    directory.mkdir(parents=True, exist_ok=True)
    return directory


# ---------------------------------------------------------------------------
# File download  (mirrors utils.js downloadFile, stdlib only)
# ---------------------------------------------------------------------------

def download_file(url: str, destination: Path) -> None:
    """Download *url* to *destination* using stdlib urllib."""
    req = urllib.request.Request(url, headers={"User-Agent": "ubel_tool"})
    with urllib.request.urlopen(req, timeout=300) as resp:
        chunk_size = 8192
        with open(destination, "wb") as fh:
            while True:
                chunk = resp.read(chunk_size)
                if not chunk:
                    break
                fh.write(chunk)


# ---------------------------------------------------------------------------
# dict_to_str  (mirrors utils.js dictToStr / engine.py dict_to_str)
# ---------------------------------------------------------------------------

def dict_to_str(data: Any, indent: int = 0, step: int = 4) -> str:
    """Recursive pretty-printer for dicts and lists."""
    lines: list[str] = []
    pad = " " * indent

    if isinstance(data, dict):
        for key, value in data.items():
            lines.append(f"{pad}{key}:")
            if isinstance(value, (dict, list)):
                lines.append(dict_to_str(value, indent + step, step))
            else:
                lines.append(" " * (indent + step) + str(value))
    elif isinstance(data, list):
        for item in data:
            if isinstance(item, (dict, list)):
                lines.append(dict_to_str(item, indent + step, step))
            else:
                lines.append(f"{pad}- {item}")
    else:
        lines.append(pad + str(data))

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Git metadata  (Python port of git_info.js getGitMetadata)
# ---------------------------------------------------------------------------

def _git(*args: str) -> Optional[str]:
    """Run a git sub-command and return stdout, or None on failure."""
    try:
        result = subprocess.run(
            ["git"] + list(args),
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            stdin=subprocess.DEVNULL,
            timeout=5,
            text=True,
        )
        return result.stdout.strip() if result.returncode == 0 else None
    except Exception:
        return None


def get_git_metadata() -> Dict[str, Any]:
    """
    Return git repository metadata for the current working directory.

    Mirrors getGitMetadata() in git_info.js exactly:
        {
            "available":     bool,
            "latest_commit": str | None,
            "branch":        str | None,
            "url":           str | None,
        }
    """
    # Check if inside a git repo
    inside = _git("rev-parse", "--is-inside-work-tree")
    if inside != "true":
        return {
            "available":     False,
            "latest_commit": None,
            "branch":        None,
            "url":           None,
        }

    # Remote URL (origin)
    url = _git("config", "--get", "remote.origin.url")

    # Normalise SSH → HTTPS  (git@github.com:user/repo.git → https://…)
    if url and url.startswith("git@"):
        import re
        m = re.match(r"^git@(.*?):(.*)$", url)
        if m:
            url = f"https://{m.group(1)}/{m.group(2)}"

    # Branch name
    branch = _git("rev-parse", "--abbrev-ref", "HEAD")
    # Detached HEAD fallback
    if branch == "HEAD":
        branch = _git("branch", "--show-current") or None

    # Latest commit (full SHA, mirrors JS)
    latest_commit = _git("rev-parse", "HEAD")

    return {
        "available":     True,
        "latest_commit": latest_commit,
        "branch":        branch,
        "url":           url,
    }