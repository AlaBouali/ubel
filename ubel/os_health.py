"""
linux_host_scanner.py — Linux host package scanner.

Pure-Python port of linux_host_scanner.js.
Zero external dependencies.

Supports:
  - Debian / Ubuntu  (dpkg)
  - Alpine           (apk)
  - RedHat / AlmaLinux / RockyLinux  (rpm)

Output record per package:
    {
        "id":           "pkg:deb/ubuntu/bash@5.2.21",
        "name":         "bash",
        "version":      "5.2.21",
        "type":         "application",
        "ecosystem":    "ubuntu",
        "license":      "unknown",
        "paths":        ["/usr/bin/bash"],
        "dependencies": ["pkg:deb/ubuntu/libc6@2.39"],
        "scopes":       ["prod"],
        "state":        "undetermined",
    }

Usage
-----
    from linux_host_scanner import LinuxHostScanner
    import asyncio

    ids = asyncio.run(LinuxHostScanner.get_installed())
    for rec in LinuxHostScanner.inventory_data:
        print(rec)
"""

from __future__ import annotations

import os
import re
import stat
import subprocess
from typing import Dict, Generator, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SUBPROCESS_TIMEOUT = 120  # seconds

ALLOWED_ECOSYSTEMS: Set[str] = {
    "debian", "ubuntu", "redhat", "almalinux", "rockylinux", "alpine",
}

PURL_TYPE: Dict[str, str] = {
    "debian":     "deb",
    "ubuntu":     "deb",
    "alpine":     "apk",
    "redhat":     "rpm",
    "almalinux":  "rpm",
    "rockylinux": "rpm",
}

BINARY_PREFIXES = (
    "/bin/", "/sbin/",
    "/usr/bin/", "/usr/sbin/",
    "/usr/local/bin/", "/usr/local/sbin/",
    "/usr/lib/", "/usr/libexec/", "/opt/",
)


# ---------------------------------------------------------------------------
# PURL helpers
# ---------------------------------------------------------------------------

def _make_purl(ecosystem: str, name: str, version: str) -> str:
    purl_type = PURL_TYPE.get(ecosystem, ecosystem)
    display_eco = "rocky-linux" if ecosystem == "rockylinux" else ecosystem
    return f"pkg:{purl_type}/{display_eco}/{name}@{version or ''}"


# ---------------------------------------------------------------------------
# OS detection
# ---------------------------------------------------------------------------

def _parse_os_release(content: str) -> str:
    data: Dict[str, str] = {}
    for raw in content.splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        eq  = line.index("=")
        key = line[:eq].strip()
        val = line[eq + 1:].strip().strip('"').strip("'")
        data[key] = val

    def normalise(v: str) -> str:
        return v.lower().replace(" ", "").replace("-", "")

    candidates: List[str] = []
    if "ID" in data:
        candidates.append(normalise(data["ID"]))
    if "ID_LIKE" in data:
        for token in data["ID_LIKE"].split():
            candidates.append(normalise(token))

    for c in candidates:
        if c in ALLOWED_ECOSYSTEMS:
            return c

    raise RuntimeError(f"Unsupported OS ecosystem: {candidates}")


def _detect_host_ecosystem() -> str:
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.exists(p):
            with open(p, "r", encoding="utf-8", errors="replace") as fh:
                return _parse_os_release(fh.read())
    raise RuntimeError("Cannot detect OS ecosystem: no os-release file found")


# ---------------------------------------------------------------------------
# Executable-path heuristic
# ---------------------------------------------------------------------------

def _is_executable_path(path: str) -> bool:
    return any(path.startswith(pfx) for pfx in BINARY_PREFIXES) and not path.endswith("/")


def _has_execute_bit(filepath: str) -> bool:
    try:
        st = os.stat(filepath)
        return stat.S_ISREG(st.st_mode) and bool(st.st_mode & 0o111)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# Dependency field parsers
# ---------------------------------------------------------------------------

_DEP_NAME_RE = re.compile(r"^([A-Za-z0-9_.+\-]+)")


def _parse_dpkg_deps(raw: str) -> List[str]:
    if not raw:
        return []
    names: List[str] = []
    for clause in raw.split(","):
        for alt in clause.split("|"):
            m = _DEP_NAME_RE.match(alt.strip())
            if m:
                names.append(m.group(1))
    return list(dict.fromkeys(names))  # deduplicate, preserve order


def _parse_apk_deps(raw: str) -> List[str]:
    if not raw:
        return []
    names: List[str] = []
    for dep in raw.split():
        name = re.split(r"[><=~!]", dep)[0].removeprefix("so:")
        if name:
            names.append(name)
    return list(dict.fromkeys(names))


def _clean_rpm_deps(raw: str) -> List[str]:
    if not raw:
        return []
    names: List[str] = []
    for token in raw.split(","):
        t = token.strip()
        if not t:                              continue
        if t.startswith("rpmlib("):           continue
        if "(" in t:                           continue  # capability / shared-lib
        if t.startswith("/"):                  continue  # file path requirement
        if re.fullmatch(r"[A-Za-z0-9_.+\-]+", t):
            names.append(t)
    return list(dict.fromkeys(names))


# ---------------------------------------------------------------------------
# Build final package dict
# ---------------------------------------------------------------------------

def _build_package(
    ecosystem: str,
    name: str,
    version: str,
    license_: str,
    paths: List[str],
    dep_names: List[str],
    purls: Dict[str, str],
) -> Dict:
    id_ = _make_purl(ecosystem, name, version)
    dependencies = [purls[d] for d in dep_names if d in purls]
    return {
        "id":           id_,
        "name":         name,
        "version":      version,
        "type":         "application",
        "ecosystem":    ecosystem,
        "license":      license_ or "unknown",
        "state":        "undetermined",
        "scopes":       ["prod"],
        "paths":        paths,
        "dependencies": dependencies,
    }


# ---------------------------------------------------------------------------
# DPKG scanner (Debian / Ubuntu)
# ---------------------------------------------------------------------------

def _parse_dpkg_status(content: str) -> Dict[str, Dict]:
    """Returns {name: {version, license, deps[]}}"""
    pkgs: Dict[str, Dict] = {}
    pkg = ver = lic = dep = None

    for raw in content.splitlines():
        line = raw.rstrip()

        if line.startswith("Package:"):
            pkg = line[len("Package:"):].strip()
        elif line.startswith("Version:"):
            ver = line[len("Version:"):].strip()
        elif line.startswith("License:"):
            lic = line[len("License:"):].strip()
        elif line.startswith("Depends:"):
            dep = line[len("Depends:"):].strip()
        elif line.strip() == "":
            if pkg and ver:
                pkgs[pkg] = {
                    "version": ver,
                    "license": lic or "unknown",
                    "deps":    _parse_dpkg_deps(dep or ""),
                }
            pkg = ver = lic = dep = None

    # flush last stanza
    if pkg and ver:
        pkgs[pkg] = {
            "version": ver,
            "license": lic or "unknown",
            "deps":    _parse_dpkg_deps(dep or ""),
        }
    return pkgs


def _scan_dpkg(ecosystem: str) -> List[Dict]:
    status_path = "/var/lib/dpkg/status"
    if not os.path.exists(status_path):
        raise RuntimeError(f"dpkg: status file not found at {status_path}")

    with open(status_path, "r", encoding="utf-8", errors="replace") as fh:
        pkgs = _parse_dpkg_status(fh.read())

    # PURL index
    purls: Dict[str, str] = {name: _make_purl(ecosystem, name, info["version"])
                              for name, info in pkgs.items()}

    # Executable paths from .list files
    paths_by_pkg: Dict[str, List[str]] = {}
    info_dir = "/var/lib/dpkg/info"

    if os.path.exists(info_dir):
        for fname in os.listdir(info_dir):
            if not fname.endswith(".list"):
                continue
            pkg_name = os.path.splitext(fname)[0].split(":")[0]  # strip :arch
            if pkg_name not in pkgs:
                continue

            list_path = os.path.join(info_dir, fname)
            try:
                with open(list_path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        fp = line.strip()
                        if fp and _is_executable_path(fp) and os.path.exists(fp) and _has_execute_bit(fp):
                            paths_by_pkg.setdefault(pkg_name, []).append(fp)
            except OSError:
                pass

    result: List[Dict] = []
    for name, info in pkgs.items():
        result.append(_build_package(
            ecosystem, name, info["version"], info["license"],
            paths_by_pkg.get(name, []),
            info["deps"],
            purls,
        ))
    return result


# ---------------------------------------------------------------------------
# APK scanner (Alpine)
# ---------------------------------------------------------------------------

def _parse_apk_installed(content: str, ecosystem: str) -> Dict[str, Dict]:
    pkgs: Dict[str, Dict] = {}
    name = version = None
    license_ = "unknown"
    deps: List[str] = []
    prefix = ""
    seeded = False

    def flush() -> None:
        nonlocal name, version, license_, deps, prefix, seeded
        if name and version and not seeded:
            pkgs[name] = {"version": version, "license": license_, "deps": deps, "paths": []}
        prefix = ""; license_ = "unknown"; deps = []; seeded = False

    for raw in content.splitlines():
        line = raw.rstrip()

        if line.startswith("P:"):
            flush()
            name    = line[2:].strip()
            version = None
        elif line.startswith("V:"):
            version = line[2:].strip()
        elif line.startswith("L:"):
            license_ = line[2:].strip() or "unknown"
        elif line.startswith("D:"):
            deps = _parse_apk_deps(line[2:].strip())
        elif line.startswith("F:"):
            prefix = line[2:].strip()
            if name and version and not seeded:
                pkgs[name] = {"version": version, "license": license_, "deps": deps, "paths": []}
                seeded = True
        elif line.startswith("R:"):
            if name and version:
                if not seeded:
                    pkgs[name] = {"version": version, "license": license_, "deps": deps, "paths": []}
                    seeded = True
                filename = line[2:].strip()
                filepath = f"/{prefix}/{filename}" if prefix else f"/{filename}"
                if _is_executable_path(filepath):
                    pkgs[name]["paths"].append(filepath)
        elif line.strip() == "":
            if name and version and not seeded:
                pkgs[name] = {"version": version, "license": license_, "deps": deps, "paths": []}
            seeded = False
            prefix = ""; license_ = "unknown"; deps = []

    flush()
    return pkgs


def _scan_apk(ecosystem: str) -> List[Dict]:
    db_path = "/lib/apk/db/installed"
    if not os.path.exists(db_path):
        raise RuntimeError(f"apk: database not found at {db_path}")

    with open(db_path, "r", encoding="utf-8", errors="replace") as fh:
        pkgs = _parse_apk_installed(fh.read(), ecosystem)

    purls: Dict[str, str] = {name: _make_purl(ecosystem, name, info["version"])
                              for name, info in pkgs.items()}

    result: List[Dict] = []
    for name, info in pkgs.items():
        result.append(_build_package(
            ecosystem, name, info["version"], info["license"],
            info["paths"],
            info["deps"],
            purls,
        ))
    return result


# ---------------------------------------------------------------------------
# RPM scanner (RedHat / AlmaLinux / RockyLinux)
# ---------------------------------------------------------------------------

_RPM_QA_QF  = r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t[%{REQUIRENAME},]\n"
_RPM_QL_QF  = r"[%{=NAME}\t%{FILENAMES}\n]"


def _rpm_query_all() -> Dict[str, Dict]:
    try:
        out = subprocess.check_output(
            ["rpm", "-qa", "--qf", _RPM_QA_QF],
            timeout=SUBPROCESS_TIMEOUT,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="replace")
    except FileNotFoundError:
        raise RuntimeError("rpm binary not found")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"rpm -qa failed: {exc}")

    pkgs: Dict[str, Dict] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts   = line.split("\t")
        name    = parts[0] if len(parts) > 0 else ""
        version = parts[1] if len(parts) > 1 else ""
        lic     = parts[2].strip() if len(parts) > 2 else "unknown"
        raw_deps = parts[3] if len(parts) > 3 else ""
        if not name or not version:
            continue
        pkgs[name] = {
            "version": version,
            "license": lic or "unknown",
            "deps":    _clean_rpm_deps(raw_deps),
        }
    return pkgs


def _rpm_query_files(pkg_names: List[str]) -> Generator[Tuple[str, str], None, None]:
    if not pkg_names:
        return

    try:
        out = subprocess.check_output(
            ["rpm", "-ql", "--qf", _RPM_QL_QF] + pkg_names,
            timeout=SUBPROCESS_TIMEOUT,
            stdin=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        ).decode("utf-8", errors="replace")
    except FileNotFoundError:
        raise RuntimeError("rpm binary not found")
    except subprocess.CalledProcessError as exc:
        # non-zero exit is common when some packages have no files — still parse stdout
        out = exc.output.decode("utf-8", errors="replace") if exc.output else ""

    for line in out.splitlines():
        line = line.strip()
        if not line or line == "(contains no files)":
            continue
        tab = line.find("\t")
        if tab == -1:
            continue
        pkg_name = line[:tab]
        filepath = line[tab + 1:].strip()
        if filepath:
            yield pkg_name, filepath


def _scan_rpm(ecosystem: str) -> List[Dict]:
    pkgs  = _rpm_query_all()

    purls: Dict[str, str] = {name: _make_purl(ecosystem, name, info["version"])
                              for name, info in pkgs.items()}

    paths_by_pkg: Dict[str, List[str]] = {}
    for pkg_name, filepath in _rpm_query_files(list(pkgs.keys())):
        if not _is_executable_path(filepath):
            continue
        if not _has_execute_bit(filepath):
            continue
        paths_by_pkg.setdefault(pkg_name, []).append(filepath)

    result: List[Dict] = []
    for name, info in pkgs.items():
        result.append(_build_package(
            ecosystem, name, info["version"], info["license"],
            paths_by_pkg.get(name, []),
            info["deps"],
            purls,
        ))
    return result


# ---------------------------------------------------------------------------
# LinuxHostScanner
# ---------------------------------------------------------------------------

class LinuxHostScanner:
    """Scan the running Linux host for installed packages."""

    inventory_data: List[Dict] = []

    @classmethod
    def get_installed(cls) -> List[str]:
        """
        Async entry-point (mirrors JS API).
        Returns a list of PURL id strings.
        Full records available on LinuxHostScanner.inventory_data.
        """
        return cls.scan()

    @classmethod
    def scan(cls) -> List[str]:
        """Synchronous scan. Returns a list of PURL id strings."""
        cls.inventory_data = []

        ecosystem = _detect_host_ecosystem()

        if ecosystem in ("debian", "ubuntu"):
            packages = _scan_dpkg(ecosystem)
        elif ecosystem == "alpine":
            packages = _scan_apk(ecosystem)
        elif ecosystem in ("redhat", "almalinux", "rockylinux"):
            packages = _scan_rpm(ecosystem)
        else:
            raise RuntimeError(f"No scanner implemented for ecosystem: {ecosystem}")

        packages.sort(key=lambda p: p["name"])
        cls.inventory_data = packages
        return [p["id"] for p in packages]