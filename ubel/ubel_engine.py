"""
engine.py — UBEL Python engine.

Full Python equivalent of the Node.js UbelEngine / engine.js.

Zero external dependencies (uses only stdlib + the sibling modules that
were already ported: cvss_parser, pypi_manager, linux_manager).

Key behavioural parity with the JS engine
------------------------------------------
* Policy schema: severity_threshold + block_unknown_vulnerabilities
* tag_vulnerabilities_with_policy_decisions  — per-vuln policy_decision field
* Infections (MAL-*) are always blocked regardless of policy
* summarize_vulnerabilities  — per-package summary with stats/sorting
* sort_vulnerabilities        — global vuln list ordered by severity
* Dependency sequences + introduced_by  built from inventory
* dependencies_tree           — nested dict for the HTML graph
* HTML report generation      — identical client-side JS/HTML (embedded)
* latest.json + latest.html   — always overwritten with most recent scan
* PolicyViolationError         — raised on block so finally can revert
* check mode reverts lockfile via Pypi_Manager / Linux_Manager
* install mode only runs after policy pass
"""

from __future__ import annotations

import datetime
import json
import os
import platform
import subprocess
import sys
import threading
import urllib.request
import urllib.error
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from .cvss_parser import process_vulnerability
from .python_runner import Pypi_Manager, PythonVenvScanner
from .linux_runner import Linux_Manager

try:
    from .info import __version__, __tool_name__, __tool_license__
except ImportError:
    __version__   = "0.0.0"
    __tool_name__ = "ubel-python"
    __tool_license__ = "Apache 2.0"


# ---------------------------------------------------------------------------
# Sentinel
# ---------------------------------------------------------------------------

class PolicyViolationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"
OSV_VULN_BASE  = "https://api.osv.dev/v1/vulns"

SEV_ORDER: Dict[str, int] = {
    "infection": -1,
    "critical":   0,
    "high":       1,
    "medium":     2,
    "low":        3,
    "unknown":    4,
}

SEVERITY_ORDER_POLICY = ["low", "medium", "high", "critical"]

DEFAULT_POLICY: Dict[str, Any] = {
    "severity_threshold":            "high",
    "block_unknown_vulnerabilities": True,
}


# ---------------------------------------------------------------------------
# HTTP helper  (stdlib only, with retry + exponential back-off)
# ---------------------------------------------------------------------------

def _fetch_json(
    url: str,
    method: str = "GET",
    body: Optional[Any] = None,
    timeout: int = 20,
    max_retries: int = 5,
) -> Tuple[int, Any]:
    attempt = 0
    last_exc: Optional[Exception] = None
    delay = 0.2

    while attempt < max_retries:
        attempt += 1
        try:
            data = json.dumps(body).encode() if body is not None else None
            req  = urllib.request.Request(
                url,
                data=data,
                method=method,
                headers={
                    "Content-Type": "application/json",
                    "User-Agent":   "ubel_tool",
                },
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
                try:
                    return resp.status, json.loads(raw)
                except json.JSONDecodeError:
                    return resp.status, raw.decode(errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code in (429,) or exc.code >= 500:
                import time; time.sleep(delay); delay *= 2
                last_exc = exc
                continue
            # Non-retryable HTTP error
            try:
                return exc.code, json.loads(exc.read())
            except Exception:
                return exc.code, {}
        except Exception as exc:
            import time; time.sleep(delay); delay *= 2
            last_exc = exc

    raise RuntimeError(f"Request failed after {max_retries} attempts: {last_exc}")


# ---------------------------------------------------------------------------
# PURL helpers
# ---------------------------------------------------------------------------

def get_dependency_from_purl(purl: str) -> Tuple[str, str]:
    if not purl or not purl.startswith("pkg:"):
        return "unknown", "unknown"

    body = purl[4:].split("?")[0].split("#")[0]
    slash = body.find("/")
    if slash == -1:
        return "unknown", "unknown"

    ptype    = body[:slash]
    remainder = body[slash + 1:]

    try:
        from urllib.parse import unquote
        remainder = unquote(remainder)
    except Exception:
        pass

    last_at = remainder.rfind("@")
    if last_at > 0:
        name    = remainder[:last_at]
        version = remainder[last_at + 1:]
    else:
        name    = remainder
        version = "unknown"

    # Distro packages: distro/name
    if ptype in ("deb", "rpm", "apk"):
        parts = name.split("/")
        name  = parts[-1]

    return name, version


def get_ecosystem_from_purl(purl: str) -> str:
    if purl.startswith("pkg:pypi/"):          return "python"
    if purl.startswith("pkg:npm/"):           return "npm"
    if purl.startswith("pkg:maven/"):         return "java"
    if purl.startswith("pkg:golang/"):        return "golang"
    if purl.startswith("pkg:cargo/"):         return "rust"
    if purl.startswith("pkg:nuget/"):         return "dotnet"
    if purl.startswith("pkg:gem/"):           return "ruby"
    if purl.startswith("pkg:composer/"):      return "php"
    if purl.startswith("pkg:deb/ubuntu/"):    return "ubuntu"
    if purl.startswith("pkg:deb/debian/"):    return "debian"
    if purl.startswith("pkg:rpm/redhat/"):    return "redhat"
    if purl.startswith("pkg:rpm/almalinux/"): return "almalinux"
    if purl.startswith("pkg:rpm/rocky-linux/"): return "rocky-linux"
    if purl.startswith("pkg:apk/alpine/"):    return "alpine"
    if purl.startswith("pkg:apk/alpaquita/"): return "alpaquita"
    return "unknown"


# ---------------------------------------------------------------------------
# OS metadata  (stdlib only)
# ---------------------------------------------------------------------------

def _get_os_metadata() -> Dict[str, Any]:
    os_id = os_name = os_version = "unknown"
    for candidate in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            data: Dict[str, str] = {}
            with open(candidate, encoding="utf-8", errors="replace") as fh:
                for raw in fh:
                    line = raw.strip()
                    if not line or line.startswith("#") or "=" not in line:
                        continue
                    eq  = line.index("=")
                    k   = line[:eq].strip().lower()
                    v   = line[eq + 1:].strip().strip('"').strip("'")
                    data[k] = v
            os_id      = data.get("id",          "unknown")
            os_name    = data.get("pretty_name") or data.get("name", os_id)
            os_version = data.get("version_id")  or data.get("version", "unknown")
            break
        except OSError:
            continue

    # Fallback for non-Linux
    if os_id == "unknown":
        os_id      = sys.platform
        os_name    = platform.system()
        os_version = platform.release()

    return {
        "os_id":      os_id,
        "os_name":    os_name,
        "os_version": os_version,
        "local_ips":  _get_local_ips(),
        "external_ip": None,          # filled in by scan() after async fetch
    }


# ---------------------------------------------------------------------------
# Network metadata helpers
# ---------------------------------------------------------------------------

def _get_local_ips() -> Dict[str, str]:
    """
    Return all non-loopback IPv4 addresses keyed by interface name.
    e.g. {"eth0": "192.168.1.42", "wlan0": "10.0.0.5"}
    Uses only stdlib — no external deps.
    """
    import socket
    result: Dict[str, str] = {}
    try:
        import socket, struct, fcntl  # fcntl is POSIX-only
        import array

        SIOCGIFCONF = 0x8912
        STRUCT_SIZE = 40 if platform.architecture()[0] == "64bit" else 32
        nstructs    = 128
        buf_size    = nstructs * STRUCT_SIZE

        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            buf  = array.array("B", b"\0" * buf_size)
            addr = buf.buffer_info()[0]
            ifreq = struct.pack("iL", buf_size, addr)
            res   = fcntl.ioctl(s.fileno(), SIOCGIFCONF, ifreq)
            out_len = struct.unpack("iL", res)[0]
            raw = bytes(buf)[:out_len]
            offset = 0
            while offset + STRUCT_SIZE <= len(raw):
                iface_name = raw[offset:offset + 16].split(b"\x00")[0].decode(errors="replace")
                ip_bytes   = raw[offset + 20:offset + 24]
                ip_str     = socket.inet_ntoa(ip_bytes)
                if ip_str and not ip_str.startswith("127."):
                    result[iface_name] = ip_str
                offset += STRUCT_SIZE
    except Exception:
        # Fallback: hostname resolution (works on all platforms including Windows)
        try:
            hostname = socket.gethostname()
            ip       = socket.gethostbyname(hostname)
            if ip and not ip.startswith("127."):
                result["primary"] = ip
        except Exception:
            pass
    return result


def _get_external_ip() -> Optional[str]:
    """
    Fetch the host's public IP via api.ipify.org.
    Returns None on any error or if the request exceeds 4 seconds.
    """
    try:
        req = urllib.request.Request(
            "https://api.ipify.org/?format=text",
            headers={"User-Agent": "ubel_tool"},
        )
        with urllib.request.urlopen(req, timeout=4) as resp:
            return resp.read().decode("ascii", errors="replace").strip() or None
    except Exception:
        return None


# ---------------------------------------------------------------------------
# SystemPath helpers
# ---------------------------------------------------------------------------

def _make_system_path(path_str: Any, host_ip: str = "") -> Dict[str, Any]:
    """
    Wrap a plain filesystem path string into the canonical SystemPath object.

    Schema: { "type": "system_path", "text": str, "ip": str, "ports": [] }
    """
    return {
        "type":  "system_path",
        "text":  str(path_str) if path_str is not None else "",
        "ip":    host_ip,
        "ports": [],
    }


def _normalize_inventory_paths(inventory: List[Dict], host_ip: str) -> None:
    """
    Convert every string path in inventory[*].paths (and the legacy singular
    .path field) to a SystemPath object in-place.
    Already-converted objects are left unchanged (idempotent).
    """
    for item in inventory:
        if isinstance(item.get("paths"), list):
            item["paths"] = [
                p if (isinstance(p, dict) and p.get("type") == "system_path")
                else _make_system_path(p, host_ip)
                for p in item["paths"]
            ]
        if "path" in item and item["path"] is not None:
            p = item["path"]
            item["path"] = (
                p if (isinstance(p, dict) and p.get("type") == "system_path")
                else _make_system_path(p, host_ip)
            )


# ---------------------------------------------------------------------------
# Git metadata  (stdlib only)
# ---------------------------------------------------------------------------

def _get_git_metadata() -> Dict[str, Any]:
    def _git(*args: str) -> Optional[str]:
        try:
            result = subprocess.run(
                ["git"] + list(args),
                capture_output=True, text=True, timeout=5,
            )
            return result.stdout.strip() if result.returncode == 0 else None
        except Exception:
            return None

    available = _git("rev-parse", "--is-inside-work-tree") == "true"
    return {
        "latest_commit": _git("rev-parse", "--short", "HEAD") if available else None,
        "branch":        _git("rev-parse", "--abbrev-ref", "HEAD") if available else None,
        "url":           _git("remote", "get-url", "origin") if available else None,
    }


# ---------------------------------------------------------------------------
# Runtime metadata
# ---------------------------------------------------------------------------

def _get_runtime() -> Dict[str, str]:
    return {
        "environment": "python",
        "version":     platform.python_version(),
        "platform":    sys.platform,
        "arch":        platform.machine(),
        "cwd":         os.getcwd(),
    }


# ---------------------------------------------------------------------------
# OSV querying
# ---------------------------------------------------------------------------

def submit_to_osv(purls_list: List[str]) -> List[Dict]:
    if not purls_list:
        return []

    PAGE    = 800
    results: List[Dict] = []

    for offset in range(0, len(purls_list), PAGE):
        chunk   = purls_list[offset: offset + PAGE]
        queries = [{"package": {"purl": p}} for p in chunk]

        try:
            status, body = _fetch_json(OSV_QUERYBATCH, "POST", {"queries": queries}, timeout=60)
        except Exception as exc:
            print(f"[!] OSV batch query error: {exc}", file=sys.stderr)
            continue

        if status != 200:
            print(f"[!] OSV batch query returned {status}", file=sys.stderr)
            continue

        for i, item in enumerate(body.get("results", [])):
            purl = chunk[i]
            dep, ver = get_dependency_from_purl(purl)
            for v in item.get("vulns", []):
                results.append({
                    "purl":             purl,
                    "vulnerability_id": v["id"],
                    "dependency":       dep,
                    "affected_version": ver,
                })

    return results


# ---------------------------------------------------------------------------
# Vulnerability enrichment
# ---------------------------------------------------------------------------

def _generate_fix(ranges: List[Dict], versions: List[str], pkg_name: str, ecosystem: str) -> str:
    fixed: List[str]        = []
    last_affected: List[str] = []
    for r in ranges:
        for event in r.get("events", []):
            if "fixed"         in event: fixed.append(event["fixed"])
            if "last_affected" in event: last_affected.append(event["last_affected"])

    fallback = last_affected or versions
    if fixed:
        return f"Upgrade {pkg_name} ( {ecosystem} ) to: {' or '.join(fixed)}"
    if fallback:
        return f"Upgrade {pkg_name} ( {ecosystem} ) to a version higher than: {' or '.join(fallback)}"
    return f"No fix available for {pkg_name}"


def _get_fixed_versions(vuln: Dict) -> List[str]:
    fixed: List[str] = []
    dep = (vuln.get("affected_dependency") or "").lower()
    for item in vuln.get("affected", []):
        if (item.get("package", {}).get("name") or "").lower() != dep:
            continue
        for r in item.get("ranges", []):
            for event in r.get("events", []):
                if "fixed" in event:
                    fixed.append(event["fixed"])
    return fixed


def _get_fix(vuln: Dict) -> None:
    dep  = vuln.get("affected_dependency", "")
    remediations: List[str] = []

    for item in vuln.get("affected", []):
        pkg      = item.get("package", {})
        if (pkg.get("name") or "").lower() != dep.lower():
            continue
        remediations.append(
            _generate_fix(
                item.get("ranges",   []),
                item.get("versions", []),
                pkg.get("name", dep),
                pkg.get("ecosystem", ""),
            )
        )

    vuln["fixed_versions"] = _get_fixed_versions(vuln)
    vuln["fixes"]          = remediations
    vuln["has_fix"]        = len(vuln["fixed_versions"]) > 0
    vuln["description"]    = (
        vuln.get("description") or vuln.get("details") or vuln.get("summary") or ""
    ).strip()
    vuln.pop("details",  None)
    vuln.pop("summary",  None)


def get_vuln_by_id(vuln_ref: Dict) -> Optional[Dict]:
    vid     = vuln_ref["vulnerability_id"]
    purl    = vuln_ref["purl"]
    dep     = vuln_ref["dependency"]
    version = vuln_ref["affected_version"]

    try:
        status, data = _fetch_json(f"{OSV_VULN_BASE}/{vid}", timeout=30)
    except Exception as exc:
        print(f"[!] Failed to fetch {vid}: {exc}", file=sys.stderr)
        return None

    if status != 200 or not isinstance(data, dict):
        return None

    process_vulnerability(data)

    data["affected_purl"]               = purl
    data["affected_dependency"]         = dep
    data["affected_dependency_version"] = version
    data["ecosystem"]                   = get_ecosystem_from_purl(purl)
    data["url"]                         = f"https://osv.dev/vulnerability/{vid}"
    data["is_infection"]                = (data.get("id") or "").startswith("MAL-")

    _get_fix(data)

    for key in ("database_specific", "affected", "schema_version"):
        data.pop(key, None)

    return data


# ---------------------------------------------------------------------------
# Inventory helpers
# ---------------------------------------------------------------------------

def match_dependencies_with_inventory(inventory: List[Dict]) -> None:
    purls = {c["id"] for c in inventory}
    for item in inventory:
        resolved: List[str] = []
        for key in item.get("dependencies", []):
            # Exact match first, then prefix match (version-stripped stubs)
            if key in purls:
                resolved.append(key)
            else:
                match = next((p for p in purls if p.startswith(key)), None)
                if match:
                    resolved.append(match)
        item["dependencies"] = resolved


def set_inventory_state(
    infected_purls: Set[str],
    vulnerable_purls: Set[str],
    inventory: List[Dict],
) -> None:
    for item in inventory:
        if item.get("version", "") == "":
            continue
        if item["id"] in infected_purls:
            item["state"] = "infected"
        elif item["id"] in vulnerable_purls:
            item["state"] = "vulnerable"
        else:
            item["state"] = "safe"


def build_dependency_sequences(inventory: List[Dict]) -> List[Dict]:
    by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

    depended: Set[str] = set()
    for comp in inventory:
        for dep in comp.get("dependencies", []):
            depended.add(dep)

    roots = [c["id"] for c in inventory if c["id"] not in depended]
    sequences: Dict[str, List] = {}

    def dfs(node: str, path: List[str]) -> None:
        next_path = path + [node]
        sequences.setdefault(node, []).append(next_path)
        for dep in by_id.get(node, {}).get("dependencies", []):
            if dep not in path and dep in by_id:
                dfs(dep, next_path)

    for root in roots:
        dfs(root, [])

    for comp in inventory:
        comp["dependency_sequences"] = sequences.get(comp["id"], [])

    return inventory


def build_introduced_by(inventory: List[Dict]) -> List[Dict]:
    """
    Populate introduced_by on each node: the set of root packages (direct
    dependencies) that have a dependency path leading to this node.
    Mirrors NodeManager.buildIntroducedBy.
    """
    by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

    depended: Set[str] = set()
    for comp in inventory:
        for dep in comp.get("dependencies", []):
            depended.add(dep)

    roots = [c["id"] for c in inventory if c["id"] not in depended]

    # BFS from each root, tagging every reachable node
    introduced: Dict[str, Set[str]] = defaultdict(set)
    for root in roots:
        queue = [root]
        visited: Set[str] = set()
        while queue:
            node = queue.pop(0)
            if node in visited:
                continue
            visited.add(node)
            introduced[node].add(root)
            for dep in by_id.get(node, {}).get("dependencies", []):
                if dep in by_id:
                    queue.append(dep)

    for comp in inventory:
        comp["introduced_by"] = sorted(introduced.get(comp["id"], set()))

    return inventory


def build_dependency_tree(inventory: List[Dict]) -> Dict:
    """
    Build a nested dict tree used by the HTML graph renderer.
    Mirrors NodeManager.buildDependencyTree.
    """
    by_id: Dict[str, Dict] = {c["id"]: c for c in inventory}

    depended: Set[str] = set()
    for comp in inventory:
        for dep in comp.get("dependencies", []):
            depended.add(dep)

    roots = [c["id"] for c in inventory if c["id"] not in depended]

    def build_subtree(node: str, visited: Set[str]) -> Dict:
        if node in visited:
            return {}
        visited = visited | {node}
        subtree: Dict[str, Any] = {}
        for dep in by_id.get(node, {}).get("dependencies", []):
            if dep in by_id:
                subtree[dep] = build_subtree(dep, visited)
        return subtree

    tree: Dict[str, Any] = {}
    for root in roots:
        tree[root] = build_subtree(root, set())
    return tree


# ---------------------------------------------------------------------------
# Scope propagation  (second-pass, engine-agnostic)
# ---------------------------------------------------------------------------

def _propagate_scopes(inventory: List[Dict]) -> None:
    """
    Forward-propagate scopes through comp.dependencies using BFS.
    Mirrors the second-pass scope propagation in the JS engine.
    """
    by_id = {c["id"]: c for c in inventory}

    # Seed: every already-scoped package (direct deps)
    queue = [c for c in inventory
             if isinstance(c.get("scopes"), list)
             and any(s != "env" for s in c["scopes"])]
    visited: Set[str] = {c["id"] for c in queue}

    while queue:
        comp = queue.pop(0)
        for dep_purl in comp.get("dependencies", []):
            dep = by_id.get(dep_purl)
            if not dep:
                continue
            changed = False
            for s in comp.get("scopes", []):
                if s == "env":
                    continue
                if s not in dep.get("scopes", []):
                    dep.setdefault("scopes", []).append(s)
                    changed = True
            if dep_purl not in visited:
                visited.add(dep_purl)
                queue.append(dep)


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

def tag_vulnerabilities_with_policy_decisions(
    vulnerabilities: List[Dict],
    policy: Dict,
) -> None:
    threshold     = (policy.get("severity_threshold") or "").lower()
    threshold_idx = SEVERITY_ORDER_POLICY.index(threshold) if threshold in SEVERITY_ORDER_POLICY else -1
    block_unknown = policy.get("block_unknown_vulnerabilities") is True

    for v in vulnerabilities:
        if v.get("is_infection"):
            v["policy_decision"] = "block"
            continue

        sev     = (v.get("severity") or "unknown").lower()
        sev_idx = SEVERITY_ORDER_POLICY.index(sev) if sev in SEVERITY_ORDER_POLICY else -1

        if sev == "unknown":
            v["policy_decision"] = "block" if block_unknown else "allow"
        elif threshold == "none" or threshold_idx == -1:
            v["policy_decision"] = "allow"
        elif sev_idx >= threshold_idx:
            v["policy_decision"] = "block"
        else:
            v["policy_decision"] = "allow"


def get_policy_violations(vulnerabilities: List[Dict]) -> List[str]:
    return list({v["id"] for v in vulnerabilities if v.get("policy_decision") == "block"})


def evaluate_policy(final_json: Dict) -> Tuple[bool, str]:
    """
    Returns (allowed: bool, reason: str).
    Mirrors evaluatePolicy in policy.js.
    """
    policy       = final_json.get("policy", {})
    vulns        = final_json.get("vulnerabilities", [])
    violations   = [v for v in vulns if v.get("policy_decision") == "block"]

    if not violations:
        return True, "No policy violations detected."

    infections = [v for v in violations if v.get("is_infection")]
    if infections:
        names = ", ".join(sorted({v.get("affected_dependency","?") for v in infections}))
        return False, f"Blocked: {len(infections)} malicious package(s) detected: {names}"

    threshold = (policy.get("severity_threshold") or "none").lower()
    return False, (
        f"Blocked: {len(violations)} vulnerabilities at or above "
        f"severity threshold '{threshold}'."
    )


# ---------------------------------------------------------------------------
# Summarize / sort
# ---------------------------------------------------------------------------

def summarize_vulnerabilities(
    vulnerabilities: List[Dict],
    inventory: List[Dict],
) -> Dict[str, Dict]:
    inv_by_id = {c["id"]: c for c in inventory}
    packages: Dict[str, Dict] = {}

    for v in vulnerabilities:
        pkg      = v.get("affected_dependency", "?")
        version  = v.get("affected_dependency_version", "?")
        purl     = v.get("affected_purl", "")
        eco      = get_ecosystem_from_purl(purl)
        inv_item = inv_by_id.get(purl, {})

        if pkg not in packages:
            packages[pkg] = {
                "name":       pkg,
                "version":    version,
                "ecosystem":  eco,
                "introduced_by": inv_item.get("introduced_by", []),
                "paths":      inv_item.get("paths", []),
                "affected_dependency_sequences": inv_item.get("dependency_sequences", []),
                "vulnerabilities": [],
                "_counts": {k: 0 for k in ("infection","critical","high","medium","low","unknown")},
            }

        sev = (v.get("severity") or "unknown").lower()
        # Normalise from CVSS score when label is missing/unrecognised
        if sev not in SEV_ORDER and v.get("severity_score") is not None:
            try:
                score = float(v["severity_score"])
                if   score >= 9.0: sev = "critical"
                elif score >= 7.0: sev = "high"
                elif score >= 4.0: sev = "medium"
                elif score >= 0.1: sev = "low"
                else:              sev = "unknown"
            except (ValueError, TypeError):
                sev = "unknown"

        vuln_obj: Dict[str, Any] = {
            "id":               v.get("id"),
            "is_infection":     v.get("is_infection", False),
            "severity":         sev,
            "severity_score":   float(v["severity_score"]) if v.get("severity_score") is not None else None,
            "fixes":            v.get("fixes", []),
            "fixed_versions":   v.get("fixed_versions", []),
            "is_policy_violation": v.get("policy_decision") == "block",
        }

        packages[pkg]["vulnerabilities"].append(vuln_obj)
        count_key = "infection" if vuln_obj["is_infection"] else (sev if sev in packages[pkg]["_counts"] else "unknown")
        packages[pkg]["_counts"][count_key] += 1

    # Sort vulns within each package
    for pkg_data in packages.values():
        pkg_data["vulnerabilities"].sort(key=lambda x: (
            SEV_ORDER.get(x["severity"], 5),
            -x["severity_score"] if x["severity_score"] is not None else float("inf"),
        ))

    # Sort packages
    def pkg_sort_key(p: Dict):
        c = p["_counts"]
        return (
            -c["infection"], -c["critical"], -c["high"],
            -c["medium"],    -c["low"],      -c["unknown"],
            p["name"],
        )

    sorted_packages = sorted(packages.values(), key=pkg_sort_key)

    for p in sorted_packages:
        p["stats"] = p.pop("_counts")

    return {p["name"]: p for p in sorted_packages}


def sort_vulnerabilities(vulns: List[Dict]) -> List[Dict]:
    def _key(v: Dict):
        sev   = "infection" if v.get("is_infection") else (v.get("severity") or "unknown").lower()
        score = v.get("severity_score")
        try:
            score = float(score)
        except (TypeError, ValueError):
            score = None
        return (
            SEV_ORDER.get(sev, 5),
            float("inf") if score is None else -score,
        )
    return sorted(vulns, key=_key)


# ---------------------------------------------------------------------------
# dict_to_str  (console pretty-printer)
# ---------------------------------------------------------------------------

def dict_to_str(data: Any, indent: int = 0, step: int = 4) -> str:
    lines: List[str] = []
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
# HTML report  (client-side JS is identical to the Node engine)
# ---------------------------------------------------------------------------

_HTML_TEMPLATE_PATH = Path(__file__).parent / "report_template.html"


def _load_html_template() -> Optional[str]:
    if _HTML_TEMPLATE_PATH.exists():
        return _HTML_TEMPLATE_PATH.read_text(encoding="utf-8")
    return None


def generate_html_report(data: Dict) -> str:
    """
    Generate the standalone HTML report.
    Attempts to load report_template.html from the same directory;
    if absent, falls back to a minimal self-contained template that
    embeds the full JSON so the client-side renderer can hydrate it.
    """
    import html as _html

    report_copy = json.loads(json.dumps(data))

    # Escape vulnerability descriptions to prevent XSS in the HTML payload
    for v in report_copy.get("vulnerabilities", []):
        if isinstance(v.get("description"), str):
            v["description"] = _html.escape(v["description"])

    safe_json = json.dumps(report_copy).replace("<", r"\u003c").replace("`", r"\u0060")

    template = """

<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubel Security Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root { --bg: #0a0a0a; --card: #141414; --border: #262626; --accent: #ef4444; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #e5e5e5; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass { background: rgba(20,20,20,0.8); backdrop-filter: blur(12px); border: 1px solid var(--border); }
        .severity-high { color: #f87171; border-color: #f87171; }
        .severity-medium { color: #fb923c; border-color: #fb923c; }
        .severity-low { color: #60a5fa; border-color: #60a5fa; }
        .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
        .tab-active { border-bottom: 2px solid var(--accent); color: white; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 50; backdrop-filter: blur(4px); }
        .modal-content { max-height: 90vh; overflow-y: auto; }
        #graph-tooltip { position: fixed; background: rgba(20,20,20,0.95); border: 1px solid #404040; border-radius: 8px; padding: 8px 12px; font-size: 11px; font-family: 'JetBrains Mono', monospace; color: #e5e5e5; pointer-events: none; max-width: 280px; z-index: 100; line-height: 1.6; white-space: pre-wrap; word-break: break-all; display: none; }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3"><div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white">U</div><div><h1 class="text-lg font-semibold tracking-tight">Security Scan Report</h1><p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p></div></div>
            <div id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider">Status: Loading...</div>
        </div>
    </header>
    <nav class="border-b border-neutral-800 bg-neutral-900/30">
        <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
            <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
            <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities</button>
            <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Inventory</button>
            <button onclick="switchTab('graph')" id="tab-graph" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Dependency Graph</button>
            <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
            <button onclick="switchTab('system')" id="tab-system" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">System Info</button>
        </div>
    </nav>
    <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
        <!-- Dashboard Section -->
        <section id="section-dashboard" class="space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Total Items</p><p class="text-3xl font-bold" id="stat-total">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-red-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerable Items</p><p class="text-3xl font-bold text-red-500" id="stat-vulnerabilities">0</p></div>
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Infections</p><p class="text-3xl font-bold" id="stat-infections">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-green-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Safe Items</p><p class="text-3xl font-bold text-green-500" id="stat-safe">0</p></div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl lg:col-span-2"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Severity Distribution</h3><div class="h-64"><canvas id="severityChart"></canvas></div></div>
                <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Decision Summary</h3><div id="decision-box" class="p-4 rounded-lg bg-neutral-800/50 border border-neutral-700"><p class="text-sm leading-relaxed" id="decision-reason">...</p></div><div class="mt-6 space-y-4"><div class="flex justify-between items-center text-sm"><span class="text-neutral-500">Policy:</span></div><div class="flex justify-between items-center text-sm"><table class="w-auto text-sm mono"><tr><td class="pr-2">Infections</td><td id="policy-infection">...</td></tr><tr><td class="pr-2">Severity Threshold</td><td id="policy-threshold">...</td></tr><tr><td class="pr-2">Block Unknown</td><td id="policy-block-unknown">...</td></tr></table></div></div></div>
            </div>
        </section>
        <!-- Vulnerabilities Section -->
        <section id="section-vulnerabilities" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Vulnerability Findings</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="vuln-search" placeholder="Search ID or package..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64"><select id="vuln-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix Available</th><th>Policy Violation</th><th>Fixed Versions</th><th class="text-right">Action</th></tr></thead><tbody id="vuln-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Inventory Section -->
        <section id="section-inventory" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Package Inventory</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="inv-search" placeholder="Search packages..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64"><select id="inv-filter-state" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All States</option><option value="safe">Safe</option><option value="vulnerable">Vulnerable</option><option value="infected">Infected</option><option value="undetermined">Undetermined</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th>Name</th><th>Version</th><th>State</th><th>Policy Violation</th><th>Ecosystem</th><th>License</th><th>Scopes</th></tr></thead><tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Dependency Graph Section with filter dropdown -->
        <section id="section-graph" class="hidden space-y-4" style="height: calc(100vh - 220px); min-height: 500px;">
            <div class="flex flex-col md:flex-row gap-3 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Dependency Graph</h2>
                <div class="flex gap-2 w-full md:w-auto items-center flex-wrap">
                    <input type="text" id="graph-search" placeholder="Search by package ID..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-72">
                    <select id="graph-filter" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
                        <option value="all">All graphs</option>
                        <option value="vulnerable" selected>Vulnerable graphs</option>
                        <option value="infected">Infected graphs</option>
                    </select>
                    <button onclick="graphZoom(0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">＋</button>
                    <button onclick="graphZoom(-0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">－</button>
                    <button onclick="graphReset()" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">Reset</button>
                    <div class="flex items-center gap-3 text-[10px] mono text-neutral-500">
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-green-500"></span>safe</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-yellow-500"></span>vulnerable</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500"></span>infected</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-neutral-500"></span>unknown</span>
                    </div>
                </div>
            </div>
            <div class="glass rounded-xl overflow-hidden relative" style="height: calc(100% - 56px);">
                <canvas id="dep-graph-canvas" style="width:100%;height:100%;cursor:grab;display:block;"></canvas>
                <div id="graph-tooltip" style="display:none;position:absolute;background:rgba(20,20,20,0.95);border:1px solid #404040;border-radius:8px;padding:8px 12px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#e5e5e5;pointer-events:none;max-width:280px;z-index:10;line-height:1.6;white-space:pre-wrap;"></div>
            </div>
        </section>
        <!-- Detailed Stats Section -->
        <section id="section-stats" class="hidden space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Inventory Stats</h3><div class="h-48"><canvas id="statsInventoryChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-neutral-500">Total Size</span><span class="mono" id="stats-inv-size">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Safe</span><span class="mono text-green-400" id="stats-inv-safe">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Vulnerable</span><span class="mono text-yellow-400" id="stats-inv-vuln">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Infected</span><span class="mono text-red-400" id="stats-inv-inf">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Undetermined</span><span class="mono text-gray-400" id="stats-inv-und">0</span></div></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Vulnerability Stats</h3><div class="h-48"><canvas id="statsVulnChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-neutral-500">Total Found</span><span class="mono" id="stats-vuln-total">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Critical</span><span class="mono text-red-600" id="stats-vuln-crit">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">High</span><span class="mono text-red-400" id="stats-vuln-high">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Medium</span><span class="mono text-orange-400" id="stats-vuln-med">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Low</span><span class="mono text-blue-400" id="stats-vuln-low">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Unknown</span><span class="mono text-gray-400" id="stats-vuln-unk">0</span></div></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Ecosystem Distribution</h3><div class="h-48"><canvas id="statsEcoChart"></canvas></div><div id="eco-legend" class="grid grid-cols-2 gap-2 text-[10px] mono text-neutral-500"></div></div>
            </div>
        </section>
        <!-- System Section -->
        <section id="section-system" class="hidden space-y-8">
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

    <!-- Runtime -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
        </svg>
        Runtime
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Environment</span>
          <span class="mono text-xs" id="run-env">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Version</span>
          <span class="mono text-xs" id="run-node">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Platform</span>
          <span class="mono text-xs" id="run-platform">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Arch</span>
          <span class="mono text-xs" id="run-arch">...</span>
        </div>
        <div class="flex flex-col gap-1">
          <span class="text-neutral-500 text-xs">CWD</span>
          <span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="run-cwd">...</span>
        </div>
      </div>
    </div>

    <!-- Engine -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
        </svg>
        Engine & Tool
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Engine Name</span>
          <span class="mono text-xs" id="engine-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Engine Version</span>
          <span class="mono text-xs" id="engine-version">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Tool Name</span>
          <span class="mono text-xs" id="tool-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Tool Version</span>
          <span class="mono text-xs" id="tool-version">...</span>
        </div>
      </div>
    </div>

    <!-- Scan Info -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        Scan Info
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Scan Type</span>
          <span class="mono text-xs" id="scan-type">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Ecosystems</span>
          <span class="mono text-xs" id="scan-ecosystems">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Scan Engine</span>
          <span class="mono text-xs" id="scan-engine">...</span>
        </div>
      </div>
    </div>

    <!-- OS -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
          <line x1="8" y1="21" x2="16" y2="21"/>
          <line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
        OS Metadata
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS ID</span>
          <span class="mono text-xs" id="os-id">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS Name</span>
          <span class="mono text-xs" id="os-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS Version</span>
          <span class="mono text-xs" id="os-version">...</span>
        </div>
        <div class="flex flex-col gap-1 border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Local IPs</span>
          <div id="os-local-ips" class="mono text-[10px] text-neutral-300 space-y-0.5"></div>
        </div>
        <div class="flex justify-between">
          <span class="text-neutral-500 text-xs">External IP</span>
          <span class="mono text-xs text-neutral-300" id="os-external-ip">...</span>
        </div>
      </div>
    </div>

    <!-- Git (fixed) -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="18" cy="18" r="3"/>
          <circle cx="6" cy="6" r="3"/>
          <path d="M13 6h3a2 2 0 0 1 2 2v7"/>
          <line x1="6" y1="9" x2="6" y2="21"/>
        </svg>
        Git Metadata
      </h3>

      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Available</span>
          <span class="mono text-xs" id="git-available">...</span>
        </div>

        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Lastest commit</span>
          <span class="mono text-xs" id="git-rev">...</span>
        </div>

        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Branch</span>
          <span class="mono text-xs" id="git-branch">...</span>
        </div>

        <div class="flex flex-col gap-1">
          <span class="text-neutral-500 text-xs">Remote URL</span>
          <span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="git-url">...</span>
        </div>

      </div>
    </div>

  </div>
</section>
    </main>
    <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50"><div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4"><p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">UBEL Security Engine</span></p></div></footer>
    <div id="modal-overlay" class="modal-overlay items-center justify-center p-4" style="display: none;">
        <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
            <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            <div id="modal-body" class="p-8"></div>
        </div>
    </div>
    <script>
        // --- DATA ---
        const reportData = __REPORT_DATA_PLACEHOLDER__;
        // ── Dependency Graph (force-directed, shows only impact chains) ────────────────
        let graphState = null;

        function initGraph() {
            const canvas = document.getElementById('dep-graph-canvas');
            if (!canvas) return;

            const tree = reportData.dependencies_tree || {};
            if (!Object.keys(tree).length) {
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#737373';
                ctx.font = '14px Inter, sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No dependency tree data available.', canvas.width / 2, canvas.height / 2);
                return;
            }

            // ---------- Build full graph (all nodes & edges) ----------
            const fullNodeMap = {};
            const allEdges = [];

            const getOrCreate = (id) => {
                if (!fullNodeMap[id]) {
                    const inv = reportData.inventory.find(x => x.id === id);
                    fullNodeMap[id] = {
                        id,
                        label: inv ? inv.name + '@' + inv.version : id.split('/').pop(),
                        fullLabel: id,
                        state: inv ? (inv.state || 'unknown') : 'unknown',
                        x: 0, y: 0, vx: 0, vy: 0,
                        fx: null, fy: null,
                        radius: 0,
                    };
                }
                return fullNodeMap[id];
            };

            const walk = (nodeId, children) => {
                getOrCreate(nodeId);
                for (const [childId, grandChildren] of Object.entries(children || {})) {
                    getOrCreate(childId);
                    allEdges.push({ source: nodeId, target: childId });
                    walk(childId, grandChildren);
                }
            };

            for (const [rootId, children] of Object.entries(tree)) {
                walk(rootId, children);
            }

            const allNodes = Object.values(fullNodeMap);
            // Deduplicate edges
            const edgeSet = new Set();
            const allUniqueEdges = allEdges.filter(e => {
                const key = e.source + '||' + e.target;
                if (edgeSet.has(key)) return false;
                edgeSet.add(key);
                return true;
            });

            // Build reverse adjacency: for each node, which nodes depend on it (incoming edges)
            const reverseAdj = new Map(); // id -> Set of ids that depend on it
            for (const n of allNodes) reverseAdj.set(n.id, new Set());
            for (const e of allUniqueEdges) {
                // e.source depends on e.target
                reverseAdj.get(e.target).add(e.source);
            }

            // Node sizing (based on out‑degree in full graph)
            const childCount = {};
            for (const e of allUniqueEdges) {
                childCount[e.source] = (childCount[e.source] || 0) + 1;
            }
            for (const n of allNodes) {
                const c = childCount[n.id] || 0;
                n.radius = c > 10 ? 18 : c > 4 ? 14 : c > 1 ? 11 : 8;
            }

            // ----- FILTER LOGIC: ancestors (dependents) of vulnerable/infected nodes -----
            let currentFilter = 'all';   // 'all', 'vulnerable', 'infected'
            let visibleNodeIds = new Set();
            let visibleEdges = [];

            function computeVisibleNodesAndEdges() {
                if (currentFilter === 'all') {
                    visibleNodeIds.clear();
                    for (const n of allNodes) visibleNodeIds.add(n.id);
                    visibleEdges = [...allUniqueEdges];
                    return;
                }

                const targetStates = currentFilter === 'vulnerable' ? new Set(['vulnerable']) : new Set(['infected']);
                // Seeds: all nodes that match the target state
                const seeds = allNodes.filter(n => targetStates.has(n.state)).map(n => n.id);
                if (seeds.length === 0) {
                    visibleNodeIds.clear();
                    visibleEdges = [];
                    return;
                }

                // BFS on reverse graph to collect all ancestors (nodes that depend on the seeds)
                const keep = new Set(seeds);
                const queue = [...seeds];
                while (queue.length) {
                    const id = queue.shift();
                    for (const depender of reverseAdj.get(id) || []) {
                        if (!keep.has(depender)) {
                            keep.add(depender);
                            queue.push(depender);
                        }
                    }
                }

                visibleNodeIds = keep;
                // Keep only edges where both ends are in the set
                visibleEdges = allUniqueEdges.filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
            }

            // Create a working set of nodes (subset of allNodes) and edges from visibleNodeIds
            function getCurrentNodesAndEdges() {
                const nodes = allNodes.filter(n => visibleNodeIds.has(n.id));
                return { nodes, edges: visibleEdges };
            }

            // ---- Force simulation state for the current visible graph ----
            let simTick = 0;
            const MAX_SIM = 300;
            const SIM_COOLDOWN = 0.92;
            let simRunning = true;
            let animId = null;

            let visibleNodes = [];
            let visibleEdgesList = [];
            let nodeMap = new Map(); // id -> node object reference

            // Rebuild simulation after filter change
            function rebuildFromFilter() {
                computeVisibleNodesAndEdges();
                const { nodes, edges } = getCurrentNodesAndEdges();
                visibleNodes = nodes;
                visibleEdgesList = edges;
                nodeMap.clear();
                for (const n of visibleNodes) nodeMap.set(n.id, n);

                // Reset forces
                for (const n of visibleNodes) {
                    n.vx = 0; n.vy = 0;
                    if (n.fx !== null) { n.fx = n.x; n.fy = n.y; }
                }
                simRunning = true;
                simTick = 0;
            }

            // Initial build (all nodes)
            currentFilter = 'vulnerable';
            rebuildFromFilter();

            // ---- Helper: initial positions (circular layout) ----
            function setInitialPositions() {
                const cx = 0, cy = 0, R = Math.max(150, visibleNodes.length * 9);
                visibleNodes.forEach((n, i) => {
                    const angle = (2 * Math.PI * i) / visibleNodes.length;
                    n.x = cx + R * Math.cos(angle) + (Math.random() - 0.5) * 40;
                    n.y = cy + R * Math.sin(angle) + (Math.random() - 0.5) * 40;
                });
            }
            setInitialPositions();

            // ---- Force simulation (works on visibleNodes & visibleEdgesList) ----
            const simulate = () => {
                if (!simRunning) return;
                if (visibleNodes.length === 0) return;

                // Repulsion
                for (let i = 0; i < visibleNodes.length; i++) {
                    for (let j = i + 1; j < visibleNodes.length; j++) {
                        const a = visibleNodes[i], b = visibleNodes[j];
                        const dx = b.x - a.x, dy = b.y - a.y;
                        const dist = Math.sqrt(dx*dx + dy*dy) || 0.01;
                        const force = Math.min(8000 / (dist * dist), 60);
                        const fx = (dx / dist) * force, fy = (dy / dist) * force;
                        a.vx -= fx; a.vy -= fy;
                        b.vx += fx; b.vy += fy;
                    }
                }

                // Spring (edges)
                for (const e of visibleEdgesList) {
                    const a = nodeMap.get(e.source);
                    const b = nodeMap.get(e.target);
                    if (!a || !b) continue;
                    const dx = b.x - a.x, dy = b.y - a.y;
                    const dist = Math.sqrt(dx*dx + dy*dy) || 0.01;
                    const ideal = (a.radius + b.radius) * 5 + 30;
                    const force = (dist - ideal) * 0.04;
                    const fx = (dx / dist) * force, fy = (dy / dist) * force;
                    a.vx += fx; a.vy += fy;
                    b.vx -= fx; b.vy -= fy;
                }

                // Center gravity
                for (const n of visibleNodes) {
                    n.vx += -n.x * 0.004;
                    n.vy += -n.y * 0.004;
                }

                // Integrate + dampen
                for (const n of visibleNodes) {
                    if (n.fx !== null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
                    n.vx *= SIM_COOLDOWN; n.vy *= SIM_COOLDOWN;
                    n.x += n.vx; n.y += n.vy;
                }

                simTick++;
                if (simTick > MAX_SIM) simRunning = false;
            };

            // ---- Viewport & interaction variables ----
            let scale = 1, panX = 0, panY = 0;
            let dragging = null;
            let isPanning = false, panStartX = 0, panStartY = 0, panOriginX = 0, panOriginY = 0;
            let highlightId = null;
            let searchMatches = new Set();

            const stateColor = (state) => ({
                safe:       { fill: '#16a34a', stroke: '#4ade80', text: '#f0fdf4' },
                vulnerable: { fill: '#ca8a04', stroke: '#fbbf24', text: '#fefce8' },
                infected:   { fill: '#dc2626', stroke: '#f87171', text: '#fef2f2' },
                unknown:    { fill: '#525252', stroke: '#a3a3a3', text: '#f5f5f5' },
            }[state] || { fill: '#525252', stroke: '#a3a3a3', text: '#f5f5f5' });

            // ---- Render (only visible nodes & edges) ----
            const render = () => {
                const dpr = window.devicePixelRatio || 1;
                const rect = canvas.getBoundingClientRect();
                if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
                    canvas.width = rect.width * dpr;
                    canvas.height = rect.height * dpr;
                }
                const ctx = canvas.getContext('2d');
                ctx.setTransform(1, 0, 0, 1, 0, 0);
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                ctx.scale(dpr, dpr);

                const W = rect.width, H = rect.height;
                const tx = W / 2 + panX, ty = H / 2 + panY;

                ctx.save();
                ctx.translate(tx, ty);
                ctx.scale(scale, scale);

                // Edges
                ctx.lineWidth = 0.8;
                for (const e of visibleEdgesList) {
                    const a = nodeMap.get(e.source), b = nodeMap.get(e.target);
                    if (!a || !b) continue;
                    const isHighlighted = highlightId && (e.source === highlightId || e.target === highlightId);
                    const isSearchMatch = searchMatches.size > 0 && (searchMatches.has(e.source) || searchMatches.has(e.target));
                    const dimmed = (highlightId && !isHighlighted) || (searchMatches.size > 0 && !isSearchMatch);
                    ctx.globalAlpha = dimmed ? 0.08 : isHighlighted ? 0.9 : 0.25;
                    ctx.strokeStyle = isHighlighted ? '#ef4444' : '#525252';
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.stroke();

                    if (isHighlighted || !dimmed) {
                        const ang = Math.atan2(b.y - a.y, b.x - a.x);
                        const ex = b.x - Math.cos(ang) * (b.radius + 3);
                        const ey = b.y - Math.sin(ang) * (b.radius + 3);
                        ctx.globalAlpha = dimmed ? 0.08 : 0.5;
                        ctx.fillStyle = isHighlighted ? '#ef4444' : '#737373';
                        ctx.beginPath();
                        ctx.moveTo(ex, ey);
                        ctx.lineTo(ex - Math.cos(ang - 0.4) * 6, ey - Math.sin(ang - 0.4) * 6);
                        ctx.lineTo(ex - Math.cos(ang + 0.4) * 6, ey - Math.sin(ang + 0.4) * 6);
                        ctx.closePath();
                        ctx.fill();
                    }
                }

                // Nodes
                for (const n of visibleNodes) {
                    const c = stateColor(n.state);
                    const isHl = n.id === highlightId;
                    const isMatch = searchMatches.has(n.id);
                    const dimmed = (highlightId && !isHl) || (searchMatches.size > 0 && !isMatch && !isHl);

                    ctx.globalAlpha = dimmed ? 0.15 : 1;

                    if (isMatch || isHl) {
                        ctx.beginPath();
                        ctx.arc(n.x, n.y, n.radius + 5, 0, Math.PI * 2);
                        ctx.fillStyle = isHl ? '#ef4444' : c.stroke;
                        ctx.globalAlpha = 0.25;
                        ctx.fill();
                        ctx.globalAlpha = dimmed ? 0.15 : 1;
                    }

                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                    ctx.fillStyle = c.fill;
                    ctx.fill();
                    ctx.strokeStyle = isHl ? '#ffffff' : c.stroke;
                    ctx.lineWidth = isHl ? 2.5 : 1.5;
                    ctx.stroke();

                    const showLabel = scale > 0.7 || isHl || isMatch;
                    if (showLabel) {
                        ctx.globalAlpha = dimmed ? 0.15 : isHl ? 1 : 0.85;
                        ctx.fillStyle = '#e5e5e5';
                        ctx.font = `${isHl ? 'bold ' : ''}${Math.max(9, Math.min(11, n.radius * 0.9))}px JetBrains Mono, monospace`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        const labelY = n.y + n.radius + 9;
                        ctx.fillStyle = 'rgba(0,0,0,0.8)';
                        ctx.fillText(n.label, n.x + 0.5, labelY + 0.5);
                        ctx.fillStyle = isHl ? '#ffffff' : '#d4d4d4';
                        ctx.fillText(n.label, n.x, labelY);
                    }
                }

                ctx.globalAlpha = 1;
                ctx.restore();
            };

            const loop = () => {
                simulate();
                render();
                animId = requestAnimationFrame(loop);
            };
            loop();

            // ---- Interaction helpers (unchanged) ----
            const toWorld = (cx, cy) => {
                const rect = canvas.getBoundingClientRect();
                const W = rect.width, H = rect.height;
                return {
                    x: (cx - W / 2 - panX) / scale,
                    y: (cy - H / 2 - panY) / scale,
                };
            };

            const hitTest = (wx, wy) => {
                let best = null, bestDist = Infinity;
                for (const n of visibleNodes) {
                    const d = Math.sqrt((wx - n.x) ** 2 + (wy - n.y) ** 2);
                    if (d < n.radius + 4 && d < bestDist) { best = n; bestDist = d; }
                }
                return best;
            };

            const tooltip = document.getElementById('graph-tooltip');
            canvas.addEventListener('mousemove', (e) => {
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    canvas.style.cursor = dragging ? 'grabbing' : 'pointer';
                    const inv = reportData.inventory.find(x => x.id === hit.id);
                    const vulns = reportData.vulnerabilities.filter(v => v.affected_purl === hit.id);
                    tooltip.textContent = [
                        hit.id,
                        `State: ${hit.state}`,
                        inv ? `License: ${inv.license || 'unknown'}` : '',
                        inv ? `Scopes: ${(inv.scopes || []).join(', ') || '—'}` : '',
                        vulns.length ? `Vulns: ${vulns.length} (${vulns.map(v=>v.severity).join(', ')})` : 'No vulnerabilities',
                    ].filter(Boolean).join('\\n');
                    tooltip.style.display = 'block';
                    tooltip.style.left = (mx + 14) + 'px';
                    tooltip.style.top = (my - 10) + 'px';
                } else {
                    canvas.style.cursor = isPanning ? 'grabbing' : 'grab';
                    tooltip.style.display = 'none';
                }

                if (dragging) {
                    dragging.fx = (mx - canvas.getBoundingClientRect().left - canvas.getBoundingClientRect().width / 2 - panX) / scale;
                    dragging.fy = (my - canvas.getBoundingClientRect().top - canvas.getBoundingClientRect().height / 2 - panY) / scale;
                    dragging.x = dragging.fx;
                    dragging.y = dragging.fy;
                }

                if (isPanning) {
                    panX = panOriginX + (e.clientX - panStartX);
                    panY = panOriginY + (e.clientY - panStartY);
                }
            });

            canvas.addEventListener('mousedown', (e) => {
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    dragging = hit;
                    hit.fx = hit.x; hit.fy = hit.y;
                    simRunning = true; simTick = 0;
                } else {
                    isPanning = true;
                    panStartX = e.clientX; panStartY = e.clientY;
                    panOriginX = panX; panOriginY = panY;
                    canvas.style.cursor = 'grabbing';
                }
            });

            canvas.addEventListener('mouseup', () => {
                if (dragging) { dragging.fx = null; dragging = null; }
                isPanning = false;
                canvas.style.cursor = 'grab';
            });

            canvas.addEventListener('click', (e) => {
                if (isPanning) return;
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    highlightId = hit.id === highlightId ? null : hit.id;
                    if (hit.id) openInvModal(hit.id);
                } else {
                    highlightId = null;
                }
            });

            // Touch & zoom
            let lastTouchDist = null;
            canvas.addEventListener('touchstart', (e) => {
                if (e.touches.length === 2) {
                    lastTouchDist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
                }
            }, { passive: true });
            canvas.addEventListener('touchmove', (e) => {
                if (e.touches.length === 2) {
                    const d = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
                    if (lastTouchDist) scale = Math.max(0.1, Math.min(5, scale * (d / lastTouchDist)));
                    lastTouchDist = d;
                    e.preventDefault();
                }
            }, { passive: false });
            canvas.addEventListener('wheel', (e) => {
                e.preventDefault();
                const delta = e.deltaY > 0 ? -0.1 : 0.1;
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const W = r.width, H = r.height;
                const wxBefore = (mx - W/2 - panX) / scale;
                const wyBefore = (my - H/2 - panY) / scale;
                scale = Math.max(0.08, Math.min(5, scale + delta * scale));
                panX = mx - W/2 - wxBefore * scale;
                panY = my - H/2 - wyBefore * scale;
            }, { passive: false });

            // Search
            document.getElementById('graph-search').addEventListener('input', (e) => {
                const q = e.target.value.trim().toLowerCase();
                searchMatches.clear();
                if (q.length >= 2) {
                    for (const n of visibleNodes) {
                        if (n.id.toLowerCase().includes(q) || n.label.toLowerCase().includes(q)) {
                            searchMatches.add(n.id);
                        }
                    }
                }
                simRunning = true; simTick = Math.max(0, MAX_SIM - 60);
            });

            // ---- FILTER DROPDOWN handler ----
            const filterSelect = document.getElementById('graph-filter');
            if (filterSelect) {
                filterSelect.addEventListener('change', (e) => {
                    currentFilter = e.target.value;
                    rebuildFromFilter();
                    setInitialPositions();
                    simRunning = true;
                    simTick = 0;
                    highlightId = null;
                    searchMatches.clear();
                    if (document.getElementById('graph-search')) document.getElementById('graph-search').value = '';
                });
            }

            graphState = {
                reset: () => {
                    scale = 1; panX = 0; panY = 0;
                    for (const n of visibleNodes) { n.fx = null; n.fy = null; }
                    simRunning = true; simTick = 0;
                },
                stop: () => { if (animId) cancelAnimationFrame(animId); },
            };
        }

        function graphZoom(delta) {
            if (!graphState) return;
            const canvas = document.getElementById('dep-graph-canvas');
            if (!canvas) return;
            // We'll handle zoom via the existing wheel event – the buttons are just for convenience.
            // Simulate a small wheel delta
            const event = new WheelEvent('wheel', { deltaY: delta > 0 ? -30 : 30 });
            canvas.dispatchEvent(event);
        }

        function graphReset() {
            if (graphState) graphState.reset();
        }

        // --- CORE LOGIC (existing - unchanged except for graph init) ---
        function init() {
            if (reportData.inventory.length < reportData.stats.inventory_size) {
                const currentCount = reportData.inventory.length;
                const needed = reportData.stats.inventory_size - currentCount;
            }

            closeModal();
            renderDashboard();
            renderVulnerabilities();
            renderInventory();
            renderStats();
            renderSystem();
            setupFilters();
        }

        function switchTab(tabId) {
            document.querySelectorAll('nav button').forEach(btn => btn.classList.remove('tab-active'));
            document.getElementById(`tab-${tabId}`).classList.add('tab-active');
            document.querySelectorAll('main section').forEach(sec => sec.classList.add('hidden'));
            document.getElementById(`section-${tabId}`).classList.remove('hidden');
            if (tabId === 'graph' && !graphState) {
                setTimeout(initGraph, 50);
            }
        }

        function renderDashboard() {
            const stats = reportData.stats;
            document.getElementById('report-id').textContent = `GENERATED_AT: ${reportData.generated_at}`;
            document.getElementById('stat-total').textContent = stats.inventory_size;
            document.getElementById('stat-vulnerabilities').textContent = stats.inventory_stats.vulnerable;
            document.getElementById('stat-infections').textContent = stats.inventory_stats.infected;
            document.getElementById('stat-safe').textContent = stats.inventory_stats.safe;

            const statusEl = document.getElementById('overall-status');
            if (reportData.decision.allowed) {
                statusEl.textContent = 'Status: Allowed';
                statusEl.className = 'px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-green-500/20 text-green-400 border border-green-500/50';
            } else {
                statusEl.textContent = 'Status: Blocked';
                statusEl.className = 'px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50';
            }

            document.getElementById('decision-reason').textContent = reportData.decision.reason;
            const pol = reportData.policy || {};
            const thresh = pol.severity_threshold || 'none';
            const blockUnk = pol.block_unknown_vulnerabilities === true ? 'block' : 'allow';
            document.getElementById('policy-threshold').textContent = thresh;
            document.getElementById('policy-block-unknown').textContent = blockUnk;
            document.getElementById('policy-infection').textContent = 'block (always)';

            const ctxSev = document.getElementById('severityChart').getContext('2d');
            const sevStats = stats.vulnerabilities_stats.severity;
            new Chart(ctxSev, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [sevStats.critical, sevStats.high, sevStats.medium, sevStats.low, sevStats.unknown],
                        backgroundColor: ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#a3a3a3'],
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373' } },
                        x: { grid: { display: false }, ticks: { color: '#737373' } }
                    }
                }
            });
        }

        function renderVulnerabilities(filter = '', severity = 'all') {
            const tbody = document.getElementById('vuln-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.vulnerabilities.filter(v => {
                const matchesSearch = v.id.toLowerCase().includes(filter.toLowerCase()) || 
                                     v.affected_dependency.toLowerCase().includes(filter.toLowerCase());
                const matchesSeverity = severity === 'all' || v.severity === severity;
                return matchesSearch && matchesSeverity;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = `<tr><td colspan="8" class="px-6 py-12 text-center text-neutral-500 italic">No vulnerabilities found matching criteria.</td></tr>`;
                return;
            }

            filtered.forEach(v => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
                row.onclick = () => openVulnModal(v.id);
                row.innerHTML = `
                    <td class="px-6 py-4 mono text-xs font-medium">${v.id}</td>
                    <td class="px-6 py-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${v.severity}">${v.severity}</span></td>
                    <td class="px-6 py-4 font-medium">${v.affected_dependency} ( ${v.ecosystem} )</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">${v.affected_dependency_version}</td>
                    <td class="px-6 py-4">${v.has_fix ? '<span class="text-green-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4">${v.is_policy_violation ? '<span class="text-red-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4 text-neutral-400 text-xs">${v.fixed_versions.join('<br>')}</td>
                    <td class="px-6 py-4 text-right"><button class="text-red-400 hover:text-red-300 text-xs font-semibold">View Details</button></td>
                `;
                tbody.appendChild(row);
            });
        }

        function renderInventory(filter = '', state = 'all') {
            const tbody = document.getElementById('inv-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.inventory.filter(item => {
                const matchesSearch = item.name.toLowerCase().includes(filter.toLowerCase());
                const matchesState = state === 'all' || item.state === state;
                return matchesSearch && matchesState;
            });

            filtered.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors';
                row.onclick = () => openInvModal(item.id);
                row.innerHTML = `
                    <td class="px-6 py-4 font-medium">${item.name}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">${item.version}</td>
                    <td class="px-6 py-4"><span class="text-xs ${
  item.state === 'safe'
    ? 'text-green-400'
    : item.state === 'undetermined'
    ? 'text-blue-400'
    : item.state === 'vulnerable'
    ? 'text-orange-400'
    : item.state === 'infected'
    ? 'text-red-400'
    : 'text-neutral-400'
}">${item.state}</span></td>
                    <td class="px-6 py-4"><span class="text-xs ${item.is_policy_violation ? 'text-red-400' : 'text-green-400'}">${item.is_policy_violation ? 'Yes' : 'No'}</span></td>
                    <td class="px-6 py-4 text-neutral-400">${item.ecosystem}</td>
                    <td class="px-6 py-4 text-neutral-400">${item.license}</td>
                    <td class="px-6 py-4 text-neutral-500 text-xs">${item.scopes.join(', ')}</td>
                `;
                tbody.appendChild(row);
            });
        }

        function renderStats() {
            const s = reportData.stats;
            
            document.getElementById('stats-inv-size').textContent = s.inventory_size;
            document.getElementById('stats-inv-safe').textContent = s.inventory_stats.safe;
            document.getElementById('stats-inv-vuln').textContent = s.inventory_stats.vulnerable;
            document.getElementById('stats-inv-inf').textContent = s.inventory_stats.infected;
            document.getElementById('stats-inv-und').textContent = s.inventory_stats.undetermined;
            
            document.getElementById('stats-vuln-total').textContent = s.total_vulnerabilities;
            document.getElementById('stats-vuln-crit').textContent = s.vulnerabilities_stats.severity.critical;
            document.getElementById('stats-vuln-high').textContent = s.vulnerabilities_stats.severity.high;
            document.getElementById('stats-vuln-med').textContent = s.vulnerabilities_stats.severity.medium;
            document.getElementById('stats-vuln-low').textContent = s.vulnerabilities_stats.severity.low;
            document.getElementById('stats-vuln-unk').textContent = s.vulnerabilities_stats.severity.unknown;

            new Chart(document.getElementById('statsInventoryChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Vulnerable', 'Infected', 'Undetermined'],
                    datasets: [{
                        data: [s.inventory_stats.safe, s.inventory_stats.vulnerable, s.inventory_stats.infected, s.inventory_stats.undetermined],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#6b7280'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            new Chart(document.getElementById('statsVulnChart'), {
                type: 'pie',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
                    datasets: [{
                        data: [
                            s.vulnerabilities_stats.severity.critical,
                            s.vulnerabilities_stats.severity.high,
                            s.vulnerabilities_stats.severity.medium,
                            s.vulnerabilities_stats.severity.low,
                            s.vulnerabilities_stats.severity.unknown
                        ],
                        backgroundColor: ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#cbd5e0'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            const ecoData = {};
            reportData.inventory.forEach(item => { ecoData[item.ecosystem] = (ecoData[item.ecosystem] || 0) + 1; });
            const ecoLabels = Object.keys(ecoData);
            const ecoValues = Object.values(ecoData);
            
            new Chart(document.getElementById('statsEcoChart'), {
                type: 'pie',
                data: {
                    labels: ecoLabels,
                    datasets: [{
                        data: ecoValues,
                        backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'],
                        borderWidth: 1,
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            const legend = document.getElementById('eco-legend');
            legend.innerHTML = ecoLabels.map((l, i) => `
                <div class="flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full" style="background: ${['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'][i % 5]}"></div>
                    <span>${l}: ${ecoValues[i]}</span>
                </div>
            `).join('');
        }

        function renderSystem() {
            const r = reportData.runtime;
            const eng = reportData.engine;
            const os = reportData.os_metadata;
            const git = reportData.git_metadata;
            const tool = reportData.tool_info;
            const scan = reportData.scan_info;

            document.getElementById('run-env').textContent = r.environment;
            document.getElementById('run-node').textContent = r.version;
            document.getElementById('run-platform').textContent = r.platform;
            document.getElementById('run-arch').textContent = r.arch;
            document.getElementById('run-cwd').textContent = r.cwd;

            document.getElementById('engine-name').textContent = eng.name;
            document.getElementById('engine-version').textContent = eng.version;
            document.getElementById('tool-name').textContent = tool.name;
            document.getElementById('tool-version').textContent = tool.version;

            document.getElementById('scan-type').textContent = scan.type;
            document.getElementById('scan-ecosystems').textContent = scan.ecosystems.join(', ');
            document.getElementById('scan-engine').textContent = scan.engine;

            document.getElementById('os-id').textContent = os.os_id;
            document.getElementById('os-name').textContent = os.os_name;
            document.getElementById('os-version').textContent = os.os_version;

            const localIpsEl = document.getElementById('os-local-ips');
            const localIPs = os.local_ips || {};
            const ifaceEntries = Object.entries(localIPs);
            localIpsEl.innerHTML = ifaceEntries.length
                ? ifaceEntries.map(([iface, ip]) =>
                    `<div class="flex justify-between gap-4"><span class="text-neutral-500">${iface}</span><span>${ip}</span></div>`
                  ).join('')
                : '<span class="text-neutral-600 italic">none detected</span>';
            document.getElementById('os-external-ip').textContent = os.external_ip || 'unavailable';

            document.getElementById('git-available').textContent = git.available ? 'Yes' : 'No';
            document.getElementById('git-rev').textContent = git.latest_commit || 'N/A';
            document.getElementById('git-branch').textContent = git.branch || 'N/A';
            document.getElementById('git-url').textContent = git.url || 'N/A';
        }

        function setupFilters() {
            document.getElementById('vuln-search').addEventListener('input', (e) => {
                renderVulnerabilities(e.target.value, document.getElementById('vuln-filter-severity').value);
            });
            document.getElementById('vuln-filter-severity').addEventListener('change', (e) => {
                renderVulnerabilities(document.getElementById('vuln-search').value, e.target.value);
            });
            document.getElementById('inv-search').addEventListener('input', (e) => {
                renderInventory(e.target.value, document.getElementById('inv-filter-state').value);
            });
            document.getElementById('inv-filter-state').addEventListener('change', (e) => {
                renderInventory(document.getElementById('inv-search').value, e.target.value);
            });
        }

        function openInvModal(id) {
            const item = reportData.inventory.find(x => x.id === id);
            if (!item) return;

            const itemVulns = reportData.vulnerabilities.filter(v => v.affected_purl === item.id);
            const stateColor = item.state === 'safe' ? 'text-green-400'
                             : item.state === 'infected' ? 'text-red-400'
                             : 'text-yellow-400';

            const vulnRows = itemVulns.length ? itemVulns.map(v => `
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openVulnModal('${v.id}'), 50)">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${v.severity}">${v.severity}</span>
                        <span class="mono text-xs text-white">${v.id}</span>
                    </div>
                    <div class="flex items-center gap-3">
                        ${v.severity_score != null ? `<span class="mono text-xs text-neutral-400">${parseFloat(v.severity_score).toFixed(1)}</span>` : ''}
                        ${v.is_policy_violation ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Policy Block</span>' : '<span class="text-[10px] text-neutral-500">Allowed</span>'}
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>
            `).join('') : '<p class="text-sm text-neutral-500 italic py-2">No vulnerabilities found.</p>';

            const introRows = (item.introduced_by || []).length
                ? (item.introduced_by).map(ib => `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${ib}'), 50)">${ib}</span>`).join('')
                : '<span class="text-neutral-500 text-xs italic">Direct dependency</span>';

            const pathRows = (item.paths || []).length
                ? item.paths.map(p => {
                    const isObj = p && typeof p === 'object' && p.type === 'system_path';
                    const text  = isObj ? p.text  : String(p ?? '');
                    const ip    = isObj ? p.ip    : '';
                    const ports = isObj && Array.isArray(p.ports) && p.ports.length ? p.ports : null;
                    return `
                      <div class="mono text-[10px] text-neutral-400 bg-neutral-900 px-2 py-1.5 rounded border border-neutral-800 break-all space-y-0.5">
                        <div class="text-neutral-300">${text}</div>
                        ${ip    ? `<div class="text-neutral-600 text-[9px]">host: ${ip}</div>`            : ''}
                        ${ports ? `<div class="text-neutral-600 text-[9px]">ports: ${ports.join(', ')}</div>` : ''}
                      </div>`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No path info</span>';

            const depsRows = (item.dependencies || []).length
                ? item.dependencies.map(d => {
                    const dep = reportData.inventory.find(x => x.id === d);
                    return `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 cursor-pointer hover:border-neutral-500 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${d}'), 50)">${dep ? dep.name + '@' + dep.version : d}</span>`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No dependencies</span>';

            document.getElementById('modal-body').innerHTML = `
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4 flex-wrap">
                        <div>
                            <div class="flex items-center gap-3 mb-1 flex-wrap">
                                <span class="text-[10px] uppercase font-bold ${stateColor} border border-current px-2 py-0.5 rounded">${item.state}</span>
                                <h2 class="text-xl font-bold">${item.name}</h2>
                                <span class="mono text-neutral-400 text-sm">v${item.version}</span>
                            </div>
                            <p class="mono text-[11px] text-neutral-500 break-all">${item.id}</p>
                        </div>
                        <div class="text-right shrink-0">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Ecosystem</p>
                            <p class="mono text-sm">${item.ecosystem}</p>
                        </div>
                    </div>

                    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">${item.type || 'library'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">License</p><p class="mono text-xs">${item.license || 'unknown'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Scopes</p><p class="mono text-xs">${(item.scopes || []).join(', ') || '—'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Policy Violation</p><p class="text-lg font-bold ${item.is_policy_violation ? 'text-red-400' : 'text-green-400'}">${item.is_policy_violation ? 'Yes' : 'No'}</p></div>
                    </div>

                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By</h4><div class="flex flex-wrap gap-2">${introRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (${(item.dependencies || []).length})</h4><div class="flex flex-wrap gap-2">${depsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4><div class="space-y-1">${pathRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerabilities (${itemVulns.length})</h4><div class="space-y-0">${vulnRows}</div></div>
                </div>
            `;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function openVulnModal(id) {
            const v = reportData.vulnerabilities.find(x => x.id === id);
            if (!v) return;

            const modalBody = document.getElementById('modal-body');
            modalBody.innerHTML = `
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-3 mb-2">
                                <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${v.severity}">${v.severity}</span>
                                <h2 class="text-2xl font-bold mono"><a href="${v.url}" target="_blank" class="text-white hover:text-blue-400">${v.id}</a></h2>
                            </div>
                            <p class="text-neutral-400 text-sm">Package: <span class="text-white font-medium">${v.affected_dependency}</span> (${v.affected_dependency_version})</p>
                        </div>
                        <div class="text-right"><p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest">Severity Score</p><p class="text-3xl font-bold text-red-500">${v.severity_score}</p></div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Published</p><p class="text-xs mono">${new Date(v.published).toLocaleDateString()}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Modified</p><p class="text-xs mono">${new Date(v.modified).toLocaleDateString()}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Vector</p><p class="text-[10px] mono text-neutral-400 truncate" title="${v.severity_vector}">${v.severity_vector}</p></div>
                    </div>
                    ${v.fixes.length > 0 ? `<div><h4 class="text-sm font-semibold mb-2 text-green-400">Recommended Fixes</h4><ul class="space-y-2">${v.fixes.map(f => `<li class="text-xs bg-green-500/10 border border-green-500/20 p-3 rounded-lg text-green-300 mono">${f}</li>`).join('')}</ul></div>` : ''}
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4><div class="flex flex-wrap gap-2">${v.references.map(r => `<a href="${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">${r.type}</a>`).join('')}</div></div>
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">${v.description}</div></div>
                </div>
            `;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
        document.getElementById('modal-overlay').addEventListener('click', (e) => { if (e.target.id === 'modal-overlay') closeModal(); });

        init();
    </script>
</body>
</html>

"""
    return template.replace("__REPORT_DATA_PLACEHOLDER__", safe_json)

# ---------------------------------------------------------------------------
# Policy file helpers
# ---------------------------------------------------------------------------

def _initiate_local_policy(policy_dir: str, policy_filename: str) -> None:
    os.makedirs(policy_dir, exist_ok=True)
    policy_file = os.path.join(policy_dir, policy_filename)
    needs = False
    if not os.path.exists(policy_file):
        needs = True
    elif os.path.getsize(policy_file) == 0:
        os.remove(policy_file)
        needs = True
    if needs:
        with open(policy_file, "w", encoding="utf-8") as fh:
            json.dump(DEFAULT_POLICY, fh, indent=4)


def _load_policy(policy_dir: str, policy_filename: str) -> Dict:
    _initiate_local_policy(policy_dir, policy_filename)
    with open(os.path.join(policy_dir, policy_filename), "r", encoding="utf-8") as fh:
        return json.load(fh)


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

class UbelEngine:

    reports_location  = "./.ubel/local/reports"
    policy_dir        = "./.ubel/local/policy"
    policy_filename   = "config.json"
    check_mode        = "health"       # health | check | install
    system_type       = "pypi"         # pypi | linux
    engine            = "pip"

    # Venv directory used when system_type == "pypi"
    venv_dir: Optional[str] = None

    # Populated during scan for cross-module inventory merging
    _vuln_ids_found: Set[str] = set()

    # ------------------------------------------------------------------
    # Policy helpers (public, mirrors JS setPolicyField)
    # ------------------------------------------------------------------

    @staticmethod
    def set_policy_field(key: str, value: Any) -> None:
        data = _load_policy(UbelEngine.policy_dir, UbelEngine.policy_filename)
        data[key] = value
        with open(
            os.path.join(UbelEngine.policy_dir, UbelEngine.policy_filename),
            "w", encoding="utf-8",
        ) as fh:
            json.dump(data, fh, indent=4)

    # ------------------------------------------------------------------
    # Requirements file helper  (pypi install mode)
    # ------------------------------------------------------------------

    @staticmethod
    def _generate_requirements_file(purls: List[str]) -> str:
        deps_dir = "./.ubel/dependencies"
        os.makedirs(deps_dir, exist_ok=True)
        req_file = os.path.join(deps_dir, "requirements.txt")
        lines: List[str] = []
        for purl in purls:
            name, version = get_dependency_from_purl(purl)
            if name != "unknown" and version not in ("", "unknown"):
                lines.append(f"{name}=={version}")
        with open(req_file, "w", encoding="utf-8") as fh:
            fh.write("\n".join(lines))
        return req_file

    # ------------------------------------------------------------------
    # Main scan
    # ------------------------------------------------------------------

    @staticmethod
    def scan(args: List[str]) -> None:
        UbelEngine._vuln_ids_found = set()

        # ── Timestamp & paths ──────────────────────────────────────────
        now       = datetime.datetime.now(datetime.timezone.utc)
        timestamp = now.strftime("%Y_%m_%d__%H_%M_%S")
        date_path = now.strftime("%Y/%m/%d")

        output_dir = Path(
            f"{UbelEngine.reports_location}/"
            f"{UbelEngine.system_type}/{UbelEngine.check_mode}/{date_path}"
        )
        output_dir.mkdir(parents=True, exist_ok=True)

        base_name  = f"{UbelEngine.system_type}_{UbelEngine.check_mode}_{UbelEngine.engine}__{timestamp}"
        json_path  = output_dir / f"{base_name}.json"
        html_path  = output_dir / f"{base_name}.html"

        policy = _load_policy(UbelEngine.policy_dir, UbelEngine.policy_filename)

        purls:          List[str]  = []
        report_content: Any        = None
        ecosystems:     Set[str]   = set()

        needs_revert = UbelEngine.check_mode in ("check", "install")

        try:
            # ── Collect packages ──────────────────────────────────────────
            if UbelEngine.system_type == "pypi":
                if needs_revert:
                    # Ensure a local venv exists
                    venv_dir = UbelEngine.venv_dir or "./venv"
                    Pypi_Manager.init_venv(venv_dir)
                    purls          = Pypi_Manager.run_dry_run(args, venv_dir)
                    report_content = Pypi_Manager.inventory_data
                else:
                    # health — scan the host Python environment via PythonVenvScanner
                    from .venv_scanner import PythonVenvScanner
                    purls          = PythonVenvScanner.scan(os.getcwd())
                    report_content = PythonVenvScanner.inventory_data

            else:  # linux
                if needs_revert:
                    packages       = Linux_Manager.resolve_packages(args)
                    system_info    = Linux_Manager.get_os_info()
                    report_content = {"packages": packages, "system_info": system_info}
                    purls          = [
                        Linux_Manager.package_to_purl(system_info, p["name"], p["version"])
                        for p in packages
                    ]
                else:
                    purls          = Linux_Manager.get_linux_packages()
                    system_info    = Linux_Manager.get_os_info()
                    report_content = {"system_info": system_info}

            # Strip version-less PURLs
            purls = [p for p in purls if not p.endswith("@")]

            # ── Build inventory ───────────────────────────────────────────
            inventory: List[Dict] = []
            if UbelEngine.system_type == "pypi":
                if needs_revert:
                    inventory = list(Pypi_Manager.inventory_data)
                else:
                    from .venv_scanner import PythonVenvScanner
                    inventory = list(PythonVenvScanner.inventory_data)
            else:
                inventory = list(Linux_Manager.inventory_data)
                for item in inventory:
                    item["scopes"] = ["prod"]
            
            for item in inventory:
                if item.get("id","").startswith("pkg:pypi/pip@"):
                    if "env" not in item.get("scopes", []):
                        item["scopes"].append("env")
            
            inventory.append(
                        {
                            "id": f"pkg:pypi/{__name__}@{__version__}",
                            "name": __name__,
                            "version": __version__,
                            "type": "library",
                            "ecosystem": "python",
                            "license": __tool_license__,
                            "paths": [],
                            "scopes": ["dev","prod","env"],
                            "dependencies": [],
                            "state": "undetermined",
                        }
                    )
            
            purls.append(f"pkg:pypi/python-ubel@{__version__}")

            match_dependencies_with_inventory(inventory)

            # ── OSV query ─────────────────────────────────────────────────
            vuln_ids = submit_to_osv(list(set(purls)))

            # ── Enrich vulnerabilities concurrently ───────────────────────
            vulnerabilities: List[Dict] = []
            CONCURRENCY = 40

            with ThreadPoolExecutor(max_workers=min(CONCURRENCY, max(1, len(vuln_ids)))) as pool:
                futures = {pool.submit(get_vuln_by_id, vid): vid for vid in vuln_ids}
                for future in as_completed(futures):
                    try:
                        result = future.result()
                        if result:
                            vulnerabilities.append(result)
                    except Exception as exc:
                        print(f"[!] Failed to fetch vulnerability: {exc}", file=sys.stderr)

            # ── Policy tagging ────────────────────────────────────────────
            tag_vulnerabilities_with_policy_decisions(vulnerabilities, policy)
            policy_violations = get_policy_violations(vulnerabilities)

            for v in vulnerabilities:
                v["is_policy_violation"] = v.get("policy_decision") == "block"

            # ── Inventory state + sequences ───────────────────────────────
            infected_purls:   Set[str] = set()
            vulnerable_purls: Set[str] = set()
            infection_count   = 0
            severity_buckets  = {k: 0 for k in ("critical","high","medium","low","unknown")}

            for v in vulnerabilities:
                UbelEngine._vuln_ids_found.add(v.get("id",""))
                if v.get("is_infection"):
                    infection_count += 1
                    infected_purls.add(v["affected_purl"])
                else:
                    sev = (v.get("severity") or "unknown").lower()
                    if sev not in severity_buckets:
                        sev = "unknown"
                    severity_buckets[sev] += 1
                    vulnerable_purls.add(v["affected_purl"])

            set_inventory_state(infected_purls, vulnerable_purls, inventory)

            inventory = build_dependency_sequences(inventory)
            inventory = build_introduced_by(inventory)
            _propagate_scopes(inventory)

            for item in inventory:
                ecosystems.add(get_ecosystem_from_purl(item["id"]))
                item["is_policy_violation"] = any(
                    v["affected_purl"] == item["id"] and v.get("policy_decision") == "block"
                    for v in vulnerabilities
                )

            # ── Network metadata ───────────────────────────────────────────
            # local IPs already collected in _get_os_metadata(); fetch external
            # IP here so it doesn't block the scan startup path.
            external_ip  = _get_external_ip()
            local_ips    = _get_local_ips()
            primary_ip   = next(iter(local_ips.values()), "")

            # ── Convert all path strings → SystemPath objects ──────────────
            _normalize_inventory_paths(inventory, primary_ip)

            # Undetermined count (version-less)
            undetermined_count = sum(1 for c in inventory if c.get("version","") == "")
            if undetermined_count:
                print(
                    f"[!] Warning: {undetermined_count} package(s) with undetermined "
                    "versions detected. Results may include false positives.",
                    file=sys.stderr,
                )

            # ── Stats ──────────────────────────────────────────────────────
            stats: Dict[str, Any] = {
                "inventory_size": len(inventory),
                "inventory_stats": {
                    "infected":      len(infected_purls),
                    "vulnerable":    len(vulnerable_purls),
                    "safe":          max(0, len(inventory) - len(infected_purls)
                                            - len(vulnerable_purls) - undetermined_count),
                    "undetermined":  undetermined_count,
                },
                "total_vulnerabilities": len(vulnerabilities),
                "vulnerabilities_stats": {"severity": severity_buckets},
                "total_infections":      infection_count,
            }

            # ── Build findings ────────────────────────────────────────────
            findings_summary = summarize_vulnerabilities(vulnerabilities, inventory)

            # Remove dependency_sequences from inventory before serialisation
            # (they're embedded in findings_summary instead)
            dep_tree = build_dependency_tree(inventory)
            for item in inventory:
                item.pop("dependency_sequences", None)
                if item.get("id","") in item.get("introduced_by", []):
                    item["introduced_by"].remove(item["id"])

            # ── Final JSON ────────────────────────────────────────────────
            os_meta = _get_os_metadata()
            os_meta["local_ips"]   = local_ips
            os_meta["external_ip"] = external_ip

            final_json: Dict[str, Any] = {
                "generated_at": now.isoformat().replace("+00:00","") + "Z",
                "runtime":      _get_runtime(),
                "engine":       {"name": UbelEngine.engine, "version": ""},
                "os_metadata":  os_meta,
                "git_metadata": _get_git_metadata(),
                "tool_info":    {"name": __tool_name__, "version": __version__, "license": __tool_license__},
                "scan_info":    {
                    "type":       UbelEngine.check_mode,
                    "ecosystems": sorted(ecosystems),
                    "engine":     UbelEngine.engine if UbelEngine.check_mode != "health" else __tool_name__,
                },
                "stats":               stats,
                "vulnerabilities_ids": sorted(UbelEngine._vuln_ids_found),
                "findings_summary":    findings_summary,
                "vulnerabilities":     sort_vulnerabilities(vulnerabilities),
                "inventory":           inventory,
                "policy":              policy,
                "dependencies_tree":   dep_tree,
            }

            allowed, reason = evaluate_policy(final_json)
            final_json["decision"] = {
                "allowed":           allowed,
                "reason":            reason,
                "policy_violations": policy_violations,
            }

            # ── Write reports ─────────────────────────────────────────────
            html_report = generate_html_report(final_json)
            html_path.write_text(html_report, encoding="utf-8")
            with open(json_path, "w", encoding="utf-8") as jf:
                json.dump(final_json, jf, indent=2)

            # latest.* — always overwritten
            latest_dir  = Path(".ubel/reports")
            latest_dir.mkdir(parents=True, exist_ok=True)
            latest_json = latest_dir / "latest.json"
            latest_html = latest_dir / "latest.html"
            latest_html.write_text(html_report, encoding="utf-8")
            with open(latest_json, "w", encoding="utf-8") as jf:
                json.dump(final_json, jf, indent=2)

            # ── Console output ────────────────────────────────────────────
            print()
            print("Policy:")
            print()
            print(dict_to_str(policy))
            print()
            print()
            print("Findings:")
            print()
            print(dict_to_str(stats))
            print()
            print()

            # Per-package summary
            summary_entries = list(findings_summary.values())
            if summary_entries:
                print("Findings Summary:")
                print()
                for pkg_data in summary_entries:
                    s = pkg_data["stats"]
                    counts: List[str] = []
                    if s.get("infection"): counts.append(f"{s['infection']} infection(s)")
                    if s.get("critical"):  counts.append(f"{s['critical']} critical")
                    if s.get("high"):      counts.append(f"{s['high']} high")
                    if s.get("medium"):    counts.append(f"{s['medium']} medium")
                    if s.get("low"):       counts.append(f"{s['low']} low")
                    if s.get("unknown"):   counts.append(f"{s['unknown']} unknown")
                    print(f"  {pkg_data['name']}@{pkg_data['version']}  [{', '.join(counts)}]")
                    for vuln_entry in pkg_data["vulnerabilities"]:
                        label = "INFECTION" if vuln_entry["is_infection"] else vuln_entry["severity"].upper()
                        score = f" ({vuln_entry['severity_score']})" if vuln_entry["severity_score"] is not None else ""
                        print(f"    \u2022 {vuln_entry['id']}  {label}{score}")
                        for fix in vuln_entry.get("fixes", []):
                            print(f"      fix: {fix}")
                    print()

            print(f"Policy Decision: {'ALLOW' if allowed else 'BLOCK'}")
            print()
            print()
            print(f"Latest JSON report saved to: {latest_json}")
            print(f"Latest HTML report saved to: {latest_html}")
            print()
            print()

            if not allowed:
                print("[!] Policy violation detected!")
                print(f"[!] {reason}")
                raise PolicyViolationError(reason)

            # ── Mode-specific post-scan actions ───────────────────────────
            if UbelEngine.check_mode == "health":
                UbelEngine.pin_versions()
                sys.exit(0)

            if UbelEngine.check_mode == "check":
                # check passed — revert dry-run artefacts and exit cleanly
                if UbelEngine.system_type == "pypi":
                    _cleanup_venv(UbelEngine.venv_dir or "./venv")
                    UbelEngine.pin_versions()
                sys.exit(0)

            # install mode
            print("[+] Policy passed. Installing dependencies...")
            if UbelEngine.system_type == "pypi":
                req_file = UbelEngine._generate_requirements_file(purls)
                venv_dir = UbelEngine.venv_dir or "./venv"
                Pypi_Manager.run_real_install(req_file, UbelEngine.engine, venv_dir)
                UbelEngine.pin_versions()
            else:
                packages_list = [get_dependency_from_purl(p) for p in purls]
                Linux_Manager.run_real_install(packages_list)

        except PolicyViolationError:
            # Revert if needed, then exit 1
            if needs_revert and UbelEngine.system_type == "pypi":
                _cleanup_venv(UbelEngine.venv_dir or "./venv")
            sys.exit(1)

        except Exception as exc:
            print(f"[!] Scan failed: {exc}", file=sys.stderr)
            if needs_revert and UbelEngine.system_type == "pypi":
                _cleanup_venv(UbelEngine.venv_dir or "./venv")
            raise
    
    @staticmethod
    def pin_versions():
        installed= []
        PythonVenvScanner.get_installed(is_recursive=False)
        for pkg in PythonVenvScanner.inventory_data:
            installed.append(f"{pkg['name']}=={pkg['version']}")
        with open("requirements.txt", "w", encoding="utf-8") as f:
            f.write("\n".join(installed))
            f.close()


# ---------------------------------------------------------------------------
# Venv cleanup helper
# ---------------------------------------------------------------------------

def _cleanup_venv(venv_dir: str) -> None:
    """
    Remove the ephemeral venv created for a dry-run / check scan.
    The venv is only cleaned up if it lives under .ubel/ (i.e. it was
    created by us, not an externally supplied venv_dir).
    """
    import shutil
    venv_path = Path(venv_dir).resolve()
    ubel_root  = Path(".ubel").resolve()
    try:
        venv_path.relative_to(ubel_root)
    except ValueError:
        # Not under .ubel/ — leave it alone
        return
    if venv_path.exists():
        shutil.rmtree(venv_path, ignore_errors=True)