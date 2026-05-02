from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    from .info import __version__, __tool_name__
except ImportError:
    __version__ = "0.0.0"
    __tool_name__ = "ubel"

# ---------------------------------------------------------------------------
# Extra inventory fields promoted to component properties
# (matches Node.js sbom_builder.js exactly – no 'license', no 'type')
# ---------------------------------------------------------------------------
_INVENTORY_PROPERTIES: List[str] = [
    "scopes",
    "paths",
    "introduced_by",
    "parents",
    "state",
    "is_policy_violation",
]


class CycloneDXBuilder:
    """
    Convert a UbelEngine final_json dict into a CycloneDX 1.6 SBOM document.
    """

    CYCLONEDX_VERSION = "1.6"

    def __init__(self, final_json: Dict[str, Any]) -> None:
        self.data = final_json

    # ------------------------------------------------------------------ utils

    @staticmethod
    def _severity_to_cdx(sev: Any) -> str:
        return {
            "critical": "critical",
            "high": "high",
            "medium": "medium",
            "low": "low",
        }.get(str(sev).lower(), "unknown")

    @staticmethod
    def _normalise_cvss_method(method: Any) -> str:
        """
        Map UBEL cvss_method strings → CycloneDX-accepted rating method values.
        Matches Node.js implementation exactly.
        """
        if not method:
            return "other"
        m = str(method).replace(".", "").upper()
        if "CVSS2" in m:
            return "CVSSv2"
        if "CVSS31" in m:
            return "CVSSv31"
        if "CVSS3" in m:
            return "CVSSv3"
        if "CVSS40" in m:
            return "CVSSv4"
        if "CVSS4" in m:
            return "CVSSv4"
        if "SSVC" in m:
            return "SSVC"
        return "other"

    @staticmethod
    def _props(record: Dict, keys: List[str]) -> List[Dict[str, str]]:
        """Serialise selected keys into a CycloneDX properties list.
        Matches Node.js behaviour:
        - string values are used as‑is (no extra quotes)
        - non‑string values are JSON.stringified
        - undefined/null values are skipped
        """
        out: List[Dict[str, str]] = []
        for k in keys:
            val = record.get(k)
            if val is None:
                continue
            if isinstance(val, str):
                out.append({"name": k, "value": val})
            else:
                out.append({"name": k, "value": json.dumps(val)})
        return out

    @staticmethod
    def _to_zulu_isoformat(dt: datetime) -> str:
        """Format datetime as YYYY-MM-DDTHH:MM:SSZ (no milliseconds, Z)."""
        return dt.strftime("%Y-%m-%dT%H:%M:%SZ")

    # --------------------------------------------------------------- builders

    def build_metadata(self) -> Dict[str, Any]:
        tool_info = self.data.get("tool_info", {})
        scan_info = self.data.get("scan_info", {})
        git = self.data.get("git_metadata", {})
        runtime = self.data.get("runtime", {})

        scan_type = scan_info.get("type", "health")
        # No 'lifecycles' field – matches Node.js (commented out)

        # Use provided generated_at, otherwise current UTC time without milliseconds
        gen_at = self.data.get("generated_at")
        if gen_at:
            timestamp = gen_at
        else:
            timestamp = self._to_zulu_isoformat(datetime.now(timezone.utc))

        meta: Dict[str, Any] = {
            "timestamp": timestamp,
            "tools": [
                {
                    "vendor": "Arcane-Spark",
                    "name": tool_info.get("name", __tool_name__),
                    "version": tool_info.get("version", __version__),
                }
            ],
            "properties": [
                {"name": "scan_type", "value": scan_type},
                {"name": "scan_scope", "value": scan_info.get("scan_scope", "repository")},
                {"name": "engine", "value": scan_info.get("engine", "")},
                {"name": "ecosystems", "value": json.dumps(scan_info.get("ecosystems", []))},
                {"name": "runtime_env", "value": runtime.get("environment", "")},
                {"name": "runtime_ver", "value": runtime.get("version", "")},
                {"name": "platform", "value": runtime.get("platform", "")},
                {"name": "arch", "value": runtime.get("arch", "")},
                {"name": "cwd", "value": runtime.get("cwd", "")},
                {"name": "git_branch", "value": str(git.get("branch") or "")},
                {"name": "git_commit", "value": str(git.get("latest_commit") or "")},
                {"name": "git_url", "value": str(git.get("url") or "")},
            ],
        }
        return meta

    def build_components(self) -> List[Dict[str, Any]]:
        """
        Map inventory items → CycloneDX components.
        Adds 'licenses' field exactly like Node.js.
        Promotes extra fields (matching Node.js set) into properties.
        """
        components: List[Dict[str, Any]] = []

        for item in self.data.get("inventory", []):
            purl = item.get("id", "") or ""
            cpe = item.get("cpe") or ""

            comp: Dict[str, Any] = {
                "bom-ref": purl,
                "type": item.get("type", "library"),
                "name": item.get("name", ""),
                "version": item.get("version", ""),
                "purl": purl,
            }
            if cpe:
                comp["cpe"] = cpe

            # Licenses as expression (matches Node.js)
            license_str = item.get("license")
            if license_str:
                comp["licenses"] = [{"expression": license_str}]
            else:
                comp["licenses"] = []

            # Properties – only the keys used in Node.js
            props = self._props(item, _INVENTORY_PROPERTIES)
            if props:
                comp["properties"] = props

            components.append(comp)

        return components

    def build_dependencies(self) -> List[Dict[str, Any]]:
        """
        Flat dependency block with deduplication and object handling.
        Matches Node.js exactly.
        """
        deps = []
        for item in self.data.get("inventory", []):
            raw_deps = item.get("dependencies", [])

            depends_on_strings = []
            for dep in raw_deps:
                if isinstance(dep, str):
                    depends_on_strings.append(dep)
                elif isinstance(dep, dict):
                    # try purl, then id, else skip
                    dref = dep.get("purl") or dep.get("id")
                    if dref and isinstance(dref, str):
                        depends_on_strings.append(dref)

            # Deduplicate while preserving order
            unique_depends_on = []
            seen = set()
            for d in depends_on_strings:
                if d not in seen:
                    seen.add(d)
                    unique_depends_on.append(d)

            # Determine component reference
            ref_id = item.get("id")
            if isinstance(ref_id, str):
                ref = ref_id
            elif isinstance(ref_id, dict):
                ref = ref_id.get("purl") or ref_id.get("id", "")
            else:
                ref = ""

            deps.append({"ref": ref, "dependsOn": unique_depends_on})

        return deps

    def build_vulnerabilities(self) -> List[Dict[str, Any]]:
        """
        Map vulnerabilities (including infections) to CycloneDX
        vulnerability + VEX analysis entries. Identical to Node.js.
        """
        out: List[Dict[str, Any]] = []

        for v in self.data.get("vulnerabilities", []):
            vid = v.get("id", "")
            is_inf = bool(v.get("is_infection"))
            sev = self._severity_to_cdx("critical" if is_inf else v.get("severity"))
            method = self._normalise_cvss_method(v.get("cvss_method"))
            purl = v.get("affected_purl", "")

            # Source
            sources = v.get("source", []) or []
            if isinstance(sources, str):
                sources = [sources]
            source_name = (sources[0] if sources else "osv").lower()
            if source_name == "osv" or is_inf:
                source_url = f"https://osv.dev/vulnerability/{vid}"
            else:
                source_url = f"https://www.cve.org/CVERecord?id={vid}"

            # Advisories from references
            refs = v.get("references") or []
            advisories = [{"url": r["url"]} for r in refs if isinstance(r, dict) and r.get("url")]

            # Remediations
            fixes = v.get("fixes") or []
            recommendation = "\n".join(fixes) if fixes else ""

            # VEX analysis
            if is_inf:
                analysis = {"state": "exploitable", "response": ["rollback", "can_not_fix"]}
            else:
                analysis = {"state": "exploitable", "response": ["update"]}

            rating: Dict[str, Any] = {"severity": sev, "method": method}
            score = v.get("severity_score")
            if score is not None:
                try:
                    rating["score"] = float(score)
                except (TypeError, ValueError):
                    pass
            vec = v.get("severity_vector")
            if vec:
                rating["vector"] = vec

            entry: Dict[str, Any] = {
                "id": vid,
                "source": {"name": source_name, "url": source_url},
                "ratings": [rating],
                "cwes": v.get("cwes", []),
                "description": v.get("description", ""),
                "advisories": advisories,
                "affects": [{"ref": purl}] if purl else [],
                "analysis": analysis,
                "recommendation": recommendation,
            }

            if v.get("published"):
                entry["published"] = v["published"]
            if v.get("modified"):
                entry["updated"] = v["modified"]

            out.append(entry)

        return out

    # ------------------------------------------------------------------ public

    def generate(self) -> Dict[str, Any]:
        decision = self.data.get("decision", {})
        stats = self.data.get("stats", {})

        sbom: Dict[str, Any] = {
            "bomFormat": "CycloneDX",
            "specVersion": self.CYCLONEDX_VERSION,
            "version": 1,
            "metadata": self.build_metadata(),
            "components": self.build_components(),
            "dependencies": self.build_dependencies(),
            "vulnerabilities": self.build_vulnerabilities(),
            "properties": [
                {"name": "policy_allowed", "value": json.dumps(decision.get("allowed"))},
                {"name": "policy_reason", "value": str(decision.get("reason", ""))},
                {"name": "policy_violations", "value": json.dumps(decision.get("policy_violations", []))},
                {"name": "inventory_size", "value": str(stats.get("inventory_size", 0))},
                {"name": "total_vulns", "value": str(stats.get("total_vulnerabilities", 0))},
                {"name": "total_infections", "value": str(stats.get("total_infections", 0))},
            ],
        }
        return sbom