# sarif_builder.py — SARIF 2.1.0 generator (Python port of sarif_builder.js)
#
# Change vs JS original:
#   • result.ruleId  stays the SHA-1 UUIDv5 of the advisory id (unchanged)
#   • result fingerprint / vuln-id key is now SHA-256( affected_package_id + ":" + vuln_id )
#     instead of a random UUID, giving fully deterministic, content-addressed IDs.

from __future__ import annotations

import hashlib,re
import os
import platform
from pathlib import Path, PurePosixPath
from typing import Any, Dict, List, Optional, Set

try:
    from .info import __version__ as TOOL_VERSION, __tool_name__ as TOOL_NAME
except ImportError:
    try:
        from info import __version__ as TOOL_VERSION, __tool_name__ as TOOL_NAME
    except ImportError:
        TOOL_VERSION = "0.0.0"
        TOOL_NAME    = "ubel-python"


class SarifBuilder:
    """Convert a UBEL final JSON dict into a SARIF 2.1.0 document."""

    SARIF_VERSION = "2.1.0"
    SARIF_SCHEMA  = "https://json.schemastore.org/sarif-2.1.0.json"

    def __init__(self, final_json: Dict[str, Any]) -> None:
        self.data: Dict[str, Any] = final_json or {}
        self._purl_location_index: Optional[Dict[str, Set[str]]] = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _truncate(self, text: Any, max: int = 10_000) -> str:
        """Clamp giant advisory texts."""
        s = str(text or "")
        if len(s) <= max:
            return s
        return s[:max] + "\n\n[truncated]"

    def _severity_to_level(self, sev: Any, is_infection: bool = False) -> str:
        """Map UBEL severity → SARIF level."""
        if is_infection:
            return "error"
        s = str(sev or "").strip().lower()
        if s in ("critical", "high"):
            return "error"
        if s in ("medium", "moderate"):
            return "warning"
        if s == "low":
            return "note"
        return "none"

    def _normalize_uri(self, uri: Any) -> Optional[str]:
        """Normalise URI/path separators (no trailing slash for normal paths)."""
        if not uri:
            return None
        s = str(uri).replace("\\", "/")
        # collapse duplicate slashes (but not the double-slash in schemes)
        import re
        s = re.sub(r"(?<!:)/{2,}", "/", s)
        s = s.rstrip("/")
        return s

    def _to_file_uri(self, p: Any) -> Optional[str]:
        """Convert a filesystem path → file:// URI (without trailing slash)."""
        if not p:
            return None
        normalized = self._normalize_uri(str(Path(str(p)).resolve()))
        if normalized is None:
            return None
        if not normalized.startswith("/"):
            normalized = "/" + normalized
        return f"file://{normalized}"

    def _to_repo_relative_uri(self, raw_path: Any) -> Optional[str]:
        """Convert absolute filesystem path → repository-relative SARIF URI."""
        if not raw_path:
            return None
        normalized = self._normalize_uri(raw_path)
        if normalized is None:
            return None
        cwd = self._normalize_uri(os.getcwd())

        lower_path = normalized.lower()
        lower_cwd  = (cwd or "").lower()

        # inside repository (case-insensitive for Windows)
        if lower_path.startswith(lower_cwd):
            relative = normalized[len(cwd or ""):]
            relative = relative.lstrip("/")
            return relative or "."

        # already relative (not an absolute Windows/Unix path)
        import re
        if not re.match(r"^[a-zA-Z]:/", normalized) and not normalized.startswith("/"):
            return normalized

        # fallback — filename only
        return Path(normalized).name

    # ------------------------------------------------------------------
    # Purl → location index
    # ------------------------------------------------------------------

    def _build_purl_location_index(self) -> Dict[str, Set[str]]:
        """Build: purl → set of installed runtime paths."""
        index: Dict[str, Set[str]] = {}

        findings = self.data.get("findings_summary") or {}

        for finding in findings.values():
            runtime_paths: List[str] = []

            # installed locations
            for p in finding.get("paths") or []:
                if isinstance(p, dict) and isinstance(p.get("text"), str):
                    normalized = self._normalize_uri(p["text"])
                    if normalized:
                        runtime_paths.append(normalized)

            if not runtime_paths:
                continue

            sequences = finding.get("affected_dependency_sequences") or []
            if not isinstance(sequences, list):
                sequences = []

            for seq in sequences:
                if not isinstance(seq, list):
                    continue
                for purl in seq:
                    if not isinstance(purl, str):
                        continue
                    if purl not in index:
                        index[purl] = set()
                    for rp in runtime_paths:
                        index[purl].add(rp)

        return index

    # ------------------------------------------------------------------
    # SARIF locations
    # ------------------------------------------------------------------

    def _build_locations(self, v: Dict[str, Any]) -> List[Dict[str, Any]]:
        locations: List[Dict[str, Any]] = []
        seen: Set[str] = set()

        def add_location(raw_uri: Any) -> None:
            relative_uri = self._to_repo_relative_uri(raw_uri)
            if not relative_uri or relative_uri in seen:
                return
            seen.add(relative_uri)
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": relative_uri,
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                    },
                },
            })

        # lazy init
        if self._purl_location_index is None:
            self._purl_location_index = self._build_purl_location_index()

        affected_purl = str(v.get("affected_package_id") or "").strip()

        # purl-derived runtime paths
        if affected_purl and affected_purl in self._purl_location_index:
            for loc in self._purl_location_index[affected_purl]:
                add_location(loc)

        # explicit paths
        for p in v.get("paths") or []:
            if isinstance(p, str):
                add_location(p)

        # explicit file
        if v.get("file"):
            add_location(v["file"])

        # GHAS fallback
        if not locations:
            locations.append({
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": ".",
                        "uriBaseId": "%SRCROOT%",
                    },
                    "region": {
                        "startLine": 1,
                        "startColumn": 1,
                    },
                },
            })

        return locations

    def _help_uri(self, v: Dict[str, Any]) -> Optional[str]:
        return v.get("url")

    # ------------------------------------------------------------------
    # CWE helpers
    # ------------------------------------------------------------------

    def _collect_all_cwes(self) -> Set[int]:
        all_cwes: Set[int] = set()
        for v in self.data.get("vulnerabilities") or []:
            for c in v.get("cwes") or []:
                if isinstance(c, int):
                    all_cwes.add(c)
        return all_cwes

    # ------------------------------------------------------------------
    # Taxonomies
    # ------------------------------------------------------------------

    def build_taxonomies(self) -> Optional[List[Dict[str, Any]]]:
        """Build the CWE taxonomy toolComponent for runs[0].taxonomies."""
        cwes = self._collect_all_cwes()
        if not cwes:
            return None

        taxa = [
            {
                "id":      f"CWE-{n}",
                "name":    f"CWE-{n}",
                "helpUri": f"https://cwe.mitre.org/data/definitions/{n}.html",
            }
            for n in sorted(cwes)
        ]

        return [{
            "name":            "CWE",
            "version":         "4.16",
            "releaseDateUtc":  "2024-03-25",
            "informationUri":  "https://cwe.mitre.org",
            "downloadUri":     "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
            "isComprehensive": False,
            "taxa":            taxa,
        }]

    # ------------------------------------------------------------------
    # Rules
    # ------------------------------------------------------------------

    def build_rules(self) -> List[Dict[str, Any]]:
        """Deduplicate and build SARIF rules."""
        all_cwes    = sorted(self._collect_all_cwes())
        taxon_index = {c: i for i, c in enumerate(all_cwes)}

        rules_map: Dict[str, Dict[str, Any]] = {}

        for v in self.data.get("vulnerabilities") or []:
            rule_id = self._rule_id(v)
            if rule_id in rules_map:
                continue

            advisory_id = str(v.get("id") or "UBEL-UNKNOWN")
            summary     = v.get("summary") or v.get("title") or advisory_id
            description = (
                v.get("description") or
                v.get("summary") or
                "No description provided."
            )

            fixes = v.get("fixes") if isinstance(v.get("fixes"), list) else []
            remediation = (
                v.get("remediation") or
                ("\n".join(fixes) if fixes else "No remediation guidance available.")
            )

            rule_cwes     = [c for c in (v.get("cwes") or []) if isinstance(c, int)]
            relationships = [
                {
                    "target": {
                        "id":            f"CWE-{c}",
                        "index":         taxon_index.get(c, 0),
                        "toolComponent": {"name": "CWE", "index": 0},
                    },
                    "kinds": ["relevant"],
                }
                for c in rule_cwes
            ]

            rule: Dict[str, Any] = {
                "id":   rule_id,
                "name": self._to_pascal_case_rule_name(self.getFirstNWords(v,10)),
                "shortDescription": {
                    "text": self._truncate(summary, 300),
                },
                "fullDescription": {
                    "text": self._truncate(description, 10_000),
                },
                "help": {
                    "text": self._truncate(remediation, 4_000),
                },
                "helpUri": self._help_uri(v),
                "properties": {
                    "advisory_id":          advisory_id,
                    "severity":             v.get("severity") or "unknown",
                    "cvss_score":           v.get("severity_score"),
                    "cvss_vector":          v.get("severity_vector") or None,
                    "cvss_method":          v.get("cvss_method") or None,
                    "cwes":                 rule_cwes,
                    "affected_package_id":  v.get("affected_package_id") or None,
                    "package":              v.get("affected_dependency") or None,
                    "package_version":      v.get("affected_dependency_version") or None,
                    "is_infection":         bool(v.get("is_infection")),
                },
            }

            if relationships:
                rule["relationships"] = relationships

            rules_map[rule_id] = rule

        return list(rules_map.values())

    # ------------------------------------------------------------------
    # Results
    # ------------------------------------------------------------------

    def build_results(self) -> List[Dict[str, Any]]:
        """Build SARIF results."""
        rules         = self.build_rules()
        rule_index_map = {r["id"]: i for i, r in enumerate(rules)}
        results: List[Dict[str, Any]] = []

        for v in self.data.get("vulnerabilities") or []:
            rule_id      = self._rule_id(v)
            is_infection = bool(v.get("is_infection"))
            message      = (
                v.get("summary") or
                v.get("title") or
                v.get("description") or
                v.get("id") or
                "Security issue detected."
            )

            vuln_id      = str(v.get("id") or "")
            affected_id  = str(v.get("affected_package_id") or "")

            # ── Deterministic hash-based vuln ID (SHA-256) ────────────────
            # Key = affected_package_id + ":" + vuln_id
            # This replaces the random UUID used in earlier versions so that
            # the same (package, advisory) pair always yields the same ID,
            # enabling stable deduplication across re-runs in GitHub / GitLab.
            composite_key     = f"{affected_id}:{vuln_id}"
            deterministic_id  = self._sha256_vuln_id(composite_key)

            results.append({
                "ruleId":    rule_id,
                "ruleIndex": rule_index_map.get(rule_id),
                "level":     self._severity_to_level(v.get("severity"), is_infection),
                "message": {
                    "text": self._truncate(message, 2_000),
                },
                "locations": self._build_locations(v),
                "partialFingerprints": {
                    "vulnerabilityId":           vuln_id,
                    "affectedPurl":              affected_id,
                    "primaryLocationLineHash":   composite_key,
                },
                "fingerprints": {
                    # Stable, content-addressed fingerprint — no more random UUID.
                    "primary": deterministic_id,
                },
                "properties": {
                    "advisory_id":          v.get("id") or None,
                    "severity":             v.get("severity") or "unknown",
                    "score":                v.get("severity_score"),
                    "vector":               v.get("severity_vector") or None,
                    "package":              v.get("affected_dependency") or None,
                    "package_version":      v.get("affected_dependency_version") or None,
                    "affected_package_id":  affected_id or None,
                    "fixed_versions":       v.get("fixes") if isinstance(v.get("fixes"), list) else [],
                    "cwes":                 v.get("cwes") if isinstance(v.get("cwes"), list) else [],
                    "published":            v.get("published") or None,
                    "modified":             v.get("modified") or None,
                    "exploitability":       "active-infection" if is_infection else "vulnerable",
                },
            })

        return results

    # ------------------------------------------------------------------
    # Tool
    # ------------------------------------------------------------------

    def build_tool(self) -> Dict[str, Any]:
        """Build tool metadata."""
        tool_info = self.data.get("tool_info") or {}

        driver: Dict[str, Any] = {
            "fullName":        f"{TOOL_NAME} v{TOOL_VERSION}",
            "name":            tool_info.get("name") or TOOL_NAME,
            "version":         tool_info.get("version") or TOOL_VERSION,
            "semanticVersion": tool_info.get("version") or TOOL_VERSION,
            "informationUri":  "https://github.com/Arcane-Spark/UBEL",
            "rules":           self.build_rules(),
        }

        if self._collect_all_cwes():
            driver["supportedTaxonomies"] = [{"name": "CWE", "index": 0}]

        return {"driver": driver}

    # ------------------------------------------------------------------
    # Invocations
    # ------------------------------------------------------------------

    def build_invocations(self) -> List[Dict[str, Any]]:
        """Build invocation metadata."""
        runtime  = self.data.get("runtime") or {}
        git      = self.data.get("git_metadata") or {}
        stats    = self.data.get("stats") or {}
        decision = self.data.get("decision") or {}

        return [{
            "executionSuccessful": True,
            "properties": {
                "runtime_environment":   runtime.get("environment") or "",
                "runtime_version":       runtime.get("version") or "",
                "platform":              runtime.get("platform") or "",
                "architecture":          runtime.get("arch") or "",
                "cwd":                   runtime.get("cwd") or "",
                "git_branch":            git.get("branch") or "",
                "git_commit":            git.get("latest_commit") or "",
                "git_url":               git.get("url") or "",
                "inventory_size":        stats.get("inventory_size") or 0,
                "total_vulnerabilities": stats.get("total_vulnerabilities") or 0,
                "total_infections":      stats.get("total_infections") or 0,
                "policy_allowed": (
                    decision["allowed"]
                    if "allowed" in decision
                    else None
                ),
                "policy_reason":         decision.get("reason") or "",
            },
        }]

    # ------------------------------------------------------------------
    # Version control provenance
    # ------------------------------------------------------------------

    def build_version_control_provenance(self) -> List[Dict[str, Any]]:
        """Build SARIF version control provenance."""
        git = self.data.get("git_metadata") or {}

        git_url  = git.get("url") or ""
        repo_uri = git_url if git_url else (self._to_file_uri(os.getcwd()) or "")

        revision_id = (
            git.get("latest_commit") or
            self._uuid_from_string(repo_uri)
        )

        return [{
            "repositoryUri": repo_uri,
            "revisionId":    revision_id,
            "branch":        git.get("branch") or "unknown",
            "mappedTo": {
                "uriBaseId": "%SRCROOT%",
            },
        }]

    # ------------------------------------------------------------------
    # Artifacts
    # ------------------------------------------------------------------

    def build_artifacts(self) -> List[Dict[str, Any]]:
        """Build optional artifacts section."""
        artifact_uris: Set[str] = set()

        for result in self.build_results():
            for loc in result.get("locations") or []:
                uri = (
                    loc
                    .get("physicalLocation", {})
                    .get("artifactLocation", {})
                    .get("uri")
                )
                if uri and uri != ".":
                    artifact_uris.add(uri)

        return [
            {
                "location": {
                    "uri":       uri,
                    "uriBaseId": "%SRCROOT%",
                },
            }
            for uri in artifact_uris
        ]

    # ------------------------------------------------------------------
    # Utility: string helpers
    # ------------------------------------------------------------------

    def getFirstNWords(self,obj, words_count):
        return " ".join(
            re.sub(r"[^a-zA-Z0-9\s]", " ", obj.get("description", ""))
            .strip()
            .split()
            [:words_count]
        )

    def _to_pascal_case_rule_name(self, input: Any) -> str:
        """Convert advisory IDs into SARIF-friendly PascalCase names."""
        import re
        parts = re.split(r"[^a-zA-Z0-9]+", str(input or "UnknownRule"))
        return "".join(
            p[0].upper() + p[1:].lower()
            for p in parts
            if p
        ) or "UnknownRule"

    # ------------------------------------------------------------------
    # Deterministic ID generators
    # ------------------------------------------------------------------

    def _uuid_from_string(self, input: Any) -> str:
        """
        Deterministic UUIDv5-like ID (SHA-1, identical algorithm to the JS original).
        Used for rule IDs and version-control provenance.
        """
        h = hashlib.sha1(str(input).encode("utf-8")).hexdigest()
        v_nibble = (int(h[16], 16) & 0x3) | 0x8
        return "-".join([
            h[0:8],
            h[8:12],
            f"5{h[13:16]}",
            f"{v_nibble:x}{h[17:20]}",
            h[20:32],
        ])

    def _sha256_vuln_id(self, composite_key: str) -> str:
        """
        Deterministic, content-addressed vuln ID.

        SHA-256( affected_package_id + ":" + vuln_id ) formatted as a
        UUID-shaped hex string so downstream SARIF consumers (GitHub, GitLab,
        VS Code SARIF Viewer) handle it without complaints.

        Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
        The version nibble is forced to '8' (custom / non-standard UUID) so
        it is visually distinct from the SHA-1 UUIDv5 used for rule IDs.
        """
        h = hashlib.sha256(composite_key.encode("utf-8")).hexdigest()
        return "-".join([
            h[0:8],
            h[8:12],
            f"8{h[13:16]}",            # '8' marks this as SHA-256 derived
            f"{(int(h[16], 16) & 0x3 | 0x8):x}{h[17:20]}",
            h[20:32],
        ])

    def _rule_id(self, v: Dict[str, Any]) -> str:
        """Stable SARIF rule id (SHA-1 UUIDv5 of the advisory id)."""
        advisory = str(
            v.get("id") or
            v.get("ghsa") or
            v.get("cve") or
            "UBEL-UNKNOWN"
        )
        return self._uuid_from_string(advisory)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def generate(self) -> Dict[str, Any]:
        """Generate the full SARIF 2.1.0 document."""
        cwd      = self._normalize_uri(os.getcwd()) or ""
        base_uri = self._to_file_uri(cwd) or f"file://{cwd}"
        if not base_uri.endswith("/"):
            base_uri += "/"

        taxonomies = self.build_taxonomies()

        run: Dict[str, Any] = {
            "tool":            self.build_tool(),
            "automationDetails": {
                "id": "ubel",
            },
            "originalUriBaseIds": {
                "%SRCROOT%": {
                    "uri": base_uri,
                },
            },
            "versionControlProvenance": self.build_version_control_provenance(),
            "invocations":             self.build_invocations(),
            "results":                 self.build_results(),
            "artifacts":               self.build_artifacts(),
            "properties": {
                "generated_at": (
                    self.data.get("generated_at") or
                    __import__("datetime").datetime.utcnow()
                    .strftime("%Y-%m-%dT%H:%M:%SZ")
                ),
                "scan_type": (
                    (self.data.get("scan_info") or {}).get("type") or "health"
                ),
                "scan_scope": (
                    (self.data.get("scan_info") or {}).get("scan_scope") or "repository"
                ),
                "ecosystems": (
                    (self.data.get("scan_info") or {}).get("ecosystems") or []
                ),
            },
        }

        if taxonomies:
            run["taxonomies"] = taxonomies

        return {
            "$schema": self.SARIF_SCHEMA,
            "version": self.SARIF_VERSION,
            "runs":    [run],
        }