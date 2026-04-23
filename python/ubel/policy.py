"""
policy.py — UBEL threshold-based policy evaluator.

Python port of policy.js.  Zero external dependencies.

Policy file schema (JSON):
{
    "severity_threshold":            "high",   // block this level and above
    "block_unknown_vulnerabilities": true       // whether to block unknowns
}

Severity order (ascending): low → medium → high → critical
"unknown" is governed solely by block_unknown_vulnerabilities.

Infections (MAL-*) are always blocked regardless of any policy setting.
"""

from __future__ import annotations

from typing import Tuple

SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def _meets_threshold(candidate: str, threshold: str) -> bool:
    """Return True if *candidate* severity is >= *threshold* severity."""
    try:
        return SEVERITY_ORDER.index(candidate) >= SEVERITY_ORDER.index(threshold)
    except ValueError:
        return False


def evaluate_policy(report: dict) -> Tuple[bool, str]:
    """
    Evaluate policy against a scan report.
    Returns (allowed: bool, reason: str).

    Mirrors evaluatePolicy() in policy.js exactly.
    """
    stats  = report.get("stats", {})
    policy = report.get("policy")

    if not policy:
        raise RuntimeError("No policy returned by API (fail-closed)")

    # ── 1. Infections: always blocked, no policy toggle ──────────────────────
    if stats.get("total_infections", 0) > 0:
        return False, "Blocked: infections detected (always enforced)"

    # ── 2. Severity threshold ─────────────────────────────────────────────────
    raw_threshold = (policy.get("severity_threshold") or "").lower()
    if raw_threshold and raw_threshold in SEVERITY_ORDER:
        severity_stats = (
            stats.get("vulnerabilities_stats", {})
                 .get("severity", {})
        )
        for level in SEVERITY_ORDER:
            if _meets_threshold(level, raw_threshold) and severity_stats.get(level, 0) > 0:
                return (
                    False,
                    f"Blocked by policy: {level} severity vulnerabilities detected "
                    f"(threshold: {raw_threshold})",
                )

    # ── 3. Unknown vulnerabilities ────────────────────────────────────────────
    if policy.get("block_unknown_vulnerabilities") is True:
        unknown_count = (
            stats.get("vulnerabilities_stats", {})
                 .get("severity", {})
                 .get("unknown", 0)
        )
        if unknown_count > 0:
            return (
                False,
                f"Blocked by policy: {unknown_count} unknown-severity vulnerabilities detected",
            )

    return True, "Policy passed"