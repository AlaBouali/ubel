"""
cvss_parser.py — CVSS parser supporting v2, v3.0, v3.1, v4.0, and Ubuntu severity labels.

Pure-Python port of cvss_parser.js.
Zero external dependencies (uses cvss40.py for v4 scoring).

API
---
    parse(vector)                  -> {"score": str|None, "severity": str}
    process_vulnerability(vuln)    -> mutates the OSV vuln dict in-place
"""

from __future__ import annotations

import math
import re
from typing import Dict, Optional

from .cvssv40 import CVSS40


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_UBUNTU_LABELS = {"critical", "high", "medium", "low", "negligible", "untriaged"}


def _score_to_severity(score_str: str) -> str:
    try:
        score = float(score_str)
    except (ValueError, TypeError):
        return "unknown"
    if math.isnan(score) or score == 0.0:
        return "unknown"
    if score < 4.0:  return "low"
    if score < 7.0:  return "medium"
    if score < 9.0:  return "high"
    return "critical"


def _parse_metrics(vector: str) -> Dict[str, str]:
    """Strip the version prefix and return a key→value dict."""
    body = re.sub(r"^CVSS:\d+\.\d+/", "", vector).strip("()")
    result: Dict[str, str] = {}
    for part in body.split("/"):
        if ":" in part:
            k, v = part.split(":", 1)
            result[k] = v
    return result


# ---------------------------------------------------------------------------
# CVSSv4 scoring
# ---------------------------------------------------------------------------

def _extract_cvss4_score(vector: str) -> Optional[str]:
    try:
        cvss = CVSS40(vector)
        return f"{cvss.score:.1f}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CVSSv3.x base-score calculation
# ---------------------------------------------------------------------------

def _round_up(value: float) -> float:
    """CVSS v3 'always round up' to 1 decimal place."""
    int_val = round(value * 100000)
    if int_val % 10000 == 0:
        return int_val / 100000
    return (math.floor(int_val / 10000) + 1) / 10


def _extract_cvss3_score(vector: str) -> Optional[str]:
    try:
        m = _parse_metrics(vector)

        AV_W  = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
        AC_W  = {"L": 0.77, "H": 0.44}
        PR_W  = {"N": 0.85, "L": 0.62, "H": 0.27}        # scope unchanged
        PR_SC = {"N": 0.85, "L": 0.68, "H": 0.50}        # scope changed
        UI_W  = {"N": 0.85, "R": 0.62}
        CIA_W = {"N": 0.00, "L": 0.22, "H": 0.56}

        S  = m.get("S", "U")
        AV = AV_W.get(m.get("AV", "N"), 0.85)
        AC = AC_W.get(m.get("AC", "L"), 0.77)
        PR = (PR_SC if S == "C" else PR_W).get(m.get("PR", "N"), 0.85)
        UI = UI_W.get(m.get("UI", "N"), 0.85)
        C  = CIA_W.get(m.get("C", "N"), 0.00)
        I  = CIA_W.get(m.get("I", "N"), 0.00)
        A  = CIA_W.get(m.get("A", "N"), 0.00)

        ISS = 1 - (1 - C) * (1 - I) * (1 - A)
        if S == "U":
            IS = 6.42 * ISS
        else:
            IS = 7.52 * (ISS - 0.029) - 3.25 * ((ISS - 0.02) ** 15)

        if IS <= 0:
            return "0.0"

        exploitability = 8.22 * AV * AC * PR * UI

        if S == "U":
            score = min(IS + exploitability, 10.0)
        else:
            score = min(1.08 * (IS + exploitability), 10.0)

        return f"{_round_up(score):.1f}"
    except Exception:
        return None


# ---------------------------------------------------------------------------
# CVSSv2 base-score calculation
# ---------------------------------------------------------------------------

def _extract_cvss2_score(vector: str) -> Optional[str]:
    try:
        m = _parse_metrics(vector)

        AV_W  = {"N": 1.0,   "A": 0.646, "L": 0.395}
        AC_W  = {"L": 0.71,  "M": 0.61,  "H": 0.35}
        Au_W  = {"N": 0.704, "S": 0.56,  "M": 0.45}
        CIA_W = {"N": 0.0,   "P": 0.275, "C": 0.660}

        AV = AV_W.get(m.get("AV", "N"), 1.0)
        AC = AC_W.get(m.get("AC", "L"), 0.71)
        Au = Au_W.get(m.get("Au", "N"), 0.704)
        C  = CIA_W.get(m.get("C",  "N"), 0.0)
        I  = CIA_W.get(m.get("I",  "N"), 0.0)
        A  = CIA_W.get(m.get("A",  "N"), 0.0)

        f_impact = 0 if (C == 0 and I == 0 and A == 0) else 1.176
        impact   = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A))
        exploit  = 20 * AV * AC * Au

        base = ((0.6 * impact) + (0.4 * exploit) - 1.5) * f_impact
        return str(round(base * 10) / 10)
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Main parse()
# ---------------------------------------------------------------------------

def parse(vector: object) -> Dict[str, Optional[str]]:
    """
    Parse a CVSS vector string (or Ubuntu severity label).

    Returns:
        {"score": str|None, "severity": str}
    """
    if not vector or not isinstance(vector, str):
        return {"score": None, "severity": "unknown"}

    v = vector.strip()

    # Ubuntu / plain severity label
    if v.lower() in _UBUNTU_LABELS:
        sev = v.lower()
        if sev == "negligible":
            sev = "low"
        if sev == "untriaged":
            sev = "unknown"
        return {"score": None, "severity": sev}

    # Plain numeric score
    if re.fullmatch(r"\d+(\.\d+)?", v):
        return {"score": v, "severity": _score_to_severity(v)}

    # CVSSv4
    if v.startswith("CVSS:4."):
        score = _extract_cvss4_score(v)
        severity = _score_to_severity(score) if score is not None else "unknown"
        return {"score": score, "severity": severity}

    # CVSSv3.x
    if v.startswith("CVSS:3."):
        score = _extract_cvss3_score(v)
        severity = _score_to_severity(score) if score is not None else "unknown"
        return {"score": score, "severity": severity}

    # CVSSv2 (no version prefix)
    if v.startswith("AV:") or v.startswith("(AV:"):
        score = _extract_cvss2_score(v)
        severity = _score_to_severity(score) if score is not None else "unknown"
        return {"score": score, "severity": severity}

    return {"score": None, "severity": "unknown"}


# ---------------------------------------------------------------------------
# process_vulnerability()  — mirrors Python process_vulnerability behaviour
# ---------------------------------------------------------------------------

def process_vulnerability(vuln: dict) -> None:
    """
    Mutate an OSV vulnerability dict in-place, setting:
        vuln["severity"]        str
        vuln["severity_score"]  float | None
        vuln["severity_vector"] str | None
    """
    severity_list = vuln.get("severity")

    if isinstance(severity_list, list) and severity_list:
        first  = severity_list[0]
        vector = first.get("score", "")
        type_  = (first.get("type") or "").lower()

        if type_ in ("ubuntu_cve", "ubuntu"):
            vuln["severity"]        = vector
            vuln["severity_score"]  = None
            vuln["severity_vector"] = None
            return

        result   = parse(vector)
        score    = result["score"]
        severity = result["severity"]

        vuln["severity"]        = severity
        vuln["severity_score"]  = float(score) if score is not None else None
        vuln["severity_vector"] = vector

        # Fallback bucket if severity still unknown but score exists
        if severity in ("unknown", None) and score is not None:
            vuln["severity"] = _score_to_severity(score)
        return

    vuln["severity"]        = "unknown"
    vuln["severity_score"]  = None
    vuln["severity_vector"] = None