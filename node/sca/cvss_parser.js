/**
 * CVSS Parser — supports v2, v3.0, v3.1, v4.0, and Ubuntu string severity labels.
 *
 * The upstream OSV "severity" array looks like:
 *   [ { "type": "CVSS_V3", "score": "CVSS:3.1/AV:N/…" }, … ]
 *   [ { "type": "UBUNTU_CVE",  "score": "medium" }, … ]
 *
 * parse(vector) → { score: string|null, severity: string }
 * processVulnerability(vuln)  mutates the OSV vuln object in-place,
 *   exactly mirroring the Python CVSS_Parser.process_vulnerability behaviour.
 */

import { CVSS40 } from "./cvss40.js";

// ── Score → severity bucket (mirrors Python fallback logic) ──────────────────
function scoreToSeverity(scoreStr) {
  const score = parseFloat(scoreStr);
  if (isNaN(score)) return "unknown";
  if (score === 0.0) return "unknown";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

// ── Numeric extraction helpers ────────────────────────────────────────────────

/**
 * Extract the base score from a CVSS vector string.
 * We compute it from the mandatory metrics rather than relying on a heavy
 * library, because the 'cvss' npm package API differs across versions.
 *
 * For our purposes (severity bucketing) a look-up of the pre-calculated
 * score embedded in the vector itself is sufficient when present, otherwise
 * we fall back to parsing the vector metrics.
 *
 * OSV frequently embeds the score directly as a numeric string instead of
 * a full vector — we handle that too.
 */

/**
 * Try to parse a CVSS vector and return { score, severity }.
 * Handles:
 *   CVSS:4.0/…   → CVSSv4
 *   CVSS:3.1/…   → CVSSv3.1
 *   CVSS:3.0/…   → CVSSv3.0
 *   AV:…         → CVSSv2 (no prefix)
 *   plain number → treat as pre-computed score
 *   Ubuntu label → pass through as severity, no numeric score
 */
export function parse(vector) {
  if (!vector || typeof vector !== "string") return { score: null, severity: "unknown" };

  const v = vector.trim();

  // ── Ubuntu / plain severity labels ────────────────────────────────────────
  const UBUNTU_LABELS = new Set(["critical", "high", "medium", "low", "negligible", "untriaged"]);
  if (UBUNTU_LABELS.has(v.toLowerCase())) {
    const sev = v.toLowerCase() === "negligible" ? "low" : v.toLowerCase();
    return { score: null, severity: sev === "untriaged" ? "unknown" : sev };
  }

  // ── Plain numeric score (some OSV entries use this) ───────────────────────
  if (/^\d+(\.\d+)?$/.test(v)) {
    const sev = scoreToSeverity(v);
    return { score: v, severity: sev };
  }

  // ── CVSSv4 ────────────────────────────────────────────────────────────────
  if (v.startsWith("CVSS:4.")) {
    const score = extractCVSS4Score(v);
    const severity = score !== null ? scoreToSeverity(score) : "unknown";
    return { score, severity };
  }

  // ── CVSSv3.x ─────────────────────────────────────────────────────────────
  if (v.startsWith("CVSS:3.")) {
    const score = extractCVSS3Score(v);
    const severity = score !== null ? scoreToSeverity(score) : "unknown";
    return { score, severity };
  }

  // ── CVSSv2 (no version prefix) ────────────────────────────────────────────
  if (v.startsWith("AV:") || v.startsWith("(AV:")) {
    const score = extractCVSS2Score(v);
    const severity = score !== null ? scoreToSeverity(score) : "unknown";
    return { score, severity };
  }

  return { score: null, severity: "unknown" };
}

function extractCVSS4Score(vector) {
  try {
    const cvss = new CVSS40(vector);
    return cvss.score.toFixed(1);
  } catch {
    return null;
  }
}

// ── CVSSv3.x base-score calculation ───────────────────────────────────────────
function extractCVSS3Score(vector) {
  try {
    const metrics = parseMetrics(vector);

    const AV_W  = { N: 0.85, A: 0.62, L: 0.55, P: 0.20 };
    const AC_W  = { L: 0.77, H: 0.44 };
    const PR_W  = {
      // Scope unchanged
      N: 0.85, L: 0.62, H: 0.27,
    };
    const PR_SC = { N: 0.85, L: 0.68, H: 0.50 }; // scope changed
    const UI_W  = { N: 0.85, R: 0.62 };
    const CIA_W = { N: 0.00, L: 0.22, H: 0.56 };

    const S   = metrics["S"]  || "U";
    const AV  = AV_W[metrics["AV"]]  ?? 0.85;
    const AC  = AC_W[metrics["AC"]]  ?? 0.77;
    const prTable = S === "C" ? PR_SC : PR_W;
    const PR  = prTable[metrics["PR"]] ?? 0.85;
    const UI  = UI_W[metrics["UI"]]  ?? 0.85;
    const C   = CIA_W[metrics["C"]]  ?? 0.00;
    const I   = CIA_W[metrics["I"]]  ?? 0.00;
    const A   = CIA_W[metrics["A"]]  ?? 0.00;

    const ISS  = 1 - (1 - C) * (1 - I) * (1 - A);
    const IS   = S === "U"
      ? 6.42 * ISS
      : 7.52 * (ISS - 0.029) - 3.25 * Math.pow(ISS - 0.02, 15);

    if (IS <= 0) return "0.0";

    const exploitability = 8.22 * AV * AC * PR * UI;

    let score;
    if (S === "U") {
      score = Math.min(IS + exploitability, 10);
    } else {
      score = Math.min(1.08 * (IS + exploitability), 10);
    }

    return roundUp(score).toFixed(1);
  } catch {
    return null;
  }
}

// ── CVSSv2 base-score calculation ─────────────────────────────────────────────
function extractCVSS2Score(vector) {
  try {
    const metrics = parseMetrics(vector);

    const AV_W = { N: 1.0, A: 0.646, L: 0.395 };
    const AC_W = { L: 0.71, M: 0.61, H: 0.35 };
    const Au_W = { N: 0.704, S: 0.56, M: 0.45 };
    const CIA_W = { N: 0.0, P: 0.275, C: 0.660 };

    const AV = AV_W[metrics["AV"]] ?? 1.0;
    const AC = AC_W[metrics["AC"]] ?? 0.71;
    const Au = Au_W[metrics["Au"]] ?? 0.704;
    const C  = CIA_W[metrics["C"]] ?? 0.0;
    const I  = CIA_W[metrics["I"]] ?? 0.0;
    const A  = CIA_W[metrics["A"]] ?? 0.0;

    const f_impact = C === 0 && I === 0 && A === 0 ? 0 : 1.176;
    const impact   = 10.41 * (1 - (1 - C) * (1 - I) * (1 - A));
    const exploit  = 20 * AV * AC * Au;

    const base = ((0.6 * impact) + (0.4 * exploit) - 1.5) * f_impact;
    return Math.round(base * 10) / 10 + "";
  } catch {
    return null;
  }
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function parseMetrics(vector) {
  const result = {};
  // Strip version prefix (CVSS:3.1/, CVSS:4.0/) or leave raw
  const body = vector.replace(/^CVSS:\d+\.\d+\//, "").replace(/^\(|\)$/g, "");
  for (const part of body.split("/")) {
    const [k, v] = part.split(":");
    if (k && v !== undefined) result[k] = v;
  }
  return result;
}

// CVSS v3 "roundup" — rounds to 1 decimal, always up
function roundUp(value) {
  const int = Math.round(value * 100000);
  if (int % 10000 === 0) return int / 100000;
  return (Math.floor(int / 10000) + 1) / 10;
}

// ── Main mutation helper (mirrors Python process_vulnerability) ───────────────
export function processVulnerability(vuln) {
  const severityList = vuln["severity"];

  if (Array.isArray(severityList) && severityList.length > 0) {
    const first = severityList[0];
    const vector = first["score"] || "";
    const type   = (first["type"] || "").toLowerCase();

    // Ubuntu label — no numeric score, pass string as-is
    if (type === "ubuntu_cve" || type === "ubuntu") {
      vuln["severity"]        = vector;
      vuln["severity_score"]  = null;
      vuln["severity_vector"] = null;
      return;
    }

    const { score, severity } = parse(vector);

    vuln["severity"]        = severity;
    vuln["severity_score"]  = parseFloat(score) || null;
    vuln["severity_vector"] = vector;

    // Fallback: if severity still unknown but we have a numeric score, bucket it
    if ((severity === "unknown" || severity === null) && score !== null) {
      vuln["severity"] = scoreToSeverity(score);
    }
    return;
  }

  vuln["severity"]        = "unknown";
  vuln["severity_score"]  = null;
  vuln["severity_vector"] = null;
}
