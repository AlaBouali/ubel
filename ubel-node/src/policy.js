/**
 * policy.js — UBEL threshold-based policy evaluator.
 *
 * Policy file schema (JSON):
 * {
 *   "severity_threshold": "high",          // block this level and above
 *   "block_unknown_vulnerabilities": true   // whether to block unknowns
 * }
 *
 * Severity order (ascending): low → medium → high → critical
 * "unknown" is governed solely by block_unknown_vulnerabilities.
 *
 * Infections are always blocked regardless of policy.
 */

const SEVERITY_ORDER = ["low", "medium", "high", "critical"];

/**
 * Returns true if `candidate` severity is >= `threshold` severity.
 * Both values must be members of SEVERITY_ORDER.
 */
function meetsThreshold(candidate, threshold) {
  return SEVERITY_ORDER.indexOf(candidate) >= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * Evaluate policy against a scan report.
 * Returns [allowed: boolean, reason: string]
 *
 * @param {object} report  - Scan report with .stats and .policy fields.
 */
export function evaluatePolicy(report) {
  const stats  = report.stats  || {};
  const policy = report.policy;

  if (!policy) {
    throw new Error("No policy returned by API (fail-closed)");
  }

  // ── 1. Infections: always blocked, no policy toggle ──────────────────────
  if ((stats.total_infections || 0) > 0) {
    return [false, "Blocked: infections detected (always enforced)"];
  }

  // ── 2. Severity threshold ─────────────────────────────────────────────────
  const rawThreshold = (policy.severity_threshold || "").toLowerCase();
  if (rawThreshold && SEVERITY_ORDER.includes(rawThreshold)) {
    const severityStats = stats?.vulnerabilities_stats?.severity || {};

    for (const level of SEVERITY_ORDER) {
      if (meetsThreshold(level, rawThreshold) && (severityStats[level] || 0) > 0) {
        return [
          false,
          `Blocked by policy: ${level} severity vulnerabilities detected ` +
          `(threshold: ${rawThreshold})`,
        ];
      }
    }
  }

  // ── 3. Unknown vulnerabilities ────────────────────────────────────────────
  if (policy.block_unknown_vulnerabilities === true) {
    const unknownCount = stats?.vulnerabilities_stats?.severity?.unknown || 0;
    if (unknownCount > 0) {
      return [false, `Blocked by policy: ${unknownCount} unknown-severity vulnerabilities detected`];
    }
  }

  return [true, "Policy passed"];
}