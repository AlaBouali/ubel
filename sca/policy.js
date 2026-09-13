/**
 * policy.js — UBEL threshold-based policy evaluator.
 *
 * Policy file schema (JSON):
 * {
 *   "severity_threshold": "high",              // block this level and above
 *   "block_unknown_vulnerabilities": true,     // whether to block unknowns
 *   "license_risk_threshold": "none",          // block this license risk level
 *                                              // and above; "none" disables
 *                                              // license-risk blocking (default)
 *   "block_unknown_license_risk": false        // separately block packages whose
 *                                              // license couldn't be classified
 *                                              // at all (default: false)
 * }
 *
 * Severity order (ascending): low → medium → high → critical
 * "unknown" is governed solely by block_unknown_vulnerabilities.
 *
 * License risk order (ascending): low → medium → high
 * "none" is not a risk level — it means the gate is off. "unknown" is
 * deliberately NOT part of this ordered threshold, for the same reason
 * unknown-severity vulnerabilities get their own separate flag above:
 * license detection can't always resolve a package's terms (missing
 * metadata, unparsable free text), and folding "unknown" into the ordered
 * gate would make license_risk_threshold silently skip over misclassified
 * packages no matter how strict the threshold is set. block_unknown_license_risk
 * is the explicit, separate opt-in for that case — default false, since an
 * unknown classification is still more often a detection gap than an actual
 * legal finding, and a fresh scan on an unfamiliar codebase can otherwise
 * block on packages nobody has looked at yet.
 *
 * Only populated for `health`-mode scans — see engine.js — so both license
 * checks above are a no-op for `check`/`install` scans regardless of config.
 *
 * Infections are always blocked regardless of policy.
 */

const SEVERITY_ORDER = ["low", "medium", "high", "critical"];
const LICENSE_RISK_ORDER = ["low", "medium", "high"];

/**
 * Returns true if `candidate` severity is >= `threshold` severity.
 * Both values must be members of SEVERITY_ORDER.
 */
function meetsThreshold(candidate, threshold) {
  return SEVERITY_ORDER.indexOf(candidate) >= SEVERITY_ORDER.indexOf(threshold);
}

/**
 * Returns true if `candidate` license risk is >= `threshold` license risk.
 * Both values must be members of LICENSE_RISK_ORDER.
 */
function meetsLicenseRiskThreshold(candidate, threshold) {
  return LICENSE_RISK_ORDER.indexOf(candidate) >= LICENSE_RISK_ORDER.indexOf(threshold);
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
  if ((report.secrets?.count || 0) > 0) {
    return [false, "Blocked: secrets detected (always enforced)"];
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

  // ── 4. License risk (health-mode scans only; see engine.js) ──────────────
  const rawLicenseThreshold = (policy.license_risk_threshold || "none").toLowerCase();
  if (rawLicenseThreshold !== "none" && LICENSE_RISK_ORDER.includes(rawLicenseThreshold)) {
    const byRisk = stats?.license_stats?.by_risk || {};

    for (const level of LICENSE_RISK_ORDER) {
      if (meetsLicenseRiskThreshold(level, rawLicenseThreshold) && (byRisk[level] || 0) > 0) {
        return [
          false,
          `Blocked by policy: ${byRisk[level]} package(s) with ${level} license risk detected ` +
          `(threshold: ${rawLicenseThreshold})`,
        ];
      }
    }
  }

  // ── 5. Unknown license risk (health-mode scans only; separate opt-in) ────
  if (policy.block_unknown_license_risk === true) {
    const unknownLicenseCount = stats?.license_stats?.by_risk?.unknown || 0;
    if (unknownLicenseCount > 0) {
      return [false, `Blocked by policy: ${unknownLicenseCount} package(s) with unclassified license risk detected`];
    }
  }

  return [true, "Policy passed"];
}