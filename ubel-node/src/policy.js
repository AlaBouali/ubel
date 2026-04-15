/**
 * Mirrors Python policy.evaluate_policy exactly.
 * Returns [allowed: boolean, reason: string]
 */
export function evaluatePolicy(report) {
  const stats  = report.stats  || {};
  const policy = report.policy;

  if (!policy) {
    throw new Error("No policy returned by API (fail-closed)");
  }

  // Infections
  if (policy.infections === "block") {
    if ((stats.total_infections || 0) > 0) {
      return [false, "Blocked by policy: infections detected"];
    }
  }

  // KEV
  if (policy.kev === "block") {
    const kevTotal = stats?.vulnerabilities_stats?.kev?.total || 0;
    if (kevTotal > 0) {
      return [false, "Blocked by policy: KEV vulnerabilities detected"];
    }
  }

  // Weaponized
  if (policy.weaponized === "block") {
    const weaponized = stats?.vulnerabilities_stats?.exploitability?.are_weaponized || 0;
    if (weaponized > 0) {
      return [false, "Blocked by policy: weaponized vulnerabilities detected"];
    }
  }

  // Severity rules
  const severityPolicy = policy.severity || {};
  const severityStats  = stats?.vulnerabilities_stats?.severity || {};

  for (const [sev, action] of Object.entries(severityPolicy)) {
    if (action === "block") {
      if ((severityStats[sev.toLowerCase()] || 0) > 0) {
        return [false, `Blocked by policy: ${sev} severity vulnerabilities detected`];
      }
    }
  }

  return [true, "Policy passed"];
}
