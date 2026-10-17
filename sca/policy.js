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
 *   "block_unknown_license_risk": false,       // separately block packages whose
 *                                              // license couldn't be classified
 *                                              // at all (default: false)
 *   "block_kev": true,                         // block vulnerabilities in the CISA
 *                                              // Known Exploited Vulnerabilities catalog
 *   "epss_threshold": 0.1,                     // block EPSS score >= this (fraction,
 *                                              // 0.1 = 10%); "none" disables
 *   "block_undetermined": false,               // true = block when any component
 *                                              // is "undetermined": no version, or
 *                                              // a source that is not matched
 *                                              // against any vulnerability database
 *                                              // (git / tarball URL / local path,
 *                                              // conda non-Python). Default false.
 *   "reachable_only": false                    // true = the vulnerability rules
 *                                              // (severity, unknown, KEV, EPSS) only
 *                                              // count REACHABLE vulnerabilities;
 *                                              // ones confirmed unreachable are
 *                                              // reported but never block. Default
 *                                              // false. Infections and KEV (while
 *                                              // block_kev is on) always block, and
 *                                              // secrets / license rules are unaffected.
 * }
 *
 * KEV / EPSS are evaluated per vulnerability in engine.js (which records the
 * reasons in vuln.policy_reasons); this file only turns those into a decision.
 * If a feed was unreachable the rule could not fire — the scan still completes
 * and the pass/fail reason says so (see report.threat_intel).
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
 * True when `v` is exempt from the vulnerability rules under `reachable_only`:
 * a non-infection whose reachability analysis confirmed it unreachable.
 * Never exempt: infections, KEV entries while block_kev is on (they always
 * block), and vulnerabilities with no reachability result (fail closed).
 */
function isUnreachableExempt(v, policy) {
  if (v.is_infection) return false;
  if (policy.block_kev !== false && v.is_kev === true) return false;
  return v.reachability?.reachable === false;
}

/**
 * Severity buckets over the vulnerabilities that count under `reachable_only`
 * (same bucketing as the engine's stats: infections are excluded, an
 * unrecognised severity counts as "unknown").
 */
function reachableSeverityStats(vulns, policy) {
  const buckets = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of vulns) {
    if (v.is_infection || isUnreachableExempt(v, policy)) continue;
    const sev = (v.severity || "unknown").toLowerCase();
    buckets[sev in buckets ? sev : "unknown"]++;
  }
  return buckets;
}

/** "a", "a and b", "a, b and c" */
function joinAnd(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}

/**
 * Evaluate policy against a scan report.
 * Returns [allowed: boolean, reason: string]
 *
 * Every rule is evaluated and every violated rule is named in the reason
 * (joined with "; "), in evaluation order: infections, secrets, KEV, EPSS,
 * severity, unknown severity, undetermined, license risk, unknown license.
 * Nothing short-circuits, so the reason never hides a violation behind an
 * earlier one. The reason keeps the "Blocked:" prefix only when every violated
 * rule is an always-enforced one (infections / secrets); otherwise it is
 * "Blocked by policy:".
 *
 * @param {object} report  - Scan report with .stats and .policy fields.
 */
export function evaluatePolicy(report) {
  const stats  = report.stats  || {};
  const policy = report.policy;

  if (!policy) {
    throw new Error("No policy returned by API (fail-closed)");
  }

  const blocks = [];        // one reason fragment per violated rule
  let onlyAlways = true;    // stays true while every fragment is always-enforced
  const block = (text, always = false) => {
    blocks.push(text);
    if (!always) onlyAlways = false;
  };

  // ── 1. Infections / secrets: always blocked, no policy toggle ─────────────
  if ((stats.total_infections || 0) > 0) {
    block("infections detected (always enforced)", true);
  }
  if ((report.secrets?.count || 0) > 0) {
    block("secrets detected (always enforced)", true);
  }

  // ── 1b. Threat intel: CISA KEV, then EPSS ────────────────────────────────
  const vulns = Array.isArray(report.vulnerabilities) ? report.vulnerabilities : [];
  const idsWith = (reason) => [...new Set(
    vulns.filter(v => Array.isArray(v.policy_reasons) && v.policy_reasons.includes(reason)).map(v => v.id)
  )];
  const fmtIds = (ids) => ids.length > 5 ? `${ids.slice(0, 5).join(", ")} and ${ids.length - 5} more` : ids.join(", ");

  // reachable_only: severity / unknown rules count only reachable vulnerabilities.
  // (KEV / EPSS need no change — the engine never tags an exempt vuln with a
  // policy_reason.) Computed from the vulnerability list rather than
  // stats.vulnerabilities_stats, which always reports the full, unfiltered totals.
  const reachableOnly  = policy.reachable_only === true;
  const exemptCount    = reachableOnly ? vulns.filter(v => isUnreachableExempt(v, policy)).length : 0;
  const severityCounts = reachableOnly
    ? reachableSeverityStats(vulns, policy)
    : (stats?.vulnerabilities_stats?.severity || {});
  const scopeNote      = reachableOnly ? ", reachable vulnerabilities only" : "";

  const kevIds = idsWith("kev");
  if (kevIds.length > 0) {
    block(`${kevIds.length} known-exploited (CISA KEV) vulnerabilit${kevIds.length === 1 ? "y" : "ies"} detected: ${fmtIds(kevIds)}`);
  }
  const epssIds = idsWith("epss");
  if (epssIds.length > 0) {
    const pct = parseFloat((Number(policy.epss_threshold) * 100).toFixed(2));
    block(`${epssIds.length} vulnerabilit${epssIds.length === 1 ? "y" : "ies"} with EPSS >= ${pct}% detected: ${fmtIds(epssIds)}`);
  }

  // ── 2. Severity threshold ─────────────────────────────────────────────────
  const rawThreshold = (policy.severity_threshold || "").toLowerCase();
  if (rawThreshold && SEVERITY_ORDER.includes(rawThreshold)) {
    // Highest severity first; every level at/above the threshold with findings is named.
    const hits = [...SEVERITY_ORDER].reverse()
      .filter(level => meetsThreshold(level, rawThreshold) && (severityCounts[level] || 0) > 0);
    if (hits.length > 0) {
      const total = hits.reduce((n, level) => n + severityCounts[level], 0);
      block(
        `${joinAnd(hits.map(level => `${severityCounts[level]} ${level}`))} severity ` +
        `vulnerabilit${total === 1 ? "y" : "ies"} detected (threshold: ${rawThreshold}${scopeNote})`
      );
    }
  }

  // ── 3. Unknown vulnerabilities ────────────────────────────────────────────
  if (policy.block_unknown_vulnerabilities === true) {
    const unknownCount = severityCounts.unknown || 0;
    if (unknownCount > 0) {
      block(`${unknownCount} unknown-severity vulnerabilities detected${reachableOnly ? " (reachable vulnerabilities only)" : ""}`);
    }
  }

  // ── 3b. Undetermined components (opt-in) ─────────────────────────────────
  // A component left "undetermined" was never matched against OSV/NVD (no
  // version, or a git / tarball URL / local-path / conda source), so a clean
  // result says nothing about it. block_undetermined turns that into a block.
  // Not affected by reachable_only: there is no vulnerability to be unreachable.
  if (policy.block_undetermined === true) {
    const undet = (Array.isArray(report.inventory) ? report.inventory : [])
      .filter(c => c && c.state === "undetermined");
    const count = undet.length || (stats?.inventory_stats?.undetermined || 0);
    if (count > 0) {
      const names = [...new Set(undet.map(c => c.name || c.id).filter(Boolean))];
      const shown = names.length > 5 ? `${names.slice(0, 5).join(", ")} and ${names.length - 5} more` : names.join(", ");
      block(`${count} component${count === 1 ? "" : "s"} could not be checked against any vulnerability database (undetermined)${shown ? `: ${shown}` : ""}`);
    }
  }

  // ── 4. License risk (health-mode scans only; see engine.js) ──────────────
  const rawLicenseThreshold = (policy.license_risk_threshold || "none").toLowerCase();
  if (rawLicenseThreshold !== "none" && LICENSE_RISK_ORDER.includes(rawLicenseThreshold)) {
    const byRisk = stats?.license_stats?.by_risk || {};

    for (const level of LICENSE_RISK_ORDER) {
      if (meetsLicenseRiskThreshold(level, rawLicenseThreshold) && (byRisk[level] || 0) > 0) {
        block(
          `${byRisk[level]} package(s) with ${level} license risk detected ` +
          `(threshold: ${rawLicenseThreshold})`
        );
      }
    }
  }

  // ── 5. Unknown license risk (health-mode scans only; separate opt-in) ────
  if (policy.block_unknown_license_risk === true) {
    const unknownLicenseCount = stats?.license_stats?.by_risk?.unknown || 0;
    if (unknownLicenseCount > 0) {
      block(`${unknownLicenseCount} package(s) with unclassified license risk detected`);
    }
  }

  if (blocks.length > 0) {
    return [false, `${onlyAlways ? "Blocked" : "Blocked by policy"}: ${blocks.join("; ")}`];
  }

  // Passed — but say so if KEV/EPSS couldn't be checked, so a pass is never
  // mistaken for "checked and clean".
  const ti = report.threat_intel || {};
  const unavailable = [];
  if (ti.kev?.status === "unavailable")  unavailable.push("CISA KEV");
  if (ti.epss?.status === "unavailable") unavailable.push("EPSS");
  if (ti.epss?.status === "partial")     unavailable.push("EPSS (partial)");
  const notes = [];
  if (unavailable.length > 0) notes.push(`${unavailable.join(" and ")} data unavailable — not enforced for this scan`);
  if (exemptCount > 0) notes.push(`${exemptCount} unreachable vulnerabilit${exemptCount === 1 ? "y" : "ies"} not evaluated (reachable_only)`);
  if (notes.length > 0) return [true, `Policy passed (note: ${notes.join("; ")})`];

  return [true, "Policy passed"];
}