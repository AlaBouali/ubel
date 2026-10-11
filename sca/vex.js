// vex.js — one decision for "does reachability let us call this finding not affected?",
// shared by the CycloneDX VEX analysis (sbom_builder.js) and the SARIF level/suppression
// (sarif_builder.js), so the two formats can never disagree.
//
// A finding is only ever "not_affected" when ALL of these hold:
//   • it is not an infection (malware record),
//   • it is not listed in CISA KEV — exploited in the wild, so a static "unreachable"
//     verdict (e.g. no import found) must never downgrade it,
//   • reachability says reachable === false with high or medium confidence.
//
// CycloneDX `justification` values used (not_affected only):
//   code_not_present   the package is scoped to dev/test and is not part of the production build
//   code_not_reachable no import of the package (or of a parent that carries it) in project source

const CONFIDENT = new Set(["high", "medium"]);

/** True when reachability confidently rules the finding out and nothing overrides it. */
export function isNotAffected(v) {
  if (!v || v.is_infection) return false;
  if (v.is_kev === true) return false;
  const r = v.reachability;
  return !!(r && r.reachable === false && CONFIDENT.has(r.confidence));
}

/** CycloneDX analysis.justification for a not-affected finding. */
export function notAffectedJustification(v) {
  const tags = (v && v.reachability && v.reachability.tags) || [];
  return tags.includes("dev_scope") ? "code_not_present" : "code_not_reachable";
}

/**
 * CycloneDX `analysis` object for a finding.
 * not_affected carries a `justification` and no `response` (a remediation response such as
 * will_not_fix describes what the vendor does about an affected product — not this case).
 */
export function vexAnalysis(v) {
  const reach = v && v.reachability;
  const detail = reach && reach.rationale ? { detail: reach.rationale } : {};
  if (v && v.is_infection) {
    return { state: "exploitable", response: ["rollback", "can_not_fix"], ...detail };
  }
  if (isNotAffected(v)) {
    return { state: "not_affected", justification: notAffectedJustification(v), ...detail };
  }
  return { state: "exploitable", response: ["update"], ...detail };
}
