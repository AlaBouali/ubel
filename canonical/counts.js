'use strict';
// canonical/counts.js — the ONE place the canonical report's counts are computed, with no dependencies (like ./types.js), so that
// canonical/common.js buildStats(), canonical/html.js (reports written before these counts existed) and the tests all use the same code.
// The Stats tab and the Dashboard (canonical/client/shell.js) render these numbers and recompute none of them.
//
// Every count below is an object whose FIXED keys are always present (0 when nothing matches, so a report with no critical finding says
// `critical: 0`, not nothing), followed by every other value found, in order of appearance ("all other types").
//
//   stats.findings
//     total
//     by_severity    critical · high · medium · low · info · unknown                  ('none' counts as info, anything unrecognised as unknown)
//     by_status      reachable · non reachable · false positive                         (finding.status; any other status follows)
//     by_verification verified · false_positive · unverified                            (details.is_valid: true · false · no verification result)
//     by_policy      violates_policy · policy_safe · not_evaluated                      (finding.violate_policy: true · false · null)
//     by_kev         kev · non_kev · unknown                                            (advisories only: details.is_kev true · false · not known)
//     by_type        every active finding type (see ./types.js), then any other         ("findings categories (all)")
//     by_confidence  high · medium · low · unknown
//     reachable_actionable   reachable findings that are not informational: the "Reachable / Exploitable" figure of the Dashboard
//     violating_policy       = by_policy.violates_policy (kept: older consumers read this name)
//   stats.inventory
//     total
//     by_status      vulnerable · infected · not_queried · safe                         (see INVENTORY_STATE_ALIASES; any other state follows)
//     by_policy      violates_policy · policy_safe · not_evaluated
//     by_type        component types as found
//     violating_policy       = by_policy.violates_policy

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];

// finding.status. Owned here (dependency-free); canonical/common.js re-exports it.
//   "reachable"       the finding applies: the original says it is reachable / exploitable, or makes no claim either way
//   "non reachable"   the original says it is NOT reachable / exploitable (SCA / EASM `reachability.reachable === false`,
//                     SAST `taint.reachable === false` or `taint.exploitable === false`)
//   "false positive"  the original says it is not a real issue (SAST / malware `is_valid === false`)
export const STATUS = { REACHABLE: 'reachable', NON_REACHABLE: 'non reachable', FALSE_POSITIVE: 'false positive' };
export const FINDING_STATUSES = [STATUS.REACHABLE, STATUS.NON_REACHABLE, STATUS.FALSE_POSITIVE];

export const VERIFICATION = ['verified', 'false_positive', 'unverified'];
export const POLICY = ['violates_policy', 'policy_safe', 'not_evaluated'];
export const KEV = ['kev', 'non_kev', 'unknown'];
export const CONFIDENCES = ['high', 'medium', 'low', 'unknown'];

// Finding types that exist today. `infection` and `code` are retired (types.js): they are counted when a canonical file written earlier
// holds them, but are not listed at 0 in a new report. Kept in step with TYPES by tests/canonical-counts.test.js.
export const ACTIVE_FINDING_TYPES = ['vuln', 'sc_vuln', 'sc_infection', 'secret', 'mal', 'misconfig', 'hardening', 'integrity', 'behavior', 'exposure', 'license', 'coverage'];

// An inventory component's state, as the canonical report counts it. The four fixed keys are what every scanner can say about a component;
// the module-specific states (misconfigured, non_compliant, at_risk, running, listening, scanned, assessed, observed, unknown …) are counted
// under their own names after them. Only words that mean the same thing are merged:
//   safe          ← clean (SCA, EASM, app scans), compliant (vm / k8s), safe
//   not_queried   ← undetermined (the SCA / EASM engines: the component was never matched against an advisory database),
//                   not_queryable (app scans: no exact, supported package URL), not_queried
export const INVENTORY_STATES = ['vulnerable', 'infected', 'not_queried', 'safe'];
export const INVENTORY_STATE_ALIASES = {
  clean: 'safe', compliant: 'safe',
  undetermined: 'not_queried', not_queryable: 'not_queried', 'not queried': 'not_queried', 'not-queried': 'not_queried',
};
export const stateKey = (s) => {
  const v = String(s ?? 'unknown').trim().toLowerCase() || 'unknown';
  return INVENTORY_STATE_ALIASES[v] ?? v;
};

export const severityKey = (s) => {
  const v = String(s ?? 'unknown').toLowerCase();
  if (SEVERITIES.includes(v)) return v;
  if (v === 'none' || v === 'informational') return 'info';
  if (v === 'moderate') return 'medium';
  return 'unknown';
};

// An advisory on a third-party component (the only findings a KEV listing applies to).
const ADVISORY_TYPES = new Set(['sc_vuln', 'sc_infection', 'infection']);

const zero = (keys) => { const o = {}; for (const k of keys) o[k] = 0; return o; };
const bump = (o, k, n = 1) => { o[k] = (o[k] || 0) + n; };
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

const policyKey = (v) => (v === true ? 'violates_policy' : v === false ? 'policy_safe' : 'not_evaluated');

const verificationKey = (f) => {
  const v = isObj(f.details) ? f.details.is_valid : undefined;
  return v === true ? 'verified' : v === false ? 'false_positive' : 'unverified';
};

const kevKey = (f) => {
  const v = isObj(f.details) ? f.details.is_kev : undefined;
  if (v === true) return 'kev';
  if (v === false) return 'non_kev';
  return ADVISORY_TYPES.has(f.type) ? 'unknown' : null;   // an advisory whose KEV listing is not known; anything else is not a KEV question
};

export function buildCounts(findings, inventory) {
  const F = Array.isArray(findings) ? findings : [];
  const I = Array.isArray(inventory) ? inventory : [];

  const fc = {
    by_severity: zero(SEVERITIES), by_status: zero(FINDING_STATUSES), by_verification: zero(VERIFICATION), by_policy: zero(POLICY),
    by_kev: zero(KEV), by_type: zero(ACTIVE_FINDING_TYPES), by_confidence: zero(CONFIDENCES),
  };
  let reachableActionable = 0;
  for (const f of F) {
    const sv = severityKey(f.severity);
    bump(fc.by_severity, sv);
    bump(fc.by_status, f.status ?? STATUS.REACHABLE);
    bump(fc.by_verification, verificationKey(f));
    bump(fc.by_policy, policyKey(f.violate_policy));
    const kv = kevKey(f); if (kv) bump(fc.by_kev, kv);
    bump(fc.by_type, f.type ?? 'unknown');
    bump(fc.by_confidence, f.confidence == null || f.confidence === '' ? 'unknown' : String(f.confidence).toLowerCase());
    if ((f.status ?? STATUS.REACHABLE) === STATUS.REACHABLE && sv !== 'info') reachableActionable++;   // informational findings (normal behaviors, passed checks) are not alarms
  }

  const ic = { by_status: zero(INVENTORY_STATES), by_policy: zero(POLICY), by_type: {} };
  for (const c of I) {
    bump(ic.by_status, stateKey(c.status));
    bump(ic.by_policy, policyKey(c.violate_policy));
    bump(ic.by_type, c.type ?? 'unknown');
  }

  return {
    findings: { total: F.length, ...fc, reachable_actionable: reachableActionable, violating_policy: fc.by_policy.violates_policy },
    inventory: { total: I.length, ...ic, violating_policy: ic.by_policy.violates_policy },
  };
}
