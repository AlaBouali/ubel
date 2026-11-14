'use strict';

/**
 * Shared AWS policy-document helpers.
 *
 * Extracted from checks/aws-checks.js so the extended checks
 * (checks/aws-extended-checks.js -- Lambda, KMS, ...) can reuse exactly the same
 * "is this Allow statement really public?" logic without a circular import
 * between the two check modules. Behaviour is unchanged for the callers that
 * already existed (IAM full-admin, SNS, SQS).
 *
 * The reasoning for the Condition allowlist (why a blanket "any Condition
 * downgrades this" rule is a false-negative trap) lives with SAFE_CONDITION_KEYS.
 */

function toArray(v) {
  if (v === undefined || v === null) return [];
  return Array.isArray(v) ? v : [v];
}

// A Condition block only downgrades a finding when it is built *entirely*
// from keys that meaningfully restrict who can use the grant. aws:RequestedRegion
// or an unevaluated aws:PrincipalTag barely restrict anything, so a dangerous
// policy with *some* condition on it must not slip past --min-severity / --fail-on.
const SAFE_CONDITION_KEYS = new Set([
  'aws:sourceip',
  'aws:sourcevpc',
  'aws:sourcevpce',
  'aws:principalarn',
  'aws:principalorgid',
  'aws:principalaccount',
  'aws:multifactorauthpresent',
]);

// KMS key policies routinely pair `Principal: "*"` with these two keys (the
// pattern AWS itself uses for service-integrated keys): the caller must belong
// to the owning account, or be going through a specific AWS service.
const KMS_SAFE_CONDITION_KEYS = new Set(['kms:calleraccount', 'kms:viaservice']);

function conditionKeys(condition) {
  const keys = [];
  for (const operatorBlock of Object.values(condition || {})) {
    if (operatorBlock && typeof operatorBlock === 'object') keys.push(...Object.keys(operatorBlock));
  }
  return keys;
}

/** True only if EVERY key used across every operator in the Condition block is
 * in the known-restrictive allowlist (plus, optionally, `extraSafeKeys`, a Set
 * of lowercase key names) -- one unknown/weak key alongside a safe one is enough
 * to withhold the downgrade, since without a real policy simulator we can't tell
 * whether the operators are AND'd or effectively OR'd. */
function isConditionSafelyRestrictive(condition, extraSafeKeys) {
  const keys = conditionKeys(condition);
  if (keys.length === 0) return false;
  return keys.every((k) => {
    const lk = k.toLowerCase();
    return SAFE_CONDITION_KEYS.has(lk) || (extraSafeKeys ? extraSafeKeys.has(lk) : false);
  });
}

/** Rank used to pick the single "worst" statement match to report per policy:
 * unconditional (0) is worse than an unrecognized/weak condition (1), which is
 * worse than a safely-restrictive one (2). */
function conditionMatchRank(m) {
  if (!m.hasCondition) return 0;
  if (!m.conditionIsSafeAllowlisted) return 1;
  return 2;
}

function worstConditionMatch(matches) {
  return matches.reduce((best, m) => (conditionMatchRank(m) < conditionMatchRank(best) ? m : best), matches[0]);
}

/** Whether an IAM Principal element (identity-policy trust doc OR a
 * resource-based policy like an SNS/SQS/Lambda/KMS policy) is a bare wildcard --
 * Principal:"*" or Principal:{"AWS":"*"}. */
function principalIsWildcard(principal) {
  if (principal === '*') return true;
  if (principal && typeof principal === 'object') {
    const awsPrincipals = toArray(principal.AWS).map(String);
    if (awsPrincipals.includes('*')) return true;
  }
  return false;
}

/** Allow statements in a resource-based policy whose Principal is a bare
 * wildcard. `extraSafeKeys` is forwarded to isConditionSafelyRestrictive. */
function findPublicPrincipalStatements(doc, extraSafeKeys) {
  const statements = toArray(doc?.Statement);
  const matches = [];
  for (const stmt of statements) {
    if (stmt.Effect !== 'Allow') continue;
    if (!principalIsWildcard(stmt.Principal)) continue;
    const hasCondition = Boolean(stmt.Condition && Object.keys(stmt.Condition).length > 0);
    matches.push({
      hasCondition,
      conditionIsSafeAllowlisted: hasCondition && isConditionSafelyRestrictive(stmt.Condition, extraSafeKeys),
      conditionKeys: hasCondition ? conditionKeys(stmt.Condition).map((k) => k.toLowerCase()) : [],
      actions: toArray(stmt.Action).map(String),
    });
  }
  return matches;
}

function addPublicResourcePolicyFinding(reporter, { service, check, resource, region, resourceLabel, remediation, match }) {
  let severity;
  let note = '';
  if (!match.hasCondition) {
    severity = 'high';
  } else if (match.conditionIsSafeAllowlisted) {
    severity = 'medium';
    note = ' A Condition key restricted to keys known to meaningfully constrain access (source IP/VPC, principal ARN/org/account, MFA) is present, which narrows this grant.';
  } else {
    severity = 'high';
    note = " A Condition key is present, but it isn't built entirely from keys known to meaningfully restrict access — treat this as effectively public until the condition is reviewed by hand.";
  }
  reporter.add({
    provider: 'aws',
    service,
    check,
    severity,
    action: `${service}-restrict-resource-policy`,
    title: `${resourceLabel} resource policy grants access to anyone (Principal: "*")`,
    resource,
    region,
    description: `The resource policy has an Allow statement with Principal "*" for action(s): ${match.actions.join(', ') || '(none listed)'}.${note}`,
    remediation,
  });
}

export {
  toArray,
  SAFE_CONDITION_KEYS,
  KMS_SAFE_CONDITION_KEYS,
  conditionKeys,
  isConditionSafelyRestrictive,
  conditionMatchRank,
  worstConditionMatch,
  principalIsWildcard,
  findPublicPrincipalStatements,
  addPublicResourcePolicyFinding,
};
