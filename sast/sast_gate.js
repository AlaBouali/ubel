// sast/sast_gate.js
//
// The single definition of "does this run pass?" for ubel-sast and ubel-mal.
//
// Two places need the answer and must never disagree:
//   - main.js, which turns it into the process exit code, and
//   - executive_summary.js, which states it on page 1 of the report.
// Both call evaluateSastGate() with the same inputs, so the verdict a reader
// sees is exactly what CI saw. The rules below are a faithful extraction of the
// logic that used to live inline in main.js (writeAnalyzeReports /
// writeMalwareReports); behaviour is unchanged.
//
//   analyze  --fail-on exploitable : exploitable || not cleared
//            --fail-on valid       : confirmed real || exploitable || not cleared
//            --fail-on any (dflt)  : as `valid`, plus: any finding at all when
//                                    BOTH verification and the exploitability
//                                    check were switched off
//   malware  --fail-on confirmed   : confirmed malicious || not cleared
//            --fail-on any (dflt)  : ANY candidate finding, including ones the
//                                    verification pass dismissed as false alarms
//
// "Not cleared" = a pass errored or was inconclusive. It is neither confirmed
// nor dismissed, so it fails the gate rather than slipping through as clean.

const liveFindings = (results) =>
  (Array.isArray(results) ? results : [])
    .flatMap((r) => (Array.isArray(r?.findings) ? r.findings : []))
    .filter((f) => f && !f._parse_error);

// ubel-sast: a finding no check could settle either way.
export function isUnresolvedSastFinding(f) {
  return f.taint?.exploitable !== true &&
    !(f.is_valid === true && f.taint?.exploitable === false) &&
    !(f.is_valid === false) &&
    !!(f.verification_error || f.taint?.error || f.taint?.inconclusive_reason || f.is_valid === null);
}

// ubel-mal: anything verification did not decide.
export function isUnresolvedMalwareFinding(f) {
  return f.is_valid !== true && f.is_valid !== false;
}

// Plain-language statement of each rule, for the report (no flags in the text).
const RULE_TEXT = {
  analyze: {
    exploitable: "The run fails when a weakness is confirmed exploitable, or when a finding could not be settled either way.",
    valid: "The run fails when a weakness is confirmed real or exploitable, or when a finding could not be settled either way.",
    any: "The run fails when a weakness is confirmed real or exploitable, or when a finding could not be settled either way. It also fails if any finding exists while both verification and the exploitability check were switched off.",
  },
  malware: {
    confirmed: "The run fails when code is confirmed malicious, or when a finding could not be settled either way.",
    any: "The run fails when any candidate finding exists, including candidates that verification later dismissed as false alarms.",
  },
};

/**
 * @param results  array of chunk results ({ findings: [...] })
 * @param opts     { mode: 'analyze'|'malware', failOn, verify, taintTrace }
 *                 verify / taintTrace are booleans (the CLI normalises them
 *                 before any report is written).
 * @returns { shouldFail, failOn, rule, counts, triggers }
 *          triggers = the conditions that actually tripped the gate, as
 *          { key, count, text } with plain-language text. They never overlap,
 *          so their counts can be added up.
 */
export function evaluateSastGate(results, { mode = "analyze", failOn, verify, taintTrace } = {}) {
  const mal = mode === "malware";
  const fo = failOn || "any";
  const all = liveFindings(results);

  let shouldFail, counts, triggers = [];

  if (mal) {
    const confirmed = all.filter((f) => f.is_valid === true).length;
    const unresolved = all.filter(isUnresolvedMalwareFinding).length;
    const dismissed = all.filter((f) => f.is_valid === false).length;
    counts = { candidates: all.length, confirmed, exploitable: 0, unresolved, dismissed };
    if (fo === "confirmed") {
      shouldFail = confirmed > 0 || unresolved > 0;
      if (confirmed) triggers.push({ key: "confirmed", count: confirmed, text: `${confirmed} confirmed malicious-code ${confirmed === 1 ? "finding" : "findings"}` });
      if (unresolved) triggers.push({ key: "unresolved", count: unresolved, text: `${unresolved} ${unresolved === 1 ? "finding" : "findings"} not cleared either way` });
    } else {
      shouldFail = all.length > 0;
      if (all.length) triggers.push({ key: "any_candidate", count: all.length, text: `${all.length} candidate ${all.length === 1 ? "finding" : "findings"} raised` + (dismissed ? ` (${dismissed} later dismissed as false ${dismissed === 1 ? "alarm" : "alarms"})` : "") });
    }
    const rule = RULE_TEXT.malware[fo === "confirmed" ? "confirmed" : "any"];
    return { shouldFail, failOn: fo, rule, counts, triggers };
  }

  const exploitable = all.filter((f) => f.taint?.exploitable === true).length;
  const valid = all.filter((f) => f.is_valid === true).length;
  const unresolved = all.filter(isUnresolvedSastFinding).length;
  const withoutPasses = !verify && !taintTrace && all.length > 0;
  counts = { candidates: all.length, confirmed: exploitable, exploitable, valid, unresolved, dismissed: all.filter((f) => f.is_valid === false).length };

  switch (fo) {
    case "exploitable":
      shouldFail = exploitable > 0 || unresolved > 0;
      break;
    case "valid":
      shouldFail = valid > 0 || exploitable > 0 || unresolved > 0;
      break;
    case "any":
    default:
      shouldFail = exploitable > 0 || valid > 0 || withoutPasses || unresolved > 0;
      break;
  }

  // What actually tripped the gate, in plain words. `valid` overlaps
  // `exploitable`, so only the confirmed-real remainder is listed separately.
  const countsValid = fo !== "exploitable";
  if (exploitable) triggers.push({ key: "exploitable", count: exploitable, text: `${exploitable} confirmed exploitable ${exploitable === 1 ? "issue" : "issues"}` });
  if (countsValid) {
    // Disjoint from the other two: a real finding whose exploitability trace was
    // inconclusive is reported as "not cleared", the same way the summary does.
    const realOnly = all.filter((f) => f.is_valid === true && f.taint?.exploitable !== true && !isUnresolvedSastFinding(f)).length;
    if (realOnly) triggers.push({ key: "valid", count: realOnly, text: `${realOnly} ${realOnly === 1 ? "issue" : "issues"} confirmed real` });
  }
  if (unresolved) triggers.push({ key: "unresolved", count: unresolved, text: `${unresolved} ${unresolved === 1 ? "finding" : "findings"} not cleared either way` });
  if (fo !== "exploitable" && fo !== "valid" && withoutPasses && !triggers.length) {
    triggers.push({ key: "unchecked", count: all.length, text: `${all.length} ${all.length === 1 ? "finding" : "findings"} reported with no verification or exploitability check` });
  }

  const rule = RULE_TEXT.analyze[fo === "exploitable" || fo === "valid" ? fo : "any"];
  return { shouldFail, failOn: fo, rule, counts, triggers };
}