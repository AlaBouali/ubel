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
//
// The same holds for CODE that never got a verdict. "No findings" only means
// "clean" for code that actually went through the scan, so a run that lost
// coverage fails under every --fail-on setting (see coverageLoss below):
//   - a chunk whose scan request failed (error.stage === "scan"; findings: [])
//   - a chunk whose reply could not be decoded (a _parse_error placeholder)
//   - a chunk whose reply was cut off, so findings after the cut-off may be missing
//   - files skipped for exceeding --max-file-size
//   - chunks dropped by the DEFAULT per-run chunk limit (not a --max-chunks the
//     caller chose themselves)
// Scope the caller chose on purpose (--only-diff, --skip-folders, --skip-files,
// --languages, --chunks-start/--max-chunks, generated files) is not a loss.

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

// What the run failed to cover, as { key, count, text } — the same shape as a trigger.
// Chunk-level facts come from the chunk results themselves; the two limits the
// chunker measures come from the recorded scan options (scanOptions), which main.js
// and the executive summary both hold, so they always see the same numbers.
function coverageLoss(results, scanOptions) {
  const chunks = Array.isArray(results) ? results : [];
  const so = scanOptions || {};
  const unit = (n) => `${n} code ${n === 1 ? "unit" : "units"}`;
  const out = [];

  const failed = chunks.filter((r) => r?.error).length;
  if (failed) out.push({ key: "scan_failed", count: failed, text: `${unit(failed)} could not be analyzed because the AI request failed` });

  const unreadable = chunks.filter((r) => !r?.error && Array.isArray(r?.findings) && r.findings.some((f) => f && f._parse_error)).length;
  if (unreadable) out.push({ key: "unreadable", count: unreadable, text: `${unit(unreadable)} could not be analyzed because the AI reply was unreadable` });

  const partial = chunks.filter((r) => r?.partial_output && !r?.error).length;
  if (partial) out.push({ key: "partial_output", count: partial, text: `${unit(partial)} had an AI reply that was cut off, so findings may be missing` });

  const tooLarge = Number.isFinite(so.files_skipped_too_large_count) ? so.files_skipped_too_large_count : 0;
  if (tooLarge > 0) out.push({ key: "files_skipped", count: tooLarge, text: `${tooLarge} ${tooLarge === 1 ? "file" : "files"} skipped for exceeding the file-size limit` });

  // Only the implicit limit is a loss; an explicit --max-chunks is a scope the caller set.
  const dropped = Number.isFinite(so.chunks_dropped_by_cap) && !so.max_chunks ? so.chunks_dropped_by_cap : 0;
  if (dropped > 0) out.push({ key: "chunks_dropped", count: dropped, text: `${unit(dropped)} never scanned because the default per-run limit was reached` });

  return out;
}

// The trigger keys that mean "code was not analyzed" (as opposed to a finding that tripped the rule).
export const COVERAGE_TRIGGER_KEYS = new Set(["scan_failed", "unreadable", "partial_output", "files_skipped", "chunks_dropped"]);

const COVERAGE_RULE = " It also fails when part of the code was not analyzed (a failed or unreadable AI call, a cut-off reply, a file skipped for size, or code dropped by the default per-run limit), because absent findings there are not evidence of a clean result.";

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
 * @param opts     { mode: 'analyze'|'malware', failOn, verify, taintTrace, scanOptions }
 *                 verify / taintTrace are booleans (the CLI normalises them
 *                 before any report is written). scanOptions is the recorded
 *                 meta.scan_options (for files skipped / chunks dropped).
 * @returns { shouldFail, failOn, rule, counts, triggers }
 *          triggers = the conditions that actually tripped the gate, as
 *          { key, count, text } with plain-language text. They never overlap,
 *          so their counts can be added up.
 */
export function evaluateSastGate(results, { mode = "analyze", failOn, verify, taintTrace, scanOptions } = {}) {
  const mal = mode === "malware";
  const fo = failOn || "any";
  const all = liveFindings(results);
  const loss = coverageLoss(results, scanOptions);
  const lossTotal = loss.reduce((n, l) => n + l.count, 0);

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
    if (loss.length) { shouldFail = true; triggers.push(...loss); }
    counts.not_covered = lossTotal;
    const rule = RULE_TEXT.malware[fo === "confirmed" ? "confirmed" : "any"] + COVERAGE_RULE;
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

  if (loss.length) { shouldFail = true; triggers.push(...loss); }
  counts.not_covered = lossTotal;

  const rule = RULE_TEXT.analyze[fo === "exploitable" || fo === "valid" ? fo : "any"] + COVERAGE_RULE;
  return { shouldFail, failOn: fo, rule, counts, triggers };
}