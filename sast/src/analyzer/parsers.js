'use strict';

// ─── Response parsers ──────────────────────────────────────────────────────────

function parseFindings(raw) {
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  try {
    const parsed   = JSON.parse(cleaned);
    const findings = Array.isArray(parsed?.findings) ? parsed.findings : [];

    return findings
      .filter(f => f && typeof f === 'object')
      .map(f => ({
        vuln_name:    String(f.vuln_name    || 'unknown').trim(),
        description:  String(f.description  || '').trim(),
        code_snippet: String(f.code_snippet || '').trim(),
        severity:     ['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'unknown',
        confidence:   ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'low',
        fix:          String(f.fix          || '').trim(),
      }))
      .filter(f => f.vuln_name !== 'unknown' && f.description.length > 0);

  } catch {
    return [{ _parse_error: true, raw: cleaned.slice(0, 300) }];
  }
}

function parseVerification(raw) {
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch (e) {
    // Model response was not valid JSON at all (prose, truncated output, etc.)
    return {
      is_valid: null,
      reason: null,
      error: { stage: 'verify', reason: 'invalid_json', detail: e.message },
    };
  }

  const reason = typeof parsed?.reason === 'string' ? parsed.reason : null;
  if (typeof parsed?.is_valid !== 'boolean') {
    // JSON parsed fine, but the model didn't return the requested field/shape —
    // distinct from a parse failure: we got an answer, just not a usable one.
    return {
      is_valid: null,
      reason,
      error: { stage: 'verify', reason: 'missing_is_valid_field', detail: cleaned.slice(0, 200) },
    };
  }
  return { is_valid: parsed.is_valid, reason, error: null };
}

function parseTaintTrace(raw) {
  let cleaned = raw.trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();

  try {
    const parsed = JSON.parse(cleaned);
    return {
      reachable:   typeof parsed?.reachable   === 'boolean' ? parsed.reachable   : null,
      sanitized:   typeof parsed?.sanitized   === 'boolean' ? parsed.sanitized   : null,
      bypassed:    typeof parsed?.bypassed    === 'boolean' ? parsed.bypassed    : null,
      exploitable: typeof parsed?.exploitable === 'boolean' ? parsed.exploitable : null,
      flow_path:   typeof parsed?.flow_path   === 'string'  ? parsed.flow_path   : null,
      reasoning:   typeof parsed?.reasoning   === 'string'  ? parsed.reasoning   : null,
      error: null,
    };
  } catch (e) {
    return {
      reachable: null, sanitized: null, bypassed: null, exploitable: null,
      flow_path: null, reasoning: null,
      error: { stage: 'taint', reason: 'invalid_json', detail: e.message },
    };
  }
}

export { parseFindings, parseVerification, parseTaintTrace };
