'use strict';

// ─── Response parsers ──────────────────────────────────────────────────────────

function stripFences(raw) {
  let cleaned = String(raw ?? '').trim();
  cleaned = cleaned.replace(/^```(?:json)?\s*/i, '').replace(/\s*```$/i, '').trim();
  return cleaned;
}

// ─── Partial-JSON salvage ─────────────────────────────────────────────────────
// When the model's reply is cut off by the output-token limit, the JSON is
// unterminated but every finding BEFORE the cut is still complete. Rather than
// paying for a second, doubled-budget call, pull those complete objects out.

// True when the text ends inside an open string / object / array — i.e. it was
// cut off, as opposed to being complete-but-wrong (prose, markdown, bad escape).
function looksTruncated(text) {
  let depth = 0, inStr = false, esc = false, started = false;
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '{' || ch === '[') { depth++; started = true; }
    else if (ch === '}' || ch === ']') depth--;
  }
  return started && (inStr || depth > 0);
}

// Returns every COMPLETE top-level object inside the array stored under `key`
// (or the first array found, if the key is absent). Never throws.
function salvageArrayObjects(text, key = 'findings') {
  let i = 0;
  const keyIdx = text.indexOf(`"${key}"`);
  i = text.indexOf('[', keyIdx >= 0 ? keyIdx : 0);
  if (i < 0) return [];
  i++;

  const out = [];
  let depth = 0, inStr = false, esc = false, objStart = -1;
  for (; i < text.length; i++) {
    const ch = text[i];
    if (inStr) {
      if (esc) esc = false;
      else if (ch === '\\') esc = true;
      else if (ch === '"') inStr = false;
      continue;
    }
    if (ch === '"') { inStr = true; continue; }
    if (ch === '{') { if (depth === 0) objStart = i; depth++; }
    else if (ch === '}') {
      depth--;
      if (depth === 0 && objStart >= 0) {
        try { out.push(JSON.parse(text.slice(objStart, i + 1))); } catch { /* skip malformed object */ }
        objStart = -1;
      }
      if (depth < 0) break;
    } else if (ch === ']' && depth === 0) break;
  }
  return out;
}

function normalizeFinding(f) {
  const out = {
    vuln_name:    String(f.vuln_name    || 'unknown').trim(),
    description:  String(f.description  || '').trim(),
    code_snippet: String(f.code_snippet || '').trim(),
    severity:     ['critical', 'high', 'medium', 'low'].includes(f.severity) ? f.severity : 'unknown',
    confidence:   ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'low',
    fix:          String(f.fix          || '').trim(),
  };
  // Present only in packed (multi-chunk) calls; consumed by analyzeSast and removed.
  if (f.chunk_id !== undefined && f.chunk_id !== null) out.chunk_id = String(f.chunk_id).trim();
  return out;
}

function normalizeFindings(list) {
  return list
    .filter(f => f && typeof f === 'object')
    .map(normalizeFinding)
    .filter(f => f.vuln_name !== 'unknown' && f.description.length > 0);
}

/**
 * Detailed parse of a Pass-1 reply.
 *   { findings, truncated, salvaged }
 *   findings  — normalized findings, or [{ _parse_error: true, raw }] when unusable
 *   truncated — the reply was cut off mid-JSON
 *   salvaged  — truncated, but ≥1 complete finding was recovered and is returned
 */
function parseFindingsDetailed(raw) {
  const cleaned = stripFences(raw);

  try {
    const parsed = JSON.parse(cleaned);
    const findings = Array.isArray(parsed?.findings) ? parsed.findings : [];
    return { findings: normalizeFindings(findings), truncated: false, salvaged: false };
  } catch {
    const truncated = looksTruncated(cleaned);
    if (truncated) {
      const recovered = normalizeFindings(salvageArrayObjects(cleaned, 'findings'));
      if (recovered.length > 0) return { findings: recovered, truncated: true, salvaged: true };
    }
    return {
      findings: [{ _parse_error: true, raw: cleaned.slice(0, 300), ...(truncated ? { truncated: true } : {}) }],
      truncated,
      salvaged: false,
    };
  }
}

// Backwards-compatible: just the findings array.
function parseFindings(raw) {
  return parseFindingsDetailed(raw).findings;
}

// ─── Verification (Pass 2) ────────────────────────────────────────────────────

function normalizeVerification(parsed, cleaned) {
  const reason = typeof parsed?.reason === 'string' ? parsed.reason : null;
  if (typeof parsed?.is_valid !== 'boolean') {
    // JSON parsed fine, but the model didn't return the requested field/shape —
    // distinct from a parse failure: we got an answer, just not a usable one.
    return {
      is_valid: null,
      reason,
      error: { stage: 'verify', reason: 'missing_is_valid_field', detail: String(cleaned ?? JSON.stringify(parsed)).slice(0, 200) },
    };
  }
  return { is_valid: parsed.is_valid, reason, error: null };
}

function parseVerification(raw) {
  const cleaned = stripFences(raw);

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
  return normalizeVerification(parsed, cleaned);
}

// Batched verification: expects {"results":[{index,is_valid,reason},…]} (a bare
// array is accepted too). Returns an array of length `count`; an entry is null
// when the model left that index out or it was unusable — the caller re-asks
// for exactly those findings one by one.
function parseVerificationBatch(raw, count) {
  const cleaned = stripFences(raw);
  const slots = new Array(count).fill(null);
  let parsed;
  try { parsed = JSON.parse(cleaned); } catch {
    const part = looksTruncated(cleaned) ? salvageArrayObjects(cleaned, 'results') : [];
    parsed = { results: part };
  }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.results) ? parsed.results : [];
  for (const item of list) {
    const idx = Number.isInteger(item?.index) ? item.index : parseInt(item?.index, 10);
    if (!Number.isInteger(idx) || idx < 0 || idx >= count || slots[idx]) continue;
    const r = normalizeVerification(item, null);
    if (r.error) continue;          // unusable entry → leave null → single-call fallback
    slots[idx] = r;
  }
  return slots;
}

// ─── Taint trace (Pass 3) ─────────────────────────────────────────────────────

function normalizeTaint(parsed) {
  return {
    reachable:   typeof parsed?.reachable   === 'boolean' ? parsed.reachable   : null,
    sanitized:   typeof parsed?.sanitized   === 'boolean' ? parsed.sanitized   : null,
    bypassed:    typeof parsed?.bypassed    === 'boolean' ? parsed.bypassed    : null,
    exploitable: typeof parsed?.exploitable === 'boolean' ? parsed.exploitable : null,
    flow_path:   typeof parsed?.flow_path   === 'string'  ? parsed.flow_path   : null,
    reasoning:   typeof parsed?.reasoning   === 'string'  ? parsed.reasoning   : null,
    error: null,
  };
}

function parseTaintTrace(raw) {
  const cleaned = stripFences(raw);

  try {
    return normalizeTaint(JSON.parse(cleaned));
  } catch (e) {
    return {
      reachable: null, sanitized: null, bypassed: null, exploitable: null,
      flow_path: null, reasoning: null,
      error: { stage: 'taint', reason: 'invalid_json', detail: e.message },
    };
  }
}

// Batched taint trace: same contract as parseVerificationBatch. An entry whose
// `exploitable` is not a boolean is treated as unusable (null) and re-asked.
function parseTaintTraceBatch(raw, count) {
  const cleaned = stripFences(raw);
  const slots = new Array(count).fill(null);
  let parsed;
  try { parsed = JSON.parse(cleaned); } catch {
    const part = looksTruncated(cleaned) ? salvageArrayObjects(cleaned, 'results') : [];
    parsed = { results: part };
  }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.results) ? parsed.results : [];
  for (const item of list) {
    const idx = Number.isInteger(item?.index) ? item.index : parseInt(item?.index, 10);
    if (!Number.isInteger(idx) || idx < 0 || idx >= count || slots[idx]) continue;
    const t = normalizeTaint(item);
    if (t.exploitable === null && t.reachable === null) continue;
    slots[idx] = t;
  }
  return slots;
}

export {
  parseFindings, parseFindingsDetailed,
  parseVerification, parseVerificationBatch,
  parseTaintTrace, parseTaintTraceBatch,
  looksTruncated, salvageArrayObjects,
};
