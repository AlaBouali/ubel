'use strict';

import { callProvider } from './dispatcher.js';
import { parseFindingsDetailed } from './parsers.js';

// ─── Shared retry logic ──────────────────────────────────────────────────────
// Returns true for status codes that should never be retried.
function isTerminalStatus(err) {
  const code = err.statusCode;
  if (code === 400 || code === 401 || code === 403 || code === 404) return true;
  const msg = err.message || '';
  if (msg.includes('HTTP 400') || msg.includes('HTTP 401') ||
      msg.includes('HTTP 403') || msg.includes('requires an API key')) return true;
  return false;
}

// Returns the delay in ms before the next retry attempt.
// Honours Retry-After when present (429/503); otherwise exponential back-off.
function retryDelayMs(err, attempt_n) {
  if (err.retryAfterMs != null && err.retryAfterMs > 0) return err.retryAfterMs;
  return (2 ** attempt_n) * 1000;
}

// Hard ceiling for the one budget-doubling retry, so a small default can't
// balloon into a request most providers would reject outright.
const MAX_RETRY_OUTPUT_TOKENS = 32_768;

// Attach how the reply was obtained without changing the return type (an
// array of findings): `findings.info = { truncated, salvaged, retried }`.
function withInfo(findings, info) {
  Object.defineProperty(findings, 'info', { value: info, enumerable: false, writable: true });
  return findings;
}

/**
 * Pass-1 call with transport retries and ONE parse-error retry.
 *
 * Parse-error policy (this used to double max_tokens blindly on every parse
 * failure, paying for a whole second call even when the reply was prose or
 * had a stray character):
 *   - valid JSON                         → return it.
 *   - cut off mid-JSON, but ≥1 COMPLETE finding precedes the cut
 *                                        → return those findings (salvaged), no second call.
 *                                          info.truncated is set so the report can say the
 *                                          tail of that reply may be missing.
 *   - cut off before any finding completes
 *                                        → retry once with DOUBLED max_tokens (it really was too small).
 *   - complete but unparseable (prose, markdown, bad escape)
 *                                        → retry once at the SAME max_tokens (doubling would not help).
 */
async function callProviderWithRetry(callOpts, { retryOnParseError = true, maxRetries = 2 } = {}) {
  let lastError = null;

  for (let attempt_n = 0; attempt_n <= maxRetries; attempt_n++) {
    try {
      const raw = await callProvider(callOpts);
      const first = parseFindingsDetailed(raw);

      if (!first.findings.some(f => f._parse_error)) {
        return withInfo(first.findings, { truncated: first.truncated, salvaged: first.salvaged, retried: false });
      }
      if (!retryOnParseError) {
        return withInfo(first.findings, { truncated: first.truncated, salvaged: false, retried: false });
      }

      try {
        const nextTokens = first.truncated
          ? Math.min(callOpts.maxTokens * 2, MAX_RETRY_OUTPUT_TOKENS)
          : callOpts.maxTokens;
        const retriedRaw = await callProvider({ ...callOpts, maxTokens: nextTokens });
        const second = parseFindingsDetailed(retriedRaw);
        if (!second.findings.some(f => f._parse_error)) {
          return withInfo(second.findings, { truncated: second.truncated, salvaged: second.salvaged, retried: true });
        }
      } catch {
        // Fall through to return the original parse-error findings
      }
      return withInfo(first.findings, { truncated: first.truncated, salvaged: false, retried: true });

    } catch (err) {
      lastError = err;

      if (isTerminalStatus(err)) throw err;

      if (attempt_n < maxRetries) {
        const delay = retryDelayMs(err, attempt_n);
        await new Promise(r => setTimeout(r, delay));
      }
    }
  }

  throw lastError;
}

// Generic transport-retry wrapper for raw-text calls (verify / taint passes).
async function callRawWithRetry(callOpts, maxRetries = 2) {
  let lastErr = null;
  for (let attempt_n = 0; attempt_n <= maxRetries; attempt_n++) {
    try {
      return await callProvider(callOpts);
    } catch (err) {
      lastErr = err;
      if (isTerminalStatus(err)) throw err;
      if (attempt_n < maxRetries) {
        await new Promise(r => setTimeout(r, retryDelayMs(err, attempt_n)));
      }
    }
  }
  throw lastErr;
}

export { isTerminalStatus, retryDelayMs, callProviderWithRetry, callRawWithRetry };
