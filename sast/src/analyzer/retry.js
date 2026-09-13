'use strict';

import { callProvider } from './dispatcher.js';
import { parseFindings } from './parsers.js';

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

async function callProviderWithRetry(callOpts, { retryOnParseError = true, maxRetries = 2 } = {}) {
  async function attempt(maxTokensOverride) {
    const opts = maxTokensOverride
      ? { ...callOpts, maxTokens: maxTokensOverride }
      : callOpts;
    const raw = await callProvider(opts);
    return { raw, findings: parseFindings(raw) };
  }

  let lastError = null;

  for (let attempt_n = 0; attempt_n <= maxRetries; attempt_n++) {
    try {
      const { findings } = await attempt();

      if (retryOnParseError && findings.some(f => f._parse_error)) {
        try {
          const { findings: retried } = await attempt(callOpts.maxTokens * 2);
          if (!retried.some(f => f._parse_error)) return retried;
        } catch {
          // Fall through to return the original parse-error findings
        }
        return findings;
      }

      return findings;

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

export { isTerminalStatus, retryDelayMs, callProviderWithRetry };
