'use strict';

/**
 * Thin wrapper around the global fetch() (built into Node >=18, no
 * dependency needed) that adds retry/backoff for throttling and
 * transient server errors, and returns the raw text body alongside the
 * parsed status/headers so callers can pick JSON vs XML decoding.
 */
async function request(url, opts = {}) {
  // 30s default (was 15s) -- large IAM ListPolicies/DescribeDBInstances/
  // CloudTrail responses on big accounts routinely took longer than 15s
  // to fully download (item 7). Callers can still override per-call.
  const { method = 'GET', headers = {}, body, maxRetries = 4, timeoutMs = 30000 } = opts;

  let lastErr;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const res = await fetch(url, { method, headers, body, signal: controller.signal });
      clearTimeout(timer);
      const text = await res.text();

      if ((res.status === 429 || res.status >= 500) && attempt < maxRetries) {
        await backoff(attempt);
        continue;
      }

      return { status: res.status, headers: res.headers, text, ok: res.ok };
    } catch (err) {
      clearTimeout(timer);
      lastErr = err;
      if (attempt < maxRetries) {
        await backoff(attempt);
        continue;
      }
    }
  }
  throw lastErr || new Error(`request failed: ${url}`);
}

function backoff(attempt) {
  const base = Math.min(1000 * 2 ** attempt, 8000);
  const jitter = Math.floor(Math.random() * 250);
  return new Promise((resolve) => setTimeout(resolve, base + jitter));
}

function safeJsonParse(text) {
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}

export { request, safeJsonParse };
