'use strict';
import { request, safeJsonParse } from '../../lib/http.js';

async function gcpRequest(url, { accessToken, method = 'GET', body }) {
  const res = await request(url, {
    method,
    headers: {
      authorization: `Bearer ${accessToken}`,
      ...(body ? { 'content-type': 'application/json' } : {}),
    },
    body: body ? JSON.stringify(body) : undefined,
  });

  const parsed = safeJsonParse(res.text);
  if (!res.ok) {
    const msg = parsed?.error?.message || res.text.slice(0, 300);
    const err = new Error(`GCP ${method} ${url} failed (${res.status}): ${msg}`);
    err.status = res.status;
    err.code = parsed?.error?.status;
    throw err;
  }
  if (res.text && parsed === null) {
    // A 2xx with a non-empty, non-JSON body (e.g. a proxy interstitial)
    // used to be swallowed here and turned into `{}`, silently making a
    // list call look like "zero results" instead of surfacing the real
    // problem (item 7: safeJsonParse masking errors).
    throw new Error(`GCP ${method} ${url} returned 2xx but an unparseable body (first 200 chars): ${res.text.slice(0, 200)}`);
  }
  return parsed || {};
}

export { gcpRequest };
