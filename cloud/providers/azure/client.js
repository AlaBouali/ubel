'use strict';
import { request, safeJsonParse } from '../../lib/http.js';

async function azureRequest(url, accessToken) {
  const res = await request(url, {
    method: 'GET',
    headers: { authorization: `Bearer ${accessToken}` },
  });
  const parsed = safeJsonParse(res.text);
  if (!res.ok) {
    const msg = parsed?.error?.message || res.text.slice(0, 300);
    const err = new Error(`Azure GET ${url} failed (${res.status}): ${msg}`);
    err.status = res.status;
    err.code = parsed?.error?.code;
    throw err;
  }
  if (res.text && parsed === null) {
    // See providers/gcp/client.js for why this isn't just `parsed || {}`
    // (item 7: silently-swallowed parse failures on a 2xx response).
    throw new Error(`Azure GET ${url} returned 2xx but an unparseable body (first 200 chars): ${res.text.slice(0, 200)}`);
  }
  return parsed || {};
}

/** Follow @odata.nextLink / nextLink pagination common to ARM list APIs. */
async function azureListAll(url, accessToken) {
  const items = [];
  let next = url;
  while (next) {
    const data = await azureRequest(next, accessToken);
    items.push(...(data.value || []));
    next = data.nextLink || data['@odata.nextLink'] || null;
  }
  return items;
}

export { azureRequest, azureListAll };
