'use strict';
import { signRequest } from '../../auth/aws-sigv4.js';
import { request, safeJsonParse } from '../../lib/http.js';
import { parseXML } from '../../lib/xml.js';

// Large IAM policy/CloudTrail/RDS responses can run well past the 15s
// default that used to be hardcoded -- see item 7 ("timeout may be too
// short for large responses"). http.js still lets any individual call
// override this further via opts.timeoutMs.
const DEFAULT_TIMEOUT_MS = 30000;

/**
 * Send a signed AWS API request. Every AWS query-protocol / REST-XML API
 * we touch here (S3 REST, EC2/IAM/RDS/STS query protocol) responds with
 * XML, so this always parses the body as XML; callers that need the raw
 * text can read res.text. Newer JSON-protocol services (CloudTrail) use
 * awsJsonRequest below instead.
 *
 * @param {object} opts
 * @param {string} opts.service   SigV4 service name, e.g. 's3' | 'ec2' | 'iam' | 'rds' | 'sts'
 * @param {string} opts.region    signing region (IAM/STS callers should pass 'us-east-1')
 * @param {string} opts.host      request host
 * @param {string} [opts.method]  defaults to 'GET'
 * @param {string} [opts.path]    defaults to '/'
 * @param {object} [opts.query]   query string params (used for S3 subresources)
 * @param {string} [opts.body]    request body (used for EC2/IAM/RDS/STS query-protocol POSTs)
 * @param {object} [opts.headers] extra headers
 * @param {number} [opts.timeoutMs]
 * @param {object} creds          { accessKeyId, secretAccessKey, sessionToken }
 */
async function awsRequest(opts, creds) {
  const method = opts.method || 'GET';
  const path = opts.path || '/';
  const query = opts.query || {};
  const body = opts.body || '';

  const signedHeaders = signRequest(
    {
      method,
      host: opts.host,
      path,
      query,
      body,
      region: opts.region,
      service: opts.service,
      headers: opts.headers,
    },
    creds
  );

  const qs = Object.keys(query)
    .sort()
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(query[k])}`)
    .join('&');
  const url = `https://${opts.host}${path}${qs ? '?' + qs : ''}`;

  const res = await request(url, {
    method,
    headers: signedHeaders,
    body: body || undefined,
    timeoutMs: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
  });
  const parsed = parseXML(res.text);

  if (!res.ok) {
    const errInfo = parsed.ErrorResponse?.Error || parsed.Error || {};
    const err = new Error(
      `AWS ${opts.service} ${method} ${path} failed (${res.status}): ${errInfo.Code || ''} ${errInfo.Message || res.text.slice(0, 300)}`
    );
    err.status = res.status;
    err.code = errInfo.Code;
    throw err;
  }

  return { status: res.status, xml: parsed, text: res.text };
}

/**
 * Send a signed AWS JSON-protocol (AWS JSON 1.1) request. SigV4 signing
 * itself is body-format-agnostic (it just hashes whatever bytes are
 * sent), so this only differs from awsRequest in the Content-Type /
 * X-Amz-Target headers and JSON (not XML) request/response bodies.
 * Used by CloudTrail, which -- unlike EC2/IAM/RDS -- doesn't speak the
 * query protocol.
 *
 * @param {object} opts
 * @param {string} opts.service   SigV4 service name, e.g. 'cloudtrail'
 * @param {string} opts.target    X-Amz-Target header value, e.g.
 *   'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.DescribeTrails'
 * @param {object} [opts.body]    plain object, JSON-encoded for the wire
 */
async function awsJsonRequest(opts, creds) {
  const method = opts.method || 'POST';
  const path = opts.path || '/';
  const body = opts.body ? JSON.stringify(opts.body) : '{}';

  const extraHeaders = {
    'content-type': 'application/x-amz-json-1.1',
    'x-amz-target': opts.target,
    ...(opts.headers || {}),
  };

  const signedHeaders = signRequest(
    {
      method,
      host: opts.host,
      path,
      query: {},
      body,
      region: opts.region,
      service: opts.service,
      headers: extraHeaders,
    },
    creds
  );

  const url = `https://${opts.host}${path}`;
  const res = await request(url, {
    method,
    headers: signedHeaders,
    body,
    timeoutMs: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
  });

  const parsed = safeJsonParse(res.text);
  if (!res.ok) {
    // AWS JSON-protocol errors come back as {"__type": "...#SomeException", "message": "..."}
    const errType = parsed?.__type || '';
    const err = new Error(
      `AWS ${opts.service} ${opts.target} failed (${res.status}): ${errType} ${parsed?.message || parsed?.Message || res.text.slice(0, 300)}`
    );
    err.status = res.status;
    err.code = errType.includes('#') ? errType.split('#').pop() : errType || undefined;
    throw err;
  }
  if (res.text && parsed === null) {
    // A 2xx with a non-empty body that isn't valid JSON is a real anomaly
    // (proxy/WAF interstitial page, truncated response, etc.) -- surface
    // it rather than silently returning {} and letting callers read
    // undefined fields off a missing response (item 7: safeJsonParse
    // masking errors).
    throw new Error(
      `AWS ${opts.service} ${opts.target} returned 2xx but an unparseable body (first 200 chars): ${res.text.slice(0, 200)}`
    );
  }

  return { status: res.status, json: parsed || {}, text: res.text };
}

/**
 * Send a signed AWS REST-JSON request -- newer services (GuardDuty,
 * Security Hub, Config, ...) route by HTTP method + URL path instead of
 * an X-Amz-Target header, unlike awsJsonRequest's AWS JSON 1.1 services,
 * and don't wrap the whole request in an XML envelope like awsRequest's
 * query-protocol services. This is the third (and last) request shape
 * alongside those two.
 *
 * @param {object} opts
 * @param {string} opts.service   SigV4 service name, e.g. 'guardduty'
 * @param {string} [opts.method]  defaults to 'GET'
 * @param {string} [opts.path]    defaults to '/'
 * @param {object} [opts.query]   query string params
 * @param {object} [opts.body]    plain object, JSON-encoded for the wire
 */
async function awsRestJsonRequest(opts, creds) {
  const method = opts.method || 'GET';
  const path = opts.path || '/';
  const query = opts.query || {};
  const body = opts.body !== undefined ? JSON.stringify(opts.body) : '';

  const extraHeaders = {
    ...(body ? { 'content-type': 'application/json' } : {}),
    ...(opts.headers || {}),
  };

  const signedHeaders = signRequest(
    {
      method,
      host: opts.host,
      path,
      query,
      body,
      region: opts.region,
      service: opts.service,
      headers: extraHeaders,
    },
    creds
  );

  const qs = Object.keys(query)
    .sort()
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(query[k])}`)
    .join('&');
  const url = `https://${opts.host}${path}${qs ? '?' + qs : ''}`;

  const res = await request(url, {
    method,
    headers: signedHeaders,
    body: body || undefined,
    timeoutMs: opts.timeoutMs || DEFAULT_TIMEOUT_MS,
  });

  const parsed = safeJsonParse(res.text);
  if (!res.ok) {
    const errType = parsed?.__type || parsed?.Code || '';
    const err = new Error(
      `AWS ${opts.service} ${method} ${path} failed (${res.status}): ${errType} ${parsed?.message || parsed?.Message || res.text.slice(0, 300)}`
    );
    err.status = res.status;
    err.code = errType.includes('#') ? errType.split('#').pop() : errType || undefined;
    throw err;
  }
  if (res.text && parsed === null) {
    // Same reasoning as awsJsonRequest above (item 7: don't mask a
    // 2xx-with-unparseable-body as an empty success).
    throw new Error(
      `AWS ${opts.service} ${method} ${path} returned 2xx but an unparseable body (first 200 chars): ${res.text.slice(0, 200)}`
    );
  }

  return { status: res.status, json: parsed || {}, text: res.text };
}

/** Build the x-www-form-urlencoded body for an EC2/IAM/RDS/STS query-protocol call. */
function formBody(params) {
  return Object.keys(params)
    .sort()
    .map((k) => `${encodeURIComponent(k)}=${encodeURIComponent(params[k])}`)
    .join('&');
}

/**
 * Generic pagination helper for query-protocol list calls that return a
 * next-page token (EC2's NextToken/nextToken, RDS/IAM's Marker). Callers
 * supply `callPage(token)` -- a closure that already knows the action,
 * fixed params, host/region, and how to fold `token` (a string or
 * undefined) into the right request parameter name for that API -- plus
 * extractors for the item list and the next token from a page's parsed
 * `res.xml`.
 *
 * Fixes item 1: EC2 DescribeSecurityGroups/DescribeInstances and RDS
 * DescribeDBInstances/DescribeDBSnapshots previously only ever fetched
 * page one, silently dropping everything past ~100 results.
 */
async function paginateQuery(callPage, extractItems, extractToken) {
  let token;
  const all = [];
  do {
    const res = await callPage(token);
    all.push(...extractItems(res.xml));
    token = extractToken(res.xml);
  } while (token);
  return all;
}

export { awsRequest, awsJsonRequest, awsRestJsonRequest, formBody, paginateQuery, DEFAULT_TIMEOUT_MS };
