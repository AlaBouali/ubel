'use strict';
import crypto from 'crypto';

const UNRESERVED = /^[A-Za-z0-9\-_.~]$/;

/** Percent-encode per the SigV4 spec: encode everything except unreserved
 * characters (A-Z a-z 0-9 - _ . ~). Space -> %20 (never '+'). */
function uriEncode(str, encodeSlash = true) {
  let out = '';
  for (const ch of Buffer.from(str, 'utf8')) {
    const c = String.fromCharCode(ch);
    if (UNRESERVED.test(c)) {
      out += c;
    } else if (c === '/' && !encodeSlash) {
      out += c;
    } else {
      out += '%' + ch.toString(16).toUpperCase().padStart(2, '0');
    }
  }
  return out;
}

function canonicalUri(path) {
  if (!path || path === '') return '/';
  // Encode each path segment individually so literal '/' separators survive.
  return path
    .split('/')
    .map((seg) => uriEncode(seg))
    .join('/');
}

function canonicalQueryString(query) {
  const keys = Object.keys(query || {}).sort();
  return keys
    .map((k) => `${uriEncode(k)}=${uriEncode(String(query[k]))}`)
    .join('&');
}

function sha256Hex(data) {
  return crypto.createHash('sha256').update(data).digest('hex');
}

function hmac(key, data) {
  return crypto.createHmac('sha256', key).update(data, 'utf8').digest();
}

function toAmzDate(date) {
  // YYYYMMDDTHHMMSSZ
  return date.toISOString().replace(/[:-]|\.\d{3}/g, '');
}

function toDateStamp(amzDate) {
  return amzDate.slice(0, 8);
}

/**
 * Sign an AWS API request per Signature Version 4.
 * https://docs.aws.amazon.com/general/latest/gr/sigv4-signing-process.html
 *
 * @param {object} req
 * @param {string} req.method
 * @param {string} req.host          e.g. 'ec2.us-east-1.amazonaws.com'
 * @param {string} [req.path]        defaults to '/'
 * @param {object} [req.query]       plain key->string map
 * @param {object} [req.headers]     extra headers to include (already
 *                                   lowercase-safe; Host/X-Amz-Date/
 *                                   X-Amz-Content-Sha256 are added here)
 * @param {string|Buffer} [req.body] request body, defaults to ''
 * @param {string} req.region        e.g. 'us-east-1'
 * @param {string} req.service       e.g. 'ec2', 's3', 'iam', 'rds'
 * @param {object} creds
 * @param {string} creds.accessKeyId
 * @param {string} creds.secretAccessKey
 * @param {string} [creds.sessionToken]
 * @returns {object} headers to send with the request (includes Authorization)
 */
function signRequest(req, creds) {
  const now = req.date || new Date();
  const amzDate = toAmzDate(now);
  const dateStamp = toDateStamp(amzDate);

  const method = req.method || 'GET';
  const path = canonicalUri(req.path || '/');
  const qs = canonicalQueryString(req.query || {});
  const body = req.body || '';
  const payloadHash = sha256Hex(body);

  const baseHeaders = {
    host: req.host,
    'x-amz-date': amzDate,
    'x-amz-content-sha256': payloadHash,
    ...(req.headers || {}),
  };
  if (creds.sessionToken) baseHeaders['x-amz-security-token'] = creds.sessionToken;

  // Canonical headers: lowercase name, trimmed value, sorted by name.
  const headerNames = Object.keys(baseHeaders)
    .map((h) => h.toLowerCase())
    .sort();
  const canonicalHeaders =
    headerNames.map((h) => `${h}:${String(baseHeaders[h]).trim()}\n`).join('') ;
  const signedHeaders = headerNames.join(';');

  const canonicalRequest = [
    method,
    path,
    qs,
    canonicalHeaders,
    signedHeaders,
    payloadHash,
  ].join('\n');

  const credentialScope = `${dateStamp}/${req.region}/${req.service}/aws4_request`;
  const stringToSign = [
    'AWS4-HMAC-SHA256',
    amzDate,
    credentialScope,
    sha256Hex(canonicalRequest),
  ].join('\n');

  const kDate = hmac('AWS4' + creds.secretAccessKey, dateStamp);
  const kRegion = hmac(kDate, req.region);
  const kService = hmac(kRegion, req.service);
  const kSigning = hmac(kService, 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign, 'utf8').digest('hex');

  const authorization =
    `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${credentialScope}, ` +
    `SignedHeaders=${signedHeaders}, Signature=${signature}`;

  return { ...baseHeaders, Authorization: authorization };
}

export { signRequest, uriEncode, canonicalQueryString };
