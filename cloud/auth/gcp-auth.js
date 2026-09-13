'use strict';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { request, safeJsonParse } from '../lib/http.js';

function base64url(input) {
  return Buffer.from(input)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

function base64urlFromBase64(b64) {
  return b64.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/**
 * Build and RS256-sign a Google service-account JWT, per
 * https://developers.google.com/identity/protocols/oauth2/service-account#authorizingrequests
 */
function buildSignedJwt(serviceAccount, scope) {
  const nowSec = Math.floor(Date.now() / 1000);
  const header = { alg: 'RS256', typ: 'JWT' };
  const claims = {
    iss: serviceAccount.client_email,
    scope,
    aud: serviceAccount.token_uri || 'https://oauth2.googleapis.com/token',
    iat: nowSec,
    exp: nowSec + 3600,
  };

  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`;
  const signer = crypto.createSign('RSA-SHA256');
  signer.update(signingInput);
  signer.end();
  const signature = signer.sign(serviceAccount.private_key, 'base64');

  return `${signingInput}.${base64urlFromBase64(signature)}`;
}

async function tokenFromServiceAccount(serviceAccount, scope) {
  const jwt = buildSignedJwt(serviceAccount, scope);
  const tokenUri = serviceAccount.token_uri || 'https://oauth2.googleapis.com/token';
  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion: jwt,
  }).toString();

  const res = await request(tokenUri, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const parsed = safeJsonParse(res.text);
  if (!res.ok || !parsed || !parsed.access_token) {
    throw new Error(`GCP token exchange failed (${res.status}): ${res.text}`);
  }
  return { accessToken: parsed.access_token, projectId: serviceAccount.project_id };
}

/**
 * `gcloud auth application-default login` produces an "authorized_user"
 * credential (a refresh token tied to gcloud's own OAuth client), not a
 * service account key — item 8 called this out as entirely unsupported.
 * Refreshing it is the standard OAuth2 refresh-token grant.
 */
async function tokenFromAuthorizedUser(adcCreds) {
  const body = new URLSearchParams({
    grant_type: 'refresh_token',
    client_id: adcCreds.client_id,
    client_secret: adcCreds.client_secret,
    refresh_token: adcCreds.refresh_token,
  }).toString();

  const res = await request('https://oauth2.googleapis.com/token', {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });
  const parsed = safeJsonParse(res.text);
  if (!res.ok || !parsed || !parsed.access_token) {
    throw new Error(`GCP ADC refresh-token exchange failed (${res.status}): ${res.text}`);
  }
  return { accessToken: parsed.access_token, projectId: adcCreds.quota_project_id };
}

/**
 * GCE/GKE/Cloud Run instance metadata server — the "workload identity"
 * path item 8 flagged as unsupported. Only reachable from inside GCP, so
 * this is tried with no retries and a short timeout: off-GCP it should
 * fail fast rather than eating several seconds of backoff per attempt.
 */
async function tokenFromMetadataServer(scope) {
  const base = 'http://metadata.google.internal/computeMetadata/v1';
  const headers = { 'Metadata-Flavor': 'Google' };

  const tokenRes = await request(`${base}/instance/service-accounts/default/token?scopes=${encodeURIComponent(scope)}`, {
    headers,
    maxRetries: 0,
    timeoutMs: 2000,
  });
  const parsed = safeJsonParse(tokenRes.text);
  if (!tokenRes.ok || !parsed || !parsed.access_token) {
    throw new Error(`GCE metadata server token request failed (${tokenRes.status})`);
  }

  let projectId;
  try {
    const projRes = await request(`${base}/project/project-id`, { headers, maxRetries: 0, timeoutMs: 2000 });
    if (projRes.ok) projectId = projRes.text.trim();
  } catch {
    // project id is optional here — GCP_PROJECT_ID env var can cover it
  }

  return { accessToken: parsed.access_token, projectId };
}

function wellKnownAdcPath() {
  // Matches gcloud's own convention: %APPDATA% on Windows, otherwise
  // ~/.config, for the file `gcloud auth application-default login` writes.
  const base =
    process.env.CLOUDSDK_CONFIG ||
    (process.platform === 'win32' ? process.env.APPDATA : path.join(os.homedir(), '.config'));
  return path.join(base || os.homedir(), 'gcloud', 'application_default_credentials.json');
}

/**
 * Load a GCP credential and exchange it for a bearer access token.
 * Resolution order mirrors google-auth-library's ADC search (item 8):
 *   1. `keyFilePath` argument (explicit --key-file / GOOGLE_APPLICATION_CREDENTIALS)
 *   2. gcloud's own well-known ADC file (~/.config/gcloud/application_default_credentials.json)
 *   3. the GCE/GKE/Cloud Run metadata server (workload identity)
 * Both service-account and authorized_user JSON shapes are handled.
 */
async function getGcpAccessToken(keyFilePath, scope = 'https://www.googleapis.com/auth/cloud-platform') {
  let resolvedPath = keyFilePath;
  if (!resolvedPath) {
    const wellKnown = wellKnownAdcPath();
    if (fs.existsSync(wellKnown)) resolvedPath = wellKnown;
  }

  if (resolvedPath) {
    const raw = fs.readFileSync(resolvedPath, 'utf8');
    const parsed = JSON.parse(raw);
    if (parsed.type === 'authorized_user') {
      return tokenFromAuthorizedUser(parsed);
    }
    if (parsed.client_email && parsed.private_key) {
      return tokenFromServiceAccount(parsed, scope);
    }
    throw new Error(`${resolvedPath} is not a recognized service-account or authorized-user credential file`);
  }

  // No file anywhere — last resort is the instance metadata server.
  return tokenFromMetadataServer(scope);
}

export { getGcpAccessToken, buildSignedJwt };
