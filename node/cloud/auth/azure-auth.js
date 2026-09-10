'use strict';
import { request, safeJsonParse } from '../lib/http.js';

/**
 * OAuth2 client-credentials grant against Azure AD, scoped to Azure
 * Resource Manager. https://learn.microsoft.com/azure/active-directory/develop/v2-oauth2-client-creds-grant-flow
 */
async function getAzureAccessTokenFromClientSecret({ tenantId, clientId, clientSecret }) {
  const url = `https://login.microsoftonline.com/${tenantId}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    grant_type: 'client_credentials',
    client_id: clientId,
    client_secret: clientSecret,
    scope: 'https://management.azure.com/.default',
  }).toString();

  const res = await request(url, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body,
  });

  const parsed = safeJsonParse(res.text);
  if (!res.ok || !parsed || !parsed.access_token) {
    throw new Error(`Azure token exchange failed (${res.status}): ${res.text}`);
  }

  return parsed.access_token;
}

/**
 * Azure Instance Metadata Service token endpoint — available on VMs,
 * VMSS, App Service, Container Apps, etc. with a system- or
 * user-assigned managed identity attached (item 8: previously
 * unsupported; only a client-secret app registration worked). Only
 * reachable from inside Azure, so this is tried with no retries and a
 * short timeout so it fails fast anywhere else.
 */
async function getAzureAccessTokenFromManagedIdentity({ clientId } = {}) {
  const url = new URL('http://169.254.169.254/metadata/identity/oauth2/token');
  url.searchParams.set('api-version', '2018-02-01');
  url.searchParams.set('resource', 'https://management.azure.com/');
  if (clientId) url.searchParams.set('client_id', clientId); // selects a user-assigned identity

  const res = await request(url.toString(), {
    headers: { Metadata: 'true' },
    maxRetries: 0,
    timeoutMs: 2000,
  });
  const parsed = safeJsonParse(res.text);
  if (!res.ok || !parsed || !parsed.access_token) {
    throw new Error(`Azure managed-identity token request failed (${res.status})`);
  }
  return parsed.access_token;
}

/**
 * Resolves an ARM access token via, in order (item 8):
 *   1. client secret (AZURE_TENANT_ID/AZURE_CLIENT_ID/AZURE_CLIENT_SECRET) — unchanged, most specific
 *   2. managed identity via Azure Instance Metadata Service (AZURE_CLIENT_ID
 *      optionally selects a user-assigned identity; omit it for system-assigned)
 * Client-certificate auth is not implemented — see README "Known limitations".
 */
async function getAzureAccessToken({ tenantId, clientId, clientSecret } = {}) {
  if (tenantId && clientId && clientSecret) {
    return getAzureAccessTokenFromClientSecret({ tenantId, clientId, clientSecret });
  }
  return getAzureAccessTokenFromManagedIdentity({ clientId });
}

export { getAzureAccessToken, getAzureAccessTokenFromClientSecret, getAzureAccessTokenFromManagedIdentity };
