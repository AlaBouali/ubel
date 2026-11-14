'use strict';
import { awsRestJsonRequest } from './client.js';

// Lambda is a REST-JSON service (method + path routing, no X-Amz-Target), so it
// uses awsRestJsonRequest -- the same wrapper GuardDuty uses. This closes the
// README's earlier "Lambda uses a REST API shape that would need its own client
// wrapper" gap: no new wrapper was needed after all.

function lambdaHost(region) {
  return `lambda.${region}.amazonaws.com`;
}

async function lambdaGet(path, query, region, creds) {
  return awsRestJsonRequest(
    { service: 'lambda', region, host: lambdaHost(region), method: 'GET', path, query: query || {} },
    creds
  );
}

/** ListFunctions, following NextMarker. Environment variable *values* are
 * returned by this call when the caller may read them; they're surfaced here so
 * the check can look at variable names / well-known secret shapes, and are never
 * written into a finding. */
async function listFunctions(region, creds) {
  const fns = [];
  let marker;
  do {
    const res = await lambdaGet('/2015-03-31/functions/', { MaxItems: '50', ...(marker ? { Marker: marker } : {}) }, region, creds);
    fns.push(...(res.json.Functions || []));
    marker = res.json.NextMarker || undefined;
  } while (marker);
  return fns.map((f) => ({
    name: f.FunctionName,
    arn: f.FunctionArn,
    runtime: f.Runtime || null,
    packageType: f.PackageType || 'Zip',
    envVars: f.Environment?.Variables || {},
    // Environment.Error is set when Lambda couldn't decrypt the variables
    // (KMS access denied) -- in that case envVars is empty, not "clean".
    envUnreadable: Boolean(f.Environment?.Error),
    hasCustomerKey: Boolean(f.KMSKeyArn),
  }));
}

/** The function's resource-based policy, or null when it has none (Lambda
 * answers 404 ResourceNotFoundException for a function with no policy). */
async function getFunctionPolicy(name, region, creds) {
  try {
    const res = await lambdaGet(`/2015-03-31/functions/${encodeURIComponent(name)}/policy`, {}, region, creds);
    if (!res.json.Policy) return null;
    try {
      return JSON.parse(res.json.Policy);
    } catch {
      return null;
    }
  } catch (err) {
    if (err.status === 404) return null;
    throw err;
  }
}

/** Function URLs (AuthType NONE = invokable by anyone who has the URL). */
async function listFunctionUrls(name, region, creds) {
  const urls = [];
  let marker;
  do {
    const res = await lambdaGet(
      `/2021-10-31/functions/${encodeURIComponent(name)}/urls`,
      { MaxItems: '50', ...(marker ? { Marker: marker } : {}) },
      region,
      creds
    );
    urls.push(...(res.json.FunctionUrlConfigs || []));
    marker = res.json.NextMarker || undefined;
  } while (marker);
  return urls.map((u) => ({ url: u.FunctionUrl, authType: u.AuthType }));
}

export { listFunctions, getFunctionPolicy, listFunctionUrls };
