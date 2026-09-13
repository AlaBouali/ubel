'use strict';
import { gcpRequest } from './client.js';

/**
 * Cloud Run services across every region in one call, via the Admin API
 * v2's `-` location wildcard -- unlike the older regional v1 API (which
 * requires a per-region host), v2 is reachable at the single global
 * run.googleapis.com host and supports aggregating across locations
 * (item 4 of the later review: "Cloud Run / Cloud Functions with
 * allUsers IAM" had no check at all before).
 */
async function listServices(project, accessToken) {
  const services = [];
  let pageToken;
  do {
    const url = new URL(`https://run.googleapis.com/v2/projects/${project}/locations/-/services`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    services.push(...(data.services || []));
    pageToken = data.nextPageToken;
  } while (pageToken);

  return services.map((s) => ({
    name: s.name, // full resource name: projects/P/locations/L/services/S
    displayName: (s.name || '').split('/').pop(),
    location: (s.name || '').split('/')[3],
    ingress: s.ingress,
  }));
}

/** Whether roles/run.invoker (or a broader role) is bound to
 * allUsers/allAuthenticatedUsers -- Cloud Run access control lives in
 * IAM, not a separate service-level ACL, so this (not some "is public"
 * flag on the service resource itself) is the actual "can anyone call
 * this without authenticating" signal. */
async function getServiceIamPolicy(serviceName, accessToken) {
  const url = `https://run.googleapis.com/v2/${serviceName}:getIamPolicy`;
  const data = await gcpRequest(url, { accessToken });
  return data.bindings || [];
}

export { listServices, getServiceIamPolicy };
