'use strict';
import { gcpRequest } from './client.js';

/**
 * Cloud Functions (2nd gen) across every region in one call, via the
 * v2 API's `-` location wildcard (parallels run.js's own use of it
 * above). item 4: "Cloud Run / Cloud Functions with allUsers IAM" had no
 * check at all before.
 */
async function listFunctions(project, accessToken) {
  const fns = [];
  let pageToken;
  do {
    const url = new URL(`https://cloudfunctions.googleapis.com/v2/projects/${project}/locations/-/functions`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    fns.push(...(data.functions || []));
    pageToken = data.nextPageToken;
  } while (pageToken);

  return fns.map((f) => ({
    name: f.name, // full resource name: projects/P/locations/L/functions/F
    displayName: (f.name || '').split('/').pop(),
    location: (f.name || '').split('/')[3],
  }));
}

/** Whether roles/cloudfunctions.invoker (or broader) is bound to
 * allUsers/allAuthenticatedUsers -- same reasoning as run.js's
 * getServiceIamPolicy: access control lives in IAM, not a resource flag. */
async function getFunctionIamPolicy(functionName, accessToken) {
  const url = `https://cloudfunctions.googleapis.com/v2/${functionName}:getIamPolicy`;
  const data = await gcpRequest(url, { accessToken });
  return data.bindings || [];
}

export { listFunctions, getFunctionIamPolicy };
