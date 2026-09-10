'use strict';
import { gcpRequest } from './client.js';

/**
 * GKE clusters across every zone/region in one call via the `-` location
 * wildcard (container.projects.locations.clusters.list, unlike Compute's
 * per-zone aggregatedList, doesn't paginate -- it returns everything in
 * one response). item 4 of the later review: "GKE cluster public control
 * plane / legacy ABAC / basic auth" had no check at all before.
 */
async function listClusters(project, accessToken) {
  const url = `https://container.googleapis.com/v1/projects/${project}/locations/-/clusters`;
  const data = await gcpRequest(url, { accessToken });
  return (data.clusters || []).map((c) => ({
    name: c.name,
    location: c.location,
    // enablePrivateEndpoint=false (the default) means the control plane
    // has a public IP in addition to (or instead of) a private one.
    publicEndpoint: !c.privateClusterConfig?.enablePrivateEndpoint,
    masterAuthorizedNetworksEnabled: Boolean(c.masterAuthorizedNetworksConfig?.enabled),
    legacyAbacEnabled: Boolean(c.legacyAbac?.enabled),
    // masterAuth.username/password is the deprecated static/basic-auth
    // credential -- non-empty means it's still configured and usable
    // alongside (or instead of) normal IAM/OIDC auth.
    basicAuthConfigured: Boolean(c.masterAuth?.username),
  }));
}

export { listClusters };
