'use strict';
import { gcpRequest } from './client.js';
import { gcpRegion, gcpZone } from '../../lib/location.js';

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
    location: c.location,   // a region (regional cluster) or a zone (zonal cluster): what the gcloud --location flag takes
    // A zonal cluster's location is a zone, which is not a region. Its name is only unique per location, so the zone goes into the resource id.
    region: gcpRegion(c.location),
    resource: gcpZone(c.location) ? `${c.name} (${c.location})` : c.name,
    // enablePrivateEndpoint=false (the default) means the control plane
    // has a public IP in addition to (or instead of) a private one.
    publicEndpoint: !c.privateClusterConfig?.enablePrivateEndpoint,
    masterAuthorizedNetworksEnabled: Boolean(c.masterAuthorizedNetworksConfig?.enabled),
    legacyAbacEnabled: Boolean(c.legacyAbac?.enabled),
    // masterAuth.username/password is the deprecated static/basic-auth
    // credential -- non-empty means it's still configured and usable
    // alongside (or instead of) normal IAM/OIDC auth.
    basicAuthConfigured: Boolean(c.masterAuth?.username),
    // Autopilot clusters manage nodes, network policy enforcement and shielded
    // nodes themselves, so the per-node / hardening checks skip them.
    autopilot: Boolean(c.autopilot?.enabled),
    // Dataplane V2 (ADVANCED_DATAPATH) enforces NetworkPolicy natively.
    networkPolicyEnforced: Boolean(c.networkPolicy?.enabled) || c.networkConfig?.datapathProvider === 'ADVANCED_DATAPATH',
    privateNodes: Boolean(c.privateClusterConfig?.enablePrivateNodes),
    workloadIdentityEnabled: Boolean(c.workloadIdentityConfig?.workloadPool),
    shieldedNodesEnabled: Boolean(c.shieldedNodes?.enabled),
    loggingDisabled: c.loggingService === 'none',
    nodePools: (c.nodePools || []).map((p) => ({
      name: p.name,
      // An unset (or literal "default") node service account means the Compute
      // Engine default service account, which is typically roles/editor.
      usesDefaultServiceAccount: !p.config?.serviceAccount || p.config.serviceAccount === 'default',
      autoUpgrade: Boolean(p.management?.autoUpgrade),
      autoRepair: Boolean(p.management?.autoRepair),
    })),
  }));
}

export { listClusters };
