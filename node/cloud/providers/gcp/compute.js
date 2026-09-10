'use strict';
import { gcpRequest } from './client.js';

async function listFirewalls(project, accessToken) {
  const rules = [];
  let pageToken;
  do {
    const url = new URL(`https://compute.googleapis.com/compute/v1/projects/${project}/global/firewalls`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    rules.push(...(data.items || []));
    pageToken = data.nextPageToken;
  } while (pageToken);

  return rules.map((r) => ({
    name: r.name,
    direction: r.direction,
    disabled: Boolean(r.disabled),
    sourceRanges: r.sourceRanges || [],
    // item 5: sourceTags/targetTags weren't surfaced at all before, so a
    // rule scoped to specific instances by tag looked identical to one
    // that applies network-wide — surface them so findings can say which
    // instances are actually affected instead of implying "everything".
    sourceTags: r.sourceTags || [],
    targetTags: r.targetTags || [],
    allowed: (r.allowed || []).map((a) => ({ protocol: a.IPProtocol, ports: a.ports || [] })),
    network: r.network,
  }));
}

/** List instances across all zones in one call via aggregatedList. */
async function listInstances(project, accessToken) {
  const instances = [];
  let pageToken;
  do {
    const url = new URL(`https://compute.googleapis.com/compute/v1/projects/${project}/aggregated/instances`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    for (const scoped of Object.values(data.items || {})) {
      for (const inst of scoped.instances || []) {
        instances.push(inst);
      }
    }
    pageToken = data.nextPageToken;
  } while (pageToken);

  return instances.map((i) => ({
    name: i.name,
    zone: (i.zone || '').split('/').pop(),
    hasExternalIp: (i.networkInterfaces || []).some((ni) => (ni.accessConfigs || []).length > 0),
    shieldedVmEnabled: Boolean(i.shieldedInstanceConfig?.enableSecureBoot),
    serviceAccounts: (i.serviceAccounts || []).map((sa) => ({ email: sa.email, scopes: sa.scopes || [] })),
  }));
}

export { listFirewalls, listInstances };
