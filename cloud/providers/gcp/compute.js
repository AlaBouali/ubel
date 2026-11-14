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
    // Instance metadata flags (CIS GCP 4.3 / 4.5 / 4.6). GKE node VMs are managed
    // by GKE and excluded from these checks by the benchmark itself.
    serialPortEnabled: metadataFlag(i.metadata, 'serial-port-enable'),
    blockProjectSshKeys: metadataFlag(i.metadata, 'block-project-ssh-keys'),
    canIpForward: Boolean(i.canIpForward),
    isGkeNode: Boolean(i.labels?.['goog-gke-node']) || String(i.name || '').startsWith('gke-'),
    serviceAccounts: (i.serviceAccounts || []).map((sa) => ({ email: sa.email, scopes: sa.scopes || [] })),
  }));
}

function metadataFlag(metadata, key) {
  const item = (metadata?.items || []).find((m) => m.key === key);
  return item ? String(item.value).trim().toLowerCase() === 'true' : false;
}

/** Project-wide (common instance) metadata: OS Login and serial-port defaults. */
async function getProjectMetadata(project, accessToken) {
  const data = await gcpRequest(`https://compute.googleapis.com/compute/v1/projects/${project}`, { accessToken });
  const md = data.commonInstanceMetadata;
  return {
    osLoginEnabled: metadataFlag(md, 'enable-oslogin'),
    serialPortEnabled: metadataFlag(md, 'serial-port-enable'),
  };
}

/** VPC networks. `IPv4Range` is only present on legacy-mode networks. */
async function listNetworks(project, accessToken) {
  const nets = [];
  let pageToken;
  do {
    const url = new URL(`https://compute.googleapis.com/compute/v1/projects/${project}/global/networks`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    nets.push(...(data.items || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return nets.map((n) => ({
    name: n.name,
    autoCreateSubnetworks: Boolean(n.autoCreateSubnetworks),
    isLegacy: Boolean(n.IPv4Range),
  }));
}

/** Subnets across every region in one aggregated call. */
async function listSubnetworks(project, accessToken) {
  const subnets = [];
  let pageToken;
  do {
    const url = new URL(`https://compute.googleapis.com/compute/v1/projects/${project}/aggregated/subnetworks`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    for (const scoped of Object.values(data.items || {})) {
      for (const s of scoped.subnetworks || []) subnets.push(s);
    }
    pageToken = data.nextPageToken;
  } while (pageToken);
  return subnets.map((s) => ({
    name: s.name,
    region: (s.region || '').split('/').pop(),
    network: (s.network || '').split('/').pop(),
    // Proxy-only / PSC / load-balancer subnets have a non-PRIVATE purpose and no flow logs.
    purpose: s.purpose || 'PRIVATE',
    flowLogsEnabled: Boolean(s.logConfig?.enable) || Boolean(s.enableFlowLogs),
  }));
}

export { listFirewalls, listInstances, getProjectMetadata, listNetworks, listSubnetworks };
