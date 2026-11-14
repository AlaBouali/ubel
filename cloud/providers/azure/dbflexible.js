'use strict';
import { azureListAll, azureRequest } from './client.js';

// Azure Database for PostgreSQL / MySQL *flexible* servers (the current offering;
// the older "single server" is retired). Both share the same shape for the fields
// the checks need, so one module serves both.
const KINDS = {
  postgres: { provider: 'Microsoft.DBforPostgreSQL', apiVersion: '2022-12-01', label: 'PostgreSQL' },
  mysql: { provider: 'Microsoft.DBforMySQL', apiVersion: '2023-06-30', label: 'MySQL' },
};

async function listFlexibleServers(kind, subscriptionId, accessToken) {
  const k = KINDS[kind];
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/${k.provider}/flexibleServers?api-version=${k.apiVersion}`;
  const servers = await azureListAll(url, accessToken);
  return servers.map((s) => ({
    id: s.id,
    name: s.name,
    location: s.location,
    // Servers injected into a VNet have a delegated subnet and no public endpoint.
    privateOnly: Boolean(s.properties?.network?.delegatedSubnetResourceId) || s.properties?.network?.publicNetworkAccess === 'Disabled',
  }));
}

async function listFirewallRules(kind, serverId, accessToken) {
  const k = KINDS[kind];
  const url = `https://management.azure.com${serverId}/firewallRules?api-version=${k.apiVersion}`;
  const rules = await azureListAll(url, accessToken);
  return rules.map((r) => ({
    name: r.name,
    startIpAddress: r.properties?.startIpAddress,
    endIpAddress: r.properties?.endIpAddress,
  }));
}

/** Whether the server refuses unencrypted connections (require_secure_transport). */
async function getRequireSecureTransport(kind, serverId, accessToken) {
  const k = KINDS[kind];
  const data = await azureRequest(`https://management.azure.com${serverId}/configurations/require_secure_transport?api-version=${k.apiVersion}`, accessToken);
  return String(data.properties?.value || '').toLowerCase() !== 'off';
}

export { KINDS, listFlexibleServers, listFirewallRules, getRequireSecureTransport };
