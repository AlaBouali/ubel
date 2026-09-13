'use strict';
import { azureListAll, azureRequest } from './client.js';

const API_VERSION = '2022-05-01-preview';

async function listSqlServers(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Sql/servers?api-version=${API_VERSION}`;
  const servers = await azureListAll(url, accessToken);
  return servers.map((s) => ({ id: s.id, name: s.name, location: s.location }));
}

async function listFirewallRules(serverId, accessToken) {
  const url = `https://management.azure.com${serverId}/firewallRules?api-version=${API_VERSION}`;
  const data = await azureRequest(url, accessToken);
  return (data.value || []).map((r) => ({
    name: r.name,
    startIpAddress: r.properties?.startIpAddress,
    endIpAddress: r.properties?.endIpAddress,
  }));
}

export { listSqlServers, listFirewallRules };
