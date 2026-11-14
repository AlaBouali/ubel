'use strict';
import { azureListAll, azureRequest } from './client.js';

const API_VERSION = '2022-05-01-preview';

async function listSqlServers(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Sql/servers?api-version=${API_VERSION}`;
  const servers = await azureListAll(url, accessToken);
  return servers.map((s) => ({
    id: s.id,
    name: s.name,
    location: s.location,
    // '' when unset (no minimum enforced); otherwise '1.0' | '1.1' | '1.2' | '1.3'.
    minimalTlsVersion: s.properties?.minimalTlsVersion || '',
  }));
}

/** Server-level auditing ('Enabled' | 'Disabled'). */
async function getAuditingState(serverId, accessToken) {
  const data = await azureRequest(`https://management.azure.com${serverId}/auditingSettings/default?api-version=${API_VERSION}`, accessToken);
  return data.properties?.state || 'Disabled';
}

/** Advanced Threat Protection / Defender for SQL policy on the server. */
async function getThreatProtectionState(serverId, accessToken) {
  const data = await azureRequest(`https://management.azure.com${serverId}/securityAlertPolicies/Default?api-version=${API_VERSION}`, accessToken);
  return data.properties?.state || 'Disabled';
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

export { listSqlServers, listFirewallRules, getAuditingState, getThreatProtectionState };
