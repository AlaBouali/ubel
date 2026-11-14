'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-10-01';

/**
 * item 5: AKS local accounts / RBAC had no check before.
 */
async function listClusters(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.ContainerService/managedClusters?api-version=${API_VERSION}`;
  const clusters = await azureListAll(url, accessToken);
  return clusters.map((c) => ({
    id: c.id,
    name: c.name,
    location: c.location,
    localAccountsDisabled: Boolean(c.properties?.disableLocalAccounts),
    // AKS's own default (when the property is absent) is true.
    rbacEnabled: c.properties?.enableRBAC !== false,
    privateCluster: Boolean(c.properties?.apiServerAccessProfile?.enablePrivateCluster),
    authorizedIpRanges: c.properties?.apiServerAccessProfile?.authorizedIPRanges || [],
    networkPolicy: c.properties?.networkProfile?.networkPolicy || '',
    // Any aadProfile (managed Entra ID integration or legacy) means directory sign-in is wired up.
    aadIntegrated: Boolean(c.properties?.aadProfile),
    monitoringEnabled:
      Boolean(c.properties?.addonProfiles?.omsagent?.enabled) || Boolean(c.properties?.azureMonitorProfile?.metrics?.enabled),
  }));
}

export { listClusters };
