'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-04-15';

async function listAccounts(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.DocumentDB/databaseAccounts?api-version=${API_VERSION}`;
  const accounts = await azureListAll(url, accessToken);
  return accounts.map((a) => {
    const p = a.properties || {};
    return {
      id: a.id,
      name: a.name,
      location: a.location,
      publicNetworkAccess: p.publicNetworkAccess || 'Enabled',
      vnetFilterEnabled: Boolean(p.isVirtualNetworkFilterEnabled),
      ipRuleCount: (p.ipRules || []).length,
      // Key-based (local) authentication is allowed unless explicitly disabled.
      localAuthEnabled: p.disableLocalAuth !== true,
    };
  });
}

export { listAccounts };
