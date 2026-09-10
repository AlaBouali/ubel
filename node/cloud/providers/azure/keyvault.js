'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-07-01';

/**
 * item 5 of the later review: Key Vault had no check at all before --
 * public network access and purge protection are two of the most
 * commonly-audited Key Vault settings.
 */
async function listVaults(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.KeyVault/vaults?api-version=${API_VERSION}`;
  const vaults = await azureListAll(url, accessToken);
  return vaults.map((v) => ({
    id: v.id,
    name: v.name,
    location: v.location,
    // Azure's own default (when the property is absent) is "Enabled".
    publicNetworkAccess: v.properties?.publicNetworkAccess || 'Enabled',
    networkAclsDefaultAction: v.properties?.networkAcls?.defaultAction || 'Allow',
    purgeProtectionEnabled: Boolean(v.properties?.enablePurgeProtection),
  }));
}

export { listVaults };
