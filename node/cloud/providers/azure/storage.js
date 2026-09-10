'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-01-01';

async function listStorageAccounts(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Storage/storageAccounts?api-version=${API_VERSION}`;
  const accounts = await azureListAll(url, accessToken);
  return accounts.map((a) => ({
    id: a.id,
    name: a.name,
    location: a.location,
    allowBlobPublicAccess: a.properties?.allowBlobPublicAccess !== false, // Azure default is true
    supportsHttpsTrafficOnly: Boolean(a.properties?.supportsHttpsTrafficOnly),
    minimumTlsVersion: a.properties?.minimumTlsVersion || 'TLS1_0',
  }));
}

/**
 * Container-level public access (item 6: "only account-level
 * allowBlobPublicAccess was checked"). ARM's control plane exposes a list
 * operation for blob containers directly — no data-plane/storage-key
 * auth needed, same Bearer token as everything else here.
 */
async function listContainers(storageAccountId, accessToken) {
  const url = `https://management.azure.com${storageAccountId}/blobServices/default/containers?api-version=${API_VERSION}`;
  const containers = await azureListAll(url, accessToken);
  return containers.map((c) => ({
    name: c.name,
    // 'None' | 'Blob' (anonymous read for blobs only) | 'Container' (anonymous read + list)
    publicAccess: c.properties?.publicAccess || 'None',
  }));
}

export { listStorageAccounts, listContainers };
