'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-07-01';

/**
 * item 5: Container Registry admin user / public access had no check
 * before. The admin user is a single shared, non-attributable
 * credential -- the ACR equivalent of a root account shared by everyone
 * who needs to push/pull.
 */
async function listRegistries(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.ContainerRegistry/registries?api-version=${API_VERSION}`;
  const registries = await azureListAll(url, accessToken);
  return registries.map((r) => ({
    id: r.id,
    name: r.name,
    location: r.location,
    adminUserEnabled: Boolean(r.properties?.adminUserEnabled),
    publicNetworkAccess: r.properties?.publicNetworkAccess || 'Enabled',
  }));
}

export { listRegistries };
