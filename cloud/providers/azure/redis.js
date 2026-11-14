'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-08-01';

async function listCaches(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Cache/redis?api-version=${API_VERSION}`;
  const caches = await azureListAll(url, accessToken);
  return caches.map((c) => ({
    id: c.id,
    name: c.name,
    location: c.location,
    nonSslPortEnabled: Boolean(c.properties?.enableNonSslPort),
    // '' when unset (older caches accept TLS 1.0).
    minimumTlsVersion: c.properties?.minimumTlsVersion || '',
  }));
}

export { listCaches };
