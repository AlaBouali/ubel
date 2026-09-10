'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2022-09-01';

/**
 * item 5: App Service / Function App httpsOnly had no check before.
 * Microsoft.Web/sites covers both App Service web apps and Function
 * Apps -- `kind` distinguishes them (e.g. "app" vs "functionapp").
 */
async function listSites(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Web/sites?api-version=${API_VERSION}`;
  const sites = await azureListAll(url, accessToken);
  return sites.map((s) => ({
    id: s.id,
    name: s.name,
    location: s.location,
    kind: s.kind || '',
    httpsOnly: Boolean(s.properties?.httpsOnly),
  }));
}

export { listSites };
