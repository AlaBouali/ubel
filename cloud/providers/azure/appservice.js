'use strict';
import { azureListAll, azureRequest } from './client.js';

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

/** Site configuration (Microsoft.Web/sites/config/web): TLS floor, FTP and debugging. */
async function getSiteConfig(siteId, accessToken) {
  const data = await azureRequest(`https://management.azure.com${siteId}/config/web?api-version=${API_VERSION}`, accessToken);
  const p = data.properties || {};
  return {
    // '1.0' | '1.1' | '1.2' | '1.3' (absent means the platform default of 1.2)
    minTlsVersion: p.minTlsVersion || '1.2',
    // 'AllAllowed' | 'FtpsOnly' | 'Disabled'
    ftpsState: p.ftpsState || 'AllAllowed',
    remoteDebuggingEnabled: Boolean(p.remoteDebuggingEnabled),
  };
}

export { listSites, getSiteConfig };
