'use strict';
import { gcpRequest } from './client.js';

/**
 * Cloud SQL instances (item 5: "very common misconfiguration" that had
 * no check at all before). instances.list is a single project-scoped
 * call — no location/zone fan-out needed, unlike Compute.
 */
async function listInstances(project, accessToken) {
  const instances = [];
  let pageToken;
  do {
    const url = new URL(`https://sqladmin.googleapis.com/v1/projects/${project}/instances`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    instances.push(...(data.items || []));
    pageToken = data.nextPageToken;
  } while (pageToken);

  return instances.map((i) => {
    const ipConfig = i.settings?.ipConfiguration || {};
    const authorizedNetworks = (ipConfig.authorizedNetworks || []).map((n) => n.value);
    return {
      name: i.name,
      databaseVersion: i.databaseVersion,
      region: i.region,
      publicIpEnabled: Boolean(ipConfig.ipv4Enabled),
      requireSsl: Boolean(ipConfig.requireSsl) || ipConfig.sslMode === 'TRUSTED_CLIENT_CERTIFICATE_REQUIRED' || ipConfig.sslMode === 'ENCRYPTED_ONLY',
      authorizedNetworks,
      hasOpenAuthorizedNetwork: authorizedNetworks.includes('0.0.0.0/0'),
    };
  });
}

export { listInstances };
