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
      instanceType: i.instanceType, // CLOUD_SQL_INSTANCE | READ_REPLICA_INSTANCE | ...
      backupsEnabled: Boolean(i.settings?.backupConfiguration?.enabled),
      deletionProtection: Boolean(i.settings?.deletionProtectionEnabled),
      // flag name -> value, e.g. { log_connections: 'on' }
      databaseFlags: Object.fromEntries((i.settings?.databaseFlags || []).map((f) => [f.name, String(f.value ?? '')])),
      authorizedNetworks,
      hasOpenAuthorizedNetwork: authorizedNetworks.includes('0.0.0.0/0'),
    };
  });
}

export { listInstances };
