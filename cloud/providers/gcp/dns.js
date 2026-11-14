'use strict';
import { gcpRequest } from './client.js';

/** Cloud DNS managed zones, with visibility and DNSSEC state. */
async function listManagedZones(project, accessToken) {
  const zones = [];
  let pageToken;
  do {
    const url = new URL(`https://dns.googleapis.com/dns/v1/projects/${project}/managedZones`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    zones.push(...(data.managedZones || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return zones.map((z) => ({
    name: z.name,
    dnsName: z.dnsName,
    // Zones default to public when visibility is absent.
    isPublic: (z.visibility || 'public') === 'public',
    // 'on' | 'off' | 'transfer'
    dnssecState: z.dnssecConfig?.state || 'off',
  }));
}

export { listManagedZones };
