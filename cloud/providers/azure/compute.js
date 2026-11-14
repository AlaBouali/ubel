'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-04-02';

/** Managed disks. `managedBy` is set while a disk is attached to a VM. */
async function listDisks(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Compute/disks?api-version=${API_VERSION}`;
  const disks = await azureListAll(url, accessToken);
  return disks.map((d) => ({
    id: d.id,
    name: d.name,
    location: d.location,
    sizeGb: Number(d.properties?.diskSizeGB || 0),
    attached: Boolean(d.managedBy) || (d.managedByExtended || []).length > 0,
    // 'Unattached' | 'Attached' | 'Reserved' | 'ActiveSAS' | ...
    diskState: d.properties?.diskState || '',
  }));
}

export { listDisks };
