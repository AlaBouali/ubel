'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2023-05-01';

async function listNsgs(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=${API_VERSION}`;
  const nsgs = await azureListAll(url, accessToken);
  return nsgs.map((n) => ({
    id: n.id,
    name: n.name,
    location: n.location,
    // The standard LIST response already includes these reference arrays
    // (no $expand needed) — item 6: an NSG with wide-open rules that
    // isn't attached to any subnet or NIC can't actually expose anything,
    // so this lets the check downgrade/skip those instead of treating
    // every open rule as equally live.
    associatedSubnetIds: (n.properties?.subnets || []).map((s) => s.id),
    associatedNetworkInterfaceIds: (n.properties?.networkInterfaces || []).map((ni) => ni.id),
    securityRules: (n.properties?.securityRules || []).map((r) => ({
      name: r.name,
      direction: r.properties?.direction,
      access: r.properties?.access,
      protocol: r.properties?.protocol,
      sourceAddressPrefix: r.properties?.sourceAddressPrefix,
      sourceAddressPrefixes: r.properties?.sourceAddressPrefixes || [],
      destinationPortRange: r.properties?.destinationPortRange,
      destinationPortRanges: r.properties?.destinationPortRanges || [],
    })),
  }));
}

export { listNsgs };
