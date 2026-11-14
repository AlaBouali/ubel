'use strict';
import { azureListAll } from './client.js';

/** Microsoft Defender for Cloud plans: name -> 'Standard' (on) | 'Free' (off). */
async function listDefenderPlans(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/pricings?api-version=2023-01-01`;
  const plans = await azureListAll(url, accessToken);
  return plans.map((p) => ({ name: p.name, tier: p.properties?.pricingTier || 'Free' }));
}

/** Security contacts (who Defender for Cloud emails about alerts). */
async function listSecurityContacts(subscriptionId, accessToken) {
  const url = `https://management.azure.com/subscriptions/${subscriptionId}/providers/Microsoft.Security/securityContacts?api-version=2020-01-01-preview`;
  const contacts = await azureListAll(url, accessToken);
  return contacts.map((c) => ({
    // `emails` is a ;-separated string in current API versions, `email` in older ones.
    emails: String(c.properties?.emails || c.properties?.email || '')
      .split(/[;,]/)
      .map((e) => e.trim())
      .filter(Boolean),
  }));
}

export { listDefenderPlans, listSecurityContacts };
