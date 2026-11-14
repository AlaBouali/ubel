'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2022-04-01';
const OWNER_ROLE_ID = '8e3af657-a8ff-443c-a75c-2fe8c4bcb635'; // built-in Owner role definition guid

/** Owner role assignments made directly on the subscription (not inherited, not on sub-scopes). */
async function listSubscriptionOwners(subscriptionId, accessToken) {
  const scope = `/subscriptions/${subscriptionId}`;
  const url = `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleAssignments?api-version=${API_VERSION}&$filter=${encodeURIComponent('atScope()')}`;
  const assignments = await azureListAll(url, accessToken);
  return assignments
    .filter((a) => String(a.properties?.roleDefinitionId || '').toLowerCase().endsWith(OWNER_ROLE_ID))
    .filter((a) => String(a.properties?.scope || '').toLowerCase() === scope.toLowerCase())
    .map((a) => ({ principalId: a.properties?.principalId, principalType: a.properties?.principalType }));
}

/** Custom (user-defined) role definitions assignable in this subscription. */
async function listCustomRoles(subscriptionId, accessToken) {
  const scope = `/subscriptions/${subscriptionId}`;
  const url = `https://management.azure.com${scope}/providers/Microsoft.Authorization/roleDefinitions?api-version=${API_VERSION}&$filter=${encodeURIComponent("type eq 'CustomRole'")}`;
  const roles = await azureListAll(url, accessToken);
  return roles.map((r) => ({
    name: r.properties?.roleName || r.name,
    actions: (r.properties?.permissions || []).flatMap((p) => p.actions || []),
    assignableScopes: r.properties?.assignableScopes || [],
  }));
}

export { listSubscriptionOwners, listCustomRoles };
