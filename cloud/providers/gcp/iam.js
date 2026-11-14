'use strict';
import { gcpRequest } from './client.js';

async function getProjectIamPolicy(project, accessToken) {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`;
  const data = await gcpRequest(url, { accessToken, method: 'POST', body: {} });
  return data.bindings || [];
}

/** Same call as getProjectIamPolicy, but also returns the audit-log configuration. */
async function getProjectIamPolicyFull(project, accessToken) {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`;
  const data = await gcpRequest(url, { accessToken, method: 'POST', body: {} });
  return { bindings: data.bindings || [], auditConfigs: data.auditConfigs || [] };
}

/** User-created and Google-managed service accounts in the project. */
async function listServiceAccounts(project, accessToken) {
  const accounts = [];
  let pageToken;
  do {
    const url = new URL(`https://iam.googleapis.com/v1/projects/${project}/serviceAccounts`);
    url.searchParams.set('pageSize', '100');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    accounts.push(...(data.accounts || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return accounts.map((a) => ({ email: a.email, disabled: Boolean(a.disabled) }));
}

/** User-managed keys only (system-managed keys are rotated by Google). */
async function listUserManagedKeys(project, saEmail, accessToken) {
  const url = `https://iam.googleapis.com/v1/projects/${project}/serviceAccounts/${encodeURIComponent(saEmail)}/keys?keyTypes=USER_MANAGED`;
  const data = await gcpRequest(url, { accessToken });
  return (data.keys || []).map((k) => ({
    id: (k.name || '').split('/').pop(),
    validAfterTime: k.validAfterTime || null,
  }));
}

export { getProjectIamPolicy, getProjectIamPolicyFull, listServiceAccounts, listUserManagedKeys };
