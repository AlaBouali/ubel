'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const IAM_API_VERSION = '2010-05-08';
const IAM_HOST = 'iam.amazonaws.com'; // IAM is a global service

// IAM is global: always sign with us-east-1 regardless of scan region.
async function iamCall(action, params, creds) {
  const body = formBody({ Action: action, Version: IAM_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'iam',
      region: 'us-east-1',
      host: IAM_HOST,
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

/** Paginate through an IAM list-style call, following the Marker token. */
async function paginate(action, params, extractItems, extractMarker, creds) {
  return paginateQuery(
    (token) => iamCall(action, token ? { ...params, Marker: token } : params, creds),
    extractItems,
    extractMarker
  );
}

async function listUsers(creds) {
  const items = await paginate(
    'ListUsers',
    {},
    (xml) => asArray(xml.ListUsersResponse?.ListUsersResult?.Users?.member),
    (xml) =>
      xml.ListUsersResponse?.ListUsersResult?.IsTruncated === 'true'
        ? xml.ListUsersResponse?.ListUsersResult?.Marker
        : undefined,
    creds
  );
  return items.map((u) => ({ userName: u.UserName, arn: u.Arn, createDate: u.CreateDate }));
}

async function listAccessKeys(userName, creds) {
  const res = await iamCall('ListAccessKeys', { UserName: userName }, creds);
  const items = asArray(res.xml.ListAccessKeysResponse?.ListAccessKeysResult?.AccessKeyMetadata?.member);
  return items.map((k) => ({ accessKeyId: k.AccessKeyId, status: k.Status, createDate: k.CreateDate }));
}

async function listMfaDevices(userName, creds) {
  const res = await iamCall('ListMFADevices', { UserName: userName }, creds);
  return asArray(res.xml.ListMFADevicesResponse?.ListMFADevicesResult?.MFADevices?.member);
}

/** Whether the user has a console (password) login at all — used to scope
 * the MFA check to users who can actually sign in to the console. */
async function hasConsoleAccess(userName, creds) {
  try {
    await iamCall('GetLoginProfile', { UserName: userName }, creds);
    return true;
  } catch (err) {
    if (err.code === 'NoSuchEntity') return false;
    throw err;
  }
}

async function getAccountPasswordPolicy(creds) {
  try {
    const res = await iamCall('GetAccountPasswordPolicy', {}, creds);
    return res.xml.GetAccountPasswordPolicyResponse?.GetAccountPasswordPolicyResult?.PasswordPolicy || null;
  } catch (err) {
    if (err.code === 'NoSuchEntity') return null;
    throw err;
  }
}

/** Customer-managed policies (Scope=Local): the ones an account owner
 * actually authored, as opposed to AWS-managed policies. Regardless of
 * whether they're currently attached to anything — an unattached policy
 * with a dangerous document is still worth flagging. */
async function listCustomerManagedPolicies(creds) {
  const items = await paginate(
    'ListPolicies',
    { Scope: 'Local' },
    (xml) => asArray(xml.ListPoliciesResponse?.ListPoliciesResult?.Policies?.member),
    (xml) =>
      xml.ListPoliciesResponse?.ListPoliciesResult?.IsTruncated === 'true'
        ? xml.ListPoliciesResponse?.ListPoliciesResult?.Marker
        : undefined,
    creds
  );
  return items.map((p) => ({
    policyName: p.PolicyName,
    arn: p.Arn,
    defaultVersionId: p.DefaultVersionId,
  }));
}

async function getPolicyDocument(policyArn, versionId, creds) {
  const res = await iamCall('GetPolicyVersion', { PolicyArn: policyArn, VersionId: versionId }, creds);
  const doc = res.xml.GetPolicyVersionResponse?.GetPolicyVersionResult?.PolicyVersion?.Document;
  if (!doc) return null;
  return JSON.parse(decodeURIComponent(doc));
}

// ─── groups & roles (item 2: inline/group/role-attached policies weren't
// checked at all before) ────────────────────────────────────────────────

async function listGroups(creds) {
  const items = await paginate(
    'ListGroups',
    {},
    (xml) => asArray(xml.ListGroupsResponse?.ListGroupsResult?.Groups?.member),
    (xml) =>
      xml.ListGroupsResponse?.ListGroupsResult?.IsTruncated === 'true'
        ? xml.ListGroupsResponse?.ListGroupsResult?.Marker
        : undefined,
    creds
  );
  return items.map((g) => ({ groupName: g.GroupName, arn: g.Arn }));
}

/** Roles carry a trust policy (AssumeRolePolicyDocument) in addition to
 * whatever's attached/inline — that document decides *who* can assume
 * the role, and is where an overly broad `Principal: "*"` lives. */
async function listRoles(creds) {
  const items = await paginate(
    'ListRoles',
    {},
    (xml) => asArray(xml.ListRolesResponse?.ListRolesResult?.Roles?.member),
    (xml) =>
      xml.ListRolesResponse?.ListRolesResult?.IsTruncated === 'true'
        ? xml.ListRolesResponse?.ListRolesResult?.Marker
        : undefined,
    creds
  );
  return items.map((r) => {
    let trustPolicy = null;
    try {
      trustPolicy = r.AssumeRolePolicyDocument ? JSON.parse(decodeURIComponent(r.AssumeRolePolicyDocument)) : null;
    } catch {
      trustPolicy = null;
    }
    return { roleName: r.RoleName, arn: r.Arn, path: r.Path, trustPolicy };
  });
}

/** Generic "list the inline policy names for a principal, then fetch
 * each document" pair — the shape is identical across users/groups/roles,
 * just with a different Action name and parameter/result key prefix. */
function inlinePolicyPair(listAction, getAction, principalParam, resultPrefix) {
  async function listNames(principalName, creds) {
    const items = await paginate(
      listAction,
      { [principalParam]: principalName },
      (xml) => asArray(xml[`${listAction}Response`]?.[`${listAction}Result`]?.PolicyNames?.member),
      (xml) =>
        xml[`${listAction}Response`]?.[`${listAction}Result`]?.IsTruncated === 'true'
          ? xml[`${listAction}Response`]?.[`${listAction}Result`]?.Marker
          : undefined,
      creds
    );
    return items;
  }
  async function getDocument(principalName, policyName, creds) {
    const res = await iamCall(getAction, { [principalParam]: principalName, PolicyName: policyName }, creds);
    const doc = res.xml[`${getAction}Response`]?.[`${getAction}Result`]?.PolicyDocument;
    if (!doc) return null;
    try {
      return JSON.parse(decodeURIComponent(doc));
    } catch {
      return null;
    }
  }
  return { listNames, getDocument };
}

const userInlinePolicies = inlinePolicyPair('ListUserPolicies', 'GetUserPolicy', 'UserName');
const groupInlinePolicies = inlinePolicyPair('ListGroupPolicies', 'GetGroupPolicy', 'GroupName');
const roleInlinePolicies = inlinePolicyPair('ListRolePolicies', 'GetRolePolicy', 'RoleName');

/** All of a principal's inline policy *documents* (not just names) — used
 * uniformly for users, groups, and roles by the same review loop. */
async function listInlinePolicyDocuments(kind, principalName, creds) {
  const pair = kind === 'user' ? userInlinePolicies : kind === 'group' ? groupInlinePolicies : roleInlinePolicies;
  const names = await pair.listNames(principalName, creds);
  const docs = [];
  for (const name of names) {
    const doc = await pair.getDocument(principalName, name, creds);
    if (doc) docs.push({ policyName: name, document: doc });
  }
  return docs;
}

/** Managed policies (customer- or AWS-managed) attached directly to a
 * group or role — used so a dangerous *AWS-managed* policy attached to a
 * role doesn't slip past just because listCustomerManagedPolicies() only
 * looks at policies this account authored itself. */
async function listAttachedPolicies(kind, principalName, creds) {
  const action = kind === 'group' ? 'ListAttachedGroupPolicies' : 'ListAttachedRolePolicies';
  const principalParam = kind === 'group' ? 'GroupName' : 'RoleName';
  const items = await paginate(
    action,
    { [principalParam]: principalName },
    (xml) => asArray(xml[`${action}Response`]?.[`${action}Result`]?.AttachedPolicies?.member),
    (xml) =>
      xml[`${action}Response`]?.[`${action}Result`]?.IsTruncated === 'true'
        ? xml[`${action}Response`]?.[`${action}Result`]?.Marker
        : undefined,
    creds
  );
  return items.map((p) => ({ policyName: p.PolicyName, arn: p.PolicyArn }));
}

export {
  listUsers,
  listAccessKeys,
  listMfaDevices,
  hasConsoleAccess,
  getAccountPasswordPolicy,
  listCustomerManagedPolicies,
  getPolicyDocument,
  listGroups,
  listRoles,
  listInlinePolicyDocuments,
  listAttachedPolicies,
};
