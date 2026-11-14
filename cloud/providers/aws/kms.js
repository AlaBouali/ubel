'use strict';
import { awsJsonRequest } from './client.js';

// KMS is an AWS JSON 1.1 service (like CloudTrail), routed by X-Amz-Target.
const TARGET_PREFIX = 'TrentService';

function kmsHost(region) {
  return `kms.${region}.amazonaws.com`;
}

async function kmsCall(action, body, region, creds) {
  const res = await awsJsonRequest(
    {
      service: 'kms',
      region,
      host: kmsHost(region),
      target: `${TARGET_PREFIX}.${action}`,
      body,
    },
    creds
  );
  return res.json;
}

/** ListKeys, following Marker/NextMarker (Truncated=true means more pages). */
async function listKeyIds(region, creds) {
  const ids = [];
  let marker;
  do {
    const data = await kmsCall('ListKeys', { Limit: 100, ...(marker ? { Marker: marker } : {}) }, region, creds);
    for (const k of data.Keys || []) if (k.KeyId) ids.push(k.KeyId);
    marker = data.Truncated ? data.NextMarker : undefined;
  } while (marker);
  return ids;
}

/**
 * Only the fields the checks need. Rotation can only be enabled on symmetric
 * ENCRYPT_DECRYPT keys whose key material AWS generated (Origin AWS_KMS) -- for
 * asymmetric, HMAC, imported (EXTERNAL) or custom-key-store keys the
 * GetKeyRotationStatus call itself fails with UnsupportedOperationException --
 * so `rotatable` lets the caller skip those up front instead of reporting a
 * "rotation disabled" finding nobody could fix.
 */
async function describeKey(keyId, region, creds) {
  const data = await kmsCall('DescribeKey', { KeyId: keyId }, region, creds);
  const m = data.KeyMetadata || {};
  const customerManaged = m.KeyManager === 'CUSTOMER';
  return {
    keyId: m.KeyId || keyId,
    arn: m.Arn,
    customerManaged,
    state: m.KeyState,
    rotatable:
      customerManaged &&
      (m.KeySpec || m.CustomerMasterKeySpec) === 'SYMMETRIC_DEFAULT' &&
      m.KeyUsage === 'ENCRYPT_DECRYPT' &&
      m.Origin === 'AWS_KMS',
  };
}

async function getKeyRotationEnabled(keyId, region, creds) {
  const data = await kmsCall('GetKeyRotationStatus', { KeyId: keyId }, region, creds);
  return Boolean(data.KeyRotationEnabled);
}

/** The key's policy document ("default" is the only policy name KMS supports). */
async function getKeyPolicy(keyId, region, creds) {
  const data = await kmsCall('GetKeyPolicy', { KeyId: keyId, PolicyName: 'default' }, region, creds);
  if (!data.Policy) return null;
  try {
    return JSON.parse(data.Policy);
  } catch {
    return null;
  }
}

export { listKeyIds, describeKey, getKeyRotationEnabled, getKeyPolicy };
