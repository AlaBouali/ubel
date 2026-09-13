'use strict';
import { awsRequest, formBody } from '../providers/aws/client.js';

const STS_API_VERSION = '2011-06-15';
const STS_HOST = 'sts.amazonaws.com'; // global endpoint, signed as us-east-1

/**
 * AssumeRole — used by loadAwsCredentials() to support chained profiles
 * (`role_arn` + `source_profile` in ~/.aws/config), which item 8 flagged
 * as entirely unsupported before. Returns short-lived credentials good
 * for the requested duration (default 1 hour, AWS's own minimum ceiling
 * for a role that hasn't had its max session duration raised).
 */
async function assumeRole({ roleArn, roleSessionName, externalId, durationSeconds = 3600 }, baseCreds) {
  const params = {
    Action: 'AssumeRole',
    Version: STS_API_VERSION,
    RoleArn: roleArn,
    RoleSessionName: roleSessionName || 'cloud-scanner',
    DurationSeconds: String(durationSeconds),
  };
  if (externalId) params.ExternalId = externalId;

  const res = await awsRequest(
    {
      service: 'sts',
      region: 'us-east-1',
      host: STS_HOST,
      method: 'POST',
      path: '/',
      body: formBody(params),
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    baseCreds
  );

  const creds = res.xml.AssumeRoleResponse?.AssumeRoleResult?.Credentials;
  if (!creds) throw new Error('AssumeRole response did not contain Credentials');
  return {
    accessKeyId: creds.AccessKeyId,
    secretAccessKey: creds.SecretAccessKey,
    sessionToken: creds.SessionToken,
    expiration: creds.Expiration,
  };
}

export { assumeRole };
