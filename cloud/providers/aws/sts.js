'use strict';
import { awsRequest, formBody } from './client.js';

const STS_API_VERSION = '2011-06-15';
const STS_HOST = 'sts.amazonaws.com'; // global endpoint, signed as us-east-1

/**
 * GetCallerIdentity -- needs no IAM permission at all (any valid credential can
 * call it). Used to learn the 12-digit account id that account-scoped APIs
 * (S3 Control) put in their host name.
 */
async function getCallerIdentity(creds) {
  const res = await awsRequest(
    {
      service: 'sts',
      region: 'us-east-1',
      host: STS_HOST,
      method: 'POST',
      path: '/',
      body: formBody({ Action: 'GetCallerIdentity', Version: STS_API_VERSION }),
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
  const r = res.xml.GetCallerIdentityResponse?.GetCallerIdentityResult;
  if (!r?.Account) throw new Error('GetCallerIdentity response did not contain an Account id');
  return { account: String(r.Account), arn: r.Arn };
}

export { getCallerIdentity };
