'use strict';
import { awsRequest } from './client.js';

/**
 * Account-level S3 Block Public Access (S3 Control API). Unlike the per-bucket
 * setting in s3.js, this one overrides every bucket in the account, so it is the
 * single strongest guard against a future bucket being made public.
 *
 * S3 Control is addressed as `<account-id>.s3-control.<region>.amazonaws.com`
 * with the account id repeated in the x-amz-account-id header, and is signed with
 * the service name "s3". The setting is account-wide, so us-east-1 is used as a
 * fixed anchor region.
 *
 * Returns all-false (not an error) when the account has never configured it --
 * S3 answers 404 NoSuchPublicAccessBlockConfiguration in that case.
 */
async function getAccountPublicAccessBlock(accountId, creds) {
  try {
    const res = await awsRequest(
      {
        service: 's3',
        region: 'us-east-1',
        host: `${accountId}.s3-control.us-east-1.amazonaws.com`,
        path: '/v20180820/configuration/publicAccessBlock',
        headers: { 'x-amz-account-id': accountId },
      },
      creds
    );
    const cfg = res.xml.PublicAccessBlockConfiguration || {};
    return {
      blockPublicAcls: cfg.BlockPublicAcls === 'true',
      ignorePublicAcls: cfg.IgnorePublicAcls === 'true',
      blockPublicPolicy: cfg.BlockPublicPolicy === 'true',
      restrictPublicBuckets: cfg.RestrictPublicBuckets === 'true',
    };
  } catch (err) {
    if (err.code === 'NoSuchPublicAccessBlockConfiguration') {
      return { blockPublicAcls: false, ignorePublicAcls: false, blockPublicPolicy: false, restrictPublicBuckets: false };
    }
    throw err;
  }
}

export { getAccountPublicAccessBlock };
