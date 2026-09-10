'use strict';
import { awsRequest } from './client.js';
import { asArray } from '../../lib/xml.js';

const GLOBAL_HOST = 's3.amazonaws.com';

async function listBuckets(creds) {
  const res = await awsRequest({ service: 's3', region: 'us-east-1', host: GLOBAL_HOST, path: '/' }, creds);
  const buckets = asArray(res.xml.ListAllMyBucketsResult?.Buckets?.Bucket);
  return buckets.map((b) => ({ name: b.Name, createdAt: b.CreationDate }));
}

async function getBucketRegion(bucket, creds) {
  try {
    const res = await awsRequest(
      { service: 's3', region: 'us-east-1', host: GLOBAL_HOST, path: `/${bucket}`, query: { location: '' } },
      creds
    );
    const loc = res.xml.LocationConstraint;
    // Empty/absent LocationConstraint means the classic us-east-1 region.
    if (!loc || typeof loc !== 'string' || loc === '') return 'us-east-1';
    // AWS uses 'EU' historically for eu-west-1.
    return loc === 'EU' ? 'eu-west-1' : loc;
  } catch {
    return 'us-east-1';
  }
}

function bucketHost(bucket, region) {
  return region === 'us-east-1' ? `${bucket}.s3.amazonaws.com` : `${bucket}.s3.${region}.amazonaws.com`;
}

async function getBucketAcl(bucket, region, creds) {
  const res = await awsRequest(
    { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { acl: '' } },
    creds
  );
  const grants = asArray(res.xml.AccessControlPolicy?.AccessControlList?.Grant);
  return grants.map((g) => ({
    granteeType: g.Grantee?.URI ? 'uri' : g.Grantee?.ID ? 'canonical' : 'unknown',
    granteeUri: g.Grantee?.URI,
    permission: g.Permission,
  }));
}

/** GetBucketPolicyStatus -- the cheap way to ask "is this bucket public?"
 * without having to parse an arbitrary IAM policy document ourselves. */
async function getBucketPolicyStatus(bucket, region, creds) {
  try {
    const res = await awsRequest(
      { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { policyStatus: '' } },
      creds
    );
    return res.xml.PolicyStatus?.IsPublic === 'true';
  } catch (err) {
    if (err.code === 'NoSuchBucketPolicy') return false;
    throw err;
  }
}

async function getPublicAccessBlock(bucket, region, creds) {
  try {
    const res = await awsRequest(
      { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { publicAccessBlock: '' } },
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

async function getBucketEncryption(bucket, region, creds) {
  try {
    const res = await awsRequest(
      { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { encryption: '' } },
      creds
    );
    const rules = asArray(
      res.xml.ServerSideEncryptionConfiguration?.Rule
    );
    return rules.length > 0;
  } catch (err) {
    if (err.code === 'ServerSideEncryptionConfigurationNotFoundError') return false;
    throw err;
  }
}

async function getBucketVersioning(bucket, region, creds) {
  const res = await awsRequest(
    { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { versioning: '' } },
    creds
  );
  return res.xml.VersioningConfiguration?.Status === 'Enabled';
}

async function getBucketLogging(bucket, region, creds) {
  const res = await awsRequest(
    { service: 's3', region, host: bucketHost(bucket, region), path: '/', query: { logging: '' } },
    creds
  );
  return Boolean(res.xml.BucketLoggingStatus?.LoggingEnabled);
}

/**
 * Object-level public access (item 4) is a hard problem to check
 * exhaustively: a bucket can hold millions of objects, and object ACLs
 * are set per-object, so a full scan would be prohibitively slow (and
 * itself run straight into the "no parallelism / thousands of buckets"
 * scaling issue called out in item 10). Bucket-level Block Public Access
 * and bucket policy already cover most real-world exposure, so this is
 * a bounded *sample* — good enough to catch "someone made individual
 * objects public" without turning every scan into an unbounded
 * per-object crawl.
 *
 * A single unanchored ListObjectsV2 call only ever returns the
 * lexicographically-first page, though, which is a biased sample: a
 * bucket with 10 million objects and one public object whose key starts
 * with "z" would never be seen. So once the first page comes back
 * truncated (i.e. the bucket has more than `budget` objects total, and a
 * single page isn't already an exhaustive scan), this fans out across a
 * handful of `start-after` anchors spread through the ASCII range —
 * simple prefix sharding — instead of only ever sampling the start of
 * the key space. Total objects inspected stays bounded either way.
 * Callers can tell a full scan (small bucket) from a partial one (large
 * bucket) via the returned `coverage`.
 */
const SAMPLE_BUDGET = 50;
const START_AFTER_ANCHORS = ['1', '4', '7', 'A', 'D', 'G', 'K', 'N', 'R', 'V', 'Z', 'c', 'f', 'i', 'l', 'o', 'r', 'u', 'x'];

async function listObjectsSample(bucket, region, creds, budget = SAMPLE_BUDGET) {
  const first = await awsRequest(
    {
      service: 's3',
      region,
      host: bucketHost(bucket, region),
      path: '/',
      query: { 'list-type': '2', 'max-keys': String(budget) },
    },
    creds
  );
  const seen = new Map();
  for (const c of asArray(first.xml.ListBucketResult?.Contents)) {
    seen.set(c.Key, { key: c.Key, size: Number(c.Size || 0) });
  }
  const isTruncated = first.xml.ListBucketResult?.IsTruncated === 'true';
  if (!isTruncated) {
    // The whole bucket fit in one page -- this is an exhaustive scan of
    // every object, not a sample at all.
    return { objects: [...seen.values()], sampled: false, coverage: 'full' };
  }

  const perAnchor = Math.max(1, Math.ceil(budget / START_AFTER_ANCHORS.length));
  for (const anchor of START_AFTER_ANCHORS) {
    if (seen.size >= budget) break;
    try {
      const res = await awsRequest(
        {
          service: 's3',
          region,
          host: bucketHost(bucket, region),
          path: '/',
          query: { 'list-type': '2', 'max-keys': String(perAnchor), 'start-after': anchor },
        },
        creds
      );
      for (const c of asArray(res.xml.ListBucketResult?.Contents)) {
        seen.set(c.Key, { key: c.Key, size: Number(c.Size || 0) });
      }
    } catch {
      // One anchor failing (e.g. a transient error) shouldn't abort the
      // rest of the sample -- it's already a best-effort spot-check.
    }
  }
  return { objects: [...seen.values()].slice(0, budget), sampled: true, coverage: 'partial' };
}

async function getObjectAcl(bucket, key, region, creds) {
  const res = await awsRequest(
    {
      service: 's3',
      region,
      host: bucketHost(bucket, region),
      path: `/${key.split('/').map(encodeURIComponent).join('/')}`,
      query: { acl: '' },
    },
    creds
  );
  const grants = asArray(res.xml.AccessControlPolicy?.AccessControlList?.Grant);
  return grants.map((g) => ({
    granteeType: g.Grantee?.URI ? 'uri' : g.Grantee?.ID ? 'canonical' : 'unknown',
    granteeUri: g.Grantee?.URI,
    permission: g.Permission,
  }));
}

export {
  listBuckets,
  getBucketRegion,
  getBucketAcl,
  getBucketPolicyStatus,
  getPublicAccessBlock,
  getBucketEncryption,
  getBucketVersioning,
  getBucketLogging,
  listObjectsSample,
  getObjectAcl,
};
