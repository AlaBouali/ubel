'use strict';
import { gcpRequest } from './client.js';
import { gcpRegion } from '../../lib/location.js';

async function listBuckets(project, accessToken) {
  const buckets = [];
  let pageToken;
  do {
    const url = new URL('https://storage.googleapis.com/storage/v1/b');
    url.searchParams.set('project', project);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    buckets.push(...(data.items || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return buckets.map((b) => ({
    name: b.name,
    location: b.location,
    // Cloud Storage spells regions in upper case (US-CENTRAL1) and also has multi-regions (US, EU): the finding's region is the normalised one.
    region: gcpRegion(b.location),
    publicAccessPrevention: b.iamConfiguration?.publicAccessPrevention,
    uniformBucketLevelAccess: Boolean(b.iamConfiguration?.uniformBucketLevelAccess?.enabled),
    versioningEnabled: Boolean(b.versioning?.enabled),
  }));
}

async function getBucketIamPolicy(bucket, accessToken) {
  const url = `https://storage.googleapis.com/storage/v1/b/${encodeURIComponent(bucket)}/iam`;
  const data = await gcpRequest(url, { accessToken });
  return data.bindings || [];
}

export { listBuckets, getBucketIamPolicy };
