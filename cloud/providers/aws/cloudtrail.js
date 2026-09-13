'use strict';
import { awsJsonRequest } from './client.js';

const TARGET_PREFIX = 'com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101';

function cloudtrailHost(region) {
  return `cloudtrail.${region}.amazonaws.com`;
}

async function cloudtrailCall(action, body, region, creds) {
  const res = await awsJsonRequest(
    {
      service: 'cloudtrail',
      region,
      host: cloudtrailHost(region),
      target: `${TARGET_PREFIX}.${action}`,
      body,
    },
    creds
  );
  return res.json;
}

/**
 * List trails whose *home region* is `region` (includeShadowTrails:false
 * excludes the read-only copies of other regions' multi-region trails
 * that would otherwise show up here too) — calling this once per scanned
 * region and relying on each trail surfacing exactly once in its home
 * region, rather than trying to dedupe shadow copies ourselves.
 */
async function describeTrails(region, creds) {
  const data = await cloudtrailCall('DescribeTrails', { includeShadowTrails: false }, region, creds);
  return (data.trailList || []).map((t) => ({
    name: t.Name,
    arn: t.TrailARN,
    homeRegion: t.HomeRegion,
    isMultiRegionTrail: Boolean(t.IsMultiRegionTrail),
    isOrganizationTrail: Boolean(t.IsOrganizationTrail),
    includesGlobalServiceEvents: Boolean(t.IncludeGlobalServiceEvents),
    logFileValidationEnabled: Boolean(t.LogFileValidationEnabled),
    kmsKeyId: t.KmsKeyId || null,
    s3BucketName: t.S3BucketName,
  }));
}

async function getTrailStatus(trailArn, region, creds) {
  const data = await cloudtrailCall('GetTrailStatus', { Name: trailArn }, region, creds);
  return { isLogging: Boolean(data.IsLogging) };
}

export { describeTrails, getTrailStatus };
