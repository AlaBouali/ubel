'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const RDS_API_VERSION = '2014-10-31';

function rdsHost(region) {
  return `rds.${region}.amazonaws.com`;
}

async function rdsCall(action, params, region, creds) {
  const body = formBody({ Action: action, Version: RDS_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'rds',
      region,
      host: rdsHost(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

/** Paginate an RDS query-protocol list call via Marker. Unlike IAM, RDS
 * doesn't send an explicit IsTruncated flag — the presence of a non-empty
 * <Marker> element in the result is itself the "more pages" signal. */
function rdsPaginate(action, params, region, creds, resultKey, extractItems) {
  return paginateQuery(
    (token) => rdsCall(action, token ? { ...params, Marker: token } : params, region, creds),
    (xml) => extractItems(xml[action + 'Response']?.[resultKey]),
    (xml) => xml[action + 'Response']?.[resultKey]?.Marker || undefined
  );
}

async function describeDBInstances(region, creds) {
  const instances = await rdsPaginate(
    'DescribeDBInstances',
    {},
    region,
    creds,
    'DescribeDBInstancesResult',
    (result) => asArray(result?.DBInstances?.DBInstance)
  );
  return instances.map((i) => ({
    id: i.DBInstanceIdentifier,
    arn: i.DBInstanceArn,
    engine: i.Engine,
    publiclyAccessible: i.PubliclyAccessible === 'true',
    storageEncrypted: i.StorageEncrypted === 'true',
  }));
}

/**
 * DescribeDBSnapshots with no SnapshotType filter returns both automated
 * and manual snapshots owned by this account (not shared/public ones —
 * that needs IncludeShared/IncludePublic, which we don't need here since
 * we're checking snapshots *this account* might have accidentally made
 * public, not ones shared *to* it).
 */
async function describeDBSnapshots(region, creds) {
  const snapshots = await rdsPaginate(
    'DescribeDBSnapshots',
    {},
    region,
    creds,
    'DescribeDBSnapshotsResult',
    (result) => asArray(result?.DBSnapshots?.DBSnapshot)
  );
  return snapshots.map((s) => ({
    id: s.DBSnapshotIdentifier,
    dbInstanceId: s.DBInstanceIdentifier,
    snapshotType: s.SnapshotType,
    encrypted: s.Encrypted === 'true',
    status: s.Status,
  }));
}

/** Only manual snapshots can be shared publicly, so this is only ever
 * called for those. Returns true if the 'restore' attribute's value list
 * includes the special "all" value (share-with-everyone). */
async function isSnapshotPublic(snapshotId, region, creds) {
  const res = await rdsCall('DescribeDBSnapshotAttributes', { DBSnapshotIdentifier: snapshotId }, region, creds);
  const attrs = asArray(
    res.xml.DescribeDBSnapshotAttributesResponse?.DescribeDBSnapshotAttributesResult?.DBSnapshotAttributesResult
      ?.DBSnapshotAttributes?.DBSnapshotAttribute
  );
  const restoreAttr = attrs.find((a) => a.AttributeName === 'restore');
  // RDS's query-protocol schema reuses the singular element name for
  // repeated children (DBSnapshots/DBSnapshot, DBSnapshotAttributes/
  // DBSnapshotAttribute, ...), not a generic <item>/<member> wrapper —
  // AttributeValues/AttributeValue follows the same convention.
  const values = asArray(restoreAttr?.AttributeValues?.AttributeValue);
  return values.includes('all');
}

export { describeDBInstances, describeDBSnapshots, isSnapshotPublic };
