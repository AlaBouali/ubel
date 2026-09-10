'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const EC2_API_VERSION = '2016-11-15';

function ec2Host(region) {
  return `ec2.${region}.amazonaws.com`;
}

async function ec2Call(action, params, region, creds) {
  const body = formBody({ Action: action, Version: EC2_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'ec2',
      region,
      host: ec2Host(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

/**
 * DescribeRegions is a partition-wide call — any regional EC2 endpoint can
 * answer it, so us-east-1 is used as a fixed, always-available anchor for
 * both the request host and the SigV4 signing region.
 *
 * With no AllRegions param (defaults to false), AWS returns only the
 * regions actually enabled for the account: opt-in-not-required regions
 * plus any opt-in regions the account has explicitly enabled. That's
 * exactly "enabled regions" for auto-discovery — opted-out regions are
 * left out on purpose.
 */
async function describeRegions(creds) {
  const region = 'us-east-1';
  const res = await ec2Call('DescribeRegions', {}, region, creds);
  const items = asArray(res.xml.DescribeRegionsResponse?.regionInfo?.item);
  return items
    .map((r) => r.regionName)
    .filter(Boolean)
    .sort();
}

/** Paginate an EC2 query-protocol list call via NextToken/nextToken. */
function ec2Paginate(action, params, region, creds, resultKey, extractItems) {
  return paginateQuery(
    (token) => ec2Call(action, token ? { ...params, NextToken: token } : params, region, creds),
    (xml) => extractItems(xml[resultKey]),
    (xml) => xml[resultKey]?.nextToken || undefined
  );
}

async function describeSecurityGroups(region, creds) {
  const groups = await ec2Paginate(
    'DescribeSecurityGroups',
    {},
    region,
    creds,
    'DescribeSecurityGroupsResponse',
    (resp) => asArray(resp?.securityGroupInfo?.item)
  );
  return groups.map((g) => ({
    groupId: g.groupId,
    groupName: g.groupName,
    vpcId: g.vpcId,
    ipPermissions: asArray(g.ipPermissions?.item).map(parsePermission),
  }));
}

function parsePermission(p) {
  return {
    protocol: p.ipProtocol,
    fromPort: p.fromPort !== undefined ? Number(p.fromPort) : null,
    toPort: p.toPort !== undefined ? Number(p.toPort) : null,
    ipv4Ranges: asArray(p.ipRanges?.item).map((r) => r.cidrIp),
    ipv6Ranges: asArray(p.ipv6Ranges?.item).map((r) => r.cidrIpv6),
  };
}

/**
 * DescribeInstances, flattened out of the Reservations -> Instances
 * nesting, for the "EC2 instance with a public IP" check (item 4). Only
 * running/pending/stopping/stopped instances are meaningfully "public";
 * terminated instances retain no network config, so they're filtered
 * out at the API level via a server-side filter to save on payload size.
 */
async function describeInstances(region, creds) {
  const reservations = await ec2Paginate(
    'DescribeInstances',
    {
      'Filter.1.Name': 'instance-state-name',
      'Filter.1.Value.1': 'running',
      'Filter.1.Value.2': 'pending',
      'Filter.1.Value.3': 'stopping',
      'Filter.1.Value.4': 'stopped',
    },
    region,
    creds,
    'DescribeInstancesResponse',
    (resp) => asArray(resp?.reservationSet?.item)
  );

  const instances = [];
  for (const res of reservations) {
    for (const inst of asArray(res.instancesSet?.item)) {
      // Top-level ipAddress mirrors the public IP for both EC2-Classic and
      // VPC instances; fall back to the primary ENI's association in case
      // a given API response ever omits it there.
      const publicIp =
        inst.ipAddress ||
        asArray(inst.networkInterfaceSet?.item)
          .map((ni) => ni.association?.publicIp)
          .find(Boolean);
      instances.push({
        instanceId: inst.instanceId,
        state: inst.instanceState?.name,
        publicIp: publicIp || null,
        vpcId: inst.vpcId,
        subnetId: inst.subnetId,
        securityGroupIds: asArray(inst.groupSet?.item).map((g) => g.groupId).filter(Boolean),
      });
    }
  }
  return instances;
}

/** DescribeVpcs — used to cross-reference against DescribeFlowLogs so we
 * can report which VPCs have *no* flow log at all (item 4). */
async function describeVpcs(region, creds) {
  const vpcs = await ec2Paginate(
    'DescribeVpcs',
    {},
    region,
    creds,
    'DescribeVpcsResponse',
    (resp) => asArray(resp?.vpcSet?.item)
  );
  return vpcs.map((v) => ({ vpcId: v.vpcId, isDefault: v.isDefault === 'true' }));
}

async function describeFlowLogs(region, creds) {
  const logs = await ec2Paginate(
    'DescribeFlowLogs',
    {},
    region,
    creds,
    'DescribeFlowLogsResponse',
    (resp) => asArray(resp?.flowLogSet?.item)
  );
  return logs.map((f) => ({
    flowLogId: f.flowLogId,
    resourceId: f.resourceId,
    flowLogStatus: f.flowLogStatus,
  }));
}

/** GetEbsEncryptionByDefault -- one account/region-level call: "is every
 * new EBS volume encrypted unless someone opts out?" (item 3: EBS default
 * encryption is high-signal and cheap -- one call per region). */
async function getEbsEncryptionByDefault(region, creds) {
  const res = await ec2Call('GetEbsEncryptionByDefault', {}, region, creds);
  return res.xml.GetEbsEncryptionByDefaultResponse?.ebsEncryptionByDefault === 'true';
}

/** DescribeVolumes, paginated -- unattached and/or unencrypted EBS
 * volumes (item 3) weren't checked at all before. */
async function describeVolumes(region, creds) {
  const volumes = await ec2Paginate(
    'DescribeVolumes',
    {},
    region,
    creds,
    'DescribeVolumesResponse',
    (resp) => asArray(resp?.volumeSet?.item)
  );
  return volumes.map((v) => ({
    volumeId: v.volumeId,
    size: Number(v.size || 0),
    encrypted: v.encrypted === 'true',
    state: v.status,
    attachmentCount: asArray(v.attachmentSet?.item).length,
  }));
}

export {
  describeRegions,
  describeSecurityGroups,
  describeInstances,
  describeVpcs,
  describeFlowLogs,
  getEbsEncryptionByDefault,
  describeVolumes,
};
