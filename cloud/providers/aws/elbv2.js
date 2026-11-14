'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

// Elastic Load Balancing v2 (Application / Network / Gateway load balancers),
// query protocol like EC2/RDS.
const ELBV2_API_VERSION = '2015-12-01';

function elbHost(region) {
  return `elasticloadbalancing.${region}.amazonaws.com`;
}

async function elbCall(action, params, region, creds) {
  const body = formBody({ Action: action, Version: ELBV2_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'elasticloadbalancing',
      region,
      host: elbHost(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

/** Marker/NextMarker pagination shared by the two list calls below. */
function elbPaginate(action, params, region, creds, listPath) {
  return paginateQuery(
    (token) => elbCall(action, token ? { ...params, Marker: token } : params, region, creds),
    (xml) => asArray(listPath(xml[`${action}Response`]?.[`${action}Result`])),
    (xml) => xml[`${action}Response`]?.[`${action}Result`]?.NextMarker || undefined
  );
}

async function describeLoadBalancers(region, creds) {
  const lbs = await elbPaginate('DescribeLoadBalancers', {}, region, creds, (r) => r?.LoadBalancers?.member);
  return lbs.map((lb) => ({
    arn: lb.LoadBalancerArn,
    name: lb.LoadBalancerName,
    // 'internet-facing' | 'internal'
    scheme: lb.Scheme,
    // 'application' | 'network' | 'gateway'
    type: lb.Type,
    dnsName: lb.DNSName,
  }));
}

async function describeListeners(loadBalancerArn, region, creds) {
  const listeners = await elbPaginate(
    'DescribeListeners',
    { LoadBalancerArn: loadBalancerArn },
    region,
    creds,
    (r) => r?.Listeners?.member
  );
  return listeners.map((l) => ({
    arn: l.ListenerArn,
    protocol: l.Protocol,
    port: Number(l.Port),
    sslPolicy: l.SslPolicy || null,
    defaultActionTypes: asArray(l.DefaultActions?.member).map((a) => a.Type),
  }));
}

/** Attributes come back as a flat Key/Value list; returned here as a plain map. */
async function describeLoadBalancerAttributes(loadBalancerArn, region, creds) {
  const res = await elbCall('DescribeLoadBalancerAttributes', { LoadBalancerArn: loadBalancerArn }, region, creds);
  const members = asArray(
    res.xml.DescribeLoadBalancerAttributesResponse?.DescribeLoadBalancerAttributesResult?.Attributes?.member
  );
  const map = {};
  for (const m of members) if (m.Key) map[m.Key] = m.Value;
  return map;
}

export { describeLoadBalancers, describeListeners, describeLoadBalancerAttributes };
