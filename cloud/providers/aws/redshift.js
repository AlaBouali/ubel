'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const REDSHIFT_API_VERSION = '2012-12-01';

function redshiftHost(region) {
  return `redshift.${region}.amazonaws.com`;
}

async function redshiftCall(action, params, region, creds) {
  const body = formBody({ Action: action, Version: REDSHIFT_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'redshift',
      region,
      host: redshiftHost(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

/** DescribeClusters, paginated via Marker (like RDS, the presence of a non-empty
 * <Marker> is the "more pages" signal). */
async function describeClusters(region, creds) {
  const clusters = await paginateQuery(
    (token) => redshiftCall('DescribeClusters', token ? { Marker: token } : {}, region, creds),
    (xml) => asArray(xml.DescribeClustersResponse?.DescribeClustersResult?.Clusters?.Cluster),
    (xml) => xml.DescribeClustersResponse?.DescribeClustersResult?.Marker || undefined
  );
  return clusters.map((c) => ({
    id: c.ClusterIdentifier,
    publiclyAccessible: c.PubliclyAccessible === 'true',
    encrypted: c.Encrypted === 'true',
    status: c.ClusterStatus,
  }));
}

export { describeClusters };
