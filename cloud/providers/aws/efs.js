'use strict';
import { awsRestJsonRequest } from './client.js';

function efsHost(region) {
  return `elasticfilesystem.${region}.amazonaws.com`;
}

/** DescribeFileSystems (REST-JSON), following NextMarker. */
async function describeFileSystems(region, creds) {
  const all = [];
  let marker;
  do {
    const res = await awsRestJsonRequest(
      {
        service: 'elasticfilesystem',
        region,
        host: efsHost(region),
        method: 'GET',
        path: '/2015-02-01/file-systems',
        query: { MaxItems: '100', ...(marker ? { Marker: marker } : {}) },
      },
      creds
    );
    all.push(...(res.json.FileSystems || []));
    marker = res.json.NextMarker || undefined;
  } while (marker);
  return all.map((f) => ({
    id: f.FileSystemId,
    name: f.Name || null,
    encrypted: Boolean(f.Encrypted),
  }));
}

export { describeFileSystems };
