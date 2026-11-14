'use strict';
import { awsJsonRequest } from './client.js';

// AWS Config is an AWS JSON 1.1 service; its internal service name (and so its
// X-Amz-Target prefix) is "StarlingDoveService".
const TARGET_PREFIX = 'StarlingDoveService';

function configHost(region) {
  return `config.${region}.amazonaws.com`;
}

/**
 * Configuration recorders in a region and whether each is recording. A region
 * with an empty list has no recorder at all (the usual "Config never turned on"
 * state); a recorder with recording=false was stopped.
 */
async function describeRecorderStatus(region, creds) {
  const res = await awsJsonRequest(
    {
      service: 'config',
      region,
      host: configHost(region),
      target: `${TARGET_PREFIX}.DescribeConfigurationRecorderStatus`,
      body: {},
    },
    creds
  );
  return (res.json.ConfigurationRecordersStatus || []).map((r) => ({
    name: r.name,
    recording: Boolean(r.recording),
    lastStatus: r.lastStatus || null,
  }));
}

export { describeRecorderStatus };
