'use strict';
import { awsRestJsonRequest } from './client.js';

function guarddutyHost(region) {
  return `guardduty.${region}.amazonaws.com`;
}

/** ListDetectors -- "is GuardDuty (threat detection) even turned on in
 * this region?" (item 3: "is threat detection on?" -- one call, high
 * signal). A region with zero detector IDs has no GuardDuty coverage at
 * all. */
async function listDetectorIds(region, creds) {
  const res = await awsRestJsonRequest(
    { service: 'guardduty', region, host: guarddutyHost(region), method: 'GET', path: '/detector' },
    creds
  );
  return res.json.DetectorIds || [];
}

/** A detector can exist but be administratively disabled -- Status is
 * 'ENABLED' or 'DISABLED'. */
async function getDetector(detectorId, region, creds) {
  const res = await awsRestJsonRequest(
    { service: 'guardduty', region, host: guarddutyHost(region), method: 'GET', path: `/detector/${detectorId}` },
    creds
  );
  return { status: res.json.Status || 'DISABLED' };
}

export { listDetectorIds, getDetector };
