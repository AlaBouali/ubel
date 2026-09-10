'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const SQS_API_VERSION = '2012-11-05';

function sqsHost(region) {
  return `sqs.${region}.amazonaws.com`;
}

async function sqsCall(action, params, region, creds) {
  const body = formBody({ Action: action, Version: SQS_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'sqs',
      region,
      host: sqsHost(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

async function listQueueUrls(region, creds) {
  return paginateQuery(
    (token) => sqsCall('ListQueues', token ? { NextToken: token } : {}, region, creds),
    (xml) => asArray(xml.ListQueuesResponse?.ListQueuesResult?.QueueUrl),
    (xml) => xml.ListQueuesResponse?.ListQueuesResult?.NextToken || undefined
  );
}

/**
 * A queue's resource policy (item 3, parallel to sns.js's
 * getTopicPolicy). Unlike SNS's Attributes map, SQS's serializes each
 * entry as <Attribute><Name>/<Value> rather than <entry><key>/<value> --
 * an inconsistency in AWS's own APIs, not a typo here.
 */
async function getQueuePolicy(queueUrl, region, creds) {
  const res = await sqsCall(
    'GetQueueAttributes',
    { QueueUrl: queueUrl, 'AttributeName.1': 'Policy', 'AttributeName.2': 'QueueArn' },
    region,
    creds
  );
  const entries = asArray(res.xml.GetQueueAttributesResponse?.GetQueueAttributesResult?.Attribute);
  const policyEntry = entries.find((e) => e.Name === 'Policy');
  const arnEntry = entries.find((e) => e.Name === 'QueueArn');
  let policy = null;
  if (policyEntry?.Value) {
    try {
      policy = JSON.parse(policyEntry.Value);
    } catch {
      policy = null;
    }
  }
  return { policy, arn: arnEntry?.Value || null };
}

export { listQueueUrls, getQueuePolicy };
