'use strict';
import { awsRequest, formBody, paginateQuery } from './client.js';
import { asArray } from '../../lib/xml.js';

const SNS_API_VERSION = '2010-03-31';

function snsHost(region) {
  return `sns.${region}.amazonaws.com`;
}

async function snsCall(action, params, region, creds) {
  const body = formBody({ Action: action, Version: SNS_API_VERSION, ...params });
  return awsRequest(
    {
      service: 'sns',
      region,
      host: snsHost(region),
      method: 'POST',
      path: '/',
      body,
      headers: { 'content-type': 'application/x-www-form-urlencoded; charset=utf-8' },
    },
    creds
  );
}

async function listTopics(region, creds) {
  return paginateQuery(
    (token) => snsCall('ListTopics', token ? { NextToken: token } : {}, region, creds),
    (xml) => asArray(xml.ListTopicsResponse?.ListTopicsResult?.Topics?.member).map((t) => t.TopicArn),
    (xml) => xml.ListTopicsResponse?.ListTopicsResult?.NextToken || undefined
  );
}

/**
 * A topic's resource policy (item 3: "SNS/SQS resource policies granting
 * public access, parallel to the S3 policy check"). GetTopicAttributes
 * returns a generic string-to-string Attributes map (Policy is just one
 * entry in it), serialized as the query protocol's usual
 * <entry><key>/<value> pairs rather than a dedicated Policy field.
 */
async function getTopicPolicy(topicArn, region, creds) {
  const res = await snsCall('GetTopicAttributes', { TopicArn: topicArn }, region, creds);
  const entries = asArray(res.xml.GetTopicAttributesResponse?.GetTopicAttributesResult?.Attributes?.entry);
  const policyEntry = entries.find((e) => e.key === 'Policy');
  if (!policyEntry?.value) return null;
  try {
    return JSON.parse(policyEntry.value);
  } catch {
    return null;
  }
}

export { listTopics, getTopicPolicy };
