'use strict';
import { gcpRequest } from './client.js';

async function listAll(url, key, accessToken) {
  const items = [];
  let pageToken;
  do {
    const u = new URL(url);
    if (pageToken) u.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(u.toString(), { accessToken });
    items.push(...(data[key] || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return items;
}

/** Full resource names: projects/P/topics/T */
async function listTopics(project, accessToken) {
  const topics = await listAll(`https://pubsub.googleapis.com/v1/projects/${project}/topics`, 'topics', accessToken);
  return topics.map((t) => ({ name: t.name, displayName: (t.name || '').split('/').pop() }));
}

/** Full resource names: projects/P/subscriptions/S */
async function listSubscriptions(project, accessToken) {
  const subs = await listAll(`https://pubsub.googleapis.com/v1/projects/${project}/subscriptions`, 'subscriptions', accessToken);
  return subs.map((s) => ({ name: s.name, displayName: (s.name || '').split('/').pop() }));
}

/** IAM bindings for a topic or subscription (full resource name). */
async function getIamPolicy(resourceName, accessToken) {
  const data = await gcpRequest(`https://pubsub.googleapis.com/v1/${resourceName}:getIamPolicy`, { accessToken });
  return data.bindings || [];
}

export { listTopics, listSubscriptions, getIamPolicy };
