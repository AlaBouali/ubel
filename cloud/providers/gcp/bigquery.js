'use strict';
import { gcpRequest } from './client.js';
import { gcpRegion } from '../../lib/location.js';

const PUBLIC_MEMBERS = new Set(['allUsers', 'allAuthenticatedUsers']);

/** Datasets with the location each one lives in (datasets.list reports it per dataset; BigQuery locations are regions or multi-regions). */
async function listDatasets(project, accessToken) {
  const datasets = [];
  let pageToken;
  do {
    const url = new URL(`https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets`);
    url.searchParams.set('all', 'true');
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    for (const d of data.datasets || []) {
      if (d.datasetReference?.datasetId) datasets.push({ id: d.datasetReference.datasetId, region: gcpRegion(d.location) });
    }
    pageToken = data.pageToken;
  } while (pageToken);
  return datasets;
}

async function listDatasetIds(project, accessToken) {
  return (await listDatasets(project, accessToken)).map((d) => d.id);
}

/**
 * BigQuery dataset ACLs are returned inline on the dataset resource
 * itself (`access` array) — no separate getIamPolicy call needed, unlike
 * Storage/projects. Public exposure here (item 5) means an `access` entry
 * with a special "iamMember"/"specialGroup" of allUsers/allAuthenticatedUsers.
 */
async function getDatasetAccess(project, datasetId, accessToken) {
  const url = `https://bigquery.googleapis.com/bigquery/v2/projects/${project}/datasets/${encodeURIComponent(datasetId)}`;
  const data = await gcpRequest(url, { accessToken });
  const entries = data.access || [];
  return entries
    .map((e) => ({
      role: e.role,
      member: e.iamMember || e.specialGroup || e.userByEmail || e.groupByEmail || e.domain || null,
    }))
    .filter((e) => e.member && PUBLIC_MEMBERS.has(e.member));
}

export { listDatasets, listDatasetIds, getDatasetAccess };
