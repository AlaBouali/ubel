'use strict';
import { azureListAll } from './client.js';

const API_VERSION = '2021-05-01-preview';

/**
 * Diagnostic settings attached to a resource (or to the subscription itself, for
 * the Activity Log). `resourceUri` is the ARM id, e.g. "/subscriptions/<id>" or a
 * Key Vault's id. An empty list means nothing is being exported.
 */
async function listDiagnosticSettings(resourceUri, accessToken) {
  const url = `https://management.azure.com${resourceUri}/providers/Microsoft.Insights/diagnosticSettings?api-version=${API_VERSION}`;
  const settings = await azureListAll(url, accessToken);
  return settings.map((s) => ({ name: s.name }));
}

export { listDiagnosticSettings };
