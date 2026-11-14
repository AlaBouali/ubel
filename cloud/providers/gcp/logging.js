'use strict';
import { gcpRequest } from './client.js';

/**
 * Log sinks (exports) defined on the project. A sink with no filter exports every
 * log entry -- what CIS GCP 2.2 asks for so logs outlive the default retention.
 * Organization/folder-level sinks aren't visible from a project-scoped call.
 */
async function listSinks(project, accessToken) {
  const sinks = [];
  let pageToken;
  do {
    const url = new URL(`https://logging.googleapis.com/v2/projects/${project}/sinks`);
    if (pageToken) url.searchParams.set('pageToken', pageToken);
    const data = await gcpRequest(url.toString(), { accessToken });
    sinks.push(...(data.sinks || []));
    pageToken = data.nextPageToken;
  } while (pageToken);
  return sinks.map((s) => ({
    name: s.name,
    destination: s.destination,
    exportsEverything: !s.filter || String(s.filter).trim() === '',
    disabled: Boolean(s.disabled),
  }));
}

export { listSinks };
