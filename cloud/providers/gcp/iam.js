'use strict';
import { gcpRequest } from './client.js';

async function getProjectIamPolicy(project, accessToken) {
  const url = `https://cloudresourcemanager.googleapis.com/v1/projects/${project}:getIamPolicy`;
  const data = await gcpRequest(url, { accessToken, method: 'POST', body: {} });
  return data.bindings || [];
}

export { getProjectIamPolicy };
