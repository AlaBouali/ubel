'use strict';

import fs   from 'fs';
import path from 'path';

// ─── Docker / IaC detection ────────────────────────────────────────────────
//
// Dockerfiles, Compose files, Terraform, Kubernetes manifests, CloudFormation
// templates, and Ansible playbooks are declarative config, not "code" in the
// function/brace sense — they are chunked whole-file (see languages/docker.js
// and languages/iac.js) rather than decomposed. This module figures out
// *which* of those a given file is, either from its name/extension alone
// (cheap, no I/O) or — for the ambiguous .yaml/.yml/.json extensions shared
// with countless non-IaC files — by sniffing already-loaded content for a
// telltale shape. Callers that have already read the file (the chunker) pass
// that content in directly so we never read a file twice.

const MAX_SNIFF_BYTES = 512_000; // mirrors dispatcher.js's file-size guard

// Kind → family (used for the --languages filter and vuln-catalog matching)
const KIND_FAMILY = {
  dockerfile:     'docker',
  compose:        'docker',
  terraform:      'iac',
  kubernetes:     'k8s',
  cloudformation: 'iac',
  ansible:        'iac',
};

// Kind → human-readable label (used as chunk.language / prompt display)
const KIND_LABEL = {
  dockerfile:     'Dockerfile',
  compose:        'Docker Compose',
  terraform:      'Terraform',
  kubernetes:     'Kubernetes',
  cloudformation: 'CloudFormation',
  ansible:        'Ansible',
};

// Kind → markdown fence tag for prompt code blocks (some labels above aren't
// valid single-word fence languages, e.g. "Docker Compose" has a space)
const KIND_FENCE_LANG = {
  dockerfile:     'dockerfile',
  compose:        'yaml',
  terraform:      'hcl',
  kubernetes:     'yaml',
  cloudformation: 'yaml',
  ansible:        'yaml',
};

// Name-only detection — Dockerfiles and Compose files are identified by
// filename convention, never by extension (Dockerfile has none).
function detectDockerKind(filePath) {
  const base = path.basename(filePath).toLowerCase();

  if (base === 'dockerfile' || base.startsWith('dockerfile.') || base.endsWith('.dockerfile')) {
    return 'dockerfile';
  }
  // docker-compose.yml, compose.yaml, docker-compose.prod.yml, etc.
  if (/^(docker-)?compose(\.[\w-]+)?\.ya?ml$/.test(base)) {
    return 'compose';
  }
  return null;
}

// Content sniff for ambiguous .yaml/.yml/.json files — only classified as
// IaC when a clear structural marker is present, so an arbitrary CI config
// or app settings file doesn't get swept in as "infrastructure as code".
function detectIacContentKind(content) {
  if (/^apiVersion:\s*\S/m.test(content) && /^kind:\s*\S/m.test(content)) {
    return 'kubernetes';
  }
  if (/AWSTemplateFormatVersion/.test(content) ||
      (/["']?Resources["']?\s*:/.test(content) && /AWS::[A-Za-z0-9]+::[A-Za-z0-9]+/.test(content))) {
    return 'cloudformation';
  }
  if (/^-?\s*hosts:\s*\S/m.test(content) && /\btasks\s*:/.test(content)) {
    return 'ansible';
  }
  return null;
}

function readSmall(filePath) {
  let content;
  try { content = fs.readFileSync(filePath, 'utf8'); }
  catch { return null; }
  if (content.length > MAX_SNIFF_BYTES) return null;
  return content;
}

// Full kind resolution for a file on disk. `content`, if the caller already
// has it loaded, avoids a redundant read for the yaml/json sniff path.
function detectConfigKind(filePath, content) {
  const dockerKind = detectDockerKind(filePath);
  if (dockerKind) return dockerKind;

  const ext = path.extname(filePath).toLowerCase();
  if (ext === '.tf' || ext === '.tfvars') return 'terraform';

  if (ext === '.yaml' || ext === '.yml' || ext === '.json') {
    const text = content !== undefined ? content : readSmall(filePath);
    if (text === null || text === undefined) return null;
    return detectIacContentKind(text);
  }
  return null;
}

function familyForKind(kind) {
  return KIND_FAMILY[kind] || null;
}

export {
  KIND_FAMILY,
  KIND_LABEL,
  KIND_FENCE_LANG,
  detectDockerKind,
  detectIacContentKind,
  detectConfigKind,
  familyForKind,
};