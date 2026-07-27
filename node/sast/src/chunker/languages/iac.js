'use strict';

import path from 'path';

import { detectConfigKind } from '../configDetect.js';

// ─── IaC chunker ────────────────────────────────────────────────────────────
//
// Terraform, Kubernetes manifests, CloudFormation templates, and Ansible
// playbooks are declarative config — submitted whole-file, same rationale as
// Docker (see docker.js). `content` is passed straight to detectConfigKind so
// the already-loaded yaml/json content is re-used for the kind sniff instead
// of reading the file a second time.

function chunkIac(filePath, lines) {
  const code = lines.join('\n');
  if (code.trim().length === 0) return [];

  const kind = detectConfigKind(filePath, code) || 'terraform';
  const name = path.basename(filePath);

  return [{
    id:        `${filePath}:all`,
    type:      kind,          // 'terraform' | 'kubernetes' | 'cloudformation' | 'ansible'
    file:      filePath,
    class:     null,
    name,
    startLine: 1,
    endLine:   lines.length,
    code,
  }];
}

export { chunkIac };
