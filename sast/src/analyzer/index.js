'use strict';

import {analyzeSast} from './analyzeSast.js';
import {analyzeMalware} from './analyzeMalware.js';
import {callProvider} from './dispatcher.js';
import {callProviderWithRetry} from './retry.js';
import {resolveGitDiffFiles} from './gitDiff.js';
import {PROVIDERS} from './providers.js';
import {DEFAULT_VULN_CLASSES, buildVulnCatalog} from './vulnCatalog.js';
import {DEFAULT_MALWARE_CLASSES, buildMalwareCatalog} from './malwareCatalog.js';
import {
  defaultBuildPrompt,
  buildScanPromptParts,
  defaultVerificationPrompt,
  defaultBatchVerificationPrompt,
  defaultTaintTracePrompt,
  defaultBatchTaintTracePrompt,
} from './prompts.js';
import {
  defaultBuildMalwarePrompt,
  buildMalwarePromptParts,
  defaultMalwareVerificationPrompt,
  defaultBatchMalwareVerificationPrompt,
} from './malwarePrompts.js';

export { 
  analyzeSast,
  analyzeMalware,
  callProvider,
  callProviderWithRetry,
  resolveGitDiffFiles,
  PROVIDERS,
  DEFAULT_VULN_CLASSES,
  DEFAULT_MALWARE_CLASSES,
  defaultBuildPrompt,
  buildScanPromptParts,
  buildVulnCatalog,
  buildMalwareCatalog,
  defaultVerificationPrompt,
  defaultBatchVerificationPrompt,
  defaultTaintTracePrompt,
  defaultBatchTaintTracePrompt,
  defaultBuildMalwarePrompt,
  buildMalwarePromptParts,
  defaultMalwareVerificationPrompt,
  defaultBatchMalwareVerificationPrompt,
};
