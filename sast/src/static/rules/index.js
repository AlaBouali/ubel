'use strict';

import { INJECTION_RULES } from './injection.js';
import { INJECTION2_RULES } from './injection2.js';
import { SECRETS_CRYPTO_RULES } from './secrets_crypto.js';
import { NATIVE_RULES } from './native.js';
import { MOBILE_RULES } from './mobile.js';
import { CONFIG_RULES } from './config.js';

export const ALL_RULES = [
  ...INJECTION_RULES, ...INJECTION2_RULES, ...SECRETS_CRYPTO_RULES, ...NATIVE_RULES, ...MOBILE_RULES, ...CONFIG_RULES,
];

// Catalog classes this engine has no rules for (they need semantic understanding of intent
// or of whole-program state). Reported in the scan stats so the gap is explicit.
export const STATIC_UNSUPPORTED_CLASSES = [
  'missing authentication check',
  'broken access control / privilege escalation',
  'insecure direct object reference (IDOR)',
  'business logic flaw',
  'null / nil dereference',
  'uninitialized variable / memory read',
  'missing rate limiting / brute force exposure',
];
