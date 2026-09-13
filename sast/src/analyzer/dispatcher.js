'use strict';

import { PROVIDERS } from './providers.js';

// ─── Dispatcher ───────────────────────────────────────────────────────────────

async function callProvider({
  provider     = 'openrouter',
  apiKey,
  apiKeyHeader,
  apiKeyPrefix,
  endpoint,
  model,
  prompt,
  maxTokens    = 1024,
  temperature  = 0.1,
  timeoutMs    = 120_000,
} = {}) {
  if (!prompt) throw new Error('callProvider: prompt is required');

  const def = PROVIDERS[provider];
  if (!def) {
    throw new Error(
      `Unknown provider "${provider}". ` +
      `Valid values: ${Object.keys(PROVIDERS).join(', ')}`
    );
  }

  const resolvedKey =
    apiKey ||
    (def.envKey ? process.env[def.envKey] : null) ||
    process.env.UBEL_SAST_API_KEY ||
    null;

  if (def.keyRequired && !resolvedKey) {
    throw new Error(
      `Provider "${provider}" requires an API key. ` +
      `Pass --api-key <key> or set ${def.envKey || 'UBEL_SAST_API_KEY'}.`
    );
  }

  // Some registry entries (e.g. "custom") have no built-in endpoint/model —
  // they exist purely so the caller can point at an arbitrary OpenAI-compatible
  // API. Fail fast with a clear message instead of letting httpPost blow up
  // on `new URL(undefined)` or the remote API reject an undefined model.
  const resolvedEndpoint = endpoint || def.endpoint;
  if (!resolvedEndpoint) {
    throw new Error(
      `Provider "${provider}" has no default endpoint. Pass --endpoint <url> ` +
      `(an OpenAI-compatible /chat/completions URL).`
    );
  }
  const resolvedModel = model || def.model;
  if (!resolvedModel) {
    throw new Error(`Provider "${provider}" has no default model. Pass --model <name>.`);
  }

  const descriptor = {
    endpoint:     resolvedEndpoint,
    apiKey:       resolvedKey,
    apiKeyHeader: apiKeyHeader || def.apiKeyHeader,
    apiKeyPrefix: apiKeyPrefix !== undefined ? apiKeyPrefix : def.apiKeyPrefix,
    model:        resolvedModel,
    prompt,
    maxTokens,
    temperature,
    timeoutMs,
  };

  return def.fn(descriptor);
}

export { callProvider };