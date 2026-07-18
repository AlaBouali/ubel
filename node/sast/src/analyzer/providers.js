'use strict';

import {httpPost} from './httpTransport.js';

// ─── Provider caller functions ────────────────────────────────────────────────

async function callOpenRouter({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                                model, prompt, maxTokens, temperature, timeoutMs }) {
  if (!apiKey) throw new Error('OpenRouter requires an API key (--api-key or OPENROUTER_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: prompt }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = {
    [apiKeyHeader]: `${apiKeyPrefix}${apiKey}`,
    'HTTP-Referer': 'https://github.com/ubel-sast',
    'X-Title':      'UBEL SAST',
  };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callOpenAI({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, maxTokens, temperature, timeoutMs }) {
  if (!apiKey) throw new Error('OpenAI requires an API key (--api-key or OPENAI_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: prompt }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = { [apiKeyHeader]: `${apiKeyPrefix}${apiKey}` };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callAnthropic({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                               model, prompt, maxTokens, temperature, timeoutMs }) {
  if (!apiKey) throw new Error('Anthropic requires an API key (--api-key or ANTHROPIC_API_KEY)');

  const body = JSON.stringify({
    model,
    max_tokens: maxTokens,
    messages:   [{ role: 'user', content: prompt }],
  });

  const headers = {
    [apiKeyHeader]:      `${apiKeyPrefix}${apiKey}`,
    'anthropic-version': '2023-06-01',
  };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.content?.[0]?.text ?? '';
}

async function callGemini({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, maxTokens, temperature, timeoutMs }) {
  if (!apiKey) throw new Error('Gemini requires an API key (--api-key or GEMINI_API_KEY)');

  let resolvedEndpoint = endpoint.includes('{model}')
    ? endpoint.replace('{model}', model)
    : endpoint;

  let headers = {};
  if (apiKeyHeader === 'query') {
    const sep = resolvedEndpoint.includes('?') ? '&' : '?';
    resolvedEndpoint = `${resolvedEndpoint}${sep}key=${apiKey}`;
  } else {
    headers[apiKeyHeader] = `${apiKeyPrefix}${apiKey}`;
  }

  const body = JSON.stringify({
    contents: [{ parts: [{ text: prompt }] }],
    generationConfig: {
      temperature,
      maxOutputTokens: maxTokens,
    },
  });

  const raw    = await httpPost(resolvedEndpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
}

async function callDeepSeek({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                              model, prompt, maxTokens, temperature, timeoutMs }) {
  if (!apiKey) throw new Error('DeepSeek requires an API key (--api-key or DEEPSEEK_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: prompt }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = { [apiKeyHeader]: `${apiKeyPrefix}${apiKey}` };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                           model, prompt, maxTokens, temperature, timeoutMs }) {
  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: prompt }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = apiKey ? { [apiKeyHeader]: `${apiKeyPrefix}${apiKey}` } : {};

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callDockerDesktop({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                                   model, prompt, maxTokens, temperature, timeoutMs }) {
  return callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                     model, prompt, maxTokens, temperature, timeoutMs });
}

async function callDocker({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, maxTokens, temperature, timeoutMs }) {
  return callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                     model, prompt, maxTokens, temperature, timeoutMs });
}

// ─── Provider registry & defaults ─────────────────────────────────────────────

const PROVIDERS = {
  nvidia: {
    fn:           callLocal,
    endpoint:     'https://integrate.api.nvidia.com/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'deepseek-ai/deepseek-v4-flash',
    envKey:       'NVIDIA_KEY',
    keyRequired:  true,
  },
  openrouter: {
    fn:           callOpenRouter,
    endpoint:     'https://openrouter.ai/api/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'deepseek/deepseek-chat',
    envKey:       'OPENROUTER_API_KEY',
    keyRequired:  true,
  },

  openai: {
    fn:           callOpenAI,
    endpoint:     'https://api.openai.com/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'gpt-4o-mini',
    envKey:       'OPENAI_API_KEY',
    keyRequired:  true,
  },

  anthropic: {
    fn:           callAnthropic,
    endpoint:     'https://api.anthropic.com/v1/messages',
    apiKeyHeader: 'x-api-key',
    apiKeyPrefix: '',
    model:        'claude-haiku-4-5-20251001',
    envKey:       'ANTHROPIC_API_KEY',
    keyRequired:  true,
  },

  gemini: {
    fn:           callGemini,
    endpoint:     'https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent',
    apiKeyHeader: 'query',
    apiKeyPrefix: '',
    model:        'gemini-2.0-flash',
    envKey:       'GEMINI_API_KEY',
    keyRequired:  true,
  },

  deepseek: {
    fn:           callDeepSeek,
    endpoint:     'https://api.deepseek.com/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'deepseek-chat',
    envKey:       'DEEPSEEK_API_KEY',
    keyRequired:  true,
  },

  local: {
    fn:           callLocal,
    endpoint:     'http://localhost:11434/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'llama3',
    envKey:       null,
    keyRequired:  false,
  },

  'docker-desktop': {
    fn:           callDockerDesktop,
    endpoint:     'http://host.docker.internal:11434/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'llama3',
    envKey:       null,
    keyRequired:  false,
  },

  docker: {
    fn:           callDocker,
    endpoint:     'http://localhost:11434/v1/chat/completions',
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        'llama3',
    envKey:       null,
    keyRequired:  false,
  },

  // Catch-all for any OpenAI-compatible /chat/completions endpoint that
  // isn't one of the named providers above (self-hosted, internal proxy,
  // less common hosted APIs, etc.). Unlike every other entry, endpoint and
  // model have no default — the caller MUST supply --endpoint and --model
  // (dispatcher.js / analyzeSast.js / analyzeMalware.js all fail fast with
  // a clear error if either is missing). apiKeyHeader/apiKeyPrefix/apiKey
  // can still be overridden the same way as any other provider, for targets
  // that don't use "Authorization: Bearer <key>".
  custom: {
    fn:           callLocal,
    endpoint:     null,
    apiKeyHeader: 'Authorization',
    apiKeyPrefix: 'Bearer ',
    model:        null,
    envKey:       'CUSTOM_API_KEY',
    keyRequired:  false,
  },
};

export {
  PROVIDERS,
  callOpenRouter, callOpenAI, callAnthropic, callGemini, callDeepSeek,
  callLocal, callDockerDesktop, callDocker,
};