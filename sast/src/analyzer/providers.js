'use strict';

import {httpPost} from './httpTransport.js';

// ─── Token usage extraction ───────────────────────────────────────────────────
// Every provider reports real token counts in its response; reading them is what
// lets a run say what it actually spent instead of a chars/4 guess. Normalised to
// { input, output, cache_read, cache_write } (any missing field is 0).
function usageFrom(parsed) {
  const u = parsed?.usage;
  if (u) {
    // Anthropic: input_tokens EXCLUDES cached tokens; OpenAI-style: prompt_tokens includes them.
    if (u.input_tokens !== undefined || u.output_tokens !== undefined) {
      return {
        input: u.input_tokens || 0, output: u.output_tokens || 0,
        cache_read: u.cache_read_input_tokens || 0, cache_write: u.cache_creation_input_tokens || 0,
      };
    }
    return {
      input: u.prompt_tokens || 0, output: u.completion_tokens || 0,
      cache_read: u.prompt_tokens_details?.cached_tokens || u.prompt_cache_hit_tokens || 0, cache_write: 0,
    };
  }
  const g = parsed?.usageMetadata;                       // Gemini
  if (g) {
    return {
      input: g.promptTokenCount || 0, output: g.candidatesTokenCount || 0,
      cache_read: g.cachedContentTokenCount || 0, cache_write: 0,
    };
  }
  return null;
}
function reportUsage(onUsage, parsed) {
  if (typeof onUsage !== 'function') return;
  // A provider that returns no usage block is still a call: report it with
  // missing:true so the totals can say how many calls were estimated, not measured.
  const u = usageFrom(parsed) || { input: 0, output: 0, cache_read: 0, cache_write: 0, missing: true };
  try { onUsage(u); } catch { /* accounting must never break a scan */ }
}

// Prompt = promptPrefix (static, cache-friendly) + prompt (the variable tail).
// Providers with no explicit cache control just get the concatenation — the
// static-prefix-first ordering still lets automatic prefix caching work.
const fullPrompt = (promptPrefix, prompt) => (promptPrefix ? promptPrefix + prompt : prompt);

// Prompt caching needs a minimum prefix length (1,024 tokens on most Claude
// models, more on some); below it the marker is simply ignored by the API, but
// there is no point sending it for a tiny prefix.
const MIN_CACHEABLE_PREFIX_CHARS = 4096;

// ─── Provider caller functions ────────────────────────────────────────────────

async function callOpenRouter({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                                model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  if (!apiKey) throw new Error('OpenRouter requires an API key (--api-key or OPENROUTER_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: fullPrompt(promptPrefix, prompt) }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = {
    'ngrok-skip-browser-warning': 'true',
    [apiKeyHeader]: `${apiKeyPrefix}${apiKey}`,
    'HTTP-Referer': 'https://github.com/ubel-sast',
    'X-Title':      'UBEL SAST',
  };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callOpenAI({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  if (!apiKey) throw new Error('OpenAI requires an API key (--api-key or OPENAI_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: fullPrompt(promptPrefix, prompt) }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = {
    'ngrok-skip-browser-warning': 'true',
    [apiKeyHeader]: `${apiKeyPrefix}${apiKey}`
  };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callAnthropic({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                               model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  if (!apiKey) throw new Error('Anthropic requires an API key (--api-key or ANTHROPIC_API_KEY)');

  // temperature MUST be sent: without it Anthropic runs at its default (1.0), which
  // silently broke the "Pass 2/3 are deterministic (temperature 0)" guarantee.
  // When a static prefix is supplied it goes in its own content block with a
  // cache_control breakpoint, so every call after the first reads it from cache.
  const content = (promptPrefix && promptPrefix.length >= MIN_CACHEABLE_PREFIX_CHARS)
    ? [
        { type: 'text', text: promptPrefix, cache_control: { type: 'ephemeral' } },
        { type: 'text', text: prompt },
      ]
    : fullPrompt(promptPrefix, prompt);

  const makeBody = (withTemperature) => JSON.stringify({
    model,
    max_tokens: maxTokens,
    ...(withTemperature && typeof temperature === 'number' && Number.isFinite(temperature) ? { temperature } : {}),
    messages:   [{ role: 'user', content }],
  });

  const headers = {
    'ngrok-skip-browser-warning': 'true',
    [apiKeyHeader]:      `${apiKeyPrefix}${apiKey}`,
    'anthropic-version': '2023-06-01',
  };

  let raw;
  try {
    raw = await httpPost(endpoint, headers, makeBody(true), timeoutMs);
  } catch (err) {
    // A few newer Claude models reject an explicit sampling temperature. Retry
    // once without it rather than failing the whole scan on a parameter the
    // model has fixed anyway.
    if (err.statusCode === 400 && /temperature/i.test(err.message || '')) {
      raw = await httpPost(endpoint, headers, makeBody(false), timeoutMs);
    } else {
      throw err;
    }
  }
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  // Join every text block (models with extended thinking put a non-text block first).
  const blocks = Array.isArray(parsed?.content) ? parsed.content : [];
  return blocks.filter(b => b && b.type === 'text').map(b => b.text).join('') || (parsed?.content?.[0]?.text ?? '');
}

async function callGemini({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  if (!apiKey) throw new Error('Gemini requires an API key (--api-key or GEMINI_API_KEY)');

  let resolvedEndpoint = endpoint.includes('{model}')
    ? endpoint.replace('{model}', model)
    : endpoint;

  let headers = {};
  if (apiKeyHeader === 'query') {
    const sep = resolvedEndpoint.includes('?') ? '&' : '?';
    resolvedEndpoint = `${resolvedEndpoint}${sep}key=${apiKey}`;
    headers['ngrok-skip-browser-warning'] = 'true';
  } else {
    headers[apiKeyHeader] = `${apiKeyPrefix}${apiKey}`;
    headers['ngrok-skip-browser-warning'] = 'true';
  }

  const body = JSON.stringify({
    contents: [{ parts: [{ text: fullPrompt(promptPrefix, prompt) }] }],
    generationConfig: {
      temperature,
      maxOutputTokens: maxTokens,
    },
  });

  const raw    = await httpPost(resolvedEndpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  return parsed?.candidates?.[0]?.content?.parts?.[0]?.text ?? '';
}

async function callDeepSeek({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                              model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  if (!apiKey) throw new Error('DeepSeek requires an API key (--api-key or DEEPSEEK_API_KEY)');

  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: fullPrompt(promptPrefix, prompt) }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = {
    'ngrok-skip-browser-warning': 'true',
    [apiKeyHeader]: `${apiKeyPrefix}${apiKey}`
  };

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                           model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  const body = JSON.stringify({
    model,
    messages:   [{ role: 'user', content: fullPrompt(promptPrefix, prompt) }],
    temperature,
    max_tokens: maxTokens,
  });

  const headers = apiKey ? { [apiKeyHeader]: `${apiKeyPrefix}${apiKey}` } : {};
  headers['ngrok-skip-browser-warning'] = 'true';

  const raw    = await httpPost(endpoint, headers, body, timeoutMs);
  const parsed = JSON.parse(raw);
  reportUsage(onUsage, parsed);
  return parsed?.choices?.[0]?.message?.content ?? '';
}

async function callDockerDesktop({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                                   model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  return callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                     model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage });
}

async function callDocker({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                            model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage }) {
  return callLocal({ endpoint, apiKey, apiKeyHeader, apiKeyPrefix,
                     model, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage });
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