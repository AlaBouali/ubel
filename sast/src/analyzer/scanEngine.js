'use strict';

// ─── Shared Pass-1 engine (vulnerability scan AND malware scan) ───────────────
//
// Two jobs the per-chunk loop used to do badly:
//
//   1. PACKING. The prompt scaffold (rules + catalog + schema) is a fixed cost
//      paid once per call. A real repo's median chunk is a few hundred chars, so
//      one-call-per-chunk spends 75–95% of Pass-1 input on scaffold. Small
//      chunks that share one catalog (same language, or languages whose
//      filtered catalog is identical, e.g. JS+TS, C+C++) are therefore grouped
//      into one call (up to
//      `pack.size` characters of code) and the model cites a chunk id per
//      finding. Anything that goes wrong with a packed call — transport error,
//      unusable reply, truncated reply, a finding that can't be attributed to a
//      chunk — falls back to scanning those chunks one by one, so packing can
//      only save tokens, never silently lose a chunk.
//
//   2. CACHING + ACCOUNTING. Every call is sent as { promptPrefix, prompt }:
//      the static scaffold first (cacheable), the code last. Token usage from
//      the provider's own response is accumulated per pass.

import { stripComments } from '../chunker/index.js';
import { callProviderWithRetry } from './retry.js';
import { runPool } from './pool.js';

// ─── Usage accounting ─────────────────────────────────────────────────────────

function emptyUsage() {
  return { calls: 0, input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0, estimated_calls: 0 };
}

// Returns an onUsage callback that folds one response's usage into `bucket`.
// When the provider reported nothing, input is estimated as chars/4 and the call
// is counted in `estimated_calls` so reports never present a guess as a measurement.
function usageSink(bucket) {
  return (u) => {
    bucket.calls++;
    if (u.missing) {
      bucket.estimated_calls++;
      bucket.input_tokens += Math.ceil((u.prompt_chars || 0) / 4);
      return;
    }
    bucket.input_tokens       += u.input       || 0;
    bucket.output_tokens      += u.output      || 0;
    bucket.cache_read_tokens  += u.cache_read  || 0;
    bucket.cache_write_tokens += u.cache_write || 0;
  };
}

// ─── Packing ──────────────────────────────────────────────────────────────────

/**
 * Greedy, order-preserving packing of chunk indices into calls.
 *   - never mixes catalogs: chunks are grouped by `keyOf(chunk)`, which defaults
 *     to the chunk's language label. Callers pass makeCatalogPackKey() so that
 *     languages whose language-filtered catalog is identical (JavaScript and
 *     TypeScript, C and C++, Terraform/CloudFormation/Ansible, Dockerfile and
 *     Compose) share calls — and the same cacheable prompt prefix — instead of
 *     being split by display label,
 *   - a chunk larger than size/2 is scanned alone (it already amortises the scaffold),
 *   - a call holds at most `maxChunks` chunks.
 * `lengths[i]` is the comment-stripped code length of chunk i.
 */
function planBins(chunks, lengths, { size = 12_000, maxChunks = 10, keyOf } = {}) {
  if (!size || size <= 0 || maxChunks <= 1) return chunks.map((_, i) => [i]);

  const groupKey = typeof keyOf === 'function' ? keyOf : (c) => c.language || 'unknown';
  const byKey = new Map();
  chunks.forEach((c, i) => {
    const k = groupKey(c);
    if (!byKey.has(k)) byKey.set(k, []);
    byKey.get(k).push(i);
  });

  const bins = [];
  for (const idxs of byKey.values()) {
    let cur = [], curLen = 0;
    const close = () => { if (cur.length) bins.push(cur); cur = []; curLen = 0; };
    for (const i of idxs) {
      const len = lengths[i];
      if (len > size / 2) { close(); bins.push([i]); continue; }
      if (cur.length >= maxChunks || curLen + len > size) close();
      cur.push(i); curLen += len;
    }
    close();
  }
  return bins;
}

/**
 * Builds a `keyOf` for planBins: two chunks get the same key exactly when the
 * language filter selects the same class list for them, i.e. when their prompt
 * prefixes would be identical. Unknown languages fail open to the full catalog
 * in the filters, so they naturally land in their own group.
 */
function makeCatalogPackKey(filterFn, classes) {
  const cache = new Map();
  return (chunk) => {
    const lang = chunk.language || 'unknown';
    if (!cache.has(lang)) cache.set(lang, filterFn(classes, lang).map(v => v.name).join('\u0001'));
    return cache.get(lang);
  };
}

// A packed reply carries the findings of up to --pack-max-chunks chunks. If the
// output budget is too small the reply is cut off, the whole pack is discarded
// and every chunk in it is re-scanned one by one — the run then costs MORE than
// it would have with a sane budget. ~1,500 tokens holds roughly a dozen findings.
const MIN_PACKED_MAX_TOKENS = 1500;

/** Returns a warning string when packing is on and `maxTokens` is too low for it, else null. */
function packedMaxTokensWarning({ maxTokens, packSize, packMaxChunks }) {
  if (!(packSize > 0) || !(packMaxChunks > 1)) return null;
  if (!Number.isFinite(maxTokens) || maxTokens >= MIN_PACKED_MAX_TOKENS) return null;
  return `--max-tokens ${maxTokens} is low while packing is on: a packed call that is cut off is discarded ` +
         `and its chunks are re-scanned one by one, which costs more than a larger budget. ` +
         `Use --max-tokens ${MIN_PACKED_MAX_TOKENS} or more, or --no-pack.`;
}

// Assign each finding of a packed reply to a chunk of the bin. Returns
// { perChunk: Finding[][], unattributed: Finding[] }.
function attributeFindings(findings, binChunks) {
  const perChunk = binChunks.map(() => []);
  const unattributed = [];
  const norm = (t) => String(t || '').replace(/\s+/g, ' ').trim();
  const normCode = binChunks.map(c => norm(c.code));

  for (const f of findings) {
    let idx = -1;
    const m = /^C?(\d+)$/i.exec(String(f.chunk_id ?? '').trim());
    if (m) { const n = parseInt(m[1], 10) - 1; if (n >= 0 && n < binChunks.length) idx = n; }
    if (idx < 0) {
      const snip = norm(f.code_snippet);
      if (snip) {
        const hits = normCode.map((c, i) => (c.includes(snip) ? i : -1)).filter(i => i >= 0);
        if (hits.length >= 1) idx = hits[0];
      }
    }
    delete f.chunk_id;
    if (idx < 0) unattributed.push(f); else perChunk[idx].push(f);
  }
  return { perChunk, unattributed };
}

const isAuthFatal = (err) => {
  const c = err && err.statusCode;
  const msg = (err && err.message) || '';
  return c === 401 || c === 403 || c === 404 || msg.includes('requires an API key') || msg.includes('HTTP 401') || msg.includes('HTTP 403');
};

// ─── The pass ─────────────────────────────────────────────────────────────────

/**
 * @param opts.chunks          enriched chunks to scan (imports already removed)
 * @param opts.buildParts      (chunks[], includeSignals) => { prefix, body }   — default prompts
 * @param opts.customPrompt    (chunk) => string — when set, packing and caching are skipped
 * @param opts.providerBase    { provider, apiKey, apiKeyHeader, apiKeyPrefix, endpoint, model }
 * @param opts.pack            { size, maxChunks }  (size 0 disables packing)
 * @param opts.packKey         (chunk) => string — chunks with the same key may share a call (default: language label)
 * @param opts.hitIcon         icon printed for a chunk with findings
 * @param opts.stats           mutable counters (pipeline stats)
 * @param opts.usage           usage bucket for this pass
 */
async function runScanPass(opts) {
  const {
    chunks, buildParts, customPrompt, includeSignals = false, providerBase,
    maxTokens, temperature, timeoutMs, retryOnParseError, maxRetries,
    pack = { size: 12_000, maxChunks: 10 }, packKey, concurrency = 5,
    hitIcon = '⚠ ', stats = {}, usage = emptyUsage(),
  } = opts;

  const total = chunks.length;
  let done = 0;

  // Comment-stripped copy, computed once, used for sizing and for the prompt.
  // The stored chunk keeps its original source.
  const cleaned = chunks.map(c => ({ ...c, code: stripComments(c.code, c.file) }));
  const lengths = cleaned.map(c => c.code.length);

  const bins = customPrompt ? chunks.map((_, i) => [i]) : planBins(cleaned, lengths, { ...pack, keyOf: packKey });
  stats.scan_calls_planned = bins.length;
  stats.scan_chunks        = total;
  stats.scan_packed_calls  = bins.filter(b => b.length > 1).length;
  stats.scan_packed_chunks = bins.filter(b => b.length > 1).reduce((n, b) => n + b.length, 0);

  const onUsage = usageSink(usage);

  async function callFor(list) {
    let prompt, promptPrefix;
    if (customPrompt && list.length === 1) {
      prompt = customPrompt(list[0]);
    } else {
      const parts = buildParts(list, includeSignals);
      prompt = parts.body; promptPrefix = parts.prefix;
    }
    return callProviderWithRetry(
      { ...providerBase, prompt, promptPrefix, maxTokens, temperature, timeoutMs, onUsage },
      { retryOnParseError, maxRetries },
    );
  }

  const record = (i, findings, error, partial) => {
    const c = chunks[i];
    const r = {
      id: c.id, file: c.file, type: c.type, class: c.class, name: c.name, language: c.language,
      startLine: c.startLine, endLine: c.endLine, findings, error,
    };
    if (partial) r.partial_output = true;
    return r;
  };

  const report = (i, findings, error, secs) => {
    done++;
    const real    = findings.filter(f => !f._parse_error);
    const flag    = real.length > 0 ? `${hitIcon} ${real.length} finding(s)` : '✓  clean';
    const errFlag = error ? ` [ERROR: ${error.detail.slice(0, 60)}]` : '';
    process.stdout.write(
      `  [${String(done).padStart(4)}/${total}] ${flag.padEnd(18)} ${secs}s  ${chunks[i].id.slice(-60)}${errFlag}\n`
    );
  };

  async function scanSingle(i) {
    const t0 = Date.now();
    let findings = [], error = null, partial = false;
    try {
      findings = await callFor([cleaned[i]]);
      for (const f of findings) delete f.chunk_id;
      if (findings.info?.salvaged) { partial = true; stats.scan_salvaged_replies = (stats.scan_salvaged_replies || 0) + 1; }
      if (findings.info?.retried)  stats.scan_parse_retries = (stats.scan_parse_retries || 0) + 1;
    } catch (e) {
      error = { stage: 'scan', reason: 'request_failed', detail: e.message };
      findings = [];
    }
    const rec = record(i, findings, error, partial);
    report(i, findings, error, ((Date.now() - t0) / 1000).toFixed(1));
    return [[i, rec]];
  }

  async function scanBin(idxs) {
    if (idxs.length === 1) return scanSingle(idxs[0]);

    const t0 = Date.now();
    let ok = false, attributed = null;
    let fatal = null, truncated = false;
    try {
      const findings = await callFor(idxs.map(i => cleaned[i]));
      truncated = !!findings.info?.truncated;
      const bad = findings.some(f => f._parse_error) || truncated;
      if (!bad) {
        const { perChunk, unattributed } = attributeFindings(findings, idxs.map(i => cleaned[i]));
        if (unattributed.length === 0) { ok = true; attributed = perChunk; }
      }
    } catch (e) {
      if (isAuthFatal(e)) fatal = e;
    }

    if (fatal) {
      // Nothing a per-chunk retry could fix (bad key, forbidden, unknown endpoint).
      return idxs.map(i => {
        const error = { stage: 'scan', reason: 'request_failed', detail: fatal.message };
        report(i, [], error, ((Date.now() - t0) / 1000).toFixed(1));
        return [i, record(i, [], error, false)];
      });
    }

    if (!ok) {
      stats.scan_pack_fallbacks = (stats.scan_pack_fallbacks || 0) + 1;
      stats.scan_pack_fallback_chunks = (stats.scan_pack_fallback_chunks || 0) + idxs.length;
      if (truncated) stats.scan_pack_truncated_fallbacks = (stats.scan_pack_truncated_fallbacks || 0) + 1;
      const out = [];
      for (const i of idxs) out.push(...await scanSingle(i));
      return out;
    }

    const secs = ((Date.now() - t0) / 1000).toFixed(1);
    return idxs.map((i, k) => {
      report(i, attributed[k], null, secs);
      return [i, record(i, attributed[k], null, false)];
    });
  }

  const binResults = await runPool(bins.map(b => () => scanBin(b)), concurrency);

  const results = new Array(total);
  for (const group of binResults) for (const [i, rec] of group) results[i] = rec;
  return results;
}

export {
  runScanPass, planBins, makeCatalogPackKey, packedMaxTokensWarning, MIN_PACKED_MAX_TOKENS,
  attributeFindings, emptyUsage, usageSink,
};
