'use strict';

import { stripComments } from '../chunker/index.js';
import { callRawWithRetry } from './retry.js';
import {
  parseVerification, parseVerificationBatch,
  parseTaintTrace, parseTaintTraceBatch,
} from './parsers.js';
import {
  defaultVerificationPrompt, defaultBatchVerificationPrompt,
  defaultTaintTracePrompt, defaultBatchTaintTracePrompt,
} from './prompts.js';
import { buildFullCallChain, prepareChainForPrompt } from './callGraph.js';

// The model only needs the finding itself, not the bookkeeping fields earlier
// passes attach (is_valid, verification_*, taint …) — sending those is pure
// token waste (and, in Pass 3, leaks the Pass-2 verdict into the trace prompt).
function publicFinding(f) {
  const out = {
    vuln_name:    f.vuln_name,
    description:  f.description,
    code_snippet: f.code_snippet,
    severity:     f.severity,
    confidence:   f.confidence,
    fix:          f.fix,
  };
  return out;
}

// ─── Verification worker ──────────────────────────────────────────────────

function applyVerification(finding, result, log) {
  finding.is_valid = result.is_valid;
  finding.verification_error = result.error;
  if (result.reason) finding.verification_reason = result.reason;

  if (log) {
    const status = result.error ? '⚠️ unknown (bad response)' :
                   result.is_valid === true ? '✅ valid' :
                   result.is_valid === false ? '❌ false positive' : '❓ unknown';
    log(`  verify ${finding.vuln_name} → ${status}`);
  }
}

async function verifyFinding(finding, chunk, providerOpts, log) {
  if (!finding || !chunk) return;

  // Strip comments here so callers don't need to pre-process the chunk —
  // consistent with how traceTaint handles it internally.
  const cleanedChunk = { ...chunk, code: stripComments(chunk.code, chunk.file) };
  const prompt = defaultVerificationPrompt(publicFinding(finding), cleanedChunk);
  const maxRetries = providerOpts.maxRetries ?? 2;

  const callOpts = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.verificationMaxTokens || 512,
  };

  try {
    const raw = await callRawWithRetry(callOpts, maxRetries);
    applyVerification(finding, parseVerification(raw), log);
  } catch (err) {
    finding.is_valid = null;
    finding.verification_error = { stage: 'verify', reason: 'request_failed', detail: err.message };
    if (log) log(`  verify ${finding.vuln_name} → ⚠️ error: ${err.message.slice(0, 60)}`);
  }
}

/**
 * Verify ALL findings of one chunk with a single call: the chunk's code is
 * sent once, not once per finding. Any finding the model's batch answer does
 * not cover (missing index, unusable entry, or the whole batch failing) is
 * re-verified individually, so batching can only ever save tokens — it never
 * leaves a finding unverified that the one-by-one path would have settled.
 */
async function verifyChunkFindings(findings, chunk, providerOpts, log, stats) {
  if (!chunk || !findings || findings.length === 0) return;
  if (findings.length === 1) return verifyFinding(findings[0], chunk, providerOpts, log);

  const cleanedChunk = { ...chunk, code: stripComments(chunk.code, chunk.file) };
  const prompt = defaultBatchVerificationPrompt(findings.map(publicFinding), cleanedChunk);
  const callOpts = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.verificationMaxTokens || 4096,
  };

  let slots = new Array(findings.length).fill(null);
  try {
    const raw = await callRawWithRetry(callOpts, providerOpts.maxRetries ?? 2);
    slots = parseVerificationBatch(raw, findings.length);
    if (stats) stats.verify_batched_calls = (stats.verify_batched_calls || 0) + 1;
  } catch {
    // whole batch failed — every finding falls back to its own call below
  }

  for (let i = 0; i < findings.length; i++) {
    if (slots[i]) applyVerification(findings[i], slots[i], log);
  }
  const missing = findings.filter((_, i) => !slots[i]);
  if (stats && missing.length) stats.verify_batch_fallbacks = (stats.verify_batch_fallbacks || 0) + missing.length;
  for (const f of missing) await verifyFinding(f, chunk, providerOpts, log);
}

// ─── Entry-point heuristic (orphan short-circuit) ─────────────────────────
//
// A chunk with no callers in the analysed code is normally an "orphan": the
// taint trace cannot say whether attacker input reaches it, so the LLM call is
// skipped and the finding is left inconclusive — UNLESS the chunk itself looks
// like an externally-invoked entry point (request handler, CLI main, …).
//
// The old heuristic matched ordinary words (message, args, query, context,
// process, execute, callback, …) that appear in almost any code, so nearly
// every orphan "looked like an entry point" and the saving never happened.
// This version requires either a handler-style NAME or a concrete framework
// source/idiom in the code.
const EP_NAME_RE = /handler|controller|endpoint|middleware|route[rs]?\b|routes?[A-Z_]|webhook|listener|servlet|resolver|dispatch(?:er)?\b|handle[A-Z_]|^do(?:Get|Post|Put|Delete|Head)$|^main$|^lambda_handler$|^(?:index|show|create|update|destroy)Action$/i;

const EP_CODE_RE = new RegExp([
  // Node / JS web frameworks
  String.raw`\b(?:req|request)\.(?:body|query|params|headers|cookies|files|form|args|json|data|GET|POST|FILES|COOKIES)\b`,
  String.raw`\bctx\.(?:request|params|query)\b`,
  String.raw`\bevent\.(?:body|queryStringParameters|pathParameters|headers)\b`,
  // Python
  String.raw`\brequest\.(?:form|args|json|data|values|files|GET|POST)\b`,
  String.raw`@(?:app|router|bp|blueprint)\.(?:route|get|post|put|delete|patch)\b`,
  String.raw`\bsys\.argv\b|\bargparse\b|\binput\s*\(`,
  // PHP
  String.raw`\$_(?:GET|POST|REQUEST|FILES|COOKIE|SERVER)\b`,
  // Java / Kotlin / C#
  String.raw`\bHttpServletRequest\b|@(?:Request|Get|Post|Put|Delete|Patch)Mapping\b|\[Http(?:Get|Post|Put|Delete)\]|\bHttpContext\b|\bIActionResult\b`,
  // Go
  String.raw`\bhttp\.Request\b|\bFormValue\s*\(|\bos\.Args\b|\bgin\.Context\b|\becho\.Context\b`,
  // Ruby / Rails
  String.raw`\bparams\[|\bparams\.(?:require|permit)\b`,
  // CLI / stdin / env as attacker-influenced sources
  String.raw`\bprocess\.argv\b|\bprocess\.stdin\b|\breadline\b`,
].join('|'));

function isEntryPoint(chunk) {
  return EP_NAME_RE.test(chunk.name || '') || EP_CODE_RE.test(chunk.code || '');
}

// ─── Taint trace workers ──────────────────────────────────────────────────

const ORPHAN_TAINT = () => ({
  reachable:   null,
  sanitized:   null,
  bypassed:    null,
  exploitable: null,
  flow_path:   'No callers found in the codebase. This function appears to be a utility or library function.',
  reasoning:   'The function has no callers in the analysed chunks. It may be called from external code or may be unused. Exploitability cannot be determined.',
  // Not a failure — the taint pass ran and reached a deliberate "cannot
  // determine" conclusion via the orphan heuristic. Tagged separately
  // from request/parse errors so the two are never conflated in reports.
  error: null,
  inconclusive_reason: 'orphan_no_callers',
});

function describeTaint(finding, result, log) {
  if (!log) return;
  const status = result.exploitable === true ? '⚠️ EXPLOITABLE' :
                 result.reachable   === false ? '🚫 NOT REACHABLE' :
                 result.sanitized   === true  ? '🛡️ SANITIZED' :
                 result.exploitable === false  ? '✅ MITIGATED' : '❓ UNKNOWN';
  log(`  taint ${finding.vuln_name} → ${status}`);
}

// The call chain depends on the CHUNK, not on the finding, so it is built (and
// comment-stripped / excerpted) once per chunk per run and shared by every
// finding in it.
function chainFor(chunk, chunkMap, providerOpts) {
  const cache = providerOpts.chainCache;
  if (cache && cache.has(chunk.id)) return cache.get(chunk.id);

  const cfg = providerOpts.taintChain || {};
  const rawChain  = buildFullCallChain(chunk, chunkMap, cfg.maxDepth ?? 10, cfg.maxChainLength ?? 15);
  const callChain = prepareChainForPrompt(
    rawChain,
    c => ({ ...c, code: stripComments(c.code, c.file) }),
    { maxChainChars: cfg.maxChainChars ?? 24000, perChunkChars: cfg.perChunkChars ?? 3500 },
  );
  const entry = { callChain, orphan: callChain.length === 1 && !isEntryPoint(chunk) };
  if (cache) cache.set(chunk.id, entry);
  return entry;
}

async function traceTaint(finding, chunk, chunkMap, providerOpts, log) {
  if (!finding || !chunk || !chunkMap) return;

  const { callChain, orphan } = chainFor(chunk, chunkMap, providerOpts);

  if (orphan) {
    finding.taint = ORPHAN_TAINT();
    if (log) log(`  taint ${finding.vuln_name} → ❓ ORPHAN (no callers found)`);
    return;
  }

  const prompt     = defaultTaintTracePrompt(publicFinding(finding), callChain);
  const maxRetries = providerOpts.maxRetries ?? 2;
  const callOpts   = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.taintMaxTokens || 1024,
  };

  try {
    const raw    = await callRawWithRetry(callOpts, maxRetries);
    const result = parseTaintTrace(raw);
    finding.taint = result;
    describeTaint(finding, result, log);
  } catch (err) {
    finding.taint = {
      reachable: null, sanitized: null, bypassed: null, exploitable: null,
      flow_path: null, reasoning: null,
      error: { stage: 'taint', reason: 'request_failed', detail: err.message },
    };
    if (log) log(`  taint ${finding.vuln_name} → ❌ error: ${err.message.slice(0, 60)}`);
  }
}

/**
 * Trace ALL findings of one chunk with a single call: the call chain (up to
 * ~24k chars) is sent once with the findings listed, instead of once per
 * finding. Findings the batch answer does not cover fall back to individual
 * calls, exactly like verifyChunkFindings.
 */
async function traceChunkFindings(findings, chunk, chunkMap, providerOpts, log, stats) {
  if (!chunk || !chunkMap || !findings || findings.length === 0) return;
  if (findings.length === 1) return traceTaint(findings[0], chunk, chunkMap, providerOpts, log);

  const { callChain, orphan } = chainFor(chunk, chunkMap, providerOpts);
  if (orphan) {
    for (const f of findings) {
      f.taint = ORPHAN_TAINT();
      if (log) log(`  taint ${f.vuln_name} → ❓ ORPHAN (no callers found)`);
    }
    return;
  }

  const prompt = defaultBatchTaintTracePrompt(findings.map(publicFinding), callChain);
  const callOpts = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.taintMaxTokens || 4096,
  };

  let slots = new Array(findings.length).fill(null);
  try {
    const raw = await callRawWithRetry(callOpts, providerOpts.maxRetries ?? 2);
    slots = parseTaintTraceBatch(raw, findings.length);
    if (stats) stats.taint_batched_calls = (stats.taint_batched_calls || 0) + 1;
  } catch {
    // whole batch failed — every finding falls back to its own call below
  }

  for (let i = 0; i < findings.length; i++) {
    if (slots[i]) { findings[i].taint = slots[i]; describeTaint(findings[i], slots[i], log); }
  }
  const missing = findings.filter((_, i) => !slots[i]);
  if (stats && missing.length) stats.taint_batch_fallbacks = (stats.taint_batch_fallbacks || 0) + missing.length;
  for (const f of missing) await traceTaint(f, chunk, chunkMap, providerOpts, log);
}

export { verifyFinding, verifyChunkFindings, traceTaint, traceChunkFindings, isEntryPoint, publicFinding };
