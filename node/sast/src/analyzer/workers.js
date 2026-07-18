'use strict';

import { stripComments } from '../chunker/index.js';
import { callProvider } from './dispatcher.js';
import { isTerminalStatus, retryDelayMs } from './retry.js';
import { parseVerification, parseTaintTrace } from './parsers.js';
import { defaultVerificationPrompt, defaultTaintTracePrompt } from './prompts.js';
import { buildFullCallChain } from './callGraph.js';

// ─── Verification worker ──────────────────────────────────────────────────

async function verifyFinding(finding, chunk, providerOpts, log) {
  if (!finding || !chunk) return;

  // Strip comments here so callers don't need to pre-process the chunk —
  // consistent with how traceTaint handles it internally.
  const cleanedChunk = { ...chunk, code: stripComments(chunk.code, chunk.file) };
  const prompt = defaultVerificationPrompt(finding, cleanedChunk);
  const maxRetries = providerOpts.maxRetries ?? 2;

  // verifyFinding works on raw text (not a findings array), so we call
  // callProviderWithRetry with retryOnParseError=false and handle the raw
  // response ourselves.  We wrap it in a one-element findings array so the
  // retry plumbing stays generic, then unwrap below.
  const callOpts = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.verificationMaxTokens || 512,
  };

  try {
    let raw = null;
    let lastErr = null;
    for (let attempt_n = 0; attempt_n <= maxRetries; attempt_n++) {
      try {
        raw = await callProvider(callOpts);
        break;
      } catch (err) {
        lastErr = err;
        if (isTerminalStatus(err)) throw err;
        if (attempt_n < maxRetries) {
          await new Promise(r => setTimeout(r, retryDelayMs(err, attempt_n)));
        }
      }
    }
    if (raw === null) throw lastErr;

    const result = parseVerification(raw);
    finding.is_valid = result.is_valid;
    finding.verification_error = result.error;
    if (result.reason) finding.verification_reason = result.reason;

    if (log) {
      const status = result.error ? '⚠️ unknown (bad response)' :
                     result.is_valid === true ? '✅ valid' :
                     result.is_valid === false ? '❌ false positive' : '❓ unknown';
      log(`  verify ${finding.vuln_name} → ${status}`);
    }
  } catch (err) {
    finding.is_valid = null;
    finding.verification_error = { stage: 'verify', reason: 'request_failed', detail: err.message };
    if (log) log(`  verify ${finding.vuln_name} → ⚠️ error: ${err.message.slice(0, 60)}`);
  }
}

// ─── Taint trace worker ──────────────────────────────────────────────────

async function traceTaint(finding, chunk, chunkMap, providerOpts, log) {
  if (!finding || !chunk || !chunkMap) return;

  // ── #5: strip comments from every chunk in the call chain before LLM submission ──
  // chunk here is the *original* (unstripped) chunk from chunkMap; we strip
  // it and all callee/caller chunks so the taint prompt sees the same code
  // that the scan and verify passes saw.
  // stripComments is imported at the top of this module from the chunker package.

  function strippedChunk(c) {
    return { ...c, code: stripComments(c.code, c.file) };
  }

  // Build the full call chain using original chunks (for name/id resolution),
  // then strip comments from each entry before passing to the prompt builder.
  const rawChain    = buildFullCallChain(chunk, chunkMap, 10, 15);
  const callChain   = rawChain.map(strippedChunk);

  // ── #6: broader entry-point heuristic ──
  // Covers common naming conventions across frameworks and languages, plus
  // parameter-name signals (req/res/request/response/ctx/context/event).
  const EP_NAME_RE = /handler|route|controller|action|endpoint|middleware|dispatch|listener|callback|hook|resolve|execute|process|receive|handle|serve|invoke|trigger/i;

  const isEntryPoint =
    EP_NAME_RE.test(chunk.name) ||
    // Parameter names that strongly suggest user-controlled input
    /\b(?:req|res|request|response|ctx|context|event|msg|message|cmd|params|query|body|headers|args)\b/.test(chunk.code) ||
    // Express/Fastify/Koa/Hapi style
    chunk.code.includes('req.body') || chunk.code.includes('req.query') ||
    chunk.code.includes('req.params') || chunk.code.includes('ctx.request') ||
    // Python Flask/Django/FastAPI style
    chunk.code.includes('request.form') || chunk.code.includes('request.args') ||
    chunk.code.includes('request.json') || chunk.code.includes('request.data');

  if (callChain.length === 1 && !isEntryPoint) {
    finding.taint = {
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
    };
    if (log) log(`  taint ${finding.vuln_name} → ❓ ORPHAN (no callers found)`);
    return;
  }

  const prompt     = defaultTaintTracePrompt(finding, callChain);
  const maxRetries = providerOpts.maxRetries ?? 2;
  const callOpts   = {
    ...providerOpts,
    prompt,
    maxTokens: providerOpts.taintMaxTokens || 1024,
  };

  try {
    // ── #4: retry wrapper for taint pass ──
    let raw = null;
    let lastErr = null;
    for (let attempt_n = 0; attempt_n <= maxRetries; attempt_n++) {
      try {
        raw = await callProvider(callOpts);
        break;
      } catch (err) {
        lastErr = err;
        if (isTerminalStatus(err)) throw err;
        if (attempt_n < maxRetries) {
          await new Promise(r => setTimeout(r, retryDelayMs(err, attempt_n)));
        }
      }
    }
    if (raw === null) throw lastErr;

    const result = parseTaintTrace(raw);
    finding.taint = result;

    if (log) {
      const status = result.exploitable === true ? '⚠️ EXPLOITABLE' :
                     result.reachable   === false ? '🚫 NOT REACHABLE' :
                     result.sanitized   === true  ? '🛡️ SANITIZED' :
                     result.exploitable === false  ? '✅ MITIGATED' : '❓ UNKNOWN';
      log(`  taint ${finding.vuln_name} → ${status}`);
    }
  } catch (err) {
    finding.taint = {
      reachable: null, sanitized: null, bypassed: null, exploitable: null,
      flow_path: null, reasoning: null,
      error: { stage: 'taint', reason: 'request_failed', detail: err.message },
    };
    if (log) log(`  taint ${finding.vuln_name} → ❌ error: ${err.message.slice(0, 60)}`);
  }
}

export { verifyFinding, traceTaint };