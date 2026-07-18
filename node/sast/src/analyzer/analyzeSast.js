'use strict';

import path from 'path';

import { buildChunks, stripComments, DEFAULT_LANGUAGES  } from '../chunker/index.js';
import { PROVIDERS } from './providers.js';
import { DEFAULT_VULN_CLASSES } from './vulnCatalog.js';
import { defaultBuildPrompt } from './prompts.js';
import { callProviderWithRetry } from './retry.js';
import { runPool } from './pool.js';
import {verifyFinding, traceTaint} from './workers.js';
import { resolveGitDiffFiles } from './gitDiff.js';

// ─── Extension → display language label ───────────────────────────────────────

const EXT_LANG = {
  '.py':   'Python',
  '.js':   'JavaScript', '.ts':  'TypeScript',
  '.mjs':  'JavaScript', '.cjs': 'JavaScript',
  '.php':  'PHP',
  '.rb':   'Ruby',
  '.go':   'Go',
  '.rs':   'Rust',
  '.java': 'Java',
  '.kt':   'Kotlin',     '.kts': 'Kotlin',
  '.cs':   'C#',
  '.c':    'C',     '.h':   'C',
  '.cpp':  'C++',   '.cc':  'C++',  '.cxx': 'C++',
  '.hpp':  'C++',   '.hh':  'C++',  '.hxx': 'C++',
};

/**
 * Analyze chunks with the configured LLM provider.
 *
 * Chunks may be passed directly as an array, or the analyzer can build them
 * itself from a directory when opts.workingDir (or opts.targetPath) is given.
 *
 * Three-pass analysis: scan → verify → taint trace (all enabled by default).
 *
 * Chunker params (only used when chunks are not passed in):
 *   opts.workingDir      {string}   Root dir to scan          (default: cwd)
 *   opts.maxChunkSize    {number}   Max chars per chunk        (default: 12000)
 *   opts.chunksStart     {number}   Slice start index          (default: 0)
 *   opts.maxChunks       {number}   Max chunks to analyze      (default: 1000)
 *   opts.skipFolders     {string[]} Extra folder names to skip (default: [])
 *   opts.skipFiles       {string[]} File names to skip         (default: [])
 *   opts.languages       {string[]} Language families to scan  (default: all)
 *
 * Token reduction:
 *   opts.skipSignals     {boolean}  Omit the per-class "Detect when you see"
 *                                   bullets from the vuln catalog in the scan
 *                                   prompt (Pass 1 only). Cuts ~2-2.5k tokens
 *                                   per call at the cost of relying on the
 *                                   class name + CWE + scope rule alone for
 *                                   detection guidance.                  (default: false)
 *
 * Diff mode params:
 *   opts.onlyDiff        {boolean}  Scan only chunks from files in git diff (default: false)
 *   opts.diffBase        {string}   Git ref to diff against (default: 'HEAD^').
 *                                   Use 'staged' to diff staged changes against HEAD.
 */
async function analyzeSast(chunks, opts = {}) {
  const {
    // ── LLM / analysis params ────────────────────────────────────────────
    provider        = 'openrouter',
    apiKey,
    apiKeyHeader,
    apiKeyPrefix,
    model,
    endpoint,
    buildPrompt     = defaultBuildPrompt,
    vulnClasses     = DEFAULT_VULN_CLASSES,
    skipSignals     = false,
    concurrency     = 5,
    maxTokens       = 4096,
    temperature     = 0.1,
    requestTimeout  = 120_000,
    retryOnParseError = true,
    maxRetries      = 2,
    silent          = false,
    verify          = true,
    taintTrace      = true,
    verificationMaxTokens = 4096,
    taintMaxTokens  = 4096,
    verifyConcurrency,
    taintConcurrency,
    // ── Chunker params (used when chunks array is not supplied) ──────────
    workingDir   = process.cwd(),
    maxChunkSize = 12_000,
    chunksStart  = 0,
    maxChunks    = 1_000,
    skipFolders  = [],
    skipFiles    = [],
    languages    = DEFAULT_LANGUAGES,
    // ── Diff mode ────────────────────────────────────────────────────────────
    // onlyDiff: when true, scan only chunks belonging to files modified since
    //   diffBase.  The full chunk set is still built and used for taint
    //   call-chain resolution — only Pass 1 is filtered to diff files.
    // diffBase: git ref to diff against (default: 'HEAD~1').
    //   Special value 'staged' diffs against HEAD (uncommitted staged changes).
    onlyDiff  = false,
    diffBase  = 'HEAD^',
  } = opts;

  const log = silent ? () => {} : (...a) => process.stdout.write(a.join('') + '\n');

  // ── Build chunks from disk when none were passed in ───────────────────
  let resolvedChunks = chunks;
  if (!resolvedChunks || resolvedChunks.length === 0) {
    log(`[ubel-sast] No chunks supplied — scanning ${path.resolve(workingDir)}\n`);
    resolvedChunks = buildChunks(path.resolve(workingDir), {
      silent, maxChunkSize, chunksStart, maxChunks,
      skipFolders, skipFiles, languages,
    });
  }

  if (!PROVIDERS[provider]) {
    throw new Error(
      `Unknown provider "${provider}". ` +
      `Valid values: ${Object.keys(PROVIDERS).join(', ')}`
    );
  }

  const def = PROVIDERS[provider];
  const effectiveEndpoint  = endpoint     || def.endpoint;
  const effectiveModel     = model        || def.model;
  // apiKeyHeader/apiKeyPrefix must fall back to the provider's registry
  // defaults the same way endpoint/model already do — without this,
  // providers whose header isn't the generic 'Authorization: Bearer '
  // pattern (e.g. Anthropic's 'x-api-key', Gemini's query-param 'query')
  // silently break unless the caller manually re-specifies them.
  const effectiveApiKeyHeader = apiKeyHeader !== undefined ? apiKeyHeader : def.apiKeyHeader;
  const effectiveApiKeyPrefix = apiKeyPrefix !== undefined ? apiKeyPrefix : def.apiKeyPrefix;
  // apiKey falls back to the provider's declared env var (def.envKey) when
  // not passed explicitly via opts.apiKey / --api-key. Every provider's
  // error message already advertises this fallback ("--api-key or
  // OPENROUTER_API_KEY") — this is what actually makes that true.
  const effectiveApiKey = apiKey || (def.envKey ? process.env[def.envKey] : undefined);

  if (def.keyRequired && !effectiveApiKey) {
    throw new Error(
      `Provider "${provider}" requires an API key. ` +
      `Pass --api-key, or set the ${def.envKey} environment variable.`
    );
  }

  // Providers without a built-in default (e.g. "custom") require the caller
  // to supply both explicitly. Fail before spinning up the chunk pool rather
  // than letting every single task hit the same error individually.
  if (!effectiveEndpoint) {
    throw new Error(
      `Provider "${provider}" has no default endpoint. Pass --endpoint <url> ` +
      `(an OpenAI-compatible /chat/completions URL).`
    );
  }
  if (!effectiveModel) {
    throw new Error(`Provider "${provider}" has no default model. Pass --model <name>.`);
  }

  log(`[ubel-sast] Provider    : ${provider}`);
  log(`[ubel-sast] Model       : ${effectiveModel}`);
  log(`[ubel-sast] Endpoint    : ${effectiveEndpoint}`);
  log(`[ubel-sast] Concurrency : ${concurrency}`);
  if (onlyDiff)    log(`[ubel-sast] Diff mode   : enabled (base: ${diffBase})`);
  if (skipSignals) log(`[ubel-sast] Skip signals: enabled (catalog detection bullets omitted from scan prompt)`);
  if (verify)      log(`[ubel-sast] Verification: enabled`);
  if (taintTrace)  log(`[ubel-sast] Taint trace : enabled`);

  const enriched  = resolvedChunks.map(c => ({
    ...c,
    language: EXT_LANG[path.extname(c.file).toLowerCase()] || 'unknown',
  }));

  // ── Resolve diff file set when --only-diff is active ─────────────────────
  // The full enriched set is always kept for chunkMap (taint chain resolution).
  // Pass 1 scan is limited to chunks from files that changed in the diff.
  let diffFileSet = null;
  if (onlyDiff) {
    diffFileSet = resolveGitDiffFiles(workingDir, diffBase, log);
    if (diffFileSet === null) {
      // git unavailable or repo not found — fall back to full scan with a warning
      log('[ubel-sast] ⚠  --only-diff: git diff failed, falling back to full scan');
      diffFileSet = null;
    } else if (diffFileSet.size === 0) {
      log('[ubel-sast] --only-diff: no modified files found — nothing to scan');
      return [];
    } else {
      log(`[ubel-sast] --only-diff: ${diffFileSet.size} modified file(s) in diff`);
      for (const f of [...diffFileSet].slice(0, 20)) {
        log(`[ubel-sast]   ${f}`);
      }
      if (diffFileSet.size > 20) log(`[ubel-sast]   … and ${diffFileSet.size - 20} more`);
    }
  }

  const toAnalyze = enriched.filter(c => {
    if (c.type === 'imports') return false;
    if (diffFileSet !== null) return diffFileSet.has(path.resolve(c.file));
    return true;
  });
  const skipped   = enriched.length - toAnalyze.length;

  log(`[ubel-sast] Chunks      : ${toAnalyze.length} to analyze, ${skipped} import chunk(s) skipped\n`);

  // ── Pass 1: Scan ─────────────────────────────────────────────────────────

  let done = 0;
  const startTime = Date.now();

  const tasks = toAnalyze.map((chunk) => async () => {
    const chunkStart = Date.now();
    let findings = [];
    let error    = null;

    // Strip comments from the raw chunk code right before submitting to LLM.
    // The stored chunk retains original source; this cleaned copy is prompt-only.
    const cleanedChunk = {
      ...chunk,
      code: stripComments(chunk.code, chunk.file),
    };

    try {
      findings = await callProviderWithRetry(
        {
          provider,
          apiKey:       effectiveApiKey,
          apiKeyHeader: effectiveApiKeyHeader,
          apiKeyPrefix: effectiveApiKeyPrefix,
          endpoint:     effectiveEndpoint,
          model:        effectiveModel,
          prompt:      buildPrompt(cleanedChunk, vulnClasses, !skipSignals),
          maxTokens,
          temperature,
          timeoutMs:   requestTimeout,
        },
        { retryOnParseError, maxRetries }
      );
    } catch (e) {
      error    = { stage: 'scan', reason: 'request_failed', detail: e.message };
      findings = [];
    }

    done++;
    const elapsed      = ((Date.now() - chunkStart) / 1000).toFixed(1);
    const realFindings = findings.filter(f => !f._parse_error);
    const flag         = realFindings.length > 0 ? `⚠  ${realFindings.length} finding(s)` : '✓  clean';
    const errFlag      = error ? ` [ERROR: ${error.detail.slice(0, 60)}]` : '';

    process.stdout.write(
      `  [${String(done).padStart(4)}/${toAnalyze.length}] ` +
      `${flag.padEnd(18)} ${elapsed}s  ` +
      `${chunk.id.slice(-60)}${errFlag}\n`
    );

    return {
      id:        chunk.id,
      file:      chunk.file,
      type:      chunk.type,
      class:     chunk.class,
      name:      chunk.name,
      language:  chunk.language,
      startLine: chunk.startLine,
      endLine:   chunk.endLine,
      findings,
      error,
    };
  });

  const results = await runPool(tasks, concurrency);

  const chunkMap = {};
  for (const c of enriched) {
    chunkMap[c.id] = c;
  }

  // ── Pass 2: Verification ────────────────────────────────────────────────

  if (verify) {
    log('\n[ubel-sast] Verifying findings...');

    const verificationTasks = [];
    for (const result of results) {
      if (result.error) continue;
      const chunk = chunkMap[result.id];
      if (!chunk) continue;
      for (const finding of result.findings) {
        if (finding._parse_error) continue;
        verificationTasks.push(() => verifyFinding(finding, chunk, {
          provider,
          apiKey:       effectiveApiKey,
          apiKeyHeader: effectiveApiKeyHeader,
          apiKeyPrefix: effectiveApiKeyPrefix,
          endpoint:     effectiveEndpoint,
          model:        effectiveModel,
          temperature: 0,   // binary verdict — must be deterministic
          timeoutMs: requestTimeout,
          verificationMaxTokens,
          maxRetries,
        }, log));
      }
    }

    if (verificationTasks.length > 0) {
      const vConcurrency = verifyConcurrency || concurrency;
      await runPool(verificationTasks, vConcurrency);
      log(`[ubel-sast] Verified ${verificationTasks.length} finding(s)`);
    } else {
      log('[ubel-sast] No findings to verify');
    }
  }

  // ── Pass 3: Taint Tracing ──────────────────────────────────────────────

  if (taintTrace) {
    log('\n[ubel-sast] Tracing taint paths...');

    const taintTasks = [];
    for (const result of results) {
      if (result.error) continue;
      const chunk = chunkMap[result.id];
      if (!chunk) continue;
      for (const finding of result.findings) {
        if (finding._parse_error) continue;
        if (verify && finding.is_valid !== true) continue;
        if (!verify) {
          finding.verification_skipped = true;
        }
        taintTasks.push(() => traceTaint(finding, chunk, chunkMap, {
          provider,
          apiKey:       effectiveApiKey,
          apiKeyHeader: effectiveApiKeyHeader,
          apiKeyPrefix: effectiveApiKeyPrefix,
          endpoint:     effectiveEndpoint,
          model:        effectiveModel,
          temperature: 0,   // binary verdict — must be deterministic
          timeoutMs: requestTimeout,
          taintMaxTokens,
          maxRetries,
        }, log));
      }
    }

    if (taintTasks.length > 0) {
      const tConcurrency = taintConcurrency || concurrency;
      await runPool(taintTasks, tConcurrency);
      log(`[ubel-sast] Traced ${taintTasks.length} taint path(s)`);
    } else {
      log('[ubel-sast] No findings to trace');
    }
  }

  // ── Summary ──────────────────────────────────────────────────────────────

  const totalFindings = results.reduce((n, r) => n + r.findings.filter(f => !f._parse_error).length, 0);
  const parseErrors   = results.reduce((n, r) => n + r.findings.filter(f =>  f._parse_error).length, 0);
  const callErrors    = results.filter(r => r.error).length;
  const highConf      = results.flatMap(r => r.findings).filter(f => f.confidence === 'high').length;
  const medConf       = results.flatMap(r => r.findings).filter(f => f.confidence === 'medium').length;
  const elapsed       = ((Date.now() - startTime) / 1000).toFixed(1);

  log('\n── Analysis complete ─────────────────────────────────────────────');
  log(`   Chunks analyzed : ${toAnalyze.length}`);
  log(`   Total findings  : ${totalFindings}  (high: ${highConf}  medium: ${medConf})`);

  if (verify) {
    const validCount = results.flatMap(r => r.findings).filter(f => f.is_valid === true).length;
    const invalidCount = results.flatMap(r => r.findings).filter(f => f.is_valid === false).length;
    const verifyErrorCount = results.flatMap(r => r.findings).filter(f => f.verification_error).length;
    log(`   Verified valid  : ${validCount}`);
    log(`   False positives : ${invalidCount}`);
    if (verifyErrorCount > 0) {
      log(`   ⚠️ Unverified    : ${verifyErrorCount}  (verification call failed or returned an unusable response — see "verification_error" in the JSON output, NOT the same as a confirmed false positive)`);
    }
  }

  if (taintTrace) {
    const exploitableCount = results.flatMap(r => r.findings).filter(f => f.taint?.exploitable === true).length;
    const mitigatedCount = results.flatMap(r => r.findings).filter(f => f.taint?.exploitable === false).length;
    const unreachableCount = results.flatMap(r => r.findings).filter(f => f.taint?.reachable === false).length;
    const taintErrorCount = results.flatMap(r => r.findings).filter(f => f.taint?.error).length;
    log(`   Exploitable     : ${exploitableCount}`);
    if (mitigatedCount) log(`   Mitigated       : ${mitigatedCount}`);
    if (unreachableCount) log(`   Not reachable   : ${unreachableCount}`);
    if (taintErrorCount > 0) {
      log(`   ⚠️ Untraced      : ${taintErrorCount}  (taint trace call failed or returned an unusable response — see "taint.error" in the JSON output, NOT the same as a confirmed-mitigated finding)`);
    }
  }

  log(`   Parse errors    : ${parseErrors}`);
  log(`   Call errors     : ${callErrors}`);
  log(`   Elapsed         : ${elapsed}s`);

  return results;
}

export { analyzeSast, EXT_LANG };