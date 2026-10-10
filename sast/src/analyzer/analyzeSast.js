'use strict';

import path from 'path';

import { buildChunks, stripComments, DEFAULT_LANGUAGES, KIND_LABEL  } from '../chunker/index.js';
import { PROVIDERS } from './providers.js';
import { DEFAULT_VULN_CLASSES } from './vulnCatalog.js';
import { defaultBuildPrompt, buildScanPromptParts } from './prompts.js';
import { runPool } from './pool.js';
import { verifyChunkFindings, traceChunkFindings } from './workers.js';
import { resolveGitDiffFiles } from './gitDiff.js';
import { runScanPass, emptyUsage, usageSink } from './scanEngine.js';

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
  '.dart': 'Dart',
  '.swift':'Swift',
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
 * Chunker params (continued):
 *   opts.maxChunkSize    {number}   HARD cap on characters per chunk — an over-long single
 *                                   line (minified bundle) is split to honour it.
 *   opts.maxFileSize     {number}   Skip files larger than this many characters (default 512000;
 *                                   skipped files are listed in the report's coverage).
 *   opts.includeFolders  {string[]} Scan these folder names even though they are in the built-in
 *                                   ignore list (node_modules, dist, build, vendor, ...).
 *   opts.includeMinified {boolean}  Scan *.min.js / *.bundle.js (default: false for this scan).
 *   opts.skipTests       {boolean}  Skip test folders / test-named files (default: false).
 *
 * Token reduction:
 *   opts.skipSignals     {boolean}  Omit the per-class "Detect when you see" bullets from the
 *                                   scan prompt (Pass 1 only). The default (true) matches the
 *                                   CLI; pass false for maximum recall — signals roughly 6x the
 *                                   catalog (about 6k tokens per Python call).
 *   opts.packSize        {number}   Pack small same-language chunks into one Pass-1 call, up to
 *                                   this many characters of code per call (default 12000;
 *                                   0 disables packing). Large chunks are always sent alone.
 *   opts.packMaxChunks   {number}   Max chunks per packed call (default 10).
 *   opts.taintChainChars {number}   Character budget of the call chain sent to Pass 3 (default 24000).
 *
 * The returned array carries a non-enumerable `scan_stats` property:
 *   { coverage, usage:{scan,verify,taint}, pipeline } — what was NOT scanned, real token
 *   usage per pass, and call/packing/fallback counters.
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
    skipSignals     = true,
    packSize        = 12_000,
    packMaxChunks   = 10,
    taintChainChars = 24_000,
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
    includeFolders  = [],
    maxFileSize     = 512_000,
    includeMinified = false,
    skipTests       = false,
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
      includeFolders, maxFileSize, includeMinified, skipTests,
    });
  }
  const chunkInfo = resolvedChunks.info || null;   // coverage record from the chunker (null when chunks were supplied)

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
  if (!skipSignals) log(`[ubel-sast] Signals     : included in the scan prompt (--include-signals)`);
  if (packSize > 0 && buildPrompt === defaultBuildPrompt) log(`[ubel-sast] Packing     : up to ${packMaxChunks} small chunks / ${packSize} chars per Pass-1 call`);
  if (verify)      log(`[ubel-sast] Verification: enabled`);
  if (taintTrace)  log(`[ubel-sast] Taint trace : enabled`);

  // Docker/IaC chunks carry their specific kind ('dockerfile', 'terraform',
  // 'kubernetes', ...) as chunk.type, set by chunkDocker/chunkIac — check
  // that first since these files aren't resolvable by extension alone
  // (Dockerfile has none; .yaml/.yml/.json is shared with everything else).
  const enrich = c => ({
    ...c,
    language: KIND_LABEL[c.type] || EXT_LANG[path.extname(c.file).toLowerCase()] || 'unknown',
  });
  const enriched = resolvedChunks.map(enrich);
  // Call-graph context = EVERY chunk found, not just the --max-chunks window,
  // so a capped or --only-diff run can still trace callers/callees outside it.
  const contextChunks = (resolvedChunks.all && resolvedChunks.all !== resolvedChunks)
    ? resolvedChunks.all.map(enrich) : enriched;

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

  const startTime = Date.now();
  const usage = { scan: emptyUsage(), verify: emptyUsage(), taint: emptyUsage() };
  const pipeline = {};

  const providerBase = {
    provider,
    apiKey:       effectiveApiKey,
    apiKeyHeader: effectiveApiKeyHeader,
    apiKeyPrefix: effectiveApiKeyPrefix,
    endpoint:     effectiveEndpoint,
    model:        effectiveModel,
  };

  // A custom prompt builder gets one chunk per call and no caching split: packing
  // and the static-prefix split are features of the default prompt only.
  const customPrompt = buildPrompt === defaultBuildPrompt
    ? null
    : (chunk) => buildPrompt(chunk, vulnClasses, !skipSignals);

  const results = await runScanPass({
    chunks: toAnalyze,
    buildParts: (list, withSignals) => buildScanPromptParts(list, vulnClasses, withSignals),
    customPrompt,
    includeSignals: !skipSignals,
    providerBase,
    maxTokens, temperature, timeoutMs: requestTimeout,
    retryOnParseError, maxRetries,
    pack: { size: packSize, maxChunks: packMaxChunks },
    concurrency,
    hitIcon: '⚠ ',
    stats: pipeline,
    usage: usage.scan,
  });

  const chunkMap = {};
  for (const c of contextChunks) chunkMap[c.id] = c;
  for (const c of enriched)      chunkMap[c.id] = c;

  // ── Pass 2: Verification ────────────────────────────────────────────────
  // One call per CHUNK (all of its findings together), not one per finding.

  if (verify) {
    log('\n[ubel-sast] Verifying findings...');

    const verifyOpts = {
      ...providerBase,
      temperature: 0,   // binary verdict — must be deterministic
      timeoutMs: requestTimeout,
      verificationMaxTokens,
      maxRetries,
      onUsage: usageSink(usage.verify),
    };

    const verificationTasks = [];
    let verifyFindingCount = 0;
    for (const result of results) {
      if (result.error) continue;
      const chunk = chunkMap[result.id];
      if (!chunk) continue;
      const live = result.findings.filter(f => !f._parse_error);
      if (live.length === 0) continue;
      verifyFindingCount += live.length;
      verificationTasks.push(() => verifyChunkFindings(live, chunk, verifyOpts, log, pipeline));
    }

    if (verificationTasks.length > 0) {
      const vConcurrency = verifyConcurrency || concurrency;
      await runPool(verificationTasks, vConcurrency);
      log(`[ubel-sast] Verified ${verifyFindingCount} finding(s) in ${verificationTasks.length} call group(s)`);
    } else {
      log('[ubel-sast] No findings to verify');
    }
  }

  // ── Pass 3: Taint Tracing ──────────────────────────────────────────────
  // Skipped for classes that do not need attacker input (hardcoded secrets, weak
  // crypto, ...): "does attacker input reach the sink" is not the question for
  // them, the trace costs the most of any pass, and its answer used to be
  // misleading ("not reachable" for a secret that is simply sitting in source).
  // Those findings keep their Pass-2 verdict and carry taint_skipped instead.

  if (taintTrace) {
    log('\n[ubel-sast] Tracing taint paths...');

    const needsInput = new Map();
    for (const v of vulnClasses) needsInput.set(String(v.name).toLowerCase().trim(), v.needsUserInput !== false);
    const requiresAttackerInput = (f) => {
      const key = String(f.vuln_class || f.vuln_name || '').replace(/\s*\(CWE[^)]*\)\s*$/i, '').toLowerCase().trim();
      return needsInput.has(key) ? needsInput.get(key) : true;   // unknown class → trace it
    };

    const taintOpts = {
      ...providerBase,
      temperature: 0,   // binary verdict — must be deterministic
      timeoutMs: requestTimeout,
      taintMaxTokens,
      maxRetries,
      onUsage: usageSink(usage.taint),
      chainCache: new Map(),
      taintChain: { maxDepth: 10, maxChainLength: 15, maxChainChars: taintChainChars, perChunkChars: 3500 },
    };

    const taintTasks = [];
    let traceFindingCount = 0, skippedNoInput = 0;
    for (const result of results) {
      if (result.error) continue;
      const chunk = chunkMap[result.id];
      if (!chunk) continue;
      const toTrace = [];
      for (const finding of result.findings) {
        if (finding._parse_error) continue;
        if (verify && finding.is_valid !== true) continue;
        if (!verify) finding.verification_skipped = true;
        if (!requiresAttackerInput(finding)) {
          finding.taint_skipped = 'no_attacker_input_required';
          skippedNoInput++;
          continue;
        }
        toTrace.push(finding);
      }
      if (toTrace.length === 0) continue;
      traceFindingCount += toTrace.length;
      taintTasks.push(() => traceChunkFindings(toTrace, chunk, chunkMap, taintOpts, log, pipeline));
    }
    pipeline.taint_skipped_no_input = skippedNoInput;

    if (taintTasks.length > 0) {
      const tConcurrency = taintConcurrency || concurrency;
      await runPool(taintTasks, tConcurrency);
      log(`[ubel-sast] Traced ${traceFindingCount} taint path(s) in ${taintTasks.length} call group(s)`);
    } else {
      log('[ubel-sast] No findings to trace');
    }
    if (skippedNoInput > 0) {
      log(`[ubel-sast] ${skippedNoInput} finding(s) of classes that need no attacker input (e.g. hardcoded secrets) were not traced`);
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

  const totalCalls = usage.scan.calls + usage.verify.calls + usage.taint.calls;
  const sum = (k) => usage.scan[k] + usage.verify[k] + usage.taint[k];
  log(`   LLM calls       : ${totalCalls}  (scan ${usage.scan.calls}, verify ${usage.verify.calls}, taint ${usage.taint.calls})`);
  log(`   Tokens          : ${sum('input_tokens')} in / ${sum('output_tokens')} out` +
      (sum('cache_read_tokens') ? `  (${sum('cache_read_tokens')} read from cache)` : '') +
      (sum('estimated_calls') ? `  [${sum('estimated_calls')} call(s) estimated — provider returned no usage]` : ''));
  if (chunkInfo?.truncated) {
    log(`   ⚠️ NOT SCANNED   : ${chunkInfo.chunks_dropped_by_cap} chunk(s) beyond --max-chunks ${chunkInfo.max_chunks}`);
  }
  if (chunkInfo?.files_skipped_too_large?.length) {
    log(`   ⚠️ NOT SCANNED   : ${chunkInfo.files_skipped_too_large.length} file(s) over ${chunkInfo.max_file_size} chars`);
  }

  Object.defineProperty(results, 'scan_stats', {
    value: {
      coverage: buildCoverage(chunkInfo, { analyzed: toAnalyze.length, importSkipped: skipped, diffMode: diffFileSet !== null, results }),
      usage,
      pipeline,
    },
    enumerable: false, writable: true,
  });

  return results;
}

// What was NOT scanned (and why), in the shape the report's scan_options carries.
// `info` is null when the caller supplied pre-built chunks (nothing to say about
// files/caps then, and the report says so by leaving those fields null).
function buildCoverage(info, { analyzed, importSkipped, diffMode, results }) {
  return {
    chunks_found:              info ? info.total_chunks : null,
    chunks_scanned:            analyzed,
    import_chunks_skipped:     importSkipped,
    max_chunks_effective:      info ? info.max_chunks : null,
    chunks_dropped_by_cap:     info ? info.chunks_dropped_by_cap : null,
    chunks_before_start:       info ? info.chunks_before_start : null,
    truncated:                 info ? info.truncated : null,
    files_found:               info ? info.files_found : null,
    files_skipped_too_large:   info ? info.files_skipped_too_large : null,
    max_file_size:             info ? info.max_file_size : null,
    files_skipped_generated:   info ? info.files_skipped_generated : null,
    files_skipped_tests:       info ? info.files_skipped_tests : null,
    chunks_hard_split:         info ? info.chunks_hard_split : null,
    chunks_partial_output:     results.filter(r => r.partial_output).length,
    diff_mode:                 diffMode,
  };
}

export { buildCoverage };

export { analyzeSast, EXT_LANG };