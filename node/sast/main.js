#!/usr/bin/env node
'use strict';

import fs   from 'fs';
import path from 'path';

import { buildChunks }            from './src/chunker/index.js';
import { analyzeSast, analyzeMalware } from './src/analyzer/index.js';
import { SastSarifBuilder }       from './sarif_report_generator.js';
import { generateSastHTMLReport } from './html_report_generator.js';
import { getGitMetadata }         from './git_info.js';
import { getOSMetadata }          from './os_metadata.js';
import { TOOL_VERSION }           from './info.js';

// ─── Shared CLI flag parser ────────────────────────────────────────────────────

function parseArgs(args) {
  const flags = {};
  let positional = null;
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith('--')) {
      const key = args[i].slice(2);
      const val = (args[i + 1] && !args[i + 1].startsWith('--')) ? args[++i] : true;
      flags[key] = val;
    } else if (!positional) {
      positional = args[i];
    }
  }
  return { flags, positional };
}

// ─── `chunk` subcommand ─────────────────────────────────────────────────────────
// Mirrors the original sast_chunker.js CLI entry: builds chunks from a
// directory/file and writes them to sast_chunks.json.

function runChunkCommand(args) {
  const { flags, positional } = parseArgs(args);

  const opts = {};
  if (positional)              opts.workingDir    = positional;
  if (flags['working-dir'])    opts.workingDir    = String(flags['working-dir']);
  if (flags['max-chunk-size']) opts.maxChunkSize  = parseInt(flags['max-chunk-size'], 10);
  if (flags['chunks-start'])   opts.chunksStart   = parseInt(flags['chunks-start'],   10);
  if (flags['max-chunks'])     opts.maxChunks     = parseInt(flags['max-chunks'],      10);
  if (flags['skip-folders'])   opts.skipFolders   = String(flags['skip-folders']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['skip-files'])     opts.skipFiles     = String(flags['skip-files']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['languages'])      opts.languages     = String(flags['languages']).split(',').map(s => s.trim()).filter(Boolean);

  const root = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();
  if (!fs.existsSync(root)) { console.error(`Error: path not found — ${root}`); process.exit(1); }

  const chunks     = buildChunks(root, opts);
  const outputPath = path.join(process.cwd(), 'sast_chunks.json');
  fs.writeFileSync(outputPath, JSON.stringify(chunks, null, 2));
  console.log(`\n[ubel-sast] Chunks written to: ${outputPath}`);

  console.log('\n── Preview (first 3 chunks) ─────────────────────────────────');
  for (const chunk of chunks.slice(0, 3)) {
    console.log(`\nID        : ${chunk.id}`);
    console.log(`Type      : ${chunk.type}`);
    console.log(`Lines     : ${chunk.startLine}–${chunk.endLine}`);
    const preview = chunk.code.split('\n').slice(0, 5).join('\n');
    const hasMore = chunk.code.split('\n').length > 5;
    console.log(`Code      :\n${preview}${hasMore ? '\n  ...' : ''}`);
  }
}

// ─── `analyze` subcommand ────────────────────────────────────────────────────────
// Mirrors the original sast_analyzer.js CLI entry: runs the three-pass
// scan → verify → taint-trace pipeline and writes JSON + HTML + SARIF reports.

function runAnalyzeCommand(args) {
  const { flags, positional } = parseArgs(args);

  // ── Build opts ───────────────────────────────────────────────────────────
  const opts = {};

  // LLM / analysis params
  if (flags['provider'])       opts.provider        = String(flags['provider']);
  if (flags['api-key'])        opts.apiKey          = String(flags['api-key']);
  if (flags['api-key-header']) opts.apiKeyHeader     = String(flags['api-key-header']);
  if (flags['api-key-prefix'] !== undefined && flags['api-key-prefix'] !== true)
                               opts.apiKeyPrefix     = String(flags['api-key-prefix']);
  if (flags['endpoint'])       opts.endpoint        = String(flags['endpoint']);
  if (flags['model'])          opts.model           = String(flags['model']);
  if (flags['concurrency'])    opts.concurrency     = parseInt(flags['concurrency'],   10);
  if (flags['temperature'])    opts.temperature     = parseFloat(flags['temperature']);
  if (flags['max-tokens'])     opts.maxTokens       = parseInt(flags['max-tokens'],    10);
  if (flags['timeout'])        opts.requestTimeout  = parseInt(flags['timeout'],       10);
  if (flags['max-retries'])    opts.maxRetries      = parseInt(flags['max-retries'],   10);
  if (flags['no-retry'] && (flags['no-retry'].toLowerCase().startsWith('t') || flags['no-retry'] === "1")) opts.retryOnParseError = false;
  if (flags['no-verify'] && (flags['no-verify'].toLowerCase().startsWith('t') || flags['no-verify'] === "1")) opts.verify      = false;
  if (flags['no-taint']  && (flags['no-taint'].toLowerCase().startsWith('t') || flags['no-taint'] === "1")) opts.taintTrace  = false;
  // Explicit defaults — without these, opts.verify/opts.taintTrace stay
  // `undefined` whenever neither --no-verify nor --no-taint is passed (the
  // default case, and the one every basic usage example in the README
  // uses). The exit-code logic below tests `!opts.verify` / `!opts.taintTrace`
  // to detect "this pass was skipped" — with undefined instead of true,
  // those negations evaluated as if verify/taint were disabled even when
  // both ran normally, which silently turned `--fail-on any` (the default)
  // into "fail on any raw Pass-1 finding" regardless of what verify/taint
  // concluded — including findings verify had already confirmed as false
  // positives.
  if (opts.verify === undefined)     opts.verify     = true;
  if (opts.taintTrace === undefined) opts.taintTrace = true;
  if (flags['include-signals'] ) {
    opts.skipSignals = false
  }else{
    opts.skipSignals = true
  };
  if (flags['verify-concurrency'])      opts.verifyConcurrency      = parseInt(flags['verify-concurrency'],      10);
  if (flags['taint-concurrency'])       opts.taintConcurrency       = parseInt(flags['taint-concurrency'],       10);
  if (flags['verification-max-tokens']) opts.verificationMaxTokens  = parseInt(flags['verification-max-tokens'], 10);
  if (flags['taint-max-tokens'])        opts.taintMaxTokens         = parseInt(flags['taint-max-tokens'],        10);

  // Chunker params
  if (positional)                opts.workingDir   = positional;
  if (flags['working-dir'])      opts.workingDir   = String(flags['working-dir']);
  if (flags['max-chunk-size'])   opts.maxChunkSize = parseInt(flags['max-chunk-size'],  10);
  if (flags['chunks-start'])     opts.chunksStart  = parseInt(flags['chunks-start'],    10);
  if (flags['max-chunks'])       opts.maxChunks    = parseInt(flags['max-chunks'],       10);
  if (flags['skip-folders'])     opts.skipFolders  = String(flags['skip-folders']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['skip-files'])       opts.skipFiles    = String(flags['skip-files']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['languages'])        opts.languages    = String(flags['languages']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['only-diff'] && (flags['only-diff'].toLowerCase().startsWith('t') || flags['only-diff'] === "1")) opts.onlyDiff   = true;
  if (flags['diff-base'])        opts.diffBase     = String(flags['diff-base']);

  // ── Exit-code policy ──────────────────────────────────────────────────────
  // --fail-on controls which findings are allowed to make the CLI exit non-zero.
  // The reports ALWAYS contain every finding regardless of this flag —
  // --fail-on only changes the CI/exit-code gate, never what gets written.
  //   any         (default) — any finding at all fails the build, including
  //                ones that couldn't be verified or traced ("didn't finish
  //                checking" is never silently clean)
  //   valid       — only findings verified as is_valid === true fail the build
  //                (confirmed real issues, regardless of exploitability)
  //   exploitable — only findings where taint-trace confirmed exploitable === true
  //                fail the build (confirmed real AND reachable from attacker input)
  const FAIL_ON_MODES = new Set(['any', 'valid', 'exploitable']);
  const failOn = flags['fail-on'] ? String(flags['fail-on']) : 'any';
  if (!FAIL_ON_MODES.has(failOn)) {
    console.error(`Error: --fail-on must be one of: ${[...FAIL_ON_MODES].join(', ')} (got "${failOn}")`);
    process.exit(2);
  }
  opts.failOn = failOn;
  if (opts.diffBase){
    //sanitize diffBase to avoid shell injection
    const allowedDiffBase = /^[\w\/\.\-]+$/;
    if (!allowedDiffBase.test(opts.diffBase)) {
      console.error(`Error: --diff-base must be a valid git ref (got "${opts.diffBase}")`);
      process.exit(1);
    }
  }

  analyzeSast([], opts).then(async results => {
    // ── Timestamps & output paths ──────────────────────────────────────────
    const now      = new Date();
    const pad      = n => String(n).padStart(2, '0');
    const ts       = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}`
                   + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
    const datePath = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;
    const generatedAt = now.toISOString().replace(/\.\d+Z$/, 'Z');

    // Resolve the working directory that was actually scanned — used for
    // placing the timestamped report sub-tree and for `latest.*` symlinks.
    const workingDir = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();

    // Timestamped report directory: <workingDir>/.ubel/local/reports/sast/<date>/
    const reportDir = path.join(workingDir, '.ubel', 'local', 'reports', 'sast', datePath);
    fs.mkdirSync(reportDir, { recursive: true });

    // latest.* lives at: <workingDir>/.ubel/reports/
    const latestDir = path.join(workingDir, '.ubel', 'reports');
    fs.mkdirSync(latestDir, { recursive: true });

    // Base name for the timestamped trio
    const baseName  = `sast__${ts}`;
    const jsonPath  = path.join(reportDir, `${baseName}.json`);
    const htmlPath  = path.join(reportDir, `${baseName}.html`);
    const sarifPath = path.join(reportDir, `${baseName}.sarif.json`);

    const latestJson  = path.join(latestDir, 'latest.sast.json');
    const latestHtml  = path.join(latestDir, 'latest.sast.html');
    const latestSarif = path.join(latestDir, 'latest.sast.sarif.json');

    // ── Collect metadata (mirrors SCA engine) ────────────────────────────
    let gitMetadata = {};
    let osMetadata  = {};
    try { gitMetadata = getGitMetadata();       } catch { /* non-fatal */ }
    try { osMetadata  = await getOSMetadata();  } catch { /* non-fatal */ }

    const meta = {
      generated_at:    generatedAt,
      tool_version:    TOOL_VERSION,
      provider:        opts.provider   || null,
      model:           opts.model      || null,
      workingDir,
      platform:        process.platform,
      arch:            process.arch,
      runtime_version: process.version.replace(/^v/, ''),
      gitMetadata,
      osMetadata,
    };

    // ── Atomic JSON write (identical pattern to SCA safeWriteJson) ───────
    function atomicWrite(filePath, content) {
      const tmp = filePath + '.tmp';
      fs.writeFileSync(tmp, content);
      fs.renameSync(tmp, filePath);
    }

    // ── Normalize findings ────────────────────────────────────────────────
    // The LLM outputs `vuln_name` (per the prompt schema).  The HTML and SARIF
    // generators expect `vuln_class`.  The LLM also sometimes appends the CWE
    // tag to the name (e.g. "SQL injection (CWE-89)") — strip it so lookup
    // tables in the generators get an exact canonical match.
    //
    // Also align field name aliases that diverged between the prompt schema,
    // the workers layer, and the report generators:
    //   taint.reasoning        → taint.rationale  (generators read rationale)
    //   finding.verification_reason → finding.reason  (generators read reason)
    for (const chunk of results) {
      for (const f of (chunk.findings || [])) {
        if (f._parse_error) continue;
        // vuln_class: canonical name, CWE suffix stripped
        const raw = f.vuln_class || f.vuln_name || 'unknown';
        f.vuln_class = raw.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
        f.vuln_name  = f.vuln_class;
        // taint field aliases
        if (f.taint) {
          if (f.taint.reasoning && !f.taint.rationale) {
            f.taint.rationale = f.taint.reasoning;
          }
        }
        // verification field alias
        if (f.verification_reason && !f.reason) {
          f.reason = f.verification_reason;
        }
      }
    }

    // ── JSON ─────────────────────────────────────────────────────────────
    // The JSON report embeds results + meta so it is fully self-describing.
    const jsonPayload = JSON.stringify({ generated_at: generatedAt, meta, results }, null, 2);
    atomicWrite(jsonPath,  jsonPayload);
    atomicWrite(latestJson, jsonPayload);
    console.log(`\n[ubel-sast] JSON  report : ${jsonPath}`);

    // ── HTML ─────────────────────────────────────────────────────────────
    let htmlReport = '';
    try {
      htmlReport = generateSastHTMLReport(results, meta);
      atomicWrite(htmlPath,  htmlReport);
      atomicWrite(latestHtml, htmlReport);
      console.log(`[ubel-sast] HTML  report : ${htmlPath}`);
    } catch (e) {
      console.warn(`[ubel-sast] HTML report failed: ${e.message}`);
    }

    // ── SARIF ────────────────────────────────────────────────────────────
    try {
      const sarifBuilder = new SastSarifBuilder(results, meta);
      const sarifPayload = JSON.stringify(sarifBuilder.generate(), null, 2);
      atomicWrite(sarifPath,  sarifPayload);
      atomicWrite(latestSarif, sarifPayload);
      console.log(`[ubel-sast] SARIF report : ${sarifPath}`);
    } catch (e) {
      console.warn(`[ubel-sast] SARIF report failed: ${e.message}`);
    }

    console.log(`\n[ubel-sast] Latest reports : ${latestDir}`);

    // ── Console summary (unchanged from original) ────────────────────────
    const exploitableResults = results.filter(r =>
      r.findings.some(f => f.taint?.exploitable === true)
    );

    const unresolvedFindings = results.flatMap(r =>
      r.findings
        .filter(f => !f._parse_error)
        .map(f => ({ result: r, finding: f }))
    ).filter(({ finding: f }) =>
      f.taint?.exploitable !== true &&
      !(f.is_valid === true && f.taint?.exploitable === false) &&
      !(f.is_valid === false) &&
      (f.verification_error || f.taint?.error || f.taint?.inconclusive_reason || f.is_valid === null)
    );

    if (exploitableResults.length > 0) {
      console.log('\n── Exploitable findings ─────────────────────────────────────');
      for (const result of exploitableResults.slice(0, 10)) {
        for (const f of result.findings.filter(f => f.taint?.exploitable === true)) {
          console.log(`\n  ⚠️ [${f.confidence.toUpperCase()}] ${f.vuln_name}`);
          console.log(`  Chunk : ${result.id}`);
          console.log(`  Lines : ${result.startLine}–${result.endLine}`);
          console.log(`  Issue : ${f.description}`);
          console.log(`  Snip  : ${f.code_snippet.slice(0, 100)}`);
          console.log(`  Fix   : ${f.fix.slice(0, 120)}`);
          if (f.taint?.flow_path) console.log(`  Flow  : ${f.taint.flow_path}`);
          if (f.taint?.reasoning) console.log(`  Reason: ${f.taint.reasoning.slice(0, 200)}`);
        }
      }
    } else if (unresolvedFindings.length === 0) {
      console.log('\n[ubel-sast] No exploitable vulnerabilities found.');
    } else {
      console.log(`\n[ubel-sast] No CONFIRMED exploitable vulnerabilities — but ${unresolvedFindings.length} finding(s) below could not be resolved either way. Review them before treating this run as clean.`);
    }

    const verifiedResults = results.filter(r =>
      r.findings.some(f => f.is_valid === true && f.taint?.exploitable !== true)
    );

    if (verifiedResults.length > 0) {
      console.log('\n── Verified but mitigated findings ──────────────────────────');
      for (const result of verifiedResults.slice(0, 5)) {
        for (const f of result.findings.filter(f => f.is_valid === true && f.taint?.exploitable !== true)) {
          const status = f.taint?.reachable === false ? '(not reachable)' :
                         f.taint?.sanitized === true ? '(sanitized)' :
                         f.taint?.exploitable === false ? '(mitigated)' : '(unknown)';
          console.log(`  🛡️ [${f.confidence.toUpperCase()}] ${f.vuln_name} ${status}`);
          console.log(`  Chunk : ${result.id}`);
          console.log(`  Lines : ${result.startLine}–${result.endLine}`);
          console.log(`  Issue : ${f.description}`);
          if (f.taint?.reasoning) console.log(`  Reason: ${f.taint.reasoning.slice(0, 150)}`);
        }
      }
    }

    if (unresolvedFindings.length > 0) {
      console.log('\n── ⚠️  Unverified / untraced findings (NOT cleared, NOT confirmed) ──');
      for (const { result, finding: f } of unresolvedFindings.slice(0, 10)) {
        const why = f.verification_error?.reason || f.taint?.error?.reason ||
                    f.taint?.inconclusive_reason ||
                    (f.is_valid === null ? 'unknown' : 'unresolved');
        const detail = f.verification_error?.detail || f.taint?.error?.detail || '';
        console.log(`\n  ❓ [${f.confidence.toUpperCase()}] ${f.vuln_name}  (reason: ${why})`);
        console.log(`  Chunk : ${result.id}`);
        console.log(`  Lines : ${result.startLine}–${result.endLine}`);
        console.log(`  Issue : ${f.description}`);
        if (detail) console.log(`  Detail: ${String(detail).slice(0, 150)}`);
      }
      if (unresolvedFindings.length > 10) {
        console.log(`\n  … and ${unresolvedFindings.length - 10} more — see ${jsonPath}`);
      }
    }

    // ── Exit codes ────────────────────────────────────────────────────────
    const allFindings = results.flatMap(r => r.findings);
    const hasExploitable            = allFindings.some(f => f.taint?.exploitable === true);
    const hasValid                  = allFindings.some(f => f.is_valid === true);
    // Only fires when BOTH verify and taint were explicitly skipped
    // (--no-verify --no-taint together) — the one case where a finding can
    // exist with zero confidence signal at all (no is_valid, no taint).
    // hasValid already covers "verified true" regardless of taint outcome,
    // so a separate "verified true but taint didn't run" check would be
    // strictly redundant with it.
    const hasFindingsWithoutPasses  = !opts.verify && !opts.taintTrace && allFindings.some(f => !f._parse_error);
    const hasUnresolved             = unresolvedFindings.length > 0;

    let shouldFail;
    switch (opts.failOn) {
      case 'exploitable':
        shouldFail = hasExploitable || hasUnresolved;
        break;
      case 'valid':
        shouldFail = hasValid || hasExploitable || hasUnresolved;
        break;
      case 'any':
      default:
        // Must stay a superset of 'valid' and 'exploitable' — any is the
        // most permissive fail-on mode by name and by documented intent,
        // so it can never legitimately let through less than the stricter
        // modes do. Explicitly includes hasValid for that reason (a
        // verified-but-mitigated finding still fails 'valid'; it must
        // still fail 'any' too).
        shouldFail = hasExploitable || hasValid || hasFindingsWithoutPasses || hasUnresolved;
        break;
    }

    if (shouldFail) {
      if (hasUnresolved && !(opts.failOn === 'exploitable' ? hasExploitable : opts.failOn === 'valid' ? hasValid : true)) {
        console.log(`\n[ubel-sast] Exiting non-zero: no finding met the --fail-on ${opts.failOn} bar, but ${unresolvedFindings.length} finding(s) could not be resolved either way (see "Unverified / untraced findings" above).`);
      }
      process.exit(1);
    }
    process.exit(0);

  }).catch(e => {
    console.error(`Fatal: ${e.message}`);
    process.exit(2);
  });
}

// ─── `malware` subcommand ─────────────────────────────────────────────────────
// Separate concern from `analyze`: scans for INTENTIONALLY malicious code /
// backdoors (reverse shells, C2 beacons, supply-chain implants, persistence
// mechanisms, exfiltration, etc.) rather than accidental vulnerability
// classes. Own catalog, own prompts, own report set — written under
// .ubel/reports/*.malware.* so it never collides with `analyze`'s output.

function runMalwareCommand(args) {
  const { flags, positional } = parseArgs(args);

  const opts = {};

  if (flags['provider'])       opts.provider        = String(flags['provider']);
  if (flags['api-key'])        opts.apiKey          = String(flags['api-key']);
  if (flags['api-key-header']) opts.apiKeyHeader     = String(flags['api-key-header']);
  if (flags['api-key-prefix'] !== undefined && flags['api-key-prefix'] !== true)
                               opts.apiKeyPrefix     = String(flags['api-key-prefix']);
  if (flags['endpoint'])       opts.endpoint        = String(flags['endpoint']);
  if (flags['model'])          opts.model           = String(flags['model']);
  if (flags['concurrency'])    opts.concurrency     = parseInt(flags['concurrency'],   10);
  if (flags['temperature'])    opts.temperature     = parseFloat(flags['temperature']);
  if (flags['max-tokens'])     opts.maxTokens       = parseInt(flags['max-tokens'],    10);
  if (flags['timeout'])        opts.requestTimeout  = parseInt(flags['timeout'],       10);
  if (flags['max-retries'])    opts.maxRetries      = parseInt(flags['max-retries'],   10);
  if (flags['no-retry']  && (flags['no-retry'].toLowerCase().startsWith('t') || flags['no-retry'] === "1")) opts.retryOnParseError = false;
  if (flags['no-verify'] && (flags['no-verify'].toLowerCase().startsWith('t') || flags['no-verify'] === "1")) opts.verify      = false;
  if (flags['include-signals']) {
    opts.skipSignals = false
  }else{
    opts.skipSignals = true
  };
  if (flags['verify-concurrency'])      opts.verifyConcurrency      = parseInt(flags['verify-concurrency'],      10);
  if (flags['verification-max-tokens']) opts.verificationMaxTokens  = parseInt(flags['verification-max-tokens'], 10);

  if (positional)                opts.workingDir   = positional;
  if (flags['working-dir'])      opts.workingDir   = String(flags['working-dir']);
  if (flags['max-chunk-size'])   opts.maxChunkSize = parseInt(flags['max-chunk-size'],  10);
  if (flags['chunks-start'])     opts.chunksStart  = parseInt(flags['chunks-start'],    10);
  if (flags['max-chunks'])       opts.maxChunks    = parseInt(flags['max-chunks'],       10);
  if (flags['skip-folders'])     opts.skipFolders  = String(flags['skip-folders']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['skip-files'])       opts.skipFiles    = String(flags['skip-files']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['languages'])        opts.languages    = String(flags['languages']).split(',').map(s => s.trim()).filter(Boolean);
  if (flags['only-diff'] && (flags['only-diff'].toLowerCase().startsWith('t') || flags['only-diff'] === "1")) opts.onlyDiff   = true;
  if (flags['diff-base'])        opts.diffBase     = String(flags['diff-base']);

  // ── Exit-code policy ──────────────────────────────────────────────────────
  //   any        (default) — any finding at all fails the build, including
  //               ones the verify pass couldn't resolve either way
  //   confirmed  — only findings verified as is_valid === true fail the build
  const FAIL_ON_MODES = new Set(['any', 'confirmed']);
  const failOn = flags['fail-on'] ? String(flags['fail-on']) : 'any';
  if (!FAIL_ON_MODES.has(failOn)) {
    console.error(`Error: --fail-on must be one of: ${[...FAIL_ON_MODES].join(', ')} (got "${failOn}")`);
    process.exit(2);
  }
  opts.failOn = failOn;
  if (opts.diffBase) {
    const allowedDiffBase = /^[\w\/\.\-]+$/;
    if (!allowedDiffBase.test(opts.diffBase)) {
      console.error(`Error: --diff-base must be a valid git ref (got "${opts.diffBase}")`);
      process.exit(1);
    }
  }

  analyzeMalware([], opts).then(async results => {
    const now      = new Date();
    const pad      = n => String(n).padStart(2, '0');
    const ts       = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}`
                   + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
    const datePath = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;
    const generatedAt = now.toISOString().replace(/\.\d+Z$/, 'Z');

    const workingDir = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();

    const reportDir = path.join(workingDir, '.ubel', 'local', 'reports', 'malware', datePath);
    fs.mkdirSync(reportDir, { recursive: true });

    const latestDir = path.join(workingDir, '.ubel', 'reports');
    fs.mkdirSync(latestDir, { recursive: true });

    const baseName  = `malware__${ts}`;
    const jsonPath  = path.join(reportDir, `${baseName}.json`);
    const htmlPath  = path.join(reportDir, `${baseName}.html`);
    const sarifPath = path.join(reportDir, `${baseName}.sarif.json`);

    const latestJson  = path.join(latestDir, 'latest.malware.json');
    const latestHtml  = path.join(latestDir, 'latest.malware.html');
    const latestSarif = path.join(latestDir, 'latest.malware.sarif.json');

    let gitMetadata = {};
    let osMetadata  = {};
    try { gitMetadata = getGitMetadata();       } catch { /* non-fatal */ }
    try { osMetadata  = await getOSMetadata();  } catch { /* non-fatal */ }

    const meta = {
      generated_at:    generatedAt,
      tool_version:    TOOL_VERSION,
      scan_type:       'malware',
      provider:        opts.provider   || null,
      model:           opts.model      || null,
      workingDir,
      platform:        process.platform,
      arch:            process.arch,
      runtime_version: process.version.replace(/^v/, ''),
      gitMetadata,
      osMetadata,
    };

    function atomicWrite(filePath, content) {
      const tmp = filePath + '.tmp';
      fs.writeFileSync(tmp, content);
      fs.renameSync(tmp, filePath);
    }

    // Same field-alias normalization as `analyze` — vuln_name → vuln_class,
    // CWE-suffix stripped, so the shared HTML/SARIF generators render these
    // findings identically to SAST findings.
    for (const chunk of results) {
      for (const f of (chunk.findings || [])) {
        if (f._parse_error) continue;
        const raw = f.vuln_class || f.vuln_name || 'unknown';
        f.vuln_class = raw.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
        f.vuln_name  = f.vuln_class;
        if (f.verification_reason && !f.reason) {
          f.reason = f.verification_reason;
        }
      }
    }

    const jsonPayload = JSON.stringify({ generated_at: generatedAt, meta, results }, null, 2);
    atomicWrite(jsonPath,  jsonPayload);
    atomicWrite(latestJson, jsonPayload);
    console.log(`\n[ubel-malware] JSON  report : ${jsonPath}`);

    let htmlReport = '';
    try {
      htmlReport = generateSastHTMLReport(results, meta);
      atomicWrite(htmlPath,  htmlReport);
      atomicWrite(latestHtml, htmlReport);
      console.log(`[ubel-malware] HTML  report : ${htmlPath}`);
    } catch (e) {
      console.warn(`[ubel-malware] HTML report failed: ${e.message}`);
    }

    try {
      const sarifBuilder = new SastSarifBuilder(results, meta);
      const sarifPayload = JSON.stringify(sarifBuilder.generate(), null, 2);
      atomicWrite(sarifPath,  sarifPayload);
      atomicWrite(latestSarif, sarifPayload);
      console.log(`[ubel-malware] SARIF report : ${sarifPath}`);
    } catch (e) {
      console.warn(`[ubel-malware] SARIF report failed: ${e.message}`);
    }

    console.log(`\n[ubel-malware] Latest reports : ${latestDir}`);

    const allFindings   = results.flatMap(r => r.findings).filter(f => !f._parse_error);
    const confirmed      = allFindings.filter(f => f.is_valid === true);
    const falsePositives = allFindings.filter(f => f.is_valid === false);
    const unresolved      = allFindings.filter(f => f.is_valid !== true && f.is_valid !== false);

    if (confirmed.length > 0) {
      console.log('\n── 🚨 Confirmed malicious-code findings ─────────────────────────');
      for (const result of results) {
        for (const f of result.findings.filter(f => f.is_valid === true)) {
          console.log(`\n  🚨 [${f.severity ? f.severity.toUpperCase() : f.confidence.toUpperCase()}] ${f.vuln_name}`);
          console.log(`  Chunk : ${result.id}`);
          console.log(`  Lines : ${result.startLine}–${result.endLine}`);
          console.log(`  Issue : ${f.description}`);
          console.log(`  Snip  : ${f.code_snippet.slice(0, 100)}`);
          console.log(`  Fix   : ${f.fix.slice(0, 120)}`);
          if (f.verification_reason) console.log(`  Reason: ${f.verification_reason.slice(0, 200)}`);
        }
      }
    } else if (unresolved.length === 0) {
      console.log('\n[ubel-malware] No malicious code found.');
    } else {
      console.log(`\n[ubel-malware] No CONFIRMED malicious code — but ${unresolved.length} finding(s) could not be resolved either way (verify pass failed/skipped). Review them before treating this run as clean.`);
    }

    if (unresolved.length > 0) {
      console.log('\n── ⚠️  Unverified findings (NOT cleared, NOT confirmed) ──────────');
      for (const result of results) {
        for (const f of result.findings.filter(f => f.is_valid !== true && f.is_valid !== false && !f._parse_error)) {
          console.log(`\n  ❓ [${f.confidence.toUpperCase()}] ${f.vuln_name}`);
          console.log(`  Chunk : ${result.id}`);
          console.log(`  Lines : ${result.startLine}–${result.endLine}`);
          console.log(`  Issue : ${f.description}`);
        }
      }
    }

    // 'any'       — any finding at all fails the build, including ones the
    //               verify pass couldn't resolve either way.
    // 'confirmed' — only findings verified as is_valid === true fail the
    //               build; unresolved findings still fail it too, since
    //               "couldn't determine" should never read as "clean".
    const shouldFail = opts.failOn === 'confirmed'
      ? (confirmed.length > 0 || unresolved.length > 0)
      : allFindings.length > 0;

    process.exit(shouldFail ? 1 : 0);

  }).catch(e => {
    console.error(`Fatal: ${e.message}`);
    process.exit(2);
  });
}

// ─── Top-level CLI dispatch ───────────────────────────────────────────────────
//
// Usage:
//   main.js chunk    [path] [--working-dir <dir>] [--max-chunk-size <n>] ...
//   main.js analyze  [path] [--provider <name>] [--api-key <key>] ...
//
// For backward compatibility, if the first argument isn't a recognized
// subcommand, it's treated as the target path and the `analyze` pipeline
// runs end-to-end (build chunks, then scan/verify/taint-trace).

function printUsage() {
  console.log(`UBEL SAST — usage:

  main.js chunk    [path] [options]   Build semantic code chunks → sast_chunks.json
  main.js analyze  [path] [options]   Run SAST analysis (scan → verify → taint trace) → .ubel/reports/
  main.js malware  [path] [options]   Scan for intentional malicious code / backdoors (scan → verify) → .ubel/reports/

If no subcommand is given, "analyze" is assumed and the first argument is
treated as the target path (or --working-dir).

─── chunk options ──────────────────────────────────────────────────────────
  [path]                             Target directory to scan (or use --working-dir).
                                      Defaults to the current working directory.
  --working-dir <dir>                Same as the positional path argument.
  --max-chunk-size <n>               Max characters per chunk (default: 12000).
  --chunks-start <n>                 Slice start index into the chunk list, useful for
                                      resuming a partial run (default: 0).
  --max-chunks <n>                   Max number of chunks to build (default: 1000).
  --skip-folders <a,b,c>             Comma-separated extra folder names to exclude
                                      (e.g. "vendor,dist,build").
  --skip-files <a,b,c>               Comma-separated file names to exclude.
  --languages <a,b,c>                Comma-separated language families to include
                                      (default: all supported languages).

─── analyze options ────────────────────────────────────────────────────────

  Chunker params (same as "chunk", used when no chunk file is piped in):
    [path]                           Target directory to scan (or use --working-dir).
    --working-dir <dir>              Same as the positional path argument.
    --max-chunk-size <n>             Max characters per chunk (default: 12000).
    --chunks-start <n>               Slice start index into the chunk list (default: 0).
    --max-chunks <n>                 Max number of chunks to analyze (default: 1000).
    --skip-folders <a,b,c>           Comma-separated extra folder names to exclude.
    --skip-files <a,b,c>             Comma-separated file names to exclude.
    --languages <a,b,c>              Comma-separated language families to include.

  LLM / provider params:
    --provider <name>                LLM provider key (default: openrouter). Must match
                                      a key in the PROVIDERS registry.
    --api-key <key>                  API key for the provider. If omitted, falls back to
                                      the provider's registered environment variable
                                      (e.g. OPENROUTER_API_KEY, ANTHROPIC_API_KEY, etc.
                                      — see the error message for the exact name per
                                      provider). Not required for "local" or
                                      "docker"/"docker-desktop".
    --api-key-header <name>          Override the HTTP header used to send the API key
                                      (provider-specific default if omitted).
    --api-key-prefix <prefix>        Override the prefix prepended to the API key in
                                      the auth header (e.g. "Bearer "). Provider default
                                      if omitted; passing the flag with no value is ignored.
    --endpoint <url>                 Override the provider's default API endpoint. REQUIRED
                                      when --provider is "custom" (no default endpoint).
    --model <name>                   Override the provider's default model. REQUIRED when
                                      --provider is "custom" (no default model).

  Custom / self-hosted providers:
    --provider custom                Use any OpenAI-compatible /chat/completions API not
                                      already in the registry (self-hosted proxy, internal
                                      gateway, less common hosted API, etc.). Requires both
                                      --endpoint and --model. Auth defaults to
                                      "Authorization: Bearer <key>" — override with
                                      --api-key-header/--api-key-prefix if your endpoint uses
                                      something else. --api-key falls back to CUSTOM_API_KEY,
                                      then UBEL_SAST_API_KEY, and is optional (e.g. for an
                                      unauthenticated local server).
                                      Example:
                                        --provider custom \
                                        --endpoint https://my-llm.internal/v1/chat/completions \
                                        --model my-org/my-model \
                                        --api-key sk-...
    --concurrency <n>                Parallel scan requests in Pass 1 (default: 5).
    --temperature <n>                Sampling temperature for the scan pass (default: 0.1).
    --max-tokens <n>                 Max response tokens for the scan pass (default: 4096).
    --timeout <ms>                   Per-request timeout in milliseconds (default: 120000).
    --max-retries <n>                Max retries per request on failure/parse error (default: 2).
    --no-retry                       Disable automatic retry on JSON parse errors
                                      (default: retries enabled).

  Three-pass pipeline controls:
    --no-verify                      Skip Pass 2 (LLM verification of findings).
                                      Findings will have is_valid: null/undefined.
                                      (default: verification enabled).
    --no-taint                       Skip Pass 3 (taint trace / exploitability check).
                                      Findings will have no taint field.
                                      (default: taint trace enabled).
    --include-signals                Include the per-class "Detect when you see" detection
                                      bullets from the vulnerability catalog in the scan
                                      prompt (Pass 1 only). Reduces prompt tokens by
                                      ~2-2.5k per chunk at the cost of relying on class
                                      name + CWE + scope rule alone for detection guidance.
                                      (default: disabled — full catalog with signals).
    --verify-concurrency <n>         Parallel requests for Pass 2 (default: same as
                                      --concurrency).
    --taint-concurrency <n>          Parallel requests for Pass 3 (default: same as
                                      --concurrency).
    --verification-max-tokens <n>    Max response tokens for the verification pass
                                      (default: 4096).
    --taint-max-tokens <n>           Max response tokens for the taint trace pass
                                      (default: 4096).

  Diff mode:
    --only-diff                      Scan only chunks from files changed in the git diff,
                                      rather than the full codebase. The full chunk set is
                                      still built for taint call-chain resolution — only
                                      Pass 1 (scan) is filtered. (default: disabled — full
                                      scan).
    --diff-base <ref>                Git ref to diff against when --only-diff is set
                                      (default: HEAD^). Use "staged" to diff staged
                                      changes against HEAD.

  Exit-code policy:
    --fail-on <any|valid|exploitable>  Which findings make the process exit non-zero
                                        (default: any).
                                        any         — any finding, including ones that
                                                      couldn't be verified or traced
                                                      ("didn't finish checking" is never
                                                      silently treated as clean).
                                        valid       — only findings verified as real
                                                      (is_valid: true) fail the build,
                                                      regardless of exploitability.
                                        exploitable — only findings where taint-trace
                                                      confirmed exploitable: true fail
                                                      the build (confirmed real AND
                                                      reachable from attacker input).
                                        In every mode, the JSON/HTML/SARIF reports always
                                        contain ALL findings — this flag only changes the
                                        exit code, never what gets written.

─── malware options ────────────────────────────────────────────────────────
  Scans for intentionally malicious code / backdoors (reverse shells, C2
  beacons, supply-chain implants, persistence mechanisms, exfiltration,
  anti-analysis evasion, etc.) — a distinct concern from "analyze", which
  looks for accidental vulnerability classes. Uses its own catalog and
  prompts, and writes its own report set (latest.malware.json/html/sarif.json)
  so it never collides with "analyze" output. Same chunker, provider, and
  diff-mode flags as "analyze" (see above), minus the taint-trace pass and
  its flags (--no-taint, --taint-*), plus:

    --fail-on <any|confirmed>        Which findings make the process exit
                                      non-zero (default: any).
                                        any       — any finding at all fails
                                                    the build, including ones
                                                    the verify pass couldn't
                                                    resolve either way.
                                        confirmed — only findings verified as
                                                    is_valid: true fail the
                                                    build (unresolved findings
                                                    still fail it too — never
                                                    silently treated as clean).
                                      In every mode, the JSON/HTML/SARIF
                                      reports always contain ALL findings —
                                      this flag only changes the exit code.

Run with --help after a subcommand is not currently supported; see project
documentation for the full list of options.`);
}

function main() {
  const rawArgs = process.argv.slice(2);
  const [first, ...rest] = rawArgs;

  if (first === 'chunk') {
    runChunkCommand(rest);
    return;
  }

  if (first === 'analyze') {
    runAnalyzeCommand(rest);
    return;
  }

  if (first === 'malware') {
    runMalwareCommand(rest);
    return;
  }

  if (first === '--help' || first === '-h') {
    printUsage();
    return;
  }

  // Backward-compatible default: no subcommand given → run analyze directly,
  // treating all args (including a leading path) as analyze's own args.
  runAnalyzeCommand(rawArgs);
}

main();