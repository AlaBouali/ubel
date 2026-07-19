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

function atomicWrite(filePath, content) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, filePath);
}

async function collectMetadata(opts) {
  let gitMetadata = {};
  let osMetadata  = {};
  try { gitMetadata = getGitMetadata();      } catch { /* non-fatal */ }
  try { osMetadata  = await getOSMetadata(); } catch { /* non-fatal */ }
  return {
    generated_at:    new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    tool_version:    TOOL_VERSION,
    provider:        opts.provider || null,
    model:           opts.model    || null,
    workingDir:      opts.workingDir,
    platform:        process.platform,
    arch:            process.arch,
    runtime_version: process.version.replace(/^v/, ''),
    gitMetadata,
    osMetadata,
  };
}

// ─── Shared report writer: `analyze` ───────────────────────────────────────────
// Used by BOTH the CLI `analyze` subcommand and the programmatic
// main({ mode: "analyze", ... }) path. Never calls process.exit — the
// caller decides what to do with the returned `shouldFail` flag.

async function writeAnalyzeReports(results, opts) {
  const now      = new Date();
  const pad      = n => String(n).padStart(2, '0');
  const ts       = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}`
                 + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
  const datePath = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;

  const workingDir = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();

  const reportDir = path.join(workingDir, '.ubel', 'local', 'reports', 'sast', datePath);
  fs.mkdirSync(reportDir, { recursive: true });

  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });

  const baseName  = `sast__${ts}`;
  const jsonPath  = path.join(reportDir, `${baseName}.json`);
  const htmlPath  = path.join(reportDir, `${baseName}.html`);
  const sarifPath = path.join(reportDir, `${baseName}.sarif.json`);

  const latestJson  = path.join(latestDir, 'latest.sast.json');
  const latestHtml  = path.join(latestDir, 'latest.sast.html');
  const latestSarif = path.join(latestDir, 'latest.sast.sarif.json');

  const meta = await collectMetadata({ ...opts, workingDir });

  // ── Normalize findings ────────────────────────────────────────────────────
  // The LLM outputs `vuln_name` (per the prompt schema). The HTML and SARIF
  // generators expect `vuln_class`. The LLM also sometimes appends the CWE
  // tag to the name (e.g. "SQL injection (CWE-89)") — strip it so lookup
  // tables in the generators get an exact canonical match. Also align field
  // name aliases that diverged between the prompt schema, the workers layer,
  // and the report generators.
  for (const chunk of results) {
    for (const f of (chunk.findings || [])) {
      if (f._parse_error) continue;
      const raw = f.vuln_class || f.vuln_name || 'unknown';
      f.vuln_class = raw.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
      f.vuln_name  = f.vuln_class;
      if (f.taint && f.taint.reasoning && !f.taint.rationale) {
        f.taint.rationale = f.taint.reasoning;
      }
      if (f.verification_reason && !f.reason) {
        f.reason = f.verification_reason;
      }
    }
  }

  const jsonPayload = JSON.stringify({ generated_at: meta.generated_at, meta, results }, null, 2);
  atomicWrite(jsonPath,  jsonPayload);
  atomicWrite(latestJson, jsonPayload);
  console.log(`\n[ubel-sast] JSON  report : ${jsonPath}`);

  try {
    const htmlReport = generateSastHTMLReport(results, meta);
    atomicWrite(htmlPath,  htmlReport);
    atomicWrite(latestHtml, htmlReport);
    console.log(`[ubel-sast] HTML  report : ${htmlPath}`);
  } catch (e) {
    console.warn(`[ubel-sast] HTML report failed: ${e.message}`);
  }

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

  // ── Console summary ────────────────────────────────────────────────────────
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

  // ── Pass/fail evaluation ────────────────────────────────────────────────────
  const failOn = opts.failOn || 'any';
  const allFindings = results.flatMap(r => r.findings);
  const hasExploitable          = allFindings.some(f => f.taint?.exploitable === true);
  const hasValid                = allFindings.some(f => f.is_valid === true);
  const hasFindingsWithoutPasses = !opts.verify && !opts.taintTrace && allFindings.some(f => !f._parse_error);
  const hasUnresolved           = unresolvedFindings.length > 0;

  let shouldFail;
  switch (failOn) {
    case 'exploitable':
      shouldFail = hasExploitable || hasUnresolved;
      break;
    case 'valid':
      shouldFail = hasValid || hasExploitable || hasUnresolved;
      break;
    case 'any':
    default:
      shouldFail = hasExploitable || hasValid || hasFindingsWithoutPasses || hasUnresolved;
      break;
  }

  if (shouldFail && hasUnresolved && !(failOn === 'exploitable' ? hasExploitable : failOn === 'valid' ? hasValid : true)) {
    console.log(`\n[ubel-sast] Exiting non-zero: no finding met the --fail-on ${failOn} bar, but ${unresolvedFindings.length} finding(s) could not be resolved either way (see "Unverified / untraced findings" above).`);
  }

  return { jsonPath, htmlPath, sarifPath, meta, shouldFail };
}

// ─── Shared report writer: `malware` ───────────────────────────────────────────
// Same contract as writeAnalyzeReports: never calls process.exit.

async function writeMalwareReports(results, opts) {
  const now      = new Date();
  const pad      = n => String(n).padStart(2, '0');
  const ts       = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}`
                 + `__${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
  const datePath = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;

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

  const meta = await collectMetadata({ ...opts, workingDir });
  meta.scan_type = 'malware';

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

  const jsonPayload = JSON.stringify({ generated_at: meta.generated_at, meta, results }, null, 2);
  atomicWrite(jsonPath,  jsonPayload);
  atomicWrite(latestJson, jsonPayload);
  console.log(`\n[ubel-malware] JSON  report : ${jsonPath}`);

  try {
    const htmlReport = generateSastHTMLReport(results, meta);
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

  const failOn = opts.failOn || 'any';
  const shouldFail = failOn === 'confirmed'
    ? (confirmed.length > 0 || unresolved.length > 0)
    : allFindings.length > 0;

  return { jsonPath, htmlPath, sarifPath, meta, shouldFail };
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
  if (flags['no-retry'] && (flags['no-retry'].toLowerCase().startsWith('t') || flags['no-retry'] === "1")) opts.retryOnParseError = false;
  if (flags['no-verify'] && (flags['no-verify'].toLowerCase().startsWith('t') || flags['no-verify'] === "1")) opts.verify      = false;
  if (flags['no-taint']  && (flags['no-taint'].toLowerCase().startsWith('t') || flags['no-taint'] === "1")) opts.taintTrace  = false;
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

  const FAIL_ON_MODES = new Set(['any', 'valid', 'exploitable']);
  const failOn = flags['fail-on'] ? String(flags['fail-on']) : 'any';
  if (!FAIL_ON_MODES.has(failOn)) {
    console.error(`Error: --fail-on must be one of: ${[...FAIL_ON_MODES].join(', ')} (got "${failOn}")`);
    process.exit(2);
  }
  opts.failOn = failOn;
  if (opts.diffBase){
    const allowedDiffBase = /^[\w\/\.\-]+$/;
    if (!allowedDiffBase.test(opts.diffBase)) {
      console.error(`Error: --diff-base must be a valid git ref (got "${opts.diffBase}")`);
      process.exit(1);
    }
  }

  analyzeSast([], opts)
    .then(results => writeAnalyzeReports(results, opts))
    .then(({ shouldFail }) => process.exit(shouldFail ? 1 : 0))
    .catch(e => {
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
  if (opts.verify === undefined) opts.verify = true;
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

  analyzeMalware([], opts)
    .then(results => writeMalwareReports(results, opts))
    .then(({ shouldFail }) => process.exit(shouldFail ? 1 : 0))
    .catch(e => {
      console.error(`Fatal: ${e.message}`);
      process.exit(2);
    });
}

// ─── Top-level CLI dispatch ───────────────────────────────────────────────────

function printUsage() {
  console.log(`UBEL SAST — usage:

  main.js chunk    [path] [options]   Build semantic code chunks → sast_chunks.json
  main.js analyze  [path] [options]   Run SAST analysis (scan → verify → taint trace) → .ubel/reports/
  main.js malware  [path] [options]   Scan for intentional malicious code / backdoors (scan → verify) → .ubel/reports/

If no subcommand is given, "analyze" is assumed and the first argument is
treated as the target path (or --working-dir).

Run with --help after a subcommand is not currently supported; see project
documentation for the full list of options.`);
}

// ─── Unified entry point ────────────────────────────────────────────────────────
// Mirrors sca/main.js: a single exported `main` used both by the CLI
// wrappers and by programmatic callers.
//
//   CLI path (bin/sast.js, bin/mal.js):
//     process.argv.splice(2, 0, "analyze" | "malware");
//     import("../sast/main.js").then(({ main }) => main());
//   — exactly the same pattern bin/bun.js and bin/pnpm.js use against
//   ../sca/main.js.
//
//   Programmatic path (agent.js, platform.js, extension.js, MCP server):
//     import { main } from "./sast/main.js";
//     const { results } = await main({ projectRoot, mode: "malware", ...opts });
//   Never touches process.argv and never calls process.exit — it returns
//   the results (and report paths, if save_reports isn't disabled) instead.

export async function main(programmaticOptions) {

  // ════════════════════════════════════════════════════════════════════════════
  // PROGRAMMATIC PATH
  // ════════════════════════════════════════════════════════════════════════════
  if (programmaticOptions !== undefined && typeof programmaticOptions === "object") {
    const {
      projectRoot,
      mode         = "analyze",   // "analyze" | "malware"
      save_reports = true,
      ...opts
    } = programmaticOptions;

    opts.workingDir = projectRoot ? path.resolve(projectRoot) : path.resolve(process.cwd());
    if (opts.verify === undefined) opts.verify = true;
    if (mode === "analyze" && opts.taintTrace === undefined) opts.taintTrace = true;
    if (opts.skipSignals === undefined) opts.skipSignals = true;
    if (opts.failOn === undefined) opts.failOn = "any";

    if (mode === "malware") {
      const results = await analyzeMalware([], opts);
      const report  = save_reports ? await writeMalwareReports(results, opts) : {};
      return { mode, results, ...report };
    }

    const results = await analyzeSast([], opts);
    const report  = save_reports ? await writeAnalyzeReports(results, opts) : {};
    return { mode, results, ...report };
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CLI PATH
  // Called by: bin/sast.js (splices "analyze"), bin/mal.js (splices "malware")
  // ════════════════════════════════════════════════════════════════════════════
  const rawArgs = process.argv.slice(2);
  const [first, ...rest] = rawArgs;

  if (first === 'chunk')   { runChunkCommand(rest);   return; }
  if (first === 'analyze') { runAnalyzeCommand(rest); return; }
  if (first === 'malware') { runMalwareCommand(rest); return; }

  if (first === '--help' || first === '-h') {
    printUsage();
    return;
  }

  // Backward-compatible default: no subcommand given → run analyze directly,
  // treating all args (including a leading path) as analyze's own args.
  runAnalyzeCommand(rawArgs);
}

export { runChunkCommand, runAnalyzeCommand, runMalwareCommand };