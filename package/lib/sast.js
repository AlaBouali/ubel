'use strict';
// sast.js — optional static application security testing (SAST) of a package's own source: `ubel-package … --sast` (alias `--no-llm`).
//
// It runs the SAME deterministic rule engine as `ubel-sast --no-llm` (sast/src/static): no model, no API key, no network, and no source code
// leaves the machine. What it adds over the install-time / behavior analysis of scan.js is data-flow aware vulnerability rules (injection, unsafe
// deserialization, path traversal, weak crypto, …) and, with --rules-dir, the user's own Semgrep-syntax rules.
//
// The SAST engine reads files from a directory (the chunker, the HTML / template discovery and the line lookup all work on disk), while the rest
// of ubel-package reads the archive in memory. So, and ONLY when SAST is switched on, the text files of the package that the engine can read are
// written to a private temporary directory, analysed, and deleted again. Rules for what is written:
//   · only regular files that scan.js already decided to read as text (size limits, role, lockfile and binary checks have been applied);
//   · never an entry whose path escapes the package (`..`, absolute paths): those are archive problems, reported by scan.js, not extracted;
//   · the path on disk is rebuilt from the normalised entry path, every segment is made safe for any file system, and the result is checked to
//     stay inside the temporary directory; no link of any kind is ever created, files are created exclusively (never overwritten) with mode 0600;
//   · nothing that was written is executed, imported or installed; the directory is removed when the analysis ends (and on process exit).

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { normalizeEntryPath } from './archive.js';
import { SAST_RULE_PREFIX, registerSastRule } from './rules.js';
import { SUPPORTED_EXTENSIONS, IGNORE_DIRS } from '../../sast/src/chunker/constants.js';
import { detectConfigKind } from '../../sast/src/chunker/configDetect.js';
import { isMarkupFile } from '../../sast/src/static/markup.js';
import { DEFAULT_VULN_CLASSES } from '../../sast/src/analyzer/vulnCatalog.js';

const MB = 1024 * 1024;
const SEVERITIES = new Set(['critical', 'high', 'medium', 'low', 'info']);

// class name (lower case) → CWE number, from the same catalog the engine's classes come from
// (a class can list several, "CWE-79 / CWE-94": the first one is the primary)
const CWE_BY_CLASS = new Map(DEFAULT_VULN_CLASSES.map(v => [String(v.name).toLowerCase(), Number(/CWE-(\d+)/i.exec(String(v.cwe || ''))?.[1]) || null]));

// Hardcoded secrets are already found by ubel-package's own secret scanner (`secret.*` rules). It runs the same Trivy-derived rule set
// (sca/secrets.js) as the engine's secret rules, so filing the engine's matches as well would report every secret twice.
const SECRET_CLASS = /hardcoded (?:secret|credential)/i;

// The chunker skips dot-directories, dot-files and a list of "build output" folder names (dist, build, bin, vendor …). Everything in a package
// archive is the package, so those names are switched back on, and dot-names are renamed when the file is written (see `diskPath`).
const INCLUDE_FOLDERS = [...IGNORE_DIRS].filter(d => !d.startsWith('.'));

const isInside = (root, abs) => { const rel = path.relative(root, abs); return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel); };

export class SastStage {
  constructor() {
    this.root = null;
    this.staged = new Map();        // path on disk (relative to root, forward slashes) → { label, origin, context }
    this.used = new Set();          // lower-cased disk paths, so a case-insensitive file system cannot merge two entries
    this.stats = { staged: 0, bytes: 0, excluded: 0, unsafe_path: 0, not_written: 0 };
    this.failures = [];
    this._onExit = () => this.dispose();
  }

  /** Path of an entry inside the temporary directory: dot-names renamed, characters that some file systems refuse replaced, collisions numbered. */
  diskPath(p) {
    const segs = String(p).split('/').filter(s => s && s !== '.' && s !== '..')
      .map(s => (s.startsWith('.') ? `_dot_${s.slice(1)}` : s).replace(/[<>:"|?*\\\u0000-\u001f]/g, '_'));
    let rel = segs.join('/') || '_unnamed';
    if (this.used.has(rel.toLowerCase())) {
      const ext = path.posix.extname(rel);
      const stem = ext ? rel.slice(0, -ext.length) : rel;
      for (let n = 2; ; n++) { const cand = `${stem}~${n}${ext}`; if (!this.used.has(cand.toLowerCase())) { rel = cand; break; } }
    }
    this.used.add(rel.toLowerCase());
    return rel;
  }

  /**
   * @param {{path:string, rawPath?:string}} f   archive entry
   * @param {string} text                         the file's text (already decoded by scan.js)
   * @param {{label:string, origin:'app'|'library', context?:string, exclude?:boolean}} meta   exclude: a file the engine could read but that is left out on
   *        purpose (tests / documentation: they do not run on a consumer's machine); it is only counted
   * @returns {boolean} whether the file was written for the analysis
   */
  add(f, text, meta) {
    const base = f.path.split('/').pop();
    const ext = path.extname(base).toLowerCase();
    // only what the engine can read: its languages, HTML / template files, Dockerfile / Compose / Terraform / Kubernetes / CloudFormation / Ansible
    if (!SUPPORTED_EXTENSIONS.has(ext) && !isMarkupFile(base) && !detectConfigKind(f.path, text)) return false;
    if (meta.exclude) { this.stats.excluded++; return false; }
    if (normalizeEntryPath(f.rawPath ?? f.path).traversal) { this.stats.unsafe_path++; return false; }
    if (!this.root) {
      this.root = fs.mkdtempSync(path.join(fs.realpathSync(os.tmpdir()), 'ubel-package-sast-'));
      process.once('exit', this._onExit);
    }
    const rel = this.diskPath(f.path);
    const abs = path.join(this.root, ...rel.split('/'));
    if (!isInside(this.root, abs)) { this.stats.unsafe_path++; return false; }
    try {
      fs.mkdirSync(path.dirname(abs), { recursive: true });
      fs.writeFileSync(abs, text, { flag: 'wx', mode: 0o600 });
    } catch (e) {
      this.stats.not_written++;
      if (this.failures.length < 10) this.failures.push(`${meta.label.length > 80 ? `${meta.label.slice(0, 77)}…` : meta.label} (${e.code || e.message})`);
      return false;
    }
    this.staged.set(rel, meta);
    this.stats.staged++; this.stats.bytes += Buffer.byteLength(text);
    return true;
  }

  /**
   * Runs the static engine over what was written.
   * @param {{rulesDirs?:string[], maxChunks:number, maxChunkSize:number, maxTextKb:number}} o
   * @returns {Promise<{items:object[], summary:object, gaps:string[], notes:string[]}>}
   */
  async analyze(o) {
    const gaps = [], notes = [];
    const limits = { max_chunks: o.maxChunks, max_chunk_size: o.maxChunkSize, max_file_size: Math.max(o.maxTextKb * 1024, 8 * MB) };
    const summary = {
      engine: 'static rules (no LLM)', engine_version: null, rules_loaded: null, custom_rules_loaded: 0, custom_rules: null, limits,
      files_staged: this.stats.staged, files_excluded_tests_docs: this.stats.excluded, chunks_found: 0, chunks_scanned: 0, chunks_dropped_by_cap: 0,
      files_skipped_too_large: 0, findings: 0, dismissed_false_positive: 0, mitigated_by_data_flow: 0, left_to_secret_scanner: 0, rules_errored: 0,
      not_statically_decidable: [],
    };
    if (this.stats.unsafe_path) gaps.push(`SAST: ${this.stats.unsafe_path} source file(s) with an unsafe archive path were not analysed.`);
    if (this.stats.not_written) gaps.push(`SAST: ${this.stats.not_written} source file(s) could not be written for the analysis and were not analysed${this.failures.length ? ` (${this.failures.slice(0, 5).join('; ')}${this.stats.not_written > 5 ? '; …' : ''})` : ''}.`);
    if (!this.stats.staged) {
      notes.push('SAST (static rules, no LLM): the package has no source file in a language or format the engine reads, so nothing was analysed.');
      return { items: [], summary, gaps, notes };
    }

    const { analyzeSast } = await import('../../sast/src/analyzer/analyzeSast.js');
    const results = await analyzeSast(null, {
      noLlm: true, rulesDir: o.rulesDirs && o.rulesDirs.length ? o.rulesDirs : undefined, silent: true,
      workingDir: this.root, maxChunks: o.maxChunks, maxChunkSize: o.maxChunkSize, maxFileSize: limits.max_file_size,
      includeFolders: INCLUDE_FOLDERS, includeMinified: true, skipTests: false, verify: true, taintTrace: true,
    });
    const st = results.scan_stats || {}, cov = st.coverage || {}, pipe = st.pipeline || {};

    summary.engine_version = pipe.engine_version ?? null;
    summary.rules_loaded = pipe.rules_loaded ?? null;
    summary.custom_rules_loaded = pipe.custom_rules_loaded || 0;
    summary.custom_rules = pipe.custom_rules || null;
    summary.chunks_found = cov.chunks_found ?? results.length;
    summary.chunks_scanned = cov.chunks_scanned ?? results.length;
    summary.chunks_dropped_by_cap = cov.chunks_dropped_by_cap || 0;
    summary.files_skipped_too_large = (cov.files_skipped_too_large || []).length;
    summary.rules_errored = pipe.rules_errored || 0;
    summary.not_statically_decidable = pipe.classes_not_statically_decidable || [];

    const items = [];
    let chunkErrors = 0;
    for (const r of results) {
      if (r.error) chunkErrors++;
      const rel = path.relative(this.root, r.file).split(path.sep).join('/');
      const meta = this.staged.get(rel) || { label: rel, origin: 'app', context: '' };
      for (const f of r.findings || []) {
        if (!f || f._parse_error) continue;
        if (f.is_valid === false) { summary.dismissed_false_positive++; continue; }                       // the engine's own verification ruled it out
        if (SECRET_CLASS.test(String(f.vuln_class || ''))) { summary.left_to_secret_scanner++; continue; }
        if (f.taint && f.taint.exploitable === false) { summary.mitigated_by_data_flow++; continue; }      // a sanitiser is on every path to the sink
        items.push({ f, meta });
      }
    }
    summary.findings = items.length;

    if (cov.truncated) gaps.push(`SAST: ${summary.chunks_dropped_by_cap} code chunk(s) beyond --max-chunks ${o.maxChunks} were not analysed.`);
    if (summary.files_skipped_too_large) gaps.push(`SAST: ${summary.files_skipped_too_large} file(s) over ${limits.max_file_size} characters were not analysed.`);
    if (chunkErrors) gaps.push(`SAST: ${chunkErrors} code chunk(s) could not be analysed by the engine.`);
    if (summary.rules_errored) gaps.push(`SAST: ${summary.rules_errored} rule evaluation(s) failed${pipe.last_rule_error ? ` (last: ${pipe.last_rule_error})` : ''}; findings of those rules may be missing.`);
    if (o.rulesDirs && o.rulesDirs.length) {
      const cr = pipe.custom_rules;
      if (!cr || !cr.loaded) gaps.push(`SAST: no usable rule was loaded from --rules-dir ${o.rulesDirs.join(', ')}; only the built-in rules ran.`);
      else {
        if (cr.skipped) gaps.push(`SAST: ${cr.skipped} custom rule(s) were skipped and did not run (${(cr.skipped_rules || []).slice(0, 3).map(s => `${s.id}: ${s.reason}`).join('; ')}${cr.skipped > 3 ? '; …' : ''}).`);
        if ((cr.file_errors || []).length) gaps.push(`SAST: ${cr.file_errors.length} rule file(s) could not be read (${cr.file_errors.slice(0, 3).map(e => `${e.file}: ${e.reason}`).join('; ')}${cr.file_errors.length > 3 ? '; …' : ''}).`);
      }
    }
    if (st.coverage && cov.chunks_hard_split) notes.push(`SAST: ${cov.chunks_hard_split} over-long line(s) were split to honour --max-chunk-size ${o.maxChunkSize}.`);
    notes.push(`SAST (static rules, no LLM, engine ${summary.engine_version || '?'}): ${summary.chunks_scanned} code chunk(s) from ${summary.files_staged} file(s) analysed with ${summary.rules_loaded ?? '?'} rule(s)${summary.custom_rules_loaded ? ` (${summary.custom_rules_loaded} of them custom)` : ''}; ${summary.findings} finding(s)${summary.dismissed_false_positive || summary.mitigated_by_data_flow ? `, ${summary.dismissed_false_positive} dismissed as false positives and ${summary.mitigated_by_data_flow} judged mitigated by data-flow analysis (not listed)` : ''}${summary.left_to_secret_scanner ? `, ${summary.left_to_secret_scanner} hardcoded-secret match(es) not repeated (the secret scanner already reports them)` : ''}.`);
    if (this.stats.excluded) notes.push(`SAST: ${this.stats.excluded} test / documentation file(s) were not analysed (they do not run on a consumer's machine).`);
    notes.push('SAST: source files were written to a private temporary directory for the analysis and deleted afterwards; nothing was installed, built, imported or run.');
    return { items, summary, gaps, notes };
  }

  dispose() {
    process.removeListener('exit', this._onExit);
    if (!this.root) return;
    try { fs.rmSync(this.root, { recursive: true, force: true }); } catch { /* best effort: it is a private directory under the system temp folder */ }
    this.root = null;
  }
}

/** One engine finding → [rule id, fields for Findings.add]. The rule is registered in the shared rule table on first use. */
export function sastFinding({ f, meta }) {
  const id = `${SAST_RULE_PREFIX}${String(f.rule_id || 'finding').replace(/[^A-Za-z0-9._\-/]+/g, '-')}`;
  const severity = SEVERITIES.has(f.severity) ? f.severity : 'medium';
  const cwe = CWE_BY_CLASS.get(String(f.vuln_class || '').toLowerCase()) ?? null;
  const title = String(f.vuln_name || f.vuln_class || id).slice(0, 200);
  registerSastRule(id, { severity, title, cwe });
  const snippet = String(f.code_snippet || '').trim().slice(0, 300);
  return [id, {
    artifact: meta.label, line: Number.isInteger(f.line) && f.line > 0 ? f.line : undefined,
    key: `${id}|${meta.label}|${f.line}|${f.vuln_class}`,
    title, severity,
    description: `${String(f.description || title).trim().replace(/[.\s]+$/, '')}${f.line ? ` (line ${f.line})` : ''}.${meta.context || ''}`,
    evidence: snippet ? [snippet] : [],
    ...(f.fix ? { remediation: String(f.fix).slice(0, 600) } : {}),
    confidence: ['high', 'medium', 'low'].includes(f.confidence) ? f.confidence : 'medium',
    origin: meta.origin,
  }];
}
