'use strict';

// ─── user rules for the --no-llm engine:  --rules-dir <dir>[,<dir>…] ──────────────────────────────────────────
//
// Loads Semgrep-syntax rule files (*.yml / *.yaml with a top-level `rules:` list) and turns each rule into a rule object of the
// static engine, so it runs in the FIRST pass next to the built-in rules and flows through the same finding / report / SARIF /
// gate code. See semgrep.js for what the pattern language supports and what it does not.
//
// A rule that cannot be run faithfully (taint mode, typed metavariables, a language ubel-sast does not scan, a bad regex, …) is
// SKIPPED and listed with the reason, never run with a weaker meaning. Findings of a user rule carry rule_id `custom.<id>`, no taint
// verdict (a pattern match is not a data-flow proof) and `is_valid: true`; they gate under `--fail-on valid|any`.

import fs from 'fs';
import path from 'path';
import { parseYaml } from './yaml.js';
import { compileFormula, evaluate, makeScope, interpolate, RuleError } from './semgrep.js';

const MAX_FILES = 5000, MAX_FILE_BYTES = 1024 * 1024, MAX_DEPTH = 20, MAX_MATCHES_PER_RULE_CHUNK = 200;
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn']);

// Semgrep language names → the engine's families (see chunker/constants.js)
const ALL_FAMILIES = ['js', 'php', 'python', 'ruby', 'go', 'rust', 'java', 'kotlin', 'dart', 'swift', 'csharp', 'c', 'docker', 'iac', 'k8s', 'html'];
const LANG_FAMILY = {
  python: ['python'], python2: ['python'], python3: ['python'], py: ['python'],
  javascript: ['js'], js: ['js'], typescript: ['js'], ts: ['js'], jsx: ['js'], tsx: ['js'],
  php: ['php'], ruby: ['ruby'], rb: ['ruby'], go: ['go'], golang: ['go'], rust: ['rust'], java: ['java'], kotlin: ['kotlin'], kt: ['kotlin'],
  dart: ['dart'], swift: ['swift'], csharp: ['csharp'], 'c#': ['csharp'], cs: ['csharp'], c: ['c'], cpp: ['c'], 'c++': ['c'],
  html: ['html'], vue: ['html'],
  dockerfile: ['docker'], docker: ['docker'], terraform: ['iac'], tf: ['iac'], hcl: ['iac'],
  yaml: ['k8s', 'iac', 'docker'],
  generic: ALL_FAMILIES, regex: ALL_FAMILIES, none: ALL_FAMILIES,
};

const SEVERITY = { ERROR: 'high', WARNING: 'medium', INFO: 'low', INVENTORY: 'info', EXPERIMENT: 'info', CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const CONFIDENCE = { HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };

// ── files ──────────────────────────────────────────────────────────────────────────────────────────────────────
function collectFiles(target, out, errors, depth = 0) {
  let st;
  try { st = fs.lstatSync(target); } catch (e) { errors.push({ file: target, reason: `cannot read: ${e.code || e.message}` }); return; }
  if (st.isSymbolicLink()) return;                                  // never follow links out of the rules directory
  if (st.isDirectory()) {
    if (depth > MAX_DEPTH) return;
    let names = [];
    try { names = fs.readdirSync(target).sort(); } catch (e) { errors.push({ file: target, reason: `cannot list: ${e.code || e.message}` }); return; }
    for (const n of names) {
      if (SKIP_DIRS.has(n)) continue;
      collectFiles(path.join(target, n), out, errors, depth + 1);
      if (out.length >= MAX_FILES) return;
    }
  } else if (st.isFile() && /\.ya?ml$/i.test(target) && !/\.test\.ya?ml$/i.test(target)) out.push({ file: target, size: st.size });
}

// ── path filters (`paths: include / exclude`, gitignore-like globs relative to the scanned directory) ──────────
function globToRegex(g) {
  let s = String(g).trim().replace(/^\.\//, '');
  const anchored = s.startsWith('/'); if (anchored) s = s.slice(1);
  const dirOnly = s.endsWith('/'); if (dirOnly) s = s.slice(0, -1);
  const bare = !s.includes('/') && !anchored;                       // `tests` / `*.min.js`: matches a file or directory NAME anywhere
  let re = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (c === '*') {
      if (s[i + 1] === '*') { if (s[i + 2] === '/') { re += '(?:.*/)?'; i += 2; } else { re += '.*'; i += 1; } }
      else re += '[^/]*';
    } else if (c === '?') re += '[^/]';
    else re += c.replace(/[.+^${}()|[\]\\]/g, '\\$&');
  }
  return new RegExp(bare ? `(?:^|/)${re}(?:/|$)` : `^${re}(?:/|$)`);
}
function compilePaths(paths) {
  if (!paths) return null;
  if (typeof paths !== 'object' || Array.isArray(paths)) throw new RuleError('paths must be a mapping with include / exclude');
  const list = (v) => (v === undefined || v === null ? [] : [].concat(v).map(String));
  const inc = list(paths.include).map(globToRegex), exc = list(paths.exclude).map(globToRegex);
  return (rel) => (!inc.length || inc.some((r) => r.test(rel))) && !exc.some((r) => r.test(rel));
}

// `nosem` / `nosem: rule-id` comment on the first line of a match
const NOSEM = /(?:#|\/\/|\/\*|<!--|--|;)\s*nosem(?:grep)?\b(?:\s*:\s*([A-Za-z0-9_.\-,\s]+))?/;
function suppressed(raw, off, id) {
  const a = raw.lastIndexOf('\n', off - 1) + 1;
  let b = raw.indexOf('\n', off); if (b < 0) b = raw.length;
  const m = NOSEM.exec(raw.slice(a, b));
  if (!m) return false;
  if (!m[1]) return true;
  return m[1].split(',').map((x) => x.trim()).filter(Boolean).some((x) => x === id || id.endsWith('.' + x));
}

// ── one rule ───────────────────────────────────────────────────────────────────────────────────────────────────
function buildRule(r, file, root) {          // root: the scanned directory (path filters are relative to it)
  if (!r || typeof r !== 'object' || Array.isArray(r)) throw new RuleError('a rule must be a mapping');
  const id = r.id === undefined ? '' : String(r.id).trim();
  if (!id) throw new RuleError('missing id');
  if (!/^[A-Za-z0-9_.\-/]+$/.test(id)) throw new RuleError(`id "${id}" may only contain letters, digits, _ . - /`);
  if (r.mode !== undefined && r.mode !== 'search') throw new RuleError(`mode: ${r.mode} is not supported (only search mode)`);
  // `symbolic_propagation: true` makes patterns match through variable assignments, which this matcher does not do
  if (r.options && typeof r.options === 'object' && r.options.symbolic_propagation === true) throw new RuleError('option symbolic_propagation: true is not supported');

  const langs = [].concat(r.languages === undefined ? [] : r.languages).map((l) => String(l).toLowerCase().trim()).filter(Boolean);
  if (!langs.length) throw new RuleError('missing languages');
  const families = new Set(), unsupported = [];
  for (const l of langs) { if (LANG_FAMILY[l]) LANG_FAMILY[l].forEach((f) => families.add(f)); else unsupported.push(l); }
  if (!families.size) throw new RuleError(`language${unsupported.length > 1 ? 's' : ''} not scanned by ubel-sast: ${unsupported.join(', ')}`);

  const formula = compileFormula(r);
  const inPath = compilePaths(r.paths);
  const meta = r.metadata && typeof r.metadata === 'object' && !Array.isArray(r.metadata) ? r.metadata : {};
  const sevKey = String(r.severity === undefined ? 'WARNING' : r.severity).toUpperCase();
  if (!SEVERITY[sevKey]) throw new RuleError(`unknown severity "${r.severity}" (use ERROR / WARNING / INFO)`);
  const message = typeof r.message === 'string' && r.message.trim() ? r.message.trim().replace(/\s*\n\s*/g, ' ') : `Matched custom rule ${id}`;
  const fix = typeof r.fix === 'string' ? r.fix : null;
  const conf = CONFIDENCE[String(meta.confidence || '').toUpperCase()] || 'medium';
  const cwe = [].concat(meta.cwe === undefined ? [] : meta.cwe).map(String).filter(Boolean);
  const cls = typeof meta.vuln_class === 'string' && meta.vuln_class.trim() ? meta.vuln_class.trim() : `Custom rule: ${id}`;
  const ruleId = `custom.${id}`;

  return {
    rule: {
      kind: 'custom', id: ruleId, cls, title: id, sev: SEVERITY[sevKey], conf, langs: [...families],
      user: true, noTaint: true, source: path.relative(process.cwd(), file) || file,
      run(flow, emit) {
        const rel = path.relative(root, flow.chunk.file || '').split(path.sep).join('/');
        if (inPath && !inPath(rel)) return;
        const scope = flow._semScope || (flow._semScope = makeScope(flow.ctx.literal, flow.chunk.code));
        scope.steps = 0;
        const hits = evaluate(formula, scope);
        let n = 0;
        for (const h of hits) {
          if (suppressed(scope.raw, h.s, ruleId)) continue;
          const desc = interpolate(message, h.env, scope) + (cwe.length ? ` (${cwe.join(', ')})` : '');
          // the first line of the match is the evidence (the engine's logical-line view splits template markup at `{`)
          const a = scope.raw.lastIndexOf('\n', h.s - 1) + 1;
          let b = scope.raw.indexOf('\n', h.s); if (b < 0) b = scope.raw.length;
          const lineText = scope.raw.slice(a, b).trim().slice(0, 400);
          emit(h.s, { title: id, sev: SEVERITY[sevKey], conf, desc, fix: fix ? interpolate(fix, h.env, scope, 400) : (meta.fix || null),
            snippet: lineText, lineNeedle: lineText, relLine: flow.ctx.lineAt(h.s) });
          if (++n >= MAX_MATCHES_PER_RULE_CHUNK) break;
        }
      },
    },
    note: unsupported.length ? `ignored language(s) not scanned by ubel-sast: ${unsupported.join(', ')}` : null,
  };
}

/**
 * @param {string|string[]} dirs  rule directories (or single rule files)
 * @param {{ workingDir?: string, log?: Function }} o
 * @returns {{ rules: object[], skipped: {id,file,reason}[], errors: {file,reason}[], files: number, dirs: string[], notes: {id,note}[] }}
 */
export function loadCustomRules(dirs, { workingDir = process.cwd(), log = () => {} } = {}) {
  const list = [].concat(dirs).map(String).filter(Boolean);
  const out = { rules: [], skipped: [], errors: [], files: 0, dirs: list, notes: [] };
  const found = [];
  for (const d of list) {
    const abs = path.resolve(d);
    if (!fs.existsSync(abs)) throw new Error(`--rules-dir: "${d}" does not exist`);
    collectFiles(abs, found, out.errors);
  }
  const ids = new Map();
  for (const { file, size } of found) {
    const shown = path.relative(process.cwd(), file) || file;
    if (size > MAX_FILE_BYTES) { out.errors.push({ file: shown, reason: `larger than ${MAX_FILE_BYTES} bytes, not read` }); continue; }
    let doc;
    try { doc = parseYaml(fs.readFileSync(file, 'utf8'), file); }
    catch (e) { out.errors.push({ file: shown, reason: `YAML: ${e.message}` }); continue; }
    if (!doc || typeof doc !== 'object' || !Array.isArray(doc.rules)) continue;            // not a rule file (a test fixture, a config …)
    out.files++;
    for (const r of doc.rules) {
      const label = (r && r.id !== undefined ? String(r.id) : '(no id)');
      try {
        const { rule, note } = buildRule(r, file, path.resolve(workingDir));
        if (ids.has(rule.id)) { out.skipped.push({ id: label, file: shown, reason: `duplicate id (already defined in ${ids.get(rule.id)})` }); continue; }
        ids.set(rule.id, shown);
        out.rules.push(rule);
        if (note) out.notes.push({ id: label, note });
      } catch (e) {
        if (e instanceof RuleError || e.name === 'RuleError') out.skipped.push({ id: label, file: shown, reason: e.message });
        else out.skipped.push({ id: label, file: shown, reason: `internal error: ${e.message}` });
      }
    }
  }
  return out;
}

/** the report-safe summary of a load (no code, no absolute paths beyond what the user passed) */
export function summarizeCustomRules(loaded) {
  return {
    dirs: loaded.dirs,
    files: loaded.files,
    loaded: loaded.rules.length,
    skipped: loaded.skipped.length,
    skipped_rules: loaded.skipped.slice(0, 100),
    file_errors: loaded.errors.slice(0, 100),
    rules: loaded.rules.map((r) => ({ id: r.id, severity: r.sev, languages: r.langs, source: r.source })),
    notes: loaded.notes.slice(0, 100),
  };
}
