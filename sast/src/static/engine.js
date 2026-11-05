'use strict';

// ─── ubel-sast --no-llm engine ────────────────────────────────────────────────
//
// Replaces the three LLM passes with deterministic ones that produce the SAME
// result records (same finding fields, is_valid, taint object), so reports,
// SARIF, the CI gate and --diff work unchanged:
//
//   Pass 1  scan    rules (rules/*.js) over each chunk: call rules (callee +
//                   argument analysis), pattern rules, config/structure rules.
//   Pass 2  verify  each candidate is re-checked against evidence that makes it
//                   a false alarm (placeholder secret, constant argument,
//                   non-security hash use, …). Dismissed ones stay in the report
//                   with is_valid:false and the reason.
//   Pass 3  taint   for classes that need attacker input: the value that reaches
//                   the sink is followed back to a source inside the function,
//                   or — when it is a parameter — through every call site up the
//                   call graph (FlowEngine.traceParam).
//
// Zero dependencies, no network, no child processes, no model.

import fs from 'fs';
import path from 'path';
import { FlowEngine, isCleared, isUsable } from './taint.js';
import { accessPaths, resolveFamily } from './context.js';
import { ALL_RULES } from './rules/index.js';
import { readFileText } from './filetext.js';

export const STATIC_ENGINE_VERSION = '1.0.0';

// ── lines ────────────────────────────────────────────────────────────────────
const fileCache = new Map();
function fileLines(file) {
  if (fileCache.has(file)) return fileCache.get(file);
  let lines = null;
  try { lines = fs.readFileSync(file, 'utf8').split(/\r?\n/); } catch { lines = null; }
  fileCache.set(file, lines);
  return lines;
}

/** Chunk-relative line → absolute file line, verified against the file text. */
function resolveLine(chunk, rel, snippet) {
  const start = chunk.startLine || 1;
  const guess = start + rel - 1;
  const lines = fileLines(chunk.file);
  const needle = (snippet || '').split('\n')[0].trim();
  if (!lines || !needle) return Math.min(Math.max(guess, start), chunk.endLine || guess);
  if (lines[guess - 1] && lines[guess - 1].includes(needle)) return guess;
  // chunks can be non-contiguous (module-level code with imports removed): search the whole file, nearest wins
  let best = null;
  for (let l = 1; l <= lines.length; l++) {
    if (lines[l - 1] && lines[l - 1].includes(needle)) {
      const inChunk = l >= start - 1 && l <= (chunk.endLine || l) + 2;
      const d = Math.abs(l - guess) + (inChunk ? 0 : 100000);
      if (best === null || d < best.d) best = { l, d };
    }
  }
  return best ? best.l : Math.min(Math.max(guess, start), chunk.endLine || guess);
}

// ── context gates ────────────────────────────────────────────────────────────
// Method names such as get/find/query/request exist everywhere; they only mean "database" or "GraphQL"
// when the surrounding file says so.
const SQL_FILE = /\b(?:sqlite3?|better-sqlite3|mysql2?|mariadb|pg|pg-promise|postgres(?:ql)?|psycopg2?|pymysql|MySQLdb|mysqlclient|sqlalchemy|django\.db|asyncpg|aiosqlite|pyodbc|cx_Oracle|oracledb|mssql|tedious|knex|sequelize|typeorm|prisma|slonik|kysely|drizzle|jdbc|java\.sql|JdbcTemplate|javax\.persistence|hibernate|mybatis|jooq|ActiveRecord|sequel|gorm|sqlx|database\/sql|pgx|diesel|rusqlite|tokio_postgres|SqlConnection|System\.Data|Dapper|EntityFramework|Npgsql|MySql|SQLite|sqflite|drift|FMDB|GRDB|CoreData|mysqli|PDO|wpdb|DB::|sqlite3_|libpq|mysql\.h|ODBC|SQLException|Statement|PreparedStatement|cursor\(\)|\.cursor|ApplicationRecord|ApplicationController|ActionController|ActiveRecord|ActiveModel|Eloquent|Illuminate|EntityManager|createNativeQuery|objects|Mongoid|exposed|room|SQLDelight|Doctrine|Propel|Medoo|CodeIgniter|Zend_Db|mysqli_\w+|mysql_\w+|pg_\w+|sqlite_\w+|sqlsrv_\w+|oci_\w+|odbc_\w+)\b/i;
const SQL_TEXT = /\b(?:select\s[\s\S]{0,200}\sfrom|insert\s+into|update\s+\w+\s+set|delete\s+from|create\s+table|drop\s+table|alter\s+table|union\s+select|order\s+by|group\s+by|where\s+\w+\s*(?:=|like|in)\b)/i;
const sqlContext = (flow, call) => SQL_FILE.test(readFileText(flow.chunk.file, flow.ctx.literal)) || call.args.some(a => SQL_TEXT.test(a.lit)) || SQL_TEXT.test(flow.ctx.literal);

// ── rule execution ───────────────────────────────────────────────────────────
const CONSTANT_WORDS = /^(?:true|false|null|None|nil|undefined|NULL|this|self)$/;
const isConstantName = (p) => CONSTANT_WORDS.test(p) || /^[A-Z][A-Z0-9_]{2,}$/.test(p);
export const hasDynamic = (text) => accessPaths(text).some(p => !isConstantName(p.path));

function stmtAround(flow, off) {
  const ll = flow.ctx.logical.find(l => off >= l.start && off < l.end) || null;
  if (ll) return { text: ll.lit.trim(), line: ll.line };
  return { text: flow.ctx.literal.slice(off, off + 200).split('\n')[0].trim(), line: flow.ctx.lineAt(off) };
}

function flowInfoFor(flow, arg, group, callLine, srcOnly = false) {
  const st = flow.stateOfArg(arg, callLine).filter(c => isUsable(c, group) && !(srcOnly && c.kind === 'param'));
  const src = st.find(c => c.kind === 'src');
  if (src) return { kind: 'src', origin: src.origin, contrib: src };
  const params = st.filter(c => c.kind === 'param');
  if (params.length) return { kind: 'param', params, contrib: params[0] };
  return null;
}

// A bare identifier that is only ever assigned string/number literals in this chunk is a constant.
function isLiteralVar(flow, text) {
  const t = text.trim().replace(/^[&*(]+|[)]+$/g, '');
  if (!/^[A-Za-z_$][\w$]*$/.test(t)) return false;
  let seen = 0;
  for (const ll of flow.ctx.logical) {
    const a = flow._parseAssignment(ll.text);
    if (!a || !a.lhs.includes(t)) continue;
    seen++;
    if (hasDynamic(a.rhs) || a.compound) return false;
  }
  return seen > 0 && !flow.params.has(t);
}

function runCallRule(rule, flow, out) {
  if (rule.fileGate && !rule.fileGate.test(readFileText(flow.chunk.file, flow.ctx.literal))) return;
  for (const call of flow.ctx.calls) {
    const target = rule.chain ? call.chain : call.callee;
    if (!rule.callee.test(target)) continue;
    if (rule.newOnly && !call.isNew) continue;
    if (rule.when && !rule.when(call, flow)) continue;
    if (rule.sqlGate && !sqlContext(flow, call)) continue;
    if (rule.unless && rule.unless.test(call.lit)) continue;
    const idxs = rule.argsFn ? rule.argsFn(call)
      : rule.args === undefined || rule.args === 'any' ? call.args.map((_, i) => i)
      : rule.args === 'last' ? [call.args.length - 1] : [].concat(rule.args);
    const need = rule.need || 'taint';
    if (need === 'always') {
      if (call.args.length === 0 && !rule.allowNoArgs) continue;
      out.push({ rule, off: call.start, call });
      continue;
    }
    for (const i of idxs) {
      const arg = call.args[i];
      if (!arg || arg.text === '') continue;
      if (rule.argUnless && rule.argUnless.test(arg.lit)) continue;
      if (need === 'dynamic') {
        if (!hasDynamic(arg.text) || isLiteralVar(flow, arg.text)) continue;
        out.push({ rule, off: call.start, call, arg, flowInfo: flowInfoFor(flow, arg, rule.group, call.line, rule.srcOnly) });
        break;
      }
      const info = flowInfoFor(flow, arg, rule.group, call.line, rule.srcOnly);
      if (!info) continue;
      out.push({ rule, off: call.start, call, arg, flowInfo: info });
      break;
    }
  }
}

function runAssignRule(rule, flow, out) {
  if (rule.fileGate && !rule.fileGate.test(readFileText(flow.chunk.file, flow.ctx.literal))) return;
  for (const ll of flow.ctx.logical) {
    const a = flow._parseAssignment(ll.text);
    if (!a || !rule.lhs.test(a.lhsText.replace(/\s+/g, ''))) continue;
    if (rule.argUnless && rule.argUnless.test(a.rhs)) continue;
    const litT = ll.lit.replace(/\s+$/, '');                       // rhs is trimmed; keep the literal view aligned (CRLF)
    const arg = { text: a.rhs, lit: litT.slice(litT.length - a.rhs.length) };
    const info = flowInfoFor(flow, arg, rule.group, ll.line, rule.srcOnly);
    if (!info) continue;
    out.push({ rule, off: ll.start, assign: { lhs: a.lhsText.replace(/\s+/g, '') }, arg, flowInfo: info });
  }
}

function runPatternRule(rule, flow, out) {
  if (rule.fileGate && !rule.fileGate.test(readFileText(flow.chunk.file, flow.ctx.literal))) return;
  const text = rule.view === 'code' ? flow.ctx.code : flow.ctx.literal;
  const re = new RegExp(rule.re.source, rule.re.flags.includes('g') ? rule.re.flags : rule.re.flags + 'g');
  let m, guard = 0;
  while ((m = re.exec(text)) !== null && guard++ < 500) {
    if (m[0] === '') { re.lastIndex++; continue; }
    // A match that starts inside a string/comment is documentation or data, not code, unless the rule is
    // about string content (header names, JSON keys, config values).
    if (!rule.inString && rule.view !== 'code' && flow.ctx.code[m.index] !== flow.ctx.literal[m.index]) continue;
    let extra = null;
    if (rule.check) { const r = rule.check(m, flow, text); if (r === false) continue; if (r && typeof r === 'object') extra = r; }
    out.push({ rule, off: m.index, match: m, extra });
  }
}

function runCustomRule(rule, flow, out) {
  if (rule.fileGate && !rule.fileGate.test(readFileText(flow.chunk.file, flow.ctx.literal))) return;
  rule.run(flow, (off, extra = {}) => out.push({ rule, off, extra, flowInfo: extra.flowInfo || null }));
}

// ── finding construction ─────────────────────────────────────────────────────
const SEV_ORDER = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

function describe(cand, flow) {
  const { rule, call, flowInfo, extra } = cand;
  if (extra?.desc) return extra.desc;
  const what = rule.what || rule.title;
  const callee = call ? call.callee : (cand.assign ? cand.assign.lhs : null);
  const sinkWord = cand.assign ? (n) => `${n}` : (n) => `${n}()`;
  if (flowInfo?.kind === 'src') return `Attacker-controlled input (${flowInfo.origin}) reaches ${sinkWord(callee)}, which ${what}. No sanitiser for this class of sink was found on the path.`;
  if (flowInfo?.kind === 'param') {
    const names = [...new Set(flowInfo.params.map(p => p.param))].map(n => `"${n}"`).join(', ');
    return `Parameter ${names} of ${flow.chunk.name || 'this function'}() reaches ${sinkWord(callee)}, which ${what}. Whether callers pass attacker-controlled data is resolved by the taint pass.`;
  }
  if (rule.desc) return typeof rule.desc === 'function' ? rule.desc(cand, flow) : rule.desc;
  return callee ? `${sinkWord(callee)} ${what}.` : String(rule.title);
}

function toFinding(cand, flow) {
  const { rule, extra } = cand;
  const stmt = stmtAround(flow, cand.off);
  const snippet = (extra?.snippet || stmt.text).slice(0, 400);
  const relLine = extra?.relLine || stmt.line;
  const line = resolveLine(flow.chunk, relLine, extra?.lineNeedle || snippet);
  let confidence = extra?.conf || rule.conf || 'medium';
  if (cand.flowInfo?.kind === 'src' && ['taint', 'dynamic', undefined].includes(rule.need)) confidence = rule.conf === 'low' ? 'medium' : 'high';
  if (cand.flowInfo?.kind === 'param') confidence = 'medium';
  const f = {
    vuln_name: extra?.title || rule.title || (cand.call ? `${rule.cls} via ${cand.call.callee}()` : rule.cls),
    vuln_class: rule.cls,
    description: describe(cand, flow),
    code_snippet: snippet,
    severity: extra?.sev || rule.sev,
    confidence,
    fix: extra?.fix || rule.fix || null,
    line,
    rule_id: rule.id,
    detection: 'static',
  };
  Object.defineProperty(f, '_cand', { value: cand, enumerable: false, writable: true });
  Object.defineProperty(f, '_flow', { value: flow, enumerable: false, writable: true });
  return f;
}

function dedupe(findings) {
  const best = new Map();
  for (const f of findings) {
    const key = `${f.vuln_class}|${f.line}`;
    const prev = best.get(key);
    if (!prev || (SEV_ORDER[f.severity] || 0) > (SEV_ORDER[prev.severity] || 0) ||
        ((SEV_ORDER[f.severity] || 0) === (SEV_ORDER[prev.severity] || 0) && f.rule_id < prev.rule_id)) best.set(key, f);
  }
  return [...best.values()].sort((a, b) => a.line - b.line);
}

// ── Pass 2: verification ─────────────────────────────────────────────────────
function verifyFinding(f) {
  const { rule } = f._cand;
  let verdict = { valid: true, reason: null };
  if (rule.verify) {
    try { verdict = rule.verify(f._cand, f._flow, f) || verdict; } catch { /* keep valid */ }
  }
  f.is_valid = verdict.valid;
  if (verdict.reason) f.verification_reason = verdict.reason;
  if (verdict.valid && verdict.conf) f.confidence = verdict.conf;
  if (verdict.valid && verdict.sev) f.severity = verdict.sev;
}

// ── Pass 3: taint ────────────────────────────────────────────────────────────
function taintFinding(f, fe) {
  const { rule, flowInfo, call, arg } = f._cand;
  const sink = call ? `${call.callee}()` : (f._cand.assign ? f._cand.assign.lhs : (rule.title || 'sink'));
  const snip = arg ? arg.text.replace(/\s+/g, ' ').slice(0, 60) : '';
  const base = { reachable: null, sanitized: false, bypassed: null, exploitable: null, flow_path: null, reasoning: '', error: null };

  if (!flowInfo) {
    // A pattern/config rule in a class that needs attacker input but has no call-site argument to follow.
    return { ...base, inconclusive_reason: 'static_input_flow_not_determined',
      reasoning: 'The construct is present, but the static engine could not tie it to a specific attacker-controlled value; review whether untrusted data can reach it.' };
  }
  if (flowInfo.kind === 'src') {
    return { ...base, reachable: true, exploitable: true,
      flow_path: `${flowInfo.origin} → ${snip || 'value'} → ${sink}`,
      reasoning: `${flowInfo.origin} is read in ${f._flow.chunk.name || 'this code'} and flows into ${sink} without a sanitiser that neutralises this class of sink.` };
  }
  // parameter: follow the callers
  const group = rule.group;
  const results = [];
  for (const p of flowInfo.params) results.push(fe.traceParam(f._flow.chunk, p.index, group));
  const hit = results.find(r => r.verdict === 'tainted');
  const where = f._flow.chunk.name || 'function';
  if (hit) {
    return { ...base, reachable: true, exploitable: true,
      flow_path: `${hit.origin} → ${hit.path.join(' → ')} → ${where}() → ${sink}`,
      reasoning: `A call chain was found where ${hit.origin} reaches parameter of ${where}() and from there ${sink}.` };
  }
  if (results.every(r => r.verdict === 'clean')) {
    return { ...base, reachable: true, exploitable: false,
      reasoning: `Every call site of ${where}() (${results[0].callers}) passes values that are not derived from request/user input.` };
  }
  const reason = results.find(r => r.verdict === 'unknown')?.reason || 'unknown';
  return { ...base, inconclusive_reason: reason === 'no_callers' ? 'orphan_no_callers' : `static_trace_${reason}`,
    reasoning: reason === 'no_callers'
      ? `${where}() has no callers in the scanned code, so whether its parameter is attacker-controlled cannot be determined from the code alone.`
      : `The static call-chain trace could not decide (${reason.replace(/_/g, ' ')}).` };
}

// ── driver ───────────────────────────────────────────────────────────────────
function rulesFor(family, classSet) {
  return ALL_RULES.filter(r => r.langs.includes(family) && (!classSet || classSet.has(r.cls.toLowerCase())));
}

/**
 * @param {object[]} toAnalyze     enriched chunks to scan
 * @param {object[]} contextChunks every chunk (call-graph context)
 * @param {object}   o             { vulnClasses, verify, taintTrace, log }
 * @returns {{ results: object[], pipeline: object }}
 */
export function runStaticAnalysis(toAnalyze, contextChunks, { vulnClasses, verify = true, taintTrace = true, log = () => {} } = {}) {
  const classSet = vulnClasses ? new Set(vulnClasses.map(v => String(v.name).toLowerCase())) : null;
  const needsInput = new Map();
  for (const v of vulnClasses || []) needsInput.set(String(v.name).toLowerCase().trim(), v.needsUserInput !== false);
  const requiresInput = (f) => (needsInput.has(f.vuln_class.toLowerCase()) ? needsInput.get(f.vuln_class.toLowerCase()) : true);

  const fe = new FlowEngine(contextChunks.filter(c => c.type !== 'imports' && resolveFamily(c)));
  const ruleCache = new Map();
  const results = [];
  const pipeline = { engine: 'static', engine_version: STATIC_ENGINE_VERSION, rules_loaded: ALL_RULES.length, rules_errored: 0, chunks_unsupported_language: 0 };
  let done = 0;
  const total = toAnalyze.length;

  const debug = !!process.env.UBEL_STATIC_DEBUG;
  for (const chunk of toAnalyze) {
    const t0 = debug ? Date.now() : 0;
    const family = resolveFamily(chunk);
    const rec = {
      id: chunk.id, file: chunk.file, type: chunk.type, class: chunk.class, name: chunk.name, language: chunk.language,
      startLine: chunk.startLine, endLine: chunk.endLine, findings: [], error: null,
    };
    let findings = [];
    if (!family) { pipeline.chunks_unsupported_language++; }
    else {
      if (!ruleCache.has(family)) ruleCache.set(family, rulesFor(family, classSet));
      let flow;
      try { flow = fe.flow(chunk); flow.absLine = (rel, needle) => resolveLine(chunk, rel, needle); }
      catch (e) { rec.error = { stage: 'scan', reason: 'static_analysis_failed', detail: `${e.message}` }; flow = null; }
      if (flow) {
        const cands = [];
        for (const rule of ruleCache.get(family)) {
          try {
            if (rule.kind === 'call') runCallRule(rule, flow, cands);
            else if (rule.kind === 'assign') runAssignRule(rule, flow, cands);
            else if (rule.kind === 'pattern') runPatternRule(rule, flow, cands);
            else runCustomRule(rule, flow, cands);
          } catch (e) { pipeline.rules_errored++; pipeline.last_rule_error = `${rule.id}: ${e.message}`; }
        }
        findings = dedupe(cands.map(c => toFinding(c, flow)));
        if (verify) findings.forEach(verifyFinding); else findings.forEach(f => { f.verification_skipped = true; });
        for (const f of findings) {
          if (verify && f.is_valid !== true) continue;
          const isParam = f._cand.flowInfo?.kind === 'param';
          const needsFlow = requiresInput(f) && !f._cand.rule.noTaint;
          if (!needsFlow) { f.taint_skipped = 'no_attacker_input_required'; continue; }
          // A flow through a parameter is only reported when the call graph proves untrusted data reaches it
          // (see taintFinding). Resolving it is cheap, so it is done even with --no-taint.
          if (!taintTrace && !isParam) continue;
          try { f.taint = taintFinding(f, fe); }
          catch (e) { f.taint = { reachable: null, sanitized: false, bypassed: null, exploitable: null, flow_path: null, reasoning: '', error: { stage: 'taint', reason: 'static_trace_failed', detail: e.message } }; }
        }
        // parameter-only flows that the callers do not confirm: not reported, but counted
        findings = findings.filter((f) => {
          if (f._cand.flowInfo?.kind !== 'param' || !f.taint) return true;
          if (f.taint.exploitable === true) return true;
          if (f.taint.exploitable === false) pipeline.param_flows_cleared = (pipeline.param_flows_cleared || 0) + 1;
          else pipeline.param_flows_unresolved = (pipeline.param_flows_unresolved || 0) + 1;
          return false;
        });
        if (!taintTrace) findings.forEach((f) => { delete f.taint; });
      }
    }
    rec.findings = findings;
    if (debug && Date.now() - t0 > 1000) log(`[static-debug] ${Date.now() - t0}ms  ${chunk.id}  (${chunk.code.length} chars)`);
    results.push(rec);
    done++;
    const flag = findings.length ? `⚠  ${findings.length} finding(s)` : '✓  clean';
    log(`  [${String(done).padStart(4)}/${total}] ${flag.padEnd(18)} ${String(chunk.id).slice(-60)}`);
  }
  return { results, pipeline };
}

export { resolveLine, path };
