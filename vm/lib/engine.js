'use strict';
// engine.js — the rule runner and Reporter shared by ubel-vm and ubel-k8s.
//
// A *rule* is a declared check:
//   { id, area, severity, title, description, remediation, action?, cap?, evaluate(ctx) }
// evaluate() returns one of
//   [ {resource, scope?, detail?, severity?, title?, remediation?} … ]  the violations ([] = the rule passed)
//   na(reason)          the rule does not apply here (service not installed, live-only rule on an offline image …)
//   unassessed(reason)  the rule applies but could not be evaluated (permission denied, API call refused …)
// An exception thrown by evaluate() is treated as `unassessed`, never as a pass.
//
// Every rule ends up in report.checks[] with one of four outcomes — pass | fail | na | unassessed — so the
// report can say how much of the baseline was actually evaluated, instead of leaving "no findings" to be read
// as "clean".

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const na = (reason) => ({ __outcome: 'na', reason });
const unassessed = (reason) => ({ __outcome: 'unassessed', reason });

class Reporter {
  /** @param {{complianceFor:(checkId:string)=>object|null, frameworksFor?:(checkId:string)=>string[], categoriesFor?:(checkId:string)=>string[]}} deps */
  constructor(deps) {
    this.deps = deps;
    this.findings = [];
    this.checks = [];
    this._seen = new Set();
    this.suppressed = 0;
  }

  add(f) {
    const key = [f.check, f.resource, f.scope || ''].join('\u0001');
    if (this._seen.has(key)) return;
    this._seen.add(key);
    this.findings.push({
      scope: '',
      ...f,
      compliance: this.deps.complianceFor(f.check),
      timestamp: new Date().toISOString(),
    });
  }

  recordCheck(rule, status, extra = {}) {
    this.checks.push({
      check: rule.id,
      area: rule.area,
      severity: rule.severity,
      title: rule.title,
      status,
      findings: extra.findings || 0,
      ...(extra.reason ? { reason: extra.reason } : {}),
      ...(extra.suppressed ? { suppressed: extra.suppressed } : {}),
      frameworks: this.deps.frameworksFor ? this.deps.frameworksFor(rule.id) : [],
    });
  }

  sorted() {
    return [...this.findings].sort((a, b) =>
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
      String(a.area).localeCompare(String(b.area)) ||
      String(a.resource).localeCompare(String(b.resource)));
  }

  printSummary(title) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
    const c = { pass: 0, fail: 0, na: 0, unassessed: 0 };
    for (const k of this.checks) c[k.status]++;
    console.log(`\n=== ${title} ===`);
    console.log(`Checks evaluated: ${this.checks.length}  passed: ${c.pass}  failed: ${c.fail}  not applicable: ${c.na}  not assessed: ${c.unassessed}`);
    console.log(`Total findings: ${this.findings.length}`);
    console.log(`  critical: ${counts.critical}  high: ${counts.high}  medium: ${counts.medium}  low: ${counts.low}  info: ${counts.info}\n`);
    for (const f of this.sorted()) {
      console.log(`[${f.severity.toUpperCase()}] (${f.area}) ${f.title}`);
      console.log(`  resource: ${f.resource}${f.scope ? '  scope: ' + f.scope : ''}`);
      console.log(`  ${f.description}`);
      console.log(`  fix: ${f.remediation}\n`);
    }
    const un = this.checks.filter((k) => k.status === 'unassessed');
    if (un.length) {
      console.log('Not assessed:');
      for (const k of un) console.log(`  ${k.check}: ${k.reason}`);
      console.log('');
    }
  }
}

/** Does `rule` match one --only / --skip selector (a rule id, an area name, or an id/area prefix ending in "*")? */
function selectorMatches(sel, rule) {
  const s = String(sel).trim().toLowerCase();
  if (!s) return false;
  if (s.endsWith('*')) return rule.id.startsWith(s.slice(0, -1)) || String(rule.area).startsWith(s.slice(0, -1));
  return rule.id === s || String(rule.area).toLowerCase() === s;
}

/**
 * Runs `rules` against `ctx`, filling `reporter`. Never throws for a failing rule.
 * @param {{only?:string[], skip?:string[], log?:(m:string)=>void}} [opts]
 */
async function runRules(rules, ctx, reporter, opts = {}) {
  const { only = [], skip = [], log = () => {} } = opts;
  for (const rule of rules) {
    if (only.length && !only.some((s) => selectorMatches(s, rule))) continue;
    if (skip.some((s) => selectorMatches(s, rule))) continue;
    let out;
    try {
      out = await rule.evaluate(ctx);
    } catch (e) {
      const reason = e && e.code === 'EACCES' ? `${e.message} (run as root, or pass --allow-partial)` : `${e && e.message ? e.message : e}`;
      log(`  ${rule.id}: not assessed — ${reason}`);
      reporter.recordCheck(rule, 'unassessed', { reason });
      continue;
    }
    if (out && out.__outcome === 'na') { log(`  ${rule.id}: n/a — ${out.reason || ''}`); reporter.recordCheck(rule, 'na', { reason: out.reason }); continue; }
    if (out && out.__outcome === 'unassessed') { log(`  ${rule.id}: not assessed — ${out.reason || ''}`); reporter.recordCheck(rule, 'unassessed', { reason: out.reason }); continue; }
    const violations = Array.isArray(out) ? out : [];
    const cap = rule.cap || 100;
    const shown = violations.slice(0, cap);
    for (const v of shown) {
      const detail = v.detail ? ` ${v.detail}` : '';
      reporter.add({
        area: rule.area,
        check: rule.id,
        severity: v.severity || rule.severity,
        title: v.title || rule.title,
        resource: v.resource,
        scope: v.scope || '',
        description: `${typeof rule.description === 'function' ? rule.description(v) : rule.description}${detail}`.trim(),
        remediation: v.remediation || (typeof rule.remediation === 'function' ? rule.remediation(v) : rule.remediation),
        ...(rule.action ? { action: rule.action } : {}),
        ...(v.evidence ? { evidence: v.evidence } : {}),
        // an SCA vulnerability record travels unchanged with its finding type (sc_vuln / sc_infection): see scfinding.js
        ...(v.type ? { type: v.type } : {}),
        ...(v.vuln ? { vuln: v.vuln } : {}),
        ...(v.package ? { package: v.package } : {}),      // the package's SCA inventory item: moved into the report's inventory by buildReportPayload
      });
    }
    const suppressed = violations.length - shown.length;
    if (suppressed > 0) reporter.suppressed += suppressed;
    log(`  ${rule.id}: ${violations.length ? violations.length + ' finding(s)' : 'pass'}`);
    reporter.recordCheck(rule, violations.length ? 'fail' : 'pass', { findings: shown.length, suppressed });
  }
}

export { Reporter, runRules, na, unassessed, SEVERITY_RANK };
