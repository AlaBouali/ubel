'use strict';
import crypto from 'crypto';
import { ruleMeta, SEVERITY_RANK, SEVERITIES, lowerSeverity } from './rules.js';

/** Masks a value for reports: never writes key material or secrets into an artifact. */
export function mask(value, keep = 3) {
  const s = String(value ?? '');
  if (s.length <= 8) return '***';
  return `${s.slice(0, keep)}…(${s.length} chars)`;
}

export class Findings {
  constructor() { this.list = []; this._seen = new Set(); }

  /**
   * @param {string} rule      id from rules.js (or secret.<id>)
   * @param {object} f
   * @param {string} f.artifact      file inside the package (e.g. "AndroidManifest.xml", "classes.dex")
   * @param {string} f.description   what was found, specific to this app
   * @param {string[]} [f.evidence]  short, already-masked items (classes, paths, URLs …)
   * @param {string} [f.severity]    overrides the catalog severity
   * @param {string} [f.title]       overrides the catalog title (secrets)
   * @param {string} [f.origin]      'app' | 'library' — library code is reported one level lower
   * @param {string} [f.confidence]  'high' | 'medium' | 'low'
   * @param {string} [f.app]         package / bundle id the finding belongs to
   */
  add(rule, f) {
    const meta = ruleMeta(rule);
    let severity = f.severity || meta.severity;
    if (f.origin === 'library') severity = lowerSeverity(severity);
    const evidence = (f.evidence || []).slice(0, 40);
    const fingerprint = crypto.createHash('sha256')
      .update([rule, f.app || '', f.artifact || '', f.key ?? evidence.join('|')].join('\0'))
      .digest('hex').slice(0, 16);
    if (this._seen.has(fingerprint)) return null;
    this._seen.add(fingerprint);
    const out = {
      rule,
      severity,
      title: f.title || meta.title,
      description: f.description,
      remediation: f.remediation || meta.remediation,
      masvs: meta.masvs,
      cwe: meta.cwe ? `CWE-${meta.cwe}` : null,
      artifact: f.artifact || '',
      ...(f.line ? { line: f.line } : {}),
      evidence,
      ...(f.evidence_total && f.evidence_total > evidence.length ? { evidence_total: f.evidence_total } : {}),
      confidence: f.confidence || 'high',
      origin: f.origin || 'app',
      ...(f.app ? { app: f.app } : {}),
      fingerprint,
    };
    this.list.push(out);
    return out;
  }

  sorted() {
    return [...this.list].sort((a, b) =>
      (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) ||
      a.rule.localeCompare(b.rule) || a.artifact.localeCompare(b.artifact));
  }

  counts() {
    const c = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
    for (const f of this.list) c[f.severity] = (c[f.severity] || 0) + 1;
    return c;
  }
}

/** Collects hits per rule, splitting app code from third-party library code, then emits one finding per rule. */
export class Aggregator {
  constructor(findings, base) { this.findings = findings; this.base = base; this.groups = new Map(); }
  hit(rule, { origin = 'app', evidence, description, severity, confidence }) {
    let g = this.groups.get(rule);
    if (!g) this.groups.set(rule, g = { app: new Set(), lib: new Set(), description, severity, confidence });
    (origin === 'library' ? g.lib : g.app).add(evidence);
    if (description && !g.description) g.description = description;
    if (severity) g.severity = severity;
  }
  flush(artifact) {
    for (const [rule, g] of this.groups) {
      const isApp = g.app.size > 0;
      const items = [...(isApp ? g.app : g.lib)];
      const extra = isApp && g.lib.size ? ` ${g.lib.size} further occurrence(s) are in third-party library code.` : '';
      const where = isApp ? '' : ' All occurrences are inside third-party library code (severity lowered one level).';
      this.findings.add(rule, {
        ...this.base, artifact,
        description: `${g.description || ''}${extra}${where}`.trim(),
        evidence: items.slice(0, 25), evidence_total: items.length,
        severity: g.severity, origin: isApp ? 'app' : 'library', confidence: g.confidence,
      });
    }
    this.groups.clear();
  }
}
