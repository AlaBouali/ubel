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
   * @param {string} [f.origin]      'app' | 'library' | 'unknown' — only 'library' is reported one level lower; 'unknown' (renamed classes
   *                                  outside the app namespace) keeps the full severity so obfuscation cannot hide a finding
   * @param {string} [f.confidence]  'high' | 'medium' | 'low' — 'low' lowers the severity one level (floor: low), except for origin 'unknown'
   * @param {boolean} [f.confidenceCap] set to false to keep the severity of a low-confidence finding
   * @param {string} [f.app]         package / bundle id the finding belongs to
   */
  add(rule, f) {
    const meta = ruleMeta(rule);
    let severity = f.severity || meta.severity;
    let description = f.description;
    if (f.origin === 'library') severity = lowerSeverity(severity);
    // Severity must not outrun the evidence: a low-confidence heuristic (a name match, an import that libraries also reference, a
    // string that merely exists in the binary) is reported one level lower, never below 'low'. Renamed ('unknown') code is exempt so
    // obfuscation cannot be used to push a finding down the list.
    if (f.confidence === 'low' && f.origin !== 'unknown' && f.confidenceCap !== false && SEVERITY_RANK[severity] < SEVERITY_RANK.low) {
      const lowered = lowerSeverity(severity);
      if (lowered !== severity) {
        severity = lowered;
        description = `${description || ''} Severity is one level lower than the rule's default because this is a low-confidence heuristic.`.trim();
      }
    }
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
      description,
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

/** Collects hits per rule, splitting app code from unattributable (renamed) code and third-party library code, then emits one finding per rule. */
export class Aggregator {
  constructor(findings, base) { this.findings = findings; this.base = base; this.groups = new Map(); }
  hit(rule, { origin = 'app', evidence, description, severity, confidence }) {
    let g = this.groups.get(rule);
    if (!g) this.groups.set(rule, g = { app: new Set(), unk: new Set(), lib: new Set(), conf: {}, description, severity, confidence });
    const bucket = origin === 'library' ? 'lib' : origin === 'unknown' ? 'unk' : 'app';
    g[bucket].add(evidence);
    (g.desc ||= {})[bucket] ||= description;      // the description must match the bucket that is finally emitted
    // Keep the strongest confidence seen for each bucket, so one weak hit cannot mask a strong one.
    const rank = { high: 3, medium: 2, low: 1 };
    if (confidence && (rank[confidence] || 0) > (rank[g.conf[bucket]] || 0)) g.conf[bucket] = confidence;
    if (description && !g.description) g.description = description;
    if (severity) g.severity = severity;
  }
  flush(artifact) {
    for (const [rule, g] of this.groups) {
      // The most specific attribution wins: app code, else code we cannot attribute, else known library code.
      const origin = g.app.size ? 'app' : g.unk.size ? 'unknown' : 'library';
      const items = [...(origin === 'app' ? g.app : origin === 'unknown' ? g.unk : g.lib)];
      const others = [];
      if (origin === 'app' && g.unk.size) others.push(`${g.unk.size} further occurrence(s) are in renamed (obfuscated) classes that could not be attributed to the app or a library`);
      if (origin !== 'library' && g.lib.size) others.push(`${g.lib.size} further occurrence(s) are in third-party library code`);
      const extra = others.length ? ` ${others.join('; ')}.` : '';
      const where = origin === 'unknown' ? ' All occurrences are in renamed (obfuscated) classes outside the app package; they are most likely third-party library code but this could not be confirmed, so the severity is not lowered.'
        : origin === 'library' ? ' All occurrences are inside third-party library code (severity lowered one level).' : '';
      this.findings.add(rule, {
        ...this.base, artifact,
        description: `${(g.desc && g.desc[origin === 'library' ? 'lib' : origin === 'unknown' ? 'unk' : 'app']) || g.description || ''}${extra}${where}`.trim(),
        evidence: items.slice(0, 25), evidence_total: items.length,
        severity: g.severity, origin, confidence: g.conf[origin === 'library' ? 'lib' : origin === 'unknown' ? 'unk' : 'app'] || g.confidence,
      });
    }
    this.groups.clear();
  }
}
