'use strict';
import { atomicWriteFile } from '../../sca/report_naming.js';
import { getComplianceForCloudCheck } from '../../sca/compliance_mappings.js';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

// One identity for "the same resource", used by the findings and by the resources the checks inspected, so the two always line up.
const resourceKey = (r) => [r.provider ?? '', r.region ?? '', r.service ?? '', r.resource ?? ''].join('\u0000');

class Reporter {
  constructor() {
    this.findings = [];
    // Every resource a check looked at, whether or not it produced a finding. Without it a resource that was found clean would leave no
    // trace in the report, and only resources with a finding could ever be listed. key -> { provider, service, resource, region,
    // raised, assessed, reason }; `raised` counts every finding ever added for it (also those a --min-severity filter later drops).
    this.inspectedResources = new Map();
  }

  /**
   * Record that a check looked at one resource. Call it for every resource a check enumerates, at the point the check runs on it, and
   * again with `error` in the catch block of every call that was meant to assess it: a resource whose assessment failed is NOT clean, it
   * is unassessed, and the report says so.
   *
   * @param {object} r
   * @param {string} r.provider  'aws' | 'gcp' | 'azure'
   * @param {string} r.service   same value the resource's findings carry
   * @param {string} r.resource  same value the resource's findings carry (the finding's `resource`, verbatim)
   * @param {string} [r.region]  same value the resource's findings carry; '' for a resource without a region
   * @param {Error|string} [error]  an assessment of this resource that failed
   */
  inspected(r, error) {
    const key = resourceKey(r);
    let e = this.inspectedResources.get(key);
    if (!e) {
      e = { provider: r.provider, service: r.service, resource: r.resource, region: r.region ?? '', raised: 0, assessed: true, reason: null };
      this.inspectedResources.set(key, e);
    }
    if (error) {
      e.assessed = false;
      e.reason = e.reason || String(error?.message ?? error).slice(0, 300);
    }
    return e;
  }

  /** The inspected resources, each with how many findings are still in the report (`findings`) and how many were dropped by a filter. */
  resources() {
    const shown = new Map();
    for (const f of this.findings) {
      const k = resourceKey(f);
      shown.set(k, (shown.get(k) || 0) + 1);
    }
    return [...this.inspectedResources.entries()].map(([k, e]) => {
      const findings = shown.get(k) || 0;
      return {
        provider: e.provider, service: e.service, resource: e.resource, region: e.region,
        assessed: e.assessed, ...(e.reason ? { reason: e.reason } : {}),
        findings, hidden_findings: Math.max(0, e.raised - findings),
      };
    });
  }

  /**
   * @param {object} f
   * @param {string} f.provider   'aws' | 'gcp' | 'azure'
   * @param {string} f.service    e.g. 's3', 'compute', 'storage'
   * @param {string} f.check      short machine-readable rule id
   * @param {string} f.severity   'critical'|'high'|'medium'|'low'|'info'
   * @param {string} f.title
   * @param {string} f.resource   resource id/name/arn
   * @param {string} [f.region]
   * @param {string} f.description
   * @param {string} f.remediation
   * @param {string} [f.action]   machine-readable remediation code (shown in the finding detail view)
   */
  add(f) {
    const finding = {
      region: '',
      ...f,
      compliance: getComplianceForCloudCheck(f.check),
      timestamp: new Date().toISOString(),
    };
    this.findings.push(finding);
    // A finding is proof the resource was inspected (account-wide findings included, which no check enumerates).
    this.inspected(finding).raised++;
  }

  sorted() {
    return [...this.findings].sort(
      (a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9)
    );
  }

  toJSON() {
    return JSON.stringify(this.sorted(), null, 2);
  }

  writeJSON(path) {
    atomicWriteFile(path, this.toJSON());
  }

  printSummary() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of this.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

    console.log('\n=== Cloud Misconfiguration Scan Summary ===');
    console.log(`Total findings: ${this.findings.length}`);
    console.log(
      `  critical: ${counts.critical}  high: ${counts.high}  medium: ${counts.medium}  low: ${counts.low}  info: ${counts.info}`
    );
    console.log('');

    for (const f of this.sorted()) {
      console.log(`[${f.severity.toUpperCase()}] (${f.provider}/${f.service}) ${f.title}`);
      console.log(`  resource: ${f.resource}${f.region ? '  region: ' + f.region : ''}`);
      console.log(`  ${f.description}`);
      console.log(`  fix: ${f.remediation}`);
      console.log('');
    }
  }
}

export { Reporter };