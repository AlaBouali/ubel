'use strict';
import fs from 'fs';
import { getComplianceForCloudCheck } from '../../sca/compliance_mappings.js';

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

class Reporter {
  constructor() {
    this.findings = [];
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
   */
  add(f) {
    this.findings.push({
      region: '',
      ...f,
      compliance: getComplianceForCloudCheck(f.check),
      timestamp: new Date().toISOString(),
    });
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
    fs.writeFileSync(path, this.toJSON());
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
