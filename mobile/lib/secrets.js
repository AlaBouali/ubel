'use strict';
// secrets.js — runs UBEL's own secrets engine (sca/secrets.js, the Trivy-derived rule set) over text pulled
// out of an app package: DEX strings, static constants, string resources, plists, bundled text files,
// native-library strings. Every finding carries a redacted preview only.

import { scanText } from '../../sca/secrets.js';

const SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const CHUNK = 40000;

export class SecretScanner {
  /** @param {import('./findings.js').Findings} findings @param {object} base fields added to every finding (app) @param {object} [limits] */
  constructor(findings, base, { maxLines = 600000 } = {}) {
    this.findings = findings; this.base = base; this.maxLines = maxLines;
    this.sources = []; this.lineCount = 0; this.truncated = false;
  }

  /** @param {string} path artifact path  @param {string[]} lines  @param {(i:number)=>string|null} [where] extra location text per line */
  add(path, lines, where = null) {
    if (!lines.length) return;
    if (this.lineCount + lines.length > this.maxLines) {
      lines = lines.slice(0, Math.max(0, this.maxLines - this.lineCount));
      this.truncated = true;
    }
    this.lineCount += lines.length;
    this.sources.push({ path, lines, where });
  }

  run() {
    let found = 0;
    for (const src of this.sources) {
      // PEM blocks are matched by whole-text rules, so a source is scanned in a few large slices, never line by line.
      for (let off = 0; off < src.lines.length; off += CHUNK) {
        const slice = src.lines.slice(off, off + CHUNK);
        let hits;
        try { hits = scanText(slice, src.path); } catch { continue; }
        for (const h of hits) {
          const idx = off + h.line - 1;
          const where = src.where ? src.where(idx) : null;
          this.findings.add(`secret.${h.id}`, {
            ...this.base,
            title: `Hardcoded secret: ${h.title}`,
            severity: SEV[h.severity] || 'high',
            artifact: src.path,
            line: src.where ? undefined : idx + 1,
            description: `${h.title} found in ${src.path}${where ? ` (${where})` : ''}. It ships inside the package, so anyone with the app can extract it.`,
            evidence: [h.match_preview],
            key: h.fingerprint,
          });
          found++;
        }
      }
    }
    return found;
  }
}
