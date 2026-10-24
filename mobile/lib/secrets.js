'use strict';
// secrets.js — runs UBEL's own secrets engine (sca/secrets.js, the Trivy-derived rule set) over text pulled
// out of an app package: DEX strings, static constants, string resources, plists, bundled text files,
// native-library strings. Every finding carries a redacted preview only.

import { scanText } from '../../sca/secrets.js';

const SEV = { CRITICAL: 'critical', HIGH: 'high', MEDIUM: 'medium', LOW: 'low' };
const CHUNK = 40000;

// Mobile-specific calibration of the shared ruleset (sca/secrets.js is used by other UBEL modules and is left alone).
//  • Generic rules match on a name or on entropy, not on a vendor-specific format: they are heuristics, so confidence is low
//    (Findings lowers the severity one level for low confidence).
//  • A Google API key (AIza…) is the Firebase / Maps client key every app of that kind ships by design. It only becomes a real
//    credential when it is unrestricted or the project also enables a billable / data API such as Gemini, which a static scan cannot
//    see, so it is reported as medium with low confidence and a review hint rather than as a leaked secret.
const GENERIC = new Set(['generic-fallback', 'generic-key-value-credential']);
const CLIENT_KEY = {
  'google-api-key': 'This is a Google client API key, which Firebase and Maps apps embed by design. It is only a problem if the key is unrestricted (no package-name + signing-certificate restriction) or if its project enables a billable or data API such as Gemini or Cloud Vision: check the key restrictions in the Google Cloud console.',
};

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
            severity: CLIENT_KEY[h.id] ? 'medium' : (SEV[h.severity] || 'high'),
            confidence: CLIENT_KEY[h.id] || GENERIC.has(h.id) ? 'low' : 'high',
            confidenceCap: CLIENT_KEY[h.id] ? false : undefined,
            artifact: src.path,
            line: src.where ? undefined : idx + 1,
            description: `${h.title} found in ${src.path}${where ? ` (${where})` : ''}. It ships inside the package, so anyone with the app can extract it.${CLIENT_KEY[h.id] ? ` ${CLIENT_KEY[h.id]}` : ''}${GENERIC.has(h.id) ? ' This rule matches on a name or on entropy, so confirm that the value is a real credential.' : ''}`,
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
