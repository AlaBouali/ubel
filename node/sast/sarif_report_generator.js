// sast_sarif_builder.js — SARIF 2.1.0 generator for ubel-sast results
//
// Input:  the array written to sast_results.json by analyzeSast()
//         i.e. Array<{
//           id, file, type, class, name, language, startLine, endLine,
//           findings: Array<{
//             vuln_class, title, description, code_snippet,
//             confidence, severity, line,
//             is_valid, reason,
//             taint: { reachable, exploitable, sanitized, flow_path, rationale, error },
//             verification_error, _parse_error
//           }>
//         }>
//
// Output: SARIF 2.1.0 document (plain JS object — caller serialises to JSON)

import path   from 'path';
import crypto from 'crypto';
import { TOOL_NAME, TOOL_VERSION } from '../sca/info.js';
import { getGitMetadata }           from '../sca/git_info.js';
import { getOSMetadata }            from '../sca/os_metadata.js';

// ─── constants ────────────────────────────────────────────────────────────────

const SARIF_VERSION = '2.1.0';
const SARIF_SCHEMA  = 'https://json.schemastore.org/sarif-2.1.0.json';
const SAST_TOOL     = '@arcane-spark/ubel-sast';

// CWE integers per vuln_class name.
// Keys must match the canonical names in vulnCatalog.js DEFAULT_VULN_CLASSES exactly
// (after the CWE suffix has been stripped by the normalizer in main.js).
const VULN_CLASS_CWE = {
  // ── canonical names (vulnCatalog.js) ────────────────────────────────────
  'hardcoded secret or credential':                      [798],
  'SQL injection':                                       [89],
  'command injection':                                   [78],
  'path traversal':                                      [22],
  'unsafe deserialization':                              [502],
  'XSS / template injection':                            [79, 94],
  'open redirect':                                       [601],
  'XXE injection':                                       [611],
  'SSRF':                                                [918],
  'missing authentication check':                        [306],
  'broken access control / privilege escalation':        [269],
  'prototype pollution':                                 [1321],
  'code injection / dangerous eval':                     [95],
  'unsafe file upload':                                  [434],
  'sensitive data exposure / information disclosure':    [200],
  'cryptographic weakness':                              [327],
  'integer overflow / underflow':                        [190, 191],
  'null / nil dereference':                              [476],
  'use after free / memory safety':                      [416, 119],
  'buffer overflow / out-of-bounds access':              [120],
  'format string vulnerability':                         [134],
  'race condition / TOCTOU':                             [362],
  'insecure direct object reference (IDOR)':             [639],
  'HTTP header injection / response splitting':          [113],
  'regex denial of service (ReDoS)':                     [1333],
};

// ─── helpers ──────────────────────────────────────────────────────────────────

function truncate(text, max = 10000) {
  const s = String(text || '');
  return s.length <= max ? s : `${s.slice(0, max)}\n\n[truncated]`;
}

function severityToLevel(severity, exploitable) {
  if (exploitable === true) return 'error';
  const s = String(severity || '').trim().toLowerCase();
  if (s === 'critical' || s === 'high')       return 'error';
  if (s === 'medium'   || s === 'moderate')   return 'warning';
  if (s === 'low')                            return 'note';
  return 'warning'; // SAST default: most findings are worth surfacing
}

function normalizeUri(uri) {
  if (!uri) return null;
  // Collapse backslashes/duplicate slashes and drop a trailing slash — but
  // never collapse a lone "/" down to "", which used to make toFileUri('/')
  // (and anything chained off it, e.g. generate()'s baseUri) return
  // undefined and crash on cwd === '/' or any other path that normalizes to
  // the filesystem root.
  return String(uri).replace(/\\/g, '/').replace(/\/+/g, '/').replace(/(.)\/$/, '$1');
}

function toFileUri(p) {
  if (!p) return undefined;
  let n = normalizeUri(path.resolve(String(p)));
  if (!n.startsWith('/')) n = `/${n}`;
  return `file://${n}`;
}

function toRepoRelativeUri(rawPath) {
  if (!rawPath) return null;
  const normalized = normalizeUri(rawPath);
  const cwd        = normalizeUri(process.cwd());
  if (normalized.toLowerCase().startsWith(cwd.toLowerCase())) {
    const rel = normalized.slice(cwd.length).replace(/^\/+/, '');
    return rel || '.';
  }
  if (!/^[a-zA-Z]:\//.test(normalized) && !normalized.startsWith('/')) return normalized;
  return path.basename(normalized);
}

// Deterministic UUIDv5-like from SHA-1
function uuidFromString(input) {
  const h = crypto.createHash('sha1').update(String(input)).digest('hex');
  return [
    h.slice(0,  8),
    h.slice(8,  12),
    `5${h.slice(13, 16)}`,
    `${((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}`,
    h.slice(20, 32),
  ].join('-');
}

// Deterministic SHA-256 fingerprint (version nibble "8" to distinguish from rule IDs)
function sha256Fingerprint(key) {
  const h = crypto.createHash('sha256').update(String(key)).digest('hex');
  return [
    h.slice(0,  8),
    h.slice(8,  12),
    `8${h.slice(13, 16)}`,
    `${((parseInt(h.slice(16, 17), 16) & 0x3) | 0x8).toString(16)}${h.slice(17, 20)}`,
    h.slice(20, 32),
  ].join('-');
}

function toPascalCase(input) {
  return String(input || 'UnknownRule')
    .replace(/[^a-zA-Z0-9]+/g, ' ')
    .split(' ')
    .filter(Boolean)
    .map(p => p.charAt(0).toUpperCase() + p.slice(1).toLowerCase())
    .join('');
}

// Stable rule ID: deterministic from vuln_class name
function ruleIdForClass(vulnClass) {
  return uuidFromString(`sast:${String(vulnClass || 'unknown')}`);
}

// ─── SastSarifBuilder ─────────────────────────────────────────────────────────

export class SastSarifBuilder {
  /**
   * @param {object[]} results   — array from sast_results.json
   * @param {object}   [meta]    — optional { workingDir, model, provider, gitMetadata, osMetadata }
   */
  constructor(results, meta = {}) {
    this.results = Array.isArray(results) ? results : [];
    this.meta    = meta;

    // Lazy-built caches
    this._rulesMap     = null;
    this._allCwes      = null;
    this._taxonIndex   = null;
  }

  // ── Collect flat findings across all chunks ──────────────────────────────

  _allFindings() {
    const out = [];
    for (const chunk of this.results) {
      for (const f of (chunk.findings || [])) {
        if (f._parse_error) continue;
        // Normalise in-place so downstream code can always read vuln_class
        if (!f.vuln_class && f.vuln_name) {
          f.vuln_class = f.vuln_name.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
        } else if (f.vuln_class) {
          f.vuln_class = f.vuln_class.replace(/\s*\(CWE[^)]*\)\s*$/i, '').trim();
        }
        out.push({ chunk, finding: f });
      }
    }
    return out;
  }

  // ── CWE helpers ──────────────────────────────────────────────────────────

  _cwesForClass(vulnClass) {
    const key = String(vulnClass || '').toLowerCase().trim()
      // Strip any trailing " (CWE-NNN)" suffix that may have slipped through
      .replace(/\s*\(cwe-[\d\s/,]+\)\s*$/i, '').trim();
    for (const [k, cwes] of Object.entries(VULN_CLASS_CWE)) {
      if (k.toLowerCase() === key) return cwes;
    }
    return [];
  }

  _collectAllCwes() {
    if (this._allCwes) return this._allCwes;
    const s = new Set();
    for (const { finding } of this._allFindings()) {
      for (const c of this._cwesForClass(finding.vuln_class)) s.add(c);
    }
    this._allCwes = s;
    return s;
  }

  // ── Taxonomies ───────────────────────────────────────────────────────────

  buildTaxonomies() {
    const cwes = this._collectAllCwes();
    if (!cwes.size) return null;

    const taxa = [...cwes].sort((a, b) => a - b).map(n => ({
      id:      `CWE-${n}`,
      name:    `CWE-${n}`,
      helpUri: `https://cwe.mitre.org/data/definitions/${n}.html`,
    }));

    return [{
      name:            'CWE',
      version:         '4.16',
      releaseDateUtc:  '2024-03-25',
      informationUri:  'https://cwe.mitre.org',
      downloadUri:     'https://cwe.mitre.org/data/xml/cwec_latest.xml.zip',
      isComprehensive: false,
      taxa,
    }];
  }

  // ── Rules ────────────────────────────────────────────────────────────────

  buildRules() {
    if (this._rulesMap) return [...this._rulesMap.values()];

    const allCwes    = [...this._collectAllCwes()].sort((a, b) => a - b);
    const taxonIndex = new Map(allCwes.map((c, i) => [c, i]));
    this._taxonIndex = taxonIndex;

    const rulesMap = new Map();

    for (const { finding } of this._allFindings()) {
      const vc     = finding.vuln_class || 'unknown';
      const ruleId = ruleIdForClass(vc);
      if (rulesMap.has(ruleId)) continue;

      const cwes = this._cwesForClass(vc);
      const relationships = cwes.map(c => ({
        target: {
          id:            `CWE-${c}`,
          index:         taxonIndex.get(c) ?? 0,
          toolComponent: { name: 'CWE', index: 0 },
        },
        kinds: ['relevant'],
      }));

      const rule = {
        id:   ruleId,
        name: toPascalCase(vc),

        shortDescription: {
          text: truncate(vc, 300),
        },

        fullDescription: {
          text: truncate(
            finding.description ||
            finding.title ||
            vc,
            10000
          ),
        },

        help: {
          text: [
            `Vulnerability class: ${vc}`,
            cwes.length ? `CWE: ${cwes.map(c => `CWE-${c}`).join(', ')}` : '',
            '',
            'Review all findings of this class and verify each one with the full context',
            'preserved in the sast_results.json report.',
          ].filter(l => l !== undefined).join('\n').trim(),
        },

        helpUri: cwes.length
          ? `https://cwe.mitre.org/data/definitions/${cwes[0]}.html`
          : 'https://owasp.org/www-project-top-ten/',

        properties: {
          vuln_class: vc,
          cwes,
          tags: ['security', 'sast', 'ubel'],
        },
      };

      if (relationships.length) rule.relationships = relationships;
      rulesMap.set(ruleId, rule);
    }

    this._rulesMap = rulesMap;
    return [...rulesMap.values()];
  }

  // ── Results ──────────────────────────────────────────────────────────────

  buildResults() {
    const rules        = this.buildRules();
    const ruleIndexMap = new Map(rules.map((r, i) => [r.id, i]));
    const out          = [];

    for (const { chunk, finding } of this._allFindings()) {
      const ruleId    = ruleIdForClass(finding.vuln_class);
      const exploitable = finding.taint?.exploitable;
      const isValid     = finding.is_valid;

      // Level: confirmed exploitable → error; confirmed false positive → none;
      // verified real but not yet traced → warning; unverified → note
      let level;
      if (exploitable === true)  level = 'error';
      else if (isValid === false) level = 'none';
      else                        level = severityToLevel(finding.severity, false);

      // Physical location — repo-relative file + line
      const relUri    = toRepoRelativeUri(chunk.file) || '.';
      const startLine = Math.max(1, parseInt(finding.line || chunk.startLine || 1, 10));

      const location = {
        physicalLocation: {
          artifactLocation: {
            uri:       relUri,
            uriBaseId: '%SRCROOT%',
          },
          region: {
            startLine,
            startColumn: 1,
          },
        },
        logicalLocations: [{
          name:             chunk.name,
          kind:             chunk.type === 'method' ? 'member' : 'function',
          fullyQualifiedName: chunk.class
            ? `${chunk.class}.${chunk.name}`
            : chunk.name,
          decoratedName: `${chunk.file}::${chunk.class ? chunk.class + '.' : ''}${chunk.name}`,
        }],
      };

      // Message text — title + description + taint rationale
      const msgParts = [
        finding.title       || finding.vuln_class,
        finding.description ? `\n${finding.description}` : '',
      ];
      if (finding.taint?.rationale) {
        msgParts.push(`\nTaint: ${finding.taint.rationale}`);
      }
      if (finding.taint?.flow_path) {
        msgParts.push(`Flow: ${finding.taint.flow_path}`);
      }

      // Fingerprint: stable across re-runs for the same finding in the same file
      const fingerprintKey = [
        chunk.file,
        chunk.name,
        finding.vuln_class,
        startLine,
      ].join(':');

      const result = {
        ruleId,
        ruleIndex: ruleIndexMap.get(ruleId),
        level,
        message:  { text: truncate(msgParts.join(' ').trim(), 2000) },
        locations: [location],

        partialFingerprints: {
          chunkId:   chunk.id,
          vulnClass: finding.vuln_class || '',
          fileLine:  `${relUri}:${startLine}`,
        },

        fingerprints: {
          primary: sha256Fingerprint(fingerprintKey),
        },

        properties: {
          // Chunk metadata (inventory)
          chunk_id:    chunk.id,
          chunk_type:  chunk.type,
          chunk_class: chunk.class  || null,
          chunk_name:  chunk.name,
          language:    chunk.language,
          file:        chunk.file,
          start_line:  chunk.startLine,
          end_line:    chunk.endLine,

          // Finding fields
          vuln_class:      finding.vuln_class  || null,
          title:           finding.title       || null,
          description:     finding.description || null,
          code_snippet:    finding.code_snippet || null,
          confidence:      finding.confidence  || null,
          severity:        finding.severity    || null,
          line:            finding.line        || null,

          // Verification pass
          is_valid:             isValid    ?? null,
          verification_reason:  finding.reason || null,
          verification_error:   finding.verification_error || null,

          // Taint trace pass
          taint: finding.taint ? {
            reachable:   finding.taint.reachable   ?? null,
            exploitable: finding.taint.exploitable ?? null,
            sanitized:   finding.taint.sanitized   ?? null,
            flow_path:   finding.taint.flow_path   || null,
            rationale:   finding.taint.rationale   || null,
            error:       finding.taint.error        || null,
          } : null,
        },
      };

      // Code flows — surfaced when the taint trace produced a flow_path
      if (finding.taint?.flow_path) {
        result.codeFlows = [{
          message: { text: 'Taint flow' },
          threadFlows: [{
            locations: [{
              location: {
                physicalLocation: {
                  artifactLocation: { uri: relUri, uriBaseId: '%SRCROOT%' },
                  region: { startLine, startColumn: 1 },
                },
                message: { text: finding.taint.flow_path },
              },
            }],
          }],
        }];
      }

      // Suppression hint for confirmed false positives
      if (isValid === false) {
        result.suppressions = [{
          kind:            'inSource',
          justification:   finding.reason || 'LLM verification pass determined this is a false positive.',
          location:        { physicalLocation: location.physicalLocation },
        }];
      }

      out.push(result);
    }

    return out;
  }

  // ── Tool ─────────────────────────────────────────────────────────────────

  buildTool() {
    const driver = {
      name:             SAST_TOOL,
      fullName:         `${SAST_TOOL} v${TOOL_VERSION} (via ${TOOL_NAME})`,
      version:          TOOL_VERSION,
      semanticVersion:  TOOL_VERSION,
      informationUri:   'https://github.com/AlaBouali/ubel',
      rules:            this.buildRules(),
    };

    if (this._collectAllCwes().size) {
      driver.supportedTaxonomies = [{ name: 'CWE', index: 0 }];
    }

    return { driver };
  }

  // ── Invocations ──────────────────────────────────────────────────────────

  buildInvocations() {
    const m = this.meta;

    // Aggregate stats
    const allPairs      = this._allFindings();
    const totalFindings = allPairs.length;
    const valid         = allPairs.filter(p => p.finding.is_valid === true).length;
    const invalid       = allPairs.filter(p => p.finding.is_valid === false).length;
    const exploitable   = allPairs.filter(p => p.finding.taint?.exploitable === true).length;
    const highConf      = allPairs.filter(p => p.finding.confidence === 'high').length;
    const medConf       = allPairs.filter(p => p.finding.confidence === 'medium').length;
    const parseErrors   = this.results.reduce((n, r) =>
      n + (r.findings || []).filter(f => f._parse_error).length, 0);

    return [{
      executionSuccessful: true,
      properties: {
        tool:                 SAST_TOOL,
        tool_version:         TOOL_VERSION,
        provider:             m.provider    || null,
        model:                m.model       || null,
        working_dir:          m.workingDir  || process.cwd(),
        runtime_version:      process.version,
        platform:             process.platform,
        arch:                 process.arch,
        git_branch:           m.gitMetadata?.branch        || null,
        git_commit:           m.gitMetadata?.latest_commit || null,
        git_url:              m.gitMetadata?.url           || null,
        chunks_analyzed:      this.results.length,
        total_findings:       totalFindings,
        verified_valid:       valid,
        verified_invalid:     invalid,
        exploitable_findings: exploitable,
        high_confidence:      highConf,
        medium_confidence:    medConf,
        parse_errors:         parseErrors,
      },
    }];
  }

  // ── Version control provenance ───────────────────────────────────────────

  buildVersionControlProvenance() {
    const git      = this.meta.gitMetadata || {};
    const repoUri  = git.url && git.url !== ''
      ? git.url
      : toFileUri(this.meta.workingDir || process.cwd());

    return [{
      repositoryUri: repoUri,
      revisionId:    git.latest_commit || uuidFromString(repoUri),
      branch:        git.branch || 'unknown',
      mappedTo:      { uriBaseId: '%SRCROOT%' },
    }];
  }

  // ── Artifacts ────────────────────────────────────────────────────────────

  buildArtifacts() {
    const seen = new Set();
    for (const chunk of this.results) {
      const rel = toRepoRelativeUri(chunk.file);
      if (rel && rel !== '.') seen.add(rel);
    }
    return [...seen].map(uri => ({
      location: { uri, uriBaseId: '%SRCROOT%' },
    }));
  }

  // ── Generate ─────────────────────────────────────────────────────────────

  generate() {
    const cwd     = normalizeUri(process.cwd());
    let baseUri   = toFileUri(cwd);
    if (!baseUri.endsWith('/')) baseUri += '/';

    const taxonomies = this.buildTaxonomies();

    const run = {
      tool:                     this.buildTool(),
      automationDetails:        { id: 'ubel-sast' },
      originalUriBaseIds:       { '%SRCROOT%': { uri: baseUri } },
      versionControlProvenance: this.buildVersionControlProvenance(),
      invocations:              this.buildInvocations(),
      results:                  this.buildResults(),
      artifacts:                this.buildArtifacts(),
      properties: {
        generated_at:    new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
        scan_type:       'sast',
        tool:            SAST_TOOL,
        tool_version:    TOOL_VERSION,
        provider:        this.meta.provider   || null,
        model:           this.meta.model      || null,
        working_dir:     this.meta.workingDir || null,
      },
    };

    if (taxonomies) run.taxonomies = taxonomies;

    return {
      $schema: SARIF_SCHEMA,
      version: SARIF_VERSION,
      runs:    [run],
    };
  }
}