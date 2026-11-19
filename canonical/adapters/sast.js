'use strict';
// SAST (ubel-sast analyze) and malware (ubel-mal) → canonical.
// Original keys used: meta{…}, results[] (one per code chunk; findings[] inside), executive_summary, diffs.
//
// rule_id:    static engine  → the finding's own rule_id (e.g. "sqli-js")
//             LLM engine     → a rule derived from the vulnerability class   ("llm.<class-slug>")
//             malware        → a rule derived from the malware class         ("mal.<class-slug>")
// finding_id: sha256(chunk_id + rule_id [+ fingerprint for secrets])  — the only family that has one.
// component:  id = chunk id (relative path); name = "<file name>: (<class>.)<function>".
import path from 'node:path';
import { arr, first, mkFinding, mkInventory, makeRel, sha, slug, uniq } from '../common.js';

export const family = 'sast';

const MAL_RE = /malware|malicious/i;

// The same rule id for the same class, every run (so a finding is stable across reports).
export function llmRuleId(vulnClass, malware) {
  return `${malware ? 'mal' : 'llm'}.${slug(vulnClass || 'unclassified')}`;
}

function chunkParts(r, R) {
  const file = R.rel(r.file || '');
  const idRaw = String(r.id ?? '');
  const part = idRaw.match(/#part(\d+)$/);
  const base = idRaw.replace(/#part\d+$/, '');
  const abs = String(r.file || '');
  // relative chunk id: swap the (absolute) file prefix for the relative one
  const cid = (abs && base.startsWith(abs) ? file + base.slice(abs.length) : R.text(base)) + (part ? `#part${part[1]}` : '');
  const fn = r.name || (base.split(':').pop() ?? '');
  const label = `${path.basename(file || abs) || file}: ${r.class ? `${r.class}.` : ''}${fn}${part ? ` (part ${part[1]})` : ''}`;
  return { cid, label, file };
}

function gate(failOn, malware) {
  const f = String(failOn || 'any');
  return (x) => {
    if (malware) { if (f === 'confirmed') return x.is_valid === true; return true; }
    const exploitable = x.taint?.exploitable === true;
    if (f === 'exploitable') return exploitable;
    if (f === 'valid') return x.is_valid === true || exploitable;
    return x.is_valid !== false;
  };
}

export function translate(p, opts, H) {
  const m = p.meta || {};
  const malware = MAL_RE.test(String(m.scan_type || '')) || MAL_RE.test(String(m.scan_options?.mode || ''));
  const R = makeRel(first(m.workingDir, opts.cwd));
  const violates = gate(m.scan_options?.fail_on, malware);
  const out = { findings: [], inventory: [], scopes: [] };
  const files = new Map();

  for (const r of arr(p.results)) {
    const { cid, label, file } = chunkParts(r, R);
    const fl = arr(r.findings).filter((x) => x && !x._parse_error);
    if (file) {
      if (!files.has(file)) files.set(file, { type: 'file', name: file, path: file, language: r.language ?? null, chunks: 0, findings: 0 });
      const e = files.get(file); e.chunks++; e.findings += fl.length;
    }
    for (const f of fl) {
      // static engine findings carry their own rule_id; LLM findings get a derived one
      const ruleId = f.rule_id || llmRuleId(f.vuln_class || f.vuln_name, malware);
      const isSecret = /secret|credential/i.test(`${f.vuln_class || ''} ${ruleId}`);
      // secrets also hash a fingerprint (the original has none: derive it from line + snippet, never storing the secret)
      const fp = isSecret ? first(f.fingerprint, sha(f.line, f.code_snippet)) : '';
      out.findings.push(mkFinding({
        finding_id: sha(cid, ruleId, fp),
        rule_id: ruleId,
        title: first(f.vuln_name, f.vuln_class, ruleId),
        component_id: cid,
        component_name: label,
        component_type: 'code',
        severity: f.severity,
        confidence: f.confidence,
        violate_policy: violates(f),
        type: isSecret ? 'secret' : 'code',
        details: R.deep({ ...f, file, chunk_id: cid, chunk_type: r.type, startLine: r.startLine, endLine: r.endLine, language: r.language, scan_mode: malware ? 'malware' : 'analyze' }),
      }));
    }
    const { findings: _drop, ...chunk } = r;
    const status = r.error ? 'error' : (fl.length ? (fl.some((x) => x.is_valid === false) && fl.every((x) => x.is_valid === false) ? 'dismissed' : 'vulnerable') : 'clean');
    out.inventory.push(mkInventory({
      component_id: cid, component_name: label, status,
      violate_policy: fl.length ? fl.some((x) => violates(x)) : false,
      type: 'code',
      details: R.deep({ ...chunk, findings_count: fl.length }),
    }));
  }

  out.scopes.push({ type: 'filesystem', name: '.', path: '.', include_folders: m.scan_options?.include_folders ?? null, skip_folders: m.scan_options?.skip_folders ?? null, languages: m.scan_options?.languages ?? null });
  out.scopes.push(...files.values());

  const langs = uniq(arr(p.results).map((r) => r.language));
  const cov = m.scan_options || {};
  const partial = !!(cov.chunks_dropped_by_cap || cov.chunks_partial_output || arr(cov.files_skipped_too_large).length);
  const meta = H.buildMetadata({
    payload: p, opts, os_meta: m.osMetadata, git: m.gitMetadata,
    runtime: { arch: m.arch, node_version: m.runtime_version },
    scan: {
      generated_at: m.generated_at || p.generated_at, status: partial ? 'partial' : 'completed',
      scan_type: malware ? 'malware' : (m.scan_type || 'analyze'), scan_scope: 'codebase', ecosystems: langs, vulnerability_scan: true,
      report_id: m.report_id, asset_id: m.asset_id, asset_name: m.asset_name, asset_type: m.asset_type, machine_id: m.machine_id, tool_version: m.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { flags: m.scan_options ?? {}, engine: { provider: m.provider ?? null, model: m.model ?? null }, gate: { fail_on: m.scan_options?.fail_on ?? 'any' } },
    ...out,
    stats_extra: { source: m.scan_stats ?? null, diffs: p.diffs ?? null },
    compliance_summary: m.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
