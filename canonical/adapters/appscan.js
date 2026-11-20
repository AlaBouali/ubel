'use strict';
// App-scanner family → canonical: ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server.
// They all share one payload (mobile/lib/report.js buildPayload; mcp/lib/report.js reuses it).
// Original keys used: schema, tool, target, apps[], vulnerabilities[], secrets[], misconfigurations[], dependencies[]
// (each with vulnerabilities[]), gate, min_severity, analysis, summary, stats, compliance_summary, executive_summary, diffs.
import { arr, isObj, first, mkFinding, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, failOnPredicate } from '../common.js';

export const family = 'appscan';

const HARDENING = /(^|[._-])(pie|relro|canary|fortify|nx|exec[_-]?stack|textrel|rpath|wx|stripped|hardening|bitcode|arc|stack[_-]?protector|no[_-]?gnu[_-]?stack)([._-]|$)/i;
const BEHAVIOUR = /behavio|intent|exfil|beacon|c2\b|dynamic[_-]?load|obfusc|persist|anti[_-]?(debug|analysis)|self[_-]?modif/i;

export function translate(p, opts, H) {
  const R = makeRel(opts.cwd);
  const gate = p.gate || {};
  const violates = failOnPredicate(first(gate.fail_on, null));
  const apps = arr(p.apps);
  const out = { findings: [], inventory: [], scopes: [] };

  const appId = (a) => first(a.id, a.key, a.package, a.bundle_id, a.name);
  const appFor = (ref) => apps.find((a) => [a.id, a.key, a.name, a.package, a.bundle_id].includes(ref)) || null;

  const push = (f, type) => {
    const a = appFor(f.app);
    const cid = a ? appId(a) : first(f.app, f.artifact);
    const name = a ? first(a.name, a.id) : first(f.app, f.artifact);
    out.findings.push(mkFinding({
      rule_id: f.rule,
      title: f.title,
      component_id: cid == null ? null : R.rel(String(cid)),
      component_name: name == null ? null : R.text(String(name)),
      component_type: 'application',
      severity: f.severity,
      confidence: f.confidence,
      violate_policy: violates(f.severity),
      type,
      details: R.deep(f),
    }));
  };
  for (const f of arr(p.vulnerabilities)) push(f, BEHAVIOUR.test(f.rule || '') ? 'behaviour' : 'code');
  for (const f of arr(p.secrets)) push(f, 'secret');
  for (const f of arr(p.misconfigurations)) push(f, BEHAVIOUR.test(f.rule || '') ? 'behaviour' : (HARDENING.test(f.rule || '') ? 'hardening' : 'misconfiguration'));

  for (const a of apps) {
    out.inventory.push(mkInventory({ component_id: R.rel(String(appId(a))), component_name: R.text(String(first(a.name, a.id))), status: 'unknown', type: 'application', details: R.deep(a) }));
    const hosts = first(a.remote_hosts?.hosts, a.remote_hosts?.items, a.remote_hosts?.list, a.native_hardening?.remote_hosts?.hosts, null);
    for (const h of arr(hosts)) {
      const v = typeof h === 'string' ? h : first(h.host, h.domain, h.ip, h.value);
      if (!v) continue;
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(':') && /^[0-9a-f:]+$/i.test(v);
      out.inventory.push(mkInventory({ component_id: v, component_name: v, status: 'observed', type: isIp ? 'ip' : 'domain', details: typeof h === 'string' ? { host: h } : R.deep(h) }));
    }
  }

  for (const d of arr(p.dependencies)) {
    const cid = first(d.purl, `${d.name}@${d.version ?? ''}`);
    out.inventory.push(mkInventory({ component_id: cid, component_name: depName(d.name, d.ecosystem, d.version), status: d.lookup_status === 'not_queryable' ? 'not_queryable' : 'unknown', type: 'dependency', details: R.deep(d) }));
    for (const v of arr(d.vulnerabilities)) {
      out.findings.push(mkFinding({
        rule_id: v.id,
        title: first(v.summary, v.id),
        component_id: cid,
        component_name: depName(d.name, d.ecosystem, d.version),
        component_type: 'dependency',
        severity: v.severity,
        confidence: d.confidence ?? null,
        violate_policy: v.is_policy_violation ?? violates(v.severity),
        type: v.is_infection ? 'sc_infection' : 'sc_vulnerability',
        details: R.deep(v),
      }));
    }
  }
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings);

  const t = p.target || {};
  out.scopes.push({ type: t.kind === 'mcp-client' || t.kind === 'mcp-server' ? 'mcp' : 'artifact', ...R.deep(t), name: R.text(t.file ?? '') });
  for (const c of arr(t.config_files)) out.scopes.push({ type: 'filesystem', name: R.rel(c.file), path: R.rel(c.file), client: c.client ?? null, scope: c.scope ?? null, servers: c.servers ?? null });

  const meta = H.buildMetadata({
    payload: p, opts, os_meta: p.os_metadata, git: p.git_metadata, runtime: { arch: p.arch, node_version: p.runtime_version },
    scan: {
      generated_at: p.generated_at, status: p.analysis?.complete === false ? 'partial' : 'completed',
      scan_type: String(p.tool || '').replace(/^ubel-/, '') || null, scan_scope: t.kind ?? null,
      ecosystems: uniq(arr(p.dependencies).map((d) => d.ecosystem)), vulnerability_scan: arr(p.dependencies).length > 0 || p.dependency_summary != null,
      report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { flags: { min_severity: p.min_severity ?? null, hidden_by_filter: p.hidden_by_filter ?? 0 }, gate: p.gate ?? null, limits: p.limits ?? null, analysis: p.analysis ?? null },
    ...out,
    stats_extra: { source: { summary: p.summary ?? null, stats: p.stats ?? null, dependency_summary: p.dependency_summary ?? null }, diffs: p.diffs ?? null, notes: p.analysis_notes ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}

// The module's own payload, rebuilt from a canonical report. Only used to call the module's server-side renderer
// (mobile/lib/report.js buildHtml) for the executive-summary section, which that template renders on the server.
export function restore(c) {
  const si = c.metadata?.scan_info || {}, st = c.stats || {}, src = st.source || {}, pol = c.policy || {};
  const own = (f) => f.type !== 'sc_vulnerability' && f.type !== 'sc_infection';
  const cat = (k) => arr(c.findings).filter((f) => own(f) && f.details?.category === k).map((f) => f.details);
  const t0 = arr(c.scopes).find((s) => s.type === 'artifact' || s.type === 'mcp') || {};
  const { type: _t, name, ...target } = t0;
  return {
    schema: `ubel-${si.scan_type}/1`, tool: c.metadata?.tool_info?.tool_cli ?? `ubel-${si.scan_type}`, tool_version: c.metadata?.tool_info?.tool_version,
    generated_at: si.generated_at, report_id: si.report_id, asset_id: si.asset_id, asset_name: si.asset_name, asset_type: si.asset_type, machine_id: si.machine_id,
    target: { file: name, ...target },
    apps: arr(c.inventory).filter((i) => i.type === 'application').map((i) => i.details),
    dependencies: arr(c.inventory).filter((i) => i.type === 'dependency').map((i) => i.details),
    vulnerabilities: cat('vulnerability'), secrets: cat('secret'), misconfigurations: cat('misconfiguration'),
    summary: src.summary, stats: src.stats, dependency_summary: src.dependency_summary, analysis_notes: st.notes,
    limits: pol.limits, analysis: pol.analysis, gate: pol.gate, min_severity: pol.flags?.min_severity, hidden_by_filter: pol.flags?.hidden_by_filter,
    compliance_summary: c.compliance_summary, executive_summary: c.executive_summary, diffs: st.diffs,
  };
}
