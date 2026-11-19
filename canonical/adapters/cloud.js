'use strict';
// Cloud scanner (AWS / GCP / Azure) → canonical.
// Original keys used: findings[] {check, resource, region, provider, service, severity, title, description, remediation, compliance},
// providers[], regions{}, accounts{}, provider_status[], scan_options, stats, compliance_summary, executive_summary, diffs.
// The original has no inventory: it is derived from the resources / regions the findings point at.
import { arr, isObj, first, mkFinding, mkInventory, uniq, applyFindingStatus, dedupeInventory, failOnPredicate } from '../common.js';

export const family = 'cloud';

const lastSeg = (r) => { const s = String(r ?? ''); const m = s.split(/[/:]/).filter(Boolean); return m.length ? m[m.length - 1] : s; };

export function translate(p, opts, H) {
  const violates = failOnPredicate(opts.fail_on);
  const out = { findings: [], inventory: [], scopes: [] };

  for (const f of arr(p.findings)) {
    out.findings.push(mkFinding({
      rule_id: f.check,
      title: f.title,
      component_id: f.resource ?? null,
      component_name: f.resource ? lastSeg(f.resource) : null,
      component_type: 'cloud_resource',
      severity: f.severity,
      confidence: f.confidence ?? null,
      violate_policy: violates(f.severity),
      type: 'misconfiguration',
      details: f,
    }));
    if (f.resource) {
      out.inventory.push(mkInventory({
        component_id: f.resource, component_name: lastSeg(f.resource), status: 'unknown', type: 'cloud_resource',
        details: { resource: f.resource, provider: f.provider ?? null, service: f.service ?? null, region: f.region ?? null, account: f.account ?? null },
      }));
    }
  }
  const regions = isObj(p.regions) ? p.regions : {};
  for (const [prov, list] of Object.entries(regions)) {
    for (const r of arr(list)) {
      const rid = typeof r === 'string' ? r : first(r.region, r.name, r.id);
      out.inventory.push(mkInventory({ component_id: `${prov}:${rid}`, component_name: String(rid), status: 'scanned', type: 'cloud_region', details: { provider: prov, region: rid, ...(isObj(r) ? r : {}) } }));
      out.scopes.push({ type: 'cloud_region', name: String(rid), provider: prov });
    }
  }
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings, { vulnerable: 'misconfigured' });
  for (const prov of arr(p.providers)) {
    const name = typeof prov === 'string' ? prov : first(prov.name, prov.provider);
    out.scopes.push({ type: 'cloud', name, account: (isObj(p.accounts) ? p.accounts[name] : null) ?? null, status: arr(p.provider_status).find((s) => s.provider === name) ?? null });
  }

  const incomplete = arr(p.provider_status).some((s) => s && (s.status === 'error' || s.ok === false));
  const meta = H.buildMetadata({
    payload: p, opts, os_meta: p.os_metadata, git: p.git_metadata,
    runtime: { arch: p.arch, node_version: p.runtime_version },
    scan: {
      generated_at: p.generated_at, status: incomplete ? 'partial' : 'completed', scan_type: 'cloud', scan_scope: 'cloud',
      ecosystems: arr(p.providers).map((x) => (typeof x === 'string' ? x : x.name)), vulnerability_scan: false,
      report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { flags: { ...(p.scan_options || {}), region_source: p.region_source ?? null }, gate: opts.fail_on != null ? { fail_on: opts.fail_on } : null },
    ...out,
    stats_extra: { source: p.stats ?? null, diffs: p.diffs ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
