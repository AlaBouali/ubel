'use strict';
// Cloud scanner (AWS / GCP / Azure) → canonical.
// Original keys used: findings[] {check, resource, region, provider, service, severity, title, description, remediation, compliance},
// providers[], regions{}, accounts{}, provider_status[], scan_options, stats, compliance_summary, executive_summary, diffs.
// The original has no inventory, so it is derived from what the payload names:
//   - resources[] (written by the scanner since it records every resource a check inspects, clean ones included) is the inventory of
//     cloud resources. An older report has no resources[]: then only resources with a finding are known (the scanner did not list the
//     resources it found clean), and the inventory falls back to the resources the findings point at.
//   - providers, accounts and regions are known whether or not they have findings.
//   cloud_resource   one per (provider, region, resource, service) the scanner inspected or a finding points at; its id IS the findings'
//                    affected_component_id, so every finding resolves to exactly one inventory entry. State: "misconfigured" when a
//                    finding in the report is about it; otherwise "clean" (inspected, nothing found), "unassessed" (a check on it failed:
//                    NOT clean) or "filtered" (it has findings, all of them below --min-severity, so none is in the report)
//   cloud_provider   one per provider, status = provider_status (scanned / partial / skipped / error): the component of the coverage observations
//   cloud_account    the account / project / subscription scanned (accounts{})
//   cloud_region     every region scanned (regions{}, and any region a resource or finding is in). A resource with no region (IAM, firewall
//                    rules, project / subscription settings) is in no region: its id says "global" and it adds no cloud_region.
import { arr, isObj, first, mkFinding, observe, mkInventory, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, TYPES } from '../common.js';
import { sha } from '../common.js';
export const family = 'cloud';

const lastSeg = (r) => { const s = String(r ?? ''); const m = s.split(/[/:]/).filter(Boolean); return m.length ? m[m.length - 1] : s; };

// The region of a finding / resource, '' when it has none. An empty value is a global resource (IAM, firewall rules, project settings).
// A value that lists several regions is not a region either: older reports wrote the scanned regions joined with " , " on the account-wide
// findings (CloudTrail / GuardDuty / Config), which would otherwise become a region of its own.
const regionOf = (f) => { const r = String(f?.region ?? '').trim(); return r.includes(',') ? '' : r; };

// The identity of the cloud component a finding is about: one function for the finding and for its inventory entry, so the two cannot drift apart.
const componentOf = (f) => {
  const provider = f.provider ?? 'unknown', region = regionOf(f) || 'global', service = f.service ?? 'unknown';
  return {
    id: `${provider}:${region}:${f.resource ?? 'unknown'}:${service}`,
    name: `${provider}: ${lastSeg(f.resource) || service} (${region}) => ${service}`,
  };
};

export function translate(p, opts, H) {
  const violates = failOnPredicate(opts.fail_on);
  const out = { findings: [], inventory: [], scopes: [] };

  const accounts = isObj(p.accounts) ? p.accounts : {};
  const accountOf = (x) => x.account ?? accounts[x.provider] ?? null;

  // The inspected resources first: dedupeInventory keeps the first entry of an id, and this one knows more (it can be unassessed / filtered).
  for (const r of arr(p.resources)) {
    if (!isObj(r) || r.resource == null) continue;
    const comp = componentOf(r);
    const findings = Number(r.findings) || 0, hidden = Number(r.hidden_findings) || 0;
    out.inventory.push(mkInventory({
      component_id: comp.id, component_name: comp.name, type: 'cloud_resource',
      // 'unknown' becomes "clean" below when no finding is about the resource; the other two are never overwritten by that.
      status: r.assessed === false ? 'unassessed' : (!findings && hidden ? 'filtered' : 'unknown'),
      details: {
        resource: r.resource, provider: r.provider ?? null, service: r.service ?? null, region: regionOf(r) || null, account: accountOf(r),
        assessed: r.assessed !== false, reason: r.reason ?? null, findings, hidden_findings: hidden,
      },
    }));
  }

  for (const f of arr(p.findings)) {
    const comp = componentOf(f);
    out.findings.push(mkFinding({
      finding_id: sha(f.check, f.provider ?? '',f.region ?? '', f.resource ?? '', f.service ?? ''),
      rule_id: f.check,
      title: f.title,
      component_id: comp.id,
      component_name: comp.name,
      component_type: 'cloud_resource',
      severity: f.severity,
      confidence: f.confidence ?? "high",
      violate_policy: violates(f.severity),
      type: TYPES.MISCONFIG,
      details: f,
    }));
    out.inventory.push(mkInventory({
      component_id: comp.id, component_name: comp.name, status: 'unknown', type: 'cloud_resource',
      details: { resource: f.resource ?? null, provider: f.provider ?? null, service: f.service ?? null, region: regionOf(f) || null, account: accountOf(f) },
    }));
  }
  const regions = isObj(p.regions) ? p.regions : {};
  for (const [prov, list] of Object.entries(regions)) {
    for (const r of arr(list)) {
      const rid = typeof r === 'string' ? r : first(r.region, r.name, r.id);
      out.inventory.push(mkInventory({ component_id: `${prov}:${rid}`, component_name: String(rid), status: 'scanned', type: 'cloud_region', details: { provider: prov, region: rid, ...(isObj(r) ? r : {}) } }));
      out.scopes.push({ type: 'cloud_region', name: String(rid), provider: prov });
    }
  }
  // A region a resource or a finding names is a scanned region even when regions{} does not list it (GCP / Azure report none). After regions{}:
  // the first entry of an id is kept, and that one carries more.
  for (const f of [...arr(p.resources), ...arr(p.findings)]) {
    const region = isObj(f) ? regionOf(f) : '';
    if (!region) continue;
    out.inventory.push(mkInventory({ component_id: `${f.provider ?? 'unknown'}:${region}`, component_name: region, status: 'scanned', type: 'cloud_region', details: { provider: f.provider ?? null, region } }));
  }
  // Providers and the account behind each one. The provider's component id is the one its coverage observations use (`provider:<name>`).
  const provName = (x) => (typeof x === 'string' ? x : first(x?.name, x?.provider));
  for (const prov of uniq([...arr(p.providers).map(provName), ...arr(p.provider_status).map((x) => x?.provider)])) {
    const ps = arr(p.provider_status).find((x) => x && x.provider === prov) ?? null;
    out.inventory.push(mkInventory({
      component_id: `provider:${prov}`, component_name: String(prov), status: ps ? String(ps.status ?? (ps.ok === false ? 'error' : 'scanned')) : 'scanned', type: 'cloud_provider',
      details: { provider: prov, account: (isObj(p.accounts) ? p.accounts[prov] : null) ?? null, status: ps?.status ?? null, reason: ps?.reason ?? null },
    }));
  }
  for (const [prov, acct] of Object.entries(isObj(p.accounts) ? p.accounts : {})) {
    if (acct == null || acct === '') continue;
    out.inventory.push(mkInventory({ component_id: `${prov}:account:${acct}`, component_name: String(acct), status: 'scanned', type: 'cloud_account', details: { provider: prov, account: acct } }));
  }
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings, { vulnerable: 'misconfigured' });
  for (const prov of arr(p.providers)) {
    const name = typeof prov === 'string' ? prov : first(prov.name, prov.provider);
    out.scopes.push({ type: 'cloud', name, account: (isObj(p.accounts) ? p.accounts[name] : null) ?? null, status: arr(p.provider_status).find((s) => s.provider === name) ?? null });
  }

  // What was and was not assessed, per provider (observations, appended after the findings). A provider that was scanned in full is the
  // normal case (info); one that was partly scanned or skipped means findings may be missing (low).
  for (const ps of arr(p.provider_status)) {
    if (!isObj(ps) || !ps.provider) continue;
    const st = String(ps.status ?? (ps.ok === false ? 'error' : 'scanned'));
    const ok = st === 'scanned';
    out.findings.push(observe({
      rule_id: `coverage.provider.${st}`,
      title: ok ? `Provider ${String(ps.provider).toUpperCase()} scanned` : `Provider ${String(ps.provider).toUpperCase()} ${st === 'skipped' ? 'skipped' : st === 'partial' ? 'only partly scanned' : 'not scanned (' + st + ')'}`,
      component_id: `provider:${ps.provider}`, component_name: String(ps.provider), component_type: 'cloud_provider',
      severity: ok ? 'info' : 'low', type: TYPES.COVERAGE,
      details: {
        check: `coverage.provider.${st}`, area: 'coverage', provider: ps.provider, service: '', region: '', resource: String(ps.provider), severity: ok ? 'info' : 'low',
        title: ok ? `Provider ${ps.provider} scanned` : `Provider ${ps.provider}: ${st}`,
        description: ok ? 'All checks for this provider ran.' : `${ps.reason || 'Some checks did not run.'} Findings for the part that was not assessed are not in this report.`,
        remediation: ok ? '' : 'Grant the scanner the missing read permissions / credentials and scan again.', compliance: null, status: st, reason: ps.reason ?? null,
      },
    }));
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
    stats_extra: { source: p.stats ?? null },
    diffs: p.diffs ?? null,
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
