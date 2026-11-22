'use strict';
// VM (ubel-vm) and Kubernetes (ubel-k8s) → canonical. Both emit the same payload from vm/lib/html_report.js.
// Original keys used: profile, target, scan_options, coverage, stats, compliance_summary, compliance_posture,
// checks[], findings[] {scope, area, check, severity, title, resource, description, remediation, compliance}, diffs, executive_summary.
// `checks` (every evaluated baseline check, pass/fail/n-a/not-assessed) goes under policy.checks; `coverage` under stats.coverage.
import { arr, isObj, first, mkFinding, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, checkObservations, isScFinding, scFinding, TYPES } from '../common.js';

export const family = 'posture';

const K8S_KIND = /^([A-Za-z]+)\//;

export function translate(p, opts, H) {
  const isK8s = (p.profile?.key || p.tool || '').toString().includes('k8s');
  const t = p.target || {};
  const root = isK8s ? (opts.cwd ?? null) : first(p.scan_options?.root, t.root, opts.cwd);
  const R = makeRel(root);
  const violates = failOnPredicate(opts.fail_on);
  const out = { findings: [], inventory: [], scopes: [] };

  for (const f of arr(p.findings)) {
    // package vulnerabilities come from the SCA engine: the SCA record + sc_vuln / sc_infection (see common.js)
    if (isScFinding(f)) { const sc = scFinding(f, { violates, R }); out.findings.push(sc.finding); out.inventory.push(sc.inventory); continue; }
    const res = f.resource == null ? null : R.rel(f.resource);
    const cid = res == null ? null : (isK8s && f.scope ? `${f.scope}/${res}` : res);
    const kind = isK8s ? 'kubernetes_resource' : (typeof res === 'string' && res.startsWith('/') ? 'filesystem' : 'host_object');
    out.findings.push(mkFinding({
      rule_id: f.check,
      title: f.title,
      component_id: cid,
      component_name: res,
      component_type: kind,
      severity: f.severity,
      confidence: "high",
      violate_policy: violates(f.severity),
      type: isK8s ? TYPES.MISCONFIG : TYPES.HARDENING,
      details: R.deep(f),
    }));
    if (cid) {
      out.inventory.push(mkInventory({ component_id: cid, component_name: res, status: 'unknown', type: kind, details: { resource: res, scope: f.scope || null, area: f.area || null, kind: isK8s ? (res.match(K8S_KIND)?.[1] ?? null) : null } }));
    }
  }
  // Passed / not-assessed checks (observations, appended after the findings so those keep their positions).
  const subject = isK8s ? (t.subject ?? 'cluster') : (t.hostname ?? 'vm');
  out.findings.push(...checkObservations(p.checks, { passType: isK8s ? TYPES.MISCONFIG : TYPES.HARDENING, component_id: isK8s ? null : subject, component_name: subject, component_type: isK8s ? 'kubernetes_cluster' : 'host', resource: subject }));
  if (!isK8s) {
    out.inventory.unshift(mkInventory({ component_id: t.hostname ?? 'vm', component_name: t.hostname ?? 'vm', status: p.coverage?.status === 'partial' ? 'partially_assessed' : 'assessed', type: 'host', details: R.deep(t) }));
  }
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings, { vulnerable: 'non_compliant', clean: 'compliant' });

  // The installed-package list (ubel-vm: operating-system and application packages, as the SCA engine read them). Every package is a
  // dependency of the inventory, like in an SCA report, whether or not it has an advisory; the dependency entries that the findings
  // above created are replaced by these. Their status uses the SCA words (vulnerable / infected / clean) and their details are the SCA
  // inventory item, which the SCA package modal renders.
  const pkgs = arr(p.package_inventory).filter((c) => isObj(c) && c.id);
  if (pkgs.length) {
    const ids = new Set(pkgs.map((c) => c.id));
    out.inventory = out.inventory.filter((i) => !(i.type === 'dependency' && ids.has(i.component_id)));
    for (const c of pkgs) out.inventory.push(mkInventory({ component_id: c.id, component_name: depName(c.name, c.ecosystem, c.version), status: 'unknown', type: 'dependency', details: R.deep(c) }));
  }
  applyFindingStatus(out.inventory.filter((i) => i.type === 'dependency'), out.findings);
  for (const i of out.inventory) if (i.type === 'dependency' && i.details && i.details.state === 'unknown' && i.status === 'clean') i.status = 'unknown';   // its lookup could not be completed: not "clean"

  if (isK8s) {
    for (const f of arr(t.paths)) out.scopes.push({ type: 'manifest', name: R.rel(f), path: R.rel(f) });
    for (const ns of arr(t.scopes_scanned)) out.scopes.push({ type: 'kubernetes_namespace', name: ns, findings: out.findings.filter((x) => x.details?.scope === ns).length });
    if (t.source && t.source !== 'manifests') out.scopes.push({ type: 'kubernetes_cluster', name: t.subject ?? null, source: t.source });
  } else {
    out.scopes.push({ type: 'filesystem', name: R.rel(t.root ?? '/'), path: R.rel(t.root ?? '/'), mode: t.mode ?? null });
    out.scopes.push({ type: 'host', name: t.hostname ?? null, os: t.os ?? null, kernel: t.kernel ?? null, virtualization: t.virtualization ?? null, container: !!t.container });
    for (const e of uniq(pkgs.map((c) => c.ecosystem).filter(Boolean))) out.scopes.push({ type: 'ecosystem', name: e, components: pkgs.filter((c) => c.ecosystem === e).length });
  }

  const meta = H.buildMetadata({
    payload: p, opts, os_meta: isK8s ? null : { os_name: t.os ?? null }, git: p.git_metadata,
    runtime: { arch: p.arch, node_version: p.runtime_version },
    scan: {
      generated_at: p.generated_at, status: p.coverage?.status === 'partial' ? 'partial' : 'completed',
      scan_type: p.profile?.key ?? (isK8s ? 'k8s' : 'vm'), scan_scope: isK8s ? (t.source ?? 'manifests') : (t.mode ?? 'live'),
      ecosystems: [], vulnerability_scan: !isK8s, report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { profile: p.profile ?? null, flags: p.scan_options ?? {}, gate: opts.fail_on != null ? { fail_on: opts.fail_on } : null, checks: p.checks ?? [] },
    ...out,
    stats_extra: { source: p.stats ?? null, coverage: p.coverage ?? null, compliance_posture: p.compliance_posture ?? null, diffs: p.diffs ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
