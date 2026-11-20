'use strict';
// EASM (ubel-url / ubel-domain / ubel-host / ubel-easm) → canonical.
// Original keys used: inventory[] (detected products), vulnerabilities[], misconfigurations[] (grouped by rule, with
// occurrences per target), secrets[], scope[], assets[], hosts[], targets[], scan_options, stats, compliance_summary,
// executive_summary, diffs, threat_intel.
//
// component_id = detected product name (+version) → "name@version" ("name" when no version is known).
// A grouped misconfiguration is split per target, so every canonical finding points at one component (a host / URL).
import { arr, isObj, first, mkFinding, observe, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, portRisk, TYPES } from '../common.js';

export const family = 'easm';

const prodId = (name, ver) => (ver ? `${name}@${ver}` : `${name}`);

export function translate(p, opts, H) {
  const R = makeRel(first(p.working_dir, opts.cwd));
  const so = p.scan_options || {};
  const out = { findings: [], inventory: [], scopes: [] };

  // detected products, keyed by every id they are known by, so a vulnerability's affected_package_id resolves
  const byId = new Map();
  for (const it of arr(p.inventory)) {
    const cid = prodId(it.name ?? 'unknown', it.version);
    const cname = depName(it.name, it.ecosystem, it.version);
    for (const id of [it.id, ...arr(it.ids)]) if (id) byId.set(id, { cid, cname });
    out.inventory.push(mkInventory({ component_id: cid, component_name: cname, status: it.state ?? 'undetermined', type: 'application', details: R.deep(it) }));
  }

  for (const v of arr(p.vulnerabilities)) {
    const hit = byId.get(v.affected_package_id) || null;
    const cid = hit ? hit.cid : prodId(v.affected_dependency ?? 'unknown', v.affected_dependency_version);
    const cname = hit ? hit.cname : depName(v.affected_dependency, v.ecosystem, v.affected_dependency_version);
    out.findings.push(mkFinding({
      rule_id: v.id, title: first(v.summary, v.id), component_id: cid, component_name: cname, component_type: 'application',
      severity: v.severity, confidence: v.release_confidence?.level ?? null,
      violate_policy: v.is_policy_violation ?? (v.policy_decision != null ? v.policy_decision === 'block' : null),
      type: v.is_infection ? TYPES.INFECTION : TYPES.VULN, details: R.deep(v),
    }));
  }

  for (const g of arr(p.misconfigurations)) {
    const targets = uniq([...arr(g.occurrences).map((o) => o.target), ...arr(g.targets)]);
    const t = targets[0] ?? null;               // a group can span several targets: it is one finding, anchored on the first
    out.findings.push(mkFinding({
      rule_id: g.id, title: g.title, component_id: t, component_name: t, component_type: 'url',
      severity: g.severity, confidence: null, violate_policy: null, type: TYPES.MISCONFIG, details: R.deep(g),
    }));
  }

  for (const s of arr(p.secrets)) {
    const t = first(s.target, s.url, s.file, s.source);
    out.findings.push(mkFinding({
      rule_id: first(s.id, s.rule_id, s.rule), title: first(s.title, s.secret_type, s.id), component_id: t, component_name: t, component_type: 'url',
      severity: s.severity, confidence: s.confidence ?? null, violate_policy: null, type: TYPES.SECRET, details: R.deep(s),
    }));
  }

  // discovered network entities → inventory (ip / domain); the scanned scope itself goes to scopes[]
  for (const row of arr(p.scope)) {
    const type = row.type === 'ip' ? 'ip' : 'domain';
    out.inventory.push(mkInventory({ component_id: row.name, component_name: row.name, status: row.status ?? 'unknown', type, details: R.deep(row) }));
    out.scopes.push({ type, name: row.name, status: row.status ?? null, ...R.deep(row) });
  }
  for (const a of arr(p.assets)) out.scopes.push({ type: 'url', name: a.target, status: a.status ?? null, ...R.deep(a) });
  for (const h of arr(p.hosts)) out.scopes.push({ type: 'host', name: h.host, ...R.deep(h) });

  // Network surface (observations, appended after the findings): every port known open on a scanned address / host name. Web and mail
  // ports are the normal case (info); administration, database and clear-text service ports are rated by what listens there.
  for (const row of arr(p.scope)) {
    if (row.status === 'skipped') continue;
    const web = new Set(arr(row.http_ports).map(String));
    for (const port of uniq([...arr(row.open_ports), ...arr(row.scanned_ports)])) {
      const { service, severity } = portRisk(port);
      out.findings.push(observe({
        rule_id: `exposure.port.${port}`,
        title: `Port ${port}/tcp open${service ? ` (${service})` : web.has(String(port)) ? ' (HTTP)' : ''}`,
        component_id: row.name, component_name: row.name, component_type: row.type === 'ip' ? 'ip' : 'domain', severity, type: TYPES.EXPOSURE,
        details: R.deep({ target: row.name, port, protocol: 'tcp', service: service ?? (web.has(String(port)) ? 'HTTP(S)' : null), http: web.has(String(port)),
          description: `${row.name} accepts TCP connections on port ${port}${service ? ` (${service})` : ''}. ${severity === 'info' ? 'This is an expected, publicly reachable service.' : 'Make sure this service is meant to be reachable from the network it was scanned from.'}` }),
      }));
    }
  }

  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings);

  const meta = H.buildMetadata({
    payload: p, opts, os_meta: p.os_metadata, git: p.git_metadata, runtime: { arch: p.arch, node_version: p.runtime_version },
    scan: {
      generated_at: p.generated_at, status: arr(p.hosts).some((h) => h.status === 'error') || arr(p.assets).some((a) => a.status === 'error') ? 'partial' : 'completed',
      scan_type: String(p.tool || '').replace(/^ubel-/, '') || null, scan_scope: 'external',
      ecosystems: ['web'], vulnerability_scan: true,
      report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { flags: so, targets: p.targets ?? [], allow_private: p.allow_private ?? false },
    ...out,
    stats_extra: { source: p.stats ?? null, diffs: p.diffs ?? null, threat_intel: p.threat_intel ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
