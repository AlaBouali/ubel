'use strict';
// SCA (ubel-npm / pip / … / docker / os / secrets / license / resbom) → canonical.
// Original keys used: vulnerabilities[], inventory[], secrets.findings[], policy, decision, scan_info, tool_info,
// os_metadata, git_metadata, runtime, stats, compliance_summary, executive_summary, diffs, threat_intel.
import { arr, isObj, first, mkFinding, observe, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, TYPES } from '../common.js';

export const family = 'sca';

export function translate(p, opts, H) {
  const R = makeRel(opts.cwd);
  const si = p.scan_info || {};
  const out = { findings: [], inventory: [], scopes: [] };

  // Sequences (root → … → affected package), by priority: the finding itself, the live per-component map the engine
  // hands over, then findings_summary (keyed by package name, valid only when its version matches the finding's).
  const seqFor = (v, cid) => {
    if (arr(v.affected_dependency_sequences).length) return v.affected_dependency_sequences;
    const live = opts.sequences instanceof Map ? opts.sequences.get(cid) : null;
    if (arr(live).length) return live;
    const fs_ = isObj(p.findings_summary) ? p.findings_summary[v.affected_dependency] : null;
    if (fs_ && (fs_.version == null || fs_.version === v.affected_dependency_version) && arr(fs_.affected_dependency_sequences).length) return fs_.affected_dependency_sequences;
    return [];
  };

  for (const v of arr(p.vulnerabilities)) {
    const cid = first(v.affected_package_id, `${v.affected_dependency ?? 'unknown'}@${v.affected_dependency_version ?? ''}`);
    out.findings.push(mkFinding({
      rule_id: `${v.id}-${v.ecosystem}-${v.affected_dependency ?? 'unknown'}@${v.affected_dependency_version ?? ''}`,
      title: `${v.id} affecting ${depName(v.affected_dependency, v.ecosystem, v.affected_dependency_version)}`,
      component_id: cid,
      component_name: depName(v.affected_dependency, v.ecosystem, v.affected_dependency_version),
      component_type: 'dependency',
      severity: v.severity,
      confidence: "high", //first(v.release_confidence?.level, v.release_confidence, null),
      violate_policy: v.is_policy_violation ?? (v.policy_decision != null ? v.policy_decision === 'block' : null),
      type: v.is_infection ? TYPES.SC_INFECTION : TYPES.SC_VULN,
      details: R.deep({ ...v, affected_dependency_sequences: seqFor(v, cid) }),
    }));
  }

  for (const s of arr(p.secrets?.findings)) {
    out.findings.push(mkFinding({
      rule_id: s.id,
      title: s.title || s.secret_type || s.id,
      component_id: R.rel(s.file_path),
      component_name: s.line != null ? `${R.rel(s.file_path)}:${s.line}` : R.rel(s.file_path),
      component_type: 'code',
      severity: s.severity,
      confidence: null,
      violate_policy: null,
      type: TYPES.SECRET,
      details: R.deep(s),
    }));
  }

  for (const c of arr(p.inventory)) {
    const isPkg = String(c.id ?? '').startsWith('pkg:');
    out.inventory.push(mkInventory({
      component_id: c.id ?? `${c.name}@${c.version}`,
      component_name: depName(c.name, c.ecosystem, c.version),
      status: 'unknown',
      type: isPkg ? 'dependency' : 'application',
      details: R.deep(c),
    }));
  }
  applyFindingStatus(out.inventory, out.findings);

  // Licenses that need a decision (observations: appended after the advisories / secrets so those keep their positions).
  // Permissive licenses are the normal case and are not listed; copyleft / proprietary / unrecognised ones are.
  const LICENSE_SEV = { high: 'medium', medium: 'low', unknown: 'low' };
  for (const c of arr(p.inventory)) {
    const li = isObj(c.license_info) ? c.license_info : null;
    const risk = li ? String(li.risk ?? 'unknown').toLowerCase() : null;
    if (!li || !(risk in LICENSE_SEV)) continue;
    const cid = c.id ?? `${c.name}@${c.version}`;
    const lic = first(li.spdx, typeof c.license === 'string' ? c.license : null, 'no license declared');
    out.findings.push(observe({
      rule_id: `license.${risk}`,
      title: `${risk === 'unknown' ? 'Unrecognised or missing license' : `${risk === 'high' ? 'Strong-copyleft / proprietary' : 'Weak-copyleft'} license`}: ${lic}`,
      component_id: cid,
      component_name: depName(c.name, c.ecosystem, c.version),
      component_type: String(c.id ?? '').startsWith('pkg:') ? 'dependency' : 'application',
      severity: LICENSE_SEV[risk],
      type: TYPES.LICENSE,
      details: R.deep({ license: lic, license_info: li, name: c.name, version: c.version, ecosystem: c.ecosystem,
        description: `The declared license (${lic}) is classified ${risk} risk${li.category ? ` (${li.category})` : ''}${li.osi_approved === false ? ' and is not OSI-approved' : ''}. Check that it is compatible with how this component is distributed.` }),
    }));
  }

  // scopes: what was scanned
  out.scopes.push({ type: si.scan_scope === 'container-image' ? 'container_image' : 'filesystem', name: '.', path: '.', scope: si.scan_scope ?? null, scan_type: si.type ?? null });
  for (const e of uniq([...arr(si.ecosystems), ...out.inventory.map((i) => i.details?.ecosystem)])) {
    out.scopes.push({ type: 'ecosystem', name: e, components: out.inventory.filter((i) => i.details?.ecosystem === e).length });
  }

  const git = p.git_metadata || {};
  const rt = p.runtime || {};
  const meta = H.buildMetadata({
    payload: p, opts, os_meta: p.os_metadata, git,
    runtime: { arch: rt.arch, node_version: first(rt.node_version, rt.version && /^v?\d/.test(String(rt.version)) ? rt.version : null) },
    scan: {
      generated_at: p.generated_at, status: 'completed', called_via: rt.editor?.kind ?? null,
      scan_type: si.type, scan_scope: si.scan_scope, ecosystems: arr(si.ecosystems), vulnerability_scan: si.vulnerability_scan,
      report_id: si.report_id, asset_id: si.asset_id, asset_name: si.asset_name, asset_type: si.asset_type, machine_id: si.machine_id,
      tool_version: p.tool_info?.version,
    },
  });
  if (!meta.scan_info.called_via) meta.scan_info.called_via = 'cli';

  return {
    metadata: meta,
    policy: { flags: { scan_scope: si.scan_scope ?? null, vulnerability_scan: si.vulnerability_scan ?? null, engine: p.engine ?? null }, policy: p.policy ?? null, decision: p.decision ?? null },
    ...out,
    stats_extra: { source: p.stats ?? null, findings_summary: p.findings_summary ?? null, diffs: p.diffs ?? null, threat_intel: p.threat_intel ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
