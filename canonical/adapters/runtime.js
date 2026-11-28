'use strict';
// Runtime scanner (ubel-runtime) → canonical. It uses the same payload as ubel-vm (profile, target, scan_options, coverage,
// checks[], findings[], compliance_*, diffs, executive_summary) plus a top-level `runtime` block {processes, listeners,
// containers, inspections, summary}. The original has no scanned directory: processes, libraries and containers belong to a
// machine, so paths are kept as they are (nothing is made relative).
//
// finding.type by check:  rt-secret-*              → secret
//                         deleted exe / memfd / code or library from temp / traced / preload hijack → behavior
//                         containers, network exposure → misconfig
//                         everything else (root service, capabilities, sandbox, wildcard bind, EOL) → hardening
// Observations (info unless noted, appended after the findings): passed checks (hardening), checks that could not run (coverage, low),
// every running program / loaded Node.js inspection / container (behavior) and every listening socket (exposure; a non-loopback port
// is rated by what normally listens there).
// inventory:  the audited host → host, processes → application, listening sockets → network_service, containers → container,
//             the container engine → container_engine. Every observation points at an inventory entry (the artifact it is about) and carries a
//             finding_id derived from what it is about, so a dashboard can follow it from one scan to the next.
// One observation per artifact: one per program (a program with several instances is still one program: the payload keeps no per-instance
// attributes beyond the pid list, and a pid does not survive to the next scan), one per listening socket, one per container, one per inspection.
import { arr, isObj, mkFinding, observe, mkInventory, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, checkObservations, listenerRisk, isLoopback, sha, TYPES } from '../common.js';

export const family = 'runtime';

const BEHAVIOUR = /^rt-(proc-(deleted-exe|memfd-exec|code-in-temp|traced)|lib-(from-temp|preload-hijack|stale-mapped))$/;

function typeOf(f) {
  const c = String(f.check || '');
  if (/^rt-secret|secret/.test(c) || f.area === 'secrets') return TYPES.SECRET;
  if (BEHAVIOUR.test(c)) return TYPES.BEHAVIOR;
  if (f.area === 'containers' || f.area === 'exposure' || /^rt-net-/.test(c)) return TYPES.MISCONFIG;
  return TYPES.HARDENING;
}

export function translate(p, opts, H) {
  const rt = isObj(p.runtime) ? p.runtime : {};
  const violates = failOnPredicate(opts.fail_on);
  const out = { findings: [], inventory: [], scopes: [] };
  const derived = [];   // components only known from a finding's resource (kept unless the runtime block already lists that id)

  for (const f of arr(p.findings)) {
    const type = typeOf(f);
    const cid = f.resource ?? null, cname = f.resource ?? null;
    out.findings.push(mkFinding({
      rule_id: f.check, title: f.title, component_id: cid, component_name: cname, component_type: 'application',
      severity: f.severity, confidence: "high", violate_policy: violates(f.severity), type, details: { ...f },
    }));
    if (cid) derived.push(mkInventory({ component_id: cid, component_name: cname, status: 'running', type: 'application', details: { resource: f.resource, scope: f.scope ?? null, area: f.area ?? null } }));
  }

  for (const pr of arr(rt.processes)) {
    const id = pr.scope && pr.scope !== 'host' ? `${pr.scope}:${pr.label}` : pr.label;
    out.inventory.push(mkInventory({ component_id: pr.label, component_name: pr.label, status: 'running', type: 'application', details: { ...pr, component_key: id } }));
  }
  for (const l of arr(rt.listeners)) {
    const id = `${l.address}:${l.port}`;
    out.inventory.push(mkInventory({ component_id: id, component_name: id, status: 'listening', type: 'network_service', details: l }));
  }
  const cont = rt.containers;
  for (const c of arr(cont?.items)) {
    out.inventory.push(mkInventory({ component_id: c.name, component_name: c.name, status: 'running', type: 'container', details: c }));
  }
  // ── observations ──
  const t0 = p.target || {};
  const hostId = t0.hostname ?? t0.subject ?? 'host';
  // the audited machine: what a passed / not-assessed check is about
  out.inventory.unshift(mkInventory({ component_id: hostId, component_name: hostId, status: p.coverage?.status === 'partial' ? 'partially_assessed' : 'assessed', type: 'host',
    details: { hostname: t0.hostname ?? null, subject: t0.subject ?? null, os: t0.os ?? null, arch: t0.arch ?? null, mode: t0.mode ?? 'live', processes_assessed: t0.processes_assessed ?? null } }));
  out.findings.push(...checkObservations(p.checks, { passType: TYPES.HARDENING, component_id: hostId, component_name: hostId, component_type: 'host', resource: hostId }));
  const obs = (o) => out.findings.push(observe({ component_type: 'application', ...o, details: { severity: o.severity ?? 'info', scope: o.details?.scope ?? '', area: o.area, check: o.rule_id, resource: o.component_name, title: o.title, remediation: '', compliance: null, ...o.details } }));
  for (const pr of arr(rt.processes)) {
    const listens = arr(pr.listening);
    obs({
      finding_id: sha('behavior.process', pr.scope ?? 'host', pr.label),
      rule_id: 'behavior.process', area: 'processes', title: `Process running: ${pr.label}${pr.count > 1 ? ` (${pr.count} instances)` : ''}`, component_id: pr.label, component_name: pr.label, type: TYPES.BEHAVIOR,
      details: { ...pr, description: `${pr.label} runs as ${pr.root ? 'root' : pr.user}${listens.length ? ` and listens on ${listens.slice(0, 5).join(', ')}` : ''}${pr.node ? '; it is a Node.js process' : ''}.` },
    });
  }
  for (const l of arr(rt.listeners)) {
    const id = `${l.address}:${l.port}`;
    const { service, severity } = listenerRisk(l.address, l.port);
    obs({
      finding_id: sha('exposure.listener', l.address, l.port, l.scope ?? 'host', l.program ?? ''),
      rule_id: `exposure.listener.${l.port}`, area: 'exposure', title: `Listening on ${id}${service ? ` (${service})` : ''}${l.program ? `: ${l.program}` : ''}`, component_id: id, component_name: id,
      component_type: 'network_service', severity, type: TYPES.EXPOSURE,
      details: { ...l, service, description: `${l.program || 'A process'} accepts connections on ${id}${isLoopback(l.address) ? ' (loopback only)' : severity === 'info' ? '' : '; this port is reachable from the network and normally hosts a service that should not be exposed unauthenticated'}.` },
    });
  }
  for (const c of arr(rt.containers?.items)) {
    obs({
      finding_id: sha('behavior.container', c.name),
      rule_id: 'behavior.container', area: 'containers', title: `Container running: ${c.name}`, component_id: c.name, component_name: c.name, component_type: 'container', type: TYPES.BEHAVIOR,
      details: { ...c, description: `Container ${c.name} runs image ${c.image} as ${c.user}${arr(c.published_ports).length ? `, publishing ${c.published_ports.slice(0, 4).join(', ')}` : ''}.` },
    });
  }
  if (rt.containers && rt.containers.status && rt.containers.status !== 'ok') {
    out.inventory.push(mkInventory({ component_id: rt.containers.socket ?? 'container engine', component_name: 'container engine', status: rt.containers.status, type: 'container_engine', details: { socket: rt.containers.socket ?? null, status: rt.containers.status, reason: rt.containers.reason ?? null } }));
    obs({ finding_id: sha('coverage.containers', rt.containers.socket ?? 'container engine'), rule_id: 'coverage.containers', area: 'containers', title: 'Container engine not inspected', component_id: rt.containers.socket ?? 'container engine', component_name: 'container engine', component_type: 'container_engine', severity: 'low', type: TYPES.COVERAGE,
      details: { description: `Containers could not be inspected (${rt.containers.status}${rt.containers.reason ? `: ${rt.containers.reason}` : ''}).`, status: rt.containers.status, reason: rt.containers.reason ?? null } });
  }
  for (const i of arr(rt.inspections)) {
    if (i.ok) obs({ finding_id: sha('behavior.inspection', i.scope ?? 'host', i.label), rule_id: 'behavior.inspection', area: 'inspection', title: `Node.js process inspected: ${i.label}`, component_id: i.label, component_name: i.label, type: TYPES.BEHAVIOR,
      details: { ...i, description: `${i.loaded_files ?? 0} script file(s) loaded by the running process were read through the V8 inspector${i.left_open ? ' (the inspector was left open)' : ''}.` } });
    else obs({ finding_id: sha('coverage.inspection', i.scope ?? 'host', i.label), rule_id: 'coverage.inspection', area: 'inspection', title: `Node.js process could not be inspected: ${i.label}`, component_id: i.label, component_name: i.label, severity: 'low', type: TYPES.COVERAGE,
      details: { ...i, description: `The V8 inspector could not be used on this process${i.reason ? ` (${i.reason})` : ''}; what it has loaded is not in this report.` } });
  }

  const known = new Set(out.inventory.map((i) => i.component_id));
  out.inventory.push(...derived.filter((d) => !known.has(d.component_id)));
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings, { vulnerable: 'at_risk', clean: 'running' });
  // keep the original "running"/"listening" state for components with no findings; applyFindingStatus only overrides 'unknown'

  const t = p.target || {};
  out.scopes.push({ type: 'host', name: t.hostname ?? t.subject ?? null, os: t.os ?? null, arch: t.arch ?? null, mode: t.mode ?? 'live', processes_assessed: t.processes_assessed ?? null });
  for (const sc of uniq([...arr(rt.processes).map((x) => x.scope), ...arr(p.findings).map((x) => x.scope)])) {
    if (sc && sc !== 'host') out.scopes.push({ type: 'container_scope', name: sc });
  }
  if (cont) out.scopes.push({ type: 'container_engine', name: cont.socket ?? 'container engine', status: cont.status ?? null, reason: cont.reason ?? null });
  for (const [k, v] of Object.entries(p.scan_options?.scope || {})) out.scopes.push({ type: 'selection', name: k, value: v });

  const meta = H.buildMetadata({
    payload: p, opts, os_meta: { os_name: t.os ?? null }, git: p.git_metadata, runtime: { arch: t.arch ?? p.arch, node_version: p.runtime_version },
    scan: {
      generated_at: p.generated_at, status: p.coverage?.status === 'partial' ? 'partial' : 'completed', scan_type: 'runtime', scan_scope: t.mode ?? 'live',
      ecosystems: [], vulnerability_scan: false,
      report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { profile: p.profile ?? null, flags: p.scan_options ?? {}, gate: opts.fail_on != null ? { fail_on: opts.fail_on } : null, checks: p.checks ?? [] },
    ...out,
    stats_extra: { source: p.stats ?? null, coverage: p.coverage ?? null, compliance_posture: p.compliance_posture ?? null, runtime_summary: rt.summary ?? null },
    diffs: p.diffs ?? null,
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
