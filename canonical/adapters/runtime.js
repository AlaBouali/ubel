'use strict';
// Runtime scanner (ubel-runtime) → canonical. It uses the same payload as ubel-vm (profile, target, scan_options, coverage,
// checks[], findings[], compliance_*, diffs, executive_summary) plus a top-level `runtime` block {processes, listeners,
// containers, inspections, summary}. The original has no scanned directory: processes, libraries and containers belong to a
// machine, so paths are kept as they are (nothing is made relative).
//
// finding.type by check:  *-vulnerable*            → vuln (rule_id = the advisory id, check kept in details.check)
//                         rt-secret-*              → secret
//                         deleted exe / memfd / code or library from temp / traced / preload hijack → behavior
//                         containers, network exposure → misconfig
//                         everything else (root service, capabilities, sandbox, wildcard bind, EOL) → hardening
// Observations (info unless noted, appended after the findings): passed checks (hardening), checks that could not run (coverage, low),
// every running program / loaded Node.js inspection / container (behavior) and every listening socket (exposure; a non-loopback port
// is rated by what normally listens there).
// inventory:  processes → application, listening sockets → network_service, containers → container,
//             packages the inspector saw loaded → dependency.
import { arr, isObj, first, mkFinding, observe, mkInventory, depName, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, checkObservations, portRisk, TYPES } from '../common.js';

export const family = 'runtime';

const BEHAVIOUR = /^rt-(proc-(deleted-exe|memfd-exec|code-in-temp|traced)|lib-(from-temp|preload-hijack|stale-mapped))$/;
// "<package|product> <version>: <advisory> (<application>)"  /  "name@version: <advisory> (<application>)"
const VULN_RESOURCE = /^(.*?): ((?:CVE|GHSA|OSV|MAL|PYSEC|RUSTSEC|GO)-[A-Za-z0-9._-]+|[A-Z]{2,}-[\w.-]+)(?: \((.*)\))?$/;

function typeOf(f) {
  const c = String(f.check || '');
  if (/vulnerable/.test(c)) return TYPES.VULN;
  if (/^rt-secret|secret/.test(c) || f.area === 'secrets') return TYPES.SECRET;
  if (BEHAVIOUR.test(c)) return TYPES.BEHAVIOR;
  if (f.area === 'containers' || f.area === 'exposure' || /^rt-net-/.test(c)) return TYPES.MISCONFIG;
  return TYPES.HARDENING;
}

function splitPkg(s) {            // "lodash@4.17.0" | "Node.js 20.1.0" | "libssl 1.1.1"  →  {name, version}
  const at = String(s).match(/^(.+)@([^@\s]+)$/);
  if (at) return { name: at[1], version: at[2] };
  const sp = String(s).match(/^(.+?)\s+v?(\d[\w.+-]*)$/);
  return sp ? { name: sp[1], version: sp[2] } : { name: String(s), version: null };
}

export function translate(p, opts, H) {
  const rt = isObj(p.runtime) ? p.runtime : {};
  const violates = failOnPredicate(opts.fail_on);
  const out = { findings: [], inventory: [], scopes: [] };
  const derived = [];   // components only known from a finding's resource (kept unless the runtime block already lists that id)

  for (const f of arr(p.findings)) {
    const type = typeOf(f);
    let cid = f.resource ?? null, cname = f.resource ?? null, ctype = 'application', rule = f.check, details = { ...f };
    if (type === TYPES.VULN) {
      const m = VULN_RESOURCE.exec(String(f.resource ?? ''));
      if (m) {
        const pk = splitPkg(m[1]);
        const eco = /^Node\.js/i.test(pk.name) ? 'Node.js runtime' : (/@/.test(m[1]) ? 'npm' : null);
        cid = m[1]; cname = depName(pk.name, eco, pk.version); ctype = 'dependency'; rule = m[2];
      }
    } else if (type === TYPES.SECRET) {
      ctype = 'application';
    }
    out.findings.push(mkFinding({
      rule_id: rule, title: f.title, component_id: cid, component_name: cname, component_type: ctype,
      severity: f.severity, confidence: null, violate_policy: violates(f.severity), type, details,
    }));
    if (cid && type !== TYPES.VULN) derived.push(mkInventory({ component_id: cid, component_name: cname, status: 'running', type: 'application', details: { resource: f.resource, scope: f.scope ?? null, area: f.area ?? null } }));
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
  for (const i of arr(rt.inspections)) {
    for (const pk of arr(i.loaded_packages)) {
      const pp = splitPkg(pk);
      out.inventory.push(mkInventory({ component_id: pk, component_name: depName(pp.name, 'npm', pp.version), status: 'loaded', type: 'dependency', details: { name: pp.name, version: pp.version, ecosystem: 'npm', source: 'v8 inspector (loaded by the running process)', application: i.label, scope: i.scope ?? null } }));
    }
  }
  // ── observations ──
  const t0 = p.target || {};
  out.findings.push(...checkObservations(p.checks, { passType: TYPES.HARDENING, component_id: t0.hostname ?? t0.subject ?? 'host', component_name: t0.hostname ?? t0.subject ?? 'host', component_type: 'host', resource: t0.hostname ?? t0.subject ?? 'host' }));
  const obs = (o) => out.findings.push(observe({ component_type: 'application', ...o, details: { severity: o.severity ?? 'info', scope: o.details?.scope ?? '', area: o.area, check: o.rule_id, resource: o.component_name, title: o.title, remediation: '', compliance: null, ...o.details } }));
  for (const pr of arr(rt.processes)) {
    const listens = arr(pr.listening);
    obs({
      rule_id: 'behavior.process', area: 'processes', title: `Process running: ${pr.label}${pr.count > 1 ? ` (${pr.count} instances)` : ''}`, component_id: pr.label, component_name: pr.label, type: TYPES.BEHAVIOR,
      details: { ...pr, description: `${pr.label} runs as ${pr.root ? 'root' : pr.user}${listens.length ? ` and listens on ${listens.slice(0, 5).join(', ')}` : ''}${pr.node ? '; it is a Node.js process' : ''}.` },
    });
  }
  const LOOP = /^(127\.|::1$|localhost)/i;
  for (const l of arr(rt.listeners)) {
    const id = `${l.address}:${l.port}`;
    const { service, severity } = LOOP.test(String(l.address)) ? { service: portRisk(l.port).service, severity: 'info' } : portRisk(l.port);
    obs({
      rule_id: `exposure.listener.${l.port}`, area: 'exposure', title: `Listening on ${id}${service ? ` (${service})` : ''}${l.program ? `: ${l.program}` : ''}`, component_id: id, component_name: id,
      component_type: 'network_service', severity, type: TYPES.EXPOSURE,
      details: { ...l, service, description: `${l.program || 'A process'} accepts connections on ${id}${LOOP.test(String(l.address)) ? ' (loopback only)' : severity === 'info' ? '' : '; this port is reachable from the network and normally hosts a service that should not be exposed unauthenticated'}.` },
    });
  }
  for (const c of arr(rt.containers?.items)) {
    obs({
      rule_id: 'behavior.container', area: 'containers', title: `Container running: ${c.name}`, component_id: c.name, component_name: c.name, component_type: 'container', type: TYPES.BEHAVIOR,
      details: { ...c, description: `Container ${c.name} runs image ${c.image} as ${c.user}${arr(c.published_ports).length ? `, publishing ${c.published_ports.slice(0, 4).join(', ')}` : ''}.` },
    });
  }
  if (rt.containers && rt.containers.status && rt.containers.status !== 'ok') {
    obs({ rule_id: 'coverage.containers', area: 'containers', title: 'Container engine not inspected', component_id: rt.containers.socket ?? 'container engine', component_name: 'container engine', component_type: 'container_engine', severity: 'low', type: TYPES.COVERAGE,
      details: { description: `Containers could not be inspected (${rt.containers.status}${rt.containers.reason ? `: ${rt.containers.reason}` : ''}).`, status: rt.containers.status, reason: rt.containers.reason ?? null } });
  }
  for (const i of arr(rt.inspections)) {
    if (i.ok) obs({ rule_id: 'behavior.inspection', area: 'inspection', title: `Node.js process inspected: ${i.label}`, component_id: i.label, component_name: i.label, type: TYPES.BEHAVIOR,
      details: { ...i, loaded_packages: arr(i.loaded_packages).length, description: `${arr(i.loaded_packages).length} package(s) loaded by the running process were read through the V8 inspector${i.left_open ? ' (the inspector was left open)' : ''}.` } });
    else obs({ rule_id: 'coverage.inspection', area: 'inspection', title: `Node.js process could not be inspected: ${i.label}`, component_id: i.label, component_name: i.label, severity: 'low', type: TYPES.COVERAGE,
      details: { ...i, description: `The V8 inspector could not be used on this process${i.reason ? ` (${i.reason})` : ''}; the packages it loaded are not in this report.` } });
  }

  const known = new Set(out.inventory.map((i) => i.component_id));
  out.inventory.push(...derived.filter((d) => !known.has(d.component_id)));
  out.inventory = dedupeInventory(out.inventory);
  applyFindingStatus(out.inventory, out.findings, { vulnerable: 'at_risk', clean: 'running' });
  // keep the original "running"/"listening"/"loaded" state for components with no findings; applyFindingStatus only overrides 'unknown'

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
      ecosystems: uniq(out.inventory.filter((i) => i.type === 'dependency').map((i) => i.details?.ecosystem)), vulnerability_scan: p.scan_options?.lookups !== false,
      report_id: p.report_id, asset_id: p.asset_id, asset_name: p.asset_name, asset_type: p.asset_type, machine_id: p.machine_id, tool_version: p.tool_version,
    },
  });
  return {
    metadata: meta,
    policy: { profile: p.profile ?? null, flags: p.scan_options ?? {}, gate: opts.fail_on != null ? { fail_on: opts.fail_on } : null, checks: p.checks ?? [] },
    ...out,
    stats_extra: { source: p.stats ?? null, coverage: p.coverage ?? null, compliance_posture: p.compliance_posture ?? null, runtime_summary: rt.summary ?? null, diffs: p.diffs ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}
