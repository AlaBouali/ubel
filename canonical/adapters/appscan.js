'use strict';
// App-scanner family → canonical: ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server.
// They all share one payload (mobile/lib/report.js buildPayload; mcp/lib/report.js reuses it).
// Original keys used: schema, tool, target, apps[], vulnerabilities[], secrets[], misconfigurations[], dependencies[]
// (each with vulnerabilities[]), gate, min_severity, analysis, summary, stats, compliance_summary, executive_summary, diffs.
import { arr, isObj, first, mkFinding, observe, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, TYPES } from '../common.js';

export const family = 'appscan';

// Behavior categories (mobile/lib/behavior.js, binary/lib/behavior.js, package/lib/sourcebehavior.js) → severity of the capability.
// info: what nearly every program does · low: needs a reason · medium: powers that fit surveillance, persistence or evasion · high: attacks other processes.
const BEHAVIOR_SEV = {
  file_io: 'info', network: 'info', ipc: 'info', crypto: 'info', system_info: 'info', reflection: 'info',
  process: 'low', device_access: 'low', native_code: 'low', dynamic_loading: 'low',
  privilege: 'medium', persistence: 'medium', input_capture: 'medium', anti_analysis: 'medium', credentials: 'medium', obfuscation: 'medium',
  injection: 'high',
};
const BEHAVIOR_TITLE = {
  file_io: 'File access', network: 'Network', ipc: 'Inter-app communication', process: 'Process execution', reflection: 'Reflection / dynamic lookup', native_code: 'Native code loading',
  device_access: 'Sensitive device APIs', dynamic_loading: 'Dynamic loading / resolution', injection: 'Debugging / process injection', anti_analysis: 'Anti-analysis', privilege: 'Privilege',
  persistence: 'Persistence', input_capture: 'Input capture / sensitive devices', crypto: 'Cryptography', system_info: 'System fingerprinting', credentials: 'Credential / environment access', obfuscation: 'Obfuscation',
};

// ubel-package --sast (static source analysis): rule ids are `package.sast.<engine rule>`; user rules (--rules-dir) can have any id, including words
// the BEHAVIOUR pattern below looks for ("exfil", "persist" …), so these are always code vulnerabilities, never behavior observations.
const SAST_RULE = /^package\.sast\./;
const HARDENING = /(^|[._-])(pie|relro|canary|fortify|nx|exec[_-]?stack|textrel|rpath|wx|stripped|hardening|bitcode|arc|stack[_-]?protector|no[_-]?gnu[_-]?stack)([._-]|$)/i;
const BEHAVIOUR = /behavio|intent|exfil|beacon|c2\b|dynamic[_-]?load|obfusc|persist|anti[_-]?(debug|analysis)|self[_-]?modif/i;

// Advisories of third-party components. The modules (binary/lib/advisories.js addAdvisoryFindings) also file each advisory as an ordinary
// entry of their own vulnerabilities[] list so their native summary, counts and diffs include it. In the canonical report a dependency's
// advisories exist ONCE, as sc_vuln / sc_infection findings of the dependency (built from dependencies[].vulnerabilities[] below), so those
// module-level copies are dropped here: they would otherwise show up as extra "code" vulnerabilities.
const DEP_ADVISORY_RULES = new Set(['binary.component.vulnerable', 'package.vulnerable', 'package.malicious', 'package.dep.vulnerable', 'package.dep.malicious']);
export const isDepAdvisory = (f) => !!f && (isObj(f.component) && f.component.advisory != null || DEP_ADVISORY_RULES.has(f.rule));

// One advisory on one component, in the shape of the SCA report's vulnerability records (what the SCA vulnerability modal, client/scvuln.js,
// renders): the advisory as the module found it, plus the package it applies to. Fields the advisory already carries are kept.
function scRecord(v, d, cid) {
  return {
    ...v,
    affected_dependency: v.affected_dependency ?? d.name ?? null,
    affected_dependency_version: v.affected_dependency_version ?? d.version ?? null,
    affected_package_id: v.affected_package_id ?? cid,
    ecosystem: v.ecosystem ?? d.ecosystem ?? null,
    url: v.url ?? (v.id ? `https://osv.dev/vulnerability/${encodeURIComponent(v.id)}` : null),
    // reports written before the modules kept the whole fetcher record carry `details` only and no references: the modal reads `description` / `references`
    description: v.description ?? v.details ?? v.summary ?? '',
    references: arr(v.references).length ? v.references : (v.url ? [{ type: 'ADVISORY', url: v.url }] : []),
    affected_dependency_sequences: arr(v.affected_dependency_sequences),
  };
}

// The module's diff against the previous run lists each dependency advisory as an ordinary vulnerability (the same module-level copy that is
// left out of the findings above). The canonical diff keeps those entries, so it covers every finding of the report, but files them the way
// the findings are filed: SCA title and rule id, type sc_vuln / sc_infection, the dependency as artifact. The component comes from the entry
// itself (mobile/index.js diffReports) or, for an entry of an older report, from the matching current finding (same fingerprint).
function dependencyDiffs(d, p) {
  if (!isObj(d) || !isObj(d.vulnerabilities)) return d ?? null;
  const current = new Map(arr(p.vulnerabilities).filter(isDepAdvisory).map((f) => [f.fingerprint, f]));
  const entry = (e) => {
    if (!isDepAdvisory(e)) return e;
    const comp = e.component || current.get(e.fingerprint)?.component;
    const infection = /\.malicious$/.test(e.rule || '');
    const type = infection ? TYPES.SC_INFECTION : TYPES.SC_VULN;
    if (!comp || comp.advisory == null) return { ...e, kind: 'dependency', type };   // identity unknown (older report): keep the module's own wording
    const dname = depName(comp.name, comp.ecosystem, comp.version);
    return { ...e, rule: `${comp.advisory}-${comp.ecosystem ?? 'unknown'}-${comp.name ?? 'unknown'}@${comp.version ?? ''}`, title: `${comp.advisory} affecting ${dname}`, artifact: dname, kind: 'dependency', type };
  };
  const list = (l) => { const seen = new Set(); return arr(l).map(entry).filter((e) => { if (e.kind !== 'dependency') return true; const k = `${e.type}|${e.rule}|${e.artifact}`; if (seen.has(k)) return false; seen.add(k); return true; }); };
  const v = { new: list(d.vulnerabilities.new), unchanged: list(d.vulnerabilities.unchanged), removed: list(d.vulnerabilities.removed) };
  const out = { ...d, vulnerabilities: v };
  if (isObj(d.counts)) out.counts = { ...d.counts, new_vulnerabilities: v.new.length, unchanged_vulnerabilities: v.unchanged.length, fixed_vulnerabilities: v.removed.length };
  return out;
}

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
      component_name: name == null ? null : R.text(String(cid)),
      component_type: 'application',
      severity: f.severity,
      confidence: f.confidence,
      violate_policy: violates(f.severity),
      type,
      details: R.deep(f),
    }));
  };
  for (const f of arr(p.vulnerabilities)) { if (isDepAdvisory(f)) continue; push(f, !SAST_RULE.test(f.rule || '') && BEHAVIOUR.test(f.rule || '') ? TYPES.BEHAVIOR : TYPES.CODE); }
  for (const f of arr(p.secrets)) push(f, TYPES.SECRET);
  for (const f of arr(p.misconfigurations)) push(f, BEHAVIOUR.test(f.rule || '') ? TYPES.BEHAVIOR : (HARDENING.test(f.rule || '') ? TYPES.HARDENING : TYPES.MISCONFIG));

  for (const a of apps) {
    out.inventory.push(mkInventory({ component_id: R.rel(String(appId(a))), component_name: R.text(String(first(a.name, a.id) || appId(a))), status: 'unknown', type: 'application', details: R.deep(a) }));
    const hosts = first(a.remote_hosts?.hosts, a.remote_hosts?.items, a.remote_hosts?.list, a.native_hardening?.remote_hosts?.hosts, null);
    for (const h of arr(hosts)) {
      const v = typeof h === 'string' ? h : first(h.host, h.domain, h.ip, h.value);
      if (!v) continue;
      const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || v.includes(':') && /^[0-9a-f:]+$/i.test(v);
      out.inventory.push(mkInventory({ component_id: v, component_name: v, status: 'observed', type: isIp ? 'ip' : 'domain', details: typeof h === 'string' ? { host: h } : R.deep(h) }));
    }
  }

  // Third-party components: inventory type "dependency"; their advisories are sc_vuln / sc_infection findings titled and keyed exactly like the SCA report's.
  const seenAdvisory = new Set();
  for (const d of arr(p.dependencies)) {
    const cid = first(d.purl, `${d.name}@${d.version ?? ''}`);
    const dname = depName(d.name, d.ecosystem, d.version);
    out.inventory.push(mkInventory({ component_id: cid, component_name: dname, status: d.lookup_status === 'not_queryable' ? 'not_queryable' : 'unknown', type: 'dependency', details: R.deep(d) }));
    for (const v of arr(d.vulnerabilities)) {
      const key = `${cid}\u0000${v.id}`;
      if (seenAdvisory.has(key)) continue;
      seenAdvisory.add(key);
      out.findings.push(mkFinding({
        rule_id: `${v.id}-${d.ecosystem ?? 'unknown'}-${d.name ?? 'unknown'}@${d.version ?? ''}`,   // advisory-ecosystem-pkgname@version (as in the SCA report)
        title: `${v.id} affecting ${dname}`,
        component_id: cid,
        component_name: dname,
        component_type: 'dependency',
        severity: v.severity,
        confidence: d.confidence ?? 'high',
        violate_policy: v.is_policy_violation ?? violates(v.severity),
        type: v.is_infection ? TYPES.SC_INFECTION : TYPES.SC_VULN,
        details: R.deep(scRecord(v, d, cid)),
      }));
    }
  }
  // ── observations (appended after the findings so those keep their positions) ──
  const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
  for (const a of apps) {
    const cid = R.rel(String(appId(a))), cname = R.text(String(first(a.name, a.id)));
    const base = { component_id: cid, component_name: cname, component_type: 'application' };
    // what the code does: one finding per behavior category. Common capabilities are the normal case (info); the rest are rated by what
    // they let code do. Code that is only in third-party library code is rated one level lower.
    for (const [cat, byOrigin] of Object.entries(a.behavior?.categories || {})) {
      const origins = Object.keys(byOrigin || {});
      if (!origins.length) continue;
      const own = origins.some((o) => o !== 'library');
      const sevFull = BEHAVIOR_SEV[cat] ?? 'info';
      const severity = own ? sevFull : LOWER[sevFull];
      const functions = origins.reduce((n, o) => n + (byOrigin[o].functions ?? Object.keys(byOrigin[o].apis || {}).length), 0);
      const calls = origins.reduce((n, o) => n + (byOrigin[o].calls ?? 0), 0);
      const apis = origins.flatMap((o) => Object.entries(byOrigin[o].apis || {}).map(([k, n]) => `${o}: ${k}${n > 1 ? ` ×${n}` : ''}`)).slice(0, 25);
      out.findings.push(observe({
        ...base, rule_id: `behavior.${cat}`, title: `Behavior: ${BEHAVIOR_TITLE[cat] ?? cat.replace(/_/g, ' ')}`, severity, confidence: own ? 'high' : 'medium', type: TYPES.BEHAVIOR,
        details: R.deep({ app: a.id ?? a.package ?? a.name, behavior_category: cat, origins: byOrigin, functions, calls, evidence: apis, artifact: a.name ?? '',
          description: `The code references ${functions} ${BEHAVIOR_TITLE[cat] ? BEHAVIOR_TITLE[cat].toLowerCase() : cat.replace(/_/g, ' ')} function(s)${calls ? ` (${calls} call site(s))` : ''} in ${origins.join(', ')} code. ${severity === 'info' ? 'This is ordinary behavior for software of this kind.' : 'Check that this capability is needed and cannot be abused.'}` }),
      }));
    }
    // remote hosts the files name
    const rh = a.remote_hosts;
    if (rh && arr(rh.hosts).length) {
      const hosts = rh.hosts.map((h) => (typeof h === 'string' ? h : first(h.host, h.domain, h.ip, h.value))).filter(Boolean);
      out.findings.push(observe({
        ...base, rule_id: 'exposure.remote_hosts', title: `Remote hosts referenced (${rh.total ?? hosts.length})`, severity: 'info', type: TYPES.EXPOSURE,
        details: R.deep({ app: a.id ?? a.package ?? a.name, total: rh.total ?? hosts.length, domains: rh.domains ?? null, ips: rh.ips ?? null, evidence: hosts.slice(0, 40), artifact: a.name ?? '',
          description: `${rh.total ?? hosts.length} remote host(s) are named in the files (${hosts.slice(0, 5).join(', ')}${hosts.length > 5 ? ', …' : ''}). Check that each is expected.` }),
      }));
    }
    // MCP: what each tool the server exposes can do, and what was seen of the live server
    for (const tl of arr(a.definitions?.tools)) {
      const caps = arr(tl.capabilities);
      const severity = caps.includes('exec') ? 'medium' : caps.some((c) => ['file_write', 'sql', 'secrets', 'messaging'].includes(c)) ? 'low' : 'info';
      out.findings.push(observe({
        ...base, rule_id: 'behavior.mcp.tool', title: `Tool exposed: ${tl.name}${caps.length ? ` (${caps.join(', ')})` : ''}`, severity, type: TYPES.BEHAVIOR,
        details: R.deep({ app: a.id ?? a.name, tool: tl.name, capabilities: caps, params: tl.params ?? [], annotations: tl.annotations ?? null, artifact: `tools.${tl.name}`,
          description: `${tl.description || 'The server registers this tool.'} ${caps.length ? `It can: ${caps.join(', ')}.` : ''}`.trim() }),
      }));
    }
    for (const o of arr(a.observed)) {
      out.findings.push(observe({
        ...base, rule_id: 'behavior.mcp.process', title: `Server process observed (pid ${o.pid})`, severity: o.uid === 0 ? 'low' : 'info', type: TYPES.BEHAVIOR,
        details: R.deep({ app: a.id ?? a.name, pid: o.pid, uid: o.uid, cmdline: o.cmdline, listening: o.listening ?? [], artifact: a.name ?? '',
          description: `The server runs as uid ${o.uid}${arr(o.listening).length ? ` and listens on ${o.listening.map((l) => `${l.addr}:${l.port}`).join(', ')}` : ''}.` }),
      }));
    }
  }
  // parts of the artifact the scan could not look at: a clean list over incomplete coverage must not read as "all clear"
  for (const gap of arr(p.analysis?.gaps)) {
    out.findings.push(observe({
      component_id: null, component_name: null, component_type: 'application', rule_id: 'coverage.gap', title: 'Part of the artifact could not be analysed', severity: 'low', type: TYPES.COVERAGE,
      details: R.deep({ description: String(typeof gap === 'string' ? gap : JSON.stringify(gap)), artifact: '' }),
    }));
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
    // flags.sast: what the optional static source analysis (ubel-package --sast / --no-llm) ran with and covered: engine, rules, custom rule directories, limits, counts
    policy: { flags: { min_severity: p.min_severity ?? null, hidden_by_filter: p.hidden_by_filter ?? 0, ...(p.sast ? { sast: R.deep(p.sast) } : {}) }, gate: p.gate ?? null, limits: p.limits ?? null, analysis: p.analysis ?? null },
    ...out,
    stats_extra: { source: { summary: p.summary ?? null, stats: p.stats ?? null, dependency_summary: p.dependency_summary ?? null }, diffs: dependencyDiffs(p.diffs, p), notes: p.analysis_notes ?? null },
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}

// The module's own payload, rebuilt from a canonical report. Only used to call the module's server-side renderer
// (mobile/lib/report.js buildHtml) for the executive-summary section, which that template renders on the server.
export function restore(c) {
  const si = c.metadata?.scan_info || {}, st = c.stats || {}, src = st.source || {}, pol = c.policy || {};
  const own = (f) => ![TYPES.VULN, TYPES.INFECTION, TYPES.SC_VULN, TYPES.SC_INFECTION].includes(f.type);
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
    limits: pol.limits, analysis: pol.analysis, gate: pol.gate, min_severity: pol.flags?.min_severity, hidden_by_filter: pol.flags?.hidden_by_filter, ...(pol.flags?.sast ? { sast: pol.flags.sast } : {}),
    compliance_summary: c.compliance_summary, executive_summary: c.executive_summary, diffs: st.diffs,
  };
}
