'use strict';
// App-scanner family → canonical: ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server.
// They all share one payload (mobile/lib/report.js buildPayload; mcp/lib/report.js reuses it).
// Original keys used: schema, tool, target, apps[], vulnerabilities[], secrets[], misconfigurations[], dependencies[]
// (each with vulnerabilities[]), gate, min_severity, analysis, summary, stats, compliance_summary, executive_summary, diffs.
// A finding's canonical `type` is not guessed from its rule's name: the rule catalogs (mobile/lib/rules.js, package/lib/rules.js, mcp/lib/rules.js)
// give every rule its type and the finding carries it as `finding_type`; see resolveType below for the order and for what is left of the old guess.
//
// finding_id (every finding, so a dashboard can follow, assign and close one from one scan to the next):
//   module findings (vulnerabilities[] / secrets[] / misconfigurations[], any type)
//                              sha256(rule + app + where in the app [+ the secret's fingerprint / redacted preview]); see findingId below
//   dependency advisories      sha256("advisory-ecosystem-pkgname@version"), exactly as the SCA report keys them
//   observations               sha256 of what they are about (app + artifact [+ origin]), never a pid or a count (see below)
import { arr, isObj, first, mkFinding, observe, mkInventory, depName, makeRel, uniq, applyFindingStatus, dedupeInventory, failOnPredicate, listenerRisk, isLoopback, sha, TYPES, isFindingType } from '../common.js';
import { catalogType } from '../../mobile/lib/rules.js';
import '../../package/lib/rules.js';   // the package and MCP catalogs register their rules in the shared table (mobile/lib/rules.js) when imported
import '../../mcp/lib/rules.js';

export const family = 'appscan';

// Observations (type behavior / exposure / coverage) are filed ONE PER THING OBSERVED, and the thing observed is an inventory entry of its own, so a
// dashboard can triage, assign and close each one separately and a component's page lists exactly what was seen on it:
//   behavior.<category>        one per API / function the code references, per origin (app code, library …) → inventory `api`
//   exposure.remote_host       one per remote host the files name → inventory `domain` / `ip` (shared by every app that names it)
//   behavior.mcp.tool[.<cap>]  one per capability of each tool an MCP server exposes (one per tool when it has none) → inventory `tool`
//   behavior.mcp.process       one per server process seen running → inventory `process`
//   exposure.listener.<port>   one per socket such a process listens on → inventory `network_service`
//   coverage.*                 one per part of the artifact the scan could not read, or list the module cut off; tied to the app when there is one
// Every observation has a finding_id derived from what it is about (app + artifact [+ origin]), never from a pid or a count, so it is the same
// observation in the next scan.

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

// ubel-package's static source analysis (always on): the SAST engine files `package.sast.<engine rule>` (type vuln), the malware engine files
// `package.mal.<engine rule>` (type mal), exactly the types ubel-sast / ubel-mal give their findings. User rules (--rules-dir) can have any id,
// including words the BEHAVIOUR pattern below looks for ("exfil", "persist" …), so these are never behavior observations.
// SAST_RULE, MAL_RULE, HARDENING and BEHAVIOUR are what remains of the old guess from a rule's name: resolveType uses them only for a rule no catalog knows.
const SAST_RULE = /^package\.sast\./;
const MAL_RULE = /^package\.mal\./;
const HARDENING = /(^|[._-])(pie|relro|canary|fortify|nx|exec[_-]?stack|textrel|rpath|wx|stripped|hardening|bitcode|arc|stack[_-]?protector|no[_-]?gnu[_-]?stack)([._-]|$)/i;
const BEHAVIOUR = /behavio|intent|exfil|beacon|c2\b|dynamic[_-]?load|obfusc|persist|anti[_-]?(debug|analysis)|self[_-]?modif/i;

/**
 * The canonical type of one finding of the module's vulnerabilities[] / secrets[] / misconfigurations[] list, and how it was found:
 *   field     the finding says it itself (`finding_type`, written by Findings.add from the rule's catalog entry, or the finding's own override)
 *   catalog   a report written before that field existed: the catalog's type for the rule id
 *   prefix    package.sast.* / package.mal.* rules, which the package scanner registers only when the engine fires
 *   fallback  a rule no catalog knows (a scanner newer than this file, a user's rule id): the old guess from the list and the rule's name.
 *             This is the only way to `code`, and tests/finding-types.test.js proves no catalog rule ever gets here.
 */
export function resolveType(f, list) {
  const rule = String(f?.rule || '');
  if (isFindingType(f?.finding_type)) return { type: f.finding_type, via: 'field' };
  const known = catalogType(rule);
  if (known) return { type: known, via: 'catalog' };
  if (SAST_RULE.test(rule)) return { type: TYPES.VULN, via: 'prefix' };
  if (MAL_RULE.test(rule)) return { type: TYPES.MAL, via: 'prefix' };
  if (list === 'secrets') return { type: TYPES.SECRET, via: 'fallback' };
  if (BEHAVIOUR.test(rule)) return { type: TYPES.BEHAVIOR, via: 'fallback' };
  if (list === 'misconfigurations') return { type: HARDENING.test(rule) ? TYPES.HARDENING : TYPES.MISCONFIG, via: 'fallback' };
  return { type: TYPES.CODE, via: 'fallback' };
}

// Advisories of third-party components. The modules (binary/lib/advisories.js addAdvisoryFindings) also file each advisory as an ordinary
// entry of their own vulnerabilities[] list so their native summary, counts and diffs include it. In the canonical report a dependency's
// advisories exist ONCE, as sc_vuln / sc_infection findings of the dependency (built from dependencies[].vulnerabilities[] below), so those
// module-level copies are dropped here: they would otherwise show up as extra vulnerabilities of the module.
const DEP_ADVISORY_RULES = new Set(['binary.component.vulnerable', 'package.vulnerable', 'package.malicious', 'package.dep.vulnerable', 'package.dep.malicious']);
export const isDepAdvisory = (f) => !!f && (isObj(f.component) && f.component.advisory != null || DEP_ADVISORY_RULES.has(f.rule));

// The rule id of one advisory on one component: advisory-ecosystem-pkgname@version (as in the SCA report). Its sha256 is the finding_id, so the
// same advisory on the same package has the same id here and in the SCA report, scan after scan.
const advisoryRule = (adv, d) => `${adv}-${d.ecosystem ?? 'unknown'}-${d.name ?? 'unknown'}@${d.version ?? ''}`;

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
// An entry whose dependency is known also carries the finding_id of the canonical finding it stands for.
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
    const rule = advisoryRule(comp.advisory, comp);
    return { ...e, rule, finding_id: sha(rule), title: `${comp.advisory} affecting ${dname}`, artifact: dname, kind: 'dependency', type };
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

  // finding_id of one module finding (vulnerabilities[] / secrets[] / misconfigurations[], whatever its type): what it is and where it is.
  //   rule      the check that fired
  //   app       the application it is about (the relative path / id the inventory uses)
  //   where     the entry / file inside the app the module points at (artifact, file, path, location), made relative: never a line number,
  //             an offset, a pid or a count, which move between scans of the same code
  //   secret    a secret also adds the scanner's fingerprint (itself a hash: the secret is never part of the id) or, without one, its redacted
  //             preview, as in the SCA report: two secrets of one rule in one file are two findings
  // Findings that still share all of these (the same rule firing twice at the same place) are numbered in report order, so every finding of a
  // report has an id of its own; the first one keeps the plain hash, which is the one a fixed duplicate leaves behind.
  const idCount = new Map();
  const whereOf = (f) => {
    const loc = isObj(f.location) ? first(f.location.file, f.location.path, f.location.entry) : f.location;
    const w = first(f.artifact, f.file, f.path, f.file_path, f.entry, loc);
    return w == null || isObj(w) ? '' : R.rel(String(w));
  };
  const findingId = (f, list, cid) => {
    const secret = list === 'secrets' ? String(first(f.fingerprint, f.match_preview, f.redacted) ?? '') : '';
    const base = sha(String(f.rule ?? ''), cid ?? '', whereOf(f), secret);
    const n = idCount.get(base) ?? 0;
    idCount.set(base, n + 1);
    return n ? sha(base, n) : base;
  };

  const push = (f, list) => {
    const a = appFor(f.app);
    const cid = a ? appId(a) : first(f.app, f.artifact);
    const name = a ? first(a.name, a.id) : first(f.app, f.artifact);
    const compId = cid == null ? null : R.rel(String(cid));
    out.findings.push(mkFinding({
      finding_id: findingId(f, list, compId),
      rule_id: f.rule,
      title: f.title,
      component_id: compId,
      component_name: name == null ? null : R.text(String(cid)),
      component_type: 'application',
      severity: f.severity,
      confidence: f.confidence,
      violate_policy: violates(f.severity),
      type: resolveType(f, list).type,
      details: R.deep(f),
    }));
  };
  for (const f of arr(p.vulnerabilities)) {
    if (isDepAdvisory(f)) continue;
    push(f, 'vulnerabilities');
  }
  for (const f of arr(p.secrets)) push(f, 'secrets');
  for (const f of arr(p.misconfigurations)) push(f, 'misconfigurations');

  // Remote hosts the files name: the module keeps the list under one of these keys, depending on its version. A host is one inventory entry
  // however many apps name it (`referenced_by` lists them); each reference is an observation of its own, below.
  const hostsOf = (a) => [a.remote_hosts?.hosts, a.remote_hosts?.items, a.remote_hosts?.list, a.native_hardening?.remote_hosts?.hosts].find((l) => arr(l).length) ?? [];
  const hostValue = (h) => (typeof h === 'string' ? h : first(h?.host, h?.domain, h?.ip, h?.value));
  const isIpHost = (v) => /^\d{1,3}(\.\d{1,3}){3}$/.test(v) || (v.includes(':') && /^[0-9a-f:]+$/i.test(v));
  const hostInv = new Map();

  for (const a of apps) {
    out.inventory.push(mkInventory({ component_id: R.rel(String(appId(a))), component_name: R.text(String(first(a.name, a.id) || appId(a))), status: 'unknown', type: 'application', details: R.deep(a) }));
    const appName = R.text(String(first(a.name, a.id) || appId(a)));
    for (const h of hostsOf(a)) {
      const v = hostValue(h);
      if (!v) continue;
      const seen = hostInv.get(v);
      if (seen) { if (!seen.details.referenced_by.includes(appName)) seen.details.referenced_by.push(appName); continue; }
      const entry = mkInventory({ component_id: v, component_name: v, status: 'observed', type: isIpHost(v) ? 'ip' : 'domain', details: { ...(typeof h === 'string' ? { host: h } : R.deep(h)), referenced_by: [appName] } });
      hostInv.set(v, entry);
      out.inventory.push(entry);
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
      const rule = advisoryRule(v.id, d);
      out.findings.push(mkFinding({
        rule_id: rule,
        finding_id: sha(rule),
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
  // One finding per thing observed; the thing observed is an inventory entry (see the header of this file). `artifact()` adds an entry once.
  const LOWER = { critical: 'high', high: 'medium', medium: 'low', low: 'info', info: 'info' };
  const catLabel = (cat) => BEHAVIOR_TITLE[cat] ?? cat.replace(/_/g, ' ');
  const seenInv = new Map();
  const artifact = (entry) => {
    const k = `${entry.type}\u0000${entry.component_id}`;
    if (!seenInv.has(k)) { seenInv.set(k, entry); out.inventory.push(entry); }
    return seenInv.get(k);
  };
  const TOOL_CAP_SEV = (c) => (c === 'exec' ? 'medium' : ['file_write', 'sql', 'secrets', 'messaging'].includes(c) ? 'low' : 'info');

  for (const a of apps) {
    const cid = R.rel(String(appId(a))), cname = R.text(String(first(a.name, a.id)));
    const aref = a.id ?? a.package ?? a.name;
    const appBase = { component_id: cid, component_name: cname, component_type: 'application' };

    // What the code does: one finding per API / function, per origin. Common capabilities are the normal case (info); the rest are rated by
    // what they let code do. An API that only third-party library code references is rated one level lower.
    for (const [cat, byOrigin] of Object.entries(a.behavior?.categories || {})) {
      const sevFull = BEHAVIOR_SEV[cat] ?? 'info';
      for (const [origin, o] of Object.entries(byOrigin || {})) {
        const library = origin === 'library';
        const severity = library ? LOWER[sevFull] : sevFull;
        const apis = Object.entries(o?.apis || {});
        for (const [api, n] of apis) {
          const aid = `${cid}::${cat}::${api}`;
          const inv = artifact(mkInventory({ component_id: aid, component_name: R.text(api), status: 'observed', type: 'api', details: R.deep({ app: cid, application: cname, behavior_category: cat, behavior_label: catLabel(cat), api, origins: {} }) }));
          inv.details.origins[origin] = { calls: n };
          out.findings.push(observe({
            component_id: aid, component_name: R.text(api), component_type: 'api',
            rule_id: `behavior.${cat}`, finding_id: sha('behavior', cid, cat, origin, api),
            title: `Behavior: ${catLabel(cat)} — ${api} (${origin} code)`, severity, confidence: library ? 'medium' : 'high', type: TYPES.BEHAVIOR,
            details: R.deep({ app: aref, application: cname, behavior_category: cat, origin, api, calls: n, basis: o.basis ?? null, evidence: [`${origin}: ${api}${n > 1 ? ` ×${n}` : ''}`], artifact: api,
              description: `The ${origin} code references ${api} (${catLabel(cat).toLowerCase()})${n > 1 ? `, ${n} times` : ''}. ${severity === 'info' ? 'This is ordinary behavior for software of this kind.' : 'Check that this capability is needed and cannot be abused.'}` }),
          }));
        }
        // the module lists at most N entries per category and origin: say so rather than let the list read as complete
        const total = o?.functions ?? apis.length;
        if (total > apis.length) {
          out.findings.push(observe({
            ...appBase, rule_id: 'coverage.behavior_apis', finding_id: sha('coverage.behavior_apis', cid, cat, origin),
            title: `Behavior: ${catLabel(cat)} — ${total - apis.length} more not listed (${origin} code)`, severity: 'info', type: TYPES.COVERAGE,
            details: R.deep({ app: aref, behavior_category: cat, origin, functions: total, listed: apis.length, artifact: cname,
              description: `The ${origin} code references ${total} ${catLabel(cat).toLowerCase()} function(s); the report lists the ${apis.length} most used. The others are not in this report.` }),
          }));
        }
      }
    }

    // Remote hosts the files name: one finding per host. A clear-text scheme, or a flag the module put on the host, is worth a look (low).
    const hosts = hostsOf(a);
    for (const h of hosts) {
      const v = hostValue(h);
      if (!v) continue;
      const rec = typeof h === 'string' ? { host: h } : h;
      const flags = arr(rec.flags);
      const severity = rec.cleartext || flags.length ? 'low' : 'info';
      out.findings.push(observe({
        component_id: v, component_name: v, component_type: isIpHost(v) ? 'ip' : 'domain',
        rule_id: 'exposure.remote_host', finding_id: sha('exposure.remote_host', cid, v),
        title: `Remote host referenced: ${v}`, severity, type: TYPES.EXPOSURE,
        details: R.deep({ app: aref, application: cname, ...rec, host: v, evidence: [...arr(rec.seen_in).map((x) => `seen in ${x}`), ...arr(rec.examples).map(String)].slice(0, 20), artifact: v,
          description: `${cname} names ${v}${rec.refs ? ` (${rec.refs} reference${rec.refs === 1 ? '' : 's'})` : ''}${rec.cleartext ? ' over a clear-text scheme' : ''}${rec.private ? '; it is a private or local address' : ''}${flags.length ? `; flagged: ${flags.join(', ').replace(/_/g, ' ')}` : ''}. The scan cannot tell whether it is contacted: check that it is expected.` }),
      }));
    }
    const knownHosts = a.remote_hosts?.total ?? hosts.length;
    if (knownHosts > hosts.length) {
      out.findings.push(observe({
        ...appBase, rule_id: 'coverage.remote_hosts', finding_id: sha('coverage.remote_hosts', cid),
        title: `Remote hosts: ${knownHosts - hosts.length} more not listed`, severity: 'info', type: TYPES.COVERAGE,
        details: R.deep({ app: aref, total: knownHosts, listed: hosts.length, artifact: cname,
          description: `The files name ${knownHosts} remote host(s); the report lists the ${hosts.length} most referenced. The others are not in this report.` }),
      }));
    }

    // MCP: what each tool the server exposes can do, one finding per capability (one per tool when it declares none)
    for (const tl of arr(a.definitions?.tools)) {
      const tname = String(tl.name ?? 'unnamed');
      const caps = arr(tl.capabilities);
      const tid = `${cid}::tool::${tname}`;
      artifact(mkInventory({ component_id: tid, component_name: tname, status: 'observed', type: 'tool', details: R.deep({ app: cid, application: cname, name: tname, description: tl.description ?? null, capabilities: caps, params: tl.params ?? [], annotations: tl.annotations ?? null }) }));
      for (const cap of (caps.length ? caps : [null])) {
        out.findings.push(observe({
          component_id: tid, component_name: tname, component_type: 'tool',
          rule_id: cap ? `behavior.mcp.tool.${cap}` : 'behavior.mcp.tool', finding_id: sha('behavior.mcp.tool', cid, tname, cap ?? ''),
          title: cap ? `Tool ${tname} can: ${cap}` : `Tool exposed: ${tname}`, severity: cap ? TOOL_CAP_SEV(cap) : 'info', type: TYPES.BEHAVIOR,
          details: R.deep({ app: aref, application: cname, tool: tname, capability: cap, params: tl.params ?? [], annotations: tl.annotations ?? null, artifact: `tools.${tname}`,
            description: `${tl.description || 'The server registers this tool.'}${cap ? ` It can: ${cap}.` : ''}`.trim() }),
        }));
      }
    }

    // MCP: the server processes seen running, and each socket they listen on
    const nth = new Map();
    for (const o of arr(a.observed)) {
      const cmd = Array.isArray(o.cmdline) ? o.cmdline.join(' ') : String(o.cmdline ?? '');
      const key = sha(cmd).slice(0, 12), i = nth.get(key) ?? 0;
      nth.set(key, i + 1);
      const pid = `${cid}::process::${key}${i ? `#${i}` : ''}`;
      const listening = arr(o.listening).filter((l) => isObj(l) && l.port != null);
      artifact(mkInventory({ component_id: pid, component_name: `${cmd || 'process'} (pid ${o.pid})`, status: 'running', type: 'process', details: R.deep({ app: cid, application: cname, pid: o.pid, uid: o.uid, cmdline: o.cmdline, listening: listening.map((l) => `${l.addr}:${l.port}`) }) }));
      out.findings.push(observe({
        component_id: pid, component_name: `${cmd || 'process'} (pid ${o.pid})`, component_type: 'process',
        rule_id: 'behavior.mcp.process', finding_id: sha('behavior.mcp.process', cid, cmd, i),
        title: `Server process observed (pid ${o.pid})`, severity: o.uid === 0 ? 'low' : 'info', type: TYPES.BEHAVIOR,
        details: R.deep({ app: aref, application: cname, pid: o.pid, uid: o.uid, cmdline: o.cmdline, listening: listening.map((l) => `${l.addr}:${l.port}`), artifact: cname,
          description: `The server runs as uid ${o.uid}${listening.length ? ` and listens on ${listening.map((l) => `${l.addr}:${l.port}`).join(', ')}` : ''}.` }),
      }));
      for (const l of listening) {
        const lid = `${l.addr}:${l.port}`;
        const { service, severity } = listenerRisk(l.addr, l.port);
        artifact(mkInventory({ component_id: lid, component_name: lid, status: 'listening', type: 'network_service', details: { address: l.addr, port: l.port, program: cmd, scope: cname, service } }));
        out.findings.push(observe({
          component_id: lid, component_name: lid, component_type: 'network_service',
          rule_id: `exposure.listener.${l.port}`, finding_id: sha('exposure.listener', cid, l.addr, l.port),
          title: `Listening on ${lid}${service ? ` (${service})` : ''}`, severity, type: TYPES.EXPOSURE,
          details: R.deep({ app: aref, application: cname, address: l.addr, port: l.port, service, program: cmd, pid: o.pid, artifact: lid,
            description: `${cname} accepts connections on ${lid}${isLoopback(l.addr) ? ' (loopback only)' : severity === 'info' ? '' : '; this port is reachable from the network and normally hosts a service that should not be exposed unauthenticated'}.` }),
        }));
      }
    }
  }

  // Parts of the artifact the scan could not look at: a clean list over incomplete coverage must not read as "all clear". One finding per gap, on
  // the app when the report has exactly one (a gap names no app, so with several it stays unattached).
  const gapApp = apps.length === 1 ? apps[0] : null;
  const gapId = gapApp ? R.rel(String(appId(gapApp))) : null, gapName = gapApp ? R.text(String(first(gapApp.name, gapApp.id))) : null;
  for (const gap of arr(p.analysis?.gaps)) {
    const text = String(typeof gap === 'string' ? gap : JSON.stringify(gap));
    out.findings.push(observe({
      component_id: gapId, component_name: gapName, component_type: 'application', rule_id: 'coverage.gap', finding_id: sha('coverage.gap', gapId ?? '', text),
      title: `Part of the artifact could not be analysed: ${text.length > 90 ? `${text.slice(0, 87)}…` : text}`, severity: 'low', type: TYPES.COVERAGE,
      details: R.deep({ description: text, artifact: gapName ?? '' }),
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
    // flags.sast: what the static source analysis of ubel-package (SAST + malware engines) ran with and covered: engines, rules, custom rule directories, limits, counts
    policy: { flags: { min_severity: p.min_severity ?? null, hidden_by_filter: p.hidden_by_filter ?? 0, ...(p.sast ? { sast: R.deep(p.sast) } : {}) }, gate: p.gate ?? null, limits: p.limits ?? null, analysis: p.analysis ?? null },
    ...out,
    stats_extra: { source: { summary: p.summary ?? null, stats: p.stats ?? null, dependency_summary: p.dependency_summary ?? null }, notes: p.analysis_notes ?? null },
    diffs: dependencyDiffs(p.diffs, p),
    compliance_summary: p.compliance_summary ?? null,
    executive_summary: p.executive_summary ?? null,
  };
}

// The module's own payload, rebuilt from a canonical report. Only used to call the module's server-side renderer
// (mobile/lib/report.js buildHtml) for the executive-summary section, which that template renders on the server.
export function restore(c) {
  const si = c.metadata?.scan_info || {}, st = c.stats || {}, src = st.source || {}, pol = c.policy || {};
  // the module's own findings: not a dependency's advisory (`vuln` is a source vulnerability here; only canonical files written long ago used it for an advisory)
  const own = (f) => ![TYPES.INFECTION, TYPES.SC_VULN, TYPES.SC_INFECTION].includes(f.type);
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
    compliance_summary: c.compliance_summary, executive_summary: c.executive_summary, diffs: c.diffs ?? st.diffs,
  };
}