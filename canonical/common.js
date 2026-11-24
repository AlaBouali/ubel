'use strict';
// canonical/common.js — helpers shared by every adapter and by the canonical HTML.
// The canonical report (schema 0.1.0) is produced by translating each module's EXISTING payload;
// nothing here re-implements a scanner or changes the original JSON.

import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getOSMetadata } from '../sca/os_metadata.js';

export const SCHEMA_VERSION = '0.1.0';

const ROOT_PKG = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', 'package.json');
let _pkg = null;
export function readPkg() {
  if (_pkg) return _pkg;
  try { _pkg = JSON.parse(fs.readFileSync(ROOT_PKG, 'utf8')); } catch { _pkg = {}; }
  return _pkg;
}

// ── small utils ──────────────────────────────────────────────────────────────
export const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export const arr = (v) => (Array.isArray(v) ? v : []);
export const first = (...vals) => { for (const v of vals) if (v !== undefined && v !== null && v !== '') return v; return null; };
export const clone = (v) => (v === undefined ? undefined : JSON.parse(JSON.stringify(v)));
export const sha = (...parts) => crypto.createHash('sha256').update(parts.map((p) => String(p ?? '')).join('\u0000')).digest('hex').slice(0, 32);
export const slug = (s) => String(s ?? '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 80);
export const uniq = (a) => [...new Set(a.filter((x) => x !== undefined && x !== null && x !== ''))];

export const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5, none: 6 };
export function sev(s) {
  const v = String(s ?? 'unknown').toLowerCase();
  return v in SEV_RANK ? v : (v === 'moderate' ? 'medium' : v === 'informational' ? 'info' : 'unknown');
}

// ── path relativisation ─────────────────────────────────────────────────────
// Filesystem paths become relative to the scanned directory (environment.cwd). A root of "/" (a VM scanned
// from its own root) is left alone: every path there is already root-relative and stripping the slash would
// make "etc/passwd" ambiguous with a package or resource name.
export function makeRel(root) {
  const base = root ? String(root).replace(/[\\/]+$/, '') : '';
  const usable = base.length > 1;
  const fwd = base.split(path.sep).join('/');
  const rel = (p) => {
    if (!usable || typeof p !== 'string') return p;
    for (const b of new Set([base, fwd])) {
      if (p === b) return '.';
      if (p.startsWith(b + '/') || p.startsWith(b + '\\')) return p.slice(b.length + 1);
    }
    return p;
  };
  const text = (s) => {
    if (!usable || typeof s !== 'string' || !s) return s;
    let out = s;
    for (const b of new Set([base, fwd])) out = out.split(b + '/').join('').split(b + '\\').join('').split(b).join('.');
    return out;
  };
  const deep = (v) => {
    if (typeof v === 'string') return text(v);
    if (Array.isArray(v)) return v.map(deep);
    if (isObj(v)) { const o = {}; for (const k of Object.keys(v)) o[k] = deep(v[k]); return o; }
    return v;
  };
  return { rel, text, deep, usable };
}

// ── finding types (short names) ─────────────────────────────────────────────
// One vocabulary for every module. A finding's `type` says what KIND of thing it is, not which scanner produced it.
//   vuln        known advisory on a package / product (CVE, GHSA, OSV …)          infection   package flagged as malicious / compromised
//   sc_vuln / sc_infection   the same two kinds, as reported by the SCA module (its own modals); EASM and app-scan keep vuln / infection
//   secret      hardcoded credential                                             code        weakness in source / bytecode (SAST, malware)
//   misconfig   insecure configuration (cloud, k8s, manifests, headers …)        hardening   missing / present host or binary protection (passed checks too)
//   behavior    what the software does or runs (capabilities, processes, tools)  exposure    reachable network surface (open ports, listeners, remote hosts)
//   license     license obligation / risk of a component                         coverage    part of the scan that could not be (fully) assessed
export const TYPES = {
  VULN: 'vuln', INFECTION: 'infection', SC_VULN: 'sc_vuln', SC_INFECTION: 'sc_infection', SECRET: 'secret', CODE: 'code', MISCONFIG: 'misconfig', HARDENING: 'hardening',
  BEHAVIOR: 'behavior', EXPOSURE: 'exposure', LICENSE: 'license', COVERAGE: 'coverage',
};

// ── finding status ───────────────────────────────────────────────────────────
// `status` (root of every finding) replaces the old `reachable` boolean. One of:
//   "reachable"       the finding applies: the original says it is reachable / exploitable, or makes no claim either way
//   "non reachable"   the original says it is NOT reachable / exploitable (SCA / EASM `reachability.reachable === false`,
//                     SAST `taint.reachable === false` or `taint.exploitable === false`)
//   "false positive"  the original says it is not a real issue (SAST / malware `is_valid === false`)
export const STATUS = { REACHABLE: 'reachable', NON_REACHABLE: 'non reachable', FALSE_POSITIVE: 'false positive' };

export function reachableOf(d) {
  if (!isObj(d)) return null;
  const r = isObj(d.reachability) ? d.reachability.reachable : undefined;
  const t = isObj(d.taint) ? d.taint : null;
  if (r === true || (t && (t.exploitable === true || t.reachable === true))) return true;
  if (r === false || (t && (t.reachable === false || t.exploitable === false))) return false;
  return null;
}

export function statusOf(d) {
  if (!isObj(d)) return STATUS.REACHABLE;
  if (d.is_valid === false || d.false_positive === true) return STATUS.FALSE_POSITIVE;
  return reachableOf(d) === false ? STATUS.NON_REACHABLE : STATUS.REACHABLE;
}

// ── network exposure ─────────────────────────────────────────────────────────
// Severity of a reachable TCP port, by what normally listens there: web and mail are the normal case (info), remote-administration and
// database ports facing a network are worth a look (low / medium), clear-text or unauthenticated-by-default services are not (high).
const PORTS = {
  21: ['FTP', 'medium'], 22: ['SSH', 'low'], 23: ['Telnet', 'high'], 25: ['SMTP', 'info'], 53: ['DNS', 'info'], 80: ['HTTP', 'info'], 110: ['POP3', 'low'],
  111: ['rpcbind', 'medium'], 135: ['MSRPC', 'medium'], 139: ['NetBIOS', 'medium'], 143: ['IMAP', 'low'], 443: ['HTTPS', 'info'], 445: ['SMB', 'high'],
  465: ['SMTPS', 'info'], 587: ['SMTP submission', 'info'], 993: ['IMAPS', 'info'], 995: ['POP3S', 'info'], 1433: ['MS SQL Server', 'medium'], 1521: ['Oracle DB', 'medium'],
  2375: ['Docker API (no TLS)', 'high'], 2376: ['Docker API', 'medium'], 3306: ['MySQL', 'medium'], 3389: ['RDP', 'high'], 5432: ['PostgreSQL', 'medium'],
  5900: ['VNC', 'high'], 5984: ['CouchDB', 'medium'], 6379: ['Redis', 'medium'], 8080: ['HTTP (alt)', 'info'], 8443: ['HTTPS (alt)', 'info'],
  9200: ['Elasticsearch', 'medium'], 11211: ['Memcached', 'medium'], 27017: ['MongoDB', 'medium'],
};
export function portRisk(port) {
  const e = PORTS[Number(port)];
  return e ? { service: e[0], severity: e[1] } : { service: null, severity: 'info' };
}

// ── finding / inventory builders ────────────────────────────────────────────
// finding_id is NOT part of the canonical finding by default; only SAST supplies one (see adapters/sast.js).
// An *observation* (observe() below) is a finding for something that is normal or merely informative: a passed check, a capability,
// a running process, an open port. It never makes its component 'vulnerable' and never violates the policy.
export function mkFinding(o) {
  const f = {};
  if (o.finding_id) f.finding_id = o.finding_id;
  f.rule_id = o.rule_id ?? null;
  f.title = o.title ?? o.rule_id ?? null;
  f.affected_component_id = o.component_id ?? null;
  f.affected_component_name = o.component_name ?? null;
  f.affected_component_type = o.component_type ?? null;
  f.severity = sev(o.severity);
  f.confidence = o.confidence == null ? null : String(o.confidence).toLowerCase();
  f.violate_policy = o.violate_policy === undefined ? null : (o.violate_policy === null ? null : !!o.violate_policy);
  f.status = o.status ?? statusOf(o.details);
  f.type = o.type;
  f.details = o.details ?? {};
  return f;
}

export function observe(o) {
  return mkFinding({
    ...o,
    violate_policy: false,
    severity: o.severity ?? 'info',
    confidence: o.confidence ?? 'high',
    details: { ...(o.details ?? {}), observation: true, category: 'observation' },
  });
}

export const isObservation = (f) => !!(f && f.details && f.details.observation === true);

/**
 * Observations for the checks of a baseline scan (ubel-vm / ubel-k8s / ubel-runtime): a check that PASSED is the normal case (info,
 * same type as its failed counterpart); one that applies but could not be evaluated is a coverage gap (low). Checks that do not apply
 * (n/a) are not findings. Details use the posture finding shape, so the module's own modal renders them.
 */
export function checkObservations(checks, { passType, component_id, component_name, component_type, resource }) {
  const out = [];
  for (const k of arr(checks)) {
    if (!isObj(k) || (k.status !== 'pass' && k.status !== 'unassessed')) continue;
    const pass = k.status === 'pass';
    out.push(observe({
      rule_id: k.check, title: pass ? `${k.title ?? k.check}: passed` : `${k.title ?? k.check}: could not be assessed`,
      component_id: component_id ?? null, component_name: component_name ?? null, component_type: component_type ?? null,
      severity: pass ? 'info' : 'low', type: pass ? passType : TYPES.COVERAGE,
      details: {
        check: k.check, area: k.area ?? '', scope: '', resource: resource ?? component_name ?? '', severity: pass ? 'info' : 'low', rule_severity: k.severity ?? null,
        title: k.title ?? k.check, outcome: k.status, frameworks: arr(k.frameworks), compliance: null,
        description: pass ? 'The check ran and found nothing to report: this part of the baseline is in the expected state.' : `The check applies here but could not be evaluated${k.reason ? `: ${k.reason}` : ''}. A violation, if any, is not in this report.`,
        remediation: pass ? '' : 'Run the scan with the access the check needs (see the reason above), then scan again.',
      },
    }));
  }
  return out;
}

export function mkInventory(o) {
  return {
    component_id: o.component_id ?? null,
    component_name: o.component_name ?? null,
    status: o.status ?? 'unknown',
    violate_policy: o.violate_policy === undefined ? null : (o.violate_policy === null ? null : !!o.violate_policy),
    type: o.type,
    details: o.details ?? {},
  };
}

export const depName = (name, eco, ver) => `${name ?? 'unknown'} (${eco || 'unknown'}) : ${ver ?? 'unknown'}`;

// fail-on threshold ("critical", "high", "N:sev", "none") → predicate on a severity
export function failOnPredicate(failOn) {
  if (failOn == null) return () => null;
  if (isObj(failOn)) failOn = failOn.mode === 'none' ? 'none' : failOn.severity;   // parsed --fail-on of vm / k8s / cloud
  if (failOn == null) return () => null;
  const s = String(failOn).toLowerCase();
  if (s === 'none') return () => false;
  const m = s.match(/^(?:\d+:)?(critical|high|medium|low|info)$/);
  if (!m) return () => null;
  const lim = SEV_RANK[m[1]];
  return (sv) => (SEV_RANK[sev(sv)] ?? 9) <= lim;
}

// ── metadata ────────────────────────────────────────────────────────────────
export function buildMetadata({ payload, opts = {}, scan, os_meta = null, git = null, runtime = {} }) {
  const osm = getOSMetadata("/");   // returns the metadata object itself (it is not a factory)
  const machine_name = `${osm.os_name ?? 'unknown'}: ${osm.os_version ?? 'unknown'}`
  if (scan.scan_type === 'runtime' || scan.scan_scope === 'developer_platform') {
    scan.asset_id=scan.machine_id;
    scan.asset_name=machine_name;
  }
  const pkg = readPkg();
  const live = !!opts.live;
  const g = git || {};
  if (live && !osm.os_id && os.platform() === 'linux') {
    const lm = getLinux();   // returns the metadata object itself (it is not a factory)
    osm.os_id = lm.id ?? null;
    osm.os_name = lm.name ?? null;
    osm.os_version = lm.version ?? null;
    osm.os_release = lm.release ?? null;
  }
  const cwd = opts.cwd ? path.resolve(opts.cwd) : (live ? process.cwd() : null);
  return {
    scan_info: {
      generated_at: scan.generated_at ?? null,
      status: scan.status ?? 'completed',
      called_via: opts.called_via || scan.called_via || 'cli',
      scan_type: scan.scan_type ?? null,
      scan_scope: scan.scan_scope ?? null,
      ecosystems: scan.ecosystems ?? [],
      vulnerability_scan: scan.vulnerability_scan ?? null,
      report_id: scan.report_id ?? null,
      asset_id: scan.asset_id ?? null,
      asset_name: scan.asset_name ?? null,
      asset_type: scan.asset_type ?? null,
      machine_id: scan.machine_id ?? null,
      machine_name: machine_name ?? null,
    },
    tool_info: {
      tool_name: pkg.name ?? '@arcane-spark/ubel-node',
      tool_version: scan.tool_version ?? pkg.version ?? null,
      tool_cli: opts.cli || scan.tool_cli || null,
      license: pkg.license ?? null,
      author: typeof pkg.author === 'string' ? pkg.author.replace(/\s*<[^>]*>\s*/, '').trim() : (pkg.author?.name ?? null),
    },
    environment: {
      os_id: first(osm.os_id, live ? process.platform : null),
      os_name: first(osm.os_name, live ? os.type() : null),
      os_version: first(osm.os_version, live ? os.version() : null),
      os_arch: first(runtime.arch, payload?.arch, live ? process.arch : null),
      os_release: first(osm.os_release, live ? os.release() : null),
      cwd,
      node_version: first(runtime.node_version, live ? process.version : null),
    },
    git_metadata: {
      version: first(g.version),
      url: first(g.url, g.remote_url, g.remote, g.origin),
      branch: first(g.branch),
      latest_commit: first(g.latest_commit, g.commit),
    },
  };
}

// ── stats ───────────────────────────────────────────────────────────────────
const count = (items, fn) => { const o = {}; for (const i of items) { const k = fn(i) ?? 'unknown'; o[k] = (o[k] || 0) + 1; } return o; };

export function buildStats(findings, inventory, source) {
  const bySev = { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 };
  for (const f of findings) bySev[f.severity] = (bySev[f.severity] || 0) + 1;
  return {
    findings: {
      total: findings.length,
      by_severity: bySev,
      by_type: count(findings, (f) => f.type),
      by_status: count(findings, (f) => f.status),
      by_confidence: count(findings, (f) => f.confidence),
      violating_policy: findings.filter((f) => f.violate_policy === true).length,
    },
    inventory: {
      total: inventory.length,
      by_type: count(inventory, (i) => i.type),
      by_status: count(inventory, (i) => i.status),
      violating_policy: inventory.filter((i) => i.violate_policy === true).length,
    },
    source: source ?? null,
  };
}

// Mark inventory components with the worst status of the findings that reference them.
export function applyFindingStatus(inventory, findings, { vulnerable = 'vulnerable', clean = 'clean', infected = 'infected' } = {}) {
  const by = new Map();
  for (const f of findings) {
    const id = f.affected_component_id;
    if (id == null || isObservation(f) || f.status === STATUS.FALSE_POSITIVE) continue;   // normal behaviour / dismissed: not a reason to mark a component
    if (!by.has(id)) by.set(id, []);
    by.get(id).push(f);
  }
  for (const c of inventory) {
    const fs_ = by.get(c.component_id);
    if (!fs_ || !fs_.length) { if (c.status === 'unknown' || c.status === undefined) c.status = clean; continue; }
    c.status = fs_.some((f) => f.type === TYPES.INFECTION || f.type === TYPES.SC_INFECTION) ? infected : vulnerable;
    c.violate_policy = fs_.some((f) => f.violate_policy === true) ? true : (fs_.every((f) => f.violate_policy === false) ? false : c.violate_policy);
  }
  return inventory;
}

// Merge identical inventory components (same id + type), keeping the first.
export function dedupeInventory(list) {
  const seen = new Map();
  for (const c of list) { const k = `${c.type}\u0000${c.component_id}`; if (!seen.has(k)) seen.set(k, c); }
  return [...seen.values()];
}
