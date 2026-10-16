// easm/lib/diffs.js
//
// The "Diffs" tab of the EASM report: what changed since the previous report of
// the same type for the same asset (same history folder, same tag). Mirrors the
// SCA Diffs tab (sca/engine.js buildDiffs) with EASM categories:
//
//   ips, domains, ports, misconfigs, techs, secrets, findings (per tech),
//   compliance (per framework: findings new / unchanged / resolved)
//
// Each category is { new, unchanged, removed } (arrays of display rows) or null
// when the two reports can't be compared on it (e.g. secrets when either run did
// not scan for them, compliance when the previous report has no mapping), so a
// gap in the older report is never read as "everything is new / removed".

import { loadPreviousReport } from "../../sca/engine.js";

const IPV4 = /^\d{1,3}(\.\d{1,3}){3}$/;
// --min-severity filters the vulnerability list BEFORE a report is built, so two
// runs with different filters hold different sets of findings. Same rank order as
// report_output.js (not imported from there: report_output imports this file).
const SEV_RANK = { infection: -1, critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };
const minRankOf = (r) => SEV_RANK[String(r?.scan_options?.min_severity || "unknown").toLowerCase()] ?? 4;
const sevRankOf = (v) => SEV_RANK[v.is_infection ? "infection" : String(v.severity || "unknown").toLowerCase()] ?? 4;

/** The vulnerabilities of `r` at or above `minRank` (infections always pass). */
const vulnsAtOrAbove = (r, minRank) => arr(r.vulnerabilities).filter((v) => sevRankOf(v) <= minRank);

const arr = (x) => (Array.isArray(x) ? x : []);
const num = (a, b) => String(a).localeCompare(String(b), undefined, { numeric: true });

// ── extraction: one Map(key -> row) per category, from a report payload ──────

function scopeRows(r) {
  if (Array.isArray(r.scope) && r.scope.length) return r.scope;
  // Reports without `scope`: rebuild the minimum from hosts[] / assets[].
  const rows = new Map();
  for (const h of arr(r.hosts)) {
    const name = String(h.host || "").toLowerCase();
    if (!name) continue;
    rows.set(`ip:${name}`, { type: IPV4.test(name) ? "ip" : "subdomain", name, subdomains: arr(h.resolved_from), open_ports: arr(h.open_ports), http_ports: arr(h.http_ports), ips: [] });
    for (const s of arr(h.resolved_from)) {
      const k = `subdomain:${String(s).toLowerCase()}`;
      if (!rows.has(k)) rows.set(k, { type: "subdomain", name: String(s).toLowerCase(), ips: [], subdomains: [] });
      rows.get(k).ips.push(name);
    }
  }
  return [...rows.values()];
}

function exIps(r) {
  const out = new Map();
  for (const s of scopeRows(r)) {
    if (s.type !== "ip") continue;
    out.set(s.name, { ip: s.name, domains: arr(s.subdomains).join(", "), status: s.status || "" });
  }
  return out;
}

function exDomains(r) {
  const out = new Map();
  for (const s of scopeRows(r)) {
    if (s.type !== "subdomain") continue;
    out.set(s.name, { domain: s.name, ips: arr(s.ips).join(", "), status: s.status || "" });
  }
  return out;
}

function exPorts(r) {
  const out = new Map();
  for (const s of scopeRows(r)) {
    // Ports belong to the IP that was port-scanned; a subdomain's own ports are
    // only listed when it has no IP row behind it (ubel-url / ubel-domain).
    if (s.type === "subdomain" && arr(s.ips).length) continue;
    const http = new Set(arr(s.http_ports).map(String));
    const ports = arr(s.type === "ip" ? s.open_ports : s.scanned_ports);
    for (const p of ports) {
      const port = String(p);
      out.set(`${s.name}:${port}`, { host: s.name, port, http: http.has(port) || (s.type !== "ip") });
    }
    for (const p of http) if (!out.has(`${s.name}:${p}`)) out.set(`${s.name}:${p}`, { host: s.name, port: p, http: true });
  }
  return out;
}

function exMisconfigs(r) {
  const out = new Map();
  for (const m of arr(r.misconfigurations)) {
    const targets = arr(m.targets).length ? m.targets : [""];
    for (const t of targets) {
      const key = `${m.id}::${t}`;
      if (!out.has(key)) out.set(key, { id: m.id, title: m.title || m.id, severity: m.severity || "unknown", category: m.category || "", target: t });
    }
  }
  return out;
}

const techOf = (r) => {
  const byId = new Map(arr(r.inventory).map((c) => [c.id, c]));
  return (id) => byId.get(id) || null;
};

function exTechs(r) {
  const out = new Map();
  for (const c of arr(r.inventory)) {
    const key = `${c.name}::${c.version || ""}`;
    if (!out.has(key)) out.set(key, { name: c.name, version: c.version || "", hosts: 0 });
    out.get(key).hosts += arr(c.assets).length;
  }
  return out;
}

function exSecrets(r) {
  // A run that did not scan for secrets must not read as "all secrets removed".
  if (r.scan_options && r.scan_options.scan_secrets === false) return null;
  if (!Array.isArray(r.secrets)) return null;
  const out = new Map();
  for (const f of r.secrets) {
    const key = `${f.id}::${f.url || ""}::${f.match_preview ?? ""}`;
    if (!out.has(key)) out.set(key, { id: f.id, title: f.title || "", severity: f.severity || "unknown", url: f.url || "", line: f.line ?? null, match_preview: f.match_preview ?? "" });
  }
  return out;
}

function exFindings(r, ctx) {
  const tech = techOf(r);
  const out = new Map();
  for (const v of vulnsAtOrAbove(r, ctx.minRank)) {
    const c = tech(v.affected_package_id);
    const name = c ? c.name : v.affected_package_id || "unknown";
    const version = c ? c.version || "" : "";
    const key = `${v.id}::${name}@${version}`;
    if (!out.has(key)) out.set(key, { id: v.id, title: v.title || "", severity: v.is_infection ? "infection" : v.severity || "unknown", tech: name, version });
  }
  return out;
}

// Every finding kind with its compliance mapping, for the per-framework diff.
function exComplianceItems(r, withSecrets, ctx) {
  const tech = techOf(r);
  const out = new Map();
  for (const v of vulnsAtOrAbove(r, ctx.minRank)) {
    const c = tech(v.affected_package_id);
    const where = c ? `${c.name}@${c.version || ""}` : v.affected_package_id || "unknown";
    const key = `vuln::${v.id}::${where}`;
    if (!out.has(key)) out.set(key, { kind: "vuln", id: v.id, title: v.title || "", severity: v.severity, where, frameworks: v.compliance?.frameworks || [] });
  }
  for (const m of arr(r.misconfigurations)) {
    const targets = arr(m.targets).length ? m.targets : [""];
    for (const t of targets) {
      const key = `misconfig::${m.id}::${t}`;
      if (!out.has(key)) out.set(key, { kind: "misconfig", id: m.id, title: m.title || "", severity: m.severity, where: t, frameworks: m.compliance?.frameworks || [] });
    }
  }
  if (withSecrets) {
    for (const f of arr(r.secrets)) {
      const key = `secret::${f.id}::${f.url || ""}::${f.match_preview ?? ""}`;
      if (!out.has(key)) out.set(key, { kind: "secret", id: f.id, title: f.title || "", severity: f.severity, where: `${f.url || ""}${f.line != null ? ":" + f.line : ""}`, frameworks: f.compliance?.frameworks || [] });
    }
  }
  return out;
}

function diffCompliance(cur, prev, ctx) {
  if (!cur.compliance_summary || !prev.compliance_summary) return null;
  const withSecrets = !!(exSecrets(cur) && exSecrets(prev));
  const fwMeta = new Map();
  const perFw = (items) => {
    const m = new Map();
    for (const [key, it] of items) {
      for (const fw of it.frameworks) {
        if (!fwMeta.has(fw.id)) fwMeta.set(fw.id, { id: fw.id, name: fw.name, version: fw.version ?? null });
        if (!m.has(fw.id)) m.set(fw.id, new Map());
        m.get(fw.id).set(key, { kind: it.kind, id: it.id, title: it.title, severity: it.severity, where: it.where, controls: arr(fw.controls).map((c) => c.id).join(", ") });
      }
    }
    return m;
  };
  const c = perFw(exComplianceItems(cur, withSecrets, ctx)), o = perFw(exComplianceItems(prev, withSecrets, ctx));
  const sortBy = (a, b) => a.kind.localeCompare(b.kind) || num(a.id, b.id) || num(a.where, b.where);
  const frameworks = [...fwMeta.values()].map((meta) => {
    const cm = c.get(meta.id) || new Map(), om = o.get(meta.id) || new Map();
    return {
      ...meta,
      new:       [...cm].filter(([k]) => !om.has(k)).map(([, e]) => e).sort(sortBy),
      unchanged: [...cm].filter(([k]) => om.has(k)).map(([, e]) => e).sort(sortBy),
      removed:   [...om].filter(([k]) => !cm.has(k)).map(([, e]) => e).sort(sortBy),
    };
  }).sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return { includes_secrets: withSecrets, frameworks };
}

// ── diff ─────────────────────────────────────────────────────────────────────

const CATEGORIES = [
  ["ips",        exIps,        (a, b) => num(a.ip, b.ip)],
  ["domains",    exDomains,    (a, b) => num(a.domain, b.domain)],
  ["ports",      exPorts,      (a, b) => num(a.host, b.host) || num(a.port, b.port)],
  ["misconfigs", exMisconfigs, (a, b) => num(a.id, b.id) || num(a.target, b.target)],
  ["techs",      exTechs,      (a, b) => num(a.name, b.name) || num(a.version, b.version)],
  ["secrets",    exSecrets,    (a, b) => num(a.url, b.url) || num(a.id, b.id)],
  ["findings",   exFindings,   (a, b) => num(a.tech, b.tech) || num(a.version, b.version) || num(a.id, b.id)],
];

function split(cur, old, sortBy) {
  if (!cur || !old) return null;
  return {
    new:       [...cur].filter(([k]) => !old.has(k)).map(([, e]) => e).sort(sortBy),
    unchanged: [...cur].filter(([k]) => old.has(k)).map(([, e]) => e).sort(sortBy),
    removed:   [...old].filter(([k]) => !cur.has(k)).map(([, e]) => e).sort(sortBy),
  };
}

/**
 * @param {object} current   the report payload being written
 * @param {{file: string, report: object}|null} previous  from loadPreviousReport()
 */
export function buildEasmDiffs(current, previous) {
  if (!previous) {
    return { enabled: true, previous: null, counts: null, compliance: null };
  }
  const prev = previous.report;
  // Compare on what BOTH runs could see: the stricter of the two --min-severity
  // filters is applied to both reports' vulnerabilities, so a finding that one run
  // filtered out never reads as new or removed in the other.
  const curMin = minRankOf(current), prevMin = minRankOf(prev);
  const ctx = { minRank: Math.min(curMin, prevMin) };
  const nameOf = (r) => String(r?.scan_options?.min_severity || "unknown").toLowerCase();
  const diffs = {
    enabled: true,
    previous: { report_id: prev.report_id ?? null, generated_at: prev.generated_at ?? null, bundle: previous.file },
    min_severity: {
      current: nameOf(current),
      previous: nameOf(prev),
      applied: Object.keys(SEV_RANK).find((k) => SEV_RANK[k] === ctx.minRank) || "unknown",
      changed: curMin !== prevMin,
    },
    counts: {},
  };
  for (const [name, extract, sortBy] of CATEGORIES) {
    const d = split(extract(current, ctx), extract(prev, ctx), sortBy);
    diffs[name] = d;
    if (d) {
      diffs.counts[`new_${name}`] = d.new.length;
      diffs.counts[`unchanged_${name}`] = d.unchanged.length;
      diffs.counts[`removed_${name}`] = d.removed.length;
    }
  }
  diffs.compliance = diffCompliance(current, prev, ctx);
  return diffs;
}

/** Loads the previous report next to `zipPath` and builds the diffs; never throws. */
export function computeEasmDiffs(current, zipPath, tag) {
  try {
    return buildEasmDiffs(current, loadPreviousReport(zipPath, tag));
  } catch (e) {
    console.warn(`[~] Diffs failed: ${e.message}`);
    return { enabled: true, previous: null, counts: null, compliance: null, error: e.message };
  }
}
