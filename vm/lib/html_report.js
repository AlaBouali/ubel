'use strict';
// html_report.js — report payload + HTML generator shared by ubel-vm and ubel-k8s.
//
// It is the counterpart of cloud/lib/html_report.js and keeps its look, tabs and behaviour (Dashboard, Executive
// Summary, Findings, Compliance, Diffs, Detailed Stats, Scan Info), with these differences:
//   - A scan evaluates a catalogue of *checks*. The report records the outcome of every one (pass / fail /
//     not applicable / not assessed), so the Stats and Compliance tabs can say how much of the baseline was
//     actually evaluated, and the Diffs tab never reads a check that was not evaluated as "fixed".
//   - Findings are grouped by `area` (ssh, kernel, rbac, workload …) and, where the target has one, by `scope`
//     (a Kubernetes namespace) instead of cloud provider / service / region.
//   - Labels, areas and the target description come from `meta.profile` (see vm/profile.js, k8s/profile.js), which is
//     embedded in the report so the JSON and the HTML are always self-describing.
//
// Static assets (Tailwind, Chart.js, Google Fonts) come from the shared `sca` module, so the report stays a single
// self-contained file with no network access at view time.

import { getTailwindScript } from "../../sca/tailwindcss.js";
import { getChartJSScript } from "../../sca/chartjs.js";
import { getGoogleFontsScript } from "../../sca/googlefonts.js";
import { summarizeCompliance, FRAMEWORKS } from "../../sca/compliance_mappings.js";
import { buildExecutiveSummary } from "./executive_summary.js";

async function loadScaStatics() {
  return {
    tailwind: await getTailwindScript(),
    chartjs: await getChartJSScript(),
    googleFonts: await getGoogleFontsScript(),
  };
}

// ─── escaping ────────────────────────────────────────────────────────────────

function escapeForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/`/g, '\\u0060')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

// ─── stats ───────────────────────────────────────────────────────────────────

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function buildStats(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byArea = {};
  const byScope = {};
  for (const f of findings) {
    const sev = SEVERITIES.includes(f.severity) ? f.severity : 'info';
    bySeverity[sev]++;
    byArea[f.area] = (byArea[f.area] || 0) + 1;
    if (f.scope) byScope[f.scope] = (byScope[f.scope] || 0) + 1;
  }
  return { total: findings.length, bySeverity, byArea, byScope };
}

/** Outcome counts of the check catalogue: how much of the baseline was actually evaluated. */
function buildCoverage(checks, notes) {
  const c = { pass: 0, fail: 0, na: 0, unassessed: 0 };
  const byArea = {};
  for (const k of checks) {
    c[k.status] = (c[k.status] || 0) + 1;
    const a = (byArea[k.area] = byArea[k.area] || { pass: 0, fail: 0, na: 0, unassessed: 0 });
    a[k.status] = (a[k.status] || 0) + 1;
  }
  const evaluated = c.pass + c.fail;
  return {
    status: c.unassessed ? 'partial' : 'complete',
    checks_total: checks.length,
    evaluated,
    passed: c.pass,
    failed: c.fail,
    not_applicable: c.na,
    not_assessed: c.unassessed,
    pass_rate: evaluated ? Math.round((c.pass / evaluated) * 1000) / 10 : null,
    by_area: byArea,
    not_assessed_checks: checks.filter((k) => k.status === 'unassessed').map((k) => ({ check: k.check, area: k.area, reason: k.reason || '' })),
    notes: notes || [],
  };
}

/**
 * Per-framework posture: of the checks mapped to a framework that were evaluated, how many pass. This complements
 * `compliance_summary` (which counts failing findings per control) with the passing side.
 */
function buildCompliancePosture(checks) {
  const m = new Map();
  for (const k of checks) {
    for (const id of k.frameworks || []) {
      if (!m.has(id)) m.set(id, { id, name: (FRAMEWORKS[id] || {}).name || id, version: (FRAMEWORKS[id] || {}).version ?? null, checks: 0, passed: 0, failed: 0, not_assessed: 0 });
      const e = m.get(id);
      if (k.status === 'na') continue;
      e.checks++;
      if (k.status === 'pass') e.passed++;
      else if (k.status === 'fail') e.failed++;
      else e.not_assessed++;
    }
  }
  return { frameworks: [...m.values()].filter((e) => e.checks > 0).sort((a, b) => b.checks - a.checks || a.name.localeCompare(b.name)) };
}

// ─── diffs against the previous report ───────────────────────────────────────
// The "Diffs" tab compares this scan with the previous report of the same asset: findings, areas and scopes
// (Kubernetes namespaces) that are new, still present, or gone, plus the same view per compliance framework.
// Findings are matched on area + check + resource + scope. Things that would make the comparison dishonest are
// left out, and a note says so:
//   - a check that was not evaluated this time (otherwise its earlier findings would read as "fixed");
//   - scopes (namespaces) that were not scanned in both runs;
//   - earlier findings below this scan's --min-severity (they were hidden, not fixed).

const DIFF_SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const diffFindingKey = (f) => [f.area, f.check, f.resource, f.scope || ''].join('::');

function diffSortFindings(a, b) {
  return (DIFF_SEV_RANK[a.severity] ?? 9) - (DIFF_SEV_RANK[b.severity] ?? 9)
    || String(a.area).localeCompare(String(b.area))
    || String(a.resource).localeCompare(String(b.resource));
}

function diffCountGroups(curFindings, prevFindings, keyOf) {
  const count = (list) => {
    const m = new Map();
    for (const f of list) { const k = keyOf(f); if (k) m.set(k, (m.get(k) || 0) + 1); }
    return m;
  };
  const cur = count(curFindings), prev = count(prevFindings);
  const entry = (k) => ({ key: k, previous: prev.get(k) || 0, current: cur.get(k) || 0, delta: (cur.get(k) || 0) - (prev.get(k) || 0) });
  const keys = [...new Set([...cur.keys(), ...prev.keys()])].sort();
  const all = keys.map(entry);
  return {
    new: all.filter((e) => e.previous === 0 && e.current > 0),
    existing: all.filter((e) => e.previous > 0 && e.current > 0),
    resolved: all.filter((e) => e.previous > 0 && e.current === 0),
  };
}

function diffCompliance(findings, allCurrent) {
  const fwOf = (f) => (f.compliance && f.compliance.frameworks) || [];
  const meta = new Map();
  for (const f of [...findings.new, ...findings.fixed, ...findings.existing.map((i) => allCurrent[i])]) {
    for (const fw of fwOf(f)) if (!meta.has(fw.id)) meta.set(fw.id, { id: fw.id, name: fw.name, version: fw.version ?? null });
  }
  const has = (f, id) => fwOf(f).some((x) => x.id === id);
  const frameworks = [...meta.values()].map((m) => ({
    ...m,
    new: findings.new.map((f, i) => (has(f, m.id) ? i : -1)).filter((i) => i >= 0),
    unchanged: findings.existing.filter((i) => has(allCurrent[i], m.id)),
    removed: findings.fixed.map((f, i) => (has(f, m.id) ? i : -1)).filter((i) => i >= 0),
  }));
  frameworks.sort((a, b) => String(a.name).localeCompare(String(b.name)));
  return { frameworks };
}

function diffsBlank(extra) {
  const group = () => ({ new: [], existing: [], resolved: [] });
  return { enabled: true, previous: null, counts: null, notes: [], findings: { new: [], existing: [], fixed: [] }, areas: group(), scopes: group(), compliance: null, ...extra };
}

/**
 * @param {object} current   the report payload being built (needs findings, checks, target, scan_options)
 * @param {{file?:string, report:object}|null} previous  the previous report (parsed JSON) or null when this is the first one
 */
function buildDiffs(current, previous) {
  const prev = previous && (previous.report || previous);
  if (!prev || !Array.isArray(prev.findings)) return diffsBlank();

  const notes = [];
  const curStatus = new Map((current.checks || []).map((c) => [c.check, c.status]));
  const comparable = (id) => ['pass', 'fail'].includes(curStatus.get(id));
  const skippedChecks = [...new Set(prev.findings.filter((f) => !comparable(f.check)).map((f) => f.check))];
  if (skippedChecks.length) {
    notes.push(`${skippedChecks.length} check(s) with findings in the previous report were not evaluated this time (not applicable, not assessed, filtered with --only/--skip, or no longer part of the baseline), so their findings are not compared.`);
  }
  const ct = current.target || {}, pt = prev.target || {};
  if (ct.mode && pt.mode && ct.mode !== pt.mode) notes.push(`The scan mode differs from the previous report (${pt.mode} before, ${ct.mode} now); results may not be comparable.`);
  if (ct.hostname && pt.hostname && ct.hostname !== pt.hostname) notes.push(`The host differs from the previous report (${pt.hostname} before, ${ct.hostname} now), so these results describe a different machine.`);
  if (ct.source && pt.source && ct.source !== pt.source) notes.push(`The scan source differs from the previous report (${pt.source} before, ${ct.source} now).`);
  if (ct.cluster && pt.cluster && ct.cluster !== pt.cluster) notes.push(`The cluster differs from the previous report (${pt.cluster} before, ${ct.cluster} now).`);

  const nsList = (t) => (Array.isArray(t.scopes_scanned) ? t.scopes_scanned : null);
  const x = nsList(ct), y = nsList(pt);
  if (x && y && (x.length !== y.length || x.some((n) => !y.includes(n)))) {
    notes.push('The scanned scopes (namespaces) differ from the previous report. Only findings in scopes scanned both times are compared.');
  }
  const scopeOk = (f) => !f.scope || !x || !y || (x.includes(f.scope) && y.includes(f.scope));

  const curMin = current.scan_options && current.scan_options.min_severity;
  const prevMin = prev.scan_options && prev.scan_options.min_severity;
  if ((curMin || null) !== (prevMin || null)) {
    notes.push(`The minimum severity filter differs from the previous report (${prevMin || 'none'} before, ${curMin || 'none'} now), so counts may not be directly comparable.`);
  }

  const indexOf = new Map(current.findings.map((f, i) => [f, i]));
  const curFindings = current.findings.filter((f) => comparable(f.check) && scopeOk(f));
  const prevFindings = prev.findings.filter((f) =>
    comparable(f.check) && scopeOk(f) && (!curMin || (DIFF_SEV_RANK[f.severity] ?? 9) <= (DIFF_SEV_RANK[curMin] ?? 9)));

  const curMap = new Map(curFindings.map((f) => [diffFindingKey(f), f]));
  const prevMap = new Map(prevFindings.map((f) => [diffFindingKey(f), f]));
  const findings = {
    new: [...curMap].filter(([k]) => !prevMap.has(k)).map(([, f]) => f).sort(diffSortFindings),
    existing: [...curMap].filter(([k]) => prevMap.has(k)).map(([, f]) => f).sort(diffSortFindings).map((f) => indexOf.get(f)),
    fixed: [...prevMap].filter(([k]) => !curMap.has(k)).map(([, f]) => f).sort(diffSortFindings),
  };
  const areas = diffCountGroups(curFindings, prevFindings, (f) => f.area);
  const scopes = diffCountGroups(curFindings, prevFindings, (f) => f.scope);

  return {
    enabled: true,
    previous: { report_id: prev.report_id ?? null, generated_at: prev.generated_at ?? null, bundle: previous.file ?? null },
    counts: {
      new_findings: findings.new.length, existing_findings: findings.existing.length, fixed_findings: findings.fixed.length,
      new_areas: areas.new.length, existing_areas: areas.existing.length, resolved_areas: areas.resolved.length,
      new_scopes: scopes.new.length, existing_scopes: scopes.existing.length, resolved_scopes: scopes.resolved.length,
    },
    notes,
    findings,
    areas,
    scopes,
    // null when the previous report predates compliance mapping, so an older report is never read as "everything is new"
    compliance: prev.compliance_summary ? diffCompliance(findings, current.findings) : null,
  };
}

// ─── payload ─────────────────────────────────────────────────────────────────

/**
 * Builds the exact object the HTML report renders from — also written verbatim as the JSON report.
 *
 * @param {import('./engine.js').Reporter} reporter
 * @param {object} meta
 * @param {object} meta.profile          labels / areas of the tool (vm/profile.js or k8s/profile.js)
 * @param {object} [meta.target]         what was scanned (host description, or cluster / manifests)
 * @param {string[]} [meta.notes]        coverage caveats collected during the scan
 * @param {string} [meta.generated_at] [meta.tool_version] [meta.report_id] [meta.asset_id] [meta.asset_name] [meta.asset_type] [meta.machine_id]
 * @param {string} [meta.min_severity]   the --min-severity filter that was applied
 * @param {number} [meta.hidden_by_filter]
 * @param {object} [meta.options]        extra scan options to record (only_checks, skipped checks, …)
 * @param {{file?:string, report:object}|null} [meta.previous_report]  undefined = no diff lookup was done (no Diffs tab)
 */
/** The VM inventory: host, objects with findings, installed packages. Entries have the shape of the canonical report's inventory. */
function buildInventory(payload, packages) {
  const t = payload.target || {};
  const host = t.hostname || 'vm';
  const inv = [{ component_id: host, component_name: host, type: 'host', status: payload.coverage && payload.coverage.status === 'partial' ? 'partially_assessed' : 'assessed', details: t }];
  const count = new Map();
  for (const f of payload.findings) { if (f.vuln || f.resource == null) continue; const id = String(f.resource); count.set(id, (count.get(id) || 0) + 1); }
  for (const [id, n] of count) inv.push({ component_id: id, component_name: id, type: id.startsWith('/') ? 'filesystem' : 'host_object', status: 'non_compliant', details: { resource: id, findings: n } });
  for (const c of packages) {
    if (!c || !c.id) continue;
    inv.push({ component_id: c.id, component_name: `${c.name} (${c.ecosystem || 'unknown'}) : ${c.version}`, type: 'dependency', status: c.state === 'safe' ? 'clean' : (c.state || 'unknown'), details: c });
  }
  return inv;
}

function buildReportPayload(reporter, meta = {}) {
  const profile = meta.profile || {};
  const findings = reporter.sorted();
  const checks = reporter.checks;
  const complianceSummary = summarizeCompliance(findings.map((f) => f.compliance));

  const payload = {
    generated_at: meta.generated_at || new Date().toISOString(),
    tool: profile.tool || 'ubel',
    tool_version: meta.tool_version || null,
    report_id: meta.report_id || null,
    asset_id: meta.asset_id || null,
    asset_name: meta.asset_name || null,
    asset_type: meta.asset_type || null,
    machine_id: meta.machine_id || null,
    profile,
    target: meta.target || {},
    scan_options: {
      min_severity: meta.min_severity || null,
      hidden_by_filter: meta.hidden_by_filter || 0,
      ...(meta.options || {}),
    },
    coverage: buildCoverage(checks, meta.notes),
    stats: buildStats(findings),
    compliance_summary: complianceSummary,
    compliance_posture: buildCompliancePosture(checks),
    checks,
    findings,
  };

  // ubel-vm: one inventory — the host, the objects the findings are about and every installed package (SCA inventory items, with their
  // state) — the same list the canonical report carries; there is no separate package block.
  if ((profile.key || '') === 'vm') payload.inventory = buildInventory(payload, Array.isArray(meta.package_inventory) ? meta.package_inventory : []);

  if (meta.previous_report !== undefined) {
    try {
      payload.diffs = buildDiffs(payload, meta.previous_report);
    } catch (e) {
      console.warn(`[~] Diffs failed: ${e.message}`);
      payload.diffs = diffsBlank({ error: e.message });
    }
  }

  // Derived purely from the finished payload, so it is built last; a failure only hides the tab.
  try {
    payload.executive_summary = buildExecutiveSummary(payload);
  } catch (e) {
    console.warn(`[~] Executive summary failed: ${e.message}`);
  }
  return payload;
}

async function generateHtmlReport(reportPayload) {
  const { tailwind, chartjs, googleFonts } = await loadScaStatics();
  const P = reportPayload.profile || {};
  const TOOL_NAME = reportPayload.tool || 'ubel';

  const safeJson = escapeForScript(reportPayload);
  const clientScript = buildClientScript(safeJson);

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${escapeHtml(P.title || 'Security report')}</title>
  <script>${tailwind}</script>
  <script>${chartjs}</script>
  <style>${googleFonts}</style>
  <style>
    :root { --bg: #0a0a0a; --card: #141414; --border: #262626; --accent: #ef4444; }
    body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #e5e5e5; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .glass { background: rgba(20,20,20,0.8); backdrop-filter: blur(12px); border: 1px solid var(--border); }
    .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
    .severity-high     { color: #f87171; border-color: #f87171; }
    .severity-medium   { color: #fb923c; border-color: #fb923c; }
    .severity-low      { color: #60a5fa; border-color: #60a5fa; }
    .severity-info     { color: #a3a3a3; border-color: #a3a3a3; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    .tab-active { border-bottom: 2px solid var(--accent); color: white; }
    .modal-overlay { display: none; position: fixed; top:0; left:0; width:100%; height:100%;
                     background: rgba(0,0,0,0.85); z-index:50; backdrop-filter: blur(4px); }
    .modal-content { max-height: 90vh; overflow-y: auto; }
    /* Executive summary: print / save-as-PDF. Prints the summary only, on white;
       page 1 is the one-page summary, details and appendix start on new pages. */
    details > summary { list-style: none; }
    details > summary::-webkit-details-marker { display: none; }
    details > summary::before { content: "+"; display: inline-block; width: 1.2em; color: #737373; }
    details[open] > summary::before { content: "-"; }
    @media print {
      @page { size: A4; margin: 12mm; }
      html, body { background: #fff !important; color: #111 !important; font-size: 11px; }
      header, nav, footer, .no-print, .modal-overlay { display: none !important; }
      main { padding: 0 !important; max-width: none !important; }
      main > section { display: none !important; }
      main > #section-executive { display: block !important; }
      #section-executive, #section-executive * { -webkit-print-color-adjust: exact; print-color-adjust: exact; box-shadow: none !important; backdrop-filter: none !important; }
      #section-executive > div, #section-executive #executive-content > * { margin-top: 0; }
      #executive-content { display: block !important; }
      #executive-content > * + * { margin-top: 12px !important; }
      #section-executive .glass { background: #fff !important; border-color: #d1d5db; break-inside: avoid; padding: 8px 12px !important; border-radius: 6px !important; }
      #section-executive .glass[style*="border-left"] { border-top-color: #d1d5db; border-right-color: #d1d5db; border-bottom-color: #d1d5db; }
      #section-executive [class*="text-neutral"], #section-executive [class*="text-white"] { color: #374151 !important; }
      #section-executive .exec-headline, #section-executive h2, #section-executive h4 { color: #111 !important; }
      #section-executive [class*="bg-neutral"] { background: #f3f4f6 !important; }
      #section-executive [class*="border-neutral"] { border-color: #d1d5db !important; }
      #section-executive [class*="divide-neutral"] > * { border-color: #e5e7eb !important; }
      #section-executive .exec-page-break { break-before: page; }
      #section-executive .exec-cols-2 { display: grid !important; grid-template-columns: 1fr 1fr !important; gap: 10px !important; }
      #section-executive .exec-figs > *, #section-executive .exec-glance > *, #section-executive .exec-cols-2 > * { min-width: 0; overflow-wrap: anywhere; }
      #section-executive .exec-figs { display: grid !important; grid-template-columns: repeat(4, 1fr) !important; gap: 8px !important; }
      #section-executive .exec-glance { display: grid !important; grid-template-columns: repeat(3, 1fr) !important; gap: 8px !important; }
      #section-executive h2 { font-size: 18px !important; margin-bottom: 4px !important; }
      #section-executive h3 { font-size: 10px !important; margin-bottom: 6px !important; break-after: avoid; }
      #section-executive h4 { font-size: 11px !important; }
      #section-executive .text-4xl { font-size: 28px !important; line-height: 1.1 !important; }
      #section-executive .text-3xl { font-size: 20px !important; line-height: 1.1 !important; }
      #section-executive .text-lg { font-size: 12.5px !important; line-height: 1.4 !important; }
      #section-executive .text-sm { font-size: 10.5px !important; line-height: 1.4 !important; }
      #section-executive .text-xs, #section-executive [class*="text-[11px]"] { font-size: 9px !important; line-height: 1.35 !important; }
      #section-executive .space-y-3 > * + * { margin-top: 6px !important; }
      #section-executive .space-y-8 > * + * { margin-top: 12px !important; }
      #section-executive table { font-size: 9.5px; }
      #section-executive td, #section-executive th { padding-top: 5px !important; padding-bottom: 5px !important; }
      #section-executive tr { break-inside: avoid; }
      #section-executive .exec-appendix { break-inside: auto; }
      #section-executive .exec-appendix > summary::before { content: ""; }
    }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- ── HEADER ─────────────────────────────────────────────────────────── -->
  <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white text-sm">${escapeHtml(P.logo || 'U')}</div>
        <div>
          <h1 class="text-lg font-semibold tracking-tight">${escapeHtml(P.title || 'Security report')}</h1>
          <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p>
        </div>
      </div>
      <span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50">
        ${TOOL_NAME}${reportPayload.tool_version ? ' v' + escapeHtml(reportPayload.tool_version) : ''}
      </span>
    </div>
  </header>

  <!-- ── NAV ───────────────────────────────────────────────────────────── -->
  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('executive')" id="tab-executive" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Executive Summary</button>
      <button onclick="switchTab('findings')"  id="tab-findings"  class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Findings(0)</button>
      <button onclick="switchTab('inventory')" id="tab-inventory" class="hidden py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Inventory(0)</button>
      <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Compliance(0)</button>
      <button onclick="switchTab('diffs')"      id="tab-diffs"      class="hidden py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Diffs</button>
      <button onclick="switchTab('stats')"      id="tab-stats"      class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
      <button onclick="switchTab('scaninfo')"  id="tab-scaninfo"  class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Scan Info</button>
    </div>
  </nav>

  <!-- ── MAIN ──────────────────────────────────────────────────────────── -->
  <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">

    <!-- Dashboard -->
    <section id="section-dashboard" class="space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-5 gap-4">
        <div class="glass p-6 rounded-xl border-l-4 border-l-red-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Critical</p>
          <p class="text-3xl font-bold text-red-500" id="stat-critical">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-red-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">High</p>
          <p class="text-3xl font-bold text-red-400" id="stat-high">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-orange-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Medium</p>
          <p class="text-3xl font-bold text-orange-400" id="stat-medium">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-blue-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Low</p>
          <p class="text-3xl font-bold text-blue-400" id="stat-low">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-neutral-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Info</p>
          <p class="text-3xl font-bold text-neutral-300" id="stat-info">0</p>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="glass p-6 rounded-xl lg:col-span-1">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">By Severity</h3>
          <div class="h-56"><canvas id="severityChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Check Results</h3>
          <div class="h-56"><canvas id="checksChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Findings by Area</h3>
          <div class="h-56"><canvas id="areaChart"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Executive Summary (plain-language, for non-technical readers) -->
    <section id="section-executive" class="hidden space-y-8">
      <div id="executive-content" class="space-y-8"></div>
    </section>

    <!-- Findings -->
    <section id="section-findings" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="f-search" type="text" placeholder="Search title, resource, area, check..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="applyFilters()">
        <select id="f-severity" onchange="applyFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select id="f-area" onchange="applyFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All areas</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">Area</th>
              <th class="px-4 py-3">Title</th>
              <th class="px-4 py-3">Resource</th>
              <th class="px-4 py-3" id="th-scope">Scope</th>
            </tr>
          </thead>
          <tbody id="findings-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Inventory (ubel-vm): host, objects with findings, installed packages -->
    <section id="section-inventory" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="i-search" type="text" placeholder="Search component, version, ecosystem..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="renderInventory()">
        <select id="i-type" onchange="renderInventory()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All types</option>
        </select>
        <select id="i-state" onchange="renderInventory()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All states</option>
        </select>
        <span id="i-count" class="text-xs text-neutral-500"></span>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr><th class="px-4 py-3">Component</th><th class="px-4 py-3">Type</th><th class="px-4 py-3">State</th><th class="px-4 py-3">Findings</th><th class="px-4 py-3"></th></tr>
          </thead>
          <tbody id="inventory-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Compliance -->
    <section id="section-compliance" class="hidden space-y-8">
      <p id="compliance-disclaimer" class="text-xs text-neutral-500 italic bg-neutral-900/50 p-3 rounded-lg border border-neutral-800"></p>
      <div id="compliance-coverage" class="glass p-4 rounded-xl flex items-center justify-between text-sm hidden">
        <span class="text-neutral-400">Findings mapped to a compliance framework</span>
        <span id="compliance-coverage-value" class="mono text-neutral-200 font-semibold"></span>
      </div>
      <div id="compliance-posture" class="hidden space-y-3"></div>
      <div id="compliance-owasp-section" class="hidden space-y-3">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">By OWASP Top 10 Category</h3>
        <div id="compliance-owasp-grid" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
      </div>
      <div id="compliance-frameworks-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
      <div id="compliance-empty" class="hidden text-sm text-neutral-500 italic">No findings mapped to a compliance framework.</div>
    </section>

    <!-- Diffs (only when a previous report was supplied) -->
    <section id="section-diffs" class="hidden space-y-8"></section>

    <!-- Detailed Stats -->
    <section id="section-stats" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <div class="glass p-6 rounded-xl space-y-6">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Check Coverage</h3>
          <div class="h-48"><canvas id="statsChecksChart"></canvas></div>
          <div class="space-y-2">
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Checks in the baseline</span><span class="mono" id="stats-checks-total">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Evaluated</span><span class="mono" id="stats-checks-eval">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Passed</span><span class="mono text-green-400" id="stats-checks-pass">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Failed</span><span class="mono text-red-400" id="stats-checks-fail">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Not applicable</span><span class="mono text-gray-400" id="stats-checks-na">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Not assessed</span><span class="mono text-orange-400" id="stats-checks-un">0</span></div>
            <div class="flex justify-between text-sm border-t border-neutral-800 pt-2"><span class="text-neutral-500">Pass rate (of evaluated)</span><span class="mono" id="stats-pass-rate">n/a</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-6">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Finding Stats</h3>
          <div class="h-48"><canvas id="statsSevChart"></canvas></div>
          <div class="space-y-2">
            <div class="flex justify-between text-sm"><span class="text-neutral-500" title="One finding per affected resource. The same check can fire on several resources.">Total findings</span><span class="mono" id="stats-total-findings">0</span></div>
            <div class="flex justify-between text-xs"><span class="text-neutral-600">of which distinct failing checks</span><span class="mono text-neutral-500" id="stats-distinct-checks">0</span></div>
            <div class="flex justify-between text-xs"><span class="text-neutral-600">distinct resources affected</span><span class="mono text-neutral-500" id="stats-distinct-resources">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Critical</span><span class="mono text-red-600" id="stats-sev-critical">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">High</span><span class="mono text-red-400" id="stats-sev-high">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Medium</span><span class="mono text-orange-400" id="stats-sev-medium">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Low</span><span class="mono text-blue-400" id="stats-sev-low">0</span></div>
            <div class="flex justify-between text-sm"><span class="text-neutral-500">Info</span><span class="mono text-gray-400" id="stats-sev-info">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-6">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Area Distribution</h3>
          <div class="h-48"><canvas id="statsAreaChart"></canvas></div>
          <p class="text-[11px] text-neutral-500">Findings per area of the baseline.</p>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Compliance Posture</h3>
          <p class="text-[11px] text-neutral-500">Passing checks per mapped framework (details in the Compliance tab).</p>
          <div id="stats-posture" class="space-y-3"></div>
        </div>

        <div id="stats-scope-card" class="hidden glass p-6 rounded-xl space-y-4">
          <h3 id="stats-scope-title" class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Findings by Scope</h3>
          <div class="h-48"><canvas id="scopeChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-1">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Check Outcomes by Area</h3>
          <table class="w-full text-left"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>
            <th class="pb-2 pr-4 font-bold">Area</th><th class="pb-2 pr-4 font-bold">Pass</th><th class="pb-2 pr-4 font-bold">Fail</th><th class="pb-2 pr-4 font-bold">N/A</th><th class="pb-2 pr-4 font-bold">Not assessed</th>
          </tr></thead><tbody id="stats-area-table" class="divide-y divide-neutral-800"></tbody></table>
        </div>

        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Most Common Checks</h3>
          <p class="text-[11px] text-neutral-500">Distinct check IDs ranked by how many findings each produced (one per affected resource).</p>
          <div id="stats-top-checks" class="space-y-0"></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Busiest Resources</h3>
          <p class="text-[11px] text-neutral-500">Resources ranked by how many findings they are carrying.</p>
          <div id="stats-hot-resources" class="space-y-0"></div>
        </div>

      </div>
    </section>

    <!-- Scan Info -->
    <section id="section-scaninfo" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scan</h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool</span><span class="mono text-xs" id="sys-tool">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="sys-version">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Asset</span><span class="mono text-xs" id="sys-asset">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Asset ID</span><span class="mono text-[10px] break-all text-right" id="sys-asset-id">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Asset type</span><span class="mono text-xs" id="sys-asset-type">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Machine ID</span><span class="mono text-xs break-all text-right" id="sys-machine-id">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Generated at</span><span class="mono text-xs" id="sys-generated">—</span></div>
            <div class="flex justify-between"><span class="text-neutral-500 text-xs">Minimum severity filter</span><span class="mono text-xs" id="sys-filter">—</span></div>
          </div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Target</h3>
          <div id="sys-target" class="space-y-2 text-sm">—</div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Options</h3>
          <div id="sys-options" class="space-y-2 text-sm">—</div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Coverage</h3>
          <div id="sys-coverage" class="text-xs mono text-neutral-300 space-y-1">—</div>
        </div>
        <div class="glass rounded-xl md:col-span-2 overflow-x-auto">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 p-6 pb-2">Check catalogue</h3>
          <table class="w-full text-left">
            <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr>
              <th class="px-4 py-3">Check</th><th class="px-4 py-3">Area</th><th class="px-4 py-3">Severity</th><th class="px-4 py-3">Outcome</th><th class="px-4 py-3">Note</th>
            </tr></thead>
            <tbody id="sys-checks-body" class="divide-y divide-neutral-800"></tbody>
          </table>
        </div>
      </div>
    </section>

  </main>

  <!-- ── FOOTER ─────────────────────────────────────────────────────────── -->
  <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50">
    <div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
      <p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">${TOOL_NAME}</span></p>
    </div>
  </footer>

  <!-- ── MODAL ──────────────────────────────────────────────────────────── -->
  <div id="modal-overlay" class="modal-overlay items-center justify-center p-4">
    <div class="modal-content glass w-full max-w-2xl rounded-2xl shadow-2xl relative">
      <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
      <div id="modal-body" class="p-8"></div>
    </div>
  </div>

  <script>${clientScript}</script>
</body>
</html>`;
}

// ─── client-side script ──────────────────────────────────────────────────────

function buildClientScript(safeJson) {
  return `
// ── DATA ──────────────────────────────────────────────────────────────────────
const reportData = ${safeJson};

// ── HELPERS ───────────────────────────────────────────────────────────────────
// Dynamic content below (finding fields) ultimately traces back to resource
// names/policies read out of the scanned cloud account — not necessarily
// chosen by the person running the scan — so every value is escaped before
// it touches innerHTML, and click targets are wired up via data attributes
// + a delegated listener rather than interpolated into onclick="..." strings.

function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function sevClass(s) {
  return {critical:'severity-critical',high:'severity-high',medium:'severity-medium',low:'severity-low',info:'severity-info'}[s] || 'severity-info';
}

// ── COMPLIANCE HELPERS ────────────────────────────────────────────────────────
//
// The compliance_summary shipped in reportData is built server-side and
// counts one unit per finding — so a control tripped by one check (e.g.
// "S3 bucket public read") sitting on 12 buckets shows as "12 findings".
// That's a fine raw number but it reads as "12 distinct problems" when it
// is really "one misconfiguration type seen on 12 resources" — the same
// pair/unit distinction ubel-url's (easm) compliance tab draws between
// "distinct CVEs" and "component-CVE pairs".
//
// These helpers recompute a per-control breakdown from the raw findings
// list so the UI can lead with the honest unit: distinct checks (rule
// types) and distinct affected resources, not just a finding count. The
// server-side summary is left untouched so JSON consumers keep seeing
// whatever shape they already rely on.

function hasComplianceControl(f, fwName, controlId) {
  const fws = f && f.compliance && f.compliance.frameworks;
  return !!fws && fws.some(x => x.name === fwName && (x.controls || []).some(c => c.id === controlId));
}

function complianceMatchesFor(fwName, controlId) {
  return (reportData.findings || []).filter(f => hasComplianceControl(f, fwName, controlId));
}

function complianceStatsFromMatches(matches) {
  const checks = new Set();
  const resources = new Set();
  for (const f of matches) {
    checks.add(f.check);
    resources.add(f.area + '::' + f.scope + '::' + f.resource);
  }
  return {
    checkCount: checks.size,
    resourceCount: resources.size,
    matchCount: matches.length,
  };
}

// For the framework card's headline figure — the same finding can appear
// under several controls of one framework, so dedupe before counting.
function complianceFrameworkTotals(fw) {
  const acc = new Set();
  for (const c of fw.controls || []) {
    complianceMatchesFor(fw.name, c.id).forEach(f => acc.add(f));
  }
  return complianceStatsFromMatches([...acc]);
}

// Right-hand count column for a framework card or control row: distinct
// checks as the primary figure, distinct resources as the secondary one.
function complianceCountsHtml(stats, primaryClass, compact) {
  const line = (cls, text) => '<span class="' + cls + '">' + text + '</span>';
  const minor = 'mono text-neutral-500 text-[10px]';
  const out = [];
  out.push(line(primaryClass, stats.checkCount + ' check' + (stats.checkCount === 1 ? '' : 's')));
  out.push(line(minor, stats.resourceCount + (compact ? ' res.' : ' resource' + (stats.resourceCount === 1 ? '' : 's'))));
  return out.join('');
}

// ── COMPLIANCE ─────────────────────────────────────────────────────────────────

function renderComplianceSection(compliance) {
  if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
  return \`<div>
    <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Compliance Frameworks</p>
    <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-2">
      \${compliance.frameworks.map(fw => \`
      <div class="flex flex-col gap-1">
        <span class="text-xs font-semibold text-red-400">\${escH(fw.name)}</span>
        <div class="flex flex-wrap gap-1.5">\${fw.controls.map(c => \`<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="\${escH(c.title)}">\${escH(c.id)}</span>\`).join('')}</div>
      </div>\`).join('')}
    </div>
  </div>\`;
}

function renderCompliance() {
  const cs = reportData.compliance_summary;
  document.getElementById('compliance-disclaimer').textContent = (cs && cs.disclaimer) || '';

  const coverageEl = document.getElementById('compliance-coverage');
  const coverageValueEl = document.getElementById('compliance-coverage-value');
  if (cs && cs.coverage && cs.coverage.total_findings) {
    const { mapped_findings, total_findings, coverage_pct } = cs.coverage;
    coverageValueEl.textContent = mapped_findings + ' / ' + total_findings + ' (' + coverage_pct + '%)';
    coverageEl.classList.remove('hidden');
  } else {
    coverageEl.classList.add('hidden');
  }

  const owaspSection = document.getElementById('compliance-owasp-section');
  const owaspGrid = document.getElementById('compliance-owasp-grid');
  if (cs && cs.by_owasp_category && cs.by_owasp_category.length) {
    owaspGrid.innerHTML = cs.by_owasp_category.map(o => \`
      <div class="glass p-4 rounded-xl flex items-start justify-between gap-3 text-xs">
        <div class="flex flex-col gap-1">
          <span class="mono text-red-400">\${escH(o.id)}</span>
          <span class="text-neutral-400">\${escH(o.title)}</span>
          <span class="text-neutral-600">via: \${escH((o.categories || []).join(', '))}</span>
        </div>
        <span class="mono text-neutral-300 whitespace-nowrap">\${o.findings_count}</span>
      </div>\`).join('');
    owaspSection.classList.remove('hidden');
  } else {
    owaspSection.classList.add('hidden');
  }

  const grid = document.getElementById('compliance-frameworks-grid');
  if (!cs || !cs.frameworks || !cs.frameworks.length) {
    document.getElementById('compliance-empty').classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const fwStats = complianceFrameworkTotals(fw);
    return \`
    <div class="glass p-6 rounded-xl space-y-4">
      <div class="flex items-start justify-between gap-3">
        <div class="flex flex-col">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">\${escH(fw.name)}</h3>
          \${fw.version ? \`<span class="text-[10px] text-neutral-500 mono">\${escH(fw.version)}</span>\` : ''}
        </div>
        <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
          \${complianceCountsHtml(fwStats, 'mono text-neutral-200 font-semibold text-xs', false)}
        </div>
      </div>
      <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
        \${fw.controls.map((c, cIdx) => {
          const stats = complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id));
          return \`
          <div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" data-fw-idx="\${fwIdx}" data-control-idx="\${cIdx}">
            <div class="flex flex-col min-w-0">
              <span class="mono text-red-400">\${escH(c.id)}</span>
              <span class="text-neutral-500">\${escH(c.title)}</span>
            </div>
            <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
              \${complianceCountsHtml(stats, 'mono text-neutral-200', true)}
            </div>
          </div>\`;
        }).join('')}
      </div>
    </div>\`;
  }).join('');
}

// Holds the exact findings array most recently rendered by
// openComplianceModal() below, so the delegated click listener can index
// straight into it — consistent with how dynamic finding data is handled
// everywhere else in this file: never re-embedded into an onclick="..."
// string, always read back from a real in-memory reference via data
// attributes + a stable listener.
let _currentComplianceMatches = null;

function openComplianceModal(fwIdx, cIdx) {
  const cs = reportData.compliance_summary;
  const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
  const control = fw && fw.controls && fw.controls[cIdx];
  if (!fw || !control) return;

  const matches = complianceMatchesFor(fw.name, control.id);
  _currentComplianceMatches = matches;
  const stats = complianceStatsFromMatches(matches);
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  const rows = matches.length ? matches.map((f, idx) => \`
    <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" data-finding-index="\${idx}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity)}</span>
        <span class="text-xs text-neutral-500">\${escH(areaLabel(f.area))}</span>
        <span class="text-sm text-white">\${escH(f.title)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]" title="\${escH(f.resource)}">\${escH(f.resource)}\${f.scope ? ' · ' + escH(f.scope) : ''}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>\`).join('') : '';

  const body = matches.length
    ? '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Findings (' + matches.length + ')</p>' + rows + '</div>'
    : '<p class="text-sm text-neutral-500 italic py-2">No findings mapped to this control.</p>';

  const bits = stats.checkCount
    ? plural(stats.checkCount, 'distinct check', 'distinct checks') + ' across ' +
      plural(stats.resourceCount, 'resource', 'resources') + ' (' +
      plural(stats.matchCount, 'finding', 'findings') + ' total)'
    : '';

  openModal(\`
    <div class="space-y-4">
      <div>
        <div class="flex items-center gap-3 mb-1 flex-wrap">
          <span class="mono text-red-400 text-sm">\${escH(control.id)}</span>
          <h2 class="text-lg font-semibold text-white">\${escH(control.title)}</h2>
        </div>
        <p class="text-xs text-neutral-500">
          \${escH(fw.name)}\${fw.version ? ' · ' + escH(fw.version) : ''}\${bits ? ' — ' + escH(bits) : ''}
        </p>
      </div>
      <div class="space-y-4">\${body}</div>
    </div>
  \`);
}

// ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
// Plain-language overview for non-technical readers. Everything shown comes
// from reportData.executive_summary (built server-side and written to the JSON
// report as-is), so this tab and the JSON can never disagree. Figures that were
// not checked arrive as null and are shown as "n/a", never 0.
//
// Layout: page 1 (cover, verdict, top risks, what to do first, four numbers) is
// meant to be readable on its own and to fit one printed page. Detail follows,
// then an appendix (methodology, scope, glossary) that is collapsed on screen
// and expanded when printing.

function execEsc(x) {
  return String(x == null ? '' : x)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function renderExecutiveSummary() {
  const root = document.getElementById('executive-content');
  if (!root) return;
  const es = reportData.executive_summary;
  if (!es) {
    root.innerHTML = '<div class="glass p-6 rounded-xl text-sm text-neutral-500 italic">No executive summary is available for this report.</div>';
    return;
  }

  const esc = execEsc;
  const colors = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3', none: '#4ade80', unknown: '#a3a3a3', not_assessed: '#a3a3a3' };
  const col = function (k) { return colors[k] || '#a3a3a3'; };
  const sectionTitle = function (t) { return '<h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">' + esc(t) + '</h3>'; };
  const badge = function (key, label) {
    return '<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold whitespace-nowrap" style="color:' + col(key) + ';border-color:' + col(key) + '">' + esc(label) + '</span>';
  };
  const figure = function (f) {
    const color = f.tone ? col(f.tone) : '';
    const v = f.value == null ? 'n/a' : f.value;
    return '<div class="glass p-5 rounded-xl"' + (color ? ' style="border-left:4px solid ' + color + '"' : '') + '>' +
      '<p class="text-xs text-neutral-500 uppercase font-semibold mb-1">' + esc(f.label) + '</p>' +
      '<p class="text-3xl font-bold"' + (color ? ' style="color:' + color + '"' : '') + '>' + esc(v) + '</p>' +
      (f.sub ? '<p class="text-xs text-neutral-500 mt-1">' + esc(f.sub) + '</p>' : '') + '</div>';
  };

  const risk = es.overall_risk || {};
  const bl = es.bottom_line || {};
  const cover = es.cover || {};
  const sc = es.scope || {};
  const riskColor = col(risk.level);
  let html = '';

  // Toolbar (screen only)
  html += '<div class="no-print flex justify-end"><button type="button" onclick="window.print()" ' +
    'class="px-4 py-2 rounded-lg bg-neutral-800 border border-neutral-700 text-xs font-medium text-neutral-200 hover:bg-neutral-700 transition-colors">' +
    'Print / save as PDF</button></div>';

  // ── PAGE 1 ────────────────────────────────────────────────────────────────
  // Cover block
  const metaItems = [
    ['Report ID', cover.report_id],
    ['Date', cover.generated_at ? String(cover.generated_at).replace('T', ' ').slice(0, 16) + ' UTC' : null],
    ['Tool', cover.tool]
  ].filter(function (m) { return m[1]; });
  html += '<div class="glass p-5 rounded-xl">' +
    '<p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest mb-1">' + esc(cover.title || 'Executive summary') + '</p>' +
    '<h2 class="text-2xl font-bold mb-3 break-words">' + esc(cover.subject || 'Environment') + '</h2>' +
    (metaItems.length ? '<div class="flex flex-wrap gap-x-8 gap-y-1 text-xs mb-3">' +
      metaItems.map(function (m) {
        return '<div class="min-w-0"><span class="text-neutral-500">' + esc(m[0]) + ': </span><span class="mono break-all text-neutral-300">' + esc(m[1]) + '</span></div>';
      }).join('') + '</div>' : '') +
    (cover.classification ? '<p class="text-[11px] text-neutral-500 uppercase tracking-wider">' + esc(cover.classification) + '</p>' : '') +
  '</div>';

  // Rating banner
  html += '<div class="glass p-6 md:p-8 rounded-xl" style="border-left:6px solid ' + riskColor + '">' +
    '<div class="flex flex-wrap items-center justify-between gap-3 mb-3">' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Overall security risk</p>' +
      '<p class="text-4xl font-bold" style="color:' + riskColor + '">' + esc(bl.risk_label || risk.label || 'Unknown') + '</p></div>' +
    '</div>' +
    '<p class="text-lg leading-relaxed text-neutral-100 exec-headline">' + esc(bl.summary || es.headline) + '</p>' +
  '</div>';

  // Top risks + do first
  const topRisks = bl.top_risks || [];
  const doFirst = bl.do_first || [];
  if (topRisks.length || doFirst.length) {
    html += '<div class="grid grid-cols-1 lg:grid-cols-2 gap-6 exec-cols-2">';
    html += '<div>' + sectionTitle('Top risks') + '<div class="space-y-3">' +
      (topRisks.length ? topRisks.map(function (f, i) {
        return '<div class="glass p-4 rounded-xl" style="border-left:4px solid ' + col(f.severity) + '">' +
          '<h4 class="font-semibold text-sm mb-1">' + (i + 1) + '. ' + esc(f.title) + '</h4>' +
          '<p class="text-xs text-neutral-400 leading-relaxed">' + esc(f.detail) + '</p></div>';
      }).join('') : '<div class="glass p-4 rounded-xl text-sm text-neutral-400">No significant risks were found.</div>') +
    '</div></div>';
    html += '<div>' + sectionTitle('Do this first') + '<div class="space-y-3">' +
      (doFirst.length ? doFirst.map(function (a, i) {
        return '<div class="glass p-4 rounded-xl flex gap-3">' +
          '<div class="w-7 h-7 shrink-0 rounded-full bg-neutral-800 border border-neutral-700 flex items-center justify-center text-xs font-bold">' + (i + 1) + '</div>' +
          '<div class="min-w-0"><p class="text-sm font-semibold leading-snug mb-1">' + esc(a.action) + '</p>' +
          '<div class="flex flex-wrap gap-2 items-center text-[10px] uppercase font-bold">' +
            '<span class="px-2 py-0.5 rounded border border-neutral-600 text-neutral-400 whitespace-nowrap">' + esc(a.timeframe) + '</span>' +
            (a.owner ? '<span class="text-neutral-500 normal-case font-medium text-xs">Suggested owner: ' + esc(a.owner) + '</span>' : '') +
          '</div></div></div>';
      }).join('') : '<div class="glass p-4 rounded-xl text-sm text-neutral-400">No urgent actions.</div>') +
    '</div></div></div>';
  }

  // Four key numbers
  if ((bl.figures || []).length) {
    html += '<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 exec-figs">' + bl.figures.map(figure).join('') + '</div>';
  }
  if (cover.statement) {
    html += '<p class="text-[11px] text-neutral-500 italic">' + esc(cover.statement) + '</p>';
  }

  // ── DETAILS ───────────────────────────────────────────────────────────────
  html += '<div class="exec-page-break pt-2"><p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest border-b border-neutral-800 pb-2">Details</p></div>';

  // Why this rating
  if (risk.rationale || risk.business_impact) {
    html += '<div>' + sectionTitle('Why this rating') + '<div class="glass p-5 rounded-xl space-y-3">' +
      (risk.rationale ? '<p class="text-sm text-neutral-300"><span class="font-semibold">Reason: </span>' + esc(risk.rationale) + '</p>' : '') +
      (risk.business_impact ? '<p class="text-sm text-neutral-400"><span class="font-semibold text-neutral-300">What it means: </span>' + esc(risk.business_impact) + '</p>' : '') +
      (risk.basis ? '<p class="text-xs text-neutral-500 italic">' + esc(risk.basis) + '</p>' : '') +
    '</div></div>';
  }

  // Key findings
  html += '<div>' + sectionTitle('All key findings') + '<div class="space-y-3">' +
    (es.key_findings || []).map(function (f) {
      return '<div class="glass p-5 rounded-xl" style="border-left:4px solid ' + col(f.severity) + '">' +
        '<h4 class="font-semibold text-sm mb-1">' + esc(f.title) + '</h4>' +
        '<p class="text-sm text-neutral-300 leading-relaxed">' + esc(f.detail) + '</p></div>';
    }).join('') + '</div></div>';

  // At a glance
  if ((es.glance_cards || []).length) {
    html += '<div>' + sectionTitle('At a glance') + '<div class="grid grid-cols-2 lg:grid-cols-3 gap-4 exec-glance">' +
      es.glance_cards.map(figure).join('') + '</div></div>';
  }

  // Coverage by cloud
  const clouds = es.coverage_rows || [];
  if (clouds.length) {
    html += '<div>' + sectionTitle('What was scanned') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Area</th><th>Status</th><th>Checks</th><th>Issues</th><th>Worst severity</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      clouds.map(function (c) {
        const stKey = c.status === 'scanned' ? 'none' : (c.status === 'partial' ? 'medium' : 'high');
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.name) + '</td>' +
          '<td class="py-4 align-top">' + badge(stKey, c.status_label) +
            (c.reason ? '<div class="text-xs text-neutral-500 mt-1 max-w-xs">' + esc(c.reason) + '</div>' : '') + '</td>' +
          '<td class="py-4 align-top mono text-xs text-neutral-400 break-all">' + esc(c.scope || '—') + '</td>' +
          '<td class="py-4 align-top">' + (c.issues == null ? 'n/a' : esc(c.issues)) + '</td>' +
          '<td class="py-4 pr-6 align-top">' + (c.worst_severity ? badge(c.worst_severity, c.worst_severity_label) : '<span class="text-xs text-neutral-500">n/a</span>') + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }

  // Issues by area
  const areas = es.risk_areas || [];
  if (areas.length) {
    html += '<div>' + sectionTitle('Issues by area') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Area</th><th>Issues</th><th>Resources</th><th>Most serious</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      areas.map(function (t) {
        return '<tr>' +
          '<td class="px-6 py-4"><div class="font-medium">' + esc(t.title) + '</div><div class="text-xs text-neutral-500 mt-1 max-w-xl">' + esc(t.plain) + '</div></td>' +
          '<td class="py-4 align-top">' + esc(t.issues) + '</td>' +
          '<td class="py-4 align-top">' + esc(t.resources_affected) + '</td>' +
          '<td class="py-4 pr-6 align-top">' + badge(t.worst_severity, t.worst_severity_label) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }

  // Issue types to fix first
  const types = es.issues_to_fix_first || [];
  if (types.length) {
    html += '<div>' + sectionTitle('Issue types to fix first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Issue</th><th>Area</th><th>Resources</th><th>Severity</th><th>What to do</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      types.map(function (c) {
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.title) +
            (c.reference ? '<div class="mono text-[10px] text-neutral-500 font-normal mt-1 break-all max-w-[16rem]">' + esc(c.reference) + '</div>' : '') + '</td>' +
          '<td class="py-4 align-top text-xs text-neutral-400">' + esc(c.area) + '</td>' +
          '<td class="py-4 align-top">' + esc(c.resources_affected) + '</td>' +
          '<td class="py-4 align-top">' + badge(c.worst_severity, c.worst_severity_label) + '</td>' +
          '<td class="py-4 pr-6 align-top text-neutral-300 text-xs">' + esc(c.action) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">The identifier under each issue is the rule id, for tickets and audit trails. Exact remediation steps for each resource are in the Findings tab.</p></div>';
  }

  // Resources to review first
  const resources = es.resources_to_review_first || [];
  if (resources.length) {
    html += '<div>' + sectionTitle('Resources to review first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Resource</th><th>Area</th><th>Scope</th><th>Issues</th><th>Worst severity</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      resources.map(function (r) {
        return '<tr>' +
          '<td class="px-6 py-4 mono text-xs break-all">' + esc(r.name) + '</td>' +
          '<td class="py-4 text-xs text-neutral-400">' + esc(r.area) + '</td>' +
          '<td class="py-4 mono text-xs text-neutral-500">' + esc(r.scope || '—') + '</td>' +
          '<td class="py-4">' + esc(r.issues) + '</td>' +
          '<td class="py-4 pr-6">' + badge(r.worst_severity, r.worst_severity_label) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Ranks individual resources carrying the most serious and most numerous issues. Informational notes are not counted.</p></div>';
  }

  // All suggested actions
  html += '<div>' + sectionTitle('All suggested actions') +
    (es.recommended_actions_basis ? '<p class="text-xs text-neutral-500 italic mb-3">' + esc(es.recommended_actions_basis) + '</p>' : '') +
    '<div class="space-y-3">' +
    (es.recommended_actions || []).map(function (a) {
      return '<div class="glass p-5 rounded-xl flex gap-4">' +
        '<div class="w-8 h-8 shrink-0 rounded-full bg-neutral-800 border border-neutral-700 flex items-center justify-center text-sm font-bold">' + esc(a.priority) + '</div>' +
        '<div class="min-w-0"><div class="flex flex-wrap items-center gap-2 mb-1"><h4 class="font-semibold text-sm">' + esc(a.action) + '</h4>' +
        '<span class="px-2 py-0.5 rounded border border-neutral-600 text-[10px] uppercase font-bold text-neutral-400 whitespace-nowrap">' + esc(a.timeframe) + '</span></div>' +
        '<p class="text-sm text-neutral-400 leading-relaxed">' + esc(a.why) + '</p>' +
        (a.owner ? '<p class="text-xs text-neutral-500 mt-1">Suggested owner: ' + esc(a.owner) + '</p>' : '') + '</div></div>';
    }).join('') + '</div></div>';

  // Compliance
  const co = es.compliance_overview;
  if (co) {
    html += '<div>' + sectionTitle('Compliance exposure') + '<div class="glass p-5 rounded-xl space-y-3">' +
      '<p class="text-sm text-neutral-300 leading-relaxed">' + esc(co.statement) + '</p>' +
      '<div class="flex flex-wrap gap-2">' +
      (co.most_affected || []).map(function (f) {
        return '<span class="px-3 py-1 rounded-full bg-neutral-800 border border-neutral-700 text-xs">' + esc(f.framework) + ' <span class="mono text-neutral-500">' + esc(f.findings) + (f.findings === 1 ? ' finding' : ' findings') + '</span></span>';
      }).join('') + '</div>' +
      '<p class="text-xs text-neutral-500 italic">' + esc(co.disclaimer) + ' Details are in the Compliance tab.</p></div></div>';
  }

  // ── APPENDIX ──────────────────────────────────────────────────────────────
  const summaryCls = 'cursor-pointer px-5 py-4 text-sm font-semibold text-neutral-200';
  html += '<div class="exec-page-break pt-2"><p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest border-b border-neutral-800 pb-2">Appendix</p></div>';

  const mt = es.methodology;
  if (mt) {
    html += '<details class="glass rounded-xl exec-appendix"><summary class="' + summaryCls + '">Methodology: how this report was produced</summary>' +
      '<div class="px-5 pb-5 space-y-5">' +
      '<ol class="space-y-3">' +
      (mt.steps || []).map(function (st, i) {
        return '<li class="flex gap-3"><span class="w-6 h-6 shrink-0 rounded-full bg-neutral-800 border border-neutral-700 flex items-center justify-center text-xs font-bold">' + (i + 1) + '</span>' +
          '<div class="text-sm"><span class="font-semibold">' + esc(st.step) + '. </span><span class="text-neutral-400 leading-relaxed">' + esc(st.detail) + '</span></div></li>';
      }).join('') + '</ol>' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-2">How the overall risk rating is decided</p>' +
      '<table class="w-full text-left text-sm"><tbody class="divide-y divide-neutral-800">' +
      (mt.rating_rules || []).map(function (r) {
        return '<tr><td class="py-2 pr-4 font-semibold whitespace-nowrap align-top">' + esc(r.level) + '</td><td class="py-2 text-neutral-400">' + esc(r.rule) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-sm text-neutral-400 leading-relaxed"><span class="font-semibold text-neutral-300">Prioritization. </span>' + esc(mt.prioritization) + '</p>' +
      '<p class="text-sm text-neutral-400 leading-relaxed"><span class="font-semibold text-neutral-300">Timeframes and owners. </span>' + esc(mt.timeframes) + '</p>' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Limitations</p>' +
      '<ul class="list-disc pl-5 space-y-1 text-sm text-neutral-400">' +
      (mt.limitations || []).map(function (l) { return '<li>' + esc(l) + '</li>'; }).join('') + '</ul></div>' +
    '</div></details>';
  }

  html += '<details class="glass rounded-xl exec-appendix"><summary class="' + summaryCls + '">About this report</summary>' +
    '<div class="px-5 pb-5 space-y-4">' +
    '<p class="text-sm text-neutral-300">' + esc(sc.description || '') + '</p>' +
    (sc.discovery ? '<p class="text-sm text-neutral-400">' + esc(sc.discovery) + '</p>' : '') +
    '<ul class="list-disc pl-5 space-y-1 text-xs text-neutral-400">' +
      (es.notes || []).map(function (n) { return '<li>' + esc(n) + '</li>'; }).join('') + '</ul>' +
    '<p class="text-xs text-neutral-500">For technical detail, use the other tabs of this report.</p>' +
  '</div></details>';

  html += '<details class="glass rounded-xl exec-appendix"><summary class="' + summaryCls + '">Plain-language glossary</summary>' +
    '<dl class="px-5 pb-5 space-y-2 text-xs text-neutral-400">' +
    (es.glossary || []).map(function (t) { return '<div><dt class="font-semibold text-neutral-300 inline">' + esc(t.term) + ': </dt><dd class="inline">' + esc(t.meaning) + '</dd></div>'; }).join('') +
    '</dl></details>';

  root.innerHTML = html;
}

// Printing: the appendix is collapsed on screen but must be open on paper.
(function () {
  let closedBeforePrint = [];
  window.addEventListener('beforeprint', function () {
    closedBeforePrint = [];
    document.querySelectorAll('#executive-content details').forEach(function (d) {
      if (!d.open) { closedBeforePrint.push(d); d.open = true; }
    });
  });
  window.addEventListener('afterprint', function () {
    closedBeforePrint.forEach(function (d) { d.open = false; });
    closedBeforePrint = [];
  });
})();

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────

function switchTab(id) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('tab-active'));
  document.getElementById('tab-' + id).classList.add('tab-active');
  document.querySelectorAll('main section').forEach(s => s.classList.add('hidden'));
  document.getElementById('section-' + id).classList.remove('hidden');
}

// ── MODAL ─────────────────────────────────────────────────────────────────────

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.body.style.overflow = 'auto';
}
function openModal(html) {
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('modal-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'modal-overlay') closeModal();
  });

  const tbody = document.getElementById('findings-table-body');
  tbody.addEventListener('click', (e) => {
    const row = e.target.closest('[data-finding-index]');
    if (!row) return;
    const idx = parseInt(row.dataset.findingIndex, 10);
    openFindingModal(idx);
  });

  const complianceGrid = document.getElementById('compliance-frameworks-grid');
  complianceGrid.addEventListener('click', (e) => {
    const row = e.target.closest('[data-fw-idx]');
    if (!row) return;
    openComplianceModal(parseInt(row.dataset.fwIdx, 10), parseInt(row.dataset.controlIdx, 10));
  });

  const modalBody = document.getElementById('modal-body');
  modalBody.addEventListener('click', (e) => {
    const row = e.target.closest('[data-finding-index]');
    if (!row || !modalBody.contains(row)) return;
    e.stopPropagation();
    const idx = parseInt(row.dataset.findingIndex, 10);
    const f = _currentComplianceMatches && _currentComplianceMatches[idx];
    if (!f) return;
    renderFindingDetail(f);
  });

  document.getElementById('section-diffs').addEventListener('click', (e) => {
    const tile = e.target.closest('[data-diff-tile]');
    if (tile) { openDiffModal(parseInt(tile.dataset.diffTile, 10)); return; }
    const fwBtn = e.target.closest('[data-diff-fw]');
    if (fwBtn) openComplianceDiffModal(parseInt(fwBtn.dataset.diffFw, 10), fwBtn.dataset.diffList);
  });

  updateTabCounts();
  renderDashboard();
  try { renderExecutiveSummary(); } catch (e) { console.error('Executive summary render failed:', e); }
  populateAreaFilter();
  applyFilters();
  renderScanInfo();
  renderCompliance();
  renderCompliancePosture();
  try { renderDiffs(); } catch (e) { console.error('Diffs render failed:', e); }
  renderStats();
  try { renderInventory(); } catch (e) { console.error('Inventory render failed:', e); }
});

// ── TAB LABEL COUNTS ─────────────────────────────────────────────────────────

function updateTabCounts() {
  document.getElementById('tab-findings').textContent = 'Findings(' + reportData.stats.total + ')';
  const cs = reportData.compliance_summary;
  document.getElementById('tab-compliance').textContent = 'Compliance(' + (cs && cs.frameworks ? cs.frameworks.length : 0) + ')';
  if (reportData.diffs && reportData.diffs.enabled) document.getElementById('tab-diffs').classList.remove('hidden');
  if (Array.isArray(reportData.inventory) && reportData.inventory.length) { const t = document.getElementById('tab-inventory'); t.classList.remove('hidden'); t.textContent = 'Inventory(' + reportData.inventory.length + ')'; }
}

// ── INVENTORY (ubel-vm: host, objects with findings and every installed package, in one list) ──────────────────────────
const INV_STATE_CLASS = { infected: 'text-red-400', vulnerable: 'text-orange-400', non_compliant: 'text-orange-400', unknown: 'text-yellow-400', partially_assessed: 'text-yellow-400', clean: 'text-green-400', assessed: 'text-green-400' };
let INV_SHOWN = [];
function invFindingCount(c) {
  if (c.type === 'dependency') return (reportData.findings || []).filter(function (f) { return f.vuln && f.vuln.affected_package_id === c.component_id; }).length;
  return c.details && typeof c.details.findings === 'number' ? c.details.findings : (c.type === 'host' ? reportData.findings.length : 0);
}
function renderInventory() {
  const all = Array.isArray(reportData.inventory) ? reportData.inventory : [];
  const body = document.getElementById('inventory-table-body');
  if (!body) return;
  const fill = function (id, values) { const sel = document.getElementById(id); if (sel && sel.options.length <= 1) Array.from(new Set(values.filter(Boolean))).sort().forEach(function (v) { const o = document.createElement('option'); o.value = v; o.textContent = v.replace(/_/g, ' '); sel.appendChild(o); }); };
  fill('i-type', all.map(function (c) { return c.type; }));
  fill('i-state', all.map(function (c) { return c.status; }));
  const q = (document.getElementById('i-search').value || '').toLowerCase();
  const ty = document.getElementById('i-type').value;
  const st = document.getElementById('i-state').value;
  INV_SHOWN = all.filter(function (c) {
    if (ty !== 'all' && c.type !== ty) return false;
    if (st !== 'all' && c.status !== st) return false;
    return !q || (String(c.component_name) + ' ' + String(c.component_id) + ' ' + (c.details && c.details.ecosystem || '')).toLowerCase().indexOf(q) !== -1;
  });
  const LIMIT = 2000;
  body.innerHTML = INV_SHOWN.slice(0, LIMIT).map(function (c, i) {
    return '<tr class="hover:bg-neutral-800/40 cursor-pointer" onclick="openInventoryItem(' + i + ')"><td class="px-4 py-3 text-sm font-medium break-all">' + escH(c.component_name) + '</td>'
      + '<td class="px-4 py-3"><span class="px-2 py-0.5 rounded border border-neutral-700 text-[11px] mono">' + escH(c.type) + '</span></td>'
      + '<td class="px-4 py-3 text-xs font-bold uppercase ' + (INV_STATE_CLASS[c.status] || 'text-neutral-400') + '">' + escH(String(c.status).replace(/_/g, ' ')) + '</td>'
      + '<td class="px-4 py-3 text-sm text-neutral-300">' + invFindingCount(c) + '</td><td class="px-4 py-3 text-right text-xs text-red-400">View Details</td></tr>';
  }).join('') || '<tr><td colspan="5" class="px-4 py-6 text-sm text-neutral-500">No component matches.</td></tr>';
  document.getElementById('i-count').textContent = INV_SHOWN.length + ' of ' + all.length + ' component(s)' + (INV_SHOWN.length > LIMIT ? ' - showing the first ' + LIMIT + '; narrow the filter' : '');
}
function openInventoryItem(i) {
  const c = INV_SHOWN[i]; if (!c) return;
  const d = Object.assign({}, c.details || {});
  ['dependencies', 'parents', 'introduced_by', 'paths', 'suggested_fixes', 'vulnerable_transitive_dependencies', 'policy_violations', 'license_info', 'scopes'].forEach(function (k) { if (d[k] && typeof d[k] === 'object' && !Array.isArray(d[k])) d[k] = JSON.stringify(d[k]); });
  if (Array.isArray(d.paths)) d.paths = d.paths.map(function (p) { return p && p.text ? p.text : String(p); });
  const related = c.type === 'dependency' ? (reportData.findings || []).filter(function (f) { return f.vuln && f.vuln.affected_package_id === c.component_id; }) : [];
  openModal('<div class="space-y-4"><div class="flex items-center gap-3"><span class="px-2 py-0.5 rounded border border-neutral-700 text-xs mono">' + escH(c.type) + '</span><h2 class="text-lg font-semibold text-white break-all">' + escH(c.component_name) + '</h2></div>'
    + '<div class="text-xs text-neutral-500">State: <span class="font-bold uppercase ' + (INV_STATE_CLASS[c.status] || '') + '">' + escH(String(c.status).replace(/_/g, ' ')) + '</span></div>'
    + (related.length ? '<div><h3 class="text-sm font-semibold mb-2">Advisories (' + related.length + ')</h3>' + related.map(function (f) { return '<div class="text-xs mono text-neutral-300 border-b border-neutral-800 py-1">' + escH(f.vuln.id) + ' - ' + escH(f.severity) + ' - ' + escH(f.vuln.summary || '') + '</div>'; }).join('') + '</div>' : '')
    + '<div class="space-y-2">' + kvLines(d) + '</div></div>');
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────

function renderDashboard() {
  const s = reportData.stats;
  document.getElementById('report-id').textContent = 'GENERATED_AT: ' + reportData.generated_at;
  document.getElementById('stat-critical').textContent = s.bySeverity.critical;
  document.getElementById('stat-high').textContent     = s.bySeverity.high;
  document.getElementById('stat-medium').textContent   = s.bySeverity.medium;
  document.getElementById('stat-low').textContent      = s.bySeverity.low;
  document.getElementById('stat-info').textContent     = s.bySeverity.info;

  new Chart(document.getElementById('severityChart').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Critical','High','Medium','Low','Info'],
      datasets: [{
        data: [s.bySeverity.critical, s.bySeverity.high, s.bySeverity.medium, s.bySeverity.low, s.bySeverity.info],
        backgroundColor: ['#ef4444','#f87171','#fb923c','#60a5fa','#a3a3a3'],
        borderWidth: 0,
      }],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10 } } } },
  });

  const cov = reportData.coverage || {};
  new Chart(document.getElementById('checksChart').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Passed', 'Failed', 'Not applicable', 'Not assessed'],
      datasets: [{ data: [cov.passed || 0, cov.failed || 0, cov.not_applicable || 0, cov.not_assessed || 0], backgroundColor: ['#4ade80', '#ef4444', '#525252', '#fb923c'], borderWidth: 0 }],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10 } } } },
  });

  const areas = Object.entries(s.byArea).sort((a,b) => b[1]-a[1]).slice(0, 8);
  new Chart(document.getElementById('areaChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: areas.map(([k]) => areaLabel(k)),
      datasets: [{ data: areas.map(([,v]) => v), backgroundColor: '#60a5faaa', borderRadius: 4 }],
    },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373', precision: 0 } },
                y: { grid: { display: false }, ticks: { color: '#a3a3a3', font: { size: 10 } } } } },
  });
}

// ── FILTERS / FINDINGS TABLE ──────────────────────────────────────────────────

let _filtered = reportData.findings;
const _hasScope = (reportData.findings || []).some(function (f) { return f.scope; });
const _scopeLabel = (reportData.profile && reportData.profile.scope_label) || 'Scope';
const _scopesLabel = (reportData.profile && reportData.profile.scopes_label) || 'Scopes';

function areaLabel(a) {
  const ai = reportData.profile && reportData.profile.areas && reportData.profile.areas[a];
  return ai && ai.label ? ai.label : a;
}

function populateAreaFilter() {
  const sel = document.getElementById('f-area');
  const areas = [...new Set(reportData.findings.map(f => f.area))].sort();
  for (const a of areas) {
    const opt = document.createElement('option');
    opt.value = a;
    opt.textContent = areaLabel(a);
    sel.appendChild(opt);
  }
  const th = document.getElementById('th-scope');
  if (th) { if (_hasScope) th.textContent = _scopeLabel; else th.classList.add('hidden'); }
}

function applyFilters() {
  const q = document.getElementById('f-search').value.trim().toLowerCase();
  const sev = document.getElementById('f-severity').value;
  const area = document.getElementById('f-area').value;

  _filtered = reportData.findings.filter(f => {
    if (sev !== 'all' && f.severity !== sev) return false;
    if (area !== 'all' && f.area !== area) return false;
    if (q && !(
      (f.title||'').toLowerCase().includes(q) ||
      (f.resource||'').toLowerCase().includes(q) ||
      (f.area||'').toLowerCase().includes(q) ||
      (f.check||'').toLowerCase().includes(q) ||
      (f.scope||'').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderFindingsTable();
}

function renderFindingsTable() {
  const tbody = document.getElementById('findings-table-body');
  tbody.innerHTML = '';

  if (!_filtered.length) {
    tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-12 text-center text-neutral-500 italic">No findings match the current filters.</td></tr>';
    return;
  }

  _filtered.forEach((f, idx) => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.findingIndex = String(idx);
    row.innerHTML =
      '<td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + sevClass(f.severity) + '">' + escH(f.severity) + '</span></td>' +
      '<td class="px-4 py-3 text-xs text-neutral-300">' + escH(areaLabel(f.area)) + '</td>' +
      '<td class="px-4 py-3 text-sm font-medium text-white">' + escH(f.title) + '</td>' +
      '<td class="px-4 py-3 mono text-[11px] text-neutral-400 break-all">' + escH(f.resource) + '</td>' +
      (_hasScope ? '<td class="px-4 py-3 mono text-[11px] text-neutral-500">' + escH(f.scope || '\u2014') + '</td>' : '');
    tbody.appendChild(row);
  });
}

function openFindingModal(idx) {
  const f = _filtered[idx];
  if (!f) return;
  renderFindingDetail(f);
}

// Pulled out of openFindingModal() so the compliance-control modal below can
// open a finding's full detail view directly from a matched finding object,
// without needing that finding's index into whatever the Findings tab's
// current filter state (_filtered) happens to be.
function renderFindingDetail(f) {
  openModal(
    '<div class="space-y-4">' +
      '<div class="flex items-center gap-3">' +
        '<span class="px-2 py-0.5 rounded border text-xs uppercase font-bold ' + sevClass(f.severity) + '">' + escH(f.severity) + '</span>' +
        '<h2 class="text-lg font-semibold text-white">' + escH(f.title) + '</h2>' +
      '</div>' +
      '<div class="grid grid-cols-2 gap-3 text-xs">' +
        '<div><span class="text-neutral-500">Area</span><div class="mono text-neutral-200">' + escH(areaLabel(f.area)) + '</div></div>' +
        '<div><span class="text-neutral-500">Check</span><div class="mono text-neutral-200">' + escH(f.check) + '</div></div>' +
        (f.scope ? '<div><span class="text-neutral-500">' + escH(_scopeLabel) + '</span><div class="mono text-neutral-200">' + escH(f.scope) + '</div></div>' : '') +
        (f.action ? '<div><span class="text-neutral-500">Action</span><div class="mono text-neutral-200">' + escH(f.action) + '</div></div>' : '') +
        '<div class="col-span-2"><span class="text-neutral-500">Resource</span><div class="mono text-neutral-200 break-all">' + escH(f.resource) + '</div></div>' +
        '<div class="col-span-2"><span class="text-neutral-500">Detected</span><div class="mono text-neutral-200">' + escH(f.timestamp) + '</div></div>' +
      '</div>' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Description</p><p class="text-sm text-neutral-300">' + escH(f.description) + '</p></div>' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Remediation</p><p class="text-sm text-neutral-300 mono bg-neutral-900 p-3 rounded-lg break-words">' + escH(f.remediation) + '</p></div>' +
      (f.evidence ? '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Evidence</p><p class="text-xs text-neutral-400 mono bg-neutral-900 p-3 rounded-lg break-all">' + escH(f.evidence) + '</p></div>' : '') +
      renderComplianceSection(f.compliance) +
    '</div>'
  );
}

// ── SCAN INFO ─────────────────────────────────────────────────────────────────

const STATUS_LABEL = { pass: 'Passed', fail: 'Failed', na: 'Not applicable', unassessed: 'Not assessed' };
const STATUS_CLASS = { pass: 'text-green-400', fail: 'text-red-400', na: 'text-neutral-500', unassessed: 'text-orange-400' };

function kvLines(obj) {
  const lines = [];
  Object.keys(obj || {}).forEach(function (k) {
    const v = obj[k];
    if (v === null || v === undefined || v === '') return;
    const txt = Array.isArray(v) ? v.join(', ') : (typeof v === 'object' ? JSON.stringify(v) : String(v));
    lines.push('<div class="flex justify-between gap-4 border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs shrink-0">' + escH(k.replace(/_/g, ' ')) + '</span><span class="mono text-xs break-all text-right">' + escH(txt) + '</span></div>');
  });
  return lines.join('');
}

function renderScanInfo() {
  const set = function (id, v) { const el = document.getElementById(id); if (el) el.textContent = v; };
  set('sys-tool', reportData.tool);
  set('sys-version', reportData.tool_version || '\u2014');
  set('sys-asset', reportData.asset_name || '\u2014');
  set('sys-asset-id', reportData.asset_id || '\u2014');
  set('sys-asset-type', reportData.asset_type || '\u2014');
  set('sys-machine-id', reportData.machine_id || '\u2014');
  set('sys-generated', reportData.generated_at);

  const so = reportData.scan_options || {};
  set('sys-filter', so.min_severity ? so.min_severity + (so.hidden_by_filter ? ' (' + so.hidden_by_filter + ' hidden)' : '') : '\u2014');

  const t = document.getElementById('sys-target');
  if (t) t.innerHTML = kvLines(reportData.target) || '<span class="text-neutral-500">\u2014</span>';

  const o = document.getElementById('sys-options');
  const opt = {};
  Object.keys(so).forEach(function (k) { if (k !== 'min_severity' && k !== 'hidden_by_filter') opt[k] = so[k]; });
  if (o) o.innerHTML = kvLines(opt) || '<span class="text-neutral-500">defaults</span>';

  const cov = reportData.coverage || {};
  const c = document.getElementById('sys-coverage');
  if (c) {
    let h = '<div class="' + (cov.status === 'complete' ? 'text-green-400' : 'text-orange-400') + ' font-semibold">' +
      (cov.status === 'complete' ? 'Complete: every applicable check was evaluated.' : 'Incomplete: ' + (cov.not_assessed || 0) + ' check(s) could not be evaluated.') + '</div>';
    (cov.not_assessed_checks || []).forEach(function (n) {
      h += '<div><span class="text-orange-400">' + escH(n.check) + '</span> <span class="text-neutral-500">\u2014 ' + escH(n.reason) + '</span></div>';
    });
    (cov.notes || []).forEach(function (n) { h += '<div class="text-yellow-500/90">' + escH(n) + '</div>'; });
    c.innerHTML = h;
  }

  const body = document.getElementById('sys-checks-body');
  if (body) {
    const order = { fail: 0, unassessed: 1, pass: 2, na: 3 };
    const sevOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
    const rows = (reportData.checks || []).slice().sort(function (a, b) {
      return (order[a.status] - order[b.status]) || ((sevOrder[a.severity] || 9) - (sevOrder[b.severity] || 9)) || a.check.localeCompare(b.check);
    });
    body.innerHTML = rows.map(function (k) {
      return '<tr><td class="px-4 py-2 mono text-[11px] text-neutral-300">' + escH(k.check) + '</td>' +
        '<td class="px-4 py-2 text-xs text-neutral-400">' + escH(areaLabel(k.area)) + '</td>' +
        '<td class="px-4 py-2"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + sevClass(k.severity) + '">' + escH(k.severity) + '</span></td>' +
        '<td class="px-4 py-2 text-xs ' + STATUS_CLASS[k.status] + '">' + STATUS_LABEL[k.status] + (k.findings ? ' (' + k.findings + ')' : '') + '</td>' +
        '<td class="px-4 py-2 text-[11px] text-neutral-500">' + escH(k.reason || '') + '</td></tr>';
    }).join('');
  }
}

// ── COMPLIANCE POSTURE ────────────────────────────────────────────────────────
// Per framework: of the evaluated checks mapped to it, how many pass / fail / could not be assessed.

function postureBar(e) {
  const t = e.checks || 1;
  const w = function (n) { return (n / t * 100).toFixed(1) + '%'; };
  return '<div class="flex h-1.5 rounded-full overflow-hidden bg-neutral-800">' +
    '<div style="width:' + w(e.passed) + ';background:#4ade80"></div>' +
    '<div style="width:' + w(e.failed) + ';background:#ef4444"></div>' +
    '<div style="width:' + w(e.not_assessed) + ';background:#fb923c"></div></div>';
}

function renderCompliancePosture() {
  const el = document.getElementById('compliance-posture');
  const fws = (reportData.compliance_posture && reportData.compliance_posture.frameworks) || [];
  if (!el || !fws.length) return;
  el.innerHTML =
    '<h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Check posture by framework</h3>' +
    '<p class="text-[11px] text-neutral-500">Of the evaluated checks that map to each framework, how many passed. Green = passed, red = failed, orange = could not be assessed.</p>' +
    '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">' +
    fws.map(function (e) {
      return '<div class="glass p-4 rounded-xl space-y-2"><div class="flex justify-between gap-3"><div><p class="text-sm font-semibold">' + escH(e.name) + '</p>' +
        (e.version ? '<p class="text-[10px] text-neutral-500 mono">' + escH(e.version) + '</p>' : '') + '</div>' +
        '<div class="text-right whitespace-nowrap"><p class="mono text-sm text-neutral-200">' + e.passed + ' / ' + e.checks + '</p><p class="text-[10px] text-neutral-500">checks passing</p></div></div>' +
        postureBar(e) + '</div>';
    }).join('') + '</div>';
  el.classList.remove('hidden');
}

// ── DETAILED STATS ────────────────────────────────────────────────────────────
// Same card layout as the SCA report: one doughnut + figures per dimension.

function renderStats() {
  const s = reportData.stats || {};
  const cov = reportData.coverage || {};
  const findings = reportData.findings || [];
  const set = function (id, val) { const el = document.getElementById(id); if (el) el.textContent = val; };

  set('stats-checks-total', cov.checks_total || 0);
  set('stats-checks-eval', cov.evaluated || 0);
  set('stats-checks-pass', cov.passed || 0);
  set('stats-checks-fail', cov.failed || 0);
  set('stats-checks-na', cov.not_applicable || 0);
  set('stats-checks-un', cov.not_assessed || 0);
  set('stats-pass-rate', cov.pass_rate == null ? 'n/a' : cov.pass_rate + '%');

  const checks = new Set(), resources = new Set();
  const byCheck = {}, byResource = {};
  findings.forEach(function (f) {
    checks.add(f.check);
    const rk = f.area + '::' + f.scope + '::' + f.resource;
    resources.add(rk);
    byCheck[f.check] = (byCheck[f.check] || 0) + 1;
    if (!byResource[rk]) byResource[rk] = { label: f.resource + (f.scope ? '  (' + f.scope + ')' : ''), count: 0 };
    byResource[rk].count++;
  });
  const sev = s.bySeverity || {};
  set('stats-total-findings', findings.length);
  set('stats-distinct-checks', checks.size);
  set('stats-distinct-resources', resources.size);
  ['critical', 'high', 'medium', 'low', 'info'].forEach(function (k) { set('stats-sev-' + k, sev[k] || 0); });

  const bar = function (label, count, max) {
    return '<div class="flex items-center gap-3 py-1.5 border-b border-neutral-800 last:border-0">' +
      '<span class="mono text-xs text-neutral-300 truncate flex-1" title="' + escH(label) + '">' + escH(label) + '</span>' +
      '<div class="w-40 bg-neutral-800 rounded-full h-1.5 shrink-0"><div class="bg-red-500 h-1.5 rounded-full" style="width:' + (max ? (count / max) * 100 : 0) + '%"></div></div>' +
      '<span class="mono text-xs text-neutral-400 w-8 text-right shrink-0">' + count + '</span></div>';
  };
  const topEl = document.getElementById('stats-top-checks');
  if (topEl) {
    const e = Object.entries(byCheck).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 15);
    topEl.innerHTML = e.length ? e.map(function (x) { return bar(x[0], x[1], e[0][1]); }).join('') : '<p class="text-xs text-neutral-500 italic">No findings detected.</p>';
  }
  const hotEl = document.getElementById('stats-hot-resources');
  if (hotEl) {
    const e = Object.values(byResource).sort(function (a, b) { return b.count - a.count; }).slice(0, 15);
    hotEl.innerHTML = e.length ? e.map(function (r) { return bar(r.label, r.count, e[0].count); }).join('') : '<p class="text-xs text-neutral-500 italic">No findings detected.</p>';
  }

  const posture = document.getElementById('stats-posture');
  if (posture) {
    const fws = ((reportData.compliance_posture && reportData.compliance_posture.frameworks) || []).slice(0, 8);
    posture.innerHTML = fws.length ? fws.map(function (e) {
      return '<div class="space-y-1"><div class="flex justify-between text-xs"><span class="text-neutral-300">' + escH(e.name) + '</span><span class="mono text-neutral-400">' + e.passed + ' / ' + e.checks + '</span></div>' + postureBar(e) + '</div>';
    }).join('') : '<p class="text-xs text-neutral-500 italic">No checks are mapped to a framework.</p>';
  }

  const tbl = document.getElementById('stats-area-table');
  if (tbl) {
    const by = cov.by_area || {};
    tbl.innerHTML = Object.keys(by).sort().map(function (a) {
      const x = by[a];
      return '<tr><td class="py-2 pr-4 text-xs text-neutral-300">' + escH(areaLabel(a)) + '</td>' +
        '<td class="py-2 pr-4 mono text-xs text-green-400">' + (x.pass || 0) + '</td>' +
        '<td class="py-2 pr-4 mono text-xs text-red-400">' + (x.fail || 0) + '</td>' +
        '<td class="py-2 pr-4 mono text-xs text-neutral-500">' + (x.na || 0) + '</td>' +
        '<td class="py-2 pr-4 mono text-xs text-orange-400">' + (x.unassessed || 0) + '</td></tr>';
    }).join('');
  }

  renderStatsCharts(s, cov);
}

function renderStatsCharts(s, cov) {
  if (typeof Chart === 'undefined') return;
  const dough = function (id, labels, data, colors) {
    const c = document.getElementById(id);
    if (!c) return;
    new Chart(c, { type: 'doughnut', data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderWidth: 0 }] },
      options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10 } } } } });
  };
  dough('statsChecksChart', ['Passed', 'Failed', 'Not applicable', 'Not assessed'], [cov.passed || 0, cov.failed || 0, cov.not_applicable || 0, cov.not_assessed || 0], ['#4ade80', '#ef4444', '#525252', '#fb923c']);
  const sev = s.bySeverity || {};
  dough('statsSevChart', ['Critical', 'High', 'Medium', 'Low', 'Info'], [sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0, sev.info || 0], ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#a3a3a3']);

  const areas = Object.entries(s.byArea || {}).sort(function (a, b) { return b[1] - a[1]; });
  const palette = ['#ef4444', '#fb923c', '#facc15', '#4ade80', '#22d3ee', '#60a5fa', '#a78bfa', '#f472b6', '#a3a3a3', '#34d399', '#f87171', '#818cf8'];
  dough('statsAreaChart', areas.map(function (x) { return areaLabel(x[0]); }), areas.map(function (x) { return x[1]; }), areas.map(function (x, i) { return palette[i % palette.length]; }));

  const scopes = Object.entries(s.byScope || {}).sort(function (a, b) { return b[1] - a[1]; }).slice(0, 12);
  const card = document.getElementById('stats-scope-card');
  const canvas = document.getElementById('scopeChart');
  if (card) card.classList.toggle('hidden', !scopes.length);
  const hd = document.getElementById('stats-scope-title');
  if (hd) hd.textContent = 'Findings by ' + _scopeLabel;
  if (canvas && scopes.length) {
    new Chart(canvas, { type: 'bar', data: { labels: scopes.map(function (x) { return x[0]; }), datasets: [{ data: scopes.map(function (x) { return x[1]; }), backgroundColor: '#a855f7aa', borderRadius: 4 }] },
      options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
        scales: { x: { beginAtZero: true, ticks: { color: '#737373', font: { size: 10 }, precision: 0 }, grid: { color: '#262626' } }, y: { ticks: { color: '#a3a3a3', font: { size: 10 } }, grid: { display: false } } } } });
  }
}

// ── DIFFS ─────────────────────────────────────────────────────────────────────
// Comparison with the previous report of this asset (reportData.diffs, built
// server-side by buildDiffs). Absent when no previous-report lookup was done.
// findings.existing and the compliance lists hold indexes, resolved below.

const DIFF_ROW_CAP = 500;
const DIFF_TILES = [
  { group: 'findings',  list: 'new',      count: 'new_findings',       label: 'New findings',             color: 'text-red-400' },
  { group: 'findings',  list: 'existing', count: 'existing_findings',  label: 'Still existing findings',  color: 'text-yellow-400' },
  { group: 'findings',  list: 'fixed',    count: 'fixed_findings',     label: 'Fixed findings',           color: 'text-green-400' },
  { group: 'areas',  list: 'new',      count: 'new_areas',       label: 'Newly affected areas',  color: 'text-red-400' },
  { group: 'areas',  list: 'existing', count: 'existing_areas',  label: 'Still affected areas',  color: 'text-yellow-400' },
  { group: 'areas',  list: 'resolved', count: 'resolved_areas',  label: 'Resolved areas',        color: 'text-green-400' },
  { group: 'scopes', list: 'new',      count: 'new_scopes',      label: 'Newly affected ' + _scopesLabel.toLowerCase(),  color: 'text-red-400' },
  { group: 'scopes', list: 'existing', count: 'existing_scopes', label: 'Still affected ' + _scopesLabel.toLowerCase(),  color: 'text-yellow-400' },
  { group: 'scopes', list: 'resolved', count: 'resolved_scopes', label: 'Resolved ' + _scopesLabel.toLowerCase(),        color: 'text-green-400' },
];
const DIFF_GROUPS = [
  { group: 'findings', title: 'Findings', hint: 'Matched on area, check, resource and scope.' },
  { group: 'areas',    title: 'Areas',    hint: 'An area is "affected" when it has at least one finding.' },
  { group: 'scopes',   title: _scopesLabel, hint: 'A scope is "affected" when it has at least one finding.' },
];

function diffDeltaHtml(n) {
  if (!n) return '<span class="text-neutral-500">0</span>';
  return n > 0 ? '<span class="text-red-400">+' + n + '</span>' : '<span class="text-green-400">' + n + '</span>';
}

function diffNameOf(group, e) {
  return group === 'areas' ? areaLabel(e.key) : e.key;
}

// Findings behind a findings tile: new / fixed are stored whole, existing as indexes.
function diffFindingList(list) {
  const f = reportData.diffs.findings;
  if (list === 'existing') return f.existing.map(i => reportData.findings[i]).filter(Boolean);
  return f[list] || [];
}

// Findings behind a framework count (see the shape note in buildDiffs).
function diffFrameworkList(fw, list) {
  const f = reportData.diffs.findings;
  const base = list === 'new' ? f.new : list === 'removed' ? f.fixed : reportData.findings;
  return (fw[list] || []).map(i => base[i]).filter(Boolean);
}

function diffControlsOf(f, fwId) {
  const fw = ((f.compliance && f.compliance.frameworks) || []).find(x => x.id === fwId);
  return fw ? (fw.controls || []).map(c => c.id).join(', ') : '';
}

function diffCountsTable(group, items) {
  return '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
    ['Name', 'Before', 'Now', 'Change'].map(c => '<th class="pb-2 pr-4 font-bold">' + c + '</th>').join('') +
    '</tr></thead><tbody class="divide-y divide-neutral-800">' +
    items.map(e =>
      '<tr><td class="py-2 pr-4 mono">' + escH(diffNameOf(group, e)) + '</td>' +
      '<td class="py-2 pr-4 mono text-neutral-400">' + e.previous + '</td>' +
      '<td class="py-2 pr-4 mono text-neutral-200">' + e.current + '</td>' +
      '<td class="py-2 pr-4 mono">' + diffDeltaHtml(e.delta) + '</td></tr>'
    ).join('') + '</tbody></table></div>';
}

// Rows open the usual finding detail view (same hook the compliance modal uses).
// Long lists show the first DIFF_ROW_CAP rows; the findings are in severity order.
function diffFindingsTable(items, fwId) {
  const shown = items.slice(0, DIFF_ROW_CAP);
  _currentComplianceMatches = shown;
  const cols = ['Severity', 'Title', 'Area', 'Resource', _scopeLabel].concat(fwId ? ['Controls'] : []);
  return '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
    cols.map(c => '<th class="pb-2 pr-4 font-bold">' + c + '</th>').join('') +
    '</tr></thead><tbody class="divide-y divide-neutral-800">' +
    shown.map((f, idx) =>
      '<tr class="hover:bg-neutral-800/30 cursor-pointer" data-finding-index="' + idx + '">' +
      '<td class="py-2 pr-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + sevClass(f.severity) + '">' + escH(f.severity) + '</span></td>' +
      '<td class="py-2 pr-4 font-medium">' + escH(f.title) + '</td>' +
      '<td class="py-2 pr-4 mono text-neutral-400">' + escH(areaLabel(f.area)) + '</td>' +
      '<td class="py-2 pr-4 mono text-neutral-400 break-all">' + escH(f.resource) + '</td>' +
      '<td class="py-2 pr-4 mono text-neutral-500">' + escH(f.scope || '\u2014') + '</td>' +
      (fwId ? '<td class="py-2 pr-4 mono text-neutral-500">' + escH(diffControlsOf(f, fwId)) + '</td>' : '') + '</tr>'
    ).join('') + '</tbody></table></div>' +
    (items.length > shown.length
      ? '<p class="text-[11px] text-neutral-500 italic mt-3">Showing the first ' + shown.length + ' of ' + items.length + ' (highest severity first). The Findings tab lists everything.</p>'
      : '');
}

function renderDiffs() {
  const sec = document.getElementById('section-diffs');
  const d = reportData.diffs;
  if (!sec || !d || !d.enabled) return;

  let html = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2>';
  if (d.previous) {
    html += '<p class="text-xs text-neutral-500 mono">vs previous report ' + escH(d.previous.report_id || d.previous.bundle || '') +
      (d.previous.generated_at ? ' (' + escH(d.previous.generated_at) + ')' : '') + '</p>';
  }
  html += '</div>';

  if (d.error) {
    sec.innerHTML = html + '<div class="glass rounded-xl p-6 text-sm text-neutral-400">The comparison with the previous report could not be built: ' + escH(d.error) + '</div>';
    return;
  }
  if (!d.previous || !d.counts) {
    sec.innerHTML = html + '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
    return;
  }

  (d.notes || []).forEach(n => {
    html += '<p class="text-xs text-yellow-500/90 bg-neutral-900/50 p-3 rounded-lg border border-neutral-800">' + escH(n) + '</p>';
  });

  const _dHasScopes = ['new', 'existing', 'resolved'].some(l => (d.scopes && d.scopes[l] || []).length);
  DIFF_GROUPS.forEach(g => {
    if (g.group === 'scopes' && !_dHasScopes) return;
    html += '<div class="space-y-3"><div><h3 class="text-lg font-bold">' + g.title + '</h3><p class="text-xs text-neutral-500">' + g.hint + '</p></div>' +
      '<div class="grid grid-cols-2 md:grid-cols-3 gap-4">';
    DIFF_TILES.forEach((t, i) => {
      if (t.group !== g.group) return;
      html += '<button type="button" data-diff-tile="' + i + '" class="glass rounded-xl p-6 text-left hover:border-neutral-500 transition-colors aspect-square md:aspect-auto md:min-h-[9rem] flex flex-col justify-between">' +
        '<span class="text-[10px] uppercase tracking-widest text-neutral-500 font-bold">' + t.label + '</span>' +
        '<span class="text-4xl font-bold mono ' + t.color + '">' + (d.counts[t.count] || 0) + '</span></button>';
    });
    html += '</div>';

    // Services / providers: before/now numbers for everything that changed.
    if (g.group !== 'findings') {
      const changed = [].concat(d[g.group].new, d[g.group].existing, d[g.group].resolved)
        .filter(e => e.delta !== 0)
        .sort((a, b) => Math.abs(b.delta) - Math.abs(a.delta) || diffNameOf(g.group, a).localeCompare(diffNameOf(g.group, b)));
      html += changed.length
        ? '<div class="glass rounded-xl p-4">' + diffCountsTable(g.group, changed) + '</div>'
        : '<p class="text-xs text-neutral-500 italic">No change in finding counts for any ' + (g.group === 'areas' ? 'area' : 'scope') + '.</p>';
    }
    html += '</div>';
  });

  if (d.compliance && d.compliance.frameworks && d.compliance.frameworks.length) {
    html += '<div class="space-y-3"><div><h3 class="text-lg font-bold">Compliance frameworks</h3>' +
      '<p class="text-xs text-neutral-500">Findings mapped to each framework, compared with the previous report.</p></div>' +
      '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    d.compliance.frameworks.forEach((fw, fi) => {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + escH(fw.name) + '</p>' +
        (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + escH(fw.version) + '</p>' : '') + '</div>' +
        '<div class="grid grid-cols-3 gap-2">';
      [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(g => {
        html += '<button type="button" data-diff-fw="' + fi + '" data-diff-list="' + g[0] + '" class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors">' +
          '<span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + g[1] + '</span>' +
          '<span class="block text-2xl font-bold mono ' + g[2] + '">' + fw[g[0]].length + '</span></button>';
      });
      html += '</div></div>';
    });
    html += '</div></div>';
  } else if (!d.compliance) {
    html += '<p class="text-xs text-neutral-500">Compliance changes are not shown: the previous report has no compliance mapping to compare against.</p>';
  }

  sec.innerHTML = html;
}

function openComplianceDiffModal(fi, list) {
  const d = reportData.diffs;
  const fw = d && d.compliance && d.compliance.frameworks[fi];
  if (!fw || !fw[list]) return;
  const labels = { new: 'New', unchanged: 'Still existing', removed: 'Resolved' };
  const items = diffFrameworkList(fw, list);
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(fw.name) + ' \u2014 ' + labels[list] + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' +
    (items.length ? diffFindingsTable(items, fw.id) : '<p class="text-sm text-neutral-500 italic">None.</p>'));
}

function openDiffModal(i) {
  const t = DIFF_TILES[i];
  const d = reportData.diffs;
  if (!t || !d) return;
  const items = t.group === 'findings' ? diffFindingList(t.list) : ((d[t.group] && d[t.group][t.list]) || []);
  let body;
  if (!items.length) body = '<p class="text-sm text-neutral-500 italic">None.</p>';
  else if (t.group === 'findings') body = diffFindingsTable(items, null);
  else body = diffCountsTable(t.group, items);
  openModal('<h3 class="text-lg font-bold mb-1">' + t.label + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}
`;
}

export { generateHtmlReport, buildReportPayload, buildDiffs, buildCoverage, buildCompliancePosture };
