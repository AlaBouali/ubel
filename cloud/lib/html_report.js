'use strict';
// html_report.js — HTML report generator for cloud-scanner findings
//
// Input:  reporter (lib/report.js Reporter instance), meta (see
//   buildReportPayload below for its fields)
//
// Output: HTML string (caller writes to disk)
//
// Static assets (Tailwind, Chart.js, Google Fonts) are pulled in from the
// shared `sca` module the same way ubel-sast's HTML report does, so the
// report stays a single self-contained file with no CDN/network calls at
// view time — consistent with UBEL's no-telemetry, offline-friendly
// posture. cloud-scanner is an ES module ("type": "module" in the node
// package), so they are imported statically.
//
// The Executive Summary (plain-language overview for non-technical readers)
// is built once, server-side, in ./executive_summary.js and attached to the
// report payload, so the JSON report and the HTML tab show the same content.

const TOOL_NAME = 'cloud-scanner';

import { getTailwindScript } from "../../sca/tailwindcss.js";
import { getChartJSScript } from "../../sca/chartjs.js";
import { getGoogleFontsScript } from "../../sca/googlefonts.js";
import { summarizeCompliance } from "../../sca/compliance_mappings.js";
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
    .replace(/`/g, '\\u0060');
}

function escapeHtml(s) {
  return String(s == null ? '' : s).replace(/[&<>"']/g, (m) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[m]));
}

// ─── stats builder ───────────────────────────────────────────────────────────

const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];

function buildStats(findings) {
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const byProvider = {};
  const byService = {};
  const byRegion = {};

  for (const f of findings) {
    const sev = SEVERITIES.includes(f.severity) ? f.severity : 'info';
    bySeverity[sev]++;
    byProvider[f.provider] = (byProvider[f.provider] || 0) + 1;
    const svcKey = `${f.provider}/${f.service}`;
    byService[svcKey] = (byService[svcKey] || 0) + 1;
    if (f.region) byRegion[f.region] = (byRegion[f.region] || 0) + 1;
  }

  return { total: findings.length, bySeverity, byProvider, byService, byRegion };
}

// ─── main export ──────────────────────────────────────────────────────────────

/**
 * Builds the exact data object the HTML report renders from — also used
 * verbatim as the JSON report, so the two are never allowed to diverge.
 *
 * @param {import('./report.js').Reporter} reporter
 * @param {object} [meta]
 * @param {string} [meta.generated_at]  ISO timestamp; defaults to now
 * @param {string[]} [meta.providers]   providers that were scanned (fully or partly), e.g. ['aws','gcp']
 * @param {object} [meta.regions]       { aws: string[] } — regions scanned per provider
 * @param {string} [meta.tool_version]
 * @param {Array<{provider:string,status:'scanned'|'partial'|'skipped',reason?:string}>} [meta.provider_status]
 *   one row per requested provider — lets the report say which clouds were NOT (fully) scanned
 * @param {object} [meta.accounts]      { gcp?: project id, azure?: subscription id }
 * @param {'cli'|'configured'|'discovered'|'fallback'} [meta.region_source]  how the AWS region list was decided
 * @param {string} [meta.min_severity]  the --min-severity filter that was applied
 * @param {number} [meta.hidden_by_filter]  findings that filter removed before the report was built
 */
function buildReportPayload(reporter, meta = {}) {
  const findings = reporter.sorted();
  const stats = buildStats(findings);
  const complianceSummary = summarizeCompliance(findings.map(f => f.compliance));

  const payload = {
    generated_at: meta.generated_at || new Date().toISOString(),
    tool: TOOL_NAME,
    tool_version: meta.tool_version || null,
    providers: meta.providers || [],
    regions: meta.regions || {},
    provider_status: meta.provider_status || [],
    accounts: meta.accounts || {},
    region_source: meta.region_source || null,
    scan_options: {
      min_severity: meta.min_severity || null,
      hidden_by_filter: meta.hidden_by_filter || 0,
    },
    stats,
    compliance_summary: complianceSummary,
    findings,
  };

  // Executive summary (plain-language overview for non-technical readers).
  // Derived purely from the finished payload above, so it must be built last.
  // Never allowed to fail the scan: a missing summary only hides one tab, and
  // the HTML tab shows a "not available" notice in that case (same contract as
  // the SCA and EASM reports).
  try {
    payload.executive_summary = buildExecutiveSummary(payload);
  } catch (e) {
    console.warn(`[~] Executive summary failed: ${e.message}`);
  }

  return payload;
}

/**
 * @param {object} reportPayload  the exact object from buildReportPayload() —
 *   also written as-is to the JSON report, so HTML and JSON always match.
 */
async function generateHtmlReport(reportPayload) {
  const { tailwind, chartjs, googleFonts } = await loadScaStatics();

  const safeJson = escapeForScript(reportPayload);
  const clientScript = buildClientScript(safeJson);

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>cloud-scanner — Misconfiguration Report</title>
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
        <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white text-sm">C</div>
        <div>
          <h1 class="text-lg font-semibold tracking-tight">Cloud Misconfiguration Report</h1>
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
      <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Compliance(0)</button>
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
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">By Provider</h3>
          <div class="h-56"><canvas id="providerChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">By Service</h3>
          <div class="h-56"><canvas id="serviceChart"></canvas></div>
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
        <input id="f-search" type="text" placeholder="Search title, resource, service..."
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
        <select id="f-provider" onchange="applyFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All providers</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">Provider</th>
              <th class="px-4 py-3">Service</th>
              <th class="px-4 py-3">Title</th>
              <th class="px-4 py-3">Resource</th>
              <th class="px-4 py-3">Region</th>
            </tr>
          </thead>
          <tbody id="findings-table-body" class="divide-y divide-neutral-800"></tbody>
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
      <div id="compliance-owasp-section" class="hidden space-y-3">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">By OWASP Top 10 Category</h3>
        <div id="compliance-owasp-grid" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
      </div>
      <div id="compliance-frameworks-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
      <div id="compliance-empty" class="hidden text-sm text-neutral-500 italic">No findings mapped to a compliance framework.</div>
    </section>

    <!-- Detailed Stats -->
    <section id="section-stats" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Misconfiguration Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Distinct issue types</span><span class="mono" id="stats-distinct-checks">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total occurrences</span><span class="mono" id="stats-total-findings">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-critical">Critical</span><span class="mono severity-critical" id="stats-sev-critical">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-high">High</span><span class="mono severity-high" id="stats-sev-high">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-medium">Medium</span><span class="mono severity-medium" id="stats-sev-medium">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-low">Low</span><span class="mono severity-low" id="stats-sev-low">0</span></div>
            <div class="flex justify-between"><span class="severity-info">Info</span><span class="mono severity-info" id="stats-sev-info">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scope Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Resources affected</span><span class="mono" id="stats-distinct-resources">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Providers scanned</span><span class="mono" id="stats-provider-count">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Services affected</span><span class="mono" id="stats-service-count">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">Regions affected</span><span class="mono" id="stats-region-count">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Findings by Region</h3>
          <div class="h-48"><canvas id="regionChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Most Common Checks</h3>
          <p class="text-[11px] text-neutral-500">Distinct check IDs ranked by how many findings each produced (one per affected resource).</p>
          <div id="stats-top-checks" class="space-y-0"></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Busiest Resources</h3>
          <p class="text-[11px] text-neutral-500">Resources ranked by how many findings they're carrying.</p>
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
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Generated at</span><span class="mono text-xs" id="sys-generated">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Providers scanned</span><span class="mono text-xs" id="sys-providers">—</span></div>
            <div class="flex justify-between"><span class="text-neutral-500 text-xs">Minimum severity filter</span><span class="mono text-xs" id="sys-filter">—</span></div>
          </div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Regions &amp; accounts</h3>
          <div id="sys-regions" class="text-xs mono text-neutral-300 space-y-1">—</div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3 md:col-span-2">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Provider status</h3>
          <div id="sys-provider-status" class="text-xs mono text-neutral-300 space-y-1">—</div>
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
    resources.add(\`\${f.provider}::\${f.service}::\${f.resource}\`);
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
        <span class="text-xs uppercase text-neutral-500">\${escH(f.provider)}/\${escH(f.service)}</span>
        <span class="text-sm text-white">\${escH(f.title)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]" title="\${escH(f.resource)}">\${escH(f.resource)}\${f.region ? ' · ' + escH(f.region) : ''}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>\`).join('') : '';

  const body = matches.length
    ? '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Misconfigurations (' + matches.length + ')</p>' + rows + '</div>'
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
    '<h2 class="text-2xl font-bold mb-3 break-words">' + esc(cover.subject || 'Cloud environment') + '</h2>' +
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
  const clouds = es.cloud_coverage || [];
  if (clouds.length) {
    html += '<div>' + sectionTitle('What was scanned') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Cloud</th><th>Status</th><th>Scope</th><th>Issues</th><th>Worst severity</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      clouds.map(function (c) {
        const stKey = c.status === 'scanned' ? 'none' : (c.status === 'partial' ? 'medium' : 'high');
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.cloud) + '</td>' +
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
      '<th class="px-6 py-4">Issue</th><th>Cloud</th><th>Resources</th><th>Severity</th><th>What to do</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      types.map(function (c) {
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.title) +
            (c.reference ? '<div class="mono text-[10px] text-neutral-500 font-normal mt-1 break-all max-w-[16rem]">' + esc(c.reference) + '</div>' : '') + '</td>' +
          '<td class="py-4 align-top text-xs text-neutral-400">' + esc(c.cloud) + (c.service ? ' / ' + esc(c.service) : '') + '</td>' +
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
      '<th class="px-6 py-4">Resource</th><th>Cloud / service</th><th>Region</th><th>Issues</th><th>Worst severity</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      resources.map(function (r) {
        return '<tr>' +
          '<td class="px-6 py-4 mono text-xs break-all">' + esc(r.name) + '</td>' +
          '<td class="py-4 text-xs text-neutral-400">' + esc(r.cloud) + (r.service ? ' / ' + esc(r.service) : '') + '</td>' +
          '<td class="py-4 mono text-xs text-neutral-500">' + esc(r.region || '—') + '</td>' +
          '<td class="py-4">' + esc(r.issues) + '</td>' +
          '<td class="py-4 pr-6">' + badge(r.worst_severity, r.worst_severity_label) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Ranks individual cloud resources carrying the most serious and most numerous issues. Informational notes are not counted.</p></div>';
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

  updateTabCounts();
  renderDashboard();
  try { renderExecutiveSummary(); } catch (e) { console.error('Executive summary render failed:', e); }
  populateProviderFilter();
  applyFilters();
  renderScanInfo();
  renderCompliance();
  renderStats();
});

// ── TAB LABEL COUNTS ─────────────────────────────────────────────────────────

function updateTabCounts() {
  document.getElementById('tab-findings').textContent = 'Findings(' + reportData.stats.total + ')';
  const cs = reportData.compliance_summary;
  document.getElementById('tab-compliance').textContent = 'Compliance(' + (cs && cs.frameworks ? cs.frameworks.length : 0) + ')';
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

  const providers = Object.entries(s.byProvider).sort((a,b) => b[1]-a[1]);
  new Chart(document.getElementById('providerChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: providers.map(([k]) => k.toUpperCase()),
      datasets: [{ data: providers.map(([,v]) => v), backgroundColor: '#ef4444aa', borderRadius: 4 }],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373', precision: 0 } },
                x: { grid: { display: false }, ticks: { color: '#737373' } } } },
  });

  const services = Object.entries(s.byService).sort((a,b) => b[1]-a[1]).slice(0, 8);
  new Chart(document.getElementById('serviceChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: services.map(([k]) => k),
      datasets: [{ data: services.map(([,v]) => v), backgroundColor: '#60a5faaa', borderRadius: 4 }],
    },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373', precision: 0 } },
                y: { grid: { display: false }, ticks: { color: '#a3a3a3', font: { size: 10 } } } } },
  });
}

// ── FILTERS / FINDINGS TABLE ──────────────────────────────────────────────────

let _filtered = reportData.findings;

function populateProviderFilter() {
  const sel = document.getElementById('f-provider');
  const providers = [...new Set(reportData.findings.map(f => f.provider))].sort();
  for (const p of providers) {
    const opt = document.createElement('option');
    opt.value = p;
    opt.textContent = p.toUpperCase();
    sel.appendChild(opt);
  }
}

function applyFilters() {
  const q = document.getElementById('f-search').value.trim().toLowerCase();
  const sev = document.getElementById('f-severity').value;
  const provider = document.getElementById('f-provider').value;

  _filtered = reportData.findings.filter(f => {
    if (sev !== 'all' && f.severity !== sev) return false;
    if (provider !== 'all' && f.provider !== provider) return false;
    if (q && !(
      (f.title||'').toLowerCase().includes(q) ||
      (f.resource||'').toLowerCase().includes(q) ||
      (f.service||'').toLowerCase().includes(q) ||
      (f.check||'').toLowerCase().includes(q) ||
      (f.region||'').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderFindingsTable();
}

function renderFindingsTable() {
  const tbody = document.getElementById('findings-table-body');
  tbody.innerHTML = '';

  if (!_filtered.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No findings match the current filters.</td></tr>';
    return;
  }

  _filtered.forEach((f, idx) => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.findingIndex = String(idx);
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity)}</span></td>
      <td class="px-4 py-3 text-xs uppercase text-neutral-400">\${escH(f.provider)}</td>
      <td class="px-4 py-3 text-xs text-neutral-300">\${escH(f.service)}</td>
      <td class="px-4 py-3 text-sm font-medium text-white">\${escH(f.title)}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400">\${escH(f.resource)}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-500">\${escH(f.region || '—')}</td>
    \`;
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
  openModal(\`
    <div class="space-y-4">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold \${sevClass(f.severity)}">\${escH(f.severity)}</span>
        <h2 class="text-lg font-semibold text-white">\${escH(f.title)}</h2>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">Provider</span><div class="mono text-neutral-200">\${escH(f.provider)}</div></div>
        <div><span class="text-neutral-500">Service</span><div class="mono text-neutral-200">\${escH(f.service)}</div></div>
        <div><span class="text-neutral-500">Check</span><div class="mono text-neutral-200">\${escH(f.check)}</div></div>
        <div><span class="text-neutral-500">Region</span><div class="mono text-neutral-200">\${escH(f.region || '—')}</div></div>
        <div class="col-span-2"><span class="text-neutral-500">Action</span><div class="mono text-neutral-200">\${escH(f.action || '—')}</div></div>
        <div class="col-span-2"><span class="text-neutral-500">Resource</span><div class="mono text-neutral-200 break-all">\${escH(f.resource)}</div></div>
        <div class="col-span-2"><span class="text-neutral-500">Detected</span><div class="mono text-neutral-200">\${escH(f.timestamp)}</div></div>
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Description</p>
        <p class="text-sm text-neutral-300">\${escH(f.description)}</p>
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Remediation</p>
        <p class="text-sm text-neutral-300 mono bg-neutral-900 p-3 rounded-lg break-all">\${escH(f.remediation)}</p>
      </div>
      \${renderComplianceSection(f.compliance)}
    </div>
  \`);
}

// ── SCAN INFO ─────────────────────────────────────────────────────────────────

function renderScanInfo() {
  document.getElementById('sys-tool').textContent      = reportData.tool;
  document.getElementById('sys-version').textContent    = reportData.tool_version || '—';
  document.getElementById('sys-generated').textContent   = reportData.generated_at;
  document.getElementById('sys-providers').textContent   = (reportData.providers || []).join(', ') || '—';

  const so = reportData.scan_options || {};
  document.getElementById('sys-filter').textContent = so.min_severity
    ? so.min_severity + (so.hidden_by_filter ? ' (' + so.hidden_by_filter + ' hidden)' : '')
    : '—';

  const regionsEl = document.getElementById('sys-regions');
  const lines = Object.entries(reportData.regions || {}).map(([provider, regions]) =>
    '<div><span class="text-neutral-500">' + escH(provider.toUpperCase()) + ':</span> ' + escH((regions||[]).join(', ')) +
    (provider === 'aws' && reportData.region_source ? ' <span class="text-neutral-600">(' + escH(reportData.region_source) + ')</span>' : '') + '</div>'
  );
  const acc = reportData.accounts || {};
  if (acc.gcp) lines.push('<div><span class="text-neutral-500">GCP project:</span> ' + escH(acc.gcp) + '</div>');
  if (acc.azure) lines.push('<div><span class="text-neutral-500">AZURE subscription:</span> ' + escH(acc.azure) + '</div>');
  regionsEl.innerHTML = lines.length ? lines.join('') : '—';

  const statusEl = document.getElementById('sys-provider-status');
  const ps = reportData.provider_status || [];
  statusEl.innerHTML = ps.length ? ps.map(p =>
    '<div><span class="text-neutral-500">' + escH(String(p.provider).toUpperCase()) + ':</span> ' + escH(p.status) +
    (p.reason ? ' <span class="text-neutral-600">— ' + escH(p.reason) + '</span>' : '') + '</div>'
  ).join('') : '—';
}

// ── DETAILED STATS ────────────────────────────────────────────────────────────
// Deliberately doesn't re-chart severity/provider/service — those already
// have a chart each on the Dashboard. This tab covers dimensions that
// aren't shown anywhere else: findings by region, which distinct check
// types are firing most often, and which individual resources are
// carrying the most findings.

function renderStats() {
  const s = reportData.stats || {};
  const findings = reportData.findings || [];

  const checks = new Set();
  const resources = new Set();
  const providers = new Set();
  const services = new Set();
  const regions = new Set();
  const byCheck = {};
  const byResource = {};
  for (const f of findings) {
    checks.add(f.check);
    const resKey = \`\${f.provider}::\${f.service}::\${f.resource}\`;
    resources.add(resKey);
    providers.add(f.provider);
    services.add(\`\${f.provider}/\${f.service}\`);
    if (f.region) regions.add(f.region);
    byCheck[f.check] = (byCheck[f.check] || 0) + 1;
    if (!byResource[resKey]) byResource[resKey] = { label: f.resource, count: 0 };
    byResource[resKey].count++;
  }

  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };
  const sev = s.bySeverity || {};
  set('stats-distinct-checks', checks.size);
  set('stats-total-findings', findings.length);
  set('stats-sev-critical', sev.critical || 0);
  set('stats-sev-high', sev.high || 0);
  set('stats-sev-medium', sev.medium || 0);
  set('stats-sev-low', sev.low || 0);
  set('stats-sev-info', sev.info || 0);
  set('stats-distinct-resources', resources.size);
  set('stats-provider-count', providers.size);
  set('stats-service-count', services.size);
  set('stats-region-count', regions.size);

  // Most common checks — ranked by how many findings each check id produced.
  const topEl = document.getElementById('stats-top-checks');
  if (topEl) {
    const byCheckEntries = Object.entries(byCheck).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const maxC = byCheckEntries.length ? byCheckEntries[0][1] : 0;
    topEl.innerHTML = byCheckEntries.length
      ? byCheckEntries.map(([check, count]) => \`
        <div class="flex items-center gap-3 py-1.5 border-b border-neutral-800 last:border-0">
          <span class="mono text-xs text-neutral-300 truncate flex-1">\${escH(check)}</span>
          <div class="w-40 bg-neutral-800 rounded-full h-1.5 shrink-0">
            <div class="bg-red-500 h-1.5 rounded-full" style="width: \${maxC ? (count / maxC) * 100 : 0}%"></div>
          </div>
          <span class="mono text-xs text-neutral-400 w-8 text-right shrink-0">\${count}</span>
        </div>\`).join('')
      : '<p class="text-xs text-neutral-500 italic">No findings detected.</p>';
  }

  // Busiest resources — same ranked-bar pattern, this time by individual
  // resource rather than check type, so a single hot bucket/instance/user
  // tripping several different checks stands out.
  const hotEl = document.getElementById('stats-hot-resources');
  if (hotEl) {
    const byResourceEntries = Object.values(byResource).sort((a, b) => b.count - a.count).slice(0, 15);
    const max = byResourceEntries.length ? byResourceEntries[0].count : 0;
    hotEl.innerHTML = byResourceEntries.length
      ? byResourceEntries.map(r => \`
        <div class="flex items-center gap-3 py-1.5 border-b border-neutral-800 last:border-0">
          <span class="mono text-xs text-neutral-300 truncate flex-1">\${escH(r.label)}</span>
          <div class="w-40 bg-neutral-800 rounded-full h-1.5 shrink-0">
            <div class="bg-red-500 h-1.5 rounded-full" style="width: \${max ? (r.count / max) * 100 : 0}%"></div>
          </div>
          <span class="mono text-xs text-neutral-400 w-8 text-right shrink-0">\${r.count}</span>
        </div>\`).join('')
      : '<p class="text-xs text-neutral-500 italic">No findings detected.</p>';
  }

  renderStatsCharts(s);
}

function renderStatsCharts(s) {
  if (typeof Chart === 'undefined') return;

  const regionEntries = Object.entries(s.byRegion || {}).sort((a, b) => b[1] - a[1]).slice(0, 12);
  const regionCanvas = document.getElementById('regionChart');
  if (regionCanvas && regionEntries.length) {
    new Chart(regionCanvas, {
      type: 'bar',
      data: {
        labels: regionEntries.map(([k]) => k),
        datasets: [{ data: regionEntries.map(([, v]) => v), backgroundColor: '#a855f7aa', borderRadius: 4 }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { beginAtZero: true, ticks: { color: '#737373', font: { size: 10 }, precision: 0 }, grid: { color: '#262626' } },
          y: { ticks: { color: '#a3a3a3', font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
  }
}
`;
}

export { generateHtmlReport, buildReportPayload };