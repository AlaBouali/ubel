'use strict';
// html-report.js — HTML report generator for cloud-scanner findings
//
// Input:  reporter (src/lib/report.js Reporter instance), meta
//   meta — { generated_at, providers, regions, tool_version }
//
// Output: HTML string (caller writes to disk)
//
// Static assets (Tailwind, Chart.js, Google Fonts) are pulled in from the
// shared `sca` module the same way ubel-sast's HTML report does, so the
// report stays a single self-contained file with no CDN/network calls at
// view time — consistent with UBEL's no-telemetry, offline-friendly
// posture. cloud-scanner itself is CommonJS, so these are loaded with a
// dynamic import() (works against either a CJS or ESM sca build) rather
// than a top-level `require`.
//
// NOTE: the shared path itself lives in ./sca-path.js (single source of
// truth — history.js's zip helper points at the same place).

const TOOL_NAME = 'cloud-scanner';

import { getTailwindScript } from "../../sca/tailwindcss.js";
import { getChartJSScript } from "../../sca/chartjs.js";
import { getGoogleFontsScript } from "../../sca/googlefonts.js";

async function loadScaStatics() {
  try {
    return {
      tailwind: await getTailwindScript(),
      chartjs: await getChartJSScript(),
      googleFonts: await getGoogleFontsScript(),
    };
  } catch (err) {
    throw new err;
  }
}


// ─── escaping ────────────────────────────────────────────────────────────────

function escapeForScript(obj) {
  return JSON.stringify(obj)
    .replace(/</g, '\\u003c')
    .replace(/`/g, '\\u0060');
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
 * @param {import('./report').Reporter} reporter
 * @param {object} [meta]
 * @param {string} [meta.generated_at]  ISO timestamp; defaults to now
 * @param {string[]} [meta.providers]   providers that were actually scanned, e.g. ['aws','gcp']
 * @param {object} [meta.regions]       { aws: string[] } — regions scanned per provider
 * @param {string} [meta.tool_version]
 */
function buildReportPayload(reporter, meta = {}) {
  const findings = reporter.sorted();
  const stats = buildStats(findings);

  return {
    generated_at: meta.generated_at || new Date().toISOString(),
    tool: TOOL_NAME,
    tool_version: meta.tool_version || null,
    providers: meta.providers || [],
    regions: meta.regions || {},
    stats,
    findings,
  };
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
        ${TOOL_NAME}${reportPayload.tool_version ? ' v' + reportPayload.tool_version : ''}
      </span>
    </div>
  </header>

  <!-- ── NAV ───────────────────────────────────────────────────────────── -->
  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('findings')"  id="tab-findings"  class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Findings(0)</button>
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

    <!-- Scan Info -->
    <section id="section-scaninfo" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scan</h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool</span><span class="mono text-xs" id="sys-tool">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="sys-version">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Generated at</span><span class="mono text-xs" id="sys-generated">—</span></div>
            <div class="flex justify-between"><span class="text-neutral-500 text-xs">Providers scanned</span><span class="mono text-xs" id="sys-providers">—</span></div>
          </div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Regions</h3>
          <div id="sys-regions" class="text-xs mono text-neutral-300 space-y-1">—</div>
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

  updateTabCounts();
  renderDashboard();
  populateProviderFilter();
  applyFilters();
  renderScanInfo();
});

// ── TAB LABEL COUNTS ─────────────────────────────────────────────────────────

function updateTabCounts() {
  document.getElementById('tab-findings').textContent = 'Findings(' + reportData.stats.total + ')';
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
    </div>
  \`);
}

// ── SCAN INFO ─────────────────────────────────────────────────────────────────

function renderScanInfo() {
  document.getElementById('sys-tool').textContent      = reportData.tool;
  document.getElementById('sys-version').textContent    = reportData.tool_version || '—';
  document.getElementById('sys-generated').textContent   = reportData.generated_at;
  document.getElementById('sys-providers').textContent   = (reportData.providers || []).join(', ') || '—';

  const regionsEl = document.getElementById('sys-regions');
  const entries = Object.entries(reportData.regions || {});
  if (!entries.length) {
    regionsEl.textContent = '—';
    return;
  }
  regionsEl.innerHTML = entries.map(([provider, regions]) =>
    '<div><span class="text-neutral-500">' + escH(provider.toUpperCase()) + ':</span> ' + escH((regions||[]).join(', ')) + '</div>'
  ).join('');
}
`;
}

export { generateHtmlReport, buildReportPayload };