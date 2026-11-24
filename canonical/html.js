'use strict';
// canonical/html.js — the one canonical HTML report.
//
// Look, colours, statics (Tailwind, Chart.js, fonts), header, tabs and modal frame are the SCA report's
// (sca/engine.js report template). The finding / inventory modals, executive summary, compliance and diff renderers are each
// module's own code, copied verbatim into client/<family>.js and fed the original `details` of every entry. client/shell.js is
// the part common to all modules (dashboard, lists with filters, scopes, stats, policy, system info). client/diffs.js is the Diffs tab's
// severity view (cards per severity level; a searchable, paginated Title / Type table in the modal), shared by all families; the per-framework
// compliance diffs stay in each family's own code. The vm / k8s / runtime reports (bundle
// posture) also carry client/scvuln.js — the SCA vulnerability modal — when they hold sc_vuln / sc_infection findings or a package list (SCA package items); so do the
// app-scan reports (package / binary / mobile / mcp) when they hold sc_vuln / sc_infection findings: each opens on its own, not inside its dependency's modal.
// In the app-scan reports that modal has no Policy Violations / Reachability Analysis sections (client/scvuln.js isAppScan); it shows KEV / EPSS like the SCA report.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getTailwindScript } from '../sca/tailwindcss.js';
import { getChartJSScript } from '../sca/chartjs.js';
import { getGoogleFontsScript } from '../sca/googlefonts.js';
import { restore as restoreAppscan } from './adapters/appscan.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CLIENT = path.join(HERE, 'client');
const read = (f) => fs.readFileSync(path.join(CLIENT, f), 'utf8');
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const forScript = (o) => JSON.stringify(o).replace(/</g, '\\u003c').replace(/>/g, '\\u003e').replace(/&/g, '\\u0026').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

// adapter family → client bundle
const BUNDLE = { sca: 'sca', sast: 'sast', cloud: 'cloud', posture: 'posture', runtime: 'posture', appscan: 'appscan', easm: 'easm' };
const SCAN_TYPE_FAMILY = { analyze: 'sast', malware: 'sast', cloud: 'cloud', vm: 'posture', k8s: 'posture', runtime: 'posture', url: 'easm', domain: 'easm', host: 'easm', easm: 'easm',
  mobile: 'appscan', binary: 'appscan', package: 'appscan', 'mcp-client': 'appscan', 'mcp-server': 'appscan', mcp_client: 'appscan', mcp_server: 'appscan' };

export function familyOfCanon(canon) {
  return SCAN_TYPE_FAMILY[String(canon?.metadata?.scan_info?.scan_type || '').toLowerCase()] || 'sca';
}

const TABS = [['dashboard', 'Dashboard'], ['executive', 'Executive Summary'], ['findings', 'Findings(0)'], ['inventory', 'Inventory(0)'], ['scopes', 'Scopes(0)'],
  ['stats', 'Detailed Stats'], ['compliance', 'Compliance(0)'], ['diffs', 'Diffs'], ['policy', 'Policy'], ['system', 'System Info']];

const DASHBOARD = `<section id="section-dashboard" class="space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Total Findings</p><p class="text-3xl font-bold" id="stat-total">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-red-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Critical / High</p><p class="text-3xl font-bold text-red-500" id="stat-critical-high">0</p></div>
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Reachable / Exploitable</p><p class="text-3xl font-bold" id="stat-reachable">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-green-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Inventory</p><p class="text-3xl font-bold text-green-500" id="stat-inventory">0</p></div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl lg:col-span-2"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Severity Distribution</h3><div class="h-64"><canvas id="severityChart"></canvas></div></div>
                <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Decision Summary</h3><div id="decision-box" class="p-4 rounded-lg bg-neutral-800/50 border border-neutral-700"><p class="text-sm leading-relaxed" id="decision-reason">...</p></div><div class="mt-6 space-y-4"><table class="w-auto text-sm mono" id="dash-facts"></table></div></div>
            </div>
        </section>`;

async function executiveSection(canon, family) {
  if (family === 'appscan') {                      // the module renders this section on the server: use its own renderer
    try {
      const { buildHtml } = await import('../mobile/lib/report.js');
      const html = await buildHtml(restoreAppscan(canon));
      const m = html.match(/<section id="section-executive".*?<\/section>/s);
      if (m) return m[0];
    } catch (e) { console.warn(`[canonical] executive summary: ${e.message}`); }
    return '<section id="section-executive" class="hidden space-y-8"><div id="executive-content" class="space-y-8"><div class="glass p-6 rounded-xl text-sm text-neutral-500 italic">No executive summary is available for this report.</div></div></section>';
  }
  return null;
}

export async function generateCanonicalHtml(canon, opts = {}) {
  const family = BUNDLE[opts.family] || familyOfCanon(canon);
  const [tailwind, chartjs, googleFonts] = await Promise.all([getTailwindScript(), getChartJSScript(), getGoogleFontsScript()]);
  const bundle = BUNDLE[family] || family;
  const si = canon?.metadata?.scan_info || {};
  const label = { analyze: 'SAST', malware: 'Malicious Code Scan', 'mcp-client': 'MCP Client', 'mcp-server': 'MCP Server', mcp_client: 'MCP Client', mcp_server: 'MCP Server' }[String(si.scan_type || '').toLowerCase()] || String(si.scan_type || 'security').toUpperCase();
  const title = `UBEL ${label} — Security Report`;
  const part = read(`${bundle}.html`);
  const pick = (id) => { const m = part.match(new RegExp(`<section id="section-${id}".*?</section>`, 's')); return m ? m[0] : ''; };
  const exec = (await executiveSection(canon, bundle)) || pick('executive');
  const nav = TABS.map(([id, label], i) => `<button onclick="switchTab('${id}')" id="tab-${id}" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors${i === 0 ? ' tab-active' : ''}">${esc(label)}</button>`).join('\n            ');
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${esc(title)}</title>
    <script>${tailwind}</script>
    <script>${chartjs}</script>
    <style>${googleFonts}</style>
    <style>${read('sca.css')}</style>
</head>
<body class="min-h-screen flex flex-col">
    <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3"><div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white">U</div><div><h1 class="text-lg font-semibold tracking-tight">${esc(title)}</h1><p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p></div></div>
            <div id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider">Status: Loading...</div>
        </div>
    </header>
    <nav class="border-b border-neutral-800 bg-neutral-900/30">
        <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
            ${nav}
        </div>
    </nav>
    <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
        ${DASHBOARD}
        ${exec}
        <section id="section-findings" class="hidden space-y-6"></section>
        <section id="section-inventory" class="hidden space-y-6"></section>
        <section id="section-scopes" class="hidden space-y-6"></section>
        <section id="section-stats" class="hidden space-y-8"></section>
        ${pick('compliance')}
        ${pick('diffs')}
        <section id="section-policy" class="hidden space-y-8"></section>
        <section id="section-system" class="hidden space-y-8"></section>
    </main>
    <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50"><div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4"><p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">Ubel Security Engine</span></p></div></footer>
    <div id="modal-overlay" class="modal-overlay items-center justify-center p-4" style="display: none;">
        <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
            <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            <div id="modal-body" class="p-8"></div>
        </div>
    </div>
    <script>const CANON = ${forScript(canon)};</script>
    ${(bundle === 'appscan' && (canon.findings || []).some((f) => f.type === 'sc_vuln' || f.type === 'sc_infection')) || bundle === 'posture' && ((canon.findings || []).some((f) => f.type === 'sc_vuln' || f.type === 'sc_infection') || (canon.inventory || []).some((c) => c.type === 'dependency' && c.details && c.details.state && String(c.details.id || '').startsWith('pkg:'))) ? `<script>${read('scvuln.js')}</script>` : ''}
    <script>${read('diffs.js')}</script>
    <script>${read(`${bundle}.js`)}</script>
    <script>${read('shell.js')}</script>
</body>
</html>`;
}
