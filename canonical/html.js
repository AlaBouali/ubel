'use strict';
// canonical/html.js — the one canonical HTML report. It renders a canonical report (schema 0.1.0) and picks the
// finding / inventory modal from each entry's `type`. Look, tabs and offline assets (Tailwind, Chart.js, fonts) are the
// ones of the per-module templates (cloud/lib/html_report.js, vm/lib/html_report.js, …); the client code is ./client.js.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { getTailwindScript } from '../sca/tailwindcss.js';
import { getChartJSScript } from '../sca/chartjs.js';
import { getGoogleFontsScript } from '../sca/googlefonts.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const forScript = (o) => JSON.stringify(o).replace(/</g, '\\u003c').replace(/\u2028/g, '\\u2028').replace(/\u2029/g, '\\u2029');

export async function generateCanonicalHtml(canon) {
  const [tailwind, chartjs, googleFonts] = await Promise.all([getTailwindScript(), getChartJSScript(), getGoogleFontsScript()]);
  const client = fs.readFileSync(path.join(HERE, 'client.js'), 'utf8');
  const si = canon?.metadata?.scan_info || {};
  const title = `UBEL ${si.scan_type || 'security'} report`;
  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(title)}</title>
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
    .severity-info, .severity-unknown { color: #a3a3a3; border-color: #a3a3a3; }
    .type-chip { border: 1px solid #404040; color: #d4d4d4; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    .tab-active { border-bottom: 2px solid var(--accent); color: white; }
    .modal-overlay { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.85); z-index:50; backdrop-filter: blur(4px); }
    .modal-content { max-height: 90vh; overflow-y: auto; }
    pre.code { background:#0d0d0d; border:1px solid var(--border); border-radius:8px; padding:12px; overflow-x:auto; font-size:12px; white-space:pre-wrap; word-break:break-word; }
    details > summary { cursor: pointer; }
    tr.row { cursor: pointer; } tr.row:hover { background: rgba(255,255,255,0.04); }
    @media print { header, nav, .no-print, .modal-overlay { display: none !important; } body { background:#fff; color:#111; } }
  </style>
</head>
<body class="min-h-screen flex flex-col">
  <header class="border-b border-neutral-800 px-6 py-4 flex items-center justify-between">
    <div><h1 class="text-xl font-bold">${esc(title)}</h1><p id="hdr-sub" class="text-xs text-neutral-500 mono"></p></div>
    <div id="hdr-badges" class="flex gap-2"></div>
  </header>
  <nav id="tabs" class="flex gap-6 px-6 border-b border-neutral-800 text-sm text-neutral-400 overflow-x-auto"></nav>
  <main id="main" class="flex-1 p-6 max-w-7xl w-full mx-auto"></main>
  <div id="modal-overlay" class="modal-overlay items-center justify-center p-4">
    <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
      <button id="modal-close" class="absolute top-3 right-4 text-neutral-400 hover:text-white text-2xl" aria-label="Close">&times;</button>
      <div id="modal-body" class="p-8"></div>
    </div>
  </div>
  <script type="application/json" id="canon-data">${forScript(canon)}</script>
  <script>${client}</script>
</body>
</html>`;
}
