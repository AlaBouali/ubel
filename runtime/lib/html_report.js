'use strict';
// html_report.js — report payload + HTML generator of ubel-runtime.
//
// It is the cloud report template (Dashboard, Executive Summary, Findings, Compliance, Diffs, Detailed Stats, Scan Info) as
// made profile-driven in vm/lib/html_report.js, with three more tabs that describe what was running:
//   Processes   — one row per program (same-program processes grouped): who runs it, what it listens on, how it is confined
//   Containers  — the running containers the engine reported (only when a container check asked the engine)
//   Live data   — with --inspect: what each Node.js process has really loaded, against what is merely installed
// The extra tabs are injected into the shared template, so the look, the Findings / Compliance / Diffs behaviour and the
// executive summary stay identical to the other scanners. Every value is escaped (escH) before it touches innerHTML.

import { generateHtmlReport as generateBase, buildReportPayload as buildBase } from '../../vm/lib/html_report.js';

/** The shared payload plus `runtime` (processes, listeners, containers, inspections — never environment values). */
function buildReportPayload(reporter, meta = {}) {
  const payload = buildBase(reporter, meta);
  payload.runtime = meta.runtime || null;
  return payload;
}

const NAV_ANCHOR = `<button onclick="switchTab('diffs')"`;
const SECTION_ANCHOR = '<!-- Scan Info -->';

const NAV = `
      <button onclick="switchTab('processes')"  id="tab-processes"  class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Processes</button>
      <button onclick="switchTab('containers')" id="tab-containers" class="hidden py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Containers</button>
      <button onclick="switchTab('livedata')"   id="tab-livedata"   class="hidden py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Live data</button>
      `;

const SECTIONS = `<!-- Processes -->
    <section id="section-processes" class="hidden space-y-6">
      <div id="rt-cards" class="grid grid-cols-2 md:grid-cols-5 gap-4"></div>
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="rt-search" type="text" placeholder="Search program, user, port..." oninput="renderProcesses()"
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500">
        <label class="text-xs text-neutral-400 flex items-center gap-2"><input id="rt-listening-only" type="checkbox" onchange="renderProcesses()"> Listening only</label>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 p-6 pb-2">Programs</h3>
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr>
            <th class="px-4 py-3">Program</th><th class="px-4 py-3">Where</th><th class="px-4 py-3">User</th><th class="px-4 py-3">Procs</th><th class="px-4 py-3">Listening</th><th class="px-4 py-3">Confinement</th>
          </tr></thead>
          <tbody id="rt-proc-body" class="divide-y divide-neutral-800 text-sm"></tbody>
        </table>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 p-6 pb-2">Listening sockets</h3>
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr>
            <th class="px-4 py-3">Address</th><th class="px-4 py-3">Port</th><th class="px-4 py-3">Program</th><th class="px-4 py-3">Where</th>
          </tr></thead>
          <tbody id="rt-listen-body" class="divide-y divide-neutral-800 text-sm"></tbody>
        </table>
      </div>
    </section>

    <!-- Containers -->
    <section id="section-containers" class="hidden space-y-6">
      <div id="rt-ctr-status" class="text-sm text-neutral-400"></div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr>
            <th class="px-4 py-3">Container</th><th class="px-4 py-3">Image</th><th class="px-4 py-3">User</th><th class="px-4 py-3">Privileges</th><th class="px-4 py-3">Published ports</th><th class="px-4 py-3">Host paths</th>
          </tr></thead>
          <tbody id="rt-ctr-body" class="divide-y divide-neutral-800 text-sm"></tbody>
        </table>
      </div>
    </section>

    <!-- Live data (--inspect) -->
    <section id="section-livedata" class="hidden space-y-6">
      <p class="text-xs text-neutral-500 italic bg-neutral-900/50 p-3 rounded-lg border border-neutral-800">Read through the V8 inspector of each Node.js process (--inspect): the scripts it has compiled and process.versions.</p>
      <div id="rt-live" class="space-y-4"></div>
    </section>

    `;

const CLIENT = `
(function () {
  var RT = reportData.runtime || { processes: [], listeners: [], containers: null, inspections: [], summary: {} };
  function chip(t, cls) { return '<span class="inline-block px-2 py-0.5 rounded border text-[11px] mono mr-1 mb-1 ' + (cls || 'border-neutral-700 text-neutral-300') + '">' + escH(t) + '</span>'; }
  function seccompLabel(v) { return v === 2 ? 'seccomp filter' : v === 1 ? 'seccomp strict' : v === 0 ? 'no seccomp' : 'seccomp ?'; }

  function renderCards() {
    var s = RT.summary || {};
    var items = [['Processes', s.processes], ['Programs', s.programs], ['Node.js', s.node_processes], ['Listening', s.listeners], ['Inspected', s.inspected]];
    document.getElementById('rt-cards').innerHTML = items.map(function (i) {
      return '<div class="glass p-4 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">' + escH(i[0]) + '</p><p class="text-2xl font-bold">' + escH(i[1] == null ? 0 : i[1]) + '</p></div>';
    }).join('');
  }

  window.renderProcesses = function () {
    var q = (document.getElementById('rt-search').value || '').toLowerCase();
    var only = document.getElementById('rt-listening-only').checked;
    var rows = (RT.processes || []).filter(function (p) {
      if (only && !p.listening.length) return false;
      if (!q) return true;
      return (p.label + ' ' + p.user + ' ' + p.scope + ' ' + p.listening.join(' ')).toLowerCase().indexOf(q) >= 0;
    });
    document.getElementById('rt-proc-body').innerHTML = rows.length ? rows.map(function (p) {
      var conf = [];
      if (p.root) conf.push(chip('root', 'border-red-500/60 text-red-400'));
      if (p.deleted_exe) conf.push(chip('deleted executable', 'border-red-500/60 text-red-400'));
      conf.push(chip((p.capabilities || []).length + ' caps', (p.capabilities || []).length > 8 ? 'border-orange-400/60 text-orange-300' : undefined));
      conf.push(chip(seccompLabel(p.seccomp)));
      if (p.no_new_privs) conf.push(chip('no_new_privs'));
      if (p.node) conf.push(chip(p.inspected === 'yes' ? 'Node.js · inspected' : p.inspected === 'failed' ? 'Node.js · inspection failed' : 'Node.js'));
      return '<tr title="' + escH(p.exe || '') + '"><td class="px-4 py-3 mono text-xs break-all">' + escH(p.label) + '</td><td class="px-4 py-3 text-xs">' + escH(p.scope) + '</td><td class="px-4 py-3 text-xs">' + escH(p.user) +
        '</td><td class="px-4 py-3 text-xs" title="pid ' + escH(p.pids.join(', ')) + '">' + escH(p.count) + '</td><td class="px-4 py-3 mono text-xs">' + (p.listening.length ? p.listening.map(escH).join('<br>') : '<span class="text-neutral-600">—</span>') +
        '</td><td class="px-4 py-3">' + conf.join('') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="px-4 py-6 text-sm text-neutral-500 italic">No process matches.</td></tr>';
  };

  function renderListeners() {
    var rows = RT.listeners || [];
    document.getElementById('rt-listen-body').innerHTML = rows.length ? rows.map(function (l) {
      var wide = l.address === '0.0.0.0' || l.address === '::' || l.address === '*';
      return '<tr><td class="px-4 py-3 mono text-xs ' + (wide ? 'text-orange-300' : '') + '">' + escH(l.address) + '</td><td class="px-4 py-3 mono text-xs">' + escH(l.port) + '</td><td class="px-4 py-3 mono text-xs break-all">' + escH(l.program || 'unidentified process') + '</td><td class="px-4 py-3 text-xs">' + escH(l.scope) + '</td></tr>';
    }).join('') : '<tr><td colspan="4" class="px-4 py-6 text-sm text-neutral-500 italic">No listening TCP socket was attributed to an assessed process.</td></tr>';
  }

  function renderContainers() {
    var c = RT.containers;
    if (!c) return;
    document.getElementById('tab-containers').classList.remove('hidden');
    if (c.status === 'ok') document.getElementById('tab-containers').textContent = 'Containers(' + (c.items ? c.items.length : 0) + ')';
    document.getElementById('rt-ctr-status').textContent = c.status === 'ok' ? 'Container engine: ' + c.socket : 'Container engine ' + c.status + (c.reason ? ' — ' + c.reason : '');
    var rows = c.items || [];
    document.getElementById('rt-ctr-body').innerHTML = rows.length ? rows.map(function (x) {
      var priv = [];
      if (x.privileged) priv.push(chip('privileged', 'border-red-500/60 text-red-400'));
      (x.dangerous_caps || []).forEach(function (k) { priv.push(chip(k, 'border-orange-400/60 text-orange-300')); });
      if (x.network_mode === 'host') priv.push(chip('host network', 'border-orange-400/60 text-orange-300'));
      if (x.pid_mode === 'host') priv.push(chip('host pid', 'border-orange-400/60 text-orange-300'));
      return '<tr><td class="px-4 py-3 mono text-xs">' + escH(x.name) + '<br><span class="text-neutral-600">' + escH(x.id) + '</span></td><td class="px-4 py-3 mono text-xs break-all">' + escH(x.image) + '</td><td class="px-4 py-3 text-xs">' + escH(x.user) +
        '</td><td class="px-4 py-3">' + (priv.join('') || '<span class="text-neutral-600">—</span>') + '</td><td class="px-4 py-3 mono text-xs">' + ((x.published_ports || []).map(escH).join('<br>') || '<span class="text-neutral-600">—</span>') +
        '</td><td class="px-4 py-3 mono text-xs break-all">' + ((x.sensitive_mounts || []).map(escH).join('<br>') || '<span class="text-neutral-600">—</span>') + '</td></tr>';
    }).join('') : '<tr><td colspan="6" class="px-4 py-6 text-sm text-neutral-500 italic">No running container.</td></tr>';
  }

  function renderLive() {
    var list = RT.inspections || [];
    var requested = reportData.scan_options && reportData.scan_options.inspect;
    if (!list.length && !requested) return;
    document.getElementById('tab-livedata').classList.remove('hidden');
    document.getElementById('tab-livedata').textContent = 'Live data(' + list.length + ')';
    document.getElementById('rt-live').innerHTML = list.length ? list.map(function (i) {
      if (!i.ok) return '<div class="glass p-5 rounded-xl"><div class="mono text-sm break-all">' + escH(i.label) + '</div><div class="text-xs text-orange-300 mt-1">Not inspected: ' + escH(i.reason) + '</div></div>';
      return '<div class="glass p-5 rounded-xl space-y-3"><div class="flex flex-wrap justify-between gap-2"><div class="mono text-sm break-all">' + escH(i.label) + '</div><div class="text-xs text-neutral-400">' + escH(i.scope) + '</div></div>' +
        '<div class="text-xs text-neutral-400">Node.js ' + escH(i.node_version || '?') + ' · ' + escH(i.scripts) + ' scripts compiled · ' + escH(i.loaded_files) + ' script files loaded' +
        (i.left_open ? ' · <span class="text-red-400">inspector left open</span>' : '') + '</div></div>';
    }).join('') : '<div class="text-sm text-neutral-500 italic">--inspect was requested but no Node.js process was in scope.</div>';
  }

  document.addEventListener('DOMContentLoaded', function () {
    try {
      document.getElementById('tab-processes').textContent = 'Processes(' + ((RT.processes || []).length) + ')';
      renderCards(); window.renderProcesses(); renderListeners(); renderContainers(); renderLive();
    } catch (e) { console.error('Runtime tabs render failed:', e); }
  });
})();
`;

async function generateHtmlReport(payload) {
  let html = await generateBase(payload);
  if (!html.includes(NAV_ANCHOR) || !html.includes(SECTION_ANCHOR) || !html.includes('</body>')) {
    throw new Error('the shared report template changed: cannot add the runtime tabs');
  }
  const script = CLIENT.replace(/<\/script/gi, '<\\/script');
  html = html.replace(NAV_ANCHOR, () => NAV.trimStart() + NAV_ANCHOR);
  html = html.replace(SECTION_ANCHOR, () => SECTIONS + SECTION_ANCHOR);
  const end = html.lastIndexOf('</body>');                  // the last one: an embedded library may contain the string
  html = `${html.slice(0, end)}<script>${script}</script>\n${html.slice(end)}`;
  return html;
}

export { generateHtmlReport, buildReportPayload };
