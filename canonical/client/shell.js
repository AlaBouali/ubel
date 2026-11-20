/* canonical/client/shell.js — the canonical report shell. Markup, classes and chart settings are the SCA report's
 * (sca/engine.js report template). Findings / inventory modals, executive summary, compliance and diffs come from the module
 * bundle (client/<family>.js) through FAMILY; everything below is only the part that is common to all modules.
 * Requires CANON and FAMILY. */
const cnEsc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
const cnIsObj = function (v) { return v !== null && typeof v === 'object' && !Array.isArray(v); };
const cnTitle = function (k) { return String(k).replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }); };
const CN_SEV = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
const CN_SEV_COLORS = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3', unknown: '#a3a3a3' };
const CN_SELECT = 'bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none';
const CN_INPUT = 'bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64';
const CN_CHECK = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg>';
const CN_CROSS = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>';

// ── tabs (switchTab is the SCA template's, unchanged) ───────────────────────────────────────────────
function switchTab(tabId) {
  document.querySelectorAll('nav button').forEach(function (btn) { btn.classList.remove('tab-active'); });
  document.getElementById('tab-' + tabId).classList.add('tab-active');
  document.querySelectorAll('main section').forEach(function (sec) { sec.classList.add('hidden'); });
  document.getElementById('section-' + tabId).classList.remove('hidden');
}

// ── small renderers (SCA classes) ───────────────────────────────────────────────────────────────────
function cnSevBadge(s) { s = String(s || 'unknown').toLowerCase(); return '<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-' + cnEsc(s) + '">' + cnEsc(s) + '</span>'; }
function cnTypeChip(t) { return '<span class="px-2 py-0.5 rounded border border-neutral-700 text-[10px] mono text-neutral-300">' + cnEsc(t) + '</span>'; }
function cnPolicyCell(v) { return v === true ? '<span class="text-red-400 flex items-center gap-1">' + CN_CROSS + ' Violates</span>' : (v === false ? '<span class="text-green-400 flex items-center gap-1">' + CN_CHECK + ' Safe</span>' : '<span class="text-neutral-600">—</span>'); }
function cnReachCell(v) { return v === true ? '<span class="text-red-400 text-xs font-semibold">Reachable</span>' : (v === false ? '<span class="text-green-400 text-xs">Not reachable</span>' : '<span class="text-neutral-600 text-xs">—</span>'); }
function cnCard(label, value, cls, border) { return '<div class="glass p-6 rounded-xl' + (border ? ' border-l-4 ' + border : '') + '"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">' + cnEsc(label) + '</p><p class="text-3xl font-bold ' + (cls || '') + '">' + cnEsc(value) + '</p></div>'; }
function cnRow(label, value, cls) { return '<div class="flex justify-between text-sm"><span class="text-neutral-500">' + cnEsc(label) + '</span><span class="mono ' + (cls || '') + '">' + cnEsc(value) + '</span></div>'; }
function cnSysRow(label, value) { return '<div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">' + cnEsc(label) + '</span><span class="mono text-xs break-all text-right">' + (value == null || value === '' ? '—' : cnEsc(Array.isArray(value) ? value.join(', ') : value)) + '</span></div>'; }
function cnSelect(id, label, values) { return '<select id="' + id + '" class="' + CN_SELECT + '"><option value="all">' + cnEsc(label) + '</option>' + values.map(function (v) { return '<option value="' + cnEsc(v) + '">' + cnEsc(v) + '</option>'; }).join('') + '</select>'; }
function cnUniq(list) { return Array.from(new Set(list.filter(function (x) { return x !== null && x !== undefined && x !== ''; }))).sort(); }
function cnHeader(title, controls) { return '<div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">' + cnEsc(title) + '</h2><div class="flex gap-2 w-full md:w-auto flex-wrap">' + controls + '</div></div>'; }
function cnTable(heads, bodyId, empty) { return '<div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' + heads.map(function (h, i) { return '<th class="' + (i === 0 ? 'px-6 ' : '') + 'py-4' + (h === 'Action' ? ' text-right' : '') + '">' + cnEsc(h) + '</th>'; }).join('') + '</tr></thead><tbody id="' + bodyId + '" class="divide-y divide-neutral-800"></tbody></table></div>'; }
function cnEmptyRow(cols, text) { return '<tr><td colspan="' + cols + '" class="px-6 py-12 text-center text-neutral-500 italic">' + cnEsc(text) + '</td></tr>'; }

// key/value rendering of an arbitrary original block (stats, policy, …): scalars as rows, nested values as indented rows
function cnKv(obj, depth) {
  depth = depth || 0;
  if (!cnIsObj(obj) && !Array.isArray(obj)) return '<span class="mono text-xs">' + cnEsc(obj) + '</span>';
  const entries = Array.isArray(obj) ? obj.map(function (v, i) { return [String(i + 1), v]; }) : Object.keys(obj).map(function (k) { return [k, obj[k]]; });
  return entries.map(function (e) {
    const k = e[0], v = e[1];
    if (v !== null && typeof v === 'object') {
      const inner = cnKv(v, depth + 1);
      return '<div class="border-b border-neutral-800 pb-2"><p class="text-neutral-500 text-xs mb-1">' + cnEsc(cnTitle(k)) + '</p><div class="pl-3 space-y-2">' + (inner || '<span class="text-neutral-600 text-xs">—</span>') + '</div></div>';
    }
    return cnSysRow(cnTitle(k), v);
  }).join('');
}
function cnBlock(title, obj, icon) { return '<div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + cnEsc(title) + '</h3><div class="space-y-3">' + (cnKv(obj) || '<span class="text-neutral-600 text-xs">—</span>') + '</div></div>'; }

// ── generic modal: only for entries whose module has no modal of its own (same frame / cards as the SCA modals) ──
function cnGenericModal(kind, badge, title, id, obj) {
  const scalars = [], nested = [];
  Object.keys(obj || {}).forEach(function (k) { const v = obj[k]; if (v !== null && typeof v === 'object') nested.push(k); else if (v !== null && v !== undefined && v !== '') scalars.push(k); });
  document.getElementById('modal-body').innerHTML = '<div class="space-y-6"><div><div class="flex items-center gap-3 mb-1 flex-wrap"><span class="text-[10px] uppercase font-bold text-neutral-300 border border-current px-2 py-0.5 rounded">' + cnEsc(badge) + '</span><h2 class="text-xl font-bold">' + cnEsc(title) + '</h2></div><p class="mono text-[11px] text-neutral-500 break-all">' + cnEsc(id) + '</p></div>'
    + '<div class="grid grid-cols-2 md:grid-cols-4 gap-3">' + scalars.map(function (k) { return '<div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">' + cnEsc(cnTitle(k)) + '</p><p class="mono text-xs break-all">' + cnEsc(obj[k]) + '</p></div>'; }).join('') + '</div>'
    + nested.map(function (k) { return '<div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">' + cnEsc(cnTitle(k)) + '</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><pre class="mono text-[11px] text-neutral-300 whitespace-pre-wrap break-all">' + cnEsc(JSON.stringify(obj[k], null, 2)) + '</pre></div></div>'; }).join('') + '</div>';
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

function cnOpenFinding(i) {
  let done = false;
  try { done = FAMILY.openFinding(i); } catch (e) { console.error('finding modal failed', e); }
  if (!done) { const f = CANON.findings[i]; cnGenericModal('finding', f.type, f.title, f.rule_id, f.details); }
}
function cnOpenInventory(i) {
  let done = false;
  try { done = FAMILY.openInventory(i); } catch (e) { console.error('inventory modal failed', e); }
  if (!done) { const c = CANON.inventory[i]; cnGenericModal('inventory', c.type, c.component_name, c.component_id, c.details); }
}
function cnOpenScope(i) { const s = CANON.scopes[i]; cnGenericModal('scope', s.type, s.name || s.type, s.path || s.name || '', s); }

// ── dashboard ───────────────────────────────────────────────────────────────────────────────────────
function cnRenderDashboard() {
  const st = CANON.stats || {}, fs = st.findings || {}, is = st.inventory || {}, bs = fs.by_severity || {};
  const reachable = CANON.findings.filter(function (f) { return f.reachable === true; }).length;
  document.getElementById('report-id').textContent = 'GENERATED_AT: ' + (CANON.metadata.scan_info.generated_at || '');
  document.getElementById('stat-total').textContent = fs.total || 0;
  document.getElementById('stat-critical-high').textContent = (bs.critical || 0) + ' / ' + (bs.high || 0);
  document.getElementById('stat-reachable').textContent = reachable;
  document.getElementById('stat-inventory').textContent = is.total || 0;
  const pol = CANON.policy || {}, dec = pol.decision, si = CANON.metadata.scan_info;
  const statusEl = document.getElementById('overall-status');
  const violating = fs.violating_policy || 0;
  const blocked = dec && dec.allowed === false || (!dec && violating > 0);
  statusEl.textContent = blocked ? 'Status: Blocked' : (dec || violating === 0 ? 'Status: Allowed' : 'Status');
  statusEl.className = 'px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider ' + (blocked ? 'bg-red-500/20 text-red-400 border border-red-500/50' : 'bg-green-500/20 text-green-400 border border-green-500/50');
  document.getElementById('decision-reason').textContent = (dec && dec.reason) || (violating ? violating + ' finding(s) violate the policy.' : 'No finding violates the policy.');
  const rows = [['Scan type', si.scan_type], ['Scope', si.scan_scope], ['Status', si.status], ['Findings violating policy', violating], ['Inventory components', is.total || 0]];
  document.getElementById('dash-facts').innerHTML = rows.map(function (r) { return '<tr><td class="pr-2 text-neutral-500">' + cnEsc(r[0]) + '</td><td>' + cnEsc(r[1] == null ? '—' : r[1]) + '</td></tr>'; }).join('');
  new Chart(document.getElementById('severityChart').getContext('2d'), {
    type: 'bar',
    data: { labels: ['Critical', 'High', 'Medium', 'Low', 'Info', 'Unknown'], datasets: [{ label: 'Findings', data: CN_SEV.map(function (s) { return bs[s] || 0; }), backgroundColor: ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#a3a3a3', '#525252'], borderRadius: 4 }] },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373' } }, x: { grid: { display: false }, ticks: { color: '#737373' } } } }
  });
}

// ── findings ────────────────────────────────────────────────────────────────────────────────────────
function cnRenderFindings() {
  const q = document.getElementById('f-search').value.toLowerCase(), sev = document.getElementById('f-sev').value, type = document.getElementById('f-type').value,
    conf = document.getElementById('f-conf').value, reach = document.getElementById('f-reach').value, pol = document.getElementById('f-policy').value;
  const tbody = document.getElementById('f-body'); tbody.innerHTML = '';
  const rows = [];
  CANON.findings.forEach(function (f, i) {
    if (sev !== 'all' && f.severity !== sev) return;
    if (type !== 'all' && f.type !== type) return;
    if (conf !== 'all' && (f.confidence || '') !== conf) return;
    if (reach === 'reachable' && f.reachable !== true) return;
    if (reach === 'unreachable' && f.reachable !== false) return;
    if (reach === 'unknown' && f.reachable !== null) return;
    if (pol === 'violate' && f.violate_policy !== true) return;
    if (pol === 'safe' && f.violate_policy === true) return;
    if (q && [f.title, f.rule_id, f.finding_id, f.affected_component_name, f.affected_component_id, f.type].join(' ').toLowerCase().indexOf(q) < 0) return;
    rows.push([i, f]);
  });
  rows.sort(function (a, b) { return CN_SEV.indexOf(a[1].severity) - CN_SEV.indexOf(b[1].severity); });
  if (!rows.length) { tbody.innerHTML = cnEmptyRow(9, 'No findings match the criteria.'); return; }
  rows.forEach(function (r) {
    const f = r[1], tr = document.createElement('tr');
    tr.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    tr.onclick = function () { cnOpenFinding(r[0]); };
    tr.innerHTML = '<td class="px-6 py-4 mono text-xs font-medium">' + cnEsc(f.rule_id) + (f.finding_id ? '<div class="text-[10px] text-neutral-600 font-normal">' + cnEsc(f.finding_id) + '</div>' : '') + '</td>'
      + '<td class="px-6 py-4">' + cnSevBadge(f.severity) + '</td>'
      + '<td class="px-6 py-4 font-medium">' + cnEsc(f.title) + '</td>'
      + '<td class="px-6 py-4">' + cnTypeChip(f.type) + '</td>'
      + '<td class="px-6 py-4 mono text-xs text-neutral-400 break-all">' + cnEsc(f.affected_component_name) + '</td>'
      + '<td class="px-6 py-4 text-xs text-neutral-400">' + cnEsc(f.confidence || '') + '</td>'
      + '<td class="px-6 py-4">' + cnReachCell(f.reachable) + '</td>'
      + '<td class="px-6 py-4">' + cnPolicyCell(f.violate_policy) + '</td>'
      + '<td class="px-6 py-4 text-right"><button class="text-red-400 hover:text-red-300 text-xs font-semibold">View Details</button></td>';
    tbody.appendChild(tr);
  });
}
function cnSetupFindings() {
  const F = CANON.findings;
  document.getElementById('section-findings').innerHTML = cnHeader('Findings',
    '<input type="text" id="f-search" placeholder="Search rule, title or component..." class="' + CN_INPUT + '">'
    + '<select id="f-sev" class="' + CN_SELECT + '"><option value="all">All Severities</option>' + CN_SEV.map(function (s) { return '<option value="' + s + '">' + cnTitle(s) + '</option>'; }).join('') + '</select>'
    + cnSelect('f-type', 'All Types', cnUniq(F.map(function (f) { return f.type; })))
    + cnSelect('f-conf', 'All Confidence', cnUniq(F.map(function (f) { return f.confidence; })))
    + '<select id="f-reach" class="' + CN_SELECT + '"><option value="all">All Reachability</option><option value="reachable">Reachable / exploitable</option><option value="unreachable">Not reachable</option><option value="unknown">Not assessed</option></select>'
    + '<select id="f-policy" class="' + CN_SELECT + '"><option value="all">All Policy</option><option value="violate">Violates Policy</option><option value="safe">Policy Safe</option></select>')
    + cnTable(['Rule', 'Severity', 'Title', 'Type', 'Component', 'Confidence', 'Reachable', 'Policy', 'Action'], 'f-body');
  ['f-search'].forEach(function (id) { document.getElementById(id).addEventListener('input', cnRenderFindings); });
  ['f-sev', 'f-type', 'f-conf', 'f-reach', 'f-policy'].forEach(function (id) { document.getElementById(id).addEventListener('change', cnRenderFindings); });
  cnRenderFindings();
}

// ── inventory ───────────────────────────────────────────────────────────────────────────────────────
function cnRenderInventory() {
  const q = document.getElementById('i-search').value.toLowerCase(), type = document.getElementById('i-type').value, status = document.getElementById('i-status').value,
    eco = document.getElementById('i-eco').value, pol = document.getElementById('i-policy').value, has = document.getElementById('i-has').value;
  const count = {}; CANON.findings.forEach(function (f) { count[f.affected_component_id] = (count[f.affected_component_id] || 0) + 1; });
  const tbody = document.getElementById('i-body'); tbody.innerHTML = '';
  const rows = [];
  CANON.inventory.forEach(function (c, i) {
    if (type !== 'all' && c.type !== type) return;
    if (status !== 'all' && c.status !== status) return;
    if (eco !== 'all' && ((c.details && c.details.ecosystem) || '') !== eco) return;
    if (pol === 'violate' && c.violate_policy !== true) return;
    if (pol === 'safe' && c.violate_policy === true) return;
    if (has === 'with' && !count[c.component_id]) return;
    if (has === 'without' && count[c.component_id]) return;
    if (q && [c.component_name, c.component_id, c.type].join(' ').toLowerCase().indexOf(q) < 0) return;
    rows.push([i, c]);
  });
  if (!rows.length) { tbody.innerHTML = cnEmptyRow(7, 'No inventory entries match the criteria.'); return; }
  rows.slice(0, 1500).forEach(function (r) {
    const c = r[1], tr = document.createElement('tr');
    tr.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    tr.onclick = function () { cnOpenInventory(r[0]); };
    const sc = c.status === 'clean' || c.status === 'safe' ? 'text-green-400' : c.status === 'infected' ? 'text-red-400' : c.status === 'undetermined' ? 'text-blue-400' : c.status === 'vulnerable' || c.status === 'misconfigured' || c.status === 'non_compliant' || c.status === 'at_risk' ? 'text-orange-400' : 'text-neutral-400';
    tr.innerHTML = '<td class="px-6 py-4 font-medium break-all">' + cnEsc(c.component_name) + '</td><td class="px-6 py-4">' + cnTypeChip(c.type) + '</td>'
      + '<td class="px-6 py-4"><span class="text-xs ' + sc + '">' + cnEsc(c.status) + '</span></td><td class="px-6 py-4 text-xs text-neutral-400">' + (count[c.component_id] || 0) + '</td>'
      + '<td class="px-6 py-4">' + cnPolicyCell(c.violate_policy) + '</td><td class="px-6 py-4 mono text-[10px] text-neutral-500 break-all">' + cnEsc(c.component_id) + '</td>'
      + '<td class="px-6 py-4 text-right"><button class="text-red-400 hover:text-red-300 text-xs font-semibold">View Details</button></td>';
    tbody.appendChild(tr);
  });
  if (rows.length > 1500) { const tr = document.createElement('tr'); tr.innerHTML = '<td colspan="7" class="px-6 py-4 text-center text-xs text-neutral-500 italic">Showing the first 1500 of ' + rows.length + ' entries; narrow the filters to see the rest.</td>'; tbody.appendChild(tr); }
}
function cnSetupInventory() {
  const I = CANON.inventory;
  document.getElementById('section-inventory').innerHTML = cnHeader('Inventory',
    '<input type="text" id="i-search" placeholder="Search component..." class="' + CN_INPUT.replace('focus:ring-red-500', 'focus:ring-blue-500') + '">'
    + cnSelect('i-type', 'All Types', cnUniq(I.map(function (c) { return c.type; })))
    + cnSelect('i-status', 'All States', cnUniq(I.map(function (c) { return c.status; })))
    + cnSelect('i-eco', 'All Ecosystems', cnUniq(I.map(function (c) { return c.details && c.details.ecosystem; })))
    + '<select id="i-policy" class="' + CN_SELECT + '"><option value="all">All</option><option value="violate">Violates Policy</option><option value="safe">Policy Safe</option></select>'
    + '<select id="i-has" class="' + CN_SELECT + '"><option value="all">All</option><option value="with">With findings</option><option value="without">Without findings</option></select>')
    + cnTable(['Component', 'Type', 'State', 'Findings', 'Policy Violation', 'Id', 'Action'], 'i-body');
  document.getElementById('i-search').addEventListener('input', cnRenderInventory);
  ['i-type', 'i-status', 'i-eco', 'i-policy', 'i-has'].forEach(function (id) { document.getElementById(id).addEventListener('change', cnRenderInventory); });
  cnRenderInventory();
}

// ── scopes ──────────────────────────────────────────────────────────────────────────────────────────
function cnSetupScopes() {
  const S = CANON.scopes || [];
  const sec = document.getElementById('section-scopes');
  if (!S.length) { sec.innerHTML = '<div class="glass p-6 rounded-xl text-sm text-neutral-500 italic">No scopes were recorded for this scan.</div>'; return; }
  const by = {}; S.forEach(function (s, i) { (by[s.type] = by[s.type] || []).push(i); });
  sec.innerHTML = '<h2 class="text-xl font-bold">Scopes</h2>' + Object.keys(by).map(function (t) {
    return '<div class="space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + cnEsc(cnTitle(t)) + ' (' + by[t].length + ')</h3><div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Name</th><th>Status</th><th>Details</th></tr></thead><tbody class="divide-y divide-neutral-800">'
      + by[t].slice(0, 500).map(function (i) {
        const s = S[i];
        const det = Object.keys(s).filter(function (k) { return k !== 'type' && k !== 'name' && k !== 'status' && s[k] !== null && typeof s[k] !== 'object'; }).slice(0, 4).map(function (k) { return k + '=' + s[k]; }).join(' · ');
        return '<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" data-scope="' + i + '"><td class="px-6 py-4 mono text-xs break-all">' + cnEsc(s.name) + '</td><td class="px-6 py-4 text-xs text-neutral-400">' + cnEsc(s.status || '') + '</td><td class="px-6 py-4 text-xs text-neutral-500 break-all">' + cnEsc(det) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }).join('');
  Array.prototype.forEach.call(sec.querySelectorAll('tr[data-scope]'), function (tr) { tr.onclick = function () { cnOpenScope(+tr.getAttribute('data-scope')); }; });
}

// ── detailed stats ──────────────────────────────────────────────────────────────────────────────────
function cnDonut(id, labels, data, colors) {
  new Chart(document.getElementById(id), { type: 'doughnut', data: { labels: labels, datasets: [{ data: data, backgroundColor: colors, borderWidth: 0 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#a3a3a3', boxWidth: 10, font: { size: 10 } } } } } });
}
function cnRenderStats() {
  const st = CANON.stats || {}, fs = st.findings || {}, is = st.inventory || {};
  const PAL = ['#ef4444', '#60a5fa', '#fb923c', '#10b981', '#a78bfa', '#facc15', '#f472b6', '#94a3b8'];
  const rows = function (o, colorOf) { return Object.keys(o || {}).map(function (k) { return cnRow(k, o[k], colorOf ? colorOf(k) : ''); }).join(''); };
  const f = CANON.findings;
  const reach = { reachable: f.filter(function (x) { return x.reachable === true; }).length, 'not reachable': f.filter(function (x) { return x.reachable === false; }).length, 'not assessed': f.filter(function (x) { return x.reachable === null; }).length };
  const card = function (title, canvas, inner) { return '<div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + title + '</h3>' + (canvas ? '<div class="h-48"><canvas id="' + canvas + '"></canvas></div>' : '') + '<div class="space-y-2">' + inner + '</div></div>'; };
  const sevColor = function (k) { return { critical: 'text-red-600', high: 'text-red-400', medium: 'text-orange-400', low: 'text-blue-400' }[k] || 'text-gray-400'; };
  const sec = document.getElementById('section-stats');
  let html = '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">'
    + card('Finding Stats', 'cnSevChart', cnRow('Total findings', fs.total || 0) + rows(fs.by_severity, sevColor))
    + card('Finding Types', 'cnTypeChart', rows(fs.by_type))
    + card('Confidence', 'cnConfChart', rows(fs.by_confidence))
    + card('Reachability', 'cnReachChart', rows(reach) + cnRow('Violating policy', fs.violating_policy || 0, 'text-red-400'))
    + card('Inventory Stats', 'cnInvTypeChart', cnRow('Total size', is.total || 0) + rows(is.by_type))
    + card('Inventory State', 'cnInvStatusChart', rows(is.by_status) + cnRow('Violating policy', is.violating_policy || 0, 'text-red-400'))
    + '</div>';
  const extra = [];
  if (st.source) extra.push(cnBlock('Scanner Statistics', st.source));
  Object.keys(st).forEach(function (k) { if (['findings', 'inventory', 'source', 'diffs', 'compliance_posture'].indexOf(k) < 0 && st[k] != null) extra.push(cnBlock(cnTitle(k), st[k])); });
  if (extra.length) html += '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">' + extra.join('') + '</div>';
  sec.innerHTML = html;
  const keys = function (o) { return Object.keys(o || {}); }, vals = function (o) { return keys(o).map(function (k) { return o[k]; }); };
  cnDonut('cnSevChart', CN_SEV, CN_SEV.map(function (s) { return (fs.by_severity || {})[s] || 0; }), CN_SEV.map(function (s) { return CN_SEV_COLORS[s]; }));
  cnDonut('cnTypeChart', keys(fs.by_type), vals(fs.by_type), PAL);
  cnDonut('cnConfChart', keys(fs.by_confidence), vals(fs.by_confidence), PAL);
  cnDonut('cnReachChart', keys(reach), vals(reach), ['#ef4444', '#10b981', '#525252']);
  cnDonut('cnInvTypeChart', keys(is.by_type), vals(is.by_type), PAL);
  cnDonut('cnInvStatusChart', keys(is.by_status), vals(is.by_status), PAL);
}

// ── policy ──────────────────────────────────────────────────────────────────────────────────────────
function cnRenderPolicy() {
  const p = CANON.policy || {}, sec = document.getElementById('section-policy');
  const blocks = [];
  Object.keys(p).forEach(function (k) {
    const v = p[k];
    if (v === null || v === undefined || k === 'checks' || k === 'profile') return;
    if (Array.isArray(v) && !v.length) return;
    blocks.push(cnBlock(k === 'flags' ? 'Scan Options / Flags' : cnTitle(k), v));
  });
  let html = '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">' + (blocks.join('') || '<div class="glass p-6 rounded-xl text-sm text-neutral-500 italic">No policy settings were recorded for this scan.</div>') + '</div>';
  const checks = Array.isArray(p.checks) ? p.checks : [];
  if (checks.length) {
    const cols = Object.keys(checks[0]).filter(function (k) { return checks[0][k] === null || typeof checks[0][k] !== 'object'; });
    html += '<div class="space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Checks evaluated (' + checks.length + ')</h3><div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' + cols.map(function (c, i) { return '<th class="' + (i === 0 ? 'px-6 ' : '') + 'py-4">' + cnEsc(cnTitle(c)) + '</th>'; }).join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">'
      + checks.map(function (c) { return '<tr>' + cols.map(function (k, i) { return '<td class="' + (i === 0 ? 'px-6 ' : '') + 'py-3 text-xs ' + (i === 0 ? 'mono' : 'text-neutral-400') + '">' + cnEsc(c[k] == null ? '' : c[k]) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div></div>';
  }
  sec.innerHTML = html;
}

// ── system info (the SCA System Info tab: runtime / engine & tool / scan / git) ─────────────────────────
function cnRenderSystem() {
  const m = CANON.metadata, sec = document.getElementById('section-system');
  const icon = '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="9"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>';
  const box = function (title, o) { return '<div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">' + icon + cnEsc(title) + '</h3><div class="space-y-3">' + Object.keys(o).map(function (k) { return cnSysRow(cnTitle(k), o[k]); }).join('') + '</div></div>'; };
  sec.innerHTML = '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">' + box('Scan Info', m.scan_info) + box('Engine & Tool', m.tool_info) + box('Environment', m.environment) + box('Git', m.git_metadata) + '</div>';
}

function cnSetupCounts() {
  document.getElementById('tab-findings').textContent = 'Findings(' + CANON.findings.length + ')';
  document.getElementById('tab-inventory').textContent = 'Inventory(' + CANON.inventory.length + ')';
  document.getElementById('tab-scopes').textContent = 'Scopes(' + (CANON.scopes || []).length + ')';
  const cs = CANON.compliance_summary;
  document.getElementById('tab-compliance').textContent = 'Compliance(' + (cs && cs.frameworks ? cs.frameworks.length : 0) + ')';
}

function cnInit() {
  closeModal();
  cnRenderDashboard();
  if (FAMILY.executive && CANON.executive_summary) { try { FAMILY.executive(); } catch (e) { console.error('Executive summary render failed:', e); } }
  cnSetupFindings(); cnSetupInventory(); cnSetupScopes(); cnRenderStats(); cnRenderPolicy(); cnRenderSystem();
  try { FAMILY.compliance(); } catch (e) { console.error('Compliance render failed:', e); }
  try { FAMILY.diffs(); } catch (e) { console.error('Diffs render failed:', e); }
  cnSetupCounts();
}
document.addEventListener('DOMContentLoaded', cnInit);
