/* canonical/client/appscan.js — mobile/lib/report.js (ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server)
 * The functions between "extracted verbatim" markers are copied unchanged from the module's own report template (modals,
 * executive summary, compliance and diff renderers, with the helpers they call). Only the data shim and the glue are new:
 * the shim rebuilds the module's own report shape (every canonical entry's `details` is the original entry), the glue says
 * which module modal a canonical finding / inventory entry opens. Requires the CANON constant (the canonical report). */

// ── data: the module report shape, rebuilt from the canonical report ──

const reportData = (function (C) {
  const st = C.stats || {};
  const own = function (f) { return ['vuln', 'infection', 'sc_vuln', 'sc_infection'].indexOf(f.type) < 0; };   // dependency advisories (sc_vuln / sc_infection; vuln / infection in older files) are not module issues
  const byCat = function (cat) { return C.findings.filter(function (f) { return own(f) && f.details && f.details.category === cat; }).map(function (f) { return f.details; }); };
  return {
    vulnerabilities: byCat('vulnerability'), secrets: byCat('secret'), misconfigurations: byCat('misconfiguration'),
    apps: C.inventory.filter(function (c) { return c.type === 'application'; }).map(function (c) { return c.details; }),
    dependencies: C.inventory.filter(function (c) { return c.type === 'dependency'; }).map(function (c) { return c.details; }),
    compliance_summary: C.compliance_summary, diffs: st.diffs || { enabled: false },
  };
})(CANON);
// Same derivation as the template in mobile/lib/report.js
const IS_MCP = reportData.apps.some(function (a) { return a && a.platform === 'mcp'; });
const IS_BINARY = reportData.apps.length > 0 && (reportData.apps.every(function (a) { return a && (a.platform === 'binary' || a.platform === 'package'); }) || IS_MCP);

// ── extracted verbatim from mobile/lib/report.js (ubel-mobile, ubel-binary, ubel-package, ubel-mcp-client, ubel-mcp-server) ──
const allFindings = [].concat(reportData.vulnerabilities || [], reportData.secrets || [], reportData.misconfigurations || []);

const AREA_NAMES = {"MASVS-STORAGE":"Data storage","MASVS-CRYPTO":"Cryptography","MASVS-AUTH":"Authentication","MASVS-NETWORK":"Network","MASVS-PLATFORM":"Platform interaction","MASVS-CODE":"Code & build hygiene","MASVS-RESILIENCE":"Tamper resistance","MASVS-PRIVACY":"Privacy","MCP-CONFIG":"Configuration","MCP-LAUNCH":"Launch command","MCP-REMOTE":"Remote server","MCP-TOOLS":"Tool definitions","MCP-SOURCE":"Server source","MCP-PROCESS":"Running process","PKG-INSTALL":"Install-time code","PKG-CODE":"Source behaviour","PKG-DEPS":"Dependencies","PKG-INTEGRITY":"Integrity & metadata","PKG-CONTENT":"Content & configuration","Unmapped":"Unmapped"};

const areaText = v => { const k = String(v || 'Unmapped').replace(/-\d+$/, ''); return IS_BINARY ? (AREA_NAMES[k] || k) : (v || 'Unmapped'); };

function escH(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }

function closeModal() { document.getElementById('modal-overlay').style.display = 'none'; document.body.style.overflow = 'auto'; }

function openModal(html) { document.getElementById('modal-body').innerHTML = html; document.getElementById('modal-overlay').style.display = 'flex'; document.body.style.overflow = 'hidden'; }

function modalMetaRow(label, value) { return '<div class="flex justify-between border-b border-neutral-800 pb-2 gap-4"><span class="text-neutral-500 text-xs">' + escH(label) + '</span><span class="mono text-xs text-right text-neutral-200 break-all">' + escH(value == null || value === '' ? '—' : value) + '</span></div>'; }

const CATEGORY_LABEL = { vulnerability: 'Vulnerability', secret: 'Secret', misconfiguration: 'Misconfiguration' };

function openFindingModal(index) {
  const f = allFindings[index]; if (!f) return;
  const c = {critical:'#ef4444',high:'#f87171',medium:'#fb923c',low:'#60a5fa',info:'#a3a3a3'}[f.severity] || '#a3a3a3';
  const evidence = Array.isArray(f.evidence) && f.evidence.length ? '<div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Evidence</h3><ul class="list-disc pl-5 text-sm text-neutral-300 space-y-2">' + f.evidence.map(e => '<li><code class="mono text-xs break-all">' + escH(e) + '</code></li>').join('') + '</ul></div>' : '';
  const compliance = f.compliance && f.compliance.frameworks ? f.compliance.frameworks.map(fw => '<div class="text-xs text-neutral-300"><span class="font-semibold">' + escH(fw.name) + '</span>: ' + (fw.controls || []).map(x => escH(x.id)).join(', ') + '</div>').join('') : '';
  openModal('<div class="space-y-5"><div><div class="flex flex-wrap items-center gap-3 mb-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + c + ';border-color:' + c + '">' + escH(f.severity || 'info') + '</span><span class="mono text-xs text-neutral-500">' + escH(f.rule || '') + '</span></div><h2 class="text-xl font-bold pr-8">' + escH(f.title || 'Untitled finding') + '</h2><p class="text-sm text-neutral-400 mt-2">' + escH(f.description || '') + '</p></div><div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + escH(CATEGORY_LABEL[f.category] || 'Issue') + ' Details</h3>' + (f.component ? modalMetaRow('Component', f.component.name + (f.component.version ? ' ' + f.component.version : '')) + modalMetaRow('Advisory', f.component.advisory) : modalMetaRow('Artifact', (f.artifact || '') + (f.line ? ':' + f.line : ''))) + modalMetaRow(IS_MCP ? 'Server' : IS_BINARY ? 'File' : 'Application', f.app || '—') + (IS_BINARY ? '' : modalMetaRow('Origin', f.origin || 'app')) + modalMetaRow('Confidence', f.confidence || 'unknown') + modalMetaRow(IS_BINARY ? 'Area' : 'MASVS', IS_BINARY ? areaText(f.masvs) : (f.masvs || 'Unmapped')) + modalMetaRow('CWE', f.cwe || '—') + '</div>' + evidence + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Remediation</h3><p class="text-sm text-neutral-300">' + escH(f.remediation || 'Review this finding manually.') + '</p></div>' + (compliance ? '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Compliance Frameworks</h3>' + compliance + '</div>' : '') + '</div>');
}

function mobileComplianceMatches(frameworkName, controlId) {
  return allFindings.filter(f => (f.compliance?.frameworks || []).some(fw =>
    fw.name === frameworkName && (fw.controls || []).some(control => control.id === controlId)));
}

function mobileComplianceFrameworkMatches(frameworkName) {
  return allFindings.filter(f => (f.compliance?.frameworks || []).some(fw => fw.name === frameworkName));
}

function renderCompliance() {
  const cs = reportData.compliance_summary;
  const disclaimer = document.getElementById('compliance-disclaimer');
  const grid = document.getElementById('compliance-frameworks-grid');
  const empty = document.getElementById('compliance-empty');
  disclaimer.textContent = cs?.disclaimer || '';
  if (!cs || !Array.isArray(cs.frameworks) || !cs.frameworks.length) {
    empty.classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  empty.classList.add('hidden');
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const frameworkCount = mobileComplianceFrameworkMatches(fw.name).length;
    const controls = (fw.controls || []).map((control, controlIdx) => {
      const count = mobileComplianceMatches(fw.name, control.id).length;
      return '<div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" onclick="openComplianceModal(' + fwIdx + ',' + controlIdx + ')">' +
        '<div class="flex flex-col min-w-0"><span class="mono text-red-400">' + escH(control.id) + '</span><span class="text-neutral-500">' + escH(control.title || control.id) + '</span></div>' +
        '<div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0"><span class="mono text-neutral-200">' + count + ' issue' + (count === 1 ? '' : 's') + '</span></div></div>';
    }).join('');
    return '<div class="glass p-6 rounded-xl space-y-4"><div class="flex items-start justify-between gap-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">' + escH(fw.name) + '</h3><div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0"><span class="mono text-red-400 font-semibold text-xs">' + frameworkCount + ' issue' + (frameworkCount === 1 ? '' : 's') + '</span></div></div>' +
      '<div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">' + (controls || '<p class="text-xs text-neutral-500 italic">No mapped controls.</p>') + '</div></div>';
  }).join('');
}

function openComplianceModal(fwIdx, controlIdx) {
  const cs = reportData.compliance_summary;
  const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
  const control = fw && fw.controls && fw.controls[controlIdx];
  if (!fw || !control) return;
  const matches = mobileComplianceMatches(fw.name, control.id);
  const rows = matches.map(f => {
    const index = allFindings.indexOf(f);
    const severity = String(f.severity || 'unknown').toLowerCase();
    return '<div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="openFindingModal(' + index + ')">' +
      '<div class="flex items-center gap-3 min-w-0"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-' + escH(severity) + '">' + escH(severity) + '</span><span class="text-xs text-white">' + escH(f.title || f.rule || 'Mobile issue') + '</span></div>' +
      '<div class="flex items-center gap-3 shrink-0"><span class="mono text-[10px] text-neutral-500">' + escH(f.artifact || '') + '</span><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg></div></div>';
  }).join('');
  const body = rows || '<p class="text-sm text-neutral-500 italic py-2">No issues mapped to this control.</p>';
  openModal('<div class="space-y-4"><div><div class="flex items-center gap-3 mb-1 flex-wrap"><span class="mono text-red-400 text-sm">' + escH(control.id) + '</span><h2 class="text-lg font-semibold text-white">' + escH(control.title || control.id) + '</h2></div><p class="text-xs text-neutral-500">' + escH(fw.name) + (fw.version ? ' · ' + escH(fw.version) : '') + ' — ' + matches.length + ' issue' + (matches.length === 1 ? '' : 's') + '</p></div><div class="glass rounded-xl p-3 space-y-1">' + body + '</div></div>');
}

// The module's diff groups, flattened into the three lists the severity view (client/diffs.js) splits by severity.
const DIFF_KINDS = [['vulnerabilities', 'Vulnerability'], ['secrets', 'Secret'], ['misconfigs', 'Misconfiguration']];
const DIFF_LIST_MAP = [['new', 'new'], ['unchanged', 'existing'], ['removed', 'fixed']];

function diffLists(d) {
  const out = { new: [], existing: [], fixed: [] };
  DIFF_KINDS.forEach(function (kind) {
    DIFF_LIST_MAP.forEach(function (m) {
      ((d[kind[0]] && d[kind[0]][m[0]]) || []).forEach(function (item) {
        out[m[1]].push({ title: item.title || item.rule || 'Untitled issue', type: item.type || kind[1], severity: item.type === 'sc_infection' ? 'infection' : item.severity });
      });
    });
  });
  return out;
}

function renderDiffs() {
  const section = document.getElementById('section-diffs');
  const d = reportData.diffs;
  if (!d || !d.enabled || !d.previous || !d.counts) {
    section.innerHTML = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2></div><div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
    return;
  }
  let html = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2><p class="text-xs text-neutral-500 mono">vs previous report ' + escH(d.previous.report_id || d.previous_file || 'previous report') + (d.previous.generated_at ? ' (' + escH(d.previous.generated_at) + ')' : '') + '</p></div>';
  html += '<div class="pt-4">' + UBEL_DIFFS.sectionHtml(diffLists(d), { hint: 'Vulnerabilities, secrets and misconfigurations compared with the previous report, split by severity level. Select a count to list them.' }) + '</div>';
  const compliance = d.compliance && d.compliance.frameworks || [];
  if (compliance.length) {
    html += '<h3 class="text-lg font-bold pt-4">Compliance</h3><p class="text-xs text-neutral-500">Issues mapped to each framework, compared with the previous report.</p><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    compliance.forEach((fw, fwIdx) => {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + escH(fw.name) + '</p>' + (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + escH(fw.version) + '</p>' : '') + '</div><div class="grid grid-cols-3 gap-2">';
      [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(status => {
        html += '<button type="button" onclick="openMobileComplianceDiffModal(' + fwIdx + ',&quot;' + status[0] + '&quot;)" class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors"><span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + status[1] + '</span><span class="block text-2xl font-bold mono ' + status[2] + '">' + ((fw[status[0]] || []).length) + '</span></button>';
      });
      html += '</div></div>';
    });
    html += '</div>';
  }
  section.innerHTML = html;
}

function openMobileComplianceDiffModal(fwIdx, list) {
  const frameworks = reportData.diffs && reportData.diffs.compliance && reportData.diffs.compliance.frameworks || [];
  const fw = frameworks[fwIdx];
  if (!fw) return;
  const labels = { new: 'New', unchanged: 'Still existing', removed: 'Resolved' };
  const items = fw[list] || [];
  const rows = items.map(item => '<tr><td class="py-2 pr-4 text-neutral-400">' + escH(item.kind === 'secret' ? 'Secret' : item.kind === 'misconfig' ? 'Misconfiguration' : 'Vulnerability') + '</td><td class="py-2 pr-4 mono">' + escH(item.id || '') + '</td><td class="py-2 pr-4 uppercase text-[10px] font-bold severity-' + escH(String(item.severity || 'unknown').toLowerCase()) + '">' + escH(item.severity || 'unknown') + '</td><td class="py-2 pr-4 font-medium">' + escH(item.title || '') + '</td><td class="py-2 pr-4 mono text-neutral-400">' + escH(item.where || '') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.controls || '') + '</td></tr>').join('');
  const body = rows ? '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' + ['Type', 'ID', 'Severity', 'Title', 'Component / File', 'Controls'].map(label => '<th class="pb-2 pr-4 font-bold">' + label + '</th>').join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">' + rows + '</tbody></table></div>' : '<p class="text-sm text-neutral-500 italic">None.</p>';
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(fw.name) + ' — ' + labels[list] + '</h3><p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}

function appDetails(index) {
  const a = reportData.apps[index]; if (!a) return;
  const rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') rows.push(modalMetaRow(k, v)); };
  if (a.remote_hosts && a.remote_hosts.total) {
    const rh = a.remote_hosts;
    add('Remote hosts', rh.total + ' (' + rh.domains + ' domain(s), ' + rh.ips + ' IP address(es)) — ' + (rh.hosts || []).slice(0, 8).map(function (h) { return h.host; }).join(', ') + (rh.total > 8 ? ' …' : ''));
  }
  add('Platform', a.platform === 'mcp' ? 'MCP ' + (a.transport || 'server') : a.platform === 'package' ? 'Package (' + (a.ecosystem_label || a.ecosystem) + ')' : a.platform === 'binary' ? (a.format === 'macho' ? 'Mach-O' : a.format === 'pe' ? 'PE' : 'ELF') : a.platform === 'ios' ? 'iOS' : 'Android');
  if (a.platform === 'package') {
    var pk = a.package || {};
    add('Name', a.name); add('Version', a.version); add('Registry', a.registry); add('Download URL', (pk.artifacts || []).map(function (x) { return x.url; }).join(' · '));
    add('SHA-256', (pk.artifacts || []).map(function (x) { return x.filename + ': ' + x.sha256; }).join(' · ')); add('Size', a.size_bytes ? (a.size_bytes / 1048576).toFixed(2) + ' MB' : '');
    add('Archive digest', pk.integrity ? pk.integrity.state + (pk.integrity.algo ? ' (' + pk.integrity.algo + ', ' + pk.integrity.source + ')' : '') : '');
    add('License', pk.info && pk.info.license); add('Repository', pk.info && pk.info.repository); add('Homepage', pk.info && pk.info.homepage); add('Published', pk.published_at); add('Publisher', pk.publisher);
    add('Files', pk.file_count); add('Unpacked size', pk.unpacked_bytes ? (pk.unpacked_bytes / 1048576).toFixed(2) + ' MB' : '');
    add('Install-time hooks', (pk.hooks || []).filter(function (h) { return h.consumer !== false; }).map(function (h) { return h.id + ' / ' + h.phase; }).join(', '));
    add('Dependencies', pk.dependency_total); add('Bundled components', (pk.bundled || []).length); if (pk.locked_total) add('Locked entries', pk.locked_total); add('Native files', (pk.native_files || []).length);
    if (a.behavior) {
      const labels = {"file_io":"File access","network":"Network","process":"Process execution","dynamic_loading":"Dynamic loading / resolution","injection":"Debugging / process injection","anti_analysis":"Anti-analysis","privilege":"Privilege","persistence":"Persistence","input_capture":"Input capture / sensitive devices","crypto":"Cryptography","system_info":"System information","credentials":"Credentials / secrets access","obfuscation":"Obfuscation / encoded payloads"};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        const origins = Object.keys(byOrigin || {}), n = origins.reduce(function (t, o) { const x = byOrigin[o]; return t + (x.functions != null ? x.functions : Object.keys(x.apis || {}).length); }, 0);
        add('Behavior · ' + (labels[cat] || cat), n + ' entr' + (n === 1 ? 'y' : 'ies') + ' — ' + origins.slice(0, 4).map(function (o) { return o + ': ' + Object.keys(byOrigin[o].apis || {}).slice(0, 3).join(', '); }).join(' · '));
      }
    }
  } else if (a.platform === 'mcp') {
    const L = a.launch || {}, R = a.remote || {}, D = a.definitions || {}, S = a.source || null;
    add('Name', a.name); add('Client', a.client); add('Scope', a.scope); add('Configuration file', a.file); add('Transport', a.transport); add('Target', a.target); add('Status', a.disabled ? 'disabled' : '');
    if (L.kind) add('Launch', [L.kind, L.runner, L.shell_wrapper && ('via ' + L.shell_wrapper)].filter(Boolean).join(' / '));
    add('Packages', (L.packages || []).map(function (x) { return x.ecosystem + ':' + x.name + (x.version ? '@' + x.version : '') + ' (' + x.pin + (x.analysis ? (x.analysis.error ? ', not analysed' : ', analysed ' + x.analysis.analysed_version + ': ' + x.analysis.findings + ' finding(s)') : '') + ')'; }).join('; '));
    if (L.image) add('Container image', L.image.image + (L.image.privileged ? ' (privileged)' : ''));
    if (L.script) add('Script', L.script.path || L.script.module);
    if (S) add('Source read', S.analysed + ' of ' + S.files + ' file(s), ' + (S.tools || []).length + ' tool(s) registered, ' + S.root);
    if (R.mcp) {
      add('Live probe', (R.transport || '') + ', protocol ' + ((R.initialize && R.initialize.protocolVersion) || '?') + ', ' + (R.exposure || '?') + ' address');
      add('Server', R.initialize && R.initialize.serverInfo ? (R.initialize.serverInfo.name || '') + ' ' + (R.initialize.serverInfo.version || '') : '');
      add('Authentication', R.unauthenticated === true ? 'none: answered without credentials' : R.unauthenticated === false ? 'required' + (R.auth && R.auth.scheme ? ' (' + R.auth.scheme + ')' : '') : '');
      if (R.checks) add('Origin / Host / CORS / bind', [R.checks.origin, R.checks.host, R.checks.cors, R.checks.bind].filter(Boolean).join(' / '));
      if (R.tls) add('TLS', (R.tls.protocol || '') + (R.tls.validTo ? ', expires ' + R.tls.validTo.slice(0, 10) : ''));
    } else if (R.skipped) add('Live probe', 'skipped: ' + R.skipped);
    else if (R.error) add('Live probe', 'not reachable (' + R.error + ')');
    const tl = D.tools || [];
    if (tl.length) {
      const caps = {}; tl.forEach(function (t) { (t.capabilities || []).forEach(function (c) { caps[c] = (caps[c] || 0) + 1; }); });
      add('Tools', tl.length + (Object.keys(caps).length ? ' (' + Object.keys(caps).map(function (k) { return caps[k] + ' ' + k; }).join(', ') + ')' : ''));
      add('Tool names', tl.slice(0, 25).map(function (t) { return t.name; }).join(', ') + (tl.length > 25 ? ' ... (' + tl.length + ' total)' : ''));
    }
    (a.observed || []).forEach(function (o, i) { add('Process ' + (i + 1), 'pid ' + o.pid + ' (uid ' + o.uid + '): ' + o.cmdline + (o.listening && o.listening.length ? ' | listening ' + o.listening.map(function (l) { return l.addr + ':' + l.port; }).join(', ') : '')); });
  } else if (a.platform === 'binary') {
    add('Name', a.name); add('Size', a.size_bytes ? (a.size_bytes / 1048576).toFixed(2) + ' MB' : ''); add('Architecture', (a.architectures || [a.arch]).join(', ')); add('Type', a.kind); add('Bits', a.bits);
    add('Linked libraries', (a.needed || []).join(', ')); add('Signed', a.signed === undefined ? '' : (a.signed ? 'yes (presence only, not verified)' : 'no'));
    add('Stripped', a.stripped === undefined ? '' : (a.stripped ? 'yes' : 'no')); add('Statically linked', a.static === undefined ? '' : (a.static ? 'yes' : 'no')); add('.NET assembly', a.managed ? 'yes' : '');
    add('Embedded runtime', (a.runtimes || []).map(r => r.name + ' ' + (r.version || '')).join(', '));
    add('Packaging', (a.packaging || []).map(x => [x.kind, x.node_version && ('Node ' + x.node_version), x.packages != null && (x.packages + ' package(s)')].filter(Boolean).join(' · ')).join('; '));
    if (a.go) add('Go build', [a.go.version || a.go.go_version, a.go.modules != null && (a.go.modules + ' module(s)')].filter(Boolean).join(' · '));
    if (a.behavior) {
      const labels = {"file_io":"File access","network":"Network","process":"Process execution","dynamic_loading":"Dynamic loading / resolution","injection":"Debugging / process injection","anti_analysis":"Anti-analysis","privilege":"Privilege","persistence":"Persistence","input_capture":"Input capture / sensitive devices","crypto":"Cryptography","system_info":"System information","credentials":"Credentials / secrets access","obfuscation":"Obfuscation / encoded payloads"};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        const origins = Object.keys(byOrigin || {}), n = origins.reduce(function (t, o) { const x = byOrigin[o]; return t + (x.functions != null ? x.functions : Object.keys(x.apis || {}).length); }, 0);
        const shown = origins.slice(0, 4).map(function (o) { const apis = Object.keys(byOrigin[o].apis || {}); return o + ': ' + apis.slice(0, 3).join(', ') + (apis.length > 3 ? ' …' : ''); });
        add('Behavior · ' + (labels[cat] || cat), n + ' function' + (n === 1 ? '' : 's') + ' — ' + shown.join(' · ') + (origins.length > 4 ? ' · … (' + origins.length + ' sources)' : ''));
      }
    }
  } else if (a.platform === 'ios') {
    if (a.behavior) {
      const labels = {"file_io":"File access","network":"Network","process":"Process execution","dynamic_loading":"Dynamic loading / resolution","injection":"Debugging / process injection","anti_analysis":"Anti-analysis","privilege":"Privilege","persistence":"Persistence","input_capture":"Input capture / sensitive devices","crypto":"Cryptography","system_info":"System information","credentials":"Credentials / secrets access","obfuscation":"Obfuscation / encoded payloads"};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        const origins = Object.keys(byOrigin || {}), n = origins.reduce(function (t, o) { const x = byOrigin[o]; return t + (x.functions != null ? x.functions : Object.keys(x.apis || {}).length); }, 0);
        add('Behavior · ' + (labels[cat] || cat), n + ' function' + (n === 1 ? '' : 's') + ' — ' + origins.map(function (o) { return o + ': ' + Object.keys(byOrigin[o].apis || {}).slice(0, 3).join(', '); }).join(' · '));
      }
    }
    add('Name', a.name); add('Bundle ID', a.bundle_id); add('Version', a.version); add('Build', a.build); add('Minimum iOS', a.min_os); add('Architectures', (a.architectures || []).join(', '));
    add('Binary', a.binary ? ('PIE ' + (a.binary.pie ? 'yes' : 'no') + ', encrypted ' + (a.binary.encrypted ? 'yes' : 'no') + ', signed ' + (a.binary.signed ? 'yes' : 'no') + (a.binary.swift ? ', Swift' : '')) : '—');
    add('Provisioning', a.provisioning ? [a.provisioning.type, a.provisioning.name, a.provisioning.team, 'expires ' + (a.provisioning.expires || '?')].filter(Boolean).join(' — ') : '—');
    add('URL schemes', (a.url_schemes || []).join(', ')); add('Frameworks', (a.frameworks || []).map(f => f.name + (f.version ? ' ' + f.version : '')).join(', ')); add('Extensions', (a.extensions || []).map(e => e.name).join(', ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; '));
  } else {
    add('Package', a.package); add('Version', (a.version_name || '?') + ' (' + (a.version_code || '?') + ')'); add('SDK', 'min ' + (a.min_sdk ?? '?') + ' / target ' + (a.target_sdk ?? '?'));
    add('Components', Object.entries(a.components || {}).map(([k,v]) => v + ' ' + k).join(', ')); add('Permissions', (a.permissions || []).length);
    add('Signing', a.signing ? (a.signing.schemes || []).join(', ') + ' — ' + (a.signing.certificates || []).map(cert => cert.subject + ' [' + cert.key + ', ' + cert.signature_algorithm + ']').join('; ') : '—');
    add('Frameworks', (a.frameworks || []).join(', ')); add('Protections', (a.protections || []).map(p => p.name + ' (' + p.confidence + ')').join('; ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; ')); add('Modules', (a.modules || []).map(m => m.name + ' (' + m.type + ')').join(', ')); add('DEX files', (a.dex_files || []).join(', ')); add('Native libraries', (a.native_libs || []).length); add('Native hardening', a.native_hardening ? (a.native_hardening.total + ' binaries / ' + a.native_hardening.libraries + ' libraries (' + (a.native_hardening.abis || []).join(', ') + ') — failing: ' + (Object.entries(a.native_hardening.failing || {}).filter(function (kv) { return kv[1] > 0; }).map(function (kv) { return kv[0] + ' x' + kv[1]; }).join(', ') || 'none')) : ''); add('Embedded libraries', (a.libraries || []).map(l => l.name + ' ' + (l.version || '')).join(', '));
    if (a.behavior) {
      const labels = {"file_io":"File access","network":"Network","ipc":"Inter-app communication","process":"Process execution","reflection":"Reflection / dynamic lookup","native_code":"Native code loading","device_access":"Sensitive device APIs","injection":"Debugging / process injection","anti_analysis":"Anti-analysis","privilege":"Privilege","persistence":"Persistence","input_capture":"Input capture / sensitive devices","crypto":"Cryptography","system_info":"System information","dynamic_loading":"Dynamic loading / resolution","credentials":"Credentials / secrets access","obfuscation":"Obfuscation / encoded payloads"};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        add('Behavior · ' + (labels[cat] || cat), ['app', 'unknown', 'library'].filter(o => byOrigin[o]).map(o => o + ': ' + byOrigin[o].calls + ' (' + Object.entries(byOrigin[o].apis).slice(0, 4).map(kv => kv[0] + ' ×' + kv[1]).join(', ') + ')').join(' · '));
      }
      const ia = a.behavior.intent_actions || {}, it = a.behavior.intent_actions_total || {};
      add('Intent actions (app code)', (ia.app || []).slice(0, 12).join(', ') + ((it.app || 0) > 12 ? ' … (' + it.app + ' total)' : ''));
      add('Intent actions (unattributed / library)', (it.unknown || 0) + ' / ' + (it.library || 0));
    }
    if (a.online_checks) {
      const o = a.online_checks;
      add('Online · App Links', (o.assetlinks || []).map(x => x.host + ': ' + x.state).join('; '));
      add('Online · Firebase database', (o.firebase_database || []).map(x => x.url + ': ' + x.state).join('; '));
      add('Online · Remote Config', o.remote_config ? o.remote_config.state + (o.remote_config.entries ? ' (' + o.remote_config.entries + ' parameters)' : '') : '');
    }
  }
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">App Inventory</p><h2 class="text-xl font-bold pr-8">' + escH(a.name || a.package || a.bundle_id || 'Application') + '</h2></div><div class="glass p-5 rounded-xl space-y-3">' + rows.join('') + '</div></div>');
}

function openDependencyModal(index) {
  const dep = (reportData.dependencies || [])[index]; if (!dep) return;
  const statusLabels = { vulnerable: 'Vulnerable', clean: IS_BINARY ? 'No known advisory' : 'Safe', not_queryable: 'Not queried', lookup_error: 'Lookup failed', lookup_incomplete: 'Lookup incomplete', pending: 'Pending' };
  const sources = [...(dep.sources || [])].map(s => '<li><code class="mono text-xs break-all">' + escH(s) + '</code></li>').join('') || '<li>Source path unavailable</li>';
  const sourceTypes = (dep.source_types || []).map(escH).join(', ') || 'Unknown';
  const advisories = (dep.vulnerabilities || []).map(v => {
    const sev = String(v.severity || 'unknown').toLowerCase();
    const color = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', moderate: '#fb923c', low: '#60a5fa', info: '#a3a3a3' }[sev] || '#a3a3a3';
    const id = v.url ? '<a class="underline text-red-300" href="' + escH(v.url) + '" target="_blank" rel="noopener noreferrer">' + escH(v.id) + '</a>' : escH(v.id || 'Unknown advisory');
    const aliases = (v.aliases || []).join(', ');
    const fixes = (v.fixed_versions || []).join(', ');
    return '<div class="glass p-4 rounded-xl space-y-2"><div class="flex flex-wrap items-center justify-between gap-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + color + ';border-color:' + color + '">' + escH(sev) + '</span><span class="mono text-xs">' + id + '</span></div><h4 class="font-semibold text-sm">' + escH(v.summary || v.id || 'OSV advisory') + '</h4>' + (v.details ? '<p class="text-xs text-neutral-400 whitespace-pre-wrap break-words">' + escH(v.details.slice(0, 5000)) + (v.details.length > 5000 ? '…' : '') + '</p>' : '') + '<div class="text-xs text-neutral-500 space-y-1">' + (aliases ? '<p>Aliases: ' + escH(aliases) + '</p>' : '') + '<p>Affected version: ' + escH(v.affected_dependency_version || dep.version || 'unknown') + '</p>' + (fixes ? '<p>Fixed versions: <span class="text-green-300">' + escH(fixes) + '</span></p>' : '<p>No fixed version is listed for this advisory.</p>') + (v.severity_score != null ? '<p>CVSS score: <span class="mono text-neutral-300">' + escH(v.severity_score) + '</span>' + (v.severity_vector ? ' <span class="mono break-all">' + escH(v.severity_vector) + '</span>' : '') + '</p>' : '') + (v.published ? '<p>Published: ' + escH(v.published) + '</p>' : '') + (v.is_infection ? '<p class="text-purple-300 font-semibold">Malicious-package advisory</p>' : '') + '</div></div>';
  }).join('');
  const error = dep.lookup_error ? '<div class="border border-orange-500/40 bg-orange-500/10 rounded-lg p-3 text-xs text-orange-200">' + escH(dep.lookup_error) + '</div>' : '';
  const reason = dep.lookup_reason ? '<p class="text-sm text-neutral-400">' + escH(dep.lookup_reason) + '</p>' : '';
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">' + (IS_BINARY ? 'Component' : 'Mobile dependency') + '</p><h2 class="text-xl font-bold pr-8 break-all">' + escH(dep.name || 'Unknown dependency') + '</h2><p class="text-xs text-neutral-500 mt-2">' + escH(dep.ecosystem || 'Unknown ecosystem') + ' · ' + escH(dep.version || 'version unavailable') + '</p></div><div class="glass p-5 rounded-xl space-y-3">' + modalMetaRow(IS_BINARY ? 'Lookup status' : 'OSV status', statusLabels[dep.lookup_status] || dep.lookup_status || 'Not queried') + (dep.cpe ? modalMetaRow('CPE', dep.cpe) : '') + (IS_BINARY && !dep.purl ? '' : modalMetaRow('Package URL', dep.purl || 'Not available')) + (IS_BINARY && !dep.coordinate ? '' : modalMetaRow('Coordinate / identity', dep.coordinate || 'Not available')) + (IS_BINARY && !dep.confidence ? '' : modalMetaRow('Detection confidence', dep.confidence || 'unknown')) + (IS_BINARY && !(dep.source_types || []).length ? '' : modalMetaRow('Evidence type', sourceTypes)) + modalMetaRow('Known advisories', dep.vulnerability_count || 0) + '</div>' + reason + error + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Evidence source(s)</h3><ul class="list-disc pl-5 text-sm text-neutral-300 space-y-1">' + sources + '</ul></div><div class="space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + (IS_BINARY ? 'Advisories (' : 'OSV advisories (') + (dep.vulnerabilities || []).length + ')</h3>' + (advisories || '<p class="text-sm text-neutral-500 italic">' + (IS_BINARY ? 'No advisory is attached to this component.' : 'No OSV advisory details are attached to this dependency.') + '</p>') + '</div></div>');
}

// ── glue: canonical entry → module modal ──
const FAMILY = {
  openFinding: function (i) {
    const f = CANON.findings[i];
    if (f.type === 'sc_vuln' || f.type === 'sc_infection' || f.type === 'vuln' || f.type === 'infection') {
      // the advisory on its own: the SCA vulnerability modal (client/scvuln.js), not the dependency's modal
      if (window.UBEL_SC_VULN && f.details && window.UBEL_SC_VULN.open(f.details)) return true;
      const k = reportData.dependencies.findIndex(function (d) { return (d.purl || (d.name + '@' + (d.version || ''))) === f.affected_component_id; });
      if (k < 0) return false; openDependencyModal(k); return true;
    }
    const k = allFindings.indexOf(f.details); if (k < 0) return false; openFindingModal(k); return true;
  },
  openInventory: function (i) {
    const c = CANON.inventory[i];
    if (c.type === 'application') { appDetails(reportData.apps.indexOf(c.details)); return true; }
    if (c.type === 'dependency') { openDependencyModal(reportData.dependencies.indexOf(c.details)); return true; }
    return false;
  },
  executive: null,   // server-rendered by the module (see canonical/html.js)
  compliance: function () { renderCompliance(); },
  diffs: function () { renderDiffs(); },
};
