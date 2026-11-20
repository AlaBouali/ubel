(function () {
  'use strict';
  var D = JSON.parse(document.getElementById('canon-data').textContent);
  var F = D.findings || [], INV = D.inventory || [], SC = D.scopes || [];
  var SEV = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  var $ = function (id) { return document.getElementById(id); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };
  var isObj = function (v) { return v !== null && typeof v === 'object' && !Array.isArray(v); };
  var pretty = function (t) { return String(t == null ? '' : t).replace(/_/g, ' ').replace(/\b\w/g, function (c) { return c.toUpperCase(); }); };
  var link = function (u) { return /^https?:\/\//i.test(u) ? '<a class="text-red-400 underline break-all" target="_blank" rel="noopener noreferrer" href="' + esc(u) + '">' + esc(u) + '</a>' : esc(u); };

  // ── small renderers ───────────────────────────────────────────────────────
  function sevBadge(s) { return '<span class="px-2 py-0.5 text-[11px] uppercase border rounded severity-' + esc(s || 'unknown') + '">' + esc(s || 'unknown') + '</span>'; }
  function chip(t) { return '<span class="px-2 py-0.5 text-[11px] rounded type-chip mono">' + esc(t) + '</span>'; }
  function policyBadge(v) { return v === true ? '<span class="text-red-400 text-xs font-semibold">violates</span>' : (v === false ? '<span class="text-neutral-500 text-xs">ok</span>' : '<span class="text-neutral-600 text-xs">n/a</span>'); }
  function val(v) {
    if (v == null || v === '') return '<span class="text-neutral-600">—</span>';
    if (typeof v === 'boolean') return v ? 'yes' : 'no';
    if (Array.isArray(v)) { if (!v.length) return '<span class="text-neutral-600">—</span>'; if (v.every(function (x) { return typeof x !== 'object' || x === null; })) return v.map(function (x) { return /^https?:\/\//i.test(String(x)) ? link(x) : esc(x); }).join(', '); return '<pre class="code">' + esc(JSON.stringify(v, null, 2)) + '</pre>'; }
    if (isObj(v)) return '<pre class="code">' + esc(JSON.stringify(v, null, 2)) + '</pre>';
    return esc(v);
  }
  function kv(rows) {
    rows = rows.filter(function (r) { return r && r[1] !== undefined && r[1] !== null && r[1] !== '' && !(Array.isArray(r[1]) && !r[1].length); });
    if (!rows.length) return '';
    return '<dl class="grid grid-cols-3 gap-x-4 gap-y-2 text-sm">' + rows.map(function (r) { return '<dt class="text-neutral-500 text-xs uppercase tracking-wide pt-0.5">' + esc(r[0]) + '</dt><dd class="col-span-2 break-words mono text-[13px]">' + val(r[1]) + '</dd>'; }).join('') + '</dl>';
  }
  function section(title, body) { return body ? '<div class="mt-5"><h4 class="text-xs uppercase tracking-wider text-neutral-500 mb-2">' + esc(title) + '</h4>' + body + '</div>' : ''; }
  function code(t) { return t ? '<pre class="code mono">' + esc(t) + '</pre>' : ''; }
  function para(t) { return t ? '<p class="text-sm text-neutral-300 leading-relaxed whitespace-pre-line">' + esc(t) + '</p>' : ''; }
  function raw(o) { return '<details class="mt-6"><summary class="text-xs text-neutral-500">Original data (as emitted by the scanner)</summary><pre class="code mono mt-2">' + esc(JSON.stringify(o, null, 2)) + '</pre></details>'; }
  function openModal(html) { $('modal-body').innerHTML = html; var o = $('modal-overlay'); o.style.display = 'flex'; o.scrollTop = 0; }
  function closeModal() { $('modal-overlay').style.display = 'none'; }
  $('modal-close').onclick = closeModal;
  $('modal-overlay').addEventListener('click', function (e) { if (e.target === $('modal-overlay')) closeModal(); });
  document.addEventListener('keydown', function (e) { if (e.key === 'Escape') closeModal(); });
  function table(heads, rows, onclickAttr) {
    return '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-sm"><thead class="text-xs uppercase text-neutral-500 border-b border-neutral-800"><tr>' + heads.map(function (h) { return '<th class="text-left px-4 py-3 font-medium">' + esc(h) + '</th>'; }).join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">' + rows.join('') + '</tbody></table></div>';
  }

  // ── compliance block shared by every finding type ─────────────────────────
  function complianceBlock(c) {
    if (!c || !Array.isArray(c.frameworks) || !c.frameworks.length) return '';
    return section('Compliance mapping', '<div class="space-y-1 text-xs">' + c.frameworks.map(function (fw) {
      return '<div><span class="text-neutral-400">' + esc(fw.name) + ' ' + esc(fw.version || '') + ':</span> ' + (fw.controls || []).map(function (k) { return '<span class="mono text-neutral-300">' + esc(k.id) + '</span>'; }).join(', ') + '</div>';
    }).join('') + '</div>');
  }

  // ── FINDING MODALS, one layout per finding type ──────────────────────────
  var FIND = {
    sc_vulnerability: function (f, d) {
      return kv([['Advisory', f.rule_id], ['Aliases', d.aliases], ['CVSS score', d.severity_score], ['CVSS vector', d.severity_vector], ['Published', d.published], ['Modified', d.modified], ['Source', d.source], ['CWEs', d.cwes], ['Release confidence', d.release_confidence && (d.release_confidence.level || d.release_confidence)]])
        + section('Summary', para(d.summary || d.details || d.description))
        + section('Fix', kv([['Fixed versions', d.fixed_versions], ['Suggested fixes', (d.fixes || []).map(function (x) { return typeof x === 'string' ? x : JSON.stringify(x); })]]))
        + section('References', (d.references || []).length ? '<ul class="text-xs space-y-1">' + d.references.slice(0, 15).map(function (r) { return '<li>' + link(typeof r === 'string' ? r : (r.url || '')) + '</li>'; }).join('') + '</ul>' : (d.url ? link(d.url) : ''));
    },
    sc_infection: function (f, d) {
      return '<div class="mb-4 p-3 rounded-lg border border-purple-500/40 text-sm" style="color:#c084fc">This package is flagged as malicious / compromised (supply-chain infection), not as an ordinary vulnerability.</div>' + FIND.sc_vulnerability(f, d);
    },
    code: function (f, d) {
      var loc = (d.file || d.artifact || '') + (d.line != null ? ':' + d.line : '') + (d.startLine != null && d.line == null ? ':' + d.startLine : '');
      var t = d.taint || null;
      return kv([['Rule', f.rule_id], ['Class', d.vuln_class], ['Location', loc], ['Chunk', d.chunk_id], ['Language', d.language], ['CWE', d.cwe], ['MASVS', d.masvs], ['Origin', d.origin], ['Detection', d.detection], ['Verified valid', d.is_valid], ['Scan mode', d.scan_mode]])
        + section('Description', para(d.description))
        + section('Code', code(d.code_snippet))
        + section('Evidence', Array.isArray(d.evidence) && d.evidence.length ? '<ul class="text-xs mono space-y-1">' + d.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '')
        + (t ? section('Taint trace', kv([['Reachable', t.reachable], ['Sanitized', t.sanitized], ['Bypassed', t.bypassed], ['Exploitable', t.exploitable], ['Flow', t.flow_path]]) + '<div class="mt-2">' + para(t.reasoning || t.rationale) + '</div>') : '')
        + section('Remediation', para(d.fix || d.remediation));
    },
    secret: function (f, d) {
      var loc = (d.file_path || d.file || d.artifact || d.target || d.url || '') + (d.line != null ? ':' + d.line : '') + (d.column_start != null ? ':' + d.column_start : '');
      return '<div class="mb-4 p-3 rounded-lg border border-red-500/40 text-sm text-red-300">A credential was exposed. Rotate it; removing it from the source does not revoke it.</div>'
        + kv([['Rule', f.rule_id], ['Type', d.secret_type || d.title], ['Category', d.category], ['Location', loc], ['Preview (redacted)', d.match_preview], ['Fingerprint', d.fingerprint || f.finding_id], ['Chunk', d.chunk_id], ['History only', d.history_only], ['MASVS', d.masvs], ['CWE', d.cwe]])
        + section('Description', para(d.description))
        + section('Code', code(d.code_snippet))
        + section('Evidence', Array.isArray(d.evidence) && d.evidence.length ? '<ul class="text-xs mono space-y-1">' + d.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '')
        + section('Remediation', para(d.remediation || d.fix));
    },
    misconfiguration: function (f, d) {
      var occ = Array.isArray(d.occurrences) ? d.occurrences : [];
      return kv([['Rule', f.rule_id], ['Resource', d.resource || d.target || f.affected_component_id], ['Provider', d.provider], ['Service', d.service], ['Region', d.region], ['Scope / namespace', d.scope], ['Area', d.area], ['Category', d.category], ['MASVS', d.masvs], ['CWE', d.cwe], ['Action', d.action], ['Artifact', d.artifact]])
        + section('Description', para(d.description))
        + section('Evidence', Array.isArray(d.evidence) && d.evidence.length ? '<ul class="text-xs mono space-y-1">' + d.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '')
        + section('Occurrences', occ.length ? table(['Target', 'Severity', 'Detail'], occ.map(function (o) { return '<tr><td class="px-4 py-2 mono text-xs">' + esc(o.target || o.url) + '</td><td class="px-4 py-2">' + sevBadge(o.severity) + '</td><td class="px-4 py-2 text-xs text-neutral-300">' + esc(o.description) + '</td></tr>'; })) : '')
        + section('Remediation', para(d.remediation || (occ[0] && occ[0].remediation)));
    },
    hardening: function (f, d) {
      return kv([['Check', f.rule_id], ['Area', d.area], ['Resource', d.resource || f.affected_component_id], ['Scope', d.scope], ['MASVS', d.masvs], ['CWE', d.cwe], ['Artifact', d.artifact]])
        + section('Description', para(d.description))
        + section('Evidence', Array.isArray(d.evidence) && d.evidence.length ? '<ul class="text-xs mono space-y-1">' + d.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '')
        + section('Remediation', para(d.remediation));
    },
    behaviour: function (f, d) {
      return kv([['Rule', f.rule_id], ['Application', f.affected_component_name], ['Artifact', d.artifact], ['Origin', d.origin], ['MASVS', d.masvs], ['CWE', d.cwe]])
        + section('Description', para(d.description))
        + section('Evidence', Array.isArray(d.evidence) && d.evidence.length ? '<ul class="text-xs mono space-y-1">' + d.evidence.map(function (e) { return '<li>' + esc(e) + '</li>'; }).join('') + '</ul>' : '')
        + section('Remediation', para(d.remediation));
    }
  };

  var INV_BY_ID = {}; INV.forEach(function (c) { if (!(c.component_id in INV_BY_ID)) INV_BY_ID[c.component_id] = c; });
  function nodeName(id) {
    var c = INV_BY_ID[id], d = c && c.details;
    if (d && d.name) return d.name + (d.version ? '@' + d.version : '');
    return String(id == null ? '' : id).split('/').pop() || String(id);
  }
  // "Affected dependency sequences": every path root → … → affected package, in a scrollable rectangle at the bottom of the modal
  function seqBox(seqs) {
    seqs = Array.isArray(seqs) ? seqs : [];
    var body = seqs.length ? seqs.map(function (sq, n) {
      var nodes = Array.isArray(sq) ? sq : [sq];
      return '<div class="border border-neutral-700 rounded-lg p-3 bg-neutral-900/40"><div class="text-[11px] text-neutral-500 mono mb-2">Sequence #' + (n + 1) + ' · ' + nodes.length + ' package' + (nodes.length === 1 ? '' : 's') + '</div><div class="flex flex-wrap items-center gap-1.5">'
        + nodes.map(function (id, k) { var last = k === nodes.length - 1; return '<span title="' + esc(id) + '" class="px-2 py-1 rounded border text-xs mono ' + (last ? 'border-red-500/60 text-red-300' : 'border-neutral-700 text-neutral-300') + '">' + esc(nodeName(id)) + '</span>' + (last ? '' : '<span class="text-neutral-600">→</span>'); }).join('') + '</div></div>';
    }).join('') : '<div class="text-sm text-neutral-500 italic text-center py-6">No dependency sequences available for this package.</div>';
    return '<div class="mt-6"><h4 class="text-xs uppercase tracking-wider text-neutral-500 mb-2">Affected dependency sequences (' + seqs.length + ')</h4><div class="border border-neutral-700 rounded-xl bg-black/30 p-3 space-y-3 overflow-y-auto" style="max-height:16rem">' + body + '</div></div>';
  }

  function findingModal(i) {
    var f = F[i], d = f.details || {};
    var body = (FIND[f.type] || function (ff, dd) { return kv(Object.keys(dd).filter(function (k) { return typeof dd[k] !== 'object'; }).map(function (k) { return [pretty(k), dd[k]]; })); })(f, d);
    openModal('<div class="flex flex-wrap items-center gap-2 mb-2">' + sevBadge(f.severity) + chip(f.type) + (f.violate_policy ? '<span class="text-red-400 text-xs font-semibold">POLICY VIOLATION</span>' : '') + '</div>'
      + '<h3 class="text-xl font-semibold mb-1">' + esc(f.title) + '</h3>'
      + '<p class="text-xs text-neutral-500 mono mb-5">' + esc(f.rule_id) + (f.finding_id ? ' · ' + esc(f.finding_id) : '') + '</p>'
      + kv([['Component', f.affected_component_name], ['Component id', f.affected_component_id], ['Component type', f.affected_component_type], ['Confidence', f.confidence]])
      + '<div class="mt-5">' + body + '</div>' + complianceBlock(d.compliance) + raw(d)
      + ((f.type === 'sc_vulnerability' || f.type === 'sc_infection' || 'affected_dependency_sequences' in d) ? seqBox(d.affected_dependency_sequences) : ''));
  }

  // ── INVENTORY MODALS, one layout per component type ──────────────────────
  function relatedFindings(id) {
    var rel = []; F.forEach(function (f, i) { if (f.affected_component_id === id) rel.push(i); });
    if (!rel.length) return '';
    return section('Findings on this component (' + rel.length + ')', '<div class="space-y-1">' + rel.slice(0, 50).map(function (i) { return '<button class="w-full text-left text-sm flex items-center gap-2 hover:bg-white/5 rounded px-2 py-1" data-f="' + i + '">' + sevBadge(F[i].severity) + '<span class="truncate">' + esc(F[i].title) + '</span><span class="ml-auto text-xs text-neutral-500 mono">' + esc(F[i].rule_id) + '</span></button>'; }).join('') + '</div>');
  }
  var INVM = {
    dependency: function (c, d) {
      return kv([['Name', d.name], ['Ecosystem', d.ecosystem], ['Version', d.version], ['Package id', c.component_id], ['Platform', d.platform], ['Source', d.source_type || d.source], ['Lookup', d.lookup_status], ['Lookup note', d.lookup_reason], ['Confidence', d.confidence], ['Scopes', d.scopes], ['Direct', d.direct], ['Dev dependency', d.is_dev], ['Licenses', d.licenses || d.license]])
        + section('Dependency path', (d.dependency_sequences || []).length ? '<div class="space-y-1 text-xs mono">' + d.dependency_sequences.slice(0, 20).map(function (s) { return '<div>' + esc(Array.isArray(s) ? s.join(' → ') : s) + '</div>'; }).join('') + '</div>' : '');
    },
    code: function (c, d) {
      return kv([['File', d.file], ['Chunk', c.component_id], ['Kind', d.type], ['Class', d.class], ['Name', d.name], ['Language', d.language], ['Lines', d.startLine != null ? d.startLine + '–' + d.endLine : null], ['Findings', d.findings_count], ['Error', d.error && (d.error.message || d.error)]]);
    },
    application: function (c, d) {
      var nh = d.native_hardening || {};
      return kv([['Name', d.name], ['Id', d.id || d.package || d.bundle_id], ['Platform', d.platform], ['Format', d.format], ['Kind', d.kind], ['Architecture', d.arch], ['Version', d.version || d.version_name], ['Client', d.client], ['Scope', d.scope], ['File', d.file], ['Transport', d.transport], ['Target', d.target], ['Size (bytes)', d.size_bytes], ['Stripped', d.stripped], ['Static', d.static], ['Needed libraries', d.needed], ['Service state', d.state], ['Service type', d.type], ['User', d.user], ['Runs as root', d.root], ['Processes', d.count], ['PIDs', d.pids], ['Executable', d.exe], ['Deleted executable', d.deleted_exe], ['Started', d.started], ['Listening on', d.listening], ['Capabilities', d.capabilities], ['no_new_privs', d.no_new_privs], ['Seccomp', d.seccomp], ['Node.js process', d.node], ['Inspected', d.inspected]])
        + (nh.failing ? section('Native hardening — failing flags', kv(Object.keys(nh.failing).map(function (k) { return [k, nh.failing[k]]; }).filter(function (r) { return r[1]; }))) : '')
        + (d.launch ? section('Launch', '<pre class="code mono">' + esc(JSON.stringify(d.launch, null, 2)) + '</pre>') : '');
    },
    ip: function (c, d) { return kv([['Address', c.component_name], ['Status', d.status || c.status], ['Hostnames', d.subdomains], ['Open ports', d.scan && d.scan.open_ports], ['Port range', d.scan && d.scan.port_range], ['Components', (d.components || []).map(function (x) { return x.name || x; })], ['Dead name', d.deadName], ['Dead reason', d.deadReason]]); },
    domain: function (c, d) { return kv([['Name', c.component_name], ['Status', d.status || c.status], ['Resolves to', d.ips], ['Targets', d.targets], ['Components', (d.components || []).map(function (x) { return x.name || x; })], ['Dead name', d.deadName], ['Dead reason', d.deadReason]]); },
    cloud_region: function (c, d) { return kv([['Provider', d.provider], ['Region', d.region], ['Status', c.status]]); },
    cloud_resource: function (c, d) { return kv([['Resource', c.component_id], ['Provider', d.provider], ['Service', d.service], ['Region', d.region], ['Account', d.account]]); },
    host: function (c, d) { return kv([['Hostname', d.hostname], ['OS', d.os], ['Kernel', d.kernel], ['Virtualization', d.virtualization], ['Container', d.container], ['Mode', d.mode], ['Root', d.root]]); },
    kubernetes_resource: function (c, d) { return kv([['Resource', d.resource], ['Kind', d.kind], ['Namespace', d.scope], ['Area', d.area]]); },
    filesystem: function (c, d) { return kv([['Path', c.component_id], ['Area', d.area], ['Scope', d.scope]]); },
    network_service: function (c, d) { return kv([['Address', d.address], ['Port', d.port], ['Program', d.program], ['Where', d.scope]]); },
    container: function (c, d) { return kv([['Name', d.name], ['Id', d.id], ['Image', d.image], ['User', d.user], ['Privileged', d.privileged], ['Network mode', d.network_mode], ['PID mode', d.pid_mode], ['Dangerous capabilities', d.dangerous_caps], ['Sensitive mounts', d.sensitive_mounts], ['Published ports', d.published_ports], ['Memory limit', d.memory_limit], ['PIDs limit', d.pids_limit]]); },
    host_object: function (c, d) { return kv([['Object', c.component_id], ['Area', d.area], ['Scope', d.scope]]); }
  };
  function inventoryModal(i) {
    var c = INV[i], d = c.details || {};
    var body = (INVM[c.type] || function (cc, dd) { return kv(Object.keys(dd).filter(function (k) { return typeof dd[k] !== 'object'; }).map(function (k) { return [pretty(k), dd[k]]; })); })(c, d);
    openModal('<div class="flex flex-wrap items-center gap-2 mb-2">' + chip(c.type) + '<span class="text-xs text-neutral-400">status: ' + esc(c.status) + '</span>' + (c.violate_policy ? '<span class="text-red-400 text-xs font-semibold">POLICY VIOLATION</span>' : '') + '</div>'
      + '<h3 class="text-xl font-semibold mb-1">' + esc(c.component_name) + '</h3><p class="text-xs text-neutral-500 mono mb-5">' + esc(c.component_id) + '</p>'
      + body + relatedFindings(c.component_id) + raw(d));
    Array.prototype.forEach.call($('modal-body').querySelectorAll('[data-f]'), function (b) { b.onclick = function () { findingModal(+b.getAttribute('data-f')); }; });
  }
  function scopeModal(i) {
    var s = SC[i];
    openModal('<div class="mb-2">' + chip(s.type) + '</div><h3 class="text-xl font-semibold mb-5">' + esc(s.name || s.type) + '</h3>' + kv(Object.keys(s).filter(function (k) { return k !== 'type' && k !== 'name'; }).map(function (k) { return [pretty(k), s[k]]; })));
  }

  // ── tabs ──────────────────────────────────────────────────────────────────
  var st = D.stats || { findings: {}, inventory: {} }, fs = st.findings || {}, is = st.inventory || {};
  var COLORS = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3', unknown: '#525252' };
  var charts = [];
  function card(label, value, sub) { return '<div class="glass rounded-xl p-5"><div class="text-xs uppercase text-neutral-500">' + esc(label) + '</div><div class="text-3xl font-bold mt-1">' + esc(value) + '</div>' + (sub ? '<div class="text-xs text-neutral-500 mt-1">' + esc(sub) + '</div>' : '') + '</div>'; }

  function dashboard() {
    var bs = fs.by_severity || {};
    $('main').innerHTML = '<div class="grid grid-cols-2 md:grid-cols-4 gap-4">'
      + card('Findings', fs.total || 0, (fs.violating_policy || 0) + ' violate policy') + card('Critical / High', (bs.critical || 0) + ' / ' + (bs.high || 0)) + card('Inventory', is.total || 0, Object.keys(is.by_type || {}).join(', ')) + card('Scopes', SC.length) + '</div>'
      + '<div class="grid md:grid-cols-2 gap-4 mt-6"><div class="glass rounded-xl p-5"><h3 class="text-xs uppercase text-neutral-500 mb-3">Findings by severity</h3><div style="height:240px"><canvas id="c-sev"></canvas></div></div>'
      + '<div class="glass rounded-xl p-5"><h3 class="text-xs uppercase text-neutral-500 mb-3">Findings by type</h3><div style="height:240px"><canvas id="c-type"></canvas></div></div></div>';
    if (window.Chart) {
      new Chart($('c-sev'), { type: 'doughnut', data: { labels: SEV, datasets: [{ data: SEV.map(function (s) { return bs[s] || 0; }), backgroundColor: SEV.map(function (s) { return COLORS[s]; }), borderWidth: 0 }] }, options: { maintainAspectRatio: false, plugins: { legend: { position: 'right', labels: { color: '#a3a3a3' } } } } });
      var bt = fs.by_type || {};
      new Chart($('c-type'), { type: 'bar', data: { labels: Object.keys(bt), datasets: [{ data: Object.values(bt), backgroundColor: '#ef4444' }] }, options: { maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { ticks: { color: '#a3a3a3' } }, y: { ticks: { color: '#a3a3a3' }, beginAtZero: true } } } });
    }
  }

  function uniqSorted(a) { return Array.from(new Set(a.filter(function (x) { return x !== null && x !== undefined && x !== ''; }))).sort(); }
  var pol = function (v) { return v === true ? 'violates' : (v === false ? 'ok' : 'n/a'); };

  // One filterable + sortable list: free-text search, one <select> per facet (options taken from the data),
  // click a column header to sort, "Show more" paging, reset. `rowClick(index)` opens the matching modal.
  function listView(o) {
    var st = { q: '', sort: o.defaultSort || null, dir: 1, limit: 300, f: {} };
    var items = o.items;
    var facetOpts = o.facets.map(function (f) { return uniqSorted(items.map(f.get)); });
    var ids = 'lv-' + o.id;
    function sel(f, k) {
      return '<select data-facet="' + k + '" class="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm"><option value="">' + esc(f.label) + ': all</option>' + facetOpts[k].map(function (v) { return '<option value="' + esc(v) + '">' + esc(v) + '</option>'; }).join('') + '</select>';
    }
    $('main').innerHTML = '<div class="flex flex-wrap gap-3 mb-3 items-center no-print"><input id="' + ids + '-q" placeholder="' + esc(o.placeholder || 'Search…') + '" class="bg-neutral-900 border border-neutral-800 rounded px-3 py-2 text-sm w-64">'
      + o.facets.map(sel).join('') + '<button id="' + ids + '-reset" class="text-xs text-neutral-400 hover:text-white underline">reset</button><span id="' + ids + '-count" class="text-xs text-neutral-600 ml-auto"></span></div><div id="' + ids + '-out"></div>';
    function matches(it) {
      for (var k = 0; k < o.facets.length; k++) { var want = st.f[k]; if (want && String(o.facets[k].get(it)) !== want) return false; }
      if (st.q && o.text(it).toLowerCase().indexOf(st.q) < 0) return false;
      return true;
    }
    function draw() {
      var rows = [];
      items.forEach(function (it, i) { if (matches(it)) rows.push([i, it]); });
      var col = o.cols.filter(function (c) { return c.key === st.sort; })[0];
      if (col) rows.sort(function (a, b) { var x = col.sort(a[1]), y = col.sort(b[1]); return (x < y ? -1 : x > y ? 1 : 0) * st.dir; });
      var shown = rows.slice(0, st.limit);
      $(ids + '-count').textContent = rows.length + ' of ' + items.length;
      $(ids + '-out').innerHTML = rows.length
        ? '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-sm"><thead class="text-xs uppercase text-neutral-500 border-b border-neutral-800"><tr>' + o.cols.map(function (c) { return '<th data-sort="' + c.key + '" class="text-left px-4 py-3 font-medium cursor-pointer select-none hover:text-white">' + esc(c.h) + (st.sort === c.key ? (st.dir === 1 ? ' ▲' : ' ▼') : '') + '</th>'; }).join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">'
          + shown.map(function (r) { return '<tr class="row" data-i="' + r[0] + '">' + o.cols.map(function (c) { return '<td class="px-4 py-3' + (c.cls ? ' ' + c.cls : '') + '">' + c.render(r[1]) + '</td>'; }).join('') + '</tr>'; }).join('') + '</tbody></table></div>'
          + (rows.length > shown.length ? '<button id="' + ids + '-more" class="mt-3 text-sm text-red-400 underline">Show ' + Math.min(300, rows.length - shown.length) + ' more (' + (rows.length - shown.length) + ' hidden)</button>' : '')
        : '<p class="text-neutral-500 text-sm">Nothing matches the current filters.</p>';
      Array.prototype.forEach.call($(ids + '-out').querySelectorAll('tr.row'), function (tr) { tr.onclick = function () { o.rowClick(+tr.getAttribute('data-i')); }; });
      Array.prototype.forEach.call($(ids + '-out').querySelectorAll('th[data-sort]'), function (th) { th.onclick = function () { var k = th.getAttribute('data-sort'); if (st.sort === k) st.dir = -st.dir; else { st.sort = k; st.dir = 1; } draw(); }; });
      var more = $(ids + '-more'); if (more) more.onclick = function () { st.limit += 300; draw(); };
    }
    $(ids + '-q').oninput = function (e) { st.q = e.target.value.toLowerCase(); st.limit = 300; draw(); };
    Array.prototype.forEach.call($('main').querySelectorAll('select[data-facet]'), function (el) { el.onchange = function () { st.f[+el.getAttribute('data-facet')] = el.value; st.limit = 300; draw(); }; });
    $(ids + '-reset').onclick = function () { st.q = ''; st.f = {}; st.limit = 300; $(ids + '-q').value = ''; Array.prototype.forEach.call($('main').querySelectorAll('select[data-facet]'), function (el) { el.value = ''; }); draw(); };
    draw();
  }

  function findingsTab() {
    listView({
      id: 'findings', items: F, placeholder: 'Search title, rule, component…', defaultSort: 'sev',
      text: function (f) { return [f.title, f.rule_id, f.finding_id, f.affected_component_name, f.affected_component_id, f.type].join(' '); },
      facets: [
        { label: 'Severity', get: function (f) { return f.severity; } },
        { label: 'Type', get: function (f) { return f.type; } },
        { label: 'Confidence', get: function (f) { return f.confidence || ''; } },
        { label: 'Component type', get: function (f) { return f.affected_component_type || ''; } },
        { label: 'Policy', get: function (f) { return pol(f.violate_policy); } }
      ],
      cols: [
        { key: 'sev', h: 'Severity', sort: function (f) { return SEV.indexOf(f.severity); }, render: function (f) { return sevBadge(f.severity); } },
        { key: 'title', h: 'Title', sort: function (f) { return String(f.title).toLowerCase(); }, render: function (f) { return esc(f.title); } },
        { key: 'rule', h: 'Rule', sort: function (f) { return String(f.rule_id); }, cls: 'mono text-xs', render: function (f) { return esc(f.rule_id); } },
        { key: 'type', h: 'Type', sort: function (f) { return f.type; }, render: function (f) { return chip(f.type); } },
        { key: 'comp', h: 'Component', sort: function (f) { return String(f.affected_component_name); }, cls: 'mono text-xs', render: function (f) { return esc(f.affected_component_name); } },
        { key: 'conf', h: 'Conf.', sort: function (f) { return String(f.confidence || ''); }, cls: 'text-xs', render: function (f) { return esc(f.confidence || ''); } },
        { key: 'pol', h: 'Policy', sort: function (f) { return pol(f.violate_policy); }, render: function (f) { return policyBadge(f.violate_policy); } }
      ],
      rowClick: findingModal
    });
  }

  function inventoryTab() {
    var withFindings = {}; F.forEach(function (f) { withFindings[f.affected_component_id] = (withFindings[f.affected_component_id] || 0) + 1; });
    listView({
      id: 'inventory', items: INV, placeholder: 'Search name, id…',
      text: function (c) { return [c.component_name, c.component_id, c.type, c.status].join(' '); },
      facets: [
        { label: 'Type', get: function (c) { return c.type; } },
        { label: 'Status', get: function (c) { return c.status; } },
        { label: 'Ecosystem', get: function (c) { return (c.details && c.details.ecosystem) || ''; } },
        { label: 'Policy', get: function (c) { return pol(c.violate_policy); } },
        { label: 'Findings', get: function (c) { return withFindings[c.component_id] ? 'with findings' : 'none'; } }
      ],
      cols: [
        { key: 'name', h: 'Component', sort: function (c) { return String(c.component_name).toLowerCase(); }, render: function (c) { return esc(c.component_name); } },
        { key: 'type', h: 'Type', sort: function (c) { return c.type; }, render: function (c) { return chip(c.type); } },
        { key: 'status', h: 'Status', sort: function (c) { return c.status; }, cls: 'text-xs', render: function (c) { return esc(c.status); } },
        { key: 'n', h: 'Findings', sort: function (c) { return withFindings[c.component_id] || 0; }, cls: 'text-xs', render: function (c) { return withFindings[c.component_id] || 0; } },
        { key: 'pol', h: 'Policy', sort: function (c) { return pol(c.violate_policy); }, render: function (c) { return policyBadge(c.violate_policy); } },
        { key: 'id', h: 'Id', sort: function (c) { return String(c.component_id); }, cls: 'text-xs mono text-neutral-500', render: function (c) { return esc(c.component_id); } }
      ],
      rowClick: inventoryModal
    });
  }

  function scopesTab() {
    if (!SC.length) { $('main').innerHTML = '<p class="text-neutral-500 text-sm">No scopes recorded.</p>'; return; }
    var by = {}; SC.forEach(function (s, i) { (by[s.type] = by[s.type] || []).push([i, s]); });
    $('main').innerHTML = Object.keys(by).map(function (t) {
      return '<h3 class="text-xs uppercase text-neutral-500 mt-6 mb-2">' + esc(pretty(t)) + ' (' + by[t].length + ')</h3>' + table(['Name', 'Status', 'Details'], by[t].slice(0, 500).map(function (r) {
        var s = r[1]; return '<tr class="row" data-i="' + r[0] + '"><td class="px-4 py-3 mono text-xs">' + esc(s.name) + '</td><td class="px-4 py-3 text-xs">' + esc(s.status || '') + '</td><td class="px-4 py-3 text-xs text-neutral-500">' + esc(Object.keys(s).filter(function (k) { return k !== 'type' && k !== 'name' && k !== 'status' && typeof s[k] !== 'object' && s[k] != null; }).slice(0, 4).map(function (k) { return k + '=' + s[k]; }).join(' · ')) + '</td></tr>';
      }));
    }).join('');
    Array.prototype.forEach.call($('main').querySelectorAll('tr.row'), function (tr) { tr.onclick = function () { scopeModal(+tr.getAttribute('data-i')); }; });
  }

  function execTab() {
    var e = D.executive_summary;
    if (!e) { $('main').innerHTML = '<p class="text-neutral-500 text-sm">No executive summary was produced for this report.</p>'; return; }
    function render(v, depth) {
      if (v == null) return '';
      if (typeof v === 'string' || typeof v === 'number' || typeof v === 'boolean') return '<p class="text-sm text-neutral-300 leading-relaxed">' + esc(v) + '</p>';
      if (Array.isArray(v)) return '<ul class="space-y-2">' + v.slice(0, 60).map(function (x) {
        if (isObj(x)) { var t = x.title || x.name || x.label || x.headline || x.area || x.action; var dtl = x.detail || x.description || x.summary || x.text || x.value; var rest = Object.keys(x).filter(function (k) { return ['title', 'name', 'label', 'headline', 'detail', 'description', 'summary', 'text', 'value', 'severity'].indexOf(k) < 0 && typeof x[k] !== 'object'; }).slice(0, 4).map(function (k) { return k + ': ' + x[k]; }).join(' · '); return '<li class="glass rounded-lg p-3 text-sm">' + (x.severity ? sevBadge(x.severity) + ' ' : '') + (t ? '<span class="font-medium">' + esc(t) + '</span>' : '') + (dtl ? '<div class="text-neutral-400 mt-1">' + esc(dtl) + '</div>' : '') + (rest ? '<div class="text-xs text-neutral-600 mt-1 mono">' + esc(rest) + '</div>' : '') + '</li>'; }
        return '<li class="text-sm text-neutral-300">' + esc(x) + '</li>';
      }).join('') + '</ul>';
      return depth > 1 ? '<pre class="code mono">' + esc(JSON.stringify(v, null, 2)) + '</pre>' : kv(Object.keys(v).map(function (k) { return [pretty(k), typeof v[k] === 'object' && v[k] !== null ? JSON.stringify(v[k]) : v[k]]; }));
    }
    var order = ['overall_risk', 'cover', 'bottom_line', 'headline', 'verdict', 'at_a_glance', 'glance_cards', 'key_findings', 'issues_to_fix_first', 'files_to_review_first', 'resources_to_review_first', 'risk_areas', 'recommended_actions', 'compliance_overview', 'scope', 'coverage_rows', 'methodology', 'notes', 'glossary'];
    var keys = order.filter(function (k) { return k in e; }).concat(Object.keys(e).filter(function (k) { return order.indexOf(k) < 0; }));
    $('main').innerHTML = '<div class="space-y-6">' + keys.map(function (k) { return '<section class="glass rounded-xl p-5"><h3 class="text-xs uppercase tracking-wider text-neutral-500 mb-3">' + esc(pretty(k)) + '</h3>' + render(e[k], 0) + '</section>'; }).join('') + '</div>';
  }

  function complianceTab() {
    var c = D.compliance_summary;
    if (!c || !Array.isArray(c.frameworks) || !c.frameworks.length) { $('main').innerHTML = '<p class="text-neutral-500 text-sm">No compliance mapping for this report.</p>'; return; }
    $('main').innerHTML = (c.disclaimer ? '<p class="text-xs text-neutral-500 mb-4">' + esc(c.disclaimer) + '</p>' : '') + '<div class="grid md:grid-cols-2 gap-4">' + c.frameworks.map(function (fw) {
      return '<div class="glass rounded-xl p-5"><h3 class="font-semibold">' + esc(fw.name) + ' <span class="text-neutral-500 text-xs">' + esc(fw.version || '') + '</span></h3><p class="text-xs text-neutral-500 mb-3">' + esc(fw.findings_count != null ? fw.findings_count + ' findings mapped' : '') + '</p>' + '<ul class="text-xs space-y-1">' + (fw.controls || []).slice(0, 30).map(function (k) { return '<li><span class="mono text-neutral-300">' + esc(k.id) + '</span> <span class="text-neutral-500">' + esc(k.title) + '</span>' + (k.findings_count != null ? ' <span class="text-neutral-600">(' + k.findings_count + ')</span>' : '') + '</li>'; }).join('') + '</ul></div>';
    }).join('') + '</div>' + (c.posture ? section('Baseline posture (checks evaluated)', '<pre class="code mono">' + esc(JSON.stringify(c.posture, null, 2)) + '</pre>') : '');
  }

  function infoTab() {
    var m = D.metadata || {};
    function block(t, o) { return '<section class="glass rounded-xl p-5"><h3 class="text-xs uppercase tracking-wider text-neutral-500 mb-3">' + esc(t) + '</h3>' + kv(Object.keys(o || {}).map(function (k) { return [pretty(k), o[k]]; })) + '</section>'; }
    $('main').innerHTML = '<div class="grid md:grid-cols-2 gap-4">' + block('Scan', m.scan_info) + block('Tool', m.tool_info) + block('Environment', m.environment) + block('Git', m.git_metadata) + '</div>'
      + '<section class="glass rounded-xl p-5 mt-4"><h3 class="text-xs uppercase tracking-wider text-neutral-500 mb-3">Policy</h3><pre class="code mono">' + esc(JSON.stringify(D.policy, null, 2)) + '</pre></section>'
      + '<section class="glass rounded-xl p-5 mt-4"><h3 class="text-xs uppercase tracking-wider text-neutral-500 mb-3">Stats</h3><pre class="code mono">' + esc(JSON.stringify(D.stats, null, 2)) + '</pre></section>';
  }

  var TABS = [['dashboard', 'Dashboard', dashboard], ['executive', 'Executive Summary', execTab], ['findings', 'Findings (' + F.length + ')', findingsTab], ['inventory', 'Inventory (' + INV.length + ')', inventoryTab], ['scopes', 'Scopes (' + SC.length + ')', scopesTab], ['compliance', 'Compliance', complianceTab], ['info', 'Scan Info', infoTab]];
  function show(id) {
    TABS.forEach(function (t) { var el = $('tab-' + t[0]); if (el) el.className = 'py-3 whitespace-nowrap hover:text-white' + (t[0] === id ? ' tab-active' : ''); });
    TABS.filter(function (t) { return t[0] === id; })[0][2]();
    if (location.hash !== '#' + id) history.replaceState(null, '', '#' + id);
  }
  $('tabs').innerHTML = TABS.map(function (t) { return '<button id="tab-' + t[0] + '" class="py-3 whitespace-nowrap">' + esc(t[1]) + '</button>'; }).join('');
  TABS.forEach(function (t) { $('tab-' + t[0]).onclick = function () { show(t[0]); }; });

  var si = (D.metadata || {}).scan_info || {};
  $('hdr-sub').textContent = [si.report_id, si.generated_at].filter(Boolean).join(' · ');
  $('hdr-badges').innerHTML = chip('schema ' + D.schema) + chip(si.scan_type || 'scan') + (si.status && si.status !== 'completed' ? '<span class="px-2 py-0.5 text-[11px] rounded border border-orange-500 text-orange-400">' + esc(si.status) + '</span>' : '');
  var start = location.hash.replace('#', '');
  show(TABS.some(function (t) { return t[0] === start; }) ? start : 'dashboard');
})();
