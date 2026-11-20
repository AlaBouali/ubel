/* canonical/client/easm.js — easm/lib/html_report.js (ubel-url, ubel-domain, ubel-host, ubel-easm)
 * The functions between "extracted verbatim" markers are copied unchanged from the module's own report template (modals,
 * executive summary, compliance and diff renderers, with the helpers they call). Only the data shim and the glue are new:
 * the shim rebuilds the module's own report shape (every canonical entry's `details` is the original entry), the glue says
 * which module modal a canonical finding / inventory entry opens. Requires the CANON constant (the canonical report). */

// ── data: the module report shape, rebuilt from the canonical report ──

const reportData = (function (C) {
  const st = C.stats || {};
  const isVuln = function (f) { return f.type === 'dependency_vulnerability' || f.type === 'dependency_infection'; };
  return {
    inventory: C.inventory.filter(function (c) { return c.type === 'application'; }).map(function (c) { return c.details; }),
    vulnerabilities: C.findings.filter(isVuln).map(function (f) { return f.details; }),
    misconfigurations: C.findings.filter(function (f) { return f.type === 'misconfiguration'; }).map(function (f) { return f.details; }),
    secrets: C.findings.filter(function (f) { return f.type === 'secret'; }).map(function (f) { return f.details; }),
    scope: C.inventory.filter(function (c) { return c.type === 'ip' || c.type === 'domain'; }).map(function (c) { return c.details; }),
    compliance_summary: C.compliance_summary, executive_summary: C.executive_summary, diffs: st.diffs || { enabled: false },
  };
})(CANON);

// ── extracted verbatim from easm/lib/html_report.js (ubel-url, ubel-domain, ubel-host, ubel-easm) ──
function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function intelPct(x) {
  return (x === null || x === undefined || isNaN(Number(x))) ? '—' : (Number(x) * 100).toFixed(2) + '%';
}

function renderIntelCells(v) {
  const cell = (label, val) => '<div><span class="text-neutral-500">' + label + '</span><div class="mono text-neutral-200">' + val + '</div></div>';
  const kev = v.is_kev === true ? 'Yes' : (v.is_kev === false ? 'No' : 'Unknown');
  return cell('Known exploited (CISA KEV)', kev)
    + cell('KEV added', escH(v.kev_added || '—'))
    + cell('KEV deadline', escH(v.kev_deadline || '—'))
    + cell('EPSS score', intelPct(v.epss_score))
    + cell('EPSS percentile', intelPct(v.epss_percentile));
}

function sevClass(s) {
  return {critical:'severity-critical',high:'severity-high',medium:'severity-medium',low:'severity-low',unknown:'severity-unknown',infection:'severity-infection'}[s] || 'severity-unknown';
}

function stateClass(s) {
  return {infected:'state-infected',vulnerable:'state-vulnerable',safe:'state-safe',undetermined:'state-undetermined'}[s] || 'state-undetermined';
}

function vulnSeverityKey(v) {
  return v.is_infection ? 'infection' : (v.severity || 'unknown').toLowerCase();
}

function vulnKey(v) {
  if (!v) return '';
  return (v.id || '') + '@@' + (v.affected_package_id || '');
}

function hostsOf(item) {
  return [...new Set((item.assets || []).map(a => a.host + (a.port ? ':' + a.port : '')))];
}

function componentLabel(id) {
  const item = reportData.inventory.find(i => i.id === id);
  return item ? (item.name + (item.version ? '@' + item.version : '')) : id;
}

function hostsOfComponentId(id) {
  const item = reportData.inventory.find(i => i.id === id);
  return item ? hostsOf(item) : [];
}

function hasComplianceControl(item, fwName, controlId) {
  const fws = item && item.compliance && item.compliance.frameworks;
  return !!fws && fws.some(x => x.name === fwName && (x.controls || []).some(c => c.id === controlId));
}

function complianceMatchesFor(fwName, controlId) {
  const pick = (list) => (list || []).filter(x => hasComplianceControl(x, fwName, controlId));
  return {
    vulns: pick(reportData.vulnerabilities),
    misconfigs: pick(reportData.misconfigurations),
    secrets: pick(reportData.secrets),
  };
}

function complianceStatsFromMatches(matches) {
  const cves = new Set();
  const components = new Set();
  const hosts = new Set();
  const misconfigHosts = new Set();
  const inventoryById = new Map();
  for (const item of reportData.inventory || []) inventoryById.set(item.id, item);
  for (const v of matches.vulns) {
    cves.add(v.id);
    components.add(v.affected_package_id);
    const item = inventoryById.get(v.affected_package_id);
    for (const a of item?.assets || []) hosts.add(a.target);
  }
  for (const m of matches.misconfigs) {
    for (const t of m.targets || []) misconfigHosts.add(t);
  }
  return {
    cveCount: cves.size,
    componentCount: components.size,
    hostCount: hosts.size,
    matchCount: matches.vulns.length,
    misconfigCount: matches.misconfigs.length,
    misconfigHostCount: misconfigHosts.size,
    secretCount: matches.secrets.length,
  };
}

function complianceFrameworkTotals(fw) {
  const acc = { vulns: new Set(), misconfigs: new Set(), secrets: new Set() };
  for (const c of fw.controls || []) {
    const m = complianceMatchesFor(fw.name, c.id);
    m.vulns.forEach(x => acc.vulns.add(x));
    m.misconfigs.forEach(x => acc.misconfigs.add(x));
    m.secrets.forEach(x => acc.secrets.add(x));
  }
  return complianceStatsFromMatches({
    vulns: [...acc.vulns],
    misconfigs: [...acc.misconfigs],
    secrets: [...acc.secrets],
  });
}

function complianceCountsHtml(stats, primaryClass, compact) {
  const line = (cls, text) => '<span class="' + cls + '">' + text + '</span>';
  const minor = 'mono text-neutral-500 text-[10px]';
  const out = [];
  if (stats.cveCount) {
    out.push(line(primaryClass, stats.cveCount + ' CVE' + (stats.cveCount === 1 ? '' : 's')));
    out.push(line(minor, stats.componentCount + (compact ? ' comp.' : ' component' + (stats.componentCount === 1 ? '' : 's'))));
  }
  if (stats.misconfigCount) out.push(line(primaryClass, stats.misconfigCount + ' misconfig' + (stats.misconfigCount === 1 ? '' : 's')));
  if (stats.secretCount) out.push(line(primaryClass, stats.secretCount + ' secret' + (stats.secretCount === 1 ? '' : 's')));
  if (!out.length) out.push(line(primaryClass, '0'));
  return out.join('');
}

function secretKey(s) {
  return s.url + '::' + s.id + '::' + s.line + '::' + s.column_start;
}

const _scopeInv = new Map((reportData.inventory || []).map(i => [i.id, i]));

const _scopeVulns = new Map((reportData.vulnerabilities || []).map(v => [vulnKey(v), v]));

const _scopeRows = (reportData.scope || []).map(s => ({
  ...s,
  key: (s.type === 'ip' ? 'ip:' : 'sub:') + s.name,
  ips: s.ips || [],
  subdomains: s.subdomains || [],
  notes: s.notes || [],
  urls: s.urls || [],
  ports: (s.type === 'ip' ? s.open_ports : s.scanned_ports) || [],
  webPorts: new Set(s.http_ports || []),
  components: (s.components || []).map(c => _scopeInv.get(c.id)).filter(Boolean),
  vulns: (s.vulnerabilities || []).map(v => _scopeVulns.get(vulnKey(v))).filter(Boolean),
}));

const SCOPE_STATUS_CLASS = { scanned: 'text-green-400', skipped: 'text-amber-400', error: 'text-red-400', dead: 'text-red-400' };

const SCOPE_TYPE_LABEL = { ip: 'IP', subdomain: 'Subdomain' };

const SCOPE_TYPE_CLASS = { ip: 'text-blue-400', subdomain: 'text-purple-400' };

function scopeTypeBadge(type, sizeClass) {
  return `<span class="px-2 py-0.5 rounded border border-neutral-700 ${sizeClass} uppercase font-bold ${SCOPE_TYPE_CLASS[type] || 'text-neutral-400'}">${escH(SCOPE_TYPE_LABEL[type] || type)}</span>`;
}

function scopeComponentsHtml(r, emptyMsg) {
  return `
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Components (${r.components.length})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          ${r.components.length ? r.components.map(c => `
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-component-id="${escH(c.id)}">
              <div class="flex items-center gap-2 min-w-0">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${stateClass(c.state)} shrink-0">${escH(c.state)}</span>
                <span class="text-xs text-neutral-200 truncate">${escH(c.name)}${c.version ? ' @ ' + escH(c.version) : ''}</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500 shrink-0"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>`).join('') : '<p class="text-neutral-500 text-xs italic p-3">' + escH(emptyMsg.components) + '</p>'}
        </div>
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerabilities (${r.vulns.length})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          ${r.vulns.length ? r.vulns.map(v => `
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-vuln-key="${escH(vulnKey(v))}">
              <div class="flex items-center gap-2 min-w-0">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${sevClass(vulnSeverityKey(v))} shrink-0">${escH(v.is_infection ? 'infection' : v.severity)}</span>
                <span class="mono text-xs text-neutral-200 shrink-0">${escH(v.id)}</span>
                <span class="text-[10px] text-neutral-500 truncate">(${escH(componentLabel(v.affected_package_id))})</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500 shrink-0"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>`).join('') : '<p class="text-neutral-500 text-xs italic p-3">' + escH(emptyMsg.vulns) + '</p>'}
        </div>
      </div>`;
}

function openScopeModal(key) {
  const r = _scopeRows.find(x => x.key === key);
  if (!r) return;
  const notesHtml = r.notes.length
    ? `<div class="col-span-2"><span class="text-neutral-500">Note</span>${r.notes.map(n => `<div class="text-neutral-300 text-xs italic mt-1">${escH(n)}</div>`).join('')}</div>`
    : '';
  const header = `
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold ${SCOPE_STATUS_CLASS[r.status] || 'text-neutral-400'}">${escH(r.status)}</span>
        ${scopeTypeBadge(r.type, 'text-xs')}
        <h2 class="text-lg font-semibold text-white mono">${escH(r.name)}</h2>
      </div>`;

  if (r.type === 'ip') {
    // An IP: every subdomain hosted on it, and every open port found on it.
    const subRow = (name) => {
      const sr = _scopeRows.find(x => x.key === 'sub:' + name);
      const st = sr ? sr.status : null;
      return `
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-scope-key="${escH('sub:' + name)}">
              <span class="mono text-xs text-neutral-200 truncate">${escH(name)}</span>
              <span class="flex items-center gap-2 shrink-0">
                ${st ? `<span class="text-[9px] uppercase font-bold ${SCOPE_STATUS_CLASS[st] || 'text-neutral-400'}">${escH(st)}</span>` : ''}
                <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
              </span>
            </div>`;
    };
    const portChip = (p) => r.webPorts.has(p)
      ? `<span class="mono text-[11px] px-1.5 py-0.5 rounded border border-green-500/40 text-green-400">${escH(p)}</span>`
      : `<span class="mono text-[11px] px-1.5 py-0.5 rounded border border-neutral-700 text-neutral-400">${escH(p)}</span>`;
    const portsEmpty = r.status === 'skipped' ? 'Not scanned.' : 'No open ports found in the scanned range.';

    openModal(`
    <div class="space-y-4">
      ${header}
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div class="col-span-2">
          <span class="text-neutral-500">Subdomains hosted (${r.subdomains.length})</span>
          <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-40 overflow-y-auto mt-1">
            ${r.subdomains.length ? r.subdomains.map(subRow).join('') : '<p class="text-neutral-500 text-xs italic p-3">No discovered subdomain resolves to this IP.</p>'}
          </div>
        </div>
        <div class="col-span-2">
          <span class="text-neutral-500">Open ports (${r.ports.length})${r.port_range ? ' — range scanned ' + escH(r.port_range) : ''}</span>
          <div class="bg-neutral-900 rounded-lg p-2 mt-1 border border-neutral-800 max-h-28 overflow-y-auto flex flex-wrap gap-1.5">
            ${r.ports.length ? r.ports.map(portChip).join('') : '<span class="text-neutral-500 italic">' + portsEmpty + '</span>'}
          </div>
          ${r.webPorts.size ? '<p class="text-[10px] text-neutral-500 mt-1"><span class="text-green-400">Green</span> = answered HTTP(S) and was fingerprinted.</p>' : ''}
        </div>
        ${notesHtml}
      </div>
      ${scopeComponentsHtml(r, { components: 'No components fingerprinted on this IP.', vulns: 'No known vulnerabilities on this IP.' })}
    </div>
  `);
    return;
  }

  // A subdomain: same view as before, aggregated over every target it was scanned as.
  const ipLink = (ip) => _scopeRows.some(x => x.key === 'ip:' + ip)
    ? `<span class="cursor-pointer underline decoration-dotted hover:text-white" data-scope-key="${escH('ip:' + ip)}">${escH(ip)}</span>`
    : escH(ip);

  openModal(`
    <div class="space-y-4">
      ${header}
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">IP</span><div class="mono text-neutral-200">${r.ips.length ? r.ips.map(ipLink).join(', ') : '—'}</div></div>
        <div><span class="text-neutral-500">Resolved URL</span><div class="mono text-neutral-200 break-all">${r.urls.length ? r.urls.map(u => escH(u)).join('<br>') : '—'}</div></div>
        <div class="col-span-2">
          <span class="text-neutral-500">Scanned Ports (${r.ports.length})</span>
          <div class="mono text-neutral-200 bg-neutral-900 rounded-lg p-2 mt-1 border border-neutral-800 max-h-24 overflow-y-auto">
            ${r.ports.length ? escH(r.ports.join(', ')) : '<span class="text-neutral-500">—</span>'}
          </div>
        </div>
        ${notesHtml}
      </div>
      ${scopeComponentsHtml(r, { components: 'No components fingerprinted on this host.', vulns: 'No known vulnerabilities on this host.' })}
    </div>
  `);
}

function renderSuggestedFixes(item) {
  const sf = item.suggested_fixes;
  if (!sf) return '<p class="text-neutral-500 text-xs italic">No suggested-fix data available.</p>';
  const fixes = sf.fixes || [];
  const unfixed = sf.unfixed || [];
  const known = new Set((reportData.vulnerabilities || []).map(vulnKey));
  const sevBadge = function(v) {
    const sev = v.is_infection ? 'infection' : String(v.severity || 'unknown').toLowerCase();
    return '<span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ' + sevClass(sev) + '">' + escH(sev) + '</span>';
  };
  const chip = function(v) {
    const key = vulnKey({ id: v.id, affected_package_id: item.id });
    const clickable = known.has(key);
    return '<div class="flex items-center gap-2 whitespace-nowrap rounded px-1 -mx-1' +
      (clickable ? ' cursor-pointer hover:bg-neutral-800/40" data-vuln-key="' + escH(key) + '"' : '"') + '>' +
      '<span class="mono text-xs text-white">' + escH(v.id) + '</span>' + sevBadge(v) + '</div>';
  };

  let html = '';
  if (fixes.length) {
    const rangeRows = {};
    fixes.forEach(function(f) { const k = f.range ? f.range.key : ''; rangeRows[k] = (rangeRows[k] || 0) + 1; });
    const rangeSeen = {};
    html += '<div class="rounded-lg border border-neutral-800 overflow-auto max-h-72">' +
      '<table class="w-full min-w-full text-xs text-left border-collapse">' +
      '<thead class="bg-neutral-800 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr>' +
      '<th class="px-3 py-2 whitespace-nowrap w-px">Range</th>' +
      '<th class="px-3 py-2 whitespace-nowrap w-px">Suggested version</th>' +
      '<th class="px-3 py-2">Vulnerabilities fixed</th>' +
      '</tr></thead><tbody>' +
      fixes.map(function(f) {
        const k = f.range ? f.range.key : '';
        let rangeCell = '';
        if (!rangeSeen[k]) {
          rangeSeen[k] = true;
          rangeCell = '<td rowspan="' + rangeRows[k] + '" class="px-3 py-2 align-top whitespace-nowrap border-t border-neutral-800 bg-neutral-900/60">' +
            '<div class="mono text-xs text-neutral-200">' + escH(f.range ? f.range.label : '—') + '</div>' +
            '<div class="text-[10px] uppercase tracking-widest text-neutral-500 mt-0.5">' + (f.range && f.range.scope === 'major' ? 'major range' : 'minor range') + '</div></td>';
        }
        return '<tr>' + rangeCell +
          '<td class="px-3 py-2 align-top whitespace-nowrap border-t border-l border-neutral-800">' +
          '<span class="mono text-sm font-bold text-green-400">' + escH(f.version) + '</span>' +
          '<span class="ml-2 text-[10px] text-neutral-500">fixes ' + escH(f.count) + '</span></td>' +
          '<td class="px-3 py-2 align-top border-t border-l border-neutral-800"><div class="flex flex-wrap gap-x-4 gap-y-1.5">' +
          (f.vulnerabilities || []).map(chip).join('') +
          '</div></td></tr>';
      }).join('') +
      '</tbody></table></div>';
  } else {
    html += '<p class="text-neutral-500 text-xs italic">No upgrade version fixes any vulnerability of this component.</p>';
  }

  if (unfixed.length) {
    html += '<p class="text-[10px] font-semibold uppercase tracking-widest text-neutral-500 mt-3 mb-2">No published fix (' + unfixed.length + ')</p>' +
      '<div class="rounded-lg border border-neutral-800 px-3 py-2 flex flex-wrap gap-x-4 gap-y-1.5">' +
      unfixed.map(chip).join('') + '</div>';
  }
  return html;
}

function openComponentModal(id) {
  const item = reportData.inventory.find(i => i.id === id);
  if (!item) return;
  const hosts = item.assets || [];
  const vulns = reportData.vulnerabilities.filter(v => v.affected_package_id === id);

  openModal(`
    <div class="space-y-4">
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold ${stateClass(item.state)}">${escH(item.state)}</span>
        <h2 class="text-lg font-semibold text-white">${escH(item.name)}${item.version ? ' @ ' + escH(item.version) : ''}</h2>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">Ecosystem</span><div class="mono text-neutral-200">${escH(item.ecosystem)}</div></div>
        <div><span class="text-neutral-500">Type</span><div class="mono text-neutral-200">${escH(item.type)}</div></div>
        <div><span class="text-neutral-500">Scopes</span><div class="mono text-neutral-200">${escH((item.scopes||[]).join(', '))}</div></div>
        <div><span class="text-neutral-500">Vulnerabilities</span><div class="mono text-neutral-200">${item.vulnerabilities_count || 0}</div></div>
        <div class="col-span-2"><span class="text-neutral-500">Identifiers (CPE / purl)</span><div class="mono text-neutral-200 break-all space-y-0.5">${(item.ids||[item.id]).map(id => `<div>${escH(id)}</div>`).join('')}</div></div>
      </div>
      ${item.low_confidence_version ? `<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs text-amber-200">
        <span class="font-bold uppercase">Not checked against OSV/NVD.</span> The version this
        component reported (${escH(item.version || '(none)')}) is too under-specified to look up
        reliably — a bare major version matches almost every historical CVE for a product rather
        than anything specific to what's actually running, so it was skipped rather than shown as
        a flood of low-precision findings. Confirm the exact installed version directly before
        drawing conclusions either way.
      </div>` : ''}
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Seen on (${hosts.length})</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1 max-h-32 overflow-y-auto">
          ${hosts.length ? hosts.map(h => `<div class="mono text-xs text-neutral-300">${escH(h.host)}${h.port ? ':' + escH(String(h.port)) : ''} <span class="text-neutral-600">(target: ${escH(h.target)})</span></div>`).join('') : '<p class="text-neutral-500 text-xs italic">No asset detail recorded.</p>'}
        </div>
      </div>
      ${vulns.length ? `<div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Suggested fixes</p>
        ${renderSuggestedFixes(item)}
      </div>` : ''}
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerabilities</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          ${vulns.length ? vulns.map(v => `
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-vuln-key="${escH(vulnKey(v))}">
              <div class="flex items-center gap-2">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${sevClass(vulnSeverityKey(v))}">${escH(v.is_infection ? 'infection' : v.severity)}</span>
                <span class="mono text-xs text-neutral-200">${escH(v.id)}</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No known vulnerabilities for this component/version.</p>'}
        </div>
      </div>
    </div>
  `);
}

function openVulnModal(key) {
  const v = (reportData.vulnerabilities || []).find(x => vulnKey(x) === key);
  if (!v) return;

  const refs = (v.references || []).slice(0, 12);
  const fixes = v.fixes && v.fixes.length ? v.fixes : (v.has_fix ? [] : ['No fix currently published upstream.']);

  openModal(`
    <div class="space-y-4">
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold ${sevClass(vulnSeverityKey(v))}">${escH(v.is_infection ? 'infection' : v.severity)}</span>
        <h2 class="text-lg font-semibold text-white">${escH(v.id)}</h2>
        <span class="text-[10px] uppercase text-neutral-500 mono">via ${escH(v.source || 'unknown')}</span>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">Component</span><div class="mono text-neutral-200">${escH(componentLabel(v.affected_package_id))}</div></div>
        <div><span class="text-neutral-500">CVSS</span><div class="mono text-neutral-200">${v.severity_score != null ? v.severity_score : '—'}${v.severity_vector ? ' (' + escH(v.severity_vector) + ')' : ''}</div></div>
        ${renderIntelCells(v)}
        <div class="col-span-2">
          <span class="text-neutral-500">Seen on (${hostsOfComponentId(v.affected_package_id).length})</span>
          <div class="mono text-neutral-200 bg-neutral-900 rounded-lg p-2 mt-1 border border-neutral-800 max-h-32 overflow-y-auto space-y-0.5">
            ${hostsOfComponentId(v.affected_package_id).length ? hostsOfComponentId(v.affected_package_id).map(h => `<div>${escH(h)}</div>`).join('') : '<span class="text-neutral-500">—</span>'}
          </div>
        </div>
        ${v.aliases && v.aliases.length ? `<div class="col-span-2"><span class="text-neutral-500">Aliases</span><div class="mono text-neutral-200">${escH(v.aliases.join(', '))}</div></div>` : ''}
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Description</p>
        <p class="text-sm text-neutral-300">${escH(v.description || 'No description available.')}</p>
      </div>
      ${(v.fix_versions_ranked && v.fix_versions_ranked.length > 0) ? `
      <div>
        <p class="text-xs text-green-400 uppercase font-semibold mb-2">Fix Version Recommendations</p>
        <div class="overflow-x-auto rounded-lg border border-neutral-800">
          <table class="w-full text-xs text-left">
            <thead class="bg-neutral-800/60 text-neutral-400 uppercase text-[10px] tracking-widest">
              <tr>
                <th class="px-4 py-2">Version</th>
                <th class="px-4 py-2">Compatibility</th>
                <th class="px-4 py-2">Recommended</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-neutral-800">
              ${v.fix_versions_ranked.map(r => `
              <tr class="${r.recommended ? 'bg-green-500/5' : ''}">
                <td class="px-4 py-2 mono font-medium text-white">${escH(r.version)}</td>
                <td class="px-4 py-2">
                  <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
                    r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                    r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                          'text-red-400 border-red-400'
                  }">${escH(r.compatibility_level)}</span>
                </td>
                <td class="px-4 py-2">
                  ${r.recommended
                    ? `<span class="flex items-center gap-1 text-green-400 font-semibold"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>`
                    : `<span class="text-neutral-500">—</span>`}
                </td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : (fixes.length ? `
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Remediation</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1">
          ${fixes.map(f => `<p class="text-xs text-neutral-300 mono break-all">${escH(f)}</p>`).join('')}
        </div>
      </div>` : '')}
      ${(v.last_affected_ranked && v.last_affected_ranked.length > 0) ? `
      <div>
        <p class="text-xs text-orange-400 uppercase font-semibold mb-1">Last Affected Versions</p>
        <p class="text-[11px] text-neutral-500 mb-2">No fixed version is available. These are the last known affected versions — upgrade to any version strictly above the highest entry shown.</p>
        <div class="overflow-x-auto rounded-lg border border-neutral-800">
          <table class="w-full text-xs text-left">
            <thead class="bg-neutral-800/60 text-neutral-400 uppercase text-[10px] tracking-widest">
              <tr>
                <th class="px-4 py-2">Last Affected Version</th>
                <th class="px-4 py-2">Compatibility</th>
                <th class="px-4 py-2">Closest to Installed</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-neutral-800">
              ${v.last_affected_ranked.map(r => `
              <tr class="${r.recommended ? 'bg-orange-500/5' : ''}">
                <td class="px-4 py-2 mono font-medium text-white">${escH(r.version)}</td>
                <td class="px-4 py-2">
                  <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
                    r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                    r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                          'text-red-400 border-red-400'
                  }">${escH(r.compatibility_level)}</span>
                </td>
                <td class="px-4 py-2">
                  ${r.recommended
                    ? `<span class="flex items-center gap-1 text-orange-400 font-semibold"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>`
                    : `<span class="text-neutral-500">—</span>`}
                </td>
              </tr>`).join('')}
            </tbody>
          </table>
        </div>
      </div>` : ''}
      ${refs.length ? `<div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">References</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1 max-h-32 overflow-y-auto">
          ${refs.map(r => `<a href="${escH(r.url)}" target="_blank" rel="noopener noreferrer" class="block text-[11px] mono text-blue-400 hover:underline break-all">${escH(r.url)}</a>`).join('')}
        </div>
      </div>` : ''}
      ${v.iocs ? renderIocTable(v.iocs) : ''}
      ${renderComplianceSection(v.compliance)}
    </div>
  `);
}

function renderIocTable(iocs) {
  const urls = iocs.urls || [], domains = iocs.domains || [], ips = iocs.ips || [];
  if (!urls.length && !domains.length && !ips.length) return '';
  const rows = [['URLs', urls], ['Domains', domains], ['IPs', ips]];
  return `<div>
    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Indicators of Compromise</p>
    <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-2">
      ${rows.map(([label, values]) => values.length ? `
        <div class="flex flex-col gap-1">
          <span class="text-[10px] uppercase text-neutral-500 font-bold">${label}</span>
          <div class="flex flex-wrap gap-1">${values.map(val => `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700">${escH(val)}</span>`).join('')}</div>
        </div>` : '').join('')}
    </div>
  </div>`;
}

function renderComplianceSection(compliance) {
  if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
  return `<div>
    <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Compliance Frameworks</p>
    <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-2">
      ${compliance.frameworks.map(fw => `
      <div class="flex flex-col gap-1">
        <span class="text-xs font-semibold text-red-400">${escH(fw.name)}</span>
        <div class="flex flex-wrap gap-1.5">${fw.controls.map(c => `<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="${escH(c.title)}">${escH(c.id)}</span>`).join('')}</div>
      </div>`).join('')}
    </div>
  </div>`;
}

function renderCompliance() {
  const cs = reportData.compliance_summary;
  document.getElementById('compliance-disclaimer').textContent = (cs && cs.disclaimer) || '';

  // Coverage pill — one figure per kind of finding: how many carry at least
  // one framework control. (The old "85 / 85 (100%)" CVE-only figure was
  // technically true and rhetorically hollow: every CVE in a CVE-based scan
  // maps to A06 / RA-5 / Req. 6.3, so it read 100% and told the reader
  // nothing. It's more useful now because misconfiguration rules can
  // genuinely fall outside the mapping.)
  const coverageEl = document.getElementById('compliance-coverage');
  const coverageValueEl = document.getElementById('compliance-coverage-value');
  const mapped = (item) => !!(item.compliance && item.compliance.frameworks && item.compliance.frameworks.length);
  const allVulns = reportData.vulnerabilities || [];
  const allMisconfigs = reportData.misconfigurations || [];
  const allSecrets = reportData.secrets || [];
  const distinctCves = new Set(allVulns.map(v => v.id));
  const mappedCves = new Set(allVulns.filter(v => mapped(v)).map(v => v.id));
  const parts = [];
  const addPart = (label, m, t) => { if (t > 0) parts.push(label + ' ' + m + ' of ' + t); };
  addPart('CVEs', mappedCves.size, distinctCves.size);
  addPart('Misconfigurations', allMisconfigs.filter(m => mapped(m)).length, allMisconfigs.length);
  addPart('Secrets', allSecrets.filter(x => mapped(x)).length, allSecrets.length);
  if (parts.length) {
    coverageValueEl.textContent = parts.join(' · ');
    coverageEl.classList.remove('hidden');
  } else {
    coverageEl.classList.add('hidden');
  }

  // OWASP by-category — recompute counts from the raw finding lists rather
  // than trusting the summary's raw count.
  const owaspSection = document.getElementById('compliance-owasp-section');
  const owaspGrid = document.getElementById('compliance-owasp-grid');
  if (cs && cs.by_owasp_category && cs.by_owasp_category.length) {
    owaspGrid.innerHTML = cs.by_owasp_category.map(o => {
      const stats = complianceStatsFromMatches(complianceMatchesFor('OWASP Top 10', o.id));
      return `
        <div class="glass p-4 rounded-xl flex items-start justify-between gap-3 text-xs">
          <div class="flex flex-col gap-1">
            <span class="mono text-red-400">${escH(o.id)}</span>
            <span class="text-neutral-400">${escH(o.title)}</span>
            <span class="text-neutral-600">via: ${escH((o.categories || []).join(', '))}</span>
          </div>
          <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
            ${complianceCountsHtml(stats, 'mono text-neutral-200 font-semibold', false)}
          </div>
        </div>`;
    }).join('');
    owaspSection.classList.remove('hidden');
  } else {
    owaspSection.classList.add('hidden');
  }

  // Framework cards — recompute from the raw finding lists so each badge
  // reads "N CVEs · M components" / "N misconfigs" / "N secrets" rather than
  // a single undifferentiated "N findings". The data-fw-idx / data-control-idx
  // keys still point into compliance_summary.frameworks so
  // openComplianceModal() continues to work unchanged.
  const grid = document.getElementById('compliance-frameworks-grid');
  if (!cs || !cs.frameworks || !cs.frameworks.length) {
    document.getElementById('compliance-empty').classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const fwStats = complianceFrameworkTotals(fw);
    return `
    <div class="glass p-6 rounded-xl space-y-4">
      <div class="flex items-start justify-between gap-3">
        <div class="flex flex-col">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">${escH(fw.name)}</h3>
          ${fw.version ? `<span class="text-[10px] text-neutral-500 mono">${escH(fw.version)}</span>` : ''}
        </div>
        <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
          ${complianceCountsHtml(fwStats, 'mono text-neutral-200 font-semibold text-xs', false)}
        </div>
      </div>
      <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
        ${fw.controls.map((c, cIdx) => {
          const stats = complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id));
          return `
          <div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" data-fw-idx="${fwIdx}" data-control-idx="${cIdx}">
            <div class="flex flex-col min-w-0">
              <span class="mono text-red-400">${escH(c.id)}</span>
              <span class="text-neutral-500">${escH(c.title)}</span>
            </div>
            <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
              ${complianceCountsHtml(stats, 'mono text-neutral-200', true)}
            </div>
          </div>`;
        }).join('')}
      </div>
    </div>`;
  }).join('');
}

let _currentComplianceMatches = null;

function openComplianceModal(fwIdx, cIdx) {
  const cs = reportData.compliance_summary;
  const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
  const control = fw && fw.controls && fw.controls[cIdx];
  if (!fw || !control) return;

  const matches = complianceMatchesFor(fw.name, control.id);
  // Only the vulnerability rows use data-match-index (resolved through this
  // array by the modal click handler); misconfig and secret rows carry their
  // own keys.
  _currentComplianceMatches = matches.vulns;
  const stats = complianceStatsFromMatches(matches);
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  const rowCls = 'flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors';
  const chevron = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>';

  const vulnRows = matches.vulns.map((v, idx) => `
    <div class="${rowCls}" data-match-index="${idx}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(vulnSeverityKey(v))}">${escH(v.is_infection ? 'infection' : v.severity)}</span>
        <span class="text-sm text-white">${escH(v.id)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]">${escH(componentLabel(v.affected_package_id))}</span>
        ${chevron}
      </div>
    </div>`).join('');

  const misconfigRows = matches.misconfigs.map(m => `
    <div class="${rowCls}" data-misconfig-key="${escH(m.id)}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(misconfigSeverityKey(m))}">${escH(misconfigSeverityKey(m))}</span>
        <span class="text-sm text-white">${escH(m.title || m.id)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]">${escH(plural(m.hosts_affected || 0, 'host', 'hosts'))}</span>
        ${chevron}
      </div>
    </div>`).join('');

  const secretRows = matches.secrets.map(s => `
    <div class="${rowCls}" data-secret-key="${escH(secretKey(s))}">
      <div class="flex items-center gap-3 min-w-0">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(secretSeverityKey(s))}">${escH(secretSeverityKey(s))}</span>
        <span class="text-sm text-white truncate">${escH(s.secret_type || s.title || s.id)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]" title="${escH(s.url)}">${escH(s.url)}:${escH(s.line)}</span>
        ${chevron}
      </div>
    </div>`).join('');

  const section = (title, count, rows) => rows
    ? '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">' + title + ' (' + count + ')</p>' + rows + '</div>'
    : '';
  const body =
    section('Vulnerabilities', matches.vulns.length, vulnRows) +
    section('Misconfigurations', matches.misconfigs.length, misconfigRows) +
    section('Exposed secrets', matches.secrets.length, secretRows);

  const bits = [];
  if (stats.cveCount) {
    bits.push(
      plural(stats.cveCount, 'distinct CVE', 'distinct CVEs') + ' across ' +
      plural(stats.componentCount, 'component', 'components') + ' on ' +
      plural(stats.hostCount, 'host', 'hosts') + ' (' +
      plural(stats.matchCount, 'component-CVE pair', 'component-CVE pairs') + ' total)'
    );
  }
  if (stats.misconfigCount) {
    bits.push(plural(stats.misconfigCount, 'misconfiguration type', 'misconfiguration types') + ' on ' + plural(stats.misconfigHostCount, 'host', 'hosts'));
  }
  if (stats.secretCount) {
    bits.push(plural(stats.secretCount, 'exposed secret', 'exposed secrets') + ' in client-side JavaScript');
  }

  openModal(`
    <div class="space-y-4">
      <div>
        <div class="flex items-center gap-3 mb-1 flex-wrap">
          <span class="mono text-red-400 text-sm">${escH(control.id)}</span>
          <h2 class="text-lg font-semibold text-white">${escH(control.title)}</h2>
        </div>
        <p class="text-xs text-neutral-500">
          ${escH(fw.name)}${fw.version ? ' · ' + escH(fw.version) : ''}${bits.length ? ' — ' + escH(bits.join('; ')) : ''}
        </p>
      </div>
      <div class="space-y-4">${body || '<p class="text-sm text-neutral-500 italic py-2">No findings mapped to this control.</p>'}</div>
    </div>
  `);
}

function misconfigSeverityKey(m) {
  return String(m.severity || 'unknown').toLowerCase();
}

function openMisconfigModal(key) {
  const m = (reportData.misconfigurations || []).find(x => x.id === key);
  if (!m) return;
  const sev = misconfigSeverityKey(m);
  const occurrences = m.occurrences || [];
  const remediations = [...new Set(occurrences.map(o => o.remediation).filter(Boolean))];

  openModal(`
    <div class="space-y-5">
      <div>
        <div class="flex items-center gap-3 mb-2 flex-wrap">
          <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(sev)}">${escH(sev)}${occurrences.length > 1 ? ' (worst seen)' : ''}</span>
          <span class="text-[10px] uppercase text-neutral-500 mono">${escH(m.category || 'misconfiguration')}</span>
        </div>
        <h2 class="text-xl font-semibold text-white">${escH(m.title || m.id)}</h2>
        <p class="text-xs text-neutral-500 mono mt-1">rule: ${escH(m.id)}</p>
      </div>

      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Seen on (${m.hosts_affected || 0} host${m.hosts_affected === 1 ? '' : 's'}, ${occurrences.length} occurrence${occurrences.length === 1 ? '' : 's'})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-72 overflow-y-auto">
          ${occurrences.length ? occurrences.map(o => `
            <div class="px-3 py-2">
              <div class="flex items-center gap-2 flex-wrap mb-1">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${sevClass(misconfigSeverityKey(o))}">${escH(misconfigSeverityKey(o))}</span>
                <span class="mono text-xs text-neutral-200">${escH(o.target || '—')}</span>
                ${o.url ? `<span class="mono text-[10px] text-neutral-500 truncate">${escH(o.url)}</span>` : ''}
              </div>
              ${o.description ? `<p class="text-[11px] text-neutral-400">${escH(o.description)}</p>` : ''}
              ${o.evidence && o.evidence.length ? `<div class="mt-1 space-y-0.5">${o.evidence.map(e => `<div class="mono text-[10px] text-neutral-500 break-all">${escH(e)}</div>`).join('')}</div>` : ''}
            </div>`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No occurrence detail recorded.</p>'}
        </div>
      </div>

      ${remediations.length ? `
      <div>
        <p class="text-xs text-green-400 uppercase font-semibold mb-1">Remediation</p>
        <div class="bg-green-500/5 border border-green-500/30 rounded-lg p-3 space-y-2">
          ${remediations.map(r => `<p class="text-xs text-neutral-300 leading-relaxed">${escH(r)}</p>`).join('')}
        </div>
      </div>` : ''}

      ${renderComplianceSection(m.compliance)}
    </div>
  `);
}

function secretSeverityKey(s) {
  return String(s.severity || 'unknown').toLowerCase();
}

function openSecretModal(key) {
  const s = (reportData.secrets || []).find(
    x => `${x.url}::${x.id}::${x.line}::${x.column_start}` === key
  );
  if (!s) return;
  const sev = secretSeverityKey(s);
  const refs = s.referenced_by || [];

  openModal(`
    <div class="space-y-5">
      <div>
        <div class="flex items-center gap-3 mb-2">
          <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${sev}">${escH(sev)}</span>
          <span class="text-[10px] uppercase text-neutral-500 mono">${escH(s.category || 'secret')}</span>
        </div>
        <h2 class="text-xl font-semibold text-white">${escH(s.secret_type || s.title || s.id)}</h2>
        <p class="text-xs text-neutral-500 mono mt-1">rule: ${escH(s.id)}</p>
      </div>

      <div class="bg-neutral-900 rounded-lg p-4 border border-neutral-800 space-y-3 text-xs">
        <div>
          <span class="text-neutral-500">Location</span>
          <div class="mono text-neutral-200 break-all mt-1">${escH(s.url)}</div>
          <div class="mono text-neutral-400 mt-1">line ${s.line}, column ${s.column_start}–${s.column_end}</div>
        </div>
        <div>
          <span class="text-neutral-500">Served as</span>
          <div class="text-neutral-300 mt-1">${s.source_type === 'js-file'
            ? 'a separate JavaScript file referenced by the page'
            : 'an inline &lt;script&gt; block in the page source (line number is relative to the page document)'}</div>
        </div>
        <div>
          <span class="text-neutral-500">Redacted value</span>
          <div class="mono text-neutral-200 mt-1">${escH(s.match_preview || '—')}</div>
        </div>
      </div>

      ${refs.length ? `
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Referenced by ${refs.length} page(s)</p>
        <div class="space-y-1 max-h-40 overflow-y-auto pr-1">
          ${refs.map(r => `<div class="mono text-[11px] text-neutral-400 bg-neutral-900 rounded px-2 py-1 border border-neutral-800 break-all">${escH(r)}</div>`).join('')}
        </div>
      </div>` : (s.page_url ? `
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Found on</p>
        <div class="mono text-[11px] text-neutral-400 bg-neutral-900 rounded px-2 py-1 border border-neutral-800 break-all">${escH(s.page_url)}</div>
      </div>` : '')}

      <div class="bg-amber-500/5 border border-amber-500/30 rounded-lg p-3">
        <p class="text-[11px] text-amber-200 leading-relaxed">
          This value was served to an unauthenticated request. Treat it as disclosed: rotate the credential,
          then remove it from the client bundle. Deleting it without rotating leaves the old value valid for
          anyone who already fetched the page.
        </p>
      </div>

      ${renderComplianceSection(s.compliance)}
    </div>
  `);
}

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
  const colors = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', none: '#4ade80', malicious: '#c084fc', unknown: '#a3a3a3', not_assessed: '#a3a3a3' };
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
    '<h2 class="text-2xl font-bold mb-3 break-all">' + esc(cover.subject || 'Scanned systems') + '</h2>' +
    (metaItems.length ? '<div class="flex flex-wrap gap-x-8 gap-y-1 text-xs mb-3">' +
      metaItems.map(function (m) {
        return '<div class="min-w-0"><span class="text-neutral-500">' + esc(m[0]) + ': </span><span class="mono break-all text-neutral-300">' + esc(m[1]) + '</span></div>';
      }).join('') + '</div>' : '') +
    (cover.classification ? '<p class="text-[11px] text-neutral-500 uppercase tracking-wider">' + esc(cover.classification) + '</p>' : '') +
  '</div>';

  // Verdict banner
  const verdict = es.verdict;
  html += '<div class="glass p-6 md:p-8 rounded-xl" style="border-left:6px solid ' + riskColor + '">' +
    '<div class="flex flex-wrap items-center justify-between gap-3 mb-3">' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Overall security risk</p>' +
      '<p class="text-4xl font-bold" style="color:' + riskColor + '">' + esc(bl.risk_label || risk.label || 'Unknown') + '</p></div>' +
      (verdict && verdict.label ? '<span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider border ' +
        (verdict.status === 'pass' ? 'bg-green-500/20 text-green-400 border-green-500/50' : 'bg-red-500/20 text-red-400 border-red-500/50') + '">' + esc(verdict.label) + '</span>' : '') +
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
      (verdict && verdict.statement ? '<p class="text-sm text-neutral-400"><span class="font-semibold text-neutral-300">Policy result: </span>' + esc(verdict.statement) + '</p>' : '') +
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

  // Configuration gaps by area (EASM)
  const themes = es.configuration_themes || [];
  if (themes.length) {
    html += '<div>' + sectionTitle('Configuration issues by area') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Area</th><th>Distinct issues</th><th>Systems</th><th>Most serious</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      themes.map(function (t) {
        return '<tr>' +
          '<td class="px-6 py-4"><div class="font-medium">' + esc(t.title) + '</div><div class="text-xs text-neutral-500 mt-1 max-w-xl">' + esc(t.plain) + '</div></td>' +
          '<td class="py-4 align-top">' + esc(t.issues) + '</td>' +
          '<td class="py-4 align-top">' + esc(t.systems_affected) + '</td>' +
          '<td class="py-4 align-top">' + badge(t.worst_severity, t.worst_severity_label) + '</td></tr>';
      }).join('') + '</tbody></table></div></div>';
  }

  // Possible upgrade paths for one component (from suggested_fixes), closest first.
  const fixOptionsHtml = function (c) {
    const opts = c.fix_options || [];
    if (!opts.length) return '';
    const rows = opts.map(function (o) {
      return '<li class="flex flex-wrap items-center gap-x-2 gap-y-1">' +
        '<span class="mono text-neutral-100">' + esc(o.version) + '</span>' +
        (o.recommended ? badge('none', 'Best') : '') +
        (o.scope === 'major' ? badge('medium', 'Major') : '') +
        '<span class="text-neutral-400">fixes ' + esc(o.resolves) + ' of ' + esc(o.of) +
        (o.known_exploited_total ? ' (' + esc(o.resolves_known_exploited) + ' of ' + esc(o.known_exploited_total) + ' exploited)' : '') +
        '</span></li>';
    }).join('');
    return '<div class="mt-3 pt-2 border-t border-neutral-800"><div class="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Possible fixes</div>' +
      '<ul class="space-y-1 text-[11px]">' + rows + '</ul>' +
      (c.fix_options_more ? '<div class="text-[10px] text-neutral-500 mt-1">+' + esc(c.fix_options_more) + ' more in the component details</div>' : '') +
      (c.no_fix_yet ? '<div class="text-[10px] text-neutral-500 mt-1">' + esc(c.no_fix_yet) + ' ' + (c.no_fix_yet === 1 ? 'issue has' : 'issues have') + ' no published fix yet.</div>' : '') +
      '</div>';
  };

  // Components to fix first
  const comps = es.components_to_fix_first || [];
  if (comps.length) {
    const hasSystems = comps.some(function (c) { return c.systems_affected !== undefined; });
    const hasUse = comps.some(function (c) { return c.likely_in_use !== undefined; });
    html += '<div>' + sectionTitle('Components to fix first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Component</th>' + (hasSystems ? '<th>Systems</th>' : '') + '<th>Issues</th><th>Worst severity</th>' +
      (hasUse ? '<th>Likely in use</th>' : '') + '<th>What to do</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      comps.map(function (c) {
        const refs = (c.references || []);
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.name) + (c.version ? ' <span class="mono text-xs text-neutral-500">' + esc(c.version) + '</span>' : '') +
            (refs.length ? '<div class="mono text-[10px] text-neutral-500 font-normal mt-1 break-all max-w-[16rem]">' + refs.map(esc).join(', ') + (c.more_references ? ' +' + esc(c.more_references) + ' more' : '') + '</div>' : '') + '</td>' +
          (hasSystems ? '<td class="py-4 align-top"><div>' + esc(c.systems_affected) + '</div>' +
            ((c.example_systems || []).length ? '<div class="mono text-[10px] text-neutral-500 break-all max-w-[12rem]">' + c.example_systems.map(esc).join(', ') + (c.systems_affected > c.example_systems.length ? ', ...' : '') + '</div>' : '') + '</td>' : '') +
          '<td class="py-4 align-top">' + esc(c.issue_count) + '</td>' +
          '<td class="py-4 align-top">' + badge(c.worst_severity, c.worst_severity_label) + (c.known_exploited ? '<div class="mt-1">' + badge('critical', 'Exploited') + '</div>' : '') + '</td>' +
          (hasUse ? '<td class="py-4 align-top text-xs ' + (c.likely_in_use ? 'text-neutral-200' : 'text-neutral-500') + '">' + (c.likely_in_use ? 'Yes' : 'Probably not') + '</td>' : '') +
          '<td class="py-4 pr-6 align-top text-neutral-300 text-xs">' + esc(c.action) + fixOptionsHtml(c) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Identifiers under each component are the advisory references, for tickets and audit trails.</p></div>';
  }

  // Systems to review first (EASM)
  const systems = es.systems_to_review_first || [];
  if (systems.length) {
    html += '<div>' + sectionTitle('Systems to review first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">System</th><th>Type</th><th>Weaknesses</th><th>Configuration issues</th><th>Worst severity</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      systems.map(function (r) {
        return '<tr>' +
          '<td class="px-6 py-4 mono text-xs break-all">' + esc(r.name) + (r.malicious_components ? ' ' + badge('malicious', 'Malicious') : '') + '</td>' +
          '<td class="py-4 text-xs text-neutral-400">' + esc(r.kind) + '</td>' +
          '<td class="py-4">' + esc(r.weaknesses) + '</td>' +
          '<td class="py-4">' + esc(r.configuration_issues) + '</td>' +
          '<td class="py-4 pr-6">' + badge(r.worst_severity, r.worst_severity_label) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Counts weaknesses and configuration issues only; exposed credentials are attributed to a web address, not to a system.</p></div>';
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
    '<p class="text-sm text-neutral-300">' + esc(sc.description || '') +
      (sc.target ? ' Target: ' + esc(sc.target) + '.' : '') +
      ((sc.ecosystems || []).length ? ' Software types covered: ' + esc(sc.ecosystems.join(', ')) + '.' : '') + '</p>' +
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

var DIFF_CATS = [
  { key: 'ips',        label: 'IPs',                  cols: [['IP', 'ip'], ['Domains', 'domains'], ['Status', 'status']] },
  { key: 'domains',    label: 'Domains',              cols: [['Domain', 'domain'], ['IPs', 'ips'], ['Status', 'status']] },
  { key: 'ports',      label: 'IP ports',             cols: [['Host', 'host'], ['Port', 'port'], ['HTTP(S)', 'http']] },
  { key: 'misconfigs', label: 'Misconfigurations',    cols: [['Rule', 'id'], ['Severity', 'severity'], ['Title', 'title'], ['Category', 'category'], ['Target', 'target']] },
  { key: 'techs',      label: 'Technologies',         cols: [['Name', 'name'], ['Version', 'version'], ['Seen on', 'hosts']] },
  { key: 'secrets',    label: 'Secrets',              cols: [['Rule', 'id'], ['Severity', 'severity'], ['Title', 'title'], ['URL', 'url'], ['Line', 'line'], ['Match', 'match_preview']] },
  { key: 'findings',   label: 'Findings per technology', cols: [['Technology', 'tech'], ['Version', 'version'], ['ID', 'id'], ['Severity', 'severity'], ['Title', 'title']] }
];

var DIFF_LISTS = [
  { key: 'new',       label: 'New',      color: 'text-red-400' },
  { key: 'unchanged', label: 'Existing', color: 'text-yellow-400' },
  { key: 'removed',   label: 'Removed',  color: 'text-green-400' }
];

function diffTable(cols, items, sevKey) {
  if (!items.length) return '<p class="text-sm text-neutral-500 italic">None.</p>';
  return '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
    cols.map(function (c) { return '<th class="pb-2 pr-4 font-bold">' + escH(c[0]) + '</th>'; }).join('') +
    '</tr></thead><tbody class="divide-y divide-neutral-800">' +
    items.map(function (e) {
      return '<tr>' + cols.map(function (c) {
        var v = e[c[1]];
        if (v === true) v = 'yes'; else if (v === false) v = 'no';
        if (c[1] === sevKey) {
          var sv = String(v || 'unknown').toLowerCase();
          return '<td class="py-2 pr-4 uppercase text-[10px] font-bold ' + (typeof sevClass === 'function' ? sevClass(sv) : '') + '">' + escH(sv) + '</td>';
        }
        return '<td class="py-2 pr-4 mono text-neutral-300 break-all">' + escH(v) + '</td>';
      }).join('') + '</tr>';
    }).join('') + '</tbody></table></div>';
}

function diffCountButton(attrs, label, count, color) {
  return '<button type="button" ' + attrs + ' class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors">' +
    '<span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + escH(label) + '</span>' +
    '<span class="block text-2xl font-bold mono ' + color + '">' + count + '</span></button>';
}

function renderDiffs() {
  var sec = document.getElementById('section-diffs');
  if (!sec) return;
  var d = reportData.diffs;
  if (!d || !d.enabled) { sec.innerHTML = ''; return; }
  var html = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2>';
  if (d.previous) {
    html += '<p class="text-xs text-neutral-500 mono">vs previous report ' + escH(d.previous.report_id || d.previous.bundle) +
      (d.previous.generated_at ? ' (' + escH(d.previous.generated_at) + ')' : '') + '</p>';
  }
  html += '</div>';
  if (!d.previous || !d.counts) {
    html += '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
    sec.innerHTML = html;
    return;
  }
  if (d.min_severity && d.min_severity.changed) {
    html += '<p class="text-xs text-yellow-400">The two reports used a different --min-severity (previous: ' + escH(d.min_severity.previous) +
      ', this one: ' + escH(d.min_severity.current) + '). Vulnerability findings (Findings per technology and the Frameworks mapping) are compared at the stricter level, ' +
      escH(d.min_severity.applied) + ' and above, so a finding hidden by one filter is not shown as new or removed.</p>';
  }
  html += '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
  var skipped = [];
  DIFF_CATS.forEach(function (cat) {
    var g = d[cat.key];
    if (!g) { skipped.push(cat.label); return; }
    html += '<div class="glass rounded-xl p-5 space-y-3"><p class="font-semibold text-sm">' + escH(cat.label) + '</p><div class="grid grid-cols-3 gap-2">';
    DIFF_LISTS.forEach(function (l) {
      html += diffCountButton('data-diff-cat="' + cat.key + '" data-diff-list="' + l.key + '"', l.label, (g[l.key] || []).length, l.color);
    });
    html += '</div></div>';
  });
  html += '</div>';
  if (skipped.length) {
    html += '<p class="text-xs text-neutral-500">Not compared: ' + escH(skipped.join(', ')) + ' (this report or the previous one did not include them, e.g. secrets were not scanned).</p>';
  }
  if (d.compliance && d.compliance.frameworks && d.compliance.frameworks.length) {
    html += '<h3 class="text-lg font-bold pt-4">Frameworks mapping</h3>' +
      '<p class="text-xs text-neutral-500">Findings mapped to each framework, compared with the previous report (vulnerabilities, misconfigurations' +
      (d.compliance.includes_secrets ? ' and secrets).' : '; secrets were not scanned in both reports).') + '</p>';
    html += '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    d.compliance.frameworks.forEach(function (fw, fi) {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + escH(fw.name) + '</p>' +
        (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + escH(fw.version) + '</p>' : '') + '</div><div class="grid grid-cols-3 gap-2">';
      [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(function (x) {
        html += diffCountButton('data-diff-fw="' + fi + '" data-diff-list="' + x[0] + '"', x[1], fw[x[0]].length, x[2]);
      });
      html += '</div></div>';
    });
    html += '</div>';
  } else if (!d.compliance) {
    html += '<p class="text-xs text-neutral-500">Frameworks mapping is not compared: the previous report has no compliance mapping.</p>';
  }
  sec.innerHTML = html;
}

function openDiffModal(catKey, listKey) {
  var d = reportData.diffs;
  var cat = DIFF_CATS.filter(function (c) { return c.key === catKey; })[0];
  var l = DIFF_LISTS.filter(function (x) { return x.key === listKey; })[0];
  if (!d || !cat || !l || !d[catKey]) return;
  var items = d[catKey][listKey] || [];
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(cat.label) + ' — ' + escH(l.label) + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + diffTable(cat.cols, items, 'severity'));
}

function openComplianceDiffModal(fi, listKey) {
  var d = reportData.diffs;
  var fw = d && d.compliance && d.compliance.frameworks[fi];
  if (!fw) return;
  var labels = { new: 'New', unchanged: 'Still existing', removed: 'Resolved' };
  var items = (fw[listKey] || []).map(function (e) {
    return Object.assign({}, e, { kindLabel: e.kind === 'secret' ? 'Secret' : e.kind === 'misconfig' ? 'Misconfiguration' : 'Vulnerability' });
  });
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(fw.name) + ' — ' + labels[listKey] + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' +
    diffTable([['Type', 'kindLabel'], ['ID', 'id'], ['Severity', 'severity'], ['Title', 'title'], ['Where', 'where'], ['Controls', 'controls']], items, 'severity'));
}

function bindDiffs() {
  var sec = document.getElementById('section-diffs');
  if (!sec) return;
  sec.addEventListener('click', function (e) {
    var b = e.target.closest('button[data-diff-list]');
    if (!b) return;
    if (b.dataset.diffFw !== undefined) openComplianceDiffModal(parseInt(b.dataset.diffFw, 10), b.dataset.diffList);
    else openDiffModal(b.dataset.diffCat, b.dataset.diffList);
  });
}

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.body.style.overflow = 'auto';
}

function openModal(html) {
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

// ── glue: canonical entry → module modal ──
const FAMILY = {
  openFinding: function (i) {
    const f = CANON.findings[i], d = f.details;
    if (f.type === 'dependency_vulnerability' || f.type === 'dependency_infection') { openVulnModal(vulnKey(d)); return true; }
    if (f.type === 'misconfiguration') { openMisconfigModal(d.id); return true; }
    if (f.type === 'secret') { openSecretModal(secretKey(d)); return true; }
    return false;
  },
  openInventory: function (i) {
    const c = CANON.inventory[i], d = c.details;
    if (c.type === 'application') { openComponentModal(d.id); return true; }
    if (c.type === 'ip' || c.type === 'domain') { openScopeModal((d.type === 'ip' ? 'ip:' : 'sub:') + d.name); return true; }
    return false;
  },
  executive: function () { renderExecutiveSummary(); },
  compliance: function () { renderCompliance(); },
  diffs: function () { renderDiffs(); bindDiffs(); },
};
