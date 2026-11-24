/* canonical/client/posture.js — vm/lib/html_report.js (ubel-vm, ubel-k8s, ubel-runtime)
 * The functions between "extracted verbatim" markers are copied unchanged from the module's own report template (modals,
 * executive summary, compliance and diff renderers, with the helpers they call). Only the data shim and the glue are new:
 * the shim rebuilds the module's own report shape (every canonical entry's `details` is the original entry), the glue says
 * which module modal a canonical finding / inventory entry opens. Requires the CANON constant (the canonical report). */

// ── data: the module report shape, rebuilt from the canonical report ──

const reportData = (function (C) {
  const st = C.stats || {};
  return {
    // observations (passed checks, coverage, behaviors …) are canonical findings only: the module's own lists / compliance / diffs never saw them
    findings: C.findings.filter(function (f) { return !(f.details && f.details.observation); }).map(function (f) { return f.details; }),
    profile: (C.policy && C.policy.profile) || null,
    compliance_summary: C.compliance_summary,
    compliance_posture: st.compliance_posture || null,
    executive_summary: C.executive_summary,
    diffs: st.diffs || { enabled: false },
  };
})(CANON);

// ── extracted verbatim from vm/lib/html_report.js (ubel-vm, ubel-k8s, ubel-runtime) ──
function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function sevClass(s) {
  return {critical:'severity-critical',high:'severity-high',medium:'severity-medium',low:'severity-low',info:'severity-info'}[s] || 'severity-info';
}

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

function complianceFrameworkTotals(fw) {
  const acc = new Set();
  for (const c of fw.controls || []) {
    complianceMatchesFor(fw.name, c.id).forEach(f => acc.add(f));
  }
  return complianceStatsFromMatches([...acc]);
}

function complianceCountsHtml(stats, primaryClass, compact) {
  const line = (cls, text) => '<span class="' + cls + '">' + text + '</span>';
  const minor = 'mono text-neutral-500 text-[10px]';
  const out = [];
  out.push(line(primaryClass, stats.checkCount + ' check' + (stats.checkCount === 1 ? '' : 's')));
  out.push(line(minor, stats.resourceCount + (compact ? ' res.' : ' resource' + (stats.resourceCount === 1 ? '' : 's'))));
  return out.join('');
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
    owaspGrid.innerHTML = cs.by_owasp_category.map(o => `
      <div class="glass p-4 rounded-xl flex items-start justify-between gap-3 text-xs">
        <div class="flex flex-col gap-1">
          <span class="mono text-red-400">${escH(o.id)}</span>
          <span class="text-neutral-400">${escH(o.title)}</span>
          <span class="text-neutral-600">via: ${escH((o.categories || []).join(', '))}</span>
        </div>
        <span class="mono text-neutral-300 whitespace-nowrap">${o.findings_count}</span>
      </div>`).join('');
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
  _currentComplianceMatches = matches;
  const stats = complianceStatsFromMatches(matches);
  const plural = (n, one, many) => n + ' ' + (n === 1 ? one : many);

  const rows = matches.length ? matches.map((f, idx) => `
    <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" data-finding-index="${idx}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(f.severity)}">${escH(f.severity)}</span>
        <span class="text-xs text-neutral-500">${escH(areaLabel(f.area))}</span>
        <span class="text-sm text-white">${escH(f.title)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]" title="${escH(f.resource)}">${escH(f.resource)}${f.scope ? ' · ' + escH(f.scope) : ''}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>`).join('') : '';

  const body = matches.length
    ? '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Findings (' + matches.length + ')</p>' + rows + '</div>'
    : '<p class="text-sm text-neutral-500 italic py-2">No findings mapped to this control.</p>';

  const bits = stats.checkCount
    ? plural(stats.checkCount, 'distinct check', 'distinct checks') + ' across ' +
      plural(stats.resourceCount, 'resource', 'resources') + ' (' +
      plural(stats.matchCount, 'finding', 'findings') + ' total)'
    : '';

  openModal(`
    <div class="space-y-4">
      <div>
        <div class="flex items-center gap-3 mb-1 flex-wrap">
          <span class="mono text-red-400 text-sm">${escH(control.id)}</span>
          <h2 class="text-lg font-semibold text-white">${escH(control.title)}</h2>
        </div>
        <p class="text-xs text-neutral-500">
          ${escH(fw.name)}${fw.version ? ' · ' + escH(fw.version) : ''}${bits ? ' — ' + escH(bits) : ''}
        </p>
      </div>
      <div class="space-y-4">${body}</div>
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

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.body.style.overflow = 'auto';
}

function openModal(html) {
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

let _filtered = reportData.findings;

const _scopeLabel = (reportData.profile && reportData.profile.scope_label) || 'Scope';

const _scopesLabel = (reportData.profile && reportData.profile.scopes_label) || 'Scopes';

function areaLabel(a) {
  const ai = reportData.profile && reportData.profile.areas && reportData.profile.areas[a];
  return ai && ai.label ? ai.label : a;
}

function openFindingModal(idx) {
  const f = _filtered[idx];
  if (!f) return;
  renderFindingDetail(f);
}

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

const DIFF_ROW_CAP = 500;

// The module's finding diff, as the three lists the severity view (client/diffs.js) splits by severity. The per-area / scope
// diffs have no severity and are no longer shown.
function diffLists() {
  const mk = f => ({ title: f.title, type: areaLabel(f.area), severity: f.severity });
  return { new: diffFindingList('new').map(mk), existing: diffFindingList('existing').map(mk), fixed: diffFindingList('fixed').map(mk) };
}

function diffFindingList(list) {
  const f = reportData.diffs.findings;
  if (list === 'existing') return f.existing.map(i => reportData.findings[i]).filter(Boolean);
  return f[list] || [];
}

function diffFrameworkList(fw, list) {
  const f = reportData.diffs.findings;
  const base = list === 'new' ? f.new : list === 'removed' ? f.fixed : reportData.findings;
  return (fw[list] || []).map(i => base[i]).filter(Boolean);
}

function diffControlsOf(f, fwId) {
  const fw = ((f.compliance && f.compliance.frameworks) || []).find(x => x.id === fwId);
  return fw ? (fw.controls || []).map(c => c.id).join(', ') : '';
}

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
      '<td class="py-2 pr-4 mono text-neutral-500">' + escH(f.scope || '—') + '</td>' +
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

  html += UBEL_DIFFS.sectionHtml(diffLists(), { hint: 'Findings compared with the previous report, split by severity level. Select a count to list them.' });

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
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(fw.name) + ' — ' + labels[list] + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' +
    (items.length ? diffFindingsTable(items, fw.id) : '<p class="text-sm text-neutral-500 italic">None.</p>'));
}

// The compliance-framework buttons (the severity cards are handled by client/diffs.js).
function bindDiffs() {
  const sec = document.getElementById('section-diffs');
  if (!sec || sec.dataset.diffsBound) return;
  sec.dataset.diffsBound = '1';
  sec.addEventListener('click', e => {
    const b = e.target.closest('[data-diff-fw]');
    if (b) openComplianceDiffModal(parseInt(b.dataset.diffFw, 10), b.dataset.diffList);
  });
}

// Clicks the report was ported without (the module's listeners on #modal-body and on the compliance grid):
//  - a finding row inside a compliance modal / compliance-diff modal -> that finding's modal (_currentComplianceMatches)
//  - a control of the Compliance tab                                  -> its compliance modal
// The target is resolved first, so a reference that cannot be resolved leaves the current modal open; a resolved one replaces the
// modal's content directly (no close / reopen).
function bindModalRefs() {
  const modalBody = document.getElementById('modal-body');
  if (modalBody && !modalBody.dataset.refsBound) {
    modalBody.dataset.refsBound = '1';
    modalBody.addEventListener('click', e => {
      const row = e.target.closest && e.target.closest('[data-finding-index]');
      if (!row || !modalBody.contains(row)) return;
      e.stopPropagation();
      const f = _currentComplianceMatches && _currentComplianceMatches[parseInt(row.dataset.findingIndex, 10)];
      if (!f) return;
      renderFindingDetail(f);
      if (typeof cnModalScrollTop === 'function') cnModalScrollTop();
    });
  }
  const grid = document.getElementById('compliance-frameworks-grid');
  if (grid && !grid.dataset.refsBound) {
    grid.dataset.refsBound = '1';
    grid.addEventListener('click', e => {
      const row = e.target.closest && e.target.closest('[data-fw-idx]');
      if (!row) return;
      openComplianceModal(parseInt(row.dataset.fwIdx, 10), parseInt(row.dataset.controlIdx, 10));
    });
  }
}

// ── glue: canonical entry → module modal ──
const FAMILY = {
  openFinding: function (i) {
    const cf = CANON.findings[i]; if (!cf) return false;
    // package vulnerabilities of the SCA engine (sc_vuln / sc_infection): the SCA vulnerability modal (client/scvuln.js)
    if ((cf.type === 'sc_vuln' || cf.type === 'sc_infection') && window.UBEL_SC_VULN) return window.UBEL_SC_VULN.open(cf.details);
    const f = cf.details; if (!f) return false; renderFindingDetail(f); return true;
  },
  // the installed-package list of ubel-vm (dependency entries whose details are the SCA inventory item): the SCA package modal (client/scvuln.js)
  openInventory: function (i) { const c = CANON.inventory[i]; return !!(c && c.type === 'dependency' && window.UBEL_SC_VULN && window.UBEL_SC_VULN.openInventory(c.details)); },
  executive: function () { renderExecutiveSummary(); },
  compliance: function () { renderCompliance(); renderCompliancePosture(); },
  diffs: function () { renderDiffs(); bindDiffs(); },
  bind: bindModalRefs,
};
