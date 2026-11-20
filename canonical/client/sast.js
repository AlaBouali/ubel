/* canonical/client/sast.js — sast/html_report_generator.js (ubel-sast, ubel-mal)
 * The functions between "extracted verbatim" markers are copied unchanged from the module's own report template (modals,
 * executive summary, compliance and diff renderers, with the helpers they call). Only the data shim and the glue are new:
 * the shim rebuilds the module's own report shape (every canonical entry's `details` is the original entry), the glue says
 * which module modal a canonical finding / inventory entry opens. Requires the CANON constant (the canonical report). */

// ── data: the module report shape, rebuilt from the canonical report ──

// The module's own "chunks" view of the results: the same projection sast/html_report_generator.js makes (no source code in the report).
const reportData = (function (C) {
  const st = C.stats || {};
  const chunks = C.inventory.filter(function (c) { return c.type === 'code'; }).map(function (c) {
    const chunk = c.details;
    return {
      id: chunk.id, file: chunk.file, type: chunk.type, class: chunk.class || null, name: chunk.name, language: chunk.language,
      startLine: chunk.startLine, endLine: chunk.endLine,
      decorators: [],
      findings: (chunk.findings || []).map(function (f) {
        return {
          vuln_class: f.vuln_class || null, title: f.title || null, description: f.description || null, code_snippet: f.code_snippet || null,
          confidence: f.confidence || null, severity: f.severity || null, line: f.line || null, is_valid: f.is_valid ?? null,
          reason: f.reason || null, verification_error: f.verification_error || null, taint: f.taint || null, cwe: f.cwe || [],
          compliance: f.compliance || null, _parse_error: f._parse_error || false,
        };
      }),
    };
  });
  return { chunks: chunks, meta: { compliance_summary: C.compliance_summary }, executive_summary: C.executive_summary, diffs: st.diffs || { enabled: false } };
})(CANON);

// ── extracted verbatim from sast/html_report_generator.js (ubel-sast, ubel-mal) ──
function escH(s) {
  if (!s) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
}

function sevClass(s) {
  const m = {critical:'severity-critical',high:'severity-high',medium:'severity-medium',low:'severity-low'};
  return m[(s||'').toLowerCase()] || 'severity-unknown';
}

function confClass(c) {
  return {high:'conf-high',medium:'conf-medium',low:'conf-low'}[(c||'').toLowerCase()] || 'conf-low';
}

function taintBadge(taint, finding) {
  // Classes that need no attacker input (hardcoded secrets, weak crypto, ...) are
  // deliberately not taint-traced: say so instead of showing an unexplained dash.
  if (!taint && finding && finding.taint_skipped) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-400 border-neutral-700" title="This weakness does not depend on attacker input, so no exploitability trace was run">NOT REQUIRED</span>';
  if (!taint) return '<span class="text-neutral-600 text-[10px]">—</span>';
  if (taint.exploitable === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-red-400 border-red-400">EXPLOITABLE</span>';
  if (taint.reachable   === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-green-400 border-green-400">UNREACHABLE</span>';
  if (taint.sanitized   === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-blue-400 border-blue-400">SANITIZED</span>';
  if (taint.exploitable === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-yellow-400 border-yellow-400">NOT EXPLOITABLE</span>';
  if (taint.inconclusive_reason === 'orphan_no_callers') return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-purple-400 border-purple-400">ORPHAN</span>';
  if (taint.error)                 return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-700">TAINT ERROR</span>';
  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-600">TRACED</span>';
}

function validBadge(isValid) {
  if (isValid === true)  return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-green-400 border-green-400">VALID</span>';
  if (isValid === false) return '<span class="px-1.5 py-0.5 rounded border text-[10px] font-bold text-neutral-500 border-neutral-600 line-through">FALSE POS.</span>';
  return '<span class="px-1.5 py-0.5 rounded border text-[10px] text-neutral-600 border-neutral-700">UNVERIFIED</span>';
}

function renderCweAndCompliance(f) {
  var cwes = f.cwe || [];
  var compliance = f.compliance;
  var hasCompliance = compliance && compliance.frameworks && compliance.frameworks.length;
  if (!cwes.length && !hasCompliance) return '';

  var cweHtml = '';
  if (cwes.length) {
    var cweBadges = cwes.map(function(c) {
      return '<a href="https://cwe.mitre.org/data/definitions/' + c + '.html" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-orange-400 hover:text-orange-300 mono">CWE-' + c + '</a>';
    }).join('');
    cweHtml = '<div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Weaknesses (CWE)</h4><div class="flex flex-wrap gap-2">' + cweBadges + '</div></div>';
  }

  var complianceHtml = '';
  if (hasCompliance) {
    var frameworksHtml = compliance.frameworks.map(function(fw) {
      var controlsHtml = fw.controls.map(function(c) {
        return '<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="' + escH(c.title) + '">' + escH(c.id) + '</span>';
      }).join('');
      return '<div class="flex flex-col gap-1"><span class="text-xs font-semibold text-red-400">' + escH(fw.name) + '</span><div class="flex flex-wrap gap-1.5">' + controlsHtml + '</div></div>';
    }).join('');
    complianceHtml = '<div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Compliance Frameworks</h4><div class="bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 space-y-2">' + frameworksHtml + '</div></div>';
  }

  return cweHtml + complianceHtml;
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
  const isMal = sc.scan_type === 'malware';
  const confirmedLabel = isMal ? 'Confirmed malicious' : 'Confirmed exploitable';
  const riskColor = col(risk.level);
  let html = '';

  // Toolbar (screen only)
  html += '<div class="no-print flex justify-end"><button type="button" onclick="window.print()" ' +
    'class="px-4 py-2 rounded-lg bg-neutral-800 border border-neutral-700 text-xs font-medium text-neutral-200 hover:bg-neutral-700 transition-colors">' +
    'Print / save as PDF</button></div>';

  // ── PAGE 1 ────────────────────────────────────────────────────────────────
  const metaItems = [
    ['Report ID', cover.report_id],
    ['Date', cover.generated_at ? String(cover.generated_at).replace('T', ' ').slice(0, 16) + ' UTC' : null],
    ['Repository', cover.repository],
    ['Code version', cover.code_version],
    ['Tool', cover.tool]
  ].filter(function (m) { return m[1]; });
  html += '<div class="glass p-5 rounded-xl">' +
    '<p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest mb-1">' + esc(cover.title || 'Executive summary') + '</p>' +
    '<h2 class="text-2xl font-bold mb-3 break-words">' + esc(cover.subject || 'Source code') + '</h2>' +
    (metaItems.length ? '<div class="flex flex-wrap gap-x-8 gap-y-1 text-xs mb-3">' +
      metaItems.map(function (m) {
        return '<div class="min-w-0"><span class="text-neutral-500">' + esc(m[0]) + ': </span><span class="mono break-all text-neutral-300">' + esc(m[1]) + '</span></div>';
      }).join('') + '</div>' : '') +
    (cover.classification ? '<p class="text-[11px] text-neutral-500 uppercase tracking-wider">' + esc(cover.classification) + '</p>' : '') +
  '</div>';

  html += '<div class="glass p-6 md:p-8 rounded-xl" style="border-left:6px solid ' + riskColor + '">' +
    '<div class="flex flex-wrap items-center justify-between gap-3 mb-3">' +
      '<div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Overall security risk</p>' +
      '<p class="text-4xl font-bold" style="color:' + riskColor + '">' + esc(bl.risk_label || risk.label || 'Unknown') + '</p></div>' +
    '</div>' +
    '<p class="text-lg leading-relaxed text-neutral-100 exec-headline">' + esc(bl.summary || es.headline) + '</p>' +
    (es.verdict ?
      '<div class="mt-4 pt-4 border-t border-neutral-800">' +
        '<div class="flex flex-wrap items-center gap-3 mb-2">' + badge(es.verdict.status === 'pass' ? 'none' : 'high', es.verdict.label) + '</div>' +
        '<p class="text-sm text-neutral-300 leading-relaxed">' + esc(es.verdict.statement) + '</p>' +
        (es.verdict.technical_reason ? '<p class="text-xs text-neutral-500 mt-2 mono">' + esc(es.verdict.technical_reason) + '</p>' : '') +
      '</div>' : '') +
  '</div>';

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

  if ((bl.figures || []).length) {
    html += '<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 exec-figs">' + bl.figures.map(figure).join('') + '</div>';
  }
  if (cover.statement) {
    html += '<p class="text-[11px] text-neutral-500 italic">' + esc(cover.statement) + '</p>';
  }

  // ── DETAILS ───────────────────────────────────────────────────────────────
  html += '<div class="exec-page-break pt-2"><p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest border-b border-neutral-800 pb-2">Details</p></div>';

  if (risk.rationale || risk.business_impact) {
    html += '<div>' + sectionTitle('Why this rating') + '<div class="glass p-5 rounded-xl space-y-3">' +
      (risk.rationale ? '<p class="text-sm text-neutral-300"><span class="font-semibold">Reason: </span>' + esc(risk.rationale) + '</p>' : '') +
      (risk.business_impact ? '<p class="text-sm text-neutral-400"><span class="font-semibold text-neutral-300">What it means: </span>' + esc(risk.business_impact) + '</p>' : '') +
      (risk.basis ? '<p class="text-xs text-neutral-500 italic">' + esc(risk.basis) + '</p>' : '') +
    '</div></div>';
  }

  html += '<div>' + sectionTitle('All key findings') + '<div class="space-y-3">' +
    (es.key_findings || []).map(function (f) {
      return '<div class="glass p-5 rounded-xl" style="border-left:4px solid ' + col(f.severity) + '">' +
        '<h4 class="font-semibold text-sm mb-1">' + esc(f.title) + '</h4>' +
        '<p class="text-sm text-neutral-300 leading-relaxed">' + esc(f.detail) + '</p></div>';
    }).join('') + '</div></div>';

  // How the AI's candidate findings were sorted
  if ((es.glance_cards || []).length) {
    html += '<div>' + sectionTitle('How the findings were sorted') +
      (es.triage && es.triage.statement ? '<p class="text-xs text-neutral-500 italic mb-3">' + esc(es.triage.statement) + '</p>' : '') +
      '<div class="grid grid-cols-2 lg:grid-cols-3 gap-4 exec-glance">' + es.glance_cards.map(figure).join('') + '</div></div>';
  }

  // What was scanned
  const cov = es.scan_coverage || {};
  if ((cov.pipeline || []).length) {
    const stKey = function (s) { return s === 'done' ? 'none' : (s === 'partial' ? 'medium' : (s === 'skipped' ? 'high' : 'unknown')); };
    html += '<div>' + sectionTitle('What was scanned') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Step</th><th>Status</th><th>Detail</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      cov.pipeline.map(function (p) {
        return '<tr><td class="px-6 py-4 font-medium align-top">' + esc(p.stage) + '</td>' +
          '<td class="py-4 align-top">' + badge(stKey(p.status), p.status_label) + '</td>' +
          '<td class="py-4 pr-6 align-top text-xs text-neutral-400">' + esc(p.detail) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      ((cov.languages || []).length ?
        '<div class="glass rounded-xl overflow-x-auto mt-4"><table class="w-full text-left text-sm">' +
        '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
        '<th class="px-6 py-4">Language</th><th>Code units analyzed</th><th>Open issues</th></tr></thead>' +
        '<tbody class="divide-y divide-neutral-800">' +
        cov.languages.map(function (l) {
          return '<tr><td class="px-6 py-3 mono text-xs">' + esc(l.language) + '</td><td class="py-3">' + esc(l.code_units) + '</td><td class="py-3">' + esc(l.open_issues) + '</td></tr>';
        }).join('') + '</tbody></table></div>' : '') +
      ((cov.scope_limits || []).length ? '<p class="text-xs text-neutral-500 italic mt-2">Scope limits for this run: ' + esc(cov.scope_limits.join('; ')) + '.</p>' : '') +
    '</div>';
  }

  // Issues by area
  const areas = es.risk_areas || [];
  if (areas.length) {
    html += '<div>' + sectionTitle('Issues by area') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Area</th><th>Open</th><th>' + esc(confirmedLabel) + '</th><th>Files</th><th>Priority</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      areas.map(function (t) {
        return '<tr>' +
          '<td class="px-6 py-4"><div class="font-medium">' + esc(t.title) + '</div><div class="text-xs text-neutral-500 mt-1 max-w-xl">' + esc(t.plain) + '</div></td>' +
          '<td class="py-4 align-top">' + esc(t.issues) + '</td>' +
          '<td class="py-4 align-top">' + esc(t.confirmed) + '</td>' +
          '<td class="py-4 align-top">' + esc(t.files_affected) + '</td>' +
          '<td class="py-4 pr-6 align-top">' + badge(t.priority, t.priority_label) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Priority is severity weighed by evidence (see Methodology): a finding not confirmed exploitable counts at most High.</p></div>';
  }

  // Issue types to fix first
  const types = es.issues_to_fix_first || [];
  if (types.length) {
    html += '<div>' + sectionTitle('Issue types to fix first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">Issue</th><th>Occurrences</th><th>Files</th><th>Status</th><th>Priority</th><th>What to do</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      types.map(function (c) {
        return '<tr>' +
          '<td class="px-6 py-4 font-medium align-top">' + esc(c.title) +
            (c.reference ? '<div class="mono text-[10px] text-neutral-500 font-normal mt-1 break-all max-w-[16rem]">' + esc(c.reference) + '</div>' : '') + '</td>' +
          '<td class="py-4 align-top">' + esc(c.occurrences) + '</td>' +
          '<td class="py-4 align-top">' + esc(c.files_affected) + '</td>' +
          '<td class="py-4 align-top text-xs text-neutral-400">' + esc(c.status) + '</td>' +
          '<td class="py-4 align-top">' + badge(c.priority, c.priority_label) + '</td>' +
          '<td class="py-4 pr-6 align-top text-neutral-300 text-xs">' + esc(c.action) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">The identifier under each issue is its weakness number (CWE), for tickets and audit trails. Exact locations and fixes are in the Findings tab.</p></div>';
  }

  // Files to review first
  const files = es.files_to_review_first || [];
  if (files.length) {
    html += '<div>' + sectionTitle('Files to review first') +
      '<div class="glass rounded-xl overflow-x-auto"><table class="w-full text-left text-sm">' +
      '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>' +
      '<th class="px-6 py-4">File</th><th>Language</th><th>Open</th><th>' + esc(confirmedLabel) + '</th><th>Priority</th></tr></thead>' +
      '<tbody class="divide-y divide-neutral-800">' +
      files.map(function (r) {
        return '<tr>' +
          '<td class="px-6 py-4 mono text-xs break-all">' + esc(r.file) + '</td>' +
          '<td class="py-4 text-xs text-neutral-400">' + esc(r.language || '—') + '</td>' +
          '<td class="py-4">' + esc(r.issues) + '</td>' +
          '<td class="py-4">' + esc(r.confirmed) + '</td>' +
          '<td class="py-4 pr-6">' + badge(r.priority, r.priority_label) + '</td></tr>';
      }).join('') + '</tbody></table></div>' +
      '<p class="text-[11px] text-neutral-500 italic mt-2">Ranks the files carrying the most serious and most numerous open issues. Findings dismissed as false alarms are not counted.</p></div>';
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
      '<p class="text-sm text-neutral-400 leading-relaxed"><span class="font-semibold text-neutral-300">Severity and priority. </span>' + esc(mt.severity_note) + '</p>' +
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

let _currentModalChunkId = null;

let _currentComplianceMatches = null;

let _allFindings = null;

function getAllFindings() {
  if (_allFindings) return _allFindings;
  const out = [];
  for (const chunk of reportData.chunks) {
    for (const f of (chunk.findings || [])) {
      if (f._parse_error) continue;
      out.push({ chunk, finding: f });
    }
  }
  _allFindings = out;
  return out;
}

function openFindingModal(chunkId, idx) {
  const list = window._filteredFindings || getAllFindings();
  const item = list[idx];
  if (!item) {
    // fallback: find by chunkId
    const match = getAllFindings().find(x => x.chunk.id === chunkId);
    if (!match) return;
    _renderFindingModal(match);
  } else {
    _renderFindingModal(item);
  }
}

function _renderFindingModal({chunk, finding: f}) {
  const relFile = (chunk.file||'').replace(/\\/g,'/');
  const qual    = chunk.class ? chunk.class + '.' + chunk.name : chunk.name;

  const taint = f.taint || {};
  const taintHtml = f.taint ? `
    <div class="space-y-3">
      <div class="flex flex-wrap gap-4 items-center">
        ${taintBadge(f.taint, f)}
        ${taint.reachable   != null ? '<span class="text-xs text-neutral-400">Reachable: <span class="font-semibold '+(taint.reachable?'text-red-400':'text-green-400')+'">'+(taint.reachable?'YES':'NO')+'</span></span>' : ''}
        ${taint.sanitized   === true ? '<span class="text-xs text-neutral-400">Sanitized: <span class="font-semibold text-blue-400">YES</span></span>' : ''}
        ${taint.exploitable != null ? '<span class="text-xs text-neutral-400">Exploitable: <span class="font-semibold '+(taint.exploitable?'text-red-500':'text-green-400')+'">'+(taint.exploitable?'YES':'NO')+'</span></span>' : ''}
      </div>
      ${taint.flow_path ? '<div class="bg-neutral-900 border border-neutral-800 rounded-lg p-3"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Flow Path</p><p class="mono text-xs text-neutral-300 leading-relaxed">'+escH(taint.flow_path)+'</p></div>' : ''}
      ${taint.rationale  ? '<p class="text-xs text-neutral-400 italic bg-neutral-900/50 px-3 py-2 rounded border border-neutral-800">'+escH(taint.rationale)+'</p>' : ''}
      ${taint.error      ? '<p class="text-xs text-red-400 bg-red-500/5 px-3 py-2 rounded border border-red-500/20">Taint error: '+escH(JSON.stringify(taint.error)  )+'</p>' : ''}
    </div>
  ` : '<p class="text-xs text-neutral-500 italic">Taint trace was not run or produced no output.</p>';

  const verifyHtml = f.is_valid != null ? `
    <div class="flex items-start gap-3">
      ${validBadge(f.is_valid)}
      ${f.reason ? '<p class="text-xs text-neutral-400 italic">'+escH(f.reason)+'</p>' : ''}
    </div>
  ` : '<p class="text-xs text-neutral-500 italic">Finding was not verified (verify pass skipped or did not run).</p>';

  const snippetHtml = f.code_snippet ? `
    <pre class="bg-neutral-950 border border-neutral-800 rounded-lg p-4 text-[11px] mono text-neutral-200 overflow-x-auto whitespace-pre-wrap break-words">${escH(f.code_snippet)}</pre>
  ` : '<p class="text-xs text-neutral-500 italic">No code snippet captured.</p>';

  openModal(`
    <div class="space-y-6">

      <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div class="flex items-center gap-3 mb-1 flex-wrap">
            <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(f.severity)}">${escH(f.severity||'?')}</span>
            <h2 class="text-xl font-bold">${escH(f.vuln_class||'Unknown')}</h2>
          </div>
          <p class="text-neutral-300 text-sm">${escH(f.title||'')}</p>
        </div>
        <div class="text-right shrink-0">
          <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Confidence</p>
          <span class="px-2 py-0.5 rounded border text-sm font-bold ${confClass(f.confidence)}">${escH(f.confidence||'?')}</span>
        </div>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">File</p>
          <p class="mono text-xs text-neutral-300 break-all">${escH(relFile)}</p>
        </div>
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Function / Method</p>
          <p class="mono text-xs text-neutral-300">${escH(qual)}</p>
        </div>
        <div>
          <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Line</p>
          <p class="mono text-xs text-neutral-300">${f.line || chunk.startLine || '—'}</p>
        </div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Description</h4>
        <p class="text-sm text-neutral-300 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">${escH(f.description||'No description provided.')}</p>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Vulnerable Code Snippet</h4>
        ${snippetHtml}
      </div>

      ${f.fix ? `
      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Recommended Fix</h4>
        <p class="text-sm text-green-300 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-green-900">${escH(f.fix)}</p>
      </div>` : ''}

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Verification Pass</h4>
        ${verifyHtml}
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Taint Trace</h4>
        ${taintHtml}
      </div>

      ${renderCweAndCompliance(f)}

      <div class="border-t border-neutral-800 pt-4">
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Chunk Context</h4>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">${escH(chunk.type||'—')}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Language</p><p class="mono text-xs">${escH(chunk.language||'—')}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Start Line</p><p class="mono text-xs">${chunk.startLine||'—'}</p></div>
          <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">End Line</p><p class="mono text-xs">${chunk.endLine||'—'}</p></div>
        </div>
      </div>

      ${f.verification_error ? '<div class="bg-red-500/5 border border-red-500/20 rounded-lg p-3"><p class="text-[10px] uppercase text-red-400 font-bold mb-1">Verification Error</p><p class="mono text-xs text-red-300">'+escH(JSON.stringify(f.verification_error))+'</p></div>' : ''}

    </div>
  `);
}

function openInvModal(chunkId) {
  const chunk = reportData.chunks.find(c => c.id === chunkId);
  if (!chunk) return;
  _currentModalChunkId = chunkId;
  _currentComplianceMatches = null;

  const findings = (chunk.findings||[]).filter(f=>!f._parse_error);
  const errors   = (chunk.findings||[]).filter(f=> f._parse_error);
  const relFile  = (chunk.file||'').replace(/\\/g,'/');

  const findingRows = findings.length ? findings.map((f, fi) => `
    <div class="flex items-center justify-between py-2.5 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors"
         data-finding-index="${fi}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(f.severity)}">${escH(f.severity||'?')}</span>
        <span class="text-sm font-medium">${escH(f.vuln_class||'unknown')}</span>
        <span class="text-xs text-neutral-500">${escH(f.title||'')}</span>
      </div>
      <div class="flex items-center gap-2">
        ${validBadge(f.is_valid)}
        ${taintBadge(f.taint, f)}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>
  `).join('') : '<p class="text-sm text-neutral-500 italic py-2">No findings in this chunk.</p>';

  const decorators = (chunk.decorators || []);
  const decHtml = decorators.length
    ? decorators.map(d=>`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 text-blue-300">${escH(d)}</span>`).join('')
    : '<span class="text-neutral-500 text-xs italic">None</span>';

  openModal(`
    <div class="space-y-6">
      <div class="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <div class="flex items-center gap-3 mb-1 flex-wrap">
            <span class="text-[10px] uppercase font-bold ${findings.length ? 'text-orange-400 border-orange-400' : 'text-green-400 border-green-400'} border px-2 py-0.5 rounded">${findings.length ? findings.length+' finding'+(findings.length>1?'s':'') : 'clean'}</span>
            <h2 class="text-xl font-bold">${escH(chunk.class ? chunk.class+'.'+chunk.name : chunk.name)}</h2>
          </div>
          <p class="mono text-[11px] text-neutral-500 break-all">${escH(chunk.id)}</p>
        </div>
        <div class="text-right shrink-0">
          <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Language</p>
          <p class="mono text-sm">${escH(chunk.language||'—')}</p>
        </div>
      </div>

      <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">${escH(chunk.type||'—')}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Class</p><p class="mono text-xs">${escH(chunk.class||'—')}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Start Line</p><p class="mono text-xs">${chunk.startLine||'—'}</p></div>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">End Line</p><p class="mono text-xs">${chunk.endLine||'—'}</p></div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">File</h4>
        <p class="mono text-[11px] text-neutral-400 bg-neutral-900 px-3 py-2 rounded border border-neutral-800 break-all">${escH(relFile)}</p>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Decorators / Annotations</h4>
        <div class="flex flex-wrap gap-2">${decHtml}</div>
      </div>

      <div>
        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Findings (${findings.length})</h4>
        <div class="space-y-0">${findingRows}</div>
      </div>

      ${errors.length ? `<div class="bg-red-500/5 border border-red-500/20 rounded-lg p-3"><p class="text-[10px] uppercase text-red-400 font-bold mb-1">Parse Errors (${errors.length})</p><p class="text-xs text-neutral-500">This chunk produced ${errors.length} parse error(s) during the scan pass. The raw LLM output could not be decoded as valid JSON findings.</p></div>` : ''}
    </div>
  `);
}

function hasComplianceControl(f, fwName, controlId) {
  return !!(f.compliance && f.compliance.frameworks &&
    f.compliance.frameworks.some(x => (x.name === fwName || String(x.name).indexOf(fwName + ' (') === 0) && x.controls.some(c => c.id === controlId)));
}

function complianceMatchesFor(fwName, controlId) {
  return getAllFindings().filter(({ finding: f }) => hasComplianceControl(f, fwName, controlId));
}

function complianceStatsFromMatches(matches) {
  const vulnClasses = new Set();
  const chunks = new Set();
  for (const { chunk, finding: f } of matches) {
    vulnClasses.add(f.vuln_class || 'unknown');
    chunks.add(chunk.id);
  }
  return {
    vulnClassCount: vulnClasses.size,
    chunkCount: chunks.size,
    matchCount: matches.length,
  };
}

function complianceFrameworkTotals(fw) {
  const acc = new Set();
  for (const c of (fw.controls || [])) {
    complianceMatchesFor(fw.name, c.id).forEach(m => acc.add(m));
  }
  return complianceStatsFromMatches([...acc]);
}

function complianceCountsHtml(stats, primaryClass) {
  const line = (cls, text) => `<span class="${cls}">${text}</span>`;
  const minor = 'mono text-neutral-500 text-[10px]';
  return line(primaryClass, stats.vulnClassCount + ' vuln class' + (stats.vulnClassCount === 1 ? '' : 'es')) +
    line(minor, stats.chunkCount + ' chunk' + (stats.chunkCount === 1 ? '' : 's'));
}

function renderCompliance() {
  const cs = reportData.meta && reportData.meta.compliance_summary;
  const disclaimerEl = document.getElementById('compliance-disclaimer');
  if (disclaimerEl) disclaimerEl.textContent = [cs && cs.scope_note, cs && cs.disclaimer].filter(Boolean).join(' ');

  const coverageEl = document.getElementById('compliance-coverage');
  const coverageValueEl = document.getElementById('compliance-coverage-value');
  if (coverageEl && coverageValueEl) {
    if (cs && cs.coverage && cs.coverage.total_findings) {
      const { mapped_findings, total_findings, coverage_pct } = cs.coverage;
      coverageValueEl.textContent = mapped_findings + ' / ' + total_findings + ' (' + coverage_pct + '%)';
      coverageEl.classList.remove('hidden');
    } else {
      coverageEl.classList.add('hidden');
    }
  }

  const owaspSection = document.getElementById('compliance-owasp-section');
  const owaspGrid = document.getElementById('compliance-owasp-grid');
  if (owaspSection && owaspGrid) {
    if (cs && cs.by_owasp_category && cs.by_owasp_category.length) {
      owaspGrid.innerHTML = cs.by_owasp_category.map(o =>
        '<div class="glass p-4 rounded-xl flex items-start justify-between gap-3 text-xs">' +
          '<div class="flex flex-col gap-1">' +
            '<span class="mono text-red-400">' + escH(o.id) + '</span>' +
            '<span class="text-neutral-400">' + escH(o.title) + '</span>' +
            '<span class="text-neutral-600">via: ' + escH((o.categories || []).join(', ')) + '</span>' +
          '</div>' +
          '<div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">' +
            complianceCountsHtml(complianceStatsFromMatches(complianceMatchesFor('OWASP Top 10', o.id)), 'mono text-neutral-200 font-semibold') +
          '</div>' +
        '</div>'
      ).join('');
      owaspSection.classList.remove('hidden');
    } else {
      owaspSection.classList.add('hidden');
    }
  }

  const grid = document.getElementById('compliance-frameworks-grid');
  if (!cs || !cs.frameworks || !cs.frameworks.length) {
    const emptyEl = document.getElementById('compliance-empty');
    if (cs && cs.scope && cs.scope.basis === 'verified') emptyEl.textContent = 'No verified finding is mapped to a compliance framework.';
    emptyEl.classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const controlRows = fw.controls.map((c, cIdx) =>
      '<div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" onclick="openComplianceModal(' + fwIdx + ',' + cIdx + ')">' +
        '<div class="flex flex-col min-w-0"><span class="mono text-red-400">' + escH(c.id) + '</span><span class="text-neutral-500">' + escH(c.title) + '</span></div>' +
        '<div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">' + complianceCountsHtml(complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id)), 'mono text-neutral-200') + '</div>' +
      '</div>'
    ).join('');
    const versionBadge = fw.version ? '<span class="text-[10px] text-neutral-500 mono">' + escH(fw.version) + '</span>' : '';
    const fwStats = complianceFrameworkTotals(fw);
    return '<div class="glass p-6 rounded-xl space-y-4">' +
      '<div class="flex items-start justify-between gap-3">' +
        '<div class="flex flex-col"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">' + escH(fw.name) + '</h3>' + versionBadge + '</div>' +
        '<div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">' + complianceCountsHtml(fwStats, 'mono text-neutral-200 font-semibold text-xs') + '</div>' +
      '</div>' +
      '<div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">' + controlRows + '</div>' +
    '</div>';
  }).join('');
}

function openComplianceModal(fwIdx, cIdx) {
  const cs = reportData.meta && reportData.meta.compliance_summary;
  const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
  const control = fw && fw.controls && fw.controls[cIdx];
  if (!fw || !control) return;

  const matches = getAllFindings().filter(({ finding: f }) =>
    f.compliance && f.compliance.frameworks &&
    f.compliance.frameworks.some(x => x.name === fw.name && x.controls.some(c => c.id === control.id))
  );

  _currentModalChunkId = null;
  _currentComplianceMatches = matches;

  const rows = matches.length ? matches.map(({ finding: f }, idx) => `
    <div class="flex items-center justify-between py-2.5 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors"
         data-finding-index="${idx}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${sevClass(f.severity)}">${escH(f.severity||'?')}</span>
        <span class="text-sm font-medium">${escH(f.vuln_class||'unknown')}</span>
        <span class="text-xs text-neutral-500">${escH(f.title||'')}</span>
      </div>
      <div class="flex items-center gap-2">
        ${validBadge(f.is_valid)}
        ${taintBadge(f.taint, f)}
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>
  `).join('') : '<p class="text-sm text-neutral-500 italic py-2">No findings mapped to this control.</p>';

  const stats = complianceStatsFromMatches(matches);
  const bit = stats.vulnClassCount
    ? stats.vulnClassCount + (stats.vulnClassCount === 1 ? ' distinct vuln class' : ' distinct vuln classes') +
      ' across ' + stats.chunkCount + (stats.chunkCount === 1 ? ' chunk' : ' chunks') +
      (stats.matchCount !== stats.vulnClassCount ? ' (' + stats.matchCount + ' finding' + (stats.matchCount === 1 ? '' : 's') + ' total)' : '')
    : '';

  openModal(`
    <div class="space-y-4">
      <div>
        <div class="flex items-center gap-3 mb-1 flex-wrap">
          <span class="mono text-red-400 text-sm">${escH(control.id)}</span>
          <h2 class="text-lg font-semibold text-white">${escH(control.title)}</h2>
        </div>
        <p class="text-xs text-neutral-500">${escH(fw.name)}${fw.version ? ' · ' + escH(fw.version) : ''}${bit ? ' — ' + bit : ''}</p>
      </div>
      <div>${rows}</div>
    </div>
  `);
}

var DIFF_TILES = [
  { count: 'new_chunks',       label: 'New chunks',              group: 'chunks', list: 'new',       color: 'text-orange-400' },
  { count: 'unchanged_chunks', label: 'Unchanged chunks',        group: 'chunks', list: 'unchanged', color: 'text-neutral-300' },
  { count: 'removed_chunks',   label: 'Removed chunks',          group: 'chunks', list: 'removed',   color: 'text-blue-400' },
  { count: 'new_vulns',        label: 'New findings',            group: 'vulns',  list: 'new',       color: 'text-red-400' },
  { count: 'existing_vulns',   label: 'Still existing findings', group: 'vulns',  list: 'existing',  color: 'text-yellow-400' },
  { count: 'fixed_vulns',      label: 'Fixed findings',          group: 'vulns',  list: 'fixed',     color: 'text-green-400' }
];

var DIFF_GROUPS = ['new', 'unchanged', 'removed'];

function diffEsc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function renderDiffs() {
  var sec = document.getElementById('section-diffs');
  if (!sec) return;
  var d = reportData.diffs;
  if (!d || !d.enabled) { sec.innerHTML = ''; return; }

  var html = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2>';
  if (d.previous) {
    html += '<p class="text-xs text-neutral-500 mono">vs previous report ' + diffEsc(d.previous.report_id || d.previous.bundle) +
      (d.previous.generated_at ? ' (' + diffEsc(d.previous.generated_at) + ')' : '') + '</p>';
  }
  html += '</div>';

  if (d.error) {
    html += '<div class="glass rounded-xl p-4 text-xs text-red-400">The comparison could not be built: ' + diffEsc(d.error) + '</div>';
  }
  if (!d.previous || !d.counts) {
    html += '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
    sec.innerHTML = html;
    return;
  }
  if (d.scope_note) {
    html += '<p class="text-xs text-yellow-400 bg-yellow-500/5 border border-yellow-500/20 rounded-lg px-3 py-2">' + diffEsc(d.scope_note) + '</p>';
  }

  html += '<div class="grid grid-cols-2 md:grid-cols-3 gap-4">';
  DIFF_TILES.forEach(function (t, i) {
    html += '<button type="button" onclick="openDiffModal(' + i + ')" class="glass rounded-xl p-6 text-left hover:border-neutral-500 transition-colors aspect-square md:aspect-auto md:min-h-[9rem] flex flex-col justify-between">' +
      '<span class="text-[10px] uppercase tracking-widest text-neutral-500 font-bold">' + t.label + '</span>' +
      '<span class="text-4xl font-bold mono ' + t.color + '">' + (d.counts[t.count] || 0) + '</span></button>';
  });
  html += '</div>';
  html += '<p class="text-xs text-neutral-500">Findings dismissed as false positives by the verification pass are not counted, so clearing one shows up as fixed.</p>';

  if (d.compliance && d.compliance.frameworks && d.compliance.frameworks.length) {
    html += '<h3 class="text-lg font-bold pt-4">Compliance frameworks</h3>' +
      '<p class="text-xs text-neutral-500">Findings mapped to each framework, compared with the previous report.</p>' +
      '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    d.compliance.frameworks.forEach(function (fw, fi) {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + diffEsc(fw.name) + '</p>' +
        (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + diffEsc(fw.version) + '</p>' : '') + '</div>' +
        '<div class="grid grid-cols-3 gap-2">';
      [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(function (g, gi) {
        html += '<button type="button" onclick="openComplianceDiffModal(' + fi + ',' + gi + ')" class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors">' +
          '<span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + g[1] + '</span>' +
          '<span class="block text-2xl font-bold mono ' + g[2] + '">' + fw[g[0]].length + '</span></button>';
      });
      html += '</div></div>';
    });
    html += '</div>';
  } else if (!d.compliance) {
    html += '<p class="text-xs text-neutral-500">Compliance changes are not shown: the previous report has no compliance mapping.</p>';
  }
  sec.innerHTML = html;
}

function diffTable(cols, rowsHtml) {
  return '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
    cols.map(function (c) { return '<th class="pb-2 pr-4 font-bold">' + c + '</th>'; }).join('') +
    '</tr></thead><tbody class="divide-y divide-neutral-800">' + rowsHtml + '</tbody></table></div>';
}

function diffSevCell(sev) {
  var s = String(sev || 'unknown').toLowerCase();
  return '<td class="py-2 pr-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + sevClass(s) + '">' + diffEsc(s) + '</span></td>';
}

function openDiffModal(i) {
  var t = DIFF_TILES[i];
  var d = reportData.diffs;
  if (!t || !d) return;
  var items = (d[t.group] && d[t.group][t.list]) || [];
  var body;
  if (items.length === 0) {
    body = '<p class="text-sm text-neutral-500 italic">None.</p>';
  } else if (t.group === 'chunks') {
    body = diffTable(['File', 'Function / Method', 'Type', 'Language'], items.map(function (e) {
      return '<tr><td class="py-2 pr-4 mono text-neutral-400 break-all">' + diffEsc(e.file) + '</td>' +
        '<td class="py-2 pr-4 font-medium">' + diffEsc(e.name) + '</td>' +
        '<td class="py-2 pr-4 text-neutral-400">' + diffEsc(e.type || '-') + '</td>' +
        '<td class="py-2 pr-4 text-neutral-400">' + diffEsc(e.language || '-') + '</td></tr>';
    }).join(''));
  } else {
    body = diffTable(['Severity', 'Vuln class', 'Title', 'File:Line', 'Function', 'Exploitable'], items.map(function (e) {
      return '<tr>' + diffSevCell(e.severity) +
        '<td class="py-2 pr-4 font-medium">' + diffEsc(e.id) + '</td>' +
        '<td class="py-2 pr-4 text-neutral-300">' + diffEsc(e.title) + '</td>' +
        '<td class="py-2 pr-4 mono text-neutral-400 break-all">' + diffEsc(e.file) + (e.line != null ? ':' + diffEsc(e.line) : '') + '</td>' +
        '<td class="py-2 pr-4 mono text-neutral-400">' + diffEsc(e.name) + '</td>' +
        '<td class="py-2 pr-4">' + (e.exploitable ? '<span class="text-red-400 font-bold">YES</span>' : '<span class="text-neutral-600">-</span>') + '</td></tr>';
    }).join(''));
  }
  _currentComplianceMatches = null;
  openModal('<h3 class="text-lg font-bold mb-1">' + t.label + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}

function openComplianceDiffModal(fi, gi) {
  var d = reportData.diffs;
  var fw = d && d.compliance && d.compliance.frameworks[fi];
  var list = DIFF_GROUPS[gi];
  if (!fw || !list) return;
  var labels = { 'new': 'New', unchanged: 'Still existing', removed: 'Resolved' };
  var items = fw[list] || [];
  var body;
  if (items.length === 0) {
    body = '<p class="text-sm text-neutral-500 italic">None.</p>';
  } else {
    body = diffTable(['Severity', 'Vuln class', 'Title', 'File:Line (function)', 'Controls'], items.map(function (e) {
      return '<tr>' + diffSevCell(e.severity) +
        '<td class="py-2 pr-4 font-medium">' + diffEsc(e.id) + '</td>' +
        '<td class="py-2 pr-4 text-neutral-300">' + diffEsc(e.title) + '</td>' +
        '<td class="py-2 pr-4 mono text-neutral-400 break-all">' + diffEsc(e.where) + '</td>' +
        '<td class="py-2 pr-4 mono text-neutral-500">' + diffEsc(e.controls) + '</td></tr>';
    }).join(''));
  }
  _currentComplianceMatches = null;
  openModal('<h3 class="text-lg font-bold mb-1">' + diffEsc(fw.name) + ' - ' + labels[list] + '</h3>' +
    '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}

// ── glue: canonical entry → module modal ──
const FAMILY = {
  openFinding: function (i) { const it = getAllFindings()[i]; if (!it) return false; _renderFindingModal(it); return true; },
  openInventory: function (i) { const c = CANON.inventory[i]; if (c.type !== 'code') return false; openInvModal(c.details.id); return true; },
  executive: function () { renderExecutiveSummary(); },
  compliance: function () { renderCompliance(); },
  diffs: function () { renderDiffs(); },
};
