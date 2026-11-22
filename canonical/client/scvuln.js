/* canonical/client/scvuln.js — the SCA vulnerability modal, for the reports of the modules that take their package vulnerabilities from the SCA engine
 * (ubel-vm, ubel-runtime, ubel-k8s: findings of type sc_vuln / sc_infection whose `details` is the SCA vulnerability record).
 * The renderers below are extracted verbatim from client/sca.js (openVulnModal and what it calls); only the record lookup is replaced:
 * the modal opens the record it is given. After it, two blocks are added that only these reports have: which check found the package and
 * where, and the dependency sequences. Exposed as window.UBEL_SC_VULN.open(record). */
(function () {
'use strict';
const NOT_PROVIDED = 'Not provided by the advisory source';
let CURRENT = null;
function findVuln() { return CURRENT; }

function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
        }

function escapeHtmlClient(str) {
            if (!str || typeof str !== 'string') return str || '';
            return str.replace(/[&<>"']/g, (m) => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[m]));
        }

function fmtAdvisoryDate(d) {
            if (!d) return NOT_PROVIDED;
            const t = new Date(d);
            return isNaN(t.getTime()) ? NOT_PROVIDED : t.toLocaleDateString();
        }

function fmtPct(x) { return (x == null || isNaN(Number(x))) ? '—' : (Number(x) * 100).toFixed(2) + '%'; }

function hasCvssScore(v) {
            return v && v.severity_score != null && v.severity_score !== '' && !isNaN(parseFloat(v.severity_score));
        }

function hasCvssVector(v) {
            return v && typeof v.severity_vector === 'string' && v.severity_vector.trim() !== '';
        }

function policyRuleBadge(x) {
            const cls = { infection: 'text-red-400 border-red-400', kev: 'text-red-400 border-red-400', epss: 'text-orange-400 border-orange-400', severity: 'text-yellow-400 border-yellow-400', unknown_severity: 'text-neutral-300 border-neutral-500' }[x.rule] || 'text-neutral-300 border-neutral-500';
            return '<span class="inline-block px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + cls + '" title="' + escapeHtmlClient(x.detail || '') + '">' + escapeHtmlClient(x.title || x.rule) + '</span>';
        }

function releaseConfBadge(level, reason) {
            if (!level) return '<span class="text-neutral-600">—</span>';
            const cls = level === 'high' ? 'text-green-400 border-green-400'
                      : level === 'medium' ? 'text-yellow-400 border-yellow-400'
                      : 'text-red-400 border-red-400';
            return '<span title="' + escapeHtml(String(reason || '')) + '" class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ' + cls + '">' + escapeHtml(String(level)) + '</span>';
        }

function tiEsc(x) { return String(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function renderComplianceSection(compliance) {
            if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
            return `<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Compliance Frameworks</h4><div class="bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 space-y-2">
                ${compliance.frameworks.map(fw => `
                <div class="flex flex-col gap-1">
                    <span class="text-xs font-semibold text-orange-400">${fw.name}</span>
                    <div class="flex flex-wrap gap-1.5">${fw.controls.map(c => `<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="${c.title}">${c.id}</span>`).join('')}</div>
                </div>`).join('')}
            </div></div>`;
        }

function renderIocTable(iocs) {
            const urls    = (iocs && iocs.urls)    || [];
            const domains = (iocs && iocs.domains) || [];
            const ips     = (iocs && iocs.ips)     || [];
            if (!urls.length && !domains.length && !ips.length) {
                return '<p class="text-neutral-500 text-xs italic">No indicators of compromise reported.</p>';
            }
            const rows = [
                ['URLs',    urls],
                ['Domains', domains],
                ['IPs',     ips],
            ];
            return `
                <table class="w-full text-left text-xs">
                    <tbody class="divide-y divide-neutral-800">
                        ${rows.map(([label, values]) => `
                            <tr>
                                <td class="py-2 pr-4 text-neutral-500 uppercase text-[10px] font-bold align-top whitespace-nowrap">${label}</td>
                                <td class="py-2 break-all">${values.length
                                    ? values.map(val => `<span class="inline-block mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 mr-1 mb-1">${escapeHtmlClient(val)}</span>`).join('')
                                    : '<span class="text-neutral-600 italic">—</span>'}</td>
                            </tr>
                        `).join('')}
                    </tbody>
                </table>
            `;
        }

function renderReachabilitySection(r) {
            if (!r) return '<div class="bg-neutral-900/50 p-4 rounded-lg border border-neutral-800"><p class="text-xs text-neutral-500 italic">Reachability analysis not available.</p></div>';
            const lc={total:'#c084fc',high:'#f87171',medium:'#fb923c',low:'#60a5fa'}[r.level]||'#737373';
            const cc={high:'#4ade80',medium:'#facc15',low:'#737373'}[r.confidence]||'#737373';
            const s=r.signals||{},imp=s.import_scan||{};
            let isHtml='';
            if(imp.searched){
                if(imp.skipped_no_source){isHtml='<span class="text-neutral-500 italic text-[10px]">No source files found</span>';}
                else if(imp.found){
                    const files=(imp.matched_files||[]).slice(0,4).map(f=>`<span class="mono text-[10px] bg-neutral-800 px-2 py-0.5 rounded border border-neutral-700 text-green-300">${f}</span>`).join('');
                    const extra=imp.matched_files.length>4?`<span class="text-neutral-500 text-[10px]">+${imp.matched_files.length-4} more</span>`:'';
                    isHtml=`<div class="flex flex-wrap gap-1 mt-1">${files}${extra}</div>`;
                }else{
                    const pe=Object.entries(imp.parent_scans||{}).filter(([,ps])=>ps.found);
                    if(pe.length){
                        const pi=pe.slice(0,3).map(([purl,ps])=>`<div class="text-[10px] bg-neutral-800 px-2 py-1 rounded border border-orange-500/30"><span class="text-orange-300 font-medium">${purl.split('/').pop().split('@')[0]}</span><span class="text-neutral-500 ml-1">via ${(ps.matched_files||[]).slice(0,2).join(', ')}</span></div>`).join('');
                        isHtml=`<div class="mt-1 space-y-1"><p class="text-[10px] text-neutral-400 mb-1">Direct import not found - reachable via parent(s):</p>${pi}</div>`;
                    }else{isHtml=`<span class="text-neutral-500 italic text-[10px]">Not imported in ${imp.files_scanned} file(s) scanned</span>`;}
                }
            }else{isHtml='<span class="text-neutral-600 italic text-[10px]">Source scan not performed</span>';}
            const tags=(r.tags||[]).map(t=>`<span class="mono text-[9px] bg-neutral-800 px-1.5 py-0.5 rounded border border-neutral-700 text-neutral-400">${t}</span>`).join('');
            return `<div class="space-y-3"><div class="flex flex-wrap gap-4"><span class="text-[10px] uppercase text-neutral-500 font-bold">Reachable: </span><span class="font-bold text-sm" style="color:${r.reachable?'#f87171':'#4ade80'}">${r.reachable?'YES':'NO'}</span><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold mono" style="color:${lc};border-color:${lc}">${r.level}</span><span class="text-[10px] font-semibold" style="color:${cc}">${r.confidence.toUpperCase()} confidence</span></div><div class="grid grid-cols-3 md:grid-cols-6 gap-2 text-[10px]"><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Depth</p><p class="mono">${s.depth!=null?s.depth:'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">AV</p><p class="mono">${s.attack_vector||'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Scope</p><p class="mono">${s.scope||'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Orphan</p><p class="mono">${s.is_orphan_tool?'yes':'no'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Paths</p><p class="mono">${s.num_paths!=null?s.num_paths:'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Non-Lib</p><p class="mono">${s.is_non_library?'yes':'no'}</p></div></div><div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Import Scan</p>${isHtml}</div><p class="text-xs text-neutral-300 bg-neutral-900/50 px-3 py-2 rounded border border-neutral-800 italic">${r.rationale}</p>${tags?'<div class="flex flex-wrap gap-1">'+tags+'</div>':''}</div>`;
        }

function renderThreatIntelSection(v) {
            const kevCell = v.is_kev === true
                ? '<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold text-red-400 border-red-400">KEV</span>'
                : (v.is_kev === false ? '<span class="text-xs mono text-neutral-400">No</span>' : '<span class="text-xs mono text-neutral-500">Unknown</span>');
            const cell = (label, inner) => '<div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">' + label + '</p>' + inner + '</div>';
            const txt  = (x) => '<p class="text-xs mono">' + (x == null ? '—' : tiEsc(x)) + '</p>';
            return '<div class="grid grid-cols-2 md:grid-cols-5 gap-4 pb-4 border-b border-neutral-800">'
                + cell('Known Exploited', kevCell)
                + cell('KEV Added', txt(v.kev_added))
                + cell('KEV Deadline', txt(v.kev_deadline))
                + cell('EPSS Score', txt(v.epss_score == null ? null : fmtPct(v.epss_score)))
                + cell('EPSS Percentile', txt(v.epss_percentile == null ? null : fmtPct(v.epss_percentile)))
                + '</div>';
        }

function renderVulnPolicyViolations(v) {
            const list = Array.isArray(v.policy_violations) ? v.policy_violations : [];
            let body;
            if (list.length === 0) {
                body = '<p class="text-xs text-neutral-500 italic">No policy violations' + (v.policy_exempt === 'unreachable' ? ' (exempt: confirmed unreachable, reachable_only is on).' : '.') + '</p>';
            } else {
                body = '<table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr><th class="pb-2 pr-4 font-bold">Rule</th><th class="pb-2 font-bold">Why it was violated</th></tr></thead><tbody class="divide-y divide-neutral-800">'
                    + list.map(function(x) {
                        return '<tr><td class="py-2 pr-4 align-top whitespace-nowrap">' + policyRuleBadge(x) + '</td><td class="py-2 text-neutral-300">' + escapeHtmlClient(x.detail || '') + '</td></tr>';
                    }).join('')
                    + '</tbody></table>';
            }
            return '<div><h4 class="text-sm font-semibold mb-3 text-neutral-300">Policy Violations (' + list.length + ')</h4><div class="bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">' + body + '</div></div>';
        }

function openVulnModal(key) {
            // key = finding_key (one finding instance); a bare advisory id still works.
            const v = findVuln(key);
            if (!v) return;

            // CVSS block: the provider's named severity (badge) is kept apart from the
            // numeric CVSS score / vector, which an advisory may not supply at all.
            const sevLabel = String(v.severity || 'unknown');
            const cvssBlock = hasCvssScore(v)
                ? '<p class="text-3xl font-bold text-red-500">' + parseFloat(v.severity_score).toFixed(1) + '</p>'
                : '<p class="text-sm font-medium text-neutral-400 max-w-[14rem] ml-auto">' + NOT_PROVIDED + '</p>'
                  + (sevLabel !== 'unknown'
                      ? '<p class="text-[10px] text-neutral-500 mt-1">Severity <span class="uppercase font-bold">' + escapeHtmlClient(sevLabel) + '</span> is the provider’s rating, not derived from a CVSS score.</p>'
                      : '<p class="text-[10px] text-neutral-500 mt-1">No severity rating either (unrated).</p>');
            const vectorBlock = hasCvssVector(v)
                ? '<p class="text-[10px] mono text-neutral-400 truncate" title="' + escapeHtmlClient(v.severity_vector) + '">' + escapeHtmlClient(v.severity_vector) + '</p>'
                : '<p class="text-xs text-neutral-500 italic">' + NOT_PROVIDED + '</p>';

            const modalBody = document.getElementById('modal-body');
            modalBody.innerHTML = `
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-3 mb-2">
                                <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${v.severity}">${v.severity}</span>
                                <h2 class="text-2xl font-bold mono"><a href="${v.url}" target="_blank" class="text-white hover:text-blue-400">${v.id}</a></h2>
                            </div>
                            <p class="text-neutral-400 text-sm">Package: <span class="text-white font-medium">${v.affected_dependency}</span> (${v.affected_dependency_version})</p>
                            ${v.release_confidence ? '<p class="text-[11px] text-neutral-500 mt-1">Release match: ' + releaseConfBadge(v.release_confidence, v.release_confidence_reason) + ' <span class="ml-1">' + escapeHtmlClient(v.release_confidence_reason || '') + '</span></p>' : ''}
                        </div>
                        <div class="text-right"><p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest">CVSS Score</p>${cvssBlock}</div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Published</p><p class="text-xs mono">${fmtAdvisoryDate(v.published)}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Modified</p><p class="text-xs mono">${fmtAdvisoryDate(v.modified)}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">CVSS Vector</p>${vectorBlock}</div>
                    </div>
                    ${renderThreatIntelSection(v)}
                    ${renderVulnPolicyViolations(v)}
                    <div>
                        <h4 class="text-sm font-semibold mb-3 text-neutral-300">Reachability Analysis</h4>
                        ${renderReachabilitySection(v.reachability)}
                    </div>
                    ${(v.fix_versions_ranked && v.fix_versions_ranked.length > 0) ? `
                    <div>
                        <h4 class="text-sm font-semibold mb-3 text-green-400">Fix Version Recommendations</h4>
                        <div class="overflow-x-auto rounded-lg border border-neutral-800">
                        <table class="w-full text-xs text-left">
                            <thead class="bg-neutral-800/60 text-neutral-400 uppercase text-[10px] tracking-widest">
                                <tr>
                                    <th class="px-4 py-2">Version</th>
                                    <th class="px-4 py-2">Compatibility</th>
                                    ${v.release_confidence ? '<th class="px-4 py-2" title="Confidence that this version is for the installed distro release">Release match</th>' : ''}
                                    <th class="px-4 py-2">Recommended</th>
                                </tr>
                            </thead>
                            <tbody class="divide-y divide-neutral-800">
                                ${v.fix_versions_ranked.map(r => `
                                <tr class="hover:bg-neutral-800/30 transition-colors ${r.recommended ? 'bg-green-500/5' : ''}">
                                    <td class="px-4 py-2 mono font-medium text-white">${r.version}</td>
                                    <td class="px-4 py-2">
                                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
                                            r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                                            r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                                                  'text-red-400 border-red-400'
                                        }">${r.compatibility_level}</span>
                                    </td>
                                    ${v.release_confidence ? '<td class="px-4 py-2">' + releaseConfBadge(r.release_confidence, r.release_confidence_reason) + '</td>' : ''}
                                    <td class="px-4 py-2">
                                        ${r.recommended
                                            ? `<span class="flex items-center gap-1 text-green-400 font-semibold"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>`
                                            : `<span class="text-neutral-500">—</span>`}
                                    </td>
                                </tr>`).join('')}
                            </tbody>
                        </table>
                        </div>
                    </div>` : (v.fixes && v.fixes.length > 0 ? `<div><h4 class="text-sm font-semibold mb-2 text-green-400">Recommended Fixes</h4><ul class="space-y-2">${v.fixes.map(f => `<li class="text-xs bg-green-500/10 border border-green-500/20 p-3 rounded-lg text-green-300 mono">${f}</li>`).join('')}</ul></div>` : '')}
                    ${(v.last_affected_ranked && v.last_affected_ranked.length > 0) ? `
                    <div class="mt-4">
                        <h4 class="text-sm font-semibold mb-1 text-orange-400">Last Affected Versions</h4>
                        <p class="text-xs text-neutral-500 mb-3">No fixed version is available. These are the last known affected versions — upgrade to any version strictly above the highest entry shown.</p>
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
                                <tr class="hover:bg-neutral-800/30 transition-colors ${r.recommended ? 'bg-orange-500/5' : ''}">
                                    <td class="px-4 py-2 mono font-medium text-white">${r.version}</td>
                                    <td class="px-4 py-2">
                                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold ${
                                            r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                                            r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                                                  'text-red-400 border-red-400'
                                        }">${r.compatibility_level}</span>
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
                    ${(v.cwes && v.cwes.length > 0) ? `<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Weaknesses (CWE)</h4><div class="flex flex-wrap gap-2">${v.cwes.map(c => `<a href="https://cwe.mitre.org/data/definitions/${c}.html" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-orange-400 hover:text-orange-300 mono">CWE-${c}</a>`).join('')}</div></div>` : ''}
                    ${renderComplianceSection(v.compliance)}
                    ${v.iocs ? `<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Indicators of Compromise</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">${renderIocTable(v.iocs)}</div></div>` : ''}
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4><div class="flex flex-wrap gap-2">${(v.references || []).map(r => `<a href="${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">${r.type}</a>`).join('')}</div></div>
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">${v.description || '<span class="italic text-neutral-500">No description provided.</span>'}</div></div>
                </div>
            `;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

function nodeLabel(id) { return String(id == null ? '' : id).replace(/^pkg:[^/]+\//, ''); }
function extraBlocks(v) {
  const by = v.detected_by || null;
  const seqs = Array.isArray(v.affected_dependency_sequences) ? v.affected_dependency_sequences : [];
  let html = '';
  if (by && (by.description || by.resource)) {
    html += '<div class="mt-6"><h4 class="text-sm font-semibold mb-2 text-neutral-300">Found by</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">'
      + '<p class="text-xs mono text-neutral-500 mb-1">' + escapeHtmlClient(by.check || '') + (by.scope ? ' · ' + escapeHtmlClient(by.scope) : '') + '</p>'
      + '<p>' + escapeHtmlClient(by.resource || '') + '</p></div></div>';
  }
  if (seqs.length) {
    html += '<div class="mt-6"><h4 class="text-sm font-semibold mb-2 text-neutral-300">Affected dependency sequences (' + seqs.length + ')</h4><div class="border border-neutral-700 rounded-xl bg-black/30 p-3 space-y-3 overflow-y-auto" style="max-height:16rem">'
      + seqs.map(function (sq, n) {
        const nodes = Array.isArray(sq) ? sq : [sq];
        return '<div class="border border-neutral-700 rounded-lg p-3 bg-neutral-900/40"><div class="text-[11px] text-neutral-500 mono mb-2">Sequence #' + (n + 1) + ' · ' + nodes.length + ' package' + (nodes.length === 1 ? '' : 's') + '</div><div class="flex flex-wrap items-center gap-1.5">'
          + nodes.map(function (id, k) { const last = k === nodes.length - 1; return '<span title="' + escapeHtmlClient(id) + '" class="px-2 py-1 rounded border text-xs mono ' + (last ? 'border-red-500/60 text-red-300' : 'border-neutral-700 text-neutral-300') + '">' + escapeHtmlClient(nodeLabel(id)) + '</span>' + (last ? '' : '<span class="text-neutral-600">→</span>'); }).join('')
          + '</div></div>';
      }).join('') + '</div></div>';
  }
  return html;
}

window.UBEL_SC_VULN = {
  open: function (record) {
    if (!record || typeof record !== 'object') return false;
    CURRENT = JSON.parse(JSON.stringify(record));
    openVulnModal(CURRENT.finding_key || CURRENT.id);
    const body = document.getElementById('modal-body');
    const root = body && body.firstElementChild;
    const extra = extraBlocks(CURRENT);
    if (root && extra) root.insertAdjacentHTML('beforeend', extra);
    return true;
  },
};
})();
