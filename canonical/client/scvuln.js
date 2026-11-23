/* canonical/client/scvuln.js — the SCA vulnerability modal and the SCA package modal, for the reports of the modules that take their package
 * vulnerabilities from the SCA engine (ubel-vm, ubel-runtime, ubel-k8s): findings of type sc_vuln / sc_infection whose `details` is the SCA
 * vulnerability record, and dependency inventory entries whose `details` is the SCA inventory item (ubel-vm lists every installed package).
 * The renderers below are extracted verbatim from client/sca.js (openVulnModal, openInvModal and what they call); the only change is that
 * they read the report data from RD, which is built from this report's CANON (findings + inventory) instead of the SCA report's reportData.
 * Two blocks that only these reports have are added to the vulnerability modal: which check found the package and where, and the
 * dependency sequences. Exposed as window.UBEL_SC_VULN.open(record) and .openInventory(item); the inline handlers of the modals
 * (openVulnModal / openInvModal) are defined on window when the page has none of its own. */
(function () {
'use strict';
const NOT_PROVIDED = 'Not provided by the advisory source';
const RD = { vulnerabilities: [], inventory: [] };
let BUILT = false;

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

function riskBadge(risk) {
            const riskColor = {
                low: 'text-green-400 border-green-400/40',
                medium: 'text-yellow-400 border-yellow-400/40',
                high: 'text-red-400 border-red-400/40',
                unknown: 'text-neutral-400 border-neutral-600'
            }[risk] || 'text-neutral-400 border-neutral-600';
            return `<span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${riskColor}">${risk || 'unknown'}</span>`;
        }

function tiEsc(x) { return String(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function findVuln(key) {
            const list = RD.vulnerabilities || [];
            return list.find(function (x) { return x.finding_key === key; })
                || list.find(function (x) { return x.id === key; });
        }

function findingKeyOf(v) {
            return v ? (v.finding_key || (v.id + '::' + (v.affected_package_id || ''))) : '';
        }

function vulnOnclick(key) {
            const arg = JSON.stringify(String(key == null ? '' : key)).replace(/&/g, '&amp;').replace(/"/g, '&quot;');
            return 'event.stopPropagation(); closeModal(); setTimeout(function () { openVulnModal(' + arg + '); }, 50)';
        }

function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

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

function renderLicenseInfoTable(licenseInfo) {
            if (!licenseInfo || typeof licenseInfo !== 'object') {
                return '<p class="text-neutral-500 text-xs italic">No license classification available.</p>';
            }
            const osiLabel = licenseInfo.osi_approved === true ? 'Yes'
                : licenseInfo.osi_approved === false ? 'No'
                : 'Unverified';
            const rows = [
                ['SPDX', escapeHtmlClient(licenseInfo.spdx || '—')],
                ['Identifiers', escapeHtmlClient((licenseInfo.identifiers || []).join(', ') || '—')],
                ['OSI Approved', osiLabel],
                ['Risk', riskBadge(licenseInfo.risk)],
                ['Category', escapeHtmlClient(licenseInfo.category || '—')],
                ['Reason', escapeHtmlClient(licenseInfo.reason || '—')],
            ];
            return `
                <table class="w-full text-left text-xs">
                    <tbody class="divide-y divide-neutral-800">
                        ${rows.map(([k, v]) => `
                            <tr>
                                <td class="py-1.5 pr-4 text-neutral-500 uppercase text-[10px] font-bold align-top whitespace-nowrap">${k}</td>
                                <td class="py-1.5 mono">${v}</td>
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

function renderSuggestedFixes(sf) {
            if (!sf) return '<p class="text-neutral-500 text-xs italic">No suggested-fix data available.</p>';
            const fixes = sf.fixes || [];
            const unfixed = sf.unfixed || [];
            // Key of one finding instance; older reports without finding_key fall back to the id.
            const openVuln = function(v) { return vulnOnclick(v.finding_key || v.id); };
            const sevBadge = function(v) {
                const sev = v.is_infection ? 'critical' : (v.severity || 'unknown');
                const label = v.is_infection ? 'infection' : sev;
                return '<span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold severity-' + escapeHtml(String(sev)) + '">' + escapeHtml(String(label)) + '</span>';
            };

            let html = '';

            if (fixes.length) {
                // One row per suggested version: range | version | vulnerabilities, side by side.
                const rangeRows = {};
                fixes.forEach(function(f) { const k = f.range ? f.range.key : ''; rangeRows[k] = (rangeRows[k] || 0) + 1; });
                const rangeSeen = {};
                const anyConf = fixes.some(function(f) { return !!f.release_confidence; });
                html += '<div class="rounded-lg border border-neutral-800 overflow-auto max-h-96">' +
                    '<table class="w-full min-w-full text-xs text-left border-collapse">' +
                    '<thead class="bg-neutral-800 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr>' +
                    '<th class="px-3 py-2 whitespace-nowrap w-px">Range</th>' +
                    '<th class="px-3 py-2 whitespace-nowrap w-px">Suggested version</th>' +
                    (anyConf ? '<th class="px-3 py-2 whitespace-nowrap w-px" title="Confidence that this version is for the installed distro release">Release match</th>' : '') +
                    '<th class="px-3 py-2">Policy-violating vulnerabilities fixed</th>' +
                    '</tr></thead><tbody>' +
                    fixes.map(function(f) {
                        const k = f.range ? f.range.key : '';
                        let rangeCell = '';
                        if (!rangeSeen[k]) {
                            rangeSeen[k] = true;
                            rangeCell = '<td rowspan="' + rangeRows[k] + '" class="px-3 py-2 align-top whitespace-nowrap border-t border-neutral-800 bg-neutral-900/60">' +
                                '<div class="mono text-xs text-neutral-200">' + escapeHtml(f.range ? f.range.label : '—') + '</div>' +
                                '<div class="text-[10px] uppercase tracking-widest text-neutral-500 mt-0.5">' + (f.range && f.range.scope === 'major' ? 'major range' : 'minor range') + '</div></td>';
                        }
                        return '<tr>' + rangeCell +
                            '<td class="px-3 py-2 align-top whitespace-nowrap border-t border-l border-neutral-800">' +
                            '<span class="mono text-sm font-bold text-green-400">' + escapeHtml(String(f.version)) + '</span>' +
                            '<span class="ml-2 text-[10px] text-neutral-500" title="Policy-violating vulnerabilities fixed by this version">fixes ' + f.count + ' violating</span></td>' +
                            (anyConf ? '<td class="px-3 py-2 align-top whitespace-nowrap border-t border-l border-neutral-800">' + releaseConfBadge(f.release_confidence, f.release_confidence_reason) + '</td>' : '') +
                            '<td class="px-3 py-2 align-top border-t border-l border-neutral-800"><div class="flex flex-wrap gap-x-4 gap-y-1.5">' +
                            (f.vulnerabilities || []).map(function(v) {
                                return '<div class="flex items-center gap-2 whitespace-nowrap cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1" onclick="' + openVuln(v) + '">' +
                                    '<span class="mono text-xs text-white">' + escapeHtml(String(v.id)) + '</span>' + sevBadge(v) + '</div>';
                            }).join('') +
                            '</div></td></tr>';
                    }).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="text-neutral-500 text-xs italic">No upgrade version fixes any policy-violating vulnerability of this package.</p>';
            }

            html += '<h5 class="text-[10px] font-semibold uppercase tracking-widest text-neutral-500 mt-4 mb-2">Policy-violating vulnerabilities with no fix (' + unfixed.length + ')</h5>';
            if (unfixed.length) {
                html += '<div class="rounded-lg border border-neutral-800 overflow-auto max-h-48">' +
                    '<table class="w-full text-xs text-left">' +
                    '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr><th class="px-3 py-2">ID</th><th class="px-3 py-2">Severity</th>' + (unfixed.some(function(v) { return !!v.release_confidence; }) ? '<th class="px-3 py-2">Release match</th>' : '') + '<th class="px-3 py-2 text-right">Score</th></tr></thead>' +
                    '<tbody class="divide-y divide-neutral-800">' +
                    unfixed.map(function(v) {
                        return '<tr class="cursor-pointer hover:bg-neutral-800/40" onclick="' + openVuln(v) + '">' +
                            '<td class="px-3 py-2 mono text-white">' + escapeHtml(String(v.id)) + '</td>' +
                            '<td class="px-3 py-2">' + sevBadge(v) + '</td>' +
                            (v.release_confidence ? '<td class="px-3 py-2">' + releaseConfBadge(v.release_confidence, '') + '</td>' : (unfixed.some(function(u) { return !!u.release_confidence; }) ? '<td class="px-3 py-2">—</td>' : '')) +
                            '<td class="px-3 py-2 mono text-neutral-400 text-right">' + (v.severity_score != null ? Number(v.severity_score).toFixed(1) : '—') + '</td></tr>';
                    }).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="text-neutral-500 text-xs italic">None — every policy-violating vulnerability has a published fix.</p>';
            }
            return html;
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

function renderVulnTransitiveTable(list) {
            if (!Array.isArray(list) || list.length === 0) {
                return '<p class="text-neutral-500 text-xs italic">No vulnerable transitive dependencies.</p>';
            }
            const rows = list.map(dep => `
                <tr class="cursor-pointer hover:bg-neutral-800/40 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${dep.id}'), 50)">
                    <td class="py-2 pr-4 mono">${escapeHtmlClient(dep.name)}</td>
                    <td class="py-2 pr-4 text-neutral-400">${dep.vulns_count}</td>
                    <td class="py-2">${dep.is_policy_violation
                        ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Yes</span>'
                        : '<span class="text-[10px] text-neutral-500">No</span>'}</td>
                </tr>
            `).join('');
            return `
                <table class="w-full text-left text-xs">
                    <thead class="text-neutral-500 uppercase text-[10px] tracking-widest">
                        <tr><th class="pb-2 pr-4 font-bold">Name</th><th class="pb-2 pr-4 font-bold">Vulns</th><th class="pb-2 font-bold">Policy Violation</th></tr>
                    </thead>
                    <tbody class="divide-y divide-neutral-800">${rows}</tbody>
                </table>
            `;
        }

function renderComponentPolicyViolations(item) {
            const list = Array.isArray(item.policy_violations) ? item.policy_violations : [];
            let body;
            if (list.length === 0) {
                body = item.policy_violation_inherited
                    ? '<p class="text-xs text-neutral-400">None of the vulnerabilities in this component violate policy on their own. It is flagged because a vulnerable dependency does (see Vulnerable Transitive Dependencies).</p>'
                    : '<p class="text-xs text-neutral-500 italic">No policy violations.</p>';
            } else {
                body = '<table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr><th class="pb-2 pr-4 font-bold">Vulnerability</th><th class="pb-2 pr-4 font-bold">Severity</th><th class="pb-2 font-bold">Violations</th></tr></thead><tbody class="divide-y divide-neutral-800">'
                    + list.map(function(r) {
                        return '<tr class="cursor-pointer hover:bg-neutral-800/40 transition-colors" onclick="' + vulnOnclick(r.finding_key || r.vuln_id) + '">'
                            + '<td class="py-2 pr-4 align-top mono text-white">' + escapeHtmlClient(r.vuln_id) + '</td>'
                            + '<td class="py-2 pr-4 align-top"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-' + escapeHtmlClient(r.severity) + '">' + escapeHtmlClient(r.severity) + '</span></td>'
                            + '<td class="py-2"><div class="flex flex-col gap-1.5">'
                            + (r.violations || []).map(function(x) {
                                return '<div class="flex flex-wrap items-center gap-2">' + policyRuleBadge(x) + '<span class="text-neutral-400">' + escapeHtmlClient(x.detail || '') + '</span></div>';
                            }).join('')
                            + '</div></td></tr>';
                    }).join('')
                    + '</tbody></table>';
            }
            return '<div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Policy Violations (' + list.length + ')</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">' + body + '</div></div>';
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

/* Package details (ubel-vm): what the package is — carried on the inventory item as `package_info` (read from the dpkg / apk / rpm database or from the
 * package's own manifest) next to `source_name` / `source_version`. Everything in it is data of the scanned machine, so it is escaped and links are
 * limited to http(s). Items without it (an SCA report's) render nothing. */
const PI_LABELS = [
  ['description', 'Description'], ['summary', 'Summary'], ['long_description', 'Details'],
  ['source_package', 'Source package'], ['origin', 'Origin'], ['source_rpm', 'Source RPM'],
  ['architecture', 'Architecture'], ['section', 'Section'], ['priority', 'Priority'], ['group', 'Group'], ['essential', 'Essential'], ['multi_arch', 'Multi-Arch'],
  ['installed_as', 'Installed as'], ['package_manager', 'Package manager'], ['maintainer', 'Maintainer'], ['vendor', 'Vendor'], ['packager', 'Packager'],
  ['author', 'Author'], ['maintainers', 'Maintainers'], ['homepage', 'Homepage'], ['license_declared', 'Declared license'],
  ['installed_size_kb', 'Installed size'], ['installed_size_bytes', 'Installed size'], ['package_size_bytes', 'Package size'], ['file_count', 'Files owned'],
  ['installed_at', 'Installed / modified'], ['install_time', 'Installed'], ['build_time', 'Built'], ['commit', 'Build commit'], ['epoch', 'Epoch'],
  ['location', 'Location'], ['locations', 'Install locations'], ['main', 'Entry point'], ['requires_python', 'Requires Python'], ['engines', 'Engines'],
  ['runtime_dependencies', 'Runtime dependencies'], ['optional_dependencies', 'Optional dependencies'], ['deprecated', 'Deprecated'],
];
const PI_LISTS = [
  ['install_scripts', 'Install-time scripts', true], ['executables', 'Executables', false], ['pre_depends', 'Pre-Depends', false], ['depends', 'Depends', false], ['recommends', 'Recommends', false],
  ['suggests', 'Suggests', false], ['provides', 'Provides', false], ['conflicts', 'Conflicts', false], ['replaces', 'Replaces', false], ['conffiles', 'Config files', false], ['project_urls', 'Project URLs', false],
];
function piFmt(k, v) {
  if (k === 'installed_size_kb') return Number(v) >= 1024 ? (Number(v) / 1024).toFixed(1) + ' MB' : Number(v) + ' KB';
  if (k === 'installed_size_bytes' || k === 'package_size_bytes') { const n = Number(v); return n >= 1048576 ? (n / 1048576).toFixed(1) + ' MB' : n >= 1024 ? (n / 1024).toFixed(1) + ' KB' : n + ' B'; }
  if (k === 'installed_at' || k === 'install_time' || k === 'build_time') { const t = new Date(v); return isNaN(t.getTime()) ? String(v) : t.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC'); }
  if (typeof v === 'boolean') return v ? 'Yes' : 'No';
  return Array.isArray(v) ? v.join(', ') : String(v);
}
function safeHref(u) { return /^https?:\/\/[^\s"'<>]+$/i.test(String(u || '')) ? String(u) : null; }
function renderPackageDetails(item) {
  const info = item && item.package_info && typeof item.package_info === 'object' ? item.package_info : null;
  if (!info || !Object.keys(info).length) return '';
  const e = escapeHtmlClient;
  const shown = new Set(['links', 'source_version']);
  const rows = [];
  const wide = new Set(['description', 'summary', 'long_description']);
  PI_LABELS.forEach(function (pair) {
    const k = pair[0]; const v = info[k];
    if (v === undefined || v === null || v === '' || (Array.isArray(v) && !v.length) || (k === 'installed_size_bytes' && info.installed_size_kb != null)) return;
    shown.add(k);
    let val;
    if (k === 'homepage' && safeHref(v)) val = '<a href="' + e(safeHref(v)) + '" target="_blank" rel="noopener noreferrer" class="text-blue-400 hover:underline">' + e(v) + '</a>';
    else if (k === 'source_package' && item.source_version) val = e(v) + ' <span class="text-neutral-500">' + e(item.source_version) + '</span>';
    else val = e(piFmt(k, v));
    rows.push('<div class="' + (wide.has(k) ? 'md:col-span-2 ' : '') + 'bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">' + e(pair[1]) + '</p><p class="mono text-xs break-words">' + val + '</p></div>');
  });
  PI_LISTS.forEach(function (t) { shown.add(t[0]); });
  Object.keys(info).forEach(function (k) {                                   // anything a reader added that has no label yet
    if (shown.has(k) || info[k] === null || typeof info[k] === 'object') return;
    rows.push('<div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">' + e(k.replace(/_/g, ' ')) + '</p><p class="mono text-xs break-words">' + e(piFmt(k, info[k])) + '</p></div>');
  });
  const lists = PI_LISTS.map(function (t) {
    const a = info[t[0]];
    if (!Array.isArray(a) || !a.length) return '';
    const chips = a.map(function (x) { return '<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border ' + (t[2] ? 'border-yellow-500/60 text-yellow-300' : 'border-neutral-700') + ' break-all">' + e(String(x)) + '</span>'; }).join('');
    return '<div class="mt-4"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-2">' + e(t[1]) + ' (' + a.length + (a.length >= 25 ? '+' : '') + ')</p><div class="flex flex-wrap gap-2">' + chips + '</div></div>';
  }).join('');
  const links = (Array.isArray(info.links) ? info.links : []).filter(function (l) { return l && safeHref(l.url); }).map(function (l) {
    return '<a href="' + e(safeHref(l.url)) + '" target="_blank" rel="noopener noreferrer" class="text-xs text-blue-400 hover:underline border border-neutral-700 rounded px-2 py-1">' + e(l.label || l.url) + ' ↗</a>';
  }).join('');
  return '<div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Package Details</h4>'
    + (rows.length ? '<div class="grid grid-cols-1 md:grid-cols-2 gap-3">' + rows.join('') + '</div>' : '') + lists
    + (links ? '<div class="flex flex-wrap gap-2 mt-4">' + links + '</div>' : '') + '</div>';
}

function openInvModal(id) {
            const item = RD.inventory.find(x => x.id === id);
            if (!item) return;

            const itemVulns = RD.vulnerabilities.filter(v => v.affected_package_id === item.id);
            const stateColor = item.state === 'safe' ? 'text-green-400'
                             : item.state === 'infected' ? 'text-red-400'
                             : 'text-yellow-400';

            const vulnRows = itemVulns.length ? itemVulns.map(v => `
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="${vulnOnclick(findingKeyOf(v))}">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${v.severity}">${v.severity}</span>
                        <span class="mono text-xs text-white">${v.id}</span>
                    </div>
                    <div class="flex items-center gap-3">
                        ${v.severity_score != null ? `<span class="mono text-xs text-neutral-400">${parseFloat(v.severity_score).toFixed(1)}</span>` : ''}
                        ${v.is_kev ? '<span class="text-[10px] font-bold text-red-400 border border-red-400 rounded px-1.5 py-0.5">KEV</span>' : ''}
                        ${v.is_policy_violation ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Policy Block</span>' : '<span class="text-[10px] text-neutral-500">Allowed</span>'}
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>
            `).join('') : '<p class="text-sm text-neutral-500 italic py-2">No vulnerabilities found.</p>';

            const introRows = (item.introduced_by || []).length
                ? (item.introduced_by).map(ib => `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${ib}'), 50)">${ib}</span>`).join('')
                : '<span class="text-neutral-500 text-xs italic">Direct dependency</span>';

            const parentsRows = (item.parents || []).length
                ? item.parents.map(p => {
                    const par = RD.inventory.find(x => x.id === p);
                    return `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 cursor-pointer hover:border-neutral-500 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${p}'), 50)">${par ? par.name + '@' + par.version : p}</span>`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No dependents (root)</span>';

            const pathRows = (item.paths || []).length
                ? item.paths.map(p => {
                    const isObj = p && typeof p === 'object' && p.type === 'system_path';
                    const text  = isObj ? p.text  : String(p ?? '');
                    return `
                      <div class="mono text-[10px] text-neutral-400 bg-neutral-900 px-2 py-1.5 rounded border border-neutral-800 break-all space-y-0.5">
                        <div class="text-neutral-300">${text}</div>
                      </div>`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No path info</span>';

            const depsRows = (item.dependencies || []).length
                ? item.dependencies.map(d => {
                    const dep = RD.inventory.find(x => x.id === d);
                    return `<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 cursor-pointer hover:border-neutral-500 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('${d}'), 50)">${dep ? dep.name + '@' + dep.version : d}</span>`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No dependencies</span>';

            document.getElementById('modal-body').innerHTML = `
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4 flex-wrap">
                        <div>
                            <div class="flex items-center gap-3 mb-1 flex-wrap">
                                <span class="text-[10px] uppercase font-bold ${stateColor} border border-current px-2 py-0.5 rounded">${item.state}</span>
                                <h2 class="text-xl font-bold">${item.name}</h2>
                                <span class="mono text-neutral-400 text-sm">v${item.version}</span>
                            </div>
                            <p class="mono text-[11px] text-neutral-500 break-all">${item.id}</p>
                        </div>
                        <div class="text-right shrink-0">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Ecosystem</p>
                            <p class="mono text-sm">${item.ecosystem}</p>
                        </div>
                    </div>

                    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">${item.type || 'library'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">License</p><p class="mono text-xs">${item.license || 'unknown'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Scopes</p><p class="mono text-xs">${(item.scopes || []).join(', ') || '—'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Policy Violation</p><p class="text-lg font-bold ${item.is_policy_violation ? 'text-red-400' : 'text-green-400'}">${item.is_policy_violation ? 'Yes' : 'No'}</p></div>
                    </div>

                    ${renderPackageDetails(item)}
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">License Risk</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">${renderLicenseInfoTable(item.license_info)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By ( root dependencies )</h4><div class="flex flex-wrap gap-2">${introRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Parents / Dependents (${(item.parents || []).length})</h4><div class="flex flex-wrap gap-2">${parentsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (${(item.dependencies || []).length})</h4><div class="flex flex-wrap gap-2">${depsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerable Transitive Dependencies (${(item.vulnerable_transitive_dependencies || []).length})</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">${renderVulnTransitiveTable(item.vulnerable_transitive_dependencies)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4><div class="space-y-1">${pathRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Suggested Fixes</h4>${renderSuggestedFixes(item.suggested_fixes)}</div>
                    ${renderComponentPolicyViolations(item)}
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerabilities (${itemVulns.length})</h4><div class="space-y-0">${vulnRows}</div></div>
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
  if (v.source_package && v.source_package !== v.affected_dependency) {     // OS package: the advisory is keyed by the source package it was built from
    html += '<div class="mt-6"><h4 class="text-sm font-semibold mb-2 text-neutral-300">Matched through source package</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">'
      + '<span class="mono text-neutral-200">' + escapeHtmlClient(v.affected_dependency || '') + '</span> is built from the source package <span class="mono text-neutral-200">' + escapeHtmlClient(v.source_package) + (v.source_package_version ? ' ' + escapeHtmlClient(v.source_package_version) : '') + '</span>, which the distribution\'s advisories are filed under; the fixed versions are that source package\'s.</div></div>';
  }
  if (by && (by.description || by.resource)) {
    html += '<div class="mt-6"><h4 class="text-sm font-semibold mb-2 text-neutral-300">Found by</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800">'
      + '<p class="text-xs mono text-neutral-500 mb-1">' + escapeHtmlClient(by.check || '') + (by.scope ? ' · ' + escapeHtmlClient(by.scope) : '') + '</p>'
      + '<p>' + escapeHtmlClient(by.resource || '') + '</p></div></div>';
  }
  if (seqs.length) {
    html += '<div class="mt-6"><h4 class="text-sm font-semibold mb-2 text-neutral-300">Affected dependency sequences (' + (v.affected_dependency_sequences_total && v.affected_dependency_sequences_total > seqs.length ? 'shortest ' + seqs.length + ' of ' + v.affected_dependency_sequences_total : seqs.length) + ')</h4><div class="border border-neutral-700 rounded-xl bg-black/30 p-3 space-y-3 overflow-y-auto" style="max-height:16rem">'
      + seqs.map(function (sq, n) {
        const nodes = Array.isArray(sq) ? sq : [sq];
        return '<div class="border border-neutral-700 rounded-lg p-3 bg-neutral-900/40"><div class="text-[11px] text-neutral-500 mono mb-2">Sequence #' + (n + 1) + ' · ' + nodes.length + ' package' + (nodes.length === 1 ? '' : 's') + '</div><div class="flex flex-wrap items-center gap-1.5">'
          + nodes.map(function (id, k) { const last = k === nodes.length - 1; return '<span title="' + escapeHtmlClient(id) + '" class="px-2 py-1 rounded border text-xs mono ' + (last ? 'border-red-500/60 text-red-300' : 'border-neutral-700 text-neutral-300') + '">' + escapeHtmlClient(nodeLabel(id)) + '</span>' + (last ? '' : '<span class="text-neutral-600">→</span>'); }).join('')
          + '</div></div>';
      }).join('') + '</div></div>';
  }
  return html;
}

/* RD from this report: the SCA records of the sc_vuln / sc_infection findings and the SCA items of the package inventory */
function build() {
  if (BUILT) return;
  BUILT = true;
  const C = (typeof CANON !== 'undefined' && CANON) || {};
  (C.findings || []).forEach(function (f) { if ((f.type === 'sc_vuln' || f.type === 'sc_infection') && f.details) RD.vulnerabilities.push(f.details); });
  (C.inventory || []).forEach(function (c) { if (c.type === 'dependency' && c.details && String(c.details.id || '').indexOf('pkg:') === 0 && c.details.state) RD.inventory.push(c.details); });
}

const openVulnModalSca = openVulnModal;
function openVulnWithExtras(key) {
  build();
  openVulnModalSca(key);
  const v = findVuln(key);
  const body = document.getElementById('modal-body');
  const root = body && body.firstElementChild;
  const extra = v ? extraBlocks(v) : '';
  if (root && extra) root.insertAdjacentHTML('beforeend', extra);
}
const openInvModalSca = openInvModal;
function openInvWithData(id) { build(); openInvModalSca(id); }
if (typeof window.openVulnModal !== 'function') window.openVulnModal = openVulnWithExtras;
if (typeof window.openInvModal !== 'function') window.openInvModal = openInvWithData;

window.UBEL_SC_VULN = {
  /** The SCA vulnerability modal for a record (the `details` of an sc_vuln / sc_infection finding). */
  open: function (record) {
    if (!record || typeof record !== 'object') return false;
    build();
    const key = findingKeyOf(record);
    if (!findVuln(key)) RD.vulnerabilities.push(JSON.parse(JSON.stringify(record)));
    openVulnWithExtras(key);
    return true;
  },
  /** The SCA package modal for an inventory item (the `details` of a dependency inventory entry); false when it is not an SCA package item. */
  openInventory: function (item) {
    if (!item || typeof item !== 'object' || String(item.id || '').indexOf('pkg:') !== 0 || !item.state) return false;
    build();
    if (!RD.inventory.some(function (x) { return x.id === item.id; })) RD.inventory.push(item);
    openInvWithData(item.id);
    return true;
  },
  /** For the tests: the data the modals read. */
  data: RD,
};
})();
