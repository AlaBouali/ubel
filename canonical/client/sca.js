/* canonical/client/sca.js — sca/engine.js (inline report template)
 * The functions between "extracted verbatim" markers are copied unchanged from the module's own report template (modals,
 * executive summary, compliance and diff renderers, with the helpers they call). Only the data shim and the glue are new:
 * the shim rebuilds the module's own report shape (every canonical entry's `details` is the original entry), the glue says
 * which module modal a canonical finding / inventory entry opens. Requires the CANON constant (the canonical report). */

// ── data: the module report shape, rebuilt from the canonical report ──
// assignFindingKeys — verbatim from sca/engine.js (the report generator runs it on the vulnerabilities before rendering)
function assignFindingKeys(vulns) {
  const seen = new Set();
  for (const v of vulns || []) {
    if (!v) continue;
    const component = v.affected_package_id
      || `${v.affected_dependency || "unknown"}@${v.affected_dependency_version || ""}`;
    const base = (typeof v.finding_key === "string" && v.finding_key) ? v.finding_key : `${v.id}::${component}`;
    let key = base;
    for (let n = 2; seen.has(key); n++) key = `${base}#${n}`;
    seen.add(key);
    v.finding_key = key;
  }
  return vulns;
}

const SCA_FINDING_REF = new Map();   // canonical finding index -> the original vulnerability object
const reportData = (function (C) {
  const vulns = [];
  C.findings.forEach(function (f, i) {
    // sc_vuln / sc_infection are what the SCA adapter emits; vuln / infection are accepted too so canonical JSON written earlier still renders
    if (f.type === 'sc_vuln' || f.type === 'sc_infection' || f.type === 'vuln' || f.type === 'infection') { const v = JSON.parse(JSON.stringify(f.details)); vulns.push(v); SCA_FINDING_REF.set(i, v); }
  });
  assignFindingKeys(vulns);
  const secrets = C.findings.filter(function (f) { return f.type === 'secret'; }).map(function (f) { return f.details; });
  const st = C.stats || {};
  return {
    vulnerabilities: vulns,
    inventory: C.inventory.map(function (x) { return x.details; }),
    secrets: { enabled: true, count: secrets.length, findings: secrets },
    compliance_summary: C.compliance_summary,
    executive_summary: C.executive_summary,
    diffs: st.diffs || { enabled: false },
  };
})(CANON);

// ── extracted verbatim from sca/engine.js (inline report template) ──
function riskBadge(risk) {
            const riskColor = {
                low: 'text-green-400 border-green-400/40',
                medium: 'text-yellow-400 border-yellow-400/40',
                high: 'text-red-400 border-red-400/40',
                unknown: 'text-neutral-400 border-neutral-600'
            }[risk] || 'text-neutral-400 border-neutral-600';
            return `<span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ${riskColor}">${risk || 'unknown'}</span>`;
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

function renderVulnTransitiveTable(list) {
            if (!Array.isArray(list) || list.length === 0) {
                return '<p class="text-neutral-500 text-xs italic">No vulnerable transitive dependencies.</p>';
            }
            const rows = list.map(dep => `
                <tr class="${hasInvTarget(dep.id) ? 'cursor-pointer hover:bg-neutral-800/40 transition-colors' : ''}"${hasInvTarget(dep.id) ? refAttr('inv', dep.id) : ' title="' + REF_MISSING_TITLE + '"'}>
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

function escapeHtmlClient(str) {
            if (!str || typeof str !== 'string') return str || '';
            return str.replace(/[&<>"']/g, (m) => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[m]));
        }

function findingKeyOf(v) {
            return v ? (v.finding_key || (v.id + '::' + (v.affected_package_id || ''))) : '';
        }

function findVuln(key) {
            const list = reportData.vulnerabilities || [];
            return list.find(function (x) { return x.finding_key === key; })
                || list.find(function (x) { return findingKeyOf(x) === key; })
                || list.find(function (x) { return x.id === key; });
        }

// ── references between modals ──
// A clickable reference inside a modal (a package chip, a vulnerability row, a dependency-sequence node) carries data-ref / data-key
// instead of an inline handler, and one delegated listener on #modal-body (bindModalRefs) opens the target. The id is only ever an
// attribute value, never code, so an id containing a quote cannot break the markup. The target is looked up BEFORE anything changes:
// a reference to something that is not in the report (a virtual or uninstalled package that a Debian package depends on) is drawn as
// plain text, and a click that still cannot be resolved leaves the current modal open instead of closing it.
function refAttr(kind, key) {
            return ' data-ref="' + kind + '" data-key="' + escapeHtmlClient(String(key == null ? '' : key)) + '"';
        }

function hasInvTarget(id) {
            return reportData.inventory.some(function (x) { return x.id === id; });
        }

function vulnRefAttr(key) { return refAttr('vuln', key); }

// The key of a vulnerability reference: its finding_key, else <id>::<package> when that finding exists, else the bare advisory id.
function vulnKeyFor(findingKey, id, pkgId) {
            if (findingKey) return findingKey;
            if (pkgId && findVuln(id + '::' + pkgId)) return id + '::' + pkgId;
            return id;
        }

const REF_CHIP = 'mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700';
const REF_MISSING_TITLE = 'Not in this report&#39;s inventory (for example a virtual or uninstalled package)';

function invChip(id, label) {
            const text = escapeHtmlClient(String(label == null || label === '' ? id : label));
            return hasInvTarget(id)
                ? '<span class="' + REF_CHIP + ' cursor-pointer hover:border-neutral-500 transition-colors"' + refAttr('inv', id) + '>' + text + '</span>'
                : '<span class="' + REF_CHIP + ' text-neutral-500" title="' + REF_MISSING_TITLE + '">' + text + '</span>';
        }

function openModalRef(kind, key) {
            if (kind === 'vuln') {
                if (!findVuln(key)) return false;
                openVulnModal(key);
            } else if (kind === 'inv') {
                if (!hasInvTarget(key)) return false;
                openInvModal(key);
            } else {
                return false;
            }
            if (typeof cnModalScrollTop === 'function') cnModalScrollTop();
            return true;
        }

function bindModalRefs() {
            const body = document.getElementById('modal-body');
            if (!body || body.dataset.refsBound) return;
            body.dataset.refsBound = '1';
            body.addEventListener('click', function (e) {
                const el = e.target && e.target.closest ? e.target.closest('[data-ref]') : null;
                if (!el || !body.contains(el)) return;
                e.stopPropagation();
                openModalRef(el.getAttribute('data-ref'), el.getAttribute('data-key'));
            });
        }

const NOT_PROVIDED = 'Not provided by the advisory source';

function hasCvssScore(v) {
            return v && v.severity_score != null && v.severity_score !== '' && !isNaN(parseFloat(v.severity_score));
        }

function hasCvssVector(v) {
            return v && typeof v.severity_vector === 'string' && v.severity_vector.trim() !== '';
        }

function fmtAdvisoryDate(d) {
            if (!d) return NOT_PROVIDED;
            const t = new Date(d);
            return isNaN(t.getTime()) ? NOT_PROVIDED : t.toLocaleDateString();
        }

function getPackageDisplay(purl) {
            const inv = reportData.inventory.find(x => x.id === purl);
            if (inv) return `${inv.name}@${inv.version}`;
            const parts = purl.split('/').pop();
            return parts || purl;
        }

function renderSequences(pkg, containerEl) {
            const container = containerEl || document.getElementById('sequences-container');
            if (!container) return;

            if (!pkg || !pkg.sequences || pkg.sequences.length === 0) {
                container.innerHTML = '<div class="text-neutral-500 italic text-center p-8">No dependency sequences available for this package.</div>';
                return;
            }

            let html = '<div class="space-y-6">';
            pkg.sequences.forEach((sequence, idx) => {
                html += '<div class="border border-neutral-700 rounded-lg p-4 bg-neutral-900/30">';
                html += `<div class="text-xs text-neutral-400 mb-3 font-mono">Sequence #${idx+1}</div>`;
                html += '<div class="flex flex-wrap items-center gap-2">';

                sequence.forEach((node, i) => {
                    const display = getPackageDisplay(node);
                    const isLast = i === sequence.length - 1;
                    html += `
                        <div class="bg-neutral-800 px-3 py-1.5 rounded-lg border border-neutral-700 text-sm font-mono transition-colors ${hasInvTarget(node) ? 'hover:bg-neutral-700 cursor-pointer' : 'text-neutral-500'}"${hasInvTarget(node) ? refAttr('inv', node) : ' title="' + REF_MISSING_TITLE + '"'}>
                            ${escapeHtml(display)}
                        </div>
                    `;
                    if (!isLast) {
                        html += '<span class="text-neutral-500 text-lg">→</span>';
                    }
                });

                html += '</div></div>';
            });
            html += '</div>';
            container.innerHTML = html;
        }

function escapeHtml(str) {
            if (!str) return '';
            return str.replace(/[&<>]/g, function(m) {
                if (m === '&') return '&amp;';
                if (m === '<') return '&lt;';
                if (m === '>') return '&gt;';
                return m;
            });
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
          // How much of the license picture is actually known (only when there is a gap).
          if (bl.license_callout) {
            const lc = bl.license_callout;
            html += '<div class="glass p-4 rounded-xl flex flex-wrap items-center gap-4" style="border-left:4px solid ' + col(lc.tone) + '">' +
              '<div class="shrink-0"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">License coverage</p>' +
              '<p class="text-3xl font-bold" style="color:' + col(lc.tone) + '">' + esc(lc.percent) + '%</p></div>' +
              '<p class="text-sm text-neutral-300 leading-relaxed flex-1 min-w-[16rem]">' + esc(lc.statement) + '</p></div>';
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

          // License review: confirmed risk and missing evidence, kept apart.
          const lr = es.license_review;
          if (lr) {
            const openInv = function (id) {
              return 'openInvModal(' + JSON.stringify(String(id)).replace(/&/g, '&amp;').replace(/"/g, '&quot;') + ')';
            };
            const metric = function (label, value, sub, tone) {
              return figure({ label: label, value: value, sub: sub, tone: tone });
            };
            html += '<div>' + sectionTitle('License review') +
              '<div class="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-4">' +
                metric('License coverage', lr.coverage_percent + '%', lr.identified + ' of ' + lr.total + ' components have an identified license', lr.unidentified === 0 ? 'none' : 'medium') +
                metric('Confirmed license risk', lr.by_risk.high + lr.by_risk.medium, lr.by_risk.high + ' high, ' + lr.by_risk.medium + ' medium; a license was identified and rated', (lr.by_risk.high + lr.by_risk.medium) > 0 ? 'medium' : 'none') +
                metric('Low risk', lr.by_risk.low, 'Identified license with few obligations', '') +
                metric('Not identified', lr.unidentified, 'No recognizable license; not rated, not cleared', lr.unidentified > 0 ? 'unknown' : 'none') +
              '</div>';

            if ((lr.confirmed_risk_components || []).length) {
              html += '<h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-500 mb-2">Components with confirmed license risk (' + lr.confirmed_risk_components.length + ')</h4>' +
                '<div class="glass rounded-xl overflow-auto max-h-80 mb-4"><table class="w-full text-left text-xs">' +
                '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr><th class="px-4 py-2">Component</th><th class="px-4 py-2">Version</th><th class="px-4 py-2">License</th><th class="px-4 py-2">Risk</th></tr></thead>' +
                '<tbody class="divide-y divide-neutral-800">' +
                lr.confirmed_risk_components.map(function (c) {
                  return '<tr class="cursor-pointer hover:bg-neutral-800/40" onclick="' + openInv(c.id) + '">' +
                    '<td class="px-4 py-2 font-medium">' + esc(c.name) + '</td>' +
                    '<td class="px-4 py-2 mono text-neutral-400">' + esc(c.version) + '</td>' +
                    '<td class="px-4 py-2 mono text-neutral-300">' + esc(c.license || 'n/a') + '</td>' +
                    '<td class="px-4 py-2">' + badge(c.risk === 'high' ? 'high' : 'medium', c.risk) + '</td></tr>';
                }).join('') + '</tbody></table></div>';
            }

            html += '<details class="glass rounded-xl"' + (lr.unidentified > 0 && lr.unidentified <= 25 ? ' open' : '') + '>' +
              '<summary class="cursor-pointer px-5 py-4 text-sm font-semibold select-none">Components needing license review (' + lr.unidentified + ')' +
              '<span class="ml-2 text-xs font-normal text-neutral-500">no recognizable license; not counted as risky</span></summary>';
            if ((lr.needs_review || []).length) {
              html += '<div class="overflow-auto max-h-96 border-t border-neutral-800"><table class="w-full text-left text-xs">' +
                '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr><th class="px-4 py-2">Component</th><th class="px-4 py-2">Version</th><th class="px-4 py-2">Type</th><th class="px-4 py-2">Declared</th><th class="px-4 py-2">Why unidentified</th></tr></thead>' +
                '<tbody class="divide-y divide-neutral-800">' +
                lr.needs_review.map(function (c) {
                  return '<tr class="cursor-pointer hover:bg-neutral-800/40" onclick="' + openInv(c.id) + '">' +
                    '<td class="px-4 py-2 font-medium">' + esc(c.name) + '</td>' +
                    '<td class="px-4 py-2 mono text-neutral-400">' + esc(c.version) + '</td>' +
                    '<td class="px-4 py-2 text-neutral-400">' + (c.direct ? 'Direct' : 'Transitive') + '</td>' +
                    '<td class="px-4 py-2 mono text-neutral-400">' + esc(c.declared || 'none') + '</td>' +
                    '<td class="px-4 py-2 text-neutral-500">' + esc(c.reason || '') + '</td></tr>';
                }).join('') + '</tbody></table></div>';
            } else {
              html += '<p class="px-5 pb-4 text-sm text-neutral-500 italic">Every component has an identified license.</p>';
            }
            html += '</details></div>';
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
              const major = o.scope === 'major';
              return '<li class="flex flex-wrap items-center gap-x-2 gap-y-1">' +
                '<span class="mono text-neutral-100">' + esc(o.version) + '</span>' +
                (o.recommended ? badge('none', 'Best') : '') +
                (major ? badge('medium', 'Major') : '') +
                '<span class="text-neutral-400" title="Policy-violating issues of this component">fixes ' + esc(o.resolves) + ' of ' + esc(o.of) + ' violating' +
                (o.known_exploited_total ? ' (' + esc(o.resolves_known_exploited) + ' of ' + esc(o.known_exploited_total) + ' exploited)' : '') +
                '</span></li>';
            }).join('');
            return '<div class="mt-3 pt-2 border-t border-neutral-800"><div class="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Possible fixes</div>' +
              '<ul class="space-y-1 text-[11px]">' + rows + '</ul>' +
              (c.fix_options_more ? '<div class="text-[10px] text-neutral-500 mt-1">+' + esc(c.fix_options_more) + ' more in the Inventory tab</div>' : '') +
              (c.no_fix_yet ? '<div class="text-[10px] text-neutral-500 mt-1">' + esc(c.no_fix_yet) + ' ' + (c.no_fix_yet === 1 ? 'policy-violating issue has' : 'policy-violating issues have') + ' no published fix yet.</div>' : '') +
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

function hasComplianceControl(item, fwName, controlId) {
            const fws = item && item.compliance && item.compliance.frameworks;
            return !!fws && fws.some(f => f.name === fwName && (f.controls || []).some(c => c.id === controlId));
        }

function complianceMatchesFor(fwName, controlId) {
            const pick = (list) => (list || []).filter(x => hasComplianceControl(x, fwName, controlId));
            return {
                vulns: pick(reportData.vulnerabilities),
                secrets: pick((reportData.secrets || {}).findings),
            };
        }

function complianceStatsFromMatches(matches) {
            const cves = new Set();
            const components = new Set();
            for (const v of matches.vulns) {
                cves.add(v.id);
                components.add(v.affected_package_id);
            }
            return {
                cveCount: cves.size,
                componentCount: components.size,
                matchCount: matches.vulns.length,
                secretCount: matches.secrets.length,
            };
        }

function complianceFrameworkTotals(fw) {
            const acc = { vulns: new Set(), secrets: new Set() };
            for (const c of (fw.controls || [])) {
                const m = complianceMatchesFor(fw.name, c.id);
                m.vulns.forEach(x => acc.vulns.add(x));
                m.secrets.forEach(x => acc.secrets.add(x));
            }
            return complianceStatsFromMatches({ vulns: [...acc.vulns], secrets: [...acc.secrets] });
        }

function complianceCountsHtml(stats, primaryClass, compact) {
            const line = (cls, text) => `<span class="${cls}">${text}</span>`;
            const minor = 'mono text-neutral-500 text-[10px]';
            const out = [];
            if (stats.cveCount) {
                out.push(line(primaryClass, stats.cveCount + ' CVE' + (stats.cveCount === 1 ? '' : 's')));
                out.push(line(minor, stats.componentCount + (compact ? ' comp.' : ' component' + (stats.componentCount === 1 ? '' : 's'))));
            }
            if (stats.secretCount) out.push(line(primaryClass, stats.secretCount + ' secret' + (stats.secretCount === 1 ? '' : 's')));
            if (!out.length) out.push(line(primaryClass, '0'));
            return out.join('');
        }

function renderCompliance() {
            const cs = reportData.compliance_summary;
            document.getElementById('compliance-disclaimer').textContent = cs?.disclaimer || '';
            const grid = document.getElementById('compliance-frameworks-grid');
            if (!cs || !cs.frameworks || !cs.frameworks.length) {
                document.getElementById('compliance-empty').classList.remove('hidden');
                grid.innerHTML = '';
                return;
            }
            grid.innerHTML = cs.frameworks.map((fw, fwIdx) => `
                <div class="glass p-6 rounded-xl space-y-4">
                    <div class="flex items-start justify-between gap-3">
                        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">${fw.name}</h3>
                        <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">${complianceCountsHtml(complianceFrameworkTotals(fw), 'mono text-red-400 font-semibold text-xs', false)}</div>
                    </div>
                    <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                        ${fw.controls.map((c, cIdx) => `
                        <div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" onclick="openComplianceModal(${fwIdx}, ${cIdx})">
                            <div class="flex flex-col min-w-0">
                                <span class="mono text-red-400">${c.id}</span>
                                <span class="text-neutral-500">${c.title}</span>
                            </div>
                            <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">${complianceCountsHtml(complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id)), 'mono text-neutral-200', true)}</div>
                        </div>`).join('')}
                    </div>
                </div>`).join('');
        }

function openComplianceModal(fwIdx, cIdx) {
            const cs = reportData.compliance_summary;
            const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
            const control = fw && fw.controls && fw.controls[cIdx];
            if (!fw || !control) return;

            const mapsToControl = (item) => !!(item.compliance && item.compliance.frameworks &&
                item.compliance.frameworks.some(f => f.name === fw.name && f.controls.some(c => c.id === control.id)));

            const vulnMatches = (reportData.vulnerabilities || []).filter(mapsToControl);
            const secretMatches = ((reportData.secrets || {}).findings || []).filter(mapsToControl);

            const vulnRows = vulnMatches.map(v => `
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" ${vulnRefAttr(findingKeyOf(v))}>
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
                </div>`).join('');

            const secretRows = secretMatches.map(f => `
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 px-2 rounded">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${(f.severity || 'unknown').toLowerCase()}">${escapeHtml(f.severity || 'unknown')}</span>
                        <span class="text-xs text-white">${escapeHtml(f.title || 'Secret finding')}</span>
                    </div>
                    <span class="mono text-[10px] text-neutral-500">${escapeHtml(f.file_path || '')}</span>
                </div>`).join('');

            const emptyRow = (!vulnMatches.length && !secretMatches.length)
                ? '<p class="text-sm text-neutral-500 italic py-2">No findings mapped to this control.</p>' : '';

            const modalStats = complianceStatsFromMatches({ vulns: vulnMatches, secrets: secretMatches });
            const modalBits = [];
            if (modalStats.cveCount) {
                modalBits.push(
                    modalStats.cveCount + (modalStats.cveCount === 1 ? ' distinct CVE' : ' distinct CVEs') +
                    ' across ' + modalStats.componentCount + (modalStats.componentCount === 1 ? ' component' : ' components') +
                    (modalStats.matchCount !== modalStats.cveCount ? ' (' + modalStats.matchCount + ' component-CVE pairs total)' : '')
                );
            }
            if (modalStats.secretCount) {
                modalBits.push(modalStats.secretCount + (modalStats.secretCount === 1 ? ' exposed secret' : ' exposed secrets'));
            }

            document.getElementById('modal-body').innerHTML = `
                <div class="space-y-4">
                    <div>
                        <div class="flex items-center gap-3 mb-1 flex-wrap">
                            <span class="mono text-red-400 text-sm">${control.id}</span>
                            <h2 class="text-lg font-semibold text-white">${control.title}</h2>
                        </div>
                        <p class="text-xs text-neutral-500">${fw.name}${fw.version ? ' · ' + fw.version : ''}${modalBits.length ? ' — ' + modalBits.join('; ') : ''}</p>
                    </div>
                    <div>${vulnRows}${secretRows}${emptyRow}</div>
                </div>
            `;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

function releaseConfBadge(level, reason) {
            if (!level) return '<span class="text-neutral-600">—</span>';
            const cls = level === 'high' ? 'text-green-400 border-green-400'
                      : level === 'medium' ? 'text-yellow-400 border-yellow-400'
                      : 'text-red-400 border-red-400';
            return '<span title="' + escapeHtml(String(reason || '')) + '" class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold ' + cls + '">' + escapeHtml(String(level)) + '</span>';
        }

function renderSuggestedFixes(sf, pkgId) {
            if (!sf) return '<p class="text-neutral-500 text-xs italic">No suggested-fix data available.</p>';
            const fixes = sf.fixes || [];
            const unfixed = sf.unfixed || [];
            // Key of one finding instance; older reports without finding_key fall back to the id.
            const openVuln = function(v) { return vulnRefAttr(vulnKeyFor(v.finding_key, v.id, pkgId)); };
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
                                return '<div class="flex items-center gap-2 whitespace-nowrap cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1"' + openVuln(v) + '>' +
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
                        return '<tr class="cursor-pointer hover:bg-neutral-800/40"' + openVuln(v) + '>' +
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

function openInvModal(id) {
            const item = reportData.inventory.find(x => x.id === id);
            if (!item) return;

            const itemVulns = reportData.vulnerabilities.filter(v => v.affected_package_id === item.id);
            const stateColor = item.state === 'safe' ? 'text-green-400'
                             : item.state === 'infected' ? 'text-red-400'
                             : 'text-yellow-400';

            const vulnRows = itemVulns.length ? itemVulns.map(v => `
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" ${vulnRefAttr(findingKeyOf(v))}>
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

            // dependency sequences of this component: the ones carried by its vulnerabilities (deduplicated), else its own
            const invSeqs = (function () {
                const seen = new Set(), out = [];
                const add = function (seq) {
                    if (!Array.isArray(seq) || !seq.length) return;
                    const k = seq.join('\u0001');
                    if (seen.has(k)) return;
                    seen.add(k); out.push(seq);
                };
                itemVulns.forEach(function (v) { (Array.isArray(v.affected_dependency_sequences) ? v.affected_dependency_sequences : []).forEach(add); });
                if (!out.length && Array.isArray(item.sequences)) item.sequences.forEach(add);
                return out;
            })();

            const introRows = (item.introduced_by || []).length
                ? (item.introduced_by).map(ib => invChip(ib, ib)).join('')
                : '<span class="text-neutral-500 text-xs italic">Direct dependency</span>';

            const parentsRows = (item.parents || []).length
                ? item.parents.map(p => {
                    const par = reportData.inventory.find(x => x.id === p);
                    return invChip(p, par ? par.name + '@' + par.version : p);
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
                    const dep = reportData.inventory.find(x => x.id === d);
                    return invChip(d, dep ? dep.name + '@' + dep.version : d);
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

                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">License Risk</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">${renderLicenseInfoTable(item.license_info)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By ( root dependencies )</h4><div class="flex flex-wrap gap-2">${introRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Parents / Dependents (${(item.parents || []).length})</h4><div class="flex flex-wrap gap-2">${parentsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (${(item.dependencies || []).length})</h4><div class="flex flex-wrap gap-2">${depsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerable Transitive Dependencies (${(item.vulnerable_transitive_dependencies || []).length})</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">${renderVulnTransitiveTable(item.vulnerable_transitive_dependencies)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4><div class="space-y-1">${pathRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Suggested Fixes</h4>${renderSuggestedFixes(item.suggested_fixes, item.id)}</div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Affected Dependency Sequences (${invSeqs.length})</h4><div id="inv-sequences-container" class="border border-neutral-700 rounded-xl bg-black/30 p-3 overflow-y-auto" style="max-height:16rem"></div></div>
                    ${renderComponentPolicyViolations(item)}
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerabilities (${itemVulns.length})</h4><div class="space-y-0">${vulnRows}</div></div>
                </div>
            `;

            renderSequences({ sequences: invSeqs }, document.getElementById('inv-sequences-container'));

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
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

function tiEsc(x) { return String(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

function fmtPct(x) { return (x == null || isNaN(Number(x))) ? '—' : (Number(x) * 100).toFixed(2) + '%'; }

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

function policyRuleBadge(x) {
            const cls = { infection: 'text-red-400 border-red-400', kev: 'text-red-400 border-red-400', epss: 'text-orange-400 border-orange-400', severity: 'text-yellow-400 border-yellow-400', unknown_severity: 'text-neutral-300 border-neutral-500' }[x.rule] || 'text-neutral-300 border-neutral-500';
            return '<span class="inline-block px-2 py-0.5 rounded border text-[10px] uppercase font-bold ' + cls + '" title="' + escapeHtmlClient(x.detail || '') + '">' + escapeHtmlClient(x.title || x.rule) + '</span>';
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
                        return '<tr class="cursor-pointer hover:bg-neutral-800/40 transition-colors"' + vulnRefAttr(vulnKeyFor(r.finding_key, r.vuln_id, item.id)) + '>'
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

function diffEsc(s) {
            return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
        }

// The module's vulnerability / secret diffs, as the three lists the severity view (client/diffs.js) splits by severity.
// The dependency diff has no severity and is no longer shown. Vulnerability entries carry their own severity and title; entries
// from a report written before that (id / package / version only) are looked up among this report's vulnerabilities, so the ones
// still present keep their severity, and fixed ones from such a report land under "Unknown".
function diffLists(d) {
  var byKey = {};
  (reportData.vulnerabilities || []).forEach(function (v) {
    var k = v.id + '::' + v.affected_dependency + '@' + v.affected_dependency_version;
    if (!(k in byKey)) byKey[k] = v;
  });
  var vuln = function (e) {
    var cur = byKey[e.id + '::' + e.name + '@' + e.version] || {};
    return {
      title: e.title || cur.title || cur.summary || e.id,
      type: 'sc_vuln' + (cur.is_infection ? 'sc_infection' : ''),
      severity: e.severity || (cur.is_infection ? 'infection' : cur.severity)
    };
  };
  var secret = function (e) { return { title: e.title || e.id, type: 'Secret', severity: e.severity }; };
  var pick = function (key) {
    var v = (d.vulns && d.vulns[key]) || [];
    var s = (d.secrets && d.secrets[key === 'existing' ? 'unchanged' : key === 'fixed' ? 'removed' : key]) || [];
    return v.map(vuln).concat(s.map(secret));
  };
  return { 'new': pick('new'), existing: pick('existing'), fixed: pick('fixed') };
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
            if (!d.previous || !d.counts) {
                html += '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
                sec.innerHTML = html;
                return;
            }
            html += UBEL_DIFFS.sectionHtml(diffLists(d), { hint: 'Vulnerabilities' + (d.secrets ? ' and secrets' : '') + ' compared with the previous report, split by severity level. Select a count to list them.' });
            if (!d.secrets) {
                html += '<p class="text-xs text-neutral-500">Secrets changes are not shown: this report or the previous one did not scan for secrets.</p>';
            }
            if (d.compliance && d.compliance.frameworks && d.compliance.frameworks.length) {
                html += '<h3 class="text-lg font-bold pt-4">Compliance frameworks</h3>' +
                    '<p class="text-xs text-neutral-500">Findings mapped to each framework, compared with the previous report' +
                    (d.compliance.includes_secrets ? ' (vulnerabilities and secrets).' : ' (vulnerabilities only: secrets were not scanned in both reports).') + '</p>';
                html += '<div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
                d.compliance.frameworks.forEach(function (fw, fi) {
                    html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + diffEsc(fw.name) + '</p>' +
                        (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + diffEsc(fw.version) + '</p>' : '') + '</div>' +
                        '<div class="grid grid-cols-3 gap-2">';
                    [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(function (g) {
                        html += '<button type="button" onclick="openComplianceDiffModal(' + fi + ',\'' + g[0] + '\')" class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors">' +
                            '<span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + g[1] + '</span>' +
                            '<span class="block text-2xl font-bold mono ' + g[2] + '">' + fw[g[0]].length + '</span></button>';
                    });
                    html += '</div></div>';
                });
                html += '</div>';
            }
            sec.innerHTML = html;
        }

function openComplianceDiffModal(fi, list) {
            var d = reportData.diffs;
            var fw = d && d.compliance && d.compliance.frameworks[fi];
            if (!fw) return;
            var labels = { new: 'New', unchanged: 'Still existing', removed: 'Resolved' };
            var items = fw[list] || [];
            var body;
            if (items.length === 0) {
                body = '<p class="text-sm text-neutral-500 italic">None.</p>';
            } else {
                body = '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' +
                    ['Type', 'ID', 'Severity', 'Title', 'Component / File', 'Controls'].map(function (c) { return '<th class="pb-2 pr-4 font-bold">' + c + '</th>'; }).join('') +
                    '</tr></thead><tbody class="divide-y divide-neutral-800">' +
                    items.map(function (e) {
                        return '<tr><td class="py-2 pr-4 text-neutral-400">' + (e.kind === 'secret' ? 'Secret' : 'Vulnerability') + '</td>' +
                            '<td class="py-2 pr-4 mono">' + diffEsc(e.id) + '</td>' +
                            '<td class="py-2 pr-4 uppercase text-[10px] font-bold severity-' + diffEsc((e.severity || 'unknown').toLowerCase()) + '">' + diffEsc(e.severity || 'unknown') + '</td>' +
                            '<td class="py-2 pr-4 font-medium">' + diffEsc(e.title) + '</td>' +
                            '<td class="py-2 pr-4 mono text-neutral-400">' + diffEsc(e.where) + '</td>' +
                            '<td class="py-2 pr-4 mono text-neutral-500">' + diffEsc(e.controls) + '</td></tr>';
                    }).join('') + '</tbody></table></div>';
            }
            document.getElementById('modal-body').innerHTML =
                '<h3 class="text-lg font-bold mb-1">' + diffEsc(fw.name) + ' — ' + labels[list] + '</h3>' +
                '<p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body;
            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

// ── glue: canonical entry → module modal ──
function showPackageDetails(id) { openModalRef('inv', id); }   // a sequence node's click: opens the component, and only if it exists
const FAMILY = {
  openFinding: function (i) {
    const v = SCA_FINDING_REF.get(i); if (!v) return false;
    openVulnModal(findingKeyOf(v));
    return true;
  },
  openInventory: function (i) { const d = CANON.inventory[i].details; if (!d || !d.id) return false; openInvModal(d.id); return true; },
  executive: function () { renderExecutiveSummary(); },
  compliance: function () { renderCompliance(); },
  diffs: function () { renderDiffs(); },
  bind: bindModalRefs,
  // Policy tab: SCA does not show policy violations there. shell.js cnRenderPolicy passes CANON.policy through this; every key
  // that mentions a violation (violations, policy_violations, is_policy_violation, violated_rules …) is dropped at any depth.
  prunePolicy: function (policy) {
    const isViol = function (k) { return /violat/i.test(String(k)); };
    const prune = function (v) {
      if (Array.isArray(v)) return v.map(prune);
      if (v && typeof v === 'object') {
        const o = {};
        Object.keys(v).forEach(function (k) { if (!isViol(k)) o[k] = prune(v[k]); });
        return o;
      }
      return v;
    };
    return prune(policy || {});
  },
};