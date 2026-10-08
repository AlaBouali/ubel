import fs      from "fs";
import path    from "path";
import https   from "https";
import http, { get }    from "http";
import { fileURLToPath } from "url";
import { NodeManager }          from "./node_runner.js";
import { processVulnerability } from "./cvss_parser.js";
import { evaluatePolicy }       from "./policy.js";
import {TOOL_NAME, TOOL_LICENSE, TOOL_VERSION }   from "./info.js";
import { dictToStr }            from "./utils.js";
import {getOSMetadata}          from "./os_metadata.js";
import {getGitMetadata, getEditorVersion}         from "./git_info.js";
import {filterFalsePositiveInfections} from "./filter_false_positive_infections.js";
import { CycloneDXBuilder } from "./sbom_builder.js";
import { SarifBuilder } from "./sarif_builder.js"
import { buildZip } from "./zip_writer.js";
import { scanSecrets } from "./secrets.js";
import { enrichReport as enrichReachability } from "./reachability_analyzer.js"
import { findClosestFixVersions, _vr_purlToEcosystem, _vr_parseSemver, _vr_semverGt } from "./version_recommender.js"
import { attachSuggestedFixes } from "./suggested_fixes.js";
import { buildExecutiveSummary } from "./executive_summary.js";
import { enrichInventoryWithLicenseRisk } from "./license_checker.js";
import { getComplianceForVulnerability, getComplianceForSecret, summarizeCompliance } from "./compliance_mappings.js";
import { PypiManagerInstance } from "./pypi_runner.js";
import { LinuxManagerInstance } from "./linux_runner.js";
import { getTailwindScript } from "./tailwindcss.js";
import { getChartJSScript } from "./chartjs.js";
import { getGoogleFontsScript } from "./googlefonts.js";


const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── Cross-module reuse ────────────────────────────────────────────────────────
// A handful of the low-level OSV/NVD query + enrichment primitives below
// (submitToOsv, submitToNvd, getVulnById, getFix, scoreToSeverity,
// getEcosystemFromPurl, deduplicateVulnerabilitiesByAlias,
// sortVulnerabilities) are exported not because UbelEngineInstance itself
// needs them from outside, but so other UBEL modules can drive the same
// vulnerability-scanning core against inventory that didn't come from a
// dependency-tree resolution. The EASM module (../easm/) is the first
// consumer: it feeds CPE ids built from passive HTTP fingerprinting
// (product/version banners, not a package manager) through submitToNvd
// (submitToOsv is a no-op there — it only matches "pkg:"-scheme ids) to get
// the same OSV.dev/NVD-backed CVE data, minus everything that assumes a
// resolvable dependency graph (license classification, dependency
// sequences/tree, reachability analysis — see easm/lib/scan.js).

// OSV API base — overridable via UBEL_OSV_ENDPOINT for self-hosted/air-gapped
// mirrors (e.g. an internal proxy in front of a local OSV database dump).
// Expected to expose the same REST path shape as the public API
// (`/v1/querybatch`, `/v1/vulns/{id}`) — only the host/base path changes.
// This only affects the live vulnerability queries below; the "view
// online" reference links shown in reports (osv.dev/vulnerability/{id})
// are left pointing at the public site regardless, since a private mirror
// generally doesn't serve an equivalent browsable web UI at that path.
const OSV_API_BASE   = (process.env.UBEL_OSV_ENDPOINT || "https://api.osv.dev").replace(/\/+$/, "");
const OSV_QUERYBATCH = `${OSV_API_BASE}/v1/querybatch`;
const OSV_VULN_BASE  = `${OSV_API_BASE}/v1/vulns`;


// ── Network metadata helpers ──────────────────────────────────────────────────

// Synchronous version using the already-imported `os` module via dynamic import
// isn't available at module level — we use Node's built-in synchronously:
import os_module from "os";
import { time } from "console";

function safeJsonString(data, maxSizeMb = 100) {
  const json = JSON.stringify(data, null);
  if (json.length > maxSizeMb * 1024 * 1024) {
    console.warn(`[!] JSON report too large (${(json.length / (1024*1024)).toFixed(1)} MB). Truncating...`);
    // Remove the heaviest field and retry
    const trimmed = { ...data };
    delete trimmed.dependencies_tree;
    delete trimmed.reachability;
    for (const item of trimmed.inventory) {
      if (Array.isArray(item.paths) && item.paths.length > 50) {
        item.paths = item.paths.slice(0, 50);
      }
    }
    return safeJsonString(trimmed, maxSizeMb);
  }
  return json;
}

function safeWriteJson(filePath, data, maxSizeMb = 100) {
  fs.writeFileSync(filePath, safeJsonString(data, maxSizeMb));
}

function getLocalIPsSync() {
  try {
    const ifaces = os_module.networkInterfaces();
    const result = {};
    for (const [name, addrs] of Object.entries(ifaces || {})) {
      for (const addr of addrs) {
        if (addr.family === "IPv4" && !addr.internal) {
          result[name] = addr.address;
        }
      }
    }
    return result;
  } catch {
    return {};
  }
}

/**
 * Wraps a plain filesystem path string into the canonical SystemPath object.
 * Port list is empty at scan time (populated by enrichment tier if needed).
 *
 * @param {string} pathStr   - Absolute or relative filesystem path.
 * @param {string} [hostIp]  - IP of the host that owns this path.
 * @returns {{ type: "system_path", text: string, ip: string, ports: [] }}
 */
function makeSystemPath(pathStr, hostIp = "") {
  return {
    type:  "system_path",
    text:  typeof pathStr === "string" ? pathStr : String(pathStr ?? ""),
    ip:    hostIp,
    ports: [],
  };
}

/**
 * Converts every path in an inventory array from a plain string to a
 * SystemPath object.  Already-converted objects are left unchanged.
 *
 * @param {object[]} inventory
 * @param {string}   hostIp
 */
function normalizeInventoryPaths(inventory, hostIp) {
  for (const item of inventory) {
    if (Array.isArray(item.paths)) {
      item.paths = item.paths.map(p =>
        p && typeof p === "object" && p.type === "system_path"
          ? p
          : makeSystemPath(p, hostIp)
      );
    }
    // Also normalise the legacy singular `path` field if present.
    if (item.path !== undefined && item.path !== null) {
      item.path = typeof item.path === "object" && item.path.type === "system_path"
        ? item.path
        : makeSystemPath(item.path, hostIp);
    }
  }
}


function escapeHTML(str) {
    if (!str || typeof str !== 'string') return str;
    return str.replace(/[&<>"']/g, (m) => ({
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
    }[m]));
}

async function generateHTMLReport(data) {
    // Deep clone data to avoid mutating original
    const reportData = JSON.parse(JSON.stringify(data));

    // Safely escape vulnerability descriptions
    if (reportData.vulnerabilities) {
        reportData.vulnerabilities = reportData.vulnerabilities.map(v => ({
            ...v,
            description: escapeHTML(v.description)
        }));
    }

    // Escape for script tag safety (prevents </script> injection)
    let safeJson = JSON.stringify(reportData).replace(/</g, '\\u003c');
    safeJson = safeJson.replace(/`/g, '\\u0060');

    // The complete client-side script (NEW: graph shows dependency sequences via autocomplete)
    const clientScript = `
        // --- DATA ---
        const reportData = ${safeJson};

        // Helper: render a small risk pill for a license_info.risk value.
        function riskBadge(risk) {
            const riskColor = {
                low: 'text-green-400 border-green-400/40',
                medium: 'text-yellow-400 border-yellow-400/40',
                high: 'text-red-400 border-red-400/40',
                unknown: 'text-neutral-400 border-neutral-600'
            }[risk] || 'text-neutral-400 border-neutral-600';
            return \`<span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold \${riskColor}">\${risk || 'unknown'}</span>\`;
        }

        // Helper: render an item's license_info classification object (see
        // license_checker.js on the backend) as a small key/value table.
        // Falls back gracefully if a report predates this field.
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
            return \`
                <table class="w-full text-left text-xs">
                    <tbody class="divide-y divide-neutral-800">
                        \${rows.map(([k, v]) => \`
                            <tr>
                                <td class="py-1.5 pr-4 text-neutral-500 uppercase text-[10px] font-bold align-top whitespace-nowrap">\${k}</td>
                                <td class="py-1.5 mono">\${v}</td>
                            </tr>
                        \`).join('')}
                    </tbody>
                </table>
            \`;
        }

        function renderVulnTransitiveTable(list) {
            if (!Array.isArray(list) || list.length === 0) {
                return '<p class="text-neutral-500 text-xs italic">No vulnerable transitive dependencies.</p>';
            }
            const rows = list.map(dep => \`
                <tr class="cursor-pointer hover:bg-neutral-800/40 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('\${dep.id}'), 50)">
                    <td class="py-2 pr-4 mono">\${escapeHtmlClient(dep.name)}</td>
                    <td class="py-2 pr-4 text-neutral-400">\${dep.vulns_count}</td>
                    <td class="py-2">\${dep.is_policy_violation
                        ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Yes</span>'
                        : '<span class="text-[10px] text-neutral-500">No</span>'}</td>
                </tr>
            \`).join('');
            return \`
                <table class="w-full text-left text-xs">
                    <thead class="text-neutral-500 uppercase text-[10px] tracking-widest">
                        <tr><th class="pb-2 pr-4 font-bold">Name</th><th class="pb-2 pr-4 font-bold">Vulns</th><th class="pb-2 font-bold">Policy Violation</th></tr>
                    </thead>
                    <tbody class="divide-y divide-neutral-800">\${rows}</tbody>
                </table>
            \`;
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
            return \`
                <table class="w-full text-left text-xs">
                    <tbody class="divide-y divide-neutral-800">
                        \${rows.map(([label, values]) => \`
                            <tr>
                                <td class="py-2 pr-4 text-neutral-500 uppercase text-[10px] font-bold align-top whitespace-nowrap">\${label}</td>
                                <td class="py-2 break-all">\${values.length
                                    ? values.map(val => \`<span class="inline-block mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 mr-1 mb-1">\${escapeHtmlClient(val)}</span>\`).join('')
                                    : '<span class="text-neutral-600 italic">—</span>'}</td>
                            </tr>
                        \`).join('')}
                    </tbody>
                </table>
            \`;
        }

        function escapeHtmlClient(str) {
            if (!str || typeof str !== 'string') return str || '';
            return str.replace(/[&<>"']/g, (m) => ({
                '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
            }[m]));
        }

        // Helper: get package display name from inventory
        function getPackageDisplay(purl) {
            const inv = reportData.inventory.find(x => x.id === purl);
            if (inv) return \`\${inv.name}@\${inv.version}\`;
            const parts = purl.split('/').pop();
            return parts || purl;
        }

        // Build list of vulnerable/infected packages from findings_summary
        function getVulnerableInfectedPackages() {
            const summary = reportData.findings_summary || {};
            return Object.values(summary).map(pkg => ({
                id: pkg.name + '@' + pkg.version,
                name: pkg.name,
                version: pkg.version,
                ecosystem: pkg.ecosystem,
                stats: pkg.stats || {},
                sequences: pkg.affected_dependency_sequences || []
            }));
        }

        let currentSelectedPkg = null;

        // Render all sequences for a selected package
        function renderSequences(pkg) {
            const container = document.getElementById('sequences-container');
            if (!container) return;

            if (!pkg || !pkg.sequences || pkg.sequences.length === 0) {
                container.innerHTML = '<div class="text-neutral-500 italic text-center p-8">No dependency sequences available for this package.</div>';
                return;
            }

            let html = '<div class="space-y-6">';
            pkg.sequences.forEach((sequence, idx) => {
                html += '<div class="border border-neutral-700 rounded-lg p-4 bg-neutral-900/30">';
                html += \`<div class="text-xs text-neutral-400 mb-3 font-mono">Sequence #\${idx+1}</div>\`;
                html += '<div class="flex flex-wrap items-center gap-2">';

                sequence.forEach((node, i) => {
                    const display = getPackageDisplay(node);
                    const isLast = i === sequence.length - 1;
                    html += \`
                        <div class="bg-neutral-800 px-3 py-1.5 rounded-lg border border-neutral-700 text-sm font-mono hover:bg-neutral-700 transition-colors cursor-pointer" onclick="showPackageDetails('\${escapeHtml(node)}')">
                            \${escapeHtml(display)}
                        </div>
                    \`;
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

        function showPackageDetails(purl) {
            const item = reportData.inventory.find(x => x.id === purl);
            if (item) {
                openInvModal(item.id);
            } else {
                // try to find by name@version
                const [name, version] = purl.split('@');
                const match = reportData.inventory.find(x => x.name === name && x.version === version);
                if (match) openInvModal(match.id);
            }
        }

        // Build the elegant display label: name ( ecosystem ) [vuln/inf]
        function pkgDisplayLabel(pkg) {
            return \`\${pkg.name}\`;
        }

        // Sorted package list: infected first, then by vuln count desc
        function getSortedPackages() {
            return getVulnerableInfectedPackages().slice().sort((a, b) => {
                const aInf = (a.stats || {}).infection || 0;
                const bInf = (b.stats || {}).infection || 0;
                if (aInf !== bInf) return bInf - aInf;
                const vuln = s => ((s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0)+(s.unknown||0));
                return vuln(b.stats||{}) - vuln(a.stats||{});
            });
        }

        // Custom dropdown helpers
        function openPkgDropdown() {
            const list = document.getElementById('pkg-options-list');
            const chevron = document.getElementById('pkg-chevron');
            if (!list) return;
            list.classList.remove('hidden');
            if (chevron) chevron.style.transform = 'rotate(180deg)';
        }

        function closePkgDropdown() {
            const list = document.getElementById('pkg-options-list');
            const chevron = document.getElementById('pkg-chevron');
            if (list) list.classList.add('hidden');
            if (chevron) chevron.style.transform = '';
        }

        function renderPkgList(pkgs) {
            const list = document.getElementById('pkg-options-list');
            if (!list) return;
            list.innerHTML = '';
            if (pkgs.length === 0) {
                list.innerHTML = '<li class="px-4 py-3 text-xs text-neutral-500 italic">No matches found.</li>';
                return;
            }
            pkgs.forEach(pkg => {
                const label = pkgDisplayLabel(pkg);
                const s = pkg.stats || {};
                const vulnCount = (s.critical||0)+(s.high||0)+(s.medium||0)+(s.low||0)+(s.unknown||0);
                const infCount = s.infection || 0;
                const badgeColor = infCount > 0 ? 'text-red-400 bg-red-500/10 border-red-500/30'
                                 : vulnCount > 0 ? 'text-orange-400 bg-orange-500/10 border-orange-500/30'
                                 : 'text-neutral-500 bg-neutral-800 border-neutral-700';
                const badgeText = infCount > 0 && vulnCount > 0 ? \`\${vulnCount}v \${infCount}i\`
                                : vulnCount > 0 ? \`\${vulnCount} vuln\`
                                : \`\${infCount} inf\`;
                const li = document.createElement('li');
                li.role = 'option';
                li.className = 'flex items-center justify-between px-4 py-2.5 text-sm cursor-pointer hover:bg-neutral-800 transition-colors gap-3';
                li.innerHTML = \`
                    <span class="font-medium text-white truncate">\${escapeHtml(pkg.name)} ( \${escapeHtml(pkg.ecosystem)} )</span>
                    <span class="shrink-0 text-[10px] font-semibold px-2 py-0.5 rounded border \${badgeColor}">\${badgeText}</span>
                \`;
                li.addEventListener('mousedown', (e) => {
                    e.preventDefault(); // keep focus on input, register click before blur
                    selectPkgOption(pkg.id, label);
                });
                list.appendChild(li);
            });
        }

        function filterPkgDropdown(query) {
            const q = query.trim().toLowerCase();
            const all = getSortedPackages();
            const filtered = q ? all.filter(p =>
                p.name.toLowerCase().includes(q) || p.ecosystem.toLowerCase().includes(q)
            ) : all;
            renderPkgList(filtered);
            openPkgDropdown();
        }

        function selectPkgOption(pkgId, label) {
            const input = document.getElementById('pkg-select-input');
            if (input) input.value = label;
            closePkgDropdown();
            currentSelectedPkg = null;
            handlePackageSelect(pkgId);
        }

        // Populate custom dropdown list
        function populatePackageSelect() {
            const pkgs = getSortedPackages();
            renderPkgList(pkgs);

            // Auto-select first package if any
            if (pkgs.length > 0 && !currentSelectedPkg) {
                const first = pkgs[0];
                const input = document.getElementById('pkg-select-input');
                if (input) input.value = pkgDisplayLabel(first);
                handlePackageSelect(first.id);
            } else if (pkgs.length === 0) {
                const container = document.getElementById('sequences-container');
                if (container) container.innerHTML = '<div class="text-neutral-500 italic text-center p-8">No vulnerable or infected packages found.</div>';
            }
        }



        function handlePackageSelect(pkgId) {
            if (!pkgId) return;
            const pkgs = getVulnerableInfectedPackages();
            const pkg = pkgs.find(p => p.id === pkgId);
            if (pkg) {
                currentSelectedPkg = pkg;
                renderSequences(pkg);
            }
        }

        // --- Existing functions (unchanged except graph tab modifications) ---
        function init() {
            closeModal();
            renderDashboard();
            try { renderExecutiveSummary(); } catch (e) { console.error('Executive summary render failed:', e); }
            renderVulnerabilities();
            renderInventory();
            renderStats();
            renderSystem();
            renderSecrets();
            renderCompliance();
            setupFilters();
            populatePackageSelect();
            setupCounts();

            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                const wrapper = document.getElementById('pkg-dropdown-wrapper');
                if (wrapper && !wrapper.contains(e.target)) {
                    closePkgDropdown();
                }
            });
        }

        function setupCounts() {
            document.getElementById('tab-secrets').textContent = \`Secrets(\${reportData.secrets?.count || 0})\`;
            document.getElementById('tab-vulnerabilities').textContent = \`Vulnerabilities(\${reportData.stats.total_vulnerabilities})\`;
            document.getElementById('tab-inventory').textContent = \`Inventory(\${reportData.stats.inventory_size})\`;
            const cs = reportData.compliance_summary;
            document.getElementById('tab-compliance').textContent = \`Compliance(\${cs && cs.frameworks ? cs.frameworks.length : 0})\`;
        }

        // ── EXECUTIVE SUMMARY ────────────────────────────────────────────────────────
        // Plain-language overview for non-technical readers. Everything shown comes
        // from reportData.executive_summary (built server-side and written to the JSON
        // report as-is), so this tab and the JSON can never disagree. Figures that were
        // not checked arrive as null and are shown as "n/a", never 0.
        //
        // Layout: page 1 (cover, verdict, top risks, what to do first, four numbers) is
        // meant to be readable on its own and to fit one printed page. Detail follows,
        // then an appendix (methodology, scope, glossary) that is collapsed on screen
        // and expanded when printing.

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
              const major = o.scope === 'major';
              return '<li class="flex flex-wrap items-center gap-x-2 gap-y-1">' +
                '<span class="mono text-neutral-100">' + esc(o.version) + '</span>' +
                (o.recommended ? badge('none', 'Best') : '') +
                (major ? badge('medium', 'Major') : '') +
                '<span class="text-neutral-400">fixes ' + esc(o.resolves) + ' of ' + esc(o.of) +
                (o.known_exploited_total ? ' (' + esc(o.resolves_known_exploited) + ' of ' + esc(o.known_exploited_total) + ' exploited)' : '') +
                '</span></li>';
            }).join('');
            return '<div class="mt-3 pt-2 border-t border-neutral-800"><div class="text-[10px] uppercase tracking-widest text-neutral-500 mb-1">Possible fixes</div>' +
              '<ul class="space-y-1 text-[11px]">' + rows + '</ul>' +
              (c.fix_options_more ? '<div class="text-[10px] text-neutral-500 mt-1">+' + esc(c.fix_options_more) + ' more in the Inventory tab</div>' : '') +
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

        // Printing: the appendix is collapsed on screen but must be open on paper.
        (function () {
          let closedBeforePrint = [];
          window.addEventListener('beforeprint', function () {
            closedBeforePrint = [];
            document.querySelectorAll('#executive-content details').forEach(function (d) {
              if (!d.open) { closedBeforePrint.push(d); d.open = true; }
            });
          });
          window.addEventListener('afterprint', function () {
            closedBeforePrint.forEach(function (d) { d.open = false; });
            closedBeforePrint = [];
          });
        })();

        function switchTab(tabId) {
            document.querySelectorAll('nav button').forEach(btn => btn.classList.remove('tab-active'));
            document.getElementById(\`tab-\${tabId}\`).classList.add('tab-active');
            document.querySelectorAll('main section').forEach(sec => sec.classList.add('hidden'));
            document.getElementById(\`section-\${tabId}\`).classList.remove('hidden');
            // No graph init needed anymore
        }

        function renderDashboard() {
            const stats = reportData.stats;
            document.getElementById('report-id').textContent = \`GENERATED_AT: \${reportData.generated_at}\`;
            document.getElementById('stat-total').textContent = stats.inventory_size;
            document.getElementById('stat-vulnerabilities').textContent = stats.inventory_stats.vulnerable;
            document.getElementById('stat-infections').textContent = stats.inventory_stats.infected;
            document.getElementById('stat-safe').textContent = stats.inventory_stats.safe;

            const statusEl = document.getElementById('overall-status');
            if (reportData.decision.allowed) {
                statusEl.textContent = 'Status: Allowed';
                statusEl.className = 'px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-green-500/20 text-green-400 border border-green-500/50';
            } else {
                statusEl.textContent = 'Status: Blocked';
                statusEl.className = 'px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50';
            }

            document.getElementById('decision-reason').textContent = reportData.decision.reason;
            const pol = reportData.policy || {};
            const thresh = pol.severity_threshold || 'none';
            const blockUnk = pol.block_unknown_vulnerabilities === true ? 'block' : 'allow';
            const licenseRisk = pol.license_risk_threshold || 'none';
            const blockUnkLicense = pol.block_unknown_license_risk === true ? 'block' : 'allow';
            document.getElementById('policy-threshold').textContent = thresh;
            document.getElementById('policy-block-unknown').textContent = blockUnk;
            document.getElementById('policy-license-risk').textContent = licenseRisk;
            document.getElementById('policy-block-unknown-license').textContent = blockUnkLicense;
            document.getElementById('policy-infection').textContent = 'block (always)';
            document.getElementById('policy-secrets').textContent = 'block (always)';
            document.getElementById('policy-kev').textContent = pol.block_kev === false ? 'allow' : 'block';
            const epssT = parseFloat(pol.epss_threshold);
            document.getElementById('policy-epss').textContent = (epssT > 0 && epssT <= 1) ? ('block >= ' + parseFloat((epssT * 100).toFixed(2)) + '%') : 'off';
            const tiWarnings = (reportData.threat_intel && Array.isArray(reportData.threat_intel.warnings)) ? reportData.threat_intel.warnings : [];
            if (tiWarnings.length) {
                const tiEl = document.getElementById('threat-intel-warning');
                tiEl.textContent = tiWarnings.join(' ');
                tiEl.style.display = 'block';
            }

            const ctxSev = document.getElementById('severityChart').getContext('2d');
            const sevStats = stats.vulnerabilities_stats.severity;
            new Chart(ctxSev, {
                type: 'bar',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
                    datasets: [{
                        label: 'Vulnerabilities',
                        data: [sevStats.critical, sevStats.high, sevStats.medium, sevStats.low, sevStats.unknown],
                        backgroundColor: ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#a3a3a3'],
                        borderRadius: 4
                    }]
                },
                options: {
                    responsive: true,
                    maintainAspectRatio: false,
                    plugins: { legend: { display: false } },
                    scales: {
                        y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373' } },
                        x: { grid: { display: false }, ticks: { color: '#737373' } }
                    }
                }
            });
        }

        function renderVulnerabilities(filter = '', severity = 'all', reachability = 'all') {
            const tbody = document.getElementById('vuln-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.vulnerabilities.filter(v => {
                const matchesSearch = v.id.toLowerCase().includes(filter.toLowerCase()) || 
                                     v.affected_dependency.toLowerCase().includes(filter.toLowerCase());
                const matchesSeverity = severity === 'all' || v.severity === severity;
                let matchesReachability = true;
                if (reachability !== 'all' && v.reachability) {
                    if (reachability === 'reachable')        matchesReachability = v.reachability.reachable === true;
                    else if (reachability === 'unreachable') matchesReachability = v.reachability.reachable === false;
                    else                                     matchesReachability = v.reachability.level === reachability;
                }
                return matchesSearch && matchesSeverity && matchesReachability;
            });

            if (filtered.length === 0) {
                tbody.innerHTML = \`<tr><td colspan="8" class="px-6 py-12 text-center text-neutral-500 italic">No vulnerabilities found matching criteria.</td></tr>\`;
                return;
            }

            filtered.forEach(v => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
                row.onclick = () => openVulnModal(v.id);
                row.innerHTML = \`
                    <td class="px-6 py-4 mono text-xs font-medium">\${v.id}</td>
                    <td class="px-6 py-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span></td>
                    <td class="px-6 py-4 font-medium">\${v.affected_dependency} ( \${v.ecosystem} )</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${v.affected_dependency_version}</td>
                    <td class="px-6 py-4">\${v.has_fix ? '<span class="text-green-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4">\${v.is_policy_violation ? '<span class="text-red-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4 text-neutral-400 text-xs">\${v.fixed_versions.join('<br>')}</td>
                    <td class="px-6 py-4">\${renderReachabilityBadge(v.reachability)}</td>
                    <td class="px-6 py-4 text-right"><button class="text-red-400 hover:text-red-300 text-xs font-semibold">View Details</button></td>
                \`;
                tbody.appendChild(row);
            });
        }

        function renderInventory(filter = '', state = 'all', directness = 'all', policy = 'all') {
            const tbody = document.getElementById('inv-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.inventory.filter(item => {
                const matchesSearch     = item.name.toLowerCase().includes(filter.toLowerCase());
                const matchesState      = state === 'all' || item.state === state;
                const matchesDirectness = directness === 'all'
                    || (directness === 'direct'     && item.is_direct)
                    || (directness === 'transitive' && !item.is_direct);
                const matchesPolicy     = policy === 'all'
                    || (policy === 'violate' && item.is_policy_violation)
                    || (policy === 'safe'    && !item.is_policy_violation);
                return matchesSearch && matchesState && matchesDirectness && matchesPolicy;
            });

            filtered.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors';
                row.onclick = () => openInvModal(item.id);
                row.innerHTML = \`
                    <td class="px-6 py-4 font-medium">\${item.name}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${item.version}</td>
                    <td class="px-6 py-4"><span class="text-xs \${item.is_direct ? 'text-white' : 'text-neutral-500'}">\${item.is_direct ? 'Direct' : 'Transitive'}</span></td>
                    <td class="px-6 py-4"><span class="text-xs \${
  item.state === 'safe'
    ? 'text-green-400'
    : item.state === 'undetermined'
    ? 'text-blue-400'
    : item.state === 'vulnerable'
    ? 'text-orange-400'
    : item.state === 'infected'
    ? 'text-red-400'
    : 'text-neutral-400'
}">\${item.state}</span></td>
                    <td class="px-6 py-4"><span class="text-xs \${item.is_policy_violation ? 'text-red-400' : 'text-green-400'}">\${item.is_policy_violation ? 'Yes' : 'No'}</span></td>
                    <td class="px-6 py-4 text-neutral-400">\${item.ecosystem}</td>
                    <td class="px-6 py-4 text-neutral-400">\${item.license || 'unknown'}</td>
                    <td class="px-6 py-4 text-neutral-500 text-xs">\${item.scopes.join(', ')}</td>
                \`;
                tbody.appendChild(row);
            });
        }

        function renderStats() {
            const s = reportData.stats;
            
            document.getElementById('stats-inv-size').textContent = s.inventory_size;
            document.getElementById('stats-inv-safe').textContent = s.inventory_stats.safe;
            document.getElementById('stats-inv-vuln').textContent = s.inventory_stats.vulnerable;
            document.getElementById('stats-inv-inf').textContent = s.inventory_stats.infected;
            document.getElementById('stats-inv-und').textContent = s.inventory_stats.undetermined;
            
            document.getElementById('stats-vuln-total').textContent = s.total_vulnerabilities;
            document.getElementById('stats-vuln-crit').textContent = s.vulnerabilities_stats.severity.critical;
            document.getElementById('stats-vuln-high').textContent = s.vulnerabilities_stats.severity.high;
            document.getElementById('stats-vuln-med').textContent = s.vulnerabilities_stats.severity.medium;
            document.getElementById('stats-vuln-low').textContent = s.vulnerabilities_stats.severity.low;
            document.getElementById('stats-vuln-unk').textContent = s.vulnerabilities_stats.severity.unknown;
            document.getElementById('stats-vuln-kev').textContent = s.vulnerabilities_stats.kev || 0;
            document.getElementById('stats-vuln-nonkev').textContent = s.vulnerabilities_stats.non_kev || 0;
            document.getElementById('stats-vuln-kevunk').textContent = s.vulnerabilities_stats.kev_unknown || 0;

            new Chart(document.getElementById('statsInventoryChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Vulnerable', 'Infected', 'Undetermined'],
                    datasets: [{
                        data: [s.inventory_stats.safe, s.inventory_stats.vulnerable, s.inventory_stats.infected, s.inventory_stats.undetermined],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#6b7280'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            new Chart(document.getElementById('statsVulnChart'), {
                type: 'pie',
                data: {
                    labels: ['Critical', 'High', 'Medium', 'Low', 'Unknown'],
                    datasets: [{
                        data: [
                            s.vulnerabilities_stats.severity.critical,
                            s.vulnerabilities_stats.severity.high,
                            s.vulnerabilities_stats.severity.medium,
                            s.vulnerabilities_stats.severity.low,
                            s.vulnerabilities_stats.severity.unknown
                        ],
                        backgroundColor: ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#cbd5e0'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            // KEV vs non-KEV — its own chart. "Unknown" (feed down / not
            // checked) is a separate slice so it can't pass as "not KEV".
            const kevVs = s.vulnerabilities_stats || {};
            new Chart(document.getElementById('statsKevChart'), {
                type: 'doughnut',
                data: {
                    labels: ['KEV', 'Not in KEV', 'Unknown'],
                    datasets: [{
                        data: [kevVs.kev || 0, kevVs.non_kev || 0, kevVs.kev_unknown || 0],
                        backgroundColor: ['#ef4444', '#3b82f6', '#6b7280'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });


            const ecoData = {};
            reportData.inventory.forEach(item => { ecoData[item.ecosystem] = (ecoData[item.ecosystem] || 0) + 1; });
            const ecoLabels = Object.keys(ecoData);
            const ecoValues = Object.values(ecoData);
            
            new Chart(document.getElementById('statsEcoChart'), {
                type: 'pie',
                data: {
                    labels: ecoLabels,
                    datasets: [{
                        data: ecoValues,
                        backgroundColor: ['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'],
                        borderWidth: 1,
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });

            const legend = document.getElementById('eco-legend');
            legend.innerHTML = ecoLabels.map((l, i) => \`
                <div class="flex items-center gap-2">
                    <div class="w-2 h-2 rounded-full" style="background: \${['#ef4444', '#3b82f6', '#10b981', '#f59e0b', '#8b5cf6'][i % 5]}"></div>
                    <span>\${l}: \${ecoValues[i]}</span>
                </div>
            \`).join('');

            // License risk — only populated on health-mode scans (see
            // engine.js / policy.js); s.license_stats is absent on
            // check/install reports, so every field here falls back to 0.
            const lic = s.license_stats || { total: 0, osi_approved: 0, by_risk: { low: 0, medium: 0, high: 0, unknown: 0 } };
            document.getElementById('stats-license-total').textContent = lic.total || 0;
            document.getElementById('stats-license-low').textContent = lic.by_risk?.low || 0;
            document.getElementById('stats-license-med').textContent = lic.by_risk?.medium || 0;
            document.getElementById('stats-license-high').textContent = lic.by_risk?.high || 0;
            document.getElementById('stats-license-unk').textContent = lic.by_risk?.unknown || 0;
            document.getElementById('stats-license-osi').textContent = lic.osi_approved || 0;

            new Chart(document.getElementById('statsLicenseChart'), {
                type: 'pie',
                data: {
                    labels: ['Low', 'Medium', 'High', 'Unknown'],
                    datasets: [{
                        data: [
                            lic.by_risk?.low || 0,
                            lic.by_risk?.medium || 0,
                            lic.by_risk?.high || 0,
                            lic.by_risk?.unknown || 0
                        ],
                        backgroundColor: ['#10b981', '#fb923c', '#ef4444', '#6b7280'],
                        borderWidth: 0
                    }]
                },
                options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } } }
            });
        }

        // ── COMPLIANCE HELPERS ──────────────────────────────────────────────
        // A single CVE can be the reason several package versions in the
        // inventory get flagged, so a raw finding count conflates two
        // different things: "how many distinct bugs" and "how many pieces of
        // software are affected". These helpers recompute both from the raw
        // vulnerability/secret lists per control, the same way the EASM
        // report does it, instead of trusting one undifferentiated number.
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

        // Framework-card headline — a CVE can map to more than one control in
        // the same framework, so dedupe across controls before counting.
        function complianceFrameworkTotals(fw) {
            const acc = { vulns: new Set(), secrets: new Set() };
            for (const c of (fw.controls || [])) {
                const m = complianceMatchesFor(fw.name, c.id);
                m.vulns.forEach(x => acc.vulns.add(x));
                m.secrets.forEach(x => acc.secrets.add(x));
            }
            return complianceStatsFromMatches({ vulns: [...acc.vulns], secrets: [...acc.secrets] });
        }

        // Right-hand count column for a framework card or control row: one
        // line per kind that has any matches, components as the secondary
        // figure under the CVE line.
        function complianceCountsHtml(stats, primaryClass, compact) {
            const line = (cls, text) => \`<span class="\${cls}">\${text}</span>\`;
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
            grid.innerHTML = cs.frameworks.map((fw, fwIdx) => \`
                <div class="glass p-6 rounded-xl space-y-4">
                    <div class="flex items-start justify-between gap-3">
                        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">\${fw.name}</h3>
                        <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">\${complianceCountsHtml(complianceFrameworkTotals(fw), 'mono text-red-400 font-semibold text-xs', false)}</div>
                    </div>
                    <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
                        \${fw.controls.map((c, cIdx) => \`
                        <div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" onclick="openComplianceModal(\${fwIdx}, \${cIdx})">
                            <div class="flex flex-col min-w-0">
                                <span class="mono text-red-400">\${c.id}</span>
                                <span class="text-neutral-500">\${c.title}</span>
                            </div>
                            <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">\${complianceCountsHtml(complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id)), 'mono text-neutral-200', true)}</div>
                        </div>\`).join('')}
                    </div>
                </div>\`).join('');
        }

        // Opens a modal listing every finding (vulnerability or secret) mapped
        // to a single compliance control, in the same row style used by the
        // inventory tab's per-package vulnerability list (openInvModal above).
        // fwIdx/cIdx are plain array indices into compliance_summary — never
        // re-embedded strings — so there's nothing to escape/quote here; they
        // only look up fw.name / control.id, which are then compared against
        // (not interpolated into) each finding's own \`.compliance.frameworks\`.
        function openComplianceModal(fwIdx, cIdx) {
            const cs = reportData.compliance_summary;
            const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
            const control = fw && fw.controls && fw.controls[cIdx];
            if (!fw || !control) return;

            const mapsToControl = (item) => !!(item.compliance && item.compliance.frameworks &&
                item.compliance.frameworks.some(f => f.name === fw.name && f.controls.some(c => c.id === control.id)));

            const vulnMatches = (reportData.vulnerabilities || []).filter(mapsToControl);
            const secretMatches = ((reportData.secrets || {}).findings || []).filter(mapsToControl);

            const vulnRows = vulnMatches.map(v => \`
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openVulnModal('\${v.id}'), 50)">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span>
                        <span class="mono text-xs text-white">\${v.id}</span>
                    </div>
                    <div class="flex items-center gap-3">
                        \${v.severity_score != null ? \`<span class="mono text-xs text-neutral-400">\${parseFloat(v.severity_score).toFixed(1)}</span>\` : ''}
                        \${v.is_kev ? '<span class="text-[10px] font-bold text-red-400 border border-red-400 rounded px-1.5 py-0.5">KEV</span>' : ''}
                        \${v.is_policy_violation ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Policy Block</span>' : '<span class="text-[10px] text-neutral-500">Allowed</span>'}
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>\`).join('');

            const secretRows = secretMatches.map(f => \`
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 px-2 rounded">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${(f.severity || 'unknown').toLowerCase()}">\${escapeHtml(f.severity || 'unknown')}</span>
                        <span class="text-xs text-white">\${escapeHtml(f.title || 'Secret finding')}</span>
                    </div>
                    <span class="mono text-[10px] text-neutral-500">\${escapeHtml(f.file_path || '')}</span>
                </div>\`).join('');

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

            document.getElementById('modal-body').innerHTML = \`
                <div class="space-y-4">
                    <div>
                        <div class="flex items-center gap-3 mb-1 flex-wrap">
                            <span class="mono text-red-400 text-sm">\${control.id}</span>
                            <h2 class="text-lg font-semibold text-white">\${control.title}</h2>
                        </div>
                        <p class="text-xs text-neutral-500">\${fw.name}\${fw.version ? ' · ' + fw.version : ''}\${modalBits.length ? ' — ' + modalBits.join('; ') : ''}</p>
                    </div>
                    <div>\${vulnRows}\${secretRows}\${emptyRow}</div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function renderSystem() {
            const r = reportData.runtime;
            const eng = reportData.engine;
            const os = reportData.os_metadata;
            const git = reportData.git_metadata;
            const tool = reportData.tool_info;
            const scan = reportData.scan_info;

            document.getElementById('run-env').textContent = r.environment;
            document.getElementById('run-node').textContent = r.version;
            document.getElementById('run-platform').textContent = r.platform;
            document.getElementById('run-arch').textContent = r.arch;
            document.getElementById('run-cwd').textContent = r.cwd;

            document.getElementById('engine-name').textContent = eng.name;
            document.getElementById('engine-version').textContent = eng.version;
            document.getElementById('tool-name').textContent = tool.name;
            document.getElementById('tool-version').textContent = tool.version;

            document.getElementById('scan-type').textContent = scan.type;
            document.getElementById('scan-ecosystems').textContent = scan.ecosystems.join(', ');
            document.getElementById('scan-engine').textContent = scan.engine;
            document.getElementById('scan-scope').textContent = scan.scan_scope || 'repository';

            document.getElementById('os-id').textContent = os.os_id;
            document.getElementById('os-name').textContent = os.os_name;
            document.getElementById('os-version').textContent = os.os_version;

            // Local IPs — render one line per interface
            const localIpsEl = document.getElementById('os-local-ips');
            const localIPs = os.local_ips || {};
            const ifaceEntries = Object.entries(localIPs);
            localIpsEl.innerHTML = ifaceEntries.length
                ? ifaceEntries.map(([iface, ip]) =>
                    \`<div class="flex justify-between gap-4"><span class="text-neutral-500">\${iface}</span><span>\${ip}</span></div>\`
                  ).join('')
                : '<span class="text-neutral-600 italic">none detected</span>';

            document.getElementById('git-rev').textContent = git.latest_commit || 'N/A';
            document.getElementById('git-branch').textContent = git.branch || 'N/A';
            document.getElementById('git-url').textContent = git.url || 'N/A';
            document.getElementById('git-version').textContent = git.version || 'N/A';
        }

        function setupFilters() {
            const gf=()=>[document.getElementById('vuln-search').value,document.getElementById('vuln-filter-severity').value,document.getElementById('vuln-filter-reachability').value];
            document.getElementById('vuln-search').addEventListener('input',()=>renderVulnerabilities(...gf()));
            document.getElementById('vuln-filter-severity').addEventListener('change',()=>renderVulnerabilities(...gf()));
            document.getElementById('vuln-filter-reachability').addEventListener('change',()=>renderVulnerabilities(...gf()));
            const invf=()=>[document.getElementById('inv-search').value,document.getElementById('inv-filter-state').value,document.getElementById('inv-filter-direct').value,document.getElementById('inv-filter-policy').value];
            document.getElementById('inv-search').addEventListener('input', () => renderInventory(...invf()));
            document.getElementById('inv-filter-state').addEventListener('change', () => renderInventory(...invf()));
            document.getElementById('inv-filter-direct').addEventListener('change', () => renderInventory(...invf()));
            document.getElementById('inv-filter-policy').addEventListener('change', () => renderInventory(...invf()));
            const sf=()=>[document.getElementById('secrets-search').value,document.getElementById('secrets-filter-severity').value];
            document.getElementById('secrets-search').addEventListener('input',()=>renderSecrets(...sf()));
            document.getElementById('secrets-filter-severity').addEventListener('change',()=>renderSecrets(...sf()));
        }

        function renderSecrets(filter = '', severity = 'all') {
            const tbody = document.getElementById('secrets-table-body');
            const banner = document.getElementById('secrets-disabled-banner');
            const secrets = reportData.secrets || { enabled: true, findings: [] };

            banner.classList.toggle('hidden', secrets.enabled !== false);

            const q = filter.trim().toLowerCase();
            const filtered = (secrets.findings || []).filter(f => {
                const matchesSearch = !q ||
                    f.file_path.toLowerCase().includes(q) ||
                    f.title.toLowerCase().includes(q) ||
                    f.id.toLowerCase().includes(q);
                const matchesSeverity = severity === 'all' || (f.severity || '').toLowerCase() === severity;
                return matchesSearch && matchesSeverity;
            });

            tbody.innerHTML = '';
            if (filtered.length === 0) {
                tbody.innerHTML = \`<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No secrets found.</td></tr>\`;
                return;
            }

            filtered.forEach(f => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors';
                const sev = (f.severity || 'unknown').toLowerCase();
                const loc = f.line;
                row.innerHTML = \`
                    <td class="px-6 py-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${sev}">\${escapeHtml(f.severity || 'unknown')}</span></td>
                    <td class="px-6 py-4 font-medium">\${escapeHtml(f.title)}</td>
                    <td class="px-6 py-4 text-neutral-400 text-xs">\${escapeHtml(f.category || '')}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${escapeHtml(f.file_path)}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${loc}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-500">\${escapeHtml(f.match_preview || '')}</td>
                \`;
                tbody.appendChild(row);
            });
        }

        // Suggested-fixes tables for the package modal (see suggested_fixes.js).
        // Built with string concatenation (no nested template literals).
        function renderSuggestedFixes(sf) {
            if (!sf) return '<p class="text-neutral-500 text-xs italic">No suggested-fix data available.</p>';
            const fixes = sf.fixes || [];
            const unfixed = sf.unfixed || [];
            const openVuln = function(id) {
                return "event.stopPropagation(); closeModal(); setTimeout(() => openVulnModal(" + JSON.stringify(id).replace(/"/g, '&quot;') + "), 50)";
            };
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
                html += '<div class="rounded-lg border border-neutral-800 overflow-auto max-h-96">' +
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
                                '<div class="mono text-xs text-neutral-200">' + escapeHtml(f.range ? f.range.label : '—') + '</div>' +
                                '<div class="text-[10px] uppercase tracking-widest text-neutral-500 mt-0.5">' + (f.range && f.range.scope === 'major' ? 'major range' : 'minor range') + '</div></td>';
                        }
                        return '<tr>' + rangeCell +
                            '<td class="px-3 py-2 align-top whitespace-nowrap border-t border-l border-neutral-800">' +
                            '<span class="mono text-sm font-bold text-green-400">' + escapeHtml(String(f.version)) + '</span>' +
                            '<span class="ml-2 text-[10px] text-neutral-500">fixes ' + f.count + '</span></td>' +
                            '<td class="px-3 py-2 align-top border-t border-l border-neutral-800"><div class="flex flex-wrap gap-x-4 gap-y-1.5">' +
                            (f.vulnerabilities || []).map(function(v) {
                                return '<div class="flex items-center gap-2 whitespace-nowrap cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1" onclick="' + openVuln(v.id) + '">' +
                                    '<span class="mono text-xs text-white">' + escapeHtml(String(v.id)) + '</span>' + sevBadge(v) + '</div>';
                            }).join('') +
                            '</div></td></tr>';
                    }).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="text-neutral-500 text-xs italic">No upgrade version fixes any vulnerability of this package.</p>';
            }

            html += '<h5 class="text-[10px] font-semibold uppercase tracking-widest text-neutral-500 mt-4 mb-2">Vulnerabilities with no fix (' + unfixed.length + ')</h5>';
            if (unfixed.length) {
                html += '<div class="rounded-lg border border-neutral-800 overflow-auto max-h-48">' +
                    '<table class="w-full text-xs text-left">' +
                    '<thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest sticky top-0"><tr><th class="px-3 py-2">ID</th><th class="px-3 py-2">Severity</th><th class="px-3 py-2 text-right">Score</th></tr></thead>' +
                    '<tbody class="divide-y divide-neutral-800">' +
                    unfixed.map(function(v) {
                        return '<tr class="cursor-pointer hover:bg-neutral-800/40" onclick="' + openVuln(v.id) + '">' +
                            '<td class="px-3 py-2 mono text-white">' + escapeHtml(String(v.id)) + '</td>' +
                            '<td class="px-3 py-2">' + sevBadge(v) + '</td>' +
                            '<td class="px-3 py-2 mono text-neutral-400 text-right">' + (v.severity_score != null ? Number(v.severity_score).toFixed(1) : '—') + '</td></tr>';
                    }).join('') +
                    '</tbody></table></div>';
            } else {
                html += '<p class="text-neutral-500 text-xs italic">None — every vulnerability has a published fix.</p>';
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

            const vulnRows = itemVulns.length ? itemVulns.map(v => \`
                <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openVulnModal('\${v.id}'), 50)">
                    <div class="flex items-center gap-3">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span>
                        <span class="mono text-xs text-white">\${v.id}</span>
                    </div>
                    <div class="flex items-center gap-3">
                        \${v.severity_score != null ? \`<span class="mono text-xs text-neutral-400">\${parseFloat(v.severity_score).toFixed(1)}</span>\` : ''}
                        \${v.is_kev ? '<span class="text-[10px] font-bold text-red-400 border border-red-400 rounded px-1.5 py-0.5">KEV</span>' : ''}
                        \${v.is_policy_violation ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Policy Block</span>' : '<span class="text-[10px] text-neutral-500">Allowed</span>'}
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>
            \`).join('') : '<p class="text-sm text-neutral-500 italic py-2">No vulnerabilities found.</p>';

            const introRows = (item.introduced_by || []).length
                ? (item.introduced_by).map(ib => \`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('\${ib}'), 50)">\${ib}</span>\`).join('')
                : '<span class="text-neutral-500 text-xs italic">Direct dependency</span>';

            const parentsRows = (item.parents || []).length
                ? item.parents.map(p => {
                    const par = reportData.inventory.find(x => x.id === p);
                    return \`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 cursor-pointer hover:border-neutral-500 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('\${p}'), 50)">\${par ? par.name + '@' + par.version : p}</span>\`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No dependents (root)</span>';

            const pathRows = (item.paths || []).length
                ? item.paths.map(p => {
                    const isObj = p && typeof p === 'object' && p.type === 'system_path';
                    const text  = isObj ? p.text  : String(p ?? '');
                    const ip    = isObj ? p.ip    : '';
                    const ports = isObj && Array.isArray(p.ports) && p.ports.length ? p.ports : null;
                    return \`
                      <div class="mono text-[10px] text-neutral-400 bg-neutral-900 px-2 py-1.5 rounded border border-neutral-800 break-all space-y-0.5">
                        <div class="text-neutral-300">\${text}</div>
                        \${ip    ? \`<div class="text-neutral-600 text-[9px]">host: \${ip}</div>\`                         : ''}
                        \${ports ? \`<div class="text-neutral-600 text-[9px]">ports: \${ports.join(', ')}</div>\` : ''}
                      </div>\`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No path info</span>';

            const depsRows = (item.dependencies || []).length
                ? item.dependencies.map(d => {
                    const dep = reportData.inventory.find(x => x.id === d);
                    return \`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700 cursor-pointer hover:border-neutral-500 transition-colors" onclick="event.stopPropagation(); closeModal(); setTimeout(() => openInvModal('\${d}'), 50)">\${dep ? dep.name + '@' + dep.version : d}</span>\`;
                  }).join('')
                : '<span class="text-neutral-500 text-xs italic">No dependencies</span>';

            document.getElementById('modal-body').innerHTML = \`
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4 flex-wrap">
                        <div>
                            <div class="flex items-center gap-3 mb-1 flex-wrap">
                                <span class="text-[10px] uppercase font-bold \${stateColor} border border-current px-2 py-0.5 rounded">\${item.state}</span>
                                <h2 class="text-xl font-bold">\${item.name}</h2>
                                <span class="mono text-neutral-400 text-sm">v\${item.version}</span>
                            </div>
                            <p class="mono text-[11px] text-neutral-500 break-all">\${item.id}</p>
                        </div>
                        <div class="text-right shrink-0">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest mb-1">Ecosystem</p>
                            <p class="mono text-sm">\${item.ecosystem}</p>
                        </div>
                    </div>

                    <div class="grid grid-cols-2 md:grid-cols-4 gap-3">
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p><p class="mono text-xs">\${item.type || 'library'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">License</p><p class="mono text-xs">\${item.license || 'unknown'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Scopes</p><p class="mono text-xs">\${(item.scopes || []).join(', ') || '—'}</p></div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800"><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Policy Violation</p><p class="text-lg font-bold \${item.is_policy_violation ? 'text-red-400' : 'text-green-400'}">\${item.is_policy_violation ? 'Yes' : 'No'}</p></div>
                    </div>

                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">License Risk</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">\${renderLicenseInfoTable(item.license_info)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By ( root dependencies )</h4><div class="flex flex-wrap gap-2">\${introRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Parents / Dependents (\${(item.parents || []).length})</h4><div class="flex flex-wrap gap-2">\${parentsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (\${(item.dependencies || []).length})</h4><div class="flex flex-wrap gap-2">\${depsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerable Transitive Dependencies (\${(item.vulnerable_transitive_dependencies || []).length})</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">\${renderVulnTransitiveTable(item.vulnerable_transitive_dependencies)}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4><div class="space-y-1">\${pathRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Suggested Fixes</h4>\${renderSuggestedFixes(item.suggested_fixes)}</div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerabilities (\${itemVulns.length})</h4><div class="space-y-0">\${vulnRows}</div></div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function openVulnModal(id) {
            const v = reportData.vulnerabilities.find(x => x.id === id);
            if (!v) return;

            const modalBody = document.getElementById('modal-body');
            modalBody.innerHTML = \`
                <div class="space-y-6">
                    <div class="flex items-start justify-between gap-4">
                        <div>
                            <div class="flex items-center gap-3 mb-2">
                                <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span>
                                <h2 class="text-2xl font-bold mono"><a href="\${v.url}" target="_blank" class="text-white hover:text-blue-400">\${v.id}</a></h2>
                            </div>
                            <p class="text-neutral-400 text-sm">Package: <span class="text-white font-medium">\${v.affected_dependency}</span> (\${v.affected_dependency_version})</p>
                        </div>
                        <div class="text-right"><p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest">Severity Score</p><p class="text-3xl font-bold text-red-500">\${v.severity_score}</p></div>
                    </div>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Published</p><p class="text-xs mono">\${new Date(v.published).toLocaleDateString()}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Modified</p><p class="text-xs mono">\${new Date(v.modified).toLocaleDateString()}</p></div>
                        <div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Vector</p><p class="text-[10px] mono text-neutral-400 truncate" title="\${v.severity_vector}">\${v.severity_vector}</p></div>
                    </div>
                    \${renderThreatIntelSection(v)}
                    <div>
                        <h4 class=\"text-sm font-semibold mb-3 text-neutral-300\">Reachability Analysis</h4>
                        \${renderReachabilitySection(v.reachability)}
                    </div>
                    \${(v.fix_versions_ranked && v.fix_versions_ranked.length > 0) ? \`
                    <div>
                        <h4 class="text-sm font-semibold mb-3 text-green-400">Fix Version Recommendations</h4>
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
                                \${v.fix_versions_ranked.map(r => \`
                                <tr class="hover:bg-neutral-800/30 transition-colors \${r.recommended ? 'bg-green-500/5' : ''}">
                                    <td class="px-4 py-2 mono font-medium text-white">\${r.version}</td>
                                    <td class="px-4 py-2">
                                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${
                                            r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                                            r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                                                  'text-red-400 border-red-400'
                                        }">\${r.compatibility_level}</span>
                                    </td>
                                    <td class="px-4 py-2">
                                        \${r.recommended
                                            ? \`<span class="flex items-center gap-1 text-green-400 font-semibold"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>\`
                                            : \`<span class="text-neutral-500">—</span>\`}
                                    </td>
                                </tr>\`).join('')}
                            </tbody>
                        </table>
                        </div>
                    </div>\` : (v.fixes && v.fixes.length > 0 ? \`<div><h4 class="text-sm font-semibold mb-2 text-green-400">Recommended Fixes</h4><ul class="space-y-2">\${v.fixes.map(f => \`<li class="text-xs bg-green-500/10 border border-green-500/20 p-3 rounded-lg text-green-300 mono">\${f}</li>\`).join('')}</ul></div>\` : '')}
                    \${(v.last_affected_ranked && v.last_affected_ranked.length > 0) ? \`
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
                                \${v.last_affected_ranked.map(r => \`
                                <tr class="hover:bg-neutral-800/30 transition-colors \${r.recommended ? 'bg-orange-500/5' : ''}">
                                    <td class="px-4 py-2 mono font-medium text-white">\${r.version}</td>
                                    <td class="px-4 py-2">
                                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${
                                            r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                                            r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                                                  'text-red-400 border-red-400'
                                        }">\${r.compatibility_level}</span>
                                    </td>
                                    <td class="px-4 py-2">
                                        \${r.recommended
                                            ? \`<span class="flex items-center gap-1 text-orange-400 font-semibold"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>\`
                                            : \`<span class="text-neutral-500">—</span>\`}
                                    </td>
                                </tr>\`).join('')}
                            </tbody>
                        </table>
                        </div>
                    </div>\` : ''}
                    \${(v.cwes && v.cwes.length > 0) ? \`<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Weaknesses (CWE)</h4><div class="flex flex-wrap gap-2">\${v.cwes.map(c => \`<a href="https://cwe.mitre.org/data/definitions/\${c}.html" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-orange-400 hover:text-orange-300 mono">CWE-\${c}</a>\`).join('')}</div></div>\` : ''}
                    \${renderComplianceSection(v.compliance)}
                    \${v.iocs ? \`<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Indicators of Compromise</h4><div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">\${renderIocTable(v.iocs)}</div></div>\` : ''}
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4><div class="flex flex-wrap gap-2">\${v.references.map(r => \`<a href="\${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">\${r.type}</a>\`).join('')}</div></div>
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">\${v.description}</div></div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        // Threat intel (KEV / EPSS) helpers
        function tiEsc(x) { return String(x).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
        function fmtPct(x) { return (x == null || isNaN(Number(x))) ? '\u2014' : (Number(x) * 100).toFixed(2) + '%'; }
        function renderThreatIntelSection(v) {
            const kevCell = v.is_kev === true
                ? '<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold text-red-400 border-red-400">KEV</span>'
                : (v.is_kev === false ? '<span class="text-xs mono text-neutral-400">No</span>' : '<span class="text-xs mono text-neutral-500">Unknown</span>');
            const cell = (label, inner) => '<div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">' + label + '</p>' + inner + '</div>';
            const txt  = (x) => '<p class="text-xs mono">' + (x == null ? '\u2014' : tiEsc(x)) + '</p>';
            return '<div class="grid grid-cols-2 md:grid-cols-5 gap-4 pb-4 border-b border-neutral-800">'
                + cell('Known Exploited', kevCell)
                + cell('KEV Added', txt(v.kev_added))
                + cell('KEV Deadline', txt(v.kev_deadline))
                + cell('EPSS Score', txt(v.epss_score == null ? null : fmtPct(v.epss_score)))
                + cell('EPSS Percentile', txt(v.epss_percentile == null ? null : fmtPct(v.epss_percentile)))
                + '</div>';
        }

        // Compliance framework helpers
        function renderComplianceBadges(compliance) {
            if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
            return compliance.frameworks.map(fw => \`<span class="text-[9px] bg-neutral-800 border border-neutral-700 px-1.5 py-0.5 rounded text-neutral-400" title="\${fw.controls.map(c => c.id + ' — ' + c.title).join('; ')}">\${fw.name}</span>\`).join('');
        }

        function renderComplianceSection(compliance) {
            if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
            return \`<div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Compliance Frameworks</h4><div class="bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 space-y-2">
                \${compliance.frameworks.map(fw => \`
                <div class="flex flex-col gap-1">
                    <span class="text-xs font-semibold text-orange-400">\${fw.name}</span>
                    <div class="flex flex-wrap gap-1.5">\${fw.controls.map(c => \`<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="\${c.title}">\${c.id}</span>\`).join('')}</div>
                </div>\`).join('')}
            </div></div>\`;
        }


        // Reachability helpers
        function renderReachabilityBadge(r) {
            if (!r) return '<span class="text-neutral-600 text-[10px] italic">-</span>';
            const lc={total:'text-purple-400 border-purple-400',high:'text-red-400 border-red-400',medium:'text-orange-400 border-orange-400',low:'text-blue-400 border-blue-400'}[r.level]||'text-neutral-400 border-neutral-400';
            const cc={high:'text-green-400',medium:'text-yellow-400',low:'text-neutral-500'}[r.confidence]||'text-neutral-500';
            const dot=r.reachable?'[R]':'[U]';
            return \`<div class="flex flex-col gap-0.5"><span class="inline-flex items-center px-1.5 py-0.5 rounded border text-[10px] uppercase font-bold \${lc}">\${dot} \${r.level}</span><span class="text-[9px] \${cc}">conf: \${r.confidence}</span></div>\`;
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
                    const files=(imp.matched_files||[]).slice(0,4).map(f=>\`<span class="mono text-[10px] bg-neutral-800 px-2 py-0.5 rounded border border-neutral-700 text-green-300">\${f}</span>\`).join('');
                    const extra=imp.matched_files.length>4?\`<span class="text-neutral-500 text-[10px]">+\${imp.matched_files.length-4} more</span>\`:'';
                    isHtml=\`<div class="flex flex-wrap gap-1 mt-1">\${files}\${extra}</div>\`;
                }else{
                    const pe=Object.entries(imp.parent_scans||{}).filter(([,ps])=>ps.found);
                    if(pe.length){
                        const pi=pe.slice(0,3).map(([purl,ps])=>\`<div class="text-[10px] bg-neutral-800 px-2 py-1 rounded border border-orange-500/30"><span class="text-orange-300 font-medium">\${purl.split('/').pop().split('@')[0]}</span><span class="text-neutral-500 ml-1">via \${(ps.matched_files||[]).slice(0,2).join(', ')}</span></div>\`).join('');
                        isHtml=\`<div class="mt-1 space-y-1"><p class="text-[10px] text-neutral-400 mb-1">Direct import not found - reachable via parent(s):</p>\${pi}</div>\`;
                    }else{isHtml=\`<span class="text-neutral-500 italic text-[10px]">Not imported in \${imp.files_scanned} file(s) scanned</span>\`;}
                }
            }else{isHtml='<span class="text-neutral-600 italic text-[10px]">Source scan not performed</span>';}
            const tags=(r.tags||[]).map(t=>\`<span class="mono text-[9px] bg-neutral-800 px-1.5 py-0.5 rounded border border-neutral-700 text-neutral-400">\${t}</span>\`).join('');
            return \`<div class="space-y-3"><div class="flex flex-wrap gap-4"><span class="text-[10px] uppercase text-neutral-500 font-bold">Reachable: </span><span class="font-bold text-sm" style="color:\${r.reachable?'#f87171':'#4ade80'}">\${r.reachable?'YES':'NO'}</span><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold mono" style="color:\${lc};border-color:\${lc}">\${r.level}</span><span class="text-[10px] font-semibold" style="color:\${cc}">\${r.confidence.toUpperCase()} confidence</span></div><div class="grid grid-cols-3 md:grid-cols-6 gap-2 text-[10px]"><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Depth</p><p class="mono">\${s.depth!=null?s.depth:'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">AV</p><p class="mono">\${s.attack_vector||'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Scope</p><p class="mono">\${s.scope||'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Orphan</p><p class="mono">\${s.is_orphan_tool?'yes':'no'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Paths</p><p class="mono">\${s.num_paths!=null?s.num_paths:'--'}</p></div><div class="bg-neutral-900 rounded p-2 border border-neutral-800"><p class="text-neutral-500">Non-Lib</p><p class="mono">\${s.is_non_library?'yes':'no'}</p></div></div><div><p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Import Scan</p>\${isHtml}</div><p class="text-xs text-neutral-300 bg-neutral-900/50 px-3 py-2 rounded border border-neutral-800 italic">\${r.rationale}</p>\${tags?'<div class="flex flex-wrap gap-1">'+tags+'</div>':''}</div>\`;
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
        document.getElementById('modal-overlay').addEventListener('click', (e) => { if (e.target.id === 'modal-overlay') closeModal(); });

        init();
    `;

    // HTML output (graph section completely redesigned)
    return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>UBEL SCA — Security Report</title>
    <script>${await getTailwindScript()}</script>
    <script>${await getChartJSScript()}</script>
    <style>${await getGoogleFontsScript()}</style>
    <style>
        :root { --bg: #0a0a0a; --card: #141414; --border: #262626; --accent: #ef4444; }
        body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #e5e5e5; }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass { background: rgba(20,20,20,0.8); backdrop-filter: blur(12px); border: 1px solid var(--border); }
        .severity-high { color: #f87171; border-color: #f87171; }
        .severity-medium { color: #fb923c; border-color: #fb923c; }
        .severity-low { color: #60a5fa; border-color: #60a5fa; }
        .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
        .tab-active { border-bottom: 2px solid var(--accent); color: white; }
        .modal-overlay { display: none; position: fixed; top: 0; left: 0; width: 100%; height: 100%; background: rgba(0,0,0,0.8); z-index: 50; backdrop-filter: blur(4px); }
        .modal-content { max-height: 90vh; overflow-y: auto; }
            /* Executive summary: print / save-as-PDF. Prints the summary only, on white;
               page 1 is the one-page summary, details and appendix start on new pages. */
            details > summary { list-style: none; }
            details > summary::-webkit-details-marker { display: none; }
            details > summary::before { content: "+"; display: inline-block; width: 1.2em; color: #737373; }
            details[open] > summary::before { content: "-"; }
            @media print {
              @page { size: A4; margin: 12mm; }
              html, body { background: #fff !important; color: #111 !important; font-size: 11px; }
              header, nav, footer, .no-print, .modal-overlay { display: none !important; }
              main { padding: 0 !important; max-width: none !important; }
              main > section { display: none !important; }
              main > #section-executive { display: block !important; }
              #section-executive, #section-executive * { -webkit-print-color-adjust: exact; print-color-adjust: exact; box-shadow: none !important; backdrop-filter: none !important; }
              #section-executive > div, #section-executive #executive-content > * { margin-top: 0; }
              #executive-content { display: block !important; }
              #executive-content > * + * { margin-top: 12px !important; }
              #section-executive .glass { background: #fff !important; border-color: #d1d5db; break-inside: avoid; padding: 8px 12px !important; border-radius: 6px !important; }
              #section-executive .glass[style*="border-left"] { border-top-color: #d1d5db; border-right-color: #d1d5db; border-bottom-color: #d1d5db; }
              #section-executive [class*="text-neutral"], #section-executive [class*="text-white"] { color: #374151 !important; }
              #section-executive .exec-headline, #section-executive h2, #section-executive h4 { color: #111 !important; }
              #section-executive [class*="bg-neutral"] { background: #f3f4f6 !important; }
              #section-executive [class*="border-neutral"] { border-color: #d1d5db !important; }
              #section-executive [class*="divide-neutral"] > * { border-color: #e5e7eb !important; }
              #section-executive .exec-page-break { break-before: page; }
              #section-executive .exec-cols-2 { display: grid !important; grid-template-columns: 1fr 1fr !important; gap: 10px !important; }
              #section-executive .exec-figs > *, #section-executive .exec-glance > *, #section-executive .exec-cols-2 > * { min-width: 0; overflow-wrap: anywhere; }
              #section-executive .exec-figs { display: grid !important; grid-template-columns: repeat(4, 1fr) !important; gap: 8px !important; }
              #section-executive .exec-glance { display: grid !important; grid-template-columns: repeat(3, 1fr) !important; gap: 8px !important; }
              #section-executive h2 { font-size: 18px !important; margin-bottom: 4px !important; }
              #section-executive h3 { font-size: 10px !important; margin-bottom: 6px !important; break-after: avoid; }
              #section-executive h4 { font-size: 11px !important; }
              #section-executive .text-4xl { font-size: 28px !important; line-height: 1.1 !important; }
              #section-executive .text-3xl { font-size: 20px !important; line-height: 1.1 !important; }
              #section-executive .text-lg { font-size: 12.5px !important; line-height: 1.4 !important; }
              #section-executive .text-sm { font-size: 10.5px !important; line-height: 1.4 !important; }
              #section-executive .text-xs, #section-executive [class*="text-[11px]"] { font-size: 9px !important; line-height: 1.35 !important; }
              #section-executive .space-y-3 > * + * { margin-top: 6px !important; }
              #section-executive .space-y-8 > * + * { margin-top: 12px !important; }
              #section-executive table { font-size: 9.5px; }
              #section-executive td, #section-executive th { padding-top: 5px !important; padding-bottom: 5px !important; }
              #section-executive tr { break-inside: avoid; }
              #section-executive .exec-appendix { break-inside: auto; }
              #section-executive .exec-appendix > summary::before { content: ""; }
            }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3"><div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white">U</div><div><h1 class="text-lg font-semibold tracking-tight">UBEL SCA — Security Report</h1><p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p></div></div>
            <div id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider">Status: Loading...</div>
        </div>
    </header>
    <nav class="border-b border-neutral-800 bg-neutral-900/30">
        <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
            <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
            <button onclick="switchTab('executive')" id="tab-executive" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Executive Summary</button>
            <button onclick="switchTab('secrets')" id="tab-secrets" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Secrets(0)</button>
            <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities(0)</button>
            <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Inventory(0)</button>
            <button onclick="switchTab('graph')" id="tab-graph" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Dependency Sequences</button>
            <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
            <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Compliance(0)</button>
            <button onclick="switchTab('system')" id="tab-system" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">System Info</button>
        </div>
    </nav>
    <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
        <!-- Dashboard Section -->
        <section id="section-dashboard" class="space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Total Items</p><p class="text-3xl font-bold" id="stat-total">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-red-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerable Items</p><p class="text-3xl font-bold text-red-500" id="stat-vulnerabilities">0</p></div>
                <div class="glass p-6 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Infections</p><p class="text-3xl font-bold" id="stat-infections">0</p></div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-green-500"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Safe Items</p><p class="text-3xl font-bold text-green-500" id="stat-safe">0</p></div>
            </div>
            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl lg:col-span-2"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Severity Distribution</h3><div class="h-64"><canvas id="severityChart"></canvas></div></div>
                <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Decision Summary</h3><div id="decision-box" class="p-4 rounded-lg bg-neutral-800/50 border border-neutral-700"><p class="text-sm leading-relaxed" id="decision-reason">...</p><div id="threat-intel-warning" class="mt-3 text-xs text-yellow-400" style="display:none"></div></div><div class="mt-6 space-y-4"><div class="flex justify-between items-center text-sm"><span class="text-neutral-500">Policy:</span></div><div class="flex justify-between items-center text-sm"><table class="w-auto text-sm mono"><tr><td class="pr-2">Infections</td><td id="policy-infection">...</td></tr><tr><td class="pr-2">Secrets</td><td id="policy-secrets">...</td></tr><tr><td class="pr-2">Severity Threshold</td><td id="policy-threshold">...</td></tr><tr><td class="pr-2">Block Unknown</td><td id="policy-block-unknown">...</td></tr><tr><td class="pr-2">License Risk Threshold</td><td id="policy-license-risk">...</td></tr><tr><td class="pr-2">Block Unknown License</td><td id="policy-block-unknown-license">...</td></tr><tr><td class="pr-2">Block KEV</td><td id="policy-kev">...</td></tr><tr><td class="pr-2">EPSS Threshold</td><td id="policy-epss">...</td></tr></table></div></div></div>
            </div>
        </section>
        <!-- Executive Summary Section (plain-language, for non-technical readers) -->
        <section id="section-executive" class="hidden space-y-8">
            <div id="executive-content" class="space-y-8"></div>
        </section>
        <!-- Vulnerabilities Section -->
        <section id="section-vulnerabilities" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Vulnerability Findings</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="vuln-search" placeholder="Search ID or package..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64"><select id="vuln-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select><select id="vuln-filter-reachability" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Reachability</option><option value="reachable">Reachable</option><option value="unreachable">Unreachable</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix Available</th><th>Policy Violation</th><th>Fixed Versions</th><th>Reachability</th><th class="text-right">Action</th></tr></thead><tbody id="vuln-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Inventory Section -->
        <section id="section-inventory" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Package Inventory</h2><div class="flex gap-2 w-full md:w-auto flex-wrap"><input type="text" id="inv-search" placeholder="Search packages..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64"><select id="inv-filter-state" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All States</option><option value="safe">Safe</option><option value="vulnerable">Vulnerable</option><option value="infected">Infected</option><option value="undetermined">Undetermined</option></select><select id="inv-filter-direct" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All</option><option value="direct">Direct</option><option value="transitive">Transitive</option></select><select id="inv-filter-policy" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All</option><option value="violate">Violates Policy</option><option value="safe">Policy Safe</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th>Name</th><th>Version</th><th>Direct</th><th>State</th><th>Policy Violation</th><th>Ecosystem</th><th>License</th><th>Scopes</th></tr></thead><tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Dependency Sequences Section (replaces old graph) -->
        <section id="section-graph" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Dependency Sequences for Vulnerable/Infected Packages</h2>
                <div class="relative w-full md:w-auto" id="pkg-dropdown-wrapper">
                    <div class="relative">
                        <input type="text" id="pkg-select-input" placeholder="Search package…" autocomplete="off" spellcheck="false"
                            class="bg-neutral-800 border border-neutral-700 hover:border-neutral-500 focus:border-red-500 rounded-lg pl-4 pr-8 py-2 text-sm w-full md:w-72 focus:outline-none focus:ring-2 focus:ring-red-500/30 transition-colors placeholder-neutral-500 text-white"
                            oninput="filterPkgDropdown(this.value)" onfocus="openPkgDropdown()" onblur="closePkgDropdown()" />
                        <svg id="pkg-chevron" class="pointer-events-none absolute right-2.5 top-1/2 -translate-y-1/2 text-neutral-500 transition-transform duration-200" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polyline points="6 9 12 15 18 9"/></svg>
                    </div>
                    <ul id="pkg-options-list" class="hidden absolute right-0 mt-1 w-full md:w-72 max-h-64 overflow-y-auto bg-neutral-900 border border-neutral-700 rounded-lg shadow-xl z-50 py-1" role="listbox"></ul>
                </div>
            </div>
            <div class="glass rounded-xl p-6">
                <div id="sequences-container" class="space-y-4">
                    <div class="text-neutral-500 italic text-center p-8">Select a package from the list to view its dependency sequences.</div>
                </div>
            </div>
        </section>
        <!-- Detailed Stats Section -->
        <section id="section-stats" class="hidden space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Inventory Stats</h3><div class="h-48"><canvas id="statsInventoryChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-neutral-500">Total Size</span><span class="mono" id="stats-inv-size">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Safe</span><span class="mono text-green-400" id="stats-inv-safe">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Vulnerable</span><span class="mono text-yellow-400" id="stats-inv-vuln">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Infected</span><span class="mono text-red-400" id="stats-inv-inf">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Undetermined</span><span class="mono text-gray-400" id="stats-inv-und">0</span></div></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Vulnerability Stats</h3><div class="h-48"><canvas id="statsVulnChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-neutral-500">Total Found</span><span class="mono" id="stats-vuln-total">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Critical</span><span class="mono text-red-600" id="stats-vuln-crit">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">High</span><span class="mono text-red-400" id="stats-vuln-high">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Medium</span><span class="mono text-orange-400" id="stats-vuln-med">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Low</span><span class="mono text-blue-400" id="stats-vuln-low">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Unknown</span><span class="mono text-gray-400" id="stats-vuln-unk">0</span></div></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Known Exploited (CISA KEV)</h3><div class="h-48"><canvas id="statsKevChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-red-400">KEV</span><span class="mono text-red-400" id="stats-vuln-kev">0</span></div><div class="flex justify-between text-sm"><span class="text-blue-400">Not in KEV</span><span class="mono text-blue-400" id="stats-vuln-nonkev">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Unknown</span><span class="mono text-gray-400" id="stats-vuln-kevunk">0</span></div></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Ecosystem Distribution</h3><div class="h-48"><canvas id="statsEcoChart"></canvas></div><div id="eco-legend" class="grid grid-cols-2 gap-2 text-[10px] mono text-neutral-500"></div></div>
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">License Risk</h3><div class="h-48"><canvas id="statsLicenseChart"></canvas></div><div class="space-y-2"><div class="flex justify-between text-sm"><span class="text-neutral-500">Total Classified</span><span class="mono" id="stats-license-total">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Low</span><span class="mono text-green-400" id="stats-license-low">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Medium</span><span class="mono text-orange-400" id="stats-license-med">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">High</span><span class="mono text-red-400" id="stats-license-high">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">Unknown</span><span class="mono text-gray-400" id="stats-license-unk">0</span></div><div class="flex justify-between text-sm"><span class="text-neutral-500">OSI Approved</span><span class="mono text-blue-400" id="stats-license-osi">0</span></div></div></div>
            </div>
        </section>
        <!-- Compliance Section -->
        <section id="section-compliance" class="hidden space-y-8">
            <p id="compliance-disclaimer" class="text-xs text-neutral-500 italic bg-neutral-900/50 p-3 rounded-lg border border-neutral-800"></p>
            <div id="compliance-frameworks-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
            <div id="compliance-empty" class="hidden text-sm text-neutral-500 italic">No findings mapped to a compliance framework.</div>
        </section>
        <!-- System Section -->
        <section id="section-system" class="hidden space-y-8">
  <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

    <!-- Runtime -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
        </svg>
        Runtime
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Environment</span>
          <span class="mono text-xs" id="run-env">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Version</span>
          <span class="mono text-xs" id="run-node">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Platform</span>
          <span class="mono text-xs" id="run-platform">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Arch</span>
          <span class="mono text-xs" id="run-arch">...</span>
        </div>
        <div class="flex flex-col gap-1">
          <span class="text-neutral-500 text-xs">CWD</span>
          <span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="run-cwd">...</span>
        </div>
      </div>
    </div>

    <!-- Engine -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/>
        </svg>
        Engine & Tool
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Engine Name</span>
          <span class="mono text-xs" id="engine-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Engine Version</span>
          <span class="mono text-xs" id="engine-version">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Tool Name</span>
          <span class="mono text-xs" id="tool-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Tool Version</span>
          <span class="mono text-xs" id="tool-version">...</span>
        </div>
      </div>
    </div>

    <!-- Scan Info -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="11" cy="11" r="8"/>
          <line x1="21" y1="21" x2="16.65" y2="16.65"/>
        </svg>
        Scan Info
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Scan Type</span>
          <span class="mono text-xs" id="scan-type">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Ecosystems</span>
          <span class="mono text-xs" id="scan-ecosystems">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Scan Engine</span>
          <span class="mono text-xs" id="scan-engine">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Scan Scope</span>
          <span class="mono text-xs" id="scan-scope">...</span>
        </div>
      </div>
    </div>

    <!-- OS -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <rect x="2" y="3" width="20" height="14" rx="2" ry="2"/>
          <line x1="8" y1="21" x2="16" y2="21"/>
          <line x1="12" y1="17" x2="12" y2="21"/>
        </svg>
        OS Metadata
      </h3>
      <div class="space-y-3">
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS ID</span>
          <span class="mono text-xs" id="os-id">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS Name</span>
          <span class="mono text-xs" id="os-name">...</span>
        </div>
        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">OS Version</span>
          <span class="mono text-xs" id="os-version">...</span>
        </div>
        <div class="flex flex-col gap-1">
          <span class="text-neutral-500 text-xs">Local IPs</span>
          <div id="os-local-ips" class="mono text-[10px] text-neutral-300 space-y-0.5"></div>
        </div>
      </div>
    </div>

    <!-- Git (fixed) -->
    <div class="glass p-6 rounded-xl space-y-4">
      <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2">
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
          <circle cx="18" cy="18" r="3"/>
          <circle cx="6" cy="6" r="3"/>
          <path d="M13 6h3a2 2 0 0 1 2 2v7"/>
          <line x1="6" y1="9" x2="6" y2="21"/>
        </svg>
        Git Metadata
      </h3>

      <div class="space-y-3">

        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Git version</span>
          <span class="mono text-xs" id="git-version">...</span>
        </div>

        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Latest commit</span>
          <span class="mono text-xs" id="git-rev">...</span>
        </div>

        <div class="flex justify-between border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Branch</span>
          <span class="mono text-xs" id="git-branch">...</span>
        </div>

        <div class="flex flex-col gap-1">
          <span class="text-neutral-500 text-xs">Remote URL</span>
          <span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="git-url">...</span>
        </div>

      </div>
    </div>

  </div>
</section>
        <!-- Secrets Section -->
        <section id="section-secrets" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Secrets Found in Source</h2>
                <div class="flex gap-2 w-full md:w-auto">
                    <input type="text" id="secrets-search" placeholder="Search file or rule..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64">
                    <select id="secrets-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                        <option value="unknown">Unknown</option>
                    </select>
                </div>
            </div>
            <div id="secrets-disabled-banner" class="hidden glass p-4 rounded-xl text-sm text-neutral-400 italic">Secrets scanning was disabled for this scan.</div>
            <div class="glass rounded-xl overflow-hidden">
                <table class="w-full text-left text-sm">
                    <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">
                        <tr><th class="px-6 py-4">Severity</th><th>Rule</th><th>Category</th><th>Location</th><th>Line</th><th>Preview</th></tr>
                    </thead>
                    <tbody id="secrets-table-body" class="divide-y divide-neutral-800"></tbody>
                </table>
            </div>
        </section>
    </main>
    <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50"><div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4"><p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">Ubel Security Engine</span></p></div></footer>
    <div id="modal-overlay" class="modal-overlay items-center justify-center p-4" style="display: none;">
        <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
            <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
            <div id="modal-body" class="p-8"></div>
        </div>
    </div>
    <script>${clientScript}</script>
</body>
</html>`;
}

function fetchJSON(url, method = "GET", body = null, opts = {}) {
  const {
    timeoutMs = 40000,
    maxRetries = 5,
  } = opts;

  return new Promise((resolve, reject) => {
    let attempt = 0;

    const attemptRequest = () => {
      attempt++;

      const parsed = new URL(url);
      const lib = parsed.protocol === "https:" ? https : http;

      const options = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers: {
          "Content-Type": "application/json",
          "User-Agent": "ubel_tool",
        },
      };

      let timedOut = false;
      let responseReceived = false;

      const req = lib.request(options, (res) => {
        responseReceived = true;
        let data = "";
        const MAX_SIZE = 5 * 1024 * 1024;

        res.on("data", (chunk) => {
          data += chunk;
          if (data.length > MAX_SIZE) {
            req.destroy(new Error("Response too large"));
          }
        });

        res.on("end", () => {
          if (timedOut) return;

          const status = res.statusCode;

          if ((status === 429 || status >= 500) && attempt < maxRetries) {
            const delay = 200 * (2 ** (attempt - 1));
            return setTimeout(() => attemptRequest(), delay);
          }

          try {
            resolve({ status, body: JSON.parse(data) });
          } catch {
            resolve({ status, body: data });
          }
        });
      });

      req.on("error", (err) => {
        if (timedOut) return;

        if (attempt < maxRetries) {
          const delay = 200 * (2 ** (attempt - 1));
          return setTimeout(() => attemptRequest(), delay);
        }

        reject(err);
      });

      req.setTimeout(timeoutMs, () => {
        if (responseReceived) return;
        timedOut = true;
        req.destroy(new Error("Request timeout"));

        if (attempt < maxRetries) {
          const delay = 200 * (2 ** (attempt - 1));
          return setTimeout(() => attemptRequest(), delay);
        }

        reject(new Error(`Request timed out after ${maxRetries} attempts`));
      });

      if (body) {
        try {
          req.write(JSON.stringify(body));
        } catch (err) {
          return reject(err);
        }
      }

      req.end();
    };

    attemptRequest();
  });
}

// ── PURL helpers ──────────────────────────────────────────────────────────────
export function getDependencyFromPurl(purl) {
  if (!purl || typeof purl !== "string" || !purl.startsWith("pkg:")) {
    return ["unknown", ""];
  }

  // Remove "pkg:"
  let body = purl.slice(4);

  // Strip qualifiers (?...) and subpath (#...)
  body = body.split("?")[0].split("#")[0];

  // Extract type
  const firstSlash = body.indexOf("/");
  if (firstSlash === -1) return ["unknown", ""];

  const type = body.slice(0, firstSlash);
  let remainder = body.slice(firstSlash + 1);

  // Decode percent encoding
  remainder = decodeURIComponent(remainder);

  // Extract version (last @ only)
  let name = "unknown";
  let version = "";
  const lastAt = remainder.lastIndexOf("@");

  if (lastAt > 0) {
    name = remainder.slice(0, lastAt);
    version = remainder.slice(lastAt + 1);
  } else {
    name = remainder;
  }

  // Normalize per ecosystem
  switch (type) {
    case "npm":
      // @scope/name OR name
      return [name, version];

    case "pypi":
      return [name.toLowerCase(), version];

    case "golang":
      // github.com/user/repo[/subpkg]
      return [name, version];

    case "maven": {
      return [name, version];
    }

    case "nuget":
      return [name.toLowerCase(), version];

    case "cargo":
      // rust
      return [name, version];

    case "gem":
      // ruby
      return [name, version];

    case "deb":
    case "rpm": {
      // distro packages (debian, ubuntu, rhel, rocky, almalinux)
      // format: distro/name
      const parts = name.split("/");
      return [parts[parts.length - 1], version];
    }

    default:
      return [name, version];
  }
}

export function getEcosystemFromPurl(purl) {
  if (purl.startsWith("cpe:"))        return "windows";
  if (purl.startsWith("pkg:gem/"))        return "ruby";
  if (purl.startsWith("pkg:nuget/"))      return "dotnet";
  if (purl.startsWith("pkg:npm/"))          return "npm";
  if (purl.startsWith("pkg:maven/"))        return "java";
  if (purl.startsWith("pkg:golang/"))       return "golang";
  if (purl.startsWith("pkg:cargo/"))        return "rust";
  if (purl.startsWith("pkg:composer/"))       return "php";
  if (purl.startsWith("pkg:pypi/"))         return "python";
  if (purl.startsWith("pkg:conda/"))        return "conda";
  if (purl.startsWith("pkg:swift/"))        return "swift";
  if (purl.startsWith("pkg:pub/"))          return "dart";
  if (purl.startsWith("pkg:deb/ubuntu/"))   return "ubuntu";
  if (purl.startsWith("pkg:deb/debian/"))   return "debian";
  if (purl.startsWith("pkg:rpm/redhat/"))   return "redhat";
  if (purl.startsWith("pkg:apk/alpine/"))   return "alpine";
  return "unknown";
}

// ── NVD CPE querying ──────────────────────────────────────────────────────────
//
// Queries the NVD REST API for each CPE string that does NOT start with "pkg:"
// (i.e. items from the Windows/Linux host scanner that have a CPE 2.3 id).
// Results are normalised into the same shape the OSV enrichment pipeline
// expects so they can flow through processVulnerability / getFix unchanged.
//
// Rate-limit: NVD allows ~5 req/30 s without an API key.  We use a serial
// queue with per-request exponential backoff (same fetchJSON opts) so we
// never hammer the endpoint.
//
// Overridable via UBEL_NVD_ENDPOINT for self-hosted/air-gapped mirrors —
// same scoping note as UBEL_OSV_ENDPOINT above: this only affects the live
// CPE query below, not the "view online" nvd.nist.gov reference link
// generated per-finding elsewhere, which assumes the public site's structure.

const NVD_CVE_BASE = (process.env.UBEL_NVD_ENDPOINT || "https://services.nvd.nist.gov/rest/json/cves/2.0").replace(/\/+$/, "");

/**
 * Pick the best available CVSS vector + score from an NVD CVE entry.
 * Preference order (highest fidelity first): 4.0 → 3.1 → 3.0 → 2.0
 * NVD uses both "cvssMetricV40" and "cvssMetricV4" as key names across
 * different API versions, so we check both aliases for the 4.x family.
 */
function extractNvdCvss(metrics = {}) {
  // CVSS 4.0 — try both key variants emitted by different NVD API versions
  const v40 = (metrics.cvssMetricV40 || metrics.cvssMetricV4 || [])[0];
  if (v40?.cvssData) {
    return {
      score:   v40.cvssData.baseScore,
      vector:  v40.cvssData.vectorString,
      version: "4.0",
    };
  }
  // CVSS 3.1
  const v31 = (metrics.cvssMetricV31 || [])[0];
  if (v31?.cvssData) {
    return {
      score:   v31.cvssData.baseScore,
      vector:  v31.cvssData.vectorString,
      version: "3.1",
    };
  }
  // CVSS 3.0
  const v30 = (metrics.cvssMetricV30 || [])[0];
  if (v30?.cvssData) {
    return {
      score:   v30.cvssData.baseScore,
      vector:  v30.cvssData.vectorString,
      version: "3.0",
    };
  }
  // CVSS 2.0
  const v2 = (metrics.cvssMetricV2 || [])[0];
  if (v2?.cvssData) {
    return {
      score:   v2.cvssData.baseScore,
      vector:  v2.cvssData.vectorString,
      version: "2.0",
    };
  }
  return { score: null, vector: null, version: null };
}

/**
 * Map a CVSS base score to a severity label.
 */
export function scoreToSeverity(score) {
  if (score == null) return "unknown";
  if (score >= 9.0)  return "critical";
  if (score >= 7.0)  return "high";
  if (score >= 4.0)  return "medium";
  if (score >= 0.1)  return "low";
  return "unknown";
}

// ── NVD local version verification ───────────────────────────────────────────
// NVD's `cpeName` query is a broad match. Even with `isVulnerable` it can hand
// back CVEs whose matching entry is a bare "all versions" wildcard, and a mirror
// set via UBEL_NVD_ENDPOINT may ignore the flag entirely. So every returned CVE
// is re-checked here against the cpeMatch entries for this vendor:product.

/** -1 / 0 / 1, or null when either side isn't parseable as a version. */
function nvdVersionCmp(a, b) {
  const pa = _vr_parseSemver(String(a ?? "").trim());
  const pb = _vr_parseSemver(String(b ?? "").trim());
  if (!pa || !pb) return null;
  if (_vr_semverGt(pa, pb)) return 1;
  if (_vr_semverGt(pb, pa)) return -1;
  return 0;
}

/** Does one `vulnerable: true` cpeMatch entry cover `installed`? Unparseable => true (fail open). */
function nvdMatchCoversVersion(match, installed, { dropUnboundedMatches = false } = {}) {
  const critVersion = (match.criteria || "").split(":")[5] ?? "*";
  const startInc = match.versionStartIncluding, startExc = match.versionStartExcluding;
  const endInc   = match.versionEndIncluding,   endExc   = match.versionEndExcluding;
  const hasRange = !!(startInc || startExc || endInc || endExc);

  // Exact version in the criteria, no range: affected only on equality.
  if (critVersion !== "*" && critVersion !== "-" && !hasRange) {
    const c = nvdVersionCmp(installed, critVersion);
    return c === null ? String(installed ?? "").trim().toLowerCase() === critVersion.toLowerCase() : c === 0;
  }

  // Bare wildcard with no bound: NVD saying "every version".
  if (!hasRange) return !dropUnboundedMatches;

  const checks = [
    [startInc, c => c >= 0],
    [startExc, c => c >  0],
    [endInc,   c => c <= 0],
    [endExc,   c => c <  0],
  ];
  for (const [bound, ok] of checks) {
    if (!bound) continue;
    const c = nvdVersionCmp(installed, bound);
    if (c === null) return true;   // can't evaluate — don't silently drop a lead
    if (!ok(c)) return false;
  }
  return true;
}

/**
 * True if at least one `vulnerable: true` cpeMatch for the queried vendor:product
 * covers the installed version. If the CVE has no usable entries for this product
 * at all (e.g. awaiting analysis), fails open and keeps it.
 */
function nvdCveAffectsVersion(cveData, cpe, installed, opts = {}) {
  const cpePrefix = cpe.split(":").slice(0, 5).join(":").toLowerCase();
  let candidates = 0;
  for (const config of (cveData.configurations || [])) {
    for (const node of (config.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (!match.vulnerable) continue;   // platform / "running on" entry — not this product being vulnerable
        const prefix = (match.criteria || "").split(":").slice(0, 5).join(":").toLowerCase();
        if (prefix !== cpePrefix) continue;
        candidates++;
        if (nvdMatchCoversVersion(match, installed, opts)) return true;
      }
    }
  }
  // No vulnerable entry for this product: if the CVE has configuration data at all,
  // our product only appears as a platform/"running on" entry => not a finding.
  // If it has no configuration data (not yet analysed), keep it rather than drop a lead.
  if (candidates === 0) return !hasAnyNvdConfig(cveData);
  return false;
}

function hasAnyNvdConfig(cveData) {
  return (cveData.configurations || []).some(c => (c.nodes || []).some(n => (n.cpeMatch || []).length));
}

/**
 * Convert a single NVD CVE item into the OSV-compatible shape that the
 * rest of the pipeline (processVulnerability, getFix, etc.) consumes.
 *
 * @param {object} nvdItem   - One element from NVD response `.vulnerabilities[]`
 * @param {string} cpe       - The CPE string used to query NVD (used as affected_package_id)
 * @param {string} name      - Human-readable package name
 * @param {string} version   - Installed version string
 * @param {string} ecosystem - e.g. "windows"
 * @param {object} [opts]
 * @param {boolean} [opts.verifyVersion=true]  re-check, locally, that the installed
 *   version really falls inside a `vulnerable: true` cpeMatch for this product; items
 *   that don't are dropped (returns null). Fails open when a version can't be parsed.
 * @param {boolean} [opts.dropUnboundedMatches=false]  also drop CVEs whose only matching
 *   entry is a bare wildcard (`*` version, no start/end bound at all) — NVD's "every
 *   version ever" placeholder, which is what shows up as old, unfixable-looking noise.
 * @returns {object|null} OSV-shaped vuln, or null if filtered out
 */
function nvdItemToOsvShape(nvdItem, cpe, name, version, ecosystem, opts = {}) {
  const cveData = nvdItem.cve || nvdItem;
  const cveId   = cveData.id || cveData.CVE_data_meta?.ID || "";

  // REJECTED / disputed-away CVEs carry no configurations and no real finding.
  if (/^\*\* REJECT \*\*/.test((cveData.descriptions || []).find(d => d.lang === "en")?.value || "")
      || cveData.vulnStatus === "Rejected") {
    return null;
  }
  if (opts.verifyVersion !== false && !nvdCveAffectsVersion(cveData, cpe, version, opts)) {
    return null;
  }

  const desc = (cveData.descriptions || [])
    .find(d => d.lang === "en")?.value || "";

  const cvss = extractNvdCvss(cveData.metrics || {});

  const refs = (cveData.references || []).map(r => ({
    type: "WEB",
    url:  r.url,
  }));

  // ── Fix extraction from NVD CPE configurations ───────────────────────────
  // NVD encodes fixed versions inside configurations[].nodes[].cpeMatch[]
  // as versionEndExcluding (exclusive upper bound → that version IS the fix)
  // or versionEndIncluding (inclusive upper bound → fix is "something higher").
  // We match each cpeMatch entry against the queried CPE by comparing the
  // vendor:product prefix (fields 3-4 of the colon-split CPE 2.3 string).
  //
  // CPE 2.3 format:  cpe:2.3:a:<vendor>:<product>:<version>:...
  //                  idx: 0   1  2       3          4         5+
  const cpePrefix = cpe.split(":").slice(0, 5).join(":");   // up to <product>

  const fixedVersions  = [];
  const fixRanges      = [];   // [{ start, fixed }] — one per branch NVD lists
  const lastAffected   = [];

  for (const config of (cveData.configurations || [])) {
    for (const node of (config.nodes || [])) {
      for (const match of (node.cpeMatch || [])) {
        if (!match.vulnerable) continue;
        // Match when the criteria shares the same vendor:product prefix.
        const matchPrefix = (match.criteria || "").split(":").slice(0, 5).join(":");
        if (matchPrefix.toLowerCase() !== cpePrefix.toLowerCase()) continue;

        if (match.versionEndExcluding) {
          // The first version that is NOT affected → it is the fix version.
          fixedVersions.push(match.versionEndExcluding);
          // Keep the branch's lower bound too (versionStartIncluding, or
          // versionStartExcluding approximated as inclusive). Without it every
          // fix looked like "0 -> fix", so a lower branch's fix (1.2.5 next to
          // 1.3.2) read as still-affected and per-range upgrade suggestions
          // (suggested_fixes.js) could never pick it.
          fixRanges.push({
            start: match.versionStartIncluding || match.versionStartExcluding || "0",
            fixed: match.versionEndExcluding,
          });
        } else if (match.versionEndIncluding) {
          // Last known affected version — fix is "upgrade beyond this".
          lastAffected.push(match.versionEndIncluding);
        }
      }
    }
  }

  // Deduplicate
  const uniqueFixes       = [...new Set(fixedVersions)];
  const uniqueLastAffected = [...new Set(lastAffected)];

  // Build an OSV-compatible "affected" block so getFix / get_fixed_versions
  // can consume the data without special-casing the NVD path.
  const affectedRangeEvents = [];
  const seenRange = new Set();
  for (const r of fixRanges) {
    const k = r.start + "|" + r.fixed;
    if (seenRange.has(k)) continue;
    seenRange.add(k);
    affectedRangeEvents.push({ introduced: r.start }, { fixed: r.fixed });
  }

  const affected = [{
    package:  { name, ecosystem, purl: cpe },
    ranges:   affectedRangeEvents.length
      ? [{ type: "ECOSYSTEM", events: affectedRangeEvents }]
      : [],
    versions: uniqueLastAffected.length ? uniqueLastAffected : [version],
  }];

  // ── CWE extraction from NVD weaknesses ──────────────────────────────────
  // NVD encodes CWEs under cve.weaknesses[].description[].value as "CWE-NNN".
  const cweSet = new Set();
  for (const weakness of (cveData.weaknesses || [])) {
    for (const desc of (weakness.description || [])) {
      if (desc.lang === "en" && typeof desc.value === "string") {
        const n = parseInt(desc.value.replace(/^CWE-/i, ""), 10);
        if (!isNaN(n)) cweSet.add(n);
      }
    }
  }
  const cwes = [...cweSet];

  return {
    id:           cveId,
    aliases:      [],
    related:      [],
    source:       "nvd",
    published:    cveData.published    || "",
    modified:     cveData.lastModified || "",
    summary:      desc.slice(0, 200),
    details:      desc,
    severity:     scoreToSeverity(cvss.score),
    severity_score: cvss.score,
    severity_vector: cvss.vector,
    cwes,
    references:   refs,
    affected,

    // pipeline fields populated later by getFix / processVulnerability
    affected_package_id:               cpe,
    affected_dependency:         name,
    affected_dependency_version: version,
    ecosystem,
    url:        `https://nvd.nist.gov/vuln/detail/${cveId}`,
    is_infection: false,
  };
}

/**
 * Query NVD for one CPE string.  Returns an array of OSV-shaped vuln objects.
 * Sleeps 650 ms between requests to stay under the unauthenticated rate limit
 * (5 req / 30 s ≈ one every 6 s; we batch per-CPE sequentially so the delay
 * is added *between* CPEs, not inside fetchJSON's own backoff).
 *
 * @param {string} cpe       CPE 2.3 string
 * @param {string} name      package name (for the OSV shape)
 * @param {string} version   installed version
 * @param {string} ecosystem e.g. "windows"
 */

/**
 * For every inventory item whose id does NOT start with "pkg:" (i.e. CPE-based
 * items from the host scanners), query NVD and return enriched vuln objects in
 * OSV shape.  Runs requests serially with a 700 ms inter-request gap to respect
 * the NVD rate limit.
 *
 * @param {object[]} inventory  Full merged inventory array
 * @returns {Promise<object[]>} Array of OSV-shaped vulnerability objects
 */
// ── Lookup failure sentinel ───────────────────────────────────────────────────
// Thrown when a vulnerability lookup (OSV batch query, OSV advisory detail, or
// NVD) could not be completed.  A scan that could not look vulnerabilities up
// has NOT established that the dependencies are clean, so callers must treat
// this as a failed scan — non-zero exit, lockfile reverted, nothing installed —
// and never as "0 findings / ALLOW".  `source` is "osv", "osv-vuln" or "nvd".
export class VulnLookupError extends Error {
  constructor(message, { source = "unknown", cause } = {}) {
    super(message);
    this.name   = "VulnLookupError";
    this.source = source;
    if (cause) this.cause = cause;
  }
}

/**
 * Query NVD for one CPE string.  Returns { status, vulns } so the caller
 * can distinguish 429 (rate-limited) from real errors.
 */
async function queryNvdForCpe(cpe, name, version, ecosystem, opts = {}) {
  // isVulnerable: only CVEs where this CPE is the *vulnerable* component. Without it,
  // cpeName also matches CVEs that merely list the CPE as the platform another product
  // runs on (WordPress core, PHP, Apache... for every plugin/app CVE) — the usual source
  // of a flood of old CVEs with no fix data. noRejected: skip REJECTED records.
  // Both are valueless flags in the NVD 2.0 API.
  const url = `${NVD_CVE_BASE}?cpeName=${encodeURIComponent(cpe)}&isVulnerable&noRejected`;
  const res  = await fetchJSON(url, "GET", null, {
    timeoutMs:  40_000,
    maxRetries: 1,   // no internal backoff — submitToNvd owns retry for 429
  });

  if (res.status === 429 || res.status === 503) {
    return { status: res.status, vulns: [] };
  }

  // NVD answers 400/404 for a cpeName it cannot resolve (e.g. one that is not
  // in the CPE dictionary).  That is "NVD has nothing for this CPE", which is a
  // complete answer — not a failed lookup.
  if (res.status === 400 || res.status === 404) {
    return { status: 200, vulns: [] };
  }

  if (res.status !== 200) {
    return { status: res.status, vulns: [] };
  }

  const items = (res.body?.vulnerabilities || [])
    .map(item => nvdItemToOsvShape(item, cpe, name, version, ecosystem, opts))
    .filter(Boolean);
  return { status: 200, vulns: items };
}

/**
 * @param {object[]} inventory
 * @param {object}   [opts]
 * @param {boolean}  [opts.verifyVersion=true]         re-check each returned CVE's cpeMatch ranges
 *   against the installed version and drop non-matches (see nvdItemToOsvShape)
 * @param {boolean}  [opts.dropUnboundedMatches=false] also drop CVEs matched only by a bare
 *   `*` wildcard with no version bound (NVD's "all versions" placeholder)
 */
export async function submitToNvd(inventory, opts = {}) {
  console.log("[*] Submitting CPE items to NVD for enrichment...");

  const cpeItems = inventory.filter(item => !item.id.startsWith("pkg:"));
  console.log(`[*] Found ${cpeItems.length} CPE items to query NVD for.`);
  if (!cpeItems.length) return [];

  const NVD_INTER_REQUEST_DELAY_MS = 5_000;  // 5 s between each CPE request
  const NVD_RATELIMIT_RETRY_MS     = 5_000;   // 5 s between retries on 429/503
  const NVD_MAX_RETRIES            = 5;        // max attempts per CPE on 429/503
  const results = [];

  for (let i = 0; i < cpeItems.length; i++) {
    const item = cpeItems[i];

    // Retry loop: up to NVD_MAX_RETRIES attempts on 429/503, 5 s apart.
    let attempt = 0;
    while (true) {
      try {
        const { status, vulns } = await queryNvdForCpe(
          item.id,
          item.name,
          item.version,
          item.ecosystem || "unknown",
          opts
        );

        if (status === 429 || status === 503) {
          attempt++;
          if (attempt >= NVD_MAX_RETRIES) {
            // Fail closed: skipping this CPE would silently drop its CVEs.
            throw new VulnLookupError(
              `NVD returned HTTP ${status} for ${item.id} after ${NVD_MAX_RETRIES} attempts — vulnerability lookup is incomplete.`,
              { source: "nvd" }
            );
          }
          console.warn(`[~] NVD ${status} on ${item.id} (attempt ${attempt}/${NVD_MAX_RETRIES}), retrying in ${NVD_RATELIMIT_RETRY_MS / 1000}s...`);
          await new Promise(r => setTimeout(r, NVD_RATELIMIT_RETRY_MS));
          continue; // retry same item
        }

        if (status !== 200) {
          throw new VulnLookupError(
            `NVD query failed for ${item.id}: HTTP ${status} — vulnerability lookup is incomplete.`,
            { source: "nvd" }
          );
        }

        results.push(...vulns);
        break; // success — move to next item

      } catch (err) {
        if (err instanceof VulnLookupError) throw err;
        // Network-level failure (DNS, TLS, timeout, reset): same rule — a CPE
        // we could not query is a CPE we could not clear.
        throw new VulnLookupError(
          `NVD query error for ${item.id}: ${err.message} — vulnerability lookup is incomplete.`,
          { source: "nvd", cause: err }
        );
      }
    }

    // Inter-request delay (skip after last item)
    if (i < cpeItems.length - 1) {
      await new Promise(r => setTimeout(r, NVD_INTER_REQUEST_DELAY_MS));
    }
  }

  return results;
}

// ── OSV querying ──────────────────────────────────────────────────────────────
export async function submitToOsv(purlsList) {
  // pkg:conda/ is excluded: OSV has no conda ecosystem, and a purl type it
  // can't map risks failing the whole batch (any non-200 fails the scan).
  // Python conda packages are emitted as pkg:pypi/ by conda_runner.js instead.
  purlsList = purlsList.filter(p => p.startsWith("pkg:") && !p.startsWith("pkg:conda/"));
  if (!purlsList.length) return [];

  const PAGE = 800;
  const results = [];

  for (let offset = 0; offset < purlsList.length; offset += PAGE) {
    const chunk   = purlsList.slice(offset, offset + PAGE);
    const queries = chunk.map((purl) => ({ package: { purl } }));
    let res;
    try {
      res = await fetchJSON(OSV_QUERYBATCH, "POST", { queries });
    } catch (err) {
      throw new VulnLookupError(
        `OSV batch query could not be completed: ${err.message} — vulnerability lookup is incomplete.`,
        { source: "osv", cause: err }
      );
    }

    if (res.status !== 200) {
      const detail = typeof res.body === "string" ? res.body.slice(0, 200) : JSON.stringify(res.body)?.slice(0, 200);
      throw new VulnLookupError(
        `OSV batch query failed: HTTP ${res.status}${detail ? ` (${detail})` : ""} — vulnerability lookup is incomplete.`,
        { source: "osv" }
      );
    }

    // OSV returns exactly one result per query, in order.  Anything else means
    // the answer was truncated or malformed, and indexing it by position would
    // attribute (or miss) findings against the wrong packages.
    const vulnResults = res.body?.results;
    if (!Array.isArray(vulnResults) || vulnResults.length !== chunk.length) {
      throw new VulnLookupError(
        `OSV batch query returned ${Array.isArray(vulnResults) ? vulnResults.length : "no"} result(s) for ${chunk.length} package(s) — vulnerability lookup is incomplete.`,
        { source: "osv" }
      );
    }
    vulnResults.forEach((item, i) => {
      const purl     = chunk[i];
      const [dep, ver] = getDependencyFromPurl(purl);
      for (const v of (item.vulns || [])) {
        results.push({ purl, vulnerability_id: v.id, dependency: dep, affected_version: ver, source: "osv" });
      }
    });
  }
  return results;
}

// ── Vulnerability enrichment ──────────────────────────────────────────────────
function generateFix(ranges, versions, pkgName, ecosystem) {
  const fixed = [];
  const lastAffected = [];

  for (const range of ranges) {
    for (const event of (range.events || [])) {
      if (event.fixed)         fixed.push(event.fixed);
      if (event.last_affected) lastAffected.push(event.last_affected);
    }
  }

  const fallback = lastAffected;//.length ? lastAffected : versions;

  if (fixed.length)
    return `Upgrade ${pkgName} ( ${ecosystem} ) to: ${fixed.join(" or ")}`;
  if (fallback.length)
    return `Upgrade ${pkgName} ( ${ecosystem} ) to a version higher than: ${fallback.join(" or ")}`;
  return `No fix available for ${pkgName}`;
}

function get_fixed_versions(vuln) {
  const fixedVersions = [];
  for (const item of (vuln.affected || [])) {
    const pkg    = item.package || {};
    const ranges = item.ranges  || [];
    if ((pkg.name || "").toLowerCase() === (vuln.affected_dependency || "").toLowerCase()) {
      for (const range of ranges) {
        for (const event of (range.events || [])) {
          if (event.fixed) fixedVersions.push(event.fixed);
        }
      }
    }
  }
  return fixedVersions;
}

function get_last_affected_versions(vuln) {
  const lastAffected = [];
  for (const item of (vuln.affected || [])) {
    const pkg    = item.package || {};
    const ranges = item.ranges  || [];
    if ((pkg.name || "").toLowerCase() === (vuln.affected_dependency || "").toLowerCase()) {
      for (const range of ranges) {
        for (const event of (range.events || [])) {
          if (event.last_affected) lastAffected.push(event.last_affected);
        }
      }
    }
  }
  return [...new Set(lastAffected)];
}

export function getFix(vuln) {
  const remediations = [];
  const dep = vuln.affected_dependency;

  for (const item of (vuln.affected || [])) {
    const pkg    = item.package || {};
    const ranges = item.ranges  || [];
    const versions = item.versions || [];
    if ((pkg.name || "").toLowerCase() === dep.toLowerCase()) {
      remediations.push(generateFix(ranges, versions, pkg.name, pkg.ecosystem));
    }
  }

  vuln.fixed_versions        = get_fixed_versions(vuln);
  vuln.last_affected_versions = get_last_affected_versions(vuln);
  vuln.fixes                 = remediations;
  vuln.has_fix               = vuln.fixed_versions.length > 0;
  vuln.description           = (vuln.description || vuln.details || vuln.summary || "").trim();
  delete vuln.details;
  delete vuln.summary;

  // Ranked fix versions for the modal upgrade table
  const _vrEco = _vr_purlToEcosystem(vuln.affected_package_id || "");
  vuln.fix_versions_ranked = vuln.fixed_versions.length > 0
    ? findClosestFixVersions(vuln.affected_dependency_version || "", vuln.fixed_versions, _vrEco)
    : [];
  // Last-affected ranked table — shown only when no fixed versions exist
  vuln.last_affected_ranked = !vuln.has_fix && vuln.last_affected_versions.length > 0
    ? findClosestFixVersions(vuln.affected_dependency_version || "", vuln.last_affected_versions, _vrEco)
    : [];
}

export async function getVulnById({ vulnerability_id, purl, dependency, affected_version }) {
  let res;
  try {
    res = await fetchJSON(`${OSV_VULN_BASE}/${vulnerability_id}`);
  } catch (err) {
    throw new VulnLookupError(
      `OSV advisory ${vulnerability_id} could not be fetched: ${err.message}`,
      { source: "osv-vuln", cause: err }
    );
  }
  // OSV already told us this advisory affects the package (that is how we got
  // its id).  Returning null here used to drop it silently — including MAL-*
  // malicious-package advisories — so a failed detail fetch turned a known
  // finding into a clean result.
  if (res.status !== 200 || !res.body || typeof res.body !== "object") {
    throw new VulnLookupError(
      `OSV advisory ${vulnerability_id} could not be fetched: HTTP ${res.status}`,
      { source: "osv-vuln" }
    );
  }

  const data = res.body;
  processVulnerability(data);

  data.affected_package_id              = purl;
  data.affected_dependency        = dependency;
  data.affected_dependency_version = affected_version;
  data.ecosystem                = getEcosystemFromPurl(purl);
  data.url                        = `https://osv.dev/vulnerability/${vulnerability_id}`;
  data.is_infection               = (data.id || "").startsWith("MAL-");

  getFix(data);

  // Extract CWE integer IDs from OSV's database_specific before deleting it.
  // OSV stores them as ["CWE-674", ...]; we normalise to plain ints [674, ...].
  const dbSpecific = data.database_specific || {};
  const cweRaw = Array.isArray(dbSpecific.cwe_ids) ? dbSpecific.cwe_ids : [];
  data.cwes = cweRaw
    .map(c => parseInt(String(c).replace(/^CWE-/i, ""), 10))
    .filter(n => !isNaN(n));

  // Extract Indicators of Compromise (populated on OSV malicious-package
  // entries, e.g. MAL-*) from database_specific before deleting it below.
  // Only attached when at least one IOC value is present, to avoid
  // dragging empty {urls:[],domains:[],ips:[]} objects onto every
  // ordinary CVE-style vulnerability.
  const iocsRaw = dbSpecific.iocs || {};
  const iocs = {
    urls:    Array.isArray(iocsRaw.urls)    ? iocsRaw.urls    : [],
    domains: Array.isArray(iocsRaw.domains) ? iocsRaw.domains : [],
    ips:     Array.isArray(iocsRaw.ips)     ? iocsRaw.ips     : [],
  };
  if (iocs.urls.length || iocs.domains.length || iocs.ips.length) {
    data.iocs = iocs;
  }

  for (const key of ["database_specific", "affected", "schema_version"]) {
    delete data[key];
  }
  return data;
}

// ── Inventory helpers ─────────────────────────────────────────────────────────
function matchDependenciesWithInventory(inventory) {
  const purls = inventory.map((c) => c.id);
  for (const item of inventory) {
    const depKeys = item.dependencies || [];
    item.dependencies = depKeys.map((key) =>
      purls.find((p) => p.startsWith(key)) || null
    ).filter(Boolean);
  }
}

function setInventoryState(infectedPurls, vulnerablePurls, inventory) {
  for (const item of inventory) {
    // pkg:conda/ components are never matched against any database (see
    // submitToOsv) — leave them "undetermined" instead of claiming "safe".
    if (item.id.startsWith("pkg:conda/")) continue;
    if (item.version !== ""){
    if (infectedPurls.has(item.id))   item.state = "infected";
    else if (vulnerablePurls.has(item.id)) item.state = "vulnerable";
    else                               item.state = "safe";
  }
  }
}

// ── Impact-only dependency tree (kept for backwards compatibility but not used in graph)
//
// Builds the nested-dict tree passed to the HTML graph renderer, but only
// includes nodes that are 'vulnerable' or 'infected' plus every ancestor
// (package that transitively depends on them) so impact chains stay connected.
// Safe-only subtrees are omitted entirely, keeping the report size proportional
// to the number of findings rather than the full inventory.
//
function buildImpactDependencyTree(inventory) {
  const byId = new Map(inventory.map(c => [c.id, c]));

  // Build reverse map: child → Set of direct parents
  const parents = new Map(inventory.map(c => [c.id, new Set()]));
  for (const comp of inventory) {
    for (const dep of (comp.dependencies || [])) {
      if (parents.has(dep)) parents.get(dep).add(comp.id);
    }
  }

  // Seeds: all vulnerable / infected nodes
  const seeds = new Set(
    inventory
      .filter(c => c.state === "vulnerable" || c.state === "infected")
      .map(c => c.id)
  );

  // BFS upward to collect every ancestor of a seed
  const keep = new Set(seeds);
  const queue = [...seeds];
  while (queue.length) {
    const node = queue.shift();
    for (const parent of (parents.get(node) || [])) {
      if (!keep.has(parent)) {
        keep.add(parent);
        queue.push(parent);
      }
    }
  }

  // Roots within the kept set: nodes not depended-on by any other kept node
  const dependedInKeep = new Set();
  for (const nodeId of keep) {
    for (const dep of (byId.get(nodeId)?.dependencies || [])) {
      if (keep.has(dep)) dependedInKeep.add(dep);
    }
  }
  const roots = [...keep].filter(n => !dependedInKeep.has(n));

  // Recursively build subtrees, pruning safe-only branches
  function buildSubtree(nodeId, visited) {
    if (visited.has(nodeId)) return {};
    const next = new Set(visited).add(nodeId);
    const subtree = {};
    for (const dep of (byId.get(nodeId)?.dependencies || [])) {
      if (keep.has(dep)) subtree[dep] = buildSubtree(dep, next);
    }
    return subtree;
  }

  const tree = {};
  for (const root of roots) tree[root] = buildSubtree(root, new Set());
  return tree;
}

// ── Summary helpers ───────────────────────────────────────────────────────────
const SEV_ORDER = { infection: -1, critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

/**
 * Deduplicate vulnerabilities per PURL using OSV alias chains.
 *
 * OSV entries that describe the same underlying issue carry each other's IDs
 * in their `aliases` array (e.g. a GHSA entry lists the CVE as an alias and
 * vice versa). Within each PURL group we walk the list in arrival order and
 * build a running set of "seen IDs". For each candidate we check whether its
 * own `id` already appears in that set — if it does, the entry is a duplicate
 * of something we already have and is dropped. Otherwise we admit it and add
 * both its `id` and all of its `aliases` to the seen set so later entries that
 * are aliases of this one are also suppressed.
 *
 * @param {{ id: string, aliases?: string[], affected_package_id?: string }[]} vulns
 * @returns same type, deduplicated
 */
export function deduplicateVulnerabilitiesByAlias(vulns) {
  // Group by PURL so alias dedup is scoped per package (an alias chain for
  // pkg A should never suppress a real finding for pkg B).
  const byPurl = new Map();
  for (const v of vulns) {
    const key = v.affected_package_id || "";
    if (!byPurl.has(key)) byPurl.set(key, []);
    byPurl.get(key).push(v);
  }

  const kept = [];
  for (const group of byPurl.values()) {
    // MAL-* entries (malware/infection) must win over any alias that arrives
    // earlier in the batch. Sort them to the front before the forward pass so
    // their ID is added to seenIds first, which prevents a GHSA/CVE alias of
    // the same issue from being kept instead.
    const sorted = [...group].sort((a, b) => {
      const aIsMal = (a.id || "").startsWith("MAL-");
      const bIsMal = (b.id || "").startsWith("MAL-");
      if (aIsMal && !bIsMal) return -1;
      if (!aIsMal && bIsMal) return  1;
      return 0;
    });
    const seenIds = new Set();
    for (const v of sorted) {
      if (seenIds.has(v.id)) continue;          // this ID was an alias of a prior entry
      kept.push(v);
      seenIds.add(v.id);
      for (const alias of (v.aliases || [])) {  // mark all aliases as seen
        seenIds.add(alias);
      }
    }
  }
  return kept;
}


function summarizeVulnerabilities(vulnerabilities,inventory) {
  const packages = {};

  for (const v of vulnerabilities) {
    const pkg      = v.affected_dependency;
    const version  = v.affected_dependency_version;
    const purl     = v.affected_package_id || "";
    const ecosystem = getEcosystemFromPurl(purl);
    const introducedBy = inventory.find((item) => item.id === purl)?.introduced_by || [];
    let affected_dep= inventory.find((item) => item.id === purl);
    
    if (!packages[pkg]) {
      packages[pkg] = {
        name: pkg,
        version,
        ecosystem: ecosystem,
        introduced_by: introducedBy,
        paths: affected_dep ? affected_dep.paths : [],
        affected_dependency_sequences: affected_dep ? affected_dep.dependency_sequences : [],
        vulnerabilities: [],
        _counts: { infection:0, critical:0, high:0, medium:0, low:0, unknown:0 },
      };
    }

    let sev = (v.severity || "unknown").toLowerCase();
    if (v.severity_score != null) {
      const score = parseFloat(v.severity_score);
      // Normalize severity label from numeric CVSS score when label is
      // missing or unrecognised — prevents misclassification.
      if (!isNaN(score) && !(sev in SEV_ORDER)) {
        if      (score >= 9.0) sev = "critical";
        else if (score >= 7.0) sev = "high";
        else if (score >= 4.0) sev = "medium";
        else if (score >= 0.1) sev = "low";
        else                   sev = "unknown";
      }
    }
    const vulnObj = {
      id:             v.id,
      is_infection:   v.is_infection,
      severity:       sev,
      severity_score: v.severity_score != null ? parseFloat(v.severity_score) : null,
      fixes:          v.fixes || [],
      fixed_versions: v.fixed_versions || [],
      is_policy_violation: v.policy_decision === "block",
    };

    packages[pkg].vulnerabilities.push(vulnObj);
    const countKey = vulnObj.is_infection ? "infection" : (sev in packages[pkg]._counts ? sev : "unknown");
    packages[pkg]._counts[countKey]++;
  }

  // Sort vulns within each package
  for (const pkg of Object.values(packages)) {
    pkg.vulnerabilities.sort((a, b) => {
      const ao = SEV_ORDER[a.severity] ?? 5;
      const bo = SEV_ORDER[b.severity] ?? 5;
      if (ao !== bo) return ao - bo;
      const as = a.severity_score ?? -Infinity;
      const bs = b.severity_score ?? -Infinity;
      return bs - as;
    });
  }

  // Sort packages
  const sorted = Object.values(packages).sort((a, b) => {
    const c = a._counts, d = b._counts;
    for (const k of ["infection","critical","high","medium","low","unknown"]) {
      if (d[k] !== c[k]) return d[k] - c[k];
    }
    return a.name.localeCompare(b.name);
  });

  for (const p of sorted) {
    p.stats = p._counts;
    delete p._counts;
  }

  return Object.fromEntries(sorted.map((p) => [p.name, p]));
}

export function sortVulnerabilities(vulns) {
  return [...vulns].sort((a, b) => {
    const sevA = a.is_infection ? "infection" : (a.severity || "unknown").toLowerCase();
    const sevB = b.is_infection ? "infection" : (b.severity || "unknown").toLowerCase();
    const oA = SEV_ORDER[sevA] ?? 5;
    const oB = SEV_ORDER[sevB] ?? 5;
    if (oA !== oB) return oA - oB;
    const sA = parseFloat(a.severity_score) || 0;
    const sB = parseFloat(b.severity_score) || 0;
    return sB - sA;
  });
}


// ── Threat intelligence: CISA KEV + FIRST EPSS ───────────────────────────────
//
// Adds to every vulnerability: is_kev, kev_added, kev_deadline, epss_score,
// epss_percentile.  CVE ids come from the vuln id (CVE-*) and its `aliases`.
//
// Neither feed is allowed to abort a scan.  If one is unreachable the
// affected fields are null (unknown — distinct from false / 0), the feed is
// marked unavailable in report.threat_intel, a warning is printed, and the
// matching policy rule is simply not enforced for that run.
const KEV_URL          = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const EPSS_URL         = "https://api.first.org/data/v1/epss";
const EPSS_BATCH_SIZE  = 100;
const INTEL_FETCH_OPTS = { timeoutMs: 15000, maxRetries: 2 };

export function extractCveIds(v) {
  const out = new Set();
  const add = (s) => {
    if (typeof s !== "string") return;
    const t = s.trim().toUpperCase();
    if (/^CVE-\d{4}-\d{4,}$/.test(t)) out.add(t);
  };
  add(v.id);
  for (const a of (Array.isArray(v.aliases) ? v.aliases : [])) add(a);
  return [...out];
}

async function loadKevCatalog() {
  const res = await fetchJSON(KEV_URL, "GET", null, INTEL_FETCH_OPTS);
  if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
  if (!res.body || !Array.isArray(res.body.vulnerabilities)) throw new Error("unexpected response format");
  const entries = new Map();
  for (const e of res.body.vulnerabilities) {
    if (e && e.cveID) entries.set(String(e.cveID).toUpperCase(), { added: e.dateAdded ?? null, deadline: e.dueDate ?? null });
  }
  return { entries, version: res.body.catalogVersion ?? null };
}

async function loadEpssScores(cves) {
  const scores = new Map();
  let failed = 0;
  let error  = null;
  for (let i = 0; i < cves.length; i += EPSS_BATCH_SIZE) {
    const chunk = cves.slice(i, i + EPSS_BATCH_SIZE);
    try {
      const res = await fetchJSON(`${EPSS_URL}?cve=${chunk.join(",")}`, "GET", null, INTEL_FETCH_OPTS);
      if (res.status !== 200) throw new Error(`HTTP ${res.status}`);
      if (!res.body || !Array.isArray(res.body.data)) throw new Error("unexpected response format");
      for (const row of res.body.data) {
        const score      = parseFloat(row?.epss);
        const percentile = parseFloat(row?.percentile);
        if (row?.cve && Number.isFinite(score) && Number.isFinite(percentile)) {
          scores.set(String(row.cve).toUpperCase(), { score, percentile });
        }
      }
    } catch (err) {
      failed += chunk.length;
      error ??= err.message;
    }
  }
  return { scores, failed, error };
}

export async function enrichWithThreatIntel(vulnerabilities) {
  const intel = { kev: { status: "ok" }, epss: { status: "ok" }, warnings: [] };

  const cvesByVuln = new Map(vulnerabilities.map(v => [v, extractCveIds(v)]));
  const allCves    = [...new Set([...cvesByVuln.values()].flat())];

  if (allCves.length === 0) {
    // Nothing to look up (e.g. only MAL-* advisories).
    intel.kev.status = intel.epss.status = "skipped";
    for (const v of vulnerabilities) {
      v.is_kev = false; v.kev_added = null; v.kev_deadline = null;
      v.epss_score = null; v.epss_percentile = null;
    }
    return intel;
  }

  const [kevR, epssR] = await Promise.allSettled([loadKevCatalog(), loadEpssScores(allCves)]);

  let kev = null;
  if (kevR.status === "fulfilled") {
    kev = kevR.value;
    intel.kev.catalog_version = kev.version;
    intel.kev.entries         = kev.entries.size;
  } else {
    intel.kev.status = "unavailable";
    intel.kev.error  = kevR.reason?.message || String(kevR.reason);
    intel.warnings.push(`CISA KEV feed unreachable (${intel.kev.error}): KEV status is unknown and KEV blocking was NOT enforced for this scan.`);
  }

  let epss = new Map();
  if (epssR.status === "fulfilled") {
    epss = epssR.value.scores;
    intel.epss.queried = allCves.length;
    intel.epss.scored  = epss.size;
    if (epssR.value.failed > 0) {
      intel.epss.status = epssR.value.failed >= allCves.length ? "unavailable" : "partial";
      intel.epss.error  = epssR.value.error;
      intel.epss.failed = epssR.value.failed;
      intel.warnings.push(
        intel.epss.status === "unavailable"
          ? `FIRST EPSS API unreachable (${intel.epss.error}): EPSS scores are unknown and EPSS blocking was NOT enforced for this scan.`
          : `FIRST EPSS API failed for ${intel.epss.failed} of ${allCves.length} CVE(s) (${intel.epss.error}): those CVEs have unknown EPSS and were NOT evaluated against the EPSS threshold.`
      );
    }
  } else {
    intel.epss.status = "unavailable";
    intel.epss.error  = epssR.reason?.message || String(epssR.reason);
    intel.warnings.push(`FIRST EPSS API unreachable (${intel.epss.error}): EPSS scores are unknown and EPSS blocking was NOT enforced for this scan.`);
  }

  for (const v of vulnerabilities) {
    const cves = cvesByVuln.get(v);

    let hit = null;
    if (kev) for (const c of cves) { if (kev.entries.has(c)) { hit = kev.entries.get(c); break; } }
    v.is_kev       = kev ? hit !== null : null;
    v.kev_added    = hit?.added    ?? null;
    v.kev_deadline = hit?.deadline ?? null;

    // Several CVEs can map to one advisory — keep the highest-risk score.
    let best = null;
    for (const c of cves) {
      const s = epss.get(c);
      if (s && (!best || s.score > best.score)) best = s;
    }
    v.epss_score      = best?.score      ?? null;
    v.epss_percentile = best?.percentile ?? null;
  }
  return intel;
}

// ── Policy ────────────────────────────────────────────────────────────────────
//
// Schema:
//   severity_threshold            — block this level and everything above it.
//                                   Order: low < medium < high < critical.
//                                   Set to "none" to disable severity blocking entirely.
//                                   Infections are ALWAYS blocked regardless.
//   block_unknown_vulnerabilities — whether to block vulnerabilities whose
//                                   severity could not be determined.
//   license_risk_threshold        — block this license risk level and everything
//                                   above it. Order: low < medium < high.
//                                   Defaults to "none" (not enforced) — license
//                                   risk is a compliance signal, not a security
//                                   one, and only ever populated for `health`-mode
//                                   scans (see the license enrichment step above
//                                   and policy.js), so it's opt-in even there.
//   block_unknown_license_risk    — separately block packages whose license
//                                   couldn't be classified at all. Deliberately
//                                   its own flag rather than folded into
//                                   license_risk_threshold — an "unknown"
//                                   classification is usually a detection gap
//                                   (unparseable free text, missing metadata),
//                                   not a real compliance finding, so it's off
//                                   by default even when a threshold is set.
//   block_kev                     — block any vulnerability listed in the CISA
//                                   Known Exploited Vulnerabilities catalog.
//                                   Default true. Not enforced if the KEV feed
//                                   was unreachable (reported in threat_intel).
//   epss_threshold                — block vulnerabilities whose EPSS score is
//                                   >= this value (fraction 0-1, so 0.1 = 10%).
//                                   Default 0.1. "none" disables. Not enforced
//                                   for CVEs with no/unavailable EPSS score.
//
const DEFAULT_POLICY = {
  severity_threshold:            "high",
  block_unknown_vulnerabilities: true,
  license_risk_threshold:        "none",
  block_unknown_license_risk:    false,
  block_kev:                     true,
  epss_threshold:                0.1,
};

function parseEpssThreshold(raw) {
  const n = typeof raw === "string" ? parseFloat(raw) : raw;
  return (typeof n === "number" && Number.isFinite(n) && n > 0 && n <= 1) ? n : null;
}

// ── Sentinel: thrown on a policy block so finally can revert before exit ─────
// main() catches this and exits with code 1 without printing an extra message.
export class PolicyViolationError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "PolicyViolationError";
  }
}

const SEVERITY_ORDER_POLICY = ["low", "medium", "high", "critical"];

function tag_vulnerabilities_with_policy_decisions(vulnerabilities, policy) {
  const threshold    = (policy.severity_threshold || "").toLowerCase();
  const thresholdIdx = SEVERITY_ORDER_POLICY.indexOf(threshold);
  const blockUnknown = policy.block_unknown_vulnerabilities === true;
  const epssThreshold = parseEpssThreshold(policy.epss_threshold);

  for (const v of vulnerabilities) {
    // Confirmed unreachable by static analysis → never block on policy.
    // Reachable or unanalysed (no reachability key, or reachable=true) still
    // go through normal policy evaluation.  Infections are always blocked
    // regardless of reachability.
    const reachability       = v.reachability || {};
    const confirmedUnreachable = (
      typeof reachability === "object" &&
      reachability.reachable === false
    );

    // Infections are unconditionally blocked — reachability is irrelevant.
    if (v.is_infection) {
      v.policy_decision = "block";
      continue;
    }

    if (confirmedUnreachable) {
      v.policy_decision = "allow";
      continue;
    }

    // Threat-intel rules apply regardless of severity (a low/unknown-severity
    // CVE that is actively exploited must still block). null = feed was
    // unreachable / no score, so the rule can't fire.
    const reasons = [];
    if (policy.block_kev !== false && v.is_kev === true) reasons.push("kev");
    if (epssThreshold !== null && typeof v.epss_score === "number" && v.epss_score >= epssThreshold) reasons.push("epss");
    if (reasons.length) {
      v.policy_reasons  = reasons;
      v.policy_decision = "block";
      continue;
    }

    const sev    = (v.severity || "unknown").toLowerCase();
    const sevIdx = SEVERITY_ORDER_POLICY.indexOf(sev);

    if (sev === "unknown") {
      v.policy_decision = blockUnknown ? "block" : "allow";
    } else if (threshold === "none" || thresholdIdx === -1) {
      // "none" (or unrecognised value) disables severity blocking entirely.
      v.policy_decision = "allow";
    } else if (sevIdx >= thresholdIdx) {
      // Severity meets or exceeds the threshold → block.
      v.policy_decision = "block";
    } else {
      v.policy_decision = "allow";
    }
  }
}

function get_policy_violations(vulnerabilities) {
  const policyViolations = vulnerabilities.filter(v => v.policy_decision === "block");
  const uniqueViolationIds = new Set(policyViolations.map(v => v.id));
  return Array.from(uniqueViolationIds);
}

// ── Engine class (instance-based) ────────────────────────────────────────────
//
// UbelEngineInstance replaces the old static UbelEngine class.
// Each scan invocation creates a fresh instance, eliminating all shared
// mutable state between concurrent or sequential scans.
//
// Constructor:
//   new UbelEngineInstance(manager, projectRoot)
//
//   manager     — a NodeManagerInstance (created by main() per invocation)
//   projectRoot — absolute path to the directory being scanned; replaces all
//                 process.cwd() references inside the scan pipeline so no
//                 process.chdir() is ever needed.
//
export class UbelEngineInstance {

  // Policy file paths are relative to projectRoot (resolved in constructor).

  constructor(manager, projectRoot) {
    this.REPORTS_SUBDIR  = ".ubel/local/reports";
    this.POLICY_SUBDIR   = ".ubel/local/policy";
    this.POLICY_FILENAME = "config.json";
    // ── per-instance mutable state ──────────────────────────────────────
    this.manager          = manager;
    this.projectRoot      = path.resolve(projectRoot);

    this.reportsLocation  = path.join(this.projectRoot, this.REPORTS_SUBDIR);
    this.policyDir        = path.join(this.projectRoot, this.POLICY_SUBDIR);

    this.checkMode        = "health";
    this.systemType       = "npm";
    this.engine           = "npm";
    this.wasSuccessfulScan = false;
    // Only consulted for systemType "pypi" (pip engine) — overrides the
    // default `<projectRoot>/venv` venv location. Mirrors Python's
    // self.venv_dir. Left null unless a caller sets it explicitly.
    this.venvDir           = null;

    this.runtime_environment = "node";
    this.runtime_version     = process.version.replace(/^v/, "").replace(/^V/, "");

    this.vulns_ids_found  = new Set();

  }

  // ── Policy helpers ──────────────────────────────────────────────────────────

  initiateLocalPolicy() {
    fs.mkdirSync(this.policyDir, { recursive: true });
    const file  = path.join(this.policyDir, this.POLICY_FILENAME);
    let needs   = false;
    if (!fs.existsSync(file)) needs = true;
    else if (fs.statSync(file).size === 0) { fs.unlinkSync(file); needs = true; }
    if (needs) {
      fs.writeFileSync(file, JSON.stringify(DEFAULT_POLICY, null, 4));
    }
  }

  loadPolicy() {
    this.initiateLocalPolicy();
    const file = path.join(this.policyDir, this.POLICY_FILENAME);
    return { ...DEFAULT_POLICY, ...JSON.parse(fs.readFileSync(file, "utf-8")) };
  }

  /**
   * Set a single top-level policy field and persist it to disk.
   *
   * @param {"severity_threshold"|"block_unknown_vulnerabilities"|"license_risk_threshold"|"block_unknown_license_risk"|"block_kev"|"epss_threshold"} key
   * @param {string|boolean} value
   */
  setPolicyField(key, value) {
    const data = this.loadPolicy();
    data[key]  = value;
    const file = path.join(this.policyDir, this.POLICY_FILENAME);
    fs.writeFileSync(file, JSON.stringify(data, null, 4));
  }

  // ── Requirements file helper (pypi install mode) ────────────────────────────
  // Mirrors ubel_engine.py's _generate_requirements_file.

  _generateRequirementsFile(purls, projectRoot) {
    const depsDir = path.join(projectRoot, ".ubel", "dependencies");
    fs.mkdirSync(depsDir, { recursive: true });
    const reqFile = path.join(depsDir, "requirements.txt");

    const lines = [];
    for (const purl of purls) {
      const [name, version] = getDependencyFromPurl(purl);
      if (name === TOOL_NAME && version === TOOL_VERSION) continue;
      if (name !== "unknown" && version !== "" && version !== "unknown") {
        lines.push(`${name}==${version}`);
      }
    }
    fs.writeFileSync(reqFile, lines.join("\n"));
    return reqFile;
  }

  // ── scan ────────────────────────────────────────────────────────────────────

  async scan(args, options = {}) {
    let {
      is_script           = false,
      save_reports        = true,
      scan_os             = false,
      full_stack          = false,
      scan_node           = true,
      is_vscanned_project = false,
      scan_scope          = "repository",
      scan_secrets        = true,
      scan_vulns          = true,
    } = options;

    const projectRoot = this.projectRoot;
    const manager     = this.manager;

    if (this.checkMode !== "health") {
      scan_secrets = false;  // secrets scanning is only supported in health mode
    }

    const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'"<>]+)?$/i;

    // Composer specifiers are always "vendor/package", optionally with a
    // ":constraint" suffix (e.g. "monolog/monolog:^3.0") — the npm-shape
    // regex above requires no "/" in the bare name and would reject every
    // composer arg outright, so composer gets its own pattern rather than
    // being folded into the npm-family check.
    const COMPOSER_PKG_ARG_RE = /^[a-z0-9]([_.-]?[a-z0-9]+)*\/[a-z0-9]([_.-]?[a-z0-9]+)*(:[^\s;&|`$(){}\\'"<>]+)?$/i;

    // pip specifiers use `==`/`>=`/extras (`black[d]>=24`) and Linux package
    // names/versions don't follow the npm @scope/name@version shape at all,
    // so pypi/linux validate more permissively here — mirrors
    // ubel_engine.py's validate_pkg_args (strip the allowed punctuation, what
    // remains must be alphanumeric).
    const validatePkgArgsLoose = (arg) => {
      const stripped = arg.replace(/[=,._+\-@/~\[\]<>!]/g, "");
      return /^[a-z0-9]+$/i.test(stripped);
    };

    // conda match specs (`numpy`, `numpy=1.26`, `conda-forge::numpy>=1.26`).
    // Stricter than the loose pip/apt validator on purpose: `:` is allowed
    // here (channel::name), which would otherwise let a URL through, so
    // option-shaped args, paths/URLs (no `/` or `\`), and bare package-file
    // names (`x.conda`, `x.tar.bz2` — conda installs those straight from
    // disk, bypassing the channel resolution this firewall scans) are all
    // rejected up front.
    const CONDA_SPEC_RE     = /^[A-Za-z0-9_][A-Za-z0-9_.*+!<>=,~:[\]-]*$/;
    const CONDA_ARTIFACT_RE = /\.(conda|tar\.bz2)$/i;

    // cargo specifiers: `name` or `name@requirement` only — no options, paths,
    // URLs or whitespace, so nothing can add a --git/--path/--registry source.
    const CARGO_SPEC_RE = /^[A-Za-z_][A-Za-z0-9_-]*(@[0-9A-Za-z.^~=<>*+!,-]+)?$/;

    if (args.length) {
      const bad = this.engine === "composer"
        ? args.filter(a => !COMPOSER_PKG_ARG_RE.test(a))
        : this.engine === "conda"
          ? args.filter(a => !CONDA_SPEC_RE.test(a) || CONDA_ARTIFACT_RE.test(a))
        : this.engine === "cargo"
          ? args.filter(a => !CARGO_SPEC_RE.test(a))
        : this.systemType === "npm"
          ? args.filter(a => !PKG_ARG_RE.test(a))
          : args.filter(a => !validatePkgArgsLoose(a));
      if (bad.length) {
        console.error(`[!] Rejected unsafe or malformed package argument(s): ${bad.join(", ")}`);
        console.error(this.engine === "composer"
          ? "[!] Expected format: vendor/package or vendor/package:constraint"
          : this.engine === "conda"
            ? "[!] Expected format: a conda match spec such as numpy, numpy=1.26 or conda-forge::numpy>=1.26 (no options, paths or URLs)"
          : this.engine === "cargo"
            ? "[!] Expected format: a crate name, optionally with a version requirement: serde or serde@1.0 (no options, paths, URLs or git sources)"
          : this.systemType === "npm"
            ? "[!] Expected format: name, name@version, or @scope/name@version"
            : "[!] Expected format: a package name, optionally with a version/extras specifier");
        process.exit(1);
      }
    }

    const os_metadata_info = await getOSMetadata();

    const getinstalledoptions = {
      full_stack,
      scan_os: options.scan_os ?? options.os_scan,
      scan_node: options.scan_node ?? true,
      // Threaded through so getInstalled() can tell "scan_os against an
      // extracted container rootfs" apart from "scan_os against the live
      // host" — those need different scanners regardless of what OS the
      // CLI itself happens to be running on. See node_runner.js.
      scan_scope,
    };

    const ecosystems = new Set();

    if (this.checkMode!=="health") {
      manager._captureEngineVersion(this.engine);
    } else {
      this.engine           = TOOL_NAME;
      manager.engineVersion = TOOL_VERSION;
    }
    

    const now       = new Date();
    const pad       = (n) => String(n).padStart(2, "0");
    const timestamp = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}__`
                    + `${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
    const datePath  = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;

    const outputDir = path.join(
      this.reportsLocation,
      this.systemType,
      this.checkMode,
      datePath
    );
    fs.mkdirSync(outputDir, { recursive: true });

    const baseName = `${this.systemType}_${this.checkMode}_${this.engine}__${timestamp}`;
    const jsonPath = path.join(outputDir, `${encodeURIComponent(baseName)}.json`);

    const policy     = this.loadPolicy();
    let purls        = [];
    let reportContent = null;

    const needsRevert =
      this.checkMode === "check" || this.checkMode === "install";

    try {
      // ── Collect packages ──────────────────────────────────────────────────
      if (this.systemType === "pypi") {
        // ── Python (pip / uv / pipx) firewall ────────────────────────────────
        if (needsRevert) {
          const venvDir = this.venvDir || path.join(projectRoot, "venv");
          if (this.engine === "pip") {
            const python = manager.initVenv(venvDir);
            manager.engineVersion = manager.getPipVersion(python) || "";
            purls = manager.runDryRun(args, venvDir);
          } else if (this.engine === "uv") {
            manager.initUvVenv(venvDir); // uv-native project + venv (`uv init` + `uv venv`), not a bare stdlib venv
            purls = manager.runDryRun(args, venvDir); // sets manager.engineVersion internally (uv --version)
          } else if (this.engine === "conda") {
            // No env pre-creation: the dry-run targets a scratch prefix that
            // never exists, so `check` leaves nothing behind (see conda_runner.js).
            purls = manager.runDryRun(args, this.venvDir || path.join(projectRoot, "conda-env")); // sets manager.engineVersion internally
          } else if (this.engine === "pipx") {
            purls = manager.dryRunCli(args[0]);
          }
          reportContent = manager.inventoryData;
        } else {
          // health — delegate entirely to PypiManagerInstance.getInstalled()
          purls = manager.getInstalled(projectRoot, {
            scanVenv: options.scan_venv ?? true,
            scanOs:   scan_os,
          });
          reportContent = {};
        }
      } else if (this.systemType === "linux") {
        // ── Linux (apt / dnf / yum) firewall ─────────────────────────────────
        if (needsRevert) {
          const packages   = manager.resolvePackages(args);
          const systemInfo = manager.getOsInfo();
          reportContent    = { packages, system_info: systemInfo };
          purls            = packages.map(p => manager.packageToPurl(systemInfo, p.name, p.version));
          manager.inventoryData = packages.map((pkg, i) => ({
            ...pkg,
            id: purls[i],
            state: "undetermined",
            scopes: ["prod"],
            dependency_sequences: [],
          }));
          manager.engineVersion = manager.pkgManagerVersion;
          // Report the concrete package manager (apt/dnf/yum), not the CLI
          // tool name — mirrors ubel_engine.py's _engine_name override.
          this.engine = manager.pkgManager;
        } else {
          purls         = manager.getLinuxPackages();
          reportContent = { system_info: manager.getOsInfo() };
        }
      } else if (this.systemType === "cargo") {
        // ── Rust (cargo) firewall ────────────────────────────────────────────
        // The dry-run resolves in a scratch copy of the project, so `check`
        // leaves the project untouched and there is nothing to revert (see
        // cargo_runner.js).
        if (needsRevert) {
          purls         = manager.runDryRun(args, projectRoot); // sets manager.engineVersion internally
          reportContent = manager.inventoryData;
        } else {
          purls         = await manager.getInstalled(projectRoot);
          reportContent = {};
        }
      } else if (needsRevert) {
        purls         = await manager.runDryRun(this.engine, args, projectRoot);
        for (const inventoryItem of manager.inventoryData) {
          inventoryItem.paths = [];
        }
        reportContent = manager.currentLockFileContent;
        if (manager._lockfileBackupDir && !is_script) {
          console.log(`[~] Original lockfiles backed up to: ${manager._lockfileBackupDir}`);
          console.log();
        }
      } else {
        // health — scan installed packages
        manager.inventoryData = [];
        purls = await manager.getInstalled(projectRoot, getinstalledoptions);
        /*manager.inventoryData.push({
          id:        `pkg:npm/${TOOL_NAME.replace("@", "%40")}@${TOOL_VERSION}`,
          name:      TOOL_NAME,
          version:   TOOL_VERSION,
          license:   TOOL_LICENSE,
          ecosystem: "npm",
          state:     "undetermined",
          scopes:    ["env"],
          dependencies: [],
          type:      "library",
          paths:     [],
        });*/
        reportContent = {};
      }

      for (const purl of purls) {
        if (purl.split("@")[1] === "") {
          purls = purls.filter(p => p !== purl);
        }
      }
      purls = [...new Set(purls)];

      let inventory = [...manager.inventoryData];

      // Dependency-id linking is needed for the inventory tree regardless of
      // whether vulnerability lookups run, so it always happens up front.
      matchDependenciesWithInventory(inventory);

      // ── OSV / NVD query ──────────────────────────────────────────────────
      // Skipped entirely when scan_vulns is false (e.g. ubel-license): no
      // OSV/NVD network calls are made, and vulnerabilities stays empty.
      let vulnerabilities = [];
      if (scan_vulns) {
        const vuln_ids = await submitToOsv(purls);

        // ── Enrich vulnerabilities concurrently ─────────────────────────────
        const CONCURRENCY = 40;
        for (let i = 0; i < vuln_ids.length; i += CONCURRENCY) {
          const batch   = vuln_ids.slice(i, i + CONCURRENCY);
          const results = await Promise.allSettled(batch.map(getVulnById));
          const failed  = results.filter(r => r.status === "rejected");
          if (failed.length) {
            for (const r of failed) console.error("[!] Failed to fetch vulnerability:", r.reason?.message);
            // Fail closed: every id in vuln_ids is a finding OSV already
            // reported for one of the scanned packages.
            throw new VulnLookupError(
              `${failed.length} OSV advisor${failed.length === 1 ? "y" : "ies"} could not be fetched — vulnerability lookup is incomplete.`,
              { source: "osv-vuln", cause: failed[0].reason }
            );
          }
          for (const r of results) {
            if (r.value) vulnerabilities.push(r.value);
          }
        }

        // ── NVD query for CPE-based inventory items ──────────────────────────
        const nvdVulns = await submitToNvd(inventory);
        if (nvdVulns.length) {
          for (const v of nvdVulns) {
            const nvdScore  = v.severity_score;
            const nvdVector = v.severity_vector;
            processVulnerability(v);
            if (v.severity_score  == null) v.severity_score  = nvdScore;
            if (v.severity_vector == null) v.severity_vector = nvdVector;
            v.severity = scoreToSeverity(v.severity_score);
            getFix(v);
            for (const key of ["database_specific", "affected", "schema_version"]) {
              delete v[key];
            }
          }
          const osvKeys = new Set(vulnerabilities.map(v => `${v.id}::${v.affected_package_id}`));
          for (const v of nvdVulns) {
            if (!osvKeys.has(`${v.id}::${v.affected_package_id}`)) {
              vulnerabilities.push(v);
            }
          }
        }
      }

      inventory = manager.buildDependencySequences(inventory);
      inventory = manager.buildIntroducedBy(inventory);
      inventory = manager.buildParents(inventory);

      // ── Second-pass scope propagation ─────────────────────────────────────
      {
        const byId = new Map(inventory.map(c => [c.id, c]));
        const queue = inventory.filter(c =>
          Array.isArray(c.scopes) && c.scopes.some(s => s !== "env")
        );
        const visited = new Set(queue.map(c => c.id));

        while (queue.length) {
          const comp = queue.shift();
          for (const depPurl of (comp.dependencies || [])) {
            const dep = byId.get(depPurl);
            if (!dep) continue;
            let changed = false;
            for (const s of comp.scopes) {
              if (s === "env") continue;
              if (!dep.scopes.includes(s)) { dep.scopes.push(s); changed = true; }
            }
            if (!visited.has(dep.id)) {
              visited.add(dep.id);
              queue.push(dep);
            }
          }
        }
      }

      for (const item of inventory) {
        if (item.scopes.length === 0) {
          item.scopes = ["prod"];
        }
      }

      // ── Network metadata ──────────────────────────────────────────────────
      // Local IP is retained: it's used below to tag every inventory item's
      // filesystem path with the host it was found on (normalizeInventoryPaths),
      // which matters once reports from multiple hosts/containers get combined.
      // The external (public) IP lookup was removed — it phoned home to a
      // third-party API (ipify) on every scan purely for a display field with
      // no other consumer, which cut against UBEL's zero-third-party-dependency
      // and fully-local-execution positioning.
      const localIPs       = getLocalIPsSync();
      const primaryLocalIP = Object.values(localIPs)[0] || "";

      normalizeInventoryPaths(inventory, primaryLocalIP);

      // ── License risk enrichment ─────────────────────────────────────────────
      // Replaces each item's raw `license` string with a classification object
      // ({ raw, spdx, identifiers, osi_approved, risk, category, reason }).
      // Handles missing/null/"unknown" values, the npm "UNLICENSED" proprietary
      // sentinel, free-text and SPDX-expression normalization, and OSI-approval
      // lookup. See license_checker.js.
      //
      // Restricted to `health` scans: license risk is a compliance/legal
      // concern over software already installed on the machine, not an
      // install-time security gate — `check`/`install` scans are evaluating
      // whether it's safe to add a new dependency, and mixing the two would
      // make the policy license-risk gate (see policy.js) fire in a context
      // it wasn't meant for. `item.license_info` / `stats.license_stats` are
      // simply absent outside health mode; every downstream consumer
      // (report UI, SBOM builder) already falls back gracefully.
      const licenseSummary = this.checkMode === "health"
        ? enrichInventoryWithLicenseRisk(inventory)
        : undefined;

      vulnerabilities = deduplicateVulnerabilitiesByAlias(vulnerabilities);

      [vulnerabilities, inventory] = filterFalsePositiveInfections(inventory, vulnerabilities);

      // ── KEV + EPSS enrichment (never aborts the scan) ─────────────────────
      let threatIntel = { kev: { status: "skipped" }, epss: { status: "skipped" }, warnings: [] };
      if (scan_vulns && vulnerabilities.length > 0) {
        try {
          threatIntel = await enrichWithThreatIntel(vulnerabilities);
        } catch (err) {
          const msg = `Threat-intel enrichment failed (${err.message}): KEV/EPSS data unavailable and KEV/EPSS blocking was NOT enforced for this scan.`;
          threatIntel = { kev: { status: "unavailable", error: err.message }, epss: { status: "unavailable", error: err.message }, warnings: [msg] };
          for (const v of vulnerabilities) {
            v.is_kev = null; v.kev_added = null; v.kev_deadline = null;
            v.epss_score = null; v.epss_percentile = null;
          }
        }
        for (const w of threatIntel.warnings) console.warn(`[!] ${w}`);
      }

      // ── Stats ──────────────────────────────────────────────────────────────
      const severityBuckets = { critical:0, high:0, medium:0, low:0, unknown:0 };
      const infectedPurls   = new Set();
      const vulnerablePurls = new Set();
      let infectionCount    = 0;
      // KEV split: is_kev is true (in CISA KEV), false (checked, not listed) or
      // null/undefined (feed down or not checked). Unknown is its own bucket so
      // a failed lookup is never silently counted as "not KEV".
      let kevCount        = 0;
      let nonKevCount     = 0;
      let kevUnknownCount = 0;

      for (const v of vulnerabilities) {
        this.vulns_ids_found.add(v.id);
        if (v.is_kev === true)       kevCount++;
        else if (v.is_kev === false) nonKevCount++;
        else                         kevUnknownCount++;
        v.compliance = getComplianceForVulnerability(v.cwes, v.is_infection);
        if (v.is_infection) {
          infectionCount++;
          infectedPurls.add(v.affected_package_id);
        } else {
          const sev = ((v.severity || "unknown").toLowerCase()) in severityBuckets
            ? (v.severity || "unknown").toLowerCase()
            : "unknown";
          severityBuckets[sev]++;
          vulnerablePurls.add(v.affected_package_id);
        }
      }

      const undeterminedCount = inventory.filter(c => c.version === "").length;
      if (undeterminedCount > 0) {
        console.warn(`[!] Warning: ${undeterminedCount} package(s) with undetermined versions were detected.`);
        console.warn();
      }

      setInventoryState(infectedPurls, vulnerablePurls, inventory);

      tag_vulnerabilities_with_policy_decisions(vulnerabilities, policy);
      const policyViolations = get_policy_violations(vulnerabilities);

      for (const v of vulnerabilities) {
        v.is_policy_violation = v.policy_decision === "block";
      }

      for (const inventoryItem of inventory) {
        ecosystems.add(getEcosystemFromPurl(inventoryItem.id));
        inventoryItem.is_policy_violation = vulnerabilities.some(
          v => v.affected_package_id === inventoryItem.id && v.policy_decision === "block"
        );
      }

      // ── Dependency-graph attributes: is_direct, policy-violation
      // propagation, and per-package vulnerable_transitive_dependencies ──
      {
        const byId = new Map(inventory.map(c => [c.id, c]));

        // Reverse map: child purl → Set of direct parent purls. A package
        // with no parents isn't depended on by anything else in the
        // inventory, i.e. it's a root/direct dependency of the project.
        const parentsOf = new Map(inventory.map(c => [c.id, new Set()]));
        for (const comp of inventory) {
          for (const dep of (comp.dependencies || [])) {
            if (parentsOf.has(dep)) parentsOf.get(dep).add(comp.id);
          }
        }

        for (const comp of inventory) {
          comp.is_direct = (parentsOf.get(comp.id)?.size || 0) === 0;
        }

        // A package that only violates policy through something it pulls
        // in should still surface as a violation itself — propagate every
        // seed violation upward through every ancestor chain.
        const propagationQueue = inventory.filter(c => c.is_policy_violation).map(c => c.id);
        const propagationSeen  = new Set(propagationQueue);
        while (propagationQueue.length) {
          const id = propagationQueue.shift();
          for (const parentId of (parentsOf.get(id) || [])) {
            const parent = byId.get(parentId);
            if (parent) parent.is_policy_violation = true;
            if (!propagationSeen.has(parentId)) {
              propagationSeen.add(parentId);
              propagationQueue.push(parentId);
            }
          }
        }

        // Vulnerability count per package, used below.
        const vulnCountByPurl = new Map();
        for (const v of vulnerabilities) {
          if (!v.affected_package_id) continue;
          vulnCountByPurl.set(v.affected_package_id, (vulnCountByPurl.get(v.affected_package_id) || 0) + 1);
        }

        // For every package, every vulnerable/infected package anywhere in
        // its full transitive dependency closure (direct children and
        // deeper descendants alike) — not just its immediate dependencies.
        for (const comp of inventory) {
          const closure = new Set();
          const stack   = [...(comp.dependencies || [])];
          while (stack.length) {
            const depId = stack.pop();
            if (closure.has(depId)) continue;
            closure.add(depId);
            const depComp = byId.get(depId);
            if (depComp) stack.push(...(depComp.dependencies || []));
          }

          comp.vulnerable_transitive_dependencies = [...closure]
            .map(id => byId.get(id))
            .filter(dep => dep && (dep.state === "vulnerable" || dep.state === "infected"))
            .map(dep => ({
              id:                  dep.id,
              name:                dep.name,
              vulns_count:         vulnCountByPurl.get(dep.id) || 0,
              is_policy_violation: !!dep.is_policy_violation,
            }));
        }
      }

      // ── Suggested fixes: per-package upgrade versions that fix vulns in bulk,
      // plus the vulnerabilities that have no published fix ────────────────
      attachSuggestedFixes(inventory, vulnerabilities);

      const stats = {
        inventory_size: inventory.length,
        inventory_stats: {
          infected:      infectedPurls.size,
          vulnerable:    vulnerablePurls.size,
          safe:          Math.max(0, inventory.length - infectedPurls.size - vulnerablePurls.size - undeterminedCount),
          undetermined:  undeterminedCount,
        },
        total_vulnerabilities: vulnerabilities.length,
        vulnerabilities_stats: {
          severity:    severityBuckets,
          kev:         kevCount,
          non_kev:     nonKevCount,
          kev_unknown: kevUnknownCount,
        },
        total_infections: infectionCount,
        license_stats: licenseSummary,
      };

      const runtime = {
        environment: this.runtime_environment,
        version:     this.runtime_version,
        platform:    process.platform,
        arch:        process.arch,
        cwd:         projectRoot,
      };

      const engine_info = {
        name:    this.engine,
        version: manager.engineVersion,
      };

      const git_metadata = getGitMetadata();

      // ── Build final JSON ───────────────────────────────────────────────────
      const findingsSummary = summarizeVulnerabilities(vulnerabilities, inventory);
      for (const item of inventory) {
        if (item.dependency_sequences) {
          delete item.dependency_sequences;
        }
      }

      if (this.checkMode === "health") {
        this.engine = TOOL_NAME;
      }

      if (is_vscanned_project) {
        const editorKind    = options.editor_kind    ?? "vscode";
        const editorLabel   = options.editor_label   ?? editorKind;
        const editorVersion = options.editor_version ?? getEditorVersion(editorKind);
        const scanScope     = options.scan_scope ?? "repository";

        if (scanScope === "editor_extension") {
          engine_info.name    = editorKind;
          engine_info.version = editorVersion;
          runtime.environment = editorKind;
          runtime.version     = editorVersion;
        } else {
          engine_info.name    = editorKind;
          engine_info.version = editorVersion;
          runtime.editor = {
            kind:    editorKind,
            label:   editorLabel,
            version: editorVersion,
          };
        }
      }

      const finalJson = {
        generated_at:      now.toISOString().replace("Z", "") + "Z",
        runtime,
        engine:            engine_info,
        os_metadata:       { ...os_metadata_info, local_ips: localIPs },
        git_metadata:      git_metadata,
        tool_info:         { name: TOOL_NAME, version: TOOL_VERSION, license: TOOL_LICENSE },
        scan_info:         { type: this.checkMode, ecosystems: Array.from(ecosystems), engine: TOOL_NAME, scan_scope: options.scan_scope ?? "repository", vulnerability_scan: scan_vulns !== false, ...(runtime.editor ? { editor: runtime.editor } : {}) },
        stats,
        vulnerabilities_ids: Array.from(this.vulns_ids_found),
        findings_summary:  findingsSummary,
        vulnerabilities:   sortVulnerabilities(vulnerabilities),
        inventory,
        policy,
        threat_intel: threatIntel,
        //dependencies_tree: buildImpactDependencyTree(inventory),  // kept for compatibility but not used in new graph
      };

      // Reachability
      try { enrichReachability(finalJson, projectRoot); } catch(e) { console.warn("[~] Reachability failed:", e.message); }

      // ── Secrets-in-source scan (independent of the dependency scan above) ──
      if (scan_secrets=== true || (this.checkMode === "health" && scan_scope !== "developer_platform")) {
        try {
          const secretsResult = await scanSecrets(projectRoot);
          const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
          for (const f of secretsResult.findings) {
            const key = (f.severity || "unknown").toLowerCase();
            bySeverity[key] = (bySeverity[key] || 0) + 1;
            f.compliance = getComplianceForSecret();
          }
          finalJson.secrets = {
            enabled: true,
            count: secretsResult.count,
            findings: secretsResult.findings,
            stats: { by_severity: bySeverity },
          };
        } catch (e) {
          console.warn("[~] Secrets scan failed:", e.message);
          finalJson.secrets = { enabled: true, count: 0, findings: [], stats: { by_severity: {} }, error: e.message };
        }
      } else {
        finalJson.secrets = { enabled: false, count: 0, findings: [], stats: { by_severity: {} } };
      }

      // ── Compliance framework mapping summary ────────────────────────────────
      // Aggregates the per-finding `.compliance` attached to vulnerabilities
      // (above) and secrets findings (above) into report-level framework/
      // control coverage counts. See compliance_mappings.js.
      finalJson.compliance_summary = summarizeCompliance([
        ...finalJson.vulnerabilities.map(v => v.compliance),
        ...finalJson.secrets.findings.map(f => f.compliance),
      ]);

      const [allowed, reason] = evaluatePolicy(finalJson);
      finalJson.decision = { allowed, reason, policy_violations: policyViolations };

      // ── Executive summary (plain-language overview for non-technical readers) ─
      // Derived purely from the finished report above, so it must run after
      // reachability, secrets, compliance and the policy decision are all set.
      // Never allowed to fail the scan: a missing summary only hides one tab.
      try {
        finalJson.executive_summary = buildExecutiveSummary(finalJson);
      } catch (e) {
        console.warn("[~] Executive summary failed:", e.message);
      }

      if (is_script && !save_reports) {
        return finalJson;
      }

      const htmlReport       = await generateHTMLReport(finalJson);
      const jsonReportString = safeJsonString(finalJson, 1000);

      if (!is_script) {
        console.log();
        console.log("Policy:");
        console.log();
        console.log(dictToStr(policy));
        console.log();
        console.log();
        console.log("Findings:");
        console.log();
        console.log(dictToStr(stats));
        console.log();
        console.log();
      }

      const summaryEntries = Object.values(findingsSummary);
      if (summaryEntries.length > 0) {
        if (!is_script) {
          console.log("Findings Summary:");
          console.log();
        }
        for (const pkg of summaryEntries) {
          const s      = pkg.stats;
          const counts = [];
          if (s.infection) counts.push(`${s.infection} infection(s)`);
          if (s.critical)  counts.push(`${s.critical} critical`);
          if (s.high)      counts.push(`${s.high} high`);
          if (s.medium)    counts.push(`${s.medium} medium`);
          if (s.low)       counts.push(`${s.low} low`);
          if (s.unknown)   counts.push(`${s.unknown} unknown`);

          if (!is_script) {
            console.log(`  ${pkg.name}@${pkg.version}  [${counts.join(", ")}]`);
          }

          for (const vuln of pkg.vulnerabilities) {
            const label = vuln.is_infection ? "INFECTION" : vuln.severity.toUpperCase();
            const score = vuln.severity_score != null ? ` (${vuln.severity_score})` : "";
            // GHSA-/OSV-style ids hide the CVE; surface it (from aliases) next to the id.
            const cves  = extractCveIds(vuln).filter(c => c !== String(vuln.id).toUpperCase());
            const cveTag = cves.length ? `  [${cves.join(", ")}]` : "";
            if (!is_script) {
              console.log(`    \u2022 ${vuln.id}${cveTag}  ${label}${score}`);
              for (const fix of (vuln.fixes || [])) {
                console.log(`      fix: ${fix}`);
              }
            }
          }

          if (!is_script) console.log();
        }
      }

      if (!is_script) {
        console.log(`Policy Decision: ${allowed ? "ALLOW" : "BLOCK"}`);
        console.log();
        console.log();
      }

      // ── latest.{json,html} — always points to the most recent scan ─────────
      // Derived from reportsLocation's own root (".../.ubel/local/reports" →
      // ".../.ubel/reports") rather than hardcoded to projectRoot, so that
      // ubel-apt/ubel-dnf/ubel-yum — which redirect reportsLocation to
      // ~/.ubel/local/reports specifically to avoid writing into whatever
      // directory the CLI happened to be run from — get the same redirect
      // applied to this convenience path too, not just the timestamped one.
      const ubelRoot        = path.dirname(path.dirname(this.reportsLocation));
      const latestDir       = path.join(ubelRoot, "reports");
      const latestPath      = path.join(latestDir, "latest.json");
      const latestHtmlPath  = path.join(latestDir, "latest.html");
      fs.mkdirSync(latestDir, { recursive: true });
      fs.writeFileSync(latestHtmlPath, htmlReport);
      fs.writeFileSync(latestPath, jsonReportString);

      // ── CycloneDX SBOM + SARIF ─────────────────────────────────────────────
      const sbomBuilder = new CycloneDXBuilder(finalJson);
      const sbomData    = sbomBuilder.generate();

      const sarifBuilder = new SarifBuilder(finalJson);
      const sarifData    = sarifBuilder.generate();

      const sbomString  = safeJsonString(sbomData, 1000);
      const sarifString = safeJsonString(sarifData, 1000);

      const latestSbom  = path.join(latestDir, "latest.cdx.json");
      const latestSarif = path.join(latestDir, "latest.sarif.json");
      fs.writeFileSync(latestSbom, sbomString);
      fs.writeFileSync(latestSarif, sarifString);

      // ── Timestamped bundle ──────────────────────────────────────────────────
      // json/html/sbom/sarif used to be written out as four separate files
      // per scan alongside each other under outputDir; they're now bundled
      // into a single baseName.zip to cut down on file count and storage as
      // reports accumulate over time. The "latest" copies above are
      // intentionally left as plain files, unzipped.
      const zipPath = jsonPath.replace(/\.json$/, ".zip");
      fs.writeFileSync(zipPath, buildZip([
        { name: "report.json",       data: jsonReportString },
        { name: "report.html",       data: htmlReport },
        { name: "sbom.cdx.json",     data: sbomString },
        { name: "report.sarif.json", data: sarifString },
      ]));

      if (!is_script) {
        console.log(`Latest JSON report saved to: ${latestPath}`);
        console.log(`Latest HTML report saved to: ${latestHtmlPath}`);
        console.log(`Timestamped report bundle saved to: ${zipPath}`);
        console.log();
        console.log();
      }

      if (!allowed) {
        if (!is_script) {
          console.error("[!] Policy violation detected!");
          console.log(`[!] ${reason}`);
        }
        // Always throw on a blocked decision, whether called from the CLI
        // (is_script: false) or programmatically (is_script: true — the VS
        // Code extension, agent.js, platform.js, etc.). Programmatic callers
        // that want the full report can read it off err.report instead of
        // relying on a normal return value, which is no longer produced for
        // a blocked scan.
        const violationError = new PolicyViolationError(reason);
        violationError.report = finalJson;
        throw violationError;
      }

      if (this.checkMode === "health" && !is_script) {
        process.exit(0);
      }

      if (this.checkMode === "check") {
        this.wasSuccessfulScan = true;
        if (this.systemType === "npm") {
          manager.revert_lock_to_original(this.engine, projectRoot);
          manager.cleanupLockfileBackup();
          if (!is_script) console.log("[+] Backup lockfiles removed.");
        }
        process.exit(0);
      }

      if (!is_script) console.log("[+] Policy passed. Installing dependencies...");
      this.wasSuccessfulScan = true;

      if (this.systemType === "npm") {
        const saveResult = await manager.saveCandidateLockfile(this.engine, projectRoot);
        if (!saveResult.written) {
          if (!is_script) console.error("[!] Could not write candidate lockfile:", saveResult.reason);
          process.exit(1);
        }

        try {
          const installResult = await manager.runRealInstall(this.engine, projectRoot);
          if (installResult.status !== 0) {
            if (!is_script) console.error(`[!] ${this.engine} install failed (exit ${installResult.status}) — dependencies were NOT installed.`);
            manager.revert_lock_to_original(this.engine, projectRoot);
            process.exit(1);
          }
        } catch (err) {
          if (!is_script) console.error(`[!] Failed to run ${this.engine} install:`, err.message);
          manager.revert_lock_to_original(this.engine, projectRoot);
          process.exit(1);
        }

        manager.cleanupLockfileBackup();
        if (!is_script) console.log("[+] Backup lockfiles removed.");

      } else if (this.systemType === "pypi") {
        // No lockfile/backup concept for pip/uv — mirrors ubel_engine.py's
        // install branch, which installs directly with no revert step.
        try {
          if (this.engine === "pip" || this.engine === "uv") {
            const venvDir = this.venvDir || path.join(projectRoot, "venv");
            const reqFile = this._generateRequirementsFile(purls, projectRoot);
            manager.runRealInstall(reqFile, this.engine, venvDir);
          } else if (this.engine === "conda") {
            const envDir   = this.venvDir || path.join(projectRoot, "conda-env");
            const specFile = manager.writeCondaSpecFile(purls, projectRoot);
            manager.runRealInstall(specFile, "conda", envDir);
          } else if (this.engine === "pipx") {
            manager.installCli(args[0]);
          }
        } catch (err) {
          if (!is_script) console.error("[!] Failed to install package(s):", err.message);
          process.exit(1);
        }

      } else if (this.systemType === "cargo") {
        // Writes the scanned Cargo.toml/Cargo.lock into the project, then
        // `cargo fetch --locked`; restores the originals if the fetch fails.
        try {
          manager.runRealInstall(projectRoot);
        } catch (err) {
          if (!is_script) console.error("[!] Failed to install package(s):", err.message);
          process.exit(1);
        }
        manager.cleanup();

      } else if (this.systemType === "linux") {
        // No lockfile/backup concept for apt/dnf either — a straight
        // `sudo <pm> install -y`, mirroring Linux_Manager.run_real_install.
        try {
          const packagesList = purls
            .filter(p => !p.includes(`/${TOOL_NAME}@${TOOL_VERSION}`))
            .map(p => getDependencyFromPurl(p));
          manager.runRealInstall(packagesList);
        } catch (err) {
          if (!is_script) console.error("[!] Failed to install package(s):", err.message);
          process.exit(1);
        }
      }

      return finalJson;

    } finally {
      if (this.systemType === "cargo") manager.cleanup();
      if (this.systemType === "npm" && !this.wasSuccessfulScan && needsRevert) {
        const revertResult = manager.revert_lock_to_original(this.engine, projectRoot);
        if (!revertResult.reverted) {
          if (!is_script) {
            console.error("[!] Failed to restore original lockfiles:", revertResult.reason);
            if (revertResult.backupDir) {
              console.error(`[~] Originals are preserved at: ${revertResult.backupDir}`);
              console.error("[~] Restore them manually if needed.");
            }
          }
        } else {
          manager.cleanupLockfileBackup();
          if (!is_script) console.log("[+] Backup lockfiles removed.");
        }
      }
    }
  }
}

// ─────────────────────────────────────────────────────────────────────────────
// Legacy alias
//
// Code that still imports { UbelEngine } gets the instance-based class under
// the old name.  The static-style API (UbelEngine.engine = ..., UbelEngine.scan)
// no longer works — callers must construct an instance.  main() is the only
// caller of scan() and has been updated.
// ─────────────────────────────────────────────────────────────────────────────

export { UbelEngineInstance as UbelEngine };