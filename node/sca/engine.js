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
import { enrichReport as enrichReachability } from "./reachability_analyzer.js"
import { findClosestFixVersions, _vr_purlToEcosystem } from "./version_recommender.js"

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_BASE  = "https://api.osv.dev/v1/vulns";


// ── Network metadata helpers ──────────────────────────────────────────────────

// Synchronous version using the already-imported `os` module via dynamic import
// isn't available at module level — we use Node's built-in synchronously:
import os_module from "os";
import { time } from "console";

function safeWriteJson(filePath, data, maxSizeMb = 100) {
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
    return safeWriteJson(filePath, trimmed, maxSizeMb);
  }
  fs.writeFileSync(filePath, json);
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
 * Fetches the host's external (public) IP via the ipify API.
 * Returns null on any error or timeout.
 */
async function getExternalIP() {
  return new Promise((resolve) => {
    const req = https.get(
      { hostname: "api.ipify.org", path: "/?format=text", timeout: 4000 },
      (res) => {
        let data = "";
        res.on("data", (c) => { data += c; });
        res.on("end",  () => resolve((data || "").trim() || null));
      }
    );
    req.on("error",   () => resolve(null));
    req.on("timeout", () => { req.destroy(); resolve(null); });
  });
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

function generateHTMLReport(data) {
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
            renderVulnerabilities();
            renderInventory();
            renderStats();
            renderSystem();
            setupFilters();
            populatePackageSelect();

            // Close dropdown when clicking outside
            document.addEventListener('click', (e) => {
                const wrapper = document.getElementById('pkg-dropdown-wrapper');
                if (wrapper && !wrapper.contains(e.target)) {
                    closePkgDropdown();
                }
            });
        }

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
            document.getElementById('policy-threshold').textContent = thresh;
            document.getElementById('policy-block-unknown').textContent = blockUnk;
            document.getElementById('policy-infection').textContent = 'block (always)';

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

        function renderInventory(filter = '', state = 'all') {
            const tbody = document.getElementById('inv-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.inventory.filter(item => {
                const matchesSearch = item.name.toLowerCase().includes(filter.toLowerCase());
                const matchesState = state === 'all' || item.state === state;
                return matchesSearch && matchesState;
            });

            filtered.forEach(item => {
                const row = document.createElement('tr');
                row.className = 'hover:bg-neutral-800/30 transition-colors';
                row.onclick = () => openInvModal(item.id);
                row.innerHTML = \`
                    <td class="px-6 py-4 font-medium">\${item.name}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${item.version}</td>
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
                    <td class="px-6 py-4 text-neutral-400">\${item.license}</td>
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

            document.getElementById('os-external-ip').textContent = os.external_ip || 'unavailable';

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
            document.getElementById('inv-search').addEventListener('input', (e) => {
                renderInventory(e.target.value, document.getElementById('inv-filter-state').value);
            });
            document.getElementById('inv-filter-state').addEventListener('change', (e) => {
                renderInventory(document.getElementById('inv-search').value, e.target.value);
            });
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

                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By ( root dependencies )</h4><div class="flex flex-wrap gap-2">\${introRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Parents / Dependents (\${(item.parents || []).length})</h4><div class="flex flex-wrap gap-2">\${parentsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (\${(item.dependencies || []).length})</h4><div class="flex flex-wrap gap-2">\${depsRows}</div></div>
                    <div><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4><div class="space-y-1">\${pathRows}</div></div>
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
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4><div class="flex flex-wrap gap-2">\${v.references.map(r => \`<a href="\${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">\${r.type}</a>\`).join('')}</div></div>
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">\${v.description}</div></div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
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
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
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
            <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities</button>
            <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Inventory</button>
            <button onclick="switchTab('graph')" id="tab-graph" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Dependency Sequences</button>
            <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
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
                <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Decision Summary</h3><div id="decision-box" class="p-4 rounded-lg bg-neutral-800/50 border border-neutral-700"><p class="text-sm leading-relaxed" id="decision-reason">...</p></div><div class="mt-6 space-y-4"><div class="flex justify-between items-center text-sm"><span class="text-neutral-500">Policy:</span></div><div class="flex justify-between items-center text-sm"><table class="w-auto text-sm mono"><tr><td class="pr-2">Infections</td><td id="policy-infection">...</td></tr><tr><td class="pr-2">Severity Threshold</td><td id="policy-threshold">...</td></tr><tr><td class="pr-2">Block Unknown</td><td id="policy-block-unknown">...</td></tr></table></div></div></div>
            </div>
        </section>
        <!-- Vulnerabilities Section -->
        <section id="section-vulnerabilities" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Vulnerability Findings</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="vuln-search" placeholder="Search ID or package..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64"><select id="vuln-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select><select id="vuln-filter-reachability" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Reachability</option><option value="reachable">Reachable</option><option value="unreachable">Unreachable</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix Available</th><th>Policy Violation</th><th>Fixed Versions</th><th>Reachability</th><th class="text-right">Action</th></tr></thead><tbody id="vuln-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Inventory Section -->
        <section id="section-inventory" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Package Inventory</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="inv-search" placeholder="Search packages..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64"><select id="inv-filter-state" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All States</option><option value="safe">Safe</option><option value="vulnerable">Vulnerable</option><option value="infected">Infected</option><option value="undetermined">Undetermined</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th>Name</th><th>Version</th><th>State</th><th>Policy Violation</th><th>Ecosystem</th><th>License</th><th>Scopes</th></tr></thead><tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
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
                <div class="glass p-6 rounded-xl space-y-6"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Ecosystem Distribution</h3><div class="h-48"><canvas id="statsEcoChart"></canvas></div><div id="eco-legend" class="grid grid-cols-2 gap-2 text-[10px] mono text-neutral-500"></div></div>
            </div>
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
        <div class="flex flex-col gap-1 border-b border-neutral-800 pb-2">
          <span class="text-neutral-500 text-xs">Local IPs</span>
          <div id="os-local-ips" class="mono text-[10px] text-neutral-300 space-y-0.5"></div>
        </div>
        <div class="flex justify-between">
          <span class="text-neutral-500 text-xs">External IP</span>
          <span class="mono text-xs text-neutral-300" id="os-external-ip">...</span>
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
function getDependencyFromPurl(purl) {
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

function getEcosystemFromPurl(purl) {
  if (purl.startsWith("cpe:"))        return "windows";
  if (purl.startsWith("pkg:gem/"))        return "ruby";
  if (purl.startsWith("pkg:nuget/"))      return "dotnet";
  if (purl.startsWith("pkg:npm/"))          return "npm";
  if (purl.startsWith("pkg:maven/"))        return "java";
  if (purl.startsWith("pkg:golang/"))       return "golang";
  if (purl.startsWith("pkg:cargo/"))        return "rust";
  if (purl.startsWith("pkg:composer/"))       return "php";
  if (purl.startsWith("pkg:pypi/"))         return "python";
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

const NVD_CVE_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0";

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
function scoreToSeverity(score) {
  if (score == null) return "unknown";
  if (score >= 9.0)  return "critical";
  if (score >= 7.0)  return "high";
  if (score >= 4.0)  return "medium";
  if (score >= 0.1)  return "low";
  return "unknown";
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
 */
function nvdItemToOsvShape(nvdItem, cpe, name, version, ecosystem) {
  const cveData = nvdItem.cve || nvdItem;
  const cveId   = cveData.id || cveData.CVE_data_meta?.ID || "";

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
  for (const fv of uniqueFixes) {
    affectedRangeEvents.push({ introduced: "0" }, { fixed: fv });
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
/**
 * Query NVD for one CPE string.  Returns { status, vulns } so the caller
 * can distinguish 429 (rate-limited) from real errors.
 */
async function queryNvdForCpe(cpe, name, version, ecosystem) {
  const url = `${NVD_CVE_BASE}?cpeName=${encodeURIComponent(cpe)}`;
  const res  = await fetchJSON(url, "GET", null, {
    timeoutMs:  40_000,
    maxRetries: 1,   // no internal backoff — submitToNvd owns retry for 429
  });

  if (res.status === 429 || res.status === 503) {
    return { status: res.status, vulns: [] };
  }

  if (res.status !== 200) {
    console.error(`[!] NVD query failed for ${cpe}: HTTP ${res.status}`);
    return { status: res.status, vulns: [] };
  }

  const items = (res.body?.vulnerabilities || []).map(
    item => nvdItemToOsvShape(item, cpe, name, version, ecosystem)
  );
  return { status: 200, vulns: items };
}

async function submitToNvd(inventory) {
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
          item.ecosystem || "unknown"
        );

        if (status === 429 || status === 503) {
          attempt++;
          if (attempt >= NVD_MAX_RETRIES) {
            console.warn(`[~] NVD returned ${status} for ${item.id} after ${NVD_MAX_RETRIES} attempts — skipping.`);
            break;
          }
          console.warn(`[~] NVD ${status} on ${item.id} (attempt ${attempt}/${NVD_MAX_RETRIES}), retrying in ${NVD_RATELIMIT_RETRY_MS / 1000}s...`);
          await new Promise(r => setTimeout(r, NVD_RATELIMIT_RETRY_MS));
          continue; // retry same item
        }

        results.push(...vulns);
        break; // success or non-retryable error — move to next item

      } catch (err) {
        console.error(`[!] NVD query error for ${item.id}: ${err.message}`);
        break; // network-level failure — skip this item, don't retry forever
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
async function submitToOsv(purlsList) {
  purlsList = purlsList.filter(p => p.startsWith("pkg:"));
  if (!purlsList.length) return [];

  const PAGE = 800;
  const results = [];

  for (let offset = 0; offset < purlsList.length; offset += PAGE) {
    const chunk   = purlsList.slice(offset, offset + PAGE);
    const queries = chunk.map((purl) => ({ package: { purl } }));
    const res     = await fetchJSON(OSV_QUERYBATCH, "POST", { queries });

    if (res.status !== 200) {
      console.error("[!] OSV batch query failed:", res.body);
      continue;
    }

    const vulnResults = res.body.results || [];
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

function getFix(vuln) {
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

async function getVulnById({ vulnerability_id, purl, dependency, affected_version }) {
  const res = await fetchJSON(`${OSV_VULN_BASE}/${vulnerability_id}`);
  if (res.status !== 200) return null;

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
function deduplicateVulnerabilitiesByAlias(vulns) {
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

function sortVulnerabilities(vulns) {
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


// ── Policy ────────────────────────────────────────────────────────────────────
//
// Schema:
//   severity_threshold            — block this level and everything above it.
//                                   Order: low < medium < high < critical.
//                                   Set to "none" to disable severity blocking entirely.
//                                   Infections are ALWAYS blocked regardless.
//   block_unknown_vulnerabilities — whether to block vulnerabilities whose
//                                   severity could not be determined.
//
const DEFAULT_POLICY = {
  severity_threshold:            "high",
  block_unknown_vulnerabilities: true,
};

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
    return JSON.parse(fs.readFileSync(file, "utf-8"));
  }

  /**
   * Set a single top-level policy field and persist it to disk.
   *
   * @param {"severity_threshold"|"block_unknown_vulnerabilities"} key
   * @param {string|boolean} value
   */
  setPolicyField(key, value) {
    const data = this.loadPolicy();
    data[key]  = value;
    const file = path.join(this.policyDir, this.POLICY_FILENAME);
    fs.writeFileSync(file, JSON.stringify(data, null, 4));
  }

  // ── scan ────────────────────────────────────────────────────────────────────

  async scan(args, options = {}) {
    const {
      is_script           = false,
      save_reports        = true,
      scan_os             = false,
      full_stack          = false,
      scan_node           = true,
      is_vscanned_project = false,
      scan_scope          = "repository",
    } = options;

    const projectRoot = this.projectRoot;
    const manager     = this.manager;

    const PKG_ARG_RE = /^(@[a-z0-9_.-]+\/)?[a-z0-9_.-]+(@[^\s;&|`$(){}\\'"<>]+)?$/i;
    if (args.length) {
      const bad = args.filter(a => !PKG_ARG_RE.test(a));
      if (bad.length) {
        console.error(`[!] Rejected unsafe or malformed package argument(s): ${bad.join(", ")}`);
        console.error("[!] Expected format: name, name@version, or @scope/name@version");
        process.exit(1);
      }
    }

    const os_metadata_info = await getOSMetadata();

    const getinstalledoptions = {
      full_stack,
      scan_os: options.scan_os ?? options.os_scan,
      scan_node: options.scan_node ?? true,
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
      if (needsRevert) {
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
        manager.inventoryData.push({
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
        });
        reportContent = {};
      }

      for (const purl of purls) {
        if (purl.split("@")[1] === "") {
          purls = purls.filter(p => p !== purl);
        }
      }
      purls = [...new Set(purls)];

      let inventory = [...manager.inventoryData];

      // ── OSV query ─────────────────────────────────────────────────────────
      const vuln_ids = await submitToOsv(purls);
      matchDependenciesWithInventory(inventory);

      // ── Enrich vulnerabilities concurrently ───────────────────────────────
      let vulnerabilities = [];
      const CONCURRENCY   = 40;
      for (let i = 0; i < vuln_ids.length; i += CONCURRENCY) {
        const batch   = vuln_ids.slice(i, i + CONCURRENCY);
        const results = await Promise.allSettled(batch.map(getVulnById));
        for (const r of results) {
          if (r.status === "fulfilled" && r.value) vulnerabilities.push(r.value);
          else if (r.status === "rejected")
            console.error("[!] Failed to fetch vulnerability:", r.reason?.message);
        }
      }

      // ── NVD query for CPE-based inventory items ────────────────────────────
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
      const localIPs       = getLocalIPsSync();
      const externalIP     = await getExternalIP();
      const primaryLocalIP = Object.values(localIPs)[0] || "";

      normalizeInventoryPaths(inventory, primaryLocalIP);

      vulnerabilities = deduplicateVulnerabilitiesByAlias(vulnerabilities);

      [vulnerabilities, inventory] = filterFalsePositiveInfections(inventory, vulnerabilities);

      // ── Stats ──────────────────────────────────────────────────────────────
      const severityBuckets = { critical:0, high:0, medium:0, low:0, unknown:0 };
      const infectedPurls   = new Set();
      const vulnerablePurls = new Set();
      let infectionCount    = 0;

      for (const v of vulnerabilities) {
        this.vulns_ids_found.add(v.id);
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

      const stats = {
        inventory_size: inventory.length,
        inventory_stats: {
          infected:      infectedPurls.size,
          vulnerable:    vulnerablePurls.size,
          safe:          Math.max(0, inventory.length - infectedPurls.size - vulnerablePurls.size - undeterminedCount),
          undetermined:  undeterminedCount,
        },
        total_vulnerabilities: vulnerabilities.length,
        vulnerabilities_stats: { severity: severityBuckets },
        total_infections: infectionCount,
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
        os_metadata:       { ...os_metadata_info, local_ips: localIPs, external_ip: externalIP || null },
        git_metadata:      git_metadata,
        tool_info:         { name: TOOL_NAME, version: TOOL_VERSION, license: TOOL_LICENSE },
        scan_info:         { type: this.checkMode, ecosystems: Array.from(ecosystems), engine: TOOL_NAME, scan_scope: options.scan_scope ?? "repository", ...(runtime.editor ? { editor: runtime.editor } : {}) },
        stats,
        vulnerabilities_ids: Array.from(this.vulns_ids_found),
        findings_summary:  findingsSummary,
        vulnerabilities:   sortVulnerabilities(vulnerabilities),
        inventory,
        policy,
        //dependencies_tree: buildImpactDependencyTree(inventory),  // kept for compatibility but not used in new graph
      };

      // Reachability
      try { enrichReachability(finalJson, projectRoot); } catch(e) { console.warn("[~] Reachability failed:", e.message); }

      const [allowed, reason] = evaluatePolicy(finalJson);
      finalJson.decision = { allowed, reason, policy_violations: policyViolations };

      if (is_script && !save_reports) {
        return finalJson;
      }

      const htmlReport = generateHTMLReport(finalJson);
      const htmlPath   = jsonPath.replace(/\.json$/, ".html");
      fs.writeFileSync(htmlPath, htmlReport);
      safeWriteJson(jsonPath, finalJson, 1000);

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
            if (!is_script) {
              console.log(`    \u2022 ${vuln.id}  ${label}${score}`);
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
      const latestDir      = path.join(projectRoot, ".ubel", "reports");
      const latestPath     = path.join(latestDir, "latest.json");
      const latestHtmlPath = path.join(latestDir, "latest.html");
      fs.mkdirSync(latestDir, { recursive: true });
      fs.writeFileSync(latestHtmlPath, htmlReport);
      safeWriteJson(latestPath, finalJson, 1000);

      // ── CycloneDX SBOM + SARIF ─────────────────────────────────────────────
      const sbomBuilder = new CycloneDXBuilder(finalJson);
      const sbomData    = sbomBuilder.generate();

      const sarifBuilder = new SarifBuilder(finalJson);
      const sarifData    = sarifBuilder.generate();

      const sbomPath  = jsonPath.replace(/\.json$/, ".cdx.json");
      const sarifPath = jsonPath.replace(/\.json$/, ".sarif.json");
      safeWriteJson(sbomPath, sbomData, 1000);
      safeWriteJson(sarifPath, sarifData, 1000);

      const latestSbom  = path.join(latestDir, "latest.cdx.json");
      const latestSarif = path.join(latestDir, "latest.sarif.json");
      safeWriteJson(latestSbom, sbomData, 1000);
      safeWriteJson(latestSarif, sarifData, 1000);

      if (!is_script) {
        console.log(`Latest JSON report saved to: ${latestPath}`);
        console.log(`Latest HTML report saved to: ${latestHtmlPath}`);
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
        manager.revert_lock_to_original(this.engine, projectRoot);
        manager.cleanupLockfileBackup();
        if (!is_script) console.log("[+] Backup lockfiles removed.");
        process.exit(0);
      }

      if (!is_script) console.log("[+] Policy passed. Installing dependencies...");
      this.wasSuccessfulScan = true;

      const saveResult = await manager.saveCandidateLockfile(this.engine, projectRoot);
      if (!saveResult.written) {
        if (!is_script) console.error("[!] Could not write candidate lockfile:", saveResult.reason);
        process.exit(1);
      }

      try {
        const installResult = await manager.runRealInstall(this.engine, projectRoot);
        if (installResult.status !== 0) {
          if (!is_script) console.error(`[!] npm ci failed (exit ${installResult.status}) — dependencies were NOT installed.`);
          manager.revert_lock_to_original(this.engine, projectRoot);
          process.exit(1);
        }
      } catch (err) {
        if (!is_script) console.error("[!] Failed to run npm ci:", err.message);
        manager.revert_lock_to_original(this.engine, projectRoot);
        process.exit(1);
      }

      manager.cleanupLockfileBackup();
      if (!is_script) console.log("[+] Backup lockfiles removed.");

      return finalJson;

    } finally {
      if (!this.wasSuccessfulScan && needsRevert) {
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