import fs      from "fs";
import path    from "path";
import https   from "https";
import http    from "http";
import { fileURLToPath } from "url";
import { NodeManager }          from "./node_runner.js";
import { processVulnerability } from "./cvss_parser.js";
import { evaluatePolicy }       from "./policy.js";
import { VERSION, TOOL_NAME }   from "./info.js";
import { dictToStr }            from "./utils.js";
import {getOSMetadata}          from "./os_metadata.js";
import {getGitMetadata}         from "./git_info.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_BASE  = "https://api.osv.dev/v1/vulns";


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
    // Also escape backticks to avoid breaking the outer template
    safeJson = safeJson.replace(/`/g, '\\u0060');

    // The complete client-side script
    const clientScript = `
        // --- DATA ---
        const reportData = ${safeJson};

        

        // ── Dependency Graph (force-directed) ──────────────────────────────────────────
        let graphState = null;

        function initGraph() {
            const canvas = document.getElementById('dep-graph-canvas');
            if (!canvas) return;

            const tree = reportData.dependencies_tree || {};
            if (!Object.keys(tree).length) {
                const ctx = canvas.getContext('2d');
                ctx.fillStyle = '#737373';
                ctx.font = '14px Inter, sans-serif';
                ctx.textAlign = 'center';
                ctx.fillText('No dependency tree data available.', canvas.width / 2, canvas.height / 2);
                return;
            }

            // Build node + edge lists from tree
            const nodeMap = {};
            const edges = [];

            const getOrCreate = (id) => {
                if (!nodeMap[id]) {
                    const inv = reportData.inventory.find(x => x.id === id);
                    nodeMap[id] = {
                        id,
                        label: inv ? inv.name + '@' + inv.version : id.split('/').pop(),
                        fullLabel: id,
                        state: inv ? (inv.state || 'unknown') : 'unknown',
                        x: 0, y: 0, vx: 0, vy: 0,
                        fx: null, fy: null,
                        radius: 0,
                    };
                }
                return nodeMap[id];
            };

            const walk = (nodeId, children, depth) => {
                getOrCreate(nodeId);
                for (const [childId, grandChildren] of Object.entries(children || {})) {
                    getOrCreate(childId);
                    edges.push({ source: nodeId, target: childId });
                    walk(childId, grandChildren, depth + 1);
                }
            };

            for (const [rootId, children] of Object.entries(tree)) {
                walk(rootId, children, 0);
            }

            const nodes = Object.values(nodeMap);

            // Deduplicate edges
            const edgeSet = new Set();
            const uniqueEdges = edges.filter(e => {
                const key = e.source + '||' + e.target;
                if (edgeSet.has(key)) return false;
                edgeSet.add(key);
                return true;
            });

            // Node sizing
            const childCount = {};
            for (const e of uniqueEdges) {
                childCount[e.source] = (childCount[e.source] || 0) + 1;
            }
            for (const n of nodes) {
                const c = childCount[n.id] || 0;
                n.radius = c > 10 ? 18 : c > 4 ? 14 : c > 1 ? 11 : 8;
            }

            // Initial positions — circular layout
            const cx = 0, cy = 0, R = Math.max(150, nodes.length * 9);
            nodes.forEach((n, i) => {
                const angle = (2 * Math.PI * i) / nodes.length;
                n.x = cx + R * Math.cos(angle) + (Math.random() - 0.5) * 40;
                n.y = cy + R * Math.sin(angle) + (Math.random() - 0.5) * 40;
            });

            // Viewport
            let scale = 1, panX = 0, panY = 0;
            let dragging = null;
            let isPanning = false, panStartX = 0, panStartY = 0, panOriginX = 0, panOriginY = 0;
            let highlightId = null;
            let searchMatches = new Set();

            const stateColor = (state) => ({
                safe:       { fill: '#16a34a', stroke: '#4ade80', text: '#f0fdf4' },
                vulnerable: { fill: '#ca8a04', stroke: '#fbbf24', text: '#fefce8' },
                infected:   { fill: '#dc2626', stroke: '#f87171', text: '#fef2f2' },
                unknown:    { fill: '#525252', stroke: '#a3a3a3', text: '#f5f5f5' },
            }[state] || { fill: '#525252', stroke: '#a3a3a3', text: '#f5f5f5' });

            // Force simulation
            let simTick = 0;
            const MAX_SIM = 300;
            const SIM_COOLDOWN = 0.92;
            let simRunning = true;

            const simulate = () => {
                if (!simRunning) return;

                const adjList = {};
                for (const n of nodes) adjList[n.id] = [];
                for (const e of uniqueEdges) {
                    adjList[e.source].push(e.target);
                    adjList[e.target].push(e.source);
                }

                // Repulsion
                for (let i = 0; i < nodes.length; i++) {
                    for (let j = i + 1; j < nodes.length; j++) {
                        const a = nodes[i], b = nodes[j];
                        const dx = b.x - a.x, dy = b.y - a.y;
                        const dist = Math.sqrt(dx*dx + dy*dy) || 0.01;
                        const force = Math.min(8000 / (dist * dist), 60);
                        const fx = (dx / dist) * force, fy = (dy / dist) * force;
                        a.vx -= fx; a.vy -= fy;
                        b.vx += fx; b.vy += fy;
                    }
                }

                // Spring (edges)
                for (const e of uniqueEdges) {
                    const a = nodeMap[e.source], b = nodeMap[e.target];
                    if (!a || !b) continue;
                    const dx = b.x - a.x, dy = b.y - a.y;
                    const dist = Math.sqrt(dx*dx + dy*dy) || 0.01;
                    const ideal = (a.radius + b.radius) * 5 + 30;
                    const force = (dist - ideal) * 0.04;
                    const fx = (dx / dist) * force, fy = (dy / dist) * force;
                    a.vx += fx; a.vy += fy;
                    b.vx -= fx; b.vy -= fy;
                }

                // Center gravity
                for (const n of nodes) {
                    n.vx += -n.x * 0.004;
                    n.vy += -n.y * 0.004;
                }

                // Integrate + dampen
                for (const n of nodes) {
                    if (n.fx !== null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
                    n.vx *= SIM_COOLDOWN; n.vy *= SIM_COOLDOWN;
                    n.x += n.vx; n.y += n.vy;
                }

                simTick++;
                if (simTick > MAX_SIM) simRunning = false;
            };

            // Render
            const render = () => {
                const dpr = window.devicePixelRatio || 1;
                const rect = canvas.getBoundingClientRect();
                if (canvas.width !== rect.width * dpr || canvas.height !== rect.height * dpr) {
                    canvas.width = rect.width * dpr;
                    canvas.height = rect.height * dpr;
                }
                const ctx = canvas.getContext('2d');
                ctx.setTransform(1, 0, 0, 1, 0, 0);
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                ctx.scale(dpr, dpr);

                const W = rect.width, H = rect.height;
                const tx = W / 2 + panX, ty = H / 2 + panY;

                ctx.save();
                ctx.translate(tx, ty);
                ctx.scale(scale, scale);

                // Edges
                ctx.lineWidth = 0.8;
                for (const e of uniqueEdges) {
                    const a = nodeMap[e.source], b = nodeMap[e.target];
                    if (!a || !b) continue;
                    const isHighlighted = highlightId && (e.source === highlightId || e.target === highlightId);
                    const isSearchMatch = searchMatches.size > 0 && (searchMatches.has(e.source) || searchMatches.has(e.target));
                    const dimmed = (highlightId && !isHighlighted) || (searchMatches.size > 0 && !isSearchMatch);
                    ctx.globalAlpha = dimmed ? 0.08 : isHighlighted ? 0.9 : 0.25;
                    ctx.strokeStyle = isHighlighted ? '#ef4444' : '#525252';
                    ctx.beginPath();
                    ctx.moveTo(a.x, a.y);
                    ctx.lineTo(b.x, b.y);
                    ctx.stroke();

                    // Arrow
                    if (isHighlighted || !dimmed) {
                        const ang = Math.atan2(b.y - a.y, b.x - a.x);
                        const ex = b.x - Math.cos(ang) * (b.radius + 3);
                        const ey = b.y - Math.sin(ang) * (b.radius + 3);
                        ctx.globalAlpha = dimmed ? 0.08 : 0.5;
                        ctx.fillStyle = isHighlighted ? '#ef4444' : '#737373';
                        ctx.beginPath();
                        ctx.moveTo(ex, ey);
                        ctx.lineTo(ex - Math.cos(ang - 0.4) * 6, ey - Math.sin(ang - 0.4) * 6);
                        ctx.lineTo(ex - Math.cos(ang + 0.4) * 6, ey - Math.sin(ang + 0.4) * 6);
                        ctx.closePath();
                        ctx.fill();
                    }
                }

                // Nodes
                for (const n of nodes) {
                    const c = stateColor(n.state);
                    const isHl = n.id === highlightId;
                    const isMatch = searchMatches.has(n.id);
                    const dimmed = (highlightId && !isHl) || (searchMatches.size > 0 && !isMatch && !isHl);

                    ctx.globalAlpha = dimmed ? 0.15 : 1;

                    // Glow ring for matches
                    if (isMatch || isHl) {
                        ctx.beginPath();
                        ctx.arc(n.x, n.y, n.radius + 5, 0, Math.PI * 2);
                        ctx.fillStyle = isHl ? '#ef4444' : c.stroke;
                        ctx.globalAlpha = 0.25;
                        ctx.fill();
                        ctx.globalAlpha = dimmed ? 0.15 : 1;
                    }

                    ctx.beginPath();
                    ctx.arc(n.x, n.y, n.radius, 0, Math.PI * 2);
                    ctx.fillStyle = c.fill;
                    ctx.fill();
                    ctx.strokeStyle = isHl ? '#ffffff' : c.stroke;
                    ctx.lineWidth = isHl ? 2.5 : 1.5;
                    ctx.stroke();

                    // Label (only if zoomed enough or highlighted/matched)
                    const showLabel = scale > 0.7 || isHl || isMatch;
                    if (showLabel) {
                        ctx.globalAlpha = dimmed ? 0.15 : isHl ? 1 : 0.85;
                        ctx.fillStyle = '#e5e5e5';
                        ctx.font = \`\${isHl ? 'bold ' : ''}\${Math.max(9, Math.min(11, n.radius * 0.9))}px JetBrains Mono, monospace\`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        const labelY = n.y + n.radius + 9;
                        // Shadow
                        ctx.fillStyle = 'rgba(0,0,0,0.8)';
                        ctx.fillText(n.label, n.x + 0.5, labelY + 0.5);
                        ctx.fillStyle = isHl ? '#ffffff' : '#d4d4d4';
                        ctx.fillText(n.label, n.x, labelY);
                    }
                }

                ctx.globalAlpha = 1;
                ctx.restore();
            };

            // Animation loop
            let animId;
            const loop = () => {
                simulate();
                render();
                animId = requestAnimationFrame(loop);
            };
            loop();

            // Canvas → world coords
            const toWorld = (cx, cy) => {
                const rect = canvas.getBoundingClientRect();
                const W = rect.width, H = rect.height;
                return {
                    x: (cx - W / 2 - panX) / scale,
                    y: (cy - H / 2 - panY) / scale,
                };
            };

            const hitTest = (wx, wy) => {
                let best = null, bestDist = Infinity;
                for (const n of nodes) {
                    const d = Math.sqrt((wx - n.x) ** 2 + (wy - n.y) ** 2);
                    if (d < n.radius + 4 && d < bestDist) { best = n; bestDist = d; }
                }
                return best;
            };

            // Tooltip
            const tooltip = document.getElementById('graph-tooltip');
            canvas.addEventListener('mousemove', (e) => {
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    canvas.style.cursor = dragging ? 'grabbing' : 'pointer';
                    const inv = reportData.inventory.find(x => x.id === hit.id);
                    const vulns = reportData.vulnerabilities.filter(v => v.affected_purl === hit.id);
                    tooltip.textContent = [
                        hit.id,
                        \`State: \${hit.state}\`,
                        inv ? \`License: \${inv.license || 'unknown'}\` : '',
                        inv ? \`Scopes: \${(inv.scopes || []).join(', ') || '—'}\` : '',
                        vulns.length ? \`Vulns: \${vulns.length} (\${vulns.map(v=>v.severity).join(', ')})\` : 'No vulnerabilities',
                    ].filter(Boolean).join('\\n');
                    tooltip.style.display = 'block';
                    tooltip.style.left = (mx + 14) + 'px';
                    tooltip.style.top = (my - 10) + 'px';
                } else {
                    canvas.style.cursor = isPanning ? 'grabbing' : 'grab';
                    tooltip.style.display = 'none';
                }

                if (dragging) {
                    dragging.fx = (mx - canvas.getBoundingClientRect().left - canvas.getBoundingClientRect().width / 2 - panX) / scale;
                    dragging.fy = (my - canvas.getBoundingClientRect().top - canvas.getBoundingClientRect().height / 2 - panY) / scale;
                    dragging.x = dragging.fx;
                    dragging.y = dragging.fy;
                }

                if (isPanning) {
                    panX = panOriginX + (e.clientX - panStartX);
                    panY = panOriginY + (e.clientY - panStartY);
                }
            });

            canvas.addEventListener('mousedown', (e) => {
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    dragging = hit;
                    hit.fx = hit.x; hit.fy = hit.y;
                    simRunning = true; simTick = 0;
                } else {
                    isPanning = true;
                    panStartX = e.clientX; panStartY = e.clientY;
                    panOriginX = panX; panOriginY = panY;
                    canvas.style.cursor = 'grabbing';
                }
            });

            canvas.addEventListener('mouseup', (e) => {
                if (dragging) {
                    dragging.fx = null; dragging.fy = null;
                    dragging = null;
                }
                isPanning = false;
                canvas.style.cursor = 'grab';
            });

            canvas.addEventListener('click', (e) => {
                if (isPanning) return;
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const { x: wx, y: wy } = toWorld(mx, my);
                const hit = hitTest(wx, wy);
                if (hit) {
                    highlightId = hit.id === highlightId ? null : hit.id;
                    if (hit.id) openInvModal(hit.id);
                } else {
                    highlightId = null;
                }
            });

            // Touch support
            let lastTouchDist = null;
            canvas.addEventListener('touchstart', (e) => {
                if (e.touches.length === 2) {
                    lastTouchDist = Math.hypot(
                        e.touches[0].clientX - e.touches[1].clientX,
                        e.touches[0].clientY - e.touches[1].clientY
                    );
                }
            }, { passive: true });
            canvas.addEventListener('touchmove', (e) => {
                if (e.touches.length === 2) {
                    const d = Math.hypot(
                        e.touches[0].clientX - e.touches[1].clientX,
                        e.touches[0].clientY - e.touches[1].clientY
                    );
                    if (lastTouchDist) { scale = Math.max(0.1, Math.min(5, scale * (d / lastTouchDist))); }
                    lastTouchDist = d;
                    e.preventDefault();
                }
            }, { passive: false });

            // Scroll zoom
            canvas.addEventListener('wheel', (e) => {
                e.preventDefault();
                const delta = e.deltaY > 0 ? -0.1 : 0.1;
                const r = canvas.getBoundingClientRect();
                const mx = e.clientX - r.left, my = e.clientY - r.top;
                const W = r.width, H = r.height;
                const wxBefore = (mx - W/2 - panX) / scale;
                const wyBefore = (my - H/2 - panY) / scale;
                scale = Math.max(0.08, Math.min(5, scale + delta * scale));
                panX = mx - W/2 - wxBefore * scale;
                panY = my - H/2 - wyBefore * scale;
            }, { passive: false });

            // Search
            document.getElementById('graph-search').addEventListener('input', (e) => {
                const q = e.target.value.trim().toLowerCase();
                searchMatches.clear();
                if (q.length >= 2) {
                    for (const n of nodes) {
                        if (n.id.toLowerCase().includes(q) || n.label.toLowerCase().includes(q)) {
                            searchMatches.add(n.id);
                        }
                    }
                }
                // Re-kick sim briefly so things settle
                simRunning = true; simTick = Math.max(0, MAX_SIM - 60);
            });

            graphState = {
                nodes, scale: () => scale, setScale: (v) => { scale = v; },
                panX: () => panX, panY: () => panY,
                setPan: (x, y) => { panX = x; panY = y; },
                reset: () => {
                    scale = 1; panX = 0; panY = 0;
                    for (const n of nodes) { n.fx = null; n.fy = null; }
                    simRunning = true; simTick = 0;
                },
                stop: () => { cancelAnimationFrame(animId); },
            };
        }

        function graphZoom(delta) {
            if (!graphState) return;
            graphState.setScale(Math.max(0.08, Math.min(5, graphState.scale() + delta)));
        }

        function graphReset() {
            if (!graphState) return;
            graphState.reset();
        }


        // --- CORE LOGIC (existing) ---
        function init() {
            // Fill inventory to match reported size if needed
            if (reportData.inventory.length < reportData.stats.inventory_size) {
                const currentCount = reportData.inventory.length;
                const needed = reportData.stats.inventory_size - currentCount;
                for (let i = 0; i < needed; i++) {
                    reportData.inventory.push({
                        id: \`pkg:npm/dummy-pkg-\${i + 1}@1.0.0\`,
                        name: \`dummy-pkg-\${i + 1}\`,
                        version: "1.0.0",
                        type: "library",
                        license: "MIT",
                        ecosystem: "npm",
                        state: "safe",
                        dependencies: [],
                        paths: [],
                        scopes: ["prod"],
                        introduced_by: []
                    });
                }
            }

            closeModal();
            renderDashboard();
            renderVulnerabilities();
            renderInventory();
            renderStats();
            renderSystem();
            setupFilters();
        }

        function switchTab(tabId) {
            document.querySelectorAll('nav button').forEach(btn => btn.classList.remove('tab-active'));
            document.getElementById(\`tab-\${tabId}\`).classList.add('tab-active');
            document.querySelectorAll('main section').forEach(sec => sec.classList.add('hidden'));
            document.getElementById(\`section-\${tabId}\`).classList.remove('hidden');
            if (tabId === 'graph' && !graphState) {
                setTimeout(initGraph, 50);
            }
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
            document.getElementById('policy-infection').textContent = reportData.policy.infections;
            document.getElementById('policy-high').textContent = reportData.policy.severity.high;
            document.getElementById('policy-medium').textContent = reportData.policy.severity.medium;
            document.getElementById('policy-low').textContent = reportData.policy.severity.low;
            document.getElementById('policy-critical').textContent = reportData.policy.severity.critical;

            // Severity Chart
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

        function renderVulnerabilities(filter = '', severity = 'all') {
            const tbody = document.getElementById('vuln-table-body');
            tbody.innerHTML = '';

            const filtered = reportData.vulnerabilities.filter(v => {
                const matchesSearch = v.id.toLowerCase().includes(filter.toLowerCase()) || 
                                     v.affected_dependency.toLowerCase().includes(filter.toLowerCase());
                const matchesSeverity = severity === 'all' || v.severity === severity;
                return matchesSearch && matchesSeverity;
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
                    <td class="px-6 py-4">
                        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span>
                    </td>
                    <td class="px-6 py-4 font-medium">\${v.affected_dependency} ( \${v.ecosystem} )</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${v.affected_dependency_version}</td>
                    <td class="px-6 py-4">
                        \${v.has_fix ? '<span class="text-green-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}
                    </td>
                    <td class="px-6 py-4">
                        \${v.is_policy_violation
                              ? '<span class="text-red-400 flex items-center gap-1">' +
                                '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3">' +
                                '<line x1="18" y1="6" x2="6" y2="18"></line>' +
                                '<line x1="6" y1="6" x2="18" y2="18"></line>' +
                                '</svg> Yes</span>'
                              : '<span class="text-neutral-500">No</span>'
                          }
                    </td>
                    <td class="px-6 py-4 text-neutral-400 text-xs">\${v.fixed_versions.join('<br>')}</td>
                    <td class="px-6 py-4 text-right">
                        <button class="text-red-400 hover:text-red-300 text-xs font-semibold">View Details</button>
                    </td>
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
                    <td class="px-6 py-4 mono text-xs font-medium">\${item.id}</td>
                    <td class="px-6 py-4 font-medium">\${item.name}</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${item.version}</td>
                    <td class="px-6 py-4">
                        <span class="text-xs \${item.state === 'safe' ? 'text-green-400' : 'text-red-400'}">\${item.state}</span>
                    </td>
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
            
            document.getElementById('stats-vuln-total').textContent = s.total_vulnerabilities;
            document.getElementById('stats-vuln-crit').textContent = s.vulnerabilities_stats.severity.critical;
            document.getElementById('stats-vuln-high').textContent = s.vulnerabilities_stats.severity.high;
            document.getElementById('stats-vuln-med').textContent = s.vulnerabilities_stats.severity.medium;
            document.getElementById('stats-vuln-low').textContent = s.vulnerabilities_stats.severity.low;
            document.getElementById('stats-vuln-unk').textContent = s.vulnerabilities_stats.severity.unknown;

            new Chart(document.getElementById('statsInventoryChart'), {
                type: 'doughnut',
                data: {
                    labels: ['Safe', 'Vulnerable', 'Infected'],
                    datasets: [{
                        data: [s.inventory_stats.safe, s.inventory_stats.vulnerable, s.inventory_stats.infected],
                        backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
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

            document.getElementById('os-id').textContent = os.os_id;
            document.getElementById('os-name').textContent = os.os_name;
            document.getElementById('os-version').textContent = os.os_version;

            document.getElementById('git-available').textContent = git.available ? 'Yes' : 'No';
            document.getElementById('git-reason').textContent = git.reason || 'N/A';
        }

        function setupFilters() {
            document.getElementById('vuln-search').addEventListener('input', (e) => {
                renderVulnerabilities(e.target.value, document.getElementById('vuln-filter-severity').value);
            });
            document.getElementById('vuln-filter-severity').addEventListener('change', (e) => {
                renderVulnerabilities(document.getElementById('vuln-search').value, e.target.value);
            });
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

            const itemVulns = reportData.vulnerabilities.filter(v => v.affected_purl === item.id);
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
                        \${v.is_policy_violation
                            ? '<span class="text-[10px] text-red-400 border border-red-400/50 rounded px-1.5 py-0.5">Policy Block</span>'
                            : '<span class="text-[10px] text-neutral-500">Allowed</span>'}
                        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
                    </div>
                </div>
            \`).join('') : '<p class="text-sm text-neutral-500 italic py-2">No vulnerabilities found.</p>';

            const introRows = (item.introduced_by || []).length
                ? (item.introduced_by).map(ib => \`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700">\${ib}</span>\`).join('')
                : '<span class="text-neutral-500 text-xs italic">Direct dependency</span>';

            const pathRows = (item.paths || []).length
                ? item.paths.map(p => \`<div class="mono text-[10px] text-neutral-400 bg-neutral-900 px-2 py-1.5 rounded border border-neutral-800 break-all">\${p}</div>\`).join('')
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
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Type</p>
                            <p class="mono text-xs">\${item.type || 'library'}</p>
                        </div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">License</p>
                            <p class="mono text-xs">\${item.license || 'unknown'}</p>
                        </div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Scopes</p>
                            <p class="mono text-xs">\${(item.scopes || []).join(', ') || '—'}</p>
                        </div>
                        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Vulnerabilities</p>
                            <p class="text-lg font-bold \${itemVulns.length > 0 ? 'text-red-400' : 'text-green-400'}">\${itemVulns.length}</p>
                        </div>
                    </div>

                    <div>
                        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Introduced By</h4>
                        <div class="flex flex-wrap gap-2">\${introRows}</div>
                    </div>

                    <div>
                        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Dependencies (\${(item.dependencies || []).length})</h4>
                        <div class="flex flex-wrap gap-2">\${depsRows}</div>
                    </div>

                    <div>
                        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Install Paths</h4>
                        <div class="space-y-1">\${pathRows}</div>
                    </div>

                    <div>
                        <h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-3">Vulnerabilities (\${itemVulns.length})</h4>
                        <div class="space-y-0">\${vulnRows}</div>
                    </div>
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
                        <div class="text-right">
                            <p class="text-[10px] uppercase text-neutral-500 font-bold tracking-widest">Severity Score</p>
                            <p class="text-3xl font-bold text-red-500">\${v.severity_score}</p>
                        </div>
                    </div>

                    <div class="grid grid-cols-1 md:grid-cols-3 gap-4 py-4 border-y border-neutral-800">
                        <div>
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Published</p>
                            <p class="text-xs mono">\${new Date(v.published).toLocaleDateString()}</p>
                        </div>
                        <div>
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Modified</p>
                            <p class="text-xs mono">\${new Date(v.modified).toLocaleDateString()}</p>
                        </div>
                        <div>
                            <p class="text-[10px] uppercase text-neutral-500 font-bold mb-1">Vector</p>
                            <p class="text-[10px] mono text-neutral-400 truncate" title="\${v.severity_vector}">\${v.severity_vector}</p>
                        </div>
                    </div>

                    <div>
                        <h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4>
                        <div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">\${v.description}</div>
                    </div>

                    \${v.fixes.length > 0 ? \`
                    <div>
                        <h4 class="text-sm font-semibold mb-2 text-green-400">Recommended Fixes</h4>
                        <ul class="space-y-2">
                            \${v.fixes.map(f => \`<li class="text-xs bg-green-500/10 border border-green-500/20 p-3 rounded-lg text-green-300 mono">\${f}</li>\`).join('')}
                        </ul>
                    </div>
                    \` : ''}

                    <div>
                        <h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4>
                        <div class="flex flex-wrap gap-2">
                            \${v.references.map(r => \`<a href="\${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">\${r.type}</a>\`).join('')}
                        </div>
                    </div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        window.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') closeModal();
        });

        document.getElementById('modal-overlay').addEventListener('click', (e) => {
            if (e.target.id === 'modal-overlay') closeModal();
        });

        init();
    `;

    // Now produce the final HTML with all sections intact
    return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubel Security Scan Report</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <script src="https://d3js.org/d3.v7.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
    <style>
        :root {
            --bg: #0a0a0a;
            --card: #141414;
            --border: #262626;
            --accent: #ef4444;
        }
        body {
            font-family: 'Inter', sans-serif;
            background-color: var(--bg);
            color: #e5e5e5;
        }
        .mono { font-family: 'JetBrains Mono', monospace; }
        .glass {
            background: rgba(20, 20, 20, 0.8);
            backdrop-filter: blur(12px);
            border: 1px solid var(--border);
        }
        .severity-high { color: #f87171; border-color: #f87171; }
        .severity-medium { color: #fb923c; border-color: #fb923c; }
        .severity-low { color: #60a5fa; border-color: #60a5fa; }
        .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
        
        ::-webkit-scrollbar { width: 6px; height: 6px; }
        ::-webkit-scrollbar-track { background: var(--bg); }
        ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
        ::-webkit-scrollbar-thumb:hover { background: #404040; }

        .tab-active {
            border-bottom: 2px solid var(--accent);
            color: white;
        }
        
        .modal-overlay {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 50;
            backdrop-filter: blur(4px);
        }
        .modal-content {
            max-height: 90vh;
            overflow-y: auto;
        }
        #tree-tooltip {
            position: fixed;
            background: rgba(20,20,20,0.95);
            border: 1px solid #404040;
            border-radius: 8px;
            padding: 8px 12px;
            font-size: 11px;
            font-family: 'JetBrains Mono', monospace;
            color: #e5e5e5;
            pointer-events: none;
            max-width: 280px;
            z-index: 100;
            line-height: 1.6;
            white-space: pre-wrap;
            word-break: break-all;
            display: none;
        }
    </style>
</head>
<body class="min-h-screen flex flex-col">

    <!-- Header -->
    <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3">
                <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white">U</div>
                <div>
                    <h1 class="text-lg font-semibold tracking-tight">Security Scan Report</h1>
                    <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p>
                </div>
            </div>
            <div id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider">
                Status: Loading...
            </div>
        </div>
    </header>

    <!-- Navigation Tabs -->
    <nav class="border-b border-neutral-800 bg-neutral-900/30">
        <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
            <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
            <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities</button>
            <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Inventory</button>
            <button onclick="switchTab('graph')" id="tab-graph" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Dependency Graph</button>
            <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
            <button onclick="switchTab('system')" id="tab-system" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">System Info</button>
        </div>
    </nav>

    <!-- Main Content -->
    <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
        
        <!-- Dashboard Section -->
        <section id="section-dashboard" class="space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div class="glass p-6 rounded-xl">
                    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Total Items</p>
                    <p class="text-3xl font-bold" id="stat-total">0</p>
                </div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-red-500">
                    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerable Items</p>
                    <p class="text-3xl font-bold text-red-500" id="stat-vulnerabilities">0</p>
                </div>
                <div class="glass p-6 rounded-xl">
                    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Infections</p>
                    <p class="text-3xl font-bold" id="stat-infections">0</p>
                </div>
                <div class="glass p-6 rounded-xl border-l-4 border-l-green-500">
                    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Safe Items</p>
                    <p class="text-3xl font-bold text-green-500" id="stat-safe">0</p>
                </div>
            </div>

            <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl lg:col-span-2">
                    <h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Severity Distribution</h3>
                    <div class="h-64">
                        <canvas id="severityChart"></canvas>
                    </div>
                </div>
                <div class="glass p-6 rounded-xl">
                    <h3 class="text-sm font-semibold mb-6 uppercase tracking-widest text-neutral-400">Decision Summary</h3>
                    <div id="decision-box" class="p-4 rounded-lg bg-neutral-800/50 border border-neutral-700">
                        <p class="text-sm leading-relaxed" id="decision-reason">...</p>
                    </div>
                    <div class="mt-6 space-y-4">
                        <div class="flex justify-between items-center text-sm">
                            <span class="text-neutral-500">Policy:</span>
                        </div>
                        <div class="flex justify-between items-center text-sm">
                            <table class="w-auto text-sm mono">
                                <tr><td class="pr-2">Infection</td><td id="policy-infection">...</td></tr>
                                <tr><td class="pr-2">Critical</td><td id="policy-critical">...</td></tr>
                                <tr><td class="pr-2">High</td><td id="policy-high">...</td></tr>
                                <tr><td class="pr-2">Medium</td><td id="policy-medium">...</td></tr>
                                <tr><td class="pr-2">Low</td><td id="policy-low">...</td></tr>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </section>

        <!-- Vulnerabilities Section -->
        <section id="section-vulnerabilities" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Vulnerability Findings</h2>
                <div class="flex gap-2 w-full md:w-auto">
                    <input type="text" id="vuln-search" placeholder="Search ID or package..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64">
                    <select id="vuln-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
                        <option value="all">All Severities</option>
                        <option value="critical">Critical</option>
                        <option value="high">High</option>
                        <option value="medium">Medium</option>
                        <option value="low">Low</option>
                    </select>
                </div>
            </div>

            <div class="glass rounded-xl overflow-hidden">
                <table class="w-full text-left text-sm">
                    <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">
                        <tr><th class="px-6 py-4">ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix Available</th><th>Policy Violation</th><th>Fixed Versions</th><th class="text-right">Action</th></tr>
                    </thead>
                    <tbody id="vuln-table-body" class="divide-y divide-neutral-800"></tbody>
                </table>
            </div>
        </section>

        <!-- Inventory Section -->
        <section id="section-inventory" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Package Inventory</h2>
                <div class="flex gap-2 w-full md:w-auto">
                    <input type="text" id="inv-search" placeholder="Search packages..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64">
                    <select id="inv-filter-state" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
                        <option value="all">All States</option>
                        <option value="safe">Safe</option>
                        <option value="vulnerable">Vulnerable</option>
                        <option value="infected">Infected</option>
                    </select>
                </div>
            </div>

            <div class="glass rounded-xl overflow-hidden">
                <table class="w-full text-left text-sm">
                    <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">
                        <tr><th class="px-6 py-4">ID</th><th>Name</th><th>Version</th><th>State</th><th>Ecosystem</th><th>License</th><th>Scopes</th></tr>
                    </thead>
                    <tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody>
                </table>
            </div>
        </section>

        <!-- Dependency Graph Section -->
        <section id="section-graph" class="hidden space-y-4" style="height: calc(100vh - 220px); min-height: 500px;">
            <div class="flex flex-col md:flex-row gap-3 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Dependency Graph</h2>
                <div class="flex gap-2 w-full md:w-auto items-center flex-wrap">
                    <input type="text" id="graph-search" placeholder="Search by package ID..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-72">
                    <button onclick="graphZoom(0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700 transition-colors">＋</button>
                    <button onclick="graphZoom(-0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700 transition-colors">－</button>
                    <button onclick="graphReset()" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700 transition-colors">Reset</button>
                    <div class="flex items-center gap-3 text-[10px] mono text-neutral-500 flex-wrap">
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-green-500"></span>safe</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-yellow-500"></span>vulnerable</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500"></span>infected</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-neutral-500"></span>unknown</span>
                    </div>
                </div>
            </div>
            <div class="glass rounded-xl overflow-hidden relative" style="height: calc(100% - 56px);">
                <canvas id="dep-graph-canvas" style="width:100%;height:100%;cursor:grab;display:block;"></canvas>
                <div id="graph-tooltip" style="display:none;position:absolute;background:rgba(20,20,20,0.95);border:1px solid #404040;border-radius:8px;padding:8px 12px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#e5e5e5;pointer-events:none;max-width:280px;z-index:10;line-height:1.6;white-space:pre-wrap;word-break:break-all;"></div>
            </div>
        </section>


        <!-- Detailed Stats Section -->
        <section id="section-stats" class="hidden space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <div class="glass p-6 rounded-xl space-y-6">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Inventory Stats</h3>
                    <div class="h-48"><canvas id="statsInventoryChart"></canvas></div>
                    <div class="space-y-2">
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Total Size</span><span class="mono" id="stats-inv-size">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Safe</span><span class="mono text-green-400" id="stats-inv-safe">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Vulnerable</span><span class="mono text-yellow-400" id="stats-inv-vuln">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Infected</span><span class="mono text-red-400" id="stats-inv-inf">0</span></div>
                    </div>
                </div>
                <div class="glass p-6 rounded-xl space-y-6">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Vulnerability Stats</h3>
                    <div class="h-48"><canvas id="statsVulnChart"></canvas></div>
                    <div class="space-y-2">
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Total Found</span><span class="mono" id="stats-vuln-total">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Critical</span><span class="mono text-red-600" id="stats-vuln-crit">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">High</span><span class="mono text-red-400" id="stats-vuln-high">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Medium</span><span class="mono text-orange-400" id="stats-vuln-med">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Low</span><span class="mono text-blue-400" id="stats-vuln-low">0</span></div>
                        <div class="flex justify-between text-sm"><span class="text-neutral-500">Unknown</span><span class="mono text-gray-400" id="stats-vuln-unk">0</span></div>
                    </div>
                </div>
                <div class="glass p-6 rounded-xl space-y-6">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Ecosystem Distribution</h3>
                    <div class="h-48"><canvas id="statsEcoChart"></canvas></div>
                    <div id="eco-legend" class="grid grid-cols-2 gap-2 text-[10px] mono text-neutral-500"></div>
                </div>
            </div>
        </section>

        <!-- System Section -->
        <section id="section-system" class="hidden space-y-8">
            <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
                <!-- Runtime -->
                <div class="glass p-6 rounded-xl space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg> Runtime</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Environment</span><span class="mono text-xs" id="run-env">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="run-node">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Platform</span><span class="mono text-xs" id="run-platform">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Arch</span><span class="mono text-xs" id="run-arch">...</span></div>
                        <div class="flex flex-col gap-1"><span class="text-neutral-500 text-xs">CWD</span><span class="mono text-[10px] break-all bg-neutral-900 p-2 rounded" id="run-cwd">...</span></div>
                    </div>
                </div>
                <!-- Engine & Tool -->
                <div class="glass p-6 rounded-xl space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.77-3.77a6 6 0 0 1-7.94 7.94l-6.91 6.91a2.12 2.12 0 0 1-3-3l6.91-6.91a6 6 0 0 1 7.94-7.94l-3.76 3.76z"/></svg> Engine & Tool</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Engine Name</span><span class="mono text-xs" id="engine-name">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Engine Version</span><span class="mono text-xs" id="engine-version">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool Name</span><span class="mono text-xs" id="tool-name">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool Version</span><span class="mono text-xs" id="tool-version">...</span></div>
                    </div>
                </div>
                <!-- Scan Info -->
                <div class="glass p-6 rounded-xl space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg> Scan Info</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Scan Type</span><span class="mono text-xs" id="scan-type">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Ecosystems</span><span class="mono text-xs" id="scan-ecosystems">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Scan Engine</span><span class="mono text-xs" id="scan-engine">...</span></div>
                    </div>
                </div>
                <!-- OS Metadata -->
                <div class="glass p-6 rounded-xl space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg> OS Metadata</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS ID</span><span class="mono text-xs" id="os-id">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS Name</span><span class="mono text-xs" id="os-name">...</span></div>
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OS Version</span><span class="mono text-xs" id="os-version">...</span></div>
                    </div>
                </div>
                <!-- Git Metadata -->
                <div class="glass p-6 rounded-xl space-y-4">
                    <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="18" r="3"/><circle cx="6" cy="6" r="3"/><path d="M13 6h3a2 2 0 0 1 2 2v7"/><line x1="6" y1="9" x2="6" y2="21"/></svg> Git Metadata</h3>
                    <div class="space-y-3">
                        <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Available</span><span class="mono text-xs" id="git-available">...</span></div>
                        <div class="flex flex-col gap-1"><span class="text-neutral-500 text-xs">Reason</span><span class="mono text-[10px] text-neutral-400 italic" id="git-reason">...</span></div>
                    </div>
                </div>
            </div>
        </section>
    </main>

    <!-- Footer -->
    <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50">
        <div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
            <p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">Ubel Security Engine v1.0.0</span></p>
        </div>
    </footer>

    <!-- Modal Overlay -->
    <div id="modal-overlay" class="modal-overlay items-center justify-center p-4" style="display: none;">
        <div class="modal-content glass w-full max-w-3xl rounded-2xl shadow-2xl relative">
            <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors">
                <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
            </button>
            <div id="modal-body" class="p-8"></div>
        </div>
    </div>

    <script>
        ${clientScript}
    </script>
</body>
</html>`;
}


function fetchJSON(url, method = "GET", body = null, opts = {}) {
  const {
    timeoutMs = 20000,
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
  // e.g. pkg:npm/%40scope/name@1.2.3  or  pkg:npm/name@1.2.3
  let info;
  if (purl.startsWith("pkg:pypi/") || purl.startsWith("pkg:npm/")) {
    const prefix = purl.startsWith("pkg:pypi/") ? "pkg:pypi/" : "pkg:npm/";
    info = purl.slice(prefix.length);
  } else {
    info = purl.split("/").pop();
  }
  // Decode percent-encoded @ for scoped packages (%40scope/name → @scope/name)
  info = info.replace(/^%40/, "@");
  // Handle scoped packages: @scope/name@version has two @ signs
  const lastAt = info.lastIndexOf("@");
  if (lastAt <= 0) return [info, "unknown"];
  return [info.slice(0, lastAt), info.slice(lastAt + 1)];
}

function getEcosystemFromPurl(purl) {
  if (purl.startsWith("pkg:npm/"))          return "npm";
  if (purl.startsWith("pkg:maven/"))        return "maven";
  if (purl.startsWith("pkg:composer/"))       return "composer";
  if (purl.startsWith("pkg:pypi/"))         return "pypi";
  if (purl.startsWith("pkg:deb/ubuntu/"))   return "ubuntu";
  if (purl.startsWith("pkg:deb/debian/"))   return "debian";
  if (purl.startsWith("pkg:rpm/redhat/"))   return "redhat";
  if (purl.startsWith("pkg:apk/alpine/"))   return "alpine";
  return "unknown";
}

// ── OSV querying ──────────────────────────────────────────────────────────────
async function submitToOsv(purlsList) {
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
        results.push({ purl, vulnerability_id: v.id, dependency: dep, affected_version: ver });
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

  const fallback = lastAffected.length ? lastAffected : versions;

  if (fixed.length)
    return `Upgrade ${pkgName} ( ${ecosystem} ) to: ${fixed.join(" or ")}`;
  if (fallback.length)
    return `Upgrade ${pkgName} ( ${ecosystem} ) to a version other than: ${fallback.join(" or ")}`;
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

  vuln.fixed_versions = get_fixed_versions(vuln);
  vuln.fixes          = remediations;
  vuln.has_fix        = vuln.fixed_versions.length > 0;
  vuln.description    = (vuln.description || vuln.details || vuln.summary || "").trim();
  delete vuln.details;
  delete vuln.summary;
}

async function getVulnById({ vulnerability_id, purl, dependency, affected_version }) {
  const res = await fetchJSON(`${OSV_VULN_BASE}/${vulnerability_id}`);
  if (res.status !== 200) return null;

  const data = res.body;
  processVulnerability(data);

  data.affected_purl              = purl;
  data.affected_dependency        = dependency;
  data.affected_dependency_version = affected_version;
  data.ecosystem                = getEcosystemFromPurl(purl);
  data.url                        = `https://osv.dev/vulnerability/${vulnerability_id}`;
  data.is_infection               = (data.id || "").startsWith("MAL-");

  getFix(data);

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
    if (infectedPurls.has(item.id))   item.state = "infected";
    else if (vulnerablePurls.has(item.id)) item.state = "vulnerable";
    else                               item.state = "safe";
  }
}

// ── Summary helpers ───────────────────────────────────────────────────────────
const SEV_ORDER = { infection: -1, critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function summarizeVulnerabilities(vulnerabilities,inventory) {
  const packages = {};

  for (const v of vulnerabilities) {
    const pkg      = v.affected_dependency;
    const version  = v.affected_dependency_version;
    const purl     = v.affected_purl || "";
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
const DEFAULT_POLICY = {
  infections: "block",
  severity: {
    critical: "block",
    high:     "block",
    medium:   "allow",
    low:      "allow",
    unknown:  "allow",
  },
  // kev and weaponized enrichment require an API key (paid tier)
  // and are intentionally excluded from the freemium default policy.
};

// ── Sentinel: thrown on a policy block so finally can revert before exit ─────
// main() catches this and exits with code 1 without printing an extra message.
export class PolicyViolationError extends Error {
  constructor(reason) {
    super(reason);
    this.name = "PolicyViolationError";
  }
}

function tag_vulnerabilities_with_policy_decisions(vulnerabilities, policy) {
  for (const v of vulnerabilities) {
    if (v.is_infection && policy.infections === "block") {
      v.policy_decision = "block";
    } else if (!v.is_infection) {
      const sev = (v.severity || "unknown").toLowerCase();
      v.policy_decision = policy.severity[sev] === "block" ? "block" : "allow";
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

// ── Engine class ──────────────────────────────────────────────────────────────
export class UbelEngine {
  static reportsLocation       = "./.ubel/local/reports";
  static policyDir             = "./.ubel/local/policy";
  static policyFilename        = "config.json";
  static checkMode             = "health";
  static systemType            = "npm";
  static engine                = "npm";
  static was_successful_scan = false;

  static vulns_ids_found= new Set();

  static initiateLocalPolicy() {
    fs.mkdirSync(UbelEngine.policyDir, { recursive: true });
    const file = path.join(UbelEngine.policyDir, UbelEngine.policyFilename);
    let needs = false;
    if (!fs.existsSync(file)) needs = true;
    else if (fs.statSync(file).size === 0) { fs.unlinkSync(file); needs = true; }
    if (needs) {
      fs.writeFileSync(file, JSON.stringify(DEFAULT_POLICY, null, 4));
    }
  }

  static loadPolicy() {
    UbelEngine.initiateLocalPolicy();
    const file = path.join(UbelEngine.policyDir, UbelEngine.policyFilename);
    return JSON.parse(fs.readFileSync(file, "utf-8"));
  }

  static setPolicyRules(action, severities) {
    const data = UbelEngine.loadPolicy();
    for (const rule of Object.keys(data.severity)) {
      if (severities.includes(rule)) data.severity[rule] = action;
    }
    const file = path.join(UbelEngine.policyDir, UbelEngine.policyFilename);
    fs.writeFileSync(file, JSON.stringify(data, null, 4));
  }

  static async scan(args, options = {is_script: false}) {
    const ecosystems = new Set();
    if (!options.is_script) {
      NodeManager._captureEngineVersion(UbelEngine.engine);
    }else{
      UbelEngine.engine=TOOL_NAME;
      NodeManager.engineVersion=TOOL_VERSION;
    }
    const now       = new Date();
    const pad       = (n) => String(n).padStart(2, "0");
    const timestamp = `${now.getUTCFullYear()}_${pad(now.getUTCMonth()+1)}_${pad(now.getUTCDate())}__`
                    + `${pad(now.getUTCHours())}_${pad(now.getUTCMinutes())}_${pad(now.getUTCSeconds())}`;
    const datePath  = `${now.getUTCFullYear()}/${pad(now.getUTCMonth()+1)}/${pad(now.getUTCDate())}`;

    const outputDir = path.join(
      UbelEngine.reportsLocation,
      UbelEngine.systemType,
      UbelEngine.checkMode,
      datePath
    );
    fs.mkdirSync(outputDir, { recursive: true });

    const baseName    = `${UbelEngine.systemType}_${UbelEngine.checkMode}_${UbelEngine.engine}__${timestamp}`;
    const jsonPath    = path.join(outputDir, `${baseName}.json`);

    const policy = UbelEngine.loadPolicy();
    let purls = [];
    let reportContent = null;
    // Tracks whether we entered a mode that mutated the lockfile on disk so
    // the finally block knows whether a revert is needed.
    const needsRevert =
      UbelEngine.checkMode === "check" || UbelEngine.checkMode === "install";

    try {
      // ── Collect packages ──────────────────────────────────────────────────
      if (needsRevert) {
        purls         = await NodeManager.runDryRun(UbelEngine.engine, args);
        for (const inventoryItem of NodeManager.inventoryData) {
          inventoryItem.paths =  [];
        }
        reportContent = NodeManager.currentLockFileContent;
        // Tell the user where the originals are in case anything goes wrong.
        if (NodeManager._lockfileBackupDir) {
          console.log(`[~] Original lockfiles backed up to: ${NodeManager._lockfileBackupDir}`);
          console.log();
        }
      } else {
        // health — scan installed packages
        NodeManager.inventoryData = [];
        purls = await NodeManager.getInstalled();
        reportContent = {};
      }

      // ── OSV query ─────────────────────────────────────────────────────────
      const vuln_ids = await submitToOsv(purls);
      const uniquePurls = [...new Set(purls)];
      let inventory = [...NodeManager.inventoryData];
      matchDependenciesWithInventory(inventory);

      // ── Enrich vulnerabilities concurrently ───────────────────────────────
      const vulnerabilities = [];
      const CONCURRENCY = 40;
      for (let i = 0; i < vuln_ids.length; i += CONCURRENCY) {
        const batch = vuln_ids.slice(i, i + CONCURRENCY);
        const results = await Promise.allSettled(batch.map(getVulnById));
        for (const r of results) {
          if (r.status === "fulfilled" && r.value) vulnerabilities.push(r.value);
          else if (r.status === "rejected")
            console.error("[!] Failed to fetch vulnerability:", r.reason?.message);
        }
      }

      tag_vulnerabilities_with_policy_decisions(vulnerabilities, policy);
      const policyViolations = get_policy_violations(vulnerabilities);

      for (const v of vulnerabilities) {
        v.is_policy_violation = v.policy_decision === "block";
      }

      // ── Stats ──────────────────────────────────────────────────────────────
      const severityBuckets = { critical:0, high:0, medium:0, low:0, unknown:0 };
      const infectedPurls   = new Set();
      const vulnerablePurls = new Set();
      let infectionCount    = 0;

      for (const v of vulnerabilities) {
        UbelEngine.vulns_ids_found.add(v.id);
        if (v.is_infection) {
          infectionCount++;
          infectedPurls.add(v.affected_purl);
        } else {
          const sev = ((v.severity || "unknown").toLowerCase()) in severityBuckets
            ? (v.severity || "unknown").toLowerCase()
            : "unknown";
          severityBuckets[sev]++;
          vulnerablePurls.add(v.affected_purl);
        }
      }

      setInventoryState(infectedPurls, vulnerablePurls, inventory);

      inventory = NodeManager.buildDependencySequences(inventory);

      inventory = NodeManager.buildIntroducedBy(inventory);

      // ── Second-pass scope propagation ─────────────────────────────────────
      // _assignScopes runs inside runDryRun against the lockfile dep graph,
      // but pnpm's lockfile often omits dependencies for packages that have
      // no explicit dep block in the snapshots section (peer-only, platform
      // optionals, etc.).  This leaves BFS blind past those nodes, so only
      // direct deps get scoped.
      //
      // Fix: now that introduced_by is populated (a reliable reverse-edge map
      // built from the actual inventory), propagate scopes forward through
      // comp.dependencies using a BFS over the inventory itself.  This is
      // engine-agnostic and requires no lockfile parsing.
      {
        const byId = new Map(inventory.map(c => [c.id, c]));
        // Seed the queue with every already-scoped package (direct deps tagged
        // by the first-pass _assignScopes).
        const queue = inventory.filter(c =>
          Array.isArray(c.scopes) && c.scopes.some(s => s !== 'env')
        );
        const visited = new Set(queue.map(c => c.id));

        while (queue.length) {
          const comp = queue.shift();
          for (const depPurl of (comp.dependencies || [])) {
            const dep = byId.get(depPurl);
            if (!dep) continue;
            ecosystems.add(dep.ecosystem);
            // Propagate all non-env scopes from parent to child.
            let changed = false;
            for (const s of comp.scopes) {
              if (s === 'env') continue;
              if (!dep.scopes.includes(s)) { dep.scopes.push(s); changed = true; }
            }
            if (!visited.has(dep.id)) {
              visited.add(dep.id);
              queue.push(dep);
            }
          }
        }
      }

      const stats = {
        inventory_size: inventory.length,
        inventory_stats: {
          infected:   infectedPurls.size,
          vulnerable: vulnerablePurls.size,
          safe:       Math.max(0, inventory.length - infectedPurls.size - vulnerablePurls.size),
        },
        total_vulnerabilities: vulnerabilities.length,
        vulnerabilities_stats: { severity: severityBuckets },
        total_infections: infectionCount,
      };

      const runtime = {
        environment: "node",
        version: process.version.replace(/^v/, "").replace(/^V/, ""),
        platform: process.platform,
        arch: process.arch,
        cwd: process.cwd(),
        execPath: process.execPath,
      };

      const engine_info ={
        name: UbelEngine.engine,
        version: NodeManager.engineVersion,
      }

      const git_metadata = getGitMetadata();
      const isEmpty = (git_metadata)=> Object.keys(git_metadata).length === 0;
      if (isEmpty) {
        git_metadata.available = false;
        git_metadata.reason = "not_a_git_repository";
      }else{
        git_metadata.available = true;
      }

      // ── Build final JSON ───────────────────────────────────────────────────
      const findingsSummary = summarizeVulnerabilities(vulnerabilities, inventory);
      for (const item of inventory) {
        if (item.dependency_sequences) {
          delete item.dependency_sequences;
        }
      }
      const finalJson = {
        generated_at: now.toISOString().replace("Z","") + "Z",
        runtime,
        engine: engine_info,
        os_metadata: getOSMetadata(),
        git_metadata: git_metadata,
        tool_info:    { name: TOOL_NAME, version: VERSION },
        scan_info:    { type: UbelEngine.checkMode, ecosystems: Array.from(ecosystems), engine: UbelEngine.engine },
        stats,
        vulnerabilities_ids: Array.from(UbelEngine.vulns_ids_found),
        findings_summary: findingsSummary,
        vulnerabilities:  sortVulnerabilities(vulnerabilities),
        inventory,
        policy,
        dependencies_tree: NodeManager.buildDependencyTree(inventory),
      };

      const [allowed, reason] = evaluatePolicy(finalJson);
      finalJson.decision = { allowed, reason, policy_violations: policyViolations };

      const htmlReport = generateHTMLReport(finalJson);
      const htmlPath = jsonPath.replace(/\.json$/, ".html");
      fs.writeFileSync(htmlPath, htmlReport);

      fs.writeFileSync(jsonPath, JSON.stringify(finalJson, null, 2));

      // ── Console output ─────────────────────────────────────────────────────
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

      // ── Findings summary — one block per affected package ─────────────────
      const summaryEntries = Object.values(findingsSummary);
      if (summaryEntries.length > 0) {
        console.log("Findings Summary:");
        console.log();
        for (const pkg of summaryEntries) {
          const s = pkg.stats;
          const counts = [];
          if (s.infection) counts.push(`${s.infection} infection(s)`);
          if (s.critical)  counts.push(`${s.critical} critical`);
          if (s.high)      counts.push(`${s.high} high`);
          if (s.medium)    counts.push(`${s.medium} medium`);
          if (s.low)       counts.push(`${s.low} low`);
          if (s.unknown)   counts.push(`${s.unknown} unknown`);

          console.log(`  ${pkg.name}@${pkg.version}  [${counts.join(", ")}]`);

          for (const vuln of pkg.vulnerabilities) {
            const label = vuln.is_infection ? "INFECTION" : vuln.severity.toUpperCase();
            const score = vuln.severity_score != null ? ` (${vuln.severity_score})` : "";
            console.log(`    \u2022 ${vuln.id}  ${label}${score}`);
            for (const fix of (vuln.fixes || [])) {
              console.log(`      fix: ${fix}`);
            }
          }
          console.log();
        }
      }

      console.log(`Policy Decision: ${allowed ? "ALLOW" : "BLOCK"}`);
      console.log();
      console.log();
      /* console.log(`JSON report saved to: ${jsonPath}`);
      console.log();
      console.log(); */

      // ── latest.json — always points to the most recent scan ───────────────
      const latestDir  = path.join(".ubel", "reports");
      const latestPath = path.join(latestDir, "latest.json");
      fs.mkdirSync(latestDir, { recursive: true });
      const lateshtmlpath=latestPath.replace(/\.json$/, ".html");
      fs.writeFileSync(lateshtmlpath, htmlReport);
      fs.writeFileSync(latestPath, JSON.stringify(finalJson, null, 2));
      console.log(`Latest JSON report saved to: ${latestPath}`);
      console.log(`Latest HTML report saved to: ${lateshtmlpath}`);
      console.log();
      console.log();

      if (!allowed) {
        // Throw so the finally block runs and reverts the lockfile before we exit.
        // main() catches PolicyViolationError and exits with code 1 silently
        // (the messages below have already been printed).
        console.error("[!] Policy violation detected!");
        console.log(`[!] ${reason}`);
        throw new PolicyViolationError(reason);
      }

      if (UbelEngine.checkMode === "health") {
        process.exit(0);
      }
      if (UbelEngine.checkMode === "check") {
        // check succeeded — finally will not revert (was_successful_scan=true),
        // so we explicitly restore originals and clean up the backup here.
        NodeManager.was_successful_scan = true;
        NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
        NodeManager.cleanupLockfileBackup();
        console.log("[+] Backup lockfiles removed.");
        process.exit(0);
      }

      console.log("[+] Policy passed. Installing dependencies...");
      NodeManager.was_successful_scan = true;

      const saveResult = NodeManager.saveCandidateLockfile(UbelEngine.engine, process.cwd())
      if (!saveResult.written) {
        console.error("[!] Could not write candidate lockfile:", saveResult.reason);
        process.exit(1);
      }

      const installResult = NodeManager.runRealInstall(UbelEngine.engine);
      if (installResult.status !== 0) {
        console.error(`[!] npm ci failed (exit ${installResult.status}) — dependencies were NOT installed.`);
        // Restore originals so the project is left in a consistent state.
        NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
        process.exit(1);
      }

      /* console.log("[+] Verifying installed dependency graph...");

      // Reset inventory before re-scan so we get a clean actual state.
      NodeManager.inventoryData = [];

      const installedPurls = await NodeManager.getInstalled();

      const verification = NodeManager.compareGraphs(purls, installedPurls);

      if (!verification.match) {
        console.error("[!] Dependency graph mismatch detected after install!");

        if (verification.missing.length) {
          console.error("[!] Missing packages (expected but not installed):");
          for (const p of verification.missing) console.error("  -", p);
        }

        if (verification.extra.length) {
          console.error("[!] Unexpected packages (installed but not scanned):");
          for (const p of verification.extra) console.error("  -", p);
        }

        // Keep the backup — user may need it to recover manually.
        if (NodeManager._lockfileBackupDir) {
          console.error(`[~] Original lockfiles preserved at: ${NodeManager._lockfileBackupDir}`);
        }

        console.error("[!] Blocking due to non-deterministic install (possible PM drift or tampering)");
        process.exit(1);
      }

      console.log("[+] Dependency graph verified: no drift detected."); */

      // Everything succeeded — safe to remove the disk backup now.
      NodeManager.cleanupLockfileBackup();
      console.log("[+] Backup lockfiles removed.");

    } finally {
      // Always restore the lockfile and package.json if a dry-run mutated them,
      // regardless of whether the scan succeeded, was blocked, or threw.
      if (!NodeManager.was_successful_scan && needsRevert) {
        const revertResult = NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
        if (!revertResult.reverted) {
          console.error("[!] Failed to restore original lockfiles:", revertResult.reason);
          if (revertResult.backupDir) {
            console.error(`[~] Originals are preserved at: ${revertResult.backupDir}`);
            console.error("[~] Restore them manually if needed.");
          }
        } else {
          NodeManager.cleanupLockfileBackup();
          console.log("[+] Backup lockfiles removed.");
        }
      }
    }
  }
}