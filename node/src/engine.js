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
import {getGitMetadata, getvscodeversion}         from "./git_info.js";
import {filterFalsePositiveInfections} from "./filter_false_positive_infections.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));

// ── buildParents — injected here so node_runner.js needs no edits ─────────────
// Populates comp.parents: the list of packages that directly depend on this
// node (one-hop reverse of comp.dependencies). Distinct from introduced_by,
// which tracks root ancestors only.
NodeManager.buildParents = function buildParents(inventory) {
  const parents = new Map(inventory.map(c => [c.id, []]));
  for (const comp of inventory) {
    for (const depId of (comp.dependencies || [])) {
      if (parents.has(depId)) {
        parents.get(depId).push(comp.id);
      }
    }
  }
  for (const comp of inventory) {
    comp.parents = (parents.get(comp.id) || []).sort();
  }
  return inventory;
};

const OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch";
const OSV_VULN_BASE  = "https://api.osv.dev/v1/vulns";

// ── Network metadata helpers ──────────────────────────────────────────────────

// Synchronous version using the already-imported `os` module via dynamic import
// isn't available at module level — we use Node's built-in synchronously:
import os_module from "os";

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

    // The complete client-side script
    const clientScript = `
        // --- DATA ---
        const reportData = ${safeJson};

        // ── Dependency Graph (force-directed, shows only impact chains) ────────────────
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

            // ---------- Build full graph (all nodes & edges) ----------
            const fullNodeMap = {};
            const allEdges = [];

            const getOrCreate = (id) => {
                if (!fullNodeMap[id]) {
                    const inv = reportData.inventory.find(x => x.id === id);
                    fullNodeMap[id] = {
                        id,
                        label: inv ? inv.name + '@' + inv.version : id.split('/').pop(),
                        fullLabel: id,
                        state: inv ? (inv.state || 'unknown') : 'unknown',
                        x: 0, y: 0, vx: 0, vy: 0,
                        fx: null, fy: null,
                        radius: 0,
                    };
                }
                return fullNodeMap[id];
            };

            const walk = (nodeId, children) => {
                getOrCreate(nodeId);
                for (const [childId, grandChildren] of Object.entries(children || {})) {
                    getOrCreate(childId);
                    allEdges.push({ source: nodeId, target: childId });
                    walk(childId, grandChildren);
                }
            };

            for (const [rootId, children] of Object.entries(tree)) {
                walk(rootId, children);
            }

            const allNodes = Object.values(fullNodeMap);
            // Deduplicate edges
            const edgeSet = new Set();
            const allUniqueEdges = allEdges.filter(e => {
                const key = e.source + '||' + e.target;
                if (edgeSet.has(key)) return false;
                edgeSet.add(key);
                return true;
            });

            // Build reverse adjacency: for each node, which nodes depend on it (incoming edges)
            const reverseAdj = new Map(); // id -> Set of ids that depend on it
            for (const n of allNodes) reverseAdj.set(n.id, new Set());
            for (const e of allUniqueEdges) {
                // e.source depends on e.target
                reverseAdj.get(e.target).add(e.source);
            }

            // Node sizing (based on out‑degree in full graph)
            const childCount = {};
            for (const e of allUniqueEdges) {
                childCount[e.source] = (childCount[e.source] || 0) + 1;
            }
            for (const n of allNodes) {
                const c = childCount[n.id] || 0;
                n.radius = c > 10 ? 18 : c > 4 ? 14 : c > 1 ? 11 : 8;
            }

            // ----- FILTER LOGIC: ancestors (dependents) of vulnerable/infected nodes -----
            let currentFilter = 'all';   // 'all', 'vulnerable', 'infected'
            let visibleNodeIds = new Set();
            let visibleEdges = [];

            function computeVisibleNodesAndEdges() {
                if (currentFilter === 'all') {
                    visibleNodeIds.clear();
                    for (const n of allNodes) visibleNodeIds.add(n.id);
                    visibleEdges = [...allUniqueEdges];
                    return;
                }

                const targetStates = currentFilter === 'vulnerable' ? new Set(['vulnerable']) : new Set(['infected']);
                // Seeds: all nodes that match the target state
                const seeds = allNodes.filter(n => targetStates.has(n.state)).map(n => n.id);
                if (seeds.length === 0) {
                    visibleNodeIds.clear();
                    visibleEdges = [];
                    return;
                }

                // BFS on reverse graph to collect all ancestors (nodes that depend on the seeds)
                const keep = new Set(seeds);
                const queue = [...seeds];
                while (queue.length) {
                    const id = queue.shift();
                    for (const depender of reverseAdj.get(id) || []) {
                        if (!keep.has(depender)) {
                            keep.add(depender);
                            queue.push(depender);
                        }
                    }
                }

                visibleNodeIds = keep;
                // Keep only edges where both ends are in the set
                visibleEdges = allUniqueEdges.filter(e => visibleNodeIds.has(e.source) && visibleNodeIds.has(e.target));
            }

            // Create a working set of nodes (subset of allNodes) and edges from visibleNodeIds
            function getCurrentNodesAndEdges() {
                const nodes = allNodes.filter(n => visibleNodeIds.has(n.id));
                return { nodes, edges: visibleEdges };
            }

            // ---- Force simulation state for the current visible graph ----
            let simTick = 0;
            const MAX_SIM = 300;
            const SIM_COOLDOWN = 0.92;
            let simRunning = true;
            let animId = null;

            let visibleNodes = [];
            let visibleEdgesList = [];
            let nodeMap = new Map(); // id -> node object reference

            // Rebuild simulation after filter change
            function rebuildFromFilter() {
                computeVisibleNodesAndEdges();
                const { nodes, edges } = getCurrentNodesAndEdges();
                visibleNodes = nodes;
                visibleEdgesList = edges;
                nodeMap.clear();
                for (const n of visibleNodes) nodeMap.set(n.id, n);

                // Reset forces
                for (const n of visibleNodes) {
                    n.vx = 0; n.vy = 0;
                    if (n.fx !== null) { n.fx = n.x; n.fy = n.y; }
                }
                simRunning = true;
                simTick = 0;
            }

            // Initial build (all nodes)
            currentFilter = 'vulnerable';
            rebuildFromFilter();

            // ---- Helper: initial positions (circular layout) ----
            function setInitialPositions() {
                const cx = 0, cy = 0, R = Math.max(150, visibleNodes.length * 9);
                visibleNodes.forEach((n, i) => {
                    const angle = (2 * Math.PI * i) / visibleNodes.length;
                    n.x = cx + R * Math.cos(angle) + (Math.random() - 0.5) * 40;
                    n.y = cy + R * Math.sin(angle) + (Math.random() - 0.5) * 40;
                });
            }
            setInitialPositions();

            // ---- Force simulation (works on visibleNodes & visibleEdgesList) ----
            const simulate = () => {
                if (!simRunning) return;
                if (visibleNodes.length === 0) return;

                // Repulsion
                for (let i = 0; i < visibleNodes.length; i++) {
                    for (let j = i + 1; j < visibleNodes.length; j++) {
                        const a = visibleNodes[i], b = visibleNodes[j];
                        const dx = b.x - a.x, dy = b.y - a.y;
                        const dist = Math.sqrt(dx*dx + dy*dy) || 0.01;
                        const force = Math.min(8000 / (dist * dist), 60);
                        const fx = (dx / dist) * force, fy = (dy / dist) * force;
                        a.vx -= fx; a.vy -= fy;
                        b.vx += fx; b.vy += fy;
                    }
                }

                // Spring (edges)
                for (const e of visibleEdgesList) {
                    const a = nodeMap.get(e.source);
                    const b = nodeMap.get(e.target);
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
                for (const n of visibleNodes) {
                    n.vx += -n.x * 0.004;
                    n.vy += -n.y * 0.004;
                }

                // Integrate + dampen
                for (const n of visibleNodes) {
                    if (n.fx !== null) { n.x = n.fx; n.y = n.fy; n.vx = 0; n.vy = 0; continue; }
                    n.vx *= SIM_COOLDOWN; n.vy *= SIM_COOLDOWN;
                    n.x += n.vx; n.y += n.vy;
                }

                simTick++;
                if (simTick > MAX_SIM) simRunning = false;
            };

            // ---- Viewport & interaction variables ----
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

            // ---- Render (only visible nodes & edges) ----
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
                for (const e of visibleEdgesList) {
                    const a = nodeMap.get(e.source), b = nodeMap.get(e.target);
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
                for (const n of visibleNodes) {
                    const c = stateColor(n.state);
                    const isHl = n.id === highlightId;
                    const isMatch = searchMatches.has(n.id);
                    const dimmed = (highlightId && !isHl) || (searchMatches.size > 0 && !isMatch && !isHl);

                    ctx.globalAlpha = dimmed ? 0.15 : 1;

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

                    const showLabel = scale > 0.7 || isHl || isMatch;
                    if (showLabel) {
                        ctx.globalAlpha = dimmed ? 0.15 : isHl ? 1 : 0.85;
                        ctx.fillStyle = '#e5e5e5';
                        ctx.font = \`\${isHl ? 'bold ' : ''}\${Math.max(9, Math.min(11, n.radius * 0.9))}px JetBrains Mono, monospace\`;
                        ctx.textAlign = 'center';
                        ctx.textBaseline = 'middle';
                        const labelY = n.y + n.radius + 9;
                        ctx.fillStyle = 'rgba(0,0,0,0.8)';
                        ctx.fillText(n.label, n.x + 0.5, labelY + 0.5);
                        ctx.fillStyle = isHl ? '#ffffff' : '#d4d4d4';
                        ctx.fillText(n.label, n.x, labelY);
                    }
                }

                ctx.globalAlpha = 1;
                ctx.restore();
            };

            const loop = () => {
                simulate();
                render();
                animId = requestAnimationFrame(loop);
            };
            loop();

            // ---- Interaction helpers (unchanged) ----
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
                for (const n of visibleNodes) {
                    const d = Math.sqrt((wx - n.x) ** 2 + (wy - n.y) ** 2);
                    if (d < n.radius + 4 && d < bestDist) { best = n; bestDist = d; }
                }
                return best;
            };

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

            canvas.addEventListener('mouseup', () => {
                if (dragging) { dragging.fx = null; dragging = null; }
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

            // Touch & zoom
            let lastTouchDist = null;
            canvas.addEventListener('touchstart', (e) => {
                if (e.touches.length === 2) {
                    lastTouchDist = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
                }
            }, { passive: true });
            canvas.addEventListener('touchmove', (e) => {
                if (e.touches.length === 2) {
                    const d = Math.hypot(e.touches[0].clientX - e.touches[1].clientX, e.touches[0].clientY - e.touches[1].clientY);
                    if (lastTouchDist) scale = Math.max(0.1, Math.min(5, scale * (d / lastTouchDist)));
                    lastTouchDist = d;
                    e.preventDefault();
                }
            }, { passive: false });
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
                    for (const n of visibleNodes) {
                        if (n.id.toLowerCase().includes(q) || n.label.toLowerCase().includes(q)) {
                            searchMatches.add(n.id);
                        }
                    }
                }
                simRunning = true; simTick = Math.max(0, MAX_SIM - 60);
            });

            // ---- FILTER DROPDOWN handler ----
            const filterSelect = document.getElementById('graph-filter');
            if (filterSelect) {
                filterSelect.addEventListener('change', (e) => {
                    currentFilter = e.target.value;
                    rebuildFromFilter();
                    setInitialPositions();
                    simRunning = true;
                    simTick = 0;
                    highlightId = null;
                    searchMatches.clear();
                    if (document.getElementById('graph-search')) document.getElementById('graph-search').value = '';
                });
            }

            graphState = {
                reset: () => {
                    scale = 1; panX = 0; panY = 0;
                    for (const n of visibleNodes) { n.fx = null; n.fy = null; }
                    simRunning = true; simTick = 0;
                },
                stop: () => { if (animId) cancelAnimationFrame(animId); },
            };
        }

        function graphZoom(delta) {
            if (!graphState) return;
            const canvas = document.getElementById('dep-graph-canvas');
            if (!canvas) return;
            // We'll handle zoom via the existing wheel event – the buttons are just for convenience.
            // Simulate a small wheel delta
            const event = new WheelEvent('wheel', { deltaY: delta > 0 ? -30 : 30 });
            canvas.dispatchEvent(event);
        }

        function graphReset() {
            if (graphState) graphState.reset();
        }

        // --- CORE LOGIC (existing - unchanged except for graph init) ---
        function init() {
            if (reportData.inventory.length < reportData.stats.inventory_size) {
                const currentCount = reportData.inventory.length;
                const needed = reportData.stats.inventory_size - currentCount;
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
                    <td class="px-6 py-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${v.severity}">\${v.severity}</span></td>
                    <td class="px-6 py-4 font-medium">\${v.affected_dependency} ( \${v.ecosystem} )</td>
                    <td class="px-6 py-4 mono text-xs text-neutral-400">\${v.affected_dependency_version}</td>
                    <td class="px-6 py-4">\${v.has_fix ? '<span class="text-green-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"></polyline></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4">\${v.is_policy_violation ? '<span class="text-red-400 flex items-center gap-1"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg> Yes</span>' : '<span class="text-neutral-500">No</span>'}</td>
                    <td class="px-6 py-4 text-neutral-400 text-xs">\${v.fixed_versions.join('<br>')}</td>
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
                    \${v.fixes.length > 0 ? \`<div><h4 class="text-sm font-semibold mb-2 text-green-400">Recommended Fixes</h4><ul class="space-y-2">\${v.fixes.map(f => \`<li class="text-xs bg-green-500/10 border border-green-500/20 p-3 rounded-lg text-green-300 mono">\${f}</li>\`).join('')}</ul></div>\` : ''}
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">References</h4><div class="flex flex-wrap gap-2">\${v.references.map(r => \`<a href="\${r.url}" target="_blank" class="text-[10px] bg-neutral-800 hover:bg-neutral-700 border border-neutral-700 px-3 py-1.5 rounded transition-colors text-neutral-400 hover:text-white">\${r.type}</a>\`).join('')}</div></div>
                    <div><h4 class="text-sm font-semibold mb-2 text-neutral-300">Description</h4><div class="text-sm text-neutral-400 leading-relaxed bg-neutral-900/50 p-4 rounded-lg border border-neutral-800 whitespace-pre-wrap">\${v.description}</div></div>
                </div>
            \`;

            document.getElementById('modal-overlay').style.display = 'flex';
            document.body.style.overflow = 'hidden';
        }

        function closeModal() {
            document.getElementById('modal-overlay').style.display = 'none';
            document.body.style.overflow = 'auto';
        }

        window.addEventListener('keydown', (e) => { if (e.key === 'Escape') closeModal(); });
        document.getElementById('modal-overlay').addEventListener('click', (e) => { if (e.target.id === 'modal-overlay') closeModal(); });

        init();
    `;

    // HTML output (same as before, with the filter dropdown already present)
    return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Ubel Security Scan Report</title>
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
        #graph-tooltip { position: fixed; background: rgba(20,20,20,0.95); border: 1px solid #404040; border-radius: 8px; padding: 8px 12px; font-size: 11px; font-family: 'JetBrains Mono', monospace; color: #e5e5e5; pointer-events: none; max-width: 280px; z-index: 100; line-height: 1.6; white-space: pre-wrap; word-break: break-all; display: none; }
    </style>
</head>
<body class="min-h-screen flex flex-col">
    <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
        <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
            <div class="flex items-center gap-3"><div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white">U</div><div><h1 class="text-lg font-semibold tracking-tight">Security Scan Report</h1><p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p></div></div>
            <div id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider">Status: Loading...</div>
        </div>
    </header>
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
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Vulnerability Findings</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="vuln-search" placeholder="Search ID or package..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64"><select id="vuln-filter-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All Severities</option><option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option><option value="unknown">Unknown</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">ID</th><th>Severity</th><th>Package</th><th>Version</th><th>Fix Available</th><th>Policy Violation</th><th>Fixed Versions</th><th class="text-right">Action</th></tr></thead><tbody id="vuln-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Inventory Section -->
        <section id="section-inventory" class="hidden space-y-6">
            <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Package Inventory</h2><div class="flex gap-2 w-full md:w-auto"><input type="text" id="inv-search" placeholder="Search packages..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-blue-500 w-full md:w-64"><select id="inv-filter-state" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All States</option><option value="safe">Safe</option><option value="vulnerable">Vulnerable</option><option value="infected">Infected</option><option value="undetermined">Undetermined</option></select></div></div>
            <div class="glass rounded-xl overflow-hidden"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th>Name</th><th>Version</th><th>State</th><th>Policy Violation</th><th>Ecosystem</th><th>License</th><th>Scopes</th></tr></thead><tbody id="inv-table-body" class="divide-y divide-neutral-800"></tbody></table></div>
        </section>
        <!-- Dependency Graph Section with filter dropdown -->
        <section id="section-graph" class="hidden space-y-4" style="height: calc(100vh - 220px); min-height: 500px;">
            <div class="flex flex-col md:flex-row gap-3 justify-between items-start md:items-center">
                <h2 class="text-xl font-bold">Dependency Graph</h2>
                <div class="flex gap-2 w-full md:w-auto items-center flex-wrap">
                    <input type="text" id="graph-search" placeholder="Search by package ID..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-72">
                    <select id="graph-filter" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none">
                        <option value="all">All graphs</option>
                        <option value="vulnerable" selected>Vulnerable graphs</option>
                        <option value="infected">Infected graphs</option>
                    </select>
                    <button onclick="graphZoom(0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">＋</button>
                    <button onclick="graphZoom(-0.2)" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">－</button>
                    <button onclick="graphReset()" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm hover:bg-neutral-700">Reset</button>
                    <div class="flex items-center gap-3 text-[10px] mono text-neutral-500">
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-green-500"></span>safe</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-yellow-500"></span>vulnerable</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-red-500"></span>infected</span>
                        <span class="flex items-center gap-1"><span class="inline-block w-2.5 h-2.5 rounded-full bg-neutral-500"></span>unknown</span>
                    </div>
                </div>
            </div>
            <div class="glass rounded-xl overflow-hidden relative" style="height: calc(100% - 56px);">
                <canvas id="dep-graph-canvas" style="width:100%;height:100%;cursor:grab;display:block;"></canvas>
                <div id="graph-tooltip" style="display:none;position:absolute;background:rgba(20,20,20,0.95);border:1px solid #404040;border-radius:8px;padding:8px 12px;font-size:11px;font-family:'JetBrains Mono',monospace;color:#e5e5e5;pointer-events:none;max-width:280px;z-index:10;line-height:1.6;white-space:pre-wrap;"></div>
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
 * @param {string} cpe       - The CPE string used to query NVD (used as affected_purl)
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

  return {
    id:           cveId,
    published:    cveData.published    || "",
    modified:     cveData.lastModified || "",
    summary:      desc.slice(0, 200),
    details:      desc,
    severity:     scoreToSeverity(cvss.score),
    severity_score: cvss.score,
    severity_vector: cvss.vector,
    references:   refs,
    affected,

    // pipeline fields populated later by getFix / processVulnerability
    affected_purl:               cpe,
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
    if (item.version !== ""){
    if (infectedPurls.has(item.id))   item.state = "infected";
    else if (vulnerablePurls.has(item.id)) item.state = "vulnerable";
    else                               item.state = "safe";
  }
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
    // Infections are always blocked — no policy toggle.
    if (v.is_infection) {
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

// ── Engine class ──────────────────────────────────────────────────────────────
export class UbelEngine {

  static reportsLocation       = "./.ubel/local/reports";
  static policyDir             = "./.ubel/local/policy";
  static policyFilename        = "config.json";
  static checkMode             = "health";
  static systemType            = "npm";
  static engine                = "npm";
  static was_successful_scan = false;

  static runtime_environment = "node"
  static runtime_version = process.version.replace(/^v/, "").replace(/^V/, "");

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

  /**
   * Set a single top-level policy field and persist it to disk.
   * Replaces the old setPolicyRules(action, severities) API.
   *
   * @param {"severity_threshold"|"block_unknown_vulnerabilities"} key
   * @param {string|boolean} value
   */
  static setPolicyField(key, value) {
    const data = UbelEngine.loadPolicy();
    data[key] = value;
    const file = path.join(UbelEngine.policyDir, UbelEngine.policyFilename);
    fs.writeFileSync(file, JSON.stringify(data, null, 4));
  }

  static async scan(args, options = {current_dir: process.cwd(), is_script: false, save_reports: true, scan_os: false, full_stack: false, is_vscanned_project: false, scan_node:true, scan_scope: "repository" }) {
    const os_metadata_info = await getOSMetadata();
    const getinstalledoptions = {
      full_stack: options.full_stack,
      scan_os: options.scan_os ?? options.os_scan,
      scan_node: options.scan_node ?? true,
    }
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
          if (options.is_script==false){
          console.log(`[~] Original lockfiles backed up to: ${NodeManager._lockfileBackupDir}`);
          console.log();
          }
        }
      } else {
        // health — scan installed packages
        NodeManager.inventoryData = [];
        purls = await NodeManager.getInstalled(options.current_dir,getinstalledoptions);
        NodeManager.inventoryData.push(
          {
                id: `pkg:npm/${TOOL_NAME}@${TOOL_VERSION}`,
                name: TOOL_NAME,
                version: TOOL_VERSION,
                license: TOOL_LICENSE,
                ecosystem: "npm",
                state: "undetermined",
                scopes: ["env", "prod", "dev"],
                dependencies: [],
                type: "library",
                paths: [],
              }
        )
        reportContent = {};
      }

      for (const purl of purls) {
        if (purl.split('@')[1] === "") {
          purls = purls.filter(p => p !== purl);
        }
      }
      purls = [...new Set(purls)]; 
      let inventory = [...NodeManager.inventoryData];
      // ── OSV query ─────────────────────────────────────────────────────────
      const vuln_ids = await submitToOsv(purls);
      matchDependenciesWithInventory(inventory);

      // ── Enrich vulnerabilities concurrently ───────────────────────────────
      let vulnerabilities = [];
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

      // ── NVD query for CPE-based inventory items (host scanner) ────────────
      const nvdVulns = await submitToNvd(inventory);
      if (nvdVulns.length) {
        // Apply processVulnerability + getFix to each NVD result so the
        // severity/score fields go through the same normalisation pipeline.
        for (const v of nvdVulns) {
          // Stash the CVSS fields extracted directly from NVD metrics before
          // processVulnerability runs: that function reads the OSV severity[]
          // array, which NVD records don't carry, so it would overwrite these
          // with null/undefined.  We restore them afterward if it did.
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
        // Deduplicate: if OSV already found the same CVE for the same purl, skip.
        const osvKeys = new Set(vulnerabilities.map(v => `${v.id}::${v.affected_purl}`));
        for (const v of nvdVulns) {
          if (!osvKeys.has(`${v.id}::${v.affected_purl}`)) {
            vulnerabilities.push(v);
          }
        }
      }

      inventory = NodeManager.buildDependencySequences(inventory);

      inventory = NodeManager.buildIntroducedBy(inventory);
      inventory = NodeManager.buildParents(inventory);

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

      // ── Network metadata ──────────────────────────────────────────────────
      // Collect local IPs synchronously; fetch external IP asynchronously.
      // Both are stored on os_metadata for traceability across hosts.
      const localIPs      = getLocalIPsSync();
      const externalIP    = await getExternalIP();
      const primaryLocalIP = Object.values(localIPs)[0] || "";

      // ── Convert all path strings → SystemPath objects ─────────────────────
      normalizeInventoryPaths(inventory, primaryLocalIP);

      [vulnerabilities, inventory] = filterFalsePositiveInfections(inventory, vulnerabilities);

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

      const undeterminedCount = inventory.filter(c => c.version === "").length;
      if (undeterminedCount > 0) {
        console.warn(`[!] Warning: ${undeterminedCount} vulnerable package(s) with undetermined versions were detected. This may lead to false positives or negatives in the report. Please ensure all dependencies have resolvable versions for accurate scanning.`);
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
        inventoryItem.is_policy_violation = vulnerabilities.some(v => v.affected_purl === inventoryItem.id && v.policy_decision === "block");
      }

      const stats = {
        inventory_size: inventory.length,
        inventory_stats: {
          infected:   infectedPurls.size,
          vulnerable: vulnerablePurls.size,
          safe:       Math.max(0, inventory.length - infectedPurls.size - vulnerablePurls.size - undeterminedCount),
          undetermined: undeterminedCount
        },
        total_vulnerabilities: vulnerabilities.length,
        vulnerabilities_stats: { severity: severityBuckets },
        total_infections: infectionCount,
      };

      const runtime = {
        environment: UbelEngine.runtime_environment,
        version: UbelEngine.runtime_version,
        platform: process.platform,
        arch: process.arch,
        cwd: process.cwd(),
      };

      const engine_info ={
        name: UbelEngine.engine,
        version: NodeManager.engineVersion,
      }

      const git_metadata = getGitMetadata();

      // ── Build final JSON ───────────────────────────────────────────────────
      const findingsSummary = summarizeVulnerabilities(vulnerabilities, inventory);
      for (const item of inventory) {
        if (item.dependency_sequences) {
          delete item.dependency_sequences;
        }
      }
      if (UbelEngine.checkMode === "health") {
        UbelEngine.engine = TOOL_NAME;
      }

      if (options.is_vscanned_project) {
        engine_info.name    = "vscode";
        engine_info.version = getvscodeversion();
        // runtime was built before VS Code was detected — patch it now so the
        // report reflects the host editor, not the embedded Node runtime.
        runtime.environment = "vscode";
        runtime.version     = getvscodeversion();
      }
      const finalJson = {
        generated_at: now.toISOString().replace("Z","") + "Z",
        runtime,
        engine: engine_info,
        os_metadata: { ...os_metadata_info, local_ips: localIPs, external_ip: externalIP || null },
        git_metadata: git_metadata,
        tool_info:    { name: TOOL_NAME, version: TOOL_VERSION, license: TOOL_LICENSE },
        scan_info:    { type: UbelEngine.checkMode, ecosystems: Array.from(ecosystems), engine: UbelEngine.engine, scan_scope: options.scan_scope ?? "repository" },
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

      if (options.is_script==true&& options.save_reports === false) {
        return finalJson;
      }

      const htmlReport = generateHTMLReport(finalJson);
      const htmlPath = jsonPath.replace(/\.json$/, ".html");
      fs.writeFileSync(htmlPath, htmlReport);

      fs.writeFileSync(jsonPath, JSON.stringify(finalJson, null, 2));
      if (options.is_script==false){
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
      }

      // ── Findings summary — one block per affected package ─────────────────
      const summaryEntries = Object.values(findingsSummary);
      if (summaryEntries.length > 0) {
        if (options.is_script==false){
        console.log("Findings Summary:");
        console.log();
          }
        for (const pkg of summaryEntries) {
          const s = pkg.stats;
          const counts = [];
          if (s.infection) counts.push(`${s.infection} infection(s)`);
          if (s.critical)  counts.push(`${s.critical} critical`);
          if (s.high)      counts.push(`${s.high} high`);
          if (s.medium)    counts.push(`${s.medium} medium`);
          if (s.low)       counts.push(`${s.low} low`);
          if (s.unknown)   counts.push(`${s.unknown} unknown`);


          if (options.is_script==false){
          console.log(`  ${pkg.name}@${pkg.version}  [${counts.join(", ")}]`);
            }

          for (const vuln of pkg.vulnerabilities) {
            const label = vuln.is_infection ? "INFECTION" : vuln.severity.toUpperCase();
            const score = vuln.severity_score != null ? ` (${vuln.severity_score})` : "";
            if (options.is_script==false){

            console.log(`    \u2022 ${vuln.id}  ${label}${score}`);
            for (const fix of (vuln.fixes || [])) {

              console.log(`      fix: ${fix}`);
            }
          }
          }
          if (options.is_script==false){
          console.log();
          }
        }
      }
      if (options.is_script==false){
      console.log(`Policy Decision: ${allowed ? "ALLOW" : "BLOCK"}`);
      console.log();
      console.log();
      }
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
      if (options.is_script==false){
      console.log(`Latest JSON report saved to: ${latestPath}`);
      console.log(`Latest HTML report saved to: ${lateshtmlpath}`);
      console.log();
      console.log();
      }

      if (!allowed) {
        // Throw so the finally block runs and reverts the lockfile before we exit.
        // main() catches PolicyViolationError and exits with code 1 silently
        // (the messages below have already been printed).
        if (options.is_script==false){
        console.error("[!] Policy violation detected!");
        console.log(`[!] ${reason}`);
        }
        throw new PolicyViolationError(reason);
      }

      if (UbelEngine.checkMode === "health" && !options.is_script) {
        process.exit(0);
      }
      if (UbelEngine.checkMode === "check") {
        // check succeeded — finally will not revert (was_successful_scan=true),
        // so we explicitly restore originals and clean up the backup here.
        NodeManager.was_successful_scan = true;
        NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
        NodeManager.cleanupLockfileBackup();
        if (options.is_script==false){
        console.log("[+] Backup lockfiles removed.");
        }
        process.exit(0);
      }
      if (options.is_script==false){
      console.log("[+] Policy passed. Installing dependencies...");
      }
      NodeManager.was_successful_scan = true;

      const saveResult = await NodeManager.saveCandidateLockfile(UbelEngine.engine, process.cwd())
      if (!saveResult.written) {
        if (options.is_script==false){
        console.error("[!] Could not write candidate lockfile:", saveResult.reason);
        }
        process.exit(1);
      }
      try {
        const installResult = await NodeManager.runRealInstall(UbelEngine.engine);
        if (installResult.status !== 0) {
          if (options.is_script==false){
          console.error(`[!] npm ci failed (exit ${installResult.status}) — dependencies were NOT installed.`);
          }
          // Restore originals so the project is left in a consistent state.
          NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
          process.exit(1);
        }
      } catch (err) {
        if (options.is_script==false){
        console.error("[!] Failed to run npm ci:", err.message);
        }
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
      if (options.is_script==false){
      console.log("[+] Backup lockfiles removed.");
      }

    } finally {
      // Always restore the lockfile and package.json if a dry-run mutated them,
      // regardless of whether the scan succeeded, was blocked, or threw.
      if (!NodeManager.was_successful_scan && needsRevert) {
        const revertResult = NodeManager.revert_lock_to_original(UbelEngine.engine, process.cwd());
        if (!revertResult.reverted) {
          if (options.is_script==false){
          console.error("[!] Failed to restore original lockfiles:", revertResult.reason);
          }
          if (revertResult.backupDir) {
            if (options.is_script==false){
            console.error(`[~] Originals are preserved at: ${revertResult.backupDir}`);
            console.error("[~] Restore them manually if needed.");
            }
          }
        } else {
          NodeManager.cleanupLockfileBackup();
          if (options.is_script==false){
          console.log("[+] Backup lockfiles removed.");
          }
        }
      }
    }
  }
}