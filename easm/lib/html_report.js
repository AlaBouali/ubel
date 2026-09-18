'use strict';
// html_report.js — HTML report generator for ubel-url / ubel-domain (EASM) findings
//
// Input:  scanResult — { assets, inventory, vulnerabilities, misconfigurations } from ../lib/scan.js
//         meta       — { tool, generated_at, tool_version, targets, allowPrivate,
//                         osvEndpoint, nvdEndpoint, wpvulnerabilityEndpoint,
//                         domain, subdomainEndpoint }
//
// Output: HTML string (caller writes to disk)
//
// Deliberately scoped down from the SCA report this borrows its look from:
// no license tab, no dependency-sequence/graph tab, no reachability column
// or filter — see ../README.md for why. What's kept: severity/CVSS detail,
// fix-version recommendations, and the same compliance-framework mapping
// (OWASP/PCI/HIPAA/SOC2/ISO 27001/NIST/GDPR/CIS) the rest of UBEL uses, via
// the shared sca/compliance_mappings.js.
//
// Static assets (Tailwind, Chart.js, Google Fonts) are pulled from the
// shared sca module, same as the cloud scanner's report, so this stays a
// single self-contained file with no CDN/network calls at view time.

import { getTailwindScript } from "../../sca/tailwindcss.js";
import { getChartJSScript } from "../../sca/chartjs.js";
import { getGoogleFontsScript } from "../../sca/googlefonts.js";
import { summarizeCompliance } from "../../sca/compliance_mappings.js";

const TOOL_NAME = "ubel-url";

export const USAGE_NOTICE =
  "ubel-url performs live, unauthenticated HTTP(S) reconnaissance against every target " +
  "given to it, then discloses those targets' fingerprinted software/versions to " +
  "OSV.dev and/or NVD to look up known vulnerabilities. Only ever point it at " +
  "infrastructure you own or have explicit, documented authorization to test — the " +
  "same rule the rest of UBEL's own-infrastructure-only license and every other " +
  "module (cloud, docker, secrets, SAST) already holds you to. Scanning systems you " +
  "don't own or lack authorization for can violate computer-fraud laws (e.g. the " +
  "CFAA), the target's terms of service, and/or applicable regulations, regardless " +
  "of intent. This report is a point-in-time, best-effort read of what a remote " +
  "server chose to disclose (headers, banners, page markup) — absence of a finding " +
  "is not proof of absence of a vulnerability, and every finding here should be " +
  "verified against the authoritative advisory before you act on it.";

async function loadScaStatics() {
  return {
    tailwind: await getTailwindScript(),
    chartjs: await getChartJSScript(),
    googleFonts: await getGoogleFontsScript(),
  };
}

// ─── escaping ────────────────────────────────────────────────────────────────

function escapeForScript(obj) {
  return JSON.stringify(obj).replace(/</g, "\\u003c").replace(/`/g, "\\u0060");
}

// ─── stats builder ───────────────────────────────────────────────────────────

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"];
const STATES = ["infected", "vulnerable", "safe", "undetermined"];

function buildStats(inventory, vulnerabilities, resolution) {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  let infections = 0;
  for (const v of vulnerabilities) {
    if (v.is_infection) {
      infections++;
    } else {
      const key = (v.severity || "unknown").toLowerCase();
      severity[SEVERITIES.includes(key) ? key : "unknown"]++;
    }
  }

  const stateCounts = { infected: 0, vulnerable: 0, safe: 0, undetermined: 0 };
  const byHost = {};
  let lowConfidence = 0;
  let wpComponents = 0;
  let withPurl = 0;
  let multiId = 0;
  const byType = {};
  for (const item of inventory) {
    const st = STATES.includes(item.state) ? item.state : "undetermined";
    stateCounts[st]++;
    if (item.low_confidence_version) lowConfidence++;
    if (item.wp_kind) wpComponents++;
    const ids = item.ids || [];
    if (ids.some((id) => String(id).startsWith("pkg:"))) withPurl++;
    if (ids.length > 1) multiId++;
    byType[item.type || "service"] = (byType[item.type || "service"] || 0) + 1;
    for (const a of item.assets || []) {
      byHost[a.host] = (byHost[a.host] || 0) + 1;
    }
  }

  // Where findings came from — worth surfacing because the three sources
  // have genuinely different coverage characteristics (see README's
  // "Vulnerability data sources"), so a report that's 100% NVD means
  // something different from one that's mostly wpvulnerability.net.
  const bySource = {};
  let withFix = 0;
  for (const v of vulnerabilities) {
    bySource[v.source || "unknown"] = (bySource[v.source || "unknown"] || 0) + 1;
    if (v.has_fix) withFix++;
  }

  return {
    component_count: inventory.length,
    total_vulnerabilities: vulnerabilities.length,
    infections,
    severity,
    state_counts: stateCounts,
    by_host: byHost,
    by_component_type: byType,
    by_source: bySource,
    with_fix: withFix,
    without_fix: vulnerabilities.length - withFix,
    low_confidence_components: lowConfidence,
    wordpress_components: wpComponents,
    components_with_purl: withPurl,
    components_multi_id: multiId,
    resolution: resolution || { total: 0, resolved: 0, dead: 0, dead_hosts: [] },
  };
}

// ─── misconfiguration grouping ──────────────────────────────────────────────
//
// misconfig_scan.js emits one finding per (host, check) — so a rule like
// "missing-hsts" that fires on 12 hosts arrives as 12 separate finding
// objects, and the same rule id can even repeat *within* one host (the TLS
// legacy-protocol probe pushes one finding for TLSv1 and another for
// TLSv1.1 with the same id/target/url). Left flat, that's both noisy (the
// same issue repeated once per host instead of shown once) and unsafe to
// key by id+target+url in the UI (two same-host TLS findings collide on
// that key). This groups by rule id — the one thing that's always constant
// for a given check — the same "one row per distinct thing, not one row
// per host it happens to appear on" shape Components/Vulnerabilities
// already use, with a deduplicated "seen on" host list taking the place of
// their asset/component host lists.
const MISCONFIG_SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, unknown: 4 };

function misconfigSeverityRank(severity) {
  const key = String(severity || "unknown").toLowerCase();
  return key in MISCONFIG_SEVERITY_RANK ? MISCONFIG_SEVERITY_RANK[key] : MISCONFIG_SEVERITY_RANK.unknown;
}

function groupMisconfigurationsByType(findings) {
  const groups = new Map();

  for (const f of findings || []) {
    const id = f.id || "unknown";
    if (!groups.has(id)) {
      groups.set(id, { id, title: f.title || id, category: f.category || "Misconfiguration", severity: f.severity || "unknown", occurrences: [] });
    }
    const g = groups.get(id);
    if (misconfigSeverityRank(f.severity) < misconfigSeverityRank(g.severity)) g.severity = f.severity || g.severity;
    g.occurrences.push({
      target: f.target || "",
      url: f.url || "",
      severity: f.severity || "unknown",
      description: f.description || "",
      evidence: Array.isArray(f.evidence) ? f.evidence : f.evidence ? [String(f.evidence)] : [],
      remediation: f.remediation || "",
    });
  }

  return [...groups.values()]
    .map((g) => {
      const targets = [...new Set(g.occurrences.map((o) => o.target).filter(Boolean))];
      return { ...g, targets, hosts_affected: targets.length, occurrence_count: g.occurrences.length };
    })
    .sort((a, b) => misconfigSeverityRank(a.severity) - misconfigSeverityRank(b.severity) || b.occurrence_count - a.occurrence_count);
}

/**
 * @param {object} misconfigResult   the raw {findings, errors, stats} from scanMisconfigurations()
 * @param {object[]} grouped         output of groupMisconfigurationsByType()
 */
function buildMisconfigStats(misconfigResult, grouped) {
  const raw = misconfigResult.stats || { hosts_checked: 0, hosts_wp_checked: 0, total: 0, by_severity: {}, by_category: {} };

  const bySeverityTypes = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const byTarget = {};
  for (const g of grouped) {
    const key = String(g.severity || "unknown").toLowerCase();
    bySeverityTypes[key in bySeverityTypes ? key : "unknown"]++;
    for (const t of g.targets) byTarget[t] = (byTarget[t] || 0) + 1;
  }

  return {
    ...raw, // hosts_checked, hosts_wp_checked, total (raw per-host occurrence count), by_severity/by_category (also occurrence-level)
    distinct: grouped.length,
    hosts_affected: Object.keys(byTarget).length,
    by_severity_types: bySeverityTypes, // one count per rule id, using its worst-seen severity — what the grouped table/severity chart reflects
    by_target: byTarget, // occurrence count per host — the "grouped by seen on" breakdown
  };
}

// ─── main export ──────────────────────────────────────────────────────────────

/**
 * Builds the exact data object the HTML report renders from — also written
 * as-is to the JSON report, so the two never diverge.
 *
 * @param {{assets: object[], inventory: object[], vulnerabilities: object[], misconfigurations?: object}} scanResult
 * @param {object} [meta]
 * @param {string} [meta.tool]              which CLI produced this report
 *   (default "ubel-url") — e.g. "ubel-domain" when built via
 *   easm/domain.js, so the report accurately names its own entry point
 * @param {string} [meta.generated_at]
 * @param {string} [meta.tool_version]
 * @param {string[]} [meta.targets]        every target requested (including skipped/errored)
 * @param {boolean} [meta.allowPrivate]
 * @param {string} [meta.osvEndpoint]
 * @param {string} [meta.nvdEndpoint]
 * @param {string} [meta.wpvulnerabilityEndpoint]
 * @param {string} [meta.domain]           set only for ubel-domain runs — the
 *   root domain crt.sh was queried for; `targets` is the resulting
 *   discovered-subdomain list that was actually fingerprinted
 * @param {string} [meta.subdomainEndpoint]  crt.sh endpoint used, when meta.domain is set
 */
export function buildReportPayload(scanResult, meta = {}) {
  const { assets, inventory, vulnerabilities, resolution, secrets, misconfigurations } = scanResult;
  const stats = buildStats(inventory, vulnerabilities, resolution);
  const complianceSummary = summarizeCompliance(vulnerabilities.map((v) => v.compliance));
  const secretsResult = secrets || { findings: [], errors: [], stats: { total: 0 } };
  stats.secrets = secretsResult.stats || { total: 0 };
  const misconfigResult = misconfigurations || {
    findings: [],
    errors: [],
    stats: { total: 0, by_severity: {}, by_category: {} },
  };
  const groupedMisconfigs = groupMisconfigurationsByType(misconfigResult.findings || []);
  stats.misconfigurations = buildMisconfigStats(misconfigResult, groupedMisconfigs);

  return {
    generated_at: meta.generated_at || new Date().toISOString(),
    tool: meta.tool || TOOL_NAME,
    tool_version: meta.tool_version || null,
    usage_notice: USAGE_NOTICE,
    targets: meta.targets || [],
    allow_private: !!meta.allowPrivate,
    osv_endpoint: meta.osvEndpoint || null,
    nvd_endpoint: meta.nvdEndpoint || null,
    wpvulnerability_endpoint: meta.wpvulnerabilityEndpoint || null,
    domain: meta.domain || null,
    subdomain_endpoint: meta.domain ? meta.subdomainEndpoint || null : null,
    platform: meta.platform || null,
    arch: meta.arch || null,
    runtime_version: meta.runtime_version || null,
    working_dir: meta.workingDir || null,
    git_metadata: meta.gitMetadata || null,
    os_metadata: meta.osMetadata || null,
    stats,
    compliance_summary: complianceSummary,
    assets,
    inventory,
    vulnerabilities,
    secrets: secretsResult.findings || [],
    secrets_errors: secretsResult.errors || [],
    misconfigurations: groupedMisconfigs,
    misconfigurations_errors: misconfigResult.errors || [],
  };
}

/**
 * @param {object} reportPayload  the exact object from buildReportPayload()
 */
export async function generateHtmlReport(reportPayload) {
  const { tailwind, chartjs, googleFonts } = await loadScaStatics();

  const safeJson = escapeForScript(reportPayload);
  const clientScript = buildClientScript(safeJson);

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${reportPayload.tool} — External Attack Surface Report</title>
  <script>${tailwind}</script>
  <script>${chartjs}</script>
  <style>${googleFonts}</style>
  <style>
    :root { --bg: #0a0a0a; --card: #141414; --border: #262626; --accent: #ef4444; }
    body { font-family: 'Inter', sans-serif; background-color: var(--bg); color: #e5e5e5; }
    .mono { font-family: 'JetBrains Mono', monospace; }
    .glass { background: rgba(20,20,20,0.8); backdrop-filter: blur(12px); border: 1px solid var(--border); }
    .severity-critical { color: #ef4444; border-color: #ef4444; font-weight: bold; }
    .severity-high     { color: #f87171; border-color: #f87171; }
    .severity-medium   { color: #fb923c; border-color: #fb923c; }
    .severity-low      { color: #60a5fa; border-color: #60a5fa; }
    .severity-unknown  { color: #a3a3a3; border-color: #a3a3a3; }
    .severity-infection{ color: #c084fc; border-color: #c084fc; font-weight: bold; }
    .state-infected     { color: #c084fc; border-color: #c084fc; font-weight: bold; }
    .state-vulnerable   { color: #ef4444; border-color: #ef4444; }
    .state-safe         { color: #4ade80; border-color: #4ade80; }
    .state-undetermined { color: #a3a3a3; border-color: #a3a3a3; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    .tab-active { border-bottom: 2px solid var(--accent); color: white; }
    .modal-overlay { display: none; position: fixed; top:0; left:0; width:100%; height:100%;
                     background: rgba(0,0,0,0.85); z-index:50; backdrop-filter: blur(4px); }
    .modal-content { max-height: 90vh; overflow-y: auto; }
  </style>
</head>
<body class="min-h-screen flex flex-col">

  <!-- ── HEADER ─────────────────────────────────────────────────────────── -->
  <header class="border-b border-neutral-800 bg-neutral-900/50 sticky top-0 z-40 backdrop-blur-md">
    <div class="max-w-7xl mx-auto px-4 h-16 flex items-center justify-between">
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white text-sm">U</div>
        <div>
          <h1 class="text-lg font-semibold tracking-tight">External Attack Surface Report</h1>
          <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ...</p>
        </div>
      </div>
      <span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50">
        ${reportPayload.tool}${reportPayload.tool_version ? " v" + reportPayload.tool_version : ""}
      </span>
    </div>
  </header>


  <!-- ── NAV ───────────────────────────────────────────────────────────── -->
  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')"  id="tab-dashboard"  class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('scope')"       id="tab-scope"       class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Scope(0)</button>
      <button onclick="switchTab('components')" id="tab-components" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Components(0)</button>
      <button onclick="switchTab('vulns')"       id="tab-vulns"       class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities(0)</button>
      <button onclick="switchTab('misconfigs')" id="tab-misconfigs" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Misconfigurations(0)</button>
      <button onclick="switchTab('secrets')"    id="tab-secrets"    class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Secrets(0)</button>
      <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Compliance(0)</button>
      <button onclick="switchTab('stats')"      id="tab-stats"      class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
      <button onclick="switchTab('scaninfo')"   id="tab-scaninfo"   class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Scan Info</button>
    </div>
  </nav>

  <!-- ── MAIN ──────────────────────────────────────────────────────────── -->
  <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">

    <!-- Dashboard -->
    <section id="section-dashboard" class="space-y-8">
      <div class="grid grid-cols-2 md:grid-cols-6 gap-4">
        <div class="glass p-6 rounded-xl border-l-4 border-l-purple-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Infections</p>
          <p class="text-3xl font-bold text-purple-400" id="stat-infection">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-red-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Critical</p>
          <p class="text-3xl font-bold text-red-500" id="stat-critical">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-red-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">High</p>
          <p class="text-3xl font-bold text-red-400" id="stat-high">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-orange-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Medium</p>
          <p class="text-3xl font-bold text-orange-400" id="stat-medium">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-blue-400">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Low</p>
          <p class="text-3xl font-bold text-blue-400" id="stat-low">0</p>
        </div>
        <div class="glass p-6 rounded-xl border-l-4 border-l-neutral-500">
          <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Unknown</p>
          <p class="text-3xl font-bold text-neutral-300" id="stat-unknown">0</p>
        </div>
      </div>

      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Vulnerabilities by Severity</h3>
          <div class="h-56"><canvas id="severityChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Components by State</h3>
          <div class="h-56"><canvas id="stateChart"></canvas></div>
        </div>
        <div class="glass p-6 rounded-xl">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Components by Host</h3>
          <div class="h-56"><canvas id="hostChart"></canvas></div>
        </div>
      </div>
    </section>

    <!-- Scope -->
    <section id="section-scope" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="sc-search" type="text" placeholder="Search subdomain, IP..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="applyScopeFilters()">
        <select id="sc-status" onchange="applyScopeFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All statuses</option>
          <option value="scanned">Scanned</option>
          <option value="dead">Dead</option>
          <option value="skipped">Skipped</option>
          <option value="error">Error</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">Status</th>
              <th class="px-4 py-3">Subdomain</th>
              <th class="px-4 py-3">IP</th>
              <th class="px-4 py-3">Ports</th>
              <th class="px-4 py-3">Components</th>
              <th class="px-4 py-3">Vulns</th>
            </tr>
          </thead>
          <tbody id="scope-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
      <p id="scope-empty" class="hidden text-sm text-neutral-500 italic">No targets in scope.</p>
    </section>

    <!-- Components -->
    <section id="section-components" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="c-search" type="text" placeholder="Search name, host, CPE/purl..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="applyComponentFilters()">
        <select id="c-state" onchange="applyComponentFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All states</option>
          <option value="infected">Infected</option>
          <option value="vulnerable">Vulnerable</option>
          <option value="safe">Safe</option>
          <option value="undetermined">Undetermined</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">State</th>
              <th class="px-4 py-3">Name</th>
              <th class="px-4 py-3">Version</th>
              <th class="px-4 py-3">Host(s)</th>
              <th class="px-4 py-3">Vulns</th>
              <th class="px-4 py-3">Identifiers</th>
            </tr>
          </thead>
          <tbody id="components-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Vulnerabilities -->
    <section id="section-vulns" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="v-search" type="text" placeholder="Search ID, component, host..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="applyVulnFilters()">
        <select id="v-severity" onchange="applyVulnFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All severities</option>
          <option value="infection">Infection</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="unknown">Unknown</option>
        </select>
        <select id="v-source" onchange="applyVulnFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All sources</option>
          <option value="osv">OSV</option>
          <option value="nvd">NVD</option>
          <option value="wpvulnerability">WPVulnerability</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">ID</th>
              <th class="px-4 py-3">Component</th>
              <th class="px-4 py-3">Host(s)</th>
              <th class="px-4 py-3">Source</th>
              <th class="px-4 py-3">Fix</th>
            </tr>
          </thead>
          <tbody id="vulns-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
    </section>

    <!-- Misconfigurations -->
    <section id="section-misconfigs" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="m-search" type="text" placeholder="Search title, URL, target, category..."
               class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500"
               oninput="applyMisconfigFilters()">
        <select id="m-severity" onchange="applyMisconfigFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select id="m-category" onchange="applyMisconfigFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All categories</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider">
            <tr>
              <th class="px-4 py-3">Severity</th>
              <th class="px-4 py-3">Title</th>
              <th class="px-4 py-3">Seen On</th>
              <th class="px-4 py-3">Category</th>
              <th class="px-4 py-3">Occurrences</th>
            </tr>
          </thead>
          <tbody id="misconfigs-table-body" class="divide-y divide-neutral-800"></tbody>
        </table>
      </div>
      <p id="misconfigs-empty" class="hidden text-sm text-neutral-500 italic">
        No misconfigurations detected on any scanned host.
      </p>
      <div id="misconfigs-errors" class="hidden glass p-4 rounded-xl">
        <h3 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Probes that couldn't complete</h3>
        <p class="text-[11px] text-neutral-500 mb-2">These probes failed or timed out — absence of a finding for them means nothing either way.</p>
        <div id="misconfigs-errors-list" class="space-y-1 text-xs max-h-48 overflow-y-auto pr-1"></div>
      </div>
    </section>

    <!-- Compliance -->
    <section id="section-compliance" class="hidden space-y-8">
      <p id="compliance-disclaimer" class="text-xs text-neutral-500 italic bg-neutral-900/50 p-3 rounded-lg border border-neutral-800"></p>

      <div class="glass p-4 rounded-xl border border-neutral-800">
        <p class="text-xs text-neutral-400 leading-relaxed">
          <span class="font-semibold uppercase tracking-wide text-neutral-300">How to read the counts.</span>
          Each framework and control is scored in <span class="text-white font-semibold">distinct CVEs</span> — the same
          CVE affecting three component versions counts once here, because a compliance control is not violated three
          times by the same bug. The secondary figure is the number of <span class="text-white font-semibold">affected
          components</span> — that is the raw CVE-to-component pairing and shows how widely each issue is deployed.
          A control showing <span class="mono text-neutral-300">12 CVEs · 20 components</span> means twelve distinct
          bugs landed on twenty pieces of software, not twelve findings total.
        </p>
      </div>

      <div id="compliance-coverage" class="glass p-4 rounded-xl flex items-center justify-between text-sm hidden">
        <span class="text-neutral-400">Distinct CVEs mapped to at least one framework control</span>
        <span id="compliance-coverage-value" class="mono text-neutral-200 font-semibold"></span>
      </div>
      <div id="compliance-owasp-section" class="hidden space-y-3">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">By OWASP Top 10 Category</h3>
        <div id="compliance-owasp-grid" class="grid grid-cols-1 md:grid-cols-2 gap-3"></div>
      </div>
      <div id="compliance-frameworks-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
      <div id="compliance-empty" class="hidden text-sm text-neutral-500 italic">No vulnerabilities mapped to a compliance framework.</div>
    </section>

    <!-- Secrets -->
    <section id="section-secrets" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl border border-amber-500/30 bg-amber-500/5">
        <p class="text-xs text-amber-200 leading-relaxed">
          <span class="font-bold uppercase tracking-wide">Client-side exposure.</span>
          These credentials were read out of JavaScript the target serves to anyone who loads the page —
          inline <span class="mono">&lt;script&gt;</span> blocks and the <span class="mono">.js</span> files they
          reference. Anything listed here should be treated as already disclosed and rotated, not merely removed.
          Values are redacted in this report; open the URL at the line and column shown to see the original.
        </p>
      </div>

      <div class="flex flex-wrap gap-3">
        <input id="s-search" type="text" placeholder="Search URL, type, category..."
          oninput="applySecretFilters()"
          class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:border-red-500">
        <select id="s-severity" onchange="applySecretFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select id="s-source" onchange="applySecretFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm">
          <option value="all">All sources</option>
          <option value="inline-script">Inline &lt;script&gt;</option>
          <option value="js-file">External .js file</option>
        </select>
      </div>

      <div class="glass rounded-xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full text-sm text-left">
            <thead class="bg-neutral-900/50 text-neutral-400 uppercase text-xs tracking-wider">
              <tr>
                <th class="px-4 py-3">Severity</th>
                <th class="px-4 py-3">Secret Type</th>
                <th class="px-4 py-3">URL</th>
                <th class="px-4 py-3">Position</th>
                <th class="px-4 py-3">Source</th>
                <th class="px-4 py-3">Preview</th>
              </tr>
            </thead>
            <tbody id="secrets-table-body" class="divide-y divide-neutral-800"></tbody>
          </table>
        </div>
      </div>
      <p id="secrets-empty" class="hidden text-sm text-neutral-500 italic">
        No secrets found in the JavaScript served by the scanned hosts.
      </p>
      <div id="secrets-errors" class="hidden glass p-4 rounded-xl">
        <h3 class="text-xs font-semibold uppercase tracking-widest text-neutral-400 mb-2">Not scanned</h3>
        <p class="text-[11px] text-neutral-500 mb-2">These URLs couldn't be fetched or were too large — they were
        skipped, so absence of a finding for them means nothing either way.</p>
        <div id="secrets-errors-list" class="space-y-1 text-xs max-h-48 overflow-y-auto pr-1"></div>
      </div>
    </section>

    <!-- Detailed Stats -->
    <section id="section-stats" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Target Reachability</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Targets</span><span class="mono" id="stats-tgt-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-green-400">Resolved</span><span class="mono text-green-400" id="stats-tgt-resolved">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-red-400">Dead (no DNS)</span><span class="mono text-red-400" id="stats-tgt-dead">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Scanned</span><span class="mono" id="stats-tgt-scanned">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-amber-400">Skipped (safety guard)</span><span class="mono text-amber-400" id="stats-tgt-skipped">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">Errored</span><span class="mono" id="stats-tgt-errored">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Component Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total</span><span class="mono" id="stats-comp-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-purple-400">Infected</span><span class="mono text-purple-400" id="stats-comp-infected">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-red-400">Vulnerable</span><span class="mono text-red-400" id="stats-comp-vulnerable">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-green-400">Safe</span><span class="mono text-green-400" id="stats-comp-safe">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Undetermined</span><span class="mono" id="stats-comp-undetermined">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Low-confidence version</span><span class="mono" id="stats-comp-lowconf">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">WordPress plugin/theme/core</span><span class="mono" id="stats-comp-wp">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">With a purl id</span><span class="mono" id="stats-comp-purl">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">With multiple ids</span><span class="mono" id="stats-comp-multiid">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Vulnerability Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total</span><span class="mono" id="stats-vuln-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-purple-400">Infections</span><span class="mono text-purple-400" id="stats-vuln-infections">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-critical">Critical</span><span class="mono severity-critical" id="stats-vuln-critical">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-high">High</span><span class="mono severity-high" id="stats-vuln-high">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-medium">Medium</span><span class="mono severity-medium" id="stats-vuln-medium">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-low">Low</span><span class="mono severity-low" id="stats-vuln-low">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-unknown">Unknown</span><span class="mono severity-unknown" id="stats-vuln-unknown">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-green-400">With a fix available</span><span class="mono text-green-400" id="stats-vuln-fix">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">No fix published</span><span class="mono" id="stats-vuln-nofix">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Findings by Data Source</h3>
          <div class="h-48"><canvas id="sourceChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Components by Type</h3>
          <div class="h-48"><canvas id="typeChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Exposed Secrets (client-side JS)</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total</span><span class="mono" id="stats-sec-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-critical">Critical</span><span class="mono severity-critical" id="stats-sec-critical">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-high">High</span><span class="mono severity-high" id="stats-sec-high">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-medium">Medium</span><span class="mono severity-medium" id="stats-sec-medium">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-low">Low</span><span class="mono severity-low" id="stats-sec-low">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Affected URLs</span><span class="mono" id="stats-sec-urls">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Pages crawled</span><span class="mono" id="stats-sec-pages">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Inline blocks scanned</span><span class="mono" id="stats-sec-inline">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">External .js scanned</span><span class="mono" id="stats-sec-ext">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Misconfiguration Counts</h3>
          <div class="space-y-2 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Distinct issue types</span><span class="mono" id="stats-mc-distinct">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Total occurrences</span><span class="mono" id="stats-mc-total">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-critical">Critical</span><span class="mono severity-critical" id="stats-mc-critical">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-high">High</span><span class="mono severity-high" id="stats-mc-high">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-medium">Medium</span><span class="mono severity-medium" id="stats-mc-medium">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="severity-low">Low</span><span class="mono severity-low" id="stats-mc-low">0</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Hosts checked</span><span class="mono" id="stats-mc-hosts-checked">0</span></div>
            <div class="flex justify-between"><span class="text-neutral-500">Hosts affected</span><span class="mono" id="stats-mc-hosts-affected">0</span></div>
          </div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Misconfigurations by Severity</h3>
          <div class="h-48"><canvas id="misconfigSeverityChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-4">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Misconfigurations by Category</h3>
          <div class="h-48"><canvas id="misconfigCategoryChart"></canvas></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-3 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Misconfigurations by Host</h3>
          <p class="text-[11px] text-neutral-500">Occurrence count per host — the same issue type on 3 hosts counts 3 times here, matching "Seen On" in the Misconfigurations tab.</p>
          <div id="stats-misconfig-hosts" class="space-y-0"></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Dead Hosts</h3>
          <p class="text-[11px] text-neutral-500">Targets with no DNS record — not probed. For a domain scan these are
          usually decommissioned hosts still present in append-only Certificate Transparency history.</p>
          <div id="stats-dead-hosts" class="space-y-1 text-xs max-h-56 overflow-y-auto pr-1"></div>
        </div>

        <div class="glass p-6 rounded-xl space-y-3 md:col-span-2 lg:col-span-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Busiest Hosts (by component count)</h3>
          <div id="stats-hot-hosts" class="space-y-0"></div>
        </div>

      </div>
    </section>

    <!-- Scan Info -->
    <section id="section-scaninfo" class="hidden space-y-8">
      <div class="glass p-6 rounded-xl border border-amber-500/30 bg-amber-500/5">
        <h3 class="text-sm font-semibold uppercase tracking-widest text-amber-400 mb-3">Responsible Use Notice</h3>
        <p class="text-sm text-neutral-300 leading-relaxed" id="usage-notice">—</p>
      </div>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scan</h3>
          <div class="space-y-3 text-sm">
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Tool</span><span class="mono text-xs" id="sys-tool">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Version</span><span class="mono text-xs" id="sys-version">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Generated at</span><span class="mono text-xs" id="sys-generated">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">--allow-private</span><span class="mono text-xs" id="sys-allow-private">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">OSV endpoint</span><span class="mono text-xs" id="sys-osv-endpoint">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">NVD endpoint</span><span class="mono text-xs" id="sys-nvd-endpoint">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">WPVulnerability endpoint</span><span class="mono text-xs" id="sys-wpvuln-endpoint">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Domain (ubel-domain only)</span><span class="mono text-xs" id="sys-domain">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Subdomain source</span><span class="mono text-xs" id="sys-crtsh-endpoint">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Platform</span><span class="mono text-xs" id="sys-platform">—</span></div>
            <div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500 text-xs">Arch</span><span class="mono text-xs" id="sys-arch">—</span></div>
            <div class="flex justify-between"><span class="text-neutral-500 text-xs">Node</span><span class="mono text-xs" id="sys-node">—</span></div>
          </div>
        </div>
        <div class="glass p-6 rounded-xl space-y-3">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Targets</h3>
          <div id="sys-resolution-summary" class="text-xs bg-neutral-900 rounded-lg p-3 border border-neutral-800 mb-2">—</div>
          <div id="sys-targets" class="text-xs space-y-2 max-h-72 overflow-y-auto pr-1">—</div>
        </div>
      </div>
    </section>

  </main>

  <!-- ── FOOTER ─────────────────────────────────────────────────────────── -->
  <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50">
    <div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4">
      <p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">${reportPayload.tool}</span> — part of UBEL. For authorized use only.</p>
    </div>
  </footer>

  <!-- ── MODAL ──────────────────────────────────────────────────────────── -->
  <div id="modal-overlay" class="modal-overlay items-center justify-center p-4">
    <div class="modal-content glass w-full max-w-2xl rounded-2xl shadow-2xl relative">
      <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors">
        <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
      </button>
      <div id="modal-body" class="p-8"></div>
    </div>
  </div>

  <script>${clientScript}</script>
</body>
</html>`;
}

// ─── client-side script ──────────────────────────────────────────────────────

function buildClientScript(safeJson) {
  return `
// ── DATA ──────────────────────────────────────────────────────────────────────
const reportData = ${safeJson};

// ── HELPERS ───────────────────────────────────────────────────────────────────
// Every dynamic value below ultimately traces back to a remote server's own
// response (headers, banners, page markup) or a public vulnerability
// database — never something the person running the scan typed — so it's
// all escaped before touching innerHTML, and clicks are wired through data
// attributes + delegated listeners rather than interpolated onclick="..." strings.

function escH(s) {
  if (s === null || s === undefined) return '';
  return String(s).replace(/[&<>"']/g, m => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[m]));
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

// A vulnerability's (id) alone is NOT unique within a report: the same CVE
// routinely appears multiple times when it affects several component
// versions (e.g. CVE-2025-55182 against React 19.0.0 and React 19.1.0). The
// composite (id, affected_package_id) tuple is what every UI element that
// needs to point at one specific row must key on — using just id silently
// resolves to whichever variant appears first in the vulnerabilities array,
// which is exactly the wrong behaviour when the user clicked a row that
// visibly carries a different component label.
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

// ── COMPLIANCE HELPERS ────────────────────────────────────────────────────────
//
// The compliance_summary shipped in reportData is built server-side by
// summarizeCompliance() and counts each (vulnerability, affected-component)
// pair once. That's a fine raw number but it reads as "N distinct problems"
// when it is really "one CVE seen on N component versions" — which is what
// makes a report say "85 PCI DSS findings" for what is, in this scan, about
// a dozen distinct CVEs spread across a couple of dozen components.
//
// These helpers recompute a per-control breakdown from the raw vulnerability
// list so the UI can lead with the honest unit (distinct CVEs) and show the
// component count as a secondary figure. The server-side summary is left
// untouched so JSON consumers keep seeing whatever shape they already rely on.

function complianceMatchesFor(fwName, controlId) {
  return (reportData.vulnerabilities || []).filter(v =>
    v.compliance && v.compliance.frameworks &&
    v.compliance.frameworks.some(x =>
      x.name === fwName && x.controls.some(c => c.id === controlId)
    )
  );
}

function complianceStatsFromMatches(matches) {
  const cves = new Set();
  const components = new Set();
  const hosts = new Set();
  const inventoryById = new Map();
  for (const item of reportData.inventory || []) inventoryById.set(item.id, item);
  for (const v of matches) {
    cves.add(v.id);
    components.add(v.affected_package_id);
    const item = inventoryById.get(v.affected_package_id);
    for (const a of item?.assets || []) hosts.add(a.target);
  }
  return {
    cveCount: cves.size,
    componentCount: components.size,
    hostCount: hosts.size,
    matchCount: matches.length,
  };
}

// For the framework card's headline figure — the same CVE can appear under
// several controls of one framework (e.g. a path-traversal RCE maps to both
// A06 and A01), so dedupe before counting.
function complianceFrameworkTotals(fw) {
  const allMatches = [];
  for (const c of fw.controls || []) {
    allMatches.push(...complianceMatchesFor(fw.name, c.id));
  }
  return complianceStatsFromMatches(allMatches);
}

// ── DASHBOARD ─────────────────────────────────────────────────────────────────

function renderDashboard() {
  const s = reportData.stats;
  document.getElementById('report-id').textContent = 'GENERATED_AT: ' + reportData.generated_at;
  document.getElementById('stat-infection').textContent = s.infections;
  document.getElementById('stat-critical').textContent  = s.severity.critical;
  document.getElementById('stat-high').textContent      = s.severity.high;
  document.getElementById('stat-medium').textContent    = s.severity.medium;
  document.getElementById('stat-low').textContent       = s.severity.low;
  document.getElementById('stat-unknown').textContent   = s.severity.unknown;

  new Chart(document.getElementById('severityChart').getContext('2d'), {
    type: 'doughnut',
    data: {
      labels: ['Infection','Critical','High','Medium','Low','Unknown'],
      datasets: [{
        data: [s.infections, s.severity.critical, s.severity.high, s.severity.medium, s.severity.low, s.severity.unknown],
        backgroundColor: ['#c084fc','#ef4444','#f87171','#fb923c','#60a5fa','#a3a3a3'],
        borderWidth: 0,
      }],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10 } } } },
  });

  const st = s.state_counts;
  new Chart(document.getElementById('stateChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: ['Infected','Vulnerable','Safe','Undetermined'],
      datasets: [{ data: [st.infected, st.vulnerable, st.safe, st.undetermined], backgroundColor: ['#c084fc','#ef4444','#4ade80','#737373'], borderRadius: 4 }],
    },
    options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { y: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373', precision: 0 } },
                x: { grid: { display: false }, ticks: { color: '#737373' } } } },
  });

  const hosts = Object.entries(s.by_host).sort((a,b) => b[1]-a[1]).slice(0, 8);
  new Chart(document.getElementById('hostChart').getContext('2d'), {
    type: 'bar',
    data: {
      labels: hosts.map(([k]) => k),
      datasets: [{ data: hosts.map(([,v]) => v), backgroundColor: '#60a5faaa', borderRadius: 4 }],
    },
    options: { indexAxis: 'y', responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } },
      scales: { x: { beginAtZero: true, grid: { color: '#262626' }, ticks: { color: '#737373', precision: 0 } },
                y: { grid: { display: false }, ticks: { color: '#a3a3a3', font: { size: 10 } } } } },
  });
}

// ── SCOPE ─────────────────────────────────────────────────────────────────────
// Per-target ("subdomain") view: what was found on each host in scope, not
// what was found overall. Joins back to inventory/vulnerabilities by
// matching "target" — every inventory item's assets[] entry already
// carries the exact target string it was seen under (see scan.js), so this
// needs no separate lookup table, just a filter.

function scopeComponentsFor(target) {
  return (reportData.inventory || []).filter(item =>
    (item.assets || []).some(a => a.target === target)
  );
}

function scopePortsFor(target) {
  const ports = new Set();
  for (const item of reportData.inventory || []) {
    for (const a of item.assets || []) {
      if (a.target === target && a.port != null && a.port !== '') ports.add(a.port);
    }
  }
  return [...ports].sort((a, b) => (typeof a === 'number' && typeof b === 'number') ? a - b : String(a).localeCompare(String(b)));
}

function scopeVulnsFor(target) {
  const compIds = new Set(scopeComponentsFor(target).map(c => c.id));
  return (reportData.vulnerabilities || []).filter(v => compIds.has(v.affected_package_id));
}

let _filteredScope = reportData.assets || [];

function applyScopeFilters() {
  const q = document.getElementById('sc-search').value.trim().toLowerCase();
  const status = document.getElementById('sc-status').value;
  const all = reportData.assets || [];

  _filteredScope = all.filter(a => {
    if (status !== 'all' && a.status !== status) return false;
    if (q && !(
      (a.target || '').toLowerCase().includes(q) ||
      (a.resolved_ip || '').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderScopeTable();
}

const SCOPE_STATUS_CLASS = { scanned: 'text-green-400', skipped: 'text-amber-400', error: 'text-red-400', dead: 'text-red-400' };

function renderScopeTable() {
  const tbody = document.getElementById('scope-table-body');
  tbody.innerHTML = '';

  const all = reportData.assets || [];
  document.getElementById('scope-empty').classList.toggle('hidden', all.length > 0);

  if (all.length && !_filteredScope.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No targets match the current filters.</td></tr>';
    return;
  }

  for (const a of _filteredScope) {
    const ports = scopePortsFor(a.target);
    const comps = scopeComponentsFor(a.target);
    const vulns = scopeVulnsFor(a.target);
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.scopeTarget = a.target;
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${SCOPE_STATUS_CLASS[a.status] || 'text-neutral-400'}">\${escH(a.status)}</span></td>
      <td class="px-4 py-3 mono text-sm \${a.status === 'dead' ? 'text-neutral-500 line-through' : 'text-neutral-200'}">\${escH(a.target)}</td>
      <td class="px-4 py-3 mono text-xs text-neutral-400">\${escH(a.resolved_ip || '—')}</td>
      <td class="px-4 py-3 mono text-xs text-neutral-400">\${ports.length ? escH(ports.join(', ')) : '—'}</td>
      <td class="px-4 py-3 text-xs text-neutral-300">\${comps.length}</td>
      <td class="px-4 py-3 text-xs \${vulns.length ? 'text-red-400 font-semibold' : 'text-neutral-500'}">\${vulns.length}</td>
    \`;
    tbody.appendChild(row);
  }
}

function openScopeModal(target) {
  const a = (reportData.assets || []).find(x => x.target === target);
  if (!a) return;
  const ports = scopePortsFor(target);
  const comps = scopeComponentsFor(target);
  const vulns = scopeVulnsFor(target);

  openModal(\`
    <div class="space-y-4">
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold \${SCOPE_STATUS_CLASS[a.status] || 'text-neutral-400'}">\${escH(a.status)}</span>
        <h2 class="text-lg font-semibold text-white mono">\${escH(a.target)}</h2>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">IP</span><div class="mono text-neutral-200">\${escH(a.resolved_ip || '—')}</div></div>
        <div><span class="text-neutral-500">Resolved URL</span><div class="mono text-neutral-200 break-all">\${escH(a.resolved_url || '—')}</div></div>
        <div class="col-span-2">
          <span class="text-neutral-500">Scanned Ports (\${ports.length})</span>
          <div class="mono text-neutral-200 bg-neutral-900 rounded-lg p-2 mt-1 border border-neutral-800 max-h-24 overflow-y-auto">
            \${ports.length ? escH(ports.join(', ')) : '<span class="text-neutral-500">—</span>'}
          </div>
        </div>
        \${a.error ? \`<div class="col-span-2"><span class="text-neutral-500">Note</span><div class="text-neutral-300 text-xs italic mt-1">\${escH(a.error)}</div></div>\` : ''}
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Components (\${comps.length})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          \${comps.length ? comps.map(c => \`
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-component-id="\${escH(c.id)}">
              <div class="flex items-center gap-2 min-w-0">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold \${stateClass(c.state)} shrink-0">\${escH(c.state)}</span>
                <span class="text-xs text-neutral-200 truncate">\${escH(c.name)}\${c.version ? ' @ ' + escH(c.version) : ''}</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500 shrink-0"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>\`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No components fingerprinted on this host.</p>'}
        </div>
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerabilities (\${vulns.length})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          \${vulns.length ? vulns.map(v => \`
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-vuln-key="\${escH(vulnKey(v))}">
              <div class="flex items-center gap-2 min-w-0">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold \${sevClass(vulnSeverityKey(v))} shrink-0">\${escH(v.is_infection ? 'infection' : v.severity)}</span>
                <span class="mono text-xs text-neutral-200 shrink-0">\${escH(v.id)}</span>
                <span class="text-[10px] text-neutral-500 truncate">(\${escH(componentLabel(v.affected_package_id))})</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500 shrink-0"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>\`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No known vulnerabilities on this host.</p>'}
        </div>
      </div>
    </div>
  \`);
}

// ── COMPONENTS ─────────────────────────────────────────────────────────────────

let _filteredComponents = reportData.inventory;

function applyComponentFilters() {
  const q = document.getElementById('c-search').value.trim().toLowerCase();
  const state = document.getElementById('c-state').value;

  _filteredComponents = reportData.inventory.filter(item => {
    if (state !== 'all' && item.state !== state) return false;
    if (q && !(
      (item.name||'').toLowerCase().includes(q) ||
      (item.ids||[]).some(id => (id||'').toLowerCase().includes(q)) ||
      hostsOf(item).join(' ').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderComponentsTable();
}

function renderComponentsTable() {
  const tbody = document.getElementById('components-table-body');
  tbody.innerHTML = '';

  if (!_filteredComponents.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No components match the current filters.</td></tr>';
    return;
  }

  _filteredComponents.forEach((item) => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.componentId = item.id;
    const hosts = hostsOf(item);
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${stateClass(item.state)}">\${escH(item.state)}</span></td>
      <td class="px-4 py-3 text-sm font-medium text-white">\${escH(item.name)}</td>
      <td class="px-4 py-3 mono text-xs text-neutral-300">\${escH(item.version || '—')}\${item.low_confidence_version ? ' <span class="text-[9px] text-amber-400 border border-amber-500/40 rounded px-1 align-middle" title="Version is under-specified (e.g. a bare major version) — not queried against OSV/NVD, see modal for why">low-confidence</span>' : ''}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400">\${escH(hosts.slice(0,2).join(', '))}\${hosts.length > 2 ? ' +' + (hosts.length - 2) : ''}</td>
      <td class="px-4 py-3 text-xs text-neutral-400">\${item.vulnerabilities_count || 0}</td>
      <td class="px-4 py-3 mono text-[10px] text-neutral-500 truncate max-w-[240px]" title="\${escH((item.ids||[]).join(', '))}">\${escH((item.ids||[]).join(' / '))}</td>
    \`;
    tbody.appendChild(row);
  });
}

function openComponentModal(id) {
  const item = reportData.inventory.find(i => i.id === id);
  if (!item) return;
  const hosts = item.assets || [];
  const vulns = reportData.vulnerabilities.filter(v => v.affected_package_id === id);

  openModal(\`
    <div class="space-y-4">
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold \${stateClass(item.state)}">\${escH(item.state)}</span>
        <h2 class="text-lg font-semibold text-white">\${escH(item.name)}\${item.version ? ' @ ' + escH(item.version) : ''}</h2>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">Ecosystem</span><div class="mono text-neutral-200">\${escH(item.ecosystem)}</div></div>
        <div><span class="text-neutral-500">Type</span><div class="mono text-neutral-200">\${escH(item.type)}</div></div>
        <div><span class="text-neutral-500">Scopes</span><div class="mono text-neutral-200">\${escH((item.scopes||[]).join(', '))}</div></div>
        <div><span class="text-neutral-500">Vulnerabilities</span><div class="mono text-neutral-200">\${item.vulnerabilities_count || 0}</div></div>
        <div class="col-span-2"><span class="text-neutral-500">Identifiers (CPE / purl)</span><div class="mono text-neutral-200 break-all space-y-0.5">\${(item.ids||[item.id]).map(id => \`<div>\${escH(id)}</div>\`).join('')}</div></div>
      </div>
      \${item.low_confidence_version ? \`<div class="bg-amber-500/10 border border-amber-500/30 rounded-lg p-3 text-xs text-amber-200">
        <span class="font-bold uppercase">Not checked against OSV/NVD.</span> The version this
        component reported (\${escH(item.version || '(none)')}) is too under-specified to look up
        reliably — a bare major version matches almost every historical CVE for a product rather
        than anything specific to what's actually running, so it was skipped rather than shown as
        a flood of low-precision findings. Confirm the exact installed version directly before
        drawing conclusions either way.
      </div>\` : ''}
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Seen on (\${hosts.length})</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1 max-h-32 overflow-y-auto">
          \${hosts.length ? hosts.map(h => \`<div class="mono text-xs text-neutral-300">\${escH(h.host)}\${h.port ? ':' + escH(String(h.port)) : ''} <span class="text-neutral-600">(target: \${escH(h.target)})</span></div>\`).join('') : '<p class="text-neutral-500 text-xs italic">No asset detail recorded.</p>'}
        </div>
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Vulnerabilities</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-56 overflow-y-auto">
          \${vulns.length ? vulns.map(v => \`
            <div class="flex items-center justify-between px-3 py-2 cursor-pointer hover:bg-neutral-800/40 transition-colors" data-vuln-key="\${escH(vulnKey(v))}">
              <div class="flex items-center gap-2">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold \${sevClass(vulnSeverityKey(v))}">\${escH(v.is_infection ? 'infection' : v.severity)}</span>
                <span class="mono text-xs text-neutral-200">\${escH(v.id)}</span>
              </div>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
            </div>\`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No known vulnerabilities for this component/version.</p>'}
        </div>
      </div>
    </div>
  \`);
}

// ── VULNERABILITIES ────────────────────────────────────────────────────────────

let _filteredVulns = reportData.vulnerabilities;

function applyVulnFilters() {
  const q = document.getElementById('v-search').value.trim().toLowerCase();
  const sev = document.getElementById('v-severity').value;
  const source = document.getElementById('v-source').value;

  _filteredVulns = reportData.vulnerabilities.filter(v => {
    if (sev !== 'all' && vulnSeverityKey(v) !== sev) return false;
    if (source !== 'all' && (v.source || '') !== source) return false;
    if (q && !(
      (v.id||'').toLowerCase().includes(q) ||
      componentLabel(v.affected_package_id).toLowerCase().includes(q) ||
      hostsOfComponentId(v.affected_package_id).join(' ').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderVulnsTable();
}

function renderVulnsTable() {
  const tbody = document.getElementById('vulns-table-body');
  tbody.innerHTML = '';

  if (!_filteredVulns.length) {
    tbody.innerHTML = '<tr><td colspan="6" class="px-6 py-12 text-center text-neutral-500 italic">No vulnerabilities match the current filters.</td></tr>';
    return;
  }

  _filteredVulns.forEach((v) => {
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.vulnKey = vulnKey(v);
    const hosts = hostsOfComponentId(v.affected_package_id);
    const recommendedFix = v.fix_versions_ranked && v.fix_versions_ranked.find(r => r.recommended);
    const fix = v.has_fix ? (recommendedFix ? recommendedFix.version : (v.fixed_versions || [])[0] || 'available') : 'none published';
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(vulnSeverityKey(v))}">\${escH(v.is_infection ? 'infection' : v.severity)}</span></td>
      <td class="px-4 py-3 mono text-xs text-white">\${escH(v.id)}</td>
      <td class="px-4 py-3 text-sm text-neutral-300">\${escH(componentLabel(v.affected_package_id))}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400">\${escH(hosts.slice(0,2).join(', '))}\${hosts.length > 2 ? ' +' + (hosts.length - 2) : ''}</td>
      <td class="px-4 py-3 text-xs uppercase text-neutral-500">\${escH(v.source || '—')}</td>
      <td class="px-4 py-3 text-xs \${v.has_fix ? 'text-green-400' : 'text-neutral-500'}">\${escH(fix)}</td>
    \`;
    tbody.appendChild(row);
  });
}

function openVulnModal(key) {
  const v = (reportData.vulnerabilities || []).find(x => vulnKey(x) === key);
  if (!v) return;

  const refs = (v.references || []).slice(0, 12);
  const fixes = v.fixes && v.fixes.length ? v.fixes : (v.has_fix ? [] : ['No fix currently published upstream.']);

  openModal(\`
    <div class="space-y-4">
      <div class="flex items-center gap-3 flex-wrap">
        <span class="px-2 py-0.5 rounded border text-xs uppercase font-bold \${sevClass(vulnSeverityKey(v))}">\${escH(v.is_infection ? 'infection' : v.severity)}</span>
        <h2 class="text-lg font-semibold text-white">\${escH(v.id)}</h2>
        <span class="text-[10px] uppercase text-neutral-500 mono">via \${escH(v.source || 'unknown')}</span>
      </div>
      <div class="grid grid-cols-2 gap-3 text-xs">
        <div><span class="text-neutral-500">Component</span><div class="mono text-neutral-200">\${escH(componentLabel(v.affected_package_id))}</div></div>
        <div><span class="text-neutral-500">CVSS</span><div class="mono text-neutral-200">\${v.severity_score != null ? v.severity_score : '—'}\${v.severity_vector ? ' (' + escH(v.severity_vector) + ')' : ''}</div></div>
        <div class="col-span-2">
          <span class="text-neutral-500">Seen on (\${hostsOfComponentId(v.affected_package_id).length})</span>
          <div class="mono text-neutral-200 bg-neutral-900 rounded-lg p-2 mt-1 border border-neutral-800 max-h-32 overflow-y-auto space-y-0.5">
            \${hostsOfComponentId(v.affected_package_id).length ? hostsOfComponentId(v.affected_package_id).map(h => \`<div>\${escH(h)}</div>\`).join('') : '<span class="text-neutral-500">—</span>'}
          </div>
        </div>
        \${v.aliases && v.aliases.length ? \`<div class="col-span-2"><span class="text-neutral-500">Aliases</span><div class="mono text-neutral-200">\${escH(v.aliases.join(', '))}</div></div>\` : ''}
      </div>
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Description</p>
        <p class="text-sm text-neutral-300">\${escH(v.description || 'No description available.')}</p>
      </div>
      \${(v.fix_versions_ranked && v.fix_versions_ranked.length > 0) ? \`
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
              \${v.fix_versions_ranked.map(r => \`
              <tr class="\${r.recommended ? 'bg-green-500/5' : ''}">
                <td class="px-4 py-2 mono font-medium text-white">\${escH(r.version)}</td>
                <td class="px-4 py-2">
                  <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${
                    r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                    r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                          'text-red-400 border-red-400'
                  }">\${escH(r.compatibility_level)}</span>
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
      </div>\` : (fixes.length ? \`
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Remediation</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1">
          \${fixes.map(f => \`<p class="text-xs text-neutral-300 mono break-all">\${escH(f)}</p>\`).join('')}
        </div>
      </div>\` : '')}
      \${(v.last_affected_ranked && v.last_affected_ranked.length > 0) ? \`
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
              \${v.last_affected_ranked.map(r => \`
              <tr class="\${r.recommended ? 'bg-orange-500/5' : ''}">
                <td class="px-4 py-2 mono font-medium text-white">\${escH(r.version)}</td>
                <td class="px-4 py-2">
                  <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${
                    r.compatibility_level === 'high'   ? 'text-green-400 border-green-400' :
                    r.compatibility_level === 'medium' ? 'text-yellow-400 border-yellow-400' :
                                                          'text-red-400 border-red-400'
                  }">\${escH(r.compatibility_level)}</span>
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
      \${refs.length ? \`<div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">References</p>
        <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-1 max-h-32 overflow-y-auto">
          \${refs.map(r => \`<a href="\${escH(r.url)}" target="_blank" rel="noopener noreferrer" class="block text-[11px] mono text-blue-400 hover:underline break-all">\${escH(r.url)}</a>\`).join('')}
        </div>
      </div>\` : ''}
      \${v.iocs ? renderIocTable(v.iocs) : ''}
      \${renderComplianceSection(v.compliance)}
    </div>
  \`);
}

function renderIocTable(iocs) {
  const urls = iocs.urls || [], domains = iocs.domains || [], ips = iocs.ips || [];
  if (!urls.length && !domains.length && !ips.length) return '';
  const rows = [['URLs', urls], ['Domains', domains], ['IPs', ips]];
  return \`<div>
    <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Indicators of Compromise</p>
    <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-2">
      \${rows.map(([label, values]) => values.length ? \`
        <div class="flex flex-col gap-1">
          <span class="text-[10px] uppercase text-neutral-500 font-bold">\${label}</span>
          <div class="flex flex-wrap gap-1">\${values.map(val => \`<span class="mono text-[10px] bg-neutral-800 px-2 py-1 rounded border border-neutral-700">\${escH(val)}</span>\`).join('')}</div>
        </div>\` : '').join('')}
    </div>
  </div>\`;
}

// ── COMPLIANCE ─────────────────────────────────────────────────────────────────

function renderComplianceSection(compliance) {
  if (!compliance || !compliance.frameworks || !compliance.frameworks.length) return '';
  return \`<div>
    <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Compliance Frameworks</p>
    <div class="bg-neutral-900 rounded-lg p-3 border border-neutral-800 space-y-2">
      \${compliance.frameworks.map(fw => \`
      <div class="flex flex-col gap-1">
        <span class="text-xs font-semibold text-red-400">\${escH(fw.name)}</span>
        <div class="flex flex-wrap gap-1.5">\${fw.controls.map(c => \`<span class="text-[10px] bg-neutral-800 border border-neutral-700 px-2 py-1 rounded text-neutral-300" title="\${escH(c.title)}">\${escH(c.id)}</span>\`).join('')}</div>
      </div>\`).join('')}
    </div>
  </div>\`;
}

function renderCompliance() {
  const cs = reportData.compliance_summary;
  document.getElementById('compliance-disclaimer').textContent = (cs && cs.disclaimer) || '';

  // Coverage pill — reframed from "component-mappings mapped" to
  // "distinct CVEs that carry at least one framework control". The old
  // "85 / 85 (100%)" figure was technically true and rhetorically hollow:
  // every CVE in a CVE-based scan maps to A06 / RA-5 / Req. 6.3, so the
  // metric was guaranteed to read as 100% and told the reader nothing.
  const coverageEl = document.getElementById('compliance-coverage');
  const coverageValueEl = document.getElementById('compliance-coverage-value');
  const allVulns = reportData.vulnerabilities || [];
  const distinctCves = new Set(allVulns.map(v => v.id));
  const mappedCves = new Set();
  for (const v of allVulns) {
    if (v.compliance && v.compliance.frameworks && v.compliance.frameworks.length) {
      mappedCves.add(v.id);
    }
  }
  if (distinctCves.size > 0) {
    const pct = Math.round((mappedCves.size / distinctCves.size) * 100);
    coverageValueEl.textContent = mappedCves.size + ' of ' + distinctCves.size + ' (' + pct + '%)';
    coverageEl.classList.remove('hidden');
  } else {
    coverageEl.classList.add('hidden');
  }

  // OWASP by-category — recompute distinct-CVE counts from the raw
  // vulnerability list rather than trusting the summary's raw count.
  const owaspSection = document.getElementById('compliance-owasp-section');
  const owaspGrid = document.getElementById('compliance-owasp-grid');
  if (cs && cs.by_owasp_category && cs.by_owasp_category.length) {
    owaspGrid.innerHTML = cs.by_owasp_category.map(o => {
      const stats = complianceStatsFromMatches(complianceMatchesFor('OWASP Top 10', o.id));
      return \`
        <div class="glass p-4 rounded-xl flex items-start justify-between gap-3 text-xs">
          <div class="flex flex-col gap-1">
            <span class="mono text-red-400">\${escH(o.id)}</span>
            <span class="text-neutral-400">\${escH(o.title)}</span>
            <span class="text-neutral-600">via: \${escH((o.categories || []).join(', '))}</span>
          </div>
          <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
            <span class="mono text-neutral-200 font-semibold">\${stats.cveCount} CVE\${stats.cveCount === 1 ? '' : 's'}</span>
            <span class="mono text-neutral-500 text-[10px]">\${stats.componentCount} component\${stats.componentCount === 1 ? '' : 's'}</span>
          </div>
        </div>\`;
    }).join('');
    owaspSection.classList.remove('hidden');
  } else {
    owaspSection.classList.add('hidden');
  }

  // Framework cards — recompute from raw vulnerabilities so the badge
  // says "N CVEs · M components" rather than "N findings". The data-fw-idx
  // / data-control-idx keys still point into compliance_summary.frameworks
  // so openComplianceModal() continues to work unchanged.
  const grid = document.getElementById('compliance-frameworks-grid');
  if (!cs || !cs.frameworks || !cs.frameworks.length) {
    document.getElementById('compliance-empty').classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const fwStats = complianceFrameworkTotals(fw);
    return \`
    <div class="glass p-6 rounded-xl space-y-4">
      <div class="flex items-start justify-between gap-3">
        <div class="flex flex-col">
          <h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">\${escH(fw.name)}</h3>
          \${fw.version ? \`<span class="text-[10px] text-neutral-500 mono">\${escH(fw.version)}</span>\` : ''}
        </div>
        <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
          <span class="mono text-neutral-200 font-semibold text-xs">\${fwStats.cveCount} CVE\${fwStats.cveCount === 1 ? '' : 's'}</span>
          <span class="mono text-neutral-500 text-[10px]">\${fwStats.componentCount} component\${fwStats.componentCount === 1 ? '' : 's'}</span>
        </div>
      </div>
      <div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">
        \${fw.controls.map((c, cIdx) => {
          const stats = complianceStatsFromMatches(complianceMatchesFor(fw.name, c.id));
          return \`
          <div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" data-fw-idx="\${fwIdx}" data-control-idx="\${cIdx}">
            <div class="flex flex-col min-w-0">
              <span class="mono text-red-400">\${escH(c.id)}</span>
              <span class="text-neutral-500">\${escH(c.title)}</span>
            </div>
            <div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0">
              <span class="mono text-neutral-200">\${stats.cveCount} CVE\${stats.cveCount === 1 ? '' : 's'}</span>
              <span class="mono text-neutral-500 text-[10px]">\${stats.componentCount} comp.</span>
            </div>
          </div>\`;
        }).join('')}
      </div>
    </div>\`;
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

  const rows = matches.length ? matches.map((v, idx) => \`
    <div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" data-match-index="\${idx}">
      <div class="flex items-center gap-3">
        <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(vulnSeverityKey(v))}">\${escH(v.is_infection ? 'infection' : v.severity)}</span>
        <span class="text-sm text-white">\${escH(v.id)}</span>
      </div>
      <div class="flex items-center gap-3">
        <span class="mono text-[10px] text-neutral-500 truncate max-w-[220px]">\${escH(componentLabel(v.affected_package_id))}</span>
        <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg>
      </div>
    </div>\`).join('') : '<p class="text-sm text-neutral-500 italic py-2">No vulnerabilities mapped to this control.</p>';

  openModal(\`
    <div class="space-y-4">
      <div>
        <div class="flex items-center gap-3 mb-1 flex-wrap">
          <span class="mono text-red-400 text-sm">\${escH(control.id)}</span>
          <h2 class="text-lg font-semibold text-white">\${escH(control.title)}</h2>
        </div>
        <p class="text-xs text-neutral-500">
          \${escH(fw.name)}\${fw.version ? ' · ' + escH(fw.version) : ''} —
          \${stats.cveCount} distinct CVE\${stats.cveCount === 1 ? '' : 's'} across
          \${stats.componentCount} component\${stats.componentCount === 1 ? '' : 's'}
          on \${stats.hostCount} host\${stats.hostCount === 1 ? '' : 's'}
          (\${stats.matchCount} component-CVE pair\${stats.matchCount === 1 ? '' : 's'} total)
        </p>
      </div>
      <div>\${rows}</div>
    </div>
  \`);
}

// ── MISCONFIGURATIONS ─────────────────────────────────────────────────────────
// reportData.misconfigurations is already grouped by rule id server-side
// (see groupMisconfigurationsByType() in buildReportPayload) — one entry per
// distinct issue type, each carrying a deduplicated list of hosts it was
// seen on plus a per-host \`occurrences\` array (a rule can fire more than
// once per host, e.g. the TLS legacy-protocol probe reporting TLSv1 and
// TLSv1.1 separately, and per-host detail like exact days-to-expiry can
// differ even for the same rule). The rule id is unique per group, so it's
// used directly as the row/modal key instead of the old id+target+url combo.

let _filteredMisconfigs = reportData.misconfigurations || [];

function misconfigSeverityKey(m) {
  return String(m.severity || 'unknown').toLowerCase();
}

function populateMisconfigCategories() {
  const sel = document.getElementById('m-category');
  if (!sel) return;
  const cats = [...new Set((reportData.misconfigurations || []).map(m => m.category).filter(Boolean))].sort();
  for (const c of cats) {
    const opt = document.createElement('option');
    opt.value = c;
    opt.textContent = c;
    sel.appendChild(opt);
  }
}

function applyMisconfigFilters() {
  const all = reportData.misconfigurations || [];
  const q = document.getElementById('m-search').value.trim().toLowerCase();
  const sev = document.getElementById('m-severity').value;
  const cat = document.getElementById('m-category').value;

  _filteredMisconfigs = all.filter(m => {
    if (sev !== 'all' && misconfigSeverityKey(m) !== sev) return false;
    if (cat !== 'all' && (m.category || '') !== cat) return false;
    if (q && !(
      (m.title || '').toLowerCase().includes(q) ||
      (m.id || '').toLowerCase().includes(q) ||
      (m.category || '').toLowerCase().includes(q) ||
      (m.targets || []).join(' ').toLowerCase().includes(q) ||
      (m.occurrences || []).some(o => (o.url || '').toLowerCase().includes(q) || (o.description || '').toLowerCase().includes(q))
    )) return false;
    return true;
  });

  renderMisconfigsTable();
}

function renderMisconfigsTable() {
  const tbody = document.getElementById('misconfigs-table-body');
  tbody.innerHTML = '';

  const all = reportData.misconfigurations || [];
  document.getElementById('misconfigs-empty').classList.toggle('hidden', all.length > 0);

  if (!_filteredMisconfigs.length) {
    if (all.length) {
      tbody.innerHTML = '<tr><td colspan="5" class="px-6 py-12 text-center text-neutral-500 italic">No misconfigurations match the current filters.</td></tr>';
    }
    renderMisconfigErrors();
    return;
  }

  for (const m of _filteredMisconfigs) {
    const sev = misconfigSeverityKey(m);
    const targets = m.targets || [];
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/30 transition-colors cursor-pointer';
    row.dataset.misconfigKey = m.id;
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(sev)}">\${escH(sev)}</span></td>
      <td class="px-4 py-3 text-sm text-neutral-200">\${escH(m.title || m.id)}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400 truncate max-w-[220px]" title="\${escH(targets.join(', '))}">\${escH(targets.slice(0,2).join(', ') || '—')}\${targets.length > 2 ? ' +' + (targets.length - 2) : ''}</td>
      <td class="px-4 py-3 text-xs text-neutral-500">\${escH(m.category || '—')}</td>
      <td class="px-4 py-3 text-xs text-neutral-400">\${m.occurrence_count || 0}\${m.hosts_affected ? \` <span class="text-neutral-600">(\${m.hosts_affected} host\${m.hosts_affected === 1 ? '' : 's'})</span>\` : ''}</td>
    \`;
    tbody.appendChild(row);
  }
  renderMisconfigErrors();
}

function renderMisconfigErrors() {
  const errs = reportData.misconfigurations_errors || [];
  const errWrap = document.getElementById('misconfigs-errors');
  if (!errs.length) {
    errWrap.classList.add('hidden');
    return;
  }
  errWrap.classList.remove('hidden');
  document.getElementById('misconfigs-errors-list').innerHTML = errs.slice(0, 200).map(e => \`
    <div class="flex items-center justify-between bg-neutral-900 rounded px-2 py-1.5 border border-neutral-800">
      <span class="mono text-[11px] text-neutral-400 truncate">\${escH((e.check || 'probe') + ' → ' + (e.url || e.target || ''))}</span>
      <span class="text-[10px] text-neutral-500 shrink-0 ml-2">\${escH(e.error || '')}</span>
    </div>\`).join('');
}

function openMisconfigModal(key) {
  const m = (reportData.misconfigurations || []).find(x => x.id === key);
  if (!m) return;
  const sev = misconfigSeverityKey(m);
  const occurrences = m.occurrences || [];
  const remediations = [...new Set(occurrences.map(o => o.remediation).filter(Boolean))];

  openModal(\`
    <div class="space-y-5">
      <div>
        <div class="flex items-center gap-3 mb-2 flex-wrap">
          <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold \${sevClass(sev)}">\${escH(sev)}\${occurrences.length > 1 ? ' (worst seen)' : ''}</span>
          <span class="text-[10px] uppercase text-neutral-500 mono">\${escH(m.category || 'misconfiguration')}</span>
        </div>
        <h2 class="text-xl font-semibold text-white">\${escH(m.title || m.id)}</h2>
        <p class="text-xs text-neutral-500 mono mt-1">rule: \${escH(m.id)}</p>
      </div>

      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Seen on (\${m.hosts_affected || 0} host\${m.hosts_affected === 1 ? '' : 's'}, \${occurrences.length} occurrence\${occurrences.length === 1 ? '' : 's'})</p>
        <div class="bg-neutral-900 rounded-lg border border-neutral-800 divide-y divide-neutral-800 max-h-72 overflow-y-auto">
          \${occurrences.length ? occurrences.map(o => \`
            <div class="px-3 py-2">
              <div class="flex items-center gap-2 flex-wrap mb-1">
                <span class="px-1.5 py-0.5 rounded border text-[9px] uppercase font-bold \${sevClass(misconfigSeverityKey(o))}">\${escH(misconfigSeverityKey(o))}</span>
                <span class="mono text-xs text-neutral-200">\${escH(o.target || '—')}</span>
                \${o.url ? \`<span class="mono text-[10px] text-neutral-500 truncate">\${escH(o.url)}</span>\` : ''}
              </div>
              \${o.description ? \`<p class="text-[11px] text-neutral-400">\${escH(o.description)}</p>\` : ''}
              \${o.evidence && o.evidence.length ? \`<div class="mt-1 space-y-0.5">\${o.evidence.map(e => \`<div class="mono text-[10px] text-neutral-500 break-all">\${escH(e)}</div>\`).join('')}</div>\` : ''}
            </div>\`).join('') : '<p class="text-neutral-500 text-xs italic p-3">No occurrence detail recorded.</p>'}
        </div>
      </div>

      \${remediations.length ? \`
      <div>
        <p class="text-xs text-green-400 uppercase font-semibold mb-1">Remediation</p>
        <div class="bg-green-500/5 border border-green-500/30 rounded-lg p-3 space-y-2">
          \${remediations.map(r => \`<p class="text-xs text-neutral-300 leading-relaxed">\${escH(r)}</p>\`).join('')}
        </div>
      </div>\` : ''}
    </div>
  \`);
}

// ── SECRETS ───────────────────────────────────────────────────────────────────

let _filteredSecrets = reportData.secrets || [];

function secretSeverityKey(s) {
  return String(s.severity || 'unknown').toLowerCase();
}

function applySecretFilters() {
  const all = reportData.secrets || [];
  const q = document.getElementById('s-search').value.trim().toLowerCase();
  const sev = document.getElementById('s-severity').value;
  const src = document.getElementById('s-source').value;

  _filteredSecrets = all.filter(s => {
    if (sev !== 'all' && secretSeverityKey(s) !== sev) return false;
    if (src !== 'all' && (s.source_type || '') !== src) return false;
    if (q && !(
      (s.url || '').toLowerCase().includes(q) ||
      (s.secret_type || '').toLowerCase().includes(q) ||
      (s.category || '').toLowerCase().includes(q) ||
      (s.id || '').toLowerCase().includes(q)
    )) return false;
    return true;
  });

  renderSecretsTable();
}

function renderSecretsTable() {
  const tbody = document.getElementById('secrets-table-body');
  tbody.innerHTML = '';

  const all = reportData.secrets || [];
  const emptyEl = document.getElementById('secrets-empty');
  if (!all.length) {
    emptyEl.classList.remove('hidden');
  } else {
    emptyEl.classList.add('hidden');
  }

  for (const s of _filteredSecrets) {
    const sev = secretSeverityKey(s);
    const row = document.createElement('tr');
    row.className = 'hover:bg-neutral-800/40 transition-colors cursor-pointer';
    row.dataset.secretKey = \`\${s.url}::\${s.id}::\${s.line}::\${s.column_start}\`;
    row.innerHTML = \`
      <td class="px-4 py-3"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${sev}">\${escH(sev)}</span></td>
      <td class="px-4 py-3 text-sm text-neutral-200">\${escH(s.secret_type || s.title || s.id)}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400 truncate max-w-[280px]" title="\${escH(s.url)}">\${escH(s.url)}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-400">\${s.line}:\${s.column_start}</td>
      <td class="px-4 py-3 text-xs text-neutral-500">\${s.source_type === 'js-file' ? '.js file' : 'inline'}</td>
      <td class="px-4 py-3 mono text-[11px] text-neutral-500">\${escH(s.match_preview || '—')}</td>
    \`;
    tbody.appendChild(row);
  }

  const errs = reportData.secrets_errors || [];
  const errWrap = document.getElementById('secrets-errors');
  if (errs.length) {
    errWrap.classList.remove('hidden');
    document.getElementById('secrets-errors-list').innerHTML = errs.map(e => \`
      <div class="flex items-center justify-between bg-neutral-900 rounded px-2 py-1.5 border border-neutral-800">
        <span class="mono text-[11px] text-neutral-400 truncate">\${escH(e.url)}</span>
        <span class="text-[10px] text-neutral-500 shrink-0 ml-2">\${escH(e.error)}</span>
      </div>\`).join('');
  } else {
    errWrap.classList.add('hidden');
  }
}

function openSecretModal(key) {
  const s = (reportData.secrets || []).find(
    x => \`\${x.url}::\${x.id}::\${x.line}::\${x.column_start}\` === key
  );
  if (!s) return;
  const sev = secretSeverityKey(s);
  const refs = s.referenced_by || [];

  openModal(\`
    <div class="space-y-5">
      <div>
        <div class="flex items-center gap-3 mb-2">
          <span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-\${sev}">\${escH(sev)}</span>
          <span class="text-[10px] uppercase text-neutral-500 mono">\${escH(s.category || 'secret')}</span>
        </div>
        <h2 class="text-xl font-semibold text-white">\${escH(s.secret_type || s.title || s.id)}</h2>
        <p class="text-xs text-neutral-500 mono mt-1">rule: \${escH(s.id)}</p>
      </div>

      <div class="bg-neutral-900 rounded-lg p-4 border border-neutral-800 space-y-3 text-xs">
        <div>
          <span class="text-neutral-500">Location</span>
          <div class="mono text-neutral-200 break-all mt-1">\${escH(s.url)}</div>
          <div class="mono text-neutral-400 mt-1">line \${s.line}, column \${s.column_start}–\${s.column_end}</div>
        </div>
        <div>
          <span class="text-neutral-500">Served as</span>
          <div class="text-neutral-300 mt-1">\${s.source_type === 'js-file'
            ? 'a separate JavaScript file referenced by the page'
            : 'an inline &lt;script&gt; block in the page source (line number is relative to the page document)'}</div>
        </div>
        <div>
          <span class="text-neutral-500">Redacted value</span>
          <div class="mono text-neutral-200 mt-1">\${escH(s.match_preview || '—')}</div>
        </div>
      </div>

      \${refs.length ? \`
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Referenced by \${refs.length} page(s)</p>
        <div class="space-y-1 max-h-40 overflow-y-auto pr-1">
          \${refs.map(r => \`<div class="mono text-[11px] text-neutral-400 bg-neutral-900 rounded px-2 py-1 border border-neutral-800 break-all">\${escH(r)}</div>\`).join('')}
        </div>
      </div>\` : (s.page_url ? \`
      <div>
        <p class="text-xs text-neutral-500 uppercase font-semibold mb-2">Found on</p>
        <div class="mono text-[11px] text-neutral-400 bg-neutral-900 rounded px-2 py-1 border border-neutral-800 break-all">\${escH(s.page_url)}</div>
      </div>\` : '')}

      <div class="bg-amber-500/5 border border-amber-500/30 rounded-lg p-3">
        <p class="text-[11px] text-amber-200 leading-relaxed">
          This value was served to an unauthenticated request. Treat it as disclosed: rotate the credential,
          then remove it from the client bundle. Deleting it without rotating leaves the old value valid for
          anyone who already fetched the page.
        </p>
      </div>
    </div>
  \`);
}

// ── SCAN INFO ─────────────────────────────────────────────────────────────────

function renderScanInfo() {
  document.getElementById('usage-notice').textContent = reportData.usage_notice || '';
  document.getElementById('sys-tool').textContent = reportData.tool;
  document.getElementById('sys-version').textContent = reportData.tool_version || '—';
  document.getElementById('sys-generated').textContent = reportData.generated_at;
  document.getElementById('sys-allow-private').textContent = reportData.allow_private ? 'true' : 'false';
  document.getElementById('sys-osv-endpoint').textContent = reportData.osv_endpoint || 'https://api.osv.dev (default)';
  document.getElementById('sys-nvd-endpoint').textContent = reportData.nvd_endpoint || 'https://services.nvd.nist.gov (default)';
  document.getElementById('sys-wpvuln-endpoint').textContent = reportData.wpvulnerability_endpoint || 'https://www.wpvulnerability.net (default)';
  document.getElementById('sys-domain').textContent = reportData.domain || 'n/a (not a domain scan)';
  document.getElementById('sys-crtsh-endpoint').textContent = reportData.domain ? (reportData.subdomain_endpoint || 'https://crt.sh (default)') : '—';
  document.getElementById('sys-platform').textContent = reportData.platform || '—';
  document.getElementById('sys-arch').textContent = reportData.arch || '—';
  document.getElementById('sys-node').textContent = reportData.runtime_version || '—';

  const res = (reportData.stats && reportData.stats.resolution) || { total: 0, resolved: 0, dead: 0 };
  document.getElementById('sys-resolution-summary').innerHTML =
    \`<span class="text-neutral-400">\${res.total} target(s): </span>\` +
    \`<span class="text-green-400 font-semibold">\${res.resolved} resolved</span>\` +
    \`<span class="text-neutral-600"> · </span>\` +
    \`<span class="\${res.dead ? 'text-red-400 font-semibold' : 'text-neutral-500'}">\${res.dead} dead</span>\` +
    (res.dead ? \`<div class="text-[10px] text-neutral-500 mt-1 italic">Dead hosts have no DNS record and were not probed — see the Detailed Stats tab for the full list.</div>\` : '');

  const targetsEl = document.getElementById('sys-targets');
  const assets = reportData.assets || [];
  if (!assets.length) {
    targetsEl.textContent = '—';
    return;
  }
  const statusClass = { scanned: 'text-green-400', skipped: 'text-amber-400', error: 'text-red-400', dead: 'text-red-400' };
  targetsEl.innerHTML = assets.map(a => \`
    <div class="bg-neutral-900 rounded-lg p-3 border \${a.status === 'dead' ? 'border-red-500/30' : 'border-neutral-800'}">
      <div class="flex items-center justify-between">
        <span class="mono text-xs \${a.status === 'dead' ? 'text-neutral-500 line-through' : 'text-neutral-200'}">\${escH(a.target)}</span>
        <span class="text-[10px] uppercase font-bold \${statusClass[a.status] || 'text-neutral-400'}">\${escH(a.status)}</span>
      </div>
      \${a.resolved_ip ? \`<div class="mono text-[10px] text-neutral-500 mt-1">resolved to \${escH(a.resolved_ip)}</div>\` : ''}
      \${a.resolved_url ? \`<div class="mono text-[10px] text-neutral-500 mt-1">\${escH(a.resolved_url)} — \${a.components_found} component(s)</div>\` : ''}
      \${a.error ? \`<div class="text-[10px] text-neutral-500 mt-1 italic">\${escH(a.error)}</div>\` : ''}
    </div>\`).join('');
}

// ── DETAILED STATS ────────────────────────────────────────────────────────────

function renderStats() {
  const s = reportData.stats || {};
  const res = s.resolution || { total: 0, resolved: 0, dead: 0, dead_hosts: [] };
  const assets = reportData.assets || [];
  const countStatus = (st) => assets.filter(a => a.status === st).length;
  const set = (id, val) => { const el = document.getElementById(id); if (el) el.textContent = val; };

  set('stats-tgt-total', res.total);
  set('stats-tgt-resolved', res.resolved);
  set('stats-tgt-dead', res.dead);
  set('stats-tgt-scanned', countStatus('scanned'));
  set('stats-tgt-skipped', countStatus('skipped'));
  set('stats-tgt-errored', countStatus('error'));

  const st = s.state_counts || {};
  set('stats-comp-total', s.component_count || 0);
  set('stats-comp-infected', st.infected || 0);
  set('stats-comp-vulnerable', st.vulnerable || 0);
  set('stats-comp-safe', st.safe || 0);
  set('stats-comp-undetermined', st.undetermined || 0);
  set('stats-comp-lowconf', s.low_confidence_components || 0);
  set('stats-comp-wp', s.wordpress_components || 0);
  set('stats-comp-purl', s.components_with_purl || 0);
  set('stats-comp-multiid', s.components_multi_id || 0);

  const sev = s.severity || {};
  set('stats-vuln-total', s.total_vulnerabilities || 0);
  set('stats-vuln-infections', s.infections || 0);
  set('stats-vuln-critical', sev.critical || 0);
  set('stats-vuln-high', sev.high || 0);
  set('stats-vuln-medium', sev.medium || 0);
  set('stats-vuln-low', sev.low || 0);
  set('stats-vuln-unknown', sev.unknown || 0);
  set('stats-vuln-fix', s.with_fix || 0);
  set('stats-vuln-nofix', s.without_fix || 0);

  const sec = s.secrets || {};
  const secSev = sec.by_severity || {};
  set('stats-sec-total', sec.total || 0);
  set('stats-sec-critical', secSev.critical || 0);
  set('stats-sec-high', secSev.high || 0);
  set('stats-sec-medium', secSev.medium || 0);
  set('stats-sec-low', secSev.low || 0);
  set('stats-sec-urls', sec.affected_urls || 0);
  set('stats-sec-pages', sec.pages_crawled || 0);
  set('stats-sec-inline', sec.inline_blocks || 0);
  set('stats-sec-ext', sec.external_scripts || 0);

  // Misconfiguration counts
  const mc = s.misconfigurations || { total: 0, distinct: 0, by_severity_types: {}, by_category: {}, by_target: {} };
  const mcSevTypes = mc.by_severity_types || {};
  set('stats-mc-distinct', mc.distinct || 0);
  set('stats-mc-total', mc.total || 0);
  set('stats-mc-critical', mcSevTypes.critical || 0);
  set('stats-mc-high', mcSevTypes.high || 0);
  set('stats-mc-medium', mcSevTypes.medium || 0);
  set('stats-mc-low', mcSevTypes.low || 0);
  set('stats-mc-hosts-checked', mc.hosts_checked || 0);
  set('stats-mc-hosts-affected', mc.hosts_affected || 0);

  // Misconfigurations by host — same "grouped by seen on" breakdown the
  // Misconfigurations tab's Seen On column reflects, ranked here like
  // Busiest Hosts above.
  const mcHostEl = document.getElementById('stats-misconfig-hosts');
  if (mcHostEl) {
    const byTarget = Object.entries(mc.by_target || {}).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const maxT = byTarget.length ? byTarget[0][1] : 0;
    mcHostEl.innerHTML = byTarget.length
      ? byTarget.map(([host, count]) => \`
        <div class="flex items-center gap-3 py-1.5 border-b border-neutral-800 last:border-0">
          <span class="mono text-xs text-neutral-300 truncate flex-1">\${escH(host)}</span>
          <div class="w-40 bg-neutral-800 rounded-full h-1.5 shrink-0">
            <div class="bg-red-500 h-1.5 rounded-full" style="width: \${maxT ? (count / maxT) * 100 : 0}%"></div>
          </div>
          <span class="mono text-xs text-neutral-400 w-8 text-right shrink-0">\${count}</span>
        </div>\`).join('')
      : '<p class="text-xs text-neutral-500 italic">No misconfigurations detected.</p>';
  }

  // Dead host list
  const deadEl = document.getElementById('stats-dead-hosts');
  if (deadEl) {
    const dead = res.dead_hosts || [];
    deadEl.innerHTML = dead.length
      ? dead.map(d => \`
        <div class="flex items-center justify-between bg-neutral-900 rounded px-2 py-1.5 border border-neutral-800">
          <span class="mono text-[11px] text-neutral-400 truncate">\${escH(d.target)}</span>
          <span class="mono text-[10px] text-red-400 shrink-0 ml-2">\${escH(d.error || 'no record')}</span>
        </div>\`).join('')
      : '<p class="text-xs text-neutral-500 italic">Every target resolved.</p>';
  }

  // Busiest hosts — mirrors the SAST report's "Hottest Files" panel; the
  // equivalent question for an attack surface is which host is carrying the
  // most fingerprinted software.
  const hotEl = document.getElementById('stats-hot-hosts');
  if (hotEl) {
    const byHost = Object.entries(s.by_host || {}).sort((a, b) => b[1] - a[1]).slice(0, 15);
    const max = byHost.length ? byHost[0][1] : 0;
    hotEl.innerHTML = byHost.length
      ? byHost.map(([host, count]) => \`
        <div class="flex items-center gap-3 py-1.5 border-b border-neutral-800 last:border-0">
          <span class="mono text-xs text-neutral-300 truncate flex-1">\${escH(host)}</span>
          <div class="w-40 bg-neutral-800 rounded-full h-1.5 shrink-0">
            <div class="bg-red-500 h-1.5 rounded-full" style="width: \${max ? (count / max) * 100 : 0}%"></div>
          </div>
          <span class="mono text-xs text-neutral-400 w-8 text-right shrink-0">\${count}</span>
        </div>\`).join('')
      : '<p class="text-xs text-neutral-500 italic">No components found on any host.</p>';
  }

  renderStatsCharts(s);
}

function renderStatsCharts(s) {
  if (typeof Chart === 'undefined') return;

  const sourceEntries = Object.entries(s.by_source || {});
  const sourceCanvas = document.getElementById('sourceChart');
  if (sourceCanvas && sourceEntries.length) {
    new Chart(sourceCanvas, {
      type: 'doughnut',
      data: {
        labels: sourceEntries.map(([k]) => k),
        datasets: [{
          data: sourceEntries.map(([, v]) => v),
          backgroundColor: ['#ef4444', '#f97316', '#a855f7', '#3b82f6', '#22c55e', '#a3a3a3'],
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10, font: { size: 10 } } } },
      },
    });
  }

  const typeEntries = Object.entries(s.by_component_type || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const typeCanvas = document.getElementById('typeChart');
  if (typeCanvas && typeEntries.length) {
    new Chart(typeCanvas, {
      type: 'bar',
      data: {
        labels: typeEntries.map(([k]) => k),
        datasets: [{ data: typeEntries.map(([, v]) => v), backgroundColor: '#ef4444', borderWidth: 0 }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#a3a3a3', font: { size: 10 }, precision: 0 }, grid: { color: '#262626' } },
          y: { ticks: { color: '#a3a3a3', font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
  }

  const mc = s.misconfigurations || {};
  const mcSevEntries = Object.entries(mc.by_severity_types || {}).filter(([, v]) => v > 0);
  const MC_SEV_COLORS = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', unknown: '#a3a3a3' };
  const mcSevCanvas = document.getElementById('misconfigSeverityChart');
  if (mcSevCanvas && mcSevEntries.length) {
    new Chart(mcSevCanvas, {
      type: 'doughnut',
      data: {
        labels: mcSevEntries.map(([k]) => k),
        datasets: [{
          data: mcSevEntries.map(([, v]) => v),
          backgroundColor: mcSevEntries.map(([k]) => MC_SEV_COLORS[k] || MC_SEV_COLORS.unknown),
          borderWidth: 0,
        }],
      },
      options: {
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10, font: { size: 10 } } } },
      },
    });
  }

  const mcCatEntries = Object.entries(mc.by_category || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
  const mcCatCanvas = document.getElementById('misconfigCategoryChart');
  if (mcCatCanvas && mcCatEntries.length) {
    new Chart(mcCatCanvas, {
      type: 'bar',
      data: {
        labels: mcCatEntries.map(([k]) => k),
        datasets: [{ data: mcCatEntries.map(([, v]) => v), backgroundColor: '#fb923c', borderWidth: 0, borderRadius: 4 }],
      },
      options: {
        indexAxis: 'y',
        responsive: true, maintainAspectRatio: false,
        plugins: { legend: { display: false } },
        scales: {
          x: { ticks: { color: '#a3a3a3', font: { size: 10 }, precision: 0 }, grid: { color: '#262626' } },
          y: { ticks: { color: '#a3a3a3', font: { size: 10 } }, grid: { display: false } },
        },
      },
    });
  }
}

// ── TAB SWITCHING ─────────────────────────────────────────────────────────────

function switchTab(id) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('tab-active'));
  document.getElementById('tab-' + id).classList.add('tab-active');
  document.querySelectorAll('main section').forEach(s => s.classList.add('hidden'));
  document.getElementById('section-' + id).classList.remove('hidden');
}

// ── MODAL ─────────────────────────────────────────────────────────────────────

function closeModal() {
  document.getElementById('modal-overlay').style.display = 'none';
  document.body.style.overflow = 'auto';
}
function openModal(html) {
  document.getElementById('modal-body').innerHTML = html;
  document.getElementById('modal-overlay').style.display = 'flex';
  document.body.style.overflow = 'hidden';
}

document.addEventListener('DOMContentLoaded', () => {
  document.getElementById('modal-overlay').addEventListener('click', (e) => {
    if (e.target.id === 'modal-overlay') closeModal();
  });

  document.getElementById('scope-table-body').addEventListener('click', (e) => {
    const row = e.target.closest('[data-scope-target]');
    if (!row) return;
    openScopeModal(row.dataset.scopeTarget);
  });

  document.getElementById('components-table-body').addEventListener('click', (e) => {
    const row = e.target.closest('[data-component-id]');
    if (!row) return;
    openComponentModal(row.dataset.componentId);
  });

  document.getElementById('vulns-table-body').addEventListener('click', (e) => {
    const row = e.target.closest('[data-vuln-key]');
    if (!row) return;
    openVulnModal(row.dataset.vulnKey);
  });

  document.getElementById('misconfigs-table-body').addEventListener('click', (e) => {
    const row = e.target.closest('[data-misconfig-key]');
    if (!row) return;
    openMisconfigModal(row.dataset.misconfigKey);
  });

  document.getElementById('secrets-table-body').addEventListener('click', (e) => {
    const row = e.target.closest('[data-secret-key]');
    if (!row) return;
    openSecretModal(row.dataset.secretKey);
  });

  document.getElementById('compliance-frameworks-grid').addEventListener('click', (e) => {
    const row = e.target.closest('[data-fw-idx]');
    if (!row) return;
    openComplianceModal(parseInt(row.dataset.fwIdx, 10), parseInt(row.dataset.controlIdx, 10));
  });

  const modalBody = document.getElementById('modal-body');
  modalBody.addEventListener('click', (e) => {
    const compRow = e.target.closest('[data-component-id]');
    if (compRow && modalBody.contains(compRow)) {
      e.stopPropagation();
      openComponentModal(compRow.dataset.componentId);
      return;
    }
    const vulnRow = e.target.closest('[data-vuln-key]');
    if (vulnRow && modalBody.contains(vulnRow)) {
      e.stopPropagation();
      openVulnModal(vulnRow.dataset.vulnKey);
      return;
    }
    const matchRow = e.target.closest('[data-match-index]');
    if (matchRow && modalBody.contains(matchRow)) {
      e.stopPropagation();
      const idx = parseInt(matchRow.dataset.matchIndex, 10);
      const v = _currentComplianceMatches && _currentComplianceMatches[idx];
      if (v) openVulnModal(vulnKey(v));
    }
  });

  updateTabCounts();
  renderDashboard();
  applyScopeFilters();
  applyComponentFilters();
  applyVulnFilters();
  populateMisconfigCategories();
  applyMisconfigFilters();
  applySecretFilters();
  renderScanInfo();
  renderCompliance();
  renderStats();
});

// ── TAB LABEL COUNTS ─────────────────────────────────────────────────────────

function updateTabCounts() {
  document.getElementById('tab-scope').textContent = 'Scope(' + ((reportData.assets || []).length) + ')';
  document.getElementById('tab-components').textContent = 'Components(' + reportData.stats.component_count + ')';
  document.getElementById('tab-vulns').textContent = 'Vulnerabilities(' + reportData.stats.total_vulnerabilities + ')';
  document.getElementById('tab-misconfigs').textContent = 'Misconfigurations(' + ((reportData.misconfigurations || []).length) + ')';
  document.getElementById('tab-secrets').textContent = 'Secrets(' + ((reportData.secrets || []).length) + ')';
  const cs = reportData.compliance_summary;
  document.getElementById('tab-compliance').textContent = 'Compliance(' + (cs && cs.frameworks ? cs.frameworks.length : 0) + ')';
}
`;
}