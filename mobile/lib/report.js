'use strict';
// report.js — turns findings into the report payload (JSON), the plain-language executive summary
// and a self-contained HTML report (no external assets, everything escaped).

import { SEVERITIES, SEVERITY_RANK } from './rules.js';
import { getTailwindScript } from '../../sca/tailwindcss.js';
import { getChartJSScript } from '../../sca/chartjs.js';
import { getGoogleFontsScript } from '../../sca/googlefonts.js';
import { getComplianceForSecret, getComplianceForSastFinding, summarizeCompliance } from '../../sca/compliance_mappings.js';

export const LIMITS = [
  'Static analysis only: the app is never executed or uploaded. When supported dependency package URLs and exact versions are identified, only those identifiers/versions are sent to OSV.dev through UBEL’s shared SCA engine; app source, binaries, manifests and secrets are not uploaded.',
  'There is no decompiler: findings come from the manifest/plist, resources, constant tables, API references and call arguments, and binary metadata — not from data-flow analysis. Items marked low or medium confidence are leads to verify.',
  'Obfuscated or packed code, encrypted strings, native/Hermes bytecode and code downloaded at runtime are only partly visible.',
  'Hardcoded-secret detection uses UBEL’s shared secrets rules; a match proves the string is in the package, not that the credential is still valid.',
];

const MASVS_FRAMEWORK = {
  id: 'owasp_masvs_mobile',
  name: 'OWASP Mobile Application Security Verification Standard (MASVS)',
  version: null,
};

const MISCONFIG_RULE = /^(?:android\.(?:manifest|nsc|cordova|signing|native)\.|ios\.(?:plist|profile|macho)\.|bundle\.debug_build$|rn\.dev_bundle$|unity\.(?:development_build|certificate_handler)$|dotnet\.(?:tls_validation_disabled|debug_build)$|android\.dex\.(?:build_debug|debug_libraries|weak_tls_protocol|trust_all_certs|allow_all_hostnames|custom_trust_manager|webview_ssl_proceed|webview_js_interface|webview_file_access|webview_mixed_content|webview_debugging|cleartext_urls|world_accessible_storage|external_storage)$|ios\.code\.(?:tls_validation_disabled|custom_auth_challenge|cleartext_urls|no_pinning|wkwebview_file_access|uiwebview|keychain_always|file_protection_none)$)/;

export function isMisconfigurationFinding(finding) {
  return MISCONFIG_RULE.test(String(finding?.rule || ''));
}

export function isSecretFinding(finding) {
  return String(finding?.rule || '').startsWith('secret.');
}

/** Everything that is neither a hardcoded secret nor a misconfiguration: insecure code, crypto, storage and data handling. */
export function isVulnerabilityFinding(finding) {
  return !isSecretFinding(finding) && !isMisconfigurationFinding(finding);
}

/**
 * Every issue belongs to exactly one category, so the three report lists never overlap:
 *   secret            — hardcoded secrets (`secret.*`)
 *   misconfiguration  — manifest / plist / signing / binary-hardening / TLS-and-WebView settings (MISCONFIG_RULE)
 *   vulnerability     — all the rest
 */
export function findingCategory(finding) {
  if (isSecretFinding(finding)) return 'secret';
  if (isMisconfigurationFinding(finding)) return 'misconfiguration';
  return 'vulnerability';
}

/** The three disjoint lists of a report payload, concatenated in a fixed order (vulnerabilities, secrets, misconfigurations). */
export function flattenFindings(payload) {
  return [
    ...(payload?.vulnerabilities || []),
    ...(payload?.secrets || []),
    ...(payload?.misconfigurations || []),
  ];
}

export function complianceForMobileFinding(finding) {
  const cwes = finding?.cwe ? [finding.cwe] : [];
  const base = isSecretFinding(finding)
    ? getComplianceForSecret()
    : getComplianceForSastFinding(finding?.rule, cwes);
  const categories = [...new Set(base?.categories || [])];
  const frameworks = (base?.frameworks || []).map(fw => ({ ...fw, controls: [...(fw.controls || [])] }));
  const controlId = String(finding?.masvs || '').trim();
  if (controlId) {
    let masvs = frameworks.find(fw => fw.id === MASVS_FRAMEWORK.id);
    if (!masvs) {
      masvs = { ...MASVS_FRAMEWORK, controls: [] };
      frameworks.push(masvs);
    }
    if (!masvs.controls.some(control => control.id === controlId)) {
      masvs.controls.push({ id: controlId, title: controlId });
    }
  }
  return { categories, frameworks };
}

function buildMobileStats(findings, apps) {
  const byRule = {};
  const byOrigin = { app: 0, unknown: 0, library: 0 };
  const byConfidence = { high: 0, medium: 0, low: 0 };
  const byApp = {};
  for (const finding of findings) {
    const rule = String(finding.rule || 'unknown');
    byRule[rule] = (byRule[rule] || 0) + 1;
    const origin = finding.origin === 'library' ? 'library' : finding.origin === 'unknown' ? 'unknown' : 'app';
    byOrigin[origin]++;
    const confidence = ['high', 'medium', 'low'].includes(finding.confidence) ? finding.confidence : 'low';
    byConfidence[confidence]++;
    const appName = finding.app || (apps.length === 1 ? (apps[0].package || apps[0].bundle_id || apps[0].name) : 'Not attributed to one app');
    byApp[appName || 'Unknown app'] = (byApp[appName || 'Unknown app'] || 0) + 1;
  }
  return { by_rule: byRule, by_origin: byOrigin, by_confidence: byConfidence, by_app: byApp };
}

export function buildPayload({ meta, target, apps, findings, dependencies = [], dependencySummary = null, notes, diffs }) {
  const sorted = findings.sorted().map(f => ({ ...f, category: findingCategory(f), compliance: complianceForMobileFinding(f) }));
  // Disjoint partition: each issue lands in exactly one of these lists.
  const vulnerabilities = sorted.filter(f => f.category === 'vulnerability');
  const secrets = sorted.filter(f => f.category === 'secret');
  const misconfigurations = sorted.filter(f => f.category === 'misconfiguration');
  const counts = Object.fromEntries(SEVERITIES.map(severity => [severity, 0]));
  const byMasvs = {};
  for (const f of sorted) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    const k = String(f.masvs || 'Unmapped').replace(/-\d+$/, '');
    byMasvs[k] = (byMasvs[k] || 0) + 1;
  }
  const highest = SEVERITIES.find(s => counts[s] > 0) || 'none';
  const payload = {
    schema: 'ubel-mobile/2', tool: 'ubel-mobile', ...meta,
    target, apps,
    // `total` / `counts` / `by_masvs` cover all three lists together (they drive the risk rating and the --fail-on gate);
    // `by_category` says how that total splits.
    summary: {
      total: sorted.length, counts, highest_severity: highest, by_masvs: byMasvs,
      by_category: { vulnerabilities: vulnerabilities.length, secrets: secrets.length, misconfigurations: misconfigurations.length },
    },
    stats: buildMobileStats(sorted, apps),
    vulnerabilities,
    secrets,
    misconfigurations,
    dependencies: Array.isArray(dependencies) ? dependencies : [],
    dependency_summary: dependencySummary || { total: 0, queryable: 0, vulnerable_dependencies: 0, vulnerabilities: 0, clean_dependencies: 0, not_queryable: 0, lookup_errors: 0, by_severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 } },
    analysis_notes: notes,
    limits: LIMITS,
    diffs: diffs || null,
  };
  payload.compliance_summary = summarizeCompliance(sorted.map(f => f.compliance));
  payload.compliance_summary.disclaimer = `${payload.compliance_summary.disclaimer} Mobile findings are mapped to their catalogued MASVS control and, where a CWE mapping exists, to general security-framework references. This is guidance, not a certified assessment.`;
  payload.executive_summary = executiveSummary(payload);
  // Coverage: places the scan could not look. A clean list over incomplete coverage must not read as "all clear".
  const gaps = Array.isArray(notes?.gaps) ? [...notes.gaps] : [];
  payload.analysis = { complete: gaps.length === 0, gaps };
  if (gaps.length) {
    const es = payload.executive_summary;
    if (es.rating === 'No issues found') { es.rating = 'No issues found (analysis incomplete)'; es.headline = 'Nothing was found in the parts of the package that could be analysed, but some parts could not be.'; }
    es.paragraphs.push(`Coverage is incomplete: ${gaps.length} part(s) of the package could not be examined (${gaps.slice(0, 3).join('; ')}${gaps.length > 3 ? '; …' : ''}). Findings there, if any, are not in this report. See the analysis notes.`);
  }
  return payload;
}

// ── executive summary ──────────────────────────────────────────────────────────────────────────────
const MASVS_LABEL = {
  'MASVS-STORAGE': 'data storage', 'MASVS-CRYPTO': 'cryptography and key handling', 'MASVS-AUTH': 'authentication', 'MASVS-NETWORK': 'network communication',
  'MASVS-PLATFORM': 'interaction with the operating system and other apps', 'MASVS-CODE': 'code quality and build hygiene', 'MASVS-RESILIENCE': 'resistance to tampering and debugging',
  'MASVS-PRIVACY': 'user privacy',
};

export function executiveSummary(p) {
  const c = p.summary.counts;
  const appNames = p.apps.map(a => (a.platform === 'ios' ? `${a.name || a.bundle_id} (${a.bundle_id})` : `${a.package}`));
  const platform = p.apps.some(a => a.platform === 'ios') ? 'iOS' : 'Android';
  let rating, headline;
  if (c.critical > 0 || c.high >= 3) { rating = 'High risk'; headline = 'Serious weaknesses were found that should be fixed before this app is released or kept in production.'; }
  else if (c.high > 0) { rating = 'Elevated risk'; headline = 'At least one significant weakness was found; fix it soon.'; }
  else if (c.medium > 0) { rating = 'Moderate risk'; headline = 'No severe problems were found, but several configuration weaknesses deserve attention.'; }
  else if (c.low + c.info > 0) { rating = 'Low risk'; headline = 'Only minor or informational points were found.'; }
  else { rating = 'No issues found'; headline = 'The automated checks found nothing to report.'; }
  // The three lists are disjoint; merge and re-rank them so the most severe issues come first whatever their category.
  const all = flattenFindings(p).sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
  const top = all.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 6)
    .map(f => ({ severity: f.severity, title: f.title, where: f.artifact, category: f.category || findingCategory(f) }));
  const bc = p.summary.by_category || {};
  const areas = Object.entries(p.summary.by_masvs).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => MASVS_LABEL[k] || k.toLowerCase());
  const paragraphs = [
    `This report covers the ${platform} app ${appNames.join(', ') || 'in the scanned package'}. The package was examined without running it: its configuration, embedded files, code and resources were inspected for hardcoded secrets, insecure data handling and risky settings, and the results are mapped to the OWASP Mobile Application Security Verification Standard (MASVS).`,
    `${p.summary.total} issue(s) were recorded — ${bc.vulnerabilities || 0} vulnerabilit${bc.vulnerabilities === 1 ? 'y' : 'ies'}, ${bc.secrets || 0} hardcoded secret(s) and ${bc.misconfigurations || 0} misconfiguration(s) — rated ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low and ${c.info} informational.${areas.length ? ` Most of them concern ${areas.join(', ')}.` : ''}`,
    c.critical + c.high > 0
      ? 'Critical and high issues can usually be exploited by anyone who can download the app (for example by extracting a secret from the package) or by another app on the same device. They are listed first below.'
      : 'None of the issues is rated critical or high.',
  ];
  const actions = [];
  const seen = new Set();
  for (const f of all) {
    if (seen.has(f.rule) || f.severity === 'info') continue;
    seen.add(f.rule);
    actions.push(f.remediation);
    if (actions.length >= 6) break;
  }
  return { rating, headline, paragraphs, top_findings: top, recommended_actions: actions, scope_and_limits: LIMITS };
}

// ── HTML ───────────────────────────────────────────────────────────────────────────────────────────
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export async function buildHtml(p) {
  const [tailwind, chartjs, googleFonts] = await Promise.all([
    getTailwindScript(), getChartJSScript(), getGoogleFontsScript(),
  ]);
  const c = p.summary?.counts || {};
  const es = p.executive_summary || executiveSummary(p);
  const targetFile = p.target?.file || 'Unknown file';
  const appNames = (p.apps || []).map(a => a.package || a.bundle_id || a.name).filter(Boolean);
  const appLabel = appNames.join(', ') || targetFile;
  // Three disjoint lists; `all` (same order the page script rebuilds) is what the detail modal indexes into.
  const vulns = p.vulnerabilities || [];
  const secrets = p.secrets || [];
  const misconfigs = p.misconfigurations || [];
  const all = flattenFindings(p);
  const dependencies = p.dependencies || [];
  const dependencySummary = p.dependency_summary || {};
  const dependencyStatusLabel = { vulnerable: 'Vulnerable', clean: 'Safe', not_queryable: 'Not queried', lookup_error: 'Lookup failed', lookup_incomplete: 'Lookup incomplete', pending: 'Pending' };
  const severityColors = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3' };
  const total = all.length;
  const appIdentity = a => a.platform === 'ios' ? (a.name || a.bundle_id || 'iOS app') : (a.package || a.name || 'Android app');
  const appVersion = a => a.platform === 'ios' ? `${a.version || '?'} (${a.build || '?'})` : `${a.version_name || '?'} (${a.version_code || '?'})`;
  const appPlatform = a => a.platform === 'ios' ? 'iOS' : 'Android';
  const appRows = (p.apps || []).map((a, i) => {
    const id = a.platform === 'ios' ? a.bundle_id : a.package;
    const scope = a.platform === 'ios' ? (a.min_os ? `iOS ${a.min_os}+` : 'iOS') : `min ${a.min_sdk ?? '?'} / target ${a.target_sdk ?? '?'}`;
    const componentCount = a.platform === 'ios'
      ? (a.frameworks || []).length + (a.extensions || []).length
      : Object.values(a.components || {}).reduce((sum, n) => sum + Number(n || 0), 0) + (a.native_libs || []).length;
    return `<tr class="border-b border-neutral-800 hover:bg-neutral-900 cursor-pointer" data-app-index="${i}" title="Open app metadata">
      <td class="px-4 py-3">${esc(appPlatform(a))}</td>
      <td class="px-4 py-3 font-semibold">${esc(appIdentity(a))}</td>
      <td class="px-4 py-3 mono text-xs">${esc(id || '—')}</td>
      <td class="px-4 py-3 mono text-xs">${esc(appVersion(a))}</td>
      <td class="px-4 py-3 text-xs">${esc(scope)}</td>
      <td class="px-4 py-3 text-right mono">${Number(componentCount)}</td>
    </tr>`;
  }).join('');

  const dependencyRows = dependencies.map((dep, i) => {
    const status = dep.lookup_status || 'not_queryable';
    const badgeClass = status === 'vulnerable' ? 'text-red-400 border-red-500/50 bg-red-500/10' : status === 'clean' ? 'text-green-400 border-green-500/50 bg-green-500/10' : status === 'lookup_error' || status === 'lookup_incomplete' ? 'text-orange-300 border-orange-500/50 bg-orange-500/10' : 'text-neutral-400 border-neutral-700 bg-neutral-800/50';
    const sources = Array.isArray(dep.sources) ? dep.sources : [];
    return `<tr class="border-b border-neutral-800 hover:bg-neutral-900 cursor-pointer" data-dependency-index="${i}" data-dependency-row="true" data-status="${esc(status)}" title="Open dependency and OSV advisory details">
      <td class="px-4 py-3 font-semibold min-w-[12rem]">${esc(dep.name || 'Unknown dependency')}</td>
      <td class="px-4 py-3 mono text-xs whitespace-nowrap">${esc(dep.version || 'unknown')}</td>
      <td class="px-4 py-3 text-xs">${esc(dep.ecosystem || 'Unknown')}</td>
      <td class="px-4 py-3 mono text-xs break-all">${esc(dep.purl || dep.coordinate || 'identity unavailable')}</td>
      <td class="px-4 py-3"><span class="px-2 py-1 rounded border text-[10px] font-semibold ${badgeClass}">${esc(dependencyStatusLabel[status] || status)}</span></td>
      <td class="px-4 py-3 text-right mono">${Number(dep.vulnerability_count || 0)}</td>
      <td class="px-4 py-3 text-xs text-neutral-500 break-all">${esc(sources[0] || '—')}${sources.length > 1 ? ` (+${sources.length - 1} source(s))` : ''}</td>
    </tr>`;
  }).join('');

  const findingRows = (list, { clickable = true } = {}) => (list || []).map(f => {
    const index = all.indexOf(f);
    const origin = f.origin === 'library' ? 'library' : f.origin === 'unknown' ? 'unknown' : 'app';
    const app = f.app || (p.apps?.length === 1 ? appIdentity(p.apps[0]) : '—');
    return `<tr class="border-b border-neutral-800 ${clickable ? 'hover:bg-neutral-900 cursor-pointer' : ''}"
      ${clickable ? `data-finding-index="${index}"` : ''}
      data-finding-row="true" data-severity="${esc(f.severity || 'info')}" data-origin="${esc(origin)}"
      data-masvs="${esc(String(f.masvs || 'Unmapped').replace(/-\d+$/, ''))}" data-rule="${esc(f.rule || '')}">
      <td class="px-4 py-3 whitespace-nowrap"><span class="px-2 py-1 rounded border text-xs uppercase font-bold severity-${esc(f.severity || 'info')}">${esc(f.severity || 'info')}</span></td>
      <td class="px-4 py-3 font-semibold min-w-[15rem]">${esc(f.title || f.rule || 'Untitled finding')}</td>
      <td class="px-4 py-3">${esc(app)}</td>
      <td class="px-4 py-3 mono text-xs break-all">${esc(f.artifact || '—')}${f.line ? `:${esc(f.line)}` : ''}</td>
      <td class="px-4 py-3 mono text-xs">${esc(f.masvs || 'Unmapped')}</td>
      <td class="px-4 py-3 text-xs">${esc(f.confidence || 'unknown')}</td>
    </tr>`;
  }).join('');

  const vulnRows = findingRows(vulns);
  const secretRows = findingRows(secrets);
  const misconfigRows = findingRows(misconfigs);

  const statsByMasvs = Object.entries(p.summary?.by_masvs || {}).sort((a, b) => b[1] - a[1]);
  const statsByRule = Object.entries(p.stats?.by_rule || {}).sort((a, b) => b[1] - a[1]).slice(0, 30);
  const statsByApp = Object.entries(p.stats?.by_app || {}).sort((a, b) => b[1] - a[1]);
  const kvRow = (label, value, extra = '') => `<div class="flex justify-between border-b border-neutral-800 pb-2 gap-4"><span class="text-neutral-500 text-xs">${esc(label)}</span><span class="mono text-xs text-right break-all ${extra}">${esc(value == null || value === '' ? '—' : String(value))}</span></div>`;
  const actions = es.recommended_actions?.length
    ? `<ol class="list-decimal pl-5 space-y-2 text-sm text-neutral-300">${es.recommended_actions.map(t => `<li>${esc(t)}</li>`).join('')}</ol>`
    : '<p class="text-sm text-neutral-500">No remediation actions were generated.</p>';
  const topFindings = es.top_findings?.length
    ? es.top_findings.map(f => `<div class="glass p-4 rounded-xl" style="border-left:4px solid ${severityColors[f.severity] || '#a3a3a3'}"><h4 class="font-semibold text-sm mb-1">${esc(f.title)}</h4><p class="text-xs text-neutral-400">${esc(f.where || '')}</p></div>`).join('')
    : '<div class="glass p-4 rounded-xl text-sm text-neutral-400">No critical or high issues were reported.</div>';
  const scopeLimits = (es.scope_and_limits || p.limits || []).map(x => `<li>${esc(x)}</li>`).join('');
  const safeJson = JSON.stringify(p).replace(/[<>&\u2028\u2029]/g, ch => ({ '<': '\\u003c', '>': '\\u003e', '&': '\\u0026', '\u2028': '\\u2028', '\u2029': '\\u2029' }[ch]));
  const countCards = [
    ['critical', 'Critical', 'red-500'], ['high', 'High', 'red-400'], ['medium', 'Medium', 'orange-400'],
    ['low', 'Low', 'blue-400'], ['info', 'Info', 'neutral-500'], ['total', 'Total Issues', 'neutral-500'],
  ].map(([key, label, color]) => `<div class="glass p-6 rounded-xl border-l-4 border-l-${color}"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${label}</p><p class="text-3xl font-bold ${key === 'total' ? 'text-neutral-300' : `text-${color}`}" id="stat-${key}">${key === 'total' ? total : Number(c[key] || 0)}</p></div>`).join('');
  const severityChartColors = ['#ef4444', '#f87171', '#fb923c', '#60a5fa', '#a3a3a3'];
  const ruleOptions = list => [...new Set(list.map(f => f.rule).filter(Boolean))].sort().map(rule => `<option value="${esc(rule)}">${esc(rule)}</option>`).join('');
  const misconfigOptions = ruleOptions(misconfigs);
  const secretOptions = ruleOptions(secrets);
  const masvsOptions = [...new Set(vulns.map(f => String(f.masvs || 'Unmapped').replace(/-\d+$/, '')))].sort().map(value => `<option value="${esc(value)}">${esc(value)}</option>`).join('');

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(p.tool || 'ubel-mobile')} — Mobile Application Security Report</title>
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
    .severity-info, .severity-unknown { color: #a3a3a3; border-color: #a3a3a3; }
    .severity-infection{ color: #c084fc; border-color: #c084fc; font-weight: bold; }
    .state-infected     { color: #c084fc; border-color: #c084fc; font-weight: bold; }
    .state-vulnerable   { color: #ef4444; border-color: #ef4444; }
    .state-safe         { color: #4ade80; border-color: #4ade80; }
    .state-undetermined { color: #a3a3a3; border-color: #a3a3a3; }
    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg); }
    ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 10px; }
    .tab-active { border-bottom: 2px solid var(--accent); color: white; }
    .modal-overlay { display: none; position: fixed; top:0; left:0; width:100%; height:100%; background: rgba(0,0,0,0.85); z-index:50; backdrop-filter: blur(4px); }
    .modal-content { max-height: 90vh; overflow-y: auto; }
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
      <div class="flex items-center gap-3">
        <div class="w-8 h-8 bg-red-600 rounded flex items-center justify-center font-bold text-white text-sm">U</div>
        <div>
          <h1 class="text-lg font-semibold tracking-tight">Mobile Application Security Report</h1>
          <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ${esc(p.generated_at || 'unknown')}</p>
        </div>
      </div>
      <span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider bg-red-500/20 text-red-400 border border-red-500/50">${esc(p.tool || 'ubel-mobile')}${p.tool_version ? ` v${esc(p.tool_version)}` : ''}</span>
    </div>
  </header>

  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('executive')" id="tab-executive" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Executive Summary</button>
      <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">App Inventory(${(p.apps || []).length})</button>
      <button onclick="switchTab('dependencies')" id="tab-dependencies" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Dependencies(${dependencies.length})</button>
      <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Vulnerabilities(${vulns.length})</button>
      <button onclick="switchTab('secrets')" id="tab-secrets" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Secrets(${secrets.length})</button>
      <button onclick="switchTab('misconfigs')" id="tab-misconfigs" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Misconfigurations(${misconfigs.length})</button>
      <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Compliance(${(p.compliance_summary?.frameworks || []).length})</button>
      <button onclick="switchTab('diffs')" id="tab-diffs" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Diffs</button>
      <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
      <button onclick="switchTab('scaninfo')" id="tab-scaninfo" class="py-4 text-sm font-medium text-neutral-400 hover:text-white transition-colors">Scan Info</button>
    </div>
  </nav>

  <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
    <section id="section-dashboard" class="space-y-8">
      <div class="grid grid-cols-2 md:grid-cols-6 gap-4">${countCards}</div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Issues by Severity</h3><div class="h-56"><canvas id="severityChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Issues by MASVS Area</h3><div class="h-56"><canvas id="masvsChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Issues by Origin</h3><div class="h-56"><canvas id="originChart"></canvas></div></div>
      </div>
    </section>

    <section id="section-executive" class="hidden space-y-8">
      <div id="executive-content" class="space-y-8">
        <div class="glass p-5 rounded-xl">
          <p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest mb-1">Mobile application security summary</p>
          <h2 class="text-2xl font-bold mb-3 break-all">${esc(appLabel)}</h2>
          <div class="flex flex-wrap gap-x-8 gap-y-1 text-xs"><div><span class="text-neutral-500">Report ID: </span><span class="mono text-neutral-300">${esc(p.report_id || '—')}</span></div><div><span class="text-neutral-500">Generated: </span><span class="mono text-neutral-300">${esc(p.generated_at || '—')}</span></div><div><span class="text-neutral-500">Tool: </span><span class="mono text-neutral-300">${esc(p.tool || 'ubel-mobile')}</span></div></div>
        </div>
        <div class="glass p-6 md:p-8 rounded-xl" style="border-left:6px solid ${severityColors[c.critical > 0 ? 'critical' : c.high > 0 ? 'high' : c.medium > 0 ? 'medium' : c.low > 0 ? 'low' : 'info']}">
          <div class="flex flex-wrap items-center justify-between gap-3 mb-3"><div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Overall security risk</p><p class="text-4xl font-bold" style="color:${severityColors[c.critical > 0 ? 'critical' : c.high > 0 ? 'high' : c.medium > 0 ? 'medium' : c.low > 0 ? 'low' : 'info']}">${esc(es.rating || 'Unknown')}</p></div><span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider border ${c.critical + c.high > 0 ? 'bg-red-500/20 text-red-400 border-red-500/50' : c.medium > 0 ? 'bg-orange-500/20 text-orange-400 border-orange-500/50' : 'bg-neutral-800 text-neutral-300 border-neutral-700'}">${c.critical + c.high > 0 ? 'REVIEW REQUIRED' : c.medium > 0 ? 'REVIEW' : 'AUTOMATED CHECKS'}</span></div>
          <p class="text-lg leading-relaxed text-neutral-100 exec-headline">${esc(es.headline || '')}</p>
        </div>
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 exec-cols-2">
          <div><h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Top risks</h3><div class="space-y-3">${topFindings}</div></div>
          <div><h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Recommended actions</h3><div class="glass p-5 rounded-xl">${actions}</div></div>
        </div>
        <div class="grid grid-cols-2 lg:grid-cols-4 gap-4 exec-figs">
          ${[['Vulnerabilities', vulns.length, '#f87171'], ['Secrets', secrets.length, '#ef4444'], ['Misconfigurations', misconfigs.length, '#fb923c'], ['Critical + High', Number(c.critical || 0) + Number(c.high || 0), '#a3a3a3']].map(([label, value, color]) => `<div class="glass p-5 rounded-xl" style="border-left:4px solid ${color}"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${esc(label)}</p><p class="text-3xl font-bold" style="color:${color}">${value}</p></div>`).join('')}
        </div>
        <div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scope and limits</h3><ul class="list-disc pl-5 text-sm text-neutral-400 space-y-2">${scopeLimits || '<li>No scope notes were recorded.</li>'}</ul></div>
      </div>
    </section>

    <section id="section-inventory" class="hidden space-y-4">
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Platform</th><th class="px-4 py-3">Application</th><th class="px-4 py-3">Package / Bundle ID</th><th class="px-4 py-3">Version</th><th class="px-4 py-3">OS / SDK</th><th class="px-4 py-3 text-right">Components</th></tr></thead>
          <tbody id="apps-table-body" class="divide-y divide-neutral-800">${appRows || '<tr><td colspan="6" class="px-4 py-3 text-sm text-neutral-500">No app metadata was extracted.</td></tr>'}</tbody>
        </table>
      </div>
      <p class="text-xs text-neutral-500">Select an app row to inspect extracted package metadata. This is static package analysis; the app is not executed.</p>
    </section>

    <section id="section-dependencies" class="hidden space-y-4">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        ${[['Detected components', dependencySummary.total || dependencies.length, '#d4d4d4'], ['OSV-queryable', dependencySummary.queryable || 0, '#60a5fa'], ['Components with advisories', dependencySummary.vulnerable_dependencies || 0, '#f87171'], ['Advisory matches', dependencySummary.vulnerabilities || 0, '#fb923c']].map(([label, value, color]) => `<div class="glass p-5 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${esc(label)}</p><p class="text-2xl font-bold" style="color:${color}">${Number(value)}</p></div>`).join('')}
      </div>
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="dep-search" type="text" placeholder="Search package, version, PURL or source..." class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500" oninput="applyDependencyFilters()">
        <select id="dep-status" onchange="applyDependencyFilters()" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All lookup states</option><option value="vulnerable">Vulnerable</option><option value="clean">Safe</option><option value="not_queryable">Not queried</option><option value="lookup_error">Lookup failed</option><option value="lookup_incomplete">Lookup incomplete</option></select>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Dependency</th><th class="px-4 py-3">Version</th><th class="px-4 py-3">Ecosystem</th><th class="px-4 py-3">Package URL / Identity</th><th class="px-4 py-3">Status</th><th class="px-4 py-3 text-right">Advisories</th><th class="px-4 py-3">Evidence source</th></tr></thead>
          <tbody id="dependencies-table-body" class="divide-y divide-neutral-800">${dependencyRows || '<tr><td colspan="7" class="px-4 py-3 text-sm text-neutral-500">No dependency metadata was extracted from this package.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="dependencies-empty" class="hidden text-sm text-neutral-500 italic">No dependencies match the selected filters.</p>
      <p id="dependencies-filter-count" class="text-xs text-neutral-500"></p>
      <p class="text-xs text-neutral-500">Only exact, supported, versioned package URLs are queried. Native .so/.dylib binaries and embedded native frameworks are excluded from the Dependencies tab and are never submitted to OSV; native hardening and secret checks remain separate. If an APK/IPA omits its build lockfiles or package metadata, a package may remain Not queried rather than being reported as clean. Click a row to inspect advisory details and source evidence.</p>
    </section>

    <section id="section-vulnerabilities" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="v-search" type="text" placeholder="Search title, rule, artifact, evidence..." class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500">
        <select id="v-severity" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="v-origin" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All origins</option><option value="app">App / package</option><option value="unknown">Unattributed (renamed classes)</option><option value="library">Third-party library</option></select>
        <select id="v-masvs" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All MASVS areas</option>${masvsOptions}</select>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Severity</th><th class="px-4 py-3">Vulnerability</th><th class="px-4 py-3">App</th><th class="px-4 py-3">Artifact</th><th class="px-4 py-3">MASVS</th><th class="px-4 py-3">Confidence</th></tr></thead>
          <tbody id="vulnerabilities-table-body" class="divide-y divide-neutral-800">${vulnRows || '<tr><td colspan="6" class="px-4 py-3 text-sm text-neutral-500">No vulnerabilities detected.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="vulnerabilities-empty" class="hidden text-sm text-neutral-500 italic">No vulnerabilities match the selected filters.</p>
      <p id="vulnerabilities-filter-count" class="text-xs text-neutral-500"></p>
      <p class="text-xs text-neutral-500">Insecure code, cryptography, storage and data handling. Hardcoded secrets and configuration weaknesses are listed in their own tabs and never repeated here. Known-vulnerable third-party packages are on the Dependencies tab.</p>
    </section>

    <section id="section-secrets" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="s-search" type="text" placeholder="Search title, rule, artifact, app..." class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500">
        <select id="s-severity" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="s-rule" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All secret types</option>${secretOptions}</select>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Severity</th><th class="px-4 py-3">Title</th><th class="px-4 py-3">App</th><th class="px-4 py-3">Artifact</th><th class="px-4 py-3">Rule</th><th class="px-4 py-3">MASVS</th></tr></thead>
          <tbody id="secrets-table-body" class="divide-y divide-neutral-800">${secretRows || '<tr><td colspan="6" class="px-4 py-3 text-sm text-neutral-500">No hardcoded secrets detected.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="secrets-empty" class="hidden text-sm text-neutral-500 italic">No secrets match the selected filters.</p>
      <p id="secrets-filter-count" class="text-xs text-neutral-500"></p>
      <p class="text-xs text-neutral-500">Secret values are never written to the report; only a masked preview is shown. A match proves the string is in the package, not that the credential is still valid.</p>
    </section>

    <section id="section-misconfigs" class="hidden space-y-4">
      <div class="glass p-4 rounded-xl flex flex-wrap gap-3 items-center">
        <input id="m-search" type="text" placeholder="Search title, rule, artifact, app..." class="flex-1 min-w-[220px] bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none focus:border-red-500">
        <select id="m-severity" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="m-rule" class="bg-neutral-900 border border-neutral-700 rounded-lg px-3 py-2 text-sm"><option value="all">All rule categories</option>${misconfigOptions}</select>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left">
          <thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Severity</th><th class="px-4 py-3">Title</th><th class="px-4 py-3">App</th><th class="px-4 py-3">Artifact</th><th class="px-4 py-3">Rule</th><th class="px-4 py-3">MASVS</th></tr></thead>
          <tbody id="misconfigs-table-body" class="divide-y divide-neutral-800">${misconfigRows || '<tr><td colspan="6" class="px-4 py-3 text-sm text-neutral-500">No misconfigurations detected.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="misconfigs-empty" class="hidden text-sm text-neutral-500 italic">No misconfigurations match the selected filters.</p>
      <p id="misconfigs-filter-count" class="text-xs text-neutral-500"></p>
    </section>

    <section id="section-compliance" class="hidden space-y-8">
      <p id="compliance-disclaimer" class="text-xs text-neutral-500 italic bg-neutral-900/50 p-3 rounded-lg border border-neutral-800"></p>
      <div id="compliance-frameworks-grid" class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6"></div>
      <div id="compliance-empty" class="hidden text-sm text-neutral-500 italic">No issues mapped to a compliance framework.</div>
    </section>

    <section id="section-diffs" class="hidden space-y-6"></section>

    <section id="section-stats" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-8">
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Issue Counts</h3><div class="space-y-2 text-sm">
          ${[['Total issues', total, 'text-neutral-400'], ['Vulnerabilities', vulns.length, 'text-neutral-300'], ['Secrets', secrets.length, 'text-neutral-300'], ['Misconfigurations', misconfigs.length, 'text-neutral-300'], ['Critical', c.critical || 0, 'severity-critical'], ['High', c.high || 0, 'severity-high'], ['Medium', c.medium || 0, 'severity-medium'], ['Low', c.low || 0, 'severity-low'], ['Info', c.info || 0, 'severity-info']].map(([label, value, cls], i, rows) => `<div class="flex justify-between ${i < rows.length - 1 ? 'border-b border-neutral-800 pb-2' : ''}"><span class="${i === 0 ? 'text-neutral-500' : cls}">${esc(label)}</span><span class="mono ${i === 0 ? 'text-neutral-200' : cls}">${Number(value)}</span></div>`).join('')}
        </div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Issues by Origin</h3><div class="h-48"><canvas id="originStatsChart"></canvas></div><div class="space-y-2 text-sm"><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">App / package</span><span class="mono">${Number(p.stats?.by_origin?.app || 0)}</span></div><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Unattributed (renamed classes)</span><span class="mono">${Number(p.stats?.by_origin?.unknown || 0)}</span></div><div class="flex justify-between"><span class="text-neutral-500">Third-party library</span><span class="mono">${Number(p.stats?.by_origin?.library || 0)}</span></div></div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Confidence Distribution</h3><div class="h-48"><canvas id="confidenceChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Issues by MASVS Area</h3><div class="overflow-x-auto"><table class="w-full text-left"><thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Area</th><th class="px-4 py-3 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByMasvs.map(([k, v]) => `<tr><td class="px-4 py-3 mono">${esc(k)}</td><td class="px-4 py-3 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-4 py-3 text-neutral-500">No MASVS data.</td></tr>'}</tbody></table></div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Issues by App</h3><div class="overflow-x-auto"><table class="w-full text-left"><thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">App</th><th class="px-4 py-3 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByApp.map(([k, v]) => `<tr><td class="px-4 py-3 break-all">${esc(k)}</td><td class="px-4 py-3 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-4 py-3 text-neutral-500">No findings.</td></tr>'}</tbody></table></div></div>
        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Most Frequent Rules</h3><div class="overflow-x-auto"><table class="w-full text-left"><thead class="border-b border-neutral-800 text-xs text-neutral-500 uppercase tracking-wider"><tr><th class="px-4 py-3">Rule</th><th class="px-4 py-3 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByRule.map(([k, v]) => `<tr><td class="px-4 py-3 mono break-all">${esc(k)}</td><td class="px-4 py-3 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-4 py-3 text-neutral-500">No rule data.</td></tr>'}</tbody></table></div></div>
      </div>
    </section>

    <section id="section-scaninfo" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scan</h3><div class="space-y-3 text-sm">
          ${kvRow('Tool', p.tool || 'ubel-mobile')}${kvRow('Version', p.tool_version || 'unknown')}${kvRow('Generated at', p.generated_at || 'unknown')}${kvRow('Report ID', p.report_id || 'unknown')}${kvRow('Minimum severity filter', p.min_severity || 'info')}${kvRow('Hidden by filter', p.hidden_by_filter || 0)}
        </div></div>
        <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Target Artifact</h3><div class="space-y-3 text-sm">
          ${kvRow('File', targetFile)}${kvRow('Kind', p.target?.kind || 'unknown')}${kvRow('Size', `${(Number(p.target?.size_bytes || 0) / 1048576).toFixed(2)} MB`)}${kvRow('SHA-256', p.target?.sha256 || 'unknown')}${kvRow('Detected apps', (p.apps || []).length)}${kvRow('Asset name', p.asset_name || 'unknown')}${kvRow('Asset ID', p.asset_id || 'unknown')}${kvRow('Machine ID', p.machine_id || 'unknown')}
        </div></div>
      </div>
      <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Analysis Notes</h3>${(p.analysis_notes || []).length ? `<ul class="list-disc pl-5 text-sm text-neutral-400 space-y-2">${p.analysis_notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : '<p class="text-sm text-neutral-500">No analysis notes were recorded.</p>'}</div>
      <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scanner Scope and Limits</h3><ul class="list-disc pl-5 text-sm text-neutral-400 space-y-2">${(p.limits || []).map(n => `<li>${esc(n)}</li>`).join('')}</ul></div>
    </section>
  </main>

  <footer class="border-t border-neutral-800 p-6 bg-neutral-900/50">
    <div class="max-w-7xl mx-auto flex flex-col md:flex-row justify-between items-center gap-4"><p class="text-xs text-neutral-500">Powered by <span class="text-neutral-300 font-semibold">${esc(p.tool || 'ubel-mobile')}</span> — part of UBEL. For authorized use only.</p></div>
  </footer>

  <div id="modal-overlay" class="modal-overlay items-center justify-center p-4">
    <div class="modal-content glass w-full max-w-2xl rounded-2xl shadow-2xl relative">
      <button onclick="closeModal()" class="absolute top-6 right-6 text-neutral-500 hover:text-white transition-colors"><svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg></button>
      <div id="modal-body" class="p-8"></div>
    </div>
  </div>

  <script>
const reportData = ${safeJson};
// Same order as the server-side list the table rows index into: vulnerabilities, secrets, misconfigurations.
const allFindings = [].concat(reportData.vulnerabilities || [], reportData.secrets || [], reportData.misconfigurations || []);
const chartInstances = [];
function escH(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
function switchTab(id) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('tab-active'));
  const button = document.getElementById('tab-' + id); if (button) button.classList.add('tab-active');
  document.querySelectorAll('main section').forEach(section => section.classList.add('hidden'));
  const section = document.getElementById('section-' + id); if (section) section.classList.remove('hidden');
  chartInstances.forEach(chart => { try { chart.resize(); } catch (_) {} });
}
function closeModal() { document.getElementById('modal-overlay').style.display = 'none'; document.body.style.overflow = 'auto'; }
function openModal(html) { document.getElementById('modal-body').innerHTML = html; document.getElementById('modal-overlay').style.display = 'flex'; document.body.style.overflow = 'hidden'; }
function modalMetaRow(label, value) { return '<div class="flex justify-between border-b border-neutral-800 pb-2 gap-4"><span class="text-neutral-500 text-xs">' + escH(label) + '</span><span class="mono text-xs text-right text-neutral-200 break-all">' + escH(value == null || value === '' ? '—' : value) + '</span></div>'; }
const CATEGORY_LABEL = { vulnerability: 'Vulnerability', secret: 'Secret', misconfiguration: 'Misconfiguration' };
function openFindingModal(index) {
  const f = allFindings[index]; if (!f) return;
  const c = {critical:'#ef4444',high:'#f87171',medium:'#fb923c',low:'#60a5fa',info:'#a3a3a3'}[f.severity] || '#a3a3a3';
  const evidence = Array.isArray(f.evidence) && f.evidence.length ? '<div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Evidence</h3><ul class="list-disc pl-5 text-sm text-neutral-300 space-y-2">' + f.evidence.map(e => '<li><code class="mono text-xs break-all">' + escH(e) + '</code></li>').join('') + '</ul></div>' : '';
  const compliance = f.compliance && f.compliance.frameworks ? f.compliance.frameworks.map(fw => '<div class="text-xs text-neutral-300"><span class="font-semibold">' + escH(fw.name) + '</span>: ' + (fw.controls || []).map(x => escH(x.id)).join(', ') + '</div>').join('') : '';
  openModal('<div class="space-y-5"><div><div class="flex flex-wrap items-center gap-3 mb-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + c + ';border-color:' + c + '">' + escH(f.severity || 'info') + '</span><span class="mono text-xs text-neutral-500">' + escH(f.rule || '') + '</span></div><h2 class="text-xl font-bold pr-8">' + escH(f.title || 'Untitled finding') + '</h2><p class="text-sm text-neutral-400 mt-2">' + escH(f.description || '') + '</p></div><div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + escH(CATEGORY_LABEL[f.category] || 'Issue') + ' Details</h3>' + modalMetaRow('Artifact', (f.artifact || '') + (f.line ? ':' + f.line : '')) + modalMetaRow('Application', f.app || '—') + modalMetaRow('Origin', f.origin || 'app') + modalMetaRow('Confidence', f.confidence || 'unknown') + modalMetaRow('MASVS', f.masvs || 'Unmapped') + modalMetaRow('CWE', f.cwe || '—') + '</div>' + evidence + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Remediation</h3><p class="text-sm text-neutral-300">' + escH(f.remediation || 'Review this finding manually.') + '</p></div>' + (compliance ? '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Compliance Frameworks</h3>' + compliance + '</div>' : '') + '</div>');
}
function mobileComplianceMatches(frameworkName, controlId) {
  return allFindings.filter(f => (f.compliance?.frameworks || []).some(fw =>
    fw.name === frameworkName && (fw.controls || []).some(control => control.id === controlId)));
}
function mobileComplianceFrameworkMatches(frameworkName) {
  return allFindings.filter(f => (f.compliance?.frameworks || []).some(fw => fw.name === frameworkName));
}
function renderCompliance() {
  const cs = reportData.compliance_summary;
  const disclaimer = document.getElementById('compliance-disclaimer');
  const grid = document.getElementById('compliance-frameworks-grid');
  const empty = document.getElementById('compliance-empty');
  disclaimer.textContent = cs?.disclaimer || '';
  if (!cs || !Array.isArray(cs.frameworks) || !cs.frameworks.length) {
    empty.classList.remove('hidden');
    grid.innerHTML = '';
    return;
  }
  empty.classList.add('hidden');
  grid.innerHTML = cs.frameworks.map((fw, fwIdx) => {
    const frameworkCount = mobileComplianceFrameworkMatches(fw.name).length;
    const controls = (fw.controls || []).map((control, controlIdx) => {
      const count = mobileComplianceMatches(fw.name, control.id).length;
      return '<div class="flex items-start justify-between gap-2 text-xs border-b border-neutral-800 pb-1.5 last:border-0 cursor-pointer hover:bg-neutral-800/40 rounded px-1 -mx-1 transition-colors" onclick="openComplianceModal(' + fwIdx + ',' + controlIdx + ')">' +
        '<div class="flex flex-col min-w-0"><span class="mono text-red-400">' + escH(control.id) + '</span><span class="text-neutral-500">' + escH(control.title || control.id) + '</span></div>' +
        '<div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0"><span class="mono text-neutral-200">' + count + ' issue' + (count === 1 ? '' : 's') + '</span></div></div>';
    }).join('');
    return '<div class="glass p-6 rounded-xl space-y-4"><div class="flex items-start justify-between gap-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-300">' + escH(fw.name) + '</h3><div class="flex flex-col items-end gap-0.5 whitespace-nowrap shrink-0"><span class="mono text-red-400 font-semibold text-xs">' + frameworkCount + ' issue' + (frameworkCount === 1 ? '' : 's') + '</span></div></div>' +
      '<div class="space-y-1.5 max-h-64 overflow-y-auto pr-1">' + (controls || '<p class="text-xs text-neutral-500 italic">No mapped controls.</p>') + '</div></div>';
  }).join('');
}
function openComplianceModal(fwIdx, controlIdx) {
  const cs = reportData.compliance_summary;
  const fw = cs && cs.frameworks && cs.frameworks[fwIdx];
  const control = fw && fw.controls && fw.controls[controlIdx];
  if (!fw || !control) return;
  const matches = mobileComplianceMatches(fw.name, control.id);
  const rows = matches.map(f => {
    const index = allFindings.indexOf(f);
    const severity = String(f.severity || 'unknown').toLowerCase();
    return '<div class="flex items-center justify-between py-2 border-b border-neutral-800 last:border-0 cursor-pointer hover:bg-neutral-800/40 px-2 rounded transition-colors" onclick="openFindingModal(' + index + ')">' +
      '<div class="flex items-center gap-3 min-w-0"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-' + escH(severity) + '">' + escH(severity) + '</span><span class="text-xs text-white">' + escH(f.title || f.rule || 'Mobile issue') + '</span></div>' +
      '<div class="flex items-center gap-3 shrink-0"><span class="mono text-[10px] text-neutral-500">' + escH(f.artifact || '') + '</span><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" class="text-neutral-500"><polyline points="9 18 15 12 9 6"></polyline></svg></div></div>';
  }).join('');
  const body = rows || '<p class="text-sm text-neutral-500 italic py-2">No issues mapped to this control.</p>';
  openModal('<div class="space-y-4"><div><div class="flex items-center gap-3 mb-1 flex-wrap"><span class="mono text-red-400 text-sm">' + escH(control.id) + '</span><h2 class="text-lg font-semibold text-white">' + escH(control.title || control.id) + '</h2></div><p class="text-xs text-neutral-500">' + escH(fw.name) + (fw.version ? ' · ' + escH(fw.version) : '') + ' — ' + matches.length + ' issue' + (matches.length === 1 ? '' : 's') + '</p></div><div class="glass rounded-xl p-3 space-y-1">' + body + '</div></div>');
}
const DIFF_GROUPS = [
  { key: 'vulnerabilities', title: 'Vulnerabilities', cards: [
    { list: 'new', label: 'New vulnerabilities', count: 'new_vulnerabilities', color: 'text-red-400' },
    { list: 'unchanged', label: 'Still existing vulnerabilities', count: 'unchanged_vulnerabilities', color: 'text-yellow-400' },
    { list: 'removed', label: 'Fixed vulnerabilities', count: 'fixed_vulnerabilities', color: 'text-green-400' }
  ]},
  { key: 'secrets', title: 'Secrets', cards: [
    { list: 'new', label: 'New secrets', count: 'new_secrets', color: 'text-red-400' },
    { list: 'unchanged', label: 'Still existing secrets', count: 'unchanged_secrets', color: 'text-yellow-400' },
    { list: 'removed', label: 'Removed secrets', count: 'removed_secrets', color: 'text-green-400' }
  ]},
  { key: 'misconfigs', title: 'Misconfigs', cards: [
    { list: 'new', label: 'New misconfigurations', count: 'new_misconfigs', color: 'text-red-400' },
    { list: 'unchanged', label: 'Still existing misconfigurations', count: 'unchanged_misconfigs', color: 'text-yellow-400' },
    { list: 'removed', label: 'Fixed misconfigurations', count: 'fixed_misconfigs', color: 'text-green-400' }
  ]}
];
function renderDiffs() {
  const section = document.getElementById('section-diffs');
  const d = reportData.diffs;
  if (!d || !d.enabled || !d.previous || !d.counts) {
    section.innerHTML = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2></div><div class="glass rounded-xl p-6 text-sm text-neutral-400">No previous report found for this asset, so there is nothing to compare against.</div>';
    return;
  }
  let html = '<div class="flex flex-col md:flex-row gap-2 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Diffs</h2><p class="text-xs text-neutral-500 mono">vs previous report ' + escH(d.previous.report_id || d.previous_file || 'previous report') + (d.previous.generated_at ? ' (' + escH(d.previous.generated_at) + ')' : '') + '</p></div>';
  const renderDiffGroup = group => {
    let groupHtml = '<h3 class="text-lg font-bold pt-4">' + group.title + '</h3><div class="grid grid-cols-2 md:grid-cols-3 gap-4">';
    group.cards.forEach(card => {
      groupHtml += '<button type="button" onclick="openMobileDiffModal(&quot;' + group.key + '&quot;,&quot;' + card.list + '&quot;)" class="glass rounded-xl p-6 text-left hover:border-neutral-500 transition-colors aspect-square md:aspect-auto md:min-h-[9rem] flex flex-col justify-between"><span class="text-[10px] uppercase tracking-widest text-neutral-500 font-bold">' + card.label + '</span><span class="text-4xl font-bold mono ' + card.color + '">' + Number(d.counts[card.count] || 0) + '</span></button>';
    });
    return groupHtml + '</div>';
  };
  html += renderDiffGroup(DIFF_GROUPS[0]);
  html += renderDiffGroup(DIFF_GROUPS[1]);
  const compliance = d.compliance && d.compliance.frameworks || [];
  if (compliance.length) {
    html += '<h3 class="text-lg font-bold pt-4">Compliance</h3><p class="text-xs text-neutral-500">Issues mapped to each framework, compared with the previous report.</p><div class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">';
    compliance.forEach((fw, fwIdx) => {
      html += '<div class="glass rounded-xl p-5 space-y-3"><div><p class="font-semibold text-sm">' + escH(fw.name) + '</p>' + (fw.version ? '<p class="text-[10px] text-neutral-500 mono">' + escH(fw.version) + '</p>' : '') + '</div><div class="grid grid-cols-3 gap-2">';
      [['new', 'New', 'text-red-400'], ['unchanged', 'Existing', 'text-yellow-400'], ['removed', 'Resolved', 'text-green-400']].forEach(status => {
        html += '<button type="button" onclick="openMobileComplianceDiffModal(' + fwIdx + ',&quot;' + status[0] + '&quot;)" class="bg-neutral-900 border border-neutral-800 hover:border-neutral-500 rounded-lg p-3 text-left transition-colors"><span class="block text-[9px] uppercase tracking-widest text-neutral-500 font-bold">' + status[1] + '</span><span class="block text-2xl font-bold mono ' + status[2] + '">' + ((fw[status[0]] || []).length) + '</span></button>';
      });
      html += '</div></div>';
    });
    html += '</div>';
  }
  html += renderDiffGroup(DIFF_GROUPS[2]);
  section.innerHTML = html;
}
function openMobileDiffModal(group, list) {
  const d = reportData.diffs;
  const items = d && d[group] && d[group][list] || [];
  const labels = { new: 'New', unchanged: 'Still existing', removed: group === 'secrets' ? 'Removed' : 'Fixed' };
  const groupLabels = { vulnerabilities: 'vulnerabilities', secrets: 'secrets', misconfigs: 'misconfigurations' };
  const rows = items.map(item => '<tr><td class="py-2 pr-4 uppercase text-[10px] font-bold severity-' + escH(String(item.severity || 'unknown').toLowerCase()) + '">' + escH(item.severity || 'unknown') + '</td><td class="py-2 pr-4 font-medium">' + escH(item.title || item.rule || 'Untitled issue') + '</td><td class="py-2 pr-4 text-neutral-400">' + escH(item.app || '—') + '</td><td class="py-2 pr-4 mono text-neutral-400">' + escH(item.artifact || '—') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.rule || '—') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.masvs || '—') + '</td></tr>').join('');
  const body = rows ? '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' + ['Severity', 'Issue', 'App', 'Artifact', 'Rule', 'MASVS'].map(label => '<th class="pb-2 pr-4 font-bold">' + label + '</th>').join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">' + rows + '</tbody></table></div>' : '<p class="text-sm text-neutral-500 italic">None.</p>';
  openModal('<h3 class="text-lg font-bold mb-1">' + labels[list] + ' ' + groupLabels[group] + '</h3><p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}
function openMobileComplianceDiffModal(fwIdx, list) {
  const frameworks = reportData.diffs && reportData.diffs.compliance && reportData.diffs.compliance.frameworks || [];
  const fw = frameworks[fwIdx];
  if (!fw) return;
  const labels = { new: 'New', unchanged: 'Still existing', removed: 'Resolved' };
  const items = fw[list] || [];
  const rows = items.map(item => '<tr><td class="py-2 pr-4 text-neutral-400">' + escH(item.kind === 'secret' ? 'Secret' : item.kind === 'misconfig' ? 'Misconfiguration' : 'Vulnerability') + '</td><td class="py-2 pr-4 mono">' + escH(item.id || '') + '</td><td class="py-2 pr-4 uppercase text-[10px] font-bold severity-' + escH(String(item.severity || 'unknown').toLowerCase()) + '">' + escH(item.severity || 'unknown') + '</td><td class="py-2 pr-4 font-medium">' + escH(item.title || '') + '</td><td class="py-2 pr-4 mono text-neutral-400">' + escH(item.where || '') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.controls || '') + '</td></tr>').join('');
  const body = rows ? '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' + ['Type', 'ID', 'Severity', 'Title', 'Component / File', 'Controls'].map(label => '<th class="pb-2 pr-4 font-bold">' + label + '</th>').join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">' + rows + '</tbody></table></div>' : '<p class="text-sm text-neutral-500 italic">None.</p>';
  openModal('<h3 class="text-lg font-bold mb-1">' + escH(fw.name) + ' — ' + labels[list] + '</h3><p class="text-xs text-neutral-500 mb-6">' + items.length + ' item(s)</p>' + body);
}
function appDetails(index) {
  const a = reportData.apps[index]; if (!a) return;
  const rows = [];
  const add = (k, v) => { if (v !== undefined && v !== null && v !== '') rows.push(modalMetaRow(k, v)); };
  add('Platform', a.platform === 'ios' ? 'iOS' : 'Android');
  if (a.platform === 'ios') {
    add('Name', a.name); add('Bundle ID', a.bundle_id); add('Version', a.version); add('Build', a.build); add('Minimum iOS', a.min_os); add('Architectures', (a.architectures || []).join(', '));
    add('Binary', a.binary ? ('PIE ' + (a.binary.pie ? 'yes' : 'no') + ', encrypted ' + (a.binary.encrypted ? 'yes' : 'no') + ', signed ' + (a.binary.signed ? 'yes' : 'no') + (a.binary.swift ? ', Swift' : '')) : '—');
    add('Provisioning', a.provisioning ? [a.provisioning.type, a.provisioning.name, a.provisioning.team, 'expires ' + (a.provisioning.expires || '?')].filter(Boolean).join(' — ') : '—');
    add('URL schemes', (a.url_schemes || []).join(', ')); add('Frameworks', (a.frameworks || []).map(f => f.name + (f.version ? ' ' + f.version : '')).join(', ')); add('Extensions', (a.extensions || []).map(e => e.name).join(', ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; '));
  } else {
    add('Package', a.package); add('Version', (a.version_name || '?') + ' (' + (a.version_code || '?') + ')'); add('SDK', 'min ' + (a.min_sdk ?? '?') + ' / target ' + (a.target_sdk ?? '?'));
    add('Components', Object.entries(a.components || {}).map(([k,v]) => v + ' ' + k).join(', ')); add('Permissions', (a.permissions || []).length);
    add('Signing', a.signing ? (a.signing.schemes || []).join(', ') + ' — ' + (a.signing.certificates || []).map(cert => cert.subject + ' [' + cert.key + ', ' + cert.signature_algorithm + ']').join('; ') : '—');
    add('Frameworks', (a.frameworks || []).join(', ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; ')); add('Modules', (a.modules || []).map(m => m.name + ' (' + m.type + ')').join(', ')); add('DEX files', (a.dex_files || []).join(', ')); add('Native libraries', (a.native_libs || []).length); add('Embedded libraries', (a.libraries || []).map(l => l.name + ' ' + (l.version || '')).join(', '));
  }
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">App Inventory</p><h2 class="text-xl font-bold pr-8">' + escH(a.name || a.package || a.bundle_id || 'Application') + '</h2></div><div class="glass p-5 rounded-xl space-y-3">' + rows.join('') + '</div></div>');
}
function openDependencyModal(index) {
  const dep = (reportData.dependencies || [])[index]; if (!dep) return;
  const statusLabels = { vulnerable: 'Vulnerable', clean: 'Safe', not_queryable: 'Not queried', lookup_error: 'Lookup failed', lookup_incomplete: 'Lookup incomplete', pending: 'Pending' };
  const sources = [...(dep.sources || [])].map(s => '<li><code class="mono text-xs break-all">' + escH(s) + '</code></li>').join('') || '<li>Source path unavailable</li>';
  const sourceTypes = (dep.source_types || []).map(escH).join(', ') || 'Unknown';
  const advisories = (dep.vulnerabilities || []).map(v => {
    const sev = String(v.severity || 'unknown').toLowerCase();
    const color = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', moderate: '#fb923c', low: '#60a5fa', info: '#a3a3a3' }[sev] || '#a3a3a3';
    const id = v.url ? '<a class="underline text-red-300" href="' + escH(v.url) + '" target="_blank" rel="noopener noreferrer">' + escH(v.id) + '</a>' : escH(v.id || 'Unknown advisory');
    const aliases = (v.aliases || []).join(', ');
    const fixes = (v.fixed_versions || []).join(', ');
    return '<div class="glass p-4 rounded-xl space-y-2"><div class="flex flex-wrap items-center justify-between gap-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + color + ';border-color:' + color + '">' + escH(sev) + '</span><span class="mono text-xs">' + id + '</span></div><h4 class="font-semibold text-sm">' + escH(v.summary || v.id || 'OSV advisory') + '</h4>' + (v.details ? '<p class="text-xs text-neutral-400 whitespace-pre-wrap break-words">' + escH(v.details.slice(0, 5000)) + (v.details.length > 5000 ? '…' : '') + '</p>' : '') + '<div class="text-xs text-neutral-500 space-y-1">' + (aliases ? '<p>Aliases: ' + escH(aliases) + '</p>' : '') + '<p>Affected version: ' + escH(v.affected_dependency_version || dep.version || 'unknown') + '</p>' + (fixes ? '<p>Fixed versions: <span class="text-green-300">' + escH(fixes) + '</span></p>' : '<p>No fixed version supplied by OSV.</p>') + (v.published ? '<p>Published: ' + escH(v.published) + '</p>' : '') + (v.is_infection ? '<p class="text-purple-300 font-semibold">Malicious-package advisory</p>' : '') + '</div></div>';
  }).join('');
  const error = dep.lookup_error ? '<div class="border border-orange-500/40 bg-orange-500/10 rounded-lg p-3 text-xs text-orange-200">' + escH(dep.lookup_error) + '</div>' : '';
  const reason = dep.lookup_reason ? '<p class="text-sm text-neutral-400">' + escH(dep.lookup_reason) + '</p>' : '';
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">Mobile dependency</p><h2 class="text-xl font-bold pr-8 break-all">' + escH(dep.name || 'Unknown dependency') + '</h2><p class="text-xs text-neutral-500 mt-2">' + escH(dep.ecosystem || 'Unknown ecosystem') + ' · ' + escH(dep.version || 'version unavailable') + '</p></div><div class="glass p-5 rounded-xl space-y-3">' + modalMetaRow('OSV status', statusLabels[dep.lookup_status] || dep.lookup_status || 'Not queried') + modalMetaRow('Package URL', dep.purl || 'Not available') + modalMetaRow('Coordinate / identity', dep.coordinate || 'Not available') + modalMetaRow('Detection confidence', dep.confidence || 'unknown') + modalMetaRow('Evidence type', sourceTypes) + modalMetaRow('Known advisories', dep.vulnerability_count || 0) + '</div>' + reason + error + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Evidence source(s)</h3><ul class="list-disc pl-5 text-sm text-neutral-300 space-y-1">' + sources + '</ul></div><div class="space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">OSV advisories (' + (dep.vulnerabilities || []).length + ')</h3>' + (advisories || '<p class="text-sm text-neutral-500 italic">No OSV advisory details are attached to this dependency.</p>') + '</div></div>');
}
function applyDependencyFilters() {
  const q = (document.getElementById('dep-search').value || '').toLowerCase();
  const status = document.getElementById('dep-status').value;
  let shown = 0;
  const rows = document.querySelectorAll('#dependencies-table-body tr[data-dependency-row]');
  rows.forEach(row => {
    const ok = (!q || row.textContent.toLowerCase().includes(q)) && (status === 'all' || row.dataset.status === status);
    row.classList.toggle('hidden', !ok); if (ok) shown++;
  });
  document.getElementById('dependencies-filter-count').textContent = shown + ' of ' + rows.length + ' dependencies shown';
  document.getElementById('dependencies-empty').classList.toggle('hidden', shown > 0);
}
// One filter routine for the three issue tables (prefix = DOM id prefix of its search / severity / extra selects).
function applyIssueFilters(key, prefix, noun, extras) {
  const q = (document.getElementById(prefix + '-search').value || '').toLowerCase();
  const sev = document.getElementById(prefix + '-severity').value;
  const filters = extras.map(([id, attr]) => [document.getElementById(prefix + '-' + id).value, attr]);
  const rows = document.querySelectorAll('#' + key + '-table-body tr[data-finding-row]');
  let shown = 0;
  rows.forEach(row => {
    const ok = (!q || row.textContent.toLowerCase().includes(q)) && (sev === 'all' || row.dataset.severity === sev) && filters.every(([value, attr]) => value === 'all' || row.dataset[attr] === value);
    row.classList.toggle('hidden', !ok); if (ok) shown++;
  });
  document.getElementById(key + '-filter-count').textContent = shown + ' of ' + rows.length + ' ' + noun + ' shown';
  document.getElementById(key + '-empty').classList.toggle('hidden', shown > 0 || rows.length === 0);
}
function applyVulnerabilityFilters() { applyIssueFilters('vulnerabilities', 'v', 'vulnerabilities', [['origin', 'origin'], ['masvs', 'masvs']]); }
function applySecretFilters() { applyIssueFilters('secrets', 's', 'secrets', [['rule', 'rule']]); }
function applyMisconfigFilters() { applyIssueFilters('misconfigs', 'm', 'misconfigurations', [['rule', 'rule']]); }
function makeChart(id, type, labels, data, colors) {
  const el = document.getElementById(id); if (!el || !window.Chart || !labels.length) return;
  const chart = new Chart(el, { type, data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: '#171717', borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: true, plugins: { legend: { labels: { color: '#a3a3a3', boxWidth: 10 } } }, scales: type === 'bar' ? { x: { ticks: { color: '#a3a3a3' }, grid: { color: '#262626' } }, y: { beginAtZero: true, ticks: { precision: 0, color: '#a3a3a3' }, grid: { color: '#262626' } } } : {} } }); chartInstances.push(chart);
}
const severityKeys = ['critical','high','medium','low','info'];
const severityPalette = ['#ef4444','#f87171','#fb923c','#60a5fa','#a3a3a3'];
makeChart('severityChart','doughnut',severityKeys.map(s=>s.toUpperCase()),severityKeys.map(s=>Number(reportData.summary?.counts?.[s]||0)),severityPalette);
const masvsEntries=Object.entries(reportData.summary?.by_masvs||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);
makeChart('masvsChart','bar',masvsEntries.map(x=>x[0]),masvsEntries.map(x=>x[1]),masvsEntries.map((_,i)=>['#ef4444','#fb923c','#60a5fa','#a78bfa','#34d399','#f472b6','#facc15','#94a3b8'][i%8]));
makeChart('originChart','doughnut',['App / package','Unattributed (renamed)','Third-party library'],[Number(reportData.stats?.by_origin?.app||0),Number(reportData.stats?.by_origin?.unknown||0),Number(reportData.stats?.by_origin?.library||0)],['#ef4444','#a3a3a3','#60a5fa']);
makeChart('originStatsChart','doughnut',['App / package','Unattributed (renamed)','Third-party library'],[Number(reportData.stats?.by_origin?.app||0),Number(reportData.stats?.by_origin?.unknown||0),Number(reportData.stats?.by_origin?.library||0)],['#ef4444','#a3a3a3','#60a5fa']);
const confidenceKeys=['high','medium','low']; makeChart('confidenceChart','bar',confidenceKeys.map(s=>s.toUpperCase()),confidenceKeys.map(s=>Number(reportData.stats?.by_confidence?.[s]||0)),['#34d399','#fb923c','#f87171']);
renderCompliance();
renderDiffs();
['vulnerabilities','secrets','misconfigs'].forEach(key=>document.getElementById(key+'-table-body').addEventListener('click',e=>{const row=e.target.closest('[data-finding-index]');if(row)openFindingModal(Number(row.dataset.findingIndex));}));
document.getElementById('apps-table-body').addEventListener('click',e=>{const row=e.target.closest('[data-app-index]');if(row)appDetails(Number(row.dataset.appIndex));});
document.getElementById('dependencies-table-body').addEventListener('click',e=>{const row=e.target.closest('[data-dependency-index]');if(row)openDependencyModal(Number(row.dataset.dependencyIndex));});
document.getElementById('modal-overlay').addEventListener('click',e=>{if(e.target.id==='modal-overlay')closeModal();});
document.addEventListener('keydown',e=>{if(e.key==='Escape')closeModal();});
[[['v-search','v-severity','v-origin','v-masvs'],applyVulnerabilityFilters],[['s-search','s-severity','s-rule'],applySecretFilters],[['m-search','m-severity','m-rule'],applyMisconfigFilters]].forEach(([ids,fn])=>ids.forEach(id=>document.getElementById(id).addEventListener(id.endsWith('-search')?'input':'change',fn)));
['dep-search','dep-status'].forEach(id=>document.getElementById(id).addEventListener(id==='dep-search'?'input':'change',applyDependencyFilters));
applyVulnerabilityFilters(); applySecretFilters(); applyMisconfigFilters(); applyDependencyFilters();
  </script>
</body>
</html>`;
}

