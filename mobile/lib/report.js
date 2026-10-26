'use strict';
// report.js — turns findings into the report payload (JSON), the plain-language executive summary
// and a self-contained HTML report (no external assets, everything escaped).

import { BEHAVIOR_LABELS, functionsOf } from './behavior.js';
import { NATIVE_BEHAVIOR_LABELS, NATIVE_BEHAVIOR_INFO } from '../../binary/lib/behavior.js';
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

export const BINARY_LIMITS = [
  'Static analysis only: the file is never executed or loaded. Only the names and versions of recognised components (and Go / Rust / npm / Python packages) are sent to NVD and OSV.dev; the binary itself, its strings and any secrets are not uploaded.',
  'There is no disassembly or data-flow analysis: unknown memory-corruption bugs are not detected. Hardening flags, imported functions and version banners are indicators; items marked low or medium confidence are leads to verify.',
  'A known-vulnerable component shows that the vulnerable library code is present in the file (its version was read from the file), not that the affected function is reachable from the program.',
  'Packed or obfuscated code, encrypted strings and code downloaded at run time are only partly visible. Hardcoded-secret detection uses UBEL’s shared secrets rules; a match proves the string is in the file, not that the credential is still valid.',
];

const MASVS_FRAMEWORK = {
  id: 'owasp_masvs_mobile',
  name: 'OWASP Mobile Application Security Verification Standard (MASVS)',
  version: null,
};

const MISCONFIG_RULE = /^(?:binary\.(?!risky\.|component\.)|android\.(?:manifest|nsc|cordova|signing|native|online)\.|ios\.(?:plist|profile|macho)\.|bundle\.debug_build$|rn\.dev_bundle$|unity\.(?:development_build|certificate_handler)$|dotnet\.(?:tls_validation_disabled|debug_build)$|android\.dex\.(?:anti_analysis|build_debug|debug_libraries|weak_tls_protocol|trust_all_certs|allow_all_hostnames|custom_trust_manager|webview_ssl_proceed|webview_js_interface|webview_file_access|webview_mixed_content|webview_debugging|cleartext_urls|world_accessible_storage|external_storage)$|ios\.code\.(?:tls_validation_disabled|custom_auth_challenge|cleartext_urls|no_pinning|wkwebview_file_access|uiwebview|keychain_always|file_protection_none)$)/;

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
  if (controlId && !/^binary\./.test(String(finding?.rule || ''))) {          // MASVS is a mobile-app standard: native-binary findings keep their CWE mapping only
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
    limits: apps.length && apps.every(a => a.platform === 'binary') ? BINARY_LIMITS : LIMITS,
    diffs: diffs || null,
  };
  payload.compliance_summary = summarizeCompliance(sorted.map(f => f.compliance));
  const binaryOnly = apps.length > 0 && apps.every(a => a.platform === 'binary');
  payload.compliance_summary.disclaimer = binaryOnly
    ? `${payload.compliance_summary.disclaimer} Binary findings are mapped, where a CWE mapping exists, to general security-framework references. This is guidance, not a certified assessment.`
    : `${payload.compliance_summary.disclaimer} Mobile findings are mapped to their catalogued MASVS control and, where a CWE mapping exists, to general security-framework references. This is guidance, not a certified assessment.`;
  payload.executive_summary = executiveSummary(payload);
  // Coverage: places the scan could not look. A clean list over incomplete coverage must not read as "all clear".
  const gaps = Array.isArray(notes?.gaps) ? [...notes.gaps] : [];
  payload.analysis = { complete: gaps.length === 0, gaps };
  if (gaps.length) {
    const es = payload.executive_summary;
    if (es.rating === 'No issues found') { es.rating = 'No issues found (analysis incomplete)'; es.headline = `Nothing was found in the parts of the ${binaryOnly ? 'file' : 'package'} that could be analysed, but some parts could not be.`; }
    es.paragraphs.push(`Coverage is incomplete: ${gaps.length} part(s) of the ${binaryOnly ? 'file' : 'package'} could not be examined (${gaps.slice(0, 3).join('; ')}${gaps.length > 3 ? '; …' : ''}). Findings there, if any, are not in this report. See the analysis notes.`);
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
  const isBinary = p.apps.length > 0 && p.apps.every(a => a.platform === 'binary');
  const appNames = p.apps.map(a => (a.platform === 'binary' ? `${a.name}` : a.platform === 'ios' ? `${a.name || a.bundle_id} (${a.bundle_id})` : `${a.package}`));
  const platform = p.apps.some(a => a.platform === 'ios') ? 'iOS' : 'Android';
  const subject = isBinary ? 'binary' : 'app';
  let rating, headline;
  if (c.critical > 0 || c.high >= 3) { rating = 'High risk'; headline = `Serious weaknesses were found that should be fixed before this ${subject} is released or kept in production.`; }
  else if (c.high > 0) { rating = 'Elevated risk'; headline = 'At least one significant weakness was found; fix it soon.'; }
  else if (c.medium > 0) { rating = 'Moderate risk'; headline = 'No severe problems were found, but several weaknesses deserve attention.'; }
  else if (c.low + c.info > 0) { rating = 'Low risk'; headline = 'Only minor or informational points were found.'; }
  else { rating = 'No issues found'; headline = 'The automated checks found nothing to report.'; }
  // The three lists are disjoint; merge and re-rank them so the most severe issues come first whatever their category.
  const all = flattenFindings(p).sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9));
  const top = all.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 6)
    .map(f => ({ severity: f.severity, title: f.title, where: f.artifact, category: f.category || findingCategory(f) }));
  const bc = p.summary.by_category || {};
  const areas = Object.entries(p.summary.by_masvs).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => MASVS_LABEL[k] || k.toLowerCase());
  const counts = `${p.summary.total} issue(s) were recorded — ${bc.vulnerabilities || 0} vulnerabilit${bc.vulnerabilities === 1 ? 'y' : 'ies'}, ${bc.secrets || 0} hardcoded secret(s) and ${bc.misconfigurations || 0} misconfiguration(s) — rated ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low and ${c.info} informational.${areas.length ? ` Most of them concern ${areas.join(', ')}.` : ''}`;
  let paragraphs;
  if (isBinary) {
    const a = p.apps[0] || {}, t = p.target || {}, ds = p.dependency_summary || {};
    const fmt = a.format === 'pe' ? 'Windows PE' : a.format === 'macho' ? 'Mach-O' : 'ELF';
    const mb = Number(t.size_bytes || a.size_bytes || 0) / 1048576;
    const sev = ds.by_severity || {};
    const sevText = ['critical', 'high', 'medium', 'low'].filter(k => sev[k]).map(k => `${sev[k]} ${k}`).join(', ');
    const names = (p.dependencies || []).map(d => `${d.name} ${d.version || ''}`.trim());
    const comp = !ds.total ? 'No third-party components were recognised inside the file.'
      : `${ds.total} component(s) were recognised inside the file (${names.slice(0, 5).join(', ')}${names.length > 5 ? ', …' : ''}). ` + (ds.vulnerable_dependencies
        ? `${ds.vulnerable_dependencies} of them ${ds.vulnerable_dependencies === 1 ? 'has' : 'have'} known vulnerabilities: ${ds.vulnerabilities} advisory match(es)${sevText ? ` (${sevText})` : ''}. These are counted in the issues above and listed on the Components tab.`
        : 'None has a known advisory at scan time.') + (ds.lookup_errors ? ` ${ds.lookup_errors} component(s) could not be fully checked.` : '');
    paragraphs = [
      `This report covers the ${fmt}${a.arch ? ` (${a.arch})` : ''} file ${appNames.join(', ')}${mb ? `, ${mb.toFixed(1)} MB` : ''}. The file was examined without running it: its headers, imported functions, embedded strings and library version banners were inspected for missing build hardening, risky function use, hardcoded secrets and known-vulnerable components. It is not a search for memory-corruption bugs: that needs disassembly and data-flow analysis, which this scan does not do.`,
      counts,
      comp,
      c.critical + c.high > 0
        ? 'Critical and high issues should be fixed before the binary is shipped. A vulnerable component is compiled into the file, so it is fixed by updating the library and rebuilding; a version match shows the vulnerable code is present, not that it is reachable.'
        : 'None of the issues is rated critical or high.',
    ];
  } else {
    paragraphs = [
      `This report covers the ${platform} app ${appNames.join(', ') || 'in the scanned package'}. The package was examined without running it: its configuration, embedded files, code and resources were inspected for hardcoded secrets, insecure data handling and risky settings, and the results are mapped to the OWASP Mobile Application Security Verification Standard (MASVS).`,
      counts,
      c.critical + c.high > 0
        ? 'Critical and high issues can usually be exploited by anyone who can download the app (for example by extracting a secret from the package) or by another app on the same device. They are listed first below.'
        : 'None of the issues is rated critical or high.',
    ];
  }
  const actions = [];
  const seen = new Set();
  for (const f of all) {
    const key = String(f.rule || '').startsWith('binary.component.') ? `r:${f.remediation}` : f.rule;       // one action per rule; component advisories are told apart by their fix
    if (seen.has(key) || f.severity === 'info') continue;
    seen.add(key);
    actions.push(f.remediation);
    if (actions.length >= 6) break;
  }
  return { rating, headline, paragraphs, top_findings: top, recommended_actions: actions, scope_and_limits: p.limits || LIMITS };
}

// ── HTML ───────────────────────────────────────────────────────────────────────────────────────────
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const HARDENING_BADGE = {
  ok: 'text-green-400 border-green-500/50 bg-green-500/10', bad: 'text-red-400 border-red-500/50 bg-red-500/10',
  warn: 'text-orange-300 border-orange-500/50 bg-orange-500/10', na: 'text-neutral-400 border-neutral-700 bg-neutral-800/50',
};
const HARDENING_LABEL = {
  no_pie: 'No PIE', exec_stack: 'Executable stack', no_gnu_stack: 'No GNU_STACK', wx_segment: 'W+X segment', textrel: 'Text relocations',
  no_relro: 'No RELRO', partial_relro: 'Partial RELRO', no_canary: 'No stack canary', no_fortify: 'No FORTIFY', rpath: 'RPATH / RUNPATH',
  no_aslr: 'No ASLR', relocs_stripped: 'Relocations stripped', no_high_entropy_va: 'No high-entropy ASLR', no_nx: 'No DEP / NX', no_cfg: 'No CFG', no_safeseh: 'No SafeSEH', no_gs: 'No /GS cookie',
  not_stripped: 'Not stripped', static_linked: 'Statically linked',
  unsigned: 'Unsigned', adhoc_signed: 'Ad-hoc signature', no_hardened_runtime: 'No hardened runtime', get_task_allow: 'get-task-allow', dangerous_entitlement: 'Risky entitlement',
};

/**
 * Per-ABI native hardening table (PIE, NX, RELRO, stack canary, FORTIFY, RPATH) for every Android app that has one. Server-rendered
 * and escaped: library names and RPATH values come from the package. Returns '' when no app has native libraries.
 */
/** Hardening table of a standalone Mach-O (one row per architecture slice). Server-rendered and escaped. */
function machoHardeningHtml(a) {
  const h = a.native_hardening;
  const cell = (text, level, title = '') => `<td class="px-3 py-3"><span class="px-2 py-0.5 rounded border text-[10px] font-semibold whitespace-nowrap ${HARDENING_BADGE[level]}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span></td>`;
  const chips = Object.entries(h.failing || {}).filter(([, n]) => n > 0)
    .map(([k, n]) => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.bad}">${esc(HARDENING_LABEL[k] || k)} × ${Number(n)}</span>`).join(' ');
  const rows = h.binaries.map(b => {
    const pie = b.kind !== 'executable' ? cell('n/a', 'na', 'Libraries and bundles are always relocatable') : b.pie ? cell('yes', 'ok') : cell('no', 'bad', 'MH_PIE is not set: the executable loads at a fixed address');
    const stack = b.stack_exec ? cell('executable', 'bad', 'MH_ALLOW_STACK_EXECUTION is set') : cell('no', 'ok');
    const canary = b.canary === 'yes' ? cell('yes', 'ok') : b.canary === 'no' ? cell('no', 'bad', 'Unbounded copy functions are imported but no __stack_chk_fail')
      : cell('none', 'na', 'No canary, but no unbounded copy functions are imported');
    const sig = b.signature === 'signed' ? cell('signed', 'ok') : b.signature === 'adhoc' ? cell('ad-hoc', 'warn', 'Not tied to a signing identity') : cell('none', 'bad', 'No LC_CODE_SIGNATURE');
    const rt = b.hardened_runtime === 'yes' ? cell('yes', 'ok') : b.hardened_runtime === 'no' ? cell('no', 'bad', 'CS_RUNTIME is not set in the code directory')
      : cell('n/a', 'na', 'Applies to signed macOS executables');
    const ent = (b.entitlements || []).length ? (b.entitlements || []).map(e => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold mono ${HARDENING_BADGE.bad}">${esc(String(e).replace(/^com\.apple\.security\./, ''))}</span>`).join(' ') : '--';
    return `<tr class="hover:bg-neutral-800/30 transition-colors">
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.arch)}${b.bits ? ` · ${Number(b.bits)}-bit` : ''}</td>
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.kind)}</td>
        ${pie}${stack}${canary}${sig}${rt}
        <td class="px-3 py-3">${ent}</td>
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${b.min_os ? esc(b.min_os) : '--'}</td>
      </tr>`;
  }).join('');
  return `<div class="glass p-6 rounded-xl space-y-4 native-hardening">
      <div class="flex flex-wrap items-baseline justify-between gap-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Mach-O hardening</h3><span class="mono text-xs text-neutral-500">${esc(a.name || 'Binary')}</span></div>
      <p class="text-xs text-neutral-400">${Number(h.total)} slice${h.total === 1 ? '' : 's'} · architectures: ${esc((h.abis || []).join(', '))}</p>
      <div class="flex flex-wrap gap-2">${chips || `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.ok}">No hardening gaps found</span>`}</div>
      <div class="overflow-x-auto"><table class="w-full text-left text-sm">
        <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-3 py-3">Slice</th><th class="px-3 py-3">Type</th><th class="px-3 py-3">PIE</th><th class="px-3 py-3">Exec stack</th><th class="px-3 py-3">Canary</th><th class="px-3 py-3">Signature</th><th class="px-3 py-3">Hardened runtime</th><th class="px-3 py-3">Risky entitlements</th><th class="px-3 py-3">Min OS</th></tr></thead>
        <tbody class="divide-y divide-neutral-800">${rows}</tbody>
      </table></div>
      <p class="text-xs text-neutral-500">Every architecture slice of a fat binary is checked on its own. PIE, stack execution, signature and hardened-runtime flags are read from the Mach-O header and code directory; entitlements from the embedded signature. The canary is inferred from imported symbols (<span class="mono">___stack_chk_fail</span>): a binary that imports no unbounded copy function legitimately has none. The signature is read, never verified.</p>
    </div>`;
}

/** Hardening table of a Windows PE image (one row). Server-rendered and escaped. */
function peHardeningHtml(a) {
  const h = a.native_hardening;
  const cell = (text, level, title = '') => `<td class="px-3 py-3"><span class="px-2 py-0.5 rounded border text-[10px] font-semibold whitespace-nowrap ${HARDENING_BADGE[level]}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span></td>`;
  const flag = (value, title, { warnOnNo = false } = {}) => value === 'yes' ? cell('yes', 'ok') : value === 'no' ? cell('no', warnOnNo ? 'warn' : 'bad', title) : cell(value, 'na', 'Does not apply to this image');
  const chips = Object.entries(h.failing || {}).filter(([, n]) => n > 0)
    .map(([k, n]) => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.bad}">${esc(HARDENING_LABEL[k] || k)}${n > 1 ? ` × ${Number(n)}` : ''}</span>`).join(' ');
  const rows = h.binaries.map(b => `<tr class="hover:bg-neutral-800/30 transition-colors">
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.arch)}${b.bits ? ` · ${Number(b.bits)}-bit` : ''}</td>
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.kind)}${b.managed ? ' · .NET' : ''}</td>
        ${flag(b.aslr, 'DYNAMIC_BASE is not set, or the relocations were stripped: the image loads at a fixed address')}
        ${flag(b.high_entropy_va, 'HIGH_ENTROPY_VA is not set: a much smaller address range is used', { warnOnNo: true })}
        ${flag(b.nx, 'NX_COMPAT is not set: the loader may leave stack and heap executable')}
        ${flag(b.cfg, 'GUARD_CF is not set: indirect calls are not checked', { warnOnNo: true })}
        ${flag(b.safeseh, 'No SafeSEH table and not marked NO_SEH')}
        ${flag(b.gs, 'No security cookie in the load configuration', { warnOnNo: true })}
        ${(b.wx_sections || []).length ? cell(b.wx_sections.join(', '), 'bad', 'Writable and executable section(s)') : cell('none', 'ok')}
        ${flag(b.signed, 'No Authenticode signature', { warnOnNo: true })}
      </tr>`).join('');
  const th = t => `<th class="px-3 py-3">${t}</th>`;
  return `<div class="glass p-6 rounded-xl space-y-4 native-hardening">
      <div class="flex flex-wrap items-baseline justify-between gap-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Windows PE hardening</h3><span class="mono text-xs text-neutral-500">${esc(a.name || 'Binary')}</span></div>
      <div class="flex flex-wrap gap-2">${chips || `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.ok}">No hardening gaps found</span>`}</div>
      <div class="overflow-x-auto"><table class="w-full text-left text-sm">
        <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr>${th('Architecture')}${th('Type')}${th('ASLR')}${th('High-entropy ASLR')}${th('DEP / NX')}${th('CFG')}${th('SafeSEH')}${th('/GS cookie')}${th('W+X sections')}${th('Signature')}</tr></thead>
        <tbody class="divide-y divide-neutral-800">${rows}</tbody>
      </table></div>
      <p class="text-xs text-neutral-500">Flags are read from the PE headers and the load configuration directory. <b>n/a</b> means the check does not apply (SafeSEH exists only on 32-bit x86, high-entropy ASLR only on 64-bit images, CFG and /GS are not assessed for .NET assemblies). The /GS cookie is inferred from the load configuration, and the Authenticode signature is only checked for presence, never verified.</p>
    </div>`;
}

export function nativeHardeningHtml(apps) {
  const cell = (text, level, title = '') => `<td class="px-3 py-3"><span class="px-2 py-0.5 rounded border text-[10px] font-semibold whitespace-nowrap ${HARDENING_BADGE[level]}"${title ? ` title="${esc(title)}"` : ''}>${esc(text)}</span></td>`;
  return (apps || []).filter(a => a?.native_hardening?.binaries?.length).map(a => {
    if (a.native_hardening.format === 'macho') return machoHardeningHtml(a);
    if (a.native_hardening.format === 'pe') return peHardeningHtml(a);
    const h = a.native_hardening;
    const chips = Object.entries(h.failing || {}).filter(([, n]) => n > 0)
      .map(([k, n]) => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.bad}">${esc(HARDENING_LABEL[k] || k)} × ${Number(n)}</span>`).join(' ');
    const rows = h.binaries.map(b => {
      const failed = new Set(b.failed || []);
      const pie = !b.pie ? cell('no', 'bad', 'ET_EXEC: not position independent') : b.textrel ? cell('text relocations', 'warn', 'Position independent image, but relocations patch code pages') : cell('yes', 'ok');
      const nxTitle = b.nx === 'disabled' ? 'PT_GNU_STACK requests an executable stack' : b.nx === 'missing' ? 'No PT_GNU_STACK header' : b.wx_segments ? `${b.wx_segments} writable and executable segment(s)` : '';
      const nx = cell((b.nx === 'enabled' ? 'yes' : b.nx === 'disabled' ? 'no' : 'not asserted') + (b.wx_segments ? ' · W+X' : ''),
        b.nx === 'disabled' || b.wx_segments ? 'bad' : b.nx === 'missing' ? 'warn' : 'ok', nxTitle);
      const relro = cell(b.relro, b.relro === 'full' ? 'ok' : b.relro === 'partial' ? 'warn' : 'bad');
      const canary = b.canary === null ? cell('unknown', 'na', 'The dynamic symbol table could not be read')
        : b.canary ? cell('yes', 'ok')
          : failed.has('no_canary') ? cell('no', 'bad', 'No __stack_chk_fail import although a canary is expected here')
            : cell('none', 'na', 'No canary, but no unbounded copy calls are imported and no other ABI of this library has one');
      const fortify = b.fortify === 'yes' || b.fortify === 'partial' ? cell(b.fortify, 'ok', `${b.fortified_functions} checked function(s) imported`)
        : b.fortify === 'no' ? cell('no', 'warn', `Imports ${(b.unfortified_functions || []).join(', ')} without checked variants`)
          : cell(b.fortify === 'unknown' ? 'unknown' : 'n/a', 'na');
      return `<tr class="hover:bg-neutral-800/30 transition-colors">
        <td class="px-3 py-3 font-semibold break-all">${esc(b.library)}</td>
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.abi)}</td>
        <td class="px-3 py-3 mono text-xs whitespace-nowrap">${esc(b.arch)}${b.kind === 'executable' ? ' · exe' : ''}</td>
        ${pie}${nx}${relro}${canary}${fortify}
        <td class="px-3 py-3 mono text-xs break-all">${b.rpath ? esc(b.rpath) : '—'}</td>
      </tr>`;
    }).join('');
    return `<div class="glass p-6 rounded-xl space-y-4 native-hardening">
      <div class="flex flex-wrap items-baseline justify-between gap-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">${a.platform === 'binary' ? 'ELF hardening' : 'Native library hardening'}</h3><span class="mono text-xs text-neutral-500">${esc(a.package || a.name || 'Android app')}</span></div>
      <p class="text-xs text-neutral-400">${Number(h.total)} binar${h.total === 1 ? 'y' : 'ies'} · ${Number(h.libraries)} librar${h.libraries === 1 ? 'y' : 'ies'} · ABIs: ${esc((h.abis || []).join(', '))}${h.unknown_symbols ? ` · ${Number(h.unknown_symbols)} without a readable symbol table` : ''}</p>
      <div class="flex flex-wrap gap-2">${chips || `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold ${HARDENING_BADGE.ok}">No hardening gaps found</span>`}</div>
      <div class="overflow-x-auto"><table class="w-full text-left text-sm">
        <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-3 py-3">Library</th><th class="px-3 py-3">ABI</th><th class="px-3 py-3">Arch</th><th class="px-3 py-3">PIE</th><th class="px-3 py-3">NX</th><th class="px-3 py-3">RELRO</th><th class="px-3 py-3">Canary</th><th class="px-3 py-3">FORTIFY</th><th class="px-3 py-3">RPATH</th></tr></thead>
        <tbody class="divide-y divide-neutral-800">${rows}</tbody>
      </table></div>
      <p class="text-xs text-neutral-500">Every ABI copy is checked on its own. PIE, NX and RELRO are read from the ELF headers. Canary and FORTIFY are inferred from imported symbols (<span class="mono">__stack_chk_fail</span>, <span class="mono">__*_chk</span>): a library with no stack buffers legitimately has no canary, and a fortified build still imports plain <span class="mono">memcpy</span> where the compiler could not prove the buffer size, so treat those two as indicators.</p>
    </div>`;
  }).join('');
}

/** Number of native binaries (every ABI copy) across the Android apps of a payload. */
export function nativeBinaryCount(apps) {
  return (apps || []).reduce((n, a) => n + Number(a?.native_hardening?.binaries?.length || 0), 0);
}

// ── Behavior tab ───────────────────────────────────────────────────────────────────────────────────
// What the code DOES (file access, network, IPC, processes, reflection, native code, sensitive device APIs), taken from the call inventory in
// `app.behavior` (behavior.js). Nearly every app does all of this, so the tab is context for the findings, not a list of findings: each
// category links to the findings that bear on it. Server-rendered and escaped (API names and intent actions come from the package).
const BEHAVIOR_INFO = {
  file_io: { about: 'Reads, writes and deletes files. Check that anything sensitive stays in app-private storage and is not written to shared storage or made world-accessible.',
    rules: /^(android\.dex\.(external_storage|world_accessible_storage|plaintext_prefs|plaintext_database)|android\.manifest\.(backup|legacy_storage)|bundle\.(database|sensitive_file))/ },
  network: { about: 'Opens connections: URL / HttpURLConnection, sockets, OkHttp calls and WebView loads. Check transport security, certificate validation and which endpoints are contacted.',
    rules: /^(android\.dex\.(cleartext_urls|trust_all_certs|allow_all_hostnames|custom_trust_manager|weak_tls_protocol|webview_|firebase_urls)|android\.manifest\.cleartext|android\.nsc\.|android\.network\.|android\.online\.)/ },
  ipc: { about: 'Talks to other components and apps: activities, services, broadcasts and intents. Implicit intents (an action string, no target class) can be intercepted; exported components are reachable by other apps.',
    rules: /^android\.manifest\.(exported_|deeplinks|weak_permission|shared_user_id)/ },
  process: { about: 'Starts processes (Runtime.exec, ProcessBuilder). Shell execution is rare in normal apps; check that no input reaches the command line.',
    rules: /^android\.dex\.runtime_exec$/ },
  reflection: { about: 'Looks up classes and methods by name at run time (Class.forName, Method.invoke, ClassLoader.loadClass). Common in frameworks; also how code is hidden from static analysis or loaded dynamically.',
    rules: /^(android\.dex\.dynamic_code_loading|bundle\.embedded_code)$/ },
  native_code: { about: 'Loads native libraries (System.loadLibrary / load). Native code is outside the Java sandbox of checks: see the Native Binaries tab for its hardening.',
    rules: /^android\.native\./ },
  device_access: { about: 'Uses sensitive device APIs: location, camera, microphone, SMS, clipboard, installed-package list. Each should match a declared permission and a feature the user can see.',
    rules: /^(android\.manifest\.(risky_permissions|permissions)|android\.dex\.device_identifiers)$/ },
};
const BEHAVIOR_ORIGIN = { app: 'App code', unknown: 'Renamed classes', library: 'Third-party libraries' };
const BEHAVIOR_ORIGIN_BADGE = { app: 'text-red-300 border-red-500/40 bg-red-500/10', unknown: 'text-orange-300 border-orange-500/40 bg-orange-500/10', library: 'text-neutral-300 border-neutral-600 bg-neutral-800/50' };
const SEVERITY_BADGE = {
  critical: 'text-red-300 border-red-500/60 bg-red-500/20', high: 'text-red-400 border-red-500/50 bg-red-500/10', medium: 'text-orange-300 border-orange-500/50 bg-orange-500/10',
  low: 'text-yellow-300 border-yellow-500/40 bg-yellow-500/10', info: 'text-blue-300 border-blue-500/40 bg-blue-500/10',
};
const BEHAVIOR_ORIGINS = ['app', 'unknown', 'library'];

// The tab is shared by the Android and native-binary reports. Android counts call sites in DEX code, split by who owns the class; a native
// binary (`app.platform === 'binary'`) lists the functions its import table links, in one column, because it has no call-site walker.
// Categories that only native code fills (see mobile/lib/behavior.js): same text as the binary report, related findings are the native hardening rules
const ANDROID_NATIVE_INFO = Object.fromEntries(['injection', 'anti_analysis', 'privilege', 'persistence', 'input_capture', 'crypto', 'system_info'].map(c => [c, {
  about: NATIVE_BEHAVIOR_INFO[c].about, rules: c === 'injection' ? /^android\.native\.(exec_stack|wx_segment|textrel)$/ : c === 'crypto' ? /^android\.dex\.(ecb_mode|static_iv|static_gcm_nonce)$/ : null }]));
const ANDROID_BEHAVIOR = {
  labels: BEHAVIOR_LABELS, info: { ...ANDROID_NATIVE_INFO, ...BEHAVIOR_INFO }, origins: BEHAVIOR_ORIGINS, originLabel: BEHAVIOR_ORIGIN, badge: BEHAVIOR_ORIGIN_BADGE,
  columns: { app: 'App code', unknown: 'Renamed classes', library: 'Libraries' }, ownerHeader: 'Owner', countHeader: 'Calls', totalHeader: 'Total calls', ipc: true, fallbackName: 'Android app',
  intro: b => "API references in the app's DEX code, split by who owns the class. <b>APIs</b> is the number of distinct APIs listed for a behavior (the rows of its panel); the other columns count <b>calls</b> to them. <b>Renamed classes</b> are obfuscated classes outside the app's own package: most likely library code, but not provable. This is an inventory of what the code can do, not a list of weaknesses. Select a row to see the exact APIs." + (b?.native ? " <b>Native libraries</b> (.so files) add the functions they import, labelled <i>library: function</i>, under App code or Libraries by the same rule as the hardening findings; for ELF x86-64 / arm64 the count is the direct call sites found in the library code" + (b.native.counted ? "" : " (not counted here: entries are 1, present)") + "." : ""),
};
const NATIVE_BEHAVIOR = {
  labels: NATIVE_BEHAVIOR_LABELS, info: NATIVE_BEHAVIOR_INFO, dynamicOrigins: true, origins: [], originLabel: o => o, badge: () => 'text-neutral-300 border-neutral-600 bg-neutral-800/50',
  columns: { all: 'Functions' }, ownerHeader: 'Source', countHeader: 'Present', totalHeader: 'Total', ipc: false, fallbackName: 'Binary',
  intro: b => {
    if (b?.native) return `Functions imported by the Mach-O files of the app (the executable, frameworks and extensions), grouped by what they do. <b>Source</b> is <i>app</i> for the app's own binaries and <i>library</i> for embedded frameworks and dylibs; each entry is labelled <i>binary: function</i>. An entry shows that the function is <b>linked</b>, not that it is called: call sites are not counted for Mach-O, so entries show a check mark and the numbers on this tab count functions. Calls made through Objective-C messaging or Swift are not functions of this table. This is an inventory of what the code can do, not a list of weaknesses. Select a row to see the exact functions.`;
    const from = { imports: 'the import table', go: 'the Go function table (pclntab)', rust: 'the std and crate paths left in panic messages', bundle: "the text of the packaged application's own files" };
    const src = (b?.sources?.length ? b.sources : ['imports']).map(x => from[x] || x);
    return `Functions and modules found in ${src.join(', ')}, grouped by what they do and by <b>Source</b>: the library that provides an import, the module that defines a Go function, the crate, or the owner of a bundled file. <b>Functions</b> is the number of distinct entries listed for a behavior (the rows of its panel). ${b?.counted ? '<b>Call sites</b> counts only imports: the <b>direct calls</b> found by scanning the code for calls to the import stubs (x86-64 and arm64; approximate: calls through function pointers, <code>dlsym</code> / <code>GetProcAddress</code> results and packed or obfuscated code are not seen, and 0 means imported but no direct call found). Entries from the Go / Rust tables are shown as present (✓) and entries from bundled source text count the lines that mention the module (<i>Mentions</i>); neither is added to the call-site total.' : 'An entry shows that the function is <b>linked or referenced</b>, not that it is called or reachable: call sites were not counted, so there are no call counts.'} A statically linked or stripped file lists little here even when it does a lot. This is an inventory of what the code can do, not a list of weaknesses. Select a row to see the exact functions.`;
  },
};
const behaviorProfile = a => (a && (a.platform === 'binary' || a.platform === 'ios') ? NATIVE_BEHAVIOR : ANDROID_BEHAVIOR);
/** Origins of one app's behavior summary: fixed for Android, the libraries / modules / owners that actually occur for a native binary. */
const behaviorOrigins = (P, b) => (P.dynamicOrigins ? [...new Set(Object.values(b.categories || {}).flatMap(byOrigin => Object.keys(byOrigin || {})))].sort() : P.origins);

/** Distinct entries (functions / APIs) of one category, summed over its origins: exactly the rows of its panel. */
const fnOf = byOrigin => Object.values(byOrigin || {}).reduce((n, o) => n + functionsOf(o), 0);

/** Number of distinct functions / APIs listed on the Behavior tab (the sum of the category counts, each category's rows counted once). */
export function behaviorApiCount(apps) {
  return (apps || []).reduce((n, a) => n + Object.values(a?.behavior?.categories || {}).reduce((m, byOrigin) => m + fnOf(byOrigin), 0), 0);
}

/** Number of remote hosts (IP addresses and domain names) found in the strings of the apps of a payload. */
export function remoteHostCount(apps) {
  return (apps || []).reduce((n, a) => n + Number(a?.remote_hosts?.total || 0), 0);
}

// Findings that bear on the hosts an app reaches (cleartext endpoints, Firebase databases, network policy).
const REMOTE_HOST_RULES = /^(android\.dex\.(cleartext_urls|firebase_urls|trust_all_certs|allow_all_hostnames|weak_tls_protocol)|android\.nsc\.|android\.manifest\.cleartext|android\.network\.|android\.online\.|ios\.code\.cleartext_urls|ios\.plist\.ats_)/;
const HOST_CHIP = {
  domain: ['Domain', 'text-neutral-300 border-neutral-600 bg-neutral-800/50'], ipv4: ['IPv4', 'text-blue-300 border-blue-500/40 bg-blue-500/10'], ipv6: ['IPv6', 'text-blue-300 border-blue-500/40 bg-blue-500/10'],
  private: ['private range', 'text-yellow-300 border-yellow-500/40 bg-yellow-500/10'], cleartext: ['plain-text scheme', 'text-orange-300 border-orange-500/40 bg-orange-500/10'],
};

export function behaviorHtml(apps, findings = []) {
  const hasHosts = a => Number(a?.remote_hosts?.hosts?.length || 0) > 0;
  const withBehavior = (apps || []).map((a, i) => ({ a, i })).filter(({ a }) => (a?.behavior && Object.keys(a.behavior.categories || {}).length) || hasHosts(a));
  if (!withBehavior.length) return '';
  const callsOf = (byOrigin, o) => Number(byOrigin?.[o]?.calls || 0);
  const findingList = list => list.length
    ? `<ul class="divide-y divide-neutral-800">${list.map(f => `<li class="py-2 flex flex-wrap items-center gap-2 text-sm"><span class="px-2 py-0.5 rounded border text-[10px] font-semibold uppercase ${SEVERITY_BADGE[f.severity] || SEVERITY_BADGE.info}">${esc(f.severity)}</span><span>${esc(f.title)}</span><span class="mono text-xs text-neutral-500 break-all">${esc(f.rule)} · ${esc(f.artifact)}</span></li>`).join('')}</ul>`
    : '<p class="text-xs text-neutral-500">No finding in this report bears on this behavior.</p>';
  const chip = ([label, cls]) => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold whitespace-nowrap ${cls}">${esc(label)}</span>`;

  return withBehavior.map(({ a, i }) => {
    const P = behaviorProfile(a), b = a.behavior || { categories: {}, counted: false }, ORIGINS = behaviorOrigins(P, b), rh = hasHosts(a) ? a.remote_hosts : null;
    const badgeOf = o => (typeof P.badge === 'function' ? P.badge(o) : P.badge[o]), labelOf = o => (typeof P.originLabel === 'function' ? P.originLabel(o) : P.originLabel[o]);
    const originChip = o => `<span class="px-2 py-0.5 rounded border text-[10px] font-semibold whitespace-nowrap break-all ${badgeOf(o)}">${esc(labelOf(o))}</span>`;
    const forApp = list => list.filter(f => !f.app || !a.package || f.app === a.package);
    const related = (app, cat) => {
      const re = P.info[cat]?.rules;
      return re ? findings.filter(f => re.test(String(f.rule || '')) && (!f.app || !app.package || f.app === app.package)) : [];
    };
    const hostRelated = forApp(findings.filter(f => REMOTE_HOST_RULES.test(String(f.rule || ''))));
    const cats = Object.keys(P.labels).filter(c => b.categories[c]);
    const totalCalls = c => ORIGINS.reduce((n, o) => n + callsOf(b.categories[c], o), 0);
    // Call sites are only what was counted as call sites: Go / Rust / bundled-text entries and presence entries are never added in.
    const siteCalls = c => ORIGINS.reduce((n, o) => { const x = b.categories[c]?.[o]; return n + (x && (x.basis === 'sites' || (x.basis === undefined && b.counted)) ? Number(x.calls || 0) : 0); }, 0);
    const pill = (id, label, count) => `<button type="button" data-bh-app="${i}" data-bh-pill="${esc(id)}" onclick="switchBehavior(${i}, '${esc(id)}')" class="bh-pill px-3 py-1.5 rounded-full border border-neutral-700 text-xs font-medium text-neutral-300 hover:text-white whitespace-nowrap${id === 'overview' ? ' bh-pill-active' : ''}">${esc(label)}${count == null ? '' : ` <span class="mono text-neutral-500">${Number(count)}</span>`}</button>`;
    const functionsCol = { header: P.ipc ? 'APIs' : 'Functions', of: c => fnOf(b.categories[c]) };
    const columns = P.dynamicOrigins
      ? [functionsCol, ...(b.counted ? [{ header: 'Call sites', of: siteCalls }] : [])]
      : [functionsCol, ...ORIGINS.map(o => ({ header: `${P.columns[o]} · calls`, of: c => callsOf(b.categories[c], o) }))];
    const pills = [pill('overview', 'Overview', null), ...cats.map(c => pill(c, P.labels[c], fnOf(b.categories[c]))), ...(rh ? [pill('remote_hosts', 'Remote hosts', rh.total)] : [])].join('');
    const showTotal = ORIGINS.length > 1 && !P.dynamicOrigins;                            // a native binary has one column: the origin is shown per function

    const matrix = cats.map(c => `<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" onclick="switchBehavior(${i}, '${esc(c)}')">
        <td class="px-4 py-3 font-semibold">${esc(P.labels[c])}</td>
        ${columns.map(col => `<td class="px-4 py-3 mono text-sm ${col.of(c) ? '' : 'text-neutral-600'}">${col.of(c)}</td>`).join('')}
        ${showTotal ? `<td class="px-4 py-3 mono text-sm font-semibold">${totalCalls(c)}</td>` : ''}
        <td class="px-4 py-3 mono text-sm ${related(a, c).length ? 'text-orange-300' : 'text-neutral-600'}">${related(a, c).length}</td></tr>`).join('');
    const hostsRow = rh ? `<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" onclick="switchBehavior(${i}, 'remote_hosts')">
        <td class="px-4 py-3 font-semibold">Remote hosts</td>
        <td class="px-4 py-3 mono text-sm">${Number(rh.total)}</td>
        ${'<td class="px-4 py-3 mono text-sm text-neutral-600">–</td>'.repeat(Math.max(0, columns.length - 1) + (showTotal ? 1 : 0))}
        <td class="px-4 py-3 mono text-sm ${hostRelated.length ? 'text-orange-300' : 'text-neutral-600'}">${hostRelated.length}</td></tr>` : '';
    const it = b.intent_actions_total || {}, ex = b.explicit_intents || {};
    const hostTile = ['Remote hosts', rh ? Number(rh.total) : 0];
    const fnAll = cats.reduce((n, c) => n + fnOf(b.categories[c]), 0);
    const tiles = P.ipc
      ? [['Explicit intents (app)', ex.app || 0], ['Implicit intent actions (app)', it.app || 0], ['Implicit actions (renamed / library)', `${it.unknown || 0} / ${it.library || 0}`], ['Explicit intents (all)', (ex.app || 0) + (ex.unknown || 0) + (ex.library || 0)], hostTile]
      : [['Functions listed', fnAll], ...(b.counted ? [['Call sites found', cats.reduce((n, c) => n + siteCalls(c), 0)]] : []), ['Categories observed', cats.length], ['Sources', ORIGINS.length], ['Linked libraries', (a.needed || []).length], hostTile];
    const overview = `<div data-bh-app="${i}" data-bh-panel="overview" class="space-y-4">
        <p class="text-xs text-neutral-400">${typeof P.intro === 'function' ? P.intro(b) : P.intro}</p>
        <div class="overflow-x-auto"><table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-4 py-3">Behavior</th>${columns.map(c => `<th class="px-4 py-3">${esc(c.header)}</th>`).join('')}${showTotal ? `<th class="px-4 py-3">${esc(P.totalHeader)}</th>` : ''}<th class="px-4 py-3">Related findings</th></tr></thead>
          <tbody class="divide-y divide-neutral-800">${matrix}${hostsRow}</tbody></table></div>
        <div class="grid grid-cols-2 md:grid-cols-4 gap-3">${tiles
          .map(([l, v]) => `<div class="glass p-4 rounded-xl"><div class="text-xl font-bold mono">${esc(v)}</div><div class="text-[11px] uppercase tracking-widest text-neutral-500">${esc(l)}</div></div>`).join('')}</div>
      </div>`;

    const BASIS_HEADER = { sites: 'Call sites', refs: 'Mentions', present: 'Present' };
    const BASIS_NOTE = {
      sites: '<b>Call sites</b>: direct calls found in the code (0 = imported, no direct call found).',
      refs: '<b>Mentions</b>: lines of the packaged application\'s own source that refer to the module; they are not call sites.',
      present: '<b>✓</b>: the function is linked or referenced; it is not counted.',
    };
    const panels = cats.map(c => {
      const byOrigin = b.categories[c];
      const rows = ORIGINS.filter(o => byOrigin[o]).flatMap(o => Object.entries(byOrigin[o].apis || {}).map(([api, n]) => ({ o, api, n }))).sort((x, y) => y.n - x.n || x.api.localeCompare(y.api));
      // what a number means differs by source (see binary/lib/behavior.js); reports from older versions have no `basis`
      const basisOf = o => byOrigin[o]?.basis || (b.counted ? 'sites' : 'present');
      const bases = [...new Set(ORIGINS.filter(o => byOrigin[o]).map(basisOf))].filter(x => BASIS_NOTE[x]);
      const cell = (o, n) => (P.ipc ? Number(n) : (basisOf(o) === 'present' ? '✓' : Number(n)));
      const countHeader = P.ipc ? P.countHeader : bases.length === 1 ? BASIS_HEADER[bases[0]] : 'Count';
      const shown = rows.map(r => `<tr class="hover:bg-neutral-800/30 transition-colors"><td class="px-4 py-2 mono text-xs break-all">${esc(r.api)}</td><td class="px-4 py-2">${originChip(r.o)}</td><td class="px-4 py-2 mono text-sm">${cell(r.o, r.n)}</td></tr>`).join('');
      const cut = ORIGINS.reduce((n, o) => n + (byOrigin[o] ? Math.max(0, functionsOf(byOrigin[o]) - Object.keys(byOrigin[o].apis || {}).length) : 0), 0);
      let extra = '';
      if (c === 'ipc' && P.ipc) {
        const acts = ORIGINS.filter(o => (b.intent_actions?.[o] || []).length).map(o => `<div><div class="mb-1">${originChip(o)} <span class="mono text-xs text-neutral-500">${(b.intent_actions[o] || []).length}${(it[o] || 0) > (b.intent_actions[o] || []).length ? ` of ${Number(it[o])}` : ''} action(s)</span></div><div class="flex flex-wrap gap-1">${(b.intent_actions[o] || []).map(x => `<span class="px-2 py-0.5 rounded bg-neutral-800 mono text-[11px] break-all">${esc(x)}</span>`).join('')}</div></div>`).join('');
        extra = `<div class="space-y-3"><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400">Implicit intent actions</h4><p class="text-xs text-neutral-500">An intent built from an action string (no target class) is resolved by the system and can be answered by any app that registers for it: never put secrets in one, and prefer explicit intents for internal calls.</p>${acts || '<p class="text-xs text-neutral-500">No constant action strings were found.</p>'}</div>`;
      }
      return `<div data-bh-app="${i}" data-bh-panel="${esc(c)}" class="space-y-4 hidden">
        <div><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">${esc(P.labels[c])} <span class="mono text-neutral-500">${fnOf(byOrigin)}</span></h3><p class="text-xs text-neutral-400 mt-1">${esc(P.info[c]?.about || '')}</p></div>
        <div class="overflow-x-auto"><table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-4 py-3">${P.ipc ? 'API' : 'Function'}</th><th class="px-4 py-3">${esc(P.ownerHeader)}</th><th class="px-4 py-3">${esc(countHeader)}</th></tr></thead>
          <tbody class="divide-y divide-neutral-800">${shown}</tbody></table></div>
        ${!P.ipc && bases.length ? `<p class="text-xs text-neutral-500">${bases.map(x => BASIS_NOTE[x]).join(' ')}</p>` : ''}
        ${cut > 0 ? `<p class="text-xs text-neutral-500">The ${P.ipc || b.counted ? 'most frequent' : 'first (alphabetical)'} ${P.ipc ? 'APIs' : 'functions'} of each ${P.ipc ? 'owner' : 'source'} are listed; ${cut} more ${cut === 1 ? 'is' : 'are'} counted in the totals but not shown.</p>` : ''}
        ${extra}
        <div class="space-y-2"><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400">Related findings</h4>${findingList(related(a, c))}</div>
      </div>`;
    }).join('');

    let hostsPanel = '';
    if (rh) {
      const rowsHtml = rh.hosts.map(h => {
        const flags = [chip(HOST_CHIP[h.type] || HOST_CHIP.domain), ...(h.private ? [chip(HOST_CHIP.private)] : []), ...(h.cleartext ? [chip(HOST_CHIP.cleartext)] : [])].join(' ');
        const via = [...(h.schemes || []), ...(h.ports || []).map(p => `:${p}`)].join(' ');
        const search = [h.host, ...(h.seen_in || []), ...(h.schemes || []), ...(h.examples || [])].join(' ').toLowerCase();
        return `<tr data-bh-host-app="${i}" data-search="${esc(search)}" class="hover:bg-neutral-800/30 transition-colors">
          <td class="px-4 py-2 mono text-xs break-all">${esc(h.host)}${(h.examples || [])[0] ? `<div class="text-[10px] text-neutral-500 break-all mt-0.5">${esc(h.examples[0])}</div>` : ''}</td>
          <td class="px-4 py-2"><div class="flex flex-wrap gap-1">${flags}</div></td>
          <td class="px-4 py-2 text-xs text-neutral-400 break-all">${esc((h.seen_in || []).join(', '))}</td>
          <td class="px-4 py-2 mono text-xs whitespace-nowrap">${esc(via || '—')}</td>
          <td class="px-4 py-2 mono text-sm">${Number(h.refs)}</td></tr>`;
      }).join('');
      const parts = [`${Number(rh.domains)} domain${rh.domains === 1 ? '' : 's'}`, `${Number(rh.ips)} IP address${rh.ips === 1 ? '' : 'es'}`];
      hostsPanel = `<div data-bh-app="${i}" data-bh-panel="remote_hosts" class="space-y-4 hidden">
        <div><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Remote hosts <span class="mono text-neutral-500">${Number(rh.total)}</span></h3>
          <p class="text-xs text-neutral-400 mt-1">IP addresses and domain names that the code names in its strings: URLs (<code>https://</code>, <code>wss://</code>, <code>mqtt://</code> …), <code>IP:port</code> pairs and DNS names. They show where the program <b>may</b> connect, not that it does, when, or with what data: names that are built at run time, read from a config file or received from a server are not visible to a static scan, and a documentation or SDK link looks the same as an API endpoint. Nothing was resolved or contacted.</p></div>
        <p class="mono text-xs text-neutral-500">${esc(parts.join(' · '))}${rh.private ? ` · ${Number(rh.private)} in a private range` : ''}${rh.cleartext ? ` · ${Number(rh.cleartext)} with a plain-text scheme (http, ws, ftp …)` : ''}</p>
        <input type="search" placeholder="Filter hosts…" oninput="filterHosts(${i}, this.value)" class="w-full md:w-80 px-3 py-2 rounded-lg bg-neutral-900 border border-neutral-700 text-sm mono text-neutral-200 placeholder-neutral-600 focus:outline-none focus:border-neutral-500">
        <div class="overflow-x-auto"><table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-4 py-3">Host</th><th class="px-4 py-3">Type</th><th class="px-4 py-3">Seen in</th><th class="px-4 py-3">Scheme / port</th><th class="px-4 py-3">Mentions</th></tr></thead>
          <tbody class="divide-y divide-neutral-800">${rowsHtml}</tbody></table></div>
        ${Number(rh.total) > rh.hosts.length ? `<p class="text-xs text-neutral-500">The ${rh.hosts.length} most mentioned hosts are listed; ${Number(rh.total) - rh.hosts.length} more are counted in the totals but not shown.</p>` : ''}
        ${rh.ignored ? `<p class="text-xs text-neutral-500">${Number(rh.ignored)} namespace, licence or placeholder URL(s) (w3.org schemas, example.com …) and loopback addresses were left out.</p>` : ''}
        <div class="space-y-2"><h4 class="text-xs font-semibold uppercase tracking-widest text-neutral-400">Related findings</h4>${findingList(hostRelated)}</div>
      </div>`;
    }

    return `<div class="glass p-6 rounded-xl space-y-4 behavior-block">
      <div class="flex flex-wrap items-baseline justify-between gap-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Behavior checks</h3><span class="mono text-xs text-neutral-500">${esc(a.package || a.name || P.fallbackName)}</span></div>
      <div class="flex flex-wrap gap-2">${pills}</div>
      ${overview}${panels}${hostsPanel}
    </div>`;
  }).join('');
}

export async function buildHtml(p) {
  const [tailwind, chartjs, googleFonts] = await Promise.all([
    getTailwindScript(), getChartJSScript(), getGoogleFontsScript(),
  ]);
  const c = p.summary?.counts || {};
  const es = p.executive_summary || executiveSummary(p);
  const targetFile = p.target?.file || 'Unknown file';
  const appNames = (p.apps || []).map(a => a.package || a.bundle_id || a.name).filter(Boolean);
  const appLabel = appNames.join(', ') || targetFile;
  const isBinary = (p.apps || []).length > 0 && (p.apps || []).every(a => a.platform === 'binary');
  const T = isBinary ? {
    title: 'Binary Security Report', execLabel: 'Binary security summary', inventoryTab: 'File Info', nativeTab: 'Hardening', depTab: 'Components', nativeHeading: 'Hardening Checks',
    area: 'Area', areaPlural: 'Areas', file: 'File', clean: 'No known advisory', chart2: 'Issues by Area', chart3: 'Issues by Category',
  } : {
    title: 'Mobile Application Security Report', execLabel: 'Mobile application security summary', inventoryTab: 'App Inventory', nativeTab: 'Native Binaries', depTab: 'Dependencies', nativeHeading: 'Native Binaries Analysis',
    area: 'MASVS', areaPlural: 'MASVS Areas', file: 'App', clean: 'Safe', chart2: 'Issues by MASVS Area', chart3: 'Issues by Origin',
  };
  const AREA_NAMES = { 'MASVS-STORAGE': 'Data storage', 'MASVS-CRYPTO': 'Cryptography', 'MASVS-AUTH': 'Authentication', 'MASVS-NETWORK': 'Network', 'MASVS-PLATFORM': 'Platform interaction', 'MASVS-CODE': 'Code & build hygiene', 'MASVS-RESILIENCE': 'Tamper resistance', 'MASVS-PRIVACY': 'Privacy', Unmapped: 'Unmapped' };
  const areaKey = v => String(v || 'Unmapped').replace(/-\d+$/, '');
  const areaText = v => (isBinary ? (AREA_NAMES[areaKey(v)] || areaKey(v)) : String(v || 'Unmapped'));
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  const worstSeverity = dep => { const l = (dep.vulnerabilities || []).map(v => { const x = String(v.severity || 'unknown').toLowerCase(); return x === 'moderate' ? 'medium' : x; }); return SEV_ORDER.find(x => l.includes(x)) || null; };
  // Three disjoint lists; `all` (same order the page script rebuilds) is what the detail modal indexes into.
  const vulns = p.vulnerabilities || [];
  const secrets = p.secrets || [];
  const misconfigs = p.misconfigurations || [];
  const all = flattenFindings(p);
  const dependencies = p.dependencies || [];
  const nativeCount = nativeBinaryCount(p.apps);
  const nativeHtml = nativeHardeningHtml(p.apps);
  const behaviorFunctions = behaviorApiCount(p.apps), hostCount = remoteHostCount(p.apps);
  const behaviorCount = behaviorFunctions + hostCount;                       // everything listed on the tab: functions / APIs plus remote hosts
  const behaviorPanels = behaviorHtml(p.apps, flattenFindings(p));
  const dependencySummary = p.dependency_summary || {};
  const dependencyStatusLabel = { vulnerable: 'Vulnerable', clean: T.clean, not_queryable: 'Not queried', lookup_error: 'Lookup failed', lookup_incomplete: 'Lookup incomplete', pending: 'Pending' };
  const severityColors = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', low: '#60a5fa', info: '#a3a3a3' };
  const total = all.length;
  const appIdentity = a => a.platform === 'binary' ? (a.name || 'Binary') : a.platform === 'ios' ? (a.name || a.bundle_id || 'iOS app') : (a.package || a.name || 'Android app');
  const appVersion = a => a.platform === 'binary' ? '—' : a.platform === 'ios' ? `${a.version || '?'} (${a.build || '?'})` : `${a.version_name || '?'} (${a.version_code || '?'})`;
  const appPlatform = a => a.platform === 'binary' ? (a.format === 'macho' ? 'Mach-O' : a.format === 'pe' ? 'PE' : 'ELF') : a.platform === 'ios' ? 'iOS' : 'Android';
  const fmtSize = n => (Number(n) >= 1048576 ? `${(Number(n) / 1048576).toFixed(1)} MB` : `${(Number(n) / 1024).toFixed(1)} KB`);
  const binaryRows = (p.apps || []).map((a, i) => {
    const pack = [...(a.runtimes || []).map(r => `${r.name} ${r.version || ''}`.trim()), ...(a.packaging || []).map(x => x.kind), ...(a.go ? [`Go ${a.go.version || a.go.go_version || ''}`.trim()] : [])];
    return `<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" data-app-index="${i}" title="Open file details">
      <td class="px-6 py-4">${esc(appPlatform(a))}</td>
      <td class="px-6 py-4 font-semibold break-all">${esc(appIdentity(a))}</td>
      <td class="px-6 py-4 mono text-xs">${esc(`${a.arch || '—'}${a.bits ? ` · ${a.bits}-bit` : ''}`)}</td>
      <td class="px-6 py-4 text-xs">${esc(a.kind || '—')}</td>
      <td class="px-6 py-4 text-xs">${esc(pack.join(', ') || '—')}</td>
      <td class="px-6 py-4 mono text-xs">${esc(fmtSize(a.size_bytes || p.target?.size_bytes || 0))}</td>
      <td class="px-6 py-4 text-right mono">${(a.needed || []).length}</td>
    </tr>`;
  }).join('');
  const appRows = isBinary ? binaryRows : (p.apps || []).map((a, i) => {
    const id = a.platform === 'binary' ? (a.arch || '') : a.platform === 'ios' ? a.bundle_id : a.package;
    const scope = a.platform === 'binary' ? (a.kind || '') : a.platform === 'ios' ? (a.min_os ? `iOS ${a.min_os}+` : 'iOS') : `min ${a.min_sdk ?? '?'} / target ${a.target_sdk ?? '?'}`;
    const componentCount = a.platform === 'binary' ? (a.needed || []).length : a.platform === 'ios'
      ? (a.frameworks || []).length + (a.extensions || []).length
      : Object.values(a.components || {}).reduce((sum, n) => sum + Number(n || 0), 0) + (a.native_libs || []).length;
    return `<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" data-app-index="${i}" title="Open app metadata">
      <td class="px-6 py-4">${esc(appPlatform(a))}</td>
      <td class="px-6 py-4 font-semibold">${esc(appIdentity(a))}</td>
      <td class="px-6 py-4 mono text-xs">${esc(id || '—')}</td>
      <td class="px-6 py-4 mono text-xs">${esc(appVersion(a))}</td>
      <td class="px-6 py-4 text-xs">${esc(scope)}</td>
      <td class="px-6 py-4 text-right mono">${Number(componentCount)}</td>
    </tr>`;
  }).join('');

  const dependencyRows = dependencies.map((dep, i) => {
    const status = dep.lookup_status || 'not_queryable';
    const badgeClass = status === 'vulnerable' ? 'text-red-400 border-red-500/50 bg-red-500/10' : status === 'clean' ? 'text-green-400 border-green-500/50 bg-green-500/10' : status === 'lookup_error' || status === 'lookup_incomplete' ? 'text-orange-300 border-orange-500/50 bg-orange-500/10' : 'text-neutral-400 border-neutral-700 bg-neutral-800/50';
    const sources = Array.isArray(dep.sources) ? dep.sources : [];
    return `<tr class="hover:bg-neutral-800/30 transition-colors cursor-pointer" data-dependency-index="${i}" data-dependency-row="true" data-status="${esc(status)}" title="Open dependency and OSV advisory details">
      <td class="px-6 py-4 font-semibold min-w-[12rem]">${esc(dep.name || 'Unknown dependency')}</td>
      <td class="px-6 py-4 mono text-xs whitespace-nowrap">${esc(dep.version || 'unknown')}</td>
      <td class="px-6 py-4 text-xs">${esc(dep.ecosystem || 'Unknown')}</td>
      <td class="px-6 py-4 mono text-xs break-all">${esc(dep.purl || dep.cpe || dep.coordinate || 'identity unavailable')}</td>
      <td class="px-6 py-4"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold whitespace-nowrap ${badgeClass}">${esc(dependencyStatusLabel[status] || status)}</span></td>
      <td class="px-6 py-4 whitespace-nowrap">${worstSeverity(dep) ? `<span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${esc(worstSeverity(dep))}">${esc(worstSeverity(dep))}</span>` : '<span class="text-neutral-600">—</span>'}</td>
      <td class="px-6 py-4 text-right mono">${Number(dep.vulnerability_count || 0)}</td>
      <td class="px-6 py-4 text-xs text-neutral-500 break-all">${esc(sources[0] || '—')}${sources.length > 1 ? ` (+${sources.length - 1} source(s))` : ''}</td>
    </tr>`;
  }).join('');

  const findingRows = (list, { clickable = true } = {}) => (list || []).map(f => {
    const index = all.indexOf(f);
    const origin = f.origin === 'library' ? 'library' : f.origin === 'unknown' ? 'unknown' : 'app';
    const app = f.app || (p.apps?.length === 1 ? appIdentity(p.apps[0]) : '—');
    return `<tr class="${clickable ? 'hover:bg-neutral-800/30 transition-colors cursor-pointer' : ''}"
      ${clickable ? `data-finding-index="${index}"` : ''}
      data-finding-row="true" data-severity="${esc(f.severity || 'info')}" data-origin="${esc(origin)}"
      data-masvs="${esc(String(f.masvs || 'Unmapped').replace(/-\d+$/, ''))}" data-rule="${esc(f.rule || '')}">
      <td class="px-6 py-4 whitespace-nowrap"><span class="px-2 py-0.5 rounded border text-[10px] uppercase font-bold severity-${esc(f.severity || 'info')}">${esc(f.severity || 'info')}</span></td>
      <td class="px-6 py-4 font-semibold min-w-[15rem]">${esc(f.title || f.rule || 'Untitled finding')}</td>
      <td class="px-6 py-4">${esc(app)}</td>
      <td class="px-6 py-4 mono text-xs break-all">${esc(f.artifact || '—')}${f.line ? `:${esc(f.line)}` : ''}</td>
      <td class="px-6 py-4 ${isBinary ? 'text-xs' : 'mono text-xs'}">${esc(areaText(f.masvs))}</td>
      <td class="px-6 py-4 text-xs">${esc(f.confidence || 'unknown')}</td>
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
  const masvsOptions = [...new Set(vulns.map(f => String(f.masvs || 'Unmapped').replace(/-\d+$/, '')))].sort().map(value => `<option value="${esc(value)}">${esc(areaText(value))}</option>`).join('');

  return `<!DOCTYPE html>
<html lang="en" class="dark">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${esc(p.tool || 'ubel-mobile')} — ${esc(T.title)}</title>
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
    .bh-pill-active { background: var(--accent); border-color: var(--accent); color: white; }
    .bh-pill-active .mono { color: rgba(255,255,255,.75); }
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
          <h1 class="text-lg font-semibold tracking-tight">${esc(T.title)}</h1>
          <p class="text-xs text-neutral-500 mono" id="report-id">GENERATED_AT: ${esc(p.generated_at || 'unknown')}</p>
        </div>
      </div>
      <span id="overall-status" class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider ${c.critical + c.high > 0 ? 'bg-red-500/20 text-red-400 border border-red-500/50' : c.medium > 0 ? 'bg-orange-500/20 text-orange-400 border border-orange-500/50' : 'bg-green-500/20 text-green-400 border border-green-500/50'}">Status: ${esc(es.rating || 'Unknown')}</span>
    </div>
  </header>

  <nav class="border-b border-neutral-800 bg-neutral-900/30">
    <div class="max-w-7xl mx-auto px-4 flex gap-8 overflow-x-auto">
      <button onclick="switchTab('dashboard')" id="tab-dashboard" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors tab-active">Dashboard</button>
      <button onclick="switchTab('executive')" id="tab-executive" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Executive Summary</button>
      <button onclick="switchTab('inventory')" id="tab-inventory" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">${esc(T.inventoryTab)}${isBinary ? '' : `(${(p.apps || []).length})`}</button>
      <button onclick="switchTab('native')" id="tab-native" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">${esc(T.nativeTab)}${isBinary ? '' : `(${nativeCount})`}</button>
      <button onclick="switchTab('behavior')" id="tab-behavior" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Behavior(${behaviorCount})</button>
      <button onclick="switchTab('dependencies')" id="tab-dependencies" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">${esc(T.depTab)}(${dependencies.length})</button>
      <button onclick="switchTab('vulnerabilities')" id="tab-vulnerabilities" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Vulnerabilities(${vulns.length})</button>
      <button onclick="switchTab('secrets')" id="tab-secrets" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Secrets(${secrets.length})</button>
      <button onclick="switchTab('misconfigs')" id="tab-misconfigs" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Misconfigurations(${misconfigs.length})</button>
      <button onclick="switchTab('stats')" id="tab-stats" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Detailed Stats</button>
      <button onclick="switchTab('compliance')" id="tab-compliance" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Compliance(${(p.compliance_summary?.frameworks || []).length})</button>
      <button onclick="switchTab('diffs')" id="tab-diffs" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Diffs</button>
      <button onclick="switchTab('scaninfo')" id="tab-scaninfo" class="py-4 text-sm font-medium whitespace-nowrap text-neutral-400 hover:text-white transition-colors">Scan Info</button>
    </div>
  </nav>

  <main class="flex-1 max-w-7xl mx-auto w-full p-4 md:p-8">
    <section id="section-dashboard" class="space-y-8">
      <div class="grid grid-cols-2 md:grid-cols-6 gap-4">${countCards}</div>
      <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">Issues by Severity</h3><div class="h-56 relative"><canvas id="severityChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">${esc(T.chart2)}</h3><div class="h-56 relative"><canvas id="masvsChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 mb-4">${esc(T.chart3)}</h3><div class="h-56 relative"><canvas id="originChart"></canvas></div></div>
      </div>
      ${isBinary ? `<div class="grid grid-cols-2 md:grid-cols-4 gap-4">${[['Components found', dependencySummary.total || dependencies.length, '#d4d4d4'], ['Checked for advisories', dependencies.filter(d => d.lookup_status && d.lookup_status !== 'not_queryable').length, '#60a5fa'], ['Vulnerable components', dependencySummary.vulnerable_dependencies || 0, '#f87171'], ['Advisory matches', dependencySummary.vulnerabilities || 0, '#fb923c']].map(([label, value, color]) => `<button type="button" onclick="switchTab('dependencies')" class="glass p-5 rounded-xl text-left hover:border-neutral-500 transition-colors" style="border-left:4px solid ${color}"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${esc(label)}</p><p class="text-3xl font-bold" style="color:${color}">${Number(value)}</p></button>`).join('')}</div>` : ''}
    </section>

    <section id="section-executive" class="hidden space-y-8">
      <div id="executive-content" class="space-y-8">
        <div class="glass p-5 rounded-xl">
          <p class="text-xs text-neutral-500 uppercase font-semibold tracking-widest mb-1">${esc(T.execLabel)}</p>
          <h2 class="text-2xl font-bold mb-3 break-all">${esc(appLabel)}</h2>
          <div class="flex flex-wrap gap-x-8 gap-y-1 text-xs"><div><span class="text-neutral-500">Report ID: </span><span class="mono text-neutral-300">${esc(p.report_id || '—')}</span></div><div><span class="text-neutral-500">Generated: </span><span class="mono text-neutral-300">${esc(p.generated_at || '—')}</span></div><div><span class="text-neutral-500">Tool: </span><span class="mono text-neutral-300">${esc(p.tool || 'ubel-mobile')}</span></div></div>
        </div>
        <div class="glass p-6 md:p-8 rounded-xl" style="border-left:6px solid ${severityColors[c.critical > 0 ? 'critical' : c.high > 0 ? 'high' : c.medium > 0 ? 'medium' : c.low > 0 ? 'low' : 'info']}">
          <div class="flex flex-wrap items-center justify-between gap-3 mb-3"><div><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">Overall security risk</p><p class="text-4xl font-bold" style="color:${severityColors[c.critical > 0 ? 'critical' : c.high > 0 ? 'high' : c.medium > 0 ? 'medium' : c.low > 0 ? 'low' : 'info']}">${esc(es.rating || 'Unknown')}</p></div><span class="px-3 py-1 rounded-full text-xs font-medium uppercase tracking-wider border ${c.critical + c.high > 0 ? 'bg-red-500/20 text-red-400 border-red-500/50' : c.medium > 0 ? 'bg-orange-500/20 text-orange-400 border-orange-500/50' : 'bg-neutral-800 text-neutral-300 border-neutral-700'}">${c.critical + c.high > 0 ? 'REVIEW REQUIRED' : c.medium > 0 ? 'REVIEW' : 'AUTOMATED CHECKS'}</span></div>
          <p class="text-lg leading-relaxed text-neutral-100 exec-headline">${esc(es.headline || '')}</p>
        </div>
        ${(es.paragraphs || []).length ? `<div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Summary</h3>${es.paragraphs.map(t => `<p class="text-sm leading-relaxed text-neutral-300">${esc(t)}</p>`).join('')}</div>` : ''}
        <div class="grid grid-cols-1 lg:grid-cols-2 gap-6 exec-cols-2">
          <div><h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Top risks</h3><div class="space-y-3">${topFindings}</div></div>
          <div><h3 class="text-sm font-semibold mb-4 uppercase tracking-widest text-neutral-400">Recommended actions</h3><div class="glass p-5 rounded-xl">${actions}</div></div>
        </div>
        <div class="grid grid-cols-2 ${isBinary ? 'lg:grid-cols-5' : 'lg:grid-cols-4'} gap-4 exec-figs">
          ${[['Vulnerabilities', vulns.length, '#f87171'], ['Secrets', secrets.length, '#ef4444'], ['Misconfigurations', misconfigs.length, '#fb923c'], ['Critical + High', Number(c.critical || 0) + Number(c.high || 0), '#a3a3a3'], ...(isBinary ? [['Vulnerable components', `${dependencySummary.vulnerable_dependencies || 0} of ${dependencySummary.total || dependencies.length}`, '#c084fc']] : [])].map(([label, value, color]) => `<div class="glass p-5 rounded-xl" style="border-left:4px solid ${color}"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${esc(label)}</p><p class="text-3xl font-bold" style="color:${color}">${value}</p></div>`).join('')}
        </div>
        <div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Scope and limits</h3><ul class="list-disc pl-5 text-sm text-neutral-400 space-y-2">${scopeLimits || '<li>No scope notes were recorded.</li>'}</ul></div>
      </div>
    </section>

    <section id="section-inventory" class="hidden space-y-6">
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest">${isBinary
            ? '<tr><th class="px-6 py-4">Format</th><th class="px-6 py-4">File</th><th class="px-6 py-4">Architecture</th><th class="px-6 py-4">Type</th><th class="px-6 py-4">Packaging / runtime</th><th class="px-6 py-4">Size</th><th class="px-6 py-4 text-right">Linked libraries</th></tr>'
            : '<tr><th class="px-6 py-4">Platform</th><th class="px-6 py-4">Application</th><th class="px-6 py-4">Package / Bundle ID</th><th class="px-6 py-4">Version</th><th class="px-6 py-4">OS / SDK</th><th class="px-6 py-4 text-right">Components</th></tr>'}</thead>
          <tbody id="apps-table-body" class="divide-y divide-neutral-800">${appRows || `<tr><td colspan="${isBinary ? 7 : 6}" class="px-6 py-4 text-sm text-neutral-500">No ${isBinary ? 'file' : 'app'} metadata was extracted.</td></tr>`}</tbody>
        </table>
      </div>
      <p class="text-xs text-neutral-500">${isBinary ? 'Select the row to inspect the metadata read from the file. This is static analysis; the file is never executed or loaded.' : 'Select an app row to inspect extracted package metadata. This is static package analysis; the app is not executed.'}</p>
    </section>

    <section id="section-native" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">${esc(T.nativeHeading)}</h2>${isBinary ? '' : `<p class="text-xs text-neutral-500 mono">${nativeCount} binar${nativeCount === 1 ? 'y' : 'ies'}</p>`}</div>
      ${nativeHtml || (isBinary ? '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No hardening data could be read from this file (see the analysis notes on the Scan Info tab).</div>' : '<div class="glass rounded-xl p-6 text-sm text-neutral-400">No native libraries or executables were found in this package, so there is nothing to analyse.</div>')}
    </section>

    <section id="section-behavior" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Behavior Checks</h2><p class="text-xs text-neutral-500 mono">${behaviorFunctions} ${(p.apps || []).length && (p.apps || []).every(a => a?.platform === 'binary' || a?.platform === 'ios') ? 'function' : 'API'}${behaviorFunctions === 1 ? '' : 's'} · ${hostCount} remote host${hostCount === 1 ? '' : 's'}</p></div>
      ${behaviorPanels || `<div class="glass rounded-xl p-6 text-sm text-neutral-400">${(p.apps || []).some(a => a?.platform === 'ios') && !(p.apps || []).some(a => a?.behavior) ? 'No behavior inventory was built: none of the functions imported by the Mach-O files falls in a behavior category (see the analysis notes).' : (p.apps || []).some(a => a?.platform === 'binary') ? 'No behavior inventory was built: nothing the scanner reads in this file (import table, Go function table, Rust paths, packaged-application text) falls in a behavior category (see the analysis notes).' : 'No behavior data was collected: the package has no DEX code to inventory.'}</div>`}
    </section>

    <section id="section-dependencies" class="hidden space-y-6">
      <div class="grid grid-cols-2 md:grid-cols-4 gap-4">
        ${[['Detected components', dependencySummary.total || dependencies.length, '#d4d4d4'], [isBinary ? 'Checked (NVD / OSV)' : 'OSV-queryable', isBinary ? dependencies.filter(d => d.lookup_status && d.lookup_status !== 'not_queryable').length : (dependencySummary.queryable || 0), '#60a5fa'], ['Components with advisories', dependencySummary.vulnerable_dependencies || 0, '#f87171'], ['Advisory matches', dependencySummary.vulnerabilities || 0, '#fb923c']].map(([label, value, color]) => `<div class="glass p-5 rounded-xl"><p class="text-xs text-neutral-500 uppercase font-semibold mb-1">${esc(label)}</p><p class="text-2xl font-bold" style="color:${color}">${Number(value)}</p></div>`).join('')}
      </div>
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">${isBinary ? 'Components' : 'Dependencies'}</h2><div class="flex gap-2 w-full md:w-auto flex-wrap">
        <input id="dep-search" type="text" placeholder="Search name, version, CPE / PURL or source..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64" oninput="applyDependencyFilters()">
        <select id="dep-status" onchange="applyDependencyFilters()" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All lookup states</option><option value="vulnerable">Vulnerable</option><option value="clean">${esc(T.clean)}</option><option value="not_queryable">Not queried</option><option value="lookup_error">Lookup failed</option><option value="lookup_incomplete">Lookup incomplete</option></select></div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">${isBinary ? 'Component' : 'Dependency'}</th><th class="px-6 py-4">Version</th><th class="px-6 py-4">${isBinary ? 'Type' : 'Ecosystem'}</th><th class="px-6 py-4">${isBinary ? 'CPE / Package URL' : 'Package URL / Identity'}</th><th class="px-6 py-4">Status</th><th class="px-6 py-4">Worst severity</th><th class="px-6 py-4 text-right">Advisories</th><th class="px-6 py-4">Evidence source</th></tr></thead>
          <tbody id="dependencies-table-body" class="divide-y divide-neutral-800">${dependencyRows || '<tr><td colspan="8" class="px-6 py-4 text-sm text-neutral-500">No dependency metadata was extracted from this package.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="dependencies-empty" class="hidden text-sm text-neutral-500 italic">No components or dependencies match the selected filters.</p>
      <p id="dependencies-filter-count" class="text-xs text-neutral-500"></p>
      ${isBinary ? '<p class="text-xs text-neutral-500">Components are found from version banners in the file (C / C++ libraries, Node.js and Python runtimes), Go build info, Rust crates and the packages of npm- and Python-based applications. Banners are matched against NVD CPE ranges; Go, Rust, npm and Python packages against OSV.dev. Only component names and versions leave the machine. A component with no advisory is not proof of safety: it only means none was published for that exact version at scan time. Every advisory is also listed on the Vulnerabilities tab and counted in the totals. Click a row for the advisory text, CVSS score and fixed versions.</p>' : ''}
      <p class="text-xs text-neutral-500 ${isBinary ? 'hidden' : ''}">Only exact, supported, versioned package URLs are queried. Native .so/.dylib binaries and embedded native frameworks are excluded from the Dependencies tab and are never submitted to OSV; native hardening and secret checks remain separate. If an APK/IPA omits its build lockfiles or package metadata, a package may remain Not queried rather than being reported as clean. Click a row to inspect advisory details and source evidence.</p>
    </section>

    <section id="section-vulnerabilities" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Vulnerability Findings</h2><div class="flex gap-2 w-full md:w-auto flex-wrap">
        <input id="v-search" type="text" placeholder="Search title, rule, artifact, evidence..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64">
        <select id="v-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="v-origin" class="${isBinary ? 'hidden ' : ''}bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All origins</option><option value="app">App / package</option><option value="unknown">Unattributed (renamed classes)</option><option value="library">Third-party library</option></select>
        <select id="v-masvs" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All ${isBinary ? 'areas' : 'MASVS areas'}</option>${masvsOptions}</select></div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Severity</th><th class="px-6 py-4">Vulnerability</th><th class="px-6 py-4">${esc(T.file)}</th><th class="px-6 py-4">${isBinary ? 'Component / location' : 'Artifact'}</th><th class="px-6 py-4">${esc(T.area)}</th><th class="px-6 py-4">Confidence</th></tr></thead>
          <tbody id="vulnerabilities-table-body" class="divide-y divide-neutral-800">${vulnRows || '<tr><td colspan="6" class="px-6 py-4 text-sm text-neutral-500">No vulnerabilities detected.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="vulnerabilities-empty" class="hidden text-sm text-neutral-500 italic">No vulnerabilities match the selected filters.</p>
      <p id="vulnerabilities-filter-count" class="text-xs text-neutral-500"></p>
      <p class="text-xs text-neutral-500">${isBinary ? 'Known-vulnerable components (one row per advisory, also on the Components tab) and risky imported functions. Hardcoded secrets and hardening gaps are listed in their own tabs and never repeated here. A component advisory shows the vulnerable code is present in the file, not that it is reachable.' : 'Insecure code, cryptography, storage and data handling. Hardcoded secrets and configuration weaknesses are listed in their own tabs and never repeated here. Known-vulnerable third-party packages are on the Dependencies tab.'}</p>
    </section>

    <section id="section-secrets" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Hardcoded Secrets</h2><div class="flex gap-2 w-full md:w-auto flex-wrap">
        <input id="s-search" type="text" placeholder="Search title, rule, artifact, app..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64">
        <select id="s-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="s-rule" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All secret types</option>${secretOptions}</select></div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Severity</th><th class="px-6 py-4">Title</th><th class="px-6 py-4">${esc(T.file)}</th><th class="px-6 py-4">Artifact</th><th class="px-6 py-4">${esc(T.area)}</th><th class="px-6 py-4">Confidence</th></tr></thead>
          <tbody id="secrets-table-body" class="divide-y divide-neutral-800">${secretRows || '<tr><td colspan="6" class="px-6 py-4 text-sm text-neutral-500">No hardcoded secrets detected.</td></tr>'}</tbody>
        </table>
      </div>
      <p id="secrets-empty" class="hidden text-sm text-neutral-500 italic">No secrets match the selected filters.</p>
      <p id="secrets-filter-count" class="text-xs text-neutral-500"></p>
      <p class="text-xs text-neutral-500">Secret values are never written to the report; only a masked preview is shown. A match proves the string is in the ${isBinary ? 'file' : 'package'}, not that the credential is still valid.</p>
    </section>

    <section id="section-misconfigs" class="hidden space-y-6">
      <div class="flex flex-col md:flex-row gap-4 justify-between items-start md:items-center"><h2 class="text-xl font-bold">Misconfigurations</h2><div class="flex gap-2 w-full md:w-auto flex-wrap">
        <input id="m-search" type="text" placeholder="Search title, rule, artifact, app..." class="bg-neutral-800 border border-neutral-700 rounded-lg px-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-red-500 w-full md:w-64">
        <select id="m-severity" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All severities</option>${SEVERITIES.map(s => `<option value="${s}">${esc(s)}</option>`).join('')}</select>
        <select id="m-rule" class="bg-neutral-800 border border-neutral-700 rounded-lg px-3 py-2 text-sm focus:outline-none"><option value="all">All rule categories</option>${misconfigOptions}</select></div>
      </div>
      <div class="glass rounded-xl overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Severity</th><th class="px-6 py-4">Title</th><th class="px-6 py-4">${esc(T.file)}</th><th class="px-6 py-4">Artifact</th><th class="px-6 py-4">${esc(T.area)}</th><th class="px-6 py-4">Confidence</th></tr></thead>
          <tbody id="misconfigs-table-body" class="divide-y divide-neutral-800">${misconfigRows || '<tr><td colspan="6" class="px-6 py-4 text-sm text-neutral-500">No misconfigurations detected.</td></tr>'}</tbody>
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
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">${esc(T.chart3)}</h3><div class="h-48 relative"><canvas id="originStatsChart"></canvas></div>${isBinary
          ? `<div class="space-y-2 text-sm"><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Vulnerabilities</span><span class="mono">${vulns.length}</span></div><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Secrets</span><span class="mono">${secrets.length}</span></div><div class="flex justify-between"><span class="text-neutral-500">Misconfigurations</span><span class="mono">${misconfigs.length}</span></div></div>`
          : `<div class="space-y-2 text-sm"><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">App / package</span><span class="mono">${Number(p.stats?.by_origin?.app || 0)}</span></div><div class="flex justify-between border-b border-neutral-800 pb-2"><span class="text-neutral-500">Unattributed (renamed classes)</span><span class="mono">${Number(p.stats?.by_origin?.unknown || 0)}</span></div><div class="flex justify-between"><span class="text-neutral-500">Third-party library</span><span class="mono">${Number(p.stats?.by_origin?.library || 0)}</span></div></div>`}</div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Confidence Distribution</h3><div class="h-48 relative"><canvas id="confidenceChart"></canvas></div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">${esc(T.chart2)}</h3><div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Area</th><th class="px-6 py-4 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByMasvs.map(([k, v]) => `<tr><td class="px-6 py-4 ${isBinary ? '' : 'mono'}">${esc(areaText(k))}</td><td class="px-6 py-4 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-6 py-4 text-neutral-500">No MASVS data.</td></tr>'}</tbody></table></div></div>
        <div class="glass p-6 rounded-xl space-y-4"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Issues by ${isBinary ? 'File' : 'App'}</h3><div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">${isBinary ? 'File' : 'App'}</th><th class="px-6 py-4 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByApp.map(([k, v]) => `<tr><td class="px-6 py-4 break-all">${esc(k)}</td><td class="px-6 py-4 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-6 py-4 text-neutral-500">No findings.</td></tr>'}</tbody></table></div></div>
        <div class="glass p-6 rounded-xl space-y-4 md:col-span-2 lg:col-span-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Most Frequent Rules</h3><div class="overflow-x-auto"><table class="w-full text-left text-sm"><thead class="bg-neutral-800/50 text-neutral-400 uppercase text-[10px] tracking-widest"><tr><th class="px-6 py-4">Rule</th><th class="px-6 py-4 text-right">Issues</th></tr></thead><tbody class="divide-y divide-neutral-800">${statsByRule.map(([k, v]) => `<tr><td class="px-6 py-4 mono break-all">${esc(k)}</td><td class="px-6 py-4 text-right mono">${Number(v)}</td></tr>`).join('') || '<tr><td colspan="2" class="px-6 py-4 text-neutral-500">No rule data.</td></tr>'}</tbody></table></div></div>
      </div>
    </section>

    <section id="section-scaninfo" class="hidden space-y-8">
      <div class="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>Scan</h3><div class="space-y-3 text-sm">
          ${kvRow('Tool', p.tool || 'ubel-mobile')}${kvRow('Version', p.tool_version || 'unknown')}${kvRow('Generated at', p.generated_at || 'unknown')}${kvRow('Report ID', p.report_id || 'unknown')}${kvRow('Minimum severity filter', p.min_severity || 'info')}${kvRow('Hidden by filter', p.hidden_by_filter || 0)}
        </div></div>
        <div class="glass p-6 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400 flex items-center gap-2"><svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="2" y="3" width="20" height="14" rx="2" ry="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>Target Artifact</h3><div class="space-y-3 text-sm">
          ${kvRow('File', targetFile)}${kvRow('Kind', p.target?.kind || 'unknown')}${kvRow('Size', `${(Number(p.target?.size_bytes || 0) / 1048576).toFixed(2)} MB`)}${kvRow('SHA-256', p.target?.sha256 || 'unknown')}${isBinary ? '' : kvRow('Detected apps', (p.apps || []).length)}${kvRow('Asset name', p.asset_name || 'unknown')}${kvRow('Asset ID', p.asset_id || 'unknown')}${kvRow('Machine ID', p.machine_id || 'unknown')}
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
const IS_BINARY = ${isBinary ? 'true' : 'false'};
const AREA_NAMES = ${JSON.stringify(AREA_NAMES)};
const areaText = v => { const k = String(v || 'Unmapped').replace(/-\\d+$/, ''); return IS_BINARY ? (AREA_NAMES[k] || k) : (v || 'Unmapped'); };
const chartInstances = [];
function escH(s) { return String(s == null ? '' : s).replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch])); }
function switchTab(id) {
  document.querySelectorAll('nav button').forEach(b => b.classList.remove('tab-active'));
  const button = document.getElementById('tab-' + id); if (button) button.classList.add('tab-active');
  document.querySelectorAll('main section').forEach(section => section.classList.add('hidden'));
  const section = document.getElementById('section-' + id); if (section) section.classList.remove('hidden');
  chartInstances.forEach(chart => { try { chart.resize(); } catch (_) {} });
}
function switchBehavior(app, id) {
  document.querySelectorAll('[data-bh-panel][data-bh-app="' + app + '"]').forEach(el => el.classList.toggle('hidden', el.dataset.bhPanel !== id));
  document.querySelectorAll('[data-bh-pill][data-bh-app="' + app + '"]').forEach(el => el.classList.toggle('bh-pill-active', el.dataset.bhPill === id));
}
function filterHosts(app, q) {
  const needle = String(q || '').trim().toLowerCase();
  document.querySelectorAll('tr[data-bh-host-app="' + app + '"]').forEach(function (row) { row.classList.toggle('hidden', needle !== '' && (row.dataset.search || '').indexOf(needle) < 0); });
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
  openModal('<div class="space-y-5"><div><div class="flex flex-wrap items-center gap-3 mb-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + c + ';border-color:' + c + '">' + escH(f.severity || 'info') + '</span><span class="mono text-xs text-neutral-500">' + escH(f.rule || '') + '</span></div><h2 class="text-xl font-bold pr-8">' + escH(f.title || 'Untitled finding') + '</h2><p class="text-sm text-neutral-400 mt-2">' + escH(f.description || '') + '</p></div><div class="glass p-5 rounded-xl space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + escH(CATEGORY_LABEL[f.category] || 'Issue') + ' Details</h3>' + (f.component ? modalMetaRow('Component', f.component.name + (f.component.version ? ' ' + f.component.version : '')) + modalMetaRow('Advisory', f.component.advisory) : modalMetaRow('Artifact', (f.artifact || '') + (f.line ? ':' + f.line : ''))) + modalMetaRow(IS_BINARY ? 'File' : 'Application', f.app || '—') + (IS_BINARY ? '' : modalMetaRow('Origin', f.origin || 'app')) + modalMetaRow('Confidence', f.confidence || 'unknown') + modalMetaRow(IS_BINARY ? 'Area' : 'MASVS', IS_BINARY ? areaText(f.masvs) : (f.masvs || 'Unmapped')) + modalMetaRow('CWE', f.cwe || '—') + '</div>' + evidence + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Remediation</h3><p class="text-sm text-neutral-300">' + escH(f.remediation || 'Review this finding manually.') + '</p></div>' + (compliance ? '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Compliance Frameworks</h3>' + compliance + '</div>' : '') + '</div>');
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
  html += renderDiffGroup(DIFF_GROUPS[2]);
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
  section.innerHTML = html;
}
function openMobileDiffModal(group, list) {
  const d = reportData.diffs;
  const items = d && d[group] && d[group][list] || [];
  const labels = { new: 'New', unchanged: 'Still existing', removed: group === 'secrets' ? 'Removed' : 'Fixed' };
  const groupLabels = { vulnerabilities: 'vulnerabilities', secrets: 'secrets', misconfigs: 'misconfigurations' };
  const rows = items.map(item => '<tr><td class="py-2 pr-4 uppercase text-[10px] font-bold severity-' + escH(String(item.severity || 'unknown').toLowerCase()) + '">' + escH(item.severity || 'unknown') + '</td><td class="py-2 pr-4 font-medium">' + escH(item.title || item.rule || 'Untitled issue') + '</td><td class="py-2 pr-4 text-neutral-400">' + escH(item.app || '—') + '</td><td class="py-2 pr-4 mono text-neutral-400">' + escH(item.artifact || '—') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.rule || '—') + '</td><td class="py-2 pr-4 mono text-neutral-500">' + escH(item.masvs || '—') + '</td></tr>').join('');
  const body = rows ? '<div class="overflow-auto max-h-[60vh]"><table class="w-full text-left text-xs"><thead class="text-neutral-500 uppercase text-[10px] tracking-widest"><tr>' + ['Severity', 'Issue', IS_BINARY ? 'File' : 'App', 'Artifact', 'Rule', IS_BINARY ? 'Area' : 'MASVS'].map(label => '<th class="pb-2 pr-4 font-bold">' + label + '</th>').join('') + '</tr></thead><tbody class="divide-y divide-neutral-800">' + rows + '</tbody></table></div>' : '<p class="text-sm text-neutral-500 italic">None.</p>';
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
  if (a.remote_hosts && a.remote_hosts.total) {
    const rh = a.remote_hosts;
    add('Remote hosts', rh.total + ' (' + rh.domains + ' domain(s), ' + rh.ips + ' IP address(es)) — ' + (rh.hosts || []).slice(0, 8).map(function (h) { return h.host; }).join(', ') + (rh.total > 8 ? ' …' : ''));
  }
  add('Platform', a.platform === 'binary' ? (a.format === 'macho' ? 'Mach-O' : a.format === 'pe' ? 'PE' : 'ELF') : a.platform === 'ios' ? 'iOS' : 'Android');
  if (a.platform === 'binary') {
    add('Name', a.name); add('Size', a.size_bytes ? (a.size_bytes / 1048576).toFixed(2) + ' MB' : ''); add('Architecture', (a.architectures || [a.arch]).join(', ')); add('Type', a.kind); add('Bits', a.bits);
    add('Linked libraries', (a.needed || []).join(', ')); add('Signed', a.signed === undefined ? '' : (a.signed ? 'yes (presence only, not verified)' : 'no'));
    add('Stripped', a.stripped === undefined ? '' : (a.stripped ? 'yes' : 'no')); add('Statically linked', a.static === undefined ? '' : (a.static ? 'yes' : 'no')); add('.NET assembly', a.managed ? 'yes' : '');
    add('Embedded runtime', (a.runtimes || []).map(r => r.name + ' ' + (r.version || '')).join(', '));
    add('Packaging', (a.packaging || []).map(x => [x.kind, x.node_version && ('Node ' + x.node_version), x.packages != null && (x.packages + ' package(s)')].filter(Boolean).join(' · ')).join('; '));
    if (a.go) add('Go build', [a.go.version || a.go.go_version, a.go.modules != null && (a.go.modules + ' module(s)')].filter(Boolean).join(' · '));
    if (a.behavior) {
      const labels = ${JSON.stringify(NATIVE_BEHAVIOR_LABELS)};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        const origins = Object.keys(byOrigin || {}), n = origins.reduce(function (t, o) { const x = byOrigin[o]; return t + (x.functions != null ? x.functions : Object.keys(x.apis || {}).length); }, 0);
        const shown = origins.slice(0, 4).map(function (o) { const apis = Object.keys(byOrigin[o].apis || {}); return o + ': ' + apis.slice(0, 3).join(', ') + (apis.length > 3 ? ' …' : ''); });
        add('Behavior · ' + (labels[cat] || cat), n + ' function' + (n === 1 ? '' : 's') + ' — ' + shown.join(' · ') + (origins.length > 4 ? ' · … (' + origins.length + ' sources)' : ''));
      }
    }
  } else if (a.platform === 'ios') {
    if (a.behavior) {
      const labels = ${JSON.stringify(NATIVE_BEHAVIOR_LABELS)};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        const origins = Object.keys(byOrigin || {}), n = origins.reduce(function (t, o) { const x = byOrigin[o]; return t + (x.functions != null ? x.functions : Object.keys(x.apis || {}).length); }, 0);
        add('Behavior · ' + (labels[cat] || cat), n + ' function' + (n === 1 ? '' : 's') + ' — ' + origins.map(function (o) { return o + ': ' + Object.keys(byOrigin[o].apis || {}).slice(0, 3).join(', '); }).join(' · '));
      }
    }
    add('Name', a.name); add('Bundle ID', a.bundle_id); add('Version', a.version); add('Build', a.build); add('Minimum iOS', a.min_os); add('Architectures', (a.architectures || []).join(', '));
    add('Binary', a.binary ? ('PIE ' + (a.binary.pie ? 'yes' : 'no') + ', encrypted ' + (a.binary.encrypted ? 'yes' : 'no') + ', signed ' + (a.binary.signed ? 'yes' : 'no') + (a.binary.swift ? ', Swift' : '')) : '—');
    add('Provisioning', a.provisioning ? [a.provisioning.type, a.provisioning.name, a.provisioning.team, 'expires ' + (a.provisioning.expires || '?')].filter(Boolean).join(' — ') : '—');
    add('URL schemes', (a.url_schemes || []).join(', ')); add('Frameworks', (a.frameworks || []).map(f => f.name + (f.version ? ' ' + f.version : '')).join(', ')); add('Extensions', (a.extensions || []).map(e => e.name).join(', ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; '));
  } else {
    add('Package', a.package); add('Version', (a.version_name || '?') + ' (' + (a.version_code || '?') + ')'); add('SDK', 'min ' + (a.min_sdk ?? '?') + ' / target ' + (a.target_sdk ?? '?'));
    add('Components', Object.entries(a.components || {}).map(([k,v]) => v + ' ' + k).join(', ')); add('Permissions', (a.permissions || []).length);
    add('Signing', a.signing ? (a.signing.schemes || []).join(', ') + ' — ' + (a.signing.certificates || []).map(cert => cert.subject + ' [' + cert.key + ', ' + cert.signature_algorithm + ']').join('; ') : '—');
    add('Frameworks', (a.frameworks || []).join(', ')); add('Cross-platform', (a.cross_platform || []).map(f => f.name + ' (' + [f.engine, f.backend, f.mode, f.flavour, f.dart_version && ('Dart ' + f.dart_version), f.unity_version].filter(Boolean).join(', ') + ')').join('; ')); add('Modules', (a.modules || []).map(m => m.name + ' (' + m.type + ')').join(', ')); add('DEX files', (a.dex_files || []).join(', ')); add('Native libraries', (a.native_libs || []).length); add('Native hardening', a.native_hardening ? (a.native_hardening.total + ' binaries / ' + a.native_hardening.libraries + ' libraries (' + (a.native_hardening.abis || []).join(', ') + ') — failing: ' + (Object.entries(a.native_hardening.failing || {}).filter(function (kv) { return kv[1] > 0; }).map(function (kv) { return kv[0] + ' x' + kv[1]; }).join(', ') || 'none')) : ''); add('Embedded libraries', (a.libraries || []).map(l => l.name + ' ' + (l.version || '')).join(', '));
    if (a.behavior) {
      const labels = ${JSON.stringify({ ...BEHAVIOR_LABELS, ...NATIVE_BEHAVIOR_LABELS })};
      for (const [cat, byOrigin] of Object.entries(a.behavior.categories || {})) {
        add('Behavior · ' + (labels[cat] || cat), ['app', 'unknown', 'library'].filter(o => byOrigin[o]).map(o => o + ': ' + byOrigin[o].calls + ' (' + Object.entries(byOrigin[o].apis).slice(0, 4).map(kv => kv[0] + ' ×' + kv[1]).join(', ') + ')').join(' · '));
      }
      const ia = a.behavior.intent_actions || {}, it = a.behavior.intent_actions_total || {};
      add('Intent actions (app code)', (ia.app || []).slice(0, 12).join(', ') + ((it.app || 0) > 12 ? ' … (' + it.app + ' total)' : ''));
      add('Intent actions (unattributed / library)', (it.unknown || 0) + ' / ' + (it.library || 0));
    }
    if (a.online_checks) {
      const o = a.online_checks;
      add('Online · App Links', (o.assetlinks || []).map(x => x.host + ': ' + x.state).join('; '));
      add('Online · Firebase database', (o.firebase_database || []).map(x => x.url + ': ' + x.state).join('; '));
      add('Online · Remote Config', o.remote_config ? o.remote_config.state + (o.remote_config.entries ? ' (' + o.remote_config.entries + ' parameters)' : '') : '');
    }
  }
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">App Inventory</p><h2 class="text-xl font-bold pr-8">' + escH(a.name || a.package || a.bundle_id || 'Application') + '</h2></div><div class="glass p-5 rounded-xl space-y-3">' + rows.join('') + '</div></div>');
}
function openDependencyModal(index) {
  const dep = (reportData.dependencies || [])[index]; if (!dep) return;
  const statusLabels = { vulnerable: 'Vulnerable', clean: IS_BINARY ? 'No known advisory' : 'Safe', not_queryable: 'Not queried', lookup_error: 'Lookup failed', lookup_incomplete: 'Lookup incomplete', pending: 'Pending' };
  const sources = [...(dep.sources || [])].map(s => '<li><code class="mono text-xs break-all">' + escH(s) + '</code></li>').join('') || '<li>Source path unavailable</li>';
  const sourceTypes = (dep.source_types || []).map(escH).join(', ') || 'Unknown';
  const advisories = (dep.vulnerabilities || []).map(v => {
    const sev = String(v.severity || 'unknown').toLowerCase();
    const color = { critical: '#ef4444', high: '#f87171', medium: '#fb923c', moderate: '#fb923c', low: '#60a5fa', info: '#a3a3a3' }[sev] || '#a3a3a3';
    const id = v.url ? '<a class="underline text-red-300" href="' + escH(v.url) + '" target="_blank" rel="noopener noreferrer">' + escH(v.id) + '</a>' : escH(v.id || 'Unknown advisory');
    const aliases = (v.aliases || []).join(', ');
    const fixes = (v.fixed_versions || []).join(', ');
    return '<div class="glass p-4 rounded-xl space-y-2"><div class="flex flex-wrap items-center justify-between gap-2"><span class="px-2 py-1 rounded border text-xs uppercase font-bold" style="color:' + color + ';border-color:' + color + '">' + escH(sev) + '</span><span class="mono text-xs">' + id + '</span></div><h4 class="font-semibold text-sm">' + escH(v.summary || v.id || 'OSV advisory') + '</h4>' + (v.details ? '<p class="text-xs text-neutral-400 whitespace-pre-wrap break-words">' + escH(v.details.slice(0, 5000)) + (v.details.length > 5000 ? '…' : '') + '</p>' : '') + '<div class="text-xs text-neutral-500 space-y-1">' + (aliases ? '<p>Aliases: ' + escH(aliases) + '</p>' : '') + '<p>Affected version: ' + escH(v.affected_dependency_version || dep.version || 'unknown') + '</p>' + (fixes ? '<p>Fixed versions: <span class="text-green-300">' + escH(fixes) + '</span></p>' : '<p>No fixed version is listed for this advisory.</p>') + (v.severity_score != null ? '<p>CVSS score: <span class="mono text-neutral-300">' + escH(v.severity_score) + '</span>' + (v.severity_vector ? ' <span class="mono break-all">' + escH(v.severity_vector) + '</span>' : '') + '</p>' : '') + (v.published ? '<p>Published: ' + escH(v.published) + '</p>' : '') + (v.is_infection ? '<p class="text-purple-300 font-semibold">Malicious-package advisory</p>' : '') + '</div></div>';
  }).join('');
  const error = dep.lookup_error ? '<div class="border border-orange-500/40 bg-orange-500/10 rounded-lg p-3 text-xs text-orange-200">' + escH(dep.lookup_error) + '</div>' : '';
  const reason = dep.lookup_reason ? '<p class="text-sm text-neutral-400">' + escH(dep.lookup_reason) + '</p>' : '';
  openModal('<div class="space-y-5"><div><p class="text-xs text-neutral-500 uppercase tracking-widest mb-1">' + (IS_BINARY ? 'Component' : 'Mobile dependency') + '</p><h2 class="text-xl font-bold pr-8 break-all">' + escH(dep.name || 'Unknown dependency') + '</h2><p class="text-xs text-neutral-500 mt-2">' + escH(dep.ecosystem || 'Unknown ecosystem') + ' · ' + escH(dep.version || 'version unavailable') + '</p></div><div class="glass p-5 rounded-xl space-y-3">' + modalMetaRow(IS_BINARY ? 'Lookup status' : 'OSV status', statusLabels[dep.lookup_status] || dep.lookup_status || 'Not queried') + (dep.cpe ? modalMetaRow('CPE', dep.cpe) : '') + (IS_BINARY && !dep.purl ? '' : modalMetaRow('Package URL', dep.purl || 'Not available')) + (IS_BINARY && !dep.coordinate ? '' : modalMetaRow('Coordinate / identity', dep.coordinate || 'Not available')) + (IS_BINARY && !dep.confidence ? '' : modalMetaRow('Detection confidence', dep.confidence || 'unknown')) + (IS_BINARY && !(dep.source_types || []).length ? '' : modalMetaRow('Evidence type', sourceTypes)) + modalMetaRow('Known advisories', dep.vulnerability_count || 0) + '</div>' + reason + error + '<div class="glass p-5 rounded-xl space-y-2"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">Evidence source(s)</h3><ul class="list-disc pl-5 text-sm text-neutral-300 space-y-1">' + sources + '</ul></div><div class="space-y-3"><h3 class="text-sm font-semibold uppercase tracking-widest text-neutral-400">' + (IS_BINARY ? 'Advisories (' : 'OSV advisories (') + (dep.vulnerabilities || []).length + ')</h3>' + (advisories || '<p class="text-sm text-neutral-500 italic">' + (IS_BINARY ? 'No advisory is attached to this component.' : 'No OSV advisory details are attached to this dependency.') + '</p>') + '</div></div>');
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
  document.getElementById('dependencies-filter-count').textContent = shown + ' of ' + rows.length + (IS_BINARY ? ' components shown' : ' dependencies shown');
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
  const chart = new Chart(el, { type, data: { labels, datasets: [{ data, backgroundColor: colors, borderColor: '#171717', borderWidth: 2 }] }, options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: type !== 'bar', position: 'bottom', labels: { color: '#a3a3a3', boxWidth: 10 } } }, scales: type === 'bar' ? { x: { ticks: { color: '#a3a3a3' }, grid: { color: '#262626' } }, y: { beginAtZero: true, ticks: { precision: 0, color: '#a3a3a3' }, grid: { color: '#262626' } } } : {} } }); chartInstances.push(chart);
}
const severityKeys = ['critical','high','medium','low','info'];
const severityPalette = ['#ef4444','#f87171','#fb923c','#60a5fa','#a3a3a3'];
makeChart('severityChart','doughnut',severityKeys.map(s=>s.toUpperCase()),severityKeys.map(s=>Number(reportData.summary?.counts?.[s]||0)),severityPalette);
const masvsEntries=Object.entries(reportData.summary?.by_masvs||{}).sort((a,b)=>b[1]-a[1]).slice(0,8);
const byCategory=reportData.summary?.by_category||{};
const categoryChart=[['Vulnerabilities',Number(byCategory.vulnerabilities||0),'#f87171'],['Secrets',Number(byCategory.secrets||0),'#c084fc'],['Misconfigurations',Number(byCategory.misconfigurations||0),'#fb923c']].filter(x=>x[1]>0);
makeChart('masvsChart','bar',masvsEntries.map(x=>areaText(x[0])),masvsEntries.map(x=>x[1]),masvsEntries.map((_,i)=>['#ef4444','#fb923c','#60a5fa','#a78bfa','#34d399','#f472b6','#facc15','#94a3b8'][i%8]));
['originChart','originStatsChart'].forEach(id=>IS_BINARY
  ? makeChart(id,'doughnut',categoryChart.map(x=>x[0]),categoryChart.map(x=>x[1]),categoryChart.map(x=>x[2]))
  : makeChart(id,'doughnut',['App / package','Unattributed (renamed)','Third-party library'],[Number(reportData.stats?.by_origin?.app||0),Number(reportData.stats?.by_origin?.unknown||0),Number(reportData.stats?.by_origin?.library||0)],['#ef4444','#a3a3a3','#60a5fa']));
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