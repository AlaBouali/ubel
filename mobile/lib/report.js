'use strict';
// report.js — turns findings into the report payload (JSON), the plain-language executive summary
// and a self-contained HTML report (no external assets, everything escaped).

import { SEVERITIES } from './rules.js';

export const LIMITS = [
  'Static analysis of the package only: nothing is executed, no network request is made, no server is contacted.',
  'There is no decompiler: findings come from the manifest/plist, resources, constant tables, API references and call arguments, and binary metadata — not from data-flow analysis. Items marked low or medium confidence are leads to verify.',
  'Obfuscated or packed code, encrypted strings, native/Hermes bytecode and code downloaded at runtime are only partly visible.',
  'Hardcoded-secret detection uses UBEL’s shared secrets rules; a match proves the string is in the package, not that the credential is still valid.',
];

export function buildPayload({ meta, target, apps, findings, notes, diffs }) {
  const sorted = findings.sorted();
  const counts = findings.counts();
  const byMasvs = {};
  for (const f of sorted) { const k = String(f.masvs).replace(/-\d+$/, ''); byMasvs[k] = (byMasvs[k] || 0) + 1; }
  const highest = SEVERITIES.find(s => counts[s] > 0) || 'none';
  const payload = {
    schema: 'ubel-mobile/1', tool: 'ubel-mobile', ...meta,
    target, apps,
    summary: { total: sorted.length, counts, highest_severity: highest, by_masvs: byMasvs },
    findings: sorted,
    analysis_notes: notes,
    limits: LIMITS,
    diffs: diffs || null,
  };
  payload.executive_summary = executiveSummary(payload);
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
  const top = p.findings.filter(f => f.severity === 'critical' || f.severity === 'high').slice(0, 6)
    .map(f => ({ severity: f.severity, title: f.title, where: f.artifact }));
  const areas = Object.entries(p.summary.by_masvs).sort((a, b) => b[1] - a[1]).slice(0, 3).map(([k]) => MASVS_LABEL[k] || k.toLowerCase());
  const paragraphs = [
    `This report covers the ${platform} app ${appNames.join(', ') || 'in the scanned package'}. The package was examined without running it: its configuration, embedded files, code and resources were inspected for hardcoded secrets, insecure data handling and risky settings, and the findings are mapped to the OWASP Mobile Application Security Verification Standard (MASVS).`,
    `${p.summary.total} finding(s) were recorded: ${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low and ${c.info} informational.${areas.length ? ` Most of them concern ${areas.join(', ')}.` : ''}`,
    c.critical + c.high > 0
      ? 'Critical and high findings can usually be exploited by anyone who can download the app (for example by extracting a secret from the package) or by another app on the same device. They are listed first below.'
      : 'None of the findings is rated critical or high.',
  ];
  const actions = [];
  const seen = new Set();
  for (const f of p.findings) {
    if (seen.has(f.rule) || f.severity === 'info') continue;
    seen.add(f.rule);
    actions.push(f.remediation);
    if (actions.length >= 6) break;
  }
  return { rating, headline, paragraphs, top_findings: top, recommended_actions: actions, scope_and_limits: LIMITS };
}

// ── HTML ───────────────────────────────────────────────────────────────────────────────────────────
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export function buildHtml(p) {
  const c = p.summary.counts;
  const es = p.executive_summary;
  const apps = p.apps.map(a => a.platform === 'ios' ? appCardIos(a) : appCardAndroid(a)).join('');
  const rows = p.findings.map((f, i) => `
    <details class="f sev-${esc(f.severity)}" data-sev="${esc(f.severity)}">
      <summary><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span><span class="t">${esc(f.title)}</span><span class="loc">${esc(f.artifact)}</span></summary>
      <div class="body">
        <p>${esc(f.description)}</p>
        ${f.evidence.length ? `<h4>Evidence${f.evidence_total && f.evidence_total > f.evidence.length ? ` (${f.evidence.length} of ${f.evidence_total})` : ''}</h4><ul>${f.evidence.map(e => `<li><code>${esc(e)}</code></li>`).join('')}</ul>` : ''}
        <h4>How to fix</h4><p>${esc(f.remediation)}</p>
        <p class="meta">${esc(f.rule)} · ${esc(f.masvs)}${f.cwe ? ` · ${esc(f.cwe)}` : ''} · confidence ${esc(f.confidence)} · ${esc(f.origin)} code${f.app ? ` · ${esc(f.app)}` : ''}${f.line ? ` · line ${f.line}` : ''}</p>
      </div>
    </details>`).join('') || '<p>No findings.</p>';
  const diff = p.diffs ? `
    <section><h2>Changes since the previous scan</h2>
    <p class="meta">Compared with ${esc(p.diffs.previous_file)} (${esc(p.diffs.previous_generated_at || '')}): ${p.diffs.new.length} new, ${p.diffs.fixed.length} fixed, ${p.diffs.unchanged} unchanged.</p>
    ${p.diffs.new.length ? `<h4>New</h4><ul>${p.diffs.new.map(f => `<li><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)} <code>${esc(f.artifact)}</code></li>`).join('')}</ul>` : ''}
    ${p.diffs.fixed.length ? `<h4>Fixed</h4><ul>${p.diffs.fixed.map(f => `<li><span class="badge ${esc(f.severity)}">${esc(f.severity)}</span> ${esc(f.title)} <code>${esc(f.artifact)}</code></li>`).join('')}</ul>` : ''}
    </section>` : '';
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>UBEL Mobile report — ${esc(p.apps.map(a => a.package || a.bundle_id).join(', '))}</title>
<style>
:root{--bg:#fff;--fg:#1b1f24;--mut:#59636e;--card:#f6f8fa;--bd:#d0d7de;--critical:#a40e26;--high:#d1242f;--medium:#bf8700;--low:#0969da;--info:#6e7781}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--mut:#8b949e;--card:#161b22;--bd:#30363d;--critical:#ff7b72;--high:#f85149;--medium:#d29922;--low:#58a6ff;--info:#8b949e}}
*{box-sizing:border-box}body{margin:0;font:15px/1.5 -apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;background:var(--bg);color:var(--fg)}
main{max-width:1000px;margin:0 auto;padding:24px 16px 64px}h1{font-size:24px;margin:0 0 4px}h2{font-size:18px;margin:28px 0 8px;border-bottom:1px solid var(--bd);padding-bottom:6px}h4{margin:12px 0 4px;font-size:13px;text-transform:uppercase;color:var(--mut)}
.meta{color:var(--mut);font-size:13px}.cards{display:flex;gap:10px;flex-wrap:wrap}.card{background:var(--card);border:1px solid var(--bd);border-radius:8px;padding:10px 14px;min-width:96px}.card b{font-size:22px;display:block}
.badge{display:inline-block;color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;font-weight:600;text-transform:uppercase;margin-right:8px}
.badge.critical{background:var(--critical)}.badge.high{background:var(--high)}.badge.medium{background:var(--medium)}.badge.low{background:var(--low)}.badge.info{background:var(--info)}
details.f{border:1px solid var(--bd);border-left:4px solid var(--info);border-radius:6px;margin:6px 0;background:var(--card)}details.sev-critical{border-left-color:var(--critical)}details.sev-high{border-left-color:var(--high)}details.sev-medium{border-left-color:var(--medium)}details.sev-low{border-left-color:var(--low)}
summary{cursor:pointer;padding:8px 12px;display:flex;gap:6px;align-items:baseline;flex-wrap:wrap}.t{font-weight:600}.loc{color:var(--mut);font-size:12px;margin-left:auto;word-break:break-all}.body{padding:0 14px 10px}
code{font:12.5px ui-monospace,SFMono-Regular,Menlo,monospace;background:rgba(127,127,127,.15);padding:1px 4px;border-radius:3px;word-break:break-all}
.filters button{border:1px solid var(--bd);background:var(--card);color:var(--fg);border-radius:14px;padding:3px 12px;margin:0 4px 4px 0;cursor:pointer}.filters button[aria-pressed=true]{background:var(--fg);color:var(--bg)}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border-bottom:1px solid var(--bd);padding:4px 8px;text-align:left;vertical-align:top}.rating{font-size:20px;font-weight:700}
</style></head><body><main>
<h1>UBEL Mobile report</h1>
<p class="meta">${esc(p.target.file)} · ${esc(p.target.kind)} · ${esc((p.target.size_bytes / 1048576).toFixed(1))} MB · sha256 <code>${esc(p.target.sha256)}</code><br>
Generated ${esc(p.generated_at)} · ubel-mobile ${esc(p.tool_version)} · report ${esc(p.report_id || '')} · asset ${esc(p.asset_name || '')} <code>${esc(p.asset_id || '')}</code></p>

<section><h2>Executive summary</h2>
<p class="rating">${esc(es.rating)}</p><p>${esc(es.headline)}</p>
${es.paragraphs.map(t => `<p>${esc(t)}</p>`).join('')}
${es.top_findings.length ? `<h4>Most important findings</h4><ul>${es.top_findings.map(t => `<li><span class="badge ${esc(t.severity)}">${esc(t.severity)}</span>${esc(t.title)} <span class="meta">(${esc(t.where)})</span></li>`).join('')}</ul>` : ''}
${es.recommended_actions.length ? `<h4>Recommended next steps</h4><ol>${es.recommended_actions.map(t => `<li>${esc(t)}</li>`).join('')}</ol>` : ''}
</section>

<div class="cards">${SEVERITIES.map(s => `<div class="card"><b>${c[s]}</b><span class="badge ${s}">${s}</span></div>`).join('')}</div>

<h2>Apps</h2>${apps}
${diff}
<h2>Findings</h2>
<div class="filters" id="filters"><button data-f="all" aria-pressed="true">all</button>${SEVERITIES.map(s => `<button data-f="${s}" aria-pressed="false">${s} (${c[s]})</button>`).join('')}</div>
<div id="list">${rows}</div>

${p.analysis_notes.length ? `<h2>Analysis notes</h2><ul>${p.analysis_notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
<h2>Scope and limits</h2><ul>${p.limits.map(n => `<li>${esc(n)}</li>`).join('')}</ul>
</main>
<script>
(function(){var b=document.querySelectorAll('#filters button'),l=document.querySelectorAll('#list details.f');
b.forEach(function(x){x.addEventListener('click',function(){var f=x.getAttribute('data-f');b.forEach(function(y){y.setAttribute('aria-pressed',y===x?'true':'false')});
l.forEach(function(d){d.style.display=(f==='all'||d.getAttribute('data-sev')===f)?'':'none'})})})})();
</script></body></html>`;
}

function kv(rows) { return `<table>${rows.filter(r => r[1] !== null && r[1] !== undefined && r[1] !== '').map(([k, v]) => `<tr><th>${esc(k)}</th><td>${v}</td></tr>`).join('')}</table>`; }

function appCardAndroid(a) {
  return `<h3>${esc(a.package)} <span class="meta">Android</span></h3>${kv([
    ['Version', esc(`${a.version_name ?? '?'} (${a.version_code ?? '?'})`)], ['SDK', esc(`min ${a.min_sdk ?? '?'} / target ${a.target_sdk ?? '?'}`)],
    ['Components', esc(Object.entries(a.components).map(([k, v]) => `${v} ${k}`).join(', '))], ['Permissions', esc(String(a.permissions.length))],
    ['Signing', a.signing ? esc(`${a.signing.schemes.join(', ') || 'none'} — ${a.signing.certificates.map(c => `${c.subject} [${c.key}, ${c.signature_algorithm}]`).join('; ')}`) : ''],
    ['Frameworks', esc(a.frameworks.join(', '))], ['DEX files', esc(a.dex_files.join(', '))], ['Native libraries', esc(String(a.native_libs.length))],
    ['Embedded libraries', esc(a.libraries.slice(0, 25).map(l => `${l.name} ${l.version}`).join(', ') + (a.libraries.length > 25 ? ` … (${a.libraries.length})` : ''))],
  ])}`;
}

function appCardIos(a) {
  return `<h3>${esc(a.name || a.bundle_id)} <span class="meta">iOS · ${esc(a.bundle_id)}</span></h3>${kv([
    ['Version', esc(`${a.version ?? '?'} (${a.build ?? '?'})`)], ['Minimum iOS', esc(a.min_os)], ['Architectures', esc(a.architectures.join(', '))],
    ['Binary', a.binary ? esc(`PIE ${a.binary.pie ? 'yes' : 'no'}, encrypted ${a.binary.encrypted ? 'yes' : 'no'}, signed ${a.binary.signed ? 'yes' : 'no'}${a.binary.swift ? ', Swift' : ''}`) : ''],
    ['Provisioning', a.provisioning ? esc(`${a.provisioning.type} — ${a.provisioning.name || ''} (${a.provisioning.team || ''}), expires ${a.provisioning.expires || '?'}`) : ''],
    ['URL schemes', esc(a.url_schemes.join(', '))], ['Frameworks', esc(a.frameworks.slice(0, 30).map(f => `${f.name} ${f.version || ''}`.trim()).join(', '))], ['Extensions', esc(a.extensions.map(e => e.name).join(', '))],
  ])}`;
}
