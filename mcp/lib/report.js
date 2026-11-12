'use strict';
// report.js — the ubel-mcp report: report.mcp.json + report.mcp.html, with the same file layout, report id, asset identity and history zip
// as every other UBEL report (.ubel/reports/latest.mcp.*, ~/.ubel/history/<asset>/<timestamp>.mcp.zip). Everything a server or a configuration
// said is attacker-controlled text: the HTML is built with every value escaped and carries a CSP that forbids scripts and remote content.

import fs from 'node:fs';
import path from 'node:path';
import { buildZip } from '../../sca/zip_writer.js';
import { SEVERITIES, SEVERITY_RANK } from '../../mobile/lib/rules.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId } from '../../sca/report_naming.js';

const CATEGORY = { config: 'Configuration', launch: 'Launch', remote: 'Remote server', tool: 'Tool definitions', resource: 'Tool definitions', source: 'Source', process: 'Running process', package: 'Launcher package', binary: 'Launcher package' };
export const categoryOf = rule => { const p = String(rule).split('.'); return p[0] === 'mcp' ? p[1] : p[0] === 'package' ? 'package' : p[0] === 'binary' ? 'binary' : p[0] === 'secret' ? 'config' : 'other'; };

/** Tool-definition hashes of the previous scan, by server key, for rug-pull detection. */
export function loadBaseline(workingDir, tag) {
  const map = new Map();
  try {
    const j = JSON.parse(fs.readFileSync(path.join(workingDir, '.ubel', 'reports', reportFileName('latest', tag, 'json')), 'utf8'));
    for (const s of j.servers || []) if (s.key && Array.isArray(s.definitions?.tools)) map.set(s.key, { tools: s.definitions.tools });
  } catch { /* first scan, or an unreadable previous report: no baseline */ }
  return map;
}

export function buildPayload({ meta, servers, findings, notes, files, scanned }) {
  const list = findings.map(f => ({ ...f, category: categoryOf(f.rule) }));
  const counts = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  for (const f of list) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const byCategory = {};
  for (const f of list) byCategory[f.category] = (byCategory[f.category] || 0) + 1;
  const highest = SEVERITIES.find(s => counts[s] > 0) || null;
  return {
    ...meta,
    target: { kind: 'mcp', clients: [...new Set(servers.map(s => s.client))].sort(), config_files: files },
    summary: {
      total: list.length, counts, highest_severity: highest, by_category: byCategory,
      servers: servers.length, servers_probed: servers.filter(s => s.remote?.mcp).length, servers_unauthenticated: servers.filter(s => s.remote?.unauthenticated === true).length,
      tools: servers.reduce((n, s) => n + (s.definitions?.tools?.length || 0), 0), packages_analysed: scanned.packages, processes_observed: scanned.processes,
    },
    servers,
    findings: list.sort((a, b) => (SEVERITY_RANK[a.severity] ?? 9) - (SEVERITY_RANK[b.severity] ?? 9) || a.rule.localeCompare(b.rule) || String(a.artifact).localeCompare(String(b.artifact))),
    analysis_notes: [...notes],
    analysis: { complete: !(notes.gaps || []).length, gaps: [...(notes.gaps || [])] },
  };
}

const esc = v => String(v ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const SEV_COLOR = { critical: '#b3261e', high: '#c4521a', medium: '#a67c00', low: '#2d6a9f', info: '#5f6b76' };

export function buildHtml(p) {
  const kind = String(p.tool || '').replace(/^ubel-mcp-?/, '') || 'scan';
  const sev = s => `<span class="sev" style="background:${SEV_COLOR[s] || '#555'}">${esc(s)}</span>`;
  const c = p.summary.counts;
  const rows = p.servers.map(s => `<tr><td>${esc(s.name)}</td><td>${esc(s.client)}<br><small>${esc(s.scope)}</small></td><td>${esc(s.transport)}</td><td class="mono">${esc(s.target)}</td>`
    + `<td>${esc(s.remote ? (s.remote.mcp ? (s.remote.unauthenticated === true ? 'answers without authentication' : s.remote.unauthenticated === false ? 'authentication required' : 'reachable') : s.remote.error ? `not reachable (${s.remote.error})` : 'no MCP endpoint') : (s.observed?.length ? `running (pid ${s.observed.map(o => o.pid).join(', ')})` : 'not probed'))}</td>`
    + `<td>${esc(s.definitions?.tools?.length ?? '')}</td></tr>`).join('');
  const fnd = p.findings.map(f => `<details class="f"><summary>${sev(f.severity)} <b>${esc(f.title)}</b> <small>${esc(f.category)} · ${esc(f.artifact)}</small></summary>`
    + `<p>${esc(f.description)}</p>${(f.evidence || []).length ? `<pre>${esc((f.evidence || []).join('\n'))}</pre>` : ''}`
    + `${f.remediation ? `<p><b>Fix:</b> ${esc(f.remediation)}</p>` : ''}<small class="mono">${esc(f.rule)}${f.cwe ? ` · CWE-${esc(f.cwe)}` : ''}${f.confidence && f.confidence !== 'high' ? ` · confidence ${esc(f.confidence)}` : ''}</small></details>`).join('\n');
  return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>UBEL MCP ${esc(kind)} report</title><style>
:root{color-scheme:light dark;--bg:#fff;--fg:#1c1f23;--mut:#5f6b76;--line:#d8dde2;--card:#f5f7f9}
@media(prefers-color-scheme:dark){:root{--bg:#14171a;--fg:#e6e9ec;--mut:#9aa5af;--line:#2b3238;--card:#1b1f23}}
body{font:14px/1.5 system-ui,sans-serif;margin:0;padding:24px;background:var(--bg);color:var(--fg);max-width:1100px;margin-inline:auto}
h1{font-size:22px;margin:0 0 4px}h2{font-size:16px;margin:28px 0 8px}small,.mut{color:var(--mut)}.mono{font-family:ui-monospace,monospace;font-size:12px;word-break:break-all}
.sev{color:#fff;border-radius:4px;padding:1px 7px;font-size:12px;text-transform:uppercase;margin-right:6px}
table{border-collapse:collapse;width:100%}th,td{text-align:left;border-bottom:1px solid var(--line);padding:6px 8px;vertical-align:top}
.f{border:1px solid var(--line);border-radius:6px;margin:6px 0;padding:8px 12px;background:var(--card)}.f summary{cursor:pointer}pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);padding:8px;border-radius:4px;border:1px solid var(--line)}
.kpi span{display:inline-block;margin-right:16px}</style></head><body>
<h1>UBEL MCP ${esc(kind)} report</h1><div class="mut">${esc(p.generated_at)} · ${esc(p.tool)} ${esc(p.tool_version)} · ${esc(p.report_id)}</div>
<h2>Summary</h2><div class="kpi"><span>${sev('critical')}${c.critical}</span><span>${sev('high')}${c.high}</span><span>${sev('medium')}${c.medium}</span><span>${sev('low')}${c.low}</span><span>${sev('info')}${c.info}</span></div>
<p>${esc(p.summary.servers)} server(s) declared or found, ${esc(p.summary.servers_probed)} probed live (${esc(p.summary.servers_unauthenticated)} without authentication), ${esc(p.summary.tools)} tool(s) read, ${esc(p.summary.packages_analysed)} launcher package(s) analysed.${p.analysis.complete ? '' : ` <b>Incomplete: ${esc(p.analysis.gaps.length)} part(s) could not be analysed.</b>`}</p>
<h2>Servers</h2><table><thead><tr><th>Name</th><th>Client</th><th>Transport</th><th>Target</th><th>Status</th><th>Tools</th></tr></thead><tbody>${rows || '<tr><td colspan="6" class="mut">none</td></tr>'}</tbody></table>
<h2>Findings (${esc(p.findings.length)})</h2>${fnd || '<p class="mut">No findings.</p>'}
${p.analysis_notes.length ? `<h2>Notes</h2><ul>${p.analysis_notes.map(n => `<li>${esc(n)}</li>`).join('')}</ul>` : ''}
</body></html>`;
}

export function writeReports({ tag, payloadMeta, build, workingDir, quiet }) {
  const ts = reportTimestamp(new Date());
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const asset = assetFor(tag, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, tag, asset.asset_id);
  const jsonName = reportFileName('report', tag, 'json'), htmlName = reportFileName('report', tag, 'html');
  const meta = { ...payloadMeta, report_id: generateReportId(tag, asset.asset_id), asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id };
  const payload = build(meta);
  const json = JSON.stringify(payload, null, 2);
  const html = buildHtml(payload);
  const latestJson = path.join(latestDir, reportFileName('latest', tag, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', tag, 'html'));
  atomicWriteFile(latestJson, json);
  atomicWriteFile(latestHtml, html);
  atomicWriteFile(zipPath, buildZip([{ name: jsonName, data: json }, { name: htmlName, data: html }]));
  updateLatestReportZip(zipPath, tag);
  if (!quiet) {
    console.log(`\n[${payloadMeta.tool}] JSON report : ${latestJson}`);
    console.log(`[${payloadMeta.tool}] HTML report : ${latestHtml}`);
    console.log(`[${payloadMeta.tool}] Bundle      : ${zipPath}`);
  }
  return payload;
}
