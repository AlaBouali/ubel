'use strict';
// report.js — the ubel-mcp-client / ubel-mcp-server report, built with the SAME payload builder and HTML template as ubel-mobile, ubel-binary and
// ubel-package (mobile/lib/report.js): dashboard, executive summary, servers, vulnerabilities / secrets / misconfigurations, detailed stats,
// compliance mapping, diff against the previous scan of the same kind, and scan info. The file layout, report id, asset identity and history zip
// are the shared ones too (.ubel/reports/latest.mcp_client.* / latest.mcp_server.*, ~/.ubel/history/<asset>/<timestamp>.<tag>.zip).
//
// Each declared or probed server is one entry of `apps` with platform "mcp". Everything a server or a configuration said is attacker-controlled
// text; the shared template escapes every value it renders.

import fs from 'node:fs';
import path from 'node:path';
import { buildZip } from '../../sca/zip_writer.js';
import { buildPayload, buildHtml } from '../../mobile/lib/report.js';
import { diffReports, reportIdentity } from '../../mobile/index.js';
import { loadPreviousReport } from '../../cloud/lib/previous_report.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId } from '../../sca/report_naming.js';

/** Tool-definition hashes of the previous scan, by server key, for rug-pull detection. */
export function loadBaseline(workingDir, tag) {
  const map = new Map();
  try {
    const j = JSON.parse(fs.readFileSync(path.join(workingDir, '.ubel', 'reports', reportFileName('latest', tag, 'json')), 'utf8'));
    for (const s of j.apps || j.servers || []) if (s.key && Array.isArray(s.definitions?.tools)) map.set(s.key, { tools: s.definitions.tools });
  } catch { /* first scan, or an unreadable previous report: no baseline */ }
  return map;
}

/**
 * @param {{tag:string, tool:string, meta:object, scan:{servers:object[], findings:object, notes:object, files:object[], scanned:object}, identity:string, workingDir:string, quiet?:boolean}} o
 *   scan.findings is a Findings object whose list is already filtered by --min-severity.
 */
export async function writeReports({ tag, tool, meta, scan, identity, workingDir, quiet }) {
  const ts = reportTimestamp(new Date());
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const asset = assetFor(tag, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, tag, asset.asset_id);
  const jsonName = reportFileName('report', tag, 'json'), htmlName = reportFileName('report', tag, 'html');
  const apps = scan.servers.map(s => ({ platform: 'mcp', ...s }));
  const sum = scan.scanned || {};
  const isClient = tool === 'ubel-mcp-client';
  const mcp = {
    mode: isClient ? 'client' : 'server', clients: [...new Set(scan.servers.map(s => s.client))].sort(), config_files: scan.files.length, sources: scan.servers.filter(s => s.transport === 'source').length,
    probed: scan.servers.filter(s => s.remote?.mcp).length, unauthenticated: scan.servers.filter(s => s.remote?.unauthenticated === true).length,
    tools: scan.servers.reduce((n, s) => n + (s.definitions?.tools?.length || 0), 0), packages: sum.packages || 0, processes: sum.processes || 0,
  };
  const target = {
    file: isClient ? `MCP client configuration (${scan.files.length} file${scan.files.length === 1 ? '' : 's'}, ${apps.length} entr${apps.length === 1 ? 'y' : 'ies'})` : `MCP server scan (${apps.length} target${apps.length === 1 ? '' : 's'})`,
    kind: isClient ? 'mcp-client' : 'mcp-server', size_bytes: 0, sha256: null, identity, mcp, config_files: scan.files,
  };
  const base = { schema: 'ubel-mcp/2', tool, ...meta, report_id: generateReportId(tag, asset.asset_id), asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id };
  const build = diffs => buildPayload({ meta: base, target, apps, findings: scan.findings, dependencies: [], dependencySummary: null, notes: scan.notes, diffs });
  let payload = build(null);
  payload = build(diffReports(loadPreviousReport(zipPath, tag, jsonName, r => reportIdentity(r) === reportIdentity(payload)), payload));
  const json = JSON.stringify(payload, null, 2);
  const html = await buildHtml(payload);
  const latestJson = path.join(latestDir, reportFileName('latest', tag, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', tag, 'html'));
  atomicWriteFile(latestJson, json);
  atomicWriteFile(latestHtml, html);
  atomicWriteFile(zipPath, buildZip([{ name: jsonName, data: json }, { name: htmlName, data: html }]));
  updateLatestReportZip(zipPath, tag);
  if (!quiet) {
    console.log(`\n[${tool}] JSON report : ${latestJson}`);
    console.log(`[${tool}] HTML report : ${latestHtml}`);
    console.log(`[${tool}] Bundle      : ${zipPath}`);
  }
  return payload;
}
