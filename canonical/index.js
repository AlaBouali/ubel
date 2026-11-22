'use strict';
// canonical/index.js — translation layer: original module payload → canonical report (schema 0.1.0).
//
//   import { toCanonical, writeCanonical } from './canonical/index.js';
//   const canon = toCanonical(originalPayload, { cwd, cli: 'ubel-vm', live: true, fail_on });
//
// The original payload is never modified and the original JSON/HTML keep being written as before.
// Adapters live in ./adapters (one per payload family); see each file's header for the field mapping.
import fs from 'node:fs';
import path from 'node:path';
import { SCHEMA_VERSION, buildMetadata, buildStats, isObj, clone, makeRel } from './common.js';
import * as sca from './adapters/sca.js';
import * as sast from './adapters/sast.js';
import * as cloud from './adapters/cloud.js';
import * as posture from './adapters/posture.js';
import * as appscan from './adapters/appscan.js';
import * as easm from './adapters/easm.js';
import * as runtime from './adapters/runtime.js';

export { SCHEMA_VERSION };
const ADAPTERS = { sca, sast, cloud, posture, runtime, appscan, easm };

export function detectFamily(p) {
  if (!isObj(p)) return null;
  if (isObj(p.scan_info) && isObj(p.tool_info)) return 'sca';
  if (isObj(p.meta) && Array.isArray(p.results)) return 'sast';
  if (Array.isArray(p.apps) && typeof p.schema === 'string') return 'appscan';
  if (isObj(p.profile) && Array.isArray(p.checks)) return p.profile.key === 'runtime' ? 'runtime' : 'posture';
  if (Array.isArray(p.providers) && Array.isArray(p.findings)) return 'cloud';
  if (Array.isArray(p.scope) && Array.isArray(p.inventory) && ('assets' in p || 'targets' in p)) return 'easm';
  return null;
}

/**
 * @param {object} payload   the module's original JSON payload
 * @param {object} [opts]
 * @param {string} [opts.cwd]      scanned directory; every filesystem path is made relative to it
 * @param {string} [opts.cli]      CLI that produced the report (e.g. "ubel-vm")
 * @param {string} [opts.called_via]
 * @param {boolean} [opts.live]    true when called by the scanner itself: unknown environment fields fall back to this process
 * @param {string} [opts.fail_on]  --fail-on of the run, for modules whose payload does not record it (cloud, vm, k8s)
 * @param {Map} [opts.sequences]   component id (purl) → dependency sequences, for SCA payloads whose inventory no longer carries them
 * @param {string} [opts.family]   force an adapter instead of auto-detecting
 */
export function toCanonical(payload, opts = {}) {
  const family = opts.family || detectFamily(payload);
  if (!family || !ADAPTERS[family]) throw new Error('canonical: unrecognised report format (cannot pick an adapter)');
  const t = ADAPTERS[family].translate(payload, opts, { buildMetadata });
  const findings = t.findings;
  const inventory = t.inventory;
  const stats = buildStats(findings, inventory, t.stats_extra?.source ?? null);
  for (const [k, v] of Object.entries(t.stats_extra || {})) if (k !== 'source' && v != null) stats[k] = v;

  const R = makeRel(opts.cwd);
  const canon = {
    schema: SCHEMA_VERSION,
    metadata: t.metadata,
    policy: R.deep(t.policy),
    findings,
    inventory,
    stats,
    compliance_summary: t.compliance_summary ?? null,
    executive_summary: t.executive_summary == null ? null : R.deep(t.executive_summary),
    scopes: t.scopes,
  };
  return canon;
}

export function canonicalFileName(base) { return String(base).replace(/\.json$/, '') + '.json'; }

/**
 * Translate + render + write latest.<tag>.{json,html}; returns the bundle entries to add to the history zip.
 * Never throws: a canonical failure must not fail the scan (same contract as the other report blocks).
 */
export async function writeCanonical({ payload, tag, cli, cwd, latestDir, fail_on, atomicWrite, withHtml = true, log = console.log, sequences }) {
  const entries = [];
  try {
    const canon = toCanonical(payload, { cwd, cli, live: true, fail_on, sequences });
    const json = JSON.stringify(canon);
    const write = atomicWrite || ((f, d) => fs.writeFileSync(f, d));
    const jp = path.join(latestDir, `latest.${tag}.json`);
    write(jp, json);
    entries.push({ name: `report.${tag}.json`, data: json });
    log(`[${cli}] Canonical JSON : ${jp}`);
    if (withHtml) {
      const { generateCanonicalHtml } = await import('./html.js');
      const html = await generateCanonicalHtml(canon, { family: detectFamily(payload) });
      const hp = path.join(latestDir, `latest.${tag}.html`);
      write(hp, html);
      entries.push({ name: `report.${tag}.html`, data: html });
      log(`[${cli}] Canonical HTML : ${hp}`);
    }
  } catch (e) {
    console.warn(`[${cli}] Canonical report failed: ${e.message}`);
  }
  return entries;
}
