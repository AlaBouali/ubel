// ─────────────────────────────────────────────────────────────────────────────
// resbom.js — the input side of `ubel-resbom`.
//
// `ubel-resbom <sbom.cdx.json>` takes an SBOM that UBEL itself generated (the
// latest.<tag>.cdx.json of a scan, or report.<tag>.cdx.json out of a history zip)
// and re-scans it: the component list and everything else the SBOM recorded about the
// original scan is read back, and the vulnerability lookup (OSV / NVD), exploit
// intelligence (CISA KEV + FIRST EPSS), policy, suggested fixes, executive summary,
// HTML / JSON / SARIF reports and a new SBOM are produced from it by the engine's own
// pipeline (see the `resbom` option of UbelEngineInstance.scan() in engine.js) — no
// project, lockfile or package manager is needed, and nothing is installed.
//
// This module only turns the SBOM into that option:
//
//   loadUbelSbom(fileOrObject) → {
//     inventory        components, rebuilt the way the scanners' own inventory items look
//                      (dependencies from the SBOM's dependency graph; introduced_by, parents,
//                      state, policy marks, license info and suggested fixes are derived again)
//     report_tag       "<source tag>_resbom"  (sca → sca_resbom, npm_firewall → npm_firewall_resbom)
//     scan_type, scan_scope, engine, system_type, engine_info, asset, runtime, git_metadata,
//     os_metadata      what the SBOM recorded about the original scan
//     secrets          the secrets-in-source payload the SBOM carried (never re-scanned: there is no source tree)
//     reachability     Map<"<advisory id>|<purl>", reachability> — the verdicts of the old scan
//     warnings         things worth telling the user (e.g. not an SBOM UBEL generated)
//   }
//
// SBOMs written before ubel-resbom existed lack a few properties (component distro, OS and
// engine info); those are optional and simply absent from the re-scan.
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import { TOOL_NAME, TOOL_VERSION } from "./info.js";
import { getEcosystemFromPurl } from "./engine.js";
import {
  ASSET_TYPES, isValidAssetId, parseReportId, scaReportTag, resbomReportTag, baseScaTag,
} from "./report_naming.js";

const SCAN_TYPES = new Set(["health", "check", "install"]);
// The apt / dnf / yum firewalls have no asset folder: their asset is the machine itself.
const LINUX_FIREWALL_TAG_RE = /^(apt|dnf|yum)_firewall$/;

/** name → value of a CycloneDX `properties` array (the last one wins; blank values are dropped). */
function propMap(props) {
  const out = {};
  if (!Array.isArray(props)) return out;
  for (const p of props) {
    if (!p || typeof p.name !== "string" || p.value === undefined || p.value === null) continue;
    const v = String(p.value);
    if (v !== "") out[p.name] = v;
  }
  return out;
}

function parseJson(text, fallback) {
  if (typeof text !== "string") return fallback;
  try { return JSON.parse(text); } catch { return fallback; }
}

const asBool = (v) => (v === "true" ? true : v === "false" ? false : undefined);
const asNum  = (v) => (v === undefined || v === "" || Number.isNaN(Number(v)) ? undefined : Number(v));
const asArray = (v) => (Array.isArray(v) ? v : []);

/** The raw `license` string of an inventory item, from the CycloneDX `licenses` array. */
function licenseFrom(licenses) {
  for (const l of asArray(licenses)) {
    if (l?.expression) return String(l.expression);
    if (l?.license?.id)   return String(l.license.id);
    if (l?.license?.name) return String(l.license.name);
  }
  return "unknown";
}

/** The reachability verdict an old SBOM recorded on a vulnerability, or null when it recorded none. */
function reachabilityFrom(props) {
  const reachable = asBool(props["reachability.reachable"]);
  if (reachable === undefined) return null;
  const signals = {};
  const put = (k, v) => { if (v !== undefined) signals[k] = v; };
  put("depth",               asNum(props["reachability.signals.depth"]));
  put("attack_vector",       props["reachability.signals.attack_vector"]);
  put("scope",               props["reachability.signals.scope"]);
  put("is_orphan_tool",      asBool(props["reachability.signals.is_orphan_tool"]));
  put("is_non_library",      asBool(props["reachability.signals.is_non_library"]));
  put("num_paths",           asNum(props["reachability.signals.num_paths"]));
  put("introduced_by_count", asNum(props["reachability.signals.introduced_by_count"]));
  return {
    reachable,
    level:      props["reachability.level"],
    confidence: props["reachability.confidence"],
    rationale:  props["reachability.rationale"],
    tags:       asArray(parseJson(props["reachability.tags"], [])),
    signals,
  };
}

/** Read and parse an SBOM file, with errors that say what is wrong with it. */
function readSbomFile(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new Error(`cannot read ${file}: ${e.code === "ENOENT" ? "no such file" : e.message}`);
  }
  try {
    return JSON.parse(text);
  } catch (e) {
    throw new Error(`${file} is not valid JSON (${e.message}). ubel-resbom reads the plain .cdx.json — a report bundle (.zip) has to be unzipped first.`);
  }
}

/**
 * Turn a UBEL-generated CycloneDX SBOM into the `resbom` option of UbelEngineInstance.scan().
 *
 * @param {string|object} input  path of the .cdx.json, or the parsed document
 * @returns {object}  see the header of this file
 * @throws {Error}    when the input is not a CycloneDX document with a component list
 */
export function loadUbelSbom(input) {
  const doc  = typeof input === "string" ? readSbomFile(input) : input;
  const file = typeof input === "string" ? path.basename(input) : null;

  if (!doc || typeof doc !== "object" || doc.bomFormat !== "CycloneDX") {
    throw new Error(`${file ?? "input"} is not a CycloneDX SBOM (bomFormat is not "CycloneDX").`);
  }
  if (!Array.isArray(doc.components)) {
    throw new Error(`${file ?? "input"} has no "components" array — nothing to scan.`);
  }

  const warnings = [];
  const md       = doc.metadata || {};
  const mp       = propMap(md.properties);
  const tool     = Array.isArray(md.tools) ? md.tools[0] : (md.tools?.components?.[0] ?? null);

  const generatedByUbel = !!mp.report_id || /ubel/i.test(String(tool?.name ?? ""));
  if (!generatedByUbel) {
    warnings.push("This SBOM was not generated by UBEL: scan type, asset and environment details are unknown and default to a health scan.");
  }

  // ── What kind of scan the SBOM came from ───────────────────────────────────
  const scanType  = SCAN_TYPES.has(mp.scan_type) ? mp.scan_type : "health";
  const scanScope = mp.scan_scope || "repository";
  const idParts   = parseReportId(mp.report_id);
  const sourceTag = idParts?.tag
    // Reports from before report ids existed: derive what the tag would have been.
    ?? scaReportTag({ checkMode: scanType, engine: mp.engine_name || "unknown", scanScope });
  const baseTag   = baseScaTag(sourceTag);
  if (generatedByUbel && !idParts) {
    warnings.push(`The SBOM carries no valid report id; its report type was taken to be "${baseTag}".`);
  }

  // firewall tags are "<engine>_firewall": the package manager that ran the original check / install.
  const firewallEngine = /^(.+)_firewall$/.exec(baseTag)?.[1];
  const engineName = mp.engine_name || firewallEngine || TOOL_NAME;
  const engineInfo = {
    name:    engineName,
    version: mp.engine_version || (scanType === "health" ? TOOL_VERSION : ""),
  };
  const systemType = LINUX_FIREWALL_TAG_RE.test(baseTag) || scanScope === "linux_machine" ? "linux" : "npm";

  // ── Components → inventory ─────────────────────────────────────────────────
  const dependsOn = new Map();
  for (const d of asArray(doc.dependencies)) {
    if (d && typeof d.ref === "string") dependsOn.set(d.ref, asArray(d.dependsOn).filter(x => typeof x === "string"));
  }

  const inventory = [];
  const seen = new Set();
  let skipped = 0;
  for (const c of doc.components) {
    const id = c?.["bom-ref"] || c?.purl || "";
    if (!id || seen.has(id)) { if (!id) skipped++; continue; }
    seen.add(id);
    const cp = propMap(c.properties);

    const item = {
      id,
      name:         c.name || "",
      // A component with no version stays "" — the engine reports it as "undetermined".
      version:      c.version || "",
      type:         c.type || "library",
      ecosystem:    getEcosystemFromPurl(id),
      license:      licenseFrom(c.licenses),
      state:        cp.state || "undetermined",
      scopes:       asArray(parseJson(cp.scopes, [])),
      paths:        asArray(parseJson(cp.paths, [])),
      dependencies: [...(dependsOn.get(id) || [])],
    };
    if (c.cpe) item.cpe = c.cpe;
    if (cp.distro) item.distro = cp.distro;
    if (Array.isArray(c.hashes) && c.hashes.length) item.hashes = c.hashes.map(h => ({ alg: h.alg, content: h.content }));
    inventory.push(item);
  }
  if (skipped) warnings.push(`${skipped} component(s) without a bom-ref or purl were ignored.`);
  if (inventory.length === 0) warnings.push("The SBOM lists no components: the new reports will be empty.");

  // ── What the old scan found: reachability verdicts + the finding keys, for the diff ──
  const reachability = new Map();
  for (const v of asArray(doc.vulnerabilities)) {
    if (!v || !v.id) continue;
    const key = v["bom-ref"] || `${v.id}|${v.affects?.[0]?.ref ?? ""}`;
    const r = reachabilityFrom(propMap(v.properties));
    if (r) reachability.set(key, r);
  }

  // ── Secrets-in-source: carried over, there is no source tree to scan again ──
  const topProps = propMap(doc.properties);
  const secrets  = parseJson(topProps["ubel:secrets"], null);

  // ── Asset identity (only values the engine would accept) ───────────────────
  const asset = {};
  if (isValidAssetId(mp.asset_id))              asset.asset_id   = mp.asset_id.trim().toLowerCase();
  if (mp.asset_name)                            asset.asset_name = mp.asset_name;
  if (ASSET_TYPES.includes(mp.asset_type))      asset.asset_type = mp.asset_type;
  if (mp.machine_id)                            asset.machine_id = mp.machine_id;

  const runtime = {
    environment: mp.runtime_env || "",
    version:     mp.runtime_ver || "",
    platform:    mp.platform    || "",
    arch:        mp.arch        || "",
    cwd:         mp.cwd         || "",
  };
  const git_metadata = {};
  if (mp.git_branch)  git_metadata.branch = mp.git_branch;
  if (mp.git_commit)  git_metadata.latest_commit = mp.git_commit;
  if (mp.git_url)     git_metadata.url = mp.git_url;

  return {
    inventory,
    report_tag:   resbomReportTag(sourceTag),
    scan_type:    scanType,
    scan_scope:   scanScope,
    engine:       engineName,
    system_type:  systemType,
    engine_info:  engineInfo,
    asset,
    runtime,
    git_metadata,
    os_metadata:  { os_id: mp.os_id, os_name: mp.os_name, os_version: mp.os_version },
    secrets,
    reachability,
    warnings,
  };
}