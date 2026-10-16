// ─────────────────────────────────────────────────────────────────────────────
// sbom_vulns.js — the engine of `ubel-sbom`.
//
// `ubel-sbom <sbom.cdx.json>` reads a CycloneDX JSON SBOM (UBEL's own or any other tool's),
// looks every component up in the vulnerability databases, enriches what it finds with
// CISA KEV and FIRST EPSS, and writes the result into that SBOM's `vulnerabilities` array.
// Nothing else in the document is touched, and nothing else is produced: no policy, no
// reachability, no VEX analysis, no JSON / HTML / SARIF report, no history zip, no asset id.
//
// Lookup order, per component — PURL FIRST, CPE ONLY AS A FALLBACK:
//
//   1. the component has a purl OSV can answer for  → OSV (api.osv.dev), by purl.
//      The CPE of that component, if it has one, is never consulted: a purl is an exact
//      package coordinate, a CPE is a vendor:product guess, and asking NVD as well would
//      only add look-alike matches on top of an answer that is already complete.
//   2. no such purl, but the component has a CPE    → NVD, by CPE (2.2 URIs are converted to 2.3).
//      "No such purl" means: no purl at all, or one OSV cannot be asked about — no version,
//      a VCS / download / file source, a malformed value, or a type the engine has no
//      OSV mapping for (see getEcosystemFromPurl).
//   3. neither                                      → not looked up; counted and reported.
//
// Everything below the lookup is the engine's own code, so a finding here is the finding
// `ubel-npm health` etc. would report for the same purl: submitToOsv / getVulnById (OS-package
// advisories are scoped to the distro release), submitToNvd, alias de-duplication and
// enrichWithThreatIntel (KEV + EPSS). The CycloneDX entries are written by CycloneDXBuilder, so
// they have the same shape as the vulnerabilities of an SBOM a scan writes — minus `analysis`.
//
// Failure rules are the engine's: an OSV / NVD lookup that cannot be completed throws (the file
// is NOT written — never a half-filled SBOM that reads as "clean"); an unreachable KEV / EPSS
// feed never aborts, it leaves those fields "unknown" and is reported as a warning.
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import {
  submitToOsv, submitToNvd, getVulnById, getFix, scoreToSeverity, deduplicateVulnerabilitiesByAlias,
  sortVulnerabilities, enrichWithThreatIntel, getDependencyFromPurl, getEcosystemFromPurl,
  UNVERIFIED_SOURCE_RE, VulnLookupError,
} from "./engine.js";
import { processVulnerability, cvssMethodFromVector } from "./cvss_parser.js";
import { CycloneDXBuilder } from "./sbom_builder.js";
import { atomicWriteFile } from "./report_naming.js";

// CycloneDX gained `vulnerabilities` in 1.4; `CVSSv4` as a rating method in 1.6.
const MIN_SPEC = [1, 4];
const CVSS4_SPEC = [1, 6];
const OSV_ADVISORY_CONCURRENCY = 40;   // same as the engine's scan

const parseSpec = (v) => {
  const m = /^(\d+)\.(\d+)/.exec(String(v ?? ""));
  return m ? [Number(m[1]), Number(m[2])] : null;
};
const specAtLeast = (spec, min) => spec[0] > min[0] || (spec[0] === min[0] && spec[1] >= min[1]);

// ── CPE ──────────────────────────────────────────────────────────────────────

// Characters the CPE 2.3 formatted-string binding backslash-escapes. `.` `-` `_` are literal there;
// `*` and `?` are the wildcards and stay as they are.
const CPE23_SPECIAL = /[!"#$%&'()+,/:;<=>@[\\\]^`{|}~]/g;
const escapeCpe23 = (v) => String(v).replace(CPE23_SPECIAL, (c) => `\\${c}`);
const unescapeCpe23 = (v) => String(v).replace(/\\(.)/g, "$1");
const splitCpe23 = (s) => s.split(/(?<!\\):/);

/** "cpe:/a:vendor:product:1.0:update:~edition~sw~tsw~thw~other:lang" → CPE 2.3 formatted string, or null. */
function cpe22To23(uri) {
  const comps = uri.slice("cpe:/".length).split(":");
  const part = comps[0];
  if (!/^[aoh]$/.test(part || "") || comps.length < 3) return null;
  const dec = (s) => { try { return decodeURIComponent(s); } catch { return s; } };
  const [vendor, product, version, update, edition, language] = [1, 2, 3, 4, 5, 6].map(i => comps[i] ?? "");
  let sw = "", tsw = "", thw = "", other = "", ed = edition;
  if (edition.startsWith("~")) {                     // packed edition: ~edition~sw_edition~target_sw~target_hw~other
    const p = edition.split("~");
    ed = p[1] ?? ""; sw = p[2] ?? ""; tsw = p[3] ?? ""; thw = p[4] ?? ""; other = p[5] ?? "";
  }
  const f = (s) => (s === "" ? "*" : s === "-" ? "-" : escapeCpe23(dec(s)));
  return ["cpe", "2.3", part, f(vendor), f(product), f(version), f(update), f(ed), f(language), f(sw), f(tsw), f(thw), f(other)].join(":");
}

/**
 * The CPE of a component as a CPE 2.3 formatted string whose version is a concrete one, ready for
 * NVD — or { reason } when there is nothing usable. A wildcard / "not applicable" version in the CPE
 * is replaced by the component's own version (a CPE that already names a version keeps it).
 */
function usableCpe(rawCpe, componentVersion) {
  const raw = typeof rawCpe === "string" ? rawCpe.trim() : "";
  if (!raw) return { reason: "no CPE" };

  let cpe = null;
  if (/^cpe:2\.3:/i.test(raw)) cpe = raw;
  else if (/^cpe:\//i.test(raw)) cpe = cpe22To23(raw);
  if (!cpe) return { reason: "CPE is not valid CPE 2.2/2.3" };

  const parts = splitCpe23(cpe);
  if (parts.length !== 13 || !/^[aoh]$/.test(parts[2])) return { reason: "CPE is not valid CPE 2.2/2.3" };
  parts[2] = parts[2].toLowerCase();

  if (["*", "-", ""].includes(parts[5])) {
    const v = String(componentVersion ?? "").trim();
    if (!v) return { reason: "CPE has no version and the component has none either" };
    parts[5] = escapeCpe23(v);
  }
  return { cpe: parts.join(":"), version: unescapeCpe23(parts[5]) };
}

// ── PURL ─────────────────────────────────────────────────────────────────────

/** `{ purl, distro }` when OSV can be asked about this purl, `{ reason }` when it cannot. */
function usablePurl(rawPurl) {
  const purl = typeof rawPurl === "string" ? rawPurl.trim() : "";
  if (!purl) return { reason: "no purl" };
  if (!purl.startsWith("pkg:")) return { reason: "purl is not a pkg: URL" };

  let name, version;
  try {
    [name, version] = getDependencyFromPurl(purl);
  } catch {
    return { reason: "purl is malformed" };
  }
  if (!name || name === "unknown") return { reason: "purl is malformed" };
  if (!version) return { reason: "purl has no version" };
  // Not the registry package of that name@version (see UNVERIFIED_SOURCE_RE in engine.js).
  if (UNVERIFIED_SOURCE_RE.test(purl)) return { reason: "purl points to a VCS URL, download URL or file" };

  // getEcosystemFromPurl is the engine's list of purl types it can match; OSV is never asked about
  // the rest (one purl it cannot map can fail the whole batch). pkg:conda is excluded by the engine too.
  const eco = getEcosystemFromPurl(purl);
  if (eco === "unknown" || eco === "conda" || eco === "windows") {
    const type = /^pkg:([^/]+)/.exec(purl)?.[1] ?? "?";
    return { reason: `purl type "${type}" is not matched against OSV` };
  }

  // OS packages: the distro release the advisories must be scoped to ("debian-12", "ubuntu-22.04").
  let distro = "";
  const qs = purl.split("#")[0].split("?")[1];
  if (qs) {
    for (const pair of qs.split("&")) {
      const [k, v] = pair.split("=");
      if (k === "distro" && v) { try { distro = decodeURIComponent(v); } catch { distro = v; } }
    }
  }
  return { purl, distro };
}

// ── Components ───────────────────────────────────────────────────────────────

/** Every component of the document, nested ones included (the root `metadata.component` is not one). */
function* walkComponents(list) {
  for (const c of Array.isArray(list) ? list : []) {
    if (!c || typeof c !== "object") continue;
    yield c;
    yield* walkComponents(c.components);
  }
}

/**
 * Decide, per component, how it is looked up — purl first, CPE second, else skipped — and group
 * components that resolve to the same purl / CPE so each is queried once.
 *
 * @returns {{
 *   total: number,
 *   byPurl: Map<string, {refs: Set<string>, distro: string}>,
 *   byCpe:  Map<string, {refs: Set<string>, name: string, version: string}>,
 *   nPurl: number, nCpe: number,        components resolved to a purl / to a CPE
 *   skipped: Map<string, number>,       reason → components not looked up
 *   unreferenced: Map<string, number>   purl / CPE → components that have no bom-ref
 * }}
 */
export function planLookups(doc) {
  const plan = { total: 0, byPurl: new Map(), byCpe: new Map(), nPurl: 0, nCpe: 0, skipped: new Map(), unreferenced: new Map() };
  const skip = (reason) => plan.skipped.set(reason, (plan.skipped.get(reason) ?? 0) + 1);

  for (const c of walkComponents(doc.components)) {
    plan.total++;
    const bomRef = typeof c["bom-ref"] === "string" && c["bom-ref"] ? c["bom-ref"] : "";
    const noRef = (key) => { if (!bomRef) plan.unreferenced.set(key, (plan.unreferenced.get(key) ?? 0) + 1); };
    const ownDistro = Array.isArray(c.properties) ? c.properties.find(p => p?.name === "distro")?.value : "";

    const p = usablePurl(c.purl);
    if (p.purl) {
      plan.nPurl++;
      // `affects[].ref` has to be the component's bom-ref; without one the purl is the best reference there is.
      noRef(p.purl);
      const entry = plan.byPurl.get(p.purl) ?? { refs: new Set(), distro: "" };
      entry.refs.add(bomRef || p.purl);
      entry.distro ||= p.distro || (typeof ownDistro === "string" ? ownDistro : "");
      plan.byPurl.set(p.purl, entry);
      continue;
    }

    // No purl OSV can answer for → the CPE, if there is one.
    const k = usableCpe(c.cpe, c.version);
    if (k.cpe) {
      plan.nCpe++;
      noRef(k.cpe);
      const entry = plan.byCpe.get(k.cpe) ?? { refs: new Set(), name: c.name || "", version: k.version };
      entry.refs.add(bomRef || k.cpe);
      plan.byCpe.set(k.cpe, entry);
      continue;
    }

    const hasPurl = String(c.purl ?? "").trim() !== "";
    const hasCpe  = String(c.cpe  ?? "").trim() !== "";
    skip(!hasPurl && !hasCpe ? "no purl and no CPE" : `${hasPurl ? p.reason : "no purl"}; ${hasCpe ? k.reason : "no CPE"}`);
  }
  return plan;
}

// ── Lookup ───────────────────────────────────────────────────────────────────

/** OSV by purl → advisory records (engine shape), with `affected_package_id` = the purl. */
async function lookupByPurl(byPurl, log) {
  if (!byPurl.size) return [];
  const purls = [...byPurl.keys()];
  const distroByPurl = new Map();
  for (const [purl, e] of byPurl) if (e.distro) distroByPurl.set(purl, e.distro);

  log(`[*] Querying OSV for ${purls.length} purl${purls.length === 1 ? "" : "s"}...`);
  const ids = await submitToOsv(purls, { distroByPurl });

  const out = [];
  let otherRelease = 0;
  for (let i = 0; i < ids.length; i += OSV_ADVISORY_CONCURRENCY) {
    const batch = ids.slice(i, i + OSV_ADVISORY_CONCURRENCY);
    const results = await Promise.allSettled(batch.map(getVulnById));
    const failed = results.filter(r => r.status === "rejected");
    if (failed.length) {
      // Same fail-closed rule as a scan: every id here is a finding OSV already reported.
      throw new VulnLookupError(
        `${failed.length} OSV advisor${failed.length === 1 ? "y" : "ies"} could not be fetched (${failed[0].reason?.message}) — vulnerability lookup is incomplete.`,
        { source: "osv-vuln", cause: failed[0].reason }
      );
    }
    results.forEach((r, j) => {
      if (r.value) out.push(r.value);
      else if (batch[j]?.distro) otherRelease++;   // advisory is for another distro release
    });
  }
  if (otherRelease) log(`[*] Dropped ${otherRelease} OS advisor${otherRelease === 1 ? "y" : "ies"} that apply to a different distro release than the component's.`);
  return out;
}

/** NVD by CPE → advisory records (engine shape), with `affected_package_id` = the CPE 2.3 string. */
async function lookupByCpe(byCpe) {
  if (!byCpe.size) return [];
  const items = [...byCpe].map(([cpe, e]) => ({ id: cpe, name: e.name || cpe.split(":")[4] || cpe, version: e.version, ecosystem: "unknown" }));
  const vulns = await submitToNvd(items);

  // The same post-processing the engine applies to NVD records (see UbelEngineInstance.scan()).
  for (const v of vulns) {
    const nvdScore  = v.severity_score;
    const nvdVector = v.severity_vector;
    processVulnerability(v);
    if (v.severity_score  == null) v.severity_score  = nvdScore;
    if (v.severity_vector == null) v.severity_vector = nvdVector;
    v.cvss_method = cvssMethodFromVector(v.severity_vector);
    v.severity = scoreToSeverity(v.severity_score);
    getFix(v);
    for (const key of ["database_specific", "affected", "schema_version"]) delete v[key];
  }
  return vulns;
}

// ── Entries ──────────────────────────────────────────────────────────────────

const ISO_NO_TZ = /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(\.\d+)?$/;

/** CycloneDX `vulnerabilities[]` for the findings, shaped for this document's spec version. */
function buildEntries(vulns, plan, spec) {
  const entries = new CycloneDXBuilder({ vulnerabilities: vulns, inventory: [] }).buildVulnerabilities({ analysis: false });

  for (const e of entries) {
    // `affects` names the components of the SBOM (their bom-refs), not just the purl / CPE the finding was matched on.
    const key = e["bom-ref"].slice(e.id.length + 1);
    const refs = plan.byPurl.get(key)?.refs ?? plan.byCpe.get(key)?.refs;
    if (refs?.size) e.affects = [...refs].map(ref => ({ ref }));

    // NVD stamps its dates without a zone (they are UTC); CycloneDX wants an RFC 3339 date-time.
    for (const f of ["published", "updated"]) if (ISO_NO_TZ.test(e[f] ?? "")) e[f] += "Z";

    // A CVSS 4.0 rating needs spec 1.6; older documents get the generic method (score and vector stay).
    if (!specAtLeast(spec, CVSS4_SPEC)) for (const r of e.ratings) if (r.method === "CVSSv4") r.method = "other";
  }
  return entries;
}

const SEVERITIES = ["critical", "high", "medium", "low", "unknown"];

/**
 * Look the SBOM's components up and return the CycloneDX `vulnerabilities` array for them.
 * Does not modify `doc`. Throws VulnLookupError when OSV / NVD could not be queried completely.
 *
 * @param {object} doc  parsed CycloneDX document
 * @param {object} [opts]
 * @param {(msg: string) => void} [opts.log]   progress sink (default: stdout)
 * @returns {Promise<{ vulnerabilities: object[], summary: object }>}
 */
export async function lookupSbomVulnerabilities(doc, { log = console.log } = {}) {
  const spec = parseSpec(doc?.specVersion);
  const plan = planLookups(doc);

  const notLookedUp = [...plan.skipped.values()].reduce((a, b) => a + b, 0);
  log(`[*] ${plan.total} component${plan.total === 1 ? "" : "s"}: ${plan.nPurl} by purl (OSV), ` +
      `${plan.nCpe} by CPE (NVD, no usable purl), ${notLookedUp} not looked up.`);

  // purl first, CPE second — the two sets are disjoint by construction (see planLookups).
  let vulns = [...await lookupByPurl(plan.byPurl, log), ...await lookupByCpe(plan.byCpe)];
  vulns = deduplicateVulnerabilitiesByAlias(vulns);

  // KEV + EPSS. Never aborts: an unreachable feed leaves its fields null ("unknown" in the SBOM).
  let threatIntel = { kev: { status: "skipped" }, epss: { status: "skipped" }, warnings: [] };
  if (vulns.length) {
    try {
      threatIntel = await enrichWithThreatIntel(vulns);
    } catch (err) {
      threatIntel = {
        kev: { status: "unavailable", error: err.message }, epss: { status: "unavailable", error: err.message },
        warnings: [`Threat-intel enrichment failed (${err.message}): KEV / EPSS are unknown for every vulnerability.`],
      };
      for (const v of vulns) { v.is_kev = null; v.kev_added = null; v.kev_deadline = null; v.epss_score = null; v.epss_percentile = null; }
    }
  }

  // Deterministic order: severity, then score; ties by package and id.
  vulns.sort((a, b) => String(a.affected_package_id).localeCompare(String(b.affected_package_id)) || String(a.id).localeCompare(String(b.id)));
  vulns = sortVulnerabilities(vulns);

  const bySeverity = Object.fromEntries(SEVERITIES.map(s => [s, 0]));
  let infections = 0;
  for (const v of vulns) {
    if (v.is_infection) { infections++; continue; }
    const s = String(v.severity || "unknown").toLowerCase();
    bySeverity[s in bySeverity ? s : "unknown"]++;
  }

  const summary = {
    components:       plan.total,
    looked_up_by_purl: plan.nPurl,
    looked_up_by_cpe:  plan.nCpe,
    not_looked_up:    Object.fromEntries(plan.skipped),
    // components that have findings but no bom-ref to point `affects` at (they are never modified)
    components_without_bom_ref: [...new Set(vulns.map(v => v.affected_package_id))].reduce((n, k) => n + (plan.unreferenced.get(k) ?? 0), 0),
    vulnerabilities:  vulns.length,
    infections,
    by_severity:      bySeverity,
    kev:              vulns.filter(v => v.is_kev === true).length,
    epss_scored:      vulns.filter(v => typeof v.epss_score === "number").length,
    threat_intel:     threatIntel,
  };

  return { vulnerabilities: buildEntries(vulns, plan, spec ?? CVSS4_SPEC), summary };
}

// ── File ─────────────────────────────────────────────────────────────────────

/** Indent of the file's JSON ("  ", "\t", …) so the rewrite keeps its layout; 0 = a single line. */
function detectIndent(text) {
  const m = /\n([ \t]+)["{\[]/.exec(text);
  return m ? m[1] : 0;
}

/** Parse the SBOM file; throws an Error that says what is wrong with it. */
function readSbom(file) {
  let text;
  try {
    text = fs.readFileSync(file, "utf8");
  } catch (e) {
    throw new Error(`cannot read ${file}: ${e.code === "ENOENT" ? "no such file" : e.message}`);
  }
  text = text.replace(/^\uFEFF/, "");
  let doc;
  try {
    doc = JSON.parse(text);
  } catch (e) {
    throw new Error(`${file} is not valid JSON (${e.message}). ubel-sbom reads CycloneDX JSON — XML SBOMs and report bundles (.zip) are not supported.`);
  }
  const base = path.basename(file);
  if (!doc || typeof doc !== "object" || doc.bomFormat !== "CycloneDX") {
    throw new Error(`${base} is not a CycloneDX SBOM (bomFormat is not "CycloneDX"). Only CycloneDX JSON is supported.`);
  }
  const spec = parseSpec(doc.specVersion);
  if (!spec) throw new Error(`${base} has no valid "specVersion".`);
  if (!specAtLeast(spec, MIN_SPEC)) {
    throw new Error(`${base} is CycloneDX ${doc.specVersion}; "vulnerabilities" exists from 1.4 on, so it cannot be written into this SBOM. Regenerate it as CycloneDX 1.4 or newer.`);
  }
  if (!Array.isArray(doc.components)) {
    throw new Error(`${base} has no "components" array — nothing to look up.`);
  }
  return { doc, indent: detectIndent(text), endsWithNewline: /\n$/.test(text) };
}

/**
 * Fill an SBOM's `vulnerabilities` with the vulnerabilities of its components, KEV / EPSS included.
 *
 * Only `vulnerabilities` is written; a `vulnerabilities` array already in the file is replaced (so
 * running it again refreshes the data). The file is replaced atomically and only after every
 * lookup succeeded — on failure it is left exactly as it was.
 *
 * @param {object}  opts
 * @param {string}  opts.sbom       path of the CycloneDX JSON SBOM
 * @param {string}  [opts.output]   write here instead of into `sbom` (which is then left untouched)
 * @param {(msg: string) => void} [opts.log]  progress sink; default stdout
 * @returns {Promise<{ file: string, replaced: number, summary: object }>}
 * @throws  {Error} unreadable / non-CycloneDX / pre-1.4 input, or a VulnLookupError when the OSV / NVD lookup was incomplete
 */
export async function sbomVulnsScan({ sbom, output, log = console.log } = {}) {
  if (!sbom) throw new Error("sbomVulnsScan requires `sbom`: the path of a CycloneDX JSON SBOM.");

  const { doc, indent, endsWithNewline } = readSbom(sbom);
  const { vulnerabilities, summary } = await lookupSbomVulnerabilities(doc, { log });

  const replaced = Array.isArray(doc.vulnerabilities) ? doc.vulnerabilities.length : 0;
  doc.vulnerabilities = vulnerabilities;

  // Write through the real path so an SBOM that is a symlink keeps being one.
  const target = output ? path.resolve(output) : fs.realpathSync(sbom);
  let mode;
  try { mode = fs.statSync(target).mode & 0o7777; } catch { /* new file */ }
  atomicWriteFile(target, JSON.stringify(doc, null, indent) + (endsWithNewline ? "\n" : ""));
  if (mode !== undefined) { try { fs.chmodSync(target, mode); } catch { /* best effort */ } }

  return { file: target, replaced, summary };
}
