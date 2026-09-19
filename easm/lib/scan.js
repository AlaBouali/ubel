// easm/lib/scan.js
//
// Orchestrates one ubel-url run:
//   1. Fingerprint every target (passive HTTP probing — see
//      ../fingerprint/README.md) into {Ids, Name, Version, Host, Port}
//      component records. `Ids` can mix CPE ids and purl ids — see
//      ../fingerprint/src/core/componentId.js. Targets are DNS-resolved
//      first (./resolve.js) so names that no longer exist are marked
//      "dead" and skipped rather than probed to a timeout.
//   2. Fold every detected component into a de-duplicated inventory keyed
//      by name+version, not by any single id — the same product+version
//      seen on five hosts, or seen via both a CPE and a purl, is one
//      inventory item and one set of vulnerability lookups, not five (or
//      two). See buildInventoryKey() below.
//   3. Crawl each live host's JavaScript (inline <script> blocks and
//      external .js files) and scan it for exposed credentials with the SCA
//      module's own secrets rules — see ./secrets_crawl.js.
//   4. Probe each scanned host for a fixed, deliberately small set of
//      well-known web misconfigurations — exposed .env/.git, xmlrpc.php,
//      WP user enumeration, phpinfo(), TLS certificate problems, missing
//      security headers (HSTS / clickjacking / no-HTTPS-at-all), and
//      SPF/DMARC/DKIM email-authentication gaps. Independent of the CVE
//      pipeline and the secrets crawl — see ./misconfig_scan.js.
//   5. Loop over every id (CPE *and* purl alike) of every inventory item,
//      look each up against the matching source (CPE ids → NVD, purl ids →
//      OSV, WordPress-tagged items → wpvulnerability.net instead of NVD —
//      see ./wpvulnerability.js), then attribute every result back to the
//      owning item and deduplicate per item — so a CVE surfaced twice for
//      the same component (e.g. via two CPE aliases, or via both its CPE
//      and its purl) shows up once, not twice. Reuses the exact same
//      OSV/NVD primitives the SCA engine uses (../../sca/engine.js),
//      including its enrichment (CVSS parsing, fix-version recommendation,
//      compliance mapping), rather than reimplementing any of it.
//
// Deliberately NOT included, per this module's scope (see ../README.md):
//   - License classification (there is no license to read off an HTTP
//     response — that's a source-availability concept, not applicable here).
//   - Dependency sequences / a dependency graph (fingerprinted services
//     aren't resolved from a manifest, so there is no "introduced by"
//     chain to build).
//   - Reachability analysis (that's import-graph analysis over source code
//     you have on disk; there is no source code here, only a remote host).
//
// Every inventory item's `scopes` is unconditionally `["prod"]` — anything
// this module can fingerprint over the network is, by definition, already
// running and exposed, not a dev-only or build-only dependency.

import { DomainScanner } from "../fingerprint/src/index.js";
import { mapLimit } from "../../cloud/lib/concurrency.js";
import { resolveTargets } from "./resolve.js";
import { crawlAndScanSecrets } from "./secrets_crawl.js";
import { scanMisconfigurations } from "./misconfig_scan.js";
import {
  submitToOsv,
  submitToNvd,
  getVulnById,
  getFix,
  scoreToSeverity,
  deduplicateVulnerabilitiesByAlias,
  sortVulnerabilities,
} from "../../sca/engine.js";
import { processVulnerability } from "../../sca/cvss_parser.js";
import { getComplianceForVulnerability } from "../../sca/compliance_mappings.js";
import { queryWpPlugin, queryWpTheme, queryWpCore, filterWpVulnerabilities } from "./wpvulnerability.js";

const SEVERITY_BUCKETS = () => ({ critical: 0, high: 0, medium: 0, low: 0, unknown: 0 });

// A version has to look at least like "major.minor" (e.g. "3.11", "1.26.3")
// to be worth sending to NVD. NVD's CPE range matching treats an
// underspecified version — most commonly a bare major version like "3" —
// as if it sits at the very start of that major line, which then satisfies
// almost every historical version-range recorded for that product: the
// result is a flood of CVEs spanning the product's entire history rather
// than anything specific to what's actually running, with "fix" data that
// lists every maintained branch's fix version because there's no way to
// tell which one applies. An empty version has the opposite (safer)
// failure mode — NVD's cpeName lookup just returns nothing for a fully
// wildcarded CPE — so it's the specific "some digits, not enough of them"
// case this guards against, not "no version at all" (already handled by
// the "safe" vs "undetermined" state logic below).
function isVersionSpecificEnough(version) {
  return /^\d+(\.\d+){1,}/.test(String(version || "").trim());
}

// One inventory item per distinct (name, version) pair, not per id — this
// is what lets a component's CPE alias(es) *and* its purl (when a scanner
// set one — see ../fingerprint/src/core/componentId.js) all land on the
// same item instead of splintering into separate rows that would each
// surface the same CVE independently. Lower-cased name only: versions are
// compared as-fingerprinted, since two different-looking version strings
// for what's actually the same release (rare, and not worth guessing at)
// are safer left as separate items than silently merged.
function buildInventoryKey(component) {
  return `${(component.Name || "unknown").toLowerCase()}::${component.Version || ""}`;
}

// WordPress core is fingerprinted as a plain {product:"wordpress",
// vendor:"wordpress"} component (see ../fingerprint/src/scanners/cms/wordpress.js),
// which buildCpeIds() always renders as `cpe:2.3:a:wordpress:wordpress:...`
// regardless of title-casing further up the pipeline — checking the CPE
// prefix directly sidesteps that instead of re-deriving it from Name.
// Plugins/themes carry their own tag straight from the WordPress scanner.
function detectWpKind(component, cpeId) {
  const tags = component.Tags || [];
  if (tags.includes("wordpress theme")) return "theme";
  if (tags.includes("wordpress plugin")) return "plugin";
  if (cpeId.toLowerCase().startsWith("cpe:2.3:a:wordpress:wordpress:")) return "core";
  return null;
}

/**
 * Fingerprint one target and fold its components into the shared
 * inventory map. Never throws — every outcome (scanned / skipped / error)
 * is captured on the returned asset-result object instead, so one bad
 * target can't abort a multi-target run.
 *
 * @param {string} target
 * @param {boolean} allowPrivate  passed straight through as
 *   DomainScanner's `skipVerification` — see the safety note in
 *   ../fingerprint/NOTICE.md before ever setting this true.
 * @param {Map<string, object>} inventoryByKey  keyed by buildInventoryKey()
 */
async function fingerprintTarget(target, allowPrivate, inventoryByKey) {
  const assetResult = {
    target,
    status: "scanned", // "scanned" | "skipped" | "error"
    error: null,
    resolved_url: null,
    components_found: 0,
  };

  let result;
  try {
    [result] = await DomainScanner.scan(target, allowPrivate);
  } catch (err) {
    assetResult.status = "error";
    assetResult.error = err.message;
    return assetResult;
  }

  if (!result) {
    // DomainScanner silently returns [] for a blacklisted/private/self-IP
    // target (see NOTICE.md) — surfaced here explicitly so the report
    // never reads as "clean" for a target that was actually never probed.
    assetResult.status = "skipped";
    assetResult.error =
      "resolved to a private/self IP and was skipped by the fingerprinter's safety guard " +
      "(pass --allow-private only for lab/localhost targets you own)";
    return assetResult;
  }

  assetResult.resolved_url = result.asset;
  assetResult.components_found = result.components.length;

  for (const component of result.components) {
    const host = component.Host || target;
    const port = component.Port ?? null;
    const ids = Array.isArray(component.Ids) && component.Ids.length ? component.Ids : [];
    if (!ids.length) continue; // nothing to look this component up by

    const key = buildInventoryKey(component);
    if (!inventoryByKey.has(key)) {
      inventoryByKey.set(key, {
        id: ids[0], // canonical/primary id — first one ever seen for this item; used wherever exactly one id is needed (JSON linking, WP lookups, etc.)
        ids: [], // every CPE + purl id seen for this item, deduplicated, populated below
        name: component.Name || "unknown",
        version: component.Version || "",
        ecosystem: "web",
        type: "service", // refined below once/if a WordPress tag or CPE match is seen
        scopes: ["prod"], // everything fingerprinted over the network is in prod, by definition
        state: "undetermined",
        low_confidence_version: !isVersionSpecificEnough(component.Version),
        // "plugin" | "theme" | "core" | null — routes this component to
        // wpvulnerability.net instead of NVD in scanTargets() below.
        wp_kind: null,
        assets: [],
      });
    }
    const item = inventoryByKey.get(key);

    for (const id of ids) {
      if (!item.ids.includes(id)) item.ids.push(id);
      if (!item.wp_kind) {
        const wpKind = detectWpKind(component, id);
        if (wpKind) {
          item.wp_kind = wpKind;
          item.type = wpKind === "core" ? "wordpress core" : `wordpress ${wpKind}`;
        }
      }
    }

    if (!item.assets.some((a) => a.host === host && a.port === port && a.target === target)) {
      item.assets.push({ host, port, target });
    }
  }

  return assetResult;
}

/**
 * Applies the exact same NVD-item post-processing engine.js's own scan()
 * does after submitToNvd() — see the comment there. processVulnerability()
 * expects OSV's raw `severity: [{type, score}]` shape, which an
 * NVD-derived item never has, so it always resets severity/score/vector to
 * null; the already-computed NVD score/vector are restored immediately
 * after. Kept as its own function so the exact behavior stays copy-paste
 * identical to the SCA engine rather than drifting out of sync.
 */
function finishNvdVulnerability(v) {
  const nvdScore = v.severity_score;
  const nvdVector = v.severity_vector;
  processVulnerability(v);
  if (v.severity_score == null) v.severity_score = nvdScore;
  if (v.severity_vector == null) v.severity_vector = nvdVector;
  v.severity = scoreToSeverity(v.severity_score);
  getFix(v);
  for (const key of ["database_specific", "affected", "schema_version"]) {
    delete v[key];
  }
}

/**
 * Dispatches one WordPress-tagged inventory item to the right
 * wpvulnerability.net endpoint and maps the response to this pipeline's
 * vuln shape. Never throws — a failed/unreachable query just yields no
 * findings for that component rather than aborting the whole scan, same
 * contract as fingerprintTarget() above.
 */
async function lookupWpItem(item, log) {
  try {
    let apiResponse;
    let ecosystem;
    if (item.wp_kind === "plugin") {
      apiResponse = await queryWpPlugin(item.name);
      ecosystem = "wordpress-plugin";
    } else if (item.wp_kind === "theme") {
      apiResponse = await queryWpTheme(item.name);
      ecosystem = "wordpress-theme";
    } else if (item.wp_kind === "core") {
      apiResponse = await queryWpCore(item.version);
      ecosystem = "wordpress-core";
    } else {
      return [];
    }
    return filterWpVulnerabilities(apiResponse.body, {
      pkgName: item.name,
      ecosystem,
      cpe: item.id,
      installedVersion: item.version,
    });
  } catch (err) {
    log(`[!] wpvulnerability.net query failed for ${item.name}@${item.version}: ${err.message}`);
    return [];
  }
}

/**
 * @param {string[]} targets            domains / hosts / URLs to fingerprint
 * @param {object}   [opts]
 * @param {boolean}  [opts.allowPrivate] forwarded to DomainScanner as skipVerification
 * @param {number}   [opts.concurrency]  parallel targets fingerprinted at once
 * @param {(msg:string)=>void} [opts.log] verbose-mode logger; no-op by default
 * @param {boolean}  [opts.scanSecrets]  run the JS secrets crawl (default true)
 * @param {boolean}  [opts.scanMisconfigs]  run the fixed-set misconfiguration probes (default true)
 * @param {number}   [opts.misconfigTimeout]  seconds per misconfiguration probe (default 8)
 *
 * @returns {Promise<{assets: object[], inventory: object[], vulnerabilities: object[], misconfigurations: object}>}
 */
export async function scanTargets(targets, opts = {}) {
  const {
    allowPrivate = false,
    concurrency = 4,
    log = () => {},
    scanSecrets = true,
    scanMisconfigs = true,
    misconfigTimeout = 8,
  } = opts;

  const cleanTargets = [...new Set(targets.map((t) => t.trim()).filter(Boolean))];
  const inventoryByKey = new Map();

  // ── DNS pre-resolution ─────────────────────────────────────────────────
  // Split the target list into names that exist in DNS and names that don't
  // BEFORE any probing. A dead name costs a full connect timeout to
  // discover the slow way and lands in the report as an ordinary "error",
  // which is the same status a live-but-broken host gets — so without this
  // step the report can't distinguish "this is gone" from "this failed".
  // Especially load-bearing for ubel-domain, whose target list comes from
  // append-only CT history and routinely contains long-decommissioned
  // hosts. See ./resolve.js.
  log(`[*] Resolving ${cleanTargets.length} target(s)...`);
  const { alive: liveTargets, dead: deadRecords, byTarget: resolutionByTarget } =
    await resolveTargets(cleanTargets);

  if (deadRecords.length) {
    log(
      `[*] ${deadRecords.length} target(s) did not resolve and won't be probed — ` +
      `they're reported with status "dead", not dropped.`
    );
  }

  // Dead hosts become first-class asset entries so the report accounts for
  // every target it was given. `components_found: 0` (not null) is
  // deliberate: it makes the stats math below uniform across every status.
  const deadAssets = deadRecords.map((r) => ({
    target: r.target,
    status: "dead",
    error:
      r.error === "ENOTFOUND" || r.error === "NXDOMAIN"
        ? "hostname does not resolve (no DNS record) — not probed"
        : `hostname could not be resolved (${r.error}) — not probed`,
    resolved_url: null,
    components_found: 0,
    resolved_ip: null,
    resolution_error: r.error,
  }));

  log(`[*] Fingerprinting ${liveTargets.length} resolvable target(s)...`);
  const assetResults = await mapLimit(liveTargets, concurrency, (target) =>
    fingerprintTarget(target, allowPrivate, inventoryByKey)
  );
  const scannedAssets = assetResults.map((r, i) => {
    const asset = r.ok
      ? r.value
      : { target: liveTargets[i], status: "error", error: r.error?.message || String(r.error) };
    const resolution = resolutionByTarget.get(asset.target);
    // Carried onto the asset so the report can show what a host resolved to
    // without needing the resolution map alongside it.
    asset.resolved_ip = resolution ? resolution.ip : null;
    asset.resolution_error = null;
    return asset;
  });

  // Input order, not resolution order — the report's target list should read
  // the way the user (or crt.sh) supplied it, with dead hosts in place
  // rather than collected at the end.
  const assetByTarget = new Map([...scannedAssets, ...deadAssets].map((a) => [a.target, a]));
  const assets = cleanTargets.map((t) => assetByTarget.get(t)).filter(Boolean);

  let inventory = [...inventoryByKey.values()];
  log(`[*] ${inventory.length} unique component(s) fingerprinted across all targets.`);

  // Reverse lookup so a vulnerability found under any one of an item's ids
  // (a CPE alias, or its purl) can be traced back to the item that owns it —
  // used below to collapse every id's results onto one canonical
  // affected_package_id per item before deduplicating.
  const idToItem = new Map();
  for (const item of inventory) {
    for (const id of item.ids) idToItem.set(id, item);
  }

  const queryable = inventory.filter((i) => !i.low_confidence_version);
  const skippedForLowConfidence = inventory.length - queryable.length;
  if (skippedForLowConfidence) {
    log(
      `[*] ${skippedForLowConfidence} component(s) have an under-specified version ` +
      `(e.g. a bare major version) and won't be queried against OSV/NVD/wpvulnerability.net ` +
      `— see easm/README.md's Known limitations. They're still listed in the inventory.`
    );
  }

  // WordPress plugins/themes/core are routed to wpvulnerability.net instead
  // of NVD — CPE dictionary coverage for WP plugins/themes is sparse and
  // rarely matches the wordpress.org slug this fingerprinter reads off the
  // page, so the generic CPE→NVD path misses most real findings for them.
  // See wpvulnerability.js for why this is a replacement, not an addition.
  const wpItems = queryable.filter((i) => i.wp_kind);
  const nonWpQueryable = queryable.filter((i) => !i.wp_kind);

  // Loop over every id of every non-WP queryable item and split by scheme —
  // a single item can carry both, e.g. a JS library with a CPE built from
  // vendor/product *and* a purl from a known npm package name (see
  // ../fingerprint/src/core/componentId.js) — so both get queried and both
  // sets of results land back on the same item (via idToItem above).
  const cpeQueryable = [];
  const purlIds = [];
  for (const item of nonWpQueryable) {
    for (const id of item.ids) {
      if (id.startsWith("pkg:")) purlIds.push(id);
      else cpeQueryable.push({ id, name: item.name, version: item.version, ecosystem: item.ecosystem });
    }
  }

  // ── OSV ────────────────────────────────────────────────────────────────
  // Purl ids only come from the handful of scanners that set component.purl
  // on something they can name precisely as a registry package (see
  // ../fingerprint/src/scanners/js_dev_ecosystem/*.js) — most fingerprinted
  // components have no purl and are CPE-only, which is fine: this loop
  // simply finds nothing to submit for them.
  log(`[*] Querying OSV for ${purlIds.length} purl-identified component(s)...`);
  const osvIds = await submitToOsv(purlIds);

  let vulnerabilities = [];
  if (osvIds.length) {
    const CONCURRENCY = 40;
    for (let i = 0; i < osvIds.length; i += CONCURRENCY) {
      const batch = osvIds.slice(i, i + CONCURRENCY);
      const results = await Promise.allSettled(batch.map(getVulnById));
      for (const r of results) {
        if (r.status === "fulfilled" && r.value) vulnerabilities.push(r.value);
      }
    }
  }

  // ── NVD ────────────────────────────────────────────────────────────────
  // This is where CPE-based fingerprints actually get matched to CVEs.
  // submitToNvd() already rate-limits/retries internally (NVD's
  // unauthenticated limit is ~5 req/30s) — a large multi-target scan can
  // take a while; see UBEL_NVD_ENDPOINT in ../README.md for pointing this
  // at an internal mirror or an authenticated proxy.
  log(`[*] Querying NVD for ${cpeQueryable.length} CPE id(s) (rate-limited — this can take a while)...`);
  const nvdVulns = await submitToNvd(cpeQueryable);
  for (const v of nvdVulns) {
    finishNvdVulnerability(v);
  }
  vulnerabilities.push(...nvdVulns);

  // ── wpvulnerability.net ────────────────────────────────────────────────
  if (wpItems.length) {
    log(`[*] Querying wpvulnerability.net for ${wpItems.length} WordPress component(s)...`);
    const WP_CONCURRENCY = 5;
    const wpResults = await mapLimit(wpItems, WP_CONCURRENCY, (item) => lookupWpItem(item, log));
    for (const r of wpResults) {
      if (r.ok) vulnerabilities.push(...r.value);
    }
  }

  // Every vuln above carries whichever single id it was actually queried
  // with as affected_package_id (a specific CPE alias, or a purl) — group
  // by item now, ahead of dedup, by rewriting each one onto its owning
  // item's canonical id. Without this, the same CVE surfacing via two
  // different ids for what's really one component (two CPE aliases, or a
  // CPE plus a purl) would dedup as two separate groups instead of one.
  for (const v of vulnerabilities) {
    const owningItem = idToItem.get(v.affected_package_id);
    if (owningItem) v.affected_package_id = owningItem.id;
  }

  vulnerabilities = deduplicateVulnerabilitiesByAlias(vulnerabilities);
  for (const v of vulnerabilities) {
    v.compliance = getComplianceForVulnerability(v.cwes, v.is_infection);
  }
  vulnerabilities = sortVulnerabilities(vulnerabilities);

  // ── Component state + stats ──────────────────────────────────────────────
  const vulnsByComponent = new Map();
  for (const v of vulnerabilities) {
    const key = v.affected_package_id;
    if (!vulnsByComponent.has(key)) vulnsByComponent.set(key, []);
    vulnsByComponent.get(key).push(v);
  }

  const severity = SEVERITY_BUCKETS();
  let infectionCount = 0;
  for (const v of vulnerabilities) {
    if (v.is_infection) infectionCount++;
    else severity[(v.severity || "unknown").toLowerCase() in severity ? (v.severity || "unknown").toLowerCase() : "unknown"]++;
  }

  for (const item of inventory) {
    if (item.low_confidence_version) {
      // Deliberately not queried — see isVersionSpecificEnough(). Reporting
      // "safe" here would be a false negative (we simply didn't check);
      // reporting whatever a wildcard-ish NVD match happened to return
      // would be the false-positive-flood this guard exists to avoid. The
      // honest state is "we can't say," same as a component with no
      // version at all.
      item.vulnerabilities_count = 0;
      item.state = "undetermined";
      continue;
    }
    const vs = vulnsByComponent.get(item.id) || [];
    item.vulnerabilities_count = vs.length;
    if (vs.some((v) => v.is_infection)) item.state = "infected";
    else if (vs.length) item.state = "vulnerable";
    else if (item.version) item.state = "safe";
    else item.state = "undetermined";
  }

  // ── Client-side secret exposure ────────────────────────────────────────
  // Runs after fingerprinting, against the hosts that actually answered, so
  // it only ever re-requests pages already known to be live. Independent of
  // the CVE pipeline above: a hardcoded credential in a page's JavaScript
  // isn't a "component has a known vulnerability" finding and doesn't
  // belong in the inventory/vulnerability model, so it's carried alongside
  // as its own result set. See ./secrets_crawl.js.
  let secrets = { findings: [], errors: [], stats: { total: 0 } };
  if (scanSecrets) {
    secrets = await crawlAndScanSecrets(assets, { concurrency, log });
  }

  // ── Fixed-set web misconfiguration checks ──────────────────────────────
  // Independent of both the CVE pipeline and the secrets crawl: point
  // probes against each scanned host for a fixed set of well-known
  // misconfigurations — exposed .env / .git, xmlrpc.php, WP user enum,
  // phpinfo(), TLS certificate issues, missing security headers
  // (HSTS / clickjacking / no-HTTPS-at-all), and SPF/DMARC/DKIM email-
  // authentication gaps (the one DNS-only check in the set). See
  // ./misconfig_scan.js.
  let misconfigurations = {
    findings: [],
    errors: [],
    stats: { total: 0, by_severity: {}, by_category: {} },
  };
  if (scanMisconfigs) {
    misconfigurations = await scanMisconfigurations(assets, inventory, {
      concurrency,
      timeout: misconfigTimeout,
      log,
    });
  }

  // Rolled up here rather than recomputed in the report layer so the JSON
  // and HTML reports can never disagree about how many hosts were actually
  // reachable — the numbers the Stats tab shows are the ones the scan made
  // its own decisions on.
  const resolution = {
    total: cleanTargets.length,
    resolved: liveTargets.length,
    dead: deadRecords.length,
    dead_hosts: deadRecords.map((r) => ({ target: r.target, hostname: r.hostname, error: r.error })),
  };

  return {
    assets,
    inventory,
    vulnerabilities,
    resolution,
    secrets,
    misconfigurations,
    stats: { severity, infectionCount },
  };
}