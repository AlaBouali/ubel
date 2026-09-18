// Turns an internal {product, vendor, version, tags, purl, ...} record into
// one or more identifiers: buildCpeIds() below builds CPE 2.3 ids from the
// vendor/product naming already baked into every scanner's output (it was
// written to mirror CPE fields from the start - see cpe_parser.py), and
// buildPurlIds() builds a purl id from an explicit `component.purl` hint
// when a scanner sets one (see that function for why it's opt-in rather
// than derived). normalizeComponent() in ./normalize.js concatenates both
// into one `Ids` array per component — a single component can carry both
// kinds at once (e.g. a CPE from vendor/product plus a purl from a known
// npm package name), which is what lets scan.js query it against NVD *and*
// OSV and attribute both sets of results back to the same inventory item.
//
// Format: cpe:2.3:<type>:<vendor>:<product>:<version>:*:*:*:*:*:*:*
//
// `vendor` and/or `product` may each be a single string or an array of
// aliases (e.g. a component known as both "nodejs" and "node.js", or a
// product historically filed under more than one vendor) - every
// vendor/product combination gets its own id, so one detected component can
// resolve to a list of ids instead of being forced into exactly one.

const OS_PRODUCTS = new Set(["windows", "linux", "unix", "macos", "freebsd", "ubuntu", "debian"]);

function toSlugList(value) {
  const list = Array.isArray(value) ? value : [value];
  const slugs = list.filter((v) => v != null && v !== "").map((v) => String(v).toLowerCase().replace(/\s+/g, "_"));
  return slugs.length ? slugs : ["*"];
}

/**
 * @param {{product?: string|string[], vendor?: string|string[], version?: string, tags?: string[]}} component
 * @returns {string[]} one CPE 2.3 id per vendor/product alias combination (never empty, deduplicated)
 */
export function buildCpeIds(component) {
  const vendors = toSlugList(component.vendor);
  const products = toSlugList(component.product);
  const version = component.version && component.version !== "" ? component.version : "*";
  const tags = component.tags || [];

  const ids = [];
  for (const vendor of vendors) {
    for (const product of products) {
      const type = tags.includes("operating_system") || OS_PRODUCTS.has(product) ? "o" : "a";
      ids.push(`cpe:2.3:${type}:${vendor}:${product}:${version}:*:*:*:*:*:*:*`);
    }
  }
  return [...new Set(ids)];
}

// A purl (package URL, https://github.com/package-url/purl-spec) is only
// generated when a scanner explicitly opts in via `component.purl` —
// unlike vendor/product there's no reliable way to derive a registry
// package name from arbitrary fingerprint data, so this is never inferred.
// A handful of js_dev_ecosystem scanners set it because they detect an
// individually-versioned, registry-published package by name (e.g. React
// off its own bundled version string) — see e.g.
// ../scanners/js_dev_ecosystem/react.js. Most scanners (CMSes, admin
// panels, network services, ...) have nothing meaningful to set here and
// simply don't, which is the default, unchanged path.
//
// @param {{purl?: {ecosystem: string, name: string, namespace?: string}, version?: string}} component
// @returns {string[]} zero or one purl id — no alias concept here, unlike buildCpeIds;
//   a purl names one specific registry package, not a family of vendor/product guesses
export function buildPurlIds(component) {
  const purl = component.purl;
  const version = component.version || "";
  // Without a version there's nothing for OSV to match a range against, so
  // don't bother emitting one — same reasoning as isVersionSpecificEnough()
  // gating CPE-based items out of the query pass downstream in scan.js.
  if (!purl || !purl.name || !purl.ecosystem || !version) return [];

  const segments = [];
  if (purl.namespace) segments.push(encodeURIComponent(purl.namespace));
  segments.push(encodeURIComponent(purl.name));

  return [`pkg:${purl.ecosystem}/${segments.join("/")}@${encodeURIComponent(version)}`];
}