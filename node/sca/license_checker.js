/**
 * license_checker.js
 * ─────────────────────────────────────────────────────────────────────────
 * Zero-dependency license normalization + OSI-approval + risk classification
 * module for UBEL inventory items.
 *
 * Package managers report licenses in wildly inconsistent shapes:
 *   - missing / null / "" / "unknown" / "none" / "n/a"
 *   - free text ("Apache 2.0", "BSD", "MIT License")
 *   - the npm-specific sentinel "UNLICENSED" (proprietary — NOT the SPDX
 *     "Unlicense" public-domain license, a very common footgun)
 *   - npm "SEE LICENSE IN <file>" references
 *   - legacy npm object/array forms: {type, url} or [{type, url}, ...]
 *   - Python trove classifiers: "License :: OSI Approved :: MIT License"
 *   - full SPDX expressions: "(MIT OR Apache-2.0)", "GPL-2.0-or-later"
 *
 * This module normalizes all of the above into canonical SPDX identifiers,
 * checks them against a curated table of OSI-approved licenses
 * (https://opensource.org/licenses), and derives a risk rating so
 * downstream consumers (report, policy, SBOM) don't each reinvent this.
 *
 * Nothing here talks to the network — the OSI list is small and stable
 * enough to vendor, consistent with UBEL's zero-dependency / no-egress
 * architecture.
 * ─────────────────────────────────────────────────────────────────────────
 */

// ── Canonical license table ─────────────────────────────────────────────
//
// risk:      "low" | "medium" | "high"   (permissive → weak copyleft → strong
//            copyleft / proprietary / unreviewable text)
// category:  human-facing bucket
// osi:       true  -> on the OSI-approved license list
//            false -> a real, identifiable license that is NOT OSI-approved
//            (there is no "null" here; unknown-ness is handled upstream by
//            falling through to the UNRECOGNIZED/NONE cases)
//
// This is a curated, practically-useful subset — not a mirror of every
// license SPDX has ever catalogued. Unrecognized identifiers fall through
// to a conservative "unrecognized" classification rather than guessing.
const LICENSE_TABLE = Object.freeze({
  // ── Permissive, OSI-approved ──
  "MIT":              { osi: true,  category: "permissive",     risk: "low" },
  "MIT-0":            { osi: true,  category: "permissive",     risk: "low" },
  "Apache-1.1":       { osi: true,  category: "permissive",     risk: "low" },
  "Apache-2.0":       { osi: true,  category: "permissive",     risk: "low" },
  "BSD-2-Clause":     { osi: true,  category: "permissive",     risk: "low" },
  "BSD-3-Clause":     { osi: true,  category: "permissive",     risk: "low" },
  "BSD-3-Clause-Clear": { osi: true, category: "permissive",    risk: "low" },
  "0BSD":             { osi: true,  category: "permissive",     risk: "low" },
  "ISC":              { osi: true,  category: "permissive",     risk: "low" },
  "Zlib":             { osi: true,  category: "permissive",     risk: "low" },
  "Python-2.0":       { osi: true,  category: "permissive",     risk: "low" },
  "PSF-2.0":          { osi: true,  category: "permissive",     risk: "low" },
  "BSL-1.0":          { osi: true,  category: "permissive",     risk: "low" },
  "NCSA":             { osi: true,  category: "permissive",     risk: "low" },
  "Unlicense":        { osi: true,  category: "public-domain",  risk: "low" },
  "X11":              { osi: true,  category: "permissive",     risk: "low" },
  "Artistic-2.0":     { osi: true,  category: "permissive",     risk: "low" },

  // ── Permissive-in-practice, NOT OSI-approved ──
  "WTFPL":            { osi: false, category: "permissive",     risk: "low" },
  "CC0-1.0":          { osi: false, category: "public-domain",  risk: "low" },

  // ── Weak copyleft, OSI-approved (file-level obligations) ──
  "MPL-1.1":               { osi: true, category: "weak-copyleft", risk: "medium" },
  "MPL-2.0":               { osi: true, category: "weak-copyleft", risk: "medium" },
  "LGPL-2.1-only":         { osi: true, category: "weak-copyleft", risk: "medium" },
  "LGPL-2.1-or-later":     { osi: true, category: "weak-copyleft", risk: "medium" },
  "LGPL-3.0-only":         { osi: true, category: "weak-copyleft", risk: "medium" },
  "LGPL-3.0-or-later":     { osi: true, category: "weak-copyleft", risk: "medium" },
  "EPL-1.0":               { osi: true, category: "weak-copyleft", risk: "medium" },
  "EPL-2.0":               { osi: true, category: "weak-copyleft", risk: "medium" },
  "CDDL-1.0":              { osi: true, category: "weak-copyleft", risk: "medium" },
  "CDDL-1.1":              { osi: true, category: "weak-copyleft", risk: "medium" },
  "MS-PL":                 { osi: true, category: "weak-copyleft", risk: "medium" },
  "MS-RL":                 { osi: true, category: "weak-copyleft", risk: "medium" },
  "OSL-3.0":               { osi: true, category: "weak-copyleft", risk: "medium" },
  "EUPL-1.1":              { osi: true, category: "weak-copyleft", risk: "medium" },
  "EUPL-1.2":              { osi: true, category: "weak-copyleft", risk: "medium" },

  // ── Strong copyleft, OSI-approved (project-wide obligations) ──
  "GPL-1.0-only":          { osi: true, category: "strong-copyleft", risk: "high" },
  "GPL-2.0-only":          { osi: true, category: "strong-copyleft", risk: "high" },
  "GPL-2.0-or-later":      { osi: true, category: "strong-copyleft", risk: "high" },
  "GPL-3.0-only":          { osi: true, category: "strong-copyleft", risk: "high" },
  "GPL-3.0-or-later":      { osi: true, category: "strong-copyleft", risk: "high" },
  "AGPL-3.0-only":         { osi: true, category: "strong-copyleft", risk: "high" },
  "AGPL-3.0-or-later":     { osi: true, category: "strong-copyleft", risk: "high" },

  // ── Source-available / rejected-by-OSI / proprietary-leaning ──
  // These are real, named licenses — but explicitly not OSI-approved, and
  // several (SSPL, Commons Clause) were submitted and rejected.
  "SSPL-1.0":         { osi: false, category: "source-available", risk: "high" },
  "BUSL-1.1":         { osi: false, category: "source-available", risk: "high" },
  "Elastic-2.0":      { osi: false, category: "source-available", risk: "high" },
  "Commons-Clause":   { osi: false, category: "source-available", risk: "high" },
  "CC-BY-4.0":        { osi: false, category: "non-software",     risk: "high" },
  "CC-BY-SA-4.0":     { osi: false, category: "non-software",     risk: "high" },
  "CC-BY-NC-4.0":     { osi: false, category: "non-software",     risk: "high" },
  "Proprietary":      { osi: false, category: "proprietary",      risk: "high" },
});

// GPL/LGPL/AGPL "+" suffix and bare "GPL-2.0" style ids get resolved to
// "-or-later" / "-only" forms during normalization (see NORMALIZE_SUFFIX).

// ── Alias / free-text normalization table ───────────────────────────────
// Keys are lower-cased, whitespace-collapsed strings. Values are canonical
// SPDX identifiers as used in LICENSE_TABLE above.
const ALIASES = Object.freeze({
  "mit": "MIT", "mit license": "MIT", "the mit license": "MIT", "expat": "MIT",

  "apache": "Apache-2.0", "apache 2": "Apache-2.0", "apache2": "Apache-2.0",
  "apache 2.0": "Apache-2.0", "apache license 2.0": "Apache-2.0",
  "apache license, version 2.0": "Apache-2.0", "apache-2": "Apache-2.0",
  "apache software license": "Apache-2.0", "asl 2.0": "Apache-2.0",

  "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
  "bsd 3-clause": "BSD-3-Clause", "bsd-3": "BSD-3-Clause",
  "new bsd license": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause",
  "bsd 2-clause": "BSD-2-Clause", "bsd-2": "BSD-2-Clause",
  "simplified bsd license": "BSD-2-Clause", "freebsd": "BSD-2-Clause",

  "isc license": "ISC", "isc license (iscl)": "ISC",

  "zlib license": "Zlib", "zlib/libpng license": "Zlib",

  "python software foundation license": "PSF-2.0", "psf": "PSF-2.0",
  "psf license": "PSF-2.0",

  "boost software license 1.0": "BSL-1.0", "boost software license": "BSL-1.0",

  "the unlicense": "Unlicense", "public domain": "Unlicense",

  "creative commons zero": "CC0-1.0", "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0",
  "cc0 1.0 universal": "CC0-1.0",

  "mozilla public license 2.0": "MPL-2.0", "mpl 2.0": "MPL-2.0",
  "mozilla public license 1.1": "MPL-1.1", "mpl 1.1": "MPL-1.1",

  "lesser general public license v2.1": "LGPL-2.1-only",
  "lgpl 2.1": "LGPL-2.1-only", "lgplv2.1": "LGPL-2.1-only",
  "lgpl 3.0": "LGPL-3.0-only", "lgplv3": "LGPL-3.0-only",
  "gnu lesser general public license": "LGPL-3.0-only",

  "eclipse public license 1.0": "EPL-1.0", "epl 1.0": "EPL-1.0",
  "eclipse public license 2.0": "EPL-2.0", "epl 2.0": "EPL-2.0",
  "eclipse public license": "EPL-2.0",

  "common development and distribution license 1.0": "CDDL-1.0",
  "cddl 1.0": "CDDL-1.0", "cddl 1.1": "CDDL-1.1",

  "microsoft public license": "MS-PL", "ms-pl license": "MS-PL",
  "microsoft reciprocal license": "MS-RL",

  "gnu general public license v2": "GPL-2.0-only", "gpl2": "GPL-2.0-only",
  "gplv2": "GPL-2.0-only", "gpl 2.0": "GPL-2.0-only", "gpl-2": "GPL-2.0-only",
  "gnu general public license v3": "GPL-3.0-only", "gpl3": "GPL-3.0-only",
  "gplv3": "GPL-3.0-only", "gpl 3.0": "GPL-3.0-only", "gpl-3": "GPL-3.0-only",
  "gpl": "GPL-3.0-only",

  "gnu affero general public license v3": "AGPL-3.0-only",
  "agpl3": "AGPL-3.0-only", "agplv3": "AGPL-3.0-only", "agpl 3.0": "AGPL-3.0-only",
  "agpl-3": "AGPL-3.0-only", "agpl": "AGPL-3.0-only",

  "server side public license": "SSPL-1.0", "sspl": "SSPL-1.0",
  "sspl 1.0": "SSPL-1.0",

  "business source license": "BUSL-1.1", "business source license 1.1": "BUSL-1.1",

  "elastic license": "Elastic-2.0", "elastic license 2.0": "Elastic-2.0",

  "creative commons attribution 4.0": "CC-BY-4.0", "cc-by": "CC-BY-4.0",
  "creative commons attribution-sharealike 4.0": "CC-BY-SA-4.0",
  "creative commons attribution-noncommercial 4.0": "CC-BY-NC-4.0",

  "wtfpl": "WTFPL", "do what the fuck you want": "WTFPL",

  "proprietary": "Proprietary", "all rights reserved": "Proprietary",
});

// Sentinel strings that mean "there is genuinely no usable license info",
// distinct from a real (if unrecognized) license string.
const EMPTY_SENTINELS = new Set([
  "", "unknown", "none", "null", "n/a", "na", "not specified", "unspecified",
  "nofile", "unlicensed license", // guard against odd re-serializations
]);

// npm's `"license": "UNLICENSED"` — proprietary sentinel, NOT SPDX "Unlicense".
const NPM_UNLICENSED = "unlicensed";

const RISK_RANK = { low: 1, medium: 2, high: 3, unknown: 4 };

// ── Normalization ────────────────────────────────────────────────────────

function stripPythonClassifier(str) {
  // "License :: OSI Approved :: MIT License" -> "MIT License"
  const marker = "license :: osi approved ::";
  const lower  = str.toLowerCase();
  const idx    = lower.indexOf(marker);
  if (idx !== -1) return str.slice(idx + marker.length).trim();
  if (lower.startsWith("license ::")) {
    const parts = str.split("::");
    return parts[parts.length - 1].trim();
  }
  return str;
}

function cleanToken(token) {
  return token
    .trim()
    .replace(/^\(+|\)+$/g, "")
    .replace(/\s+/g, " ")
    .replace(/\.$/, "")
    .trim();
}

/**
 * Resolves a single free-text or SPDX-ish token to a canonical SPDX id.
 * Returns null if the token can't be confidently identified.
 */
function normalizeToken(rawToken) {
  let token = cleanToken(stripPythonClassifier(rawToken));
  if (!token) return null;

  // "License" suffix noise: "MIT License" -> already aliased above, but
  // catch generic "<Name> License" forms not explicitly listed.
  const key = token.toLowerCase();
  if (ALIASES[key]) return ALIASES[key];

  // Strip a trailing " license" / " licence" and retry.
  const withoutSuffix = key.replace(/\s+licen[cs]e$/, "");
  if (withoutSuffix !== key && ALIASES[withoutSuffix]) return ALIASES[withoutSuffix];

  // GPL-family "+" shorthand: "GPL-2.0+" -> GPL-2.0-or-later
  const plusMatch = token.match(/^([A-Za-z]+)[-\s]?(\d(?:\.\d)?)\+$/);
  if (plusMatch) {
    const fam = plusMatch[1].toUpperCase();
    const ver = plusMatch[2];
    const candidate = `${fam}-${ver}-or-later`;
    if (LICENSE_TABLE[candidate]) return candidate;
  }

  // Already-canonical SPDX id (exact match, case-sensitive-ish).
  const exact = Object.keys(LICENSE_TABLE).find(
    id => id.toLowerCase() === key
  );
  if (exact) return exact;

  // Bare "GPL-2.0" / "LGPL-2.1" without -only/-or-later — default to -only,
  // the more conservative (obligation-triggering-sooner) reading.
  const bareCopyleft = token.match(
    /^(A?GPL|LGPL)[-\s]?(\d(?:\.\d)?)$/i
  );
  if (bareCopyleft) {
    const fam = bareCopyleft[1].toUpperCase();
    const ver = bareCopyleft[2];
    const candidate = `${fam}-${ver}-only`;
    if (LICENSE_TABLE[candidate]) return candidate;
  }

  // Looks like a plausible SPDX identifier shape but isn't one we know.
  if (/^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(token) && token.length <= 40) {
    return token; // returned as-is; caller checks LICENSE_TABLE membership
  }

  return null; // free-form text we can't safely parse (e.g. pasted license body)
}

/**
 * Splits an SPDX-style boolean expression into a flat operator + operand
 * list. Deliberately simple (no nested-precedence parser) — real-world
 * inventory license fields are essentially always a single id or a flat
 * "(A OR B)" / "A AND B" pair, never deeply nested expressions.
 *
 * Returns { op: "SINGLE"|"OR"|"AND", tokens: string[] }
 */
function splitExpression(raw) {
  const cleaned = raw.trim().replace(/^\(+|\)+$/g, "");
  const orParts = cleaned.split(/\s+OR\s+/i);
  if (orParts.length > 1) {
    return { op: "OR", tokens: orParts.map(cleanToken) };
  }
  const andParts = cleaned.split(/\s+AND\s+/i);
  if (andParts.length > 1) {
    return { op: "AND", tokens: andParts.map(cleanToken) };
  }
  return { op: "SINGLE", tokens: [cleaned] };
}

/**
 * Coerces the many shapes a "license" field can arrive in (string, legacy
 * npm object, array of either) into a single string expression.
 */
function coerceToString(input) {
  if (input == null) return null;
  if (typeof input === "string") return input;
  if (Array.isArray(input)) {
    const parts = input.map(coerceToString).filter(Boolean);
    return parts.length ? parts.join(" AND ") : null;
  }
  if (typeof input === "object") {
    if (typeof input.type === "string") return input.type;
    if (typeof input.spdx === "string") return input.spdx;
    if (typeof input.id === "string") return input.id;
  }
  return null;
}

function classifyId(id) {
  const entry = LICENSE_TABLE[id];
  if (entry) return { id, ...entry };
  return { id, osi: false, category: "unrecognized", risk: "unknown" };
}

function aggregate(op, classifications) {
  if (op === "SINGLE") return classifications[0];

  if (op === "OR") {
    // Best case wins — the consumer may legally pick the most favorable term.
    const best = classifications.reduce((a, b) =>
      RISK_RANK[a.risk] <= RISK_RANK[b.risk] ? a : b
    );
    return {
      id:       classifications.map(c => c.id).join(" OR "),
      osi:      classifications.some(c => c.osi),
      category: best.category,
      risk:     best.risk,
    };
  }

  // AND — conjunctive, obligations stack, worst case governs.
  const worst = classifications.reduce((a, b) =>
    RISK_RANK[a.risk] >= RISK_RANK[b.risk] ? a : b
  );
  return {
    id:       classifications.map(c => c.id).join(" AND "),
    osi:      classifications.every(c => c.osi),
    category: worst.category,
    risk:     worst.risk,
  };
}

/**
 * Classifies a single inventory item's raw license field.
 *
 * @param {string|object|Array|null|undefined} rawLicense
 * @returns {{
 *   raw: string|null,
 *   spdx: string|null,
 *   identifiers: string[],
 *   osi_approved: boolean|null,
 *   risk: "low"|"medium"|"high"|"unknown",
 *   category: string,
 *   reason: string
 * }}
 */
function classifyLicense(rawLicense) {
  const str = coerceToString(rawLicense);

  if (str === null || EMPTY_SENTINELS.has(str.trim().toLowerCase())) {
    return {
      raw: str,
      spdx: null,
      identifiers: [],
      osi_approved: null,
      risk: "unknown",
      category: "none",
      reason: "No license information reported for this package.",
    };
  }

  const trimmed = str.trim();

  if (trimmed.toLowerCase() === NPM_UNLICENSED) {
    return {
      raw: str,
      spdx: null,
      identifiers: [],
      osi_approved: false,
      risk: "high",
      category: "proprietary",
      reason: "npm \"UNLICENSED\" marker — explicitly no license grant " +
              "(all rights reserved). Not to be confused with the SPDX " +
              "\"Unlicense\" public-domain license.",
    };
  }

  if (/^see license in/i.test(trimmed)) {
    return {
      raw: str,
      spdx: null,
      identifiers: [],
      osi_approved: false,
      risk: "high",
      category: "custom",
      reason: "License terms are referenced in a file rather than declared " +
              "as an identifier; terms are not machine-verifiable.",
    };
  }

  const { op, tokens } = splitExpression(trimmed);
  const normalizedIds  = tokens.map(normalizeToken);

  if (normalizedIds.some(id => id === null)) {
    return {
      raw: str,
      spdx: null,
      identifiers: [],
      osi_approved: null,
      risk: "unknown",
      category: "unrecognized",
      reason: "License text could not be parsed into a recognizable " +
              "SPDX identifier; manual review recommended.",
    };
  }

  const classifications = normalizedIds.map(classifyId);
  const result = aggregate(op, classifications);

  const knownIds  = classifications.filter(c => c.category !== "unrecognized");
  const anyUnknown = classifications.some(c => c.category === "unrecognized");

  let reason;
  if (anyUnknown) {
    reason = `Contains an unrecognized license identifier alongside ` +
             `${knownIds.map(c => c.id).join(", ") || "no known licenses"}; ` +
             `treated conservatively.`;
  } else if (op === "SINGLE") {
    reason = result.osi
      ? `${result.id} is an OSI-approved ${result.category} license.`
      : `${result.id} is not on the OSI-approved license list (${result.category}).`;
  } else if (op === "OR") {
    reason = `Dual/multi-licensed (${result.id}); classified using the ` +
              `most favorable option (${result.category}, ${result.risk} risk).`;
  } else {
    reason = `Multiple licenses apply conjunctively (${result.id}); ` +
              `classified using the most restrictive component ` +
              `(${result.category}, ${result.risk} risk).`;
  }

  return {
    raw: str,
    spdx: op === "SINGLE" ? classifications[0].id : result.id,
    identifiers: classifications.map(c => c.id),
    osi_approved: anyUnknown ? null : result.osi,
    risk: anyUnknown ? "unknown" : result.risk,
    category: anyUnknown ? "unrecognized" : result.category,
    reason,
  };
}

/**
 * Mutates every item in an inventory array in place, adding a
 * `license_info` classification object (see classifyLicense above) built
 * from the item's existing `license` field. The original `license` field
 * itself is left untouched (still the raw string/object as reported by the
 * package manager) — `license_info` is purely additive.
 *
 * Also returns a small aggregate summary, useful for report/stats surfaces.
 *
 * @param {object[]} inventory
 * @returns {{ total: number, osi_approved: number, not_osi_approved: number,
 *             unknown: number, by_risk: {low:number, medium:number,
 *             high:number, unknown:number} }}
 */
function enrichInventoryWithLicenseRisk(inventory) {
  const summary = {
    total: inventory.length,
    osi_approved: 0,
    not_osi_approved: 0,
    unknown: 0,
    by_risk: { low: 0, medium: 0, high: 0, unknown: 0 },
  };

  for (const item of inventory) {
    const info = classifyLicense(item.license);
    item.license_info = info;

    if (info.osi_approved === true)       summary.osi_approved++;
    else if (info.osi_approved === false)  summary.not_osi_approved++;
    else                                    summary.unknown++;

    summary.by_risk[info.risk] = (summary.by_risk[info.risk] || 0) + 1;
  }

  return summary;
}

function isOsiApproved(rawLicense) {
  return classifyLicense(rawLicense).osi_approved;
}

export {
  classifyLicense,
  enrichInventoryWithLicenseRisk,
  isOsiApproved,
  LICENSE_TABLE,
  ALIASES,
};