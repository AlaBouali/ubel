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
  // MIT-CMU — a Carnegie Mellon-attributed MIT variant; distinct SPDX id
  // from plain "MIT" (CMU is listed as an added copyright holder in the
  // license text) and not on the OSI-approved list under this specific id,
  // but functionally the same permissive terms. Notably: this is Pillow's
  // own declared license.
  "MIT-CMU":          { osi: false, category: "permissive",     risk: "low" },
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
  "PHP-3.01":         { osi: true,  category: "permissive",     risk: "low" },
  "PHP-3.0":          { osi: true,  category: "permissive",     risk: "low" },
  // Blue Oak Model License 1.0.0 — maintained by the Blue Oak Council, a
  // deliberately clearer/shorter rewrite of MIT/BSD-style terms with the
  // same permissive effect (no copyleft, no attribution-notice-preservation
  // gotchas). Not currently OSI-approved (never submitted through that
  // process), but functionally equivalent risk to MIT/BSD.
  "BlueOak-1.0.0":    { osi: false, category: "permissive",     risk: "low" },
  // Ruby's own license — not currently on the OSI-approved list, but a
  // real, well-understood permissive license (dual-licensable with the
  // GPL). Distinct from the BSD-2-Clause it's often paired with in
  // "Ruby OR BSD-2-Clause" expressions.
  "Ruby":             { osi: false, category: "permissive",     risk: "low" },

  // Added for RPM/Fedora-style license metadata (AlmaLinux/RHEL/Fedora images).
  "BSD-4-Clause":     { osi: false, category: "permissive",     risk: "low" },   // "BSD with advertising"
  "AFL-2.1":          { osi: true,  category: "permissive",     risk: "low" },
  "AFL-3.0":          { osi: true,  category: "permissive",     risk: "low" },
  "OLDAP-2.8":        { osi: true,  category: "permissive",     risk: "low" },   // "OpenLDAP"
  "OpenSSL":          { osi: false, category: "permissive",     risk: "low" },   // advertising clause
  "Inner-Net-2.0":    { osi: false, category: "permissive",     risk: "low" },   // glibc, Fedora "Inner-Net"

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
  "LGPL-2.0-only":         { osi: true, category: "weak-copyleft", risk: "medium" },
  "LGPL-2.0-or-later":     { osi: true, category: "weak-copyleft", risk: "medium" },
  "SISSL":                 { osi: true, category: "weak-copyleft", risk: "medium" },
  // Vim's license (charityware): modified versions must be marked and their
  // source made available. Not OSI-approved. Weak-copyleft-like.
  "Vim":                   { osi: false, category: "weak-copyleft", risk: "medium" },

  // ── Strong copyleft, OSI-approved (project-wide obligations) ──
  "GPL-1.0-only":          { osi: true, category: "strong-copyleft", risk: "high" },
  "GPL-1.0-or-later":      { osi: true, category: "strong-copyleft", risk: "high" },
  // Berkeley DB's license: redistributing the work requires offering source
  // for the *whole* application — reciprocal, so rated like strong copyleft.
  "Sleepycat":             { osi: true, category: "strong-copyleft", risk: "high" },
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
  // GNU Free Documentation License — copyleft for documentation (glibc/GCC
  // manuals etc.), not a software license and not OSI-approved.
  "GFDL-1.3-only":        { osi: false, category: "non-software",     risk: "medium" },
  "GFDL-1.3-or-later":    { osi: false, category: "non-software",     risk: "medium" },
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
  // "Apache Software" (no trailing "License") is PyPI's classic
  // `license` metadata field value, distinct from the newer trove
  // classifier — seen as-is on real packages (motor, requests,
  // python-dateutil, s3transfer, python-multipart). Apache 1.1 is
  // essentially extinct in maintained packages, so treating this as
  // Apache-2.0 matches what other license-scanning tools (e.g.
  // pip-licenses) assume in practice.
  "apache software": "Apache-2.0",

  "bsd": "BSD-3-Clause", "bsd license": "BSD-3-Clause",
  "bsd 3-clause": "BSD-3-Clause", "bsd-3": "BSD-3-Clause",
  "new bsd license": "BSD-3-Clause", "3-clause bsd": "BSD-3-Clause",
  "bsd 2-clause": "BSD-2-Clause", "bsd-2": "BSD-2-Clause",
  "simplified bsd license": "BSD-2-Clause", "freebsd": "BSD-2-Clause",

  "isc license": "ISC", "isc license (iscl)": "ISC",
  // Same as above without the word "license" — dnspython's actual
  // declared metadata value is "ISC  (ISCL)" (collapses to this after
  // whitespace normalization).
  "isc (iscl)": "ISC",

  "blue oak model license": "BlueOak-1.0.0", "blue oak model license 1.0.0": "BlueOak-1.0.0",
  "blueoak-1.0.0": "BlueOak-1.0.0", "blueoak 1.0.0": "BlueOak-1.0.0", "blueoak": "BlueOak-1.0.0",

  "zlib license": "Zlib", "zlib/libpng license": "Zlib",

  "python software foundation license": "PSF-2.0", "psf": "PSF-2.0",
  "psf license": "PSF-2.0",

  "boost software license 1.0": "BSL-1.0", "boost software license": "BSL-1.0",

  "the unlicense": "Unlicense", "public domain": "Unlicense",

  "creative commons zero": "CC0-1.0", "cc0": "CC0-1.0", "cc0 1.0": "CC0-1.0",
  "cc0 1.0 universal": "CC0-1.0",

  "mozilla public license 2.0": "MPL-2.0", "mpl 2.0": "MPL-2.0",
  // certifi's actual declared metadata value — "Mozilla Public 2.0
  // (MPL 2.0)" (no "License" word, parenthetical suffix) after
  // whitespace normalization.
  "mozilla public 2.0 (mpl 2.0)": "MPL-2.0",
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

  // ── RPM / Fedora short names (AlmaLinux, RHEL, Fedora, CentOS) ──
  // GPLv2+/LGPLv3+/GPLv2 etc. are handled generically by GNU_SHORTHAND below;
  // these are the non-GNU tags.
  "asl 1.1": "Apache-1.1",
  "bsd with advertising": "BSD-4-Clause",
  "python": "Python-2.0",
  "boost": "BSL-1.0",
  "mplv2.0": "MPL-2.0", "mplv2": "MPL-2.0", "mplv1.1": "MPL-1.1",
  // Fedora's "AFL" is version-agnostic; 2.1 and 3.0 carry the same risk.
  "afl": "AFL-3.0",
  "openldap": "OLDAP-2.8",
  "inner-net": "Inner-Net-2.0",
  // Fedora's "GFDL" is version-agnostic; assumed 1.3-or-later.
  "gfdl": "GFDL-1.3-or-later",
  // Fedora "GPL+" / "LGPL+" = any version, or later.
  "gpl+": "GPL-1.0-or-later", "lgpl+": "LGPL-2.0-or-later",
});

// Sentinel strings that mean "there is genuinely no usable license info",
// distinct from a real (if unrecognized) license string.
const EMPTY_SENTINELS = new Set([
  "", "unknown", "none", "null", "n/a", "na", "not specified", "unspecified",
  "nofile", "unlicensed license", // guard against odd re-serializations
  // rpm's gpg-pubkey pseudo-packages (imported signing keys) carry "pubkey"
  // as their License tag — they are keys, not software.
  "pubkey",
]);

// npm's `"license": "UNLICENSED"` — proprietary sentinel, NOT SPDX "Unlicense".
const NPM_UNLICENSED = "unlicensed";

const RISK_RANK = { low: 1, medium: 2, high: 3, unknown: 4 };

// ── SPDX "WITH <exception>" modifiers ────────────────────────────────────
// A handful of copyleft licenses are commonly paired with a linking
// exception that meaningfully changes their practical risk — most notably
// the GPL family's Classpath exception, used by OpenJDK/Oracle JDK builds,
// which explicitly permits linking proprietary code without inheriting
// GPL's copyleft obligations. Without this, "GPL-2.0-only WITH
// Classpath-exception-2.0" (as reported for jre/jdk by windows_runner.js)
// would be treated as an unparsed, unrecognized expression and collapse to
// "unknown" risk, hiding the fact that it's actually a well-understood,
// lower-risk case than plain GPL.
// risk_cap: the ceiling this exception imposes on the base license's risk
// — only applied when it's actually lower than the base's own risk.
const EXCEPTIONS = Object.freeze({
  "Classpath-exception-2.0": { risk_cap: "medium" },
});

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
  let t = token.trim();
  // Strip a single layer of fully-wrapping parens, e.g. "(MIT)" -> "MIT".
  // Deliberately only when the parens wrap the ENTIRE token — the previous
  // version stripped any leading "(" run or trailing ")" run independently,
  // which mangled legitimate trailing parentheticals like "Mozilla Public
  // 2.0 (MPL 2.0)" into "Mozilla Public 2.0 (MPL 2.0" (unbalanced), causing
  // it to fail every alias/exact-match lookup downstream.
  const wrapped = t.match(/^\((.*)\)$/);
  if (wrapped) t = wrapped[1].trim();
  return t
    .replace(/\s+/g, " ")
    .replace(/\.$/, "")
    .trim();
}

// Generic GNU-family shorthand: "GPLv2+", "LGPLv3", "GPL-2.0+", "GPL v2 or
// later", "AGPL3", "LGPL2.1". A trailing "+" / "or later" -> "-or-later",
// anything else -> "-only" (the conservative, obligation-triggering reading).
const GNU_SHORTHAND =
  /^(A|L)?GPL[-\s]?v?(\d(?:\.\d)?)\s*(\+|-or-later|-only|or later|or newer|only)?$/i;

const isKnownId = id => !!id && (
  Object.prototype.hasOwnProperty.call(LICENSE_TABLE, id) || /^LicenseRef-/i.test(id)
);

/**
 * Resolves a single free-text or SPDX-ish token to a canonical SPDX id.
 * Returns null if the token can't be confidently identified.
 */
function normalizeToken(rawToken) {
  const token = cleanToken(stripPythonClassifier(rawToken));
  if (!token) return null;

  // Whole-token alias lookup FIRST — before the WITH split — so aliases that
  // legitimately contain "with" ("BSD with advertising" = BSD-4-Clause) are
  // not misread as "<license> WITH <exception>".
  const key = token.toLowerCase();
  if (ALIASES[key]) return ALIASES[key];

  // Strip a trailing " license" / " licence" and retry.
  const withoutSuffix = key.replace(/\s+licen[cs]e$/, "");
  if (withoutSuffix !== key && ALIASES[withoutSuffix]) return ALIASES[withoutSuffix];

  // SPDX "<license> WITH <exception>", e.g. "GPL-2.0-only WITH
  // Classpath-exception-2.0". Recurse to canonicalize the base license id,
  // then reassemble — classifyId() applies the exception's effect on risk.
  const withMatch = token.match(/^(.+?)\s+WITH\s+(.+)$/i);
  if (withMatch) {
    const base = normalizeToken(withMatch[1]);
    const exception = cleanToken(withMatch[2]);
    if (base && /^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(exception)) {
      // RPM-style unspecified "GPLv2+ with exceptions": not a real SPDX
      // exception id, so keep the (valid) base id and rate it conservatively.
      if (/^exceptions?$/i.test(exception)) return base;
      return `${base} WITH ${exception}`;
    }
    return null;
  }

  // Already-canonical SPDX id (case-insensitive exact match).
  const exact = Object.keys(LICENSE_TABLE).find(id => id.toLowerCase() === key);
  if (exact) return exact;

  // GNU-family shorthand ("GPLv2+", "LGPL-2.1", "GPL v3 or later", …).
  const gnu = token.match(GNU_SHORTHAND);
  if (gnu) {
    const fam = (gnu[1] || "").toUpperCase() + "GPL";
    const ver = gnu[2].includes(".") ? gnu[2] : `${gnu[2]}.0`;
    const orLater = /^(\+|-or-later|or later|or newer)$/i.test(gnu[3] || "");
    const candidate = `${fam}-${ver}-${orLater ? "or-later" : "only"}`;
    if (LICENSE_TABLE[candidate]) return candidate;
  }

  // Trailing parenthetical that carries the real identifier, e.g. PyPI's
  // "GNU General Public License v2 or later (GPLv2+)". Try the parenthetical
  // first, then the text in front of it.
  const tail = token.match(/^(.*\S)\s*\(([^()]+)\)$/);
  if (tail) {
    for (const part of [tail[2], tail[1]]) {
      const id = normalizeToken(part);
      if (isKnownId(id)) return id;
    }
  }

  // Looks like a plausible SPDX identifier shape but isn't one we know.
  if (/^[A-Za-z0-9][A-Za-z0-9.+-]*$/.test(token) && token.length <= 40) {
    return token; // returned as-is; classifyId() marks it unrecognized
  }

  return null; // free-form text we can't safely parse (e.g. pasted license body)
}

// ── Expression parsing ───────────────────────────────────────────────────
//
// Real-world license fields are NOT always a single id or one flat operator.
// RPM metadata in particular routinely mixes operators and nests groups:
//   "(GPLv2+ or AFL) and GPLv2+"
//   "MIT and Python and ASL 2.0 and BSD and (ASL 2.0 or BSD)"
// so this is a small recursive-descent parser with SPDX precedence
// (AND binds tighter than OR, parentheses group).
//
// Two details that matter for free-text names:
//   - "or later" / "or newer" are part of a license NAME ("GNU General
//     Public License v2 or later"), not an OR operator.
//   - A "(" only opens a group at the START of an operand. Mid-operand it is
//     part of the name: "Mozilla Public 2.0 (MPL 2.0)", "ISC (ISCL)".
const KEYWORD_RE = /\s+(AND|OR)\s+(?!(?:any\s+)?(?:later|newer)\b)/iy;

function tokenizeExpression(s) {
  const out = [];
  let buf = "";
  let depth = 0;
  const flush = () => {
    const v = buf.replace(/\s+/g, " ").trim();
    if (v) out.push({ type: "OPERAND", value: v });
    buf = "";
  };

  let i = 0;
  while (i < s.length) {
    const ch = s[i];

    if (ch === "(") {
      if (buf.trim() === "") {
        flush();
        out.push({ type: "LPAREN" });
        depth++;
        i++;
        continue;
      }
      // Mid-operand "(": consume through its matching ")" as part of the name.
      let d = 0, j = i;
      for (; j < s.length; j++) {
        if (s[j] === "(") d++;
        else if (s[j] === ")" && --d === 0) break;
      }
      if (j >= s.length) { buf += s.slice(i); break; } // unbalanced — keep as text
      buf += s.slice(i, j + 1);
      i = j + 1;
      continue;
    }

    if (ch === ")") {
      if (depth > 0) {
        flush();
        out.push({ type: "RPAREN" });
        depth--;
      } else {
        buf += ch;
      }
      i++;
      continue;
    }

    KEYWORD_RE.lastIndex = i;
    const m = KEYWORD_RE.exec(s);
    if (m) {
      flush();
      out.push({ type: m[1].toUpperCase() });
      i += m[0].length;
      continue;
    }

    buf += ch;
    i++;
  }
  flush();
  return out;
}

/**
 * Parses a license expression into a tree:
 *   { leaf: "<raw operand text>" } | { op: "AND"|"OR", children: [...] }
 * Returns null if the expression is malformed (unbalanced parens, dangling
 * operator, …).
 */
function parseExpression(raw) {
  const toks = tokenizeExpression(raw);
  let pos = 0;
  const peek = () => (toks[pos] ? toks[pos].type : null);

  function parseOr() {
    const kids = [parseAnd()];
    while (peek() === "OR") { pos++; kids.push(parseAnd()); }
    return kids.length === 1 ? kids[0] : { op: "OR", children: kids };
  }
  function parseAnd() {
    const kids = [parsePrimary()];
    while (peek() === "AND") { pos++; kids.push(parsePrimary()); }
    return kids.length === 1 ? kids[0] : { op: "AND", children: kids };
  }
  function parsePrimary() {
    const t = toks[pos];
    if (!t) throw new Error("unexpected end of expression");
    if (t.type === "LPAREN") {
      pos++;
      const node = parseOr();
      if (peek() !== "RPAREN") throw new Error("missing )");
      pos++;
      return node;
    }
    if (t.type === "OPERAND") { pos++; return { leaf: t.value }; }
    throw new Error(`unexpected ${t.type}`);
  }

  try {
    const tree = parseOr();
    return pos === toks.length ? tree : null;
  } catch (_) {
    return null;
  }
}

// Canonicalizes every leaf in place. Returns false if any leaf can't be parsed.
function resolveTree(node) {
  if (node.leaf !== undefined) {
    node.id = normalizeToken(node.leaf);
    return node.id !== null;
  }
  return node.children.map(resolveTree).every(Boolean);
}

function collectLeafIds(node) {
  if (node.leaf !== undefined) return [node.id];
  return node.children.flatMap(collectLeafIds);
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
  // SPDX "<license> WITH <exception>" — normalizeToken() has already
  // canonicalized the base license id and validated the exception's shape;
  // here we look up the base and, if the exception has a known risk-capping
  // effect (see EXCEPTIONS above), apply it — but only when it actually
  // lowers the risk below what the base license would carry on its own.
  const withMatch = id.match(/^(.+?)\s+WITH\s+(.+)$/i);
  if (withMatch) {
    const base = LICENSE_TABLE[withMatch[1]];
    if (base) {
      const exception = EXCEPTIONS[withMatch[2]];
      if (exception && RISK_RANK[exception.risk_cap] < RISK_RANK[base.risk]) {
        return {
          id,
          osi:      base.osi,
          category: `${base.category}-with-exception`,
          risk:     exception.risk_cap,
        };
      }
      return { id, ...base };
    }
    // Unrecognized base license — fall through to the unrecognized case
    // below rather than guessing.
  }

  const entry = LICENSE_TABLE[id];
  if (entry) return { id, ...entry };

  // SPDX "LicenseRef-*" — a real, named license or vendor EULA that has no
  // registered SPDX identifier (npm, PyPI, and UBEL's own host scanners
  // — e.g. windows_runner.js's "LicenseRef-Microsoft-Windows-EULA",
  // "LicenseRef-Proprietary", "LicenseRef-Google-Chrome-TOS" — all use
  // this convention). The governing vendor and terms aren't in question
  // here, just the lack of a public SPDX id, so this is a known,
  // proprietary-leaning classification, not "unrecognized"/unknown.
  if (/^LicenseRef-/i.test(id)) {
    return { id, osi: false, category: "proprietary-eula", risk: "high" };
  }

  return { id, osi: false, category: "unrecognized", risk: "unknown" };
}

// Combines already-classified children under one operator. `_op` records the
// operator a composite result was built with, so a differing-operator child is
// parenthesized when the id string is rebuilt (e.g. "(A OR B) AND C").
function aggregate(op, classifications) {
  const idOf = c => (c._op && c._op !== op ? `(${c.id})` : c.id);
  const id = classifications.map(idOf).join(` ${op} `);

  if (op === "OR") {
    // Best case wins — the consumer may legally pick the most favorable term.
    const best = classifications.reduce((a, b) =>
      RISK_RANK[a.risk] <= RISK_RANK[b.risk] ? a : b
    );
    return {
      id,
      osi:      classifications.some(c => c.osi),
      category: best.category,
      risk:     best.risk,
      _op:      op,
    };
  }

  // AND — conjunctive, obligations stack, worst case governs.
  const worst = classifications.reduce((a, b) =>
    RISK_RANK[a.risk] >= RISK_RANK[b.risk] ? a : b
  );
  return {
    id,
    osi:      classifications.every(c => c.osi),
    category: worst.category,
    risk:     worst.risk,
    _op:      op,
  };
}

function evaluateTree(node) {
  if (node.leaf !== undefined) return classifyId(node.id);
  return aggregate(node.op, node.children.map(evaluateTree));
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

  const tree = parseExpression(trimmed);

  if (!tree || !resolveTree(tree)) {
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

  const leafIds   = [...new Set(collectLeafIds(tree))];
  const leafCls   = leafIds.map(classifyId);
  const result    = evaluateTree(tree);

  const knownIds  = leafCls.filter(c => c.category !== "unrecognized");
  const anyUnknown = leafCls.some(c => c.category === "unrecognized");

  let reason;
  if (anyUnknown) {
    reason = `Contains an unrecognized license identifier alongside ` +
             `${knownIds.map(c => c.id).join(", ") || "no known licenses"}; ` +
             `treated conservatively.`;
  } else if (tree.leaf !== undefined) {
    reason = result.osi
      ? `${result.id} is an OSI-approved ${result.category} license.`
      : `${result.id} is not on the OSI-approved license list (${result.category}).`;
  } else if (tree.op === "OR") {
    reason = `Dual/multi-licensed (${result.id}); classified using the ` +
              `most favorable option (${result.category}, ${result.risk} risk).`;
  } else {
    reason = `Multiple licenses apply conjunctively (${result.id}); ` +
              `classified using the most restrictive component ` +
              `(${result.category}, ${result.risk} risk).`;
  }

  return {
    raw: str,
    spdx: result.id,
    identifiers: leafIds,
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

/**
 * True when a raw license value is missing or one of the "no information" placeholders
 * ("unknown", "none", "n/a", …) — i.e. there is nothing worth recording as a license name.
 */
function isNoLicenseValue(rawLicense) {
  const str = coerceToString(rawLicense);
  return str === null || EMPTY_SENTINELS.has(str.trim().toLowerCase());
}

export {
  classifyLicense,
  isNoLicenseValue,
  enrichInventoryWithLicenseRisk,
  isOsiApproved,
  LICENSE_TABLE,
  ALIASES,
};