// easm/lib/crtsh.js
//
// Passive subdomain discovery via crt.sh's Certificate Transparency log
// search (https://crt.sh/json?q=<domain>) — no active DNS brute-forcing,
// no wordlists, just reading which hostnames a public CA has ever issued a
// certificate for. This is what feeds ubel-domain's target list before it
// hands off to the exact same EASM scanning engine every other entry point
// in this module uses (../lib/scan.js's scanTargets()) — see ../domain.js.
//
// Passive-only is a deliberate scope boundary, not a missing feature: a
// subdomain with no logged certificate (internal-only, HTTP-only, or one
// whose CA doesn't log to CT — rare today but not impossible) simply won't
// surface here. --include on the ubel-domain CLI exists for exactly that
// gap — see domain.js's --help.

import https from "https";

// Overridable via UBEL_CRTSH_ENDPOINT for a self-hosted mirror or a private
// crt.sh-compatible index — same pattern as every other external data
// source this module talks to (UBEL_OSV_ENDPOINT, UBEL_NVD_ENDPOINT,
// UBEL_WPVULNERABILITY_ENDPOINT in ./wpvulnerability.js).
const CRTSH_BASE = (process.env.UBEL_CRTSH_ENDPOINT || "https://crt.sh").replace(/\/+$/, "");

/**
 * GET /json?q=<domain> against crt.sh. Never throws — resolves to [] on any
 * network failure, non-200 response, or unparseable body. crt.sh itself
 * returns a genuinely empty response body (not "[]") when a domain has no
 * matching certificates at all, which JSON.parse would choke on — that's
 * treated the same as "zero results" here rather than surfaced as an error.
 *
 * @param {string} domain
 * @returns {Promise<object[]>} raw crt.sh entries — see extractSubdomains()
 *   for the fields actually used
 */
export function queryCrtSh(domain, timeoutMs = 60_000) {
  return new Promise((resolve) => {
    let settled = false;
    const done = (result) => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const url = `${CRTSH_BASE}/json?q=${encodeURIComponent(domain)}`;
    const req = https.get(
      url,
      { headers: { "User-Agent": "ubel_tool", Accept: "application/json" }, timeout: timeoutMs },
      (res) => {
        let data = "";
        const MAX_SIZE = 25 * 1024 * 1024; // a long-lived, busy domain's cert history can be sizeable
        res.on("data", (chunk) => {
          data += chunk;
          if (data.length > MAX_SIZE) req.destroy(new Error("Response too large"));
        });
        res.on("end", () => {
          if (res.statusCode !== 200) return done([]);
          const trimmed = data.trim();
          if (!trimmed) return done([]); // crt.sh's own "no results" shape
          try {
            const parsed = JSON.parse(trimmed);
            done(Array.isArray(parsed) ? parsed : []);
          } catch {
            done([]);
          }
        });
      }
    );
    req.on("timeout", () => req.destroy(new Error("crt.sh request timed out")));
    req.on("error", () => done([]));
  });
}

// A reasonably strict but not pedantic hostname shape — just enough to
// reject the occasional garbage crt.sh returns (an email address slipped
// into a SAN, an empty label from a stray leading/trailing dot, literal
// whitespace) without rejecting anything a real certificate would name.
const VALID_HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/**
 * Extracts a deduplicated, scannable subdomain list from a crt.sh /json?q=
 * response. Each certificate entry's `name_value` is one or more
 * newline-separated SANs, frequently including both a wildcard and its
 * apex on the same certificate (e.g. "*.example.com\nexample.com") —
 * wildcards aren't scannable hosts on their own and are dropped, while
 * their non-wildcard siblings on the same line are kept normally.
 * `common_name` is intentionally not consulted as a second source: the
 * CA/Browser Forum baseline requirements guarantee the CN is already one
 * of the cert's own SANs, so everything in it is already in `name_value`.
 *
 * @param {object[]} entries   raw array from queryCrtSh()
 * @param {string} domain      the domain that was queried, used to reject
 *   anything crt.sh's search returned that isn't actually within it — the
 *   search itself matches more loosely than strict suffix containment (see
 *   e.g. an unrelated "example.com.otherdomain.com" coming back for a
 *   query of "example.com")
 * @returns {string[]} sorted, deduplicated hostnames — includes the apex
 *   domain itself whenever any matching certificate covers it
 */
export function extractSubdomains(entries, domain) {
  const root = String(domain || "").trim().toLowerCase().replace(/\.$/, "");
  const found = new Set();

  for (const entry of entries || []) {
    const raw = entry && entry.name_value;
    if (!raw) continue;
    for (const line of String(raw).split("\n")) {
      const name = line.trim().toLowerCase().replace(/\.$/, "");
      if (!name || name.startsWith("*.")) continue; // wildcard itself isn't a host to scan
      if (name !== root && !name.endsWith(`.${root}`)) continue; // not actually within the queried domain
      if (!VALID_HOSTNAME_RE.test(name)) continue;
      found.add(name);
    }
  }

  return [...found].sort();
}
