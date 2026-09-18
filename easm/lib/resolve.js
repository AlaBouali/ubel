// easm/lib/resolve.js
//
// DNS pre-resolution for the target list.
//
// Certificate Transparency logs are append-only history, not current state:
// a subdomain that had a certificate issued two years ago and has since
// been decommissioned is still in the crt.sh response forever. Without this
// step those hosts get fingerprinted like any other, time out one by one,
// and land in the report as indistinguishable "error" entries — which reads
// as "something went wrong scanning this" when the truth is "this host no
// longer exists". Resolving first separates the two, and skips the probe
// entirely for anything with no address to probe.
//
// This is not a liveness check: a name that resolves may still refuse
// connections, and that's correctly left to the fingerprinting step to
// report as an error. All this establishes is whether the name exists in
// DNS at all.

import dns from "node:dns/promises";
import { mapLimit } from "../../cloud/lib/concurrency.js";

const IPV4_LITERAL_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

/**
 * Pulls the bare hostname out of any target form this module accepts — a
 * bare domain, "host:port", or a full URL — matching how the fingerprinter
 * itself parses targets, so what gets resolved is always what gets probed.
 *
 * @param {string} target
 * @returns {string} lower-cased hostname, or the trimmed input if it can't
 *   be parsed (left for the fingerprinter to reject with a real error
 *   rather than silently dropped here)
 */
export function hostnameOf(target) {
  let t = String(target || "").trim();
  if (!t) return "";
  t = t.replace(/^[a-z][a-z0-9+.-]*:\/\//i, ""); // strip scheme
  t = t.split("/")[0];                           // strip path
  t = t.split("?")[0].split("#")[0];
  if (t.startsWith("[")) {                       // bracketed IPv6 literal
    const close = t.indexOf("]");
    if (close !== -1) return t.slice(1, close).toLowerCase();
  }
  // Only strip a trailing :port — a bare IPv6 literal has many colons and
  // isn't in brackets here, so leave it alone rather than truncating it.
  const colons = (t.match(/:/g) || []).length;
  if (colons === 1) t = t.split(":")[0];
  return t.toLowerCase().replace(/\.$/, "");
}

/**
 * Resolves one hostname. Never throws.
 *
 * IP literals resolve to themselves without a DNS query — there's no name
 * to look up, and treating one as "dead" because it has no A record would
 * be wrong.
 *
 * Both A and AAAA are accepted: a host reachable only over IPv6 is alive,
 * even though the fingerprinter's own private-IP guard works in IPv4 terms.
 *
 * @param {string} target
 * @returns {Promise<{target: string, hostname: string, alive: boolean, ip: string|null, family: 4|6|null, error: string|null}>}
 */
export async function resolveTarget(target) {
  const hostname = hostnameOf(target);
  const base = { target, hostname, alive: false, ip: null, family: null, error: null };

  if (!hostname) return { ...base, error: "empty target" };
  if (IPV4_LITERAL_RE.test(hostname)) return { ...base, alive: true, ip: hostname, family: 4 };

  try {
    const { address, family } = await dns.lookup(hostname, { verbatim: false });
    return { ...base, alive: true, ip: address, family };
  } catch (err) {
    // ENOTFOUND/NXDOMAIN is the "this host no longer exists" case this
    // module is for. Anything else (EAI_AGAIN — resolver unreachable or
    // rate-limiting, ESERVFAIL, a timeout) is a resolver problem, not
    // evidence about the host, so it's reported with its code attached and
    // the host is still treated as dead-for-this-run rather than silently
    // scanned or silently dropped — see the note in scanTargets().
    return { ...base, error: err.code || err.message || "resolution failed" };
  }
}

/**
 * Resolves a whole target list with bounded concurrency.
 *
 * @param {string[]} targets
 * @param {{concurrency?: number}} [opts]
 * @returns {Promise<{alive: string[], dead: object[], byTarget: Map<string, object>}>}
 *   `alive` preserves input order and is what should actually be scanned;
 *   `dead` carries the full per-host record for reporting.
 */
export async function resolveTargets(targets, opts = {}) {
  // Deliberately higher than the fingerprinting concurrency: these are
  // cheap UDP round-trips to the local resolver, not HTTP probes against
  // third-party infrastructure, so the politeness argument for a low cap
  // doesn't apply the same way.
  const { concurrency = 20 } = opts;

  const results = await mapLimit(targets, concurrency, (t) => resolveTarget(t));

  const alive = [];
  const dead = [];
  const byTarget = new Map();

  results.forEach((r, i) => {
    const record = r.ok
      ? r.value
      : { target: targets[i], hostname: hostnameOf(targets[i]), alive: false, ip: null, family: null,
          error: r.error?.message || String(r.error) };
    byTarget.set(record.target, record);
    if (record.alive) alive.push(record.target);
    else dead.push(record);
  });

  return { alive, dead, byTarget };
}
