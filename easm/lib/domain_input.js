'use strict';
// easm/lib/domain_input.js
//
// What ubel-domain and ubel-easm share for turning "the domain(s) the user
// gave" into a discovered hostname list: the domain syntax check, parsing of
// positional/file input into a deduplicated list, a short label for messages
// and the report, and the crt.sh discovery loop across every domain.

import { queryCrtShDetailed, extractSubdomains } from './crtsh.js';

// Deliberately strict: these are the arguments the whole run is built from,
// and a URL or "host:port" slipped in here would be passed to crt.sh as-is
// and silently return nothing useful. Rejecting it up front with a clear
// message beats an empty, confusing result.
export const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

/** "Example.COM." -> "example.com" */
export function normalizeDomain(raw) {
  return String(raw ?? '').trim().toLowerCase().replace(/\.$/, '');
}

/**
 * Splits one argument or file line into domains. Space- and comma-separated
 * lists are accepted (same convention ubel-host's host list uses).
 */
export function splitDomains(raw) {
  return String(raw ?? '').split(/[,\s]+/).map(normalizeDomain).filter(Boolean);
}

/** The first entry that is not a bare domain name, or null if all are. */
export function firstInvalidDomain(domains) {
  return domains.find((d) => !DOMAIN_RE.test(d)) ?? null;
}

/**
 * Short, human-readable name for the domain list, used in console output and
 * as the report's `domain` field. One domain is just that domain, so a
 * single-domain run reads exactly as it always has.
 */
export function describeDomains(domains) {
  if (domains.length <= 1) return domains[0] || '';
  const others = domains.length - 1;
  return `${domains[0]} and ${others} other domain${others === 1 ? '' : 's'}`;
}

/**
 * Step 1 of the ubel-domain / ubel-easm flow: domain(s) in, deduplicated
 * hostname list out.
 *
 * Every domain is looked up on crt.sh, one after another (crt.sh rate-limits
 * aggressively, so these are deliberately not parallelised). --include hosts
 * are merged in and --exclude is applied last, so it overrides both discovery
 * and --include. A hostname reachable from two of the given domains (e.g.
 * "example.com" and "api.example.com" both listed) appears once.
 *
 * The returned `discovery` is what the report records about how discovery
 * went. With several domains it is the aggregate: `ok` is false if ANY lookup
 * failed (a failed lookup looks exactly like "no certificates" otherwise, so
 * one failure must not be hidden by the others succeeding), and `per_domain`
 * carries each lookup's own outcome.
 *
 * @param {object}   args
 * @param {string[]} args.domains
 * @param {string[]} [args.include]
 * @param {string[]} [args.exclude]
 * @param {object}   opts
 * @param {(msg: string) => void} opts.log
 * @param {string}   opts.cliLabel                e.g. "[ubel-domain]"
 * @param {Function} [opts.lookup=queryCrtShDetailed]  injectable for tests
 */
export async function discoverFromCrtSh(args, { log, cliLabel, lookup = queryCrtShDetailed }) {
  const include = args.include || [];
  const exclude = args.exclude || [];

  const discovered = new Set();
  const perDomain = [];
  let totalRecords = 0;
  let totalAttempts = 0;
  let allOk = true;

  for (const domain of args.domains) {
    log(`[*] Querying crt.sh for certificates issued under ${domain}...`);
    const result = await lookup(domain);
    const entries = result.entries;

    if (!result.ok) {
      allOk = false;
      console.error(
        `${cliLabel} WARNING: the crt.sh lookup for ${domain} failed after ${result.attempts} attempt(s). ` +
        `Subdomain discovery is incomplete${include.length ? ' — only --include hosts will be scanned for it' : ''}, ` +
        `and the report will say so.`
      );
    }
    log(`[*] crt.sh returned ${entries.length} certificate record(s) for ${domain}.`);

    const found = extractSubdomains(entries, domain);
    log(`[*] ${found.length} unique host(s) extracted from those records.`);
    for (const h of found) discovered.add(h);

    totalRecords += entries.length;
    totalAttempts += result.attempts;
    perDomain.push({
      domain,
      ok: !!result.ok,
      attempts: result.attempts,
      certificate_records: entries.length,
      hosts_discovered: found.length,
    });
  }

  const excluded = new Set(exclude);
  const everything = [...new Set([...discovered, ...include])];
  const hostnames = everything.filter((h) => !excluded.has(h)).sort();

  const discovery = {
    source: 'crt.sh',
    ok: allOk,
    attempts: totalAttempts,
    certificate_records: totalRecords,
    hosts_discovered: discovered.size,
    // Names added by hand that discovery did not already return, and names
    // actually removed by --exclude (an --exclude that matched nothing
    // removed nothing).
    hosts_included: include.filter((h) => !discovered.has(h)).length,
    hosts_excluded: everything.filter((h) => excluded.has(h)).length,
    // Only worth recording when there is more than one lookup to tell apart.
    ...(perDomain.length > 1 ? { per_domain: perDomain } : {}),
  };

  return { discovered: [...discovered].sort(), hostnames, discovery };
}
