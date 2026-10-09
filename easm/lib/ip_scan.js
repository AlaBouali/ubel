// easm/lib/ip_scan.js
//
// The "hostnames in → distinct IPs → port-scanned → fingerprint targets out"
// stages that ubel-easm (../easm.js) and ubel-host (../host.js) share.
//
// ubel-easm feeds it the hostnames crt.sh discovered for a domain; ubel-host
// feeds it the IPs/domains the user typed. Everything past "where did this
// list of names come from" is deliberately the SAME code, so a host given by
// hand is resolved, de-duplicated by IP, guarded, port-scanned, expanded into
// by-name targets, and reported exactly the way a crt.sh-discovered one is —
// not a second implementation that can drift from the first.
//
//   resolveHostsToIps()  DNS-resolve every name (IP literals resolve to
//                        themselves) and collapse the result onto the set of
//                        DISTINCT IPs, remembering which names sit on each.
//                        Names that never resolve are returned as "dead"; names
//                        that resolve to an --exclude-ip address are returned as
//                        "excludedResolutions" (they resolved, they're just not
//                        being scanned).
//   scanIpPorts()        private/self-IP guard, then scanPorts() +
//                        probeHttpPorts() for ONE IP. Never throws.
//   scanIps()            scanIpPorts() across every IP, --ip-concurrency wide.
//   buildTargets()       the target list handed to scanTargets(): "ip:port"
//                        for every HTTP(S) port found, plus the names
//                        themselves (see its own comment).
//   printIpGrouping()    the --list-only / --resolve-only IP grouping view.

import { resolveTargets } from './resolve.js';
import { scanPorts, probeHttpPorts } from './portscan.js';
import { IpInfo } from '../fingerprint/src/index.js';
import { mapLimit } from '../../cloud/lib/concurrency.js';

export const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

export const SUBDOMAIN_PORT_MODES = new Set(['none', 'default', 'all']);

/** True for a bare IPv4 literal ("203.0.113.10"). */
export function isIpLiteral(host) {
  return IPV4_RE.test(String(host || ''));
}

/**
 * Same private/self-IP check ./../host.js and ../fingerprint's DomainScanner
 * apply — reused verbatim, applied to an IP that is already in hand.
 */
export async function isBlockedIp(ip) {
  return IpInfo.ipIsPrivate(ip) || IpInfo.isLocalAddress(ip);
}

/**
 * DNS-resolves a hostname list and groups it by distinct IP.
 *
 * An IP literal in the list resolves to itself and yields an IP entry with no
 * hostnames: there is no name to scan "by name" for it (a bare IP carries no
 * Host header or SNI — see buildTargets()), and listing the IP as its own
 * "hostname" would only make the report show it twice.
 *
 * @param {string[]} hostnames       already de-duplicated / --exclude-filtered
 * @param {{excludeIp?: string[]}} [opts]
 * @returns {Promise<{
 *   ips: {ip: string, hostnames: string[]}[],
 *   deadHostnames: object[],
 *   excludedResolutions: {hostname: string, ip: string}[]
 * }>}
 */
export async function resolveHostsToIps(hostnames, { excludeIp = [] } = {}) {
  const { alive, dead, byTarget } = await resolveTargets(hostnames);

  const excludedIps = new Set(excludeIp);
  const hostsByIp = new Map(); // ip -> Set<hostname>
  const excludedResolutions = []; // {hostname, ip} for hostnames that DID resolve but landed on an excluded IP

  for (const hostname of alive) {
    const resolution = byTarget.get(hostname);
    const ip = resolution ? resolution.ip : null;
    if (!ip) continue; // resolveTargets() marked it alive but gave no ip — treat like unresolved
    if (excludedIps.has(ip)) {
      excludedResolutions.push({ hostname, ip });
      continue;
    }
    if (!hostsByIp.has(ip)) hostsByIp.set(ip, new Set());
    if (!isIpLiteral(hostname)) hostsByIp.get(ip).add(hostname);
  }

  const ips = [...hostsByIp.entries()]
    .map(([ip, hostnameSet]) => ({ ip, hostnames: [...hostnameSet].sort() }))
    .sort((a, b) => a.ip.localeCompare(b.ip, undefined, { numeric: true }));

  return { ips, deadHostnames: dead, excludedResolutions };
}

/**
 * Port-scans ONE distinct IP: the private/self-IP guard, then the same
 * scanPorts()/probeHttpPorts() pair. Never throws — an error here becomes an
 * "error" status entry so one bad IP can't abort the whole run, same contract
 * ./scan.js's own fingerprintTarget() holds itself to.
 *
 * @param {{ip: string, hostnames: string[]}} ipEntry
 * @param {{allowPrivate: boolean, portFrom: number, portTo: number, portConcurrency: number,
 *          portTimeout: number, httpConcurrency: number, httpTimeout: number}} args
 * @param {(msg:string)=>void} log
 */
export async function scanIpPorts(ipEntry, args, log) {
  const { ip, hostnames } = ipEntry;
  const entry = {
    ip,
    hostnames,
    status: 'scanned', // "scanned" | "skipped" | "error"
    detail: null,
    openPorts: [],
    httpPorts: [],
  };

  if (!args.allowPrivate && (await isBlockedIp(ip))) {
    entry.status = 'skipped';
    entry.detail =
      'private/RFC1918 address or this scanning host\'s own public IP — refused by the same safety guard ' +
      'every other UBEL EASM module uses (pass --allow-private only for a lab/localhost IP you own)';
    return entry;
  }

  entry.openPorts = await scanPorts(ip, { from: args.portFrom, to: args.portTo }, {
    concurrency: args.portConcurrency,
    timeout: args.portTimeout,
    log,
  });

  entry.httpPorts = await probeHttpPorts(ip, entry.openPorts, {
    concurrency: args.httpConcurrency,
    timeout: args.httpTimeout,
    log,
  });

  return entry;
}

/**
 * scanIpPorts() across every IP, `args.ipConcurrency` at a time. An IP whose
 * scan threw becomes an "error" entry rather than failing the run.
 *
 * @returns {Promise<{ip: string, hostnames: string[], status: string, detail: string|null,
 *                    openPorts: number[], httpPorts: number[]}[]>}
 */
export async function scanIps(ips, args, log) {
  const results = await mapLimit(ips, args.ipConcurrency, (ipEntry) => scanIpPorts(ipEntry, args, log));
  return results.map((r, i) =>
    r.ok
      ? r.value
      : {
          ip: ips[i].ip,
          hostnames: ips[i].hostnames,
          status: 'error',
          detail: r.error?.message || String(r.error),
          openPorts: [],
          httpPorts: [],
        }
  );
}

/**
 * The target list for scanTargets() once every IP has been port-scanned.
 *
 *   ipTargets       "ip:port" for every HTTP(S)-speaking port found.
 *   hostnameTargets the names themselves, so name-based virtual hosts
 *                   (invisible to a bare-IP request) get fingerprinted, looked
 *                   up and misconfig-checked as their real site. Built ONLY
 *                   from ports the port scan already proved answer HTTP(S) on
 *                   the name's own IP:
 *                     - 443 open -> the bare hostname. scanTargets() tries
 *                       https first, so this is https://sub.example.com.
 *                     - only 80 open -> "http://<hostname>", explicitly: the
 *                       fingerprinter's https-first probe would otherwise
 *                       wait out a full connect timeout on a 443 we already
 *                       know isn't listening.
 *                     - neither (port range excluded them, or nothing web
 *                       there) -> no bare-hostname target.
 *                   With mode "all", every other web port also yields
 *                   "<hostname>:<port>".
 *
 * IPs whose status isn't "scanned" (private/self-IP guard, errors) yield
 * nothing — their names are not scanned by name either, so the guard can't be
 * sidestepped through a hostname.
 *
 * @param {{ip: string, hostnames: string[], status: string, httpPorts: number[]}[]} hostScans
 * @param {'none'|'default'|'all'} mode
 * @returns {{ipTargets: string[], hostnameTargets: string[]}}
 */
export function buildTargets(hostScans, mode = 'default') {
  const ipTargets = new Set();
  const hostnameTargets = new Set();

  for (const h of hostScans) {
    if (h.status !== 'scanned') continue;
    for (const p of h.httpPorts) ipTargets.add(`${h.ip}:${p}`);
    if (mode === 'none') continue;

    const has443 = h.httpPorts.includes(443);
    const has80 = h.httpPorts.includes(80);
    for (const hostname of h.hostnames) {
      if (isIpLiteral(hostname)) continue; // "ip:port" above already covers it
      if (has443) hostnameTargets.add(hostname);
      else if (has80) hostnameTargets.add(`http://${hostname}`);
      if (mode === 'all') {
        for (const p of h.httpPorts) {
          if (p !== 80 && p !== 443) hostnameTargets.add(`${hostname}:${p}`);
        }
      }
    }
  }

  return { ipTargets: [...ipTargets], hostnameTargets: [...hostnameTargets] };
}

/**
 * The passive review view shared by ubel-easm --list-only and
 * ubel-host --resolve-only: which names landed on which IP, which never
 * resolved, which were dropped by --exclude-ip. No request has been sent to
 * any of these IPs when this is printed.
 *
 * @param {string} label  what the IPs belong to, e.g. "example.com" or "the 3 given host(s)"
 * @param {{ips: object[], deadHostnames: object[], excludedResolutions: object[]}} grouping
 */
export function printIpGrouping(label, { ips, deadHostnames, excludedResolutions }) {
  console.log(`\n${ips.length} distinct IP(s) for ${label}:\n`);
  for (const { ip, hostnames } of ips) {
    console.log(`  ${ip}${hostnames.length ? `  (${hostnames.join(', ')})` : ''}`);
  }
  if (deadHostnames.length) {
    console.log(`\n${deadHostnames.length} hostname(s) did not resolve:`);
    for (const r of deadHostnames) console.log(`  ${r.target}`);
  }
  if (excludedResolutions.length) {
    console.log(`\n${excludedResolutions.length} hostname(s) resolved to an --exclude-ip address and were dropped:`);
    for (const r of excludedResolutions) console.log(`  ${r.hostname} -> ${r.ip}`);
  }
  console.log('');
}

/**
 * The per-IP `hosts` / `deadHostnames` meta entries buildReportPayload() reads
 * (see ./html_report.js) — same shape for both entry points.
 */
export function buildHostsMeta(hostScans, deadHostnames, args) {
  return {
    hosts: hostScans.map((h) => ({
      host: h.ip,
      resolvedFrom: h.hostnames,
      status: h.status,
      skipReason: h.detail,
      portRange: `${args.portFrom}-${args.portTo}`,
      openPorts: h.openPorts,
      httpPorts: h.httpPorts,
    })),
    deadHostnames: deadHostnames.map((r) => ({ hostname: r.target, error: r.error })),
  };
}
