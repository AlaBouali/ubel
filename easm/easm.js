'use strict';
// easm/easm.js — ubel-easm
//
// One flow, in order:
//   1. Take a root domain name and discover every subdomain of it via
//      Certificate Transparency logs (crt.sh) — exactly ./domain.js's own
//      step 1-2, see ./lib/crtsh.js.
//   2. Resolve every discovered (+ --include) hostname to its IP address
//      and collapse the result onto the set of DISTINCT IPs behind the
//      domain. Several subdomains commonly share one origin IP (or one
//      shared/CDN edge IP — see the warning in HELP below), and there is
//      no reason to port-scan the same IP twice just because two
//      hostnames happen to point at it.
//   3. Connect-scan every port in range on EACH of those distinct IPs and,
//      of the ports that accept a connection, keep only the ones that
//      answer HTTP(S) — ./lib/portscan.js's scanPorts() / probeHttpPorts(),
//      the exact same two functions ./host.js itself uses, just run once
//      per discovered IP instead of once for a single host given directly.
//   4. Fingerprint every "ip:port" target discovered across every scanned
//      IP AND the discovered subdomains themselves (see "Subdomain
//      targets" below) in ONE combined pass, look up its technologies against
//      OSV/NVD/wpvulnerability.net, and run the same secrets crawl +
//      misconfiguration checks ubel-url, ubel-domain and ubel-host all
//      already share.
//   5. Generate the report.
//
// Subdomain targets: an "ip:port" request can never see a name-based
// virtual host — the web server picks the site from the Host header (and,
// over TLS, from SNI), and a bare IP supplies neither, so it lands on
// whatever the server's default site is. The sites people actually visit
// live at https://app.example.com, not https://203.0.113.7. So, on top of
// the IP targets, every subdomain that resolved to a scanned IP is also
// handed to scanTargets() BY NAME — exactly what ./domain.js does — but only
// for ports this module's own port scan already found speaking HTTP(S) on
// that hostname's IP (see buildTargets()), never blind. Controlled by
// --subdomain-ports (none | default | all).
//
// Steps 4-5 are not reimplemented here, same as ./domain.js and ./host.js:
// they delegate to the exact same scanTargets() pipeline (./lib/scan.js),
// which is what makes step 4 "collective" — every IP's HTTP(S)-speaking
// ports are merged into ONE target list before a single scanTargets() call,
// so a component seen on five different IPs behind this domain is still
// one inventory item and one set of OSV/NVD/wpvulnerability.net lookups,
// not five — same dedup-by-name+version guarantee ubel-domain gets across
// subdomains, just extended across this module's own discovered IPs.
//
// What this module adds ahead of that shared pipeline is genuinely new,
// not a recombination of ./domain.js's or ./host.js's own steps: neither
// of them resolves a discovered hostname to an IP and port-scans it.
// ubel-domain only ever sends default-port HTTP(S) fingerprint requests to
// the hostnames it discovers; ubel-host only ever port-scans the single
// host it's given directly, never something it resolved itself from a
// wider discovery step. This is the first EASM entry point to do both:
// discover *and* port-scan, across potentially many IPs in one run.

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { scanTargets } from './lib/scan.js';
import { buildReportPayload, USAGE_NOTICE } from './lib/html_report.js';
import { queryCrtSh, extractSubdomains } from './lib/crtsh.js';
import { resolveTargets } from './lib/resolve.js';
import { scanPorts, probeHttpPorts } from './lib/portscan.js';
import { IpInfo } from './fingerprint/src/index.js';
import { mapLimit } from '../cloud/lib/concurrency.js';
import {
  VALID_SEVERITIES,
  parseFailOn,
  filterByMinSeverity,
  failOnExitCode,
  writeEasmReports,
  printScanSummary,
  collectScanMetadata,
} from './lib/report_output.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;

const BANNER = `╔══════════════════════════════════════════════════════════════════════════╗
║  AUTHORIZED USE ONLY.                                                    ║
║  This discovers subdomains of the domain you give it, resolves EVERY     ║
║  one of them to an IP address, then connects to every port in range on   ║
║  EVERY distinct IP found and sends a live HTTP(S) request to each one    ║
║  that accepts a connection — the combined risk of ubel-domain's          ║
║  unbounded discovery AND ubel-host's full port sweep, run automatically  ║
║  across as many IPs as the domain's subdomains happen to resolve to.     ║
║  It then ALSO sends live requests to each discovered subdomain BY NAME,  ║
║  on every web port found on the IP that subdomain resolves to (see       ║
║  --subdomain-ports).                                                     ║
║  A domain's DNS records can point at infrastructure you do not           ║
║  exclusively control (shared hosting, a CDN/edge IP) — see the "Shared   ║
║  IPs" note in --help before running this unattended. Only run it         ║
║  against a domain you own or have explicit, documented authorization to  ║
║  test. See ./README.md.                                                  ║
╚══════════════════════════════════════════════════════════════════════════╝`;

const HELP = `
ubel-easm — EASM: crt.sh discovery + per-IP port scan + fingerprinting + vuln lookup

${BANNER}

Usage:
  ubel-easm <domain> [options]

  <domain> is a bare registrable domain ("example.com"). Subdomains of it
  are discovered from Certificate Transparency logs via crt.sh (same
  discovery ubel-domain uses), each discovered hostname is resolved to its
  IP address, and every DISTINCT IP found is then port-scanned the way
  ubel-host port-scans a single host — one connect-scan across the whole
  range, then an HTTP(S) liveness probe of whatever accepted a connection.
  Every IP's HTTP(S)-speaking ports are merged into one target list and
  fingerprinted, looked up, and reported together in a single run — not one
  report per IP.

  The subdomains are scanned too, by NAME, not just the IPs behind them: a
  request to a bare IP carries no Host header or TLS SNI, so it only ever
  reaches the server's default site and misses every name-based virtual
  host. Each subdomain that resolved to a scanned IP is fingerprinted at
  its own URL (https://sub.example.com, falling back to http://) whenever
  that IP answered HTTP(S) on port 443 or 80 — the same per-host scan
  ubel-domain does, but only where the port scan found something listening.
  See --subdomain-ports.

  This is the most invasive EASM entry point UBEL ships: think of it as
  "run ubel-domain's discovery, then run ubel-host's full port sweep against
  every IP that discovery turns up, and report on all of it together."
  Discovery is passive (CT logs only) — no DNS brute-forcing, no wordlists —
  but the port scan that follows it is not: it is a live 1-30000 connect
  scan against every IP found, same as ubel-host.

Shared IPs — read before running unattended:
  Several subdomains of a domain frequently resolve to the SAME IP —
  sometimes because they're genuinely served by the domain owner's own
  single origin server, and sometimes because they sit behind a CDN, a
  load balancer, or shared hosting whose IP is NOT exclusively the domain
  owner's infrastructure. This module only de-duplicates identical IPs so
  it doesn't port-scan the same address twice; it has no way to tell "my
  dedicated server" apart from "a shared edge IP thousands of other sites
  also resolve to." Owning a domain does not by itself authorize a full
  port sweep of every IP that domain's DNS happens to point at. Review the
  IP list with --list-only first, and use --exclude / --exclude-ip to drop
  any host or IP you don't have standalone authorization to port-scan.

Options:
  --include <host>          Additionally resolve+scan this hostname, even
                             if crt.sh didn't return it. Repeatable.
  --exclude <host>          Never resolve this hostname, even if
                             discovered. Repeatable. Matches the exact
                             hostname, applied before resolution.
  --exclude-ip <ip>         Never port-scan this IP, even if a resolved
                             hostname points at it. Repeatable. Use this for
                             a shared/CDN IP you've identified via
                             --list-only that you don't want swept — see
                             "Shared IPs" above.
  --list-only                Discover subdomains, resolve them, group them
                              by distinct IP, and print that grouping, then
                              exit — before a single port is probed and
                              before any report is written. No requests are
                              sent to any of the discovered IPs. Review this
                              output (and re-run with --exclude/--exclude-ip
                              as needed) before ever dropping this flag.
  --allow-private            Disable the private/self-IP safety guard.
                              Only ever use this for lab/localhost IPs you
                              own.
  --ports <from-to>          Port range to scan on each IP, inclusive
                              (default: 1-30000) — same meaning as
                              ubel-host's own --ports, applied once per IP.
  --port-concurrency <n>     TCP connect attempts in parallel, per IP
                              (default: 500).
  --port-timeout <ms>        Per-port connect timeout in milliseconds
                              (default: 1500).
  --http-concurrency <n>     Open ports probed for HTTP(S) in parallel, per
                              IP (default: 20).
  --http-timeout <ms>        Per-port HTTP(S) liveness-probe timeout in
                              milliseconds (default: 5000).
  --subdomain-ports <mode>   Which URLs to fingerprint for each discovered
                              subdomain, in addition to the IP:port targets:
                                none     - IP:port targets only (the old
                                           behavior; subdomains are used to
                                           find IPs and then not scanned).
                                default  - the subdomain's own URL on the
                                           default web port (443, else 80),
                                           if its IP answered there.
                                           (default)
                                all      - as "default", plus
                                           subdomain:port for EVERY other
                                           HTTP(S) port found on its IP.
                                           Multiplies the target count by
                                           (subdomains per IP) x (web ports
                                           per IP) — on a shared IP with
                                           many subdomains and several web
                                           ports that gets large fast.
                              Each subdomain scan resolves DNS itself, so on a
                              name with several A records it may reach a
                              different IP than the one that was port-scanned.
  --ip-concurrency <n>       Distinct IPs port-scanned in parallel (default:
                              2). Kept low by default: each IP's own port
                              scan already opens up to --port-concurrency
                              TCP connections at once, so scanning several
                              IPs at the same time multiplies that load —
                              raise this only if you know the network (and
                              every target IP) can take it.
  --concurrency <n>          HTTP(S)-speaking targets fingerprinted in
                              parallel, across ALL IPs combined (default:
                              4) — same meaning as ubel-url/ubel-domain/
                              ubel-host's own --concurrency; the CVE-lookup
                              stage, unlike --ip-concurrency/--port-
                              concurrency/--http-concurrency above which are
                              all discovery-stage knobs.
  --working-dir <path>       Directory reports are written under (default: cwd).
  --min-severity <sev>       Only report vulnerabilities at or above this
                              severity in the Vulnerabilities tab (default:
                              unknown, i.e. everything). Component inventory
                              and per-component vulnerability counts always
                              reflect the full, unfiltered scan regardless
                              of this flag. One of: critical|high|medium|low|unknown
  --fail-on <sev|none|N:sev>
                              Non-zero exit if a vulnerability at or above
                              <sev> exists (default: critical). Infections
                              always count regardless of threshold. "none"
                              always exits 0. "N:sev" fails only once MORE
                              than N matches exist, e.g. "5:high".
  --no-secrets                Skip the client-side JavaScript secrets crawl
                              (see ubel-url --help for what this covers).
  --verbose                   Print per-hostname/per-IP/per-port progress.
  --quiet                     Suppress the console summary (reports still write).
  --help, -h                  Show this help.

Every run writes a timestamped easm-full__<ts>.zip bundle (report.json +
report.html inside) under .ubel/local/reports/easm-full/<y>/<m>/<d>/, plus
fixed, unzipped "latest" copies at .ubel/reports/latest.easm-full.json and
.html — kept separate from ubel-url's, ubel-domain's, and ubel-host's own
reports so none of the four ever overwrites another's latest pointer.

Discovered hosts are DNS-resolved before any port is touched. Certificate
Transparency is append-only history, so a crt.sh result routinely includes
hostnames that were decommissioned years ago; those simply never resolve to
an IP and are listed as "dead" — same handling ubel-domain gives them —
and contribute no IP to port-scan.

Safety guard: by default, a resolved IP that is private/RFC1918 or is this
scanning host's own public IP is refused outright, before a single port is
probed on it — same guard ubel-host applies to the one host it's given
directly, applied here to every IP this module resolves for itself.
--allow-private disables it — only for an IP you actually own, e.g. a local
dev/staging box. This guard does NOT and cannot detect the separate "shared/
CDN IP" risk described above — that one has no automatic detection and is
on you to review via --list-only.

Data sources (overridable for self-hosted/air-gapped mirrors):
  UBEL_CRTSH_ENDPOINT           default https://crt.sh
  UBEL_OSV_ENDPOINT             default https://api.osv.dev
  UBEL_NVD_ENDPOINT             default https://services.nvd.nist.gov/rest/json/cves/2.0
  UBEL_WPVULNERABILITY_ENDPOINT default https://www.wpvulnerability.net
NVD's unauthenticated rate limit (~5 req/30s) is respected internally. A
domain with many subdomains resolving to many distinct IPs, each with a wide
port range, can take a long while — narrow --ports or raise --ip-concurrency
only once you've reviewed the --list-only output and know what you're
authorizing.
`;

// Same posture as ./domain.js's own DOMAIN_RE: this is the one argument the
// whole run is built from, and a URL or "host:port" slipped in here would
// be passed to crt.sh as-is and silently return nothing useful.
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

// Same posture as ./host.js's own IPV4_RE, reused here for validating
// --exclude-ip values up front rather than silently never matching anything.
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

const SUBDOMAIN_PORT_MODES = new Set(['none', 'default', 'all']);

function parseArgs(argv) {
  const args = {
    domain: null,
    include: [],
    exclude: [],
    excludeIp: [],
    listOnly: false,
    allowPrivate: false,
    portFrom: 1,
    portTo: 30000,
    portConcurrency: 500,
    portTimeout: 1500,
    httpConcurrency: 20,
    httpTimeout: 5000,
    ipConcurrency: 2,
    subdomainPorts: 'default',
    concurrency: 4,
    minSeverity: 'unknown',
    failOn: 'critical',
    scanSecrets: true,
    verbose: false,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      console.log(HELP);
      process.exit(0);
    } else if (a === '--include') {
      const host = argv[++i];
      if (!host) { console.error('--include requires a hostname\n'); process.exit(2); }
      args.include.push(host.trim().toLowerCase());
    } else if (a === '--exclude') {
      const host = argv[++i];
      if (!host) { console.error('--exclude requires a hostname\n'); process.exit(2); }
      args.exclude.push(host.trim().toLowerCase());
    } else if (a === '--exclude-ip') {
      const ip = argv[++i];
      if (!ip) { console.error('--exclude-ip requires an IPv4 address\n'); process.exit(2); }
      args.excludeIp.push(ip.trim());
    } else if (a === '--list-only') args.listOnly = true;
    else if (a === '--allow-private') args.allowPrivate = true;
    else if (a === '--ports') {
      const raw = argv[++i];
      const m = raw && raw.match(/^(\d+)-(\d+)$/);
      if (!m) { console.error(`--ports requires "<from>-<to>", got ${JSON.stringify(raw)}\n`); process.exit(2); }
      args.portFrom = parseInt(m[1], 10);
      args.portTo = parseInt(m[2], 10);
    } else if (a === '--port-concurrency') args.portConcurrency = parseInt(argv[++i], 10);
    else if (a === '--port-timeout') args.portTimeout = parseInt(argv[++i], 10);
    else if (a === '--http-concurrency') args.httpConcurrency = parseInt(argv[++i], 10);
    else if (a === '--http-timeout') args.httpTimeout = parseInt(argv[++i], 10);
    else if (a === '--ip-concurrency') args.ipConcurrency = parseInt(argv[++i], 10);
    else if (a === '--subdomain-ports') args.subdomainPorts = argv[++i];
    else if (a === '--concurrency') args.concurrency = parseInt(argv[++i], 10);
    else if (a === '--working-dir') args.workingDir = argv[++i];
    else if (a === '--min-severity') args.minSeverity = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--no-secrets') args.scanSecrets = false;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a.startsWith('--')) {
      console.error(`Unknown argument: ${a}\n`);
      console.log(HELP);
      process.exit(2);
    } else if (args.domain) {
      console.error(
        `ubel-easm takes exactly one domain (got "${args.domain}" and "${a}").\n` +
        `To scan several unrelated domains, run it once per domain.\n`
      );
      process.exit(2);
    } else {
      args.domain = a.trim().toLowerCase().replace(/\.$/, '');
    }
  }

  if (!args.domain) {
    console.error('No domain given — pass exactly one domain, e.g. "ubel-easm example.com".\n');
    console.log(HELP);
    process.exit(2);
  }

  if (!DOMAIN_RE.test(args.domain)) {
    console.error(
      `"${args.domain}" doesn't look like a bare domain name.\n` +
      `Pass just the registrable domain — "example.com", not a URL, a "host:port"\n` +
      `pair, or a wildcard.\n`
    );
    process.exit(2);
  }

  for (const ip of args.excludeIp) {
    if (!IPV4_RE.test(ip)) {
      console.error(`--exclude-ip expects an IPv4 address, got "${ip}"`);
      process.exit(2);
    }
  }

  if (
    !Number.isInteger(args.portFrom) || !Number.isInteger(args.portTo) ||
    args.portFrom < 1 || args.portTo > 65535 || args.portFrom > args.portTo
  ) {
    console.error(`--ports must be "<from>-<to>" with 1 <= from <= to <= 65535 (got ${args.portFrom}-${args.portTo})`);
    process.exit(2);
  }

  for (const [flag, value] of [
    ['--port-concurrency', args.portConcurrency],
    ['--port-timeout', args.portTimeout],
    ['--http-concurrency', args.httpConcurrency],
    ['--http-timeout', args.httpTimeout],
    ['--ip-concurrency', args.ipConcurrency],
  ]) {
    if (!Number.isInteger(value) || value < 1) {
      console.error(`${flag} must be a positive integer`);
      process.exit(2);
    }
  }

  if (!SUBDOMAIN_PORT_MODES.has(args.subdomainPorts)) {
    console.error(`--subdomain-ports must be one of: ${[...SUBDOMAIN_PORT_MODES].join(', ')} (got "${args.subdomainPorts}")`);
    process.exit(2);
  }

  if (!VALID_SEVERITIES.has(args.minSeverity)) {
    console.error(`--min-severity must be one of: ${[...VALID_SEVERITIES].join(', ')} (got "${args.minSeverity}")`);
    process.exit(2);
  }

  if (!Number.isInteger(args.concurrency) || args.concurrency < 1) {
    console.error('--concurrency must be a positive integer');
    process.exit(2);
  }

  args.failOn = parseFailOn(args.failOn);
  if (!args.failOn) {
    console.error(
      `--fail-on must be "none", one of: ${[...VALID_SEVERITIES].join(', ')}, or "<count>:<severity>" e.g. "5:high"`
    );
    process.exit(2);
  }

  return args;
}

/**
 * Step 1-2 of the flow: domain in, { ip -> hostnames } grouping out.
 * --include hosts are merged in (and resolved) alongside crt.sh's own
 * discoveries; --exclude drops a hostname before it's ever resolved;
 * --exclude-ip drops an already-resolved IP before it's added to the
 * scan group (a hostname excluded this way still shows up in
 * `deadHostnames`-adjacent bookkeeping as "resolved but excluded", not as
 * "dead" — it did resolve, it just isn't being scanned).
 */
async function discoverIps(args, log) {
  log(`[*] Querying crt.sh for certificates issued under ${args.domain}...`);
  const entries = await queryCrtSh(args.domain);
  log(`[*] crt.sh returned ${entries.length} certificate record(s).`);

  const discovered = extractSubdomains(entries, args.domain);
  log(`[*] ${discovered.length} unique host(s) extracted from those records.`);

  const excludedHosts = new Set(args.exclude);
  const hostnames = [...new Set([...discovered, ...args.include])]
    .filter((h) => !excludedHosts.has(h))
    .sort();

  log(`[*] Resolving ${hostnames.length} hostname(s) to IP addresses...`);
  const { alive, dead, byTarget } = await resolveTargets(hostnames);

  if (dead.length) {
    log(`[*] ${dead.length} hostname(s) did not resolve and contribute no IP.`);
  }

  const excludedIps = new Set(args.excludeIp);
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
    hostsByIp.get(ip).add(hostname);
  }

  const ips = [...hostsByIp.entries()]
    .map(([ip, hostnameSet]) => ({ ip, hostnames: [...hostnameSet].sort() }))
    .sort((a, b) => a.ip.localeCompare(b.ip));

  return { discovered, hostnames, deadHostnames: dead, excludedResolutions, ips };
}

/**
 * Same private/self-IP check ./host.js's own isBlockedHost() applies —
 * reused verbatim here except that the IP is already in hand (resolved in
 * discoverIps() above), so there's no need for DomainInfo.getIpFromDomain.
 */
async function isBlockedIp(ip) {
  const myIp = await IpInfo.myIp();
  return IpInfo.ipIsPrivate(ip) || (myIp != null && ip === myIp);
}

/**
 * Step 3 of the flow, for ONE distinct IP: the private/self-IP guard, then
 * the same scanPorts()/probeHttpPorts() pair ./host.js itself calls.
 * Never throws — an error here becomes a "error" status entry so one bad
 * IP can't abort the whole run, same contract ./lib/scan.js's own
 * fingerprintTarget() holds itself to.
 *
 * @param {{ip: string, hostnames: string[]}} ipEntry
 * @param {object} args
 * @param {(msg:string)=>void} log
 */
async function scanIpPorts(ipEntry, args, log) {
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
 * Step 4's target list: what to hand scanTargets() once every IP has been
 * port-scanned.
 *
 *   ipTargets       "ip:port" for every HTTP(S)-speaking port found — what
 *                   this module has always scanned.
 *   hostnameTargets the discovered subdomains themselves, so name-based
 *                   virtual hosts (invisible to a bare-IP request) get
 *                   fingerprinted, looked up and misconfig-checked as their
 *                   real site. Built ONLY from ports the port scan already
 *                   proved answer HTTP(S) on the subdomain's own IP:
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
 * nothing — their subdomains are not scanned by name either, so the guard
 * can't be sidestepped through a hostname.
 *
 * @param {{ip: string, hostnames: string[], status: string, httpPorts: number[]}[]} hostScans
 * @param {'none'|'default'|'all'} mode
 * @returns {{ipTargets: string[], hostnameTargets: string[]}}
 */
function buildTargets(hostScans, mode = 'default') {
  const ipTargets = new Set();
  const hostnameTargets = new Set();

  for (const h of hostScans) {
    if (h.status !== 'scanned') continue;
    for (const p of h.httpPorts) ipTargets.add(`${h.ip}:${p}`);
    if (mode === 'none') continue;

    const has443 = h.httpPorts.includes(443);
    const has80 = h.httpPorts.includes(80);
    for (const hostname of h.hostnames) {
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

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.quiet) {
    console.log('\n' + BANNER + '\n');
  }

  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  const discovery = await discoverIps(args, log);

  if (!discovery.ips.length) {
    console.error(
      `\nNo scannable IP found for "${args.domain}".\n` +
      `Every discovered/included hostname either failed to resolve or landed on an\n` +
      `excluded IP. Pass --verbose to see the raw counts, or --include <host> to add\n` +
      `specific hostnames by hand.\n`
    );
    process.exitCode = 1;
    return;
  }

  // Stops here, before a single port is probed on any IP — the discovery
  // above (crt.sh + DNS resolution) is passive; everything after this
  // checkpoint is a live, invasive port sweep. Same checkpoint philosophy
  // as ./domain.js's own --list-only, placed one stage earlier here since
  // the "actual scan" this module gates is a full port sweep, not just a
  // single fingerprint request.
  if (args.listOnly) {
    console.log(`\n${discovery.ips.length} distinct IP(s) for ${args.domain}:\n`);
    for (const { ip, hostnames } of discovery.ips) {
      console.log(`  ${ip}  (${hostnames.join(', ')})`);
    }
    if (discovery.deadHostnames.length) {
      console.log(`\n${discovery.deadHostnames.length} hostname(s) did not resolve:`);
      for (const r of discovery.deadHostnames) console.log(`  ${r.target}`);
    }
    if (discovery.excludedResolutions.length) {
      console.log(`\n${discovery.excludedResolutions.length} hostname(s) resolved to an --exclude-ip address and were dropped:`);
      for (const r of discovery.excludedResolutions) console.log(`  ${r.hostname} -> ${r.ip}`);
    }
    console.log('');
    process.exitCode = 0;
    return;
  }

  if (!args.quiet) {
    console.log(
      `[ubel-easm] ${args.domain}: ${discovery.hostnames.length} hostname(s) resolved to ` +
      `${discovery.ips.length} distinct IP(s) to port-scan` +
      `${discovery.deadHostnames.length ? `, ${discovery.deadHostnames.length} did not resolve` : ''}` +
      `${discovery.excludedResolutions.length ? `, ${discovery.excludedResolutions.length} dropped via --exclude-ip` : ''}.\n`
    );
  }

  const ipResults = await mapLimit(discovery.ips, args.ipConcurrency, (ipEntry) =>
    scanIpPorts(ipEntry, args, log)
  );
  const hostScans = ipResults.map((r, i) =>
    r.ok
      ? r.value
      : {
          ip: discovery.ips[i].ip,
          hostnames: discovery.ips[i].hostnames,
          status: 'error',
          detail: r.error?.message || String(r.error),
          openPorts: [],
          httpPorts: [],
        }
  );

  // The collective merge: every IP's HTTP(S)-speaking ports become one
  // flat target list, deduplicated, so the fingerprinting/OSV/NVD/
  // wpvulnerability.net stage below runs exactly once across the whole
  // domain's discovered attack surface — not once per IP.
  const { ipTargets, hostnameTargets } = buildTargets(hostScans, args.subdomainPorts);
  // Subdomain (name-based) targets first: they're the sites people actually
  // reach, so they lead the report's target list.
  const targets = [...hostnameTargets, ...ipTargets];

  if (!args.quiet) {
    const scannedCount = hostScans.filter((h) => h.status === 'scanned').length;
    const skippedCount = hostScans.filter((h) => h.status === 'skipped').length;
    console.log(
      `[ubel-easm] ${scannedCount} IP(s) port-scanned, ${skippedCount} skipped by the private/self-IP guard ` +
      `→ ${targets.length} HTTP(S) target(s) to fingerprint ` +
      `(${ipTargets.length} by IP:port, ${hostnameTargets.length} by subdomain name).\n`
    );
  }

  if (!targets.length && !args.quiet) {
    console.log(
      `[ubel-easm] No HTTP(S)-speaking port was found on any of the ${discovery.ips.length} scanned IP(s) — ` +
      `nothing to fingerprint or look up, but the report will still record the full port-scan results.\n`
    );
  }

  const scanResult = await scanTargets(targets, {
    allowPrivate: args.allowPrivate,
    concurrency: args.concurrency,
    scanSecrets: args.scanSecrets,
    log,
  });

  scanResult.vulnerabilities = filterByMinSeverity(scanResult.vulnerabilities, args.minSeverity);

  const meta = {
    tool: 'ubel-easm',
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(await collectScanMetadata(args)),
    // The merged HTTP(S) target list actually fingerprinted, same meaning
    // as ubel-domain's/ubel-host's own `targets` — the discovered-and-
    // scanned set, not the raw input.
    targets,
    domain: args.domain,
    subdomainEndpoint: process.env.UBEL_CRTSH_ENDPOINT || null,
    // Per-IP port-scan detail — the plural counterpart to ubel-host's own
    // singular host/portRange/openPorts meta fields, one entry per distinct
    // IP this run resolved and (attempted to) port-scan.
    hosts: hostScans.map((h) => ({
      host: h.ip,
      resolvedFrom: h.hostnames,
      status: h.status,
      skipReason: h.detail,
      portRange: `${args.portFrom}-${args.portTo}`,
      openPorts: h.openPorts,
      httpPorts: h.httpPorts,
    })),
    deadHostnames: discovery.deadHostnames.map((r) => ({ hostname: r.target, error: r.error })),
    allowPrivate: args.allowPrivate,
    osvEndpoint: process.env.UBEL_OSV_ENDPOINT || null,
    nvdEndpoint: process.env.UBEL_NVD_ENDPOINT || null,
    wpvulnerabilityEndpoint: process.env.UBEL_WPVULNERABILITY_ENDPOINT || null,
  };

  const reportPayload = buildReportPayload(scanResult, meta);

  if (!args.quiet) {
    printScanSummary(reportPayload, `ubel-easm External Attack Surface Scan Summary — ${args.domain}`);
  }

  // reportType is "easm-full" rather than "easm-easm": every sibling entry
  // point names its report type "easm-<word>" (easm-domain, easm-host,
  // easm-url) using a word that isn't the module's own name; this keeps
  // that same convention instead of doubling "easm" here, while still
  // starting with "easm-" so all four report families sort and namespace
  // together under .ubel/local/reports/ and .ubel/reports/latest.*.
  await writeEasmReports(reportPayload, args, { reportType: 'easm-full', cliLabel: '[ubel-easm]' });

  process.exitCode = failOnExitCode(scanResult.vulnerabilities, args.failOn);
}

export { main, parseArgs, discoverIps, buildTargets, USAGE_NOTICE };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}