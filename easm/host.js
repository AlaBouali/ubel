'use strict';
// easm/host.js — ubel-host
//
// One flow, in order:
//   1. Take one or more hosts — bare hostnames and/or IPv4 addresses, given
//      as arguments or via --hosts-file.
//   2. Resolve every one of them to its IP address and collapse the result
//      onto the set of DISTINCT IPs behind them (an IP given directly
//      resolves to itself). Several names commonly share one IP, and there is
//      no reason to port-scan the same IP twice just because two names point
//      at it. Names that never resolve are reported as "dead".
//   3. Connect-scan every port in a range (default 1-30000) on EACH of those
//      distinct IPs and, of the ports that accepted a connection, keep only the
//      ones that answer HTTP(S) — see ./lib/portscan.js's scanPorts() /
//      probeHttpPorts().
//   4. Fingerprint every "ip:port" target found across every scanned IP AND
//      the given hostnames themselves (by name, on the web ports their IP
//      answered on — a bare-IP request never reaches a name-based virtual
//      host), look up the technologies against OSV/NVD/wpvulnerability.net and
//      run the fixed-set misconfiguration checks, all in ONE combined pass.
//   5. Generate the report.
//
// Steps 2-4 are exactly what ubel-easm does with the hostnames it gets from
// crt.sh, and they are the same code: ./lib/ip_scan.js holds the
// resolve/group/guard/port-scan/target-building stages both entry points call.
// The only difference is where the host list comes from — crt.sh discovery
// there, the command line here. Fingerprinting and reporting then delegate to
// the same scanTargets() pipeline (./lib/scan.js) ubel-url, ubel-domain and
// ubel-easm use.

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { scanTargets } from './lib/scan.js';
import { loadTargetsFileOrExit } from './lib/targets_file.js';
import { buildReportPayload, USAGE_NOTICE } from './lib/html_report.js';
import { resolveHostsToIps, scanIps, buildTargets, printIpGrouping, buildHostsMeta, SUBDOMAIN_PORT_MODES, IPV4_RE } from './lib/ip_scan.js';
import {
  VALID_SEVERITIES,
  parseFailOn,
  filterByMinSeverity,
  failOnExitCode,
  parseEpssThresholdArg,
  DEFAULT_EPSS_THRESHOLD,
  writeEasmReports,
  printScanSummary,
  collectScanMetadata,
} from './lib/report_output.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;

const BANNER = `╔══════════════════════════════════════════════════════════════════════════╗
║  AUTHORIZED USE ONLY.                                                    ║
║  This connects to every port in range on EVERY distinct IP the hosts you ║
║  give it resolve to, sends a live HTTP(S) request to each port that      ║
║  accepts a connection, and discloses what it fingerprints on the ones    ║
║  that answer to OSV.dev/NVD. A name can resolve to infrastructure you    ║
║  do not exclusively control (shared hosting, a CDN/edge IP) — see the    ║
║  "Shared IPs" note in --help. Only run this against hosts you own or     ║
║  have explicit, documented authorization to test. See ./README.md.       ║
╚══════════════════════════════════════════════════════════════════════════╝`;

const HELP = `
ubel-host — EASM: resolve + per-IP port scan + HTTP(S) discovery + fingerprinting + vuln lookup

${BANNER}

Usage:
  ubel-host <host> [<host> ...] [options]
  ubel-host --hosts-file <path> [options]

  Each <host> is a bare hostname or IPv4 address — not a URL, not a
  "host:port" pair. Give as many as you like, space- or comma-separated, via
  --hosts-file, or both. They are handled exactly the way ubel-easm handles
  the hostnames it discovers from crt.sh: each is resolved to its IP address
  (an IP given directly resolves to itself), and every DISTINCT IP found is
  port-scanned once — one connect-scan across the whole range, then an
  HTTP(S) liveness probe of whatever accepted a connection. Every IP's
  HTTP(S)-speaking ports are merged into one target list and fingerprinted,
  looked up, and reported together in a single run — not one report per host.

  The hostnames are scanned too, by NAME, not just the IPs behind them: a
  request to a bare IP carries no Host header or TLS SNI, so it only ever
  reaches the server's default site and misses every name-based virtual
  host. Each hostname that resolved to a scanned IP is fingerprinted at its
  own URL (https://name, falling back to http://) whenever that IP answered
  HTTP(S) on port 443 or 80. An IP given directly has no name, so it is
  scanned as ip:port only. See --subdomain-ports. To fingerprint specific
  already-known host:port targets without a port scan, use ubel-url instead.

Shared IPs — read before running unattended:
  Several of the hosts you give it may resolve to the SAME IP — sometimes
  because one origin server really serves all of them, and sometimes because
  they sit behind a CDN, a load balancer, or shared hosting whose IP is NOT
  exclusively yours. This module only de-duplicates identical IPs so it
  doesn't port-scan the same address twice; it can't tell "my dedicated
  server" from "a shared edge IP thousands of other sites also resolve to."
  Owning a domain does not by itself authorize a full port sweep of every IP
  it points at. Review the IP list with --resolve-only first, and use
  --exclude / --exclude-ip to drop anything you don't have standalone
  authorization to port-scan.

Options:
  --hosts-file <path>      Read newline-separated hosts from a file (blank
                            lines and lines starting with "#" are ignored).
                            Combines with any hosts given as arguments.
                            Alias: --targets-file.
  --exclude <host>         Never resolve or scan this host, even if it was
                            given. Repeatable. Matches the exact hostname,
                            applied before resolution.
  --exclude-ip <ip>        Never port-scan this IP, even if a given host
                            resolves to it. Repeatable. Use this for a
                            shared/CDN IP you've identified via
                            --resolve-only that you don't want swept.
  --resolve-only           Resolve the hosts, group them by distinct IP, and
                            print that grouping, then exit — before a single
                            port is probed and before any report is written.
                            No requests are sent to any of the IPs. Review
                            this output (and re-run with --exclude/
                            --exclude-ip as needed) before ever dropping this
                            flag.
  --ports <from-to>        Port range to scan on each IP, inclusive
                            (default: 1-30000).
  --port-concurrency <n>   TCP connect attempts in parallel, per IP
                            (default: 500).
  --port-timeout <ms>      Per-port connect timeout in milliseconds
                            (default: 1500).
  --http-concurrency <n>   Open ports probed for HTTP(S) in parallel, per
                            IP (default: 20).
  --http-timeout <ms>      Per-port HTTP(S) liveness-probe timeout in
                            milliseconds (default: 5000).
  --subdomain-ports <mode> Which URLs to fingerprint for each given hostname,
                            in addition to the IP:port targets:
                              none     - IP:port targets only (hostnames are
                                         used to find IPs and then not
                                         scanned by name).
                              default  - the hostname's own URL on the
                                         default web port (443, else 80), if
                                         its IP answered there. (default)
                              all      - as "default", plus hostname:port for
                                         EVERY other HTTP(S) port found on
                                         its IP. Multiplies the target count
                                         by (names per IP) x (web ports per
                                         IP).
                            Each by-name scan resolves DNS itself, so on a
                            name with several A records it may reach a
                            different IP than the one that was port-scanned.
  --ip-concurrency <n>     Distinct IPs port-scanned in parallel (default:
                            2). Kept low by default: each IP's own port
                            scan already opens up to --port-concurrency
                            TCP connections at once, so scanning several IPs
                            at the same time multiplies that load.
  --list-only              Port-scan every IP and print each one's open-port
                            list and the HTTP(S) subset of it, then exit —
                            before fingerprinting anything or writing a
                            report. No OSV/NVD queries, no secrets crawl, no
                            misconfiguration probes. (Unlike --resolve-only,
                            this does connect to the IPs.)
  --allow-private          Disable the private/self-IP safety guard (see
                            below). Only ever use this for lab/localhost
                            hosts you own — never against a third party.
  --concurrency <n>        HTTP(S)-speaking targets fingerprinted in
                            parallel, across ALL IPs combined (default: 4) —
                            same meaning as ubel-url/ubel-domain/ubel-easm's
                            own --concurrency; unlike --ip-concurrency/
                            --port-concurrency/--http-concurrency above,
                            this is the heavier fingerprint+CVE-lookup stage.
  --working-dir <path>     Directory reports are written under (default: cwd).
  --min-severity <sev>     Only report vulnerabilities at or above this
                            severity in the Vulnerabilities tab (default:
                            unknown, i.e. everything). Component inventory
                            and per-component vulnerability counts always
                            reflect the full, unfiltered scan regardless of
                            this flag. One of: critical|high|medium|low|unknown
  --fail-on <sev|none|N:sev>
                            Non-zero exit if a vulnerability or web
                            misconfiguration at or above <sev> exists
                            (default: critical). Infections
                            always count regardless of threshold. "none"
                            always exits 0. "N:sev" fails only once MORE
                            than N matches exist, e.g. "5:high".
  --block-kev [true|false]
                            Exit 2 if any vulnerability is in the CISA Known
                            Exploited Vulnerabilities catalog, whatever its
                            severity (default: true; a bare flag means true).
  --epss-threshold <value>
                            Exit 2 if any vulnerability's FIRST EPSS score is at
                            or above <value>: a fraction (0.1), a percentage
                            (10%) or "none" (default: 0.1). KEV/EPSS data is
                            best-effort: if either feed is unreachable the scan
                            still completes, the report says so, and that rule
                            is not enforced. "--fail-on none" disables both.
  --no-secrets             Skip the client-side JavaScript secrets crawl
                            (see ubel-url --help for what this covers).
  --cookie <value>          Send this Cookie header on every fingerprinting
                            request, e.g. --cookie "session=abc123". Useful
                            for fingerprinting behind a login. Sent only on
                            the fingerprinting requests (initial probe +
                            directory-list checks) - the secrets crawl and
                            misconfiguration probes stay unauthenticated,
                            since some of those checks (CORS, TRACE) rely on
                            a credential-free baseline response.
  --header <"Name: Value">  Send an additional custom header on every
                            fingerprinting request. Repeatable, e.g.
                            --header "X-Api-Key: xyz" --header "Accept-Language: en".
                            Same scope as --cookie above; a header here can
                            override the default User-Agent or a Cookie set
                            via --cookie.
  --verbose                Print per-host/per-IP/per-port progress.
  --quiet                  Suppress the console summary (reports still write).
  --help, -h               Show this help.

Project commands (run instead of a scan):
  ubel-host project-id [folder] [--json]    Print this folder's project id
  ubel-host set-project-id <id> [folder]    Link this folder to an existing project id
  ubel-host version [--json]                Print the UBEL version

Every run writes a timestamped <ts>.host.zip bundle (report.host.json +
report.host.html inside) under $HOME/.ubel/history/host/, plus
fixed, unzipped "latest" copies at .ubel/reports/latest.host.json and
latest.host.html — kept separate from ubel-url's and ubel-domain's own reports so one
never overwrites another's latest pointer. Both include a plain-language
Executive Summary for non-technical readers (the tab after Dashboard in the
HTML).

Hosts given by name are DNS-resolved before any port is touched. A name that
does not resolve is listed as "dead" — same handling ubel-domain/ubel-easm
give it — and contributes no IP to port-scan.

The discovery stages, in order, per distinct IP:
  1. Every port in --ports is connect-scanned in parallel. A port that
     accepts a TCP connection counts as "open" — nothing about what's
     actually listening on it is known yet.
  2. Each open port is then probed with an HTTP(S) request (HTTPS first,
     falling back to plain HTTP) to filter that list down to the ones
     actually speaking HTTP(S) — most open ports on a typical host (SSH, a
     database, a message queue, ...) are not web servers, and only the
     HTTP(S)-speaking subset is handed to the fingerprinter.
Both the full open-port list and the HTTP(S)-speaking subset are recorded
per IP: the latter becomes the report's usual Targets/assets list (identical
shape to a ubel-url run), the former is additionally listed in the Scan Info
tab so the report reflects the whole scanned port range, not just the ports
that went on to be fingerprinted.

Safety guard: by default, a resolved IP that is private/RFC1918 or is this
scanning host's own public IP is refused outright, before a single port is
probed on it — the same guard ubel-url/ubel-domain apply to every target they
fingerprint, applied here one step earlier since a full port scan of an
unintended target is a bigger deal than a single fingerprint request. A
refused IP is reported as "skipped" (never silently dropped), and the names
that resolve to it are not scanned by name either. --allow-private disables
it — only for hosts you actually own, e.g. a local dev/staging box. This
guard does NOT and cannot detect the separate "shared/CDN IP" risk described
above — that one is on you to review via --resolve-only.

Vulnerability data sources (overridable for self-hosted/air-gapped mirrors,
same env vars every other EASM entry point honors):
  UBEL_OSV_ENDPOINT             default https://api.osv.dev
  UBEL_NVD_ENDPOINT             default https://services.nvd.nist.gov/rest/json/cves/2.0
  UBEL_WPVULNERABILITY_ENDPOINT default https://www.wpvulnerability.net
NVD's unauthenticated rate limit (~5 req/30s) is respected internally.
`;

// Deliberately strict, same posture as ubel-domain's own DOMAIN_RE (see
// ./domain.js): these are the arguments the whole run is built from, and a URL
// or "host:port" pair slipped in here would silently connect-scan the wrong
// thing. IPv4 literal accepted alongside a bare hostname; a plain hostname
// regex borrowed from ./lib/crtsh.js's own VALID_HOSTNAME_RE. IPV4_RE comes
// from ./lib/ip_scan.js.
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;

/** Normalises one host argument the way every EASM entry point does: trimmed, lower-cased, no trailing dot. */
function normalizeHost(raw) {
  return String(raw).trim().toLowerCase().replace(/\.$/, '');
}

/** An all-numeric dotted quad with an octet over 255 is a typo'd IP, not a hostname worth a DNS lookup. */
function isBadIpv4(host) {
  return IPV4_RE.test(host) && host.split('.').some((o) => Number(o) > 255);
}

function parseArgs(argv) {
  const args = {
    hosts: [],
    exclude: [],
    excludeIp: [],
    resolveOnly: false,
    ipConcurrency: 2,
    subdomainPorts: 'default',
    portFrom: 1,
    portTo: 30000,
    portConcurrency: 500,
    portTimeout: 1500,
    httpConcurrency: 20,
    httpTimeout: 5000,
    listOnly: false,
    allowPrivate: false,
    concurrency: 4,
    minSeverity: 'unknown',
    failOn: 'critical',
    blockKev: true,
    epssThreshold: DEFAULT_EPSS_THRESHOLD,
    scanSecrets: true,
    cookie: null,
    headers: {},
    verbose: false,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      console.log(HELP);
      process.exit(0);
    } else if (a === '--hosts-file' || a === '--targets-file') {
      const file = argv[++i];
      if (!file) { console.error(`${a} requires a path\n`); console.log(HELP); process.exit(2); }
      for (const line of loadTargetsFileOrExit(file, a)) {
        args.hosts.push(...line.split(/[,\s]+/).filter(Boolean).map(normalizeHost));
      }
    } else if (a === '--exclude') {
      const host = argv[++i];
      if (!host) { console.error('--exclude requires a hostname\n'); process.exit(2); }
      args.exclude.push(normalizeHost(host));
    } else if (a === '--exclude-ip') {
      const ip = argv[++i];
      if (!ip) { console.error('--exclude-ip requires an IPv4 address\n'); process.exit(2); }
      args.excludeIp.push(ip.trim());
    } else if (a === '--resolve-only') args.resolveOnly = true;
    else if (a === '--ip-concurrency') args.ipConcurrency = parseInt(argv[++i], 10);
    else if (a === '--subdomain-ports') args.subdomainPorts = argv[++i];
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
    else if (a === '--list-only') args.listOnly = true;
    else if (a === '--allow-private') args.allowPrivate = true;
    else if (a === '--concurrency') args.concurrency = parseInt(argv[++i], 10);
    else if (a === '--working-dir') args.workingDir = argv[++i];
    else if (a === '--min-severity') args.minSeverity = argv[++i];
    else if (a === '--fail-on') args.failOn = argv[++i];
    else if (a === '--block-kev') {
      const next = argv[i + 1];
      if (next !== undefined && /^(true|false)$/i.test(next)) { args.blockKev = next.toLowerCase() === 'true'; i++; }
      else args.blockKev = true;
    } else if (a === '--epss-threshold') {
      const v = parseEpssThresholdArg(String(argv[++i] ?? '').toLowerCase());
      if (v === undefined) {
        console.error('--epss-threshold must be a fraction in (0, 1] (e.g. 0.1), a percentage (e.g. 10%), or "none"');
        process.exit(2);
      }
      args.epssThreshold = v;
    }
    else if (a === '--no-secrets') args.scanSecrets = false;
    else if (a === '--cookie') {
      const val = argv[++i];
      if (!val) { console.error('--cookie requires a value\n'); console.log(HELP); process.exit(2); }
      args.cookie = val;
    } else if (a === '--header') {
      const val = argv[++i];
      if (!val) { console.error('--header requires "Name: Value"\n'); console.log(HELP); process.exit(2); }
      const idx = val.indexOf(':');
      if (idx === -1) {
        console.error(`--header must be "Name: Value" (got ${JSON.stringify(val)})\n`);
        process.exit(2);
      }
      const name = val.slice(0, idx).trim();
      const value = val.slice(idx + 1).trim();
      if (!name) { console.error(`--header must be "Name: Value" (got ${JSON.stringify(val)})\n`); process.exit(2); }
      args.headers[name] = value;
    }
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a.startsWith('--')) {
      console.error(`Unknown argument: ${a}\n`);
      console.log(HELP);
      process.exit(2);
    } else {
      // Any number of hosts, space- and/or comma-separated.
      args.hosts.push(...a.split(',').map(normalizeHost).filter(Boolean));
    }
  }

  if (!args.hosts.length) {
    console.error('No host given — pass at least one host (or --hosts-file), e.g. "ubel-host example.com 203.0.113.10".\n');
    console.log(HELP);
    process.exit(2);
  }

  // Same host given twice (or via both argv and --hosts-file) is one host.
  args.hosts = [...new Set(args.hosts)];

  for (const host of args.hosts) {
    if ((!HOSTNAME_RE.test(host) && !IPV4_RE.test(host)) || isBadIpv4(host)) {
      console.error(
        `"${host}" doesn't look like a bare hostname or IPv4 address.\n` +
        `Pass just the host — "example.com" or "203.0.113.10", not a URL or a\n` +
        `"host:port" pair.\n`
      );
      process.exit(2);
    }
  }

  for (const ip of args.excludeIp) {
    if (!IPV4_RE.test(ip)) {
      console.error(`--exclude-ip expects an IPv4 address, got "${ip}"`);
      process.exit(2);
    }
  }

  if (!SUBDOMAIN_PORT_MODES.has(args.subdomainPorts)) {
    console.error(`--subdomain-ports must be one of: ${[...SUBDOMAIN_PORT_MODES].join(', ')} (got "${args.subdomainPorts}")`);
    process.exit(2);
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

/** What the given hosts are called in console output: the host itself, or a count. */
function hostsLabel(hosts) {
  return hosts.length === 1 ? hosts[0] : `${hosts.length} given hosts`;
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.quiet) {
    console.log('\n' + BANNER + '\n');
  }

  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  // Step 1: the host list, minus --exclude (applied before resolution, same as
  // ubel-easm's own --exclude).
  const excludedHosts = new Set(args.exclude);
  const hostnames = args.hosts.filter((h) => !excludedHosts.has(h)).sort();
  const label = hostsLabel(hostnames);

  if (!hostnames.length) {
    console.error('\nEvery host given was removed by --exclude — nothing to scan.\n');
    process.exitCode = 1;
    return;
  }

  // Step 2: resolve every host and collapse onto the distinct IPs behind
  // them — the exact same call ubel-easm makes for crt.sh's hostnames.
  log(`[*] Resolving ${hostnames.length} host(s) to IP addresses...`);
  const grouping = await resolveHostsToIps(hostnames, { excludeIp: args.excludeIp });
  const { ips, deadHostnames, excludedResolutions } = grouping;

  if (deadHostnames.length) {
    log(`[*] ${deadHostnames.length} hostname(s) did not resolve and contribute no IP.`);
  }

  if (!ips.length) {
    console.error(
      `\nNo scannable IP found for ${label}.\n` +
      `Every host either failed to resolve or landed on an excluded IP.\n` +
      (deadHostnames.length ? `Did not resolve: ${deadHostnames.map((r) => r.target).join(', ')}\n` : '') +
      (excludedResolutions.length
        ? `Dropped by --exclude-ip: ${excludedResolutions.map((r) => `${r.hostname} -> ${r.ip}`).join(', ')}\n`
        : '')
    );
    process.exitCode = 1;
    return;
  }

  // Stops here, before a single port is probed on any IP — everything up to
  // this point (DNS) is passive; everything after is a live port sweep. Same
  // checkpoint ubel-easm's --list-only is.
  if (args.resolveOnly) {
    printIpGrouping(label, grouping);
    process.exitCode = 0;
    return;
  }

  if (!args.quiet) {
    console.log(
      `[ubel-host] ${label}: ${hostnames.length} host(s) resolved to ${ips.length} distinct IP(s) to port-scan` +
      `${deadHostnames.length ? `, ${deadHostnames.length} did not resolve` : ''}` +
      `${excludedResolutions.length ? `, ${excludedResolutions.length} dropped via --exclude-ip` : ''}.\n`
    );
  }

  // Step 3: port-scan every distinct IP (guard, connect-scan, HTTP(S) probe).
  const hostScans = await scanIps(ips, args, log);

  // Stops here, before a single fingerprinting request is sent — mirrors
  // ubel-domain's own --list-only checkpoint (see ./domain.js), just one
  // stage later: the port scan + HTTP(S) probe above already happened (that
  // IS the discovery step here), but nothing beyond it has.
  if (args.listOnly) {
    for (const h of hostScans) {
      const names = h.hostnames.length ? `  (${h.hostnames.join(', ')})` : '';
      console.log(`${h.ip}${names}`);
      if (h.status !== 'scanned') {
        console.log(`  ${h.status}: ${h.detail}\n`);
        continue;
      }
      console.log(`  Open ports (${h.openPorts.length}): ${h.openPorts.length ? h.openPorts.join(', ') : '(none)'}`);
      console.log(`  HTTP(S)-speaking ports (${h.httpPorts.length}): ${h.httpPorts.length ? h.httpPorts.join(', ') : '(none)'}\n`);
    }
    process.exitCode = 0;
    return;
  }

  // Step 4's target list — the collective merge: every IP's HTTP(S)-speaking
  // ports become one flat, deduplicated target list, so the fingerprinting/
  // OSV/NVD/wpvulnerability.net stage below runs exactly once across all the
  // hosts, not once per host. Name-based targets lead: they're the sites
  // people actually reach.
  const { ipTargets, hostnameTargets } = buildTargets(hostScans, args.subdomainPorts);
  const targets = [...hostnameTargets, ...ipTargets];

  const scannedCount = hostScans.filter((h) => h.status === 'scanned').length;
  const skippedCount = hostScans.filter((h) => h.status === 'skipped').length;
  if (!args.quiet) {
    console.log(
      `[ubel-host] ${scannedCount} IP(s) port-scanned, ${skippedCount} skipped by the private/self-IP guard ` +
      `→ ${targets.length} HTTP(S) target(s) to fingerprint ` +
      `(${ipTargets.length} by IP:port, ${hostnameTargets.length} by hostname).\n`
    );
    if (!targets.length) {
      console.log(
        `[ubel-host] No HTTP(S)-speaking port was found on any of the ${ips.length} IP(s) — ` +
        `nothing to fingerprint or look up, but the report will still record the full port-scan results.\n`
      );
    }
  }

  const scanResult = await scanTargets(targets, {
    allowPrivate: args.allowPrivate,
    concurrency: args.concurrency,
    scanSecrets: args.scanSecrets,
    cookie: args.cookie,
    headers: args.headers,
    log,
  });

  scanResult.vulnerabilities = filterByMinSeverity(scanResult.vulnerabilities, args.minSeverity);

  // A single given host keeps the singular host/portRange/openPorts report
  // fields it has always had; several hosts are described by the per-IP
  // `hosts` list below (and `inputHosts`), same as a ubel-easm report.
  const single = hostnames.length === 1;
  const allOpenPorts = [...new Set(hostScans.flatMap((h) => h.openPorts))].sort((x, y) => x - y);

  const meta = {
    tool: 'ubel-host',
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(await collectScanMetadata(args)),
    // The merged HTTP(S) target list actually fingerprinted, same meaning as
    // ubel-domain's/ubel-easm's own `targets` — the discovered-and-scanned
    // set, not the raw input. The raw open-port lists travel separately in
    // `hosts` so the report can show the full scanned scope even for ports
    // that never made it to fingerprinting.
    targets,
    inputHosts: hostnames,
    host: single ? hostnames[0] : null,
    portRange: `${args.portFrom}-${args.portTo}`,
    openPorts: single ? allOpenPorts : [],
    // Per-IP port-scan detail + hostnames that never resolved — same shape
    // (and same builder) as ubel-easm's.
    ...buildHostsMeta(hostScans, deadHostnames, args),
    allowPrivate: args.allowPrivate,
    // Deliberately not the cookie value or header values themselves - those can be
    // session tokens/API keys and have no business landing in a written report.
    usedCookie: Boolean(args.cookie),
    customHeaderNames: Object.keys(args.headers),
    scanSecrets: args.scanSecrets,
    minSeverity: args.minSeverity,
    blockKev: args.blockKev,
    epssThreshold: args.epssThreshold,
    osvEndpoint: process.env.UBEL_OSV_ENDPOINT || null,
    nvdEndpoint: process.env.UBEL_NVD_ENDPOINT || null,
    wpvulnerabilityEndpoint: process.env.UBEL_WPVULNERABILITY_ENDPOINT || null,
  };

  const reportPayload = buildReportPayload(scanResult, meta);

  if (!args.quiet) {
    printScanSummary(reportPayload, `ubel-host External Attack Surface Scan Summary — ${label}`);
  }

  await writeEasmReports(reportPayload, args, { reportType: 'easm-host', cliLabel: '[ubel-host]' });

  process.exitCode = failOnExitCode(scanResult.vulnerabilities, args.failOn, { blockKev: args.blockKev, epssThreshold: args.epssThreshold, misconfigurations: scanResult.misconfigurations?.findings });

  // Nothing was actually port-scanned (every IP refused by the guard, or
  // errored): the report records that, but a clean "no findings" exit code
  // would read as a pass in CI when nothing was examined at all.
  if (!scannedCount && !process.exitCode) {
    console.error(
      `[ubel-host] No IP was actually scanned (${skippedCount} skipped by the private/self-IP guard, ` +
      `${hostScans.length - skippedCount} failed) — exiting 1 because nothing was examined.`
    );
    process.exitCode = 1;
  }
}

export { main, parseArgs, USAGE_NOTICE };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}