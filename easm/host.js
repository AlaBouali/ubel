'use strict';
// easm/host.js — ubel-host
//
// One flow, in order:
//   1. Connect-scan every port in a range (default 1-30000) on one host —
//      see ./lib/portscan.js's scanPorts().
//   2. Of the ports that accepted a connection, probe each for HTTP(S) and
//      keep only the ones that answered — see ./lib/portscan.js's
//      probeHttpPorts().
//   3. Fingerprint every "host:port" that passed step 2, look up its
//      technologies against OSV/NVD, and run the fixed-set misconfiguration
//      checks against it.
//   4. Generate the report.
//
// Steps 3-4 are not reimplemented here: they are exactly what ubel-url and
// ubel-domain already do, so this delegates to the same scanTargets()
// pipeline (./lib/scan.js) — the same shared-engine relationship
// ubel-domain itself has with ubel-url (see ./domain.js's own comment).
// The only things ubel-host adds ahead of it are steps 1-2, and the only
// thing it adds to the report afterward is the raw open-port list (every
// port that accepted a connection, not just the HTTP(S)-speaking subset)
// in the Scan Info tab — everything else in the report is unchanged.

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { scanTargets } from './lib/scan.js';
import { buildReportPayload, USAGE_NOTICE } from './lib/html_report.js';
import { scanPorts, probeHttpPorts } from './lib/portscan.js';
import { DomainInfo, IpInfo } from './fingerprint/src/index.js';
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
║  This connects to every port in range on the host you give it, sends a   ║
║  live HTTP(S) request to each one that accepts a connection, and         ║
║  discloses what it fingerprints on the ones that answer to OSV.dev/NVD.  ║
║  Only run this against a host you own or have explicit, documented       ║
║  authorization to test. See ./README.md.                                 ║
╚══════════════════════════════════════════════════════════════════════════╝`;

const HELP = `
ubel-host — EASM: port scan + HTTP(S) discovery + fingerprinting + vuln lookup

${BANNER}

Usage:
  ubel-host <host> [options]

  <host> is a single bare hostname or IPv4 address — not a URL, not a
  "host:port" pair. Every port in range is connect-scanned on this one host;
  to fingerprint specific already-known host:port targets directly, without
  a port scan, use ubel-url instead.

Options:
  --ports <from-to>        Port range to scan, inclusive (default: 1-30000).
  --port-concurrency <n>   TCP connect attempts in parallel (default: 500).
  --port-timeout <ms>      Per-port connect timeout in milliseconds
                            (default: 1500).
  --http-concurrency <n>   Open ports probed for HTTP(S) in parallel
                            (default: 20).
  --http-timeout <ms>      Per-port HTTP(S) liveness-probe timeout in
                            milliseconds (default: 5000).
  --list-only              Print the open-port list and the HTTP(S) subset
                            of it, then exit — before fingerprinting
                            anything or writing a report. No OSV/NVD queries,
                            no secrets crawl, no misconfiguration probes.
  --allow-private          Disable the private/self-IP safety guard (see
                            below). Only ever use this for lab/localhost
                            hosts you own — never against a third party.
  --concurrency <n>        HTTP(S)-speaking targets fingerprinted in
                            parallel (default: 4) — same meaning as
                            ubel-url/ubel-domain's own --concurrency; unlike
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
                            Non-zero exit if a vulnerability at or above
                            <sev> exists (default: critical). Infections
                            always count regardless of threshold. "none"
                            always exits 0. "N:sev" fails only once MORE
                            than N matches exist, e.g. "5:high".
  --no-secrets             Skip the client-side JavaScript secrets crawl
                            (see ubel-url --help for what this covers).
  --verbose                Print per-port/per-host progress.
  --quiet                  Suppress the console summary (reports still write).
  --help, -h               Show this help.

Every run writes a timestamped easm-host__<ts>.zip bundle (report.json +
report.html inside) under .ubel/local/reports/easm-host/<y>/<m>/<d>/, plus
fixed, unzipped "latest" copies at .ubel/reports/latest.easm-host.json and
.html — kept separate from ubel-url's and ubel-domain's own reports so one
never overwrites another's latest pointer.

The two discovery stages, in order:
  1. Every port in --ports is connect-scanned in parallel. A port that
     accepts a TCP connection counts as "open" — nothing about what's
     actually listening on it is known yet.
  2. Each open port is then probed with an HTTP(S) request (HTTPS first,
     falling back to plain HTTP) to filter that list down to the ones
     actually speaking HTTP(S) — most open ports on a typical host (SSH, a
     database, a message queue, ...) are not web servers, and only the
     HTTP(S)-speaking subset is handed to the fingerprinter.
Both the full open-port list and the HTTP(S)-speaking subset are recorded:
the latter becomes the report's usual Targets/assets list (identical shape
to a ubel-url run), the former is additionally listed in the Scan Info tab
so the report reflects the whole scanned port range, not just the ports
that went on to be fingerprinted.

Safety guard: by default, a host that resolves to a private/RFC1918 IP or to
this scanning host's own public IP is refused outright, before a single
port is probed — the same guard ubel-url/ubel-domain apply to every target
they fingerprint, applied here one step earlier since a full port scan of
an unintended target is a bigger deal than a single fingerprint request.
--allow-private disables it — only for a host you actually own, e.g. a
local dev/staging box.

Vulnerability data sources (overridable for self-hosted/air-gapped mirrors,
same env vars every other EASM entry point honors):
  UBEL_OSV_ENDPOINT             default https://api.osv.dev
  UBEL_NVD_ENDPOINT             default https://services.nvd.nist.gov/rest/json/cves/2.0
  UBEL_WPVULNERABILITY_ENDPOINT default https://www.wpvulnerability.net
NVD's unauthenticated rate limit (~5 req/30s) is respected internally.
`;

// Deliberately strict, same posture as ubel-domain's own DOMAIN_RE (see
// ./domain.js): this is the one argument the whole run is built from, and a
// URL or "host:port" pair slipped in here would silently connect-scan the
// wrong thing. IPv4 literal accepted alongside a bare hostname; a plain
// hostname regex borrowed from ./lib/crtsh.js's own VALID_HOSTNAME_RE.
const HOSTNAME_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$/;
const IPV4_RE = /^\d{1,3}(\.\d{1,3}){3}$/;

function parseArgs(argv) {
  const args = {
    host: null,
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
    scanSecrets: true,
    verbose: false,
    quiet: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      console.log(HELP);
      process.exit(0);
    } else if (a === '--ports') {
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
    else if (a === '--no-secrets') args.scanSecrets = false;
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a.startsWith('--')) {
      console.error(`Unknown argument: ${a}\n`);
      console.log(HELP);
      process.exit(2);
    } else if (args.host) {
      console.error(
        `ubel-host takes exactly one host (got "${args.host}" and "${a}").\n` +
        `To scan several hosts, run it once per host; to scan a known list of\n` +
        `host:port targets directly, without a port scan, use ubel-url instead.\n`
      );
      process.exit(2);
    } else {
      args.host = a.trim().toLowerCase().replace(/\.$/, '');
    }
  }

  if (!args.host) {
    console.error('No host given — pass exactly one host, e.g. "ubel-host example.com".\n');
    console.log(HELP);
    process.exit(2);
  }

  if (!HOSTNAME_RE.test(args.host) && !IPV4_RE.test(args.host)) {
    console.error(
      `"${args.host}" doesn't look like a bare hostname or IPv4 address.\n` +
      `Pass just the host — "example.com" or "203.0.113.10", not a URL or a\n` +
      `"host:port" pair.\n`
    );
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

/**
 * Same private/self-IP check DomainScanner.scan() itself applies to every
 * target it's given (see ../fingerprint/src/core/domainScanner.js) — reused
 * here verbatim rather than reimplemented, and applied one step earlier:
 * before the port scan even starts, not just before fingerprinting.
 */
async function isBlockedHost(host) {
  const ip = await DomainInfo.getIpFromDomain(host);
  const myIp = await IpInfo.myIp();
  return { blocked: IpInfo.ipIsPrivate(ip) || (myIp != null && ip === myIp), ip };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.quiet) {
    console.log('\n' + BANNER + '\n');
  }

  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  if (!args.allowPrivate) {
    const guard = await isBlockedHost(args.host);
    if (guard.blocked) {
      console.error(
        `\n"${args.host}"${guard.ip ? ` resolved to ${guard.ip}, which` : ''} is a private/RFC1918 address ` +
        `or this scanning host's own public IP.\nPort-scanning it is refused by the same safety guard every ` +
        `other UBEL EASM module uses — pass --allow-private only for a lab/localhost host you own.\n`
      );
      process.exitCode = 1;
      return;
    }
  }

  const openPorts = await scanPorts(args.host, { from: args.portFrom, to: args.portTo }, {
    concurrency: args.portConcurrency,
    timeout: args.portTimeout,
    log,
  });

  const httpPorts = await probeHttpPorts(args.host, openPorts, {
    concurrency: args.httpConcurrency,
    timeout: args.httpTimeout,
    log,
  });

  const targets = httpPorts.map((p) => `${args.host}:${p}`);

  if (!args.quiet) {
    console.log(
      `[ubel-host] ${args.host}: ${openPorts.length} open port(s) in ${args.portFrom}-${args.portTo}, ` +
      `${httpPorts.length} answering HTTP(S) → ${targets.length} target(s) to scan.\n`
    );
  }

  // Stops here, before a single fingerprinting request is sent — mirrors
  // ubel-domain's own --list-only checkpoint (see ./domain.js), just one
  // stage later: the port scan + HTTP(S) probe above already happened (that
  // IS the discovery step here), but nothing beyond it has.
  if (args.listOnly) {
    console.log(`Open ports on ${args.host} (${openPorts.length}):\n`);
    console.log(`  ${openPorts.length ? openPorts.join(', ') : '(none)'}\n`);
    console.log(`HTTP(S)-speaking ports (${httpPorts.length}):\n`);
    console.log(`  ${httpPorts.length ? httpPorts.join(', ') : '(none)'}\n`);
    process.exitCode = 0;
    return;
  }

  const scanResult = await scanTargets(targets, {
    allowPrivate: args.allowPrivate,
    concurrency: args.concurrency,
    scanSecrets: args.scanSecrets,
    log,
  });

  scanResult.vulnerabilities = filterByMinSeverity(scanResult.vulnerabilities, args.minSeverity);

  const meta = {
    tool: 'ubel-host',
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(await collectScanMetadata(args)),
    // The HTTP(S)-speaking targets actually fingerprinted — same meaning as
    // ubel-domain's `targets` (the discovered-and-scanned list, not the
    // single input). The raw open-port list travels separately below so the
    // report can show the full scanned scope even for ports that never made
    // it to fingerprinting.
    targets,
    host: args.host,
    portRange: `${args.portFrom}-${args.portTo}`,
    openPorts,
    allowPrivate: args.allowPrivate,
    osvEndpoint: process.env.UBEL_OSV_ENDPOINT || null,
    nvdEndpoint: process.env.UBEL_NVD_ENDPOINT || null,
    wpvulnerabilityEndpoint: process.env.UBEL_WPVULNERABILITY_ENDPOINT || null,
  };

  const reportPayload = buildReportPayload(scanResult, meta);

  if (!args.quiet) {
    printScanSummary(reportPayload, `ubel-host External Attack Surface Scan Summary — ${args.host}`);
  }

  await writeEasmReports(reportPayload, args, { reportType: 'easm-host', cliLabel: '[ubel-host]' });

  process.exitCode = failOnExitCode(scanResult.vulnerabilities, args.failOn);
}

export { main, parseArgs, USAGE_NOTICE };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}
