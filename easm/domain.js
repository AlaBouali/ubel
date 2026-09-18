'use strict';
// easm/domain.js — ubel-domain
//
// One flow, in order:
//   1. Take a root domain name.
//   2. Look up every subdomain of it via Certificate Transparency logs
//      (crt.sh) — see ./lib/crtsh.js.
//   3. Fingerprint all of them and group the detected technologies by
//      name+version with the list of hosts each was seen on.
//   4. Look up vulnerabilities for those technologies.
//   5. Generate the report.
//
// Steps 3-5 are not reimplemented here: they are exactly what ubel-url
// already does, so this delegates to the same scanTargets() pipeline
// (./lib/scan.js), which already keys its inventory by name+version and
// accumulates an `assets` host list per item — i.e. the grouping step is a
// property of that shared engine, not something this entry point layers on
// top. The only thing ubel-domain adds ahead of it is step 2, and the only
// thing it adds after is naming itself in the report metadata.

import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { scanTargets } from './lib/scan.js';
import { buildReportPayload, USAGE_NOTICE } from './lib/html_report.js';
import { queryCrtSh, extractSubdomains } from './lib/crtsh.js';
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
║  This discovers subdomains of the domain you give it, then sends live,   ║
║  unauthenticated requests to EVERY ONE of them and discloses what it     ║
║  fingerprints to OSV.dev/NVD. A domain's subdomain list can include      ║
║  hosts you did not expect — only run this against a domain you own or    ║
║  have explicit, documented authorization to test. See ./README.md.       ║
╚══════════════════════════════════════════════════════════════════════════╝`;

const HELP = `
ubel-domain — EASM: crt.sh subdomain discovery + fingerprinting + vuln lookup

${BANNER}

Usage:
  ubel-domain <domain> [options]

  <domain> is a bare registrable domain ("example.com"). Subdomains of it
  are discovered from Certificate Transparency logs via crt.sh, then each
  discovered host is fingerprinted and its detected technologies looked up
  for known vulnerabilities — the same engine ubel-url uses, just with the
  target list discovered for you instead of supplied by you.

  Discovery is passive (CT logs only) — no DNS brute-forcing, no wordlists.
  A subdomain that has never had a logged certificate issued for it won't
  be found; use --include to add such hosts by hand.

Options:
  --include <host>         Additionally scan this host, even if crt.sh
                            didn't return it. Repeatable. Useful for
                            internal/HTTP-only hosts with no CT record.
  --exclude <host>         Never scan this host, even if discovered.
                            Repeatable. Matches the exact hostname.
  --list-only              Discover and print the subdomain list, then exit
                            without fingerprinting anything or writing a
                            report. No requests are sent to the targets.
  --allow-private          Disable the private/self-IP safety guard. Only
                            ever use this for lab/localhost targets you own.
  --concurrency <n>        Hosts fingerprinted in parallel (default: 4).
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
  --no-secrets             Skip the client-side JavaScript secrets crawl (see
                            below). Cuts one page fetch plus its script
                            fetches per live host.
  --verbose                Print per-host discovery/fingerprinting progress.
  --quiet                  Suppress the console summary (reports still write).
  --help, -h               Show this help.

Every run writes a timestamped easm-domain__<ts>.zip bundle (report.json +
report.html inside) under .ubel/local/reports/easm-domain/<y>/<m>/<d>/, plus
fixed, unzipped "latest" copies at .ubel/reports/latest.easm-domain.json and
.html — same bundling flow the SAST/malware scanners use. These are kept
separate from ubel-url's own easm/ reports so a domain-wide sweep never
overwrites a targeted scan's latest pointer, or vice versa.

Discovered hosts are DNS-resolved before probing. Certificate Transparency
is append-only history, so a crt.sh result routinely includes hosts that
were decommissioned years ago; those resolve to nothing, are marked "dead"
in the report (Scan Info + Detailed Stats tabs), and are never probed.

Client-side secrets: after fingerprinting, each live host's page is fetched
once more and every piece of JavaScript it serves — inline <script> blocks
and the .js files they reference — is scanned for hardcoded credentials
using the same rule set as ubel-secrets. Findings report the exact URL plus
line:column, with the value redacted. Disable with --no-secrets. This is one
level deep: it does not follow links, enumerate routes, or execute JS.

Safety guard: by default, a discovered host that resolves to a private
/RFC1918 IP or to this host's own public IP is skipped, not scanned
(reported as "skipped" in the report, never silently dropped). This matters
more here than for ubel-url: CT logs routinely expose internal-only names
("jenkins.", "grafana.", "vpn.") that resolve to private space, and those
are exactly the ones you don't want an "external" scan touching by
accident.

Data sources (overridable for self-hosted/air-gapped mirrors):
  UBEL_CRTSH_ENDPOINT           default https://crt.sh
  UBEL_OSV_ENDPOINT             default https://api.osv.dev
  UBEL_NVD_ENDPOINT             default https://services.nvd.nist.gov/rest/json/cves/2.0
  UBEL_WPVULNERABILITY_ENDPOINT default https://www.wpvulnerability.net
NVD's unauthenticated rate limit (~5 req/30s) is respected internally. A
domain with many subdomains running many distinct technologies can take a
while; point UBEL_NVD_ENDPOINT at an authenticated proxy/mirror to speed
this up.
`;

// Deliberately strict: this is the one argument the whole run is built
// from, and a URL or "host:port" slipped in here would be passed to crt.sh
// as-is and silently return nothing useful. Rejecting it up front with a
// clear message beats an empty, confusing result.
const DOMAIN_RE = /^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)+$/;

function parseArgs(argv) {
  const args = {
    domain: null,
    include: [],
    exclude: [],
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
    } else if (a === '--include') {
      const host = argv[++i];
      if (!host) { console.error('--include requires a hostname\n'); process.exit(2); }
      args.include.push(host.trim().toLowerCase());
    } else if (a === '--exclude') {
      const host = argv[++i];
      if (!host) { console.error('--exclude requires a hostname\n'); process.exit(2); }
      args.exclude.push(host.trim().toLowerCase());
    } else if (a === '--list-only') args.listOnly = true;
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
    } else if (args.domain) {
      console.error(
        `ubel-domain takes exactly one domain (got "${args.domain}" and "${a}").\n` +
        `To scan several unrelated domains, run it once per domain; to scan a\n` +
        `known list of hosts directly, use ubel-url --targets-file instead.\n`
      );
      process.exit(2);
    } else {
      args.domain = a.trim().toLowerCase().replace(/\.$/, '');
    }
  }

  if (!args.domain) {
    console.error('No domain given — pass exactly one domain, e.g. "ubel-domain example.com".\n');
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
 * Step 1-2 of the flow: domain in, deduplicated host list out.
 * --include hosts are merged in (and deduplicated against) the discovered
 * set; --exclude is applied last so it overrides both discovery and
 * --include.
 */
async function discoverTargets(args, log) {
  log(`[*] Querying crt.sh for certificates issued under ${args.domain}...`);
  const entries = await queryCrtSh(args.domain);
  log(`[*] crt.sh returned ${entries.length} certificate record(s).`);

  const discovered = extractSubdomains(entries, args.domain);
  log(`[*] ${discovered.length} unique host(s) extracted from those records.`);

  const excluded = new Set(args.exclude);
  const merged = [...new Set([...discovered, ...args.include])]
    .filter((h) => !excluded.has(h))
    .sort();

  return { discovered, targets: merged };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.quiet) {
    console.log('\n' + BANNER + '\n');
  }

  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  const { discovered, targets } = await discoverTargets(args, log);

  if (!targets.length) {
    console.error(
      `\nNo scannable hosts found for "${args.domain}".\n` +
      `crt.sh returned no usable certificate records for it. That can mean the\n` +
      `domain genuinely has no logged certificates, that crt.sh was unreachable\n` +
      `or rate-limiting, or that everything found was excluded. Pass --verbose to\n` +
      `see the raw counts, or --include <host> to scan specific hosts anyway.\n`
    );
    process.exitCode = 1;
    return;
  }

  // --list-only stops here, before a single request is sent to any
  // discovered host — the point is to let someone review (and trim, via
  // --exclude) the target list before authorizing an actual scan of it.
  if (args.listOnly) {
    console.log(`\n${targets.length} host(s) for ${args.domain}:\n`);
    for (const t of targets) console.log(`  ${t}`);
    console.log('');
    process.exitCode = 0;
    return;
  }

  if (!args.quiet) {
    console.log(
      `[ubel-domain] ${args.domain}: ${discovered.length} host(s) discovered via crt.sh` +
      `${args.include.length ? `, +${args.include.length} via --include` : ''}` +
      `${args.exclude.length ? `, -${args.exclude.length} excluded` : ''}` +
      ` → ${targets.length} to scan.\n`
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
    tool: 'ubel-domain',
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(await collectScanMetadata(args)),
    // The discovered host list, not the single input domain — `targets` is
    // what was actually fingerprinted, and the report's Targets panel
    // reports per-host scanned/skipped/error status against it. The root
    // domain travels separately as meta.domain.
    targets,
    domain: args.domain,
    subdomainEndpoint: process.env.UBEL_CRTSH_ENDPOINT || null,
    allowPrivate: args.allowPrivate,
    osvEndpoint: process.env.UBEL_OSV_ENDPOINT || null,
    nvdEndpoint: process.env.UBEL_NVD_ENDPOINT || null,
    wpvulnerabilityEndpoint: process.env.UBEL_WPVULNERABILITY_ENDPOINT || null,
  };

  const reportPayload = buildReportPayload(scanResult, meta);

  if (!args.quiet) {
    printScanSummary(reportPayload, `ubel-domain External Attack Surface Scan Summary — ${args.domain}`);
  }

  await writeEasmReports(reportPayload, args, { reportType: 'easm-domain', cliLabel: '[ubel-domain]' });

  process.exitCode = failOnExitCode(scanResult.vulnerabilities, args.failOn);
}

export { main, parseArgs, discoverTargets, USAGE_NOTICE };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}
