'use strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { scanTargets } from './lib/scan.js';
import { buildReportPayload, USAGE_NOTICE } from './lib/html_report.js';
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
║  This sends live, unauthenticated requests to every target given to it   ║
║  and discloses what it fingerprints to OSV.dev/NVD. Only run it against  ║
║  infrastructure you own or have explicit, documented authorization to    ║
║  test — same rule as every other UBEL module. See ./README.md.           ║
╚══════════════════════════════════════════════════════════════════════════╝`;

const HELP = `
ubel-url — EASM: passive HTTP fingerprinting + OSV/NVD vulnerability lookup

${BANNER}

Usage:
  ubel-url <target> [<target2> ...] [options]
  ubel-url --targets-file <path> [options]

  <target> is a bare domain ("example.com"), a "host:port" pair, or a full
  URL ("https://example.com:8443"). Scheme defaults to https, falling back
  to http on the initial probe only.

  Only fingerprints hosts you already know about — for discovering the
  subdomains of a domain first via crt.sh and scanning all of them in one
  run, see ubel-domain instead.

Options:
  --targets-file <path>   Read newline-separated targets from a file (blank
                            lines and lines starting with "#" are ignored),
                            in addition to any given as arguments.
  --allow-private          Disable the private/self-IP safety guard (see
                            below). Only ever use this for lab/localhost
                            targets you own — never against a third party.
  --concurrency <n>        Targets fingerprinted in parallel (default: 4).
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
                            (malicious-package-style advisories) always
                            count regardless of threshold. "none" always
                            exits 0. "N:sev" fails only once MORE than N
                            matches exist, e.g. "5:high" — for CI gates
                            that tolerate a known baseline.
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
  --no-secrets             Skip the client-side JavaScript secrets crawl (see
                            below). Cuts one page fetch plus its script
                            fetches per live host.
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
  --verbose                Print per-target fingerprinting/query progress.
  --quiet                  Suppress the console summary (reports still write).
  --help, -h               Show this help.

Every run writes a timestamped easm_url__<ts>.zip bundle (report.json +
report.html inside) under .ubel/local/reports/easm_url/<year>/<month>/<day>/,
plus fixed, unzipped "latest" copies at .ubel/reports/latest.easm_url.json and
.ubel/reports/latest.easm_url.html — same bundling flow the SAST/malware
scanners use. JSON and HTML are the only output formats — no SBOM, no SARIF
(see README). Both carry a plain-language Executive Summary (overall risk,
key findings, suggested actions and the methodology used) written for
non-technical readers; in the HTML it is the tab right after Dashboard.

Targets are DNS-resolved before probing: a hostname with no DNS record is
marked "dead" in the report and skipped rather than probed to a timeout.

Client-side secrets: after fingerprinting, each live host's page is fetched
once more and every piece of JavaScript it serves — inline <script> blocks
and the .js files they reference — is scanned for hardcoded credentials
using the same rule set as ubel-secrets. Findings report the exact URL plus
line:column, with the value redacted. Disable with --no-secrets. This is one
level deep: it does not follow links, enumerate routes, or execute JS.

Safety guard: by default, a target that resolves to a private/RFC1918 IP or
to this host's own public IP is skipped, not scanned (reported as
"skipped" in the JSON/HTML Scan Info, never silently dropped). This exists
to make it harder to accidentally point an "external" scan at your own
scanning host or an internal-only address. --allow-private disables it —
only for targets you actually own, e.g. a local dev/staging box.

Vulnerability data sources (overridable for self-hosted/air-gapped mirrors,
same env vars the SCA module already honors):
  UBEL_OSV_ENDPOINT             default https://api.osv.dev
  UBEL_NVD_ENDPOINT             default https://services.nvd.nist.gov/rest/json/cves/2.0
  UBEL_WPVULNERABILITY_ENDPOINT default https://www.wpvulnerability.net
NVD's unauthenticated rate limit (~5 req/30s) is respected internally — a
scan with many unique components can take a while; point UBEL_NVD_ENDPOINT
at an authenticated proxy/mirror to speed this up.
`;

function parseArgs(argv) {
  const args = {
    targets: [],
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
    } else if (a === '--targets-file') {
      const file = argv[++i];
      if (!file) { console.error('--targets-file requires a path\n'); console.log(HELP); process.exit(2); }
      let lines;
      try {
        lines = fs.readFileSync(path.resolve(file), 'utf8').split(/\r?\n/);
      } catch (err) {
        console.error(`Failed to read --targets-file "${file}": ${err.message}`);
        process.exit(2);
      }
      for (const line of lines) {
        const t = line.trim();
        if (t && !t.startsWith('#')) args.targets.push(t);
      }
    } else if (a === '--allow-private') args.allowPrivate = true;
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
      args.targets.push(a);
    }
  }

  if (!args.targets.length) {
    console.error('No targets given — pass at least one target or --targets-file.\n');
    console.log(HELP);
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

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (!args.quiet) {
    console.log('\n' + BANNER + '\n');
  }

  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  const scanResult = await scanTargets(args.targets, {
    allowPrivate: args.allowPrivate,
    concurrency: args.concurrency,
    scanSecrets: args.scanSecrets,
    cookie: args.cookie,
    headers: args.headers,
    log,
  });

  scanResult.vulnerabilities = filterByMinSeverity(scanResult.vulnerabilities, args.minSeverity);

  const meta = {
    tool: 'ubel-url',
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    ...(await collectScanMetadata(args)),
    targets: args.targets,
    allowPrivate: args.allowPrivate,
    // Deliberately not the cookie value or header values themselves - those can be
    // session tokens/API keys and have no business landing in a written report.
    usedCookie: Boolean(args.cookie),
    customHeaderNames: Object.keys(args.headers),
    // Recorded so the report (and its executive summary) can tell "no secrets
    // found" from "secrets were not searched for", and can say when
    // --min-severity hid findings from the vulnerability list.
    scanSecrets: args.scanSecrets,
    minSeverity: args.minSeverity,
    blockKev: args.blockKev,
    epssThreshold: args.epssThreshold,
    osvEndpoint: process.env.UBEL_OSV_ENDPOINT || null,
    nvdEndpoint: process.env.UBEL_NVD_ENDPOINT || null,
    wpvulnerabilityEndpoint: process.env.UBEL_WPVULNERABILITY_ENDPOINT || null,
  };

  const reportPayload = buildReportPayload(scanResult, meta);

  if (!args.quiet) printScanSummary(reportPayload, 'ubel-url External Attack Surface Scan Summary');

  await writeEasmReports(reportPayload, args, { reportType: 'easm-url', cliLabel: '[ubel-url]' });

  process.exitCode = failOnExitCode(scanResult.vulnerabilities, args.failOn, { blockKev: args.blockKev, epssThreshold: args.epssThreshold, misconfigurations: scanResult.misconfigurations?.findings });
}

export { main, parseArgs, USAGE_NOTICE };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}