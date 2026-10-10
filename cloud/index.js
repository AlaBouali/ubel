'use strict';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { Reporter } from './lib/report.js';
import { generateHtmlReport, buildReportPayload } from './lib/html_report.js';
import { buildZip } from '../sca/zip_writer.js';
import { reportTimestamp, reportFileName, historyZipPath, projectFor } from '../sca/report_naming.js';
import { loadAwsCredentials, loadAwsRegionsFromEnv } from './auth/aws-creds.js';
import { describeRegions } from './providers/aws/ec2.js';
import { getGcpAccessToken } from './auth/gcp-auth.js';
import { getAzureAccessToken } from './auth/azure-auth.js';
import { runAwsChecks } from './checks/aws-checks.js';
import { runGcpChecks } from './checks/gcp-checks.js';
import { runAzureChecks } from './checks/azure-checks.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;

const HELP = `
cloud-scanner — stdlib-only AWS/GCP/Azure misconfiguration scanner

Usage:
  ubel-cloud [--provider aws,gcp,azure]
                    [--working-dir <path>] [--regions us-east-1,eu-west-1]
                    [--profile <aws-profile>] [--min-severity critical|high|medium|low|info]
                    [--fail-on critical|high|medium|low|info|none|<count>:<severity>]
                    [--verbose] [--quiet]

Every run bundles a report.cloud.json + report.cloud.html into a timestamped zip under
$HOME/.ubel/history/cloud/<timestamp>.cloud.zip, and
also writes plain, always-overwritten "latest" copies to
.ubel/reports/latest.cloud.json and .ubel/reports/latest.cloud.html.

Options:
  --provider <a,b,c>     Comma-separated providers to scan (default: aws,gcp,azure)
  --working-dir <path>   Target directory reports are written under (default: cwd)
  --regions <a,b>        Explicit AWS region override — skips DescribeRegions auto-discovery
  --profile <name>       AWS profile to use from ~/.aws/credentials (same as AWS_PROFILE)
  --min-severity <sev>   Only report findings at or above this severity (default: info)
  --fail-on <sev|none|N:sev>
                          Non-zero exit if a finding at or above <sev> exists (default: critical).
                          "none" always exits 0. "N:sev" instead fails only once MORE than N
                          findings at or above <sev> exist, e.g. "5:high" fails on the 6th+
                          high-or-above finding — for CI gates that tolerate a known baseline.
  --verbose              Print per-check progress
  --quiet                Suppress the console findings summary (reports are still written)
  --help, -h             Show this help

Project commands (run instead of a scan):
  ubel-cloud project-id [folder] [--json]    Print this folder's project id
  ubel-cloud set-project-id <id> [folder]    Link this folder to an existing project id
  ubel-cloud version [--json]                Print the UBEL version

AWS region resolution (highest priority first):
  1. --regions <list>              explicit override
  2. AWS_REGIONS / AWS_REGION / AWS_DEFAULT_REGION   environment variables
  3. DescribeRegions()             auto-discovers every enabled region on the account

Credentials, in resolution order (environment variables unless noted):
  AWS:    1. AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY [+ AWS_SESSION_TOKEN]
          2. a profile in ~/.aws/credentials or ~/.aws/config (AWS_PROFILE,
             or --profile), including role_arn + source_profile chains
             (resolved via STS AssumeRole)
  GCP:    1. GOOGLE_APPLICATION_CREDENTIALS=/path/to/key.json (service-account
             or 'gcloud auth application-default login' authorized-user JSON)
          2. gcloud's own ADC file (~/.config/gcloud/application_default_credentials.json)
          3. the GCE/GKE/Cloud Run instance metadata server (workload identity)
          GCP_PROJECT_ID=my-project overrides the project id from any of the above
  Azure:  1. AZURE_TENANT_ID + AZURE_CLIENT_ID + AZURE_CLIENT_SECRET (app registration)
          2. a managed identity via the Azure Instance Metadata Service
             (AZURE_CLIENT_ID optionally selects a user-assigned identity)
          AZURE_SUBSCRIPTION_ID is always required.

Any provider whose credentials aren't set is skipped with a warning, so you
can run this against just one cloud at a time.
`;

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
const VALID_SEVERITIES = new Set(Object.keys(SEVERITY_RANK));
const VALID_PROVIDERS = new Set(['aws', 'gcp', 'azure']);

function parseArgs(argv) {
  const args = {
    provider: 'aws,gcp,azure',
    minSeverity: 'info',
    failOn: 'critical',
    verbose: false,
    quiet: false,
  };
  // A flag that needs a value but is last on the line (or is followed by
  // another flag) must be a usage error, not an undefined that crashes later.
  const value = (flag, i) => {
    const v = argv[i + 1];
    if (v === undefined || v.startsWith('--')) {
      console.error(`${flag} requires a value\n`);
      console.log(HELP);
      process.exit(2);
    }
    return v;
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') {
      console.log(HELP);
      process.exit(0);
    } else if (a === '--provider') args.provider = value(a, i++);
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--regions') args.regions = value(a, i++);
    else if (a === '--profile') args.profile = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') args.failOn = value(a, i++);
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else {
      console.error(`Unknown argument: ${a}\n`);
      console.log(HELP);
      process.exit(2);
    }
  }

  // An unrecognised provider name used to be ignored silently, leaving a scan
  // of nothing that wrote an empty report and exited 0 — which reads as "clean".
  const requested = args.provider.split(',').map((p) => p.trim().toLowerCase()).filter(Boolean);
  const unknown = requested.filter((p) => !VALID_PROVIDERS.has(p));
  if (!requested.length || unknown.length) {
    console.error(`--provider must be a comma-separated list of: ${[...VALID_PROVIDERS].join(', ')} (got "${args.provider}")`);
    process.exit(2);
  }

  if (!VALID_SEVERITIES.has(args.minSeverity)) {
    console.error(`--min-severity must be one of: ${[...VALID_SEVERITIES].join(', ')} (got "${args.minSeverity}")`);
    process.exit(2);
  }

  args.failOn = parseFailOn(args.failOn);
  if (!args.failOn) {
    console.error(
      `--fail-on must be "none", one of: ${[...VALID_SEVERITIES].join(', ')}, or "<count>:<severity>" e.g. "5:high" (got "${argv[argv.indexOf('--fail-on') + 1]}")`
    );
    process.exit(2);
  }

  return args;
}

/**
 * item 7 of the review: a plain severity threshold is an all-or-nothing
 * gate -- the moment a CI pipeline has even one accepted/baselined
 * finding at that severity, the whole gate has to be loosened to the
 * next severity down, or disabled with --fail-on none. "<count>:<sev>"
 * (e.g. "5:high") instead fails only once MORE than that many findings
 * at or above the severity exist, which is what most mature CI
 * integrations actually want: a tolerated baseline plus a trip-wire for
 * regressions past it.
 */
function parseFailOn(value) {
  if (value === 'none') return { mode: 'none' };
  if (value.includes(':')) {
    const [countStr, severity] = value.split(':');
    const count = Number(countStr);
    if (!Number.isInteger(count) || count < 0 || !VALID_SEVERITIES.has(severity)) return null;
    return { mode: 'threshold', count, severity };
  }
  if (!VALID_SEVERITIES.has(value)) return null;
  return { mode: 'severity', severity: value };
}

function atomicWrite(filePath, content) {
  const tmp = filePath + '.tmp';
  fs.writeFileSync(tmp, content);
  fs.renameSync(tmp, filePath);
}

/**
 * Resolves AWS regions per the precedence documented in HELP:
 *   --regions  >  AWS_REGIONS/AWS_REGION/AWS_DEFAULT_REGION  >  DescribeRegions()
 * Falls back to us-east-1 if auto-discovery itself fails (e.g. the
 * credentials lack ec2:DescribeRegions) rather than aborting the scan.
 *
 * Returns { regions, source } — source is 'cli' | 'configured' |
 * 'discovered' | 'fallback' and ends up in the report, so a reader can tell
 * a deliberate one-region scan from a failed discovery.
 */
async function resolveAwsRegions(args, creds, log) {
  if (args.regions) {
    const regions = args.regions.split(',').map((r) => r.trim()).filter(Boolean);
    log(`Regions: explicit --regions override (${regions.join(', ')})`);
    return { regions, source: 'cli' };
  }

  const envRegions = loadAwsRegionsFromEnv();
  if (envRegions) {
    log(`Regions: from AWS_REGIONS/AWS_REGION/AWS_DEFAULT_REGION (${envRegions.join(', ')})`);
    return { regions: envRegions, source: 'configured' };
  }

  console.log('No --regions or AWS_REGIONS set — calling DescribeRegions to discover enabled regions...');
  try {
    const regions = await describeRegions(creds);
    if (!regions.length) throw new Error('account has no enabled regions');
    console.log(`Discovered ${regions.length} enabled region(s): ${regions.join(', ')}`);
    return { regions, source: 'discovered' };
  } catch (err) {
    console.log(`DescribeRegions failed (${err.message}); falling back to us-east-1`);
    return { regions: ['us-east-1'], source: 'fallback' };
  }
}

/**
 * Shared report writer — mirrors ubel-sast's writeAnalyzeReports /
 * writeMalwareReports: a timestamped report.json + report.html bundled
 * into one zip under $HOME/.ubel/history/cloud/, plus fixed
 * "latest" plain-file copies under .ubel/reports/ that always get
 * overwritten. Never calls process.exit — the caller decides what to do
 * with the exit code.
 */
async function writeCloudReports(reporter, meta, opts) {
  const now      = new Date();
  const ts       = reportTimestamp(now);

  const workingDir = opts.workingDir ? path.resolve(opts.workingDir) : process.cwd();

  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });

  // <timestamp>.cloud.zip (in $HOME/.ubel/history/cloud/), latest.cloud.<ext>, and report.cloud.<ext> inside the zip.
  const tag     = 'cloud';
  const project = projectFor('cloud', path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath('cloud', ts, tag, project?.project_id ?? null);

  const latestJson = path.join(latestDir, reportFileName('latest', tag, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', tag, 'html'));

  // ── Timestamped bundle ────────────────────────────────────────────────────
  // Same rationale as ubel-sast: json/html bundled into one <timestamp>.cloud.zip
  // instead of separate files, with unzipped "latest" copies left alongside.
  const bundleEntries = [];

  // Built once so the JSON report and the HTML report's embedded data are
  // the exact same object — never a separately-shaped, stripped-down JSON.
  const reportPayload = buildReportPayload(reporter, {
    ...meta,
    project_id:   project?.project_id   ?? null,
    project_name: project?.project_name ?? null,
  });

  const jsonPayload = JSON.stringify(reportPayload, null, 2);
  atomicWrite(latestJson, jsonPayload);
  bundleEntries.push({ name: reportFileName('report', tag, 'json'), data: jsonPayload });
  console.log(`\n[ubel-cloud] JSON  report : ${latestJson}`);

  try {
    const htmlReport = await generateHtmlReport(reportPayload);
    atomicWrite(latestHtml, htmlReport);
    bundleEntries.push({ name: reportFileName('report', tag, 'html'), data: htmlReport });
    console.log(`[ubel-cloud] HTML  report : ${latestHtml}`);
  } catch (e) {
    console.warn(`[ubel-cloud] HTML report failed: ${e.message}`);
  }

  atomicWrite(zipPath, buildZip(bundleEntries));

  console.log(`\n[ubel-cloud] Timestamped bundle : ${zipPath}`);
  console.log(`[ubel-cloud] Latest reports      : ${latestDir}`);

  return { zipPath };
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const providers = args.provider.split(',').map((p) => p.trim().toLowerCase());
  const log = args.verbose ? (msg) => console.log(msg) : () => {};

  if (args.profile) process.env.AWS_PROFILE = args.profile;

  const reporter = new Reporter();
  const scannedProviders = [];
  const scannedRegions = {};
  const accounts = {};
  let regionSource = null;

  // One row per requested provider, written into the report so it can say
  // which clouds were NOT (fully) scanned:
  //   scanned — checks ran to completion
  //   partial — checks started but threw part-way; findings gathered before the
  //             failure are kept, but the provider's results are incomplete
  //   skipped — never started (missing credentials, setup error)
  const providerStatus = [];
  const record = (provider, status, reason) =>
    providerStatus.push({ provider, status, ...(reason ? { reason } : {}) });

  if (providers.includes('aws')) {
    console.log('== AWS ==');
    let started = false;
    try {
      const creds = await loadAwsCredentials();
      const resolved = await resolveAwsRegions(args, creds, log);
      const regions = resolved.regions;
      regionSource = resolved.source;
      console.log(`Scanning regions: ${regions.join(', ')}`);
      started = true;
      scannedRegions.aws = regions;
      await runAwsChecks({ creds, regions }, reporter, log);
      scannedProviders.push('aws');
      record('aws', 'scanned');
    } catch (err) {
      if (started) {
        console.log(`AWS scan stopped part-way: ${err.message}`);
        scannedProviders.push('aws');
        record('aws', 'partial', err.message);
      } else {
        console.log(`Skipping AWS: ${err.message}`);
        record('aws', 'skipped', err.message);
      }
    }
  }

  if (providers.includes('gcp')) {
    console.log('== GCP ==');
    let started = false;
    try {
      const keyFile = process.env.GOOGLE_APPLICATION_CREDENTIALS;
      // getGcpAccessToken() falls through to gcloud's ADC file and then
      // the GCE/GKE metadata server when no keyFile is given (item 8), so
      // this is no longer an immediate hard-fail when the env var is unset.
      const { accessToken, projectId } = await getGcpAccessToken(keyFile ? path.resolve(keyFile) : undefined);
      const project = process.env.GCP_PROJECT_ID || projectId;
      if (!project) throw new Error('No GCP project id (set GCP_PROJECT_ID or use a key file that has project_id)');
      console.log(`Scanning project: ${project}`);
      started = true;
      accounts.gcp = project;
      await runGcpChecks({ project, accessToken }, reporter, log);
      scannedProviders.push('gcp');
      record('gcp', 'scanned');
    } catch (err) {
      if (started) {
        console.log(`GCP scan stopped part-way: ${err.message}`);
        scannedProviders.push('gcp');
        record('gcp', 'partial', err.message);
      } else {
        console.log(`Skipping GCP: ${err.message}`);
        record('gcp', 'skipped', err.message);
      }
    }
  }

  if (providers.includes('azure')) {
    console.log('== Azure ==');
    let started = false;
    try {
      const tenantId = process.env.AZURE_TENANT_ID;
      const clientId = process.env.AZURE_CLIENT_ID;
      const clientSecret = process.env.AZURE_CLIENT_SECRET;
      const subscriptionId = process.env.AZURE_SUBSCRIPTION_ID;
      if (!subscriptionId) throw new Error('AZURE_SUBSCRIPTION_ID must be set');
      // getAzureAccessToken() falls through to a managed identity (via the
      // Azure Instance Metadata Service) when the client-secret trio isn't
      // fully set (item 8), so this only hard-fails on a missing subscription id.
      const accessToken = await getAzureAccessToken({ tenantId, clientId, clientSecret });
      console.log(`Scanning subscription: ${subscriptionId}`);
      started = true;
      accounts.azure = subscriptionId;
      await runAzureChecks({ subscriptionId, accessToken }, reporter, log);
      scannedProviders.push('azure');
      record('azure', 'scanned');
    } catch (err) {
      if (started) {
        console.log(`Azure scan stopped part-way: ${err.message}`);
        scannedProviders.push('azure');
        record('azure', 'partial', err.message);
      } else {
        console.log(`Skipping Azure: ${err.message}`);
        record('azure', 'skipped', err.message);
      }
    }
  }

  const minRank = SEVERITY_RANK[args.minSeverity];
  const totalBeforeFilter = reporter.findings.length;
  reporter.findings = reporter.findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 4) <= minRank);
  const hiddenByFilter = totalBeforeFilter - reporter.findings.length;

  if (!args.quiet) reporter.printSummary();

  const meta = {
    generated_at: new Date().toISOString(),
    tool_version: TOOL_VERSION,
    providers: scannedProviders,
    regions: scannedRegions,
    provider_status: providerStatus,
    accounts,
    region_source: regionSource,
    min_severity: args.minSeverity,
    hidden_by_filter: hiddenByFilter,
  };

  await writeCloudReports(reporter, meta, args);

  if (args.failOn.mode === 'none') {
    process.exitCode = 0;
  } else if (args.failOn.mode === 'threshold') {
    const failRank = SEVERITY_RANK[args.failOn.severity];
    const matchCount = reporter.findings.filter((f) => (SEVERITY_RANK[f.severity] ?? 4) <= failRank).length;
    process.exitCode = matchCount > args.failOn.count ? 2 : 0;
  } else {
    const failRank = SEVERITY_RANK[args.failOn.severity];
    const shouldFail = reporter.findings.some((f) => (SEVERITY_RANK[f.severity] ?? 4) <= failRank);
    process.exitCode = shouldFail ? 2 : 0;
  }
}

export { main, parseArgs };

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch((err) => {
    console.error('Fatal error:', err.stack || err.message);
    process.exitCode = 1;
  });
}