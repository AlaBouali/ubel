# UBEL — Unified Bill / Enforced Law
### Cloud Misconfiguration Scanner (AWS / GCP / Azure)

Ubel-cloud scans your AWS, GCP, and Azure accounts directly via each
provider's own read-only API — live account state, not a static IaC/manifest
scan, and nothing is ever deployed or modified — for public exposure,
IAM misconfiguration, missing encryption, and disabled audit logging, and
maps every finding onto industry compliance frameworks.

This document covers the **cloud misconfiguration scanner** (`ubel-cloud`),
one of the CLIs shipped in the `@arcane-spark/ubel-node` package alongside
the SCA/firewall CLI ([node/sca/README.md](../sca/README.md)) and the
AI-powered SAST/malware scanner ([node/sast/README.md](../sast/README.md)).

Written against **Node.js's standard library only** — no AWS SDK, no
`googleapis`, no `@azure/*` packages, zero runtime `dependencies` in
`package.json`.

---

## Features

- Live AWS/GCP/Azure account scanning via each provider's own read-only API — actual account state, not a static IaC/manifest scan
- 69 checks across three providers covering public storage/database/network exposure, IAM posture, missing encryption, and disabled audit logging (see [What it checks](#what-it-checks))
- Condition-aware severity on wildcard IAM/SNS/SQS policy findings — a matching statement is only downgraded from `high` when its `Condition` block is built entirely from keys that meaningfully restrict access, not just any `Condition` at all
- Fully paginated AWS list calls (security groups, instances, volumes, DB instances/snapshots) — accounts past one page of resources are scanned completely, not silently truncated
- Bounded concurrency for per-bucket/per-user/per-region work (see `lib/concurrency.js`) instead of serial, one-item-at-a-time scanning
- Auto-discovers enabled AWS regions via `DescribeRegions` by default — no need to list them out by hand
- Credentials are only ever used for that run — nothing stored or reused, same model as the SAST module's LLM credentials
- **Compliance framework mapping** — every finding is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, with a report-level per-framework/per-control finding-count summary (see [Compliance Framework Mapping](#compliance-framework-mapping))
- Automatic report generation: timestamped **JSON** + interactive **HTML**, plus `latest.*` convenience links; a zipped snapshot of both is also saved for historic tracking
- `--fail-on` severity/count gate — same syntax as the rest of UBEL — for CI use
- Zero external runtime dependencies (Node.js stdlib only)

---

## Installation

```bash
npm install -g @arcane-spark/ubel-node
```

This installs `ubel-cloud` alongside every other UBEL binary (SCA/firewall,
SAST, secrets, license). There's no separate package to install — the
cloud scanner ships as part of `@arcane-spark/ubel-node`.

---

## Requirements

- Node.js `>=18.0.0` (for the built-in global `fetch`)
- Read-only credentials for whichever of AWS/GCP/Azure you're scanning — see [Setup](#setup) for the exact permissions and resolution order per provider
- Any provider without credentials set is skipped with a warning rather than aborting the whole scan, so a partial credential setup (e.g. AWS-only) works fine

---

## Why stdlib-only

Every cloud SDK is really three things bolted together: an HTTP client, an
auth/signing layer, and a pile of typed request/response models. Node's
`fetch`/`https` cover the HTTP client. `crypto` covers every signing scheme
these three clouds use (HMAC-SHA256 for AWS SigV4, RS256 for GCP JWTs). The
only real gap is that AWS's older APIs (EC2, IAM, RDS, and S3's XML
responses) speak XML, and there's no XML parser in Node core — so this
project ships a small one (`lib/xml.js`) built and tested specifically
for the shape of AWS's responses, rather than pulling in a general-purpose
XML dependency.

---

## What it checks

**AWS** (S3, EC2, IAM, RDS, CloudTrail, GuardDuty, SNS, SQS):
- S3 buckets: public ACL grants, public bucket policy (via
  `GetBucketPolicyStatus`), Block Public Access not fully enabled, default
  encryption disabled, versioning disabled, access logging disabled, and a
  *bounded, prefix-sharded sample* of object-level public ACLs — an
  exhaustive scan of every object doesn't happen, but a small bucket
  (first page not truncated) is scanned in full and the finding says so;
  see "Known limitations"
- EC2: security groups with ingress open to `0.0.0.0/0`/`::/0` on all
  ports/protocols, on sensitive ports (SSH/RDP/DB ports/etc.), or on any
  other port (fully paginated — see below); instances with a public IP;
  VPCs with no active flow log; EBS default encryption disabled
  (account/region-level); EBS volumes unencrypted or unattached (fully
  paginated)
- IAM: console users without MFA, access keys unrotated for 90+ days, no
  account password policy, any customer-managed policy *or inline policy
  on a user/group/role* granting `Action:"*"`/`Resource:"*"` (a matching
  statement is only downgraded to medium if its `Condition` is built
  *entirely* from keys known to meaningfully restrict access —
  `aws:SourceIp`/`SourceVpc`/`SourceVpce`, `aws:PrincipalArn`/`PrincipalOrgID`/
  `PrincipalAccount`, `aws:MultiFactorAuthPresent`; anything else, e.g.
  `aws:RequestedRegion` or an unevaluated `aws:PrincipalTag`, keeps it at
  high with a "review the condition" note, since we can't evaluate
  arbitrary condition logic), IAM roles whose trust policy allows
  `Principal: "*"`
- RDS: publicly accessible instances, unencrypted storage, publicly shared
  manual snapshots, unencrypted snapshots (fully paginated)
- CloudTrail: no active multi-region trail, logging stopped, missing KMS
  encryption, log file validation disabled
- GuardDuty: no enabled detector in any scanned region; a detector that
  exists but is administratively disabled
- SNS/SQS: topic/queue resource policies with `Principal: "*"` (same
  condition-aware severity logic as the IAM full-admin check above)

**GCP** (Storage, Compute, IAM, Cloud SQL, BigQuery, Cloud Run, Cloud
Functions, GKE):
- Storage buckets: IAM bindings granting `allUsers`/`allAuthenticatedUsers`
  (the finding notes whether Public Access Prevention would already block
  it), fine-grained ACLs instead of uniform bucket-level access, Public
  Access Prevention not set to `enforced`
- Firewall rules: ingress from `0.0.0.0/0` **or `::/0`** on all protocols,
  on a protocol with no port restriction, on sensitive ports, or on any
  other port (a rule scoped to `targetTags` is downgraded one severity
  notch from the unscoped case, rather than treated identically — it
  still applies to every instance carrying that tag, just not the whole
  network)
- Project IAM policy: primitive roles (`roles/owner`/`roles/editor`) or any
  other role bound to `allUsers`/`allAuthenticatedUsers`
- Compute instances: public IP + default service account with
  `cloud-platform` (full API access) scope
- Cloud SQL: instances open to `0.0.0.0/0`, public IP enabled, SSL not
  required
- BigQuery: datasets granting access to `allUsers`/`allAuthenticatedUsers`
- Cloud Run / Cloud Functions: `allUsers`/`allAuthenticatedUsers` bound in
  IAM (a plain invoker-only role is flagged at medium, since
  unauthenticated invocation is often an intentional public
  endpoint/webhook; a broader role bound publicly is flagged higher)
- GKE: public control plane with no `masterAuthorizedNetworks` restriction,
  legacy ABAC enabled, legacy static/basic-auth credentials configured

**Azure** (Storage, Network, SQL, Key Vault, App Service, Container
Registry, AKS):
- Storage accounts: public blob access allowed at the account level *and*
  per-container `publicAccess != None`, HTTP traffic allowed, outdated
  minimum TLS version
- NSGs: inbound `Allow` rules from a public source on all ports, on
  sensitive ports, or on any other port — skipped (and instead reported as
  a single low-severity housekeeping note) when the NSG isn't associated
  with any subnet or NIC, since an unattached NSG can't expose anything
- SQL servers: firewall rules spanning the entire IPv4 space, or unusually
  broad ranges (now informational/low severity, since a large-but-bounded
  range can be a legitimate corporate VPN block — the standard "Allow
  Azure services" `0.0.0.0`-`0.0.0.0` marker rule is still recognized and
  skipped)
- Key Vault: public network access not restricted, purge protection
  disabled
- App Service / Function App: `httpsOnly` disabled
- Container Registry: admin user enabled, public network access allowed
- AKS: Kubernetes RBAC disabled, local (non-Azure AD) accounts allowed,
  public API server with no authorized IP ranges configured

Every finding includes a severity, a machine-readable `action` code (for
tooling/auto-remediation integrations), the affected resource, a
plain-language description, a concrete remediation command, and a
compliance framework mapping (see [Compliance Framework Mapping](#compliance-framework-mapping)).

EC2 (`DescribeSecurityGroups`/`DescribeInstances`/`DescribeFlowLogs`/
`DescribeVolumes`) and RDS (`DescribeDBInstances`/`DescribeDBSnapshots`)
list calls are fully paginated, so accounts with more than one page's
worth of resources (~100 security groups/instances) are scanned
completely rather than silently truncated. Per-bucket/per-user/per-region
work runs with bounded concurrency (see `lib/concurrency.js`) instead
of one item at a time.

---

## Compliance Framework Mapping

Every finding, from all three providers, is mapped onto industry compliance/security frameworks by default — no separate flag needed, and included in both the JSON and HTML report.

Each finding's `check` id (e.g. `s3-acl-public`, `iam-no-password-policy`) resolves to one or more internal risk categories — `public_exposure`, `iam_misconfiguration`, `cryptography`, `logging_monitoring`, `data_protection_resilience`, or `security_misconfiguration` — and each category carries a fixed list of framework control references: **OWASP Top 10 (2021)**, **PCI DSS v4.0**, **NIST SP 800-53 Rev. 5**, **SOC 2**, **ISO/IEC 27001:2022**, **GDPR**, and **CIS Controls v8**. As with the SCA module's [Compliance Framework Mapping](../sca/README.md#compliance-framework-mapping) (shared engine, same category system), this is best-effort guidance derived from public framework documentation, not a certified compliance assessment — every report's `compliance_summary.disclaimer` field says so verbatim.

Each finding gets a `compliance` object:

```json
{
  "check": "s3-acl-public",
  "compliance": {
    "categories": ["public_exposure"],
    "frameworks": [
      { "id": "owasp_top10_2021", "name": "OWASP Top 10 (2021)", "controls": [{ "id": "A01:2021 / A05:2021", "title": "Broken Access Control / Security Misconfiguration" }] }
    ]
  }
}
```

The top-level `compliance_summary` field (same shape as the SCA module's — see its README for the full example) aggregates every finding in the report into per-framework, per-control finding counts. In the HTML report this powers a dedicated Compliance tab (one card per framework) plus a Compliance Frameworks section in each finding's detail modal. There's no SARIF output for this module (see [Reports](#reports) below) — compliance data is JSON + HTML only.

---

## Setup

### AWS credentials

```
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
export AWS_SESSION_TOKEN=...        # optional, for temporary credentials
export AWS_REGIONS=us-east-1,eu-west-1   # optional — skips auto-discovery (see below)
```

or configure a profile in `~/.aws/credentials` / `~/.aws/config` and set
`AWS_PROFILE` (or pass `--profile`). Profiles that assume a role — a
`role_arn` + `source_profile` pair — are resolved automatically via STS
`AssumeRole`; `credential_source` (EC2/ECS instance-role-based base
credentials, rather than a `source_profile`) is not supported. A `region`
set in the active `~/.aws/config` profile is honored as a fallback (see
"Region resolution" below).

Minimum IAM permissions (read-only): `s3:ListAllMyBuckets`,
`s3:GetBucketLocation`, `s3:GetBucketAcl`, `s3:GetBucketPolicyStatus`,
`s3:GetBucketPublicAccessBlock`, `s3:GetEncryptionConfiguration`,
`s3:GetBucketVersioning`, `s3:GetBucketLogging`, `s3:ListBucket`,
`s3:GetObjectAcl`, `ec2:DescribeSecurityGroups`, `ec2:DescribeInstances`,
`ec2:DescribeVpcs`, `ec2:DescribeFlowLogs`, `ec2:DescribeVolumes`,
`ec2:GetEbsEncryptionByDefault`, `ec2:DescribeRegions` (only needed when
regions aren't given explicitly — see below), `iam:ListUsers`,
`iam:ListAccessKeys`, `iam:ListMFADevices`, `iam:GetLoginProfile`,
`iam:GetAccountPasswordPolicy`, `iam:ListPolicies`, `iam:GetPolicyVersion`,
`iam:ListGroups`, `iam:ListRoles`, `iam:ListUserPolicies`,
`iam:GetUserPolicy`, `iam:ListGroupPolicies`, `iam:GetGroupPolicy`,
`iam:ListRolePolicies`, `iam:GetRolePolicy`, `iam:ListAttachedGroupPolicies`,
`iam:ListAttachedRolePolicies`, `rds:DescribeDBInstances`,
`rds:DescribeDBSnapshots`, `rds:DescribeDBSnapshotAttributes`,
`cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus`,
`guardduty:ListDetectors`, `guardduty:GetDetector`, `sns:ListTopics`,
`sns:GetTopicAttributes`, `sqs:ListQueues`, `sqs:GetQueueAttributes`. The
AWS-managed `ReadOnlyAccess` / `SecurityAudit` policies both cover this. If
a chained profile is used, the target role's trust policy must also allow
the base credentials to assume it.

#### Region resolution

By default, AWS regions are auto-discovered via `DescribeRegions` — every
region actually enabled on the account is scanned, with no need to list
them out by hand. Precedence, highest first:

```
--regions <list>            (explicit CLI override)
        ↓
AWS_REGIONS / AWS_REGION / AWS_DEFAULT_REGION   (environment variables)
        ↓
`region` in the active ~/.aws/config profile
        ↓
DescribeRegions()           (otherwise, auto-discover enabled regions)
```

```
export AWS_REGIONS=us-east-1,eu-west-1   # optional — skips auto-discovery
```

or pass `--regions us-east-1,eu-west-1` on the command line, which takes
priority over `AWS_REGIONS` too. If `DescribeRegions` itself fails (e.g.
the credentials lack that permission), the scan falls back to `us-east-1`
with a warning rather than aborting.

### GCP credentials

```
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account-key.json
export GCP_PROJECT_ID=my-project     # optional, defaults to the key's project_id
```

`GOOGLE_APPLICATION_CREDENTIALS` accepts either a service-account key file
or the `authorized_user` JSON that `gcloud auth application-default login`
produces. If it's unset, credentials are resolved the same way
google-auth-library's Application Default Credentials does: gcloud's own
ADC file (`~/.config/gcloud/application_default_credentials.json`), then
the GCE/GKE/Cloud Run instance metadata server (workload identity) as a
last resort.

The service account (or attached workload identity) needs (read-only):
`roles/viewer` plus `roles/iam.securityReviewer` (for IAM policy reads),
`roles/cloudsql.viewer`, `roles/bigquery.metadataViewer`,
`roles/run.viewer`, `roles/cloudfunctions.viewer`,
`roles/container.viewer`, or equivalently `storage.buckets.list`,
`storage.buckets.getIamPolicy`, `compute.firewalls.list`,
`compute.instances.list`, `resourcemanager.projects.getIamPolicy`,
`cloudsql.instances.list`, `bigquery.datasets.get`,
`bigquery.datasets.getIamPolicy`, `run.services.list`,
`run.services.getIamPolicy`, `cloudfunctions.functions.list`,
`cloudfunctions.functions.getIamPolicy`, `container.clusters.list`.

### Azure credentials

```
export AZURE_TENANT_ID=...
export AZURE_CLIENT_ID=...
export AZURE_CLIENT_SECRET=...
export AZURE_SUBSCRIPTION_ID=...
```

Create a service principal with the built-in `Reader` role on the
subscription: `az ad sp create-for-rbac --role Reader --scopes /subscriptions/<sub-id>`.

`AZURE_SUBSCRIPTION_ID` is always required. If `AZURE_TENANT_ID` /
`AZURE_CLIENT_ID` / `AZURE_CLIENT_SECRET` aren't all set, a managed
identity is used instead, via the Azure Instance Metadata Service (only
reachable when actually running on an Azure VM/VMSS/App
Service/Container App with an identity attached) — set `AZURE_CLIENT_ID`
alone (with no secret) to select a specific user-assigned identity, or
leave it unset for the system-assigned one. Client-certificate auth is not
supported — see "Known limitations".

---

## Usage

```bash
ubel-cloud                                             # all three providers, always writes JSON + HTML
ubel-cloud --provider aws                              # AWS only
ubel-cloud --regions us-east-1,us-west-2,eu-west-1     # skip DescribeRegions auto-discovery
ubel-cloud --working-dir /path/to/project --verbose    # reports written under <path>/.ubel/ instead of cwd
ubel-cloud --profile prod-readonly                     # use an ~/.aws/credentials profile
ubel-cloud --min-severity high                         # only report high/critical findings
ubel-cloud --fail-on high                              # non-zero exit on high or critical (default: critical)
ubel-cloud --fail-on 5:high                            # non-zero exit only once MORE than 5 high-or-above findings exist
ubel-cloud --fail-on none                              # always exit 0 (reports are still written)
ubel-cloud --quiet                                     # suppress the console summary; reports still written
ubel-cloud --help
```

Any provider whose credentials aren't set is skipped with a warning rather
than aborting the whole scan, so you can run this incrementally.

Every run always writes both JSON and HTML — there's no `--format` flag,
and no CSV or SARIF output. There's also no `--output` path flag: report
paths are fixed, under `.ubel/`, the same convention the SCA and SAST
modules use (see [Reports](#reports) below) — `--working-dir` only changes
which directory that `.ubel/` lives under, defaulting to the current
directory.

Exit code is `2` if the `--fail-on` condition is met (default: any finding
at `critical` severity; pass `--fail-on none` to always exit `0`, or
`--fail-on <count>:<severity>` — e.g. `5:high` — to fail only once MORE
than `<count>` findings at or above `<severity>` exist, for a CI gate that
tolerates a known/accepted baseline instead of an all-or-nothing
threshold), `0` otherwise, `1` on a fatal/unexpected error.

---

## Reports

Every run writes:

```
.ubel/reports/latest.cloud.json     ← always current
.ubel/reports/latest.cloud.html     ← always current

.ubel/local/reports/cloud/<YYYY>/<MM>/<DD>/
    cloud__<timestamp>.zip
```

No SARIF and no SBOM — this isn't a dependency scan, so neither format applies.

The HTML report is fully self-contained (no server required) and includes:

- Dashboard with severity, provider, and per-service breakdown charts
- Searchable, filterable findings table (free-text search plus severity and provider filters)
- Per-finding detail modal (resource, region, description, remediation command, compliance framework mapping)
- Dedicated Compliance tab — one card per framework, showing which controls this run's findings touch and how often (see [Compliance Framework Mapping](#compliance-framework-mapping))
- Scan Info tab (tool version, generated-at timestamp, providers and regions scanned)

The JSON report is the full machine-readable equivalent — `stats`, `compliance_summary`, and the complete `findings` array — and can be consumed by CI/CD tooling directly.

---

## Programmatic API

`cloud/index.js` exports `main` and `parseArgs` for scripting or CI wrappers that need argv control beyond what the `ubel-cloud` binary exposes:

```js
import { main } from "../cloud/index.js";   // relative path within the ubel-node package tree

process.argv = ['node', 'ubel-cloud', '--provider', 'aws', '--fail-on', 'high'];
await main();
```

Unlike the SCA and SAST modules, this isn't yet wired into `package.json`'s
`exports` map (only `./sca` and `./sast` are) — so `import { main } from
"@arcane-spark/ubel-node/cloud"` doesn't resolve from an external package
today. `main()` is reachable via a relative import within the installed
package's own file tree, or simply by invoking the `ubel-cloud` binary
directly, which is the supported path for CI and scripting alike.

---

## CI/CD Integration

`ubel-cloud` exits non-zero on findings that clear the configured
`--fail-on` bar, making it native to any CI runner:

```yaml
# GitHub Actions
- name: UBEL cloud misconfiguration scan
  run: ubel-cloud --fail-on high
  env:
    AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
    AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
```

```dockerfile
# Dockerfile
RUN ubel-cloud --fail-on high
```

Credentials are read from the environment at scan time only — nothing is
written to disk or reused between runs, so there's nothing extra to clean
up in a CI job or container layer.

---

## Known limitations / natural next steps

- AWS `credential_source` (deriving a role's base credentials from
  EC2/ECS instance metadata rather than a `source_profile`) isn't
  supported — only the `source_profile` chaining form is.
- Azure client-certificate authentication isn't supported — only client
  secret and managed identity. Full workload-identity-federation-style
  external OIDC token exchange (AWS/GCP-issued tokens exchanged for cloud
  credentials without any long-lived secret) also isn't implemented for
  any of the three providers, beyond each cloud's own native
  instance/workload identity (EC2 role via `source_profile`+STS isn't
  automatic — see above; GCE/GKE metadata server; Azure managed identity).
- S3 object-level public-ACL checking is a bounded *sample*, not an
  exhaustive per-object scan — see "What it checks". A full scan would
  need to page through every object in every bucket, which doesn't scale
  for buckets with millions of objects. The sample fans out across
  several `start-after` anchors spread through the key space (simple
  prefix sharding) rather than only ever reading the lexicographically-
  first page, so it's no longer biased toward whichever prefix happens
  to sort first — but it's still a spot-check, not a guarantee, for any
  bucket bigger than the sample budget.
- GCP KMS key rotation and default Compute Engine disk encryption checks
  are not implemented. Both would need per-location API fan-out (Cloud
  KMS keys and, less usefully, disks are already encrypted by default —
  the interesting signal is customer-managed key usage) that didn't seem
  worth the added scan time/noise relative to the checks that are in
  (Cloud SQL, BigQuery, Cloud Run/Functions, GKE) — worth revisiting if
  CMEK usage becomes a requirement to track.
- A handful of other checks were deliberately left out as lower-signal or
  higher-effort than what's already covered, rather than missed: AWS
  Config recorder status, Security Hub enabled, Lambda resource-policy
  `Principal: "*"` (the SNS/SQS equivalent exists; Lambda uses a REST API
  shape that would need its own client wrapper), and KMS key rotation.
  Worth adding if a specific audit needs them.
- S3 bucket names containing dots use virtual-hosted-style addressing
  (`bucket.name.s3.region.amazonaws.com`), which can hit TLS SNI mismatches
  for such buckets. Fall back to path-style addressing for those.
- GCP zones aren't auto-discovered — Compute already relies on GCP's
  project-wide aggregated APIs, so this only matters if per-zone scanning
  is ever needed. AWS regions *are* auto-discovered now (via
  `DescribeRegions`), with `--regions`/`AWS_REGIONS` as an override.
- Findings are point-in-time; there's no diffing between scan runs yet.
- No SARIF output — findings don't currently plug into code-scanning
  dashboards (GitHub Advanced Security, etc.) the way the SCA and SAST
  modules' reports do; JSON + HTML only for now.
- `lib/history.js` and `lib/sca-path.js` are present in the codebase but
  not on the active report-writing path — `index.js`'s own
  `writeCloudReports()` writes reports directly under `.ubel/` (see
  [Reports](#reports)) and imports `sca`'s zip writer itself, rather than
  going through `history.js`. Worth removing or reconnecting one of the
  two rather than leaving both in place.

---

## Quick-start examples

```bash
# Scan whichever providers you have credentials for
ubel-cloud

# AWS only, explicit region list
ubel-cloud --provider aws --regions us-east-1,eu-west-1

# Only fail the build on high-or-above findings
ubel-cloud --fail-on high

# CI gate that tolerates a baseline of 5 known high-severity findings
ubel-cloud --fail-on 5:high

# Report only, never fail the build
ubel-cloud --fail-on none

# Quiet mode for CI logs, only critical+ findings reported
ubel-cloud --quiet --min-severity critical

# Use a named AWS profile instead of environment-variable credentials
ubel-cloud --provider aws --profile prod-readonly
```

---

*Ubel — Find the misconfiguration before an attacker does.*
