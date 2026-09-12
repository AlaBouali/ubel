# UBEL — Node.js

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, and AI-powered source-level scanning ( SAST ) .**

UBEL is a zero-dependency, source-available application security toolkit. This package (`@arcane-spark/ubel-node`) ships multiple CLIs for dependency-security and source-level scanner:

- **SCA** — resolves your dependency tree (and, in full-stack mode, other ecosystems present in the repo) and scans it against OSV.dev and NVD **in real time, on every scan** — not from a periodically-synced local database — with heuristic reachability analysis, SBOM (CycloneDX v1.6), and SARIF output. Both endpoints can be pointed at internal mirrors via `UBEL_OSV_ENDPOINT`/`UBEL_NVD_ENDPOINT` for air-gapped deployments (see [node/sca/README.md](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#environment-variables)). This is the audit/reporting side — `health` mode reads what's already installed.
- **Firewall** — a distinct mode of the same CLI (`check` / `install`) that gates the install itself before anything touches `node_modules`, `pnpm`'s store, `bun`'s install path, or Composer's `vendor/` directory, with atomic lockfile revert on violation and SHA-256 TOCTOU checks between scan and install. The same pull → scan → keep-or-remove pattern also gates **Docker images** (`ubel-docker install <image>`) before you run them. **Also included in this same package:** `ubel-pip`/`ubel-uv`/`ubel-pipx` gate `pip`/`uv` installs and isolated CLI-tool installs behind a dry-run resolution, and `ubel-apt`/`ubel-dnf`/`ubel-yum` (one binary per package manager, same as npm/pnpm/bun) gate `apt`/`dnf`/`yum` installs behind each one's own native dry-run — neither has a lockfile to revert, so a rejected scan simply never runs the real install rather than reverting one.
- **Secrets Detection** — built on Trivy's ported, Apache-2.0-attributed secret-scanning ruleset (see [NOTICE](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault tokens, GCP API keys and OAuth tokens, Anthropic and OpenRouter keys, Stripe restricted keys, Twilio Account/App SIDs, and URL-embedded git credentials, among others). Runs standalone via `ubel-secrets`, or as part of any SCA/firewall scan.
- **License Compliance** — every scanned package's declared license (SPDX id, free text like "Apache 2.0", npm's `UNLICENSED` proprietary sentinel, a Python trove classifier, an SPDX `OR`/`AND` expression, or missing entirely) is normalized and checked against the OSI-approved license list, with a derived risk rating (permissive / weak-copyleft / strong-copyleft / proprietary / unknown). Included in every SCA/firewall scan by default — surfaced per-package in the HTML report, as license properties on every SBOM component, and as a dedicated SARIF run. Runs standalone via `ubel-license` — inventory + license classification only, no OSV/NVD vulnerability lookups, no secrets scan.
- **Compliance Framework Mapping** — every finding across SCA (vulnerabilities, secrets), SAST (vulnerability and malicious-code findings), and Cloud (misconfigurations) is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, via one shared mapping engine so the same underlying risk maps identically regardless of which module found it. Included by default in every scan, with a report-level per-framework/per-control finding-count summary, across JSON, HTML, and SARIF (where the module emits SARIF). Best-effort guidance, not a certified compliance assessment — see the per-module docs for the full framework list and the disclaimer carried in every report.
- **SAST / Malicious-Code Scanner** — a separate module: an LLM-powered pipeline (**scan → verify → taint-trace**) that reads your actual source code, cross-references a structured CWE-mapped vulnerability catalog, and separately screens for intentionally malicious code (backdoors, C2 beacons, supply-chain implants). It also scans IaC, Docker, and Kubernetes manifest files — each as its own dedicated language family, not lumped together.
- **Cloud** — scans your AWS, GCP, and Azure accounts directly via each provider's own read-only API (live account state, not static IaC files) for misconfigurations: public storage/database/network exposure, over-permissive IAM and cluster (AKS/GKE) authorization, missing encryption, and disabled audit logging (CloudTrail/GuardDuty/VPC flow logs). Runs via `ubel-cloud`. See [node/cloud/README.md](https://github.com/AlaBouali/ubel/blob/main/node/cloud/README.md).

Everything runs on your own infrastructure: no source code egress, no credentials required beyond your chosen LLM provider's API key (SAST only), no telemetry.

---

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

This installs the binaries for the SCA/firewall CLI, the SAST module, and the cloud scanner:

| Binary | Covers | What it does |
|---|---|---|
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` | SCA + Firewall | Same binary, mode-dependent: `health` = SCA scan of installed deps; `check`/`install` = firewall gate on a lockfile dry-run |
| `ubel-composer` | SCA + Firewall | `health` = SCA scan of `vendor/`/`composer.lock`; `check`/`install` = firewall gate on a `composer require`/`update --no-install --no-scripts` dry-run, same lockfile-backed shape as npm/pnpm/bun |
| `ubel-pip` / `ubel-pipx` | SCA + Firewall | `health` = SCA scan of a venv's installed packages; `check`/`install` = firewall gate on a `pip install --dry-run` resolution. `ubel-pipx` additionally installs CLI tools into isolated, managed per-tool venvs with a global shim, reducing blast radius the way `pipx` itself does |
| `ubel-uv` | SCA + Firewall | Same `health`/`check`/`install` split as `ubel-pip`, but targeting a uv-native venv (`uv init --bare` + `uv venv`, not a stdlib one) — the real install always still runs as `uv pip install -r <generated, exact-pinned file>`, same as pip; dry-run uses `uv pip install --dry-run` internally, which (unlike pip's JSON report) yields no dependency-graph data — see the Python section below. A real `install` on either engine also syncs any existing `requirements.txt`/`pyproject.toml` to the now-installed versions |
| `ubel-apt` / `ubel-dnf` / `ubel-yum` | SCA + Firewall | Same `health`/`check`/`install` split, one binary per native package manager (no auto-detection between them, same as npm/pnpm/bun). Reports and policy live under `~/.ubel/local` so routine use never needs `sudo` — only the real package-manager install does |
| `ubel-docker` | SCA + Firewall | Scans a container image without running it; `install` mode pulls, scans, and removes the image on a policy violation |
| `ubel-secrets` | Secrets | Standalone secrets-only scan of the target directory — no dependency resolution, no LLM calls |
| `ubel-license` | SCA | Standalone inventory + license-compliance scan — no vulnerability lookups (OSV/NVD), no secrets scan |
| `ubel-agent` | SCA | AI-agent workspace scan (OS, runtimes, tools, dependencies) |
| `ubel-cicd` | SCA | Post-install CI/CD scan of the final built workspace (OS, runtimes, tools, dependencies) |
| `ubel-platform` | SCA | Host platform scan (OS, runtimes, tools) |
| `ubel-sast` | SAST | Static analysis for accidental vulnerabilities (injection, XSS, insecure deserialization, hardcoded secrets, …) |
| `ubel-mal` | SAST | Malicious-code scan for intentional backdoors, C2 implants, exfiltration, persistence |
| `ubel-chunk` | SAST | Free, LLM-cost-free utility to preview how a codebase will be chunked |
| `ubel-cloud` | Cloud | Live AWS/GCP/Azure account scan via each provider's own API for misconfigurations — public exposure, IAM, encryption, audit logging — not a static IaC/manifest scan |

`ubel-pip`/`ubel-uv`/`ubel-pipx` additionally need a `python3`/`python` interpreter on `PATH` (to create their venv); Node.js itself can't provision one. `ubel-uv` additionally needs the `uv` binary itself on `PATH`, separate from Python — same one-binary-per-tool requirement as `ubel-pnpm` needing `pnpm`. `ubel-composer` additionally needs the `composer` binary itself on `PATH`, same one-binary-per-tool requirement.

Node.js `>=18.0.0` required.

---

## SCA — Dependency Vulnerability Scanning

Resolves dependencies (with PURL generation), scans them against OSV.dev and NVD, and annotates each finding with a heuristic **reachability** verdict (package type, scope, dependency depth, attack vector, and optional source-level import-scan confirmation). Malicious-package advisories (`MAL-*`) are always flagged. Output: JSON, HTML, CycloneDX v1.6 SBOM, and SARIF 2.1.0 reports.

```bash
# Audit the currently installed dependency graph — no install, no lockfile mutation
ubel-npm health
ubel-pnpm health
ubel-bun health
ubel-composer health
```

`health` mode also supports full-stack monorepo scanning (Python, PHP, Rust, Go, .NET, Java, Ruby alongside Node) and host/platform scanning (Linux package managers, Windows registry) when invoked programmatically.

**yarn** is supported in `health` mode only — it can't do a lockfile-only dry-run, so it has no firewall coverage below.

## Firewall — Install-Time Gate

A distinct mode of the same `ubel-npm` / `ubel-pnpm` / `ubel-bun` binaries: before any real install, a lockfile-only dry-run (`--package-lock-only` / `--lockfile-only`) resolves the candidate tree without touching `node_modules`, scans it, and either proceeds or reverts the lockfile from its on-disk backup. Pre/post-install scripts are always blocked (`--ignore-scripts`) during this phase. A SHA-256 check re-verifies the lockfile and `package.json` immediately before the real install, closing the TOCTOU window between scan and install.

The same block-before-you-touch-it pattern applies to `ubel-docker`: `install` mode pulls the image, extracts its filesystem without ever running it (`docker create` + in-process tar extraction, no shell `tar`, no `ENTRYPOINT`/`CMD` execution), scans it, and removes the image again if policy blocks it.

`ubel-composer` extends the same lockfile-backed pattern npm/pnpm/bun use to PHP: `composer require`/`update --no-install --no-scripts` (Composer's own equivalent of `--package-lock-only`) resolves the candidate tree and writes a candidate `composer.lock`/`composer.json` without touching `vendor/`, UBEL scans that candidate, and either proceeds via `composer install --no-scripts` or reverts both files from their on-disk backup — the same SHA-256 TOCTOU check and atomic revert as npm/pnpm/bun, just against Composer's own files. Unlike pip's dry-run below, this has no sdist-style caveat: resolving a Composer dependency graph never runs a package's own code, since build/lifecycle scripts only fire on a real `composer install`/`update`, which is exactly why `--no-scripts` covers both the dry-run and the real install.

`ubel-pip`/`ubel-uv`/`ubel-pipx` extend the same before-you-touch-it approach to Python: `pip install --dry-run --report` (pip) or `uv pip install --dry-run` (uv) resolves the candidate set — including transitive dependencies — without installing anything, UBEL scans that resolution, and only then runs the real install (`pip install -r` / `uv pip install -r` against the same generated, exact-pinned file either way). A successful real install additionally syncs any `requirements.txt`/`pyproject.toml` already sitting in the project directory to the versions that actually got installed — see the Python section further down for exactly what that does and doesn't touch. There's no lockfile here, so there's nothing to revert — a blocked scan just means the real install never runs. One caveat worth being upfront about, and it applies to both installers equally since it's inherent to how Python packaging resolution works: resolving a package's metadata can still need to build an sdist when no pre-built wheel is available, and building an sdist can execute arbitrary `setup.py`/build-backend code — a wheel-only install has no such gap, but a source-only package does carry it. `ubel-apt`/`ubel-dnf`/`ubel-yum` mirror this for Linux host packages — three separate binaries, each bound to exactly one package manager's own native dry-run (`apt-get -s`, `dnf --assumeno`, `yum --assumeno` respectively, no auto-detection between them); their reports and policy live under `~/.ubel/local` so ordinary use never needs `sudo` — only the real install does.

```bash

# examples

# Dry-run only — scan and exit, nothing installed
ubel-npm check lodash express

# Scan-gated real install — proceeds only if policy allows
ubel-npm install lodash@4.17.21

# install current project
ubel-pnpm install

# check the current project

ubel-bun check

# pull, scan, and keep or remove a Docker image based on policy
ubel-docker install node:20-alpine

# PHP: dry-run scan, then a scan-gated real install
ubel-composer check monolog/monolog
ubel-composer install monolog/monolog:^3.0
ubel-composer install                  # no args → resolves from existing composer.lock

# Python: dry-run scan, then a scan-gated real install into ./venv
ubel-pip check requests==2.31.0
ubel-pip install requests==2.31.0
ubel-pip install                       # no args → falls back to ./requirements.txt, then ./pyproject.toml

# Same, driven by uv instead of pip
ubel-uv check requests==2.31.0
ubel-uv install requests==2.31.0

# Python CLI tool: scan-gated install into an isolated venv + global shim
ubel-pipx install black

# Linux packages: dry-run scan, then a scan-gated `sudo apt install`
ubel-apt check curl
ubel-apt install curl
# (ubel-dnf / ubel-yum work the same way, against dnf/yum instead)
```

Policy (severity threshold, unknown-severity blocking) is configurable via `ubel-npm threshold <level>` and `ubel-npm block-unknown <bool>` (same subcommands under `ubel-composer`/`ubel-pip`/`ubel-uv`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum`); malicious-package advisories are always blocked regardless of policy. License-risk policy (`license-risk`, `license-block-unknown`) is npm-family-only (npm/pnpm/bun/composer) — it isn't exposed as a subcommand on `ubel-pip`/`ubel-uv`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum`, matching those CLIs' narrower mode set.

**Exit codes:** `check` and `install` exit `0` if policy passes, `1` if policy blocks or the scan itself fails — a failed scan is never treated as a pass.

**Full documentation — every mode, policy config, reachability decision ladder, and programmatic API:**
[**node/sca/README.md**](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md)

---

## Fixed-Configuration Scan CLIs

`ubel-agent`, `ubel-cicd`, and `ubel-platform` wrap the same `health`-mode scan engine as `ubel-npm health`, each with a fixed option set for one deployment context — no `<engine> <mode>` arguments, just an optional target path. All three print the full JSON report to stdout and exit `1` on a policy block.

```bash
# AI-agent sandbox workspace — OS packages + every app ecosystem present
ubel-agent /path/to/agent/workspace

# Post-build CI/CD scan of the final built workspace
ubel-cicd /path/to/build/output

# Host/developer-machine scan — OS packages and dev tools/runtimes only,
# no application dependency resolution. Defaults to the home directory.
ubel-platform
```

**Full documentation — exact flags per binary and how they differ from `ubel-secrets`/`ubel-license`:**
[**node/sca/README.md#fixed-configuration-scan-clis**](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#fixed-configuration-scan-clis)

---

## Secrets Detection

Built on Trivy's ported secret-scanning ruleset (Apache-2.0, attributed in [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/NOTICE)), extended with rules for vendors not yet covered by Trivy's current upstream ruleset: HashiCorp Vault tokens, Google Cloud API keys and OAuth tokens, Anthropic and OpenRouter API keys, Firebase tokens, Stripe restricted keys, Twilio Account/App SIDs, Square and Braintree credentials, and URL-embedded git credentials. Match previews in every report are redacted — the raw secret value is never written to disk.

```bash
# Standalone secrets-only scan — no dependency resolution, no LLM calls
ubel-secrets /path/to/project
```

Secrets findings are also included in every SCA/firewall scan by default, surfaced in a dedicated tab in the HTML report and as a schema-correct extension on both the SBOM (a `ubel:secrets` property, since CycloneDX's root schema doesn't permit arbitrary top-level keys) and the SARIF output (its own `run`, separate from the dependency-vulnerability run).

---

## License Compliance

Every scanned package's declared license — whatever form it arrives in (an SPDX id, free text like "Apache 2.0", npm's `UNLICENSED` proprietary sentinel, a Python trove classifier, an `OR`/`AND` SPDX expression, or missing entirely) — is normalized into a canonical SPDX identifier, checked against the OSI-approved license list, and assigned a risk rating (`low` / `medium` / `high` / `unknown`) based on license category (permissive, weak-copyleft, strong-copyleft, proprietary, public-domain, unrecognized). Included in every SCA/firewall scan by default.

```bash
# Standalone inventory + license scan — resolves dependencies (full-stack,
# every ecosystem present in the repo) and classifies licenses only; no
# OSV/NVD calls, no secrets scan. Same JSON, HTML, CycloneDX SBOM, and
# SARIF 2.1.0 outputs as any other SCA scan.
ubel-license /path/to/project
```

Surfaced per-package in the HTML report's inventory table and detail view, as `license.osi_approved` / `license.risk` / `license.category` properties on every SBOM component, and as its own SARIF run (`ubel-license-compliance`) that flags any non-OSI-approved or high-risk license as a finding.

**Full documentation:** [node/sca/README.md#license-compliance](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#license-compliance)

---

## Compliance Framework Mapping

Every finding produced anywhere in UBEL — SCA vulnerabilities and secrets, SAST vulnerability and malicious-code findings, and Cloud misconfigurations — is mapped onto industry compliance/security frameworks by default, no separate flag needed. All three modules share one mapping engine (`sca/compliance_mappings.js`): a finding is assigned one or more internal risk categories (e.g. `injection`, `public_exposure`, `vulnerable_components`), and each category carries a fixed list of framework control references, so the same underlying risk maps identically whether it was found by the dependency scanner, the AI SAST pipeline, or the cloud scanner.

**Frameworks:** OWASP Top 10 (2021), PCI DSS v4.0, HIPAA Security Rule, SOC 2 (Trust Services Criteria), ISO/IEC 27001:2022 (Annex A), NIST SP 800-53 Rev. 5, GDPR, and CIS Controls v8.

Every finding gets a `compliance` object (categories + per-framework control list); every report gets a top-level `compliance_summary` aggregating all findings into per-framework/per-control finding counts. Surfaced in a dedicated Compliance tab in every module's HTML report, in the JSON report's `compliance`/`compliance_summary` fields, and — for SCA and SAST, which emit SARIF — as `compliance`/`compliance_categories`/`compliance_frameworks` properties on SARIF rules and results.

**This is best-effort guidance, not a certified compliance assessment** — control identifiers are the stable, publicly documented ones for each framework, but framework text, versioning, and applicable scope can change and depend on your own environment. Every report carries this disclaimer verbatim in `compliance_summary.disclaimer`.

**Full documentation:** [node/sca/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#compliance-framework-mapping) (canonical framework/category reference) · [node/sast/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md#compliance-framework-mapping) · [node/cloud/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/node/cloud/README.md#compliance-framework-mapping)

---

## SAST — AI-Powered Static Analysis & Malicious Code Scanner

Chunks your codebase into semantically-bounded units (11 language families, including Docker, IaC, and Kubernetes manifests as their own dedicated families) and runs a three-pass LLM pipeline — **scan → verify → taint trace** — cross-referenced against a 59-class CWE-mapped vulnerability catalog. A fully separate 15-class malicious-code catalog covers intentionally planted backdoors and implants; that scan (`ubel-mal`) stops after **scan → verify**, since reachability isn't the relevant question for code that's itself the payload. Outputs JSON, interactive HTML, and SARIF 2.1.0 reports, ready for CI/CD gating.

```bash
# Vulnerability scan
ubel-sast /path/to/project

# Malicious-code / backdoor scan
ubel-mal /path/to/project

# Free preview of how a codebase will be chunked, no LLM calls
ubel-chunk /path/to/project
```

Supports OpenRouter, OpenAI, Anthropic, Gemini, DeepSeek, NVIDIA, local/Docker-hosted (Ollama-compatible), and fully custom endpoints — selectable per run, no code changes.

**Exit codes:** governed by `--fail-on`, which only changes the process exit code — reports on disk always contain every finding regardless of this flag.
- `ubel-sast` (`analyze`): `any` *(default)* fails on any finding, including unresolved ones; `valid` fails only on findings verified `is_valid: true`; `exploitable` fails only on findings taint-traced `exploitable: true`.
- `ubel-mal` (`malware`): `any` *(default)* fails on any finding, including unresolved ones; `confirmed` fails only on findings verified `is_valid: true` — an unresolved finding still fails the build, since "couldn't determine" is never treated as clean.

**Full documentation — pipeline mechanics, every flag, token-cost breakdown, and CI examples:**
[**node/sast/README.md**](https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md)

---

## Cloud — AWS / GCP / Azure Misconfiguration Scanning

Scans your AWS, GCP, and Azure accounts directly via each provider's own read-only API — live account state, not a static IaC/manifest scan, and nothing is deployed or modified. Covers public storage/database/network exposure (S3/GCS/Storage buckets, RDS/Cloud SQL/Azure SQL, security groups/NSGs/firewall rules open to the internet), IAM posture (overly permissive policies, missing MFA, stale access keys, permissive trust policies), Kubernetes cluster authorization (GKE/AKS control-plane exposure, RBAC/ABAC, legacy auth), missing encryption (EBS, RDS, CloudTrail, storage accounts), and disabled audit logging (CloudTrail, GuardDuty, VPC flow logs). Credentials are only ever used for that run — nothing stored or reused, same model as SAST's LLM credentials.

```bash
# Scan whichever providers you have credentials for (default: aws,gcp,azure)
ubel-cloud

# Scan a specific provider only
ubel-cloud --provider aws

# Explicit AWS region override — skips DescribeRegions auto-discovery
ubel-cloud --provider aws --regions us-east-1,eu-west-1
```

Outputs JSON and HTML (no SARIF, no SBOM — this isn't a dependency scan). **Exit codes:** governed by `--fail-on` (default `critical`), same severity-threshold/count syntax as the rest of UBEL — reports on disk always contain every finding regardless of this flag.

**Full documentation — every check, per-provider credential setup, and all flags:**
[**node/cloud/README.md**](https://github.com/AlaBouali/ubel/blob/main/node/cloud/README.md)

---

## CI/CD Integration

All binaries exit non-zero on findings that clear their respective gate, so any of them fit natively into a CI runner.

### GitHub Actions — using the packaged action

[`action.yml`](https://github.com/AlaBouali/ubel/blob/main/action.yml) wraps `npx @arcane-spark/ubel-node@<version>` as a composite action, behind an explicit `command` allow-list validated against UBEL's actual registered `package.json` bin names — so it can never construct or execute a binary name that isn't one of ours, regardless of what a caller passes. `command`, `version`, and `args` are step inputs referenced as shell variables (`$COMMAND`/`$ARGS`), never interpolated directly into the script with `${{ }}`, closing off GitHub's documented script-injection risk for composite actions.

```yaml
- uses: AlaBouali/ubel@<commit-sha>   # pin to a commit SHA, not a mutable tag
  with:
    command: npm
    version: 0.8.0
    args: check

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: npm                      # `command` selects the bin; the mode (check/install/health) goes in `args`
    version: 0.8.0
    args: install

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: sast
    args: --fail-on exploitable

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: mal
    args: --fail-on confirmed

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: license                  # inventory + license compliance only — no OSV/NVD calls, no secrets scan

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: cloud
    args: --provider aws,gcp,azure --fail-on high

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: pip
    args: install                     # scan-gated `pip install`, resolved from ./requirements.txt

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: composer
    args: install                     # scan-gated `composer install --no-scripts`, resolved from composer.lock

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: apt                      # dnf/yum work the same way, as their own `command` values
    args: check curl
```

`command` must be one of: `sast`, `mal`, `chunk`, `cicd`, `agent`, `platform`, `secrets`, `license`, `cloud`, `npm`, `pnpm`, `bun`, `yarn`, `composer`, `docker`, `pip`, `pipx`, `uv`, `apt`, `dnf`, `yum` — anything else fails the step before `npx` ever runs.

### Calling the binaries directly

Equivalent, for self-hosted runners, non-GitHub CI, or a Dockerfile:

```yaml
# GitHub Actions
- name: UBEL dependency scan (SCA)
  run: ubel-npm check

- name: UBEL firewall-gated install
  run: ubel-npm install

- name: UBEL PHP firewall-gated install
  run: ubel-composer install

- name: UBEL SAST scan
  run: ubel-sast --fail-on exploitable

- name: UBEL malicious-code scan
  run: ubel-mal --fail-on confirmed

- name: UBEL license compliance scan
  run: ubel-license .

- name: UBEL cloud misconfiguration scan
  run: ubel-cloud --fail-on high
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-composer install
RUN ubel-sast --fail-on valid .
```
---
# UBEL — Capability Reference by Ecosystem, Language, and OS

This document details exactly what UBEL does — and doesn't do — for every
ecosystem it supports, across five capability axes:

- **SCA** — dependency inventory + vulnerability matching (OSV/NVD)
- **Firewall** — pre-install/pre-deploy blocking, not just after-the-fact reporting
- **SAST** — LLM-driven source/config vulnerability scanning
- **Malware SAST** — LLM-driven detection of intentionally malicious code
- **Secrets** — hardcoded credential detection
- **License compliance** — SPDX normalization + OSI/risk classification
- **Compliant outputs** — SARIF, CycloneDX SBOM, JSON, HTML

A quick note before the detail: **Firewall and SCA are not the same capability
everywhere.** SCA (health scanning) works on anything UBEL can resolve a
dependency tree for. Firewall (blocking a bad install *before* it lands)
only exists where a package manager supports some form of dry-run
resolution with no (or, for pip/uv, no *typical*) side effects — today
that's **npm, pnpm, bun, and Docker images** via a true lockfile-only
dry-run, **PHP (Composer)** via the same lockfile-backed mechanism
(`composer require`/`update --no-install --no-scripts`), plus **pip/uv/pipx**
(`pip install --dry-run` / `uv pip install --dry-run`) and **Linux host
packages** (`apt`/`dnf`/`yum`'s own native dry-run). Ruby, Rust, Go,
Java/Kotlin, C#, and Windows remain SCA-covered but not firewall-covered
below — their package managers genuinely have no dry-run-without-side-effects
equivalent to gate against, which is a mechanical constraint of each
ecosystem's tooling, not an oversight.

---

## Capability Matrix

| Ecosystem | SCA | Firewall | SAST | Malware SAST | Reachability | License Compliance | Secrets |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Node.js (npm/pnpm/bun) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node.js (yarn) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python (pip/uv/pipx/venv) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP (Composer) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby (Bundler) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust (Cargo) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go (modules) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Java / Kotlin (Maven) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C# / .NET (NuGet) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Docker images | ✅ (OS + app deps) | ✅ | — | — | — | ✅ | ✅ (in image) |
| Kubernetes manifests | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Terraform / CloudFormation (IaC) | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Linux host (apt/dnf/yum) | ✅ | ✅ | — | — | — | ✅ | — |
| Windows host | ✅ | ❌ | — | — | — | ✅ | — |
| VS Code / Cursor / VSCodium extensions | ✅ | — | — | — | — | — | — |

✅ = built and shipped · ❌ = not currently possible/present for a stated reason · — = not applicable to that layer

Cloud account misconfiguration scanning (AWS/GCP/Azure, via `ubel-cloud`) isn't tied to a dependency ecosystem, so it doesn't have a row here — see the [Cloud section](#cloud--aws--gcp--azure-misconfiguration-scanning) above.

---

## Node.js — npm / pnpm / bun / yarn

**SCA:** Full lockfile parsing across npm v1/v2/v3, pnpm v5/v6/v9, yarn
classic and berry, and bun v0/v1. Dependency resolution walks the actual
installed `node_modules` tree in addition to the lockfile, so it reflects
what's really on disk, not just what the manifest declares. Scope
assignment (production / dev / environment) is computed via BFS
propagation from the manifest's declared dependency types down through the
full tree.

**Firewall:** One of the ecosystems (alongside Docker and PHP/Composer) with a **lockfile-backed**
pre-install gate — atomic revert and TOCTOU hashing depend on there being a
lockfile to revert *to*, which is specific to npm/pnpm/bun/Docker/Composer's
mechanics. `npm`, `pnpm`, and `bun` each support a lockfile-only dry run
(`--package-lock-only`, `--lockfile-only`, and a `node_modules`-untouched
equivalent respectively) — UBEL resolves what *would* be installed, scans
it against policy, and only proceeds if it's clean. TOCTOU is closed with
SHA-256 integrity checks on the lockfile and `package.json` before and after
resolution, and any policy-blocked change is rolled back atomically via
`revert_lock_to_original`. **Yarn is deliberately excluded from firewalling**
— not because UBEL doesn't support it, but because yarn itself has no
side-effect-free dry-run equivalent to hook into: `yarn add` always writes
to `node_modules` before you'd get a chance to block it. Yarn projects still
get full SCA, SAST, secrets, and license coverage — they just can't be
gated pre-install the way npm/pnpm/bun can, because yarn's own CLI doesn't
offer a resolution step that stops short of writing to disk. (Python and
Linux host packages also get a real pre-install gate now — see their
sections below — just via a simpler revert-less mechanism, since neither
has a lockfile to roll back.)

**SAST / Malware SAST:** Full three-pass (scan → verify → taint-trace)
vulnerability pipeline and two-pass malware pipeline, JS/TS-aware chunking.

**Reachability analysis:** Full import-graph reachability — a vulnerable
package is downgraded in priority if nothing in your code path actually
imports the vulnerable module, and orphaned/unused dependencies get
flagged separately. This is one of eight ecosystems with this capability
(see the Reachability Analysis note under Cross-Cutting Capabilities).

**Editor integration:** The VS Code/Cursor/VSCodium extension runs
in-process (no shell-out), with dedicated commands for project scan, host
scan, and — uniquely for this ecosystem — a scan of the **editor's own
installed extensions**, since a malicious VS Code extension is itself a
supply-chain vector most tools never consider.

---

## Python — pip / uv / pipx / venv

**SCA:** Resolves dependencies by walking virtual environment directories
directly (not just parsing `requirements.txt`), so it reflects the actual
installed environment, including transitive packages a manifest wouldn't
show on its own.

**Firewall:** Available via `ubel-pip`/`ubel-uv`/`ubel-pipx` — two
installers, same firewall shape, different dry-run mechanics under the
hood. `ubel-pip` uses `pip`'s own `install --dry-run --report` (pip ≥22.2)
to resolve the candidate set into a machine-readable report without
installing anything; `ubel-uv` uses `uv pip install --dry-run` instead (uv
has no equivalent JSON report — its output is a flat `+ name==version`
list on stderr, see the honesty note below for what that costs). UBEL
scans whichever resolution came back, and only then runs the real install
— `pip install -r` or `uv pip install -r`, always against the same
generated, exact-pinned requirements file either way. There's no lockfile
here, so there's no revert step the way npm/pnpm/bun have one: a
policy-blocked scan just means the real install never runs, nothing needs
rolling back. `ubel-pip`/`ubel-uv` `check`/`install` accept packages on the
command line, or fall back to `./requirements.txt`, then
`./pyproject.toml`'s `[project]` dependencies, when none are given. A
successful *real* (non-dry-run) `install` — either installer — also syncs
whichever of those two files already exists in the project directory to
match what's now actually installed: it's a re-run of the same scan
`health` mode already does, not a separate `pip freeze`/`uv pip freeze`.
Existing entries get their pinned version refreshed to the installed
version; anything newly installed but not yet listed gets appended; lines
for packages that *aren't* actually installed (comments, `-r`/`-e`/`-c`
directives, a spec that failed to resolve) are left alone. Neither file is
created if it doesn't already exist, and a sync failure is logged rather
than failing the install — the install itself already succeeded by that
point. `ubel-pipx` installs CLI tools into isolated, managed per-tool
virtual environments with a global shim on `PATH`, the same blast-radius
reduction `pipx` itself provides — now gated by the same pre-install scan;
there's no `uv tool install`-equivalent CLI isolation mode here, only
pip's. One more `uv`-specific difference: `ubel-uv init` (and the first
`check`/`install` that needs a venv) provisions it via uv's own `uv init
--bare` + `uv venv` rather than the stdlib `venv` module the other five
engines use — a real uv-recognized project (`pyproject.toml` present),
not just an interpreter uv happens to be pointed at via `--python`.

Two honesty notes, both of them limits of the underlying tools rather than
gaps in UBEL's own implementation:
- Unlike npm's lockfile dry-run, neither pip's nor uv's dry-run is
  unconditionally side-effect-free — if a candidate package has no
  pre-built wheel available, resolving its metadata can require building an
  sdist, and building an sdist can execute arbitrary `setup.py`/build-backend
  code. This is inherent to Python packaging resolution generally — how
  `pip`/`uv` themselves resolve source-only packages — not something a
  scan step layered on top of either tool could close off. Wheel-only
  installs (the common case) don't have this gap.
- `uv`-sourced scans carry less detail than `pip`-sourced ones in one
  respect, and it traces back to what `uv pip install --dry-run` itself
  exposes rather than a choice UBEL made: its output is a flat
  `+ name==version` list rather than a dependency-annotated report, so it
  carries no parent/child relationships — every uv-resolved component
  comes back as its own root with empty
  `introduced_by`/`parents`/`dependency_sequences`, unlike a pip-sourced
  scan (pip's `--dry-run --report` includes that provenance; uv's dry-run
  output simply doesn't). Vulnerability scanning itself is unaffected —
  that's purl-based, not graph-based — but dependency-provenance detail
  specifically is weaker for `uv` than for `pip` today. License data isn't
  part of this gap: license classification only ever runs on `health`-mode
  scans for every ecosystem UBEL supports, not just Python, so it's not
  something a `check`/`install` dry-run needs from any installer.

**SAST / Malware SAST:** Full coverage, same three-pass/two-pass pipelines.

**Reachability analysis:** Fully covered, tracking `.py` files against the
resolved dependency graph — one of eight ecosystems with this capability.

---

## PHP — Composer

**SCA:** Resolves the dependency tree from `vendor/` and `composer.lock`.

**Firewall:** Available via `ubel-composer` — the same lockfile-backed shape
as npm/pnpm/bun, not the simpler revert-less mechanism pip/apt/dnf/yum use.
`composer require`/`update --no-install --no-scripts` (Composer's own
equivalent of `--package-lock-only`) resolves the candidate dependency tree
and writes a candidate `composer.lock`/`composer.json` without touching
`vendor/`; UBEL scans that candidate, and only then runs the real install —
`composer install --no-scripts`. A policy-blocked scan reverts
`composer.json`/`composer.lock` to their pre-scan state from an on-disk
backup, atomically, the same `revert_lock_to_original` path npm/pnpm/bun
use. TOCTOU is closed the same way too: SHA-256 checks on both files
immediately before the real install. Unlike pip's dry-run, there's no
sdist-style caveat here — resolving a Composer dependency graph never runs
a package's own code, since Composer's lifecycle scripts only fire on an
actual `install`/`update`, which is exactly why `--no-scripts` covers both
the dry-run and the real install.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered — `.php` files are scanned for
`use`/`require`/`include` references against the resolved dependency
graph, same signal set (depth, scope, attack vector, import confirmation)
as every other reachability-covered ecosystem.

---

## Ruby — Bundler

**SCA:** Resolves from `Gemfile.lock`.

**Firewall:** Not available — same reasoning as Rust/Go/Java/.NET below: no
side-effect-free dry-run install path in Bundler for UBEL to hook into.

**SAST / Malware SAST:** Full coverage, `.rb` chunking.

**Reachability analysis:** Fully covered via `.rb` import scanning.

---

## Rust — Cargo

**SCA:** Resolves from `Cargo.lock`, giving exact resolved versions rather
than semver ranges from `Cargo.toml`.

**Firewall:** Not available — `cargo add`/`cargo build` don't offer an
equivalent gate point.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered via `.rs` import scanning.

---

## Go — modules

**SCA:** Resolves from `go.sum`, which pins exact versions and hashes
already, giving high-confidence version matching against OSV.

**Firewall:** Not available.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered via `.go` import scanning.

---

## Java / Kotlin — Maven

**SCA:** Resolves the dependency tree from `pom.xml`, following transitive
Maven resolution.

**Firewall:** Not available.

**SAST / Malware SAST:** Full coverage; Java and Kotlin are tracked as
separate language families in the catalog, so idioms specific to each
(e.g., Kotlin null-safety bypasses vs. Java reflection abuse) get
distinct signal sets rather than one being shoehorned into the other's
ruleset.

**Reachability analysis:** Fully covered — `.java`, `.kt`, `.groovy`, and
`.scala` files are all scanned under the same `maven` reachability key.

**Note:** Gradle-based projects aren't mentioned as a separately-resolved
build system — Maven-style resolution is the documented path for this
ecosystem today.

---

## C# / .NET — NuGet

**SCA:** Resolves from `packages.lock.json` where present, falling back to
`obj/project.assets.json` (the MSBuild-generated resolved graph) when a
project doesn't use lock-file mode.

**Firewall:** Not available.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered — `.cs`, `.vb`, `.fs`, and `.fsx`
files are all scanned under the same `nuget` reachability key.

---

## C (bare, no package manager)

**SCA:** Not applicable — C has no standard ecosystem-level package
manager/lockfile for UBEL to resolve a dependency tree from, so there's no
SCA/vulnerability-matching layer for C the way there is for the
lockfile-based ecosystems above.

**SAST / Malware SAST:** Covered as its own language family in the
catalog — memory-safety and injection-class findings are scanned for
directly in source, independent of any dependency graph.

**License compliance:** Not applicable, for the same reason as SCA — no
per-package manifest to read a declared license from.

---

## Docker — container images

**SCA:** The most complete single-target scan in UBEL. Pulls (or reuses a
local) image or accepts an already-exported uncompressed `.tar` — never
runs the image's `ENTRYPOINT`/`CMD` — exports its filesystem to a temp dir,
and scans that filesystem exactly like any other project root: OS packages
via the Linux host scanner *and* every application-level ecosystem's
dependencies found inside the image (Node, Python, PHP, etc., all at once,
via `full_stack`).

**Firewall:** Docker gets **true pre-install (here, pre-deploy) gating**,
with three modes controlling what happens to the image after scanning:
- `health` — scan only, image left exactly as found.
- `check` — scan, then always remove the image afterward (throwaway vetting).
- `install` — scan, then remove the image *only if* the scan results in a
  policy block; a clean scan leaves it in place.

`--no-pull` scans an image that only exists locally (e.g., right after
`docker build`, before it's ever pushed to a registry) — this is the
"vet before you ship" path. `--keep` retains the extracted root filesystem
for debugging. Pointing this at a CI-built image before push, or at a
third-party base image before you adopt it, is the intended pre-deploy
firewall use.

**Malware/Secrets/License:** All inherited from whatever's found inside the
image — an image with a compromised npm package, a hardcoded AWS key in a
baked-in `.env`, or a GPL-licensed binary bundled into a proprietary image
all get caught the same way they would in a live checkout.

---

## Kubernetes manifests

**Coverage:** Not a separate scanner — Kubernetes YAML is treated as its
own chunkable language family inside the SAST catalog, so misconfigurations
get scanned with the same LLM-driven pipeline as source code. Verified
classes include: overly permissive RBAC / `ClusterRoleBinding`s, containers
configured to run as root, missing `NetworkPolicy` isolation on services
exposed via `LoadBalancer`/`NodePort`, and similar cluster-hardening gaps.

**Not covered:** Live cluster state — this scans the YAML *files* in your
repo, not a running cluster's actual applied configuration or drift from
those files. There's no `kubectl`-based live posture check.

---

## Terraform / CloudFormation (Infrastructure-as-Code)

**Coverage:** Same mechanism as Kubernetes above — IaC is its own language
family in the catalog. Confirmed classes include hardcoded secrets
embedded directly in `.tf`/CloudFormation templates and resources
provisioned with encryption-at-rest disabled.

**Not covered:** Live cloud account state. This is static analysis of the
IaC *source* — it will not detect drift where the deployed resource no
longer matches what the template says, and it isn't a cloud security
posture management (CSPM) tool that queries your cloud provider's API for
the actual state of running resources.

---

## Linux host (apt / dnf / yum)

**SCA:** `LinuxHostScanner` inventories installed OS packages and matches
them against CPE/CVE data — this is what backs both the standalone
`ubel-platform` host scan and the OS-package half of every Docker image
scan.

**Firewall:** Available via three separate binaries — `ubel-apt`,
`ubel-dnf`, `ubel-yum` — each bound to exactly one native package manager,
with no auto-detection between them (the same one-binary-per-tool shape as
`ubel-npm`/`ubel-pnpm`/`ubel-bun`; running `ubel-dnf` on a box that only has
`apt` fails clearly rather than silently doing the wrong thing). Each uses
its package manager's own native dry-run — `apt-get -s` (simulate) for
Debian/Ubuntu, `dnf --assumeno` for RHEL 8+/AlmaLinux/Rocky,
`yum --assumeno` for RHEL 7 — to resolve what *would* be installed (name,
version, and for apt, the source repo/arch) without installing it. UBEL
scans that resolution and only then runs the real
`sudo apt/dnf/yum install -y`. As with pip, there's no lockfile, so a
blocked scan just means the real install never runs — nothing to revert.
Reports and policy live under `~/.ubel/local` specifically so that routine
`health`/`check` use never needs elevated privileges; only the real install
step does, same as running the package manager yourself.

**License compliance:** Fully applied. Per-package license strings are
extracted from rpm metadata, `/usr/share/doc/<pkg>/copyright` for
dpkg-based systems, and apk metadata, then fed through the same SPDX
normalization/OSI/risk classification layer as every other ecosystem — it
isn't a separate, lesser pipeline for OS packages.

---

## Windows host

**SCA:** `WindowsHostScanner` mirrors the Linux host scanner's role for
Windows — installed software/package inventory matched against CPE/CVE.

**Firewall:** Not available. Unlike Linux's `apt-get -s`/`dnf --assumeno`,
there's no equivalent dry-run resolution UBEL can hook into for Windows'
package managers/installers today — this remains health/detection scanning
of what's already on the machine, not a gate on what's about to be
installed.

**License compliance:** Fully applied, via its own `licenseFor()` mapping
feeding the same classification pipeline as every other ecosystem.

---

## Cross-Cutting Capabilities

### Reachability Analysis — 8 ecosystems via import-graph confirmation

Every vulnerability is annotated with a reachability verdict derived from
dependency depth, scope (prod/dev/env), attack vector, orphan-tool
detection, and — where source is available — actual import/require
scanning that confirms whether the vulnerable module is ever referenced.
The import-scan half of this is implemented for **Python (`.py`), Node.js
(`.js`/`.ts`/`.mjs`/`.cjs`/`.jsx`/`.tsx`), Maven/Java+Kotlin (`.java`,
`.kt`, `.groovy`, `.scala`), NuGet/C# (`.cs`, `.vb`, `.fs`, `.fsx`), PHP
(`.php`), Go (`.go`), Cargo/Rust (`.rs`), and RubyGems/Ruby (`.rb`)** — the
same eight ecosystems that get full SCA. A known distribution-name-to-
import-name override table (e.g. `beautifulsoup4` → `bs4`,
`pyyaml` → `yaml`, `opencv-python` → `cv2`) keeps the import match accurate
even where the published package name and the name you actually import
diverge. C, OS packages, Docker, Kubernetes, and IaC don't get this layer,
since there's no per-package "is this imported by my source" question that
applies to them the same way.

### Secrets Detection — every ecosystem, uniformly

Secrets scanning is deliberately **ecosystem-independent**: it's a plain
file walk over source and config file extensions (`.js`, `.py`, `.rb`,
`.go`, `.java`, `.php`, `.cs`, `.rs`, `.kt`, `.swift`, `.json`, `.yml`,
`.yaml`, config files, etc.), pattern-matched against a ruleset ported from
Trivy's secret rules (separately attributed and licensed — only that
vendored ruleset is Apache-2.0; the scanner code around it isn't). It
never touches `node_modules`, `vendor/`, `target/`, virtual environments, or
any other dependency directory — it's scanning *your* code for accidental
commits, not your dependencies. This means it runs identically whether
you're in a Node repo, a Python repo, a Kubernetes manifests repo, or an
image filesystem — there's no per-language variance in what it can find.
It's a pure in-memory scanner with no disk writes of its own; the caller
(main engine) decides whether findings fold into the JSON/HTML/SARIF
report.

### License Compliance — every ecosystem, including OS packages

A zero-dependency, no-network normalization layer that takes whatever
inconsistent shape a package manager reports a license in — missing/null,
free text ("Apache 2.0", "BSD"), npm's `UNLICENSED` sentinel (proprietary —
**not** the SPDX "Unlicense" public-domain license, a common footgun),
`SEE LICENSE IN <file>` references, Python trove classifiers, full SPDX
expressions like `(MIT OR Apache-2.0)` — and normalizes it to a canonical
SPDX identifier, checks it against a curated OSI-approved license table,
and assigns a risk tier (permissive → weak copyleft → strong copyleft /
proprietary / unrecognized). It's applied once, uniformly, to the entire
unified scan inventory — Node, Python, PHP, Ruby, Rust, Go, Java/Kotlin,
C#, and Linux/Windows OS packages alike. The only true exception is C (no
package manager/manifest exists to read a license from in the first
place). Policy supports both a `license-risk` threshold
and a separate `license-block-unknown` flag for licenses that couldn't be
classified at all — both enforced only against health-mode scans, since
license risk is a compliance concern on what's already installed, not an
install-time security gate.

### Malware SAST — 10 source-code language families, universally

Malware detection is a two-pass LLM pipeline covering 15 intentional-malice
classes, applied identically across all 10 source-code families (JS,
Python, PHP, Ruby, Go, Rust, Java, Kotlin, C#, C) — every malware catalog
entry is tagged for `ALL_LANGUAGES`, so there's no ecosystem where malware
detection is a second-class capability. It's explicitly separate from the
vulnerability SAST catalog (different pipeline, different intent: is this
code *deliberately* malicious vs. *accidentally* exploitable) and ships as
its own CLI (`ubel-mal`), independent of the SCA/firewall engine.

### Vulnerability SAST — 13 language/config families

The vulnerability-finding catalog (59 CWE-mapped classes) spans a wider set
than malware detection: the 10 source-code families above, plus Docker,
Kubernetes, and general IaC as first-class chunkable targets — meaning
Dockerfiles, K8s manifests, and Terraform/CloudFormation get scanned with
the same three-pass scan → verify → taint-trace rigor as application code,
not treated as an afterthought bolted onto the dependency scanner.

### Compliant, Standardized Outputs

- **SARIF 2.1.0** — full-fidelity output (deterministic SHA-256
  fingerprints, not random UUIDs, so the same finding produces the same ID
  run over run) that plugs directly into GitHub code scanning and any
  other SARIF-consuming pipeline.
- **CycloneDX 1.6 SBOM** — with VEX-style vulnerability annotations,
  usable as a release artifact independent of any specific CI vendor.
- **CVSS scoring** — v2, v3, v3.1, and **v4.0** (a full port of the
  Red Hat CVSS v4 calculator, BSD-2-Clause, separately attributed) plus
  SSVC as a normalized "other" scoring method where relevant, all folded
  into a single normalized severity used consistently across JSON, SARIF,
  and SBOM output.
- **HTML reports** — force-directed dependency graphs, inventory modals,
  and reachability badges/filters wherever reachability data exists in the
  report (the eight ecosystems above).
- **JSON** — the canonical, complete report every other format is derived
  from, including effective-configuration tracing (what policy/thresholds
  were actually in effect for that specific scan run).

---

## What this matrix intentionally does *not* claim

To keep this document honest rather than aspirational:

- Firewall/pre-install gating is **npm, pnpm, bun, Composer, Docker,
  pip/uv/pipx, and Linux host packages (apt/dnf/yum) only** — not "every
  package manager," because most package managers genuinely don't offer a
  dry-run resolution UBEL can safely gate against. Ruby (Bundler), Rust
  (Cargo), Go (modules), Java/Kotlin (Maven), C#/.NET (NuGet), and the
  Windows host all remain without it for that reason — a hard mechanical
  constraint, not a roadmap gap.
- **Yarn** is the one Node.js package manager left out of that list, for
  the same kind of reason, not a different one: `yarn add` always writes
  to `node_modules` immediately, with no lockfile-only/dry-run mode the
  way npm/pnpm/bun each have. That's yarn's own CLI design, not a gap in
  UBEL's implementation — there's no side-effect-free resolution step here
  to hook a scan into before something's already been written to disk.
- pip's and uv's dry-run firewalls are the one exception with a caveat
  rather than a clean guarantee, and that caveat is Python's own packaging
  model, not a shortcoming in how UBEL drives either tool: resolving a
  source-only package's metadata can require building an sdist, which can
  run arbitrary build-backend code, and neither `pip install --dry-run`
  nor `uv pip install --dry-run` can avoid that — it's how sdist-based
  resolution works generally, independent of which tool triggers it.
  Wheel-only installs don't have this gap; see the Python section above.
- Reachability analysis's import-confirmation half covers **8 of the 8
  SCA ecosystems** — C, OS packages, Docker, Kubernetes, and IaC don't get
  it, since "is this imported by my source" isn't a meaningful question
  for those.
- Kubernetes *manifest* and IaC coverage is **static file analysis**, not
  live cluster posture management — there is no drift detection against
  what's actually running in a cluster. (Live account-level posture for
  the AWS, GCP, and Azure resources themselves — as opposed to Kubernetes
  clusters running on them — is covered separately by `ubel-cloud`, via
  each provider's own API; see the Cloud section above.)
- Every ecosystem here — including the OS-level ones (apt/dnf/yum and
  Windows) — gets full SCA **and** license compliance regardless of
  firewall status; firewalling and inventory/license coverage are tracked
  and reported independently.

---

## License

Source-available, internal-use license. Modification for internal needs is permitted; redistribution, wrapping, and hosting as a third-party service are not. See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for full terms, including the consultant-use exception.
---

## Links

- Repository: https://github.com/AlaBouali/ubel
- Issues: https://github.com/AlaBouali/ubel/issues
- SCA docs: https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md
- SAST docs: https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md
- Cloud docs: https://github.com/AlaBouali/ubel/blob/main/node/cloud/README.md

*UBEL — Find the bug before it finds production.*