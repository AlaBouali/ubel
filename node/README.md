# UBEL — Node.js

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, and AI-powered source-level scanning ( SAST ) .**

UBEL is a zero-dependency, source-available application security toolkit. This package (`@arcane-spark/ubel-node`) ships multiple CLIs for dependency-security and source-level scanner:

- **SCA** — resolves your dependency tree (and, in full-stack mode, other ecosystems present in the repo) and scans it against OSV.dev and NVD **in real time, on every scan** — not from a periodically-synced local database — with heuristic reachability analysis, SBOM (CycloneDX v1.6), and SARIF output. Both endpoints can be pointed at internal mirrors via `UBEL_OSV_ENDPOINT`/`UBEL_NVD_ENDPOINT` for air-gapped deployments (see [node/sca/README.md](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#environment-variables)). This is the audit/reporting side — `health` mode reads what's already installed.
- **Firewall** — a distinct mode of the same CLI (`check` / `install`) that gates the install itself before anything touches `node_modules`, `pnpm`'s store, or `bun`'s install path, with atomic lockfile revert on violation and SHA-256 TOCTOU checks between scan and install. The same pull → scan → keep-or-remove pattern also gates **Docker images** (`ubel-docker install <image>`) before you run them.
- **Secrets Detection** — built on Trivy's ported, Apache-2.0-attributed secret-scanning ruleset (see [NOTICE](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault tokens, GCP API keys and OAuth tokens, Anthropic and OpenRouter keys, Stripe restricted keys, Twilio Account/App SIDs, and URL-embedded git credentials, among others). Runs standalone via `ubel-secrets`, or as part of any SCA/firewall scan.
- **License Compliance** — every scanned package's declared license (SPDX id, free text like "Apache 2.0", npm's `UNLICENSED` proprietary sentinel, a Python trove classifier, an SPDX `OR`/`AND` expression, or missing entirely) is normalized and checked against the OSI-approved license list, with a derived risk rating (permissive / weak-copyleft / strong-copyleft / proprietary / unknown). Included in every SCA/firewall scan by default — surfaced per-package in the HTML report, as license properties on every SBOM component, and as a dedicated SARIF run. Runs standalone via `ubel-license` — inventory + license classification only, no OSV/NVD vulnerability lookups, no secrets scan.
- **SAST / Malicious-Code Scanner** — a separate module: an LLM-powered pipeline (**scan → verify → taint-trace**) that reads your actual source code, cross-references a structured CWE-mapped vulnerability catalog, and separately screens for intentionally malicious code (backdoors, C2 beacons, supply-chain implants). It also scans IaC, Docker, and Kubernetes manifest files — each as its own dedicated language family, not lumped together.

Everything runs on your own infrastructure: no source code egress, no credentials required beyond your chosen LLM provider's API key (SAST only), no telemetry.

---

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

This installs the binaries for both the SCA/firewall CLI and the SAST module:

| Binary | Covers | What it does |
|---|---|---|
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` | SCA + Firewall | Same binary, mode-dependent: `health` = SCA scan of installed deps; `check`/`install` = firewall gate on a lockfile dry-run |
| `ubel-docker` | SCA + Firewall | Scans a container image without running it; `install` mode pulls, scans, and removes the image on a policy violation |
| `ubel-secrets` | Secrets | Standalone secrets-only scan of the target directory — no dependency resolution, no LLM calls |
| `ubel-license` | SCA | Standalone inventory + license-compliance scan — no vulnerability lookups (OSV/NVD), no secrets scan |
| `ubel-agent` | SCA | AI-agent workspace scan (OS, runtimes, tools, dependencies) |
| `ubel-cicd` | SCA | Post-install CI/CD scan of the final built workspace (OS, runtimes, tools, dependencies) |
| `ubel-platform` | SCA | Host platform scan (OS, runtimes, tools) |
| `ubel-sast` | SAST | Static analysis for accidental vulnerabilities (injection, XSS, insecure deserialization, hardcoded secrets, …) |
| `ubel-mal` | SAST | Malicious-code scan for intentional backdoors, C2 implants, exfiltration, persistence |
| `ubel-chunk` | SAST | Free, LLM-cost-free utility to preview how a codebase will be chunked |

Node.js `>=18.0.0` required.

---

## SCA — Dependency Vulnerability Scanning

Resolves dependencies (with PURL generation), scans them against OSV.dev and NVD, and annotates each finding with a heuristic **reachability** verdict (package type, scope, dependency depth, attack vector, and optional source-level import-scan confirmation). Malicious-package advisories (`MAL-*`) are always flagged. Output: JSON, HTML, CycloneDX v1.6 SBOM, and SARIF 2.1.0 reports.

```bash
# Audit the currently installed dependency graph — no install, no lockfile mutation
ubel-npm health
ubel-pnpm health
ubel-bun health
```

`health` mode also supports full-stack monorepo scanning (Python, PHP, Rust, Go, .NET, Java, Ruby alongside Node) and host/platform scanning (Linux package managers, Windows registry) when invoked programmatically.

**yarn** is supported in `health` mode only — it can't do a lockfile-only dry-run, so it has no firewall coverage below.

## Firewall — Install-Time Gate

A distinct mode of the same `ubel-npm` / `ubel-pnpm` / `ubel-bun` binaries: before any real install, a lockfile-only dry-run (`--package-lock-only` / `--lockfile-only`) resolves the candidate tree without touching `node_modules`, scans it, and either proceeds or reverts the lockfile from its on-disk backup. Pre/post-install scripts are always blocked (`--ignore-scripts`) during this phase. A SHA-256 check re-verifies the lockfile and `package.json` immediately before the real install, closing the TOCTOU window between scan and install.

The same block-before-you-touch-it pattern applies to `ubel-docker`: `install` mode pulls the image, extracts its filesystem without ever running it (`docker create` + in-process tar extraction, no shell `tar`, no `ENTRYPOINT`/`CMD` execution), scans it, and removes the image again if policy blocks it.

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
```

Policy (severity threshold, unknown-severity blocking) is configurable via `ubel-npm threshold <level>` and `ubel-npm block-unknown <bool>`; malicious-package advisories are always blocked regardless of policy.

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
```

`command` must be one of: `sast`, `mal`, `chunk`, `cicd`, `agent`, `platform`, `secrets`, `license`, `npm`, `pnpm`, `bun`, `yarn`, `docker` — anything else fails the step before `npx` ever runs.

### Calling the binaries directly

Equivalent, for self-hosted runners, non-GitHub CI, or a Dockerfile:

```yaml
# GitHub Actions
- name: UBEL dependency scan (SCA)
  run: ubel-npm check

- name: UBEL firewall-gated install
  run: ubel-npm install

- name: UBEL SAST scan
  run: ubel-sast --fail-on exploitable

- name: UBEL malicious-code scan
  run: ubel-mal --fail-on confirmed

- name: UBEL license compliance scan
  run: ubel-license .
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-sast --fail-on valid .
```

---

## License

Source-available, internal-use license. Modification for internal needs is permitted; redistribution, wrapping, and hosting as a third-party service are not. See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for full terms, including the consultant-use exception.
---

## Links

- Repository: https://github.com/AlaBouali/ubel
- Issues: https://github.com/AlaBouali/ubel/issues
- SCA docs: https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md
- SAST docs: https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md

*UBEL — Find the bug before it finds production.*