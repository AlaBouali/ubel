# UBEL — Detailed Reference

> Full reference for every module and ecosystem. For a short overview, see the [README](./README.md).

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, and AI-powered source-level scanning ( SAST ) .**

UBEL is a zero-dependency, source-available (internal-use-only; see [License](#license)) application security toolkit. This package (`@arcane-spark/ubel-node`) ships multiple CLIs for dependency-security and source-level scanner:

- **SCA** — resolves your dependency tree (and, in full-stack mode, other ecosystems present in the repo) and scans it against OSV.dev and NVD **in real time, on every scan** — not from a periodically-synced local database — with heuristic reachability analysis, SBOM (CycloneDX v1.6), and SARIF output. Both endpoints can be pointed at internal mirrors via `UBEL_OSV_ENDPOINT`/`UBEL_NVD_ENDPOINT` for air-gapped deployments (see [sca/README.md](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#environment-variables)); the KEV/EPSS exploit-intelligence feeds have no mirror setting and are simply reported as unavailable when unreachable. This is the audit/reporting side — `health` mode reads what's already installed. A **git pre-commit hook** (`ubel-<engine> install-hook`) can gate commits on this scan, dependency-only (no OS scan).
- **Exploit intelligence** — every vulnerability is checked against CISA's [Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and scored with [FIRST EPSS](https://www.first.org/epss/) (probability of exploitation in the next 30 days). By default the policy blocks on any KEV entry or an EPSS score of 10% or more, whatever the severity (tunable with `--block-kev` / `--epss-threshold`). The fields travel into the JSON, HTML, SBOM and SARIF outputs, and a feed outage degrades gracefully — the values become `null` (unknown, never "not exploited") and the matching rule isn't enforced — rather than aborting the scan. Applies to SCA, the firewall and EASM. See [sca/README.md](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#exploit-intelligence-kev--epss).
- **Executive summary & suggested fixes** — every SCA and EASM report opens with a plain-language executive summary for non-technical readers (risk rating, key findings, recommended actions, methodology; SCA adds the policy verdict), where known-exploited and likely-exploited issues raise the rating and the priority order. Each package also gets per-release-line upgrade suggestions (the fewest, highest versions that clear the most vulnerabilities, branch-aware; in SCA only vulnerabilities that violate the policy are counted), listed per component in the summary and carried in the JSON, SBOM and SARIF. See the SCA and EASM READMEs.
- **Firewall** — a distinct mode of the same CLI (`check` / `install`) that gates the install itself before anything touches `node_modules`, `pnpm`'s store, `bun`'s install path, or Composer's `vendor/` directory, with atomic lockfile revert on violation and SHA-256 TOCTOU checks between scan and install. The same pull → scan → keep-or-remove pattern also gates **Docker images** (`ubel-docker install <image>`) before you run them. **Also included in this same package:** `ubel-pip`/`ubel-uv`/`ubel-pipx` gate `pip`/`uv` installs and isolated CLI-tool installs behind a dry-run resolution, and `ubel-apt`/`ubel-dnf`/`ubel-yum` (one binary per package manager, same as npm/pnpm/bun) gate `apt`/`dnf`/`yum` installs behind each one's own native dry-run — neither has a lockfile to revert, so a rejected scan simply never runs the real install rather than reverting one. `ubel-yarn`, `ubel-bundle`, `ubel-go`, `ubel-dotnet`, `ubel-dart`, `ubel-flutter` and `ubel-swift` (Yarn, Bundler, Go, .NET, Dart, Flutter, SwiftPM) have no dry-run UBEL can safely drive, so they are **`check`-only**: the project's lockfile must already exist and `check` scans exactly what it pins (no manifest, no toolchain needed). They have no `install` mode — install with the package manager's own frozen command once `check` passes. No lockfile, or any package argument, is refused.
- **SBOM re-scan** — `ubel-resbom <sbom.cdx.json>` takes an SBOM that UBEL generated earlier and scans it again against today's advisories: the components and dependency graph come from the SBOM, and the usual pipeline (OSV/NVD lookup, KEV/EPSS, policy, suggested fixes, executive summary, JSON / HTML / SBOM / SARIF) runs on them — no project, lockfile or package manager, and nothing is installed or reverted. It answers whether a release that was clean when scanned has become vulnerable since, and can gate a scheduled job on the policy. Reports are tagged `<source tag>_resbom` (`sca_resbom`, `npm_firewall_resbom`, …) and filed under the SBOM's own asset. See [Re-scanning an SBOM](#re-scanning-an-sbom--ubel-resbom).
- **SBOM vulnerability fill** — `ubel-sbom <sbom.cdx.json>` takes any CycloneDX JSON SBOM (UBEL's or another tool's) and writes the known vulnerabilities of its components into the SBOM's own `vulnerabilities` array, each enriched with CISA KEV and FIRST EPSS. Components are looked up by **purl** (OSV); a component's **CPE** (NVD) is only used when it has no purl OSV can be asked about. Only `vulnerabilities` is written — no reachability, VEX analysis, policy, or JSON / HTML / SARIF report. See [Filling an SBOM's vulnerabilities](#filling-an-sboms-vulnerabilities--ubel-sbom).
- **Secrets Detection** — built on Trivy's ported, Apache-2.0-attributed secret-scanning ruleset (see [NOTICE](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault tokens, GCP API keys and OAuth tokens, Anthropic and OpenRouter keys, Stripe live restricted keys, and URL-embedded git credentials for GitHub, GitLab, Bitbucket, Azure DevOps and other git hosts, among others). Runs standalone via `ubel-secrets`, or as part of any `health`-mode SCA scan.
- **License Compliance** — every scanned package's declared license (SPDX id, free text like "Apache 2.0", npm's `UNLICENSED` proprietary sentinel, a Python trove classifier, an SPDX `OR`/`AND` expression, or missing entirely) is normalized and checked against the OSI-approved license list, with a derived risk rating (permissive / weak-copyleft / strong-copyleft / proprietary / unknown). Included in every `health` scan by default (never on `check`/`install`) — surfaced per-package in the HTML report, as license properties on every SBOM component, and as a dedicated SARIF run. Runs standalone via `ubel-license` — inventory + license classification only, no OSV/NVD vulnerability lookups, no secrets scan.
- **Compliance Framework Mapping** — every finding across SCA (vulnerabilities, secrets), SAST (vulnerability and malicious-code findings), and Cloud (misconfigurations) is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, via one shared mapping engine so the same underlying risk maps identically regardless of which module found it. Included by default in every scan, with a report-level per-framework/per-control finding-count summary, across JSON, HTML, and SARIF (where the module emits SARIF). Best-effort guidance, not a certified compliance assessment — see the per-module docs for the full framework list and the disclaimer carried in every report.
- **SAST / Malicious-Code Scanner** — a separate module: an LLM-powered pipeline (**scan → verify → taint-trace**) that reads your actual source code, cross-references a structured CWE-mapped vulnerability catalog, and separately screens for intentionally malicious code (backdoors, C2 beacons, supply-chain implants). It also scans IaC, Docker, and Kubernetes manifest files — each as its own dedicated language family, not lumped together.
- **Cloud** — scans your AWS, GCP, and Azure accounts directly via each provider's own read-only API (live account state, not static IaC files) for misconfigurations: public storage/database/network exposure, over-permissive IAM and cluster (AKS/GKE) authorization, missing encryption, and disabled audit logging (CloudTrail/GuardDuty/VPC flow logs), with a Diffs tab showing what changed since the previous scan. Runs via `ubel-cloud`. See [cloud/README.md](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md).
- **EASM** — passively fingerprints the software exposed on a domain/URL over plain HTTP(S) (server banners, version headers, page markup — no login flow, no brute force, no exploitation; an operator-supplied `--cookie` / `--header` is attached to the fingerprinting requests only), checks the result against OSV.dev/NVD/wpvulnerability.net (the same vulnerability-lookup engine the SCA module uses, plus a dedicated WordPress plugin/theme/core lookup), and separately checks every host for a fixed set of common misconfigurations: exposed `.env`/`.git`/`docker-compose.yml`, an unauthenticated Spring Boot Actuator `env` endpoint, a public Swagger/OpenAPI spec or Swagger UI, WordPress `xmlrpc.php`/user enumeration, TLS/certificate weaknesses, missing/weak security headers and cookie flags, risky HTTP methods (TRACE/PUT/DELETE), CORS misconfiguration, and SPF/DMARC/DKIM email-authentication gaps. Runs via `ubel-url` against hosts you already know, `ubel-domain` to discover a domain's subdomains from Certificate Transparency logs (crt.sh) first — no DNS brute-forcing, no wordlists — and scan all of them in one run, `ubel-host` to connect-scan every port on one or more hosts and fingerprint whatever answers HTTP(S), or `ubel-easm` to combine both — discover a domain's subdomains, resolve them to distinct IPs, port-scan each, and fingerprint the combined result. **Authorized use only — see [easm/README.md](https://github.com/AlaBouali/ubel/blob/main/easm/README.md).**

UBEL has no telemetry and no UBEL-operated backend. The dependency-scanning CLIs send only package identifiers (PURLs / CPE names) to OSV.dev and NVD, both mirror-configurable via `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT`. For exploit intelligence they also send the CVE ids of whatever vulnerabilities they find to FIRST.org's EPSS API and download CISA's public KEV catalog (nothing is sent for that one); neither of those two has an endpoint override, and if they can't be reached the scan still completes with those fields marked unknown. Everything else runs on your own infrastructure. **SAST is the exception to "fully local":** the code chunks `ubel-sast` / `ubel-mal` analyze are sent to the LLM provider you configure (OpenRouter by default, and its API key is the only credential UBEL needs) — point it at a local or self-hosted model endpoint if source code must not leave your network. The EASM and cloud scanners contact only the targets and cloud APIs you point them at, plus the public data sources documented in their READMEs (for example crt.sh and wpvulnerability.net).

---

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

This installs the binaries for the SCA/firewall CLI, the SAST module, the cloud scanner, and the EASM scanner:

| Binary | Covers | What it does |
|---|---|---|
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` | SCA + Firewall | Same binary, mode-dependent: `health` = SCA scan of installed deps; `check`/`install` = firewall gate on a lockfile dry-run. Also: `install-hook` / `uninstall-hook` to install a dependency-scan git pre-commit hook |
| `ubel-yarn` | SCA + Firewall | `health` = SCA scan of the installed graph; `check` = **lockfile-required, check-only** gate. yarn has no side-effect-free dry-run, so nothing is resolved: `yarn.lock` must already exist and `check` scans what it pins (reads only `yarn.lock` — `package.json` is not required, and yarn is not run). **No `install` mode** — run `yarn install --frozen-lockfile` (Yarn 1) / `yarn install --immutable` (Yarn 2+) yourself after `check` passes. No package arguments. Supports `install-hook` / `uninstall-hook` |
| `ubel-bundle` / `ubel-go` / `ubel-dotnet` / `ubel-dart` / `ubel-flutter` / `ubel-swift` | SCA + Firewall | Same check-only lockfile model as `ubel-yarn`, for Bundler (`Gemfile.lock`), Go modules (`go.sum`), .NET/NuGet (`packages.lock.json`), Dart and Flutter (`pubspec.lock`) and SwiftPM (`Package.resolved`). `health` = SCA scan; `check` = read the lockfile only, scan what it pins, stop (no manifest and no package-manager binary required). **No `install` mode** — install with the ecosystem's own frozen command after `check` passes. No lockfile → refused; package arguments are refused in every mode. Supports `install-hook` / `uninstall-hook` |
| `ubel-composer` | SCA + Firewall | `health` = SCA scan of `vendor/composer/installed.json` (falling back to `composer.lock`); `check`/`install` = firewall gate on a `composer require`/`update --no-install --no-scripts --no-plugins` dry-run, same lockfile-backed shape as npm/pnpm/bun. Also supports `install-hook` / `uninstall-hook` |
| `ubel-pip` / `ubel-pipx` | SCA + Firewall | `health` = SCA scan of a venv's installed packages; `check`/`install` = firewall gate on a `pip install --dry-run` resolution. `ubel-pipx` additionally installs CLI tools into isolated, managed per-tool venvs with a global shim, reducing blast radius the way `pipx` itself does. Both support `install-hook` / `uninstall-hook` |
| `ubel-uv` | SCA + Firewall | Same `health`/`check`/`install` split as `ubel-pip`, but targeting a uv-native venv (`uv init --bare` + `uv venv`, not a stdlib one) — the real install always still runs as `uv pip install -r <generated, exact-pinned file>`, same as pip; dry-run uses `uv pip install --dry-run` internally, which (unlike pip's JSON report) yields no dependency-graph data — see the Python section below. A real `install` on either engine also syncs any existing `requirements.txt`/`pyproject.toml` to the now-installed versions. Supports `install-hook` / `uninstall-hook` |
| `ubel-conda` | SCA + Firewall | Same `health`/`check`/`install` split as `ubel-pip`, plus `init`. `check`/`install` resolve with `conda create --dry-run --json` against a scratch prefix that never exists (so `check` creates nothing), then a clean `install` runs `conda create`/`conda install --no-deps --file` with exact `channel::name==version=build` pins of precisely the scanned set into `./conda-env`. Only Python-distribution packages are matched against vulnerability data — see the Python section below. Supports `install-hook` / `uninstall-hook` |
| `ubel-poetry` | SCA + Firewall | Same `health`/`check`/`install` split as `ubel-pip`, plus `init`. `check`/`install` resolve in a scratch copy of the project (`poetry add --lock <packages>`; with no arguments the existing `poetry.lock` is scanned as-is) and the scanned `poetry.lock` is the inventory, so the dependency graph and prod/dev scopes are real. A clean `install` writes the scanned `pyproject.toml` + `poetry.lock` into the project and runs `poetry install --no-root` with source distributions refused (restoring the originals if it fails). Packages locked from git/URL/path are reported `undetermined`, never `safe`. Supports `install-hook` / `uninstall-hook` |
| `ubel-cargo` | SCA + Firewall | `health` = SCA scan of `Cargo.lock`; `check`/`install` = firewall gate on a dry-run resolved in a scratch copy of the project (`cargo add <crate>` if packages were given, then `cargo update --workspace`, both index-only), so `check` never touches the project. A clean `install` writes the scanned `Cargo.toml`/`Cargo.lock` into the project and runs `cargo fetch --locked`; a failed fetch restores the originals. No `init` mode. Only crates.io crates are scanned — see the Rust section below. Supports `install-hook` / `uninstall-hook` |
| `ubel-apt` / `ubel-dnf` / `ubel-yum` | SCA + Firewall | Same `health`/`check`/`install` split, one binary per native package manager (no auto-detection between them, same as npm/pnpm/bun). Reports and policy live under `~/.ubel/local` so routine use never needs `sudo` — only the real package-manager install does. No `install-hook` / `uninstall-hook` — they scan the host, not a repo |
| `ubel-docker` | SCA + Firewall | Scans a container image without running it; `install` mode pulls, scans, and removes the image on a policy violation. No `install-hook` / `uninstall-hook` |
| `ubel-secrets` | Secrets | Standalone secrets-only scan of the target directory — no dependency resolution, no LLM calls. Also scans git history (`--history`) and staged changes (`--staged`), installs a pre-commit hook, and baselines findings |
| `ubel-license` | SCA | Standalone inventory + license-compliance scan — no vulnerability lookups (OSV/NVD), no secrets scan; writes JSON + HTML reports (no SBOM/SARIF) |
| `ubel-resbom` | SCA | Re-scans an SBOM that UBEL generated earlier (`latest.<tag>.cdx.json`) against the current vulnerability data — one positional argument, the SBOM path; no project, lockfile or package manager needed, nothing installed. Same per-run policy flags as the SCA CLIs; writes `<tag>_resbom` JSON, HTML and SBOM (plus SARIF for `sca`-type sources) |
| `ubel-sbom` | SCA | Fills the `vulnerabilities` of a CycloneDX SBOM (any tool's) with its components' known vulnerabilities, each with CISA KEV and FIRST EPSS data — purl → OSV first, CPE → NVD only for components with no usable purl. One positional argument, the SBOM path; rewrites that file (or `-o <file>`) and changes nothing but `vulnerabilities`; no policy, reachability or report files |
| `ubel-agent` | SCA | AI-agent workspace scan (OS, runtimes, tools, dependencies, secrets) |
| `ubel-cicd` | SCA | Post-install CI/CD scan of the final built workspace (OS, runtimes, tools, dependencies, secrets) |
| `ubel-platform` | SCA | Host platform scan (OS, runtimes, tools) — no application dependency resolution and no secrets pass. Defaults to the home directory |
| `ubel-sast` | SAST | Static analysis for accidental vulnerabilities (injection, XSS, insecure deserialization, hardcoded secrets, …) |
| `ubel-mal` | SAST | Malicious-code scan for intentional backdoors, C2 implants, exfiltration, persistence |
| `ubel-chunk` | SAST | Utility with no LLM cost to preview how a codebase will be chunked |
| `ubel-cloud` | Cloud | Live AWS/GCP/Azure account scan via each provider's own API for misconfigurations — public exposure, IAM, encryption, audit logging — not a static IaC/manifest scan |
| `ubel-mobile` | Mobile | Static scan of an Android `.apk` / iOS `.ipa` for hardcoded secrets, insecure storage and misconfigurations, with no third-party libraries or external binaries — see [mobile/README.md](https://github.com/AlaBouali/ubel/blob/main/mobile/README.md) |
| `ubel-binary` | Binary | Static scan of a native ELF / Mach-O / PE executable or library for missing build hardening, risky imports, hardcoded secrets, remote hosts, a behavior inventory and known-vulnerable components (C/C++ banners → NVD; Go modules, Rust crates, packaged npm / Python apps → OSV.dev) — see [binary/README.md](https://github.com/AlaBouali/ubel/blob/main/binary/README.md) |
| `ubel-url` | EASM | Passive HTTP(S) fingerprinting of a domain/URL + OSV/NVD/wpvulnerability.net vulnerability lookup and misconfiguration checks on what it finds — **authorized use only, against infrastructure you own** |
| `ubel-domain` | EASM | Same as `ubel-url`, but discovers its own target list first — enumerates a domain's subdomains via Certificate Transparency logs (crt.sh), then runs the same fingerprinting/vulnerability/misconfiguration scan against all of them — **authorized use only, against infrastructure you own** |
| `ubel-host` | EASM | Takes one or more IPs/domains, resolves them to their distinct IPs (handled exactly like `ubel-easm` handles crt.sh hostnames), connect-scans every port in a range (default 1-30000) on each, probes whatever accepts a connection for HTTP(S), then runs the same fingerprinting/vulnerability/misconfiguration scan `ubel-url` does against whatever answered — **authorized use only, against infrastructure you own** |
| `ubel-easm` | EASM | Combines `ubel-domain`'s discovery with `ubel-host`'s port sweep — discovers a domain's subdomains, resolves them to distinct IPs, port-scans every IP, and fingerprints the merged IP:port targets plus the subdomains themselves by name — the most invasive EASM entry point; see the "Shared IPs" warning in `easm/README.md` — **authorized use only, against infrastructure you own** |

`ubel-pip`/`ubel-uv`/`ubel-pipx` additionally need a `python3`/`python` interpreter on `PATH` (to create their venv); Node.js itself can't provision one. `ubel-uv` additionally needs the `uv` binary itself on `PATH`, separate from Python — same one-binary-per-tool requirement as `ubel-pnpm` needing `pnpm`. `ubel-conda` additionally needs the `conda` binary itself, found via `PATH`, then `$CONDA_EXE`, then conda's default install directories (`~/miniconda3`, `~/anaconda3`, `~/miniforge3`, `/opt/conda`, …); it doesn't need a separate Python interpreter. `ubel-poetry` additionally needs the `poetry` binary itself (found via `PATH`, then `~/.local/bin`, `~/.poetry/bin`, the macOS/Windows installer directories and Homebrew) and a Poetry release that supports `poetry add --lock` and the `installer.only-binary` setting; the latter is verified before every real install. `ubel-cargo` additionally needs the `cargo` binary itself (found via `PATH`, then `$CARGO_HOME/bin`, then `~/.cargo/bin`), and cargo ≥ 1.62 to add packages (`cargo add`). `ubel-composer` additionally needs the `composer` binary itself on `PATH`, same one-binary-per-tool requirement.

Node.js `>=18.0.0` required.

---

## Startup banner

Every CLI shows the UBEL banner once when it starts — it is printed by the shared entry point (`runAssetCommand()` in `sca/asset_cli.js`, which every `bin/*.js` calls first), and the SCA engine's own calls are no-ops once it is out, so it never appears twice. It goes to stdout; `ubel-agent`, `ubel-cicd`, `ubel-platform` and `ubel-license` print their JSON result on stdout, so for them it goes to stderr. It is suppressed by `--json` and `--quiet`, by `UBEL_NO_BANNER=1` (any value but empty or `0`), and for the `asset-id` / `set-asset-id` / `version` commands. Programmatic callers of the SCA API are unaffected.

## SCA — Dependency Vulnerability Scanning

Resolves dependencies (with PURL generation), scans them against OSV.dev and NVD, and annotates each finding with a heuristic **reachability** verdict (package type, scope, dependency depth, attack vector, and optional source-level import-scan confirmation). Malicious-package advisories (`MAL-*`) are always flagged. Output: JSON, HTML, CycloneDX v1.6 SBOM, and SARIF 2.1.0 reports.

```bash
# Audit the currently installed dependency graph — no install, no lockfile mutation
ubel-npm health
ubel-pnpm health
ubel-bun health
ubel-composer health
```

Every `health` report also carries a **Diffs** tab (`diffs` in the JSON): dependencies, vulnerabilities, secrets and — per compliance framework — mapped findings that are new, unchanged or removed since the asset's previous report of the same type. Components are matched by id — a PURL, or for Windows host scans a CPE 2.3 string, so an upgraded product shows as one removed and one new component. See [SCA § Diffs against the previous report](sca/README.md#diffs-against-the-previous-report).

`health` mode also supports full-stack monorepo scanning (Python, PHP, Rust, Go, .NET, Java, Ruby, Swift, Flutter/Dart alongside Node) and host/platform scanning (Linux package managers, Windows registry) when invoked programmatically.

**yarn** can't do a lockfile-only dry-run, so it is gated differently from npm/pnpm/bun: `ubel-yarn check` (there is no `install` mode) **requires `yarn.lock` to already exist** and gates on what it pins (see [Firewall — Install-Time Gate](#firewall--install-time-gate)). The same check-only lockfile model covers Bundler, Go, .NET, Dart, Flutter and SwiftPM (`ubel-yarn`, `ubel-bundle`, `ubel-go`, `ubel-dotnet`, `ubel-dart`, `ubel-flutter` and `ubel-swift`). All of them support the dependency-scan pre-commit hook (`ubel-<engine> install-hook`).

### Pre-commit hook (dependency scanning)

```bash
ubel-npm install-hook                    # install the dependency-scan pre-commit hook
ubel-npm install-hook --force            # chain to an existing foreign pre-commit hook
ubel-npm uninstall-hook                  # remove it again
# Same on: ubel-pnpm, ubel-bun, ubel-yarn, ubel-composer,
#          ubel-pip, ubel-pipx, ubel-uv, ubel-conda, ubel-poetry, ubel-cargo,
#          ubel-bundle, ubel-go, ubel-dotnet, ubel-dart, ubel-flutter, ubel-swift
```

The hook runs `<engine> health` — a **dependency scan only**, no OS scan — on every commit, right after the secrets scan (it is the same single hook as `ubel-secrets --install-hook`). Set `UBEL_HOOK_SCA=auto` to run it only when a commit stages a package manifest or lockfile (a fixed pattern set covering npm/pnpm/bun/yarn/Composer/pip/uv/conda/Cargo/Go/Maven/Gradle/Bundler/SwiftPM/Carthage/pub manifests and lockfiles anywhere in the tree), or `UBEL_HOOK_SCA=off` to skip it. It does not run `check`, so no lockfile is written or reverted — a `health` scan is read-only against the installed graph, and a broken scan can never leave the working tree half-mutated.

- **Chainable.** `--force` moves an existing foreign pre-commit hook to `pre-commit.local` and runs it after a clean dependency scan. `uninstall-hook` moves it back. There is **one** hook shared with `ubel-secrets --install-hook`: install either or both, in any order, without `--force`, and you get a single hook with both steps (it never chains to itself).
- **Portable.** If the hooks directory is a committed `.githooks/` or husky-style path outside the git dir, the hook is written without any machine-specific absolute paths — it finds `ubel-<engine>` on `PATH`, so it's safe to commit and share.
- **Fail-open for "tool missing", fail-closed for "tool failing".** If the binary can't be found, the hook warns loudly and lets the commit through; set `UBEL_HOOK_STRICT=1` to block instead. If the binary runs and exits non-zero, the commit is always blocked.
- **Client-side only.** Skip once with `git commit --no-verify`. Also run `<engine> check` (or `health`) in CI — see [CI/CD Integration](#cicd-integration).

**Full documentation — the file patterns that trigger the hook, chaining rules, coexistence with the secrets hook:**
[**sca/README.md#pre-commit-hook**](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#pre-commit-hook)

## Firewall — Install-Time Gate

A distinct mode of the same `ubel-npm` / `ubel-pnpm` / `ubel-bun` binaries: before any real install, a lockfile-only dry-run (`--package-lock-only` / `--lockfile-only`) resolves the candidate tree without touching `node_modules`, scans it, and either proceeds or reverts the lockfile from its on-disk backup. Pre/post-install scripts are always blocked (`--ignore-scripts`) during this phase. A SHA-256 check re-verifies the lockfile and `package.json` immediately before the real install, closing the TOCTOU window between scan and install.

The same block-before-you-touch-it pattern applies to `ubel-docker`: `install` mode pulls the image, extracts its filesystem without ever running it (`docker create` + in-process tar extraction, no shell `tar`, no `ENTRYPOINT`/`CMD` execution), scans it, and removes the image again if policy blocks it.

`ubel-composer` extends the same lockfile-backed pattern npm/pnpm/bun use to PHP: `composer require`/`update --no-install --no-scripts --no-plugins` (Composer's own equivalent of `--package-lock-only`) resolves the candidate tree and writes a candidate `composer.lock`/`composer.json` without touching `vendor/`, UBEL scans that candidate, and either proceeds via `composer install --no-scripts --no-plugins` or reverts both files from their on-disk backup — the same SHA-256 TOCTOU check and atomic revert as npm/pnpm/bun, just against Composer's own files. Lifecycle scripts are disabled with `--no-scripts` and Composer plugins (PHP code Composer loads in-process at startup, which `--no-scripts` does not cover) with `--no-plugins`, on both the dry-run and the real install.

`ubel-pip`/`ubel-uv`/`ubel-pipx` extend the same before-you-touch-it approach to Python: `pip install --dry-run --report` (pip) or `uv pip install --dry-run` (uv) resolves the candidate set — including transitive dependencies — without installing anything, UBEL scans that resolution, and only then runs the real install (`pip install --only-binary=:all: --no-deps -r` / `uv pip install --only-binary=:all: --no-deps -r` against the same generated, exact-pinned file either way). A successful real install additionally syncs any `requirements.txt`/`pyproject.toml` already sitting in the project directory to the versions that actually got installed — see the Python section further down for exactly what that does and doesn't touch. There's no lockfile here, so there's nothing to revert — a blocked scan just means the real install never runs. Source distributions are refused rather than built (resolving a source-only package's metadata can require building an sdist, which runs arbitrary `setup.py`/build-backend code): the dry-run and the real install both pass `--only-binary=:all:`, so a package with no compatible wheel fails closed, and the real install also passes `--no-deps` so only the scanned, pinned set is installed. `ubel-conda` follows the same shape with a scratch-prefix dry-run: `conda create --dry-run --json` against a prefix that never exists resolves the full closure (so a fully-satisfied target still reports everything), UBEL scans it, and only then installs exactly the scanned builds (`--no-deps` plus exact pins, spec file SHA-256-checked immediately before conda runs). As with pip, there's no lockfile, so a blocked scan just means the real install never runs. `ubel-poetry` resolves the same way cargo does — in a scratch copy of the project (`poetry add --lock`, or the existing `poetry.lock` when no packages are given) — and scans the resulting `poetry.lock`, which carries the full dependency graph and the dependency groups. Only after a clean scan are the scanned `pyproject.toml`/`poetry.lock` written into the project (SHA-256-checked, and re-checked against the project's own `pyproject.toml` in case it changed mid-scan) and installed with `poetry install --no-root`, source distributions refused via `installer.only-binary` (verified against the installed Poetry first, so an older release fails closed); the originals are restored if the install fails. `ubel-cargo` resolves in a scratch copy of the project instead of editing it, so there's nothing to revert and `check` leaves the tree untouched: only after a clean scan are the scanned `Cargo.toml`/`Cargo.lock` written into the project (SHA-256-checked, and re-checked against the project's own files in case they changed mid-scan) and fetched with `cargo fetch --locked`. `ubel-apt`/`ubel-dnf`/`ubel-yum` mirror this for Linux host packages — three separate binaries, each bound to exactly one package manager's own native dry-run (`apt-get -s`, `dnf --assumeno`, `yum --assumeno` respectively, no auto-detection between them); their reports and policy live under `~/.ubel/local` so ordinary use never needs `sudo` — only the real install does.

`ubel-yarn`, `ubel-bundle`, `ubel-go`, `ubel-dotnet`, `ubel-dart`, `ubel-flutter` and `ubel-swift` cover the ecosystems where UBEL has no safe way to *resolve* a candidate lockfile first (`yarn add` always writes `node_modules`; SwiftPM resolving evaluates `Package.swift`; pub's dry-run prints a plan, not a lockfile). Instead of resolving, they **require the project's lockfile to already exist** and gate on what it pins:

| Engine | Lockfile (required) | Install it yourself with (after `check` passes) |
|---|---|---|
| `ubel-yarn` | `yarn.lock` | Yarn 1: `yarn install --frozen-lockfile --ignore-scripts`; Yarn 2+: `yarn install --immutable --mode=skip-build` |
| `ubel-bundle` | `Gemfile.lock` | `BUNDLE_FROZEN=true bundle install` |
| `ubel-go` | `go.sum` | `GOFLAGS=-mod=readonly go mod download` |
| `ubel-dotnet` | `packages.lock.json` | `dotnet restore --locked-mode` |
| `ubel-dart` / `ubel-flutter` | `pubspec.lock` | `dart pub get --enforce-lockfile` / `flutter pub get --enforce-lockfile` |
| `ubel-swift` | `Package.resolved` | `swift package resolve --force-resolved-versions` |

- **`check` is the only gate mode.** It reads **only the lockfile**, looks the pinned packages up, applies the policy, and stops. Nothing is installed, written or reverted; no manifest is required and the package manager does not need to be installed. It uses the `health` lockfile parsers but never falls back to anything else, so what is scanned is what the frozen install below would fetch: Go reads `go.sum` only (`go.mod` is not consulted, so every source version in `go.sum` is reported, stale ones included — over-reporting is the safe direction for a firewall; `health` still merges `go.mod`); Dart/Flutter read `pubspec.lock` only (not `.dart_tool/package_config.json`); .NET requires `packages.lock.json` (no fallback to `obj/project.assets.json`); SwiftPM reads `Package.resolved` only (no `.build/workspace-state.json` or `Cartfile.resolved`).
- **No `install` mode.** These engines don't install anything: run `ubel-<engine> check` first (locally or in CI), and only when it exits `0` run the package manager's own frozen/locked command from the table above, which fails instead of resolving anything the lockfile doesn't pin. **TOCTOU:** the lockfile is SHA-256-fingerprinted when it is read and re-hashed once the verdict is final; if it changed in between, `check` fails (exit `1`) instead of reporting a verdict for a file that is no longer on disk. On success it prints `<lockfile> sha256: <digest>`, so a CI step can compare that with the lockfile it installs from. UBEL cannot close the window between `check` and your own install, so run both in the same pipeline step from a committed lockfile.
- **No lockfile → refused.** A missing or empty lockfile, or **any package argument (in any mode, `health` included)**, exits `1` — adding a package means resolving it, which is the part that cannot be gated here. Add it with the package manager, review and commit the lockfile, then run `ubel-<engine> check` with no arguments. A lockfile that parses to zero packages is refused too, never reported as clean.
- **Reports** are tagged `<engine>_firewall` (e.g. `go_firewall`).
- **Install-time code:** UBEL does not run the install, so lifecycle scripts are up to you: yarn can skip them (`--ignore-scripts` / `--mode=skip-build`, in the commands above), but Bundler native extensions, SwiftPM manifests and NuGet-shipped MSBuild targets can run code during the install. `check` is the protection, not a sandbox. Dependencies from git/path/URL sources can't be matched against OSV and surface as `undetermined`.
- **Not gated:** Maven (no lockfile), Gradle (its lockfile is opt-in and it has no install step apart from a build), CocoaPods and Carthage.

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

# install a pre-commit hook (dependency scan only, no OS scan)
ubel-npm install-hook

# pull, scan, and keep or remove a Docker image based on policy
ubel-docker install node:20-alpine

# PHP: dry-run scan, then a scan-gated real install
ubel-composer check monolog/monolog
ubel-composer install monolog/monolog:^3.0
ubel-composer install                  # no args → resolves from existing composer.lock
ubel-composer install-hook             # dependency-scan pre-commit hook

# Python: dry-run scan, then a scan-gated real install into ./venv
ubel-pip check requests==2.31.0
ubel-pip install requests==2.31.0
ubel-pip install                       # no args → falls back to ./requirements.txt, then ./pyproject.toml

# Same, driven by uv instead of pip
ubel-uv check requests==2.31.0
ubel-uv install requests==2.31.0

# Python via conda: dry-run against a scratch prefix, then an exact-pinned scan-gated install into ./conda-env
ubel-conda check numpy=1.26
ubel-conda install numpy=1.26
ubel-conda install                     # no args → falls back to ./environment.yml, then ./environment.yaml

# Python via Poetry: dry-run in a scratch copy of the project, then install the scanned pyproject.toml + poetry.lock
ubel-poetry check requests@^2.31
ubel-poetry install requests@^2.31
ubel-poetry install                    # no args → scans the existing poetry.lock

# Rust: dry-run in a scratch copy of the project, then write the scanned manifest/lockfile and `cargo fetch --locked`
ubel-cargo check serde@1
ubel-cargo install serde@1
ubel-cargo install                     # no args → scans the project's existing Cargo.toml/Cargo.lock

# Lockfile-required engines (yarn, Bundler, Go, .NET, Dart, Flutter, SwiftPM): the lockfile must already exist, no package arguments
ubel-go check                          # scan what go.sum pins; installs nothing
ubel-yarn check                        # yarn.lock scanned; there is no `install` mode on these engines
# (ubel-bundle / ubel-dotnet / ubel-dart / ubel-flutter / ubel-swift work the same way)

# Python CLI tool: scan-gated install into an isolated venv + global shim
ubel-pipx install black

# Linux packages: dry-run scan, then a scan-gated `sudo apt install`
ubel-apt check curl
ubel-apt install curl
# (ubel-dnf / ubel-yum work the same way, against dnf/yum instead)
```

Policy (severity threshold, unknown-severity blocking) is configurable via `ubel-npm threshold <level>` and `ubel-npm block-unknown <bool>` (same subcommands under `ubel-composer`/`ubel-pip`/`ubel-uv`/`ubel-pipx`/`ubel-conda`/`ubel-poetry`/`ubel-cargo`/`ubel-yarn`/`ubel-bundle`/`ubel-go`/`ubel-dotnet`/`ubel-dart`/`ubel-flutter`/`ubel-swift`/`ubel-apt`/`ubel-dnf`/`ubel-yum`); malicious-package advisories are always blocked regardless of policy. License-risk policy (`license-risk`, `license-block-unknown`) is npm-family-only (npm/pnpm/bun/composer) — it isn't exposed as a subcommand on `ubel-pip`/`ubel-uv`/`ubel-pipx`/`ubel-conda`/`ubel-poetry`/`ubel-cargo`/`ubel-apt`/`ubel-dnf`/`ubel-yum`, matching those CLIs' narrower mode set.

**Exit codes:** `check` and `install` exit `0` if policy passes, `1` if policy blocks or the scan itself fails — including when a vulnerability lookup against OSV or NVD can't be completed (network error, rate limit, outage, or a malformed response). A failed or incomplete scan is never treated as a pass: for `install`, nothing is installed and the lockfile is restored from backup. On the lockfile-required engines (which only have `check`) a missing or empty lockfile, or a package argument, also exits `1`.

**Full documentation — every mode, policy config, reachability decision ladder, the pre-commit hook, and programmatic API:**
[**sca/README.md**](https://github.com/AlaBouali/ubel/blob/main/sca/README.md)

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
[**sca/README.md#fixed-configuration-scan-clis**](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#fixed-configuration-scan-clis)

---

## Re-scanning an SBOM — `ubel-resbom`

`ubel-resbom` is the one SCA binary that doesn't look at a project. It takes a CycloneDX SBOM that UBEL wrote earlier (`.ubel/reports/latest.<tag>.cdx.json`, or `report.<tag>.cdx.json` out of an unzipped history bundle), reads the components and the dependency graph from it, and runs the engine's normal pipeline over them: OSV/NVD lookup, KEV/EPSS enrichment, policy, suggested fixes, executive summary, and the JSON / HTML / SBOM / SARIF reports. No package manager runs, no lockfile is read, nothing is installed or reverted — so it works on a machine with none of the project's tooling, and there is no `check` / `install` mode.

```bash
# Is the release we scanned last quarter still clean? Re-scan its SBOM against today's advisories
ubel-resbom .ubel/reports/latest.sca.cdx.json

# Gate a scheduled job: exit 1 if anything high or worse (or on KEV) is now known — saved policy untouched
ubel-resbom ./release/report.sca.cdx.json --threshold high --block-kev

# Only fail on vulnerabilities that are reachable (verdicts recorded by the original scan are kept)
ubel-resbom latest.sca.cdx.json --reachable-only
```

- **What is recomputed vs. carried over.** Vulnerabilities, KEV/EPSS, component states, policy decision, suggested fixes, compliance mapping and the executive summary are computed again from current data (license classification too, when the SBOM came from a `health` scan). Asset id / name / type, machine id, the runtime, git and OS metadata the SBOM recorded, the secrets-in-source findings (there is no source tree to scan again) and the reachability verdicts of findings the SBOM already had are carried over; new findings get the graph-only reachability analysis, without import confirmation. OS packages (`deb` / `rpm` / `apk`) are matched against the distro release recorded on the component — see [OS Package Release Matching](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#os-package-release-matching).
- **Reports.** The file tag is the source scan's tag plus `_resbom` — `sca_resbom`, `docker_sca_resbom`, `os_sca_resbom`, `npm_firewall_resbom`, … — so a re-scan never overwrites the `latest.<tag>.*` files it came from. It gets the files its source tag gets: JSON, HTML and SBOM always, SARIF only for `sca`-type sources (`sca`, `docker_sca`, `agent_sca`, `<editor>_sca`). Files land in `./.ubel/reports/` and as a timestamped bundle under `$HOME/.ubel/history/<asset_id>/` — the asset being the one the SBOM came from, unless `--asset-id` names another.
- **Policy and exit codes.** The policy is `./.ubel/local/policy` of the current directory; `--threshold`, `--block-unknown`, `--block-kev`, `--epss-threshold`, `--block-undetermined`, `--reachable-only`, `--license-risk` and `--license-block-unknown` override it for one run. Exit `0` = policy passes, `1` = policy blocks (or bad arguments), `2` = the scan did not complete (unreadable / non-CycloneDX SBOM, incomplete advisory lookup, …). Reports are written whether the policy passes or blocks.
- **Input.** A CycloneDX JSON file — a `.zip` bundle has to be unzipped first. An SBOM from another tool is re-scanned best-effort with a warning (treated as a `health` scan of unknown origin). It can only re-check the components the SBOM lists; it never discovers new ones.
- **Programmatic.** `resbomScan({ sbom, projectRoot, policyOverrides })` from `@arcane-spark/ubel-node/sca`; throws a `PolicyViolationError` carrying the report when the policy blocks.

**Full documentation — accepted inputs, what is read from the SBOM, asset handling, tag/file matrix, exit codes, programmatic use, and limits:**
[**sca/README.md#re-scanning-an-sbom-ubel-resbom**](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#re-scanning-an-sbom-ubel-resbom)

---

## Filling an SBOM's vulnerabilities — `ubel-sbom`

`ubel-sbom` is the narrow sibling of `ubel-resbom`. Where `ubel-resbom` re-runs the whole pipeline on an SBOM UBEL wrote and produces reports, `ubel-sbom` takes **any CycloneDX JSON SBOM** — from UBEL, Syft, Trivy, cdxgen, … — and does one thing: it writes the known vulnerabilities of the components it lists into that SBOM's `vulnerabilities` array, each enriched with CISA KEV and FIRST EPSS. Nothing else in the file is touched, and nothing else is produced: no reachability, no VEX `analysis`, no policy decision, no JSON / HTML / SARIF report, no history zip.

```bash
# Fill the SBOM in place (atomically, and only once every lookup succeeded)
ubel-sbom ./bom.cdx.json

# Keep the original: write the filled copy somewhere else
ubel-sbom ./bom.cdx.json -o ./bom.with-vulns.cdx.json
```

**purl first, CPE only as a fallback.** Each component is looked up by its purl (OSV). Its CPE is consulted only when the component has no purl OSV can be asked about — no purl, a purl without a version, one that points to a VCS URL / download URL / file, a malformed one, or a type UBEL has no OSV mapping for. A component that has a usable purl is never also queried by CPE, even if it carries one. CPE 2.2 URIs are converted to 2.3, and a wildcard version in the CPE is replaced by the component's own version. A component with neither is not looked up and is reported (count and reason) on stderr.

Findings go through the same code as every scan (OS-package advisories are scoped to the component's distro release, GHSA / CVE alias pairs are collapsed, KEV and EPSS are added), and are written as standard CycloneDX vulnerabilities, with `affects` pointing at the component's `bom-ref`. A `vulnerabilities` array already in the file is replaced, so running it again refreshes the data. It fails closed like a scan: if OSV or NVD cannot be queried completely the run exits `2` and the file is left exactly as it was; an unreachable KEV / EPSS feed does not abort — those fields are written as `unknown` (never `false` / `0`) and a warning is printed. Requires CycloneDX 1.4 or newer (`vulnerabilities` does not exist before that).

See the [full reference](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#filling-an-sbom-with-vulnerabilities-ubel-sbom).

---

## Secrets Detection

Built on Trivy's ported secret-scanning ruleset (Apache-2.0, attributed in [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/NOTICE)), extended with rules for vendors not yet covered by Trivy's current upstream ruleset: HashiCorp Vault tokens, Google Cloud API keys and OAuth tokens, Anthropic and OpenRouter API keys, Firebase tokens, Stripe live restricted keys, Square and Braintree credentials, database and broker connection strings with embedded passwords (Postgres, MySQL/MariaDB, MongoDB, Redis, AMQP, SQL Server and others — as URLs, ADO.NET/libpq key=value strings, and JDBC URLs), and URL-embedded git credentials (GitHub, GitLab, Bitbucket, Azure DevOps, Codeberg, Gitea and other git hosts). Match previews in every report are redacted — the raw secret value is never written to disk.

```bash
# Standalone secrets-only scan — no dependency resolution, no LLM calls
ubel-secrets /path/to/project

# Working tree + git history (a secret committed and later deleted is still found)
ubel-secrets --history [--rev=origin/main..HEAD] [--since=2025-01-01] [--max-commits=500]

# Only what is staged for commit — what the pre-commit hook runs
ubel-secrets --staged
ubel-secrets --install-hook [--force]     # --force keeps an existing hook and chains to it
ubel-secrets --uninstall-hook

# Accept today's findings (appends fingerprints to .ubelignore) — also with --history / --staged
ubel-secrets --write-baseline

# Shared options: --include-dir= --exclude-dir= --unallow= --ignore-file= --include-env --json
```

Exit codes: `0` clean, `1` findings, `2` error. A secret found in history is compromised even if deleted — rotate it. The pre-commit hook blocks the commit on findings or on a failed scan; if `ubel-secrets` can't be found it warns and lets the commit through (`UBEL_HOOK_STRICT=1` blocks instead). Hooks are local and skippable with `--no-verify`, so also run `--history` in CI.

Every SCA binary's `install-hook` / `uninstall-hook` manages the **same single hook**, adding a dependency scan (`<engine> health`, no OS scan) to the secrets scan on every commit — see [SCA § Pre-commit hook](#pre-commit-hook-dependency-scanning).

Before anything runs, the entry point (`main.js`, not the scanners) makes sure `.gitignore` and `.dockerignore` in the working directory ignore `.ubel/` and `.ubelignore`, creating the files if needed — idempotent, append-only, and it respects an explicit `!.ubelignore`. Opt out with `UBEL_NO_IGNORE_FILES=1`.

Every `.ubel/` folder a UBEL CLI runs in also gets a `ubel_asset.json` — created by every CLI when it starts if it doesn't exist (and explicitly by `ubel-* init`, which prints it) — holding a random asset id — a random UUID v4 without hyphens, 32 hex characters (never changed) — and a readable asset name (the git repository name, else the folder name; editable). History zips are filed under the id — `~/.ubel/history/<asset_id>/<timestamp>.<tag>.zip` — so assets sharing `~/.ubel/history/` stay apart (the newest scan of each tag is also kept at `~/.ubel/latest_reports/<asset_id>/latest.<tag>.zip`), and the id, name and type are written into every report's JSON and HTML, and into the SBOM and SARIF. The type (`asset_type`) says what kind of thing was scanned — `codebase`, `cloud`, `easm`, `machine`, `agent`, `editor` or `docker` — and is decided per scan, not stored in `ubel_asset.json` (see [SCA § Asset types](sca/README.md#asset-types-asset_type)). Each report also gets its own `report_id`, `UBEL-<tag>-<asset_id>-<uuid>`: the tag is the report's file tag, the hash is a SHA-256 prefix of the asset id (so one asset's reports share it), and the uuid is random per report; it is made once per scan and is the same in the JSON, HTML, SBOM and SARIF (see [SCA § Report ID](sca/README.md#report-id-report_id)). All scanners do this — SCA, licenses, secrets, SAST/malware, docker, cloud and EASM. `ubel-apt` / `ubel-dnf` / `ubel-yum` use the machine id in `~/.ubel/ubel_machine.json` instead. That machine id (`machine_id`, an id only — no name) is also written into every report of every scanner (JSON, HTML, SBOM, SARIF) to say which machine produced it; see [SCA § Machine id](sca/README.md#machine-id-ubel_machinejson). `ubel-agent` scans use the report tag `agent_sca`. Editor-extension scans use the report tags `vscode_sca`, `cursor_sca` and `vscodium_sca`, each editor with its own asset id. See [SCA § Asset id](sca/README.md#asset-id-ubel_assetjson). Every CLI also takes `--asset-id <uuid>` to use a given id for one run (nothing is saved). Every CLI also takes `asset-id` (print the folder's id) and `set-asset-id <asset-id>` (link the folder to an existing one — a fresh clone, a deleted `.ubel/`) as commands in place of a scan, e.g. `ubel-npm asset-id`, `ubel-sast set-asset-id <id>` — see [Linking a folder to an existing asset id](sca/README.md#linking-a-folder-to-an-existing-asset-id) — and `version` (e.g. `ubel-npm version`) to print the installed version.

Secrets findings are also included in every `health`-mode SCA scan by default (`check`/`install` never run a secrets pass; `ubel-docker` runs the `health` pipeline in all three of its modes, so image scans always include one), surfaced in a dedicated tab in the HTML report and as a schema-correct extension on both the SBOM (a `ubel:secrets` property, since CycloneDX's root schema doesn't permit arbitrary top-level keys) and the SARIF output (its own `run`, separate from the dependency-vulnerability run).

---

## License Compliance

Every scanned package's declared license — whatever form it arrives in (an SPDX id, free text like "Apache 2.0", npm's `UNLICENSED` proprietary sentinel, a Python trove classifier, an `OR`/`AND` SPDX expression, or missing entirely) — is normalized into a canonical SPDX identifier, checked against the OSI-approved license list, and assigned a risk rating (`low` / `medium` / `high` / `unknown`) based on license category (permissive, weak-copyleft, strong-copyleft, proprietary, public-domain, unrecognized). Included in every `health` scan by default (license classification never runs on `check`/`install`).

```bash
# Standalone inventory + license scan — resolves dependencies (full-stack,
# every ecosystem present in the repo) and classifies licenses only; no
# OSV/NVD calls, no secrets scan. Writes JSON and HTML reports (no SBOM or
# SARIF — those come from `health` scans, which also carry the license data).
ubel-license /path/to/project
```

Surfaced per-package in the HTML report's inventory table and detail view, as `license.osi_approved` / `license.risk` / `license.category` properties on every SBOM component, and as its own SARIF run (`ubel-license-compliance`) that flags any non-OSI-approved or high-risk license as a finding.

**Full documentation:** [sca/README.md#license-compliance](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#license-compliance)

---

## Compliance Framework Mapping

Every finding produced anywhere in UBEL — SCA vulnerabilities and secrets, SAST vulnerability and malicious-code findings, and Cloud misconfigurations — is mapped onto industry compliance/security frameworks by default, no separate flag needed. All three modules share one mapping engine (`sca/compliance_mappings.js`): a finding is assigned one or more internal risk categories (e.g. `injection`, `public_exposure`, `vulnerable_components`), and each category carries a fixed list of framework control references, so the same underlying risk maps identically whether it was found by the dependency scanner, the AI SAST pipeline, or the cloud scanner.

**Frameworks:** OWASP Top 10 (2021), PCI DSS v4.0, HIPAA Security Rule, SOC 2 (Trust Services Criteria), ISO/IEC 27001:2022 (Annex A), NIST SP 800-53 Rev. 5, GDPR, and CIS Controls v8.

Every finding gets a `compliance` object (categories + per-framework control list); every report gets a top-level `compliance_summary` aggregating all findings into per-framework/per-control finding counts. Surfaced in a dedicated Compliance tab in every module's HTML report, in the JSON report's `compliance`/`compliance_summary` fields, and — for SCA and SAST, which emit SARIF — as `compliance`/`compliance_categories`/`compliance_frameworks` properties on SARIF rules and results.

**This is best-effort guidance, not a certified compliance assessment** — control identifiers are the stable, publicly documented ones for each framework, but framework text, versioning, and applicable scope can change and depend on your own environment. Every report carries this disclaimer verbatim in `compliance_summary.disclaimer`.

**Full documentation:** [sca/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#compliance-framework-mapping) (canonical framework/category reference) · [sast/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/sast/README.md#compliance-framework-mapping) · [cloud/README.md#compliance-framework-mapping](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md#compliance-framework-mapping)

---

## SAST — AI-Powered Static Analysis & Malicious Code Scanner

Chunks your codebase into semantically-bounded units (15 language families — 12 source-code languages (including Dart/Flutter and Swift) plus Docker, IaC, and Kubernetes manifests as their own dedicated families) and runs a three-pass LLM pipeline — **scan → verify → taint trace** — cross-referenced against a 64-class CWE-mapped vulnerability catalog. A fully separate 15-class malicious-code catalog covers intentionally planted backdoors and implants; that scan (`ubel-mal`) stops after **scan → verify**, since reachability isn't the relevant question for code that's itself the payload. Outputs JSON, interactive HTML, and SARIF 2.1.0 reports, ready for CI/CD gating.

Every SAST and malware report also carries a **Diffs** tab (`diffs` in the JSON): the code units (chunks), findings and — per compliance framework — mapped findings that are new, unchanged or removed since the asset's previous report of the same type (`sast` against `sast`, `malware` against `malware`), read back from the asset's history folder. Findings matched by vulnerability class + chunk (not line number), findings the verification pass dismissed as false positives are not counted, and a warning is shown when either scan was scoped (`--only-diff`, chunk cap). See [SAST § Diffs against the previous report](https://github.com/AlaBouali/ubel/blob/main/sast/README.md#diffs-against-the-previous-report).

```bash
# Vulnerability scan
ubel-sast /path/to/project

# Malicious-code / backdoor scan
ubel-mal /path/to/project

# Free preview of how a codebase will be chunked, no LLM calls
ubel-chunk /path/to/project
```

Supports OpenRouter, OpenAI, Anthropic, Gemini, DeepSeek, NVIDIA, local/Docker-hosted (Ollama-compatible), and fully custom endpoints — selectable per run, no code changes.

Like the SCA binaries, `ubel-sast` and `ubel-mal` make sure `.gitignore` and `.dockerignore` in the scanned directory ignore `.ubel/` and `.ubelignore` before they write their reports there, creating the files if needed — idempotent, append-only, and it respects an explicit `!.ubelignore`. Opt out with `UBEL_NO_IGNORE_FILES=1`.

**Exit codes:** governed by `--fail-on`, which only changes the process exit code — reports on disk always contain every finding regardless of this flag.
- `ubel-sast` (`analyze`): `any` *(default)* fails on any finding, including unresolved ones; `valid` fails only on findings verified `is_valid: true`; `exploitable` fails only on findings taint-traced `exploitable: true` (classes that need no attacker input, such as hardcoded secrets, are never traced — gate on them with `valid` or `any`). SAST also packs small chunks into shared calls, batches verification and tracing per chunk, records real token usage in the report, and reports anything it did not scan (chunk cap, oversized files, cut-off replies) instead of presenting it as a clean result: code that was not analyzed (a failed or unreadable AI call, a cut-off reply, an oversized file, chunks dropped by the default chunk limit) also fails the gate under every `--fail-on` level — see the SAST documentation.
- `ubel-mal` (`malware`): `any` *(default)* fails on any finding, including unresolved ones; `confirmed` fails only on findings verified `is_valid: true` — an unresolved finding still fails the build, since "couldn't determine" is never treated as clean, and so does code that was not analyzed.

**Full documentation — pipeline mechanics, every flag, token-cost breakdown, and CI examples:**
[**sast/README.md**](https://github.com/AlaBouali/ubel/blob/main/sast/README.md)

---

## Cloud — AWS / GCP / Azure Misconfiguration Scanning

Scans your AWS, GCP, and Azure accounts directly via each provider's own read-only API — live account state, not a static IaC/manifest scan, and nothing is deployed or modified. Covers public storage/database/network exposure (S3/GCS/Storage buckets, RDS/Cloud SQL/Azure SQL, security groups/NSGs/firewall rules open to the internet), IAM posture (overly permissive policies, missing MFA, stale access keys, permissive trust policies), Kubernetes cluster authorization (GKE/AKS control-plane exposure, RBAC/ABAC, legacy auth), missing encryption (EBS, RDS, CloudTrail, storage accounts), and disabled audit logging (CloudTrail, GuardDuty, VPC flow logs). Credentials are only ever used for that run — nothing stored or reused, same model as SAST's LLM credentials.

Every cloud report also carries a **Diffs** tab (`diffs` in the JSON): the findings, services, providers and — per compliance framework — mapped findings that are new, still present or fixed since the asset's previous cloud report, read back from the asset's history folder. Findings are matched on provider + service + check + resource + region; providers that were skipped, regions not scanned in both runs, and (with `--min-severity`) earlier findings below the current filter are left out so they never read as "fixed", and a note is shown when the scanned account or the filter changed. See [Cloud § Diffs against the previous report](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md#diffs-against-the-previous-report).

```bash
# Scan all three providers (default: aws,gcp,azure) — a provider without credentials is skipped and the run exits 3
ubel-cloud

# Scan a specific provider only
ubel-cloud --provider aws

# Explicit AWS region override — skips DescribeRegions auto-discovery
ubel-cloud --provider aws --regions us-east-1,eu-west-1

# Knowingly accept a skipped / part-way provider instead of exiting 3
ubel-cloud --allow-partial
```

Outputs JSON and HTML (no SARIF, no SBOM — this isn't a dependency scan). **Exit codes:** governed by `--fail-on` (default `critical`), same severity-threshold/count syntax as the rest of UBEL — reports on disk always contain every finding regardless of this flag. A requested provider that was skipped (no credentials) or stopped part-way makes the run exit `3` when no finding tripped `--fail-on`; `--allow-partial` accepts partial coverage, and `--fail-on none` always exits `0`.

**Full documentation — every check, per-provider credential setup, and all flags:**
[**cloud/README.md**](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md)

---

## Mobile — Android / iOS App Scanning

`ubel-mobile <app.apk | app.aab | app.ipa | app.xapk | app.apks>` statically analyses a mobile app package — nothing is executed, nothing is sent anywhere — for **hardcoded secrets** (UBEL's shared secrets rules over DEX strings and constants, string resources, plists, bundled files and native-library strings), **insecure storage and data handling** (backups, world-readable files, weak or constant crypto keys/IVs, bundled keystores/databases, Keychain/data-protection attributes) and **misconfigurations** (debuggable builds, cleartext traffic, ATS exceptions, exported components, WebView settings, TLS-validation bypasses, weak signing, missing binary hardening). Findings are mapped to OWASP MASVS and written as JSON and HTML (`report.mobile.json` / `report.mobile.html`, plus `latest.mobile.*` under `.ubel/reports/`), with a Diffs section against the asset's previous scan. The whole module is pure Node built-ins: ZIP, Android binary XML, `resources.arsc`, DEX, plist (XML and binary), Mach-O, ELF and PKCS#7/X.509 are all read directly, so no `aapt`, `apktool`, `jadx`, `otool` or `codesign` is needed. There is no decompiler: a finding comes from manifests/plists, resources, constant tables, API references and call arguments, and binary metadata. See [Mobile § Limits](https://github.com/AlaBouali/ubel/blob/main/mobile/README.md#limits).

```bash
ubel-mobile app-release.apk
ubel-mobile Bank.ipa --fail-on high --min-severity medium
```

Two kinds of component are looked up. The package's own dependencies come from `pom.properties`, `META-INF/*.version`, `dependencies.pb` (AAB), `Package.resolved` and `Podfile.lock` (OSV.dev); a library found only by DEX class names has no version and stays `not_queryable`. The software bundled *inside* the app's native libraries — the preferred-ABI copy of every `lib/<abi>/*.so` (and the `assets/**/lib/<abi>/` ones) of an APK / AAB, and every Mach-O of an IPA (main executable, frameworks, dylibs, extensions) — is read with the component detection of `ubel-binary` (see [Binary](#binary--native-executables-and-libraries)): C/C++ version banners (OpenSSL, SQLite, libcurl, zlib, …) become NVD CPE queries, Go modules and Rust crates become OSV.dev package URLs. Those components appear in the same Dependencies tab (the file they were seen in is listed as their source), their advisories are reported as `binary.component.vulnerable` findings and count towards `--fail-on`, and a component whose version could not be read is listed as `not_queryable`, never as clean. A native library that cannot be read, or a failed NVD / OSV lookup, is a coverage gap (exit 3 unless `--allow-partial`). A version banner shows the code is in the library, not that the vulnerable function is reachable. The standalone `ubel-binary` is still the tool for a binary that is not inside a package.

## Binary — Native Executables and Libraries

`ubel-binary <file>` statically analyses one native ELF (Linux, Android), Mach-O (macOS, iOS; thin and fat) or PE (Windows) executable or library — nothing is executed or loaded, and no third-party library or external tool is used. It reports missing build hardening (PIE, NX, RELRO, canary, FORTIFY, hardened runtime, ASLR / DEP / CFG …), risky imports, hardcoded secrets in the file's strings, the remote hosts it names, a behavior inventory, and known-vulnerable components. It shares its reader, report, diff and `--fail-on` gate (exit 0/1/2/3) with `ubel-mobile`, and writes `report.binary.json` / `report.binary.html` (plus `latest.binary.*` under `.ubel/reports/`). Details: [binary/README.md](https://github.com/AlaBouali/ubel/blob/main/binary/README.md).

```bash
ubel-binary ./build/server
ubel-binary libfoo.dylib --fail-on high
```

### How components reach NVD / OSV

Components come from four sources and are looked up as follows:

| Source | Record | Lookup |
|---|---|---|
| C/C++ version banners (OpenSSL, zlib, libcurl, SQLite, libxml2 …) | CPE | NVD, version-verified against each CVE's CPE ranges |
| Go build info | PURL `pkg:golang/…` | OSV.dev |
| Rust cargo-auditable data or crate paths | PURL `pkg:cargo/…` | OSV.dev |
| npm / Python packages of packaged applications | PURL | OSV.dev |

- Banners are searched over the **whole file** for ELF, PE and Mach-O alike; a Mach-O no longer depends on its banners sitting in `__cstring`-type sections (Go builds keep text in `__rodata`). For Mach-O secrets, `sectionBuffers` falls back to the whole slice when the slice has no string section.
- ELF symbol-version tags (`LIBXML2_2.4.30`) are not banners; each false component would cost one rate-limited NVD query.
- NVD advisories keep their `aliases` in the report.
- A failed lookup is reported as a failure of that component (exit 3), never as clean. Regression tests: `node --test tests/binary-components.test.js` (hand-built Mach-O fixtures and a local NVD mock).

## EASM — External Attack Surface Fingerprinting

> **⚠ Authorized use only.** `ubel-url` sends live requests (unauthenticated,
> unless you pass `--cookie` / `--header`) to
> every target you give it and discloses what it fingerprints to OSV.dev/NVD/
> wpvulnerability.net. `ubel-domain` does the same, but discovers its own
> target list from Certificate Transparency logs first — so it can end up
> scanning hosts you didn't explicitly name. `ubel-host` goes further: it
> connect-scans every port in a range (1-30000 by default) on every IP the hosts you give it resolve to and
> fingerprints whatever answers HTTP(S) — a live port sweep, not just a
> fingerprint request. `ubel-easm` combines both — it discovers a domain's
> subdomains, resolves each to an IP, then runs `ubel-host`'s full port
> sweep against every distinct IP behind the domain, the most invasive of
> the four and the most likely to reach infrastructure you didn't intend to
> touch (shared hosting, a CDN edge IP — see the "Shared IPs" note in
> `easm/README.md`). Only ever run any of these four against infrastructure
> you own or have explicit, documented authorization to test — the same
> own-infrastructure-only rule every other UBEL module already holds you to.
> See [easm/README.md](https://github.com/AlaBouali/ubel/blob/main/easm/README.md)
> for the full notice.

Passively fingerprints the software exposed on a domain/URL over plain
HTTP(S) — server banners, version headers, page markup, a small set of
well-known paths — turns what it finds into candidate CPE identifiers, and
feeds those through the exact same OSV.dev/NVD/wpvulnerability.net
vulnerability-lookup engine the SCA module uses (wpvulnerability.net for
WordPress plugins/themes/core specifically, which NVD's CPE dictionary
mostly misses). No authentication, no brute forcing, no exploitation — just
unauthenticated GETs and a lookup against public vulnerability data.

`ubel-domain` runs the identical scan, with the target list discovered for
you first:

```
domain  →  crt.sh subdomain discovery  →  fingerprint every host
        →  group techs by name+version (with the host list for each)
        →  vulnerability lookup + misconfiguration checks  →  one report
```

Give it a root domain and it enumerates every subdomain a public CA has
logged a certificate for (via [crt.sh](https://crt.sh)) — passive discovery
only, no DNS brute-forcing, no zone-transfer attempts — then fingerprints
all of them in one run through the same engine `ubel-url` uses, so a
technology found on forty subdomains is one inventory row with a forty-host
list, not forty near-identical rows. `--list-only` prints that discovered
list without sending a single request to any of those hosts, so you can
review and trim it (`--exclude`, or add hosts crt.sh missed with
`--include`) before authorizing the real scan.

`ubel-host` adds a step *before* fingerprinting instead of before discovery
— give it one or more hosts (IPs and/or domains, handled exactly the way `ubel-easm` handles crt.sh hostnames: resolved, grouped by distinct IP, and scanned by name too), and it connect-scans every port in `--ports` (default
`1-30000`), probes whatever accepts a connection for HTTP(S), and hands only
the HTTP(S)-speaking ports to the same fingerprint/lookup engine `ubel-url`
uses, so you don't need to already know which port a target's web app or
admin panel lives on. This is genuinely active reconnaissance, not passive
fingerprinting — see the warning above.

`ubel-easm` is `ubel-domain`'s discovery and `ubel-host`'s port sweep
together across a whole domain: crt.sh discovery → resolve every subdomain
to an IP → collapse to the **distinct** IPs actually behind the domain
(several subdomains commonly share one) → port-scan and HTTP(S)-probe each
of those IPs → fingerprint the merged IP:port targets **and** the
discovered subdomains by name (a bare-IP request has no Host header/SNI, so
it can't see a name-based virtual host; controlled by `--subdomain-ports`).
A component seen on five IPs behind the domain is still one inventory item,
the same name+version dedup `ubel-domain` gets across subdomains.

Every host is also checked, automatically, for a fixed set of common
misconfigurations, independent of the CVE lookup above: an exposed
`.env`/`.git`/`docker-compose.yml`, exposed `phpinfo()` output, an
unauthenticated Spring Boot Actuator `env` endpoint (`/actuator/env`,
`/env`), a publicly reachable Swagger/OpenAPI specification or Swagger UI,
TLS/certificate weaknesses
(expiry, trust, hostname mismatch, weak/legacy protocol and cipher support),
missing/weak security headers and cookie flags (HSTS, CSP, clickjacking
protection, `X-Content-Type-Options`, `Referrer-Policy`,
`Permissions-Policy`, `Secure`/`HttpOnly`/`SameSite` on any `Set-Cookie`),
risky HTTP methods (`PUT`/`DELETE`/`TRACE`/`CONNECT` advertised, plus an
actual Cross-Site Tracing probe), CORS misconfiguration (arbitrary-Origin
reflection, a wildcard paired with credentials, the `null` Origin), SPF/
DMARC/DKIM email-authentication gaps, and — on hosts already identified as
WordPress — a reachable `xmlrpc.php` and unauthenticated user enumeration.
This runs the same way across all four entry points.

All four also accept `--cookie <value>` and `--header "Name: Value"`
(repeatable) to fingerprint behind a login. They are sent on the
fingerprinting requests only — the port scan, the secrets crawl and the
misconfiguration probes stay unauthenticated — and, with `ubel-domain`,
`ubel-host` and `ubel-easm`, on every discovered subdomain and `IP:port`, so
pass only a credential you are prepared to present to all of them. Reports
record only that a cookie was used and the header *names*.

It's a deliberate subset of an SCA report: no license compliance (no
manifest to read one off of), no dependency sequences/graph (nothing here
is resolved from a lockfile), no reachability analysis (no source code to
trace), and no SBOM/SARIF — JSON and HTML only. CVSS scoring, fix-version
recommendations (including per-component suggested fixes), CISA KEV / FIRST
EPSS exploit intelligence (which also gates the exit code), an executive
summary, and the same compliance framework mapping every other module uses
are all still included. Every detected component is reported
with `scopes: ["prod"]` — anything fingerprinted over the network is, by
definition, already running.

Every EASM report (`ubel-url`, `ubel-domain`, `ubel-host`, `ubel-easm`) also carries a **Diffs** tab (`diffs` in the JSON): IPs, domains, IP ports, misconfigurations, technologies (name + version), exposed secrets, findings per technology and — per compliance framework — mapped findings that are new, existing or removed since the asset's previous report of the same CLI, read back from the asset's history folder. Secrets are only compared when both runs scanned for them (no `--no-secrets`), so a skipped crawl never reads as "all fixed"; when the two runs used a different `--min-severity`, vulnerability findings are compared at the stricter level so a filtered-out finding never reads as new or removed; a technology upgrade shows as one removed and one new row. See [EASM § Diffs against the previous report](https://github.com/AlaBouali/ubel/blob/main/easm/README.md#diffs-against-the-previous-report).

```bash
# One domain, safety guard on by default (skips private/self-IP targets)
ubel-url example.com

# Several targets in one run, one report
ubel-url a.example.com b.example.com --fail-on high

# Targets loaded from a file (one per line, "#" comments ignored)
ubel-url --targets-file targets.txt

# Several domains from a file: discover each, scan everything found, one report
ubel-domain --domains-file domains.txt --list-only

# A lab/localhost target you own
ubel-url localhost:8080 --allow-private

# See what a domain-wide sweep would touch, without touching anything
ubel-domain your-company.example --list-only

# Discover every subdomain of a domain you own, then scan them all
ubel-domain your-company.example --fail-on high

# See what ports are open on a host you own, without fingerprinting anything
ubel-host app.your-company.example --list-only

# Port-scan and fingerprint a host you own, well-known ports only
ubel-host app.your-company.example --ports 1-1024 --fail-on high

# Review the IP grouping a combined sweep would touch, before authorizing it
ubel-easm your-company.example --list-only

# Combined discovery + per-IP port sweep of a domain you own
ubel-easm your-company.example --fail-on high
```

Outputs JSON and HTML only. **Exit codes:** governed by `--fail-on` (default
`critical`), same severity-threshold/count syntax as the rest of UBEL —
reports on disk always contain every finding (vulnerabilities and
misconfigurations alike) regardless of this flag. `--fail-on` gates on
vulnerabilities, infections and web misconfigurations together: a
misconfiguration counts toward the severity bar and the `N:sev` count
exactly like a vulnerability of the same severity.

**Full documentation — the responsible-use notice, safety guard, every
`ubel-host`/`ubel-easm` flag, the "Shared IPs" warning, and the full
misconfiguration-check list:**
[**easm/README.md**](https://github.com/AlaBouali/ubel/blob/main/easm/README.md)

---

## CI/CD Integration

All binaries exit non-zero on findings that clear their respective gate, so any of them fit natively into a CI runner. `ubel-sast`, `ubel-mal` and `ubel-cloud` also exit non-zero when part of the assessment did not run — code that was not analyzed, or a requested cloud provider that was skipped or stopped part-way (`ubel-cloud --allow-partial` accepts the latter).

### GitHub Actions — using the packaged action

[`action.yml`](https://github.com/AlaBouali/ubel/blob/main/action.yml) wraps `npx @arcane-spark/ubel-node@<version>` as a composite action, behind an explicit `command` allow-list validated against UBEL's actual registered `package.json` bin names — so it can never construct or execute a binary name that isn't one of ours, regardless of what a caller passes. `command`, `version`, and `args` are step inputs referenced as shell variables (`$COMMAND`/`$ARGS`), never interpolated directly into the script with `${{ }}`, closing off GitHub's documented script-injection risk for composite actions.

```yaml
- uses: AlaBouali/ubel@<commit-sha>   # pin to a commit SHA, not a mutable tag
  with:
    command: npm
    version: 0.23.0
    args: check

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: npm                      # `command` selects the bin; the mode (check/install/health) goes in `args`
    version: 0.23.0
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
    command: url                      # EASM — only ever point `args` at infrastructure you own, see easm/README.md
    args: staging.your-own-domain.example --fail-on high

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: pip
    args: install                     # scan-gated `pip install`, resolved from ./requirements.txt

- uses: AlaBouali/ubel@<commit-sha>    # needs a preceding conda setup step (e.g. conda-incubator/setup-miniconda) for `conda` itself
  with:
    command: conda
    args: install                     # scan-gated conda install, resolved from ./environment.yml

- uses: AlaBouali/ubel@<commit-sha>    # needs a preceding step that installs Poetry (e.g. snok/install-poetry) and a Python interpreter for it
  with:
    command: poetry
    args: install                     # scan-gated; scans ./poetry.lock, then poetry install --no-root

- uses: AlaBouali/ubel@<commit-sha>    # needs the Rust toolchain on PATH (e.g. dtolnay/rust-toolchain)
  with:
    command: cargo
    args: install                     # scan-gated: scans ./Cargo.lock, then `cargo fetch --locked`

- uses: AlaBouali/ubel@<commit-sha>    # lockfile-required engine (also yarn, bundle, dotnet, dart, flutter, swift): go.sum must be committed, no package args
  with:
    command: go
    args: check                       # `check` only reads go.sum and needs no toolchain; there is no `install` mode — run `go mod download` in a later step

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: composer
    args: install                     # scan-gated `composer install --no-scripts --no-plugins`, resolved from composer.lock

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: apt                      # dnf/yum work the same way, as their own `command` values
    args: check curl
```

`command` must be one of: `sast`, `mal`, `chunk`, `cicd`, `agent`, `platform`, `secrets`, `license`, `cloud`, `mobile`, `url`, `domain`, `host`, `easm`, `npm`, `pnpm`, `bun`, `yarn`, `composer`, `docker`, `pip`, `pipx`, `uv`, `conda`, `poetry`, `cargo`, `bundle`, `go`, `dotnet`, `dart`, `flutter`, `swift`, `apt`, `dnf`, `yum`, `resbom`, `sbom` — anything else fails the step before `npx` ever runs. `domain`, `host`, and `easm` are in the allow-list too, but they actively probe whatever target you pass them: only point them at assets your organization owns, and think twice before running `easm` unattended (it expands a domain into every subdomain IP, which can include shared CDN/hosting addresses you don't own — see the comments in `action.yml`).

The lockfile-required commands (`yarn`, `bundle`, `go`, `dotnet`, `dart`, `flutter`, `swift`) fail the step with exit `1` when the lockfile is missing or `args` contains a package name — `args` is just the mode (`check` / `health`; `install` is not available on these engines). `check` only reads files and needs no toolchain on the runner; do the actual install in a separate step after it passes.

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

- name: UBEL lockfile-gated install (yarn / Bundler / Go / .NET / Dart / Flutter / SwiftPM — the lockfile must be committed)
  run: ubel-go install

- name: UBEL SAST scan
  run: ubel-sast --fail-on exploitable

- name: UBEL malicious-code scan
  run: ubel-mal --fail-on confirmed

- name: UBEL license compliance scan
  run: ubel-license .

- name: UBEL cloud misconfiguration scan
  run: ubel-cloud --fail-on high

- name: UBEL external attack surface scan (only against infra you own — see easm/README.md)
  run: ubel-url staging.your-own-domain.example --fail-on high

- name: UBEL domain-wide attack surface sweep (discovers subdomains first — only against a domain you own)
  run: ubel-domain your-own-domain.example --fail-on high

- name: UBEL port scan + fingerprint (connect-scans 1-1024, only against a host you own)
  run: ubel-host staging.your-own-domain.example --ports 1-1024 --fail-on high

- name: UBEL combined discovery + per-IP port sweep (most invasive EASM entry point — only against a domain you own, review with --list-only first)
  run: ubel-easm your-own-domain.example --fail-on high
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-composer install
RUN ubel-sast --fail-on valid .
```

### Pre-commit hook vs. CI

Every SCA binary can add a dependency scan to the single ubel git pre-commit hook with `ubel-<engine> install-hook`. It's a client-side convenience — skippable with `git commit --no-verify`, and only present on a clone where the developer actually ran `install-hook`. Treat it as a fast local gate, not a replacement for the CI scans above; keep `ubel-<engine> check` (or `health`) in the pipeline so nothing reaches a shared branch unscanned.

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
comes in two forms:

1. **Dry-run resolution** — where a package manager can resolve a candidate
   set with no (or, for pip/uv, no *typical*) side effects: **npm, pnpm, bun
   and Docker images** via a true lockfile-only dry-run, **PHP (Composer)**
   via the same lockfile-backed mechanism (`composer require`/`update
   --no-install --no-scripts --no-plugins`), **pip/uv/pipx/conda/poetry**
   (`pip install --dry-run` / `uv pip install --dry-run` / `conda create
   --dry-run --json` / `poetry add --lock` in a scratch copy), **Rust
   (Cargo)** (`cargo add` + `cargo update --workspace` in a scratch copy of
   the project) and **Linux host packages** (`apt`/`dnf`/`yum`'s own native
   dry-run).
2. **Lockfile required** — where UBEL has no safe way to resolve a candidate
   lockfile first: **yarn, Bundler (Ruby), Go modules, .NET/NuGet, Dart,
   Flutter and SwiftPM**. Nothing is resolved: the project's lockfile must
   already exist and `check` scans exactly what it pins (reading only the
   lockfile — no manifest or toolchain needed). These engines are
   **`check`-only**: there is no `install` mode, so the install itself is done
   with the package manager's own frozen command after `check` passes. No
   lockfile → refused, and package arguments are refused in every mode.

Java/Kotlin (Maven) and Windows remain SCA-covered but not firewall-covered:
Maven has no lockfile to require and no dry-run to hook into (Gradle's
lockfile is opt-in and Gradle has no install step apart from a build), and
Windows has no dry-run-without-side-effects equivalent to gate against —
a mechanical constraint of each ecosystem's tooling, not an oversight.
Carthage and CocoaPods are not gated either (SwiftPM's `Package.resolved` is).

---

## Capability Matrix

| Ecosystem | SCA | Firewall | Pre-commit hook | SAST | Malware SAST | Reachability | License Compliance | Secrets |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Node.js (npm/pnpm/bun) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node.js (yarn) | ✅ | ✅ (lockfile required) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python (pip/uv/pipx/conda/poetry/venv) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP (Composer) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby (Bundler) | ✅ | ✅ (lockfile required) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Rust (Cargo) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Go (modules) | ✅ | ✅ (lockfile required) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Java / Kotlin (Maven) | ✅ | ❌ | ⚠️ | ✅ | ✅ | ✅ | ❌ | ✅ |
| C# / .NET (NuGet) | ✅ | ✅ (lockfile required) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Swift (SwiftPM / Carthage) | ✅ | ⚠️ (SwiftPM only, lockfile required) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Flutter / Dart (pub) | ✅ | ✅ (lockfile required) | ✅ | ✅ | ✅ | ✅ | ❌ | ✅ |
| C/C++ | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Docker images | ✅ (OS + app deps) | ✅ | — | — | — | — | ✅ | ✅ (in image) |
| Kubernetes manifests | — | — | — | ✅ (misconfig) | ✅ | — | — | ✅ |
| Terraform / CloudFormation (IaC) | — | — | — | ✅ (misconfig) | ✅ | — | — | ✅ |
| Linux host (apt/dnf/yum) | ✅ | ✅ | — | — | — | — | ✅ | — |
| Windows host | ✅ | ❌ | — | — | — | — | ✅ | — |
| VS Code / Cursor / VSCodium extensions | ✅ | — | — | — | — | — | — | — |

✅ = built and shipped · ⚠️ = partial, see that ecosystem's section · ❌ = not currently possible/present for a stated reason · — = not applicable to that layer

> **Pre-commit hook** column = the dependency-scanning git hook installed by `ubel-<engine> install-hook`. It runs `<engine> health` — a dependency scan, no OS scan — on every commit (`UBEL_HOOK_SCA=auto`: only when a manifest/lockfile is staged). Since it's gated on `health` support, its coverage matches the SCA column except where there's no per-engine binary to attach `install-hook` to: Maven/Kotlin has none of its own, so it shows ⚠️ — a hook installed from an npm-family engine or `ubel-composer` runs a **full-stack** `health` scan, which also reads Maven's manifests/lockfiles in the repo (its files are in the hook's `auto`-mode trigger list too), but there is no `ubel-maven` hook of its own. Yarn, Bundler, Go, .NET, Dart, Flutter and SwiftPM each have their own binary (`ubel-yarn`, `ubel-bundle`, `ubel-go`, `ubel-dotnet`, `ubel-dart`, `ubel-flutter`, `ubel-swift`), so `ubel-<engine> install-hook` works for them like for the other engines. The pip/uv/pipx/poetry/conda/cargo hooks run a single-ecosystem `health`. The secrets pre-commit hook (`ubel-secrets --install-hook`) is a separate hook and separate feature — see [Secrets Detection](#secrets-detection).

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
`revert_lock_to_original`. **Yarn has no dry-run to resolve against** — `yarn add` always writes to
`node_modules` before you'd get a chance to block it, and yarn's own CLI offers
no resolution step that stops short of writing to disk — so `ubel-yarn` is
gated the *lockfile-required* way instead: `yarn.lock` must already exist (no
lockfile, or a package argument, is refused with exit `1`), `check` scans what
it pins (only `yarn.lock` is read; `package.json` is not needed). There is no
`ubel-yarn install`: once `check` passes, run the frozen install yourself
(`yarn install --frozen-lockfile --ignore-scripts` on Yarn 1,
`yarn install --immutable --mode=skip-build` on Yarn 2+). Because nothing is
resolved, adding a package is done with `yarn add` itself; review and commit
the lockfile, then run `ubel-yarn` again. Yarn projects also get full SCA,
SAST, secrets, license, and **pre-commit hook** coverage. (Python and Linux
host packages also get a real pre-install gate
now — see their sections below — just via a simpler revert-less mechanism,
since neither has a lockfile to roll back.)

**Pre-commit hook:** `ubel-npm install-hook`, `ubel-pnpm install-hook`,
`ubel-bun install-hook`, and `ubel-yarn install-hook` all work. The hook
runs `<engine> health` on every commit by default (a full-stack scan, so
it also reads any Go/Maven/NuGet/Ruby/Swift/pub/Cargo manifests in the
repo). With `UBEL_HOOK_SCA=auto` it runs only when a commit stages
`package.json`, `package-lock.json`, `pnpm-lock.yaml`,
`pnpm-workspace.yaml`, `bun.lock`/`bun.lockb`, or `yarn.lock` (or any
other recognised manifest/lockfile), anywhere in the tree, so monorepo
sub-packages count; `UBEL_HOOK_SCA=off` skips it. It
reads the installed dependency graph — no `node_modules` mutation, no
lockfile dry-run, no network call other than OSV/NVD lookups against what's
already there.

**SAST / Malware SAST:** Full three-pass (scan → verify → taint-trace)
vulnerability pipeline and two-pass malware pipeline, JS/TS-aware chunking.

**Reachability analysis:** Full import-graph reachability — a vulnerable
package is downgraded in priority if nothing in your code path actually
imports the vulnerable module, and orphaned/unused dependencies get
flagged separately. This is one of ten ecosystems with this capability
(see the Reachability Analysis note under Cross-Cutting Capabilities).

**Editor integration:** The VS Code/Cursor/VSCodium extension runs
in-process (no shell-out), with dedicated commands for project scan, host
scan, and — uniquely for this ecosystem — a scan of the **editor's own
installed extensions**, since a malicious VS Code extension is itself a
supply-chain vector most tools never consider.

---

## Python — pip / uv / pipx / conda / poetry / venv

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

**Pre-commit hook:** `ubel-pip install-hook`, `ubel-uv install-hook`,
`ubel-pipx install-hook`, `ubel-conda install-hook`, and `ubel-poetry install-hook` all work. The hook
runs `<engine> health` (dependency scan only) on every commit by default;
with `UBEL_HOOK_SCA=auto`, only when a commit stages `requirements*.txt`,
`constraints*.txt`, `pyproject.toml`, `Pipfile`/`Pipfile.lock`,
`setup.py`, `setup.cfg`, `poetry.lock`, `uv.lock`, `pdm.lock`,
`conda-lock.yml`, or `environment.yml`/`environment.yaml`. Not available on apt/dnf/yum (they scan the host, not a repo).

Two honesty notes, both of them limits of the underlying tools rather than
gaps in UBEL's own implementation:
- Source distributions are refused rather than built: resolving a
  source-only package's metadata can require building an sdist, which runs
  arbitrary `setup.py`/build-backend code, so the dry-run and the real
  install both pass `--only-binary=:all:` and a package with no compatible
  wheel fails closed. The real install also passes `--no-deps` (it installs
  exactly the scanned, pinned set); the dry-run does not, since it must
  resolve the transitive closure. The cost is that sdist-only packages
  can't be installed through these tools. **The pre-commit hook doesn't
  touch this at all** — it's a `health` scan of already-installed
  packages, so no resolution happens.
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

**conda firewall (`ubel-conda`):** `check`/`install` resolve with `conda create --dry-run --json` against a scratch prefix that never exists — conda fetches repodata and runs its solver but downloads and links nothing, and `check` leaves no environment behind. Unlike pip/uv, the dry-run therefore always reports the full resolved closure. On a clean scan, UBEL writes the resolved set to `.ubel/dependencies/conda-specs.txt` as exact `channel::name==version=build` pins, records its SHA-256, re-checks it immediately before conda runs, and installs with `conda create --no-deps --no-default-packages --file` into `./conda-env` (or `conda install --no-deps --file` if that environment already exists; `create` is never run against an existing environment because `conda create --yes` removes one first). A blocked scan never runs the real install; there's no lockfile to revert. Channels come from conda's own configuration — option-shaped arguments, paths, URLs and bare package-file names are rejected before conda is invoked. With no arguments, `check`/`install` read the flat `dependencies:` list of `./environment.yml` / `./environment.yaml` (a nested `- pip:` block is skipped — scan those with `ubel-pip` — and `channels:` is ignored). `ubel-conda init` creates an empty `./conda-env`; `ubel-conda health` inventories the Python packages inside conda environments (found by `conda-meta/`, including each environment under a base install's `envs/`).

Honesty notes specific to conda:
- OSV has no conda ecosystem. Packages whose build string carries conda's `py` marker are reported as `pkg:pypi/…` and matched against PyPI advisories (a small built-in map handles names that differ, e.g. `pytorch`→`torch`; an unmapped differing name is a missed match, never a wrong one). Everything else (`openssl`, `libxml2`, `python` itself, …) is inventoried as `pkg:conda/…`, is **not** matched against any database, and stays `undetermined` rather than `safe`. The summary counts (`inventory_stats`) put these in `undetermined`, not `safe`, and each conda scan with such packages prints a warning with their number.
- The dry-run JSON carries no dependency edges, so every component is its own root, and `license` is `unknown` on `check`/`install`. No `requirements.txt`/`pyproject.toml`/`environment.yml` sync happens after install.
- conda is the one engine whose real install isn't script-free: conda runs each package's own pre/post-link scripts on install and UBEL has no flag to suppress them. The firewall guarantees only that exactly the scanned builds are installed.

**poetry firewall (`ubel-poetry`):** `check`/`install` resolve in a scratch copy of the project — `pyproject.toml`, `poetry.lock`, `poetry.toml` and the declared readme are copied to a temporary directory and Poetry runs there, so the project is never modified before the scan passes. With package arguments the command is `poetry add --lock <packages>` (main group only; locks, installs nothing); with none, the project's existing `poetry.lock` is scanned as-is, and `poetry lock` runs in the scratch copy only if there is no lockfile yet. The scanned `poetry.lock` is the inventory: it holds the full closure, the dependency edges (so `introduced_by`/`parents` are populated, unlike uv/conda) and the dependency groups (packages outside `main` are scoped `dev`). On a clean scan UBEL writes the scanned `pyproject.toml` and `poetry.lock` into the project and runs `poetry install --no-root`; both files are SHA-256 recorded after resolution and re-checked immediately before the install, the project's own `pyproject.toml` must be unchanged since the scan (so a concurrent edit is never overwritten), and the originals are restored if the install fails. `--no-root` keeps the project's own build backend from running. Source distributions are refused with Poetry's `installer.only-binary = :all:`; because older Poetry releases silently ignore unknown settings, UBEL asks the installed Poetry for the value it will actually use first and aborts the install if it isn't honoured. Package sources come from Poetry's own configuration — option-shaped arguments, paths, URLs, whitespace, `:` and `;` are rejected before Poetry is invoked. `ubel-poetry init` runs `poetry init --no-interaction` when there is no `pyproject.toml`; `ubel-poetry health` scans a project-local `.venv` and also the environment reported by `poetry env info --path`.

Honesty notes specific to poetry:
- Registry packages (PyPI or any Poetry `legacy` index, treated like pip with a custom `--index-url`) are matched against OSV as `pkg:pypi/…`. Packages locked from git, a URL or a local file/directory are not the registry package of the same name: they are not queried, carry the `?vcs_url=`/`?download_url=`/`?file=` purl qualifier, and stay `undetermined` rather than `safe` (`block-undetermined` is on by default, so they fail the check/install unless you turn it off with `ubel-poetry block-undetermined false`).
- Poetry can still build a source distribution while *locking* when an index publishes no wheel metadata for a package (rare on PyPI). That is Poetry's own step and can't be disabled from outside; it never happens at install time.
- `license` is `unknown` on `check`/`install`, and no `requirements.txt` sync happens after install — Poetry owns `pyproject.toml`/`poetry.lock`, which are overwritten with the scanned versions. `--group`/`--dev` and other `poetry add` options are not accepted, and `venvDir` is not used because Poetry manages its own virtualenv.

**SAST / Malware SAST:** Full coverage, same three-pass/two-pass pipelines.

**Reachability analysis:** Fully covered, tracking `.py` files against the
resolved dependency graph — one of ten ecosystems with this capability.

---

## PHP — Composer

**SCA:** Resolves the dependency tree from `vendor/` and `composer.lock`.

**Firewall:** Available via `ubel-composer` — the same lockfile-backed shape
as npm/pnpm/bun, not the simpler revert-less mechanism pip/apt/dnf/yum use.
`composer require`/`update --no-install --no-scripts --no-plugins` (Composer's own
equivalent of `--package-lock-only`) resolves the candidate dependency tree
and writes a candidate `composer.lock`/`composer.json` without touching
`vendor/`; UBEL scans that candidate, and only then runs the real install —
`composer install --no-scripts --no-plugins`. A policy-blocked scan reverts
`composer.json`/`composer.lock` to their pre-scan state from an on-disk
backup, atomically, the same `revert_lock_to_original` path npm/pnpm/bun
use. TOCTOU is closed the same way too: SHA-256 checks on both files
immediately before the real install. There's no
sdist-style build step here; Composer's lifecycle scripts are disabled with
`--no-scripts` and its plugins (PHP code Composer loads in-process at
startup, not covered by `--no-scripts`) with `--no-plugins`, on both the
dry-run and the real install.

**Pre-commit hook:** `ubel-composer install-hook` works. Runs `health` on
every commit by default; with `UBEL_HOOK_SCA=auto`, only when a commit
stages `composer.json` or `composer.lock`.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered — `.php` files are scanned for
`use`/`require`/`include` references against the resolved dependency
graph, same signal set (depth, scope, attack vector, import confirmation)
as every other reachability-covered ecosystem.

---

## Ruby — Bundler

**SCA:** Resolves from `Gemfile.lock` (a directory counts only when it has
both a `Gemfile` and a `Gemfile.lock`); the `Gemfile` is read only to
classify gems as dev/test/prod. Gems are reported as `pkg:gem/<name>@<version>`
with license `unknown`.

**Firewall:** Available via `ubel-bundle`, **lockfile required** — Bundler has no
side-effect-free dry-run install path for UBEL to hook into, so nothing is
resolved: `Gemfile.lock` must already exist (otherwise the run is refused, as is
any package argument), and `check` scans exactly the gems the lockfile pins
without needing Bundler installed. There is no `install` mode: after `check`
passes, run `bundle install` with `BUNDLE_FROZEN=true` yourself. Native
extensions can still run code during that install.

**Pre-commit hook:** `ubel-bundle install-hook` runs `ubel-bundle health` on
each commit; `Gemfile`/`Gemfile.lock` are in the `UBEL_HOOK_SCA=auto` trigger
list (and a hook installed from an npm-family engine or `ubel-composer` also
covers Ruby through its full-stack `health`).

**SAST / Malware SAST:** Full coverage, `.rb` chunking.

**Reachability analysis:** Fully covered via `.rb` import scanning.

---

## Rust — Cargo

**SCA:** Resolves from `Cargo.lock`, giving exact resolved versions rather
than semver ranges from `Cargo.toml`.

**Firewall:** Available via `ubel-cargo`. Cargo separates resolution from
building, which is what makes a gate possible: `cargo add` and
`cargo update --workspace` resolve against the registry index only — they
download no crate sources and never run `build.rs` or proc-macros. UBEL runs
them in a **scratch copy of the project** (so `check` never modifies it and
there's nothing to revert), scans the resulting `Cargo.lock`, and only on a
clean scan writes the scanned `Cargo.toml` (when packages were added) and
`Cargo.lock` into the project and runs `cargo fetch --locked` — `--locked`
makes cargo fail rather than resolve anything that wasn't scanned. Both
files' SHA-256 are recorded at scan time and re-checked before the install,
and the project's own files are re-checked in case they changed while the
scan ran; if the fetch fails, the originals are restored. With no arguments
the scanned set is the project's current lockfile.

**Pre-commit hook:** `ubel-cargo install-hook` works. Runs `health` on
every commit by default; with `UBEL_HOOK_SCA=auto`, only when a commit
stages `Cargo.toml` or `Cargo.lock`.

Honest limits:
- Only **crates.io** crates are matched against vulnerability data. Workspace
  members and path dependencies are your own code and are left out; git
  dependencies and alternative registries are listed in a warning but **not
  scanned**. (Resolving a git dependency clones it — nothing from it runs.)
- **Build scripts aren't gated.** `fetch` populates cargo's registry cache
  only; `build.rs` and proc-macros execute later, at `cargo build`. The
  guarantee is that only the scanned crate versions are fetched, not that
  they're inert.
- Run it from a standalone package or a workspace root — a member of a parent
  workspace is refused. Path dependencies outside the project root can't
  resolve in the scratch copy, so the dry-run fails (closed) with cargo's own
  error.
- Packages are `name` or `name@requirement` only — no options, git/path
  sources or feature flags. `cargo install <binary-crate>` isn't covered.
- `license` is `unknown` on `check`/`install`; there's no `init` mode.
- Scopes (`prod`/`dev`/`build`) are read from `Cargo.toml` — `[dependencies]`, `[dev-dependencies]`, `[build-dependencies]` in inline,
  dotted and table form, target-specific sections and renamed crates — across the root manifest and every workspace member in
  `[workspace] members` (minus `exclude`; `*`/`?` wildcards per path segment, not `**`), then propagated along `Cargo.lock`
  edges. `[workspace.dependencies]` is skipped (it only declares versions). It's a minimal TOML reader, not a full parser: anything
  it can't attribute defaults to `prod`, so odd layouts err towards "production" rather than hiding a dependency.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered via `.rs` import scanning.

---

## Go — modules

**SCA:** A directory is a module root when it has a `go.mod`; versions come
from `go.mod`'s `require` entries cross-referenced with `go.sum` (which pins
exact versions and hashes, and may be absent or empty). The version in
`go.mod` wins over stale `go.sum` entries for other versions, and
`!`-escaped module paths are restored — giving high-confidence version
matching against OSV. License is `unknown`.

**Firewall:** Available via `ubel-go`, **lockfile required** — `go.sum` must
already exist (otherwise the run is refused, as is any package argument).
`check` reads `go.sum` only: `go.mod` is not
consulted, so the versions can't be narrowed to the build list and every source
entry in `go.sum` is scanned, stale versions included (`/go.mod` hash lines are
excluded) — over-reporting is the safe direction for a firewall — and no Go
toolchain is needed. There is no `install` mode: after `check` passes, run
`go mod download` with `GOFLAGS=-mod=readonly` yourself, which verifies
downloads against `go.sum` and cannot change it. Add a module with `go get`,
review and commit `go.mod`/`go.sum`, then run `ubel-go check` again.

**Pre-commit hook:** `ubel-go install-hook` runs `ubel-go health` on each
commit; `go.mod`/`go.sum`/`go.work` are in the `UBEL_HOOK_SCA=auto` trigger list
(a hook installed from an npm-family engine or `ubel-composer` also covers Go
through its full-stack `health`).

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered via `.go` import scanning.

---

## Java / Kotlin — Maven

**SCA:** Reads the dependencies declared in `pom.xml`, resolving `${…}`
properties and `<dependencyManagement>` versions (including from parent poms
that exist on disk — `../pom.xml` or `<relativePath>`) and following
`<modules>` in multi-module projects. Optional dependencies are skipped;
Maven's `test` scope maps to `dev`, everything else to `prod`. Transitive
dependencies are **not** resolved from `pom.xml` alone: run
`mvn dependency:tree -DoutputFile=.ubel/maven-deps.txt` and UBEL uses that
tree in preference to the declarations. Versions that can't be resolved
(e.g. managed by a remote-only parent) are inventoried without a version and
not sent to OSV. License is `unknown`.

**Firewall:** Not available — Maven has no lockfile for UBEL to require and no
side-effect-free dry-run to hook into. (Gradle's lockfile is opt-in and Gradle
has no install step apart from a build, so there is no frozen install to gate
either.)

**Pre-commit hook:** Partial — no dedicated `ubel-maven` binary to attach
`install-hook` to, but a full-stack `health` (from a hook installed via an
npm-family engine or `ubel-composer`) includes it; `pom.xml`, `build.gradle`,
`gradle.lockfile` and `libs.versions.toml` are in the `auto`-mode trigger list.

**SAST / Malware SAST:** Full coverage; Java and Kotlin are tracked as
separate language families in the catalog, so idioms specific to each
(e.g., Kotlin null-safety bypasses vs. Java reflection abuse) get
distinct signal sets rather than one being shoehorned into the other's
ruleset.

**Reachability analysis:** Fully covered — `.java`, `.kt`, `.groovy`, and
`.scala` files are all scanned under the same `maven` reachability key.

**Note:** Gradle is **not** resolved — only `pom.xml` is read, so a
Gradle-only project yields no Java inventory.

---

## C# / .NET — NuGet

**SCA:** A project root is a directory with a `*.csproj`, `*.fsproj` or
`*.vbproj`. Packages come from `packages.lock.json` where present, falling
back to `obj/project.assets.json` (the MSBuild-generated resolved graph) when
a project doesn't use lock-file mode; with neither file (no
`dotnet restore` yet) nothing is reported. Each target framework's graph is
kept separate so edges aren't collapsed across TFMs. Scopes are seeded from
the project file's `<PackageReference>` entries (a `Condition` mentioning
`debug`/`test` marks `dev`) and propagated down the graph. License is
`unknown`.

**Firewall:** Available via `ubel-dotnet`, **lockfile required** — NuGet lock files
are opt-in, so `packages.lock.json` must
already exist; there is deliberately no fallback to `obj/project.assets.json`. Otherwise the
run is refused, as is any package argument. `check` scans exactly what the lock
file pins (no .NET SDK needed). There is no `install` mode: after `check`
passes, run `dotnet restore --locked-mode` yourself. Create the lock file in a
trusted environment with `dotnet restore --use-lock-file`. NuGet-shipped MSBuild
targets can run code during the restore.

**Pre-commit hook:** `ubel-dotnet install-hook` runs `ubel-dotnet health` on each
commit; `packages.lock.json`, `packages.config`, `Directory.Packages.props` and
`*.csproj` are in the `auto`-mode trigger list (a hook installed from an
npm-family engine or `ubel-composer` also covers .NET through its full-stack
`health`).

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered — `.cs`, `.vb`, `.fs`, and `.fsx`
files are all scanned under the same `nuget` reachability key.

---

## Swift — SwiftPM / Carthage

**SCA:** Resolves from the lockfiles Swift tooling already writes, so
nothing needs to be built or installed first:

- `Package.resolved` (SwiftPM formats v1, v2, and v3) — next to a
  `Package.swift`, inside an Xcode workspace at
  `<X>.xcworkspace/xcshareddata/swiftpm/`, or inside an Xcode project at
  `<X>.xcodeproj/project.xcworkspace/xcshareddata/swiftpm/`.
- `.build/workspace-state.json` — fallback for a package whose
  `Package.resolved` wasn't committed (common for libraries that gitignore
  it).
- `Cartfile.resolved` (Carthage) — `binary` entries are skipped, since they
  carry no repository identity.

Packages are reported as `pkg:swift/<host>/<owner>/<repo>@<version>` (OSV
ecosystem `SwiftURL`), with a leading `v` stripped from release tags. Local
packages (`fileSystem` / `localSourceControl` pins) are first-party code and
aren't reported. A pin that resolves to a branch or a bare commit instead of
a release tag is inventoried with an empty version and dropped from OSV
queries, because a commit hash isn't a version OSV can range-match.

CocoaPods (`Podfile.lock`) is intentionally not scanned: OSV has no
CocoaPods ecosystem, so those packages could never match an advisory.

**Scopes:** None of these lockfiles distinguish dev from prod, so every
Swift package is reported as `prod`.

**Firewall:** Available via `ubel-swift` for **SwiftPM**, **lockfile required** —
`Package.resolved` must already exist (otherwise the run is refused, as is any
package argument), `check` scans exactly
what `Package.resolved` pins without needing Swift installed (it does not fall back to `.build/workspace-state.json`
or `Cartfile.resolved`). There is no `install` mode: after `check` passes, run
`swift package resolve --force-resolved-versions` yourself. Carthage and
CocoaPods are not gated. Resolving evaluates `Package.swift`, which is code.

**Pre-commit hook:** `ubel-swift install-hook` runs `ubel-swift health` on each
commit; `Package.swift`, `Package.resolved`, `Cartfile(.resolved)` and
`Podfile(.lock)` are in the `auto`-mode trigger list (a hook installed from an
npm-family engine or `ubel-composer` also covers Swift through its full-stack
`health`).

**SAST / Malware SAST:** Covered — Swift is its own language family in both
the vulnerability and malware catalogs (with dedicated mobile classes:
local storage, TLS/pinning, WebView bridges, deep links, biometric gates).
`.swift` files are also included in Secrets detection.

**Reachability analysis:** Covered — `.swift` files (plus `.m`/`.mm`/`.h`) are
scanned for `import <Module>` / `@import` / `#import <Module/…>` references,
with repository-to-module mapping (e.g. `swift-log` → `Logging`).

**License compliance:** `Package.resolved` and `Cartfile.resolved` don't
record licenses, so every Swift package is inventoried with license
`unknown`.

---

## Flutter / Dart — pub

**SCA:** A directory is scanned when it contains `pubspec.lock` or — for
packages and libraries that don't commit their lockfile —
`.dart_tool/package_config.json`, which `dart pub get` / `flutter pub get`
writes. `pubspec.lock` is preferred when both exist: it carries each
package's version, source (hosted, git, path, or sdk), and dependency kind.
From the `package_config.json` fallback only hosted packages can be
recovered (their version comes from the pub-cache directory name); git, SDK,
and relative-path packages are skipped there.

Packages are reported as `pkg:pub/<name>@<version>`, with
`?repository_url=<url>` for a package hosted on a non-pub.dev registry and
`?vcs_url=<url>` for a git dependency. `sdk` sources (`flutter`,
`flutter_test`, …) and `path` sources are skipped — first-party or toolchain
code, not installed third-party packages.

**Scopes:** From `pubspec.lock`: `direct main` and `direct overridden` →
`prod`, `direct dev` → `dev`, and `transitive` → `prod` (the lockfile
doesn't record whether a transitive dependency is reached from dev or main,
so the conservative default is used). Packages recovered from the
`package_config.json` fallback carry no dev/main signal and are reported as
`prod`.

**Dependency graph:** `pubspec.lock` has no dependency graph, so Flutter/Dart
packages are reported without introduced-by/parent edges.

**Known limitation:** OSV matches on package name. A package from a private
registry or a git repository that shares its name with a pub.dev package can
be matched against that package's advisories; the `repository_url` /
`vcs_url` qualifier keeps the identity distinct in the inventory but doesn't
stop the OSV lookup.

**Firewall:** Available via `ubel-dart` and `ubel-flutter`, **lockfile required** —
`pubspec.lock` must already exist (otherwise the run is refused, as is any
package argument), `check` scans exactly
what `pubspec.lock` pins (it does not fall back to
`.dart_tool/package_config.json`, and needs no Dart/Flutter SDK). There is no `install` mode: after `check`
passes, run `dart pub get --enforce-lockfile` / `flutter pub get
--enforce-lockfile` yourself, which fails instead of resolving anything the
lockfile doesn't already pin.

**Pre-commit hook:** `ubel-dart install-hook` / `ubel-flutter install-hook` run
the engine's `health` on each commit; `pubspec.yaml` / `pubspec.lock` are in the
`auto`-mode trigger list (a hook installed from an npm-family engine or
`ubel-composer` also covers pub through its full-stack `health`).

**SAST / Malware SAST:** Covered — Dart/Flutter is its own language family
in both the vulnerability and malware catalogs (with the same dedicated
mobile classes as Swift).

**Reachability analysis:** Covered — `.dart` files are scanned for
`import`/`export 'package:<name>/…'` references, including conditional-import
continuation lines. A federated platform implementation (e.g.
`url_launcher_android`) is also matched via its app-facing package.

**License compliance:** `pubspec.lock` doesn't record licenses, so every
Flutter/Dart package is inventoried with license `unknown`.

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
local) image or accepts an already-exported `.tar`, `.tar.gz`/`.tgz`, or
OCI image-layout directory — never
runs the image's `ENTRYPOINT`/`CMD` — exports its filesystem to a temp dir,
and scans that filesystem exactly like any other project root: OS packages
via the Linux host scanner *and* every application-level ecosystem's
dependencies found inside the image (Node, Python, PHP, etc., all at once,
via `full_stack`).

Installed OS packages are read directly from the extracted filesystem (dpkg
`status`, apk `installed`, and the rpm database — Berkeley DB `Packages` or
`rpmdb.sqlite`, parsed in-process) in every mode, so no `dpkg`/`apk`/`rpm`
binary is ever run and the scan works on hosts without them, including
Windows. The only binary executed is `docker`, to pull/create/export the
image and remove it when the mode calls for it (skipped entirely for a local
`.tar`). SUSE's NDB rpm format is not supported.

**Firewall:** Docker gets **true pre-install (here, pre-deploy) gating**,
with three modes controlling what happens to the image after scanning:
- `health` — scan only, image left exactly as found.
- `check` — scan, then remove the image afterward (throwaway vetting) — only
  if this run pulled it; an image that was already local is never removed.
- `install` — scan, then remove the image *only if* the scan results in a
  policy block (same rule); a clean scan leaves it in place.

Removal is `docker rmi` without `-f`: an image still in use fails to delete
instead of being forced.

`--no-pull` scans an image that only exists locally (e.g., right after
`docker build`, before it's ever pushed to a registry) — this is the
"vet before you ship" path. `--keep` retains the extracted root filesystem
for debugging (it does not change image removal). Pointing this at a CI-built image before push, or at a
third-party base image before you adopt it, is the intended pre-deploy
firewall use.

**Malware/Secrets/License:** All inherited from whatever's found inside the
image — an image with a compromised npm package, a hardcoded AWS key in a
baked-in `.env`, or a GPL-licensed binary bundled into a proprietary image
all get caught the same way they would in a live checkout. (One deliberate
difference: `.env*` files are skipped in repository scans but scanned in
image scans, because a `.env` inside an image ships with it.)

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
scan. Installed packages are read straight from the package databases
(dpkg `status`, apk `installed`, rpm `Packages`/`rpmdb.sqlite`) without
running any package-manager binary to do so; only `check`/`install` call
`apt`/`dnf`/`yum`, for the dry-run resolution. The distribution is taken from
`os-release` (`ID`, then each `ID_LIKE` token), so derivatives such as Amazon
Linux resolve to their parent family; Debian, Ubuntu, Alpine, Red Hat,
AlmaLinux and Rocky are supported, and anything else (e.g. SUSE, Arch) stops
the OS scan with an "Unsupported OS ecosystem" error. Each package is tagged
with its distro release (`almalinux-8.10`, …) so advisories are matched to
that release, not to other releases of the same distro.

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
step does, same as running the package manager yourself. With no project to
identify, their history zips are filed under the machine instead:
`~/.ubel/ubel_machine.json` is created once (it holds a machine id only) and
its id is the `<asset_id>/` history folder every OS scan's zip goes into.

**Pre-commit hook:** Not available — apt/dnf/yum scan the host, not a repo,
so there's no manifest to hook a commit against. Their CLI rejects
`install-hook` / `uninstall-hook` with a clear error rather than silently
doing nothing. For host scanning, use `ubel-platform` in CI.

**License compliance:** Fully applied. Per-package license strings are
extracted from rpm metadata, `/usr/share/doc/<pkg>/copyright` for
dpkg-based systems, and apk metadata, then fed through the same SPDX
normalization/OSI/risk classification layer as every other ecosystem — it
isn't a separate, lesser pipeline for OS packages.

---

## Windows host

**SCA:** `WindowsHostScanner` mirrors the Linux host scanner's role for
Windows — installed software inventory matched against CPE/CVE. It probes the
registry and known binary paths (no elevated privileges) for: Windows 10/11
(build-accurate CPE), Windows Defender, PowerShell, runtimes (Node.js,
Python, PHP, Go, Rust, Ruby, JRE, JDK), every installed .NET
Core/Desktop/ASP.NET runtime, browsers (Chrome, Firefox, Edge) and developer
tools (Git, Docker Desktop, Visual Studio Code / Visual Studio IDE, Cursor,
VSCodium, Claude Code). Host-OS health scans on Windows and Linux are filed
under the `os_sca` report tag (JSON, HTML and SBOM; no SARIF).

**Firewall:** Not available. Unlike Linux's `apt-get -s`/`dnf --assumeno`,
there's no equivalent dry-run resolution UBEL can hook into for Windows'
package managers/installers today — this remains health/detection scanning
of what's already on the machine, not a gate on what's about to be
installed.

**Pre-commit hook:** Not available — same reason (host scan, not repo).

**License compliance:** Fully applied, via its own `licenseFor()` mapping
feeding the same classification pipeline as every other ecosystem —
proprietary Microsoft/vendor components resolve to a `LicenseRef-*`
identifier, open-source runtimes and tools to their real SPDX id.

---

## Cross-Cutting Capabilities

### Reachability Analysis — 10 ecosystems via import-graph confirmation

Every vulnerability is annotated with a reachability verdict derived from
dependency depth, scope (prod/dev/env), attack vector, orphan-tool
detection, and — where source is available — actual import/require
scanning that confirms whether the vulnerable module is ever referenced.
The import-scan half of this is implemented for **Python (`.py`), Node.js
(`.js`/`.ts`/`.mjs`/`.cjs`/`.jsx`/`.tsx`), Maven/Java+Kotlin (`.java`,
`.kt`, `.groovy`, `.scala`), NuGet/C# (`.cs`, `.vb`, `.fs`, `.fsx`), PHP
(`.php`), Go (`.go`), Cargo/Rust (`.rs`), RubyGems/Ruby (`.rb`), Flutter/Dart
(`.dart`), and Swift (`.swift`, plus `.m`/`.mm`/`.h` for Objective-C interop)** —
every SCA ecosystem except C. Dart matches `import`/`export 'package:<name>/…'`;
Swift maps each package's repository to its module names (e.g. `swift-log` →
`Logging`) and matches `import <Module>`, `@import`, and `#import <Module/…>`. A known distribution-name-to-
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
The one switch is `.env*` files: skipped in repository scans, scanned in
image scans.
The scanner itself is pure in-memory, with no disk writes of its own; the
caller (main engine) decides whether findings fold into the JSON/HTML/SARIF
report. The only things the secrets tooling writes are the ones you ask
for — `.ubelignore` baseline entries (`--write-baseline`) and the git
pre-commit hook (`--install-hook`) — plus the `.gitignore` / `.dockerignore`
entries that `main.js` (never the scanner) adds up front to keep `.ubel/` and
`.ubelignore` out of git and Docker contexts.

Beyond the working tree, the same rules, allow-lists, entropy gates and
`.ubelignore` suppressions run over **git history** (`--history`: only the
lines each commit *added*, so a secret committed and later deleted is still
found, reported once at the oldest commit that introduced it) and over the
**staged index** (`--staged`: exactly what is about to be committed, so
unstaged edits are ignored and a staged `.env` is always scanned). The git
work uses only the `git` binary, via argument arrays and never a shell.

### Dependency-scanning pre-commit hook — one hook, two scans

Every SCA binary can add a dependency scan to the single ubel git
pre-commit hook. On every commit the hook runs `ubel-secrets --staged`,
then `<engine> health` — a dependency scan (no OS scan).

- **One hook.** `ubel-secrets --install-hook` and `ubel-<engine>
  install-hook` write the same script; each sets its own step and keeps
  the other's, so both can be installed in either order without `--force`.
  Idempotent re-install, `--force` chaining of a foreign hook,
  `core.hooksPath` / worktree support, portable installs to committed
  hooks directories, `UBEL_HOOK_STRICT=1` to fail closed on "tool
  missing", and `git commit --no-verify` all apply. The hook never
  chains to itself.
- **Different scope** — this hook scans the repo's *installed dependencies*
  (health mode), never the host OS. It's a `health` scan, not a `check`
  scan, so no lockfile is written or reverted and a broken scan cannot
  leave the working tree half-mutated. It runs on every commit by default;
  `UBEL_HOOK_SCA=auto` restricts it to commits that stage a manifest or
  lockfile, and `UBEL_HOOK_SCA=off` disables it.
- **Engine coverage** — install-hook exists on every SCA binary except
  `ubel-docker` (no repo checkout) and `ubel-apt`/`ubel-dnf`/`ubel-yum`
  (they scan the host, not a repo). Ecosystems that are only reachable
  through full-stack `health` scanning — Go, Maven/Kotlin, NuGet,
  Bundler, SwiftPM, pub — have no per-engine binary to attach the hook
  to, but are still scanned when the hook was installed from an
  npm-family engine or `ubel-composer`, whose `health` is full-stack
  (the pip/uv/pipx/conda/poetry/cargo hooks scan only their own ecosystem).

### SBOM re-scan — `ubel-resbom`, for every SBOM UBEL writes

Every SCA scan except `ubel-license` and `ubel-secrets` writes a CycloneDX
SBOM, and `ubel-resbom` can take any of them back in. It is not tied to an
ecosystem: the SBOM's purls are the whole input, so an npm, Python, Rust,
PHP, Go, Java, .NET, Ruby, Swift, Flutter/Dart, Docker-image, OS-package
(`deb` / `rpm` / `apk`), agent or editor-extension SBOM is re-checked the
same way, against current OSV/NVD, KEV and EPSS data.

- **No tooling needed.** It never invokes a package manager or reads a
  lockfile, so it runs where the project's toolchain isn't installed, and
  it has no firewall (`check` / `install`) side effects to revert.
- **Fidelity.** Asset identity, environment, git and OS metadata, the
  secrets findings and the reachability verdicts the SBOM recorded are
  carried over; OS packages keep the distro release they were scanned on,
  so release matching still applies. Findings that are new since the SBOM
  was written get graph-only reachability (no source tree, so no import
  confirmation).
- **Outputs.** `<source tag>_resbom` tag (`sca_resbom`,
  `npm_firewall_resbom`, …): JSON, HTML and SBOM always, SARIF only where
  the source tag gets it. Filed under the SBOM's own asset in
  `$HOME/.ubel/history/<asset_id>/`.
- **Doesn't claim** to discover components the original scan missed, to
  re-run the secrets scan, or to read non-CycloneDX formats.

See [Re-scanning an SBOM](#re-scanning-an-sbom--ubel-resbom) above and the
[full reference](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#re-scanning-an-sbom-ubel-resbom).

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
C#, Swift, Flutter/Dart, and Linux/Windows OS packages alike. Real license
data exists where the package metadata carries it — Node, Python, PHP and the
OS-package scanners (rpm metadata, dpkg `copyright`, apk) and Windows
components (a built-in vendor/EULA mapping); the Ruby, Rust, Go, Java/Kotlin,
C#, Swift and Flutter/Dart inventories read only a lockfile or
manifest with no license field, so their packages come through as
`unknown`. The only true exception is C (no
package manager/manifest exists to read a license from in the first
place). Policy supports both a `license-risk` threshold
and a separate `license-block-unknown` flag for licenses that couldn't be
classified at all — both enforced only against health-mode scans, since
license risk is a compliance concern on what's already installed, not an
install-time security gate.

### Malware SAST — all 15 language families

Malware detection is a two-pass LLM pipeline covering 15 intentional-malice
classes, applied across all 15 language families: the 12 source-code
families (JS, Python, PHP, Ruby, Go, Rust, Java, Kotlin, Dart, Swift, C#, C)
plus Docker, IaC and Kubernetes manifests. The malware catalog entries are
tagged for the 12 source-code families; a chunk from one of the three config
families matches none of them, so it is scanned against the full 15-class
catalog rather than skipped — there's no ecosystem where malware
detection is a second-class capability. It's explicitly separate from the
vulnerability SAST catalog (different pipeline, different intent: is this
code *deliberately* malicious vs. *accidentally* exploitable) and ships as
its own CLI (`ubel-mal`), independent of the SCA/firewall engine.

### Vulnerability SAST — 15 language/config families

The vulnerability-finding catalog (64 CWE-mapped classes) spans a wider set
than malware detection: the 12 source-code families above (Dart/Flutter and Swift
include dedicated mobile classes — local storage, TLS/pinning, WebView bridges,
deep links, biometric gates), plus Docker,
Kubernetes, and general IaC as first-class chunkable targets — meaning
Dockerfiles, K8s manifests, and Terraform/CloudFormation get scanned with
the same three-pass scan → verify → taint-trace rigor as application code,
not treated as an afterthought bolted onto the dependency scanner.

### Compliant, Standardized Outputs

- **Which report gets which format** — JSON and HTML on every SCA run;
  the CycloneDX SBOM on `health`, host-OS (`os_sca`) and firewall
  (`check`/`install`) runs; SARIF on `health` scans only (`sca`,
  `docker_sca`). Standalone `ubel-license` and `ubel-secrets` write JSON and
  HTML only, and firewall runs write no SARIF. A `ubel-resbom` re-scan
  (tag `<source tag>_resbom`) gets exactly the formats its source tag gets.
  See the report file-naming
  table in [sca/README.md](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#file-naming-the-tag).
- **SARIF 2.1.0** — full-fidelity output (deterministic SHA-256
  fingerprints, not random UUIDs, so the same finding produces the same ID
  run over run) that plugs directly into GitHub code scanning and any
  other SARIF-consuming pipeline. Results carry KEV / EPSS data and a
  `rank` (100 for a KEV entry, otherwise the EPSS probability), and a KEV
  finding is reported at `error` level regardless of its severity.
- **CycloneDX 1.6 SBOM** — with VEX-style vulnerability annotations,
  usable as a release artifact independent of any specific CI vendor.
  Includes KEV / EPSS exploit data and per-package suggested fixes.
- **CVSS scoring** — v2, v3, v3.1, and **v4.0** (a full port of the
  Red Hat CVSS v4 calculator, BSD-2-Clause, separately attributed) plus
  SSVC as a normalized "other" scoring method where relevant, all folded
  into a single normalized severity used consistently across JSON, SARIF,
  and SBOM output.
- **HTML reports** — force-directed dependency graphs, inventory modals,
  and reachability badges/filters wherever reachability data exists in the
  report (the ten ecosystems above).
- **JSON** — the canonical, complete report every other format is derived
  from, including effective-configuration tracing (what policy/thresholds
  were actually in effect for that specific scan run).

---

## What this matrix intentionally does *not* claim

To keep this document honest rather than aspirational:

- Firewall/pre-install gating is **npm, pnpm, bun, Composer, Docker,
  pip/uv/pipx, conda, Poetry, Cargo, and Linux host packages (apt/dnf/yum)**
  via a dry-run resolution, plus **yarn, Bundler, Go, .NET/NuGet, Dart,
  Flutter and SwiftPM** via the *lockfile-required* model — not "every
  package manager," because most package managers genuinely don't offer a
  dry-run resolution UBEL can safely gate against. Java/Kotlin (Maven) and
  the Windows host remain without it for that reason — Maven has no lockfile
  to require — a hard mechanical constraint, not a roadmap gap. Carthage and
  CocoaPods (SwiftPM's `Package.resolved` is gated, theirs are not) and
  Gradle (its lockfile is opt-in and it has no install step apart from a
  build) are not gated either.
- **The lockfile-required engines don't resolve anything.** Yarn, Bundler,
  Go, .NET, Dart, Flutter and SwiftPM are `check`-only (no `install` mode) and
  refuse to run without an existing lockfile (`check` reads nothing else — no
  manifest, no toolchain) and refuse package arguments in every mode, because
  adding a package means resolving it and that is the one step UBEL cannot
  gate there. They scan exactly what the lockfile pins — not a candidate
  resolution — and the package manager's own frozen install, which you run
  after `check` passes, fails rather than resolve anything else. Lifecycle
  scripts are up to that install: Bundler native extensions, SwiftPM manifests
  and NuGet-shipped MSBuild targets can run code during it. Packages from git/path/URL sources
  can't be matched against OSV and are reported `undetermined`.
- pip's and uv's firewalls refuse source distributions: the dry-run and
  the real install pass `--only-binary=:all:`, so a package with no
  compatible wheel fails closed instead of running build-backend code. See
  the Python section above. **The dependency pre-commit hook sidesteps
  this entirely** — it runs `health`, not `check`, so no resolution
  happens at all.
- Reachability analysis's import-confirmation half covers **10 of the 10
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
  Windows) — gets full SCA regardless of firewall status, and runs through
  the license-classification layer, but only Node, Python, PHP, and the OS
  scanners actually carry license data; Ruby, Rust, Go, Java, C#, Swift,
  Flutter/Dart packages report license `unknown` because their
  manifests/lockfiles have no license field (hence ❌ in the matrix's
  License column); firewalling and inventory/license coverage are tracked
  and reported independently.
- **Pre-commit hook coverage matches SCA coverage *among engines that
  have a dedicated binary*.** Maven/Kotlin is SCA-covered via full-stack
  `health`, but there's no per-engine CLI to attach `install-hook` to, so
  it's only covered indirectly (⚠️): a hook installed from an npm-family
  engine or `ubel-composer` scans it as part of its full-stack `health`.
  Yarn, Bundler, Go, .NET, Dart, Flutter and SwiftPM have their own
  binaries and their own `install-hook`. Docker and apt/dnf/yum have no hook
  at all — Docker has no repo checkout, and apt/dnf/yum scan the host. The
  secrets pre-commit hook (`ubel-secrets --install-hook`) is a separate
  hook, separate feature, and separate scope (staged source files, not
  installed dependencies).
- This entire matrix is about **the SCA/firewall/reachability/license/SBOM
  pipeline for dependency trees you resolve locally** (a manifest, a
  lockfile, an installed package set, a container image). `ubel-url`/
  `ubel-domain`/`ubel-host`/`ubel-easm` (EASM) are a genuinely separate
  thing — passive HTTP fingerprinting of a remote domain/URL (plus a fixed
  set of misconfiguration checks; `ubel-host`/`ubel-easm` additionally run a
  live, active TCP port scan ahead of the fingerprinting), not a
  dependency-tree scan — and deliberately doesn't carry license compliance,
  dependency sequences, reachability analysis, or SBOM/SARIF output, none of
  which are meaningful concepts for something fingerprinted over the network
  rather than resolved from a manifest. See the EASM section above and
  [easm/README.md](https://github.com/AlaBouali/ubel/blob/main/easm/README.md)
  for what it does carry over (OSV/NVD/wpvulnerability.net lookup, CVSS, fix
  recommendations, compliance mapping) and why.

---

## License

Source-available, **internal-use-only** license. Using and modifying UBEL for your organization's own internal needs (including its own CI/CD pipelines and products) is permitted. Redistribution, wrapping or embedding, exposing it to third parties over a network or API, and hosting or automating it as a service for others are not. Security consultants may use it manually during direct client engagements, provided it isn't left behind, automated, or made available to the client as a platform. See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for the full terms.
---

## Links

- Repository: https://github.com/AlaBouali/ubel
- Issues: https://github.com/AlaBouali/ubel/issues
- SCA docs: https://github.com/AlaBouali/ubel/blob/main/sca/README.md
- SAST docs: https://github.com/AlaBouali/ubel/blob/main/sast/README.md
- Cloud docs: https://github.com/AlaBouali/ubel/blob/main/cloud/README.md
- EASM docs: https://github.com/AlaBouali/ubel/blob/main/easm/README.md

*UBEL — Find the bug before it finds production.*