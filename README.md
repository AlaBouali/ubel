# UBEL — Unified Bill / Enforced Law (Node.js)

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, AI-powered SAST, cloud misconfiguration scanning, mobile app, native binary and dependency-release scanning, and external attack surface scanning.**

UBEL is a zero-dependency, source-available (internal-use-only; see [License](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md)) application security toolkit. This package (`@arcane-spark/ubel-node`) ships one CLI per job. Full details live in the [full reference](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md) and the per-module READMEs.

## Modules

| Module | What it does | Docs |
| --- | --- | --- |
| **SCA** | Resolves dependencies and scans them against OSV.dev and NVD in real time, with reachability analysis, KEV/EPSS exploit intelligence, license checks, CycloneDX SBOM and SARIF output. | [SCA documentation](https://github.com/AlaBouali/ubel/blob/main/sca/README.md) |
| **Firewall** | Gates `npm`/`pnpm`/`bun`/`composer`/`pip`/`uv`/`pipx`/`poetry`/`conda`/`cargo`/`apt`/`dnf`/`yum` installs and Docker images behind a scan before anything is installed. `yarn`/`bundle`/`go`/`dotnet`/`dart`/`flutter`/`swift` are gated on an existing lockfile instead (no lockfile, or any package argument, is refused). | [Firewall details](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#firewall--install-time-gate) |
| **Secrets** | Trivy-derived ruleset plus UBEL's own rules. Standalone via `ubel-secrets`. | [Secrets details](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#secrets-detection) |
| **SAST** | LLM-powered scan → verify → taint-trace pipeline for vulnerabilities, plus a separate malicious-code scan. | [SAST documentation](https://github.com/AlaBouali/ubel/blob/main/sast/README.md) |
| **Cloud** | Read-only AWS / GCP / Azure account scan for misconfigurations. | [Cloud documentation](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md) |
| **Mobile** | Static scan of an Android `.apk` / `.aab` (and split bundles `.xapk` / `.apks` / `.apkm`) or iOS `.ipa` for hardcoded secrets, insecure storage and misconfigurations, mapped to OWASP MASVS. Reads React Native / Hermes, Flutter, Unity and Xamarin app code, checks native-library hardening per ABI, detects packers and obfuscators, and adds a behavior inventory with the remote hosts the app names. Pure Node — no third-party libraries, no external binaries. Dependencies come from package metadata (Maven, Swift Package Manager, CocoaPods), and the native libraries inside the app (`lib/<abi>/*.so`, Mach-O frameworks) are read with `ubel-binary`'s component detection: bundled OpenSSL / SQLite / curl … banners go to NVD, Go modules and Rust crates to OSV.dev. An opt-in `--online` mode adds three read-only checks against hosts the app names. | [Mobile documentation](https://github.com/AlaBouali/ubel/blob/main/mobile/README.md) |
| **Binary** | Static scan of a native ELF, Mach-O (thin or fat) or PE executable or library: build hardening, risky imports, behavior inventory (with direct call sites for ELF / PE imports on x86-64 and arm64), hardcoded secrets and remote hosts, plus known-vulnerable components — C/C++ version banners (NVD), Go modules, Rust crates and packaged apps (pkg, Node SEA, Bun, PyInstaller; OSV.dev). Pure Node — nothing is executed or loaded. A lookup that fails is an incomplete analysis (exit 3), never a clean result. | [Binary documentation](https://github.com/AlaBouali/ubel/blob/main/binary/README.md) |
| **Package** | Static scan of one dependency release downloaded from its registry (npm, PyPI, crates.io, Go, RubyGems, NuGet, Packagist, pub.dev; any registry URL): install / build-time scripts and what they do, packages installed by those scripts, the pin class of every dependency, remote hosts, a behavior inventory, hardcoded secrets, native binaries inside the package, archive integrity and known-vulnerable / known-malicious versions (OSV.dev). Pure Node — the package is never installed, built or run. A lookup that fails is an incomplete analysis (exit 3), never a clean result. | [Package documentation](https://github.com/AlaBouali/ubel/blob/main/package/README.md) |
| **EASM** | Passive fingerprinting and misconfiguration checks of domains, hosts and ports you own. **Authorized use only.** | [EASM documentation](https://github.com/AlaBouali/ubel/blob/main/easm/README.md) |

Every finding is also mapped to OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR and CIS Controls v8 (best-effort guidance, not a compliance assessment).

## Capability matrix

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
| Android / iOS apps (`.apk` / `.aab` / `.ipa`) | ⚠️ | — | — | — | — | — | — | ✅ |
| Native binaries (ELF / Mach-O / PE) | ⚠️ | — | — | — | — | — | — | ✅ |
| Dependency releases (npm / PyPI / crates.io / Go / RubyGems / NuGet / Packagist / pub.dev) | ⚠️ | — | — | — | — | — | — | ✅ |

✅ = built and shipped ("lockfile required" = the firewall scans an existing lockfile instead of resolving a candidate) · ⚠️ = partial, see that ecosystem's section in the [full reference](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md) · ❌ = not currently possible/present for a stated reason · — = not applicable to that layer.

mobile / binary caveat: `ubel-mobile` and `ubel-binary` scan a built artifact (a package or a single file), not a dependency tree you resolve, so they have no firewall, hook, LLM SAST, reachability or license layer. Their SCA is ⚠️ because only components whose identity can be read from the file are looked up — exact package URLs (Maven, SwiftPM, CocoaPods, Go build info, cargo-auditable, bundled npm / PyPI metadata) go to OSV.dev and C/C++ version banners go to NVD; a package without a readable version is listed as `not_queryable`, never as clean. See the [Mobile](https://github.com/AlaBouali/ubel/blob/main/mobile/README.md#limits) and [Binary](https://github.com/AlaBouali/ubel/blob/main/binary/README.md#what-it-does-not-do) limits.

package caveat: `ubel-package` reads one downloaded release, not the dependency tree it belongs to. Dependencies are listed, classed by how tightly they are pinned and looked up on OSV.dev only when the declaration gives an exact (or minimum) version; ranges are shown as `not_queryable`, never as clean, and a dependency is not downloaded or analysed unless you run `ubel-package` on it. Its findings are pattern-based leads, not proof of malice — see the [Package documentation](https://github.com/AlaBouali/ubel/blob/main/package/README.md) and the [disclaimer](https://github.com/AlaBouali/ubel/blob/main/DISCLAIMER.md).

cargo caveat: only crates.io crates are scanned — git and alternative-registry dependencies are listed in a warning but not matched, and `build.rs`/proc-macros still run at `cargo build`, outside the firewall.

conda caveat: only conda packages that are Python distributions are matched against vulnerability data (OSV has no conda ecosystem); native packages such as `openssl` are inventoried but stay `undetermined` (they're not counted as `safe`, and each scan prints a warning with how many were left unmatched). See the [SCA documentation](https://github.com/AlaBouali/ubel/blob/main/sca/README.md).

Cloud account misconfiguration scanning (AWS/GCP/Azure, via `ubel-cloud`) isn't tied to a dependency ecosystem, so it doesn't have a row here — see the [Cloud documentation](https://github.com/AlaBouali/ubel/blob/main/cloud/README.md).

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

Node.js `>=18.0.0` required. `ubel-pip`/`ubel-uv`/`ubel-pipx` need Python on `PATH`; `ubel-uv`, `ubel-poetry`, `ubel-conda`, `ubel-cargo` and `ubel-composer` need their own binaries (`ubel-cargo` needs the Rust toolchain).

| Binary | Purpose |
| --- | --- |
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` | SCA (`health`) and firewall (`check` / `install`) for JS projects |
| `ubel-yarn` / `ubel-bundle` / `ubel-go` / `ubel-dotnet` / `ubel-dart` / `ubel-flutter` / `ubel-swift` | SCA (`health`) plus a lockfile-required firewall for yarn, Bundler, Go, .NET, Dart/Flutter and SwiftPM: `check` / `install` need the lockfile to already exist and take no package arguments |
| `ubel-composer` | Same, for PHP |
| `ubel-pip` / `ubel-uv` / `ubel-pipx` / `ubel-poetry` / `ubel-conda` | Same, for Python (`ubel-poetry`: `poetry add --lock` resolved in a scratch copy of the project, then `poetry install --no-root` of exactly the scanned `pyproject.toml` + `poetry.lock`, source distributions refused; `ubel-conda`: `conda create --dry-run --json` against a scratch prefix, then an exact-pinned `--no-deps` install) |
| `ubel-cargo` | Same, for Rust: `cargo add` + `cargo update --workspace` resolved in a scratch copy of the project, then `cargo fetch --locked` of the scanned lockfile |
| `ubel-apt` / `ubel-dnf` / `ubel-yum` | Same, for Linux packages |
| `ubel-docker` | Scan or gate a container image |
| `ubel-secrets` / `ubel-license` | Standalone secrets / license scans |
| `ubel-sbom` | Fills a CycloneDX SBOM's `vulnerabilities` with its components' known vulnerabilities, enriched with CISA KEV and FIRST EPSS — looked up by purl (OSV), by CPE (NVD) only when a component has no usable purl. Writes nothing else: no reachability, no reports |
| `ubel-resbom` | Re-scans an SBOM that UBEL generated earlier against today's advisories — components and dependency graph come from the SBOM, no project, lockfile or package manager needed, nothing installed. Same per-run policy flags as the SCA CLIs; writes JSON, HTML and SBOM reports (plus SARIF for `sca`-type sources) |
| `ubel-agent` / `ubel-cicd` / `ubel-platform` | Fixed-configuration scans: AI-agent workspace, built CI/CD workspace, host |
| `ubel-sast` / `ubel-mal` / `ubel-chunk` | Vulnerability SAST, malicious-code scan, chunking preview (no LLM cost) |
| `ubel-cloud` | AWS / GCP / Azure misconfiguration scan |
| `ubel-mobile` | Android `.apk` / `.aab` / `.xapk` / `.apks` / `.apkm` and iOS `.ipa` scan: hardcoded secrets, insecure storage and data handling, misconfigurations, native-library hardening, behavior inventory and known-vulnerable bundled components — static, no third-party libraries or binaries; the app is never executed or uploaded, only package URLs and component names / versions are looked up (OSV.dev, NVD). `--online` (off by default) adds three read-only checks against hosts the app names. JSON + HTML reports |
| `ubel-binary` | Native ELF / Mach-O / PE scan: build hardening, risky imports, behavior inventory, secrets, remote hosts and known-vulnerable components (banners → NVD; Go, Rust, npm and Python packages → OSV.dev). Same report, diff and `--fail-on` gate as `ubel-mobile`. A failed lookup is reported as incomplete (exit 3), never as clean. JSON + HTML reports |
| `ubel-package` | Dependency-release scan: `ubel-package <name> <version> <ecosystem> [--registry <url>]` downloads one release (npm, PyPI, crates.io, Go, RubyGems, NuGet, Packagist, pub.dev) and reports pre / post-install scripts and what they do, packages those scripts install, the pin class of every dependency, remote hosts, a behavior inventory, secrets, native binaries inside the archive and archive integrity; exact versions → OSV.dev (a known-malicious `MAL-` advisory is critical). Same report, diff and `--fail-on` gate as `ubel-binary`. A failed lookup is reported as incomplete (exit 3), never as clean. JSON + HTML reports |
| `ubel-url` / `ubel-domain` / `ubel-host` / `ubel-easm` | EASM: known hosts, CT-log subdomain discovery, port sweep of the given IPs/domains, combined sweep |
| *every binary above* | Also accepts three commands instead of a scan: `<binary> asset-id` (show the folder's asset id, creating it if there is none yet — every binary also creates it when it starts, and `<binary> init` does so explicitly), `<binary> set-asset-id <id>` (link the folder to an existing asset id so its scans join that asset's history) and `<binary> version`, plus `get-machine-id` / `set-machine-id <id>` for the machine id in `~/.ubel/ubel_machine.json`, which every report also carries as `machine_id` — e.g. `ubel-npm version`, `ubel-sast asset-id` — and a `--asset-id <uuid>` flag that sets the asset id for a single run (written into the report, SBOM and SARIF, and used to file the history zip). See [Asset id](sca/README.md#asset-id-ubel_assetjson) |
| *every report* | Carries an `asset_type` — `codebase`, `cloud`, `easm`, `mobile`, `machine`, `agent`, `editor` or `docker` — saying what kind of thing was scanned (shown as *Asset type* in the HTML report). See [Asset types](sca/README.md#asset-types-asset_type) |
| *every report* | Has a unique `report_id`, `UBEL-<tag>-<asset_id>-<report_uuid>` — the same in its JSON, HTML, SBOM and SARIF. See [Report ID](sca/README.md#report-id-report_id) |

## Quick start

```bash
ubel-npm health                      # audit installed dependencies
ubel-npm check                       # firewall: dry-run, exit non-zero if policy blocks
ubel-secrets /path/to/project         # secrets-only scan
ubel-sast /path/to/project            # AI-powered vulnerability scan
ubel-cloud                           # providers you have credentials for
ubel-mobile app-release.apk          # Android (.apk/.aab) / iOS (.ipa) package scan; nothing executed or uploaded
ubel-binary ./build/server           # ELF / Mach-O / PE scan, components checked against NVD / OSV.dev
ubel-package left-pad 1.3.0 npm      # one dependency release: install scripts, pins, hosts, secrets, integrity (--registry for a mirror)
ubel-url staging.your-domain.example --fail-on high   # EASM, your own infrastructure only
```

## Startup banner

Every CLI prints the UBEL banner (name, version, author, license) once when it starts. It goes to **stdout**, except for `ubel-agent`, `ubel-cicd`, `ubel-platform` and `ubel-license`, whose stdout is their JSON result — there it goes to **stderr**, so piping their output keeps working. It is not printed with `--json` or `--quiet`, when `UBEL_NO_BANNER` is set to anything but `0` (handy in CI logs), or by the `asset-id` / `set-asset-id` / `version` commands, whose output a script may read.

## CI exit codes

- **SCA / firewall:** exit `1` if policy blocks or the scan fails (including an incomplete OSV/NVD lookup — never treated as a pass).

- **SAST / malware SAST:** exit `1` when the `--fail-on` rule is met, or when code was not analyzed (a failed or unreadable AI call, a cut-off reply, a file skipped for size, chunks dropped by the default limit) — never treated as a pass.

- **EASM:** exit `2` when `--fail-on` is met. It gates on vulnerabilities, infections **and web misconfigurations**; KEV/EPSS rules apply to vulnerabilities. `--fail-on none` disables the gate.

- **Cloud:** governed by its own `--fail-on`; exits `3` when no finding trips it but a requested provider was skipped or stopped part-way (`--allow-partial` accepts that).

- **Mobile / Binary:** governed by `--fail-on` (default `critical`; `none` disables the gate, `5:high` tolerates five). It counts every finding and dependency advisory, whatever `--min-severity` hides from the report. Exit `0` only when the gate passed **and** the analysis was complete; `1` when the scan failed (file missing, unreadable or unsupported, report not written); `2` when the gate tripped or the arguments are bad; `3` when nothing tripped it but part of the file could not be analysed, including a failed OSV / NVD lookup (`--allow-partial` accepts that).

- **Package:** the same contract as Mobile / Binary (`--fail-on` default `critical`; exit `0` / `1` fetch or read failure / `2` gate tripped or bad arguments / `3` incomplete). `--offline`, a failed OSV / NVD lookup or a file over a limit is an incomplete analysis (exit `3`) unless `--allow-partial` accepts it.

See the [CI/CD integration details](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#cicd-integration) for GitHub Actions and Docker examples.

## Privacy

No telemetry and no UBEL-operated backend. Dependency scans send only package identifiers to OSV.dev and NVD (mirrorable via `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT`), and CVE ids to FIRST.org's EPSS API. **SAST sends code chunks to the LLM provider you configure** — use a local endpoint if code must not leave your network. `ubel-mobile` and `ubel-binary` never upload the app or the file: only package URLs and component names / versions are sent to OSV.dev and NVD. `ubel-package` downloads the release from the registry you name (the public one by default) and sends only package URLs / names and versions to OSV.dev and NVD; a `--token` / `--header` goes only to the registry's own host. `ubel-mobile --online` is opt-in and additionally contacts hosts **named by the app** (read-only, no redirects, no credentials, public names only). EASM and cloud scanners contact only the targets and APIs you point them at, plus public data sources documented in their READMEs.

## License

Source-available, **internal-use-only**. Using and modifying UBEL for your organization's own needs (including its own CI/CD and products) is permitted. Redistribution, wrapping or embedding, exposing it to third parties over a network or API, and hosting or automating it as a service for others are not. Security consultants may use it manually during direct client engagements, provided it isn't left behind, automated, or made available to the client as a platform. See the [license](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md).

## Links

- [Repository](https://github.com/AlaBouali/ubel)

- [Issues](https://github.com/AlaBouali/ubel/issues)

- [Full reference](https://github.com/AlaBouali/ubel/blob/main/DETAILS.md)