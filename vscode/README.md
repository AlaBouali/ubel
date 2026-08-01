# UBEL — Supply-Chain & Secrets Scanner for VS Code

**Multi-ecosystem dependency and secrets scanner for the developer's machine and tools.**  
Covers source repos, developer machines, and exposed secrets — zero cloud calls except for osv.dev and NVD API (both mirror-configurable).

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool, **secrets detector**, and **install-blocking firewall** built for teams who care about what enters their supply chain at every layer. Unlike report-only scanners, the full UBEL toolset enforces policy — if a scan fails, it blocks the operation and tells you exactly why.

As a project, UBEL spans the entire delivery chain: from the moment a developer adds a dependency, through CI validation, to what is running on a deployment server or inside an AI agent's runtime environment.

**This specific extension** covers the editor-side slice of that: dependency vulnerability scanning (SCA), secrets detection, and host/editor-extension auditing, all in `health` (report-only) mode. It does **not** include the install-time firewall (the scan-before-you-install gate that blocks a malicious package before it ever reaches `node_modules`), AI-powered SAST/malicious-code scanning, or CI/CD wiring — those live in the `@arcane-spark/ubel-node` CLI package ([npm](https://www.npmjs.com/package/@arcane-spark/ubel-node), [docs](https://github.com/AlaBouali/ubel/blob/main/node/README.md)) and the [official GitHub Action](https://github.com/AlaBouali/ubel), which this extension is a companion to rather than a replacement for.

---

## Extension's features

- Full dependency resolution with PURL generation
- Querying authoritative vulnerability sources in real time, allowing newly published advisories to be detected immediately without waiting for scheduled database refreshes unlike the competitors.
- Vulnerability scanning via batched API queries to OSV.dev and NVD's APIs
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- Policy engine — block/allow by severity threshold and unknown-severity packages
- Malicious package (infection) detection — always blocked regardless of policy
- **Secrets detection** — Trivy's ported, Apache-2.0-attributed ruleset, extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault, GCP API keys/OAuth tokens, Anthropic, OpenRouter, Stripe restricted keys, Twilio SIDs, URL-embedded git credentials, and more). Included by default in every project scan, or standalone via its own command. Match previews in every report are redacted.
- **License compliance** — every package's declared license is normalized (SPDX expressions, free text, npm's `UNLICENSED` proprietary marker vs. the SPDX `Unlicense` public-domain license, missing/`unknown` values) and checked against the OSI-approved license list, with a derived risk rating. Included by default in every project scan, or standalone via its own command (no vulnerability lookups, no secrets scan).
- Dependency graph with introduced-by and parent tracking
- Automatic report generation: timestamped **JSON** (`*.json`) + **HTML** (`*.html`) + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links
- Zero external runtime dependencies (Node.js stdlib only)
- Complete compliant, and enriched SBOM Cyclonedx V1.6 files with full dependencies and vulnerabilities data in VEX
- Complete compliant, and enriched SARIF v2.1.0 files
- **Reachability analysis** — each vulnerability is annotated with a reachability level (`total` / `high` / `medium` / `low`) derived from package type, scope, dependency depth, attack vector, and import-scan confirmation across all supported ecosystems

---

## Commands

| Command | Shortcut (Win/Linux) | Shortcut (Mac) | What it scans |
|---|---|---|---|
| **UBEL: Scan Project** | `Ctrl+Alt+U` | `Cmd+Alt+U` | All ecosystems inside the open workspace folder (includes secrets by default) |
| **UBEL: Scan Code Editor's Extensions** | `Ctrl+Alt+X` | `Cmd+Alt+X` | npm packages inside `~/.vscode/extensions` or `~/.vscode-oss/extensions` or `~/.cursor/extensions` |
| **UBEL: Scan Host Platform** | `Ctrl+Alt+P` | `Cmd+Alt+P` | System software installed on this machine |
| **UBEL: Scan project for Exposed Secrets** | `Ctrl+Alt+S` | `Cmd+Alt+S` | Secrets-only pass over the open workspace folder — no dependency resolution |
| **UBEL: Scan project for License Compliance** | `Ctrl+Alt+L` | `Cmd+Alt+L` | License-only pass over the open workspace folder — full dependency resolution, no vulnerability lookups, no secrets scan |

All five commands are also accessible via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) — search **UBEL**.

---

## Installation

**From the Marketplace**

Search for **UBEL** in the VS Code Extensions panel

**From VSIX**

1. Download `ubel-vscode-extension.vsix` from the [releases page](https://github.com/AlaBouali/ubel/tree/main/vscode).
2. Open the Command Palette → **Extensions: Install from VSIX…**
3. Select the downloaded file.

---

## Scan Project (`Ctrl+Alt+U`)

Scans every ecosystem present anywhere inside the currently open workspace folder. Monorepos with mixed stacks are fully covered in a single pass — no configuration needed.

**What gets scanned**

| Ecosystem | Resolved From |
|---|---|
| Node.js (npm, pnpm, yarn, bun) | `node_modules/` on-disk walk |
| Python | `.venv/`, `venv/`, virtual environment directories |
| PHP | `vendor/` |
| Rust | `Cargo.lock` |
| Go | `go.sum` |
| C#/.NET | `packages.lock.json`, `obj/project.assets.json` |
| Java | `pom.xml` resolved dependencies |
| Ruby | `Gemfile.lock` |

**Report location**

```
<project-root>/.ubel/reports/latest.*
```

---

## Scan VS Code Extensions (`Ctrl+Alt+X`)

Scans the npm packages bundled inside your installed VS Code / Cursor / VS Codium extensions (`~/.vscode/extensions` or `~/.vscode-oss/extensions` or `~/.cursor/extensions`). Extensions are a meaningful supply-chain surface — they run with full Node.js access in the editor host process and are updated silently.

**Report location**

```
~/.vscode/extensions/.ubel/reports/latest.*
```
or
```
~/.vscode-oss/extensions/.ubel/reports/latest.*
```
or
```
~/.cursor/extensions/.ubel/reports/latest.*
```

---

## Scan Host Platform (`Ctrl+Alt+P`)

Audits the system-level software installed on the developer's machine itself — a distinct attack surface from project dependencies. Vulnerabilities are matched using [CPE 2.3](https://nvd.nist.gov/products/cpe) identifiers against the CVE/NVD database.

This catches what dependency scanners miss: a vulnerable version of Git, an unpatched Python interpreter, an outdated Docker Desktop install, or an end-of-life .NET runtime.

**Windows** — detected via registry probes and PowerShell, no elevated privileges required:

| Category | Components |
|---|---|
| Operating system | Windows 10 / 11 (build-accurate CPE version) |
| Security | Windows Defender |
| Runtimes | Node.js, Python, PHP, Go, Rust, Ruby, JRE, JDK |
| .NET | All installed .NET Core / Desktop / ASP.NET runtimes (multi-version) |
| Browsers | Chrome, Firefox, Microsoft Edge |
| Developer tools | Git, Docker Desktop, VS Code, Cursor |
| Shell | PowerShell |

**Linux** — reads the system package database directly, works as a standard user on most distributions:

| Distro family | Source |
|---|---|
| Debian / Ubuntu | `/var/lib/dpkg/status` |
| Alpine | `/lib/apk/db/installed` |
| Red Hat / AlmaLinux / Rocky | `rpm -qa` |

> On RPM-based systems, `rpm -qa` may return partial results depending on SELinux policy if run without elevated privileges.

**Report location**

The report is always written to `~/.ubel/reports/latest.*`, independent of any open workspace.

```
~/.ubel/reports/latest.*
```

---

## Scan for Exposed Secrets (`Ctrl+Alt+S`)

Runs a secrets-only pass over the open workspace folder — no dependency resolution, no package-manager calls. Built on Trivy's ported secret-scanning ruleset (Apache-2.0, see [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover:

- HashiCorp Vault tokens
- Google Cloud API keys and OAuth access tokens
- Anthropic and OpenRouter API keys
- Firebase tokens
- Stripe restricted keys (`rk_live_` / `rk_test_`)
- Twilio Account/App SIDs
- Square and Braintree credentials
- Credentials embedded in a git remote URL (`https://user:token@host/...`)

Match previews shown in every report are redacted — the raw secret value is never written to disk, in this report or any other.

**This scan also runs automatically** as part of **UBEL: Scan Project** (`Ctrl+Alt+U`) — this command exists for when you want a fast, dependency-resolution-free pass, e.g. before a commit.

**Report location**

```
<project-root>/.ubel/reports/latest.*
```

> This is the same path **UBEL: Scan Project** writes to. Running one after the other overwrites `latest.*` with whichever ran most recently — the timestamped copy under `.ubel/local/reports/.../<date>/` from the earlier run is retained, but `latest.*` always reflects the most recent scan of either kind.

---

## Scan for License Compliance (`Ctrl+Alt+L`)

Runs a license-only pass over the open workspace folder: full dependency resolution across every ecosystem present, license normalization and OSI-approval/risk classification — but **no vulnerability lookups** (no OSV.dev/NVD calls) and **no secrets scan**. Use this when you only need a license inventory (e.g. for legal/compliance review) without the time or network cost of a full vulnerability scan.

See [License Compliance](#license-compliance) below for how licenses are normalized and classified — the classification logic is identical whether it runs standalone here or as part of **UBEL: Scan Project**.

**This scan is also included automatically** as part of **UBEL: Scan Project** (`Ctrl+Alt+U`) — this command exists for a faster, vulnerability-lookup-free pass when license data is all you need.

**Report location**

```
<project-root>/.ubel/reports/latest.*
```

> This is the same path **UBEL: Scan Project** and **UBEL: Scan project for Exposed Secrets** write to. Running any of the three overwrites `latest.*` with whichever ran most recently — the timestamped copy under `.ubel/local/reports/.../<date>/` from the earlier run is retained, but `latest.*` always reflects the most recent scan.

---

## Scan Results

Every scan ends with a VS Code notification:

| Result | Notification | Meaning |
|---|---|---|
| ✅ | Scan complete — no policy violations | All packages passed |
| ⚠️ | Policy violation | Vulnerable or malicious package found above threshold |
| ❌ | Scan error | Unexpected failure — message contains details |

Every notification includes an **Open Report** button that opens the full interactive HTML report in your browser.

---

## The HTML Report

Each scan produces a self-contained HTML file that works fully offline. It contains six tabs:

| Tab | Contents |
|---|---|
| **Dashboard** | Vulnerability counts by severity, policy decision summary, scan metadata |
| **Vulnerabilities** | Full list of matched CVEs with CVSS score, EPSS, severity, fix version, reachability level, and policy decision |
| **Inventory** | Every scanned package with version, PURL, CPE, ecosystem, license risk (OSI-approved status, risk level), and vulnerability count |
| **Graph** | Interactive force-directed dependency graph — colour-coded by vulnerability status, with search, filter, drag, and pin |
| **Stats** | Severity distribution charts, top vulnerable packages, ecosystem breakdown |
| **System** | OS metadata, Node.js version, scan engine info |

---

## Reachability Analysis

Every vulnerability in the report is annotated with a reachability assessment. The analyzer operates on the existing report fields — package type, scope, dependency depth, CVSS attack vector, and the dependency graph — and performs a source-level import scan over the workspace files to confirm or refute whether the vulnerable package is actually used by application code.

The goal is prioritization: to separate vulnerabilities in packages your code actively exercises from those in packages that are installed but unreachable from any production code path.

### Decision ladder

Signals are evaluated in strict priority order. The first matching rule wins.

| Priority | Signal | Reachability | Confidence |
|---|---|---|---|
| 0a | Vuln ID starts with `MAL-` | `total` | high |
| 0b | Package scope includes `env` | `total` | high |
| 1 | Package type is non-library (app, framework, plugin, OS package, …) | `total` | high |
| 2 | Scope is `dev` or `test` | `unreachable` | high |
| 3 | Import scan: package imported in source files | `high` or `medium` | high |
| 4a | Import scan: direct import absent, but importing parent found | `medium` or `low` | medium |
| 4b | Import scan: no direct or parent import found | `unreachable` | medium |
| 5 | Orphan tool (no dependents in graph, no import scan available) | `unreachable` | medium |
| 6 | Depth + attack vector heuristics | `medium` or `low` | low |

**Priority 0a (MAL-)** — Malware advisories represent active supply-chain infections. The vulnerable code *is* the infection vector; reachability is unconditional regardless of how or whether the package is imported.

**Priority 0b (env scope)** — Packages carrying the `env` scope are part of the execution environment itself — OS packages, system libraries, runtimes, container-layer components. They are not imported by application code; they *are* the environment. Reachability is unconditional.

**Priority 1 (non-library type)** — Frameworks, applications, plugins, and OS-level packages have no meaningful import boundary. The component itself is the attack surface.

**Priority 2 (dev/test scope)** — Packages that are exclusively development or test dependencies are excluded from production runtimes.

**Priorities 3–4 (import scan)** — UBEL scans workspace source files for import statements matching the package. For transitive dependencies where the package itself is not directly imported, it checks whether any of the package's parents in the dependency graph are imported — confirming that the transitive path is exercised.

**Priority 5 (orphan tool)** — Root packages with no dependents and no import scan result are most likely standalone CLI tools not called by application code.

**Priority 6 (heuristics)** — When no higher-priority signal is available, depth in the dependency tree and the CVSS attack vector are used as weak proxies.

### Import scan coverage

| Ecosystem | Extensions | Patterns matched |
|---|---|---|
| Node.js | `.js` `.ts` `.mjs` `.cjs` `.jsx` `.tsx` | `require('<pkg>')`, `from '<pkg>'` |
| Python | `.py` | `import <pkg>`, `from <pkg>` |
| Java / Kotlin | `.java` `.kt` `.groovy` `.scala` | `import <group>.<artifact>` |
| C# / .NET | `.cs` `.vb` `.fs` | `using <Namespace>` |
| PHP | `.php` | `use <Vendor>\\`, `require '<pkg>'` |
| Go | `.go` | `"<module-path>"` |
| Rust | `.rs` | `use <crate>::`, `extern crate <crate>` |
| Ruby | `.rb` | `require '<gem>'` |

Reachability results appear in the **Vulnerabilities** tab of the HTML report and in the machine-readable JSON report under each vulnerability's `reachability` field.

---

## License Compliance

Every project scan classifies each package's declared license by default. Licenses arrive in inconsistent shapes across ecosystems (SPDX ids, free text like `"Apache 2.0"`, npm's `UNLICENSED` proprietary sentinel, Python trove classifiers, `OR`/`AND` SPDX expressions, or missing entirely); UBEL normalizes all of them to a canonical SPDX identifier, checks it against the OSI-approved license list, and assigns a risk rating:

| Category | Examples | Risk |
|---|---|---|
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC | `low` |
| Weak copyleft | MPL-2.0, LGPL-2.1/3.0, EPL-2.0 | `medium` |
| Strong copyleft | GPL-2.0/3.0, AGPL-3.0 | `high` |
| Proprietary / source-available | npm `UNLICENSED`, SSPL-1.0, BUSL-1.1 | `high` |
| None / unrecognized | missing, `unknown`, or unparseable text | `unknown` |

npm's `UNLICENSED` sentinel (proprietary — all rights reserved) is deliberately not confused with the SPDX `Unlicense` public-domain license; dual-licensed packages (`OR`) are classified using the most favorable option, since the consumer may legally choose it.

Run standalone via **UBEL: Scan project for License Compliance** (`Ctrl+Alt+L`) — see above — when you want license data only, with no vulnerability lookups or secrets scan.

Results appear in the **Inventory** tab of the HTML report (per-package license, OSI-approved status, and risk) and in the machine-readable JSON/SBOM/SARIF reports under each package's `license_info` field.

---

## Policy

All package managers share the same policy engine. Policy is stored per-project in `.ubel/local/policy/config.json`.

| Field | Values | Default | Behaviour |
|---|---|---|---|
| `severity_threshold` | `low` `medium` `high` `critical` `none` | `high` | Block packages at or above this severity |
| `block_unknown_vulnerabilities` | `true` `false` | `true` | Block packages with CVEs but no CVSS score |
| Infections (`MAL-*`) | — | always blocked | Cannot be toggled; unconditionally blocked |

The threshold is inclusive — `high` blocks both `high` and `critical`. Setting `none` disables severity blocking but infections are still blocked.

---

## Coverage at a Glance

| Surface |
|---|
| Source repos & monorepos |
| Exposed secrets in source |
| Developer machines (Windows / Linux) |
| VS Code extension |

---

### Repos and Monorepos

UBEL walks the entire directory tree and detects all supported ecosystems in a single pass — no per-language configuration needed. Monorepos with mixed stacks (e.g. a Node.js frontend, Python backend, and Rust service in the same repo) are fully covered in one invocation.

### Developer Machines

The VS Code extension (`Ctrl+Alt+P`) and the `ubel-platform` CLI binary scan the host machine: OS, installed runtimes, browsers, developer tools, and security software. Vulnerabilities are matched using CPE 2.3 identifiers against the CVE/NVD database.

This surface catches what dependency scanners miss — a vulnerable version of Git, an unpatched Python interpreter, or an outdated Docker Desktop install.


### Windows

Detected via registry probes and PowerShell — no elevated privileges required.

| Category | Components |
|---|---|
| Operating system | Windows 10 / 11 (build-accurate CPE version) |
| Security | Windows Defender |
| Runtimes | Node.js, Python, PHP, Go, Rust, Ruby, JRE, JDK |
| .NET | All installed .NET Core / Desktop / ASP.NET runtimes (multi-version) |
| Browsers | Chrome, Firefox, Microsoft Edge |
| Developer tools | Git, Docker Desktop, VS Code, Cursor |
| Shell | PowerShell |

### Linux

Detected by reading the system package database directly.

| Distro family | Package manager | Source |
|---|---|---|
| Debian / Ubuntu | dpkg | `/var/lib/dpkg/status` |
| Alpine | apk | `/lib/apk/db/installed` |
| Red Hat / AlmaLinux / Rocky | rpm | `rpm -qa` |

> On RPM-based systems, `rpm -qa` may return partial results depending on SELinux policy if run without elevated privileges.

---

## Supported Ecosystems (Project Scan)

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| **Node.js** | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| **Python** | pip / virtualenv | `.venv`, `venv`, virtual environment directories |
| **PHP** | Composer | `vendor/` |
| **Rust** | Cargo | `Cargo.lock` |
| **Go** | Go Modules | `go.sum` |
| **C#/.NET** | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| **Java/Kotlin** | Maven | `pom.xml` resolved dependencies |
| **Ruby** | Bundler | `Gemfile.lock` |

---

## Reports

Every scan writes a self-contained interactive **HTML** + **JSON** + **SBOM** + **SARIF** reports.

| Scan target | Report path |
|---|---|
| Workspace | `<project-root>/.ubel/reports/latest*` |
| Secrets-only scan | `<project-root>/.ubel/reports/latest*` — same path as Workspace, see the note in [Scan for Exposed Secrets](#scan-for-exposed-secrets-ctrlalts) |
| License-only scan | `<project-root>/.ubel/reports/latest*` — same path as Workspace, see the note in [Scan for License Compliance](#scan-for-license-compliance-ctrlaltl) |
| VS Code / VS Codium / Cursor extensions | `~/.vscode/extensions/.ubel/reports/latest*` or `~/.vscode-oss/extensions/.ubel/reports/latest*` or `~/.cursor/extensions/.ubel/reports/latest*` |
| Host platform | `~/.ubel/reports/latest*` |

Previous scans are retained under:

- `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode-oss/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.cursor/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

---

## Requirements

- Node.js `>=18.0.0`
- VS Code `^1.85.0` (extension only)

---

## Privacy

UBEL is fully local. The only external calls are to [osv.dev's public API](https://osv.dev/) and [NVD's API](https://nvd.nist.gov/), which receive package PURLs (package name + version) to check for known vulnerabilities. No file contents, no dependency graphs, no machine identifiers, and no telemetry are sent anywhere. Secrets findings never leave the machine at all — match previews shown in reports are redacted before being written to disk.

Both endpoints can be redirected to an internal mirror by setting `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` in the environment the editor was launched from (e.g. via VS Code's own `terminal.integrated.env.*` settings, or the OS environment) — useful for air-gapped or regulated environments where even those two calls need to stay on an internal network. See [node/sca/README.md](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md#environment-variables) for details; this extension reads the same engine, so the same variables apply.

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
only exists where a package manager supports a lockfile-only dry run with no
side effects — today that's **npm, pnpm, bun, and Docker images**. Every
other ecosystem below is SCA-covered but not firewall-covered; this is a
mechanical constraint of each ecosystem's tooling, not an oversight.

---

## Capability Matrix

| Ecosystem | SCA | Firewall | SAST | Malware SAST | Reachability | License Compliance | Secrets |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Node.js (npm/pnpm/bun) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node.js (yarn) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python (pip/venv) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP (Composer) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby (Bundler) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Rust (Cargo) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go (modules) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Java / Kotlin (Maven) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C# / .NET (NuGet) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Docker images | ✅ (OS + app deps) | ✅ | — | — | — | ✅ | ✅ (in image) |
| Kubernetes manifests | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Terraform / CloudFormation (IaC) | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Linux host (apt/dnf) | ✅ | ❌ | — | — | — | ✅ | — |
| Windows host | ✅ | ❌ | — | — | — | ✅ | — |
| VS Code / Cursor / VSCodium extensions | ✅ | — | — | — | — | — | — |

✅ = built and shipped · ❌ = not currently possible/present for a stated reason · — = not applicable to that layer

---

## Node.js — npm / pnpm / bun / yarn

**SCA:** Full lockfile parsing across npm v1/v2/v3, pnpm v5/v6/v9, yarn
classic and berry, and bun v0/v1. Dependency resolution walks the actual
installed `node_modules` tree in addition to the lockfile, so it reflects
what's really on disk, not just what the manifest declares. Scope
assignment (production / dev / environment) is computed via BFS
propagation from the manifest's declared dependency types down through the
full tree.

**Firewall:** The only ecosystem (alongside Docker) with a true pre-install
gate. `npm`, `pnpm`, and `bun` each support a lockfile-only dry run
(`--package-lock-only`, `--lockfile-only`, and a `node_modules`-untouched
equivalent respectively) — UBEL resolves what *would* be installed, scans
it against policy, and only proceeds if it's clean. TOCTOU is closed with
SHA-256 integrity checks on the lockfile and `package.json` before and after
resolution, and any policy-blocked change is rolled back atomically via
`revert_lock_to_original`. **Yarn is deliberately excluded from firewalling**
— it has no side-effect-free dry-run equivalent; `yarn add` always writes
to `node_modules` before you'd get a chance to block it. Yarn projects still
get full SCA, SAST, secrets, and license coverage — they just can't be
gated pre-install the way npm/pnpm/bun can.

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

## Python — pip / venv

**SCA:** Resolves dependencies by walking virtual environment directories
directly (not just parsing `requirements.txt`), so it reflects the actual
installed environment, including transitive packages a manifest wouldn't
show on its own.

**Firewall:** Not available. `pip install` has no equivalent to npm's
`--package-lock-only` dry run — there's no way to resolve what *would* be
installed without actually installing it, so there's no side-effect-free
point at which to gate. Python projects get full health/SCA scanning
instead: install first, then scan, with policy enforcement working as a
detection-and-alert gate rather than a block-before-landing one. A related
CLI isolation feature (`ubel-pipx`-style) runs pip CLI tools in isolated,
managed per-project virtual environments to reduce blast radius even
without a true install-time firewall.

**SAST / Malware SAST:** Full coverage, same three-pass/two-pass pipelines.

**Reachability analysis:** Fully covered, tracking `.py` files against the
resolved dependency graph — one of eight ecosystems with this capability.

---

## PHP — Composer

**SCA:** Resolves the dependency tree from `vendor/` and `composer.lock`.

**Firewall:** Not available — Composer has no dry-run/lockfile-only install
mode UBEL can safely gate against. Health-scan only.

**SAST / Malware SAST:** Full coverage.

**Reachability analysis:** Fully covered — `.php` files are scanned for
`use`/`require`/`include` references against the resolved dependency
graph, same signal set (depth, scope, attack vector, import confirmation)
as every other reachability-covered ecosystem.

---

## Ruby — Bundler

**SCA:** Resolves from `Gemfile.lock`.

**Firewall:** Not available — same reasoning as PHP/Python: no
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

**Firewall:** Docker is the **second ecosystem with true pre-install
(here, pre-deploy) gating**, with three modes controlling what happens to
the image after scanning:
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

## Linux host (apt / dnf)

**SCA:** `LinuxHostScanner` inventories installed OS packages and matches
them against CPE/CVE data — this is what backs both the standalone
`ubel-platform` host scan and the OS-package half of every Docker image
scan.

**Firewall:** Not available. Despite covering apt/dnf package inventory,
there's no pre-install dry-run hook wired up for either package manager in
the current build — this is health/detection scanning of what's already
on the machine, not a gate on what's about to be installed.

**License compliance:** Fully applied. Per-package license strings are
extracted from rpm metadata, `/usr/share/doc/<pkg>/copyright` for
dpkg-based systems, and apk metadata, then fed through the same SPDX
normalization/OSI/risk classification layer as every other ecosystem — it
isn't a separate, lesser pipeline for OS packages.

---

## Windows host

**SCA:** `WindowsHostScanner` mirrors the Linux host scanner's role for
Windows — installed software/package inventory matched against CPE/CVE.

**Firewall:** Not available — same gap as the Linux host, no pre-install
gate.

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

- Firewall/pre-install gating is **npm, pnpm, bun, and Docker only** —
  not "every package manager," because most package managers don't offer
  a safe dry-run install to gate against. This is a hard mechanical
  constraint, not a roadmap gap.
- Reachability analysis's import-confirmation half covers **8 of the 8
  SCA ecosystems** — C, OS packages, Docker, Kubernetes, and IaC don't get
  it, since "is this imported by my source" isn't a meaningful question
  for those.
- Kubernetes and IaC coverage is **static file analysis**, not live
  cluster/cloud posture management — there is no drift detection against
  what's actually deployed.
- OS-level packages (apt/dnf, Windows) get full SCA **and** license
  compliance — the one thing they still don't get is firewalling
  (no pre-install dry-run gate), same limitation as every ecosystem
  outside npm/pnpm/bun/Docker.

---

## License

Free for scanning your own projects and systems.  
See [LICENSE.md](LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.