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

**This specific extension** covers the editor-side slice of that: dependency vulnerability scanning (SCA), secrets detection, and host/editor-extension auditing, all in `health` (report-only) mode. It does **not** include the install-time firewall (the scan-before-you-install gate that blocks a malicious package before it ever reaches `node_modules`), AI-powered SAST/malicious-code scanning, or CI/CD wiring — those live in the `@arcane-spark/ubel-node` CLI package ([npm](https://www.npmjs.com/package/@arcane-spark/ubel-node), [docs](https://github.com/AlaBouali/ubel/blob/main/README.md)) and the [official GitHub Action](https://github.com/AlaBouali/ubel), which this extension is a companion to rather than a replacement for.

---

## Extension's features

- Full dependency resolution with PURL generation
- Querying authoritative vulnerability sources in real time, allowing newly published advisories to be detected immediately without waiting for scheduled database refreshes unlike the competitors.
- Vulnerability scanning via batched API queries to OSV.dev and NVD's APIs
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- Policy engine — block/allow by severity threshold, unknown-severity packages, and license risk
- Malicious package (infection) detection — always blocked regardless of policy
- **Secrets detection** — Trivy's ported, Apache-2.0-attributed ruleset, extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault, GCP API keys/OAuth tokens, Anthropic, OpenRouter, Stripe restricted keys, Twilio SIDs, URL-embedded git credentials, and more). Included by default in every project scan, or standalone via its own command. Match previews in every report are redacted.
- **License compliance** — every package's declared license is normalized (SPDX expressions, free text, npm's `UNLICENSED` proprietary marker vs. the SPDX `Unlicense` public-domain license, missing/`unknown` values) and checked against the OSI-approved license list, with a derived risk rating. Included by default in every project scan, or standalone via its own command (no vulnerability lookups, no secrets scan).
- Dependency graph with introduced-by and parent tracking
- Automatic report generation: timestamped **JSON** (`*.json`) + **HTML** (`*.html`) + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links
- Zero external runtime dependencies (Node.js stdlib only)
- Complete compliant, and enriched SBOM Cyclonedx V1.6 files with full dependencies and vulnerabilities data in VEX
- Complete compliant, and enriched SARIF v2.1.0 files
- **Reachability analysis** — each vulnerability is annotated with a reachability level (`total` / `high` / `medium` / `low`) derived from package type, scope, dependency depth, attack vector, and import-scan confirmation across all supported ecosystems
- **Compliance framework mapping** — every vulnerability and secrets finding is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, with a report-level per-framework/per-control finding-count summary. Included by default in every scan, across the JSON, HTML, and SARIF reports (see [Compliance Framework Mapping](#compliance-framework-mapping))

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

Runs a secrets-only pass over the open workspace folder — no dependency resolution, no package-manager calls. Built on Trivy's ported secret-scanning ruleset (Apache-2.0, see [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover:

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
| **Compliance** | One card per framework (OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, CIS Controls v8) with control breakdown and finding counts — see [Compliance Framework Mapping](#compliance-framework-mapping) |
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

## Compliance Framework Mapping

Every dependency vulnerability and secrets-in-source finding is mapped onto industry compliance/security frameworks by default — no separate flag or mode needed, and included in every report format. This is distinct from [License Compliance](#license-compliance) above, which is about license-obligation risk on installed software; this is about mapping *security* findings onto the frameworks an org is typically audited against.

Each finding is first assigned one or more internal risk categories (e.g. `injection`, `secrets_management`, `vulnerable_components` — the latter always applied to a dependency finding as a baseline, since every SCA finding is a known-vulnerable-component finding by definition), and each category carries a fixed list of framework control references, so two findings with the same underlying risk always map identically.

**Frameworks covered**

| Framework | Notes |
|---|---|
| OWASP Top 10 (2021) | Category codes (`A01:2021`–`A10:2021`) |
| PCI DSS v4.0 | Requirement numbers |
| HIPAA Security Rule | §164.312 / §164.308 citations |
| SOC 2 (Trust Services Criteria) | `CC*`/`A1.*` codes |
| ISO/IEC 27001:2022 (Annex A) | `A.*` control numbers |
| NIST SP 800-53 Rev. 5 | Control IDs (e.g. `SI-10`, `AC-3`) |
| GDPR | Article citations |
| CIS Controls v8 | Numbered controls |

**This is best-effort guidance, not a certified compliance assessment.** Control identifiers are the stable, publicly documented ones for each framework, but framework text, versioning, and applicable scope can change, and always depend on the org's own environment. Every report carries this disclaimer verbatim in `compliance_summary.disclaimer` — treat the mapping as a starting point for an audit conversation, not a citation to quote in one.

**Output**

- **HTML report**: a dedicated **Compliance** tab with one card per framework (control breakdown + finding counts), plus a Compliance Frameworks section in each vulnerability's detail modal.
- **JSON report**: a `compliance` object on every vulnerability and secrets finding, plus a report-level `compliance_summary` aggregating all findings into per-framework, per-control counts.
- **SARIF report**: `compliance_categories` / `compliance_frameworks` on each rule, and the full `compliance` object on each result.

---

## Policy

All package managers share the same policy engine. Policy is stored per-project in `.ubel/local/policy/config.json`.

| Field | Values | Default | Behaviour |
|---|---|---|---|
| `severity_threshold` | `low` `medium` `high` `critical` `none` | `high` | Block packages at or above this severity |
| `block_unknown_vulnerabilities` | `true` `false` | `true` | Block packages with CVEs but no CVSS score |
| `license_risk_threshold` | `none` `low` `medium` `high` | `none` | Block packages whose license risk is at or above this level; never blocks on `unknown` regardless of setting (see `block_unknown_license_risk`) |
| `block_unknown_license_risk` | `true` `false` | `false` | Separately block packages whose license couldn't be classified at all |
| Infections (`MAL-*`) | — | always blocked | Cannot be toggled; unconditionally blocked |

The severity threshold is inclusive — `high` blocks both `high` and `critical`. Setting `none` disables severity blocking but infections are still blocked. `license_risk_threshold`/`block_unknown_license_risk` are opt-in (both default off) since license-risk tolerance varies by org and license detection has real gaps (free-text licenses, missing metadata); every extension scan runs in `health` mode, where these two gates are active.

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

Both endpoints can be redirected to an internal mirror by setting `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` in the environment the editor was launched from (e.g. via VS Code's own `terminal.integrated.env.*` settings, or the OS environment) — useful for air-gapped or regulated environments where even those two calls need to stay on an internal network. See [sca/README.md](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#environment-variables) for details; this extension reads the same engine, so the same variables apply.

---

## License

Free for scanning your own projects and systems.  
See [LICENSE.md](LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.