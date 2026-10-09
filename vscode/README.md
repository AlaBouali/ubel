# UBEL — Supply-Chain & Secrets Scanner for VS Code

**Multi-ecosystem dependency and secrets scanner for the developer's machine and tools.**  
Covers source repos, developer machines, and exposed secrets — runs entirely locally. The only network calls are to osv.dev and the NVD API for vulnerability data (both mirror-configurable), plus best-effort lookups to the CISA KEV catalog and the FIRST EPSS API for exploit intelligence.

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool, **secrets detector**, and **install-blocking firewall** built for teams who care about what enters their supply chain at every layer. Unlike report-only scanners, the full UBEL toolset enforces policy — if a scan fails, it blocks the operation and tells you exactly why.

As a project, UBEL spans the entire delivery chain: from the moment a developer adds a dependency, through CI validation, to what is running on a deployment server or inside an AI agent's runtime environment.

**This specific extension** covers the editor-side slice of that: dependency vulnerability scanning (SCA) enriched with exploit intelligence (CISA KEV + EPSS), secrets detection, license compliance, and host/editor-extension auditing, all in `health` (report-only) mode. It is built directly on the SCA engine of the `@arcane-spark/ubel-node` package, so findings, policy, and reports are identical to what the CLI's `health` mode produces (see [Extension vs. CLI](#extension-vs-cli)). It does **not** include the install-time firewall (the scan-before-you-install gate that blocks a malicious package before it ever reaches `node_modules`), AI-powered SAST/malicious-code scanning, or CI/CD wiring — those live in the `@arcane-spark/ubel-node` CLI package ([npm](https://www.npmjs.com/package/@arcane-spark/ubel-node), [docs](https://github.com/AlaBouali/ubel/blob/main/README.md)) and the [official GitHub Action](https://github.com/AlaBouali/ubel), which this extension is a companion to rather than a replacement for.

---

## Extension's features

- Full dependency resolution with PURL generation
- Querying authoritative vulnerability sources in real time, allowing newly published advisories to be detected immediately without waiting for scheduled database refreshes unlike the competitors.
- Vulnerability scanning via batched API queries to OSV.dev and NVD's APIs
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- **Exploit intelligence** — every vulnerability is checked against the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and scored with [FIRST EPSS](https://www.first.org/epss/); policy blocks KEV entries and anything at or above an EPSS threshold, and a feed outage never aborts the scan (see [Exploit Intelligence](#exploit-intelligence-kev--epss))
- Policy engine — block/allow by severity threshold, unknown-severity packages, CISA KEV membership, EPSS score, and license risk
- Malicious package (infection) detection — always blocked regardless of policy
- **Secrets detection** — Trivy's ported, Apache-2.0-attributed ruleset, extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover (HashiCorp Vault, GCP API keys/OAuth tokens, Anthropic, OpenRouter, live Stripe restricted keys, URL-embedded git credentials, database connection strings with embedded passwords, and more). Findings can be suppressed with a `.ubelignore` file or inline `ubel:ignore` markers (see [Suppressing findings](#suppressing-findings)). Included by default in every project scan, or standalone via its own command. Match previews in every report are redacted.
- **License compliance** — every package's declared license is normalized (SPDX expressions, free text, npm's `UNLICENSED` proprietary marker vs. the SPDX `Unlicense` public-domain license, missing/`unknown` values) and checked against the OSI-approved license list, with a derived risk rating. Included by default in every project scan, or standalone via its own command (no vulnerability lookups, no secrets scan).
- Dependency graph with introduced-by and parent tracking (Swift and Flutter/Dart lockfiles don't record a dependency graph, so those packages have no edges)
- Automatic report generation: timestamped **JSON** (`*.json`) + **HTML** (`*.html`) + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links. For historic tracking, a zipped snapshot of each scan's reports is saved too
- Zero external runtime dependencies (Node.js stdlib only)
- Complete compliant, and enriched SBOM Cyclonedx V1.6 files with full dependencies and vulnerabilities data in VEX
- Complete compliant, and enriched SARIF v2.1.0 files
- **Reachability analysis** — each vulnerability is annotated with a reachability level (`total` / `high` / `medium` / `low`) derived from package type, scope, dependency depth, attack vector, and import-scan confirmation across all supported ecosystems
- **Executive summary** — every JSON and HTML report opens with a plain-language overview for non-technical readers: overall risk rating, policy verdict, key numbers, key findings (including weaknesses already exploited in real attacks), the components to fix first, and prioritized recommended actions (see [Executive Summary](#executive-summary))
- **Recommended package-level fixes** — for every package, UBEL works out which versions to upgrade to, grouped per version range (stay on your current minor line, or move to a newer one/major), picking the fewest and highest versions that clear the most vulnerabilities, and lists whatever has no fix at all (see [Recommended Package Fixes](#recommended-package-fixes))
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

**What each command runs**

| Command | Dependency resolution | Host OS / dev tools | Vulnerability lookups (OSV / NVD) | KEV / EPSS enrichment | Secrets scan | License classification |
|---|---|---|---|---|---|---|
| Scan Project | ✅ every ecosystem | ❌ | ✅ | ✅ | ✅ | ✅ |
| Scan Code Editor's Extensions | ✅ npm packages | ❌ | ✅ | ✅ | ✅ | ✅ |
| Scan Host Platform | ❌ | ✅ | ✅ (CPE / NVD) | ✅ | ❌ | ✅ |
| Scan project for Exposed Secrets | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| Scan project for License Compliance | ✅ every ecosystem | ❌ | ❌ | ❌ | ❌ | ✅ |

Only one scan runs at a time — starting a second while one is in progress shows a warning and does nothing.

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

Scans every ecosystem present anywhere inside the currently open workspace folder. Monorepos with mixed stacks are fully covered in a single pass — no configuration needed. Each discovered package is deduplicated by PURL, so packages shared across sub-projects are scanned exactly once. See [Supported Ecosystems](#supported-ecosystems-project-scan) for Swift and Flutter/Dart specifics.

**What gets scanned**

| Ecosystem | Resolved From |
|---|---|
| Node.js (npm, pnpm, yarn, bun) | `node_modules/` on-disk walk |
| Python | `.venv/`, `venv/`, virtual environment directories |
| PHP | `vendor/`, `composer.lock` |
| Rust | `Cargo.lock` |
| Go | `go.sum` |
| C#/.NET | `packages.lock.json`, `obj/project.assets.json` |
| Java | `pom.xml` resolved dependencies |
| Ruby | `Gemfile.lock` |
| Swift | `Package.resolved` (SwiftPM v1/v2/v3, incl. Xcode workspaces), `.build/workspace-state.json` fallback, `Cartfile.resolved` (Carthage) |
| Flutter / Dart | `pubspec.lock`, or `.dart_tool/package_config.json` when no lockfile is committed |

**Report location**

```
<project-root>/.ubel/reports/latest.*
```

---

## Scan VS Code Extensions (`Ctrl+Alt+X`)

Scans the npm packages bundled inside your installed VS Code / Cursor / VS Codium extensions (`~/.vscode/extensions` or `~/.vscode-oss/extensions` or `~/.cursor/extensions`). Extensions are a meaningful supply-chain surface — they run with full Node.js access in the editor host process and are updated silently. The extension detects which editor is hosting it (VS Code, Cursor, or VSCodium) and scans that editor's directory. As with a project scan, the secrets pass and license classification are included, and the report header is tagged with the scanned editor and its version.

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

Every detected component carries its actual license or vendor EULA — proprietary Microsoft/vendor components (Windows itself, Defender, Edge, Chrome, Docker Desktop, Visual Studio, Cursor, Claude Code, …) resolve to a `LicenseRef-*` identifier rather than `unknown`, while open-source runtimes and tools resolve to their real SPDX id (e.g. `MIT` for Node.js/.NET, `PSF-2.0` for Python). Findings are also enriched with KEV/EPSS data. The host-platform scan does **not** run the secrets pass.

**Windows** — detected via registry probes and PowerShell, no elevated privileges required:

| Category | Components |
|---|---|
| Operating system | Windows 10 / 11 (build-accurate CPE version) |
| Security | Windows Defender |
| Runtimes | Node.js, Python, PHP, Go, Rust, Ruby, JRE, JDK |
| .NET | All installed .NET Core / Desktop / ASP.NET runtimes (multi-version) |
| Browsers | Chrome, Firefox, Microsoft Edge |
| Developer tools | Git, Docker Desktop, Visual Studio, VS Code, Cursor, Claude Code |
| Shell | PowerShell |

**Linux** — reads the system package database directly, works as a standard user on most distributions:

| Distribution | Package manager | Source | PURL type |
|---|---|---|---|
| Ubuntu | dpkg | `/var/lib/dpkg/status` | `pkg:deb/ubuntu/` |
| Debian | dpkg | `/var/lib/dpkg/status` | `pkg:deb/debian/` |
| Alpine | apk | `/lib/apk/db/installed` | `pkg:apk/alpine/` |
| Alpaquita | apk | `/lib/apk/db/installed` | `pkg:apk/alpaquita/` |
| Red Hat / RHEL | rpm | `rpm -qa` | `pkg:rpm/redhat/` |
| AlmaLinux | rpm | `rpm -qa` | `pkg:rpm/almalinux/` |
| Rocky Linux | rpm | `rpm -qa` | `pkg:rpm/rocky-linux/` |
| CentOS / Fedora | rpm | `rpm -qa` | `pkg:rpm/redhat/` |

Each package entry includes its binary install paths and direct dependency edges as reported by the package database.

> On RPM-based systems, `rpm -qa` may return partial results depending on SELinux policy if run without elevated privileges.

**Report location**

The report is always written to `~/.ubel/reports/latest.*`, independent of any open workspace.

```
~/.ubel/reports/latest.*
```

---

## Scan for Exposed Secrets (`Ctrl+Alt+S`)

Runs a secrets-only pass over the open workspace folder — no dependency resolution, no package-manager calls. Built on Trivy's ported secret-scanning ruleset (Apache-2.0, see [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/NOTICE)), extended with UBEL's own rules for vendors Trivy's current upstream doesn't cover:

- HashiCorp Vault tokens (`hvs.` prefix)
- Google Cloud API keys (`AIza…`) and OAuth access tokens (`ya29.`)
- Anthropic and OpenRouter API keys
- Firebase server tokens
- Amazon MWS auth tokens
- Square OAuth secrets and access tokens, Braintree access tokens. A Square `EAAA…` token must be a standalone string with enough entropy: it is not reported when it sits inside a longer base64/base64url run (inlined wasm, data URIs)
- Stripe live restricted keys (`rk_live_`) — Trivy covers publishable/secret keys but not this format. Test-mode keys (`rk_test_`) are deliberately skipped, since they can only reach test-mode data
- Credentials embedded in a git remote URL (`https://user:token@host/...`) — covers GitHub, GitLab, Bitbucket, Azure DevOps, Codeberg, Gitea, Gitee and SourceHut, self-hosted instances whose hostname starts with `git`, `gitlab`, `bitbucket`, `gitea`, `gogs` or `forgejo`, and any other host when the URL is a `.git` remote. Placeholder passwords (`password`, `token`, `xxxx`, …) and `${VAR}` references are ignored
- Database and broker connection strings with an embedded password — three forms, all reporting the password only:
  - **URL** (rule `database-url-credentials`): `postgres://`, `postgresql://`, `mysql://`, `mariadb://`, `mongodb://` / `mongodb+srv://`, `redis://` / `rediss://`, `amqp://` / `amqps://`, `mssql://`, `sqlserver://`, `cockroachdb://`, `clickhouse://`, `neo4j://`, `bolt://`, and SQLAlchemy-style `postgresql+psycopg2://`
  - **Key/value** (rule `database-connection-string-password`): ADO.NET, ODBC and libpq strings such as `Server=…;Database=…;Password=…` or `host=… password=…`; a host/database key must appear earlier on the same line, so a bare `password=` is left to the generic rule
  - **JDBC** (rule `jdbc-url-password`): `jdbc:mysql://host/db?user=u&password=…`, `jdbc:sqlserver://host;…;password=…`

  Not reported: placeholders and templates (`${DB_PASS}`, `<password>`, `changeme`, `YOUR_PASSWORD`, `xxxx`, …), `user:user` pairs such as `guest:guest`, default passwords (`postgres`, `root`, `admin`, `test`, …) against `localhost`, `127.0.0.1`, `host.docker.internal` or a bare docker-compose service name, and hosts containing `example`. The same default password against a real hostname *is* reported.
- Generic high-entropy fallback for unknown vendors — a vendor-style prefix (`sk-`, `pk_`, `xox*`, `api_`, `key_`, `token_`) followed by 32+ characters, where the part after the prefix must also clear a Shannon-entropy check, so repeated runs and plain snake_case identifiers aren't reported
- Generic key-value fallback — `password`/`secret`/`token`/`api_key`/`private_key` assigned a 32+ character value; there is no entropy check here, the key name is the signal

Twilio Account/App SIDs are intentionally **not** detected: the `AC…`/`AP…` + 32-character pattern has no checksum or distinguishing context and produced far too much noise.

The ruleset is a generated snapshot of Trivy's, regenerated from upstream when it changes — not a live mirror.

Match previews shown in every report are redacted — the raw secret value is never written to disk, in this report or any other.

In the other report formats, secrets are exposed as a `ubel:secrets` entry in the SBOM's root `properties`, and as their own `run` in the SARIF file (separate tool driver and rule set from the dependency-vulnerability run).

**This scan also runs automatically** as part of **UBEL: Scan Project** (`Ctrl+Alt+U`) — this command exists for when you want a fast, dependency-resolution-free pass, e.g. before a commit.

**Report location**

```
<project-root>/.ubel/reports/latest.*
```

> This is the same path **UBEL: Scan Project** writes to. Running one after the other overwrites `latest.*` with whichever ran most recently — the timestamped copy under `.ubel/local/reports/.../<date>/` from the earlier run is retained, but `latest.*` always reflects the most recent scan of either kind.

### What gets scanned

- **Every match on every line** is reported, not just the first per rule; overlapping matches collapse to one finding (a specific rule beats a generic one).
- **Private keys**: PEM blocks are matched across lines (the finding points at the `BEGIN` line and carries `end_line`), including encrypted/legacy PEM and PGP blocks. Extensionless key files are opened too: `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` (and `id_rsa.bak`-style variants) are always scanned, and files with no extension or a backup-style one (`.bak`, `.old`, `.orig`, `.p8`, `.ppk`, `.asc` …) are scanned if they start with a PEM private-key header.
- **`.env*` files are skipped** (they aren't meant to be committed). The global allow-rules still apply, so a file such as `.env.example` is skipped either way.
- **Skipped directories**: dependency trees, build output and caches are skipped (`node_modules`, `vendor`, `target`, `dist`, `build`, `out`, virtualenvs, …). `packages`, `bin`, `obj` and `env` are ambiguous names, so they are skipped only when the layout says they hold generated content — a NuGet `packages/` (next to a `.sln`, or containing `repositories.config`), a .NET `bin/`/`obj/` (next to a `.sln`/`.csproj`), a Python venv (`pyvenv.cfg`). A monorepo's `packages/*` and a Node `bin/` are scanned. Any default-skipped directory can be re-included with `include-dir:` in `.ubelignore` (below); VCS metadata (`.git`, `.svn`, `.hg`) and UBEL's own `.ubel/` directory are never walked and cannot be re-included.

### Suppressing findings

Put a `.ubelignore` file at the workspace root. One entry per line; `#` starts a comment.

```gitignore
docs/generated/                 # skip a directory
*.snap                          # skip files by glob, at any depth
/fixtures/keys/*.pem            # leading "/" anchors to the scan root
src/seed.js rule:generic-key-value-credential   # suppress one rule (comma list ok) on matching paths
rule:generic-fallback           # disable a rule everywhere
fingerprint:3f9a1c0be27d4a55    # accept one specific finding
include-dir:dist                # scan a directory that is skipped by default
exclude-dir:generated           # skip a directory name wherever it appears
unallow:tests                   # switch off a builtin allow-rule (e.g. scan test paths)
```

Or mark the line in the source, in any comment syntax:

```js
const k = "..."; // ubel:ignore
const k = "..."; // ubel:ignore[aws-access-key-id]
// ubel:ignore-next-line
```

Every finding carries a `fingerprint` in the JSON report — a hash of rule id, path and the secret, stable across line moves and never containing the secret itself — so a finding can be accepted by adding its `fingerprint:` line. The scan result also reports `suppressed` (how many findings the ignore rules dropped). The CLI's `ubel-secrets --write-baseline`, which writes these lines for you, is not available in the extension.

The builtin allow-list still skips paths containing `test`/`example` and secrets whose text contains "example"; `unallow:tests` / `unallow:examples` turn those off. The per-rule allow-lists of the database-connection-string rules are part of the rule, so `unallow:` does not affect them; switch one off with `rule:<id>`.

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

## Files UBEL Writes to Your Workspace

Besides the reports under `.ubel/` (see [Reports](#reports)), the **Scan Project**, **Scan Code Editor's Extensions**, **Scan project for Exposed Secrets** and **Scan project for License Compliance** commands make sure the scanned directory's `.gitignore` **and** `.dockerignore` ignore both `.ubel/` and `.ubelignore`, creating either file if it doesn't exist. **Scan Host Platform** does not touch them.

- **Idempotent.** An entry counts as covered if any equivalent pattern is already present (`.ubel`, `/.ubel/`, `.ubel/*`, `.ubel*`, …), so a hand-written entry is never duplicated.
- **Append-only.** Existing content, ordering and line endings (LF/CRLF) are preserved; new entries go under a `# ubel:` comment.
- **Opt-out respected.** A negation such as `!.ubelignore` means you want that entry tracked, so it is not re-added — this is how you commit a shared `.ubelignore` while everything else stays ignored.
- **Never fails a scan.** A read-only checkout or a permissions problem is silently skipped.
- **Kill switch:** set `UBEL_NO_IGNORE_FILES=1` in the environment the editor was launched from to turn this off.

---

## Scan Results

Every scan ends with a VS Code notification:

| Result | Notification | Meaning |
|---|---|---|
| ✅ | Scan complete — no policy violations | All packages passed |
| ⚠️ | Policy violation | A malicious package, a vulnerability at or above the severity threshold, a known-exploited (CISA KEV) or high-EPSS vulnerability, an exposed secret, or a configured license-risk gate was hit — see [Policy](#policy) |
| ❌ | Scan error | Unexpected failure — message contains details. This includes an OSV.dev/NVD lookup that couldn't be completed: an incomplete lookup is a failed scan, never a clean one |

KEV/EPSS lookups are the exception: they only add risk signal, so if either feed is unreachable the scan still completes, the affected fields are `null` (unknown), a warning is shown in the report, and the matching policy rule is not enforced for that run — see [Exploit Intelligence](#exploit-intelligence-kev--epss).

Every notification includes an **Open Report** button that opens the full interactive HTML report in your browser.

---

## The HTML Report

Each scan produces a self-contained HTML file that works fully offline. It contains nine tabs:

| Tab | Contents |
|---|---|
| **Dashboard** | Vulnerability counts by severity, policy decision summary (including threat-intel feed warnings), license-risk stats card, scan metadata |
| **Executive Summary** | Plain-language risk rating, policy verdict, key findings, components to fix first, and suggested actions for non-technical readers, printable as a PDF — see [Executive Summary](#executive-summary) |
| **Secrets** | Exposed secrets by category, severity, file/line, and redacted match preview |
| **Vulnerabilities** | Full list of matched CVEs with CVSS score, EPSS score/percentile, KEV badge, severity, fix version, reachability level, and policy decision. Click any row for a detail modal (CVSS vector, fix recommendations, OSV/NVD references, compliance frameworks) |
| **Inventory** | Every scanned package with version, PURL, CPE, ecosystem, state (safe / vulnerable / infected / undetermined), license risk (OSI-approved status, risk level), and vulnerability count. Click a package for its detail modal, which includes **Suggested Fixes** — see [Recommended Package Fixes](#recommended-package-fixes) |
| **Dependency Sequences** | Interactive force-directed dependency graph — colour-coded by vulnerability status, with search, filter, drag, and pin |
| **Detailed Stats** | Severity distribution charts, top vulnerable packages, ecosystem breakdown |
| **Compliance** | One card per framework (OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, CIS Controls v8) with control breakdown and finding counts — see [Compliance Framework Mapping](#compliance-framework-mapping) |
| **System Info** | OS metadata, local network interfaces, git info, Node.js version, engine/tool versions |

---

## Executive Summary

Every report (JSON and HTML) carries an `executive_summary` written for readers who don't work with CVEs, CVSS scores, or package URLs — management, risk and compliance teams, product owners. It is derived entirely from data already in the report (no extra scanning or network calls), so the JSON field and the HTML tab always show the same content. It is built after the policy decision is made and never fails a scan: if it can't be built, only the summary is omitted.

In the HTML report it is the **Executive Summary** tab, placed right after the Dashboard.

**What it contains**

| Section | What it tells the reader |
|---|---|
| Overall risk rating | One of Critical / High / Medium / Low / Minimal / Not assessed, with a rationale and general business-impact text |
| Headline & verdict | A one-sentence overview and whether the scan meets or fails the security policy, in plain language (with the technical reason alongside) |
| At a glance | Components reviewed and with issues, vulnerabilities by severity, how many have a fix available, how many are likely in use by your code vs. not, how many block policy, exposed credentials, how many are known to be exploited (KEV) or have a high exploit likelihood (EPSS) |
| Key findings | The handful of things that matter most, each with a severity |
| Components to fix first | Up to five components, ranked by malicious status, then known-exploited (and not judged unused), then whether they're likely in use, then worst severity, then forecast exploit likelihood, then issue count — each with a suggested upgrade action and the possible upgrade paths (see [Recommended Package Fixes](#recommended-package-fixes)) |
| Suggested actions | Prioritized actions with a timeframe and the reason for each |
| Compliance overview | Which frameworks the findings touch and which are most affected (omitted when nothing maps to a framework) — see [Compliance Framework Mapping](#compliance-framework-mapping) |
| Scope, methodology & glossary | What was scanned, how this specific report was produced, and plain-language definitions of the terms used |

**Layout and printing**

The HTML tab is laid out so the first screen can be read on its own and fits one printed page:

1. **Cover** — report title, what was scanned, report ID, date, and tool (`cover`).
2. **Bottom line** — the overall risk rating next to the policy verdict, a one-paragraph summary, the **Top risks**, **Do this first** (each action with its timeframe and a *suggested owner*), and four key figures (`bottom_line`).
3. **Details** — why this rating, all key findings, at-a-glance cards (`glance_cards`), components to fix first, all suggested actions, and compliance exposure.
4. **Appendix** — methodology, "About this report" (scope and notes), and the plain-language glossary. The appendix is collapsed on screen and expanded automatically when printing.

A **Print / save as PDF** button at the top of the tab prints the summary only (on a white background, other tabs hidden), so it can be handed to someone who never opens the interactive report. In the *Components to fix first* table, the identifiers under each component are the advisory references, for tickets and audit trails. For multi-system scans, the tab also shows *Configuration issues by area* and *Systems to review first* tables when that data is present.

**Overall risk rating**

| Rating | Assigned when |
|---|---|
| Critical | any malicious (`MAL-*`) component was found |
| High | any Critical/High-severity vulnerability that isn't confirmed unreachable, any [CISA KEV](#exploit-intelligence-kev--epss) vulnerability that isn't confirmed unreachable (whatever its severity), or any exposed High/Critical credential |
| Medium | Medium/unrated issues, vulnerabilities at or above the EPSS threshold, lower-severity secrets, or Critical/High/KEV issues that [reachability analysis](#reachability-analysis) confirmed are not used by production code |
| Low | only Low-severity issues (none at or above the EPSS threshold), or Medium/unrated issues that reachability analysis confirmed are all unused |
| Minimal | nothing found |
| Not assessed | the scan skipped vulnerability lookups (e.g. **UBEL: Scan project for License Compliance**) and nothing else raised the rating — shown instead of "Minimal" so an unchecked scan is never read as a clean one |

The rating and the policy verdict are independent: the rating discounts findings that reachability analysis confirmed are unused, while the verdict counts every finding at or above the blocking thresholds (and any exposed secret), so a report can be rated Medium yet still be blocked. Reachability is a heuristic; a finding with no reachability result is treated as potentially reachable.

**Exploit intelligence in the summary.** The summary uses the same two signals the policy blocks on, so a report is never rated "Low" while the policy blocks it for an actively exploited vulnerability:

- **Known-exploited (`is_kev: true`)** — gets its own key finding (with CISA's earliest remediation due date), an *Immediately* suggested action, the **Known to be exploited** card, and raises the rating to High unless reachability analysis confirmed the code unused (then Medium). Components with a known-exploited issue rank first among the non-malicious ones and carry an *Exploited* badge.
- **High EPSS** — vulnerabilities at or above `epss_threshold` that aren't already KEV get a key finding and, when they are lower-severity, a *Within days* action; they set a floor of Medium. If the EPSS rule is turned off in the policy, 10% is still used for this informational reporting, and the text says the policy doesn't block on it.
- **Unknown stays unknown** — if a feed was unreachable, the matching figures are `null` (shown as "n/a", never `0`), a key finding says so, the methodology shows the lookup as *incomplete*, and a Low/Medium rating notes that it could be understated.

**Checks that didn't run or didn't finish.** When vulnerability lookups were skipped, the vulnerability-derived figures (including the exploit-intelligence ones) are `null` (shown as "n/a" in the HTML tab), not `0`. When the secrets pass failed, `exposed_credentials` is `null` and a key finding says the result is unavailable instead of reporting zero. Components with no determinable version can't be matched against vulnerability databases, so they are called out in the methodology, limitations, and notes.

**Good to know**

- The rating scale is UBEL's own — not CVSS or a regulatory standard — and the impact text is general guidance per rating level.
- Action timeframes are built-in defaults, not your organization's remediation SLAs. The HTML tab labels the section "Suggested actions" for this reason.
- Suggested upgrades are indicative, not a guarantee.
- Malicious-component advisories are counted separately, so "Known weaknesses" can be lower than the Vulnerabilities tab total; a note says so when it applies.
- `scope.subject` identifies what was scanned: `name`, `repository`, `branch`, `commit` (first 8 characters), `scanned_at` and `tool`, taken from the report's git, runtime, and tool metadata. Fields that aren't available are omitted from the header.
- `overall_risk.basis` and `recommended_actions_basis` state that the rating scale is UBEL's own (not CVSS or a regulatory standard) and that action timeframes are built-in defaults rather than your organization's remediation policy.
- For host-platform scans, the project name is left empty rather than showing a temp or home directory. Credentials embedded in a git remote URL are stripped from the scan header.

**JSON**

```json
{
  "executive_summary": {
    "overall_risk": { "level": "high", "label": "High", "rationale": "...", "business_impact": "..." },
    "cover": { "title": "...", "subject": "my-app", "report_id": "...", "generated_at": "2026-10-06T09:30:00Z", "tool": "...", "classification": "...", "statement": "..." },
    "bottom_line": { "risk_label": "High", "summary": "...",
                     "top_risks": [ { "severity": "high", "title": "...", "detail": "..." } ],
                     "do_first": [ { "action": "...", "timeframe": "Immediately", "owner": "..." } ],
                     "figures": [ { "label": "...", "value": 9, "sub": "...", "tone": "high" } ] },
    "glance_cards": [ { "label": "...", "value": 142, "sub": "...", "tone": null } ],
    "headline": "This scan reviewed 142 software components and found ...",
    "verdict": { "status": "blocked", "label": "Does not meet security policy", "statement": "...", "technical_reason": "..." },
    "at_a_glance": { "vulnerabilities_assessed": true, "components_reviewed": 142, "components_with_issues": 4, "malicious_components": 0,
                     "total_vulnerabilities": 9, "by_severity": { "critical": 1, "high": 2, "medium": 4, "low": 2, "unknown": 0 },
                     "fix_available": 7, "fix_available_percent": 78, "likely_in_use": 6, "not_in_use": 3,
                     "blocking_policy": 3, "exposed_credentials": 2,
                     "known_exploited": 1, "high_exploit_likelihood": 2, "exploit_data_complete": true },
    "key_findings": [ { "severity": "high", "title": "...", "detail": "..." } ],
    "components_to_fix_first": [ { "name": "lodash", "version": "4.17.15", "issue_count": 3, "worst_severity": "critical",
                                   "worst_severity_label": "Critical", "likely_in_use": true, "blocks_policy": true, "known_exploited": 1, "max_epss": 0.42, "upgrade_to": "4.17.21",
                                   "fix_options": [ { "version": "4.17.21", "range": "4.17.x", "scope": "minor", "resolves": 3, "of": 3, "resolves_known_exploited": 1, "known_exploited_total": 1, "recommended": true } ], "fix_options_more": 0, "no_fix_yet": 0,
                                   "references": [ "GHSA-xxxx-xxxx-xxxx" ], "more_references": 2, "action": "Upgrade to version 4.17.21." } ],
    "recommended_actions": [ { "priority": 1, "timeframe": "Immediately", "owner": "...", "action": "...", "why": "..." } ],
    "compliance_overview": { "frameworks_touched": 3, "most_affected": [ { "framework": "...", "findings": 5 } ], "statement": "...", "disclaimer": "..." },
    "scope": { "scan_type": "health", "description": "...", "target": "a code repository", "subject": { "name": "my-app", "repository": "...", "branch": "main", "commit": "a1b2c3d4", "scanned_at": "...", "tool": "..." }, "ecosystems": ["npm"], "components_reviewed": 142 },
    "methodology": { "steps": [], "rating_rules": [], "prioritization": "...", "timeframes": "...", "limitations": [] },
    "notes": [ "..." ],
    "glossary": [ { "term": "Vulnerability", "meaning": "..." } ]
  }
}
```

**Methodology.** `executive_summary.methodology` (and the Methodology section of the HTML tab) describes how that specific report was produced. Steps are included only if the stage ran for that scan: the usage estimate needs reachability results, the exploit-intelligence lookup needs vulnerability lookups (and is labelled *incomplete* when a feed failed), the credential search needs secrets scanning on, license review appears on `health` scans, and compliance mapping needs a `compliance_summary`. The *Policy check* step prints the policy values actually in force, including the KEV and EPSS rules.

**Fix options.** The suggested upgrade for each component comes from the per-package analysis in [Recommended Package Fixes](#recommended-package-fixes): the closest upgrade path that resolves the most of that component's issues (a major version change is called out, and any issues it leaves open are stated). Every upgrade path is also listed as `fix_options` — closest release line first, at most five, the recommended one always kept — with the version, its range, whether it is a `major` change, how many of the component's issues it resolves (and how many of the known-exploited ones), plus `no_fix_yet` for issues no version fixes. The HTML tab shows them as a **Possible fixes** list with *Best* and *Major* badges. If the per-package analysis is missing or failed, the older per-issue heuristic is used instead. Either way, the suggested upgrade is indicative, not a guarantee.

---

## Recommended Package Fixes

For every package in the inventory, UBEL looks at **all** of its vulnerabilities and the fixed version of every affected range, then suggests which versions to upgrade to. Instead of a single "latest" version, suggestions are grouped **per version range**, so you can pick the least disruptive upgrade that still closes the most issues:

- **One group per minor range above your installed version** — e.g. `4.17.x`, `4.18.x` (same major version, so typically non-breaking)
- **Then one group per higher major range** — e.g. `5.x`, `6.x` (may be breaking)

Groups are listed closest-first: minor ranges, then major ranges, with the highest version first inside a range.

**How versions are picked.** Inside each range, UBEL picks the version that fixes the most still-open vulnerabilities (ties go to the highest version), then repeats until nothing more can be fixed in that range — so you get the fewest, highest versions that cover the most. A vulnerability can therefore appear in several ranges: each range is an **alternative upgrade path**, not a sequence of steps to apply together.

**Branch-aware matching.** A candidate version is only counted as a fix if it genuinely falls outside every affected range of that vulnerability — not merely because it is numerically higher than some fixed version. This matters for advisories fixed on several release branches (e.g. a fix backported to `4.17.21` while `4.18.0`–`4.18.2` stays affected). When an advisory carries no usable range data, UBEL falls back to "at or after a known fixed version". Git-commit ranges are ignored since they can't be compared to package versions. For NVD-sourced advisories, each branch's lower bound is kept alongside its fix version, so a fix on a lower branch (say `1.2.5` next to `1.3.2`) is recognized as a fix for that branch rather than looking still-affected.

**Unfixed vulnerabilities.** Anything with no fixed version above the one you have installed — or that no candidate version actually clears — is listed separately as `unfixed` rather than silently dropped, so you can see what an upgrade won't solve.

**In the HTML report**

Open the **Inventory** tab and click a package: its detail modal has a **Suggested Fixes** section.

- A table with one row per suggested version — **Range** (label plus *minor range* / *major range*), **Suggested version** (with "fixes N"), and **Vulnerabilities fixed**, each with its severity badge. Click any vulnerability to jump to its detail modal.
- Below it, **Vulnerabilities with no fix (N)** — ID, severity, and score for everything no suggested version resolves.
- Malicious (infection) entries are shown with an `infection` badge. If nothing can be fixed by upgrading, the modal says so; if the package has no suggestion data, it says that instead.

**Ordering.** Vulnerabilities inside every group are ordered most severe first: malicious (infection), then critical, high, medium, low, unknown; ties are broken by CVSS score, then ID.

**Ecosystem-aware version comparison.** Versions are compared with one ecosystem-agnostic comparator that handles semver, PEP 440, and deb/rpm-style versions — including epochs (`1:2.3`), `v` prefixes, pre-release tags (`1.0.0-rc1` sorts below `1.0.0`), and ignored build metadata (`+build`) — across every supported ecosystem.

**In SBOM and SARIF.** SBOM: each component has a `suggested_fixes` property (JSON string), and each vulnerability gets the properties `suggested_fix_version` and `suggested_fix_bulk_count` when a suggested version covers it. SARIF: each result has `suggested_fix_version` and `suggested_fixes` in `properties`, and the run's `properties.inventory_suggested_fixes` lists the plan per package.

Suggestions are computed only when vulnerability lookups ran, so they are absent from license-only scans.

**JSON**

Each inventory item in the JSON report carries a `suggested_fixes` object:

```json
{
  "suggested_fixes": {
    "fixes": [
      {
        "version": "4.17.21",
        "count": 3,
        "range": { "key": "m:4.17", "label": "4.17.x", "scope": "minor" },
        "vulnerabilities": [
          { "id": "GHSA-xxxx-xxxx-xxxx", "severity": "critical", "severity_score": 9.8, "is_infection": false }
        ]
      }
    ],
    "unfixed": [
      { "id": "CVE-0000-0000", "severity": "medium", "severity_score": 5.3, "is_infection": false }
    ]
  }
}
```

| Field | Meaning |
|---|---|
| `fixes[].version` | A suggested version to upgrade to |
| `fixes[].count` | How many of the package's vulnerabilities that version resolves |
| `fixes[].range` | The range the version belongs to: `scope` is `minor` (same major as installed) or `major` (higher major); `label` is e.g. `4.17.x` or `5.x` |
| `fixes[].vulnerabilities` | The vulnerabilities resolved, most severe first |
| `unfixed` | Vulnerabilities no suggested version resolves |

If suggestions can't be computed for a package, its `suggested_fixes` carries an `error` message with empty `fixes`/`unfixed`, and the rest of the report is unaffected. Suggestions are computed once per scan, right after vulnerabilities are matched, and before the executive summary is built.

---

## Exploit Intelligence (KEV & EPSS)

Severity says how bad a flaw *could* be; these two feeds say whether it is actually being exploited or is likely to be. Every vulnerability found by a scan that performs vulnerability lookups is enriched with:

| Field | Source | Meaning |
|---|---|---|
| `is_kev` | [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | `true` if the CVE is in the catalog, `false` if not, `null` if the catalog couldn't be fetched |
| `kev_added` | CISA KEV | Date the CVE was added to the catalog (`YYYY-MM-DD`), else `null` |
| `kev_deadline` | CISA KEV | CISA's remediation due date, else `null` |
| `epss_score` | [FIRST EPSS](https://api.first.org/data/v1/epss) | Probability (0–1) of exploitation in the next 30 days, else `null` |
| `epss_percentile` | FIRST EPSS | Percentile (0–1) of that score among all scored CVEs, else `null` |

`null` always means *unknown* (feed down, or no EPSS score exists for the CVE), never "not exploited" or `0`. The HTML report shows EPSS as percentages and flags KEV entries with a badge; the JSON report keeps the raw 0–1 values.

**CVE matching.** OSV advisories are frequently GHSA/other ids, so the CVE is taken from the vulnerability `id` if it starts with `CVE-`, and from its `aliases` otherwise. If an advisory maps to several CVEs, it is KEV if any of them is, and the highest EPSS score is reported.

**Policy.** With the defaults, a scan blocks on any KEV entry (`block_kev: true`) and on any vulnerability with `epss_score >= 0.1` (10%), whatever its severity. Both are tunable in `config.json` — see [Policy](#policy). The block reason names the offending ids, e.g. `Blocked by policy: 1 known-exploited (CISA KEV) vulnerability detected: GHSA-xxxx-xxxx-xxxx`.

**When a feed is unreachable.** Unlike OSV/NVD (where a failed lookup fails the scan, because a missing answer would look like "no vulnerabilities"), KEV/EPSS only *add* risk signal, so an outage degrades the result instead of aborting it:

- the scan completes and the affected fields are `null`;
- a warning is shown in the HTML decision box and recorded under `threat_intel` in the report (`status` of `ok`, `partial`, `unavailable` or `skipped` per feed, plus the error);
- the matching policy rule is not enforced for that run, and a passing verdict says so — e.g. `Policy passed (note: CISA KEV data unavailable — not enforced for this scan)`;
- other rules (severity, the other feed, infections, secrets) are unaffected.

Each feed is tried with a 15-second timeout and two retries. There is currently no endpoint override for either feed, so a fully air-gapped setup runs without KEV/EPSS data.

**Other report formats**

- **SBOM (CycloneDX v1.6)**: each `vulnerabilities[]` entry gets the properties `kev.listed` (`true`, `false` or `unknown`), `kev.date_added`, `kev.due_date`, `epss.score` and `epss.percentile`; KEV entries also get an advisory link to the CISA catalog, and EPSS is added as a second `ratings[]` entry (source `FIRST EPSS`, score in percent). The root `properties` carry `kev_vulnerabilities` and `ubel:threat_intel` — read the count together with the feed status, since an outage leaves the count at 0.
- **SARIF 2.1.0**: rules and results carry `is_kev`, `kev_added`, `kev_deadline`, `epss_score` and `epss_percentile` in `properties`; rules get the tags `kev` / `known-exploited` / `epss` where they apply. Each result gets a `rank` (0–100): 100 for a KEV entry, otherwise the EPSS probability ×100. A KEV result is reported at level `error` whatever its severity, unless reachability confidently ruled it out.

---

## Reachability Analysis

Every vulnerability in the report is annotated with a heuristic reachability assessment. The analyzer operates on the existing report fields — package type, scope, dependency depth, CVSS attack vector, and the dependency graph — and optionally performs a source-level import scan over the project files to confirm or refute whether the vulnerable package is actually used by application code. The host-platform scan has no project source, so it has no import-scan signal.

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

**Priority 2 (dev/test scope)** — Packages that are exclusively development or test dependencies are excluded from production runtimes. Scope is derived from `package.json` `devDependencies` (for Rust, from the `[dev-dependencies]` / `[build-dependencies]` sections of `Cargo.toml` and its workspace members) and propagated through the dependency graph via BFS.

**Priorities 3–4 (import scan)** — When a project root is provided, UBEL scans source files for import statements matching the package. For transitive dependencies where the package itself is not directly imported, it checks whether any of the package's parents in the dependency graph are imported — confirming that the transitive path is exercised.

**Priority 5 (orphan tool)** — Root packages with no dependents and no import scan result are most likely standalone CLI tools included in the environment but not called by application code.

**Priority 6 (heuristics)** — When no higher-priority signal is available, depth in the dependency tree and the CVSS attack vector are used as weak proxies. Network-reachable (`AV:N`) and shallow (`depth ≤ 1`) packages score higher.

### Import scan coverage

Source files are scanned for ecosystem-appropriate import patterns:

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
| Flutter / Dart | `.dart` | `import 'package:<pkg>/…'`, `export 'package:<pkg>/…'` |
| Swift | `.swift` `.m` `.mm` `.h` | `import <Module>`, `@import <Module>`, `#import <Module/…>` |

Reachability results appear in the **Vulnerabilities** tab of the HTML report and in the machine-readable JSON report. Each vulnerability record includes a `reachability` object:

```json
{
  "reachability": {
    "reachable": true,
    "level": "high",
    "confidence": "high",
    "rationale": "Import of this package was found in project source code. Found in 2 source file(s): src/index.js, src/utils.js. Depth=0, AV=N.",
    "tags": ["import_confirmed", "network_av"],
    "signals": {
      "depth": 0,
      "attack_vector": "N",
      "is_orphan_tool": false,
      "scope": "prod",
      "num_paths": 3,
      "introduced_by_count": 1,
      "pkg_type": "library",
      "is_non_library": false,
      "is_malware": false,
      "has_env_scope": false,
      "import_scan": {
        "searched": true,
        "found": true,
        "files_scanned": 87,
        "matched_files": ["src/index.js", "src/utils.js"],
        "skipped_no_source": false
      }
    }
  }
}
```

| Field | Description |
|---|---|
| `reachable` | `true` if the vulnerable code is considered reachable from production |
| `level` | `total`, `high`, `medium`, or `low` |
| `confidence` | `high`, `medium`, or `low` — how much evidence backs the verdict |
| `rationale` | Human-readable explanation of which signal drove the decision |
| `tags` | Machine-readable labels for the signals that fired (e.g. `import_confirmed`, `dev_scope`, `malware`, `env_scope`) |
| `signals` | Full signal snapshot — all inputs that were considered, regardless of which rule fired |

---

## License Compliance

Every project scan classifies each package's declared license by default. Licenses arrive in inconsistent shapes across ecosystems (SPDX ids, free text like `"Apache 2.0"`, npm's `UNLICENSED` proprietary sentinel, Python trove classifiers, `OR`/`AND` SPDX expressions, or missing entirely); UBEL normalizes all of them to a canonical SPDX identifier, checks it against the OSI-approved license list, and assigns a risk rating:

| Category | Examples | Risk |
|---|---|---|
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC, 0BSD | `low` |
| Public domain | Unlicense (OSI-approved), CC0-1.0 (not OSI-approved but permissive in practice) | `low` |
| Weak copyleft | MPL-2.0, LGPL-2.1/3.0, EPL-2.0, CDDL | `medium` |
| Strong copyleft with linking exception | GPL-2.0-only WITH Classpath-exception-2.0 (OpenJDK JRE/JDK) | `medium` |
| Strong copyleft | GPL-2.0/3.0, AGPL-3.0 | `high` |
| Source-available / rejected by OSI | SSPL-1.0, BUSL-1.1, Elastic-2.0 | `high` |
| Proprietary | npm `UNLICENSED`, `Proprietary`, `LicenseRef-*` vendor EULAs (Windows, Defender, Chrome, Docker Desktop, …) | `high` |
| None / unrecognized | missing, `unknown`, or unparseable text | `unknown` |

npm's `UNLICENSED` sentinel (proprietary — all rights reserved) is deliberately not confused with the SPDX `Unlicense` public-domain license; dual-licensed packages (`OR`) are classified using the most favorable option, since the consumer may legally choose it, while conjunctively-licensed packages (`AND`) are classified using the most restrictive one, since all obligations stack.

Other shapes that are normalized: case/whitespace variants, SPDX expressions (`GPL-2.0-or-later`, `GPL-2.0+`), `WITH` exception expressions (the Classpath exception permits linking without inheriting GPL's copyleft obligations, so it's capped at `medium`), `LicenseRef-*` identifiers (a real, named vendor license with no SPDX id — treated as proprietary-leaning rather than "unrecognized"), legacy npm object/array forms, and Python trove classifiers (`License :: OSI Approved :: MIT License` → `MIT`). `SEE LICENSE IN <file>` is flagged as unverifiable rather than guessed at, and missing/empty/`unknown` values are classified as `none`. `osi_approved` is `true` only for licenses on the OSI-approved list, `false` for a real license that isn't on it (proprietary, source-available, Creative Commons), and `null` when there's nothing to check.

Run standalone via **UBEL: Scan project for License Compliance** (`Ctrl+Alt+L`) — see above — when you want license data only, with no vulnerability lookups or secrets scan.

**Output fields.** Each inventory item gets a `license_info` object:

```json
{
  "license": "UNLICENSED",
  "license_info": {
    "raw": "UNLICENSED",
    "spdx": null,
    "identifiers": [],
    "osi_approved": false,
    "risk": "high",
    "category": "proprietary",
    "reason": "npm \"UNLICENSED\" marker — explicitly no license grant (all rights reserved). Not to be confused with the SPDX \"Unlicense\" public-domain license."
  }
}
```

The top-level `stats.license_stats` field summarizes the whole inventory:

```json
{
  "total": 142,
  "osi_approved": 118,
  "not_osi_approved": 9,
  "unknown": 15,
  "by_risk": { "low": 112, "medium": 6, "high": 9, "unknown": 15 }
}
```

- **HTML report**: the **Inventory** tab and the per-package detail modal render `license_info` as a risk-badged license table (SPDX id, identifiers, OSI-approved, risk, category, reason) rather than a bare string, and the Dashboard carries a license-risk stats card.

- **SBOM (CycloneDX v1.6)**: `components[].licenses` uses the normalized SPDX `expression` form when a usable identifier was found, falling back to free-text `license.name`; OSI status, risk, category, and reason are added as component `properties`, and the root `properties` carry the OSI/unknown counts.
- **SARIF 2.1.0**: a dedicated `ubel-license-compliance` run, separate from the vulnerability and secrets runs. Only packages that need review are reported — any package with `risk: "high"`, or `osi_approved` not equal to `true` — so a fully permissively-licensed tree produces no findings. Result `level` maps from risk (`high` → `error`, `medium` → `warning`, `low` → `note`).

---

## Compliance Framework Mapping

Every dependency vulnerability and secrets-in-source finding is mapped onto industry compliance/security frameworks by default — no separate flag or mode needed, and included in every report format. This is distinct from [License Compliance](#license-compliance) above, which is about license-obligation risk on installed software; this is about mapping *security* findings onto the frameworks an org is typically audited against.

Each finding is first assigned one or more internal risk categories — for a dependency vulnerability, derived from its advisory's CWE(s); for a secrets finding, always `secrets_management` (e.g. `injection`, `secrets_management`, `vulnerable_components` — the latter always applied to a dependency finding as a baseline, since every SCA finding is a known-vulnerable-component finding by definition), and each category carries a fixed list of framework control references, so two findings with the same underlying risk always map identically.

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

**Output fields.** Each vulnerability and secrets finding gets a `compliance` object:

```json
{
  "compliance": {
    "categories": ["vulnerable_components", "injection"],
    "frameworks": [
      {
        "id": "owasp_top10_2021",
        "name": "OWASP Top 10 (2021)",
        "controls": [
          { "id": "A06:2021", "title": "Vulnerable and Outdated Components" },
          { "id": "A03:2021", "title": "Injection" }
        ]
      }
    ]
  }
}
```

The top-level `compliance_summary` field aggregates every vulnerability and secrets finding in the report into per-framework, per-control finding counts:

```json
{
  "disclaimer": "Compliance framework references are best-effort guidance ...",
  "frameworks": [
    {
      "id": "owasp_top10_2021",
      "name": "OWASP Top 10 (2021)",
      "findings_count": 14,
      "controls": [
        { "id": "A06:2021", "title": "Vulnerable and Outdated Components", "findings_count": 11 },
        { "id": "A03:2021", "title": "Injection", "findings_count": 3 }
      ]
    }
  ],
  "by_category": { "vulnerable_components": 11, "injection": 3, "secrets_management": 2 }
}
```

**Output**

- **HTML report**: a dedicated **Compliance** tab with one card per framework (control breakdown + finding counts), plus a Compliance Frameworks section in each vulnerability's detail modal.
- **JSON report**: a `compliance` object on every vulnerability and secrets finding, plus a report-level `compliance_summary` aggregating all findings into per-framework, per-control counts.
- **SARIF report**: `compliance_categories` / `compliance_frameworks` on each rule, and the full `compliance` object on each result — in both the dependency-vulnerability run and the secrets run.

---

## Policy

All ecosystems share the same policy engine. Policy is stored as JSON at `.ubel/local/policy/config.json`, relative to the scan root — `<project-root>` for project, secrets, and license scans, the editor's extensions directory for the extensions scan, and `~` for the host-platform scan. The file is created with defaults on the first scan.

The extension has no `threshold` / `block-unknown` / per-run-flag commands (those belong to the CLI) — to change policy, edit `config.json` directly. Default policy:

```json
{
  "severity_threshold": "high",
  "block_unknown_vulnerabilities": true,
  "license_risk_threshold": "none",
  "block_unknown_license_risk": false,
  "block_kev": true,
  "epss_threshold": 0.1
}
```

| Field | Values | Default | Behaviour |
|---|---|---|---|
| `severity_threshold` | `low` `medium` `high` `critical` `none` | `high` | Block packages at or above this severity |
| `block_unknown_vulnerabilities` | `true` `false` | `true` | Block packages with CVEs but no CVSS score |
| `license_risk_threshold` | `none` `low` `medium` `high` | `none` | Block packages whose license risk is at or above this level; never blocks on `unknown` regardless of setting (see `block_unknown_license_risk`) |
| `block_unknown_license_risk` | `true` `false` | `false` | Separately block packages whose license couldn't be classified at all |
| `block_kev` | `true` `false` | `true` | Block any vulnerability listed in the CISA KEV catalog, regardless of severity |
| `epss_threshold` | fraction in (0, 1], or `"none"` | `0.1` | Block any vulnerability whose EPSS score is at or above this value (`0.1` = 10%), regardless of severity |
| Infections (`MAL-*`) | — | always blocked | Cannot be toggled; unconditionally blocked |

The severity threshold is inclusive — `high` blocks both `high` and `critical`. KEV and EPSS blocking apply on top of it: a Low-severity vulnerability that is known to be exploited, or whose EPSS score is at or above the threshold, still blocks. Both rules need data from an external feed; if it couldn't be fetched, that rule can't fire for the run (see [Exploit Intelligence](#exploit-intelligence-kev--epss)), and a passing verdict says so. Policy files created before these fields existed pick up the defaults automatically. Setting `none` disables severity blocking but infections are still blocked. `license_risk_threshold`/`block_unknown_license_risk` are opt-in (both default off) since license-risk tolerance varies by org and license detection has real gaps (free-text licenses, missing metadata); every extension scan runs in `health` mode, where these two gates are active.

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
| Developer tools | Git, Docker Desktop, Visual Studio, VS Code, Cursor, Claude Code |
| Shell | PowerShell |

### Linux

Detected by reading the system package database directly.

| Distribution | Package manager | Source | PURL type |
|---|---|---|---|
| Ubuntu | dpkg | `/var/lib/dpkg/status` | `pkg:deb/ubuntu/` |
| Debian | dpkg | `/var/lib/dpkg/status` | `pkg:deb/debian/` |
| Alpine | apk | `/lib/apk/db/installed` | `pkg:apk/alpine/` |
| Alpaquita | apk | `/lib/apk/db/installed` | `pkg:apk/alpaquita/` |
| Red Hat / RHEL | rpm | `rpm -qa` | `pkg:rpm/redhat/` |
| AlmaLinux | rpm | `rpm -qa` | `pkg:rpm/almalinux/` |
| Rocky Linux | rpm | `rpm -qa` | `pkg:rpm/rocky-linux/` |
| CentOS / Fedora | rpm | `rpm -qa` | `pkg:rpm/redhat/` |

Each package entry includes its binary install paths and direct dependency edges as reported by the package database.

> On RPM-based systems, `rpm -qa` may return partial results depending on SELinux policy if run without elevated privileges.

---

## Supported Ecosystems (Project Scan)

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| **Node.js** | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| **Python** | pip / virtualenv | `.venv`, `venv`, virtual environment directories |
| **PHP** | Composer | `vendor/`, `composer.lock` |
| **Rust** | Cargo | `Cargo.lock` |
| **Go** | Go Modules | `go.sum` |
| **C#/.NET** | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| **Java/Kotlin** | Maven | `pom.xml` resolved dependencies |
| **Ruby** | Bundler | `Gemfile.lock` |
| **Swift** | SwiftPM, Carthage | `Package.resolved` / `.build/workspace-state.json` / `Cartfile.resolved` |
| **Flutter/Dart** | pub | `pubspec.lock` / `.dart_tool/package_config.json` |

**Swift and Flutter/Dart notes.** PURLs are `pkg:swift/<host>/<owner>/<repo>@<version>` (OSV ecosystem `SwiftURL`) and `pkg:pub/<name>@<version>`, with `?repository_url=` / `?vcs_url=` qualifiers on pub packages from a non-pub.dev registry or a git repository. Local packages (SwiftPM `fileSystem` / `localSourceControl`, pub `path`) and pub `sdk` packages are skipped, and CocoaPods (`Podfile.lock`) is intentionally not scanned because OSV has no CocoaPods ecosystem. A SwiftPM pin on a branch or bare commit is inventoried with an empty version and dropped from vulnerability lookups. Swift lockfiles carry no dev/prod signal, so every Swift package is `prod`; for pub, `direct dev` → `dev` and everything else → `prod`. Neither lockfile records a dependency graph or license data, so these packages have no introduced-by/parent edges and their license is `unknown`.

---

## Reports

Every scan writes a self-contained interactive **HTML** report plus machine-readable **JSON**, **SBOM**, and **SARIF** files:

| File | Format | Notes |
|---|---|---|
| `latest.html` | Self-contained HTML | Works fully offline, no server needed |
| `latest.json` | JSON | Full report, including the executive summary, suggested fixes, reachability, KEV/EPSS, and compliance data |
| `latest.cdx.json` | CycloneDX v1.6 SBOM | Components, dependency graph, and vulnerabilities as VEX; secrets, license, KEV/EPSS, and suggested-fix data in `properties` |
| `latest.sarif.json` | SARIF 2.1.0 | Separate runs for dependency vulnerabilities, secrets, and license compliance |

| Scan target | Report path |
|---|---|
| Workspace | `<project-root>/.ubel/reports/latest*` |
| Secrets-only scan | `<project-root>/.ubel/reports/latest*` — same path as Workspace, see the note in [Scan for Exposed Secrets](#scan-for-exposed-secrets-ctrlalts) |
| License-only scan | `<project-root>/.ubel/reports/latest*` — same path as Workspace, see the note in [Scan for License Compliance](#scan-for-license-compliance-ctrlaltl) |
| VS Code / VS Codium / Cursor extensions | `~/.vscode/extensions/.ubel/reports/latest*` or `~/.vscode-oss/extensions/.ubel/reports/latest*` or `~/.cursor/extensions/.ubel/reports/latest*` |
| Host platform | `~/.ubel/reports/latest*` |

Previous scans are retained as timestamped zipped snapshots (`<ecosystem>_<mode>_<engine>__<timestamp>.zip`) under:

- `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode-oss/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.cursor/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

---

## Extension vs. CLI

The extension runs the same engine as the CLI's `health` mode. These parts of the [`@arcane-spark/ubel-node`](https://github.com/AlaBouali/ubel/blob/main/sca/README.md) package are **not** in the extension:

- The install-time firewall (`check` / `install` modes) for npm, pnpm, bun, composer, pip, uv, pipx, conda, cargo, apt, dnf, and yum, including lockfile backup/revert and TOCTOU integrity protection (always with install scripts blocked)
- `ubel-docker` container-image scanning
- Fixed-configuration CLIs for AI-agent sandboxes and CI/CD (`ubel-agent`, `ubel-cicd`)
- The git pre-commit hook (`install-hook` / `uninstall-hook`) and the `ubel-secrets` extras: git-history scanning (`--history`), staged-changes scanning (`--staged`), and baselining (`--write-baseline`) — the extension scans the working tree only
- Persistent policy modes and per-run policy flags (`--threshold`, `--block-kev`, `--epss-threshold`, …) — in the extension, edit `config.json` instead
- The GitHub Action

---

## Requirements

- Node.js `>=18.0.0`
- VS Code `^1.85.0` (extension only)
- Network access to osv.dev and the NVD API (or your configured mirrors) for vulnerability lookups; KEV/EPSS lookups are best-effort

---

## Privacy

UBEL is fully local. The external calls it makes are:

| Service | Purpose | Failure behavior |
|---|---|---|
| [osv.dev](https://osv.dev/) public API | Vulnerability lookups — receives package PURLs (package name + version) | Scan fails with an error |
| [NVD API](https://nvd.nist.gov/) | Host-platform CPE lookups and advisory enrichment | Scan fails with an error |
| [CISA KEV catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (`www.cisa.gov`) | Known-exploited flag | Best-effort — scan completes, KEV fields are `null` |
| [FIRST EPSS API](https://www.first.org/epss/) (`api.first.org`) | Exploit-likelihood score, queried by CVE id | Best-effort — scan completes, EPSS fields are `null` |

No file contents, no dependency graphs, no machine identifiers, and no telemetry are sent anywhere. UBEL does not look up your public IP address; the local network interfaces recorded in reports are used only inside the report and never leave the machine. Secrets findings never leave the machine at all — match previews shown in reports are redacted before being written to disk. If an OSV or NVD lookup can't be completed, the scan ends with an error message rather than reporting a clean result.

The OSV and NVD endpoints can be redirected to an internal mirror by setting `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` in the environment the editor was launched from (e.g. via VS Code's own `terminal.integrated.env.*` settings, or the OS environment) — useful for air-gapped or regulated environments where those calls need to stay on an internal network. A mirror must expose the same path shape as the public API, and the "view online" reference links in reports still point at the public sites. There is currently no endpoint override for KEV/EPSS: in a fully air-gapped setup the scan runs without that data and says so. See [sca/README.md](https://github.com/AlaBouali/ubel/blob/main/sca/README.md#environment-variables) for details; this extension reads the same engine, so the same variables apply.

---

## License

Source-available, **internal use only**: you may use UBEL on your own projects and systems and within your own organization. Redistribution, wrapping, and offering it as a service to others are not permitted.  
See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for the full terms, or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) to discuss licensing beyond internal use.