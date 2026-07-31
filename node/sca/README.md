# UBEL — Unified Bill / Enforced Law
### Node.js Supply-Chain Security CLI

Ubel resolves dependencies, generates PURLs, scans them through [OSV.dev](https://osv.dev) and [NVD](https://nvd.nist.gov/), and enforces configurable security policies at install-time to block supply-chain attacks before they reach production.

This document covers the **Node.js** ecosystem (npm, pnpm, bun, yarn).
scan_project
---

## Features

- Full dependency resolution with PURL generation via lockfile dry-run
- Querying authoritative vulnerability sources in real time, allowing newly published advisories to be detected immediately without waiting for scheduled database refreshes unlike the competitors.
- OSV.dev vulnerability scanning via batched API queries and NVD's APIs
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- Policy engine — block/allow by severity threshold and unknown-severity packages
- Malicious package (infection) detection — always blocked regardless of policy
- `check` mode — dry-run resolution and scan with no side effects
- `install` mode — scan-gate before installation; blocks if policy violated
- `health` mode — scan the current project's installed dependencies
- Atomic lockfile revert — originals are always restored on violation or error
- Disk-based lockfile backup under `.ubel/lockfiles/<timestamp>/` with manual recovery on failure
- Dependency graph with introduced-by and parent tracking
- Automatic report generation: timestamped **JSON** (`*.json`) + **HTML** (`*.html`) + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links
- Zero external runtime dependencies (Node.js stdlib only)
- Complete compliant, and enriched SBOM Cyclonedx v1.6 files with full dependencies and vulnerabilities data in VEX
- Complete compliant, and enriched SARIF v2.1.0 files
- **Reachability analysis** — each vulnerability is annotated with a heuristic reachability assessment derived from package type, scope, dependency depth, attack vector, and import-scan confirmation across all supported ecosystems (see [Reachability Analysis](#reachability-analysis))
- **Secrets detection** — Trivy's ported ruleset plus UBEL's own rules for vendors Trivy's current upstream doesn't cover (see [Secrets Detection](#secrets-detection)), included in every scan by default and runnable standalone via `ubel-secrets`
- **License compliance** — every package's declared license is normalized (SPDX expressions, free text, npm's `UNLICENSED` proprietary marker vs. the SPDX `Unlicense` public-domain license, missing/`unknown` values) and checked against the OSI-approved license list, with a derived risk rating; included in every scan by default (see [License Compliance](#license-compliance))

---

## Installation

```bash
npm install -g @arcane-spark/ubel-node
```

After installation, the following entry-point binaries are available:

| Binary | Package Manager |
|---|---|
| `ubel-npm` | npm |
| `ubel-pnpm` | pnpm |
| `ubel-bun` | bun |
| `ubel-agent` | AI agent workspace scan ( OS, runtimes, tools, dependencies ) |
| `ubel-cicd` | post-build scan ( OS, runtimes, tools, dependencies ) |
| `ubel-platform` | Host platform scan (OS, runtimes, tools) |
| `ubel-docker` | scan a given docker image's OS and dependencies |
| `ubel-secrets` | standalone secrets-only scan of a directory |


> **yarn** does not support a lockfile-only dry-run — `yarn add` always writes `node_modules`. UBEL supports yarn in `health` scan mode only and cannot provide install-blocking firewall coverage for it.

---

## Requirements

- Node.js `>=18.0.0`
- The package manager binary being targeted (`npm`, `pnpm`, or `bun`) must be available on `PATH`

---

## Environment Variables

| Variable | Default | Effect |
|---|---|---|
| `UBEL_OSV_ENDPOINT` | `https://api.osv.dev` | Overrides the OSV API base used for live vulnerability queries. `/v1/querybatch` and `/v1/vulns/{id}` are appended to whatever base is set, so a mirror must expose the same path shape as the public API. A trailing slash is stripped automatically. |
| `UBEL_NVD_ENDPOINT` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Overrides the NVD CVE API endpoint used for host/platform CPE lookups (`?cpeName=...` is appended as a query string). A trailing slash is stripped automatically. |

Both are intended for self-hosted or air-gapped deployments — e.g. an internal proxy in front of a local OSV data dump, or a cached/rate-limit-friendly NVD mirror — where UBEL should never reach the public internet to do a live scan. Neither variable changes the "view online" reference links (`osv.dev/vulnerability/{id}`, `nvd.nist.gov/vuln/detail/{id}`) shown per-finding in reports — those stay pointed at the public sites by default, since a private mirror generally doesn't serve an equivalent browsable web UI at the same path. If your mirror does, you can still open the report and follow the link manually; it just isn't rewritten automatically.

```bash
# Point live queries at internal mirrors instead of the public APIs
export UBEL_OSV_ENDPOINT="https://osv-mirror.internal.example.com"
export UBEL_NVD_ENDPOINT="https://nvd-mirror.internal.example.com/rest/json/cves/2.0"

ubel-npm health
```

---

## Usage

```
ubel-npm   <mode> [packages...]
ubel-pnpm  <mode> [packages...]
ubel-bun   <mode> [packages...]
```

Package arguments are optional for `check` and `install` — when omitted, the existing lockfile in the working directory is used as the dependency source.

---

## Firewall Mechanics

### npm

`ubel-npm check` and `ubel-npm install <pkg>` invoke npm's `--package-lock-only` flag, which resolves the full dependency tree and writes a candidate `package-lock.json` without touching `node_modules/`. UBEL scans the candidate lockfile, then makes a binary decision:

- **Clean** — the candidate lockfile is accepted and the actual install proceeds via `npm ci`.
- **Violation** — `package-lock.json` is reverted to its pre-scan state from the disk backup. `node_modules/` is never touched. The process exits non-zero.

### pnpm

Identical flow to npm, using pnpm's `--lockfile-only` flag. The candidate `pnpm-lock.yaml` is written, scanned, then either accepted or reverted. `node_modules/` is never written during the scan phase.

### bun

Uses bun's `--lockfile-only` flag. The candidate `bun.lock` is written and scanned before any `node_modules/` mutation. The revert path is identical to npm and pnpm.

### docker

`ubel-docker` scans a container image **without ever running it** – it creates a stopped container (`docker create`), exports its filesystem, and extracts the tar in‑process (no shell `tar`). This blocks path‑traversal attacks and never executes `ENTRYPOINT`/`CMD` or any scripts. The scan automatically includes OS packages (`scan_os: true`) and all application dependencies (`full_stack: true`). 
Modes: 
- `health` (scan only)
- `check` (scan + always remove the image)
- `install` (scan + remove only on policy violation). Also supports scanning a local `.tar` file directly (skip pull/export).

### UBEL's firewall always blocks pre/post install scripts to prevent running malicious scripts

All the 3 package manager are triggered with the flag: `--ignore-scripts`

### Lockfile backup and recovery

Before any dry-run mutation, originals are backed up to `.ubel/lockfiles/<timestamp>/`. If the revert itself fails (e.g. a disk error mid-restore), the original lockfile is preserved at the backup path and its location is printed to stderr so the user can recover manually.

### TOCTOU integrity protection

After the dry-run completes and the scan passes policy, there is a window between the scan decision and the real install during which the on-disk lockfile or `package.json` could be mutated — by another process, a racing script, or a compromised tool. UBEL closes this window with SHA-256 integrity checks before any real install is allowed to proceed.

At the end of every dry-run, UBEL captures two digests in memory:

- **`_candidateLockfileHash`** — SHA-256 of the raw candidate lockfile bytes written to disk by the dry-run (`package-lock.json`, `pnpm-lock.yaml`, or `bun.lock`).
- **`_candidatePackageJsonHash`** — SHA-256 of `package.json` as it exists on disk after the dry-run. For npm, this digest is re-captured after UBEL regenerates `package.json` with exact pinned versions from the lockfile, so the hash always reflects the file that will be present at install time.

Immediately before invoking the real install command (`npm ci`, `pnpm install --frozen-lockfile`, `bun install --frozen-lockfile`), both files are re-hashed from disk and compared against the in-memory digests. If either hash does not match, the install is aborted and the lockfile is reverted — nothing is written to `node_modules/`. The mismatch details (expected hash, actual hash, file path) are printed to stderr.

```
Lockfile integrity check FAILED — the lockfile was modified after scanning.
  Expected : a3f1…
  Got      : 9c2b…
  File     : /project/package-lock.json
```

If no lockfile existed before the dry-run (fresh project), the absence itself is recorded as the expected state and enforced the same way.

This protection also extends to the backup manifest files created earlier before reverting the changes.

---

## Modes

### `health`

Scans the current project's installed dependency graph without running any install. Reads the existing lockfile directly and submits resolved packages to OSV.dev and NVD's APIs (or your configured mirrors — see [Environment Variables](#environment-variables)).

```bash
ubel-npm health
ubel-pnpm health
ubel-bun health
```

#### Full-stack monorepo scanning

When invoked programmatically with `full_stack: true`, `health` walks the entire directory tree from the project root and collects packages across all supported ecosystems in a single pass — no per-language configuration required. Mixed-stack monorepos (e.g. a Node.js frontend, Python backend, Rust service, and Go tooling in the same repo) are fully covered in one invocation.

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| Node.js | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| Python | pip / virtualenv | `.venv`, `venv`, virtualenv directories |
| PHP | Composer | `vendor/` |
| Rust | Cargo | `Cargo.lock` |
| Go | Go Modules | `go.sum` |
| C# / .NET | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| Java | Maven | `pom.xml` resolved dependencies |
| Ruby | Bundler | `Gemfile.lock` |

Each discovered package is deduplicated by PURL before submission, so packages shared across sub-projects are scanned exactly once.

#### Platform scanning (Linux)

When invoked with `scan_os: true` on Linux, the scanner reads the host's system package database directly — no elevated privileges required — and includes all installed system packages in the scan inventory.

| Distribution | Package Manager | Source | PURL type |
|---|---|---|---|
| Ubuntu | dpkg | `/var/lib/dpkg/status` | `pkg:deb/ubuntu/` |
| Debian | dpkg | `/var/lib/dpkg/status` | `pkg:deb/debian/` |
| Alpine / Alpaquita | apk | `/lib/apk/db/installed` | `pkg:apk/alpine/` |
| Red Hat / RHEL | rpm | `rpm -qa` | `pkg:rpm/redhat/` |
| AlmaLinux | rpm | `rpm -qa` | `pkg:rpm/almalinux/` |
| Rocky Linux | rpm | `rpm -qa` | `pkg:rpm/rocky-linux/` |
| CentOS / Fedora | rpm | `rpm -qa` | `pkg:rpm/redhat/` |

Each package entry includes its binary install paths and direct dependency edges as reported by the package database.

#### Platform scanning (Windows)

When invoked with `scan_os: true` on Windows, the scanner probes the registry and known binary paths — no elevated privileges required — and enumerates the following software components using CPE 2.3 identifiers:

| Category | Components |
|---|---|
| Operating system | Windows 10 / 11 (build-accurate CPE version) |
| Security | Windows Defender |
| Runtimes | Node.js, Python, PHP, Go, Rust, Ruby, JRE, JDK |
| .NET | All installed .NET Core / Desktop / ASP.NET runtimes (multi-version) |
| Browsers | Chrome, Firefox, Microsoft Edge |
| Developer tools | Git, Docker Desktop, Visual Studio, Cursor, Claude Code |
| Shell | PowerShell |

---

### `check`

Dry-run: resolves the given packages (or the existing lockfile) via a lockfile-only pass, scans the resolved set, and exits. Nothing is installed and lockfiles are fully reverted to their original state afterwards.

```bash
# Scan specific packages without installing
ubel-npm check lodash express

# Scan the current lockfile with no changes
ubel-npm check
```

Exits `0` if policy passes, `1` if policy blocks or the scan fails.

---

### `install`

Same pipeline as `check`, but proceeds to install (via `npm ci` / `pnpm install --frozen-lockfile` / `bun install`) if and only if the policy decision is **allow**.

```bash
ubel-npm install lodash@4.17.21 express
ubel-npm install                          # resolves from existing lockfile

ubel-pnpm install react react-dom
ubel-bun install
```

If the policy blocks, installation is aborted, the lockfile is reverted, and the process exits `1`.

---

### `threshold`

Sets the severity level at or above which vulnerabilities block the scan. Accepts `low`, `medium`, `high`, `critical`, or `none` (disable threshold blocking).

```bash
ubel-npm threshold high       # block high and critical
ubel-npm threshold critical   # block critical only
ubel-npm threshold none       # disable severity blocking
```

Infections (`MAL-*` advisories) are always blocked regardless of this setting.

The threshold is persisted to the local policy file and applies to all subsequent scans until changed.

---

### `block-unknown`

Controls whether packages with unknown-severity vulnerabilities are blocked.

```bash
ubel-npm block-unknown true
ubel-npm block-unknown false
```

---

## Policy

Policy is stored as JSON at `.ubel/local/policy/config.json` relative to the project root.

Default policy created on first run:

```json
{
    "severity_threshold": "high",
    "block_unknown_vulnerabilities": true
}
```

**Severity threshold** — vulnerabilities at or above this level cause a block. Severity order: `low → medium → high → critical`.

**Block unknown** — when `true`, any vulnerability whose severity cannot be determined also causes a block.

**Infections** — advisories with IDs beginning `MAL-` are always blocked and are not subject to either setting above.

---

## Reachability Analysis

Every vulnerability in the report is annotated with a heuristic reachability assessment. The analyzer operates on the existing report fields — package type, scope, dependency depth, CVSS attack vector, and the dependency graph — and optionally performs a source-level import scan over the project files to confirm or refute whether the vulnerable package is actually used by application code.

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

**Priority 2 (dev/test scope)** — Packages that are exclusively development or test dependencies are excluded from production runtimes. Scope is derived from `package.json` `devDependencies` and propagated through the dependency graph via BFS.

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

### Output fields

Each vulnerability record in the enriched report includes a `reachability` object:

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
| `confidence` | `high`, `medium`, or `low` — reflects how much evidence backs the verdict |
| `rationale` | Human-readable explanation of which signal drove the decision |
| `tags` | Machine-readable labels identifying which signals fired (e.g. `import_confirmed`, `dev_scope`, `malware`, `env_scope`) |
| `signals` | Full signal snapshot — all inputs that were considered, regardless of which rule fired |

---

## Secrets Detection

Every scan includes a secrets pass by default (`scan_secrets: true`), and it's also reachable standalone via `ubel-secrets`, which runs a secrets-only pass with no dependency resolution and no LLM calls:

```bash
ubel-secrets /path/to/project
```

### Ruleset

The builtin ruleset (`sca/vendor/trivy/rules.js`, `sca/vendor/trivy/allow-rules.js`) is ported from [Trivy's](https://github.com/aquasecurity/trivy) built-in secret scanner (`pkg/fanal/secret/builtin-rules.go`), Apache-2.0, with full attribution in [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/NOTICE) and [`LICENSE`](https://github.com/AlaBouali/ubel/blob/main/node/sca/vendor/trivy/LICENSE). It's kept in sync with Trivy's own upstream additions.

On top of the ported set, `sca/secrets.js` defines an `extraRules` array covering credential types not present in Trivy's current builtin rules, including:

- HashiCorp Vault tokens (`hvs.` prefix)
- Google Cloud API keys (`AIza…`) and OAuth access tokens (`ya29.`)
- Anthropic and OpenRouter API keys
- Firebase server tokens
- Amazon MWS auth tokens
- Square OAuth secrets and access tokens, Braintree access tokens
- Stripe restricted keys (`rk_live_` / `rk_test_`) — Trivy covers publishable/secret keys but not this format
- Twilio Account SIDs and App SIDs (Trivy covers the API-key format only)
- Credentials embedded in a git remote URL (`https://user:token@host/...`) — a different injection vector from the token-format-specific rules above
- Generic high-entropy and key-value fallback rules for unknown vendors

### Output

- **HTML report**: a dedicated Secrets tab (category, severity, file/line, redacted match preview — the raw secret value is never written to any report or log).
- **SBOM (CycloneDX v1.6)**: exposed as a `ubel:secrets` entry in the root `properties` array, as a JSON-string value. Not a top-level `x-`-prefixed key — CycloneDX's root schema sets `additionalProperties: false`, so a custom root key would fail strict schema validation; the `properties` array is the schema's actual documented extension point.
- **SARIF 2.1.0**: its own `run`, with a dedicated `tool.driver` and rule set, kept separate from the dependency-vulnerability run.

---

## License Compliance

Every scan classifies each inventory item's declared license by default — no separate flag, no separate command. The classification is purely additive: the raw `license` field reported by the package manager is left untouched, and a `license_info` object is added alongside it.

### Normalization

Licenses arrive in wildly inconsistent shapes across ecosystems, and all of the following are normalized to the same canonical SPDX identifier before classification:

- Case and whitespace variants — `mit`, `MIT`, `Mit` → `MIT`
- Free text — `"Apache 2.0"`, `"apache2"`, `"Apache License 2.0"` → `Apache-2.0`
- SPDX boolean expressions — `(MIT OR Apache-2.0)`, `GPL-2.0-or-later`, `GPL-2.0+`
- Legacy npm object/array forms — `{ type: "ISC", url: "..." }`, `[{type:"MIT"}, {type:"Apache-2.0"}]`
- Python trove classifiers — `"License :: OSI Approved :: MIT License"` → `MIT`
- npm's `"UNLICENSED"` sentinel — a *proprietary* marker (all rights reserved), deliberately not confused with the SPDX `Unlicense` public-domain license
- `"SEE LICENSE IN <file>"` — flagged as unverifiable rather than guessed at
- Missing, empty, `null`, or `"unknown"` values — classified as `none` rather than silently dropped

Dual/multi-licensed packages (`OR`) are classified using the most favorable component, since the consumer may legally choose it; conjunctively-licensed packages (`AND`) are classified using the most restrictive component, since all obligations stack.

### Risk classification

Each normalized license is checked against a curated OSI-approved license table and assigned a category and risk level:

| Category | Examples | Risk |
|---|---|---|
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC, 0BSD | `low` |
| Public domain | Unlicense (OSI-approved), CC0-1.0 (not OSI-approved but permissive in practice) | `low` |
| Weak copyleft | MPL-2.0, LGPL-2.1/3.0, EPL-2.0, CDDL | `medium` |
| Strong copyleft | GPL-2.0/3.0, AGPL-3.0 | `high` |
| Source-available / rejected by OSI | SSPL-1.0, BUSL-1.1, Elastic-2.0 | `high` |
| Proprietary | npm `UNLICENSED`, `"Proprietary"` | `high` |
| None / unrecognized | missing, `unknown`, or unparseable text | `unknown` |

`osi_approved` is `true` only for licenses on the [OSI-approved list](https://opensource.org/licenses); `false` for a real, identifiable license that isn't on it (proprietary, source-available, or non-software licenses like Creative Commons); `null` when there's nothing to check (missing license, or text that couldn't be parsed).

### Output fields

Each inventory item gets a `license_info` object:

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

### Output

- **HTML report**: the inventory table and per-package detail modal render `license_info` as a risk-badged license table (SPDX id, identifiers, OSI-approved, risk, category, reason) rather than a bare string.
- **SBOM (CycloneDX v1.6)**: `components[].licenses` uses the normalized SPDX `expression` form when a usable identifier was found, falling back to free-text `license.name` otherwise; `license.osi_approved` / `license.risk` / `license.category` / `license.reason` are added as component `properties`. Root-level `properties` include `license_osi_approved` / `license_not_osi_approved` / `license_unknown` counts.
- **SARIF 2.1.0**: a dedicated `ubel-license-compliance` run, separate from both the dependency-vulnerability run and the secrets run. Only packages that need review are reported — any package with `risk: "high"`, or `osi_approved` not equal to `true` (i.e. `false` or `null`) — so a fully permissively-licensed tree produces no findings. Rules are deduplicated per license classification (one rule per distinct SPDX id / category combination); result `level` maps from risk (`high` → `error`, `medium` → `warning`, `low` → `note`).

---

## Package Argument Validation

All package specifiers passed to `check` and `install` are validated against an allow-list pattern before any subprocess is invoked. Accepted formats:

```
name
name@version
@scope/name
@scope/name@version
```

Specifiers containing shell metacharacters or other unsafe characters are rejected immediately and the process exits non-zero before any filesystem or network operation occurs.

---

## Programmatic API

`main()` doubles as a programmatic entry point for agents, platform scanners, and the VS Code extension:

```js
import { SCA_scan } from "@arcane-spark/ubel-node/sca";

const report = await SCA_scan({
  projectRoot : "/abs/path/to/project",
  engine      : "npm",
  mode        : "health",
  is_script   : true,
  save_reports: true,
  scan_os     : false,
  full_stack  : false,
  scan_node   : true,
  scan_scope  : "repository",   // repository | agent | developer_platform | editor_extension
});
// report is the full finalJson object (inventory, vulnerabilities, decision, …)
```

When called this way, the banner and interactive console output are suppressed. The return value is the same machine-readable report object written to disk.

---

## Reports

Every scan writes two files to a timestamped path and overwrites the `latest*` convenience links:

```
.ubel/reports/latest.json          ← always current
.ubel/reports/latest.html          ← always current
.ubel/reports/latest.cdx.json          ← always current
.ubel/reports/latest.sarif.json          ← always current

.ubel/local/reports/<ecosystem>/<mode>/<YYYY>/<MM>/<DD>/
    <ecosystem>_<mode>_<engine>__<timestamp>.json
    <ecosystem>_<mode>_<engine>__<timestamp>.html
    <ecosystem>_<mode>_<engine>__<timestamp>.cdx.json
    <ecosystem>_<mode>_<engine>__<timestamp>.sarif.json
```

The HTML report is fully self-contained (no server required) and includes:

- Dashboard with severity breakdown chart and policy decision
- Searchable, filterable vulnerability table
- Full inventory with state (safe / vulnerable / infected / undetermined)
- Interactive force-directed dependency graph with vulnerable-subtree filter
- Per-vulnerability detail modals (CVSS vector, fix recommendations, OSV/NVD references)
- Dedicated Secrets tab (category, severity, file/line, redacted match preview)
- System and runtime metadata

The JSON report contains the full machine-readable equivalent and can be consumed by CI/CD tooling directly.

---

## CI/CD Integration

All CLI commands exit non-zero on policy violations, making them native to any CI runner:

```yaml
# GitHub Actions
- name: UBEL dependency scan
  run: ubel-npm check

- name: UBEL firewall-gated install
  run: ubel-npm install
```

```dockerfile
# Dockerfile
RUN ubel-npm install
```

---

## Quick-start examples

```bash
# Scan the current lockfile without installing anything
ubel-npm check

# Gate the actual install behind a policy scan
ubel-npm install

# Scan a single package for vulnerabilities before it touches node_modules
ubel-npm check lodash@4.17.20

# Tighten policy, then re-scan
ubel-npm threshold critical
ubel-npm check

# Scan the installed project dependencies
ubel-npm health

# Same workflows with pnpm and bun
ubel-pnpm install react react-dom
ubel-bun check
```

---

*Ubel — Secure every dependency, before it reaches production.*