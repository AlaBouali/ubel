# UBEL — Unified Bill / Enforced Law
### Multi-Ecosystem Supply-Chain Security Platform

Ubel resolves dependencies, generates PURLs, scans them through [OSV.dev](https://osv.dev) and [NVD](https://nvd.nist.gov/), and enforces configurable security policies at install-time to block supply-chain attacks before they reach production.

[![License](https://img.shields.io/badge/license-AGPL--3.0--only-green)](LICENSE.md)
[![PyPI](https://img.shields.io/badge/pypi-ubel--python-blue)](https://pypi.org/project/ubel-python/)
[![npm](https://img.shields.io/badge/npm-%40arcane--spark%2Fubel--node-red)](https://www.npmjs.com/package/@arcane-spark/ubel-node)
[![VS Code](https://img.shields.io/badge/vscode-Arcane--Spark.ubel-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool and **install-blocking firewall** built for developers and teams who care about what enters their supply chain at every layer. Unlike report-only scanners, UBEL enforces policy — if a scan fails, it blocks the operation and tells you exactly why.

It spans the entire delivery chain: from the moment a developer adds a dependency, through CI validation, to what is running on a deployment server or inside an AI agent's runtime environment.

---

## Repository Structure

```
ubel/
├── python/          # Python CLI — ubel-pip, ubel (Linux host scanner)
├── node/            # Node.js CLI — ubel-npm, ubel-pnpm, ubel-bun, ubel-agent, ubel-platform
└── vscode/          # VS Code extension — bundles the node/ engine at package time
```

The VS Code extension imports the Node.js engine directly from `node/src/` at package time via the `prepackage` script — no separate install step required when building locally.

---

## Features

- Full dependency resolution with PURL generation across all supported ecosystems
- Vulnerability scanning via batched queries to OSV.dev and NVD's APIs
- Concurrent enrichment (CVSS, EPSS, fix recommendations, references) with up to 40 parallel threads
- Policy engine — block/allow by severity threshold and unknown-severity packages
- Malicious package detection (`MAL-*` advisories) — always blocked regardless of policy
- `check` mode — dry-run resolution and scan with no side effects
- `install` mode — scan-gate before installation; blocks if policy violated
- `health` mode — scan the current project's installed dependencies
- Full-stack monorepo scanning — all supported ecosystems in a single pass
- Platform scanning — Linux (dpkg/apk/rpm) and Windows (registry/PowerShell), no elevated privileges required
- Atomic lockfile revert with TOCTOU SHA-256 integrity protection (Node.js)
- Automatic report generation: timestamped **JSON** + **HTML** + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links
- Zero external runtime dependencies (stdlib only, in both Python and Node.js)
- Complete, compliant, and enriched SBOM CycloneDX v1.6 with full dependency graph and vulnerabilities in VEX format
- Complete, compliant, and enriched SARIF v2.1.0 output

---

## Supported Ecosystems

### Project / Repository Scanning

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| Node.js | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| Python | pip / virtualenv | `.dist-info` / `.egg-info` inside venv `site-packages/` |
| PHP | Composer | `vendor/` |
| Rust | Cargo | `Cargo.lock` |
| Go | Go Modules | `go.sum` |
| C# / .NET | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| Java / Kotlin | Maven | `pom.xml` resolved dependencies |
| Ruby | Bundler | `Gemfile.lock` |

Each discovered package is deduplicated by PURL before submission — packages shared across sub-projects are scanned exactly once.

### Platform Scanning (Linux)

| Distribution | Package Manager | Source | PURL type |
|---|---|---|---|
| Ubuntu | dpkg | `/var/lib/dpkg/status` | `pkg:deb/ubuntu/` |
| Debian | dpkg | `/var/lib/dpkg/status` | `pkg:deb/debian/` |
| Alpine / Alpaquita | apk | `/lib/apk/db/installed` | `pkg:apk/alpine/` |
| Red Hat / RHEL | rpm | `rpm -qa` | `pkg:rpm/redhat/` |
| AlmaLinux | rpm | `rpm -qa` | `pkg:rpm/almalinux/` |
| Rocky Linux | rpm | `rpm -qa` | `pkg:rpm/rocky-linux/` |
| CentOS / Fedora | rpm | `rpm -qa` | `pkg:rpm/redhat/` |

### Platform Scanning (Windows)

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

Vulnerabilities are matched using CPE 2.3 identifiers against the CVE/NVD database.

---

## Components

### `python/` — Python CLI

```bash
pip install ubel-python
```

| Binary | Purpose |
|---|---|
| `ubel-pip` | Python / PyPI ecosystem (virtualenv scanning, dry-run installs) |
| `ubel` | Linux host OS package scanning (dpkg, apk, rpm) |

**Requirements:** Python `>= 3.8`, `pip` available in the target virtual environment.

See [`python/README.md`](python/README.md) for full documentation.

---

### `node/` — Node.js CLI

```bash
npm install -g @arcane-spark/ubel-node
```

| Binary | Purpose |
|---|---|
| `ubel-npm` | npm ecosystem |
| `ubel-pnpm` | pnpm ecosystem |
| `ubel-bun` | bun ecosystem |
| `ubel-agent` | AI agent workspace scan (OS, runtimes, tools, dependencies) |
| `ubel-platform` | Host platform scan (OS, runtimes, tools) |

**Requirements:** Node.js `>= 18.0.0`, target package manager binary on `PATH`.

> **yarn** does not support a lockfile-only dry-run — `yarn add` always writes `node_modules`. UBEL supports yarn in `health` mode only and cannot provide install-blocking firewall coverage for it.

See [`node/README.md`](node/README.md) for full documentation.

---

### `vscode/` — VS Code Extension

**From the Marketplace:**

```
ext install Arcane-Spark.ubel-vscode
```

**From VSIX:**

1. Download `ubel-vscode-extension.vsix` from the [releases page](https://github.com/AlaBouali/ubel/releases).
2. Open the Command Palette → **Extensions: Install from VSIX…**
3. Select the downloaded file.

**Requirements:** Node.js `>= 18.0.0`, VS Code `^1.85.0`.

| Command | Shortcut (Win/Linux) | Shortcut (Mac) | What it scans |
|---|---|---|---|
| UBEL: Scan Project | `Ctrl+Alt+U` | `Cmd+Alt+U` | All ecosystems inside the open workspace folder |
| UBEL: Scan Code Editor's Extensions | `Ctrl+Alt+X` | `Cmd+Alt+X` | npm packages inside installed VS Code / Cursor extensions |
| UBEL: Scan Host Platform | `Ctrl+Alt+P` | `Cmd+Alt+P` | System software installed on this machine |

See [`vscode/README.md`](vscode/README.md) for full documentation.

---

## Firewall Mechanics (Node.js)

`ubel-npm/pnpm/bun check` and `install` invoke the package manager's lockfile-only flag, resolving the full dependency tree and writing a candidate lockfile without touching `node_modules/`. UBEL scans the candidate lockfile, then makes a binary decision:

- **Clean** — the candidate lockfile is accepted and the actual install proceeds.
- **Violation** — the lockfile is reverted to its pre-scan state from the disk backup. `node_modules/` is never touched.

Before any real install is allowed to proceed, SHA-256 digests of the candidate lockfile and `package.json` are re-verified to close the TOCTOU window between scan and install.

All three package managers are invoked with `--ignore-scripts` to block malicious pre/post install scripts.

---

## Policy

Policy is stored as JSON at `.ubel/local/policy/config.json` relative to the project root (Linux host scanner and the VS Code extension's host scan use `~/.ubel/`).

Default policy created on first run:

```json
{
    "severity_threshold": "high",
    "block_unknown_vulnerabilities": true
}
```

| Field | Values | Default | Behaviour |
|---|---|---|---|
| `severity_threshold` | `low` `medium` `high` `critical` `none` | `high` | Block packages at or above this severity |
| `block_unknown_vulnerabilities` | `true` `false` | `true` | Block packages with CVEs but no CVSS score |
| Infections (`MAL-*`) | — | always blocked | Cannot be toggled; unconditionally blocked |

The threshold is inclusive — `high` blocks both `high` and `critical`. Setting `none` disables severity blocking but infections are still blocked.

---

## Reports

Every scan writes files to a timestamped path and overwrites the `latest.*` convenience links:

```
.ubel/reports/latest.json
.ubel/reports/latest.html
.ubel/reports/latest.cdx.json
.ubel/reports/latest.sarif.json

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
- System and runtime metadata

The SBOM is a fully valid [CycloneDX v1.6](https://cyclonedx.org) document including all components, their dependency relationships, and enriched vulnerability data in VEX format. The SARIF output is a fully valid [SARIF v2.1.0](https://sarifweb.azurewebsites.net/) file with deterministic SHA-256 fingerprinting per finding.

---

## CI/CD Integration

All CLI commands exit non-zero on policy violations:

```yaml
# GitHub Actions
- name: UBEL dependency scan
  run: ubel-npm check          # or ubel-pip check

- name: UBEL firewall-gated install
  run: ubel-npm install        # or ubel-pip install
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-pip install
```

---

## Programmatic API

Both engines expose a `main()` entry point for agents, CI tools, and the VS Code extension.

**Node.js:**

```js
import { main } from "@arcane-spark/ubel-node";

const report = await main({
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
```

**Python:**

```python
from ubel.__main__ import main

report = main({
    "project_root": "/abs/path/to/project",
    "engine":       "pip",
    "mode":         "health",
    "packages":     [],
    "is_script":    True,
    "save_reports": True,
    "scan_os":      False,
    "full_stack":   False,
    "scan_venv":    True,
    "scan_scope":   "repository",
})
```

When called this way, the banner and interactive console output are suppressed. The return value is the same machine-readable report object written to disk.

---

## Privacy

UBEL is fully local. The only external calls are to [osv.dev's public API](https://osv.dev/) and [NVD's API](https://nvd.nist.gov/), which receive package PURLs (name + version) to check for known vulnerabilities. No file contents, no dependency graphs, no machine identifiers, and no telemetry are sent anywhere.

---

## License

AGPL-3.0-only — free for scanning your own projects and systems.  
See [LICENSE.md](LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.

---

*Ubel — Secure every dependency, before it reaches production.*