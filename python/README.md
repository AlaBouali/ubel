# UBEL — Unified Bill / Enforced Law
### Python Supply-Chain Security CLI

Ubel resolves dependencies, generates PURLs, scans them through [OSV.dev](https://osv.dev), and enforces configurable security policies at install-time to block supply-chain attacks before they reach production.

This document covers the **Python** ecosystem (`ubel-pip`) and the **Linux host** scanner (`ubel`).

---

## Features

- Full dependency resolution with PURL generation via `pip --dry-run --report`
- OSV.dev vulnerability scanning via batched API queries (up to 800 PURLs per batch)
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references) with up to 40 parallel threads
- Policy engine — block/allow by severity threshold and unknown-severity packages
- Malicious package (infection) detection — always blocked regardless of policy
- `check` mode — dry-run resolution and scan with no side effects
- `install` mode — scan-gate before installation; blocks if policy violated
- `health` mode — scan the current project's installed Python environments and/or host OS packages
- Isolated virtual environment management — UBEL creates and manages its own venv for dry-runs
- Version pinning — `health` and `install` modes rewrite `requirements.txt` with exact resolved versions after a clean scan
- Full-stack monorepo scanning — walks the entire directory tree and collects packages across all supported ecosystems in a single pass
- Linux host scanning — reads system package databases directly (no elevated privileges required)
- Automatic report generation: timestamped **JSON** + **HTML** + **SBOM** per scan, plus `latest.*` convenience links
- Zero external runtime dependencies (Python stdlib only)
- Complete, compliant, and enriched SBOM CycloneDX v1.6 with full dependency graph and vulnerabilities in VEX format
- Programmatic API — doubles as a library entry-point for agents, CI tools, and the VS Code extension

---

## Installation

```bash
pip install ubel-python
```

On Linux, it is recommended to install inside a virtual environment to avoid system-level conflicts:

```bash
python3 -m venv venv
source venv/bin/activate
pip install ubel-python
```

After installation, the following entry-point binaries are available:

| Binary | Purpose |
|---|---|
| `ubel-pip` | Python / PyPI ecosystem (virtualenv scanning, dry-run installs) |
| `ubel` | Linux host OS package scanning (dpkg, apk, rpm) |

---

## Requirements

- Python `>= 3.8`
- `pip` available inside the target virtual environment
- For Linux host scanning: a supported Linux distribution (see [Platform Scanning](#platform-scanning-linux))

---

## Usage

```
ubel-pip  <mode> [packages...]
ubel      <mode> [packages...]
```

Package arguments are optional for `check` and `install` — when omitted, `requirements.txt` in the current working directory is used as the dependency source.

---

## Modes

### `health`

Scans the current project's installed dependency graph without running any install. Walks the directory tree from the working directory, discovers all virtual environments, reads installed packages from `.dist-info` / `.egg-info` metadata, and submits resolved PURLs to OSV.dev.

```bash
ubel-pip health
ubel health       # Linux host packages
```

#### Full-stack monorepo scanning

When invoked programmatically with `full_stack=True`, `health` walks the entire directory tree from the project root and collects packages across all supported ecosystems in a single pass — no per-language configuration required.

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| Python | pip / virtualenv | `.dist-info` / `.egg-info` metadata inside venv `site-packages/` |
| Node.js | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| PHP | Composer | `vendor/` |
| Rust | Cargo | `Cargo.lock` |
| Go | Go Modules | `go.sum` |
| C# / .NET | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| Java | Maven | `pom.xml` resolved dependencies |
| Ruby | Bundler | `Gemfile.lock` |

Each discovered package is deduplicated by PURL before submission, so packages shared across sub-projects are scanned exactly once.

#### Platform scanning (Linux)

When invoked with `scan_os=True` (programmatic) or via the `ubel` CLI, the scanner reads the host's system package database directly — no elevated privileges required — and includes all installed system packages in the scan inventory.

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

---

### `check`

Dry-run: resolves the given packages (or `requirements.txt`) via `pip install --dry-run --report`, scans the resolved set against OSV.dev, and exits. Nothing is installed and no packages are written to disk.

```bash
# Scan specific packages without installing
ubel-pip check flask==3.1.0 requests

# Scan the current requirements.txt with no changes
ubel-pip check
```

Exits `0` if policy passes, `1` if policy blocks or the scan fails.

---

### `install`

Same pipeline as `check`, but proceeds to install (via `pip install -r <requirements>`) into the managed virtual environment if and only if the policy decision is **allow**. After a successful install, `requirements.txt` is rewritten with exact pinned versions from the resolved environment.

```bash
ubel-pip install flask==3.1.0 requests
ubel-pip install                          # resolves from requirements.txt

# Linux system packages
ubel install curl wget
```

If the policy blocks, installation is aborted and the process exits `1`. No packages are written to `site-packages/`.

---

### `init`

Creates and initialises the managed virtual environment at `./venv` (or the path configured in `UbelEngine.venv_dir`). Safe to call on an existing venv — idempotent.

```bash
ubel-pip init
```

---

### `threshold`

Sets the severity level at or above which vulnerabilities block the scan. Accepts `low`, `medium`, `high`, `critical`, or `none` (disable threshold blocking).

```bash
ubel-pip threshold high       # block high and critical
ubel-pip threshold critical   # block critical only
ubel-pip threshold none       # disable severity blocking
```

Infections (`MAL-*` advisories) are always blocked regardless of this setting.

The threshold is persisted to the local policy file and applies to all subsequent scans until changed.

---

### `block-unknown`

Controls whether packages with unknown-severity vulnerabilities are blocked.

```bash
ubel-pip block-unknown true
ubel-pip block-unknown false
```

---

## Policy

Policy is stored as JSON at `.ubel/local/policy/config.json` relative to the project root. For the Linux host scanner (`ubel`), the policy lives under `~/.ubel/local/policy/config.json` to avoid requiring write access to the project directory.

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

## Virtual Environment Management

UBEL creates and manages its own isolated virtual environment for dry-run operations. By default this is `./venv`. The venv is created with `pip` available (using Python's built-in `venv` module — no external tooling required).

```
./venv/                  ← managed by UBEL
    bin/python           (Unix)
    Scripts/python.exe   (Windows)
    lib/site-packages/
```

UBEL uses the venv's own `pip` for all dry-run and install operations, keeping the tool's own installation completely separate from the scanned environment.

---

## Package Argument Validation

All package specifiers passed to `check` and `install` are validated before any subprocess is invoked. Only characters that are legal in package names and version specifiers are accepted (`=`, `.`, `_`, `+`, `-`, `@`, `/`, `~`). Specifiers containing shell metacharacters or other unsafe characters are rejected immediately and the process exits non-zero before any filesystem or network operation occurs.

---

## Programmatic API

`main()` doubles as a programmatic entry point for agents, platform scanners, and the VS Code extension:

```python
from ubel.__main__ import main

report = main({
    "project_root": "/abs/path/to/project",
    "engine":       "pip",         # "pip" (default) or linux tool name
    "mode":         "health",      # "health" | "check" | "install"
    "packages":     [],            # package specifiers for check/install mode
    "is_script":    True,          # suppress banner and console output
    "save_reports": True,          # write reports to disk
    "scan_os":      False,         # include host OS packages
    "full_stack":   False,         # scan all ecosystems, not just Python venvs
    "scan_venv":    True,          # include Python venvs
    "scan_scope":   "repository",  # repository | agent | developer_platform | editor_extension
})
# report is the full final_json object (inventory, vulnerabilities, decision, …)
```

When called this way, the banner and interactive console output are suppressed. The return value is the same machine-readable report object written to disk.

**IMPORTANT:** The programmatic API is primarily exposed for lightweight integrations and automation around UBEL's CLI and VS Code workflows. UBEL is designed first and foremost as a single-operation CLI/runtime scanner, not as a multi-tenant concurrent scanning library.

`main()` is therefore currently not concurrency-safe. Do not invoke multiple `install`, `check`, or `health` operations in parallel within the same process, as report generation and internal scan state may overlap.

Run operations sequentially until parallel execution support is introduced in a future release.

---

## Reports

Every scan writes three files to a timestamped path and overwrites the `latest*` convenience links:

```
.ubel/reports/latest.json              ← always current
.ubel/reports/latest.html              ← always current
.ubel/reports/latest_sbom.cdx.json    ← always current

.ubel/local/reports/<ecosystem>/<mode>/<YYYY>/<MM>/<DD>/
    <ecosystem>_<mode>_<engine>__<timestamp>.json
    <ecosystem>_<mode>_<engine>__<timestamp>.html
    <ecosystem>_<mode>_<engine>__<timestamp>_sbom.cdx.json
```

For the Linux host scanner (`ubel`), all reports and policy live under `~/.ubel/` to avoid requiring write access to the working directory.

The HTML report is fully self-contained (no server required) and includes:

- Dashboard with severity breakdown chart and policy decision
- Searchable, filterable vulnerability table
- Full inventory with state (safe / vulnerable / infected / undetermined)
- Interactive force-directed dependency graph with vulnerable-subtree filter
- Per-vulnerability detail modals (CVSS vector, fix recommendations, OSV references)
- System and runtime metadata (Python version, OS info, git metadata, local and external IPs)

The JSON report contains the full machine-readable equivalent and can be consumed by CI/CD tooling directly.

The SBOM is a fully valid [CycloneDX v1.6](https://cyclonedx.org) document including all components, their dependency relationships, and enriched vulnerability data in VEX format.

---

## CI/CD Integration

All CLI commands exit non-zero on policy violations, making them native to any CI runner:

```yaml
# GitHub Actions
- name: UBEL dependency scan
  run: ubel-pip check

- name: UBEL firewall-gated install
  run: ubel-pip install
```

```dockerfile
# Dockerfile
RUN ubel-pip install
```

---

## Scope Detection

UBEL automatically detects whether each package is a production or development dependency by reading `requirements.txt`, `requirements-dev.txt`, `requirements/base.txt`, `requirements/prod.txt`, and `requirements/dev.txt` relative to each discovered virtual environment. Scopes are then propagated forward through the dependency graph via BFS — a transitive dependency of a production package inherits the `prod` scope.

Packages that cannot be matched to any requirements file default to `prod`.

---

## Quick-start examples

```bash
# Scan the current requirements.txt without installing anything
ubel-pip check

# Gate the actual install behind a policy scan
ubel-pip install

# Scan a single package for vulnerabilities before it touches site-packages
ubel-pip check flask==3.1.0

# Tighten policy, then re-scan
ubel-pip threshold critical
ubel-pip check

# Scan installed project dependencies
ubel-pip health

# Scan Linux system packages
ubel health

# Scan the whole system: Python venvs AND host OS packages
# (programmatic, or via the VS Code extension / agent)
# scan_os=True adds host packages into the unified inventory
```

---

## Report JSON schema (top-level fields)

| Field | Description |
|---|---|
| `generated_at` | ISO 8601 UTC timestamp of the scan |
| `runtime` | Python version, platform, arch, cwd |
| `engine` | Package manager name and version used for the scan |
| `os_metadata` | OS name/version, local IPs, external IP |
| `git_metadata` | Branch, commit, remote URL |
| `tool_info` | UBEL tool name, version, license |
| `scan_info` | Scan type, ecosystems covered, scope label |
| `stats` | Inventory size, vulnerable / infected / safe counts, severity breakdown |
| `vulnerabilities_ids` | Sorted list of all vulnerability IDs found |
| `findings_summary` | Per-package summary with sorted vulnerability list and counts |
| `vulnerabilities` | Full enriched vulnerability records, sorted by severity |
| `inventory` | Full component list with PURL, state, scopes, paths, dependency graph |
| `policy` | Active policy at the time of the scan |
| `dependencies_tree` | Nested dict representation of the dependency graph |
| `decision` | `allowed`, `reason`, and list of policy-violating vulnerability IDs |

---

*Ubel — Secure every dependency, before it reaches production.*