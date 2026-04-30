# UBEL — Unified Bill / Enforced Law
### Python & Linux Supply-Chain Security CLI

Ubel resolves dependencies, generates PURLs, scans them through [OSV.dev](https://osv.dev), and enforces configurable security policies at install-time to block supply-chain attacks before they reach production.

This document covers the **Python (PyPI)** and **Linux** ecosystems.

---

## Features

- Full dependency resolution with PURL generation
- OSV.dev vulnerability scanning via batched API queries
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- Policy engine — block/allow by severity threshold and unknown-severity packages
- Malicious package (infection) detection — always blocked regardless of policy
- `check` mode — dry-run resolution and scan with no side effects
- `install` mode — scan-gate before installation; blocks if policy violated
- `health` mode — scan the running environment (installed venvs or all system packages)
- `init` mode — initialize a local virtual environment
- Dependency graph with introduced-by and parent tracking
- Automatic report generation: timestamped **JSON** + **HTML** per scan, plus `latest.*` symlinks
- Zero external dependencies (stdlib only)

---

## Installation

```bash
pip install ubel
```

On Linux, use a virtual environment to avoid requiring root for pip:

```bash
python3 -m venv venv
source venv/bin/activate
pip install ubel
```

After installation, two entry-point binaries are available:

| Binary | Ecosystem |
|---|---|
| `ubel-pip` | Python / PyPI projects |
| `ubel` | Linux system packages (apt / dnf / yum / apk) |

---

## Usage

```
ubel-pip  <mode> [packages...]
ubel      <mode> [packages...]
```

Both CLIs share the same set of modes. Package arguments are optional for `check` and `install` — when omitted they are read from `requirements.txt` (pip) or resolved from the installed system (Linux health).

---

## Modes

### `health`

Scans the current environment without installing anything.

**Python** — recursively walks the current directory for virtualenvs, reads all installed packages from `.dist-info` metadata, and submits them to OSV.

```bash
ubel-pip health
```

**Linux** — reads all installed system packages from dpkg / apk / rpm databases, including binary paths, dependency edges, and the running kernel version (apt-based distros).

```bash
ubel health
```

Reports and policy for the Linux entry-point are written under `$HOME/.ubel/` to avoid requiring root for writes.

---

### `check`

Dry-run: resolves the given packages (or `requirements.txt`) via `pip install --dry-run`, scans the resolved set, and exits. Nothing is installed and `requirements.txt` is not modified.

```bash
# Scan specific packages
ubel-pip check requests==2.32.3 flask

# Scan everything in requirements.txt
ubel-pip check
```

Linux dry-run resolution uses the native package manager (`apt-get -s`, `dnf --assumeno`, `yum --assumeno`):

```bash
ubel check curl nginx
```

Exits `0` if policy passes, `1` if policy blocks or the scan fails.

---

### `install`

Same pipeline as `check`, but proceeds to install if and only if the policy decision is **allow**.

```bash
ubel-pip install flask==3.1.0 sqlalchemy
ubel-pip install                            # reads requirements.txt
```

```bash
ubel install curl                           # Linux
```

If the policy blocks, installation is aborted and the process exits `1`.

---

### `init`

Creates a Python virtual environment at `./venv` (idempotent — safe to run on an existing venv).

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

Policy is stored as JSON at `.ubel/local/policy/config.json` (pip) or `~/.ubel/local/policy/config.json` (Linux).

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

## Supported Linux Distributions

| Distribution | Package manager | PURL type |
|---|---|---|
| Ubuntu | apt / apt-get | `pkg:deb/ubuntu/` |
| Debian | apt / apt-get | `pkg:deb/debian/` |
| Red Hat / RHEL | dnf / yum | `pkg:rpm/redhat/` |
| AlmaLinux | dnf | `pkg:rpm/almalinux/` |
| Rocky Linux | dnf / yum | `pkg:rpm/rocky-linux/` |
| Alpine | apk (db file) | `pkg:apk/alpine/` |
| Alpaquita | apk (db file) | `pkg:apk/alpaquita/` |

---

## Reports

Every scan writes two files to a timestamped path and overwrites the `latest.*` convenience links:

```
.ubel/reports/latest.json          ← always current
.ubel/reports/latest.html          ← always current

.ubel/local/reports/<ecosystem>/<mode>/<YYYY>/<MM>/<DD>/
    <ecosystem>_<mode>_<engine>__<timestamp>.json
    <ecosystem>_<mode>_<engine>__<timestamp>.html
```

Linux reports land under `$HOME/.ubel/` instead of the project directory.

The HTML report is fully self-contained (no server required) and includes:

- Dashboard with severity breakdown chart and policy decision
- Searchable, filterable vulnerability table
- Full inventory with state (safe / vulnerable / infected / undetermined)
- Interactive force-directed dependency graph with vulnerable-subtree filter
- Per-vulnerability detail modals (CVSS vector, fix recommendations, OSV references)
- System and runtime metadata

The JSON report contains the full machine-readable equivalent and can be consumed by CI/CD tooling directly.

After a successful `health` or `install` scan, pinned versions of all installed packages are written back to `requirements.txt`.

---

## Quick-start examples

```bash
# Python project — check all deps before installing
ubel-pip check

# Python project — gate the actual install
ubel-pip install

# Python project — scan a single package for a CVE check
ubel-pip check pillow==9.5.0

# Python project — tighten policy, then re-scan
ubel-pip threshold critical
ubel-pip check

# Scan the full Python environment on this machine
ubel-pip health

# Linux — check what curl would pull in before installing it
ubel check curl

# Linux — scan all installed system packages
ubel health

# Linux — lower the block threshold
ubel threshold medium
```

---

*Ubel — Secure every dependency, before it reaches production.*