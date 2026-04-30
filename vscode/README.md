# UBEL — Supply-Chain Firewall

**Multi-ecosystem security scanner and install-blocking firewall for the full software delivery chain.**  
Covers source repos, developer machines, deployment servers, CI/CD pipelines, and AI agent workspaces — entirely on your infrastructure, zero cloud calls except for osv.dev's API.

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE.md)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool and **install-blocking firewall** built for teams who care about what enters their supply chain at every layer. Unlike report-only scanners, UBEL enforces policy — if a scan fails, it blocks the operation and tells you exactly why.

It spans the entire delivery chain: from the moment a developer adds a dependency, through CI validation, to what is running on a deployment server or inside an AI agent's runtime environment.

---

## Coverage at a Glance

| Surface | Mode | Toolchain |
|---|---|---|
| Source repos & monorepos | Scan + firewall | npm, pnpm, bun, pip |
| Developer machines (Windows / Linux) | Scan | System packages, runtimes, browsers, tools |
| Deployment servers (Linux) | Scan + firewall | apt, dnf, pip |
| CI/CD pipelines | Scan + firewall | npm, pnpm, bun, pip, apt, dnf |
| AI agent workspaces | Scan | Platform (OS + runtimes) + project dependencies |

---

## Firewall Mechanics

UBEL wraps six package managers. In every case the invariant is the same: **packages are scanned before they touch the environment**. If a policy violation is found, the install is aborted and nothing is written to disk or to any environment.

---

### npm

**Mechanism: lockfile dry-run + atomic revert**

`ubel-npm check` and `ubel-npm install <pkg>` invoke npm's `--package-lock-only` flag, which resolves the full dependency tree and writes a candidate `package-lock.json` without touching `node_modules/`. UBEL scans the candidate lockfile, then makes a binary decision:

- **Clean** — the candidate lockfile is accepted. The original is restored from the `.ubel/lockfiles/<timestamp>/` backup and the actual install proceeds.
- **Violation** — `package-lock.json` is reverted to its pre-scan state from the disk backup. `node_modules/` is never touched. A `PolicyViolationError` is thrown, and the process exits non-zero.

The backup is written to `.ubel/lockfiles/<timestamp>/` before any mutation. If the revert itself fails (e.g. disk error mid-restore), the original lockfile is preserved at the backup path and its location is printed to stderr so the user can recover manually.

```
ubel-npm install lodash        # firewall-gated
ubel-npm check                 # scan current lockfile, no install
ubel-npm health                # scan only, always exits 0
ubel-npm threshold high        # set severity threshold
ubel-npm block-unknown true    # block packages with no CVE data
```

---

### pnpm

**Mechanism: lockfile dry-run + atomic revert**

Identical flow to npm, using pnpm's `--lockfile-only` flag. The candidate `pnpm-lock.yaml` is written, scanned, then either accepted or reverted from `.ubel/lockfiles/<timestamp>/`. `node_modules/` is never written during the scan phase.

```
ubel-pnpm install lodash
ubel-pnpm check
ubel-pnpm health
```

---

### bun

**Mechanism: lockfile dry-run + atomic revert**

Uses bun's `--lockfile-only` flag. The candidate `bun.lockb` (or `bun.lock`) is written and scanned before any `node_modules/` mutation. Revert path is identical to npm and pnpm.

```
ubel-bun install lodash
ubel-bun check
ubel-bun health
```

> **yarn** does not support a lockfile-only dry-run (`yarn add` always writes `node_modules`). UBEL supports yarn in scan mode (`ubel-yarn health`) but cannot provide install-blocking firewall coverage.

---

### pip

**Mechanism: isolated venv + pre-install scan**

`ubel-pip` manages its own isolated virtual environment under `.ubel/venv/`. It never installs into the system Python or any externally managed environment. The flow for `ubel-pip install <pkg>`:

1. Resolve the full dependency tree for `<pkg>` without installing — using `pip install --dry-run --report` to produce a JSON manifest of all packages that *would* be installed.
2. Scan the resolved manifest against osv.dev.
3. **Clean** — proceed with the actual install into `.ubel/venv/`. The venv is isolated from the system Python and from any project-level venv in the working directory.
4. **Violation** — abort. Nothing is written to any environment.

The managed venv is created once and reused across invocations. It is never exposed on `PATH` unless the user explicitly activates it — UBEL's own runtime is fully contained.

```
ubel-pip install requests       # firewall-gated install into managed venv
ubel-pip check requirements.txt # scan a requirements file, no install
ubel-pip health                  # scan current environment
ubel-pip threshold high
ubel-pip block-unknown true
```

---

### apt

**Mechanism: simulate + pre-install scan**

`ubel-apt` wraps Debian/Ubuntu's `apt-get --simulate` (equivalent to `-s`) to resolve the full package set — including all pulled-in dependencies — without writing anything to disk. The resolved list is scanned against the CVE/NVD database using CPE 2.3 identifiers. If clean, the real `apt-get install` is executed. If a violation is found, nothing is installed.

`apt-get --simulate` requires no root privileges; the subsequent real install does. UBEL intentionally separates the two steps so the scan always runs as the invoking user before privilege escalation occurs.

```
ubel-apt install nginx          # firewall-gated
ubel-apt check nginx            # scan without installing
ubel-apt health                  # scan all installed apt packages
ubel-apt threshold critical
```

---

### dnf

**Mechanism: dry-run + pre-install scan**

`ubel-dnf` uses `dnf install --assumeno` to resolve the transaction — including dependency pulls — without committing it. The resolved package list is scanned using CPE 2.3 identifiers. If clean, UBEL re-runs the install with `--assumeyes`. If a violation is found, the transaction is abandoned.

Applies to Red Hat, AlmaLinux, Rocky Linux, Fedora, and any dnf-compatible distribution.

```
ubel-dnf install nginx          # firewall-gated
ubel-dnf check nginx            # scan without installing
ubel-dnf health                  # scan all installed dnf packages
ubel-dnf threshold critical
```

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

## Deployment Surfaces

### Repos and Monorepos

UBEL walks the entire directory tree and detects all supported ecosystems in a single pass — no per-language configuration needed. Monorepos with mixed stacks (e.g. a Node.js frontend, Python backend, and Rust service in the same repo) are fully covered in one invocation.

### Developer Machines

The VS Code extension (`Ctrl+Alt+P`) and the `ubel-platform` CLI binary scan the host machine: OS, installed runtimes, browsers, developer tools, and security software. Vulnerabilities are matched using CPE 2.3 identifiers against the CVE/NVD database.

This surface catches what dependency scanners miss — a vulnerable version of Git, an unpatched Python interpreter, or an outdated Docker Desktop install.

### Deployment Servers

On Linux servers, `ubel-apt` and `ubel-dnf` gate system package installs at the point of provisioning. The same policy engine applies. Useful in Dockerfile `RUN` layers, Ansible tasks, and bare-metal provisioning scripts.

```dockerfile
RUN ubel-apt install python3 nginx && apt-get install -y python3 nginx
```

### CI/CD Pipelines

All CLI commands exit non-zero on policy violations, making them native to any CI runner. A failed scan fails the pipeline.

```yaml
# GitHub Actions
- name: UBEL dependency scan
  run: ubel-npm check

- name: UBEL system package scan
  run: ubel-apt check build-essential libssl-dev
```

### AI Agent Workspaces

`ubel-agent` combines platform and full-stack project scanning in a single invocation, covering the entire attack surface of an agent host: OS layer, inference runtime layer (Python environment, ML/AI packages), and tooling layer (Node.js, npm packages, additional runtimes).

```bash
ubel-agent /path/to/agent/workspace
```

Supply chain attacks targeting ML/AI packages — PyPI typosquatting, malicious model loaders, compromised inference libraries — are an active threat. `ubel-agent` is specifically built for this use case.

---

## Platform Scanning

The `ubel-platform` CLI and the VS Code `Ctrl+Alt+P` command enumerate and audit system-level software on the host machine.

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
| **Java** | Maven | `pom.xml` resolved dependencies |
| **Ruby** | Bundler | `Gemfile.lock` |

---

## Reports

Every scan writes a self-contained interactive HTML report.

| Scan target | Report path |
|---|---|
| Workspace | `<project-root>/.ubel/reports/latest.html` |
| VS Code extensions | `~/.vscode/extensions/.ubel/reports/latest.html` |
| Host platform | `~/.ubel/reports/latest.html` |
| Agent workspace | `<workspace>/.ubel/reports/latest.html` |

Previous scans are retained under:

- `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

---

## Requirements

- Node.js `>=18.0.0`
- Python `>=3.9` (for `ubel-pip`, `ubel-apt`, `ubel-dnf`)
- VS Code `^1.85.0` (extension only)

---

## Repository Structure

```
ubel/
├── node/          # Node.js scanner + firewall (npm, pnpm, bun, yarn)
│   ├── src/       # Engine, policy, lockfile parsers, OS runners
│   └── bin/       # CLI entry points (ubel-npm, ubel-pnpm, …)
├── python/        # Python scanner + firewall (pip, apt, dnf)
├── vscode/        # VS Code extension
└── go/            # Orchestration layer (unified ubel command, WIP)
```

See [`vscode/README.md`](vscode/README.md) for VS Code extension-specific documentation.

---

## License

Apache-2.0 with Commons Clause — free for scanning your own projects and systems.  
See [LICENSE.md](LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.