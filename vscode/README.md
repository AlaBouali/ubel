# UBEL — Supply-Chain Firewall

**Multi-ecosystem dependency security scanner and supply-chain firewall for VS Code.**  
Scans your project, your installed extensions, and your host platform for vulnerabilities and malicious packages — entirely on your machine, zero cloud calls except for osv.dev's API.

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE.md)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool and **install-blocking firewall** built for developers who care about what goes into their supply chain. Unlike report-only scanners, UBEL enforces a policy — if a scan fails, it tells you clearly and blocks the operation.

It covers **8 ecosystems in a single scan pass**, works via calling the public osv.dev API to query the installed packages, and ships with zero external runtime dependencies. No API keys required for local use.

---

## Features

- 🔍 **Multi-ecosystem** — Node.js, Python, PHP, Rust, Go, C#, Java, Ruby in one pass
- 🖥️ **Platform scanning** — enumerate and audit system-level software: OS, runtimes, browsers, Docker, Git, and more
- 🛡️ **Policy enforcement** — configurable severity threshold; violations surface as explicit warnings
- ☠️ **Malware blocking** — `MAL-*` infected packages are unconditionally blocked
- 📄 **HTML report** — self-contained interactive report written on every scan
- 🔒 **Fully local** — no dependency tree, no package names, no data sent anywhere except for PURLs sent to osv.dev's API
- ⚡ **Zero setup** — no extra installs, no Docker, no config files required to get started
- 🧩 **Scans your extensions too** — audit `~/.vscode/extensions` with a single command

---

## Commands

| Command | Shortcut (Win/Linux) | Shortcut (Mac) | Description |
|---|---|---|---|
| **UBEL: Scan Project** | `Ctrl+Alt+U` | `Cmd+Alt+U` | Scans the currently open workspace folder |
| **UBEL: Scan VS Code Extensions** | `Ctrl+Alt+X` | `Cmd+Alt+X` | Scans `~/.vscode/extensions` for vulnerable npm packages |
| **UBEL: Scan Host Platform** | `Ctrl+Alt+P` | `Cmd+Alt+P` | Scans system-level software installed on this machine |

All commands are also reachable via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) — search for **UBEL**.

---

## Installation

1. Download `ubel-vscode-extension.vsix` from the [releases page](https://github.com/AlaBouali/ubel/releases).
2. Open the Command Palette and run **Extensions: Install from VSIX…**
3. Select the downloaded file.

---

## Usage

Run any command. A progress notification appears while the scan runs. When it finishes:

| Result | Notification |
|---|---|
| ✅ Clean | No policy violations detected |
| ⚠️ Blocked | Policy violation — vulnerable or malicious package found |
| ❌ Error | Scan failed — see message for details |

Every notification includes an **Open Report** button that opens the full HTML report in your browser.

Reports are saved to:

| Scan target | Report path |
|---|---|
| Workspace | `<project-root>/.ubel/reports/latest.html` |
| Extensions | `~/.vscode/extensions/.ubel/reports/latest.html` |
| Host platform | `~/.ubel/reports/latest.html` |

Previous scans are stored locally under:

- `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`
- `~/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

---

## Platform Scanning

**UBEL: Scan Host Platform** (`Ctrl+Alt+P`) audits the software installed on your development machine itself — a distinct attack surface from your project's dependencies. It detects and cross-references against the CVE/NVD database using [CPE 2.3](https://nvd.nist.gov/products/cpe) identifiers.

### What gets scanned

**Windows**

Detected via registry probes and PowerShell — no elevated privileges required.

| Category | Components |
|---|---|
| Operating system | Windows 10 / 11 (build-accurate version) |
| Security | Windows Defender |
| Runtimes | Node.js, Python, PHP, Go, Rust, Ruby, JRE, JDK |
| .NET | All installed .NET Core / Desktop / ASP.NET runtimes (multi-version) |
| Browsers | Chrome, Firefox, Microsoft Edge |
| Developer tools | Git, Docker Desktop, VS Code, Cursor |
| Shell | PowerShell |

**Linux**

Detected by reading the system package database directly — works as a standard user on most distributions.

| Distro family | Package manager | Database path |
|---|---|---|
| Debian / Ubuntu | dpkg | `/var/lib/dpkg/status` |
| Alpine | apk | `/lib/apk/db/installed` |
| Red Hat / AlmaLinux / Rocky | rpm | `rpm -qa` |

> On RPM-based systems, `rpm -qa` may return partial results depending on SELinux policy if run without elevated privileges.

### Report output

The platform scan produces the same interactive HTML report as a project scan. Each detected component is shown in the **Inventory** tab with its CPE identifier, detected version, and any matched CVEs. The **Dependency Graph** and **Vulnerability** tabs are fully populated.

Because the platform scan target is your home directory rather than a project folder, the report is always written to `~/.ubel/reports/latest.html` — independent of whether a workspace is open in VS Code.

---

## Supported Ecosystems (Project Scan)

UBEL performs a full-stack scan, automatically detecting all of the following ecosystems anywhere inside the scanned directory. Monorepos with mixed stacks are covered in a single pass.

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

## Requirements

- VS Code `^1.85.0`
- Node.js `>=18.0.0`

---

## License

Apache-2.0 with Commons Clause — free for scanning your own projects and systems.  
See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/vscode/LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.