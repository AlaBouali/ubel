# UBEL — Supply-Chain Firewall

**Multi-ecosystem dependency security scanner and supply-chain firewall for VS Code.**  
Scans your project and your installed extensions for vulnerabilities and malicious packages — entirely on your machine, zero cloud calls except for osv.dev's API.

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE.md)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![GitHub](https://img.shields.io/badge/github-AlaBouali%2Fubel-lightgrey)](https://github.com/AlaBouali/ubel)

---

## What is UBEL?

UBEL is a **software composition analysis (SCA)** tool and **install-blocking firewall** built for developers who care about what goes into their supply chain. Unlike report-only scanners, UBEL enforces a policy — if a scan fails, it tells you clearly and blocks the operation.

It covers **8 ecosystems in a single scan pass**, works via calling the public osv.dev's API to query the installed packages, and ships with zero external runtime dependencies. No API keys required for local use.

---

## Features

- 🔍 **Multi-ecosystem** — Node.js, Python, PHP, Rust, Go, C#, Java, Ruby in one pass
- 🛡️ **Policy enforcement** — configurable severity threshold; violations surface as explicit warnings
- ☠️ **Malware blocking** — `MAL-*` infected packages are unconditionally blocked
- 📄 **HTML report** — self-contained report written to `.ubel/reports/latest.html` on every scan
- 🔒 **Fully local** — no dependency tree, no package names, no data sent anywhere except for PURLs sent to osv.dev's API.
- ⚡ **Zero setup** — no extra installs, no Docker, no config files required to get started
- 🧩 **Scans your extensions too** — audit `~/.vscode/extensions` with a single command

---

## Commands

| Command | Shortcut (Win/Linux) | Shortcut (Mac) | Description |
|---|---|---|---|
| **UBEL: Scan Project** | `Ctrl+Alt+U` | `Cmd+Alt+U` | Scans the currently open workspace folder |
| **UBEL: Scan VS Code Extensions** | `Ctrl+Alt+X` | `Cmd+Alt+X` | Scans `~/.vscode/extensions` |

All commands are also reachable via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) — search for **UBEL**.

---

## Installation

1. Download `ubel-vscode-extension.vsix` from the [releases page](https://github.com/AlaBouali/ubel/releases).
2. Open the Command Palette and run **Extensions: Install from VSIX…**
3. Select the downloaded file.

---

## Usage

Run either command. A progress notification appears while the scan runs. When it finishes:

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
| Extensions | `<user_home_directory>/.vscode/extensions/.ubel/reports/latest.html` |

---

and the previous scans are stored locally under these folders:

 - `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

 - `<user_home_directory>/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/`

## Supported Ecosystems

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

> Linux host package scanning (dpkg / apk / rpm) is available in the UBEL CLI but not active in the extension.

---

## Requirements

- VS Code `^1.85.0`
- Node.js `>=18.0.0`

---

## License

Apache-2.0 with Commons Clause — free for scanning your own projects and systems.  
See [LICENSE.md](LICENSE.md) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.