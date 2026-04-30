# UBEL — VS Code Extension

**Supply-chain firewall and vulnerability scanner for VS Code.**  
Scan your workspace, your installed extensions, and your host platform — directly from the editor, with no terminal required.

[![Publisher](https://img.shields.io/badge/publisher-Arcane--Spark-blue)](https://github.com/AlaBouali)
[![License](https://img.shields.io/badge/license-Apache--2.0-green)](LICENSE.md)
[![VS Code](https://img.shields.io/badge/vscode-%5E1.85.0-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)
[![Marketplace](https://img.shields.io/badge/marketplace-Install-007ACC)](https://marketplace.visualstudio.com/items?itemName=Arcane-Spark.ubel)

> For CLI usage, CI/CD integration, server-side firewall (apt, dnf, pip), and full architecture documentation, see the [main README](https://github.com/AlaBouali/ubel/blob/main/README.md).

---

## Commands

| Command | Shortcut (Win/Linux) | Shortcut (Mac) | What it scans |
|---|---|---|---|
| **UBEL: Scan Project** | `Ctrl+Alt+U` | `Cmd+Alt+U` | All ecosystems inside the open workspace folder |
| **UBEL: Scan VS Code Extensions** | `Ctrl+Alt+X` | `Cmd+Alt+X` | npm packages inside `~/.vscode/extensions` |
| **UBEL: Scan Host Platform** | `Ctrl+Alt+P` | `Cmd+Alt+P` | System software installed on this machine |

All three commands are also accessible via the Command Palette (`Ctrl+Shift+P` / `Cmd+Shift+P`) — search **UBEL**.

---

## Installation

**From the Marketplace**

Search for **UBEL** in the VS Code Extensions panel, or install directly:

```
ext install Arcane-Spark.ubel
```

**From VSIX**

1. Download `ubel-vscode-extension.vsix` from the [releases page](https://github.com/AlaBouali/ubel/vscode).
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
<project-root>/.ubel/reports/latest.html
```

---

## Scan VS Code Extensions (`Ctrl+Alt+X`)

Scans the npm packages bundled inside your installed VS Code extensions (`~/.vscode/extensions`). Extensions are a meaningful supply-chain surface — they run with full Node.js access in the editor host process and are updated silently.

**Report location**

```
~/.vscode/extensions/.ubel/reports/latest.html
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

The report is always written to `~/.ubel/reports/latest.html`, independent of any open workspace.

```
~/.ubel/reports/latest.html
```

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
| **Vulnerabilities** | Full list of matched CVEs with CVSS score, EPSS, severity, fix version, and policy decision |
| **Inventory** | Every scanned package with version, PURL, CPE, ecosystem, and vulnerability count |
| **Graph** | Interactive force-directed dependency graph — colour-coded by vulnerability status, with search, filter, drag, and pin |
| **Stats** | Severity distribution charts, top vulnerable packages, ecosystem breakdown |
| **System** | OS metadata, Node.js version, scan engine info |

---

## Policy

Policy is stored per-project at `.ubel/local/policy/config.json` and shared across the VS Code extension and CLI.

| Setting | Values | Default |
|---|---|---|
| `severity_threshold` | `low` `medium` `high` `critical` `none` | `high` |
| `block_unknown_vulnerabilities` | `true` `false` | `true` |

The threshold is inclusive — `high` blocks both `high` and `critical`. `MAL-*` (malware) packages are unconditionally blocked regardless of any setting.

To change policy from the CLI:

```bash
ubel-npm threshold critical
ubel-npm block-unknown false
```

---

## Report Storage

| Scan | Latest report | History |
|---|---|---|
| Project | `<project-root>/.ubel/reports/latest.html` | `<project-root>/.ubel/local/reports/npm/health/<year>/<month>/<day>/` |
| Extensions | `~/.vscode/extensions/.ubel/reports/latest.html` | `~/.vscode/extensions/.ubel/local/reports/npm/health/<year>/<month>/<day>/` |
| Platform | `~/.ubel/reports/latest.html` | `~/.ubel/local/reports/npm/health/<year>/<month>/<day>/` |

---

## Requirements

- VS Code `^1.85.0`
- Node.js `>=18.0.0`

---

## Privacy

UBEL is fully local. The only external call is to [osv.dev's public API](https://osv.dev/) and [NVD's API] (https://nvd.nist.gov/) , which receives package PURLs (package name + version) to check for known vulnerabilities. No file contents, no dependency graphs, no machine identifiers, and no telemetry are sent anywhere.

---

## License

Apache-2.0 with Commons Clause — free for scanning your own projects and systems.  
See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE) for details or contact [ala.bouali.1997@gmail.com](mailto:ala.bouali.1997@gmail.com) for commercial licensing.