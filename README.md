# UBEL — Unified Bill / Enforced Law (Node.js)

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, AI-powered SAST, cloud misconfiguration scanning and external attack surface scanning.**

UBEL is a zero-dependency, source-available (internal-use-only; see [License](#license)) application security toolkit. This package (`@arcane-spark/ubel-node`) ships one CLI per job. Full details live in [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md) and the per-module READMEs.

## Modules

| Module | What it does | Docs |
|---|---|---|
| **SCA** | Resolves dependencies and scans them against OSV.dev and NVD in real time, with reachability analysis, KEV/EPSS exploit intelligence, license checks, CycloneDX SBOM and SARIF output. | [sca/README.md](./sca/README.md) |
| **Firewall** | Gates `npm`/`pnpm`/`bun`/`composer`/`pip`/`uv`/`pipx`/`apt`/`dnf`/`yum` installs and Docker images behind a scan before anything is installed. | [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#firewall--install-time-gate) |
| **Secrets** | Trivy-derived ruleset plus UBEL's own rules. Standalone via `ubel-secrets`. | [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#secrets-detection) |
| **SAST** | LLM-powered scan → verify → taint-trace pipeline for vulnerabilities, plus a separate malicious-code scan. | [sast/README.md](./sast/README.md) |
| **Cloud** | Read-only AWS / GCP / Azure account scan for misconfigurations. | [cloud/README.md](./cloud/README.md) |
| **EASM** | Passive fingerprinting and misconfiguration checks of domains, hosts and ports you own. **Authorized use only.** | [easm/README.md](./easm/README.md) |

Every finding is also mapped to OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR and CIS Controls v8 (best-effort guidance, not a compliance assessment).

## Capability matrix

| Ecosystem | SCA | Firewall | SAST | Malware SAST | Reachability | License Compliance | Secrets |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| Node.js (npm/pnpm/bun) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Node.js (yarn) | ✅ | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Python (pip/uv/pipx/venv) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| PHP (Composer) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Ruby (Bundler) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Rust (Cargo) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Go (modules) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Java / Kotlin (Maven) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| C# / .NET (NuGet) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Swift (SwiftPM / Carthage) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| Flutter / Dart (pub) | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| C/C++ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ✅ |
| Docker images | ✅ (OS + app deps) | ✅ | — | — | — | ✅ | ✅ (in image) |
| Kubernetes manifests | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Terraform / CloudFormation (IaC) | — | — | ✅ (misconfig) | — | — | — | ✅ |
| Linux host (apt/dnf/yum) | ✅ | ✅ | — | — | — | ✅ | — |
| Windows host | ✅ | ❌ | — | — | — | ✅ | — |
| VS Code / Cursor / VSCodium extensions | ✅ | — | — | — | — | — | — |

✅ = built and shipped · ⚠️ = partial, see that ecosystem's section in [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md) · ❌ = not currently possible/present for a stated reason · — = not applicable to that layer

Cloud account misconfiguration scanning (AWS/GCP/Azure, via `ubel-cloud`) isn't tied to a dependency ecosystem, so it doesn't have a row here — see [cloud/README.md](./cloud/README.md).

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

Node.js `>=18.0.0` required. `ubel-pip`/`ubel-uv`/`ubel-pipx` need Python on `PATH`; `ubel-uv` and `ubel-composer` need their own binaries.

| Binary | Purpose |
|---|---|
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` / `ubel-yarn` | SCA (`health`) and firewall (`check` / `install`) for JS projects |
| `ubel-composer` | Same, for PHP |
| `ubel-pip` / `ubel-uv` / `ubel-pipx` | Same, for Python |
| `ubel-apt` / `ubel-dnf` / `ubel-yum` | Same, for Linux packages |
| `ubel-docker` | Scan or gate a container image |
| `ubel-secrets` / `ubel-license` | Standalone secrets / license scans |
| `ubel-agent` / `ubel-cicd` / `ubel-platform` | Fixed-configuration scans: AI-agent workspace, built CI/CD workspace, host |
| `ubel-sast` / `ubel-mal` / `ubel-chunk` | Vulnerability SAST, malicious-code scan, chunking preview (no LLM cost) |
| `ubel-cloud` | AWS / GCP / Azure misconfiguration scan |
| `ubel-url` / `ubel-domain` / `ubel-host` / `ubel-easm` | EASM: known hosts, CT-log subdomain discovery, port sweep of one host, combined sweep |

## Quick start

```bash
ubel-npm health                      # audit installed dependencies
ubel-npm check                       # firewall: dry-run, exit non-zero if policy blocks
ubel-secrets /path/to/project         # secrets-only scan
ubel-sast /path/to/project            # AI-powered vulnerability scan
ubel-cloud                           # providers you have credentials for
ubel-url staging.your-domain.example --fail-on high   # EASM, your own infrastructure only
```

## CI exit codes

- **SCA / firewall:** exit `1` if policy blocks or the scan fails (including an incomplete OSV/NVD lookup — never treated as a pass).
- **EASM:** exit `2` when `--fail-on` is met. It gates on vulnerabilities, infections **and web misconfigurations**; KEV/EPSS rules apply to vulnerabilities. `--fail-on none` disables the gate.
- **Cloud:** governed by its own `--fail-on`.

See [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md#cicd-integration) for GitHub Actions and Docker examples.

## Privacy

No telemetry and no UBEL-operated backend. Dependency scans send only package identifiers to OSV.dev and NVD (mirrorable via `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT`), and CVE ids to FIRST.org's EPSS API. **SAST sends code chunks to the LLM provider you configure** — use a local endpoint if code must not leave your network. EASM and cloud scanners contact only the targets and APIs you point them at, plus public data sources documented in their READMEs.

## License

Source-available, **internal-use-only**. Using and modifying UBEL for your organization's own needs (including its own CI/CD and products) is permitted. Redistribution, wrapping or embedding, exposing it to third parties over a network or API, and hosting or automating it as a service for others are not. Security consultants may use it manually during direct client engagements, provided it isn't left behind, automated, or made available to the client as a platform. See [LICENSE.md](./LICENSE.md).

## Links

- Repository: https://github.com/AlaBouali/ubel
- Issues: https://github.com/AlaBouali/ubel/issues
- Full reference: [DETAILS.md](.https://github.com/AlaBouali/ubel/blob/main/DETAILS.md)