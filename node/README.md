# UBEL — Node.js

**Software supply-chain and source-code security: dependency scanning, an install-time firewall, and AI-powered source-level scanning ( SAST ) .**

UBEL is a zero-dependency, source-available application security toolkit. This package (`@arcane-spark/ubel-node`) ships multiple CLIs for dependency-security and source-level scanner:

- **SCA** — resolves your dependency tree (and, in full-stack mode, other ecosystems present in the repo) and scans it against OSV.dev and NVD, with heuristic reachability analysis, SBOM (CycloneDX v1.6), and SARIF output. This is the audit/reporting side — `health` mode reads what's already installed.
- **Firewall** — a distinct mode of the same CLI (`check` / `install`) that gates the install itself: a lockfile-only dry-run is scanned *before* anything touches `node_modules`, with atomic lockfile revert on violation and SHA-256 TOCTOU checks between scan and install.
- **SAST / Malicious-Code Scanner** — a separate module: an LLM-powered pipeline (**scan → verify → taint-trace**) that reads your actual source code, cross-references a structured CWE-mapped vulnerability catalog, and separately screens for intentionally malicious code (backdoors, C2 beacons, supply-chain implants).

Everything runs on your own infrastructure: no source code egress, no credentials required beyond your chosen LLM provider's API key (SAST only), no telemetry.

---

## Install

```bash
npm install -g @arcane-spark/ubel-node
```

This installs the binaries for both the SCA/firewall CLI and the SAST module:

| Binary | Covers | What it does |
|---|---|---|
| `ubel-npm` / `ubel-pnpm` / `ubel-bun` | SCA + Firewall | Same binary, mode-dependent: `health` = SCA scan of installed deps; `check`/`install` = firewall gate on a lockfile dry-run |
| `ubel-agent` | SCA | AI-agent workspace scan (OS, runtimes, tools, dependencies) |
| `ubel-platform` | SCA | Host platform scan (OS, runtimes, tools) |
| `ubel-sast` | SAST | Static analysis for accidental vulnerabilities (injection, XSS, insecure deserialization, hardcoded secrets, …) |
| `ubel-mal` | SAST | Malicious-code scan for intentional backdoors, C2 implants, exfiltration, persistence |
| `ubel-chunk` | SAST | Free, LLM-cost-free utility to preview how a codebase will be chunked |

Node.js `>=18.0.0` required.

---

## SCA — Dependency Vulnerability Scanning

Resolves dependencies (with PURL generation), scans them against OSV.dev and NVD, and annotates each finding with a heuristic **reachability** verdict (package type, scope, dependency depth, attack vector, and optional source-level import-scan confirmation). Malicious-package advisories (`MAL-*`) are always flagged. Output: JSON, HTML, CycloneDX v1.6 SBOM, and SARIF 2.1.0 reports.

```bash
# Audit the currently installed dependency graph — no install, no lockfile mutation
ubel-npm health
ubel-pnpm health
ubel-bun health
```

`health` mode also supports full-stack monorepo scanning (Python, PHP, Rust, Go, .NET, Java, Ruby alongside Node) and host/platform scanning (Linux package managers, Windows registry) when invoked programmatically.

**yarn** is supported in `health` mode only — it can't do a lockfile-only dry-run, so it has no firewall coverage below.

## Firewall — Install-Time Gate

A distinct mode of the same `ubel-npm` / `ubel-pnpm` / `ubel-bun` binaries: before any real install, a lockfile-only dry-run (`--package-lock-only` / `--lockfile-only`) resolves the candidate tree without touching `node_modules`, scans it, and either proceeds or reverts the lockfile from its on-disk backup. Pre/post-install scripts are always blocked (`--ignore-scripts`) during this phase. A SHA-256 check re-verifies the lockfile and `package.json` immediately before the real install, closing the TOCTOU window between scan and install.

```bash
# Dry-run only — scan and exit, nothing installed
ubel-npm check lodash express

# Scan-gated real install — proceeds only if policy allows
ubel-npm install lodash@4.17.21
```

Policy (severity threshold, unknown-severity blocking) is configurable via `ubel-npm threshold <level>` and `ubel-npm block-unknown <bool>`; malicious-package advisories are always blocked regardless of policy.

**Exit codes:** `check` and `install` exit `0` if policy passes, `1` if policy blocks or the scan itself fails — a failed scan is never treated as a pass.

**Full documentation — every mode, policy config, reachability decision ladder, and programmatic API:**
[**node/sca/README.md**](https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md)

---

## SAST — AI-Powered Static Analysis & Malicious Code Scanner

Chunks your codebase into semantically-bounded units (10 language families) and runs a three-pass LLM pipeline — **scan → verify → taint trace** — cross-referenced against a 46-class CWE-mapped vulnerability catalog. A fully separate 15-class malicious-code catalog covers intentionally planted backdoors and implants; that scan (`ubel-mal`) stops after **scan → verify**, since reachability isn't the relevant question for code that's itself the payload. Outputs JSON, interactive HTML, and SARIF 2.1.0 reports, ready for CI/CD gating.

```bash
# Vulnerability scan
ubel-sast /path/to/project

# Malicious-code / backdoor scan
ubel-mal /path/to/project

# Free preview of how a codebase will be chunked, no LLM calls
ubel-chunk /path/to/project
```

Supports OpenRouter, OpenAI, Anthropic, Gemini, DeepSeek, NVIDIA, local/Docker-hosted (Ollama-compatible), and fully custom endpoints — selectable per run, no code changes.

**Exit codes:** governed by `--fail-on`, which only changes the process exit code — reports on disk always contain every finding regardless of this flag.
- `ubel-sast` (`analyze`): `any` *(default)* fails on any finding, including unresolved ones; `valid` fails only on findings verified `is_valid: true`; `exploitable` fails only on findings taint-traced `exploitable: true`.
- `ubel-mal` (`malware`): `any` *(default)* fails on any finding, including unresolved ones; `confirmed` fails only on findings verified `is_valid: true` — an unresolved finding still fails the build, since "couldn't determine" is never treated as clean.

**Full documentation — pipeline mechanics, every flag, token-cost breakdown, and CI examples:**
[**node/sast/README.md**](https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md)

---

## CI/CD Integration

All binaries exit non-zero on findings that clear their respective gate, so any of the three fit natively into a CI runner:

```yaml
# GitHub Actions
- name: UBEL dependency scan (SCA)
  run: ubel-npm check

- name: UBEL firewall-gated install
  run: ubel-npm install

- name: UBEL SAST scan
  run: ubel-sast --fail-on exploitable

- name: UBEL malicious-code scan
  run: ubel-mal --fail-on confirmed
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-sast --fail-on valid .
```

---

## License

Source-available, internal-use license. Modification for internal needs is permitted; redistribution, wrapping, and hosting as a third-party service are not. See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for full terms, including the consultant-use exception.

For commercial licenses permitting redistribution, hosting, or embedding, contact:
**ala.bouali.1997@gmail.com**

---

## Links

- Repository: https://github.com/AlaBouali/ubel
- Issues: https://github.com/AlaBouali/ubel/issues
- SCA docs: https://github.com/AlaBouali/ubel/blob/main/node/sca/README.md
- SAST docs: https://github.com/AlaBouali/ubel/blob/main/node/sast/README.md

*UBEL — Find the bug before it finds production.*