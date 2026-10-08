# UBEL — Unified Bill / Enforced Law
### Node.js-Packaged Supply-Chain Security CLI

Ubel resolves dependencies, generates PURLs, scans them through [OSV.dev](https://osv.dev) and [NVD](https://nvd.nist.gov/), and enforces configurable security policies at install-time to block supply-chain attacks before they reach production.

This document's core is the `<engine> <mode>` firewall/SCA surface across every ecosystem shipped in the `@arcane-spark/ubel-node` package: **Node.js** (npm, pnpm, bun, yarn), **PHP** (Composer), **Rust** (Cargo), **Python** (pip, uv, pipx, conda), and the **Linux host** (apt, dnf, yum). They share one engine, one policy format, and one report format — the differences are called out inline wherever a given mode, flag, or guarantee doesn't carry over identically across ecosystems. The fixed-configuration and standalone binaries (`ubel-docker`, `ubel-agent`, `ubel-cicd`, `ubel-platform`, `ubel-secrets`, `ubel-license`) are also documented below, each in their own section.

---

## Features

- Full dependency resolution with PURL generation via lockfile dry-run (npm/pnpm/bun/composer) or native dry-run (pip/pipx via `pip install --dry-run --report`; uv via `uv pip install --dry-run`; conda via `conda create --dry-run --json` against a scratch prefix; cargo via `cargo add` + `cargo update --workspace` in a scratch copy of the project; apt/dnf/yum via each manager's own simulate/assume-no flag)
- Querying authoritative vulnerability sources in real time, allowing newly published advisories to be detected immediately without waiting for scheduled database refreshes unlike the competitors.
- OSV.dev vulnerability scanning via batched API queries and NVD's APIs
- Concurrent vulnerability enrichment (CVSS, fix recommendations, references)
- **Exploit intelligence** — every vulnerability is checked against the [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog and scored with [FIRST EPSS](https://www.first.org/epss/); policy blocks KEV entries and anything at or above an EPSS threshold, and a feed outage never aborts the scan (see [Exploit Intelligence](#exploit-intelligence-kev--epss))
- Policy engine — block/allow by severity threshold, unknown-severity packages, CISA KEV membership, EPSS score, and (on `health` scans) license risk
- Malicious package (infection) detection — always blocked regardless of policy
- `check` mode — dry-run resolution and scan with no side effects
- `install` mode — scan-gate before installation; blocks if policy violated
- `health` mode — scan the current project's installed dependencies
- **Pre-commit hook** — `install-hook` / `uninstall-hook` modes wire up the single ubel git pre-commit hook: a secrets scan of the staged changes on every commit, plus a dependency scan (`<engine> health`, no OS scan) on every commit, so a bad change is blocked at `git commit` time rather than after it lands (see [Pre-commit Hook](#pre-commit-hook))
- Atomic lockfile revert — originals are always restored on violation or error (npm/pnpm/bun/composer only — pip/uv/pipx/conda/apt/dnf/yum have no lockfile to revert, and cargo resolves in a scratch copy so the project is never modified before the scan passes; see [Firewall Mechanics](#firewall-mechanics))
- Disk-based lockfile backup under `.ubel/lockfiles/<timestamp>/` with manual recovery on failure (npm/pnpm/bun/composer only)
- Dependency graph with introduced-by and parent tracking (all ecosystems except `uv`- and `conda`-sourced firewall scans, which report a flat package list — see [Firewall Mechanics § uv](#uv) and [§ conda](#conda); Swift and Flutter/Dart lockfiles don't record a dependency graph either, so those packages have no edges)
- Automatic report generation: timestamped **JSON** (`*.json`) + **HTML** (`*.html`) + **SBOM** (`*.cdx.json`) + **SARIF** (`*.sarif.json`) per scan, plus `latest.*` convenience links. For historic tracking, a zipped snapshot of these reports are generated and saved, too.
- Zero external runtime dependencies (Node.js stdlib only)
- Complete compliant, and enriched SBOM Cyclonedx v1.6 files with full dependencies and vulnerabilities data in VEX
- Complete compliant, and enriched SARIF v2.1.0 files
- **Reachability analysis** — each vulnerability is annotated with a heuristic reachability assessment derived from package type, scope, dependency depth, attack vector, and import-scan confirmation for the ecosystems listed under [Import scan coverage](#import-scan-coverage) (see [Reachability Analysis](#reachability-analysis))
- **Secrets detection** — Trivy's ported ruleset plus UBEL's own rules for vendors Trivy's current upstream doesn't cover (see [Secrets Detection](#secrets-detection)), included in every `health`-mode scan by default (never in `check`/`install`) and runnable standalone via `ubel-secrets`
- **License compliance** — every package's declared license is normalized (SPDX expressions, free text, npm's `UNLICENSED` proprietary marker vs. the SPDX `Unlicense` public-domain license, missing/`unknown` values) and checked against the OSI-approved license list, with a derived risk rating; included by default on every `health`-mode scan (see [License Compliance](#license-compliance))
- **Executive summary** — every JSON and HTML report opens with a plain-language overview for non-technical readers: overall risk rating, policy verdict, key numbers, key findings (including weaknesses already exploited in real attacks), the components to fix first, and prioritized recommended actions (see [Executive Summary](#executive-summary))
- **Recommended package-level fixes** — for every package, UBEL works out which versions to upgrade to, grouped per version range (stay on your current minor line, or move to a newer minor/major), picking the fewest and highest versions that clear the most vulnerabilities, and lists whatever has no fix at all (see [Recommended Package Fixes](#recommended-package-fixes))
- **Compliance framework mapping** — every vulnerability and secrets finding is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, with a report-level per-framework/per-control finding-count summary; included by default in every scan, across JSON, HTML, and SARIF (see [Compliance Framework Mapping](#compliance-framework-mapping))

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
| `ubel-composer` | Composer (PHP) |
| `ubel-yarn` | yarn — `health` mode only, no firewall (`check`/`install`) coverage; see note below |
| `ubel-pip` | pip — `health`/`check`/`install`, plus CLI-tool isolation via `ubel-pipx` below |
| `ubel-uv` | uv — same `health`/`check`/`install` shape as `ubel-pip`, driven by `uv` instead; see note below |
| `ubel-conda` | conda — same six modes as `ubel-pip`; `check`/`install` driven by `conda create --dry-run`; see note below and [Firewall Mechanics § conda](#conda) |
| `ubel-cargo` | Cargo (Rust) — `health`/`check`/`install` plus `threshold`/`block-unknown` (no `init`); `check`/`install` resolve in a scratch copy of the project; see note below and [Firewall Mechanics § cargo](#cargo) |
| `ubel-pipx` | pip, CLI-tool isolation mode — installs into a dedicated per-tool venv with a global shim, same idea as upstream `pipx`, now scan-gated |
| `ubel-apt` | apt (Debian/Ubuntu) |
| `ubel-dnf` | dnf (RHEL 8+, AlmaLinux, Rocky) |
| `ubel-yum` | yum (RHEL 7) |
| `ubel-docker` | scan a given docker image's OS and dependencies |
| `ubel-agent` | Fixed-config workspace scan for AI-agent sandboxes — see [Fixed-Configuration Scan CLIs](#fixed-configuration-scan-clis) |
| `ubel-cicd` | Fixed-config post-build scan for CI/CD pipelines — see [Fixed-Configuration Scan CLIs](#fixed-configuration-scan-clis) |
| `ubel-platform` | Fixed-config host/developer-machine scan (OS, runtimes, tools; no app dependencies) — see [Fixed-Configuration Scan CLIs](#fixed-configuration-scan-clis) |
| `ubel-secrets` | standalone secrets-only scan of a directory — see [Secrets Detection](#secrets-detection) |
| `ubel-license` | standalone inventory + license-compliance scan, no OSV/NVD or secrets — see [License Compliance](#license-compliance) |


> **yarn** does not support a lockfile-only dry-run — this is yarn's own CLI design, not a gap in UBEL's implementation: `yarn add` always writes `node_modules` immediately, with no resolution step that stops short of that the way npm/pnpm/bun each have. UBEL supports yarn in `health` scan mode only (via `ubel-yarn health`) and cannot provide install-blocking firewall coverage for it; `ubel-yarn check`/`install` exit non-zero immediately with a clear "not supported" message rather than silently doing nothing. **yarn does support the pre-commit hook** (`ubel-yarn install-hook`) since the hook only needs a `health` scan, which yarn does support.
>
> **composer** gets the same lockfile-backed firewall treatment as npm/pnpm/bun — see [Firewall Mechanics § composer](#composer) — via `composer require`/`update --no-install --no-scripts`, Composer's own equivalent of `--package-lock-only`. It needs the `composer` binary itself on `PATH`, separate from PHP — same one-binary-per-tool requirement as `ubel-pnpm` needing `pnpm`.
>
> **uv** shares `ubel-pip`'s six modes, requirements.txt/pyproject.toml fallback, generated-requirements-file real install, and post-install manifest sync, but its dry-run mechanism is internally different (`uv pip install --dry-run`, not `pip install --dry-run --report`) since uv has no equivalent JSON install report — see [Firewall Mechanics § uv](#uv) for the honest difference this creates (no dependency-graph provenance from uv's resolution).
>
> **conda** shares `ubel-pip`'s six modes and its `check`/`install` shape, but resolves with `conda create --dry-run --json` against a scratch prefix (so `check` creates nothing) and installs the exact scanned builds with `--no-deps`. OSV has no conda ecosystem, so only conda packages that are Python distributions are matched against it (as PyPI packages) — see [Firewall Mechanics § conda](#conda) for exactly what that does and doesn't cover. It needs the `conda` binary itself on `PATH` (or via `$CONDA_EXE`, or in a default install location); `mamba`/`micromamba` aren't driven directly.
>
> **cargo** gates installs by resolving in a **scratch copy of the project** — `cargo add <crate>` (only if packages were given) then `cargo update --workspace`, both of which read the registry index only and never run build scripts — so `check` never modifies your tree. A clean `install` then writes the scanned `Cargo.toml`/`Cargo.lock` and runs `cargo fetch --locked`. Only crates.io crates are matched against vulnerability data; git and alternative-registry dependencies are listed in a warning but not scanned, and `build.rs`/proc-macros still run later at `cargo build`, outside the firewall — see [Firewall Mechanics § cargo](#cargo). It needs the `cargo` binary itself (found via `PATH`, then `$CARGO_HOME/bin`, then `~/.cargo/bin`); there's no `init` mode.
>
> **apt / dnf / yum** are three separate binaries, each bound to exactly one native package manager — there's no auto-detection between them, the same one-binary-per-tool shape as `ubel-npm`/`ubel-pnpm`/`ubel-bun`. Running `ubel-dnf` on a host that only has `apt` fails with a clear "not found on PATH" error rather than silently falling back to a different manager.

---

## Requirements

- Node.js `>=18.0.0`
- The package manager binary being targeted (`npm`, `pnpm`, `bun`, or `composer`) must be available on `PATH`
- `ubel-pip`/`ubel-uv`/`ubel-pipx` additionally need a `python3`/`python` interpreter on `PATH` — Node.js can't provision one itself, it only shells out to it to create/manage the venv
- `ubel-uv` additionally needs the `uv` binary itself on `PATH`, separate from Python — same one-binary-per-tool requirement as `ubel-pnpm` needing `pnpm`
- `ubel-conda` additionally needs the `conda` binary itself — found via `PATH`, then `$CONDA_EXE` (exported by `conda init`'s shell hook), then conda's default install directories (`~/miniconda3`, `~/anaconda3`, `~/miniforge3`, `/opt/conda`, …). It doesn't need a Python interpreter on `PATH`
- `ubel-cargo` additionally needs the `cargo` binary itself (Rust toolchain) — found via `PATH`, then `$CARGO_HOME/bin`, then `~/.cargo/bin` — and cargo ≥ 1.62 when packages are given (`cargo add`). It doesn't need a Python interpreter on `PATH`
- `ubel-apt`/`ubel-dnf`/`ubel-yum` additionally need their specific package manager on `PATH` (each binary targets exactly one — no auto-detection between them) and, for `install` mode only, passwordless-or-prompted `sudo` access; `health`/`check` never need elevated privileges

---

## Environment Variables

| Variable | Default | Effect |
|---|---|---|
| `UBEL_OSV_ENDPOINT` | `https://api.osv.dev` | Overrides the OSV API base used for live vulnerability queries. `/v1/querybatch` and `/v1/vulns/{id}` are appended to whatever base is set, so a mirror must expose the same path shape as the public API. A trailing slash is stripped automatically. |
| `UBEL_NVD_ENDPOINT` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Overrides the NVD CVE API endpoint used for host/platform CPE lookups (`?cpeName=...` is appended as a query string). A trailing slash is stripped automatically. |
| `UBEL_HOOK_STRICT` | unset | When set to `1`, the pre-commit hook **blocks the commit** if a ubel binary cannot be found on `PATH`, instead of warning and letting it through; it also turns the "staged file larger than the scan cap" warning into a failed scan. Useful in locked-down environments where a "tool missing" state should fail closed. |
| `UBEL_HOOK_SCA` | `always` | When the pre-commit hook runs its dependency scan: `always` = on every commit (default), `auto` = only when a manifest/lockfile is staged, `off` = never. The secrets scan is not affected. |
| `UBEL_STAGED_MAX_FILE_MB` | `128` | Per-file cap, in MB of added content, for `ubel-secrets --staged`. Past it the scan of that file stops and a warning is printed (nothing is dropped silently below it). |

Both `UBEL_OSV_ENDPOINT` and `UBEL_NVD_ENDPOINT` are intended for self-hosted or air-gapped deployments — e.g. an internal proxy in front of a local OSV data dump, or a cached/rate-limit-friendly NVD mirror — where UBEL should never reach the public internet to do a live scan. Neither variable changes the "view online" reference links (`osv.dev/vulnerability/{id}`, `nvd.nist.gov/vuln/detail/{id}`) shown per-finding in reports — those stay pointed at the public sites by default, since a private mirror generally doesn't serve an equivalent browsable web UI at the same path. If your mirror does, you can still open the report and follow the link manually; it just isn't rewritten automatically.

If a configured endpoint (or the public API) is unreachable, rate-limited, or returns an error or a malformed response, the scan **fails** (non-zero exit) instead of reporting a clean result — an air-gapped or mirrored deployment therefore needs a mirror that is actually reachable and complete.

Aside from these (and the OS/NVD-name CPE lookups they front), the only other outbound calls UBEL makes during a scan are the two exploit-intelligence lookups — the CISA KEV catalog (`www.cisa.gov`) and the FIRST EPSS API (`api.first.org`) — see [Exploit Intelligence](#exploit-intelligence-kev--epss). Unlike OSV/NVD, these are best-effort: if either is unreachable the scan still completes (and says so), and there is currently no endpoint override for them, so a fully air-gapped deployment runs without KEV/EPSS data. Earlier versions queried a third-party IP-lookup API (ipify) to record the host's public IP in reports; this was removed — it was a network call to an external service on every scan for a display-only field with no other consumer, which cut against the zero-third-party-dependency, fully-local-execution positioning above. (The EASM modules' private/own-address safety guard used the same service and now compares against the machine's own network interfaces instead — also with no network request.) The scan's *local* network interfaces are still recorded (used internally to tag which host a given inventory item's filesystem path came from, useful once reports from multiple hosts/containers get combined) — that information never leaves the machine.

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
ubel-composer <mode> [packages...]
ubel-yarn  health              # health only — check/install unsupported, see below

ubel-pip   <mode> [packages...]        # health | check | install | init | threshold | block-unknown
ubel-uv    <mode> [packages...]        # same six modes, same shape as ubel-pip
ubel-conda <mode> [packages...]        # same six modes; check/install driven by conda
ubel-cargo <mode> [crate[@req]...]     # health | check | install | threshold | block-unknown (no init)
ubel-pipx  <mode> [package]

ubel-apt   <mode> [packages...]        # dnf/yum below take the same shape
ubel-dnf   <mode> [packages...]
ubel-yum   <mode> [packages...]

# Pre-commit hook (any engine except docker and apt/dnf/yum):
ubel-npm   install-hook [--force]      # install the pre-commit hook (secrets scan + dependency scan)
ubel-npm   uninstall-hook              # remove it
ubel-pip   install-hook                # works on pip/pipx/uv/conda/cargo/composer/yarn too

# Any of the above, on health | check | install — one-off policy overrides, nothing saved:
ubel-npm   check [packages...] [--threshold <level>] [--block-unknown [true|false]]
                               [--license-risk <level>] [--license-block-unknown [true|false]]
                               [--block-kev [true|false]] [--epss-threshold <fraction|percent|none>]
```

The policy flags are covered in [Per-run policy flags](#per-run-policy-flags).

Package arguments are optional for `check`/`install` on every engine, but what "omitted" falls back to differs: npm/pnpm/bun/composer use the existing lockfile in the working directory (`composer.lock`/`composer.json` for composer); `ubel-pip`/`ubel-uv` fall back to `./requirements.txt`, then `./pyproject.toml`'s `[project]` dependencies if that's absent too (erroring only if neither is present); `ubel-conda` falls back to `./environment.yml`, then `./environment.yaml` (the `dependencies:` list — see [§ conda](#conda)); `ubel-cargo` uses the project's existing `Cargo.toml`/`Cargo.lock` (see [§ cargo](#cargo)); `ubel-apt`/`ubel-dnf`/`ubel-yum` have no fallback source — packages must be given explicitly. `ubel-pip`/`ubel-uv`/`ubel-conda`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum` also support only six modes (`health`, `check`, `install`, `init`, `threshold`, `block-unknown`) — `license-risk`/`license-block-unknown` are npm-family-only, see [Modes](#modes). `ubel-cargo` supports the same minus `init` (there's no environment to create); `ubel-cargo init` exits with an error rather than falling back to `health`. `install-hook`/`uninstall-hook` are supported on every engine except `docker` and `apt`/`dnf`/`yum`.

---

## Pre-commit Hook

`ubel-<engine> install-hook` writes **the** ubel git pre-commit hook into the current repository's hooks directory (respecting `core.hooksPath` and worktrees). It is one script that runs two scans:

1. **Secrets** — `ubel-secrets --staged`, on **every** commit.
2. **Dependencies** — `<engine> health` — a **dependency scan only**, never the OS scanner — on every commit (`UBEL_HOOK_SCA=auto` limits it to commits that stage a manifest or lockfile).

It blocks the commit on a non-zero exit from either. `ubel-<engine> uninstall-hook` (or `ubel-secrets --uninstall-hook`) removes it again.

`ubel-secrets --install-hook` writes the same hook. Each installer sets its own step and keeps the other's, so you can run both, in either order, **without `--force`** — you end up with one hook that has both steps. (The secrets step is always present; the dependency step exists once an engine has run `install-hook`.)

```bash
# Install the pre-commit hook (refuses if someone else's hook already exists)
ubel-npm install-hook

# Chain to an existing hook instead of refusing
ubel-npm install-hook --force

# Remove it again
ubel-npm uninstall-hook

# Same, from any supported engine
ubel-pnpm install-hook
ubel-composer install-hook
ubel-pip install-hook
ubel-uv install-hook
ubel-cargo install-hook
```

### What the hook does — and, importantly, what it doesn't

- **Dependency scan only, no OS scan.** The hook runs `<engine> health`, whose CLI path forces `scan_os: false`. It never touches the host's package database.
- **Both steps run on every commit.** The secrets step always runs. The dependency step runs on every commit too, once an engine has run `install-hook`. If a full `health` scan is too slow for your repo, set `UBEL_HOOK_SCA=auto` to run it only when a dependency file is staged (the hook lists the staged paths with `git -c core.quotepath=off diff --cached --name-only -z`, so paths with non-ASCII characters match, and looks for a manifest/lockfile anywhere in the tree: `package.json`, `package-lock.json`, `npm-shrinkwrap.json`, `pnpm-lock.yaml`, `bun.lock(b)`, `yarn.lock`, `composer.json`/`.lock`, `requirements*.txt`/`.in` (including `requirements_dev.txt` and anything under `requirements/`), `constraints*.txt`, `pyproject.toml`, `Pipfile(.lock)`, `setup.py`/`.cfg`, `poetry.lock`, `uv.lock`, `pdm.lock`, `conda-lock.yml`, `environment.yml`/`.yaml`, `Cargo.toml`/`.lock`, `go.mod`/`.sum`/`.work`, `pom.xml`, `build.gradle(.kts)`, `gradle.lockfile`, `libs.versions.toml`, `Gemfile(.lock)`, `Package.swift`/`.resolved`, `Cartfile(.resolved)`, `Podfile(.lock)`, `pubspec.yaml`/`.lock`, `packages.config`, `packages.lock.json`, `Directory.Packages.props`, `*.csproj`), or `UBEL_HOOK_SCA=off` to skip it.
- **Exit codes are told apart.** A dependency policy violation (exit `1`) prints "dependency policy violation"; a scan that did not complete — OSV unreachable, a crash — exits `2` and prints "scan did not complete". Both block the commit.
- **No lockfile mutation.** It's a `health` scan, not a `check` scan — nothing is dry-run, no lockfile is written or reverted. A broken scan can never leave the working tree half-mutated.
- **`health` scans the *installed* dependency graph**, so it catches what's currently on disk. If you've staged a `package.json` change but haven't yet run `install`, the new (potentially vulnerable) dependency won't be in the installed tree yet — the hook still runs, but it's scanning the previous state. For the fully accurate check of the *staged* dependency graph, run `ubel-<engine> check` yourself or in CI.
- **Chainable.** `--force` moves an existing foreign pre-commit hook to `pre-commit.local` and runs it *after* both scans pass. `uninstall-hook` moves it back. The hook never chains to itself.
- **Portable installs.** If the hooks directory is a committed `.githooks/` or husky-style path outside the git dir, the hook is written without any machine-specific absolute paths — it just finds `ubel-secrets` and `ubel-<engine>` on `PATH`, so it's safe to commit and share. Everyone on the team then needs it installed.
- **Fail-open for "tool missing", fail-closed for "tool failing".** If a ubel binary can't be found, the hook warns loudly on stderr and lets the commit through — set `UBEL_HOOK_STRICT=1` to block instead. If the binary runs and exits non-zero, the commit is always blocked: a broken scan must not look like a clean one.
- **Bypass once with `git commit --no-verify`.** Hooks are client-side, so this is also a reason to run the same scan in CI (see [CI/CD Integration](#cicd-integration)).

### Upgrading from the two-hook layout

Earlier versions installed the secrets hook and the dependency hook as two separate scripts that had to be combined with `--force`. That combination was broken: both scripts chained to `pre-commit.local`, which — once a hook had been moved there — is the script itself, so a manifest commit looped forever, and the dependency script exited before reaching the chain when no manifest was staged, so the secrets hook never ran on most commits. If you have that layout, run `ubel-secrets --install-hook` or `ubel-<engine> install-hook` again: both old scripts (including the one at `pre-commit.local`) are merged into the single hook and the stale `pre-commit.local` is removed. A foreign hook of your own is never touched without `--force`.

### Files the hook writes

- The hook itself, at `<hooks-dir>/pre-commit`.
- A chained foreign hook, at `<hooks-dir>/pre-commit.local` (only when `--force` was used and there was a foreign hook).
- Nothing else. Reports still go to the usual `<project>/.ubel/local/reports/...` path when the hook actually runs a scan that produces one.

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

### composer

`ubel-composer check` and `ubel-composer install <vendor/package>` invoke `composer require`/`update --no-install --no-scripts`, Composer's own equivalent of npm's `--package-lock-only` — it resolves the full dependency tree and writes a candidate `composer.lock` (and, for `require`, an updated `composer.json` with the requested constraint) without touching `vendor/`. UBEL scans the candidate lockfile, then makes the same binary decision as npm/pnpm/bun:

- **Clean** — the candidate lockfile is accepted and the actual install proceeds via `composer install --no-scripts`.
- **Violation** — `composer.json`/`composer.lock` are reverted to their pre-scan state from the disk backup. `vendor/` is never touched. The process exits non-zero.

Unlike pip/apt/dnf/yum, this dry-run has no equivalent side-effect caveat: resolving a Composer dependency graph never runs a package's own code — build/lifecycle scripts (`scripts.pre-install-cmd`, `post-install-cmd`, etc., declared in `composer.json`) only fire on an actual `composer install`/`update`, which is why `--no-scripts` is passed on both the dry-run and the real install (same reasoning as npm's `--ignore-scripts` — see below). If no `composer.json` exists yet, UBEL writes a minimal one (`{"name": "ubel/scan-temp", "type": "project"}`) rather than shelling out to `composer init`, since non-interactive `init` behavior isn't consistent across Composer versions.

### docker

`ubel-docker` scans a container image **without ever running it** – it creates a stopped container (`docker create`), exports its filesystem, and extracts the tar in‑process (no shell `tar`). This blocks path‑traversal attacks and never executes `ENTRYPOINT`/`CMD` or any scripts. The scan automatically includes OS packages (`scan_os: true`) and all application dependencies (`full_stack: true`).

```bash
ubel-docker <health|check|install> <image|tar-path> [--no-pull] [--keep]
```

Modes:
- `health` — scan only, image left exactly as found.
- `check` — scan, then always remove the image afterward.
- `install` — scan, then remove the image only if the scan results in a policy block; a clean scan leaves it in place.

Flags:
- `--no-pull` — scan an image that only exists locally (e.g. right after `docker build`, before it's pushed); skips `docker pull`.
- `--keep` — skip cleanup of the extracted rootfs afterward, for debugging.

In place of an image reference, `<image|tar-path>` also accepts a path to a local, uncompressed `.tar` file (e.g. from a prior `docker save`/`docker export`, or a CI artifact) — detected automatically by a `.tar` extension that resolves to an existing file. That skips `docker pull`/`docker create`/`docker export` entirely and extracts the given tar directly; `--no-pull` is a no-op in that case, and `check`/`install` won't attempt `docker rmi` since there's no pulled image to remove. Compressed tarballs (`.tar.gz`/`.tgz`) aren't supported — decompress first.

```bash
# Scan a base image before it's ever run
ubel-docker health node:20-alpine

# Pull, scan, and keep or remove based on policy
ubel-docker install node:20-alpine

# Scan a locally-built image without pulling
ubel-docker check myapp:latest --no-pull

# Scan a tar artifact from CI (e.g. docker save output) directly
ubel-docker health ./myapp-image.tar
```

### pip

`ubel-pip check` and `ubel-pip install <pkg>` invoke `pip install --dry-run --report <path>` (pip ≥22.2), which resolves the full candidate set — including transitive dependencies and their declared licenses — into a JSON report without installing anything. UBEL scans that report, then makes the same binary decision as the lockfile-based engines:

- **Clean** — the real install proceeds via `pip install -r <generated requirements file>` inside the target venv.
- **Violation** — the real install never runs. There's no lockfile to revert, so there's no revert step — a blocked scan simply means nothing happened.

Every `ubel-pip` invocation targets a venv: `<projectRoot>/venv` by default, or `ubel-pip init` (which also runs implicitly the first time `check`/`install` needs one) to provision it explicitly at a custom path. `check`/`install` accept packages on the command line, or fall back to `./requirements.txt`, then `./pyproject.toml`'s `[project]` dependencies if that's absent too. Either fallback source is just parsed into the same flat list of specifier strings fed into the dry-run above — a `pyproject.toml`-sourced check/install is never run as `pip install .`/`-e .` against the project itself, and the real install always goes through the same generated, exact-pinned requirements file either way (see the **Violation**/**Clean** decision above). Only the standard PEP 621 `[project]` table is read — Poetry's legacy `[tool.poetry.dependencies]` table uses a different, non-PEP-508 syntax and isn't parsed, and `[project.optional-dependencies]` (extras) are deliberately excluded, matching what a plain `pip install .` would resolve by default.

A successful **Clean** install additionally syncs whichever of `requirements.txt`/`pyproject.toml` already exists in the project directory to match what's now actually installed — this reuses the same `.dist-info` scan `health` mode already does (not a separate `pip freeze` shell-out), filtered to the venv's Python packages. For each file: an existing entry whose name matches an installed package gets its pin rewritten to the installed version; anything installed but not yet listed gets appended; comments, blank lines, and directives (`-r`/`-e`/`-c`/`--index-url` in requirements.txt, any table other than `[project].dependencies` in pyproject.toml) are left untouched. Neither file is created if it doesn't already exist, and a sync failure is logged rather than failing the install, since the install itself already succeeded by that point. One asymmetry worth knowing: pip's own bootstrap packages (`pip`, and on some Python versions `setuptools`) live inside a stdlib-created venv the same as anything else installed into it, so they can show up in a synced `requirements.txt` too — `uv venv`-created venvs don't have this since uv doesn't bundle pip into the venvs it creates (see the uv section below).

**One honesty note, unlike npm's (or composer's) lockfile dry-run — a limit of Python packaging itself, not of UBEL's implementation:** resolving a package's metadata during `pip install --dry-run` can require building an sdist when no pre-built wheel is available for the current platform, and building an sdist can execute arbitrary `setup.py`/build-backend code. A wheel-only install has no such gap; a source-only dependency does. This is a real, if narrow, difference from npm/pnpm/bun/composer's guarantee, and it's inherent to how pip resolves packages — not something UBEL's scan step can close.

### uv

`ubel-uv` is `ubel-pip`'s sibling — same six modes, same requirements.txt/pyproject.toml fallback, same post-install manifest sync — driven by [uv](https://docs.astral.sh/uv/) instead of pip. It's implemented differently internally, though, for reasons worth explaining rather than glossing over.

`ubel-uv` uses `uv pip install --dry-run`: confirmed by testing directly against uv 0.11.7, it writes a flat `+ name==version` list to **stderr**, with no dependency relationships between packages, and — like pip's own `--dry-run --report` — it only reports what would *change*, so a fully-satisfied target prints nothing at all. That last part is a non-issue in practice here specifically because `ubel-uv` always runs this against a venv it just created/reused via `initUvVenv()` (see below), never one with unrelated packages already sitting in it, so every requested package and its transitive dependencies reliably show up as `+` lines. What doesn't come back, unlike `pip`'s report or the dependency-annotated resolution an earlier version of `ubel-uv` used (`uv pip compile`, which this replaced): any parent/child relationship between packages. Every uv-resolved component is reported as its own root — see the honesty note below for exactly what that costs downstream.

Venv provisioning is uv-native too, unlike every other engine here: `ubel-uv init` (and the first `check`/`install` that needs a venv) runs `uv init --bare` followed by `uv venv`, rather than the stdlib `venv` module `ubel-pip`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum` all use. `--bare` keeps this from scaffolding a `README.md`/`main.py`/`.python-version` or running `git init` into what's very often the caller's actual project root — it writes only the minimal `pyproject.toml` uv needs to recognize the directory as a project. Both steps are skipped if already done (an existing `pyproject.toml`, an existing venv), so this is safe to call repeatedly.

- **Clean** — the real install proceeds via `uv pip install -r <generated requirements file>` inside the target venv — the exact same generated file `ubel-pip` would produce for the same resolved set, just installed with `uv` instead of `pip -m pip`. Same post-install sync as `ubel-pip` afterward, too — see [`install`](#install).
- **Violation** — same as pip: the real install never runs, nothing to revert.

One difference from `ubel-pip` is worth knowing about, and it's a consequence of what `uv`'s own dry-run output does and doesn't expose, not an implementation choice UBEL made: `uv pip install --dry-run`'s output is a flat `+ name==version` list rather than a dependency-annotated report, so it carries no parent/child relationships — every uv-resolved component comes back as its own root, with empty `introduced_by`/`parents`/`dependency_sequences`, unlike a pip-sourced scan (pip's `--dry-run --report` includes that provenance; uv's dry-run output simply doesn't carry it, so there's no report UBEL could parse it out of even if it wanted to). Vulnerability scanning is unaffected — that's purl-based, not graph-based — but dependency-provenance detail specifically is sparser from `ubel-uv` than from `ubel-pip` today. (License data is a separate question and not a `uv`-specific gap either way: license classification only ever runs on `health`-mode scans for every ecosystem, `uv` included — see [License Compliance](#license-compliance) — so it's not something a `check`/`install` dry-run needs from any installer, `uv`'s or otherwise.)

Same sdist-build caveat as pip applies here too, for the same reason: resolving a source-only package's metadata can still require building an sdist — that's inherent to how Python packaging resolution works generally, not specific to either tool's implementation, and not something a scan step layered on top of `pip`/`uv` could close off.

`uv` itself must be on `PATH`, separately from the `python3`/`python` interpreter that pip's stdlib-venv engines use — `ubel-uv` doesn't install or manage `uv`, only shells out to it. If `uv --version` isn't reachable as a bare command (a common gap: an installer that only updated PATH via a shell rc file `spawnSync` never sources), `ubel-uv` falls back through uv's own documented default install locations (`~/.local/bin`, `~/.cargo/bin`, Homebrew's prefixes, and the Windows equivalents) before reporting it as missing.

### pipx

`ubel-pipx install <pkg>` runs the same `--dry-run --report` scan against a fresh, isolated venv created specifically for that one CLI tool (mirroring what upstream `pipx` does), then — if clean — installs the tool into that venv and writes a shim on `PATH` (`~/.ubel/bin` by default) so the tool is runnable globally without polluting any project's own environment. `ubel-pipx check <pkg>` runs the same dry-run scan without installing. There's no `uv tool install`-equivalent CLI isolation mode here — `ubel-pipx` is pip-only.

```bash
ubel-pip check requests==2.31.0
ubel-pip install requests==2.31.0
ubel-pip install                       # falls back to ./requirements.txt, then ./pyproject.toml

ubel-uv check requests==2.31.0
ubel-uv install requests==2.31.0       # same fallback and generated-requirements-file install as ubel-pip

ubel-pipx check black
ubel-pipx install black                # installs into an isolated venv + global shim
```

### conda

`ubel-conda check` and `ubel-conda install <spec>` resolve the full package set with `conda create --dry-run --json` against a **scratch prefix that never exists** — conda fetches repodata and runs its solver, but downloads and links nothing. UBEL scans the resolved set, then makes the same binary decision as the other Python engines:

- **Clean** — the real install runs `conda create --no-deps --no-default-packages --file <specs>` into `<projectRoot>/conda-env` (or `conda install --no-deps --file <specs>` if that environment already exists). `create` is never run against an existing environment, because `conda create --yes` removes one first; a non-empty directory that isn't a conda environment is refused outright.
- **Violation** — the real install never runs. There's no lockfile to revert, and since the dry-run only ever touched the scratch prefix, `check` leaves no environment behind either.

Why this is built differently from `ubel-pip`:

- **Full closure, every time.** pip's and uv's dry-runs only report what would *change* in the target venv; a dry-run against a scratch prefix always reports everything the specs resolve to, whatever is already installed.
- **The scanned set is the installed set.** The resolved packages are written to `.ubel/dependencies/conda-specs.txt` as exact `channel::name==version=build` pins, and `--no-deps` stops the solver adding anything that wasn't scanned — if a pin can't be satisfied the install fails rather than substituting. The file's SHA-256 is recorded when it's written and re-checked immediately before conda runs; a mismatch aborts the install.
- **Channels come from conda's own configuration** (`.condarc`, `CONDARC`, `CONDA_*` variables) — UBEL doesn't add or override any. Option-shaped arguments (`-c …`), paths, URLs, and bare package-file names (`x.conda`, `x.tar.bz2`) are rejected before conda is invoked, so a specifier can't smuggle in a channel or install a file from disk. Which channels you trust remains your decision in `.condarc`.

```bash
ubel-conda check numpy=1.26 conda-forge::scipy
ubel-conda install numpy=1.26         # scan-gated; creates ./conda-env if it doesn't exist
ubel-conda install                    # no args → ./environment.yml, then ./environment.yaml
ubel-conda init                       # optional: create an empty ./conda-env up front
```

**What is and isn't matched against vulnerability data — read this before relying on it.** OSV has no conda ecosystem. UBEL treats a conda package as a Python distribution when its build string carries conda's `py` marker (`py311h…`, `pyh…`, `py_0`, `cpu_…_py311h…` — the convention used by both conda-forge and `defaults`) and reports it as `pkg:pypi/<name>@<version>`, so it's matched against PyPI advisories like any other Python package. A small built-in map covers names that differ from PyPI (`pytorch`→`torch`, `matplotlib-base`→`matplotlib`, …); a package whose conda name differs and isn't in that map is simply not matched (a missed finding, never a wrong one). Everything else — `openssl`, `libxml2`, `python` itself, … — is inventoried as `pkg:conda/<name>@<version>` and **is not matched against any database**. Those components stay in the `undetermined` state in the report rather than being marked `safe`, the `inventory_stats` summary counts them as `undetermined` (not `safe`), and every conda scan that contains any prints a warning with how many packages were left unmatched — a clean result therefore means "nothing found in the packages that could be checked", not "the whole environment is clean".

Other differences worth knowing:

- Like `ubel-uv`, conda's dry-run JSON carries no dependency edges, so every component is its own root (empty `introduced_by`/`parents`). Vulnerability scanning is unaffected — it's purl-based — but dependency provenance is sparser than from `ubel-pip`.
- `license` is `unknown` on `check`/`install` (the dry-run exposes no metadata beyond name/version/build); license classification only ever runs on `health` scans anyway.
- No manifest sync after a clean install: unlike `ubel-pip`/`ubel-uv`, nothing is written to `requirements.txt`, `pyproject.toml`, or `environment.yml`.
- `environment.yml` fallback reads the flat `dependencies:` list only. A nested `- pip:` block is skipped (those packages are installed by pip, outside this firewall — scan them with `ubel-pip`) and `channels:` is ignored (conda's configured channels apply); both are reported when present.
- `ubel-conda health` finds conda environments by their `conda-meta/` directory (including each environment under a conda base install's `envs/`) and inventories the Python packages inside them via the same `.dist-info`/`.egg-info` scan as `ubel-pip health`. Native conda packages aren't part of the `health` inventory.

### cargo

`ubel-cargo check` and `ubel-cargo install [crate[@req] ...]` resolve in a **scratch copy of the project**: UBEL copies it (minus `target/`, `.git/`, `node_modules/` and `.ubel/`) to a temp directory, runs `cargo add <specs>` there when packages were given, then `cargo update --workspace`. `--workspace` leaves every crate already in `Cargo.lock` where it is and only resolves what's missing, so the scanned set is your existing lockfile plus exactly what was added. Both commands read the registry index only — they download no crate sources and never run `build.rs` or proc-macros. UBEL scans the resulting `Cargo.lock`, then makes the same binary decision as the other engines:

- **Clean** — the scanned `Cargo.toml` (only if packages were added) and `Cargo.lock` are written into the project, then `cargo fetch --locked` runs. If the fetch fails, the original files are put back.
- **Violation** — nothing is written. The project was never modified, so there's nothing to revert; `check` never touches it either, even if the process is killed mid-scan.

Why this is built the way it is:

- **The scanned set is the fetched set.** `--locked` makes cargo fail instead of resolving anything that wasn't scanned. With no arguments the scanned set is the project's current `Cargo.lock` (generated in the copy if there isn't one).
- **Integrity.** The SHA-256 of the scanned files is recorded and re-checked immediately before they're written, and the project's own `Cargo.toml`/`Cargo.lock` are re-checked too — if either changed while the scan ran, the install aborts and you re-run.
- **`install` fetches; it doesn't build.** It leaves your project with the scanned manifest/lockfile and cargo's registry cache populated. `cargo build --locked` is still yours to run.
- Specifiers are `name` or `name@requirement` only; options, paths, URLs, spaces and git/registry sources are rejected before cargo is invoked.

```bash
ubel-cargo check serde@1 tokio
ubel-cargo install serde@1            # scan-gated; updates Cargo.toml/Cargo.lock, then cargo fetch --locked
ubel-cargo install                    # no args → scans ./Cargo.toml + ./Cargo.lock, then cargo fetch --locked
ubel-cargo health                     # SCA scan of Cargo.lock(s), unchanged from before
```

**What is and isn't scanned — read this before relying on it.** Only crates from crates.io are put in the inventory and matched against OSV (RustSec advisories). Workspace members and path dependencies are your own code and are left out. **Git dependencies and alternative registries are not scanned**: they're named in a warning on every run and the install is not blocked because of them. Resolving a git dependency clones the repository (nothing from it is executed).

Other differences worth knowing:

- **Build scripts aren't gated.** `cargo fetch` only populates the registry cache; `build.rs` and proc-macros execute later, at `cargo build`. What the firewall guarantees is that only the scanned crate versions are fetched — not that they're inert.
- Run it from a standalone package or a workspace root. A member of a parent workspace is refused, because the copy would resolve against a different lockfile than cargo uses in place. Path dependencies outside the project root can't be resolved in the copy, so the dry-run fails (closed) with cargo's own error.
- `license` is `unknown` on `check`/`install`; license classification only ever runs on `health` scans.
- Dependency edges come from `Cargo.lock`, so `introduced_by`/`parents` are populated (unlike `ubel-uv`/`ubel-conda`).
- **Scopes** (`prod` / `dev` / `build`) come from `Cargo.toml`: `[dependencies]`, `[dev-dependencies]` and `[build-dependencies]`, written inline (`foo = "1"`), dotted (`foo.version = "1"`) or as a table (`[dev-dependencies.foo]`), including `[target.'cfg(…)'.…]` sections and renamed crates (`package = "real-name"`). The root manifest and every workspace member named in `[workspace] members` (minus `exclude`; `*` and `?` wildcards work within a path segment, `**` does not) are read. `[workspace.dependencies]` only declares versions, so it's skipped — what a member actually uses is taken from the member's own manifest. Scopes then propagate down `Cargo.lock` edges. This is a minimal TOML reader, not a full parser: a crate it can't attribute to any section defaults to `prod`, so an unusual manifest layout errs towards treating a dependency as production rather than hiding it.
- `cargo install <binary-crate>` isn't covered — only a project's dependencies are gated.
- Adding packages needs cargo ≥ 1.62 (`cargo add`).

### apt / dnf / yum

Three separate binaries, one per native package manager, no auto-detection between them. Each invokes that manager's own simulate/dry-run flag to resolve what *would* be installed — including exact resolved versions — without installing anything:

| Binary | Package manager | Dry-run command |
|---|---|---|
| `ubel-apt` | apt (Debian/Ubuntu) | `apt-get -s --no-install-recommends install <pkgs>` |
| `ubel-dnf` | dnf (RHEL 8+, AlmaLinux, Rocky) | `dnf install --assumeno <pkgs>` |
| `ubel-yum` | yum (RHEL 7) | `yum install --assumeno <pkgs>` |

UBEL parses the simulated-install output into the same PURL-tagged inventory shape used everywhere else, scans it, and only then runs the real install: `sudo <apt|dnf|yum> install -y <pkgs>`. As with pip, there's no lockfile, so a blocked scan just means the real install never runs. Unlike pip, this dry-run has no equivalent side-effect caveat — none of the three package managers execute arbitrary code to resolve a simulated install.

Reports and policy for all three live under `~/.ubel/local/{reports,policy}` rather than under the target project — there's no "project" for host-level OS packages, and keeping output under `$HOME` means routine `health`/`check` use never needs elevated privileges; only the real `sudo ... install` step does.

```bash
ubel-apt check curl
ubel-apt install curl
# ubel-dnf / ubel-yum take the same arguments against their own package manager
```

### UBEL's firewall always blocks pre/post install scripts to prevent running malicious scripts

npm/pnpm/bun/composer-specific: npm/pnpm/bun are triggered with the flag `--ignore-scripts`; composer with `--no-scripts` (Composer's own name for the same opt-out) — every dry-run *and* real-install invocation across all four passes it. pip/apt/dnf/yum don't have an equivalent opt-out flag for this document to invoke, because their dry-run modes don't run install-time lifecycle scripts to begin with — apt/dnf/yum's simulate flags never execute package maintainer scripts, and pip's `--dry-run` doesn't run a package's own `post_install` hooks (the sdist-build caveat above is a distinct, narrower concern: build-backend code, not install-time scripts).

conda is the one engine where the real install is *not* script-free: `conda create --dry-run` only solves and never links a package, but the real install runs each conda package's own pre/post-link scripts, and UBEL passes no flag to suppress them. What the conda firewall guarantees is that only the exact scanned builds are installed (exact pins plus `--no-deps`) — not that those packages' install-time scripts are inert.

cargo's real install (`cargo fetch --locked`) is script-free too, but for a narrower reason: it only populates the registry cache, and `build.rs`/proc-macros run later at `cargo build`, which this firewall doesn't gate. See [§ cargo](#cargo).

### Lockfile backup and recovery

npm/pnpm/bun/composer-specific — pip/apt/dnf/yum have no lockfile, so there's nothing to back up or recover here; see their sections above for what "clean vs. violation" means for them instead.

Before any dry-run mutation, originals are backed up to `.ubel/lockfiles/<timestamp>/` (composer backs up both `composer.json` and `composer.lock` there, same as npm backs up `package.json`/`package-lock.json`). If the revert itself fails (e.g. a disk error mid-restore), the original lockfile is preserved at the backup path and its location is printed to stderr so the user can recover manually.

### TOCTOU integrity protection

npm/pnpm/bun/composer-specific, for the same reason as the backup/recovery section above — TOCTOU hashing exists to protect a *lockfile* between scan and install, and pip/apt/dnf/yum's revert-less design (nothing written to disk to gate on until the real install itself runs) doesn't have that window to close in the first place.

After the dry-run completes and the scan passes policy, there is a window between the scan decision and the real install during which the on-disk lockfile or manifest could be mutated — by another process, a racing script, or a compromised tool. UBEL closes this window with SHA-256 integrity checks before any real install is allowed to proceed.

At the end of every dry-run, UBEL captures two digests in memory:

- **`_candidateLockfileHash`** — SHA-256 of the raw candidate lockfile bytes written to disk by the dry-run (`package-lock.json`, `pnpm-lock.yaml`, `bun.lock`, or `composer.lock`).
- **`_candidatePackageJsonHash`** (`_candidateComposerJsonHash` for composer) — SHA-256 of `package.json`/`composer.json` as it exists on disk after the dry-run. For npm, this digest is re-captured after UBEL regenerates `package.json` with exact pinned versions from the lockfile, so the hash always reflects the file that will be present at install time; for composer, `composer require`/`update` already wrote the resolved constraint directly, so no separate reconciliation step is needed before the digest is taken.

Immediately before invoking the real install command (`npm ci`, `pnpm install --frozen-lockfile`, `bun install --frozen-lockfile`, `composer install --no-scripts`), both files are re-hashed from disk and compared against the in-memory digests. If either hash does not match, the install is aborted and the lockfile is reverted — nothing is written to `node_modules/`/`vendor/`. The mismatch details (expected hash, actual hash, file path) are printed to stderr.

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

Scans the current project's installed dependency graph without running any install. For npm/pnpm/bun/yarn/composer this reads the existing lockfile directly (`composer.lock` for composer); `ubel-pip` walks the target venv directly instead (see [Full-stack monorepo scanning](#full-stack-monorepo-scanning) below); `ubel-apt`/`ubel-dnf`/`ubel-yum` read the host's own package database. All of them submit the resolved packages to OSV.dev and NVD's APIs (or your configured mirrors — see [Environment Variables](#environment-variables)).

This is also the mode the [pre-commit hook](#pre-commit-hook) runs — dependency scan only, no OS scan.

```bash
ubel-npm health
ubel-pnpm health
ubel-bun health
ubel-composer health
ubel-yarn health

ubel-pip health
ubel-apt health   # ubel-dnf / ubel-yum health work the same way
```

#### Full-stack monorepo scanning

When invoked programmatically with `full_stack: true`, `health` walks the entire directory tree from the project root and collects packages across all supported ecosystems in a single pass — no per-language configuration required. Mixed-stack monorepos (e.g. a Node.js frontend, Python backend, Rust service, Go tooling, and a Flutter or Swift mobile app in the same repo) are fully covered in one invocation.

| Ecosystem | Package Manager | Resolved From |
|---|---|---|
| Node.js | npm, pnpm, yarn, bun | `node_modules/` (on-disk walk) |
| Python | pip / virtualenv | `.venv`, `venv`, virtualenv directories |
| PHP | Composer | `vendor/`, `composer.lock` |
| Rust | Cargo | `Cargo.lock` |
| Go | Go Modules | `go.sum` |
| C# / .NET | NuGet | `packages.lock.json` / `obj/project.assets.json` |
| Java | Maven | `pom.xml` resolved dependencies |
| Ruby | Bundler | `Gemfile.lock` |
| Swift | SwiftPM, Carthage | `Package.resolved` (also inside `.xcworkspace` / `.xcodeproj`), `.build/workspace-state.json` fallback, `Cartfile.resolved` |
| Flutter / Dart | pub | `pubspec.lock`, falling back to `.dart_tool/package_config.json` |

Each discovered package is deduplicated by PURL before submission, so packages shared across sub-projects are scanned exactly once.

**Swift and Flutter/Dart notes.** PURLs are `pkg:swift/<host>/<owner>/<repo>@<version>` (OSV ecosystem `SwiftURL`) and `pkg:pub/<name>@<version>`, with `?repository_url=` / `?vcs_url=` qualifiers on pub packages from a non-pub.dev registry or a git repository. Local packages (SwiftPM `fileSystem` / `localSourceControl`, pub `path`) and pub `sdk` packages are skipped, and CocoaPods (`Podfile.lock`) is intentionally not scanned because OSV has no CocoaPods ecosystem. A SwiftPM pin on a branch or bare commit is inventoried with an empty version and dropped from OSV queries. Scopes: Swift lockfiles carry no dev/prod signal, so every Swift package is `prod`; for pub, `direct dev` → `dev` and everything else → `prod` (a transitive dependency's origin isn't recorded), and the `package_config.json` fallback reports `prod`. Neither lockfile records a dependency graph or license data, so these packages have no introduced-by/parent edges and their license is `unknown`. Neither ecosystem has firewall (`check` / `install`).

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

Each component is reported with its actual license or vendor EULA (see [License Compliance](#license-compliance)) — proprietary Microsoft/vendor components (Windows itself, Defender, Edge, VS Code/Visual Studio IDE, Chrome, Docker Desktop, Cursor, Claude Code) resolve to a `LicenseRef-*` identifier rather than `unknown`; open-source runtimes and tools resolve to their real SPDX id (e.g. `MIT` for Node.js/.NET, `PSF-2.0` for Python, `GPL-2.0-only WITH Classpath-exception-2.0` for JRE/JDK).

---

### `check`

Dry-run: resolves the given packages (or, for npm/pnpm/bun/composer, the existing lockfile) via each ecosystem's own dry-run mechanism, scans the resolved set, and exits. Nothing is installed; npm/pnpm/bun/composer's lockfiles are fully reverted to their original state afterwards (pip/uv/apt/dnf/yum have no lockfile to revert — see [Firewall Mechanics](#firewall-mechanics)).

```bash
# Scan specific packages without installing
ubel-npm check lodash express

# Scan the current lockfile with no changes
ubel-npm check

# PHP: scan a specific package, or the existing composer.lock with no changes
ubel-composer check monolog/monolog
ubel-composer check

# Python and Linux equivalents
ubel-pip check requests==2.31.0
ubel-uv check requests==2.31.0
ubel-conda check numpy=1.26
ubel-apt check curl
```

Exits `0` if policy passes, `1` if policy blocks or the scan fails.

---

### `install`

Same pipeline as `check`, but proceeds to install if and only if the policy decision is **allow** — via `npm ci` / `pnpm install --frozen-lockfile` / `bun install` for the npm family, `composer install --no-scripts` for composer, `pip install -r <requirements>` / `uv pip install -r <requirements>` for pip/uv (the same generated file either way), `conda create|install --no-deps --file <exact-pinned specs>` for conda, or `sudo <apt|dnf|yum> install -y` for the Linux host binaries.

```bash
ubel-npm install lodash@4.17.21 express
ubel-npm install                          # resolves from existing lockfile

ubel-pnpm install react react-dom
ubel-bun install

ubel-composer install monolog/monolog:^3.0
ubel-composer install                     # resolves from existing composer.lock

ubel-pip install requests==2.31.0
ubel-pip install                          # resolves from ./requirements.txt
ubel-uv install requests==2.31.0          # same fallback and generated-file install as ubel-pip
ubel-pipx install black                   # isolated venv + global shim

ubel-apt install curl                     # ubel-dnf / ubel-yum work the same way
```

If the policy blocks, installation is aborted and the process exits `1`. For npm/pnpm/bun/composer the lockfile is also reverted; pip/uv/apt/dnf/yum have nothing to revert — the real install command simply never runs.

---

### `init`

A no-op on npm/pnpm/bun/yarn/composer (nothing to provision — a lockfile is created lazily by the package manager itself on first `check`/`install`; for composer, a minimal `composer.json` is likewise created lazily on first `check`/`install` if one doesn't already exist — see [Firewall Mechanics § composer](#composer)). On `ubel-pip`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum`, it provisions a stdlib `venv` at `<projectRoot>/venv` (or wherever `venvDir` is set programmatically) and exits — this happens **regardless of which of those five binaries you run**, including the Linux ones, since venv provisioning is shared, generic setup rather than something specific to any one package manager. `ubel-uv init` is the one exception: it provisions the venv via uv's own `uv init --bare` + `uv venv` instead, so the result is a project uv itself recognizes (`pyproject.toml` present), not just a stdlib interpreter uv is pointed at via `--python`; `--bare` skips uv's normal `README.md`/`main.py`/`.python-version`/`git init` scaffolding, since this is very often being run straight in the caller's real project root, not a fresh scratch directory. Both steps are skipped if already done (existing `pyproject.toml`, existing venv), so it's safe to call repeatedly. `ubel-pip`/`ubel-uv`/`ubel-pipx` all still run their respective provisioning implicitly on first `check`/`install` if the venv doesn't exist yet, so calling `init` explicitly is only needed to provision ahead of time or at a non-default path.

```bash
ubel-pip init
```

`ubel-conda init` creates an empty conda environment at `<projectRoot>/conda-env` with `conda create --yes --prefix`, and does nothing if one is already there. It's never required — `ubel-conda check` creates nothing and `install` creates the environment when it needs it — it just provisions ahead of time.

---

### `install-hook` / `uninstall-hook`

Install / remove the single ubel git pre-commit hook: a secrets scan on every commit, plus `<engine> health` — a **dependency scan only**, no OS scan — whenever a commit stages a package manifest or lockfile. See [Pre-commit Hook](#pre-commit-hook) above for the full behavior, chaining rules, and file patterns.

```bash
ubel-npm install-hook              # install the pre-commit hook (secrets + dependency scan)
ubel-npm install-hook --force      # chain to an existing foreign hook
ubel-npm uninstall-hook            # remove it again
```

Supported on every engine except `docker` (no repo checkout) and `apt`/`dnf`/`yum` (they scan the host, not a repo).

---

### `threshold`

Sets the severity level at or above which vulnerabilities block the scan. Accepts `low`, `medium`, `high`, `critical`, or `none` (disable threshold blocking). Available on every engine.

```bash
ubel-npm threshold high       # block high and critical
ubel-npm threshold critical   # block critical only
ubel-npm threshold none       # disable severity blocking

ubel-composer threshold high  # composer works the same way

ubel-pip threshold high
ubel-uv threshold high
ubel-apt threshold high       # ubel-dnf / ubel-yum work the same way
```

Infections (`MAL-*` advisories) are always blocked regardless of this setting.

The threshold is persisted to the local policy file and applies to all subsequent scans until changed. To apply a level to a single run without saving it, use [`--threshold`](#per-run-policy-flags) instead.

---

### `block-unknown`

Controls whether packages with unknown-severity vulnerabilities are blocked. Available on every engine.

```bash
ubel-npm block-unknown true
ubel-npm block-unknown false

ubel-composer block-unknown true

ubel-pip block-unknown true
ubel-uv block-unknown true
```

Like `threshold`, this is persisted. For a one-off run use [`--block-unknown`](#per-run-policy-flags).

---

### `license-risk`

**npm/pnpm/bun/yarn/composer only** — not exposed as a subcommand on `ubel-pip`/`ubel-uv`/`ubel-pipx`/`ubel-apt`/`ubel-dnf`/`ubel-yum`, matching those CLIs' narrower six-mode surface (`health`/`check`/`install`/`init`/`threshold`/`block-unknown`). Sets the license risk level at or above which a `health` scan is blocked. Accepts `none`, `low`, `medium`, or `high`. Order: `low → medium → high`.

```bash
ubel-npm license-risk high     # block only high-risk licenses (e.g. GPL/AGPL, proprietary EULAs)
ubel-npm license-risk medium   # block medium and up (also weak-copyleft: MPL, LGPL, EPL, CDDL)
ubel-npm license-risk none     # disable license-risk blocking (default)
```

Unlike `threshold`/`block-unknown`, this gate is only ever evaluated on `health`-mode scans — see [License Compliance](#license-compliance) for why license classification itself is restricted to `health` mode. Setting it on `check`/`install` policy files has no effect on those scans.

---

### `license-block-unknown`

**npm/pnpm/bun/yarn/composer only**, same scope restriction as `license-risk` above. Separately controls whether packages whose license couldn't be classified at all cause a block — distinct from `license-risk` above, which only governs the `low`/`medium`/`high` buckets and deliberately never blocks on `unknown`.

```bash
ubel-npm license-block-unknown true
ubel-npm license-block-unknown false   # default
```

Same `health`-mode-only scope as `license-risk`. Off by default: an `unknown` classification is usually a detection gap (unparseable free-text license, missing metadata) rather than an actual compliance finding, so this is opt-in even on a strict `license-risk` policy — a fresh scan of an unfamiliar codebase can otherwise block on packages nobody has actually looked at yet, purely because their metadata didn't parse.

---

## Per-run policy flags

Every policy field that has a mode can also be passed as a flag on `health`, `check`, and `install`. A flag overrides the saved policy **for that one invocation only** — the policy file is restored when the process exits (clean run, policy block, scan failure, or Ctrl-C), so it's byte-for-byte what it was before. Use the modes above (`threshold`, `block-unknown`, ...) when you want the change to stick.

| Flag | Overrides | Values | Engines |
|---|---|---|---|
| `--threshold <level>` | `severity_threshold` | `low` \| `medium` \| `high` \| `critical` \| `none` | all |
| `--block-unknown [true\|false]` | `block_unknown_vulnerabilities` | `true` \| `false` (bare flag = `true`) | all |
| `--license-risk <level>` | `license_risk_threshold` | `none` \| `low` \| `medium` \| `high` | npm/pnpm/bun/yarn/composer |
| `--license-block-unknown [true\|false]` | `block_unknown_license_risk` | `true` \| `false` (bare flag = `true`) | npm/pnpm/bun/yarn/composer |
| `--block-kev [true\|false]` | `block_kev` | `true` \| `false` (bare flag = `true`) | all |
| `--epss-threshold <value>` | `epss_threshold` | a fraction in (0, 1] (`0.1`), a percentage (`10%`), or `none` | all |

Both `--flag value` and `--flag=value` are accepted, and flags can sit anywhere among the package arguments. Anything that isn't one of these flags is treated exactly as before. An invalid value, or a license flag on pip/uv/pipx/conda/cargo/apt/dnf/yum, exits `1` with an error before any scan starts. For `--epss-threshold`, a bare number above 1 (e.g. `10`) is rejected as ambiguous — write `0.1` or `10%` — and `0` is rejected because it would block everything; use `none` to disable. `--block-kev` and `--epss-threshold` have no persistent mode: to change them permanently, edit `config.json` (see [Policy](#policy)). `ubel-docker` has its own flags (`--no-pull`, `--keep`) and doesn't take these.

```bash
# Block only critical vulnerabilities for this run; saved policy untouched
ubel-npm check --threshold critical

# Stricter gate for one install
ubel-pnpm install --threshold=medium --block-unknown react

# CI: fail a health scan on high-risk licenses without editing the shared policy file
ubel-npm health --license-risk high --license-block-unknown

# Linux / Python engines take the vulnerability flags (severity, unknown, KEV, EPSS)
ubel-apt check --threshold critical curl
ubel-pip install --threshold high requests==2.31.0

# Block anything with EPSS >= 5% for this run, but don't block on KEV membership
ubel-npm check --epss-threshold 5% --block-kev false
```

`license-risk` / `license-block-unknown` keep their usual scope: they're only evaluated on `health` scans, so passing them to `check`/`install` has no effect on the result.

**Precedence:** flag > saved policy > default policy.

---

## Policy

Policy is stored as JSON at `.ubel/local/policy/config.json` relative to the project root — except for `ubel-apt`/`ubel-dnf`/`ubel-yum`, where it's relative to `$HOME` instead (`~/.ubel/local/policy/config.json`), since there's no "project" for host-level OS packages; see [Firewall Mechanics](#firewall-mechanics). The schema and every field below is identical either way.

Default policy created on first run:

```json
{
    "severity_threshold": "high",
    "block_unknown_vulnerabilities": true,
    "license_risk_threshold": "none",
    "block_unknown_license_risk": false,
    "block_kev": true,
    "epss_threshold": 0.1
}
```

**Severity threshold** — vulnerabilities at or above this level cause a block. Severity order: `low → medium → high → critical`.

**Block unknown** — when `true`, any vulnerability whose severity cannot be determined also causes a block.

**License risk threshold** — packages whose license risk is at or above this level cause a block. Risk order: `low → medium → high`. Defaults to `"none"` (disabled) — unlike the vulnerability gates above, this is opt-in even when license classification runs, because license detection has real gaps (free-text licenses, missing metadata) and legal risk tolerance for e.g. weak copyleft varies by organization. This threshold never blocks on `unknown` regardless of how strict it's set — see `block_unknown_license_risk` below. This gate is also a no-op outside `health`-mode scans, since `license_stats` is only populated there — see [License Compliance](#license-compliance).

**Block unknown license risk** — separately controls whether packages whose license couldn't be classified at all cause a block. Defaults to `false`, for the same reason `license_risk_threshold` excludes `unknown` from its ordered levels: an unclassified license is more often a detection gap than a real finding. Same `health`-mode-only scope.

**Block KEV** — when `true` (the default), any vulnerability listed in the CISA Known Exploited Vulnerabilities catalog causes a block, regardless of its severity. Policy files created before this field existed pick up the default automatically.

**EPSS threshold** — vulnerabilities whose EPSS score is at or above this value cause a block, regardless of severity. Stored as a fraction (`0.1` = 10%); defaults to `0.1`. Set to `"none"` to disable.

Both rules need data from an external feed; if it couldn't be fetched the rule cannot fire — see [Exploit Intelligence](#exploit-intelligence-kev--epss).

**Infections** — advisories with IDs beginning `MAL-` are always blocked and are not subject to any of the settings above.

---

## Exploit Intelligence (KEV & EPSS)

Severity says how bad a flaw *could* be; these two feeds say whether it is actually being exploited or is likely to be. Every vulnerability is enriched with:

| Field | Source | Meaning |
|---|---|---|
| `is_kev` | [CISA KEV catalog](https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json) | `true` if the CVE is in the catalog, `false` if not, `null` if the catalog couldn't be fetched |
| `kev_added` | CISA KEV | Date the CVE was added to the catalog (`YYYY-MM-DD`), else `null` |
| `kev_deadline` | CISA KEV | CISA's remediation due date, else `null` |
| `epss_score` | [FIRST EPSS](https://api.first.org/data/v1/epss) | Probability (0–1) of exploitation in the next 30 days, else `null` |
| `epss_percentile` | FIRST EPSS | Percentile (0–1) of that score among all scored CVEs, else `null` |

`null` always means *unknown* (feed down, or no EPSS score exists for the CVE), never "not exploited" or `0`. The HTML report shows `epss_score` and `epss_percentile` as percentages (×100) and flags KEV entries with a badge; The JSON report keeps the raw 0–1 values. The SBOM and SARIF outputs carry them too — see [Output](#exploit-intelligence-output).

**CVE matching.** OSV advisories are frequently GHSA/other ids, so the CVE is taken from the vulnerability `id` if it starts with `CVE-`, and from its `aliases` otherwise. If an advisory maps to several CVEs, it is KEV if any of them is, and the highest EPSS score is reported. The CVE ids are also printed next to the advisory id in the console findings list:

```
• GHSA-xxxx-xxxx-xxxx  [CVE-2026-88779]  HIGH (8.1)
```

**Policy.** With the defaults, a scan blocks on any KEV entry (`block_kev: true`) and on any vulnerability with `epss_score >= 0.1` (10%), whatever its severity. Both are tunable with [`--block-kev` / `--epss-threshold`](#per-run-policy-flags) or in `config.json`. The block reason names the offending ids, e.g. `Blocked by policy: 1 known-exploited (CISA KEV) vulnerability detected: GHSA-xxxx-xxxx-xxxx`.

**When a feed is unreachable.** Unlike OSV/NVD (where a failed lookup fails the scan, because a missing answer would look like "no vulnerabilities"), KEV/EPSS only *add* risk signal, so an outage degrades the result instead of aborting it:

- the scan completes and the affected fields are `null`;
- a warning is printed, shown in the HTML decision box, and recorded under `threat_intel` in the report (`status` of `ok`, `partial`, `unavailable` or `skipped` per feed, plus the error);
- the matching policy rule is not enforced for that run, and a passing verdict says so — e.g. `Policy passed (note: CISA KEV data unavailable — not enforced for this scan)`;
- other rules (severity, the other feed, infections, secrets) are unaffected.

Each feed is tried with a 15-second timeout and two retries. There is currently no endpoint override for either feed.

### Exploit intelligence output

<a id="exploit-intelligence-output"></a>

- **JSON**: the five fields above on every vulnerability, plus `threat_intel` (feed status and warnings).
- **SBOM (CycloneDX v1.6)**: on each `vulnerabilities[]` entry, the properties `kev.listed` (`true`, `false` or `unknown`), `kev.date_added` and `kev.due_date` (KEV entries only), and `epss.score` / `epss.percentile` (raw 0–1; `unknown` when no score). A KEV entry also gets an advisory link to the CISA catalog. EPSS is also added as a second `ratings[]` entry (`method: "other"`, source `FIRST EPSS`) whose `score` is the probability **in percent (0–100)**, since CycloneDX 1.6 has no EPSS method. Nothing is written when enrichment never ran. The root `properties` carry `kev_vulnerabilities` (count) and `ubel:threat_intel` (feed status as a JSON string) — read the count together with that status, because a feed outage leaves the count at 0.
- **SARIF 2.1.0**: rules and results carry `is_kev`, `kev_added`, `kev_deadline`, `epss_score` and `epss_percentile` in `properties` (`null` = unknown); rules get the tags `kev` / `known-exploited` / `epss` where they apply. Each result gets a `rank` (0–100): 100 for a KEV entry, otherwise the EPSS probability ×100, omitted when there is no signal. A KEV result is reported at level `error` whatever its severity, unless reachability confidently ruled it out (then `none`, as for any unreachable finding). The run's `properties.threat_intel` holds the feed status.

---

## Fixed-Configuration Scan CLIs

`ubel-agent`, `ubel-cicd`, and `ubel-platform` are thin wrappers around the same `health`-mode scan engine as `ubel-npm health` — each hardcodes a specific `SCA_scan()` option set for one deployment context, rather than exposing the full `<engine> <mode>` argument surface. All three: take a single optional path argument (defaults shown below), print the full JSON report to stdout, always write reports to disk exactly like any other scan (see [Reports](#reports)), and use the same exit-code contract as `check`/`install` — `0` if policy passes, `1` if policy blocks or the scan itself throws.

| Binary | Target (arg default) | `scan_os` | `scan_node` (full-stack) | `scan_secrets` | Fixed `scan_scope` |
|---|---|---|---|---|---|
| `ubel-agent` | `process.cwd()` | ✅ | ✅ | default | `agent` |
| `ubel-cicd` | `process.cwd()` | ✅ | ✅ | default | `cicd` |
| `ubel-platform` | home directory (`os.homedir()`) | ✅ | ❌ | default | `developer_platform` |
| `ubel-secrets` | `process.cwd()` | ❌ | ❌ | ✅ (forced on; `scan_os`/`scan_node` forced off) | `agent` |
| `ubel-license` | `process.cwd()` | ❌ | ✅ (full-stack) | ❌ (forced off; `scan_vulns` also forced off) | `license` |

```bash
# Scan an AI agent's sandboxed working directory before it's allowed to run
# further tool calls — OS packages + every app ecosystem in the sandbox.
ubel-agent /path/to/agent/workspace

# Post-build CI/CD scan of the final built workspace (after install, before deploy)
ubel-cicd /path/to/build/output

# Host/developer-machine platform scan — OS packages and installed dev
# tools/runtimes only, no application dependency resolution. Defaults to
# the invoking user's home directory when no path is given.
ubel-platform
ubel-platform /path/to/specific/directory
```

`scan_scope` only affects labeling in the report (`scan_info.scan_scope`) and how the report path is filed under `.ubel/local/reports/<ecosystem>/<mode>/...` — it has no effect on scan behavior itself. All three are also reachable programmatically via `SCA_scan()`/`main()` with the same options, for embedding in a VS Code extension, an orchestration agent, or a custom CI step (see [Programmatic API](#programmatic-api)).

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

**Priority 2 (dev/test scope)** — Packages that are exclusively development or test dependencies are excluded from production runtimes. Scope is derived from `package.json` `devDependencies` (for Rust, from the `[dev-dependencies]` / `[build-dependencies]` sections of `Cargo.toml` and its workspace members) and propagated through the dependency graph via BFS.

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
| Flutter / Dart | `.dart` | `import 'package:<pkg>/…'`, `export 'package:<pkg>/…'` |
| Swift | `.swift` `.m` `.mm` `.h` | `import <Module>`, `@import <Module>`, `#import <Module/…>` |


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

Every `health`-mode scan includes a secrets pass by default (`scan_secrets: true`); `check` and `install` never run one, whatever `scan_secrets` is set to. (`ubel-docker` is the one place this looks different from the CLI: all three of its modes run the same `health`-mode pipeline on the extracted image, so image scans always include secrets.) It's also reachable standalone via `ubel-secrets`, which runs a secrets-only pass with no dependency resolution and no LLM calls:

```bash
ubel-secrets /path/to/project
```

`ubel-secrets` also scans git history, scans exactly what is staged for commit, installs a git pre-commit hook, and baselines existing findings — see [Git history](#git-history), [Pre-commit hook](#pre-commit-hook-staged-changes), [Baselining](#baselining) and the [flag reference](#ubel-secrets-flag-reference). Run with none of those flags, it is the plain secrets-only pipeline scan above.

`ubel-license` never runs a secrets pass: `scan_secrets` is forced off, and the `license` scope skips secrets regardless of what a caller passes.

### Ruleset

The builtin ruleset (`sca/vendor/trivy/rules.js`, `sca/vendor/trivy/allow-rules.js`) is ported from [Trivy's](https://github.com/aquasecurity/trivy) built-in secret scanner (`pkg/fanal/secret/builtin-rules.go`), Apache-2.0, with full attribution in [`sca/vendor/trivy/NOTICE`](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/NOTICE) and [`LICENSE`](https://github.com/AlaBouali/ubel/blob/main/sca/vendor/trivy/LICENSE). It's a generated snapshot of Trivy's ruleset, regenerated from upstream when that ruleset changes — not a live mirror.

On top of the ported set, `sca/secrets.js` defines an `extraRules` array covering credential types not present in Trivy's current builtin rules, including:

- HashiCorp Vault tokens (`hvs.` prefix)
- Google Cloud API keys (`AIza…`) and OAuth access tokens (`ya29.`)
- Anthropic and OpenRouter API keys
- Firebase server tokens
- Amazon MWS auth tokens
- Square OAuth secrets and access tokens, Braintree access tokens. A Square `EAAA…` token must be a standalone string with enough entropy: it is not reported when it sits inside a longer base64/base64url run (inlined wasm, data URIs), which the unbounded upstream pattern flagged dozens of times per file
- Stripe live restricted keys (`rk_live_`) — Trivy covers publishable/secret keys but not this format. This extra rule deliberately skips test-mode keys (`rk_test_`), which can only reach test-mode data
- Credentials embedded in a git remote URL (`https://user:token@host/...`) — a different injection vector from the token-format-specific rules above. Covers GitHub, GitLab, Bitbucket, Azure DevOps, Codeberg, Gitea, Gitee and SourceHut, self-hosted instances whose hostname starts with `git`, `gitlab`, `bitbucket`, `gitea`, `gogs` or `forgejo`, and any other host when the URL is a `.git` remote. Placeholder passwords (`password`, `token`, `xxxx`, …) and `${VAR}` references are ignored
- Database and broker connection strings with an embedded password — three forms, all reporting the password only:
  - **URL**: `postgres://`, `postgresql://`, `mysql://`, `mariadb://`, `mongodb://` / `mongodb+srv://`, `redis://` / `rediss://` (including the empty-user `redis://:pass@host`), `amqp://` / `amqps://`, `mssql://`, `sqlserver://`, `cockroachdb://`, `clickhouse://`, `neo4j://`, `bolt://`, and SQLAlchemy-style `postgresql+psycopg2://` (rule `database-url-credentials`)
  - **Key/value**: ADO.NET, ODBC and libpq strings such as `Server=…;Database=…;Password=…` or `host=… password=…`; a host/database key must appear earlier on the same line, so a bare `password=` is left to the generic rule (rule `database-connection-string-password`)
  - **JDBC**: `jdbc:mysql://host/db?user=u&password=…`, `jdbc:sqlserver://host;…;password=…` (rule `jdbc-url-password`)

  Not reported: placeholders and templates (`${DB_PASS}`, `$DB_PASS`, `<password>`, `{0}`, `%PWD%`, `@param`, `%s`, `changeme`, `YOUR_PASSWORD`, `xxxx`, …), `user:user` pairs such as `guest:guest`, default passwords (`postgres`, `root`, `admin`, `test`, …) against `localhost`, `127.0.0.1`, `host.docker.internal` or a bare docker-compose service name, and hosts containing `example`. The same default password against a real hostname *is* reported. Switch a rule off with `rule:<id>` in `.ubelignore`; the per-rule allow-lists are part of the rule, not builtin allow-rules, so `unallow:` does not affect them
- Generic high-entropy fallback for unknown vendors — a vendor-style prefix (`sk-`, `pk_`, `xox*`, `api_`, `key_`, `token_`) followed by 32+ characters, where the part after the prefix must also clear a Shannon-entropy check (at least 4.0 bits per character, or 3.0 for hex-only values), so repeated runs and plain snake_case identifiers aren't reported
- Generic key-value fallback — `password`/`secret`/`token`/`api_key`/`private_key` assigned a 32+ character value; there is no entropy check here, the key name is the signal

Twilio SIDs are intentionally not detected: the `AC…`/`AP…` + 32-character pattern has no checksum or distinguishing context and produced far too much noise.

`.env*` files are skipped in repository scans (they aren't meant to be committed) but scanned in Docker image scans, where a baked-in `.env` ships with the image. The global allow-rules still apply, so a file such as `.env.example` is skipped either way.

### What gets scanned

- **Every match on every line** is reported, not just the first per rule; overlapping matches collapse to one finding (a specific rule beats a generic one).
- **Private keys**: PEM blocks are matched across lines (finding points at the `BEGIN` line and carries `end_line`), including encrypted/legacy PEM and PGP blocks with `Proc-Type`/`DEK-Info`/`Version` headers. Extensionless key files are opened too: `id_rsa`/`id_dsa`/`id_ecdsa`/`id_ed25519` (and `id_rsa.bak`-style variants) are always scanned, and files with no extension or a backup-style one (`.bak`, `.old`, `.orig`, `.p8`, `.ppk`, `.asc` …) are scanned if they start with a PEM private-key header.
- **Skipped directories**: dependency trees, build output and caches are skipped (`node_modules`, `vendor`, `target`, `dist`, `build`, `out`, virtualenvs, …). `packages`, `bin`, `obj` and `env` are ambiguous names, so they are skipped only when the layout says they hold generated content — a NuGet `packages/` (next to a `.sln`, or containing `repositories.config`), a .NET `bin/`/`obj/` (next to a `.sln`/`.csproj`), a Python venv (`pyvenv.cfg`). A monorepo's `packages/*` and a Node `bin/` are scanned. Any default-skipped directory can be re-included (below). The exceptions are VCS metadata (`.git`, `.svn`, `.hg`) and UBEL's own `.ubel/` directory: those are never walked and cannot be re-included.

### Suppressing findings

Put a `.ubelignore` file at the scan root (or pass `ignoreFile` / `ignorePatterns`). One entry per line; `#` starts a comment.

```gitignore
docs/generated/                 # skip a directory
*.snap                          # skip files by glob, at any depth
/fixtures/keys/*.pem            # leading "/" anchors to the scan root
src/seed.js rule:generic-key-value-credential   # suppress one rule (comma list ok) on matching paths
rule:generic-fallback           # disable a rule everywhere
fingerprint:3f9a1c0be27d4a55    # accept one specific finding
include-dir:dist                # scan a directory that is skipped by default
exclude-dir:generated           # skip a directory name wherever it appears
unallow:tests                   # switch off a builtin allow-rule (e.g. scan test paths)
```

Or mark the line in the source, in any comment syntax:

```js
const k = "..."; // ubel:ignore
const k = "..."; // ubel:ignore[aws-access-key-id]
// ubel:ignore-next-line
```

Every finding carries a `fingerprint` — a hash of rule id, path and the secret, stable across line moves and never containing the secret itself. `ubel-secrets <path> --write-baseline` appends the current findings' fingerprints to `.ubelignore` so you can adopt the scanner on an existing codebase and only be told about *new* secrets. Review that diff before committing it. The scan result also reports `suppressed` (how many findings the ignore rules dropped).

Note the builtin allow-list still skips paths containing `test`/`example` and secrets whose text contains "example"; `unallow:tests` / `unallow:examples` turn those off.

### Git history

```bash
ubel-secrets /path/to/repo --history
ubel-secrets --history --rev=origin/main..HEAD     # only a branch's new commits
ubel-secrets --history --since=2025-01-01 --max-commits=500
ubel-secrets --history --json
```

Most leaked secrets are in commits, not in today's tree. `--history` runs the normal working-tree scan **and** a history scan in one pass: it streams `git log -p` and scans the lines each commit **added**, so a secret committed and later deleted is still found. Contiguous added lines are scanned together, so multi-line PEM blocks are caught. Only `git` is used (via argument arrays, never a shell) and nothing is written to disk.

Results use the same rules, allow-lists, entropy gates and `.ubelignore` as a tree scan. Each history finding adds `commit`, `commit_date` and `author`, and the oldest commit that introduced a given (rule, path, secret) is the one reported — later re-additions (reverts, cherry-picks, merges of the same content) are not repeated. A secret still in the tree is annotated with its introducing commit (`in_history`); one that has since been deleted is listed as `history_only`. The text output shows `[<commit> <date>, history only]` next to each such finding. `.env*` files are scanned in history (if one is in history, it was committed).

`--rev` selects what to walk (default: all refs) and may be repeated; a value starting with `-` is rejected. `--since` takes any date git accepts, and `--max-commits` must be a positive integer.

A secret in history is compromised even if it is no longer in the tree: **rotate it** — rewriting history alone is not enough. In a shallow clone (CI's default `fetch-depth: 1`) older commits do not exist, and the result carries a `shallow` warning (`history.warnings`); fetch full history first (`git fetch --unshallow`, or `fetch-depth: 0` in GitHub Actions). The result's `history` object reports `commits_scanned`, `shallow`, `warnings` and `history_only_findings`.

### Pre-commit hook (staged changes)

```bash
ubel-secrets --install-hook            # install .git/hooks/pre-commit (the single ubel hook)
ubel-secrets --install-hook --force    # keep an existing foreign hook and chain to it
ubel-secrets --uninstall-hook          # remove it again
ubel-secrets --staged                  # what the hook runs; also usable on its own
```

`--staged` scans what is in the **index** (staged vs `HEAD`), not the working tree: unstaged edits are ignored, and a secret you staged but then deleted from the file on disk is still caught. It works before the first commit (it diffs against the empty tree) and uses rename detection, so moving a file never re-flags secrets it already had. A clean staged scan prints nothing — it runs on every commit.

**What a staged scan covers.** The skip lists of a whole-tree scan (above) exist to keep that scan fast and quiet; they are not applied to a file somebody is explicitly staging. Staged files are scanned wherever they live and whatever they are called — including `build/`, `out/`, `dist/`, `vendor/`, `coverage/`, test and example paths, `docs/*.md`, notebooks, `Jenkinsfile`, `Procfile`, `.tfstate`, `.env*`, and files git's attributes mark `-diff`/`binary` (they are diffed as text). Only these are skipped: installed-dependency trees (`node_modules`, `site-packages`, virtualenvs), machine-generated lockfiles, files that are binary (a NUL byte in the first 8000 bytes, or an image/archive/font/media extension), and what you exclude in `.ubelignore` (path globs, `exclude-dir:`). `include-dir:` and `unallow:` still apply. Placeholder-looking values (`example`, `${VAR}`, `process.env.X`) are still ignored by the content rules.

**Large additions are never dropped.** An added block is scanned in slices (each slice re-scans the tail of the previous one, so a multi-line key straddling a boundary is still found), and a single huge line is split with an overlap. Only a file adding more than 128 MB in one diff is cut short; that is reported as a warning (`[!] <path>: more than 128 MB added - only the first 128 MB was scanned`, and `incomplete: true` in `--json`), and with `UBEL_HOOK_STRICT=1` it fails the scan (exit `2`) instead. Change the cap with `UBEL_STAGED_MAX_FILE_MB`. `--history` uses the same slicing.

The hook is the single ubel pre-commit hook (see [Pre-commit Hook](#pre-commit-hook)): a small POSIX `sh` script that runs `ubel-secrets --staged` on every commit — and, if you also ran `ubel-<engine> install-hook`, the dependency scan too — and blocks the commit on a non-zero exit (`1` = findings, `2` = the scan itself failed).

- **Idempotent** — re-installing replaces UBEL's own hook (recognised by a marker comment).
- **Never clobbers someone else's hook.** Without `--force` it refuses. With `--force` the existing hook is moved to `pre-commit.local` and still runs after a clean secrets scan; `--uninstall-hook` moves it back. It refuses to remove a hook it did not install.
- **Respects `core.hooksPath` and git worktrees** — the hooks directory comes from `git rev-parse --git-path hooks`.
- **Shareable.** If the hooks directory lives outside the git dir (a committed `.githooks/`, husky-style), the script embeds no machine-specific paths and finds `ubel-secrets` on `PATH`, so every contributor needs it installed. Otherwise it embeds the absolute paths of the `node` binary and CLI script that installed it.
- **Tool missing vs. tool failing.** If `ubel-secrets` cannot be found, the hook warns loudly that the staged changes were **not** scanned and lets the commit through; set `UBEL_HOOK_STRICT=1` to block instead. If the tool runs and fails, the commit is blocked — a broken scan must not look like a clean one.

Skip once with `git commit --no-verify`. Hooks are client-side and local, so also run `ubel-secrets --history` in CI.

To add the dependency scan to the same hook, run `ubel-<engine> install-hook` (see [Pre-commit Hook](#pre-commit-hook)); neither order needs `--force`.

### Baselining

```bash
ubel-secrets --write-baseline              # accept the current tree's findings
ubel-secrets --history --write-baseline    # ...including history findings
ubel-secrets --staged --write-baseline     # ...or the staged ones
```

Baselining adopts the scanner on an existing codebase: it appends `fingerprint:<hex>  # <rule> <path>:<line>` entries to `.ubelignore` (or the file given by `--ignore-file`) under a dated `# baseline` header, skipping fingerprints already present, so you are only told about *new* secrets afterwards. It prints how many findings it baselined and exits `0` — accepting the current state is a success. Review the diff before committing it, and rotate anything that was real.

### `ubel-secrets` flag reference

| Flag | Meaning |
|---|---|
| `[path]` | Directory to scan (default: the current directory) |
| `--history` | Scan the working tree and git history |
| `--rev=<range>` | With `--history`: revisions/ranges to walk (repeatable; default: all refs) |
| `--since=<date>` | With `--history`: only commits after this date |
| `--max-commits=<n>` | With `--history`: only the `n` most recent commits |
| `--staged` | Scan only what is staged for commit (cannot be combined with `--history`) |
| `--install-hook` / `--uninstall-hook` | Install / remove the pre-commit hook (cannot be combined with a scan option; mutually exclusive) |
| `--force` | With `--install-hook`: move an existing foreign hook aside and chain to it |
| `--write-baseline` | Append the current findings' fingerprints to `.ubelignore` instead of reporting them |
| `--include-env` | Also scan `.env*` files in a working-tree scan |
| `--include-dir=<name>` | Scan a directory that is skipped by default (repeatable) |
| `--exclude-dir=<name>` | Skip a directory name wherever it appears (repeatable) |
| `--unallow=<id>` | Switch off a builtin allow-rule, e.g. `tests`, `examples` (repeatable) |
| `--ignore-file=<path>` | Use this ignore file instead of `<root>/.ubelignore` |
| `--json` | Print the result object as JSON on stdout; progress output is silenced |

The shared options (`--include-dir`, `--exclude-dir`, `--unallow`, `--ignore-file`, `--include-env`) are also honoured on their own — they select this scan path rather than being silently ignored by the full pipeline scan. Unknown flags and a second positional argument are errors. Exit codes: `0` clean (or baselined, hook installed/removed), `1` findings, `2` error.

### Keeping UBEL's own files out of git and Docker

UBEL writes `.ubel/` (reports, policy, extracted images, dependency scratch space) and, for suppressions, `.ubelignore` into your project. Before anything else runs, the entry point (`main.js`) makes sure `.gitignore` **and** `.dockerignore` in the working directory ignore both, creating either file if it does not exist. This is done by the entry point only — the secrets scanner, CLI, git and hook modules never edit those files.

- **Idempotent.** An entry counts as covered if any equivalent pattern is present (`.ubel`, `/.ubel/`, `.ubel/*`, `.ubel*`, …), so a hand-written entry is never duplicated.
- **Append-only.** Existing content, ordering and line endings (LF/CRLF) are preserved; new entries go under a `# ubel:` comment.
- **Opt-out respected.** A negation such as `!.ubelignore` means you want that entry tracked, so it is not re-added — this is how you commit a shared baseline while everything else stays ignored.
- **Never fails a scan.** A read-only checkout or a permissions problem is swallowed (with `DEBUG` set, it is logged).
- **Once per directory per process.** Changed files are announced with one `[ubel] Created|Updated …` line on stderr (CLI only; not with `--json`).
- **Where it applies.** The working directory for every CLI engine except `ubel-apt`/`ubel-dnf`/`ubel-yum` (their reports and policy live under `~/.ubel`, not the project); for `ubel-docker`, the working directory, where its `.ubel/<uuid>` scratch space is created — never the extracted image rootfs. Programmatically, `projectRoot`, except for `docker` and the `container-image` and `developer_platform` (home directory) scopes. `ubel-secrets --staged` and `--uninstall-hook` skip it: they run inside `git commit`, where mutating the tree would be surprising (`--install-hook` already did it).
- **Kill switch:** `UBEL_NO_IGNORE_FILES=1`.

`ubel-secrets` runs its extra flags without ever reaching the main scan engine, so its `bin/secrets.js` wrapper calls the exported `ensureUbelIgnoreFilesForSecrets(argv)` from `main.js` before dispatching.

### Output

- **HTML report**: a dedicated Secrets tab (category, severity, file/line, redacted match preview — the raw secret value is never written to any report or log).
- **SBOM (CycloneDX v1.6)**: exposed as a `ubel:secrets` entry in the root `properties` array, as a JSON-string value. Not a top-level `x-`-prefixed key — CycloneDX's root schema sets `additionalProperties: false`, so a custom root key would fail strict schema validation; the `properties` array is the schema's actual documented extension point.
- **SARIF 2.1.0**: its own `run`, with a dedicated `tool.driver` and rule set, kept separate from the dependency-vulnerability run.

---

## License Compliance

Every `health`-mode scan classifies each inventory item's declared license by default — no separate flag needed. Classification is restricted to `health` scans: license risk is a compliance/legal concern over software already installed on the machine, not an install-time security gate, and running it during `check`/`install` would let the license-risk policy gate (see [Policy](#policy)) fire in a context it wasn't meant for — those pre-install dry-run scans are evaluating whether it's safe to add a new dependency, a separate question. `check`/`install` reports simply have no `license_info` on inventory items and no `stats.license_stats`; every downstream consumer (report UI, SBOM builder) already falls back gracefully when it's absent. The classification itself is purely additive: the raw `license` field reported by the package manager is left untouched, and a `license_info` object is added alongside it.

For an inventory + license-only scan with no OSV/NVD vulnerability lookups and no secrets scan, use the standalone `ubel-license` command (`bin/license.js`), or pass `scan_vulns: false, scan_secrets: false` to `SCA_scan()`/`main()` programmatically. `scan_vulns: false` skips OSV/NVD entirely — no network calls are made for vulnerability data — while dependency resolution and license classification run exactly as they do in any other `health` scan.

### Normalization

Licenses arrive in wildly inconsistent shapes across ecosystems, and all of the following are normalized to the same canonical SPDX identifier before classification:

- Case and whitespace variants — `mit`, `MIT`, `Mit` → `MIT`
- Free text — `"Apache 2.0"`, `"apache2"`, `"Apache License 2.0"` → `Apache-2.0`
- SPDX boolean expressions — `(MIT OR Apache-2.0)`, `GPL-2.0-or-later`, `GPL-2.0+`
- SPDX `WITH` exception expressions — `GPL-2.0-only WITH Classpath-exception-2.0` (as reported for JRE/JDK by the Windows host scanner) is recognized as a distinct, lower-risk case rather than falling through as unparseable free text — the Classpath exception permits linking without inheriting GPL's copyleft obligations, so it's capped at `medium` risk instead of plain GPL's `high`
- `LicenseRef-*` identifiers — SPDX's convention for a real, named license or vendor EULA with no registered SPDX id (used by the Windows host scanner for OS/vendor components — e.g. `LicenseRef-Microsoft-Windows-EULA`, `LicenseRef-Google-Chrome-TOS`, `LicenseRef-Proprietary`); classified as a known proprietary-leaning license rather than "unrecognized"
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
| Permissive | MIT, Apache-2.0, BSD-2/3-Clause, ISC, 0BSD, PHP-3.01, Ruby, BlueOak-1.0.0 | `low` |
| Public domain | Unlicense (OSI-approved), CC0-1.0 (not OSI-approved but permissive in practice) | `low` |
| Weak copyleft | MPL-2.0, LGPL-2.1/3.0, EPL-2.0, CDDL | `medium` |
| Strong copyleft (with linking exception) | GPL-2.0-only WITH Classpath-exception-2.0 (Oracle/OpenJDK JRE/JDK) | `medium` |
| Strong copyleft | GPL-2.0/3.0, AGPL-3.0 | `high` |
| Source-available / rejected by OSI | SSPL-1.0, BUSL-1.1, Elastic-2.0 | `high` |
| Proprietary | npm `UNLICENSED`, `"Proprietary"`, `LicenseRef-*` vendor EULAs (Windows OS/Defender, Chrome, Docker Desktop, Visual Studio, …) | `high` |
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

## Compliance Framework Mapping

Every dependency vulnerability and secrets-in-source finding is mapped onto industry compliance/security frameworks by default — no separate flag or mode needed, and included in every report format. This is distinct from [License Compliance](#license-compliance) above, which is about license-obligation risk on installed software; this section is about mapping *security* findings onto the frameworks an org is typically audited against.

Mapping works by first assigning each finding one or more internal risk categories (e.g. `injection`, `secrets_management`, `vulnerable_components`) — for a dependency vulnerability, from its advisory's CWE(s), always including `vulnerable_components` as a baseline since every SCA finding is a known-vulnerable-component finding by definition; for a secrets finding, always `secrets_management`. Each category then carries a fixed list of framework control references, so two findings with the same underlying risk always map identically.

### Frameworks covered

| Framework | Notes |
|---|---|
| OWASP Top 10 (2021) | Category codes (`A01:2021`–`A10:2021`) |
| PCI DSS v4.0 | Requirement numbers |
| HIPAA Security Rule | §164.312 / §164.308 citations |
| SOC 2 (Trust Services Criteria) | `CC*`/`A1.*` codes |
| ISO/IEC 27001:2022 (Annex A) | `A.*` control numbers |
| NIST SP 800-53 Rev. 5 | Control IDs (e.g. `SI-10`, `AC-3`) |
| GDPR | Article citations |
| CIS Controls v8 | Numbered controls |

**This is best-effort guidance, not a certified compliance assessment.** Control identifiers are the stable, publicly documented ones for each framework, but framework text, versioning, and applicable scope can change, and always depend on the org's own environment. Every report carries this disclaimer verbatim in `compliance_summary.disclaimer` — treat the mapping as a starting point for an audit conversation, not a citation to quote in one.

### Output fields

Each vulnerability and secrets finding gets a `compliance` object:

```json
{
  "compliance": {
    "categories": ["vulnerable_components", "injection"],
    "frameworks": [
      {
        "id": "owasp_top10_2021",
        "name": "OWASP Top 10 (2021)",
        "controls": [
          { "id": "A06:2021", "title": "Vulnerable and Outdated Components" },
          { "id": "A03:2021", "title": "Injection" }
        ]
      }
    ]
  }
}
```

The top-level `compliance_summary` field aggregates every vulnerability and secrets finding in the report into per-framework, per-control finding counts:

```json
{
  "disclaimer": "Compliance framework references are best-effort guidance ...",
  "frameworks": [
    {
      "id": "owasp_top10_2021",
      "name": "OWASP Top 10 (2021)",
      "findings_count": 14,
      "controls": [
        { "id": "A06:2021", "title": "Vulnerable and Outdated Components", "findings_count": 11 },
        { "id": "A03:2021", "title": "Injection", "findings_count": 3 }
      ]
    }
  ],
  "by_category": { "vulnerable_components": 11, "injection": 3, "secrets_management": 2 }
}
```

### Output

- **HTML report**: a dedicated Compliance tab with one card per framework (control breakdown + finding counts), plus a Compliance Frameworks section in each vulnerability's detail modal.
- **JSON report**: `compliance` on every vulnerability and secrets finding, plus the report-level `compliance_summary` described above.
- **SARIF 2.1.0**: `compliance_categories` / `compliance_frameworks` on each rule, and the full `compliance` object on each result — in both the dependency-vulnerability run and the secrets run.

---

## Package Argument Validation

All package specifiers passed to `check` and `install` are validated before any subprocess is invoked — the exact rule differs by ecosystem, since npm/pip/apt specifiers don't share a syntax.

**npm/pnpm/bun** — validated against a strict allow-list pattern. Accepted formats:

```
name
name@version
@scope/name
@scope/name@version
```

Specifiers containing shell metacharacters or other unsafe characters are rejected immediately.

**composer** — validated against its own allow-list pattern, since Composer specifiers are always `vendor/package` rather than npm's `name`/`@scope/name` shape:

```
vendor/package
vendor/package:constraint
```

Specifiers containing shell metacharacters or other unsafe characters are rejected immediately, same as npm/pnpm/bun.

**pip/pipx/apt/dnf/yum** — validated more permissively, to allow the specifier shapes those ecosystems actually use (`black[d]>=24`, `requests==2.31.0`, a bare Linux package name): every character in `=._+-@/~[]<>!` is stripped from the specifier, and what remains must be alphanumeric. This rejects shell metacharacters, whitespace, quotes, and other characters that aren't part of a legitimate version/extras specifier. It checks *characters*, not structure, though: a leading `-` is allowed, so an option-shaped argument such as `--no-deps` passes validation as if it were a package specifier. Don't forward untrusted input to these CLIs.

**conda** — validated against its own, stricter pattern, because `ubel-conda` allows `:` (for `channel::name`), which the loose pattern above would turn into a way to pass a URL. A specifier must start with a letter, digit or underscore (so no option-shaped arguments like `-c` or `--file`) and may then contain only letters, digits and `. _ - + * ! < > = , ~ : [ ]` — no `/`, `\`, spaces or quotes, so no paths or URLs — and must not end in `.conda` or `.tar.bz2` (conda installs those from disk, bypassing the channel resolution UBEL scans). `numpy`, `numpy=1.26`, `python>=3.10,<3.13` and `conda-forge::scipy` are accepted.

**cargo** — validated against a strict `name` or `name@requirement` pattern: the name must start with a letter or underscore (so no option-shaped arguments like `--git`), and the optional requirement after `@` may contain only letters, digits and `. ^ ~ = < > * + ! , -` — no spaces, `/`, `:` or quotes, so no paths, URLs or sources. `serde`, `serde@1.0` and `tokio@^1.35` are accepted.

Either way, a rejected specifier exits non-zero before any filesystem or network operation occurs.

---

## Programmatic API

`main()` doubles as a programmatic entry point for agents, platform scanners, and the VS Code extension:

```js
import { SCA_scan } from "@arcane-spark/ubel-node/sca";

const report = await SCA_scan({
  projectRoot : "/abs/path/to/project",
  engine      : "npm",   // npm | pnpm | bun | yarn | composer | docker | pip | uv | pipx | conda | cargo | apt | dnf | yum
  mode        : "health",
  is_script   : true,
  save_reports: true,
  scan_os     : false,
  full_stack  : false,
  scan_node   : true,
  scan_scope  : "repository",   // repository | agent | developer_platform | editor_extension | cli_tool | linux_machine
});
// report is the full finalJson object (inventory, vulnerabilities, decision, …)
```

Two additional options only apply to the pypi-family engines (`engine: "pip"`, `"uv"` or `"conda"`):

```js
const report = await SCA_scan({
  projectRoot: "/abs/path/to/project",
  engine     : "pip",    // or "uv" / "conda" — same two options each time
  mode       : "health",
  scan_venv  : true,     // default true — include the project's venv in a health scan
  venvDir    : "/abs/path/to/a/custom/venv",   // overrides the default `<projectRoot>/venv` (`<projectRoot>/conda-env` for conda)
});
```

They're accepted and simply ignored for every other `engine` value — no need to omit them conditionally.

When called this way, the banner and interactive console output are suppressed. The return value is the same machine-readable report object written to disk.

The pre-commit hook installer is not exposed programmatically; use the CLI (`ubel-<engine> install-hook` / `uninstall-hook`) if you need to wire it up.

---

## Reports

Every scan writes two files to a timestamped path and overwrites the `latest*` convenience links:

```
.ubel/reports/latest.json          ← always current
.ubel/reports/latest.html          ← always current
.ubel/reports/latest.cdx.json          ← always current
.ubel/reports/latest.sarif.json          ← always current

.ubel/local/reports/<ecosystem>/<mode>/<YYYY>/<MM>/<DD>/
    <ecosystem>_<mode>_<engine>__<timestamp>.zip
```

`<ecosystem>` is `npm` for npm/pnpm/bun/yarn/composer, `pypi` for pip/uv/pipx/conda, `cargo` for cargo, and `linux` for apt/dnf/yum; `<engine>` is the specific binary invoked (`npm`, `pnpm`, `composer`, `pip`, `uv`, `apt`, …). For `ubel-apt`/`ubel-dnf`/`ubel-yum` specifically, both report paths above are rooted at `$HOME` rather than the project (`~/.ubel/reports/latest.json`, `~/.ubel/local/reports/...`) — see [Firewall Mechanics](#firewall-mechanics) for why.

The HTML report is fully self-contained (no server required) and includes:

- Dashboard with severity breakdown chart and policy decision
- Executive Summary tab (right after the Dashboard) — plain-language risk rating, key findings, and recommended actions for non-technical readers, with a one-page layout and a Print / save as PDF button, see [Executive Summary](#executive-summary)
- Searchable, filterable vulnerability table
- Full inventory with state (safe / vulnerable / infected / undetermined)
- Interactive force-directed dependency graph with vulnerable-subtree filter
- Per-vulnerability detail modals (CVSS vector, fix recommendations, OSV/NVD references)
- Per-package detail modals with **Suggested Fixes** — upgrade versions grouped by range, plus the vulnerabilities that have no fix, see [Recommended Package Fixes](#recommended-package-fixes)
- Dedicated Secrets tab (category, severity, file/line, redacted match preview)
- License Risk stats card (low/medium/high/unknown breakdown, OSI-approved count) — populated on `health`-mode scans, see [License Compliance](#license-compliance)
- Dedicated Compliance tab — per-framework cards showing which controls a scan's findings touch and how often, see [Compliance Framework Mapping](#compliance-framework-mapping)
- System and runtime metadata (OS, local network interfaces, git info, engine/tool versions)

The JSON report contains the full machine-readable equivalent and can be consumed by CI/CD tooling directly.

---

## Executive Summary

Every report (JSON and HTML) carries an `executive_summary` written for readers who don't work with CVEs, CVSS scores, or package URLs — management, risk and compliance teams, product owners. It is derived entirely from the data already in the report (no extra scanning or network calls), so the JSON field and the HTML tab always show the same content. It is generated by `executive_summary.js` after the policy decision is made, and it never fails a scan: if it can't be built, only the summary is omitted.

### Overall risk rating

| Rating | Assigned when |
|---|---|
| Critical | any malicious (`MAL-*`) component was found |
| High | any Critical/High-severity vulnerability that isn't confirmed unreachable, any [CISA KEV](#exploit-intelligence-kev--epss) vulnerability that isn't confirmed unreachable (whatever its severity), or any exposed High/Critical credential |
| Medium | Medium/unrated issues, vulnerabilities at or above the EPSS threshold, lower-severity secrets, or Critical/High/KEV issues that reachability analysis confirmed are not used by production code |
| Low | only Low-severity issues (none at or above the EPSS threshold), or Medium/unrated issues that reachability analysis confirmed are all unused |
| Minimal | nothing found |
| Not assessed | the scan skipped vulnerability lookups (`scan_info.vulnerability_scan: false`, e.g. `ubel-license`) and nothing else raised the rating — shown instead of "Minimal" so an unchecked scan is never read as a clean one |

Reachability is a heuristic (see [Reachability Analysis](#reachability-analysis)); a finding with no reachability result is treated as potentially reachable.

The rating and the policy verdict are independent. The rating discounts findings that reachability analysis confirmed unused; the verdict comes from `policy.js`, which counts every finding at or above the blocking thresholds (and any exposed secret, of any severity), so a report can be rated Medium yet still be blocked.

### Exploit intelligence in the summary

The summary uses the same two signals the policy blocks on (see [Exploit Intelligence](#exploit-intelligence-kev--epss)), so a report is never rated "Low" while the policy blocks it for an actively exploited vulnerability:

- **Known-exploited (`is_kev: true`)** — gets its own key finding (with CISA's earliest remediation due date), an *Immediately* suggested action, the **Known to be exploited** card, and raises the rating to High unless reachability analysis confirmed the code unused (then Medium). Components with a known-exploited issue rank first among the non-malicious ones and carry an *Exploited* badge.
- **High EPSS** — vulnerabilities at or above `epss_threshold` that aren't already KEV get a key finding and, when they are lower-severity, a *Within days* action; they set a floor of Medium. If the EPSS rule is turned off in the policy, 10% is still used for this informational reporting, and the text says the policy doesn't block on it.
- **Unknown stays unknown** — if a feed was unreachable, the matching figures are `null` (shown as "n/a", never `0`), a key finding says so, the methodology shows the lookup as *incomplete*, and a Low/Medium rating notes that it could be understated.

### JSON structure

```json
{
  "executive_summary": {
    "overall_risk": { "level": "high", "label": "High", "rationale": "...", "business_impact": "..." },
    "cover": { "title": "...", "subject": "my-app", "report_id": "...", "generated_at": "2026-10-06T09:30:00Z", "tool": "...", "classification": "...", "statement": "..." },
    "bottom_line": { "risk_label": "High", "summary": "...",
                     "top_risks": [ { "severity": "high", "title": "...", "detail": "..." } ],
                     "do_first": [ { "action": "...", "timeframe": "Immediately", "owner": "..." } ],
                     "figures": [ { "label": "...", "value": 9, "sub": "...", "tone": "high" } ] },
    "glance_cards": [ { "label": "...", "value": 142, "sub": "...", "tone": null } ],
    "headline": "This scan reviewed 142 software components and found ...",
    "verdict": { "status": "blocked", "label": "Does not meet security policy", "statement": "...", "technical_reason": "..." },
    "at_a_glance": { "vulnerabilities_assessed": true, "components_reviewed": 142, "components_with_issues": 4, "malicious_components": 0,
                     "total_vulnerabilities": 9, "by_severity": { "critical": 1, "high": 2, "medium": 4, "low": 2, "unknown": 0 },
                     "fix_available": 7, "fix_available_percent": 78, "likely_in_use": 6, "not_in_use": 3,
                     "blocking_policy": 3, "exposed_credentials": 2,
                     "known_exploited": 1, "high_exploit_likelihood": 2, "exploit_data_complete": true },
    "key_findings": [ { "severity": "high", "title": "...", "detail": "..." } ],
    "components_to_fix_first": [ { "name": "lodash", "version": "4.17.15", "issue_count": 3, "worst_severity": "critical",
                                   "worst_severity_label": "Critical", "likely_in_use": true, "blocks_policy": true, "known_exploited": 1, "max_epss": 0.42, "upgrade_to": "4.17.21",
                                   "fix_options": [ { "version": "4.17.21", "range": "4.17.x", "scope": "minor", "resolves": 3, "of": 3, "resolves_known_exploited": 1, "known_exploited_total": 1, "recommended": true } ], "fix_options_more": 0, "no_fix_yet": 0,
                                   "references": [ "GHSA-xxxx-xxxx-xxxx" ], "more_references": 2, "action": "Upgrade to version 4.17.21." } ],
    "recommended_actions": [ { "priority": 1, "timeframe": "Immediately", "owner": "...", "action": "...", "why": "..." } ],
    "compliance_overview": { "frameworks_touched": 3, "most_affected": [ { "framework": "...", "findings": 5 } ], "statement": "...", "disclaimer": "..." },
    "scope": { "scan_type": "health", "description": "...", "target": "a code repository", "ecosystems": ["npm"], "components_reviewed": 142 },
    "notes": [ "..." ],
    "glossary": [ { "term": "Vulnerability", "meaning": "..." } ]
  }
}
```

### Layout and printing

The HTML tab is laid out so the first screen can be read on its own and fits one printed page:

1. **Cover** — report title, what was scanned, report ID, date, and tool (`cover`).
2. **Bottom line** — the overall risk rating next to the policy verdict, a one-paragraph summary, the **Top risks**, **Do this first** (each action with its timeframe and a *suggested owner*), and four key figures (`bottom_line`).
3. **Details** — why this rating, all key findings, at-a-glance cards (`glance_cards`), components to fix first, all suggested actions, and compliance exposure.
4. **Appendix** — methodology, "About this report" (scope and notes), and the plain-language glossary. The appendix is collapsed on screen and expanded automatically when printing.

A **Print / save as PDF** button at the top of the tab prints the summary only (on a white background, other tabs hidden), so it can be handed to someone who never opens the interactive report. In the *Components to fix first* table, the identifiers under each component are the advisory references, for tickets and audit trails, and an *Exploited* badge marks components with a known-exploited issue. For multi-system scans, the tab also shows *Configuration issues by area* and *Systems to review first* tables when that data is present.

### Scan subject and labelling

`executive_summary.scope.subject` identifies what was scanned: `name`, `repository`, `branch`, `commit` (first 8 characters), `scanned_at` and `tool`, taken from the report's `git_metadata`, `runtime` and `tool_info`. Credentials embedded in a git remote URL (`https://user:token@host/...`) are stripped. The project name comes from the git remote, or the working-directory name for repository/agent/CI scans; for container-image, Linux-host and developer-platform scans it is left empty rather than showing a temp or home directory. Fields that aren't available are omitted from the header.

`overall_risk.basis` and `recommended_actions_basis` state that the rating scale is this tool's own (not CVSS or a regulatory standard), that the impact text is general guidance per rating level, and that action timeframes are built-in defaults rather than the organization's remediation policy. The HTML tab shows these notes, and labels the actions section "Suggested actions".

### Methodology

`executive_summary.methodology` (and the Methodology section of the HTML tab) describes how that specific report was produced. Steps are included only if the stage ran for that scan: the usage estimate needs reachability results, the exploit-intelligence lookup needs vulnerability lookups (and is labelled *incomplete* when a feed failed), the credential search needs secrets scanning on, license review appears on `health` scans only, and compliance mapping needs a `compliance_summary`. The Policy check step prints the policy values actually in force, including the KEV and EPSS rules. The section also states the risk-rating rules, how components are prioritized, that the action timeframes are built-in defaults rather than your SLAs, and the main limitations.

```json
"methodology": {
  "steps": [ { "step": "Inventory", "detail": "..." } ],
  "rating_rules": [ { "level": "Critical", "rule": "..." } ],
  "prioritization": "...", "timeframes": "...", "limitations": [ "..." ]
}
```

The rating and prioritization text in `methodology` is a prose copy of the logic in `executive_summary.js`; if you change that logic, update the text in `buildMethodology()` too.

**Checks that didn't run or didn't finish.** When vulnerability lookups were skipped, the vulnerability-derived `at_a_glance` figures are `null` (shown as "n/a" in the HTML tab), not `0`, and the methodology lists the lookup as "not run". When the secrets pass was enabled but failed (`secrets.error`), `exposed_credentials` is `null`, the credential-search step is omitted, and a key finding and note say the result is unavailable instead of reporting zero. Components with no determinable version (`stats.inventory_stats.undetermined`) are called out in the inventory step, the limitations, and the notes, since they can't be matched against vulnerability databases. Malicious-component advisories are counted separately in the summary, so "Known weaknesses" can be lower than the Vulnerabilities tab total; a note says so when it applies.

`compliance_overview` is `null` when no findings map to a framework. `components_to_fix_first` lists at most five components, ranked by malicious status, then known-exploited (and not judged unused), then whether they're likely in use, then worst severity, then forecast exploit likelihood, then issue count. The suggested upgrade is the closest upgrade path from the per-package analysis in [Recommended Package Fixes](#recommended-package-fixes) that resolves the most of that component's issues (a major version change is called out, and any issues it leaves open are stated); if that analysis is missing or failed for a package, the older per-issue heuristic is used instead. Each component also lists every upgrade path from that analysis as `fix_options` (closest release line first, at most five, the recommended one always kept, `fix_options_more` for the rest): the version, its range, whether it is a `major` change, how many of the component's issues it resolves and how many of the known-exploited ones, plus `no_fix_yet` for issues no version fixes. The HTML tab shows them under the action as a **Possible fixes** list with *Best* and *Major* badges. Either way the suggested upgrade is indicative, not a guarantee.

---

## Recommended Package Fixes

For every package in the inventory, UBEL looks at **all** of its vulnerabilities and the fixed version of every affected range, then suggests which versions to upgrade to. Instead of a single "latest" version, suggestions are grouped **per version range**, so you can pick the least disruptive upgrade that still closes the most issues:

- **One group per minor range above your installed version** — e.g. `4.17.x`, `4.18.x` (same major version, so typically non-breaking)
- **Then one group per higher major range** — e.g. `5.x`, `6.x` (may be breaking)

Groups are listed closest-first: minor ranges, then major ranges, with the highest version first inside a range.

**How versions are picked.** Inside each range, UBEL picks the version that fixes the most still-open vulnerabilities (ties go to the highest version), then repeats until nothing more can be fixed in that range — so you get the fewest, highest versions that cover the most. A vulnerability can therefore appear in several ranges: each range is an **alternative upgrade path**, not a sequence of steps to apply together.

**Branch-aware matching.** A candidate version is only counted as a fix if it genuinely falls outside every affected range of that vulnerability — not merely because it is numerically higher than some fixed version. This matters for advisories fixed on several release branches (e.g. a fix backported to `4.17.21` while `4.18.0`–`4.18.2` stays affected). When an advisory carries no usable range data, UBEL falls back to "at or after a known fixed version". Git-commit ranges are ignored since they can't be compared to package versions. For NVD-sourced advisories, each branch's lower bound is kept alongside its fix version, so a fix on a lower branch (say `1.2.5` next to `1.3.2`) is recognized as a fix for that branch rather than looking still-affected.

**Unfixed vulnerabilities.** Anything with no fixed version above the one you have installed — or that no candidate version actually clears — is listed separately as `unfixed` rather than silently dropped, so you can see what an upgrade won't solve.

**In the HTML report**

Open the **Inventory** tab and click a package: its detail modal has a **Suggested Fixes** section.

- A table with one row per suggested version — **Range** (label plus *minor range* / *major range*), **Suggested version** (with "fixes N"), and **Vulnerabilities fixed**, each with its severity badge. Click any vulnerability to jump to its detail modal.
- Below it, **Vulnerabilities with no fix (N)** — ID, severity, and score for everything no suggested version resolves.
- Malicious (infection) entries are shown with an `infection` badge. If nothing can be fixed by upgrading, the modal says so; if the package has no suggestion data, it says that instead.

**Ordering.** Vulnerabilities inside every group are ordered most severe first: malicious (infection), then critical, high, medium, low, unknown; ties are broken by CVSS score, then ID.

**Ecosystem-aware version comparison.** Versions are compared with one ecosystem-agnostic comparator that handles semver, PEP 440, and deb/rpm-style versions — including epochs (`1:2.3`), `v` prefixes, pre-release tags (`1.0.0-rc1` sorts below `1.0.0`), and ignored build metadata (`+build`) — across every supported ecosystem.

**In SBOM and SARIF.** SBOM: each component has a `suggested_fixes` property (JSON string), and each vulnerability the properties `suggested_fix_version` and `suggested_fix_bulk_count` when a suggested version covers it. SARIF: each result has `suggested_fix_version` and `suggested_fixes` in `properties`, and the run's `properties.inventory_suggested_fixes` lists the plan per package.

Suggestions are computed only when vulnerability lookups ran, so they are absent from `ubel-license` scans (and from any scan run with `scan_vulns: false`).

**JSON**

Each inventory item in the JSON report carries a `suggested_fixes` object:

```json
{
  "suggested_fixes": {
    "fixes": [
      {
        "version": "4.17.21",
        "count": 3,
        "range": { "key": "m:4.17", "label": "4.17.x", "scope": "minor" },
        "vulnerabilities": [
          { "id": "GHSA-xxxx-xxxx-xxxx", "severity": "critical", "severity_score": 9.8, "is_infection": false }
        ]
      }
    ],
    "unfixed": [
      { "id": "CVE-0000-0000", "severity": "medium", "severity_score": 5.3, "is_infection": false }
    ]
  }
}
```

| Field | Meaning |
|---|---|
| `fixes[].version` | A suggested version to upgrade to |
| `fixes[].count` | How many of the package's vulnerabilities that version resolves |
| `fixes[].range` | The range the version belongs to: `scope` is `minor` (same major as installed) or `major` (higher major); `label` is e.g. `4.17.x` or `5.x` |
| `fixes[].vulnerabilities` | The vulnerabilities resolved, most severe first |
| `unfixed` | Vulnerabilities no suggested version resolves |

If suggestions can't be computed for a package, its `suggested_fixes` carries an `error` message with empty `fixes`/`unfixed`, and the rest of the report is unaffected. Suggestions are computed once per scan by `suggested_fixes.js` (`attachSuggestedFixes`), right after vulnerabilities are matched and before the executive summary is built, so the summary can use them. A failure on one package never fails the scan.

---

## CI/CD Integration

All CLI commands exit non-zero on policy violations — and when a vulnerability lookup against OSV or NVD can't be completed — making them native to any CI runner. An incomplete lookup is a failed scan, never a clean one.

**Via the packaged GitHub Action** ([`action.yml`](https://github.com/AlaBouali/ubel/blob/main/action.yml), a composite action wrapping `npx @arcane-spark/ubel-node@<version>` behind a `command` allow-list checked against UBEL's own `package.json` bin names):

```yaml
- uses: AlaBouali/ubel@<commit-sha>   # pin to a commit SHA, not a mutable tag
  with:
    command: npm
    version: 0.21.2
    args: check

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: npm
    version: 0.21.2
    args: install

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: license                  # inventory + license compliance only

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: pip
    version: 0.21.2
    args: install                     # scan-gated `pip install`, resolved from ./requirements.txt

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: composer
    version: 0.21.2
    args: install                     # scan-gated `composer install --no-scripts`, resolved from the existing composer.lock

- uses: AlaBouali/ubel@<commit-sha>    # needs a preceding astral-sh/setup-uv step for `uv` itself
  with:
    command: uv
    version: 0.21.2
    args: install                     # same fallback + generated-file install as the pip example above

- uses: AlaBouali/ubel@<commit-sha>    # needs a preceding conda setup step (e.g. conda-incubator/setup-miniconda) for `conda` itself
  with:
    command: conda
    version: 0.21.2
    args: install                     # scan-gated; resolves from ./environment.yml, installs the exact scanned builds

- uses: AlaBouali/ubel@<commit-sha>    # needs the Rust toolchain on PATH (e.g. dtolnay/rust-toolchain)
  with:
    command: cargo
    version: 0.21.2
    args: install                     # scan-gated; scans ./Cargo.lock, then cargo fetch --locked

- uses: AlaBouali/ubel@<commit-sha>
  with:
    command: apt                      # dnf/yum work the same way, as their own `command` values
    version: 0.21.2
    args: check curl
```

`command` must be one of: `sast`, `mal`, `chunk`, `cicd`, `agent`, `platform`, `secrets`, `license`, `npm`, `pnpm`, `bun`, `yarn`, `composer`, `docker`, `pip`, `pipx`, `uv`, `conda`, `cargo`, `apt`, `dnf`, `yum`.

**Calling the binaries directly** (self-hosted runners, non-GitHub CI, Dockerfiles):

```yaml
# GitHub Actions
- name: UBEL dependency scan
  run: ubel-npm check

- name: UBEL firewall-gated install
  run: ubel-npm install

- name: UBEL license compliance scan
  run: ubel-license .

- name: UBEL PHP firewall-gated install
  run: ubel-composer install

- name: UBEL Python firewall-gated install
  run: ubel-pip install

- name: UBEL Python firewall-gated install (via uv)
  run: ubel-uv install

- name: UBEL Python firewall-gated install (via conda)
  run: ubel-conda install

- name: UBEL apt firewall-gated install
  run: ubel-apt install curl
```

```dockerfile
# Dockerfile
RUN ubel-npm install
RUN ubel-composer install
RUN ubel-apt install curl
```

### Pre-commit hook vs. CI

The pre-commit hook (`ubel-<engine> install-hook`) is a client-side convenience — it's skippable with `git commit --no-verify` and doesn't exist on a fresh clone for a contributor who hasn't run `install-hook`. That's fine for a fast local gate, but treat it as a supplement, not a substitute, for a real CI scan: keep running `ubel-<engine> check` (or `health`) in the pipeline so nothing reaches a shared branch without a scan.

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

# Block installed high-risk-licensed software on health scans
ubel-npm license-risk high
ubel-npm health

# Scan the installed project dependencies
ubel-npm health

# Install a pre-commit hook that runs a dependency scan on every commit
# that stages a manifest/lockfile
ubel-npm install-hook

# Same workflows with pnpm and bun
ubel-pnpm install react react-dom
ubel-bun check
ubel-pnpm install-hook

# PHP: dry-run scan, then a scan-gated real install
ubel-composer check monolog/monolog
ubel-composer install monolog/monolog:^3.0
ubel-composer install                     # no args → resolves from the existing composer.lock

# Python: dry-run, then a scan-gated real install
ubel-pip check requests==2.31.0
ubel-pip install requests==2.31.0
ubel-pip install                          # no args → falls back to ./requirements.txt, then ./pyproject.toml
ubel-pip install-hook                     # dependency-scan pre-commit hook

# Same, driven by uv instead of pip — same fallback, same generated-file install
ubel-uv check requests==2.31.0
ubel-uv install requests==2.31.0

# Python via conda: dry-run against a scratch prefix, then an exact-pinned scan-gated install
ubel-conda check numpy=1.26
ubel-conda install numpy=1.26
ubel-conda install                        # no args → ./environment.yml

# Rust: dry-run in a scratch copy of the project, then write the scanned manifest/lockfile and `cargo fetch --locked`
ubel-cargo check serde@1
ubel-cargo install serde@1
ubel-cargo install                        # no args → scans ./Cargo.lock

# Python CLI tool, installed into an isolated venv + global shim
ubel-pipx install black

# Linux host packages: dry-run, then a scan-gated `sudo apt install`
ubel-apt check curl
ubel-apt install curl
# ubel-dnf / ubel-yum take the same arguments against their own package manager

# Tighten policy for the Linux firewall too, then re-scan
ubel-apt threshold critical
ubel-apt check curl

# One-off overrides — same fields, nothing written to the policy file
ubel-npm check --threshold critical
ubel-npm health --license-risk high
ubel-apt check --threshold=low curl
```

---

*Ubel — Secure every dependency, before it reaches production.*