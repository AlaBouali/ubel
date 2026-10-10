# UBEL — Unified Bill / Enforced Law
### AI-Powered Static Analysis & Malicious Code Scanner

Ubel chunks a codebase into semantically-bounded units, runs them through a three-pass LLM pipeline — **scan → verify → taint trace** — and cross-references findings against a structured, CWE-mapped vulnerability catalog to surface real, exploitable bugs instead of generic pattern-matches.

This document covers the **SAST / malware-scan** component (source-level code analysis, as opposed to the dependency/SCA firewall).

---

## Features

- Semantic code chunker across 15 language families (12 source-code languages — including Dart/Flutter and Swift — plus Docker, IaC, and Kubernetes) — class/function-aware boundaries, not naive line-splitting
- Three-pass analysis pipeline for vulnerability findings: **scan** (Pass 1) → **verify** (Pass 2) → **taint trace** (Pass 3)
- Structured, CWE-mapped vulnerability catalog — 64 classes across the 15 language families, each with concrete "detect when you see" signals available to the model (sent only with `--include-signals`; the default prompt carries class name, CWE and scope rule)
- Per-language catalog filtering — classes irrelevant to a chunk's language are dropped before the prompt is built, cutting token usage and false positives
- **Token-lean by design** — small chunks are packed into shared Pass-1 calls, findings are verified and traced per chunk (not per finding), classes that need no attacker input skip the taint pass, the static prompt prefix is prompt-cache-friendly (explicit `cache_control` on Anthropic), and every report records the real token usage the provider returned (see [Token Consumption & Optimization](#token-consumption--optimization))
- **Honest coverage** — anything that was *not* scanned (chunks past `--max-chunks`, files over the size limit, AI replies cut off) is measured by the scanner, recorded in the report and stated in the executive summary; a capped run can never read as a clean one
- Cross-chunk call-graph resolution — `buildFullCallChain` walks callers/callees across chunk boundaries so the taint-trace pass reasons about real source→sink flow, not a single isolated snippet
- Separate **malicious code / backdoor** scan — its own catalog (15 classes: reverse shells, C2 beacons, supply-chain implants, persistence, exfiltration, anti-analysis evasion, logic bombs, and more), own prompts, own report set, never mixed with accidental-vulnerability findings
- `--only-diff` mode — scan only chunks touched by a git diff, while still building the full chunk set so cross-file taint chains keep resolving correctly
- Configurable `--fail-on` exit-code gate (`any` / `valid` / `exploitable` for SAST, `any` / `confirmed` for malware) — reports always contain every finding regardless of this flag; it only changes the CI exit code
- Pluggable LLM provider registry — OpenRouter, OpenAI, Anthropic, Gemini, DeepSeek, NVIDIA, and local/Docker-hosted models (Ollama-compatible), selectable per run with no code changes
- Automatic report generation: timestamped **JSON** + interactive **HTML** + **SARIF 2.1.0**, plus `latest.<tag>.*` convenience links (`latest.sast.*`, `latest.malware.*`), kept in a separate namespace per scan type so SAST and malware runs never collide. For historic tracking, a zipped snapshot of these reports are generated and saved, too.
- **Executive Summary** in the JSON and HTML reports — a plain-language overview for non-technical readers (overall risk rating, top risks, what to do first, suggested actions, methodology and limitations), printable as a one-page summary (see [Executive summary](#executive-summary))
- **Compliance framework mapping** — every finding (vulnerability or malicious-code) is mapped onto OWASP Top 10, PCI DSS, HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, and CIS Controls v8, with a report-level per-framework/per-control finding-count summary, across JSON, HTML, and SARIF (see [Compliance Framework Mapping](#compliance-framework-mapping))
- Zero external runtime dependencies (Node.js stdlib only)

---

> **Data handling:** SAST sends the code chunks it analyzes to the LLM provider you select (`--provider`, `openrouter` by default). Choose a local or self-hosted endpoint (e.g. Ollama-compatible) if source code must not leave your network. UBEL itself has no telemetry and no UBEL-operated backend.

## Installation

```bash
npm install -g @arcane-spark/ubel-node
```

After installation, the following entry-point binaries are available:

| Binary | Scan Type |
|---|---|
| `ubel-sast` | Static analysis — accidental vulnerability classes (injection, XSS, insecure deserialization, hardcoded secrets, …) |
| `ubel-mal` | Malicious code scan — intentional backdoors, C2 implants, exfiltration, persistence, supply-chain implants |

Both binaries wrap the same underlying pipeline (`sast/main.js`) and simply pre-select the `analyze` or `malware` subcommand:

```js
// bin/ubel-sast
process.argv.splice(2, 0, "analyze");
import("../sast/main.js");

// bin/ubel-mal
process.argv.splice(2, 0, "malware");
import("../sast/main.js");
```

So `ubel-sast [args]` ≡ `node main.js analyze [args]`, and `ubel-mal [args]` ≡ `node main.js malware [args]`. A third subcommand, `chunk`, also has its own dedicated binary, `ubel-chunk` (≡ `node main.js chunk [args]`) — it's the free "look before you spend tokens" utility. Every flag documented below applies to both `analyze` and `malware` unless stated otherwise.

---

## Requirements

- Node.js `>=18.0.0`
- An API key for your chosen LLM provider (set via `--api-key` or the provider's environment variable, e.g. `ANTHROPIC_API_KEY`) — not required for `local`, `docker`, or `docker-desktop` providers
- `git` on `PATH` if using `--only-diff`

---

## Usage

```
ubel-sast  [path] [options]
ubel-mal   [path] [options]
```

The target path is optional — when omitted, the current working directory is scanned.

```bash
# Scan the current directory for vulnerabilities
ubel-sast

# Scan a specific project
ubel-sast /path/to/project

# Scan only what changed since HEAD^
ubel-sast --only-diff

# Scan for intentionally malicious code instead
ubel-mal /path/to/project
```

---

## Pipeline Mechanics

### Pass 1 — Scan

The chunker (`buildChunks`) walks the target directory and splits each source file into semantically-bounded chunks (functions, classes, or brace-delimited blocks depending on the language). `--max-chunk-size` is a **hard cap** on characters per chunk: an over-long single line (a minified bundle, a generated data blob) is cut at the nearest statement or space boundary rather than sent as one oversized chunk. Each chunk has its comments stripped (`stripComments`) before submission and is matched against the vulnerability (or malware) catalog filtered to its language family. The LLM returns candidate findings with a `vuln_name`, code snippet, description, fix suggestion, severity and confidence level.

**Packing.** The prompt scaffold (rules, catalog, schema) is a fixed cost per call, and a real repository's median chunk is only a few hundred characters. Small chunks of the **same language** are therefore packed into one call (up to `--pack-size` characters of code, at most `--pack-max-chunks` chunks); each is labelled `C1…Cn` and every finding cites its `chunk_id`. A chunk larger than half the pack size is always sent alone. If anything goes wrong with a packed call — a transport error, an unreadable or truncated reply, or a finding that cannot be attributed to a chunk — those chunks are re-scanned one by one, so packing can only save tokens, never silently lose a chunk. `--no-pack` restores one call per chunk. A custom `buildPrompt` / `buildMalwarePrompt` override always gets one chunk per call.

**What is skipped (and how to override it).**

| Skipped by default | Why | Override |
|---|---|---|
| Directories: `node_modules`, `.nyc_output`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.tox`, `venv`, `.venv`, `env`, `.env`, `eggs`, `.eggs`, `htmlcov`, `dist`, `build`, `out`, `target`, `bin`, `obj`, `vendor`, `Pods`, `Carthage`, `DerivedData`, `SourcePackages`, `.gradle`, `.idea`, `.vs`, `packages`, `.git`, `.svn`, `.hg`, `coverage`, `.terraform` | dependency, build and tooling output | `--include-folders <names>` |
| **Every dot-directory** (`.github`, `.dart_tool`, `.build`, `.symlinks`, …) | tooling / hidden state | `--include-folders <name>` |
| `*.d.ts` | type declarations only — no executable code | none (always skipped) |
| `*.min.js`, `*.bundle.js` (and `.mjs`/`.cjs` forms) | one-line generated output | `--include-generated`. **The malware scan scans them by default.** |
| Generated Dart (`*.g.dart`, `*.freezed.dart`, `*.gr.dart`, `*.mocks.dart`, `*.chopper.dart`, `generated_plugin_registrant.dart`) | codegen noise | none |
| Files over 512,000 characters | cost guard | `--max-file-size <n>`. **Skipped files are listed in the report** |
| Test folders / test-named files | *scanned by default* (fixtures sometimes hold real secrets) | opt in to skipping with `--skip-tests` |

Pointing the scanner *inside* an ignored folder works (only sub-folders are checked), so `ubel-mal ./node_modules/some-pkg` scans that package; to sweep a dependency tree or build output from its parent, use `--include-folders node_modules,dist`.

**Coverage is measured, not assumed.** The run records how many chunks were found, how many fell outside `--max-chunks` (default 1000) or `--chunks-start`, which files were over the size limit, and how many AI replies were cut off. Anything that was not scanned is printed at the end of the run, stored in `meta.scan_options` / `meta.scan_stats.coverage`, and stated in the executive summary — which also refuses to give a *Minimal* rating when part of the code was left out.

### Pass 2 — Verify

Candidate findings from Pass 1 are re-submitted, alongside their originating chunk, to the LLM with a narrower prompt: *is this finding actually valid given the code shown?* This catches cases where Pass 1 flagged a pattern that is provably safe in context (e.g. a query built from a fully hardcoded string that only looks parameterized). **All findings of one chunk are verified in a single call** (the chunk's code is sent once, not once per finding); any finding the batched answer does not cover is re-asked on its own, so batching never leaves a finding unverified that a one-by-one run would have settled. Only the finding itself is sent — none of the bookkeeping fields earlier passes attach. Verification always runs at `temperature: 0` regardless of the `--temperature` flag, **on every provider including Anthropic** (the temperature is sent explicitly; a model that rejects the parameter is retried without it) — it's a binary verdict and needs to be deterministic — and sets `is_valid: true | false | null` (`null` = inconclusive) on each finding.

### Pass 3 — Taint Trace (SAST only)

For verified findings whose class needs attacker-controlled input to be exploitable, `buildFullCallChain` walks the call graph — masking out string/comment contents first so identifiers inside logs or strings never produce false call edges — to resolve the finding's caller/callee chain across chunk boundaries:

- Callers are followed for up to **10 BFS levels** (callers of callers of callers …), callees for two levels. The call graph is built from **every chunk found**, not just the `--max-chunks` window, so a capped or `--only-diff` run still sees callers outside it.
- The chain is capped at **15 chunks**. When the graph is bigger, the **nearest** callers and callees are kept (alternating, so slots one side doesn't need go to the other).
- Every entry is labelled from its real role — `OUTERMOST CALLER`, `CALLER n`, `SINK (contains the flagged finding)`, `CALLEE n` — and presented outermost caller → sink → callees.
- The chain also has a **character budget** (`--taint-chain-chars`, default 24,000): the sink is always sent whole, callers are cut down to the windows around their call sites, callees to their head, and the prompt says when an entry is an excerpt.
- The chain depends on the chunk, not the finding, so it is built once per chunk and all of that chunk's findings are traced in **one call**; findings the batched answer misses are re-asked individually. Passes run at `temperature: 0`.

The pass sets `taint.exploitable`, `taint.reachable`, `taint.sanitized`, and `taint.flow_path` on the finding. Two cases never cost an LLM call:

- **Orphans.** A finding in a function with no callers in the analysed code *and* no entry-point signature is answered locally with `inconclusive_reason: "orphan_no_callers"`. "Entry-point signature" means a handler-style name (`*Handler`, `*Controller`, `route`, `endpoint`, `middleware`, `webhook`, `main`, …) or a concrete framework idiom in the code (`req.query`, `request.args`, `$_GET`, `HttpServletRequest`, `@GetMapping`, `os.Args`, `sys.argv`, …). Ordinary words such as `message`, `args`, `query`, `context` or `process` no longer count, so the shortcut actually fires on library/utility code.
- **Classes that need no attacker input** (`needsUserInput: false` in the catalog — hardcoded secrets, weak crypto, and similar). "Does attacker input reach the sink" is not the question for them, and the answer used to be misleading. They keep their Pass-2 verdict and carry `taint_skipped: "no_attacker_input_required"`; in reports they show as *confirmed real, reachability not established* and the HTML badge reads **NOT REQUIRED**. Consequently they are **never** counted as `exploitable`: gate on them with `--fail-on valid` (or the default `any`), not `--fail-on exploitable`.

The malware scan omits Pass 3 — intent-based findings (a planted backdoor, a hardcoded C2 endpoint) don't hinge on attacker-input reachability the way accidental vulnerabilities do, so malware findings stop after verification.

### Diff mode

`--only-diff [--diff-base <ref>]` restricts **Pass 1** to chunks belonging to files changed in the given git diff (default base: `HEAD^`; `staged` diffs the index against `HEAD`). The full, untouched chunk set is still built in the background — for free, since chunking is pure static parsing, not an LLM call — and used as call-graph context, so Pass 3 can trace a diff-introduced sink back through unchanged code. The diff is the union of the commits since the base and any uncommitted (staged or unstaged) working-tree changes; paths are matched relative to the scanned directory. **If the diff can't be resolved** — not a git repo, `git` missing, an unknown ref, or a shallow clone that doesn't contain the base commit (the default for `actions/checkout`) — `--only-diff` never skips anything: it logs the reason and scans everything, because an unresolvable diff must not be mistaken for an empty one. In CI, use `fetch-depth: 0` (or a `--diff-base` that exists in the clone) to get the real diff-scoped run. A diff that resolves and is genuinely empty scans nothing. `--diff-base` must look like a git ref (no leading `-`, no whitespace); `git` is invoked without a shell.

---

## Modes, Flags, and Examples

### `chunk` *(lower-level utility, both binaries support it via `main.js chunk`)*

Builds the semantic chunk set for a directory and writes it to `sast_chunks.json` **without running any LLM analysis** — no cost, pure static parsing. Useful for inspecting how a codebase will be split before spending API calls on it.

| Flag | Type | Default | What it does |
|---|---|---|---|
| `[path]` / `--working-dir <dir>` | string | cwd | Root directory to walk |
| `--max-chunk-size <n>` | int | `12000` | **Hard** cap on characters per chunk (over-long lines are split) |
| `--max-file-size <n>` | int | `512000` | Files longer than this many characters are skipped — and listed in the report |
| `--chunks-start <n>` | int | `0` | Slice offset into the chunk list — resume support |
| `--max-chunks <n>` | int | `1000` | Cap on chunks returned. Chunks beyond it are **reported as not scanned**, never silently dropped |
| `--skip-folders <a,b,c>` | CSV | `[]` | Extra folder names to exclude, on top of the built-in ignore set |
| `--include-folders <a,b,c>` | CSV | `[]` | Folders to scan even though they are in the built-in ignore set or are dot-directories |
| `--skip-files <a,b,c>` | CSV | `[]` | File names to exclude |
| `--skip-tests` | flag | off | Skip test folders and test-named files |
| `--include-generated` | flag | off | Scan `*.min.js` / `*.bundle.js` (`ubel-mal` does this by default) |
| `--languages <a,b,c>` | CSV | all 15 families | Restrict to specific language families |

The built-in ignore list, the dot-directory rule and the other default skips are tabulated under [Pass 1 — Scan](#pass-1--scan).

```bash
node sast/main.js chunk /path/to/project --max-chunk-size 8000 --languages python,go
```

### `analyze` *(the `ubel-sast` binary)*

Runs the full scan → verify → taint-trace pipeline against accidental vulnerability classes.

**Chunker params** — same as `chunk` above.

**LLM / provider params**

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--provider <name>` | string | `openrouter` | Key into the `PROVIDERS` registry |
| `--api-key <key>` | string | env var fallback | Auth key; falls back to the provider's env var if omitted, not required for `local`/`docker`/`docker-desktop` |
| `--api-key-header <name>` | string | provider default | Overrides the HTTP header the key is sent in |
| `--api-key-prefix <prefix>` | string | provider default | Overrides the value prefix (e.g. `"Bearer "`); passing the flag with no value is ignored |
| `--endpoint <url>` | string | provider default | Overrides the API base URL |
| `--model <name>` | string | provider default | Overrides the model string |
| `--concurrency <n>` | int | `5` | Parallel Pass-1 requests |
| `--temperature <n>` | float | `0.1` | Pass-1 sampling temperature (Passes 2/3 are hardcoded to `0`) |
| `--max-tokens <n>` | int | `4096` | Pass-1 response token budget |
| `--timeout <ms>` | int | `120000` | Per-request timeout, shared across all passes |
| `--max-retries <n>` | int | `2` | Max retry attempts per request |
| `--no-retry` | flag | retries on | Disables the parse-error-triggered retry specifically |

**Pipeline controls**

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--no-verify` | flag | verify on | Skip Pass 2 — findings get `is_valid: undefined` |
| `--no-taint` | flag | taint on | Skip Pass 3 — findings get no `taint` field |
| `--include-signals` | flag | off (signals omitted by default) | Include the "Detect when you see" bullets from the vuln catalog in the scan prompt (Pass 1 only); class name, CWE, and scope rule are always kept regardless of this flag. Roughly 6–7× the catalog size |
| `--pack-size <n>` | int | `12000` | Pack small same-language chunks into one Pass-1 call, up to `<n>` characters of code. `0` disables |
| `--pack-max-chunks <n>` | int | `10` | Maximum chunks per packed call |
| `--no-pack` | flag | packing on | One Pass-1 call per chunk (same as `--pack-size 0`) |
| `--verify-concurrency <n>` | int | = `--concurrency` | Parallel Pass-2 requests |
| `--taint-concurrency <n>` | int | = `--concurrency` | Parallel Pass-3 requests |
| `--verification-max-tokens <n>` | int | `4096` | Pass-2 response token budget |
| `--taint-max-tokens <n>` | int | `4096` | Pass-3 response token budget |
| `--taint-chain-chars <n>` | int | `24000` | Character budget of the call chain sent to Pass 3 |

**Diff mode**

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--only-diff` | flag | off | Restrict Pass 1 to diff-changed chunks; full chunk set still built for Pass 3 |
| `--diff-base <ref>` | string | `HEAD^` | Git ref to diff against; `staged` diffs the index against `HEAD` |

**Exit-code policy**

| `--fail-on` | Fails the build when… |
|---|---|
| `any` *(default)* | A finding is confirmed exploitable, verified valid, or couldn't be resolved either way (a Pass 2/3 error or inconclusive result) — "didn't finish checking" is never silently treated as clean. With both verification and taint-trace switched off, any finding at all fails the build. Findings Pass 2 dismissed as false positives never fail it. |
| `valid` | A finding was verified `is_valid: true`, regardless of exploitability. |
| `exploitable` | A finding was taint-traced with `exploitable: true`. Classes that need no attacker input (e.g. hardcoded secrets) are never traced, so they do not trip this mode — use `valid` or `any` to gate on them. |

In every mode, the JSON/HTML/SARIF reports contain **all** findings regardless of the gate — `--fail-on` only changes the process exit code, never what gets written to disk.

```bash
# Basic scan of the current directory, all defaults
ubel-sast

# Scan a specific project
ubel-sast /path/to/project

# Only scan what changed since main — fast CI re-scan
ubel-sast --only-diff --diff-base main

# Switch provider/model, cap cost with a cheaper output budget
ubel-sast --provider anthropic --model claude-haiku-4-5-20251001 --max-tokens 800

# Skip taint-trace, only fail the build on confirmed real bugs
ubel-sast --no-taint --fail-on valid

# Only fail on confirmed-exploitable findings, higher concurrency for speed
ubel-sast --fail-on exploitable --concurrency 10

# Scan only Kubernetes manifests in a mixed IaC repo (Terraform/CloudFormation/Ansible excluded)
ubel-sast --languages k8s

# Small, high-value repo — opt into the full catalog detection bullets for max recall
ubel-sast --include-signals --skip-folders legacy,scripts --languages java,kotlin

# Skip tests and raise the file-size guard for a repo with a few big generated sources
ubel-sast --skip-tests --max-file-size 1500000

# Point at a local Ollama model, no API key needed
ubel-sast --provider local --endpoint http://localhost:11434/v1/chat/completions
```

### `malware` *(the `ubel-mal` binary)*

Runs scan → verify against the 15-class intentional-malicious-code catalog. No taint-trace pass — reachability isn't the relevant question for code that's itself the payload. Writes an entirely separate report set (`*.malware.*`) so it never collides with `analyze` output.

**Flags:** identical to `analyze` above, **minus** everything taint-related (no `--no-taint`, `--taint-concurrency`, `--taint-max-tokens`, `--taint-chain-chars`). Mode-specific differences: the `--fail-on` value set below, and `*.min.js` / `*.bundle.js` are **scanned by default** (bundles are where planted code hides; `--include-generated` is implied). Like `analyze`, it hard-excludes `node_modules`, `dist`, `build`, `vendor`, `bin`, `packages` and the rest of the ignore list unless you pass `--include-folders`.

| `--fail-on` | Fails the build when… |
|---|---|
| `any` *(default)* | Any finding exists at all, including unresolved ones and ones verification dismissed as false positives (unlike `analyze`'s `any`). |
| `confirmed` | A finding was verified `is_valid: true` — unresolved findings still fail the build too, since "couldn't determine" is never treated as clean. |

```bash
# Basic backdoor/malicious-code scan
ubel-mal /path/to/project

# CI gate: only fail on confirmed malicious code
ubel-mal --fail-on confirmed

# Sweep installed dependencies. node_modules is ignored by default, so name it explicitly
ubel-mal --include-folders node_modules --provider local --concurrency 8

# Sweep one package (pointing INSIDE an ignored folder needs no flag)
ubel-mal ./node_modules/some-package

# Include build output that normally stays out
ubel-mal --include-folders dist,build,vendor

# Malware scan restricted to files changed in a PR
ubel-mal --only-diff --diff-base origin/main --fail-on confirmed
```

---

## Supported Languages

| Family | Extensions/Files |
|---|---|
| Python | `.py` |
| JavaScript / TypeScript | `.js` `.ts` `.mjs` `.cjs` |
| PHP | `.php` |
| Ruby | `.rb` |
| Go | `.go` |
| Rust | `.rs` |
| Java | `.java` |
| Kotlin | `.kt` `.kts` |
| Dart / Flutter | `.dart` (generated `*.g.dart`, `*.freezed.dart`, `*.gr.dart`, `*.mocks.dart`, `*.chopper.dart` and `generated_plugin_registrant.dart` are skipped; alias `--languages flutter`) |
| Swift | `.swift` |
| C# | `.cs` |
| C / C++ | `.c` `.h` `.cpp` `.cc` `.cxx` `.hpp` `.hh` `.hxx` |
| Docker | `Docker` `docker-compose.yml` |
| IaC | `.tf` `.tfvars`, plus content-sniffed `.yaml`/`.yml`/`.json` for CloudFormation and Ansible |
| Kubernetes | content-sniffed `.yaml`/`.yml`/`.json` (`apiVersion:` + `kind:`) — its own family, not bundled under IaC |

`--languages <a,b,c>` restricts a run to a subset of these families (e.g. `--languages python,go`).

---

## Vulnerability Catalog (64 classes)

Each catalog entry carries a canonical name, primary CWE, a `needsUserInput` flag (whether the class requires a visible attacker-controlled source to be reportable — hardcoded secrets don't, SQL injection does), the language families it realistically applies to, and a set of concrete "detect when you see" signal bullets that are shown to the model when `--include-signals` is set. Classes irrelevant to a chunk's language are filtered out before the prompt is built via `filterVulnClassesForLanguage()`.

Representative coverage: SQL/command/code injection, XSS, XXE, insecure deserialization, path traversal, SSRF, hardcoded secrets, weak cryptography, race conditions, use-after-free / buffer overflow (C/Rust/Go/JVM/.NET-scoped), CSRF, open redirect, insecure randomness, prototype pollution (JS-scoped), insecure container/pod configuration, missing Kubernetes network segmentation, IaC public-cloud exposure, and more — spanning CWE-20 through CWE-1104.

Per-language filtering already trims this list before it reaches a prompt, automatically:

| Language | Applicable classes |
|---|---|
| C | 19 / 64 |
| Ruby | 34 / 64 |
| Python | 34 / 64 |
| C# | 34 / 64 |
| Go | 33 / 64 |
| JS/TS | 35 / 64 |
| Java / Kotlin | 35 / 64 |
| PHP | 36 / 64 |
| Rust | 36 / 64 |
| Dart / Flutter | 21 / 64 |
| Swift | 23 / 64 |
| IaC (Terraform / CloudFormation / Ansible) | 5 / 64 |
| Docker | 6 / 64 |
| Kubernetes | 6 / 64 |

Dart/Flutter and Swift are mobile/client languages, so they intentionally do **not** receive the server-side web classes (CSRF, cookie attributes, CORS, GraphQL, host-header …). They get the generic classes (secrets, SQL/command injection, path traversal, crypto, null-deref, …), a few web-adjacent ones (XSS via WebView/templating, JWT handling, code injection, ReDoS), and five mobile-specific classes: insecure local data storage, insecure TLS / certificate validation, insecure WebView or JavaScript bridge, unvalidated deep link / URL scheme / platform channel input, and client-side-only biometric gates.

---

## Malicious Code Catalog (15 classes)

A deliberately separate catalog and prompt from the vulnerability scan — "was this written on purpose to do something the codebase owner would not approve of" is a different judgement from "is this an accidental bug," and mixing the two measurably increases false negatives on subtle backdoors because the model anchors on the larger, more familiar accidental-bug catalog.

| Class |
|---|
| Reverse shell / remote command execution backdoor |
| Hardcoded command-and-control (C2) endpoint |
| Obfuscated or dynamically decoded payload execution |
| Unauthorized data exfiltration |
| Hidden backdoor authentication bypass |
| Malicious persistence mechanism |
| Supply-chain implant in build/install scripts |
| Cryptomining payload |
| Anti-analysis / sandbox and debugger evasion |
| Logic bomb / time bomb |
| Disabling or tampering with security controls |
| Credential or keystroke harvesting |
| DNS tunneling / covert channel |
| Self-modifying or self-propagating code |
| Unauthorized remote dynamic code loading |

Unlike the vuln catalog, per-language filtering here is shallow — 14–15 of 15 classes apply to almost every language, since intent-based patterns like C2 beacons or persistence mechanisms aren't language-specific the way, say, CSRF is. The one exception is "supply-chain implant in build/install scripts," which excludes C.

---

## LLM Providers

| Provider key | Default model | Env var |
|---|---|---|
| `openrouter` *(default)* | `deepseek/deepseek-chat` | `OPENROUTER_API_KEY` |
| `openai` | `gpt-4o-mini` | `OPENAI_API_KEY` |
| `anthropic` | `claude-haiku-4-5-20251001` | `ANTHROPIC_API_KEY` |
| `gemini` | `gemini-2.0-flash` | `GEMINI_API_KEY` |
| `deepseek` | `deepseek-chat` | `DEEPSEEK_API_KEY` |
| `nvidia` | `deepseek-ai/deepseek-v4-flash` | `NVIDIA_KEY` |
| `local` | `llama3` | *(none — Ollama-compatible endpoint on localhost)* |
| `docker` / `docker-desktop` | `llama3` | *(none — Ollama-compatible endpoint via Docker)* |
| `custom` | *(none — the user must set all the flags of the LLM)* | `CUSTOM_API_KEY` |

Override endpoint, model, auth header, and header prefix per-run with `--endpoint`, `--model`, `--api-key-header`, and `--api-key-prefix` — useful for self-hosted or OpenAI-compatible gateways not in the registry above.

Every registry default is a small/cheap/fast model tier, not a flagship one — the tool is architected to run its (potentially thousands-of-calls) Pass-1 sweep economically, reserving the option to point `--model` at a stronger model selectively (e.g. only on `--only-diff` runs, where call volume is already small) rather than by default across a full-repo sweep.

---

## Programmatic API

`main.js` can also be invoked directly for scripting or CI wrappers that need argv control beyond what the `ubel-sast` / `ubel-mal` binaries expose:

```bash
node sast/main.js analyze /path/to/project --provider anthropic --fail-on exploitable
node sast/main.js malware /path/to/project --fail-on confirmed
```

If no subcommand is given, `analyze` is assumed and the first argument is treated as the target path.

From code, `main({ projectRoot, mode: "analyze" | "malware", ...options })` takes the same settings as camelCase options (`maxChunks`, `maxFileSize`, `includeFolders`, `includeMinified`, `skipTests`, `packSize`, `packMaxChunks`, `taintChainChars`, `skipSignals`, …) and never calls `process.exit`. The array of per-chunk `results` it returns carries a non-enumerable `scan_stats` property — `{ coverage, usage, pipeline }` — with what was not scanned, the real token usage per pass, and the packing/batching counters; the same data is written to the report's `meta`. `skipSignals` defaults to `true` here exactly as it does on the CLI.

---

## Reports

Every `analyze` run writes:

```
.ubel/reports/latest.sast.json          ← always current
.ubel/reports/latest.sast.html          ← always current
.ubel/reports/latest.sast.sarif.json    ← always current
.ubel/ubel_project.json                 ← this project's id and name (id created once, never changed)

$HOME/.ubel/history/sast/<project_id>/
    <timestamp>.sast.zip            ← YYYY_MM_DD__HH_MM_SS (UTC)
        report.sast.json
        report.sast.html
        report.sast.sarif.json
```

Every `malware` run writes the equivalent set under its own namespace:

```
.ubel/reports/latest.malware.json
.ubel/reports/latest.malware.html
.ubel/reports/latest.malware.sarif.json

$HOME/.ubel/history/malware/<project_id>/
    <timestamp>.malware.zip
        report.malware.json
        report.malware.html
        report.malware.sarif.json
```

Files follow the shared `<file_name>.<tag>.<extension>` scheme: the tag (`sast` or `malware`) sits between the file name and the extension; the file name is `latest` for the always-current copies, a timestamp for the zip, and `report` for the files inside the zip. The zips go to the shared `$HOME/.ubel/history/<mode>/` folder (the same one every UBEL scanner uses), in a sub-folder named after the project: `<project_id>` is the UUID in `<project>/.ubel/ubel_project.json`, created on the first run and never changed. `project_id` and `project_name` (also from that file) are written into the report's `meta` and shown in the HTML report's system panel — see the SCA README's [Project id](../sca/README.md#project-id-ubel_projectjson) section. A second run of the same project in the same second gets a `_2` suffix instead of overwriting the first. (Earlier versions wrote `<project>/.ubel/local/reports/sast/<date>/sast__<timestamp>.zip` and `…/malware/<date>/malware__<timestamp>.zip` with untagged `report.json` / `report.html` / `report.sarif.json` inside; old files are left untouched.)

The HTML report is fully self-contained (no server required) and includes an Executive Summary tab (right after the Dashboard), a searchable findings table, per-finding detail views (code snippet, CWE, fix suggestion, taint flow path where applicable, compliance framework mapping), and run metadata (git commit, OS, provider/model used), plus a dedicated Compliance tab. The JSON report is the full machine-readable equivalent — `{ generated_at, meta, executive_summary, results }`, where `meta.scan_type` is `analyze` or `malware`, `meta.scan_options` records the non-secret run settings **and the measured coverage** (verification and taint-trace on/off, diff mode, the limits actually in force, `chunks_found` / `chunks_scanned` / `chunks_dropped_by_cap`, files skipped as too large, AI replies cut off) the summary needs to say what was and was not checked, and `meta.scan_stats` records the **real token usage** the provider returned per pass (`usage.scan|verify|taint|total`: calls, input/output/cache-read/cache-write tokens, and `estimated_calls` for any provider that returned no usage) plus pipeline counters (packed calls, pack fallbacks, batched verify/trace calls, findings not traced); the SARIF 2.1.0 report is meant for direct consumption by CI/CD tooling and code-scanning dashboards (GitHub Code Scanning, etc.).

### Keeping UBEL's own files out of git and Docker

`ubel-sast` and `ubel-mal` write `.ubel/` (the reports above) into the scanned directory. Before the first file is read or LLM request sent, the entry point (`main.js` — never the analyzers) makes sure `.gitignore` **and** `.dockerignore` in that directory ignore `.ubel/` and `.ubelignore`, creating either file if it does not exist. It is the same guard the SCA binaries use (`sca/ignore_files.js`), with the same rules:

- **Idempotent.** An entry counts as covered if any equivalent pattern is present (`.ubel`, `/.ubel/`, `.ubel/*`, `.ubel*`, …), so a hand-written entry is never duplicated.
- **Append-only.** Existing content, ordering and line endings (LF/CRLF) are preserved; new entries go under a `# ubel:` comment.
- **Opt-out respected.** A negation such as `!.ubelignore` means you want that entry tracked, so it is not re-added.
- **Never fails a scan.** A read-only checkout or a permissions problem is swallowed (with `DEBUG` set, it is logged).
- **Where it applies.** The directory the reports are written under — the positional path / `--working-dir`, else the current directory. Changed files are announced with one `[ubel] Created|Updated …` line on stderr. Programmatically (`main({ projectRoot, … })`) it applies to `projectRoot`, but only when `save_reports` is on: with `save_reports: false` nothing is written to `.ubel/`, so nothing in your tree is touched either. `ubel-chunk` and `--help` never trigger it (`ubel-chunk` only writes `sast_chunks.json` to the current directory).
- **Kill switch:** `UBEL_NO_IGNORE_FILES=1`.

### Keeping UBEL's own files out of git and Docker

`ubel-sast` and `ubel-mal` write `.ubel/` (the reports above) into the scanned directory. Before the first file is read or LLM request sent, the entry point (`main.js` — never the analyzers) makes sure `.gitignore` **and** `.dockerignore` in that directory ignore `.ubel/` and `.ubelignore`, creating either file if it does not exist. It is the same guard the SCA binaries use (`sca/ignore_files.js`), with the same rules:

- **Idempotent.** An entry counts as covered if any equivalent pattern is present (`.ubel`, `/.ubel/`, `.ubel/*`, `.ubel*`, …), so a hand-written entry is never duplicated.
- **Append-only.** Existing content, ordering and line endings (LF/CRLF) are preserved; new entries go under a `# ubel:` comment.
- **Opt-out respected.** A negation such as `!.ubelignore` means you want that entry tracked, so it is not re-added.
- **Never fails a scan.** A read-only checkout or a permissions problem is swallowed (with `DEBUG` set, it is logged).
- **Where it applies.** The directory the reports are written under — the positional path / `--working-dir`, else the current directory. Changed files are announced with one `[ubel] Created|Updated …` line on stderr. Programmatically (`main({ projectRoot, … })`) it applies to `projectRoot`, but only when `save_reports` is on: with `save_reports: false` nothing is written to `.ubel/`, so nothing in your tree is touched either. `ubel-chunk` and `--help` never trigger it (`ubel-chunk` only writes `sast_chunks.json` to the current directory).
- **Kill switch:** `UBEL_NO_IGNORE_FILES=1`.

---

## Executive summary

`executive_summary` is a plain-language overview for readers who are not security engineers (management, risk, compliance, product owners). It is the source-code counterpart of the SCA, EASM and cloud-scanner executive summaries and follows the same rules: it is derived only from data already in the scan (no extra LLM or network calls), it is built once and shared by the JSON and HTML reports so they never differ, it avoids code and flags in its headline text, and a figure that could not be checked is `null` ("n/a" in the HTML), never `0`. Both `ubel-sast` and `ubel-mal` produce one; for `ubel-mal` the wording and rules switch to malicious-code terms.

It contains the overall risk rating with its reason and business impact, a one-page `cover` / `bottom_line` (top three risks, three things to do first, four key numbers), key findings, a `triage` breakdown of every candidate finding, scan coverage (which passes ran, per-language counts, scope limits), issues grouped by kind of weakness, issue types and files to fix first, suggested actions with default timeframes and owners, a compliance overview, scope, a **methodology** (steps actually performed, how the rating is decided, how things are prioritized, limitations), notes and a glossary. In the HTML report the tab has a *Print / save as PDF* button that prints the summary alone.

Findings are AI-proposed candidates, so the summary sorts each into exactly one group — **confirmed exploitable**, **confirmed real** (reachability not established), **blocked by other code**, **not cleared** (a pass errored or was inconclusive), **unverified** (verification off), or **dismissed as a false alarm** — and the groups add up to the total. Only the open groups count as risk; dismissed findings never do. The rating is evidence-weighted: a finding's severity is capped at **High** unless the taint trace confirmed it exploitable (so a run with `--no-taint` can't rate above High, and the summary says so), a weakness blocked by other code counts as Low, and for `ubel-mal` a confirmed malicious-code finding counts at least High.

| Rating | `analyze` rule |
|---|---|
| Critical | at least one Critical-severity issue confirmed exploitable |
| High | a High issue confirmed exploitable, or a Critical/High finding that is real or not cleared but not confirmed exploitable |
| Medium | Medium-priority issues, nothing more serious |
| Low | only low-priority issues, real weaknesses blocked by other code, or no issues but some code units could not be analyzed or were never scanned (size / count limits) |
| Minimal | nothing open, nothing uncleared, every code unit analyzed |
| Not assessed | no code unit could be analyzed — no rating is given instead of "Minimal" |

Anything that means "not everything was checked" — code units beyond the `--max-chunks` limit (including the default of 1000), files over the size limit, AI replies that were cut off, code units whose AI reply could not be decoded, verification or the taint trace switched off, `--only-diff`, `--max-chunks`/`--chunks-start`, `--languages`, `--skip-folders`/`--skip-files` — is stated in the summary and never presented as a clean result. The suggested timeframes (Critical: immediately; High: within days; the rest: next maintenance cycle) and owners are generic defaults, not your organization's remediation policy.

---

## Compliance Framework Mapping

Every finding — from both the `analyze` (vulnerability) and `malware` pipelines — is mapped onto industry compliance/security frameworks by default, no separate flag needed, across every report format.

Each finding's `vuln_class` (e.g. `"SQL injection"`, `"reverse shell / remote command execution backdoor"`) resolves to one or more internal risk categories (e.g. `injection`, `malicious_code_supply_chain`) via the same lookup table used to derive its CWE — every malicious-code finding maps to `malicious_code_supply_chain` regardless of its specific mechanism, since intentional malicious code is a supply-chain integrity concern first. Each category carries a fixed list of framework control references: **OWASP Top 10 (2021)**, **PCI DSS v4.0**, **HIPAA Security Rule**, **SOC 2**, **ISO/IEC 27001:2022**, **NIST SP 800-53 Rev. 5**, **GDPR**, and **CIS Controls v8**. As with [the SCA module's Compliance Framework Mapping](../sca/README.md#compliance-framework-mapping), this is best-effort guidance derived from public framework documentation, not a certified compliance assessment — every report's `compliance_summary.disclaimer` field says so verbatim.

Each finding gets a `cwe` array and a `compliance` object:

```json
{
  "vuln_class": "SQL injection",
  "cwe": [89],
  "compliance": {
    "categories": ["injection"],
    "frameworks": [
      { "id": "owasp_top10_2021", "name": "OWASP Top 10 (2021)", "controls": [{ "id": "A03:2021", "title": "Injection" }] }
    ]
  }
}
```

`meta.compliance_summary` on the report aggregates every finding into per-framework, per-control finding counts (same shape as the SCA module's `compliance_summary` — see its README for the full example). In the HTML report this powers a dedicated Compliance tab (one card per framework) plus a Compliance Frameworks section in each finding's detail view; in SARIF, `compliance_categories`/`compliance_frameworks` sit on each rule and the full `compliance` object sits on each result, with `compliance_summary` also attached to the run's `invocations[].properties`.

---

## CI/CD Integration

Both binaries exit non-zero on findings that clear the configured `--fail-on` bar, making them native to any CI runner:

```yaml
# GitHub Actions
- name: UBEL SAST scan
  run: ubel-sast --fail-on exploitable

- name: UBEL malicious-code scan
  run: ubel-mal --fail-on confirmed
```

```dockerfile
# Dockerfile
RUN ubel-sast --fail-on valid .
```

---

## Token Consumption & Optimization

Every scan is, mechanically, a batch of HTTP calls to a chat-completions endpoint. Total token spend is a function of **(a) how many calls are made** and **(b) how large each call's prompt is**. `--concurrency` and friends change *wall-clock time*, not total tokens consumed — that distinction matters, because it's the first thing people reach for when trying to "reduce usage" and it does nothing for cost.

### Real usage, not a guess

Each response's `usage` block is read and totalled per pass. The end-of-run summary prints calls and tokens (`LLM calls : …`, `Tokens : … in / … out (… read from cache)`), and the JSON report carries the same numbers in `meta.scan_stats.usage` (`scan`, `verify`, `taint`, `total`) next to counters for packing and batching in `meta.scan_stats.pipeline`. A provider that returns no usage is counted in `estimated_calls` with a `chars / 4` input estimate, so a measurement is never confused with a guess.

### What drives call count, pass by pass

| Pass | Runs when | Number of calls | Governed by |
|---|---|---|---|
| **1 — Scan** | always | 1 call per **pack** of small chunks, or per large chunk | chunk count and size → `--pack-size`, `--pack-max-chunks`, `--max-chunk-size`, `--max-chunks`, `--languages`, `--skip-folders/files`, `--skip-tests`, `--only-diff` |
| **2 — Verify** | default on, off via `--no-verify` | 1 call per **chunk that has findings** (all its findings together) | Pass-1 hit rate |
| **3 — Taint trace** | `analyze` only, default on, off via `--no-taint` | 1 call per chunk with verified findings **of classes that need attacker input**; none for orphans | verification pass-through, class mix, call-graph size |

A 1,000-chunk repo with a 3% hit rate costs roughly 1,000 chunks' worth of Pass-1 code plus a few dozen Pass-2/3 calls. **Pass 1 is the dominant cost by call count and by tokens** — which is why it is the pass that gets packed.

### Fixed prompt scaffolding, measured

Tokens are approximated as `chars / 4`, measured from the real prompt builders (every real prompt is **language-filtered**, so the 64-class totals in the first row are an upper bound that no single call sends):

| Component | Chars | ≈ Tokens |
|---|---|---|
| All 64 classes, with signals / lean | 50,940 / 8,110 | 12,735 / 2,028 (6.3×) |
| **Python** catalog (34 classes), with signals / lean | 28,041 / 4,205 | 7,010 / 1,051 (6.7×) |
| **JavaScript/TypeScript** catalog (35), with signals / lean | 28,525 / 4,325 | 7,131 / 1,081 (6.6×) |
| **Go** catalog (33), with signals / lean | 26,719 / 4,065 | 6,680 / 1,016 (6.6×) |
| **C/C++** catalog (19), with signals / lean | 16,248 / 2,272 | 4,062 / 568 (7.2×) |
| **Dart** (21) / **Swift** (23), lean | 2,626 / 2,876 | 657 / 719 |
| Terraform (5) / Dockerfile (6), lean | 639 / 748 | 160 / 187 |
| Malware catalog (15 classes), with signals / lean | 9,092 / 789 | 2,273 / 197 |
| Scan prompt scaffold (rules + schema + headers, catalog excluded) | ~2,800 | ~700 |
| **Whole static prefix per Pass-1 call**, Python, lean / with signals | 6,982 / 30,818 | ~1,750 / ~7,700 |
| Verification prompt scaffold (excluding code + finding JSON) | ~950 | ~240 |
| Taint prompt scaffold (excluding call-chain code) | ~1,500 | ~375 |

Class name, CWE, and the scope rule (attacker-input-required or not) are always retained; only the worked-example detection bullets are gated behind `--include-signals`. Signals are omitted by default because Pass 1 is the dominant cost — pass the flag when the extra recall is worth roughly **6× the catalog** (about 6k extra tokens on every Python call), e.g. a small or high-value repo.

### Why packing matters — measured on this repository

On the `sast/` directory itself (242 chunks): the median chunk is 588 characters of code and 64% of chunks are under 1,000. With one call per chunk, the fixed prefix is the large majority of Pass-1 input — about **77%** in the default lean mode and about **94%** with `--include-signals`. Packing (default `--pack-size 12000`, ≤10 chunks per call, same language only) turns **242 calls into 57**:

| Pass-1 mode | One call per chunk | Packed | Saved |
|---|---|---|---|
| Lean (default) | 242 calls, ≈549k tokens | 57 calls, ≈225k tokens | **≈59%** |
| `--include-signals` | 242 calls, ≈2.01M tokens | 57 calls, ≈570k tokens | **≈72%** |

(Input-token estimates, comment-stripped code; real savings depend on language mix and chunk sizes.) Packing does not change what is sent about each chunk — only how many times the scaffold is paid for.

### Chunk body cost

Each chunk's code is appended after `stripComments()` runs (comments never reach the LLM — a free, small saving). `--max-chunk-size` is a hard cap on a chunk (12,000 characters ≈ 3,000 tokens by default), so a single huge line can no longer become one enormous call. It does **not** merge small functions — packing does that — so raising it only matters for functions that would otherwise be split mid-body; lowering it makes more, smaller chunks (which packing then regroups).

### Prompt caching

Every request is built as a **static prefix** (role, catalog, rules, schema — identical for every chunk of a language) followed by the variable code. On Anthropic the prefix is sent as its own content block with `cache_control: {type: "ephemeral"}`, so after the first call the rest read it from cache (`cache_read_tokens` in the report). Prefixes under ~4,000 characters are sent without the marker, and a model whose minimum cacheable length is above the prefix size simply won't cache — the lean prefix is near that boundary on some models, so the saving is largest with `--include-signals`. OpenAI-, DeepSeek- and Gemini-style endpoints cache identical prompt prefixes automatically; the prefix-first layout is what lets them.

### Per-finding passes

- **Verify** sends a chunk once with all of its findings (see Pass 2). The per-finding bookkeeping fields are no longer included in the prompt.
- **Taint trace** builds the call chain once per chunk, caps it at 15 chunks **and** `--taint-chain-chars` characters (call-site windows for callers, function heads for callees), and traces all of the chunk's findings in one call. It is skipped for classes that need no attacker input and for orphans (see Pass 3). `--taint-max-tokens` only bounds the *response*; the levers on request size are `--taint-chain-chars`, `--no-taint`, or fewer findings reaching Pass 3.

### Retry behavior and its token cost

A Pass-1 reply that fails JSON parsing is handled by what actually went wrong, instead of always doubling `max_tokens`:

- **Cut off, but at least one complete finding precedes the cut** → those findings are kept (no second call). The chunk is marked `partial_output`, counted in the report, and the executive summary says findings after the cut may be missing.
- **Cut off before any finding completed** → one retry with `max_tokens` doubled (capped at 32,768).
- **Complete but unparseable** (prose, markdown, a bad escape) → one retry at the *same* `max_tokens`; doubling cannot help.
- A **packed** call whose reply is unreadable, truncated or unattributable is not salvaged — its chunks are re-scanned individually.

Disable the parse retry with `--no-retry`. This is separate from the transport-failure retry loop governed by `--max-retries`; rate-limit (`429`) retries re-send the same request at the original `maxTokens`. Verification and taint calls retry only on transport failure.

### Concurrency ≠ token cost

`--concurrency`, `--verify-concurrency`, and `--taint-concurrency` control how many requests are in flight at once — they change how fast the total call count gets processed, not how large that total is. Raising concurrency is free from a spend perspective, though it raises requests/sec against provider rate limits, which can trigger more `429`/backoff cycles.

### `--only-diff` — the highest-leverage lever for repeat runs

Because Pass 1 is normally the majority of total calls, restricting it to files touched since `--diff-base` is the single biggest lever for repeat/CI runs — a PR touching 5 files out of 500 pays roughly `(5/500)` of the normal Pass-1 bill, plus whatever Pass 2/3 calls the new findings generate. The full chunk set is still built (for Pass 3's cross-file resolution), but that costs nothing — chunking has no LLM calls. In a shallow CI checkout the base commit is usually missing, so UBEL scans everything (and says so); use `fetch-depth: 0` to get the saving.

### Optimization playbook, ordered by typical impact

1. **`chunk` first, always**, on an unfamiliar repo — free, and shows the real chunk count (and anything that would be capped or skipped) before spend is committed.
2. **`--only-diff --diff-base <ref>`** for any repeat/CI run against an already-baselined codebase.
3. **Leave packing on** (the default) — it is the biggest single saving on a full sweep. Raise `--pack-size` (e.g. 16000–24000) for models with generous context; use `--no-pack` only to debug a model that handles multi-chunk prompts badly.
4. **Leave `--include-signals` off** (the default) — it multiplies the catalog about 6×. Turn it on only when the extra recall is worth it.
5. **`--skip-tests`**, **`--languages <subset>`** and **`--skip-folders`** on repos with test suites, incidental languages or vendored code you don't need scanned.
6. **Use a provider with prompt caching** (Anthropic, or any endpoint that caches identical prefixes) — most valuable together with `--include-signals`.
7. **Right-size `--max-tokens`** for Pass 1: a packed call returns findings for several chunks, so an over-small budget produces truncated replies (kept up to the cut, but the tail is lost).
8. **`--no-taint`** when "is this a real bug" (verification) is enough without confirming attacker-reachability — removes the most expensive per-call pass.
9. **`--concurrency` tuning is a speed lever, not a cost lever.**
10. **Cheap model by default, expensive model selectively** — keep registry defaults for full-repo sweeps, reserve a stronger `--model` for `--only-diff` runs or a manual second pass on confirmed/exploitable findings only.

---

## Quick-start examples

```bash
# Full vulnerability scan of the current directory
ubel-sast

# Only fail the build on confirmed-exploitable findings
ubel-sast --fail-on exploitable

# Scan only files changed since main
ubel-sast --only-diff --diff-base main

# Use Anthropic instead of the default OpenRouter provider
ubel-sast --provider anthropic --api-key sk-ant-...

# Malicious-code / backdoor scan, confirmed-only gate
ubel-mal --fail-on confirmed

# Inspect how a codebase will be chunked before spending API calls
ubel-chunk . --max-chunk-size 8000

# Cheapest possible full scan (signals omitted by default)
ubel-sast --no-taint --provider local

# Cheapest possible CI re-scan on a PR
ubel-sast --only-diff --diff-base main

# Highest-fidelity scan (accept the cost)
ubel-sast --provider anthropic --model claude-opus-4-8 --max-tokens 2048 --include-signals
```

---

*Ubel — Find the bug before it finds production.*

## License

UBEL is source-available under an **internal-use-only** license. You may install, run, and modify it for your own organization's internal needs, including your own CI/CD pipelines and products. You may not redistribute, wrap, or embed it, expose it to third parties over a network or API, or use it to provide scanning or similar services to others. See [LICENSE.md](https://github.com/AlaBouali/ubel/blob/main/LICENSE.md) for the full terms, including the consultant-use exception.