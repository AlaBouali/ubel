# UBEL — Unified Bill / Enforced Law
### AI-Powered Static Analysis & Malicious Code Scanner

Ubel chunks a codebase into semantically-bounded units, runs them through a three-pass LLM pipeline — **scan → verify → taint trace** — and cross-references findings against a structured, CWE-mapped vulnerability catalog to surface real, exploitable bugs instead of generic pattern-matches.

This document covers the **SAST / malware-scan** component (source-level code analysis, as opposed to the dependency/SCA firewall).

---

## Features

- Semantic code chunker across 10 language families — class/function-aware boundaries, not naive line-splitting
- Three-pass analysis pipeline for vulnerability findings: **scan** (Pass 1) → **verify** (Pass 2) → **taint trace** (Pass 3)
- Structured, CWE-mapped vulnerability catalog — 46 classes across 10 language families, each with concrete "detect when you see" signals fed to the model
- Per-language catalog filtering — classes irrelevant to a chunk's language are dropped before the prompt is built, cutting token usage and false positives
- Cross-chunk call-graph resolution — `buildFullCallChain` walks callers/callees across chunk boundaries so the taint-trace pass reasons about real source→sink flow, not a single isolated snippet
- Separate **malicious code / backdoor** scan — its own catalog (15 classes: reverse shells, C2 beacons, supply-chain implants, persistence, exfiltration, anti-analysis evasion, logic bombs, and more), own prompts, own report set, never mixed with accidental-vulnerability findings
- `--only-diff` mode — scan only chunks touched by a git diff, while still building the full chunk set so cross-file taint chains keep resolving correctly
- Configurable `--fail-on` exit-code gate (`any` / `valid` / `exploitable` for SAST, `any` / `confirmed` for malware) — reports always contain every finding regardless of this flag; it only changes the CI exit code
- Pluggable LLM provider registry — OpenRouter, OpenAI, Anthropic, Gemini, DeepSeek, NVIDIA, and local/Docker-hosted models (Ollama-compatible), selectable per run with no code changes
- Automatic report generation: timestamped **JSON** + interactive **HTML** + **SARIF 2.1.0**, plus `latest.*` convenience links, kept in a separate namespace per scan type so SAST and malware runs never collide
- Zero external runtime dependencies (Node.js stdlib only)

---

## Installation

```bash
npm install -g @arcane-spark/ubel-sast
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

So `ubel-sast [args]` ≡ `node main.js analyze [args]`, and `ubel-mal [args]` ≡ `node main.js malware [args]`. A third subcommand, `chunk`, is reachable only via `node sast/main.js chunk` directly (no dedicated binary) — it's the free "look before you spend tokens" utility. Every flag documented below applies to both `analyze` and `malware` unless stated otherwise.

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

The chunker (`buildChunks`) walks the target directory, skipping `node_modules`, `vendor`, `dist`, `.git`, and similar noise directories, and splits each source file into semantically-bounded chunks (functions, classes, or brace-delimited blocks depending on the language) up to `--max-chunk-size` characters each. Each chunk has its comments stripped (`stripComments`) before submission, is matched against the vulnerability (or malware) catalog filtered to its language family, and sent to the configured LLM provider, which returns candidate findings with a `vuln_name`, `CWE`, code snippet, description, fix suggestion, and confidence level.

### Pass 2 — Verify

Every candidate finding from Pass 1 is re-submitted, alongside its originating chunk, to the LLM with a narrower prompt: *is this finding actually valid given the code shown?* This catches cases where Pass 1 flagged a pattern that is provably safe in context (e.g. a query built from a fully hardcoded string that only looks parameterized). Verification always runs at `temperature: 0` regardless of the `--temperature` flag — it's a binary verdict and needs to be deterministic — and sets `is_valid: true | false | null` (`null` = inconclusive) on each finding.

### Pass 3 — Taint Trace (SAST only)

For findings that need attacker-controlled input to be exploitable, `buildFullCallChain` walks the call graph — masking out string/comment contents first so identifiers inside logs or strings never produce false call edges — to resolve the finding's full caller/callee chain across chunk boundaries, up to a configurable depth (10 BFS levels, capped at 15 total chunks in the assembled chain). The assembled call chain is handed to the LLM, also at `temperature: 0`, with a dedicated prompt asking whether attacker input can actually reach the flagged sink, and whether any sanitization occurs along the way. This pass sets `taint.exploitable`, `taint.reachable`, `taint.sanitized`, and `taint.flow_path` on the finding. Findings that resolve to an isolated function with no callers and no entry-point signature are short-circuited locally with `inconclusive_reason: "orphan_no_callers"` — no LLM call spent.

The malware scan omits Pass 3 — intent-based findings (a planted backdoor, a hardcoded C2 endpoint) don't hinge on attacker-input reachability the way accidental vulnerabilities do, so malware findings stop after verification.

### Diff mode

`--only-diff [--diff-base <ref>]` restricts **Pass 1** to chunks belonging to files changed in the given git diff (default base: `HEAD^`; `staged` diffs the index against `HEAD`). The full, untouched chunk set is still built in the background — for free, since chunking is pure static parsing, not an LLM call — so Pass 3's call-graph resolution can trace a diff-introduced sink back through unchanged code. If the diff base ref can't be resolved (shallow clone, first commit), it falls back to `git diff --name-only HEAD` and, failing that, scans everything. `--diff-base` is validated against `/^[\w\/\.\-]+$/` before being shelled out to `git`, as a shell-injection guard.

---

## Modes, Flags, and Examples

### `chunk` *(lower-level utility, both binaries support it via `main.js chunk`)*

Builds the semantic chunk set for a directory and writes it to `sast_chunks.json` **without running any LLM analysis** — no cost, pure static parsing. Useful for inspecting how a codebase will be split before spending API calls on it.

| Flag | Type | Default | What it does |
|---|---|---|---|
| `[path]` / `--working-dir <dir>` | string | cwd | Root directory to walk |
| `--max-chunk-size <n>` | int | `12000` | Max characters per chunk |
| `--chunks-start <n>` | int | `0` | Slice offset into the chunk list — resume support |
| `--max-chunks <n>` | int | `1000` | Hard cap on chunks returned |
| `--skip-folders <a,b,c>` | CSV | `[]` | Extra folder names to exclude, on top of the built-in ignore set |
| `--skip-files <a,b,c>` | CSV | `[]` | File names to exclude |
| `--languages <a,b,c>` | CSV | all 10 families | Restrict to specific language families |

Built-in ignore directories (always excluded, on top of `--skip-folders`): `node_modules`, `.nyc_output`, `__pycache__`, `.mypy_cache`, `.pytest_cache`, `.tox`, `venv`, `.venv`, `env`, `.env`, `eggs`, `.eggs`, `htmlcov`, `dist`, `build`, `out`, `target`, `bin`, `obj`, `vendor`, `.gradle`, `.idea`, `.vs`, `packages`, `.git`, `.svn`, `.hg`, `coverage`.

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
| `--skip-signals` | flag | off | Omit the "Detect when you see" bullets from the vuln catalog in the scan prompt (Pass 1 only); class name, CWE, and scope rule are always kept |
| `--verify-concurrency <n>` | int | = `--concurrency` | Parallel Pass-2 requests |
| `--taint-concurrency <n>` | int | = `--concurrency` | Parallel Pass-3 requests |
| `--verification-max-tokens <n>` | int | `4096` | Pass-2 response token budget |
| `--taint-max-tokens <n>` | int | `4096` | Pass-3 response token budget |

**Diff mode**

| Flag | Type | Default | What it does |
|---|---|---|---|
| `--only-diff` | flag | off | Restrict Pass 1 to diff-changed chunks; full chunk set still built for Pass 3 |
| `--diff-base <ref>` | string | `HEAD^` | Git ref to diff against; `staged` diffs the index against `HEAD` |

**Exit-code policy**

| `--fail-on` | Fails the build when… |
|---|---|
| `any` *(default)* | Any finding exists at all — including ones Pass 2/3 couldn't resolve either way. "Didn't finish checking" is never silently treated as clean. |
| `valid` | A finding was verified `is_valid: true`, regardless of exploitability. |
| `exploitable` | A finding was taint-traced with `exploitable: true`. |

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

# Trim prompt size (skip catalog detection bullets) for a big legacy repo
ubel-sast --skip-signals --skip-folders legacy,scripts --languages java,kotlin

# Point at a local Ollama model, no API key needed
ubel-sast --provider local --endpoint http://localhost:11434/v1/chat/completions
```

### `malware` *(the `ubel-mal` binary)*

Runs scan → verify against the 15-class intentional-malicious-code catalog. No taint-trace pass — reachability isn't the relevant question for code that's itself the payload. Writes an entirely separate report set (`*.malware.*`) so it never collides with `analyze` output.

**Flags:** identical to `analyze` above, **minus** everything taint-related (no `--no-taint`, `--taint-concurrency`, `--taint-max-tokens`). The only mode-specific difference is the `--fail-on` value set:

| `--fail-on` | Fails the build when… |
|---|---|
| `any` *(default)* | Any finding exists at all, including unresolved ones. |
| `confirmed` | A finding was verified `is_valid: true` — unresolved findings still fail the build too, since "couldn't determine" is never treated as clean. |

```bash
# Basic backdoor/malicious-code scan
ubel-mal /path/to/project

# CI gate: only fail on confirmed malicious code
ubel-mal --fail-on confirmed

# Cheap, fast malware sweep on a dependency tree pulled in via CI
ubel-mal --skip-signals --provider local --concurrency 8

# Malware scan restricted to files changed in a PR
ubel-mal --only-diff --diff-base origin/main --fail-on confirmed
```

---

## Supported Languages

| Family | Extensions |
|---|---|
| Python | `.py` |
| JavaScript / TypeScript | `.js` `.ts` `.mjs` `.cjs` |
| PHP | `.php` |
| Ruby | `.rb` |
| Go | `.go` |
| Rust | `.rs` |
| Java | `.java` |
| Kotlin | `.kt` `.kts` |
| C# | `.cs` |
| C / C++ | `.c` `.h` `.cpp` `.cc` `.cxx` `.hpp` `.hh` `.hxx` |

`--languages <a,b,c>` restricts a run to a subset of these families (e.g. `--languages python,go`).

---

## Vulnerability Catalog (46 classes)

Each catalog entry carries a canonical name, primary CWE, a `needsUserInput` flag (whether the class requires a visible attacker-controlled source to be reportable — hardcoded secrets don't, SQL injection does), the language families it realistically applies to, and a set of concrete "detect when you see" signal bullets shown to the model. Classes irrelevant to a chunk's language are filtered out before the prompt is built via `filterVulnClassesForLanguage()`.

Representative coverage: SQL/command/code injection, XSS, XXE, insecure deserialization, path traversal, SSRF, hardcoded secrets, weak cryptography, race conditions, use-after-free / buffer overflow (C/Rust/Go/JVM/.NET-scoped), CSRF, open redirect, insecure randomness, prototype pollution (JS-scoped), and more — spanning CWE-20 through CWE-943.

Per-language filtering already trims this list before it reaches a prompt, automatically:

| Language | Applicable classes |
|---|---|
| C | 19 / 45 |
| Python | 34 / 45 |
| C# | 34 / 45 |
| JS/TS | 35 / 45 |
| Rust | 36 / 45 |

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

---

## Reports

Every `analyze` run writes:

```
.ubel/reports/latest.sast.json          ← always current
.ubel/reports/latest.sast.html          ← always current
.ubel/reports/latest.sast.sarif.json    ← always current

.ubel/local/reports/sast/<YYYY>/<MM>/<DD>/
    sast__<timestamp>.json
    sast__<timestamp>.html
    sast__<timestamp>.sarif.json
```

Every `malware` run writes the equivalent set under its own namespace:

```
.ubel/reports/latest.malware.json
.ubel/reports/latest.malware.html
.ubel/reports/latest.malware.sarif.json

.ubel/local/reports/malware/<YYYY>/<MM>/<DD>/
    malware__<timestamp>.json
    malware__<timestamp>.html
    malware__<timestamp>.sarif.json
```

The HTML report is fully self-contained (no server required) and includes a searchable findings table, per-finding detail views (code snippet, CWE, fix suggestion, taint flow path where applicable), and run metadata (git commit, OS, provider/model used). The JSON report is the full machine-readable equivalent; the SARIF 2.1.0 report is meant for direct consumption by CI/CD tooling and code-scanning dashboards (GitHub Code Scanning, etc.).

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

Every scan is, mechanically, a large batch of independent HTTP calls to a chat-completions endpoint. Total token spend is a function of **(a) how many calls are made** and **(b) how large each call's prompt is**. `--concurrency` and friends change *wall-clock time*, not total tokens consumed — that distinction matters, because it's the first thing people reach for when trying to "reduce usage" and it does nothing for cost.

### What drives call count, pass by pass

| Pass | Runs when | Number of calls | Governed by |
|---|---|---|---|
| **1 — Scan** | always | 1 call per non-import chunk that survives filtering | chunk count → `--max-chunk-size`, `--max-chunks`, `--languages`, `--skip-folders/files`, `--only-diff` |
| **2 — Verify** | default on, off via `--no-verify` | 1 call per **finding** from Pass 1 (not per chunk) | Pass-1 hit rate |
| **3 — Taint trace** | `analyze` only, default on, off via `--no-taint` | 1 call per verified finding (or per *every* finding if `--no-verify` is also set) | verification pass-through + call-graph size per finding |

A 1,000-chunk repo with a 3% Pass-1 hit rate produces roughly: 1,000 scan calls + ~30 verify calls + ~15–25 taint calls (`analyze`) or 1,000 scan calls + ~30 verify calls (`malware`). **Pass 1 is the dominant cost by call count** in almost every real run — Passes 2 and 3 are a small fraction of total calls, but individually *larger* prompts, so they're not negligible per-call.

### Fixed prompt scaffolding, measured

Approximating tokens as `chars / 4` (measured directly from the actual prompt-builder output):

| Component | Chars | ≈ Tokens |
|---|---|---|
| Full vuln catalog, 45 classes, with signals (unfiltered) | 30,523 | ~7,631 |
| Full vuln catalog, 45 classes, no signals (`--skip-signals`) | 5,618 | ~1,405 |
| Malware catalog, 15 classes, with signals | 8,642 | ~2,161 |
| Malware catalog, 15 classes, no signals | 789 | ~197 |
| Scan prompt scaffold (rules + schema + headers, catalog excluded) | ~2,600 | ~650 |
| Verification prompt scaffold (excluding injected code + finding JSON) | ~1,000 | ~250 |
| Taint prompt scaffold (excluding injected call-chain code) | ~1,800 | ~450 |

Per-language catalog filtering (see the catalog table above) already trims the 45-class list before it reaches a prompt — automatic, not a flag. Worked for a Python chunk, a full Pass-1 prompt (scaffold + catalog + empty-ish code) measures ~26,115 chars (~6,529 tokens) with signals vs. ~7,122 chars (~1,781 tokens) with `--skip-signals` — **roughly a 3.7× reduction** in the catalog+scaffold portion of every Pass-1 call, before the code chunk is even added. Class name, CWE, and the scope rule (attacker-input-required or not) are always retained; only the worked-example detection bullets are dropped.

### Chunk body cost

Each chunk's code is appended after `stripComments()` runs (comments never reach the LLM — a free, small saving). `--max-chunk-size` caps this at 12,000 characters by default, i.e. up to ~3,000 tokens of code per Pass-1 call on top of scaffold+catalog. Lowering `--max-chunk-size` produces *more, smaller* chunks — it doesn't reduce total code tokens sent, but it does mean the fixed scaffold+catalog cost is paid more times over. **Larger chunks are generally more token-efficient**, as long as the model's output budget (`--max-tokens`) can still cover a chunk's worth of findings.

### The taint-trace call chain — the pass most likely to blow up spend

`buildFullCallChain()` BFS-walks up to 10 levels of callers and callees across the entire chunk map (masking string/comment contents so a log line mentioning a function name never creates a false edge), caps any single function name's callers at 20 matches before treating it as too generic, and hard-excludes common short names (`run`, `get`, `handle`, etc.) regardless of match count. The assembled chain is capped at **15 chunks total**, split roughly evenly between caller-side and callee-side context. That means one taint-trace call can legitimately bundle up to 15 full chunks — easily the largest individual call type in the pipeline. Two things bound this automatically:

- **Orphan short-circuit**: a finding whose chunk has no callers and no entry-point signature (no route/handler-style name, no `req`/`ctx` framework idioms) skips the LLM call entirely — answered locally as `inconclusive_reason: "orphan_no_callers"`, at zero token cost.
- The 15-chunk cap is a hard ceiling regardless of the real call graph's size.

`--taint-max-tokens` only bounds the *response*; the practical levers on Pass-3 request cost are `--no-taint` (cuts it to zero) or reducing how many findings reach Pass 3 in the first place.

### Retry behavior and its token cost

If a Pass-1 response fails JSON parsing and `retryOnParseError` is true (default; disable via `--no-retry`), the retry doubles `maxTokens` for that one attempt, on the theory that parse failures are often truncation from too-small a budget. This is separate from, and additional to, the transport-failure retry loop governed by `--max-retries`. Setting `--max-tokens` too low doesn't just risk truncated findings — it can silently double the Pass-1 output budget on every chunk the model struggles with, compounding at high concurrency across a large chunk set. Verification and taint calls don't have this doubling behavior — their retries only fire on transport failure, at the original `maxTokens`.

### Concurrency ≠ token cost

`--concurrency`, `--verify-concurrency`, and `--taint-concurrency` control how many requests are in flight at once — they change how fast the total call count gets processed, not how large that total is. Raising concurrency is free from a spend perspective, though it raises requests/sec against provider rate limits, which can trigger more `429`/backoff cycles — those retries do cost tokens, at the original (non-doubled) `maxTokens`.

### `--only-diff` — the highest-leverage lever for repeat runs

Because Pass 1 is normally the majority of total calls, restricting it to files touched since `--diff-base` is the single biggest lever for repeat/CI runs — a PR touching 5 files out of 500 pays roughly `(5/500)` of the normal Pass-1 bill, plus whatever Pass 2/3 calls the new findings generate. The full chunk set for all 500 files is still built (for Pass 3's cross-file resolution), but that costs nothing — chunking has no LLM calls.

### Optimization playbook, ordered by typical impact

1. **`chunk` first, always**, on an unfamiliar repo — free, and shows the real chunk count before spend is committed.
2. **`--only-diff --diff-base <ref>`** for any repeat/CI run against an already-baselined codebase.
3. **`--skip-signals`** cuts the catalog+scaffold portion of every Pass-1 call by ~3–4×, trading some recall for a flat, compounding saving.
4. **Right-size `--max-tokens`** for Pass 1 to avoid the parse-error doubling path firing repeatedly.
5. **`--no-taint`** when "is this a real bug" (verification) is enough without confirming attacker-reachability — removes the most expensive per-call pass.
6. **`--languages <subset>`** on monorepos with incidental languages you don't need scanned.
7. **Bigger `--max-chunk-size`, not smaller**, unless specific functions risk truncated findings.
8. **`--concurrency` tuning is a speed lever, not a cost lever.**
9. **Cheap model by default, expensive model selectively** — keep registry defaults for full-repo sweeps, reserve a stronger `--model` for `--only-diff` runs or a manual second pass on confirmed/exploitable findings only.

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
node sast/main.js chunk . --max-chunk-size 8000

# Cheapest possible full scan
ubel-sast --skip-signals --no-taint --provider local

# Cheapest possible CI re-scan on a PR
ubel-sast --only-diff --diff-base main --skip-signals

# Highest-fidelity scan (accept the cost)
ubel-sast --provider anthropic --model claude-opus-4-8 --max-tokens 2048
```

---

*Ubel — Find the bug before it finds production.*