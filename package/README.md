# ubel-package

Static security analysis of **one dependency release**, downloaded from its registry. Give it a package name, a version and an ecosystem (and, optionally, a registry URL); it fetches the archive, reads it, and reports what installing, building or importing it would do. No third-party libraries are used, and the package is **never installed, built or run**.

```
ubel-package <name> <version> <ecosystem> [--registry <url>]
ubel-package left-pad 1.3.0 npm
ubel-package requests 2.31.0 pypi --registry https://pypi.example.com
ubel-package serde_derive latest cargo
ubel-package github.com/gorilla/mux v1.8.1 go --registry https://goproxy.example.com
ubel-package x 1.0.0 npm --file ./x-1.0.0.tgz   # analyse a local archive
ubel-package left-pad 1.3.0 npm                 # static source analysis (SAST + malware, no LLM, no network) is always part of the scan
ubel-package left-pad 1.3.0 npm --rules-dir ./semgrep-rules   # … and your own Semgrep-syntax rules in the SAST pass
```

| Ecosystem | Names accepted | Archive | Default registry |
| --- | --- | --- | --- |
| npm | `npm`, `pnpm`, `yarn`, `bun` | `.tgz` | registry.npmjs.org |
| PyPI | `pypi`, `pip`, `uv`, `poetry`, `pipx` | sdist `.tar.gz` and wheels (`--artifact sdist\|wheel\|all`) | pypi.org (JSON API, else the Simple API for private indexes) |
| crates.io | `cargo`, `crates`, `rust` | `.crate` | the sparse index (`index.crates.io`) |
| Go | `go`, `golang` | module `.zip` | proxy.golang.org (GOPROXY protocol) |
| RubyGems | `gem`, `bundler`, `ruby` | `.gem` | rubygems.org |
| NuGet | `nuget`, `dotnet` | `.nupkg` | api.nuget.org (v3 service index) |
| Packagist | `composer`, `php` | zip | repo.packagist.org |
| pub.dev | `pub`, `dart`, `flutter` | `.tar.gz` | pub.dev |

Not supported, with the reason printed when named: conda (zstd / bzip2 archives), SwiftPM and Carthage (git repositories, not registry artifacts), OS packages (`ubel-apt`, `ubel-dnf`), Maven (use the Java scanners). bzip2, xz and zstd archives cannot be read with Node built-ins and are reported as an analysis gap.

## What it reports

Everything is filed in the same report as the other UBEL scanners (`report.package.json` / `report.package.html`, the history bundle, the diff against the previous run, the compliance mapping and the `--fail-on` gate with exit codes 0/1/2/3).

| Question | Where | How |
| --- | --- | --- |
| Pre / post-install scripts and other code that runs on the consumer's machine | **Package Info → hooks**, findings `package.install.*` | npm `preinstall` / `install` / `postinstall` (and the implicit `node-gyp rebuild` when `binding.gyp` exists), PyPI `setup.py` / build backends / `.pth` / `sitecustomize` / entry points, cargo `build.rs` and proc-macros, gem extensions (`extconf.rb`) and `rubygems_plugin.rb`, NuGet `install.ps1` / `init.ps1` / MSBuild `.targets` and analyzers, Composer plugins and `autoload.files`, pub build hooks, Go `cgo`. Each hook says whether it reaches **consumers** (and when) or only the publisher. |
| What those scripts do | the hook's "what it does" column, findings by rule | The command line of npm lifecycle scripts is read: download-and-run, inline shell, package installs, credential reads, persistence, destructive commands, privilege changes, encoded payloads, reverse shells, miners, TLS verification off. The files a hook runs (`setup.py`, `build.rs`, `extconf.rb`, …) are read by the malware and SAST engines like the rest of the source, with the install-time context added to their findings. |
| **Dependencies installed when scripts run** | `package.install.runtime_install`, **Package Info → install-time installs** | `npm install`, `pip install`, `gem install`, `cargo install`, `go get` … inside a hook: packages the lockfile, the pin review and the advisory check never see. |
| Pinned versions of dependencies | **Package Info → declared dependencies**, findings `package.dep.*` | Each declaration is classed `pinned`, `minimum`, `range`, `unbounded`, `not from the registry` (git / URL / path / branch) or `unknown`, per ecosystem's own rules (caret and tilde ranges, PEP 440, Cargo's bare version = caret, Go minimal version selection, NuGet "plain version = minimum", Composer constraints, pub constraints). |
| Known vulnerabilities and known-malicious releases | **Dependencies**, findings `package.vulnerable`, `package.malicious`, `package.dep.vulnerable`, `package.dep.malicious` | OSV.dev, by exact version: the release itself, declared dependencies with an exact (or minimum) version, copies bundled inside the archive, and component banners found in native files (NVD). OSV `MAL-` advisories are reported as critical. Ranges and unbounded declarations are shown as *not queried*: the installed version is chosen at install time. |
| Remote hosts | **Behavior → Remote hosts**, findings `package.install.remote_fetch`, `package.code.exfiltration` | Every host named in the package's files, with the file it is in, whether it is clear text, private, and flags: paste sites, callback services, tunnels, chat webhooks, dynamic DNS, URL shorteners, raw code hosts, bare public IPs. A host named in install-time code is a finding only when it is a hostile kind of host or the file can reach the network (a project URL in `setup.py` metadata is not a fetch). |
| Behavior and other behaviors | **Behavior** tab | The same inventory as `ubel-binary` (process, network, file access, dynamic loading, credentials, persistence, obfuscation …), filled from the package's source and scripts, split by where the code runs (install-time, package code, bundled dependency, tests / docs). |
| Secrets | **Secrets** tab | The shared secret scanner over every text file (the package's own code and bundled / test code are tagged separately), plus files that normally hold secrets (`.npmrc`, `.pypirc`, private keys, `.env`, `id_rsa` …). |
| Vulnerabilities in the package's own source | **Vulnerabilities** tab, findings `package.sast.*` (canonical type `vuln`) | The deterministic rule engine of `ubel-sast --no-llm` (injection, unsafe deserialization, path traversal, weak crypto, template / XSS, IaC and Dockerfile checks … with data-flow and sanitiser checks) plus your own rules from `--rules-dir`. See [Static source analysis](#static-source-analysis-sast-and-malware). |
| Malicious code in the package's own source | **Vulnerabilities** tab, findings `package.mal.*` (canonical type `mal`) | The malware rule set of `ubel-mal --no-llm` (reverse shells, miners, credential theft, exfiltration, persistence, encoded payloads, evasion …), run on the same files. These rules replace the source-pattern rules this tool used to have of its own (`package.code.*` / source-based `package.install.*`). See [Static source analysis](#static-source-analysis-sast-and-malware). |
| Binaries inside the package | **Native binaries** tab | Every ELF / Mach-O / PE file is analysed like `ubel-binary` does (hardening, risky imports, behavior, secrets in strings, hosts, component banners). A native executable named like a text file or an image is a `package.files.disguised_binary` finding. |
| Misconfigurations | **Misconfigurations** tab | Unbounded or non-registry dependencies, package-manager configuration shipped in the package, plain-`http` sources, compiled bytecode without source, nested archives, archive problems (path traversal, links that leave the package, setuid files, device files, duplicate entries), yanked / deprecated releases. |
| Integrity | **Package Info → downloaded archive** | The archive is checked against the registry's own digest (npm `dist.integrity`, PyPI sha256, crates.io checksum, RubyGems sha, NuGet catalog `packageHash` when the catalog is reachable, Go `h1:` against `sum.golang.org` when the default proxy is used, Composer `shasum` when the metadata has one); a mismatch is critical, a missing digest is reported as *unverified*. npm **manifest confusion** (the registry says no scripts, the tarball has them) is a high finding. |

### Python dependency sources

A release is read for every place Python tooling can state a dependency, not only `Requires-Dist`:

- `PKG-INFO` / wheel `METADATA`, `*.egg-info/requires.txt`;
- `pyproject.toml`: `[project]` and optional dependencies, `[build-system].requires`, PEP 735 `[dependency-groups]` (with `include-group`), Poetry (`dependencies`, `dev-dependencies`, `group.*`, git / path / url sources), PDM and uv dev groups, `[tool.uv.sources]`, Flit, Hatch environments, and `tool.setuptools.dynamic` files;
- `setup.py`: **evaluated by a small static interpreter, never run**: variables, `+` / `+=` / `.append` / `.extend`, conditional lists, dict `extras_require`, `open("requirements.txt")` and `parse_requirements`-style readers; a value that cannot be resolved is reported as a note instead of being skipped silently;
- `setup.cfg` (`install_requires`, `setup_requires`, `tests_require`, extras, `file:` and `attr:`);
- requirements files (`-r`, `-c`, hashes, VCS / URL / editable entries, `--index-url`, `--extra-index-url`, `--find-links`, `--trusted-host`, `--require-hashes`). A file the build reads is a consumer dependency list; a file that is ≥ 80 % `==` pins is treated as a pinned list; the rest are development files that are listed but not installed for consumers;
- `Pipfile`, `environment.yml` (conda and its `pip:` block);
- the registry's own `requires_dist` when the archive states nothing.

**Lockfiles** (`poetry.lock`, `uv.lock`, `pdm.lock`, `pylock.toml` (PEP 751), `Pipfile.lock`, pinned requirements lists) are parsed for package, version, source and hash coverage. They are shown on their own card and are **not** counted as dependencies, because a consumer's installer ignores a lockfile shipped in a library. Exact registry versions are still looked up on OSV.dev (findings from them are capped at *low*, malicious packages stay *critical*); entries from git / URL / path sources are counted as non-registry.

Dependency files inside `tests/`, `docs/`, `examples/`, fixtures and vendored directories describe those directories, not the package, and are ignored (the number ignored is noted).

**Vendored libraries** (requests ≤ 2.15 ships `requests/packages/urllib3` and `charade`; pip ships `_vendor/`) are listed as bundled components with the version read from `vendor.txt`, nested `dist-info` / `egg-info`, `__version__` or a version tuple. A copy whose source does not state a valid version (`__version__ = 'dev'`) is listed as *version not readable* and is not looked up. Files in a vendored copy are reported as belonging to it, not to the package's own code.

Dependencies are **listed, pinned and looked up — not downloaded**. Run `ubel-package` on any of them for the same analysis; platform-specific optional dependencies (for example esbuild's prebuilt binaries) are noted as such.

## Static source analysis (SAST and malware)

Always on. The package's own source is run through **two static rule engines of UBEL**, both without a model: the SAST engine of `ubel-sast --no-llm` (vulnerabilities) and the malware rule set of `ubel-mal --no-llm` (malicious code). No API key, no network, and no code leaves the machine. SAST looks for vulnerabilities in what the package ships (command / SQL / NoSQL / LDAP injection, path traversal, unsafe deserialization, SSRF, XSS and template injection, weak crypto, ReDoS, prototype pollution, memory-safety classes in C, Dockerfile / Compose / Terraform / Kubernetes / CloudFormation / Ansible mistakes …), following data flow from sources to sinks and dropping a finding when a sanitiser is on every path; the malware pass looks for code that is malicious by intent. The findings are filed exactly as the two scans file theirs: `vuln` entries from SAST and `mal` entries from the malware pass, next to the rest of the package's findings (hooks, dependencies, advisories, secrets, integrity).

```
ubel-package <name> <version> <ecosystem> [--rules-dir <dir[,dir…]>] [--max-chunks <n>] [--max-chunk-size <n>]
```

| Option | Meaning |
| --- | --- |
| `--sast`, `--no-llm` | accepted and ignored (the analysis is always on); kept so existing command lines still work |
| `--rules-dir <dir[,dir…]>` | also run **your** Semgrep-syntax rules in the SAST engine: directories (searched recursively) or single `*.yml` / `*.yaml` files with a top-level `rules:`, repeatable. Findings are filed as `package.sast.custom.<id>`. A rule that cannot be run with its exact meaning is skipped, never run weaker, and listed in the report and as an analysis gap. The directory must exist (exit 2), so a rule set is never silently skipped. Custom rules do not run in the malware pass |
| `--max-chunks <n>` | most chunks of source (functions, classes, templates, config files) each engine analyses. Default **500000**. Chunks beyond it are counted and reported as an analysis gap |
| `--max-chunk-size <n>` | hard cap on characters per chunk; an over-long chunk or line (a minified bundle) is split to honour it. Default **1000000** |

What is analysed and what is not:

- **Analysed:** the package's code, install-time files, HTML / template files, and Dockerfile / Compose / IaC files; minified files and build output folders (`dist`, `build`, `bin`, …) and dot-directories included, because in a package archive everything is the package. Languages: JavaScript / TypeScript, Python, PHP, Ruby, Go, Rust, Java, Kotlin, Dart, Swift, C#, C / C++.
- **Bundled copies** of other packages (`node_modules/`, `vendor/`, `_vendor/`) are analysed too, but are reported as library code, one severity level lower.
- **Not analysed:** test and documentation files (they do not run on a consumer's machine; the number is noted), lockfiles, text files over `--max-text-kb`, native binaries (they have their own analysis) and languages the engine has no rules for.
- **Not repeated:** hardcoded secrets (the secret scanner of this tool already reports them, with the same rule set), and findings an engine itself dismissed as false positives or, for SAST, judged mitigated by a sanitiser on every path (counted in the report's `sast` block, and in its `malware` sub-block for the malware pass).
- **Weaknesses that need semantic review** (missing authorization, business logic, IDOR, …) are not decided by a rule engine; the report lists them under limits. A finding is a lead, not proof that the package is exploitable in your use of it.

Reports: SAST findings are rules named `package.sast.<engine rule id>` and malware findings `package.mal.<engine rule id>`, both under the **Source behaviour** area, with the engine's severity and the CWE of its class (CWE-506 for most malware classes); in the canonical report they are typed `vuln` and `mal`. They take part in `--min-severity`, `--fail-on`, the diff against the previous run and the compliance mapping like every other finding. The JSON report (and the canonical report, under `policy.flags.sast`) carries a `sast` block with the engine version, the number of rules (and custom rules) that ran, the limits, and the counts of chunks, files and findings, and a `malware` sub-block with the same for the malware pass. Anything an engine could not cover (chunks over `--max-chunks`, files over the size limit, failed rule evaluations, custom rules that were skipped, files that could not be written, an engine that failed to run) is an analysis gap, so exit code 3 applies unless `--allow-partial` is given.

**Disk use.** The engines read files from a directory, while the rest of this tool reads the archive in memory. So the text files that the engines can read are written to a private temporary directory (mode 0600 inside a directory created with `mkdtemp`), analysed by both, and deleted again, also on exit. Entries whose path escapes the package (`..`, absolute paths) are never written (they are reported as archive problems and as a gap), no link is ever created, nothing is overwritten, and nothing that is written is executed, imported or installed.

## Options

```
--registry <url>            registry / mirror / private index (npm: registry base · PyPI: site base or /simple · crates.io: sparse index ·
                            Go: GOPROXY · RubyGems / Packagist / pub: site base · NuGet: v3/index.json)
--token <token>             Authorization: Bearer … for the registry (env UBEL_PACKAGE_TOKEN); never sent to any other host
--header "Name: value"      extra registry header, repeatable (same rule)
--file <archive>            analyse a local archive; name, version and ecosystem are still required
--artifact sdist|wheel|all  PyPI: what to download (default all) · --max-wheels <n> (default 2)
--allow-insecure            allow an http:// link that the registry returns (an http:// --registry is always allowed)
--offline                   skip OSV.dev / NVD; reported as an analysis gap (exit 3 unless --allow-partial)
--max-size-mb / --max-text-kb / --max-binary-mb / --max-binaries   limits (defaults 256 MB / 2048 KB / 64 MB / 25)
--sast | --no-llm           accepted and ignored: static source analysis (SAST + malware, no LLM, no network) is always on
--rules-dir <dir[,dir…]>    your own Semgrep-syntax rules for the SAST engine (repeatable)
--max-chunks <n>            most chunks each engine analyses (default 500000)
--max-chunk-size <n>        hard cap on characters per chunk (default 1000000)
--working-dir <path>        where .ubel/ is written
--min-severity <sev>  --fail-on <sev|none|N:sev>  --allow-partial  --verbose  --quiet
```

Exit codes: 0 clean (or nothing at/above `--fail-on`), 1 the package could not be fetched or read, 2 the gate failed or a usage error, 3 nothing tripped the gate but part of the analysis could not be done (an OSV lookup failed, `--offline`, a file over a limit) — a clean result is then not proof of a clean package.

## Safety

- The archive is parsed in memory by a reader written for this tool; **nothing is extracted to disk** (the one exception is the static source analysis, see [Disk use](#static-source-analysis-sast-and-malware): sanitised text files in a private temporary directory, deleted afterwards), so a hostile archive cannot write outside anything. Entry paths with `..`, absolute paths, links that leave the package, setuid files and device files are reported, not followed.
- Limits: entry count, per-entry size and total unpacked size (a decompression bomb stops at 1 GB), and `--max-size-mb` for the download. Redirects to another host drop the registry credentials.
- Pattern matching shows that code **refers** to something, not that it is reachable or what data it handles. Minified or packed files give coarser results. Treat low-confidence findings as leads.

## Tests

```
node --test tests/package-units.test.js tests/package-scan.test.js tests/package-cli.test.js tests/package-python.test.js
```

The unit tests cover the parsers, the Python dependency sources and lockfiles, the pin classes, the command and source analysers and the archive reader. The scan tests build malicious and benign packages for every ecosystem and serve them from a mock registry; the CLI tests cover arguments, exit codes, reports and the advisory path (with a local OSV stand-in). No test uses the network.
