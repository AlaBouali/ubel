# ubel-package

Static security analysis of **one dependency release**, downloaded from its registry. Give it a package name, a version and an ecosystem (and, optionally, a registry URL); it fetches the archive, reads it, and reports what installing, building or importing it would do. No third-party libraries are used, and the package is **never installed, built or run**.

```
ubel-package <name> <version> <ecosystem> [--registry <url>]
ubel-package left-pad 1.3.0 npm
ubel-package requests 2.31.0 pypi --registry https://pypi.example.com
ubel-package serde_derive latest cargo
ubel-package github.com/gorilla/mux v1.8.1 go --registry https://goproxy.example.com
ubel-package x 1.0.0 npm --file ./x-1.0.0.tgz   # analyse a local archive
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
| What those scripts do | the hook's "what it does" column, findings by rule | The command line and the files it runs are read: download-and-run, inline shell, package installs, credential reads, persistence, destructive commands, privilege changes, encoded payloads, reverse shells, miners, TLS verification off. A file that runs at install time is judged more strictly than the same code elsewhere. |
| **Dependencies installed when scripts run** | `package.install.runtime_install`, **Package Info → install-time installs** | `npm install`, `pip install`, `gem install`, `cargo install`, `go get` … inside a hook: packages the lockfile, the pin review and the advisory check never see. |
| Pinned versions of dependencies | **Package Info → declared dependencies**, findings `package.dep.*` | Each declaration is classed `pinned`, `minimum`, `range`, `unbounded`, `not from the registry` (git / URL / path / branch) or `unknown`, per ecosystem's own rules (caret and tilde ranges, PEP 440, Cargo's bare version = caret, Go minimal version selection, NuGet "plain version = minimum", Composer constraints, pub constraints). |
| Known vulnerabilities and known-malicious releases | **Dependencies**, findings `package.vulnerable`, `package.malicious`, `package.dep.vulnerable`, `package.dep.malicious` | OSV.dev, by exact version: the release itself, declared dependencies with an exact (or minimum) version, copies bundled inside the archive, and component banners found in native files (NVD). OSV `MAL-` advisories are reported as critical. Ranges and unbounded declarations are shown as *not queried*: the installed version is chosen at install time. |
| Remote hosts | **Behavior → Remote hosts**, findings `package.install.remote_fetch`, `package.code.exfiltration` | Every host named in the package's files, with the file it is in, whether it is clear text, private, and flags: paste sites, callback services, tunnels, chat webhooks, dynamic DNS, URL shorteners, raw code hosts, bare public IPs. A host named in install-time code is a finding only when it is a hostile kind of host or the file can reach the network (a project URL in `setup.py` metadata is not a fetch). |
| Behavior and other behaviors | **Behavior** tab | The same inventory as `ubel-binary` (process, network, file access, dynamic loading, credentials, persistence, obfuscation …), filled from the package's source and scripts, split by where the code runs (install-time, package code, bundled dependency, tests / docs). |
| Secrets | **Secrets** tab | The shared secret scanner over every text file (the package's own code and bundled / test code are tagged separately), plus files that normally hold secrets (`.npmrc`, `.pypirc`, private keys, `.env`, `id_rsa` …). |
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
--working-dir <path>        where .ubel/ is written
--min-severity <sev>  --fail-on <sev|none|N:sev>  --allow-partial  --verbose  --quiet
```

Exit codes: 0 clean (or nothing at/above `--fail-on`), 1 the package could not be fetched or read, 2 the gate failed or a usage error, 3 nothing tripped the gate but part of the analysis could not be done (an OSV lookup failed, `--offline`, a file over a limit) — a clean result is then not proof of a clean package.

## Safety

- The archive is parsed in memory by a reader written for this tool; **nothing is extracted to disk**, so a hostile archive cannot write outside anything. Entry paths with `..`, absolute paths, links that leave the package, setuid files and device files are reported, not followed.
- Limits: entry count, per-entry size and total unpacked size (a decompression bomb stops at 1 GB), and `--max-size-mb` for the download. Redirects to another host drop the registry credentials.
- Pattern matching shows that code **refers** to something, not that it is reachable or what data it handles. Minified or packed files give coarser results. Treat low-confidence findings as leads.

## Tests

```
node --test tests/package-units.test.js tests/package-scan.test.js tests/package-cli.test.js tests/package-python.test.js
```

The unit tests cover the parsers, the Python dependency sources and lockfiles, the pin classes, the command and source analysers and the archive reader. The scan tests build malicious and benign packages for every ecosystem and serve them from a mock registry; the CLI tests cover arguments, exit codes, reports and the advisory path (with a local OSV stand-in). No test uses the network.
