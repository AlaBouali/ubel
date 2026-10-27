# Disclaimer for the missing `hashes` in the `components` section of the generated `cyclonedx` files:

Package hashes are not consistently available across all supported ecosystems and package managers at scan time. It is impossible to provide the hashes consistently for all detected packages/dependencies across all stacks. So, for the sake of consistency, I chose to remove them entirely instead of generated inconsistent outputs across scans.

# Disclaimer for the SARIF files generated outside the scopes of repositories/Code editors ( specifically host scanning ) :

The vulnerability/rules data are generated correctly, but some metadata like the `%SRCROOT%` and `originalUriBaseIds` can't be generated consistently since the scanned binaries are spread across the whole machine's filesystem. The vulnerability and rule data, CVSS vectors, affected package PURLs, etc.. are still valid.

# Disclaimer for `MAL-2022-4691` and `monorepo-symlink-test@0.0.0` ( a well-known false positive ) :

The function `filterFalsePositiveInfections` in this project suppresses
the detection of MAL-2022-4691 for `monorepo-symlink-test@0.0.0` when found
under specific path: `node_modules/resolve/test/resolver/multirepo` because it is a well-known false positive:

https://github.com/Unitech/pm2/issues/5669
https://github.com/browserify/resolve/issues?q=is%3Aissue%20monorepo-symlink-test


THIS FILTER IS PROVIDED “AS IS” AND WITHOUT ANY WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY ARISING FROM THE USE OF THIS FILTER, INCLUDING BUT NOT LIMITED
TO THE SUPPRESSION OF GENUINE SECURITY VULNERABILITIES.

Users are solely responsible for reviewing the filter’s logic and
determining its suitability for their environment.

# Disclaimer for the AI-assisted SAST:

Results are entirely dependent on the LLM and provider you choose for each
scan. The tool returns every finding it produces — nothing is filtered out —
so you can audit the LLM's output yourself and decide what to trust.

This chunker and taint-tracer are best-effort: it chunks code across the
supported languages with zero third-party dependencies, which means no real
parser is doing the heavy lifting underneath. The chunker can occasionally miss a function boundary and place multiple functions in the same chunks instead of splitting them perfectly as planned (not a serious issue, but worth mentioning for transparency), and the taint-tracer's reachability/exploitability
labels are a best-effort prioritization signal layered on top of the
complete findings list — not a correctness-critical gate. A "verified but
not exploitable" label means our best guess is that it's mitigated, not a
guarantee — and the absence of a finding for some piece of code isn't proof
that code is clean. Treat every finding, and every part of your codebase, as
something to verify yourself before relying on this tool's read of it.

# Disclaimer for EASM / `ubel-url` and `ubel-domain`:

These CLIs identifies software and versions purely from what a remote server
chooses to disclose over plain HTTP(S) — response headers, banners, and page
markup — via passive pattern matching against a fixed set of registered
fingerprints (see `easm/fingerprint/README.md`). It does not inspect
running processes, filesystems, or anything else only reachable with
authenticated/local access, and it does not verify a match beyond that
pattern match. This means:

- A false positive is possible when a server's banner/markup happens to
  match a fingerprint's pattern without actually running that software.
- A false negative is possible, and likely, whenever an operator has
  changed or removed the identifying banner/header (a common, deliberate
  hardening practice) or is running a version/product this scanner simply
  has no fingerprint for. Absence of a finding is not evidence of absence
  of a vulnerability, or even of the underlying software itself.
- A version string, once matched, is passed to OSV/NVD as-is for CVE
  lookup. If a vendor backports a security fix without changing the
  version string a server reports (common for enterprise/LTS branches),
  this tool has no way to know that and will report the CVE as unresolved
  regardless.

None of this is a defect to "fix" so much as an inherent limit of
unauthenticated, remote, banner-based identification versus actually
having access to the host. Every finding here is a lead to verify against
the authoritative advisory and the actual deployed software/patch level —
not a confirmed, exploitable vulnerability on its own.

# Disclaimer for the SCA / firewall modules (`ubel-npm`, `ubel-pip`, `ubel-cargo`, `ubel-apt`, … and `ubel-docker`):

Everything below is stated in `sca/README.md` and applies to every ecosystem unless noted.

- **Only what can be identified is matched.** Packages resolved from a VCS URL, a download URL or a local path are not the registry package of the same name, so they are not looked up and stay `undetermined`, never `safe`. A component with no version is `undetermined` as well. `block-undetermined` (on by default) blocks on them.
- **Conda:** OSV has no conda ecosystem. A package is matched only when its build string marks it as a Python distribution (reported as `pkg:pypi/…`); a package whose conda name differs from its PyPI name and is not in the built-in name map is simply not matched (a missed finding, never a wrong one). Native packages (`openssl`, `libxml2`, `python` itself …) are inventoried but **not matched against any database** and are counted as `undetermined`, not `safe`.
- **Maven:** only `pom.xml` is read (Gradle is not). A parent that exists only in a remote repository cannot be read, so the versions it manages stay unresolved and are not sent to OSV. Transitive dependencies are not resolved from `pom.xml` alone; generate `mvn dependency:tree` output for them. Maven and Windows are SCA-covered but have no firewall.
- **Cargo:** only crates.io crates are matched; git and alternative-registry dependencies are listed in a warning but not matched, and `build.rs` / proc-macros still run at `cargo build`, outside the firewall. A member of a parent workspace is refused, and path dependencies outside the project root fail the dry-run closed.
- **Poetry** can still build a source distribution *while locking* when an index publishes no wheel metadata (rare on PyPI); that step is Poetry's own and never happens at install time. **pip / uv** refuse source distributions (`--only-binary=:all:`), so a package with no compatible wheel fails closed.
- **The firewall is not a sandbox.** The lockfile-required engines (yarn, Bundler, Go, .NET, Dart, Flutter, SwiftPM) scan exactly what the lockfile pins and install nothing; install-time code (Bundler native extensions, SwiftPM manifests, NuGet-shipped MSBuild targets) can still run when *you* run the ecosystem's frozen install afterwards. Any `install` that UBEL performs runs only after the scan, with no lockfile to revert for apt / dnf / yum / pip-family / conda / Cargo (a rejected scan simply never runs the real install). `ubel-apt` / `ubel-dnf` / `ubel-yum` only work on a Linux host that has that exact tool, and `install` needs passwordless `sudo`.
- **Reachability is a heuristic**, used for prioritisation. It combines package type, scope, dependency depth, the CVSS attack vector and (for ten ecosystems) an import scan; the last-resort rungs (depth and attack vector) are weak proxies. A finding with no reachability result is treated as potentially reachable. It is informational unless you set `reachable_only`.
- **Exploit intelligence is best-effort.** CISA KEV and FIRST EPSS have no endpoint override. If a feed is unreachable the affected fields are `null` (unknown, never "not exploited"), the matching policy rule cannot fire, and the report says the exploit data is incomplete.
- **A failed OSV / NVD lookup is never a pass:** the scan fails (exit non-zero) instead of reporting zero findings. A mirror you configure through `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` is only as complete as that mirror.
- **Suggested fixes and the executive summary are derived from the data above.** An upgrade suggestion counts a version only if it falls outside every affected range of the vulnerability, but it does not know whether the new release breaks your code. The summary carries its own limitations list and says when a check did not run.
- **`ubel-resbom` and `ubel-sbom` only look up what an SBOM lists.** They cannot find a dependency that was not in the original scan, never re-detect secrets, and only read CycloneDX JSON (`ubel-sbom`: 1.4+). `ubel-sbom` falls back to a CPE only when a component has no usable purl, and CPE matching is looser than purl matching (it names products, not packages), so it can produce false positives and misses. Neither assesses exploitability (no VEX `analysis`). A non-UBEL SBOM is re-scanned best-effort with a warning.
- **The dependency pre-commit hook scans the *installed* graph** (`health`, not `check`): a staged `package.json` change that has not been installed yet is not in it. It is client-side and skippable with `git commit --no-verify`, fails open when the UBEL binary cannot be found (unless `UBEL_HOOK_STRICT=1`) and fails closed when a scan fails. Run the same scan in CI.
- **Compliance framework mapping is best-effort guidance, not a certified compliance assessment.** Control identifiers are the publicly documented ones for each framework, but framework text, versioning and applicable scope change and always depend on your own environment. It is a starting point for an audit conversation, not a citation to quote in one. Every report carries this disclaimer in `compliance_summary.disclaimer`.

# Disclaimer for secrets detection (`ubel-secrets` and the secrets pass of every `health` scan):

- Detection is rule-based (Trivy's ported ruleset plus UBEL's own rules), so a value that merely looks like a credential can be a false positive and a credential with no recognisable shape can be missed. Verify a finding, and whether it was ever valid, before rotating anything production-critical; a secret found in git history is compromised even if it was later deleted, and should be rotated.
- Dependency trees, build output and caches are skipped (`node_modules`, `vendor`, `target`, `dist`, `build`, `out`, virtualenvs, …); `packages`, `bin`, `obj` and `env` are skipped only when the layout says they hold generated content. `.env*` files are skipped in repository scans (they are scanned in Docker image scans), so a committed `.env` is not reported by a repository scan.
- Some values are deliberately **not** reported: placeholders and templates (`${DB_PASS}`, `changeme`, `YOUR_PASSWORD` …), `user:user` pairs, default passwords against `localhost` or a bare docker-compose service name, and hosts containing `example`. Twilio SIDs are intentionally not detected (no checksum or distinguishing context, too much noise). The generic key-value fallback has no entropy check (the key name is the signal), so it is the likeliest source of false positives.
- The raw secret value is never written to any report or log: only a redacted preview is kept.
- The pre-commit hook scans staged changes only, can be bypassed with `--no-verify`, and fails open when `ubel-secrets` cannot be found (set `UBEL_HOOK_STRICT=1` to block). Run `--history` in CI as well.

# Disclaimer for Cloud / `ubel-cloud`:

- **Read-only, but it needs real credentials.** It calls each provider's own read-only API with credentials you supply and reports live account state. The credentials need the read permissions listed in `cloud/README.md`; a provider without credentials is skipped, and a provider or region that is skipped or stops part-way makes the run exit `3` unless `--allow-partial` accepts it. A skipped provider is never reported as clean.
- **Supported authentication is limited.** AWS `credential_source` (instance-metadata base credentials) is not supported, only `source_profile` chaining; Azure client-certificate authentication is not supported (client secret and managed identity only); OIDC workload-identity federation is not implemented for any provider. A CI runner is not on AWS / GCP / Azure, so the metadata-server fallback does not apply there.
- **S3 object-level public-ACL checking is a bounded, prefix-sharded sample**, not an exhaustive scan, and remains a spot-check for any bucket larger than the sample budget. Buckets whose names contain dots can hit TLS SNI mismatches with virtual-hosted-style addressing.
- **Some checks are deliberately not implemented** (GCP KMS key rotation and default Compute Engine disk encryption, AWS Config recorder status, Security Hub, Lambda resource-policy `Principal: "*"`, KMS key rotation), and GCP zones are not auto-discovered. Absence of a finding for those is not evidence that the setting is fine.
- **Findings are point-in-time.** A report is compared only with the immediately previous report of the same asset (no baseline selection, no trend over more than two runs), and providers or regions skipped both times are excluded from the comparison, so a narrower scan shows less change, not more.
- No SARIF output: JSON and HTML only. Compliance mapping is best-effort guidance (see above).

# Disclaimer for the AI-assisted SAST and malware scanner (`ubel-sast`, `ubel-mal`), additional points:

- **Your code is sent to the LLM provider you configure.** SAST sends the code chunks it analyses (and, for the taint-trace pass, a bounded call chain) to that provider (`openrouter` by default). Use a local or self-hosted endpoint if source code must not leave your network. UBEL itself has no telemetry and no backend.
- **Findings are AI-proposed candidates.** The executive summary sorts them into confirmed exploitable, confirmed real (reachability not established), blocked by other code, not cleared (a pass errored or was inconclusive) and unverified. "Didn't finish checking" is never silently treated as clean: code that was not analysed (a failed or unreadable AI call, a cut-off reply, a file skipped for size, chunks dropped by the default limit) fails the run.
- **The malicious-code scan (`ubel-mal`) has no taint-trace pass**, because reachability is not the relevant question for code that is itself the payload. A confirmed label is the model's judgement; review it before acting. The false-positive suppression for `MAL-2022-4691` described above is the only filter applied.
- **Diffs compare with the previous report of the same type for the same asset** and do not key on line numbers or snippets, so two different issues of the same class in the same function can be merged; findings the verification pass dismissed are left out of both reports.
- Token cost depends on the number and size of the calls, not on the concurrency settings; chunk packing changes how often the prompt scaffold is paid for, not what is sent about each chunk.

# Disclaimer for EASM, additional points (`ubel-url`, `ubel-domain`, `ubel-host`, `ubel-easm`):

- **Authorized use only.** Only point these tools at infrastructure you own or are explicitly authorised to test. The safety guard (private / RFC1918 and the machine's own interface addresses are skipped and reported as `skipped`) is a local check: a public address that exists only on an upstream NAT or router is not detected, and `--allow-private` disables the guard entirely. It is not a way around the authorised-use requirement.
- **`ubel-host` and `ubel-easm` are not passive:** before fingerprinting they run a live TCP connect scan over a port range (1-30000 by default). `ubel-easm` additionally expands a domain into every subdomain IP, which can include shared CDN / hosting addresses you do not own; it only de-duplicates identical IPs and cannot detect shared infrastructure. Authorisation to scan a domain does not by itself authorise a port sweep of every IP its DNS points at: use `--exclude` / `--exclude-ip`, and review with `--list-only` first.
- **Subdomain discovery is passive and incomplete.** `ubel-domain` and `ubel-easm` use Certificate Transparency logs (crt.sh) only: a host with no logged certificate (internal-only, HTTP-only, a CA that does not log to CT) is not discovered, so a short result describes the CT record, not what is deployed; CT logs are history, so decommissioned subdomains appear (and are reported as dead rather than probed).
- **Under-specified versions are not looked up.** A component that discloses only a bare major version (for example `Python 3`) is listed with a low-confidence badge and `undetermined`, but not queried against OSV / NVD, because NVD's range matching would otherwise match an entire multi-year CVE history.
- **The secrets crawl is one level deep:** a host's root document and the scripts it references, with no link following, route enumeration or JavaScript execution. A credential in a lazily-loaded chunk or injected at runtime is not found, and scripts that fail to fetch or exceed the size cap are listed under "not scanned". Findings are rule-based and can be false positives.
- **No login or session handling.** `--cookie` / `--header` attach to the fingerprinting requests only; the port scan, the secrets crawl and the misconfiguration probes stay unauthenticated, so anything only visible behind a login is not covered. There is no `--proxy`.
- **The WordPress-specific checks** (`wp-xmlrpc-exposed`, `wp-user-enumeration`) only run on hosts the fingerprinter already identified as WordPress. The misconfiguration checks run on every scan and have no CLI switch; misconfiguration counts are not printed on the console summary (see the HTML or JSON report).
- **KEV / EPSS** are best-effort with no endpoint override (see the SCA section above). A different target list or `--ports` range between two runs shows up as new / removed items in the diff.
- **A vendored fingerprinting engine.** The detection engine under `easm/fingerprint/` is a port of a third-party toolkit, kept with its own provenance and licence notice (`easm/fingerprint/NOTICE.md`); it is a fixed set of registered fingerprints, and a product or version it has no fingerprint for is simply invisible to it.

# Disclaimer for Mobile / `ubel-mobile`:

Everything here is stated in `mobile/README.md` (section *Limits*). `ubel-mobile` is a static analyser: nothing in the app is executed, decompiled or uploaded, and there is no data-flow analysis.

- **Static only.** By default the only network requests are the OSV.dev lookups for extracted, versioned package URLs (and NVD / OSV.dev lookups for components bundled in native libraries). Backend behaviour, Firebase database rules and the validity of a found key are not tested; it scans the package you give it, not the app's backend. `--online` adds three read-only checks against hosts the app names and nothing else; it never tests keys against other services and never writes anything. Only use it on apps you are allowed to test.
- **No decompiler.** Findings come from configuration, constant tables, API references, call arguments and binary metadata. The DEX walker tracks constants straight-line within one method, so values assembled at runtime are not seen. A finding marked `confidence: low` or `medium` is a lead to verify, not a confirmed vulnerability.
- **Obfuscation weakens attribution.** R8 / ProGuard rename app *and* library classes, so a class is `app` when it sits under the manifest package or a component's package, `library` when it matches a known library prefix, and `unknown` when it is renamed and outside the app's package; `unknown` findings keep their full severity because they cannot be proven to be library code. Packers, DexGuard-style string encryption, Hermes bytecode and code downloaded at runtime are only partly visible; a recognised packer is an analysis gap. Packer, protector and framework detection is heuristic (file names, resource layout, class names).
- **Sensitive-data rules are heuristics.** `logging_sensitive`, `plaintext_prefs` and `plaintext_database` work from what is visible in one method: *direct* evidence (`medium` confidence) or *nearby* evidence (`low`), and drop to `low` when `androidx.security.crypto` or SQLCipher is packaged. `hardcoded_credential` needs a constant whose *name* says password / secret / token / key **and** a value that looks like a secret, so an all-lowercase word such as `"letmein"` is deliberately not reported. Treat these as pointers for manual review. Bypassing root / emulator detection is runtime behaviour and out of scope; only the presence of such checks is reported.
- **Native-library hardening is partly inferred.** PIE, NX and RELRO are read straight from the ELF headers, but the stack canary and FORTIFY checks are indicators inferred from imports, not proof: Rust, Go and other non-C toolchains typically do not use the stack protector, a fortified build still imports plain `memcpy` where the compiler could not prove the destination size, and a statically linked libc hides both. `no_fortify` is low / low confidence and `no_canary` low / medium. When no symbol table can be found the columns show `unknown` and no finding is raised from missing evidence. Little-endian ELF only; at most 600 binaries and a 512 MB read budget for the non-preferred ABIs, and anything skipped is a reported gap.
- **Framework code is read as data, not decompiled.** Hermes bytecode, Dart snapshots, IL2CPP binaries and .NET IL yield string literals, identifiers, configuration and build flags, not logic, so a certificate callback that returns `true` or a token written to storage cannot be proven from them. Dart-side TLS handling is invisible; Dart package *versions* are not shipped, so Flutter dependencies are listed by name only and are not looked up in OSV. The `.aab` assembly-store and Hermes layouts are version-dependent: they are validated before use, and a mismatch is reported rather than guessed. LZMA-compressed UnityFS bundles and encrypted or custom-packed `global-metadata.dat` are not read.
- **App Store IPAs are FairPlay-encrypted** (`cryptid=1`): `Info.plist`, provisioning, entitlements, bundled files and imported symbols are analysed, but strings inside the binary are not. Scan a development-signed or decrypted build for full coverage. A repeating-key XOR or other second obfuscation layer is deliberately not recovered, and XALZ/LZ4-compressed Xamarin assemblies lose the identifier heap the checks depend on.
- **Dependency lookup covers only exact identities.** A dependency is sent to OSV.dev only when a versioned package URL could be extracted (for example from `META-INF/*.version`, `dependencies.pb`, `Package.resolved` or `Podfile.lock`). A library detected by namespace only ("Firebase Android SDK", "Google Play Services") is `not_queryable`, never clean; a failed lookup is `lookup_error` / `lookup_incomplete`.
- **Components inside native libraries are found by what the library says about itself.** A version banner (`OpenSSL 1.1.1k`, `libcurl/7.68.0`) proves the code is in the file, not that the vulnerable function is reachable, and a library with no banner shows nothing; absence is not proof of absence. Only the preferred-ABI copy of each library is read for components.
- **The behavior inventory and the remote-host list are context, not findings**, and a summary of what the code *can* do and *mentions*: nearly every app does all of it. Intent actions or hosts built at runtime are not visible, namespaces, licence URLs, placeholders and loopback addresses are left out, and nothing is resolved or contacted.
- **Severity is adjusted, not absolute.** A catalog severity is a default; a finding with `confidence: low` is reported one level lower (never below `low`), findings only in third-party library code are reported one level lower, and the overall risk rating counts findings after this adjustment. The `--fail-on` gate counts every finding whatever `--min-severity` hides from the report.
- **Coverage can be partial** (a DEX that failed to parse, an unreadable or oversized file, an exhausted scan budget, per-file and total inflated-size caps, a failed OSV / NVD lookup): the report lists the gaps, the run exits `3`, and the executive summary says "No issues found (analysis incomplete)". `--allow-partial` accepts the gaps, so a green build then only means the part that was read is clean.
- **Test fixtures are not real apps.** The parsers' tests use in-memory fixtures that follow the file-format specifications (plus a few real files); run the scanner against your own builds as well.
- Findings are mapped to OWASP MASVS and general security-framework references as best-effort guidance, not a certified compliance assessment.

# Disclaimer for Binary / `ubel-binary`:

Everything here is stated in `binary/README.md` (section *What it does not do*). `ubel-binary` reads one file statically; nothing is executed or loaded.

- **It does not find unknown memory-corruption bugs**: that needs disassembly and data-flow analysis. Risky imports (`gets`, the `strcpy` / `sprintf` family, `system`, `mktemp`, weak crypto) come from the import table, so they show a function is *linked*, not that a call site is exploitable.
- **Version banners prove presence, not reachability.** A banner shows that library code is in the file, not that the vulnerable function can be reached. Components are `medium` confidence (banner, crate path) or `high` (Go build info, cargo-auditable). A banner must look like the library's own version string (ELF symbol-version tags such as `LIBXML2_2.4.30` are not banners), stripped binaries that removed their banners yield no components, and libraries that carry only a bare version string (`libsqlite3`, `libbz2`, `libz`) are not matched by the banner list.
- **Dynamically linked libraries are not followed.** Scan each library separately: a binary that only links `libssl.so` carries no OpenSSL banner itself.
- **Go:** binaries built before modules (GOPATH mode, ≤ 1.17) have no module list, and a binary whose build info was removed on purpose yields no components. Go was exercised on ELF, Mach-O (arm64) and PE.
- **Packaged applications are read, not run.** For pkg the code is usually V8 bytecode, so string constants (secrets) are visible but logic is not analysed. SEA and Bun bundles keep package versions only sometimes: packages without one are listed as *not queryable* (scan the project with `ubel-npm` instead), and the Node / Bun runtime's own embedded packages are not reported as application dependencies. PyInstaller versions from a `__version__` module are `medium` confidence, from bundled metadata `high`; PyInstaller < 6 archives encrypted with `--key` cannot be read (a gap, exit 3). Nuitka, cx_Freeze, py2exe and PyOxidizer executables are recognised only by marker strings and reported as *not inventoried* (a gap, exit 3). Mach-O / PE builds of pkg, SEA and PyInstaller were only exercised on ELF files, and the runtime image around a packaged Node / Bun application is checked for C library banners and the Node.js version but not scanned for secrets.
- **Managed .NET assemblies** get their PE header flags checked, not their IL. **Authenticode** is checked for *presence*, not validity. Static / stripped ELF files have no dynamic symbol table, so the canary and FORTIFY checks are skipped (and noted).
- **The behavior inventory is a capability summary, not a list of findings.** Call sites are counted only for ELF and PE imports on x86-64 and arm64 (arm64 is exact; on x86-64 a byte pattern only counts when its target is exactly a known stub or slot, which is not disassembly): calls through function pointers, vtables or `dlsym` / `GetProcAddress` results are not seen, packed or obfuscated code can hide or invent sites, and everything else (Mach-O imports, Go functions, Rust paths, bundled text) is presence only. Rust paths are weaker still: only code that can panic leaves one. Python is read as names, not behaviour. Functions imported by ordinal have no name to classify. A short list is not a clean result, and a few common imports (`mprotect`, `GetProcAddress`, `LoadLibrary`, `OpenProcess`) are used by ordinary programs. `ptrace(PTRACE_TRACEME)` is only recognised where call sites are available.
- **Remote hosts are references, not connections.** A name in the file shows that the code mentions it, not that it connects there, when, or with what; addresses built at run time, read from a config file or received from a server are invisible, and documentation links look the same as API endpoints. Nothing is resolved or contacted.
- **Coverage limits make a run incomplete:** more than 400,000 strings (Node, Bun and similar runtime images) means the rest is not searched and the run exits 3, as does a failed NVD / OSV lookup (never reported as clean). Only component names and versions leave the machine.
- **Shared code with `ubel-mobile`.** `ubel-binary` reuses `scanMobileDependencies` for PURL records and passes `includeNative`, so `ubel-mobile`'s filter that drops a package's own `.so` / `.dylib` / framework entries does not apply to the records `ubel-binary` produces; banner (CPE) records go to NVD directly and are not filtered. `ubel-mobile` runs this same component detection over the native libraries inside an `.apk` / `.aab` / `.ipa`, so a library that is part of an app does not need a separate run.
- Findings are mapped to general security-framework references as best-effort guidance, not a certified compliance assessment.
