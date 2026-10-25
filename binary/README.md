# ubel-binary

Static security scan of a native executable or library. No third-party libraries, no external tools; nothing is executed or loaded.

```
ubel-binary <binary> [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>] [--allow-partial] [--max-size-mb <n>] [--verbose] [--quiet]
```

Formats are detected from magic bytes: **ELF** (Linux, Android), **Mach-O** (macOS, iOS; thin and fat) and **PE** (Windows .exe/.dll).
Output is the same as `ubel-mobile`: `report.binary.json` + `report.binary.html`, written to `.ubel/reports/latest.binary.*` and to a
timestamped history zip, with the diff against the previous run, the compliance mapping and the `--fail-on` gate (exit 0/1/2/3).

## What it checks

| Format | Hardening / configuration |
| --- | --- |
| ELF | PIE, NX / executable stack, W+X segments, RELRO, stack canary, FORTIFY, text relocations, RPATH/RUNPATH, stripped, static linking |
| Mach-O | PIE, executable stack, stack canary, code signature, ad-hoc signature, hardened runtime (macOS), `get-task-allow`, entitlements that weaken the hardened runtime |
| PE | ASLR (`DYNAMIC_BASE`), stripped relocations, high-entropy ASLR, DEP (`NX_COMPAT`), CFG, SafeSEH (x86), `/GS` cookie, W+X sections, Authenticode **presence** (validity is not verified) |

Also, for every format:

- **Risky imports** (`gets`, `strcpy`/`sprintf` family, `system`/`popen`/`WinExec`, `mktemp`/`tmpnam`, MD5/SHA-1/DES/RC4/Blowfish): reported as vulnerabilities. They come from the import table, so they show a function is linked, not that a call site is exploitable.
- **Secrets** in the binary's strings (same scanner as `ubel-mobile`).
- **Known-vulnerable components** (Dependencies tab):
  - C/C++ version banners (OpenSSL, LibreSSL, zlib, libcurl and the libraries it lists, SQLite, libpng, FFmpeg, expat, libxml2, xz, bzip2, BusyBox, Lua, PCRE/PCRE2, glibc, mbed TLS, wolfSSL, libtiff) are mapped to NVD CPEs and checked against the CPE ranges of each CVE (`UBEL_NVD_ENDPOINT` overrides the host).
  - Go module build info (Go 1.18+) and the Go standard-library version, and Rust crates from cargo-auditable data (or, failing that, crate paths left in panic messages), are checked against OSV.dev (`UBEL_OSV_ENDPOINT`).
  - Only component names and versions leave the machine. A lookup that fails is reported as an incomplete analysis (exit 3), never as clean.

## What it does not do

- It does not find unknown memory-corruption bugs; that needs disassembly and data-flow analysis.
- A version banner shows that library code is in the file, not that the vulnerable function is reachable. Components are reported with confidence `medium` (banner, crate path) or `high` (Go build info, cargo-auditable).
- Dynamically linked libraries are not followed: scan each library separately. A binary that only links `libssl.so` carries no OpenSSL banner itself.
- Go binaries older than 1.18, and stripped binaries that removed their banners, yield no components. Managed .NET assemblies get their PE header flags checked, not their IL.
- Static / stripped ELF files have no dynamic symbol table, so the canary and FORTIFY checks are skipped (and noted in the report).
