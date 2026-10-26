# ubel-binary

Static security scan of a native executable or library. No third-party libraries, no external tools; nothing is executed or loaded.

```
ubel-binary <binary> [--working-dir <path>] [--min-severity <sev>] [--fail-on <sev|none|N:sev>] [--allow-partial] [--max-size-mb <n>] [--verbose] [--quiet]
```

Formats are detected from magic bytes: **ELF** (Linux, Android), **Mach-O** (macOS, iOS; thin and fat) and **PE** (Windows .exe/.dll).
Output is the same as `ubel-mobile`, including the Behavior tab: `report.binary.json` + `report.binary.html`, written to `.ubel/reports/latest.binary.*` and to a
timestamped history zip, with the diff against the previous run, the compliance mapping and the `--fail-on` gate (exit 0/1/2/3).

## What it checks

| Format | Hardening / configuration |
| --- | --- |
| ELF | PIE, NX / executable stack, W+X segments, RELRO, stack canary, FORTIFY, text relocations, RPATH/RUNPATH, stripped, static linking |
| Mach-O | PIE, executable stack, stack canary, code signature, ad-hoc signature, hardened runtime (macOS), `get-task-allow`, entitlements that weaken the hardened runtime |
| PE | ASLR (`DYNAMIC_BASE`), stripped relocations, high-entropy ASLR, DEP (`NX_COMPAT`), CFG, SafeSEH (x86), `/GS` cookie, W+X sections, Authenticode **presence** (validity is not verified) |

Also, for every format:

- **Risky imports** (`gets`, `strcpy`/`sprintf` family, `system`/`popen`/`WinExec`, `mktemp`/`tmpnam`, MD5/SHA-1/DES/RC4/Blowfish): reported as vulnerabilities. They come from the import table, so they show a function is linked, not that a call site is exploitable.
- **Behavior inventory** (`app.behavior`, the report's **Behavior** tab): what the file can do, grouped into file access, network, process execution, dynamic loading, debugging / process injection, anti-analysis, privilege, persistence, input capture / sensitive devices, cryptography and system information. Read from the import table, and for Go, Rust and packaged applications from what they carry instead of imports. See *Behavior inventory* below.
- **Secrets** in the binary's strings (same scanner as `ubel-mobile`).
- **Known-vulnerable components** (Dependencies tab):
  - C/C++ version banners (OpenSSL, LibreSSL, zlib, libcurl and the libraries it lists, SQLite, libpng, FFmpeg, expat, libxml2, xz, bzip2, BusyBox, Lua, PCRE/PCRE2, glibc, mbed TLS, wolfSSL, libtiff) are mapped to NVD CPEs and checked against the CPE ranges of each CVE (`UBEL_NVD_ENDPOINT` overrides the host).
  - Go module build info and the Go standard-library version, Rust crates from cargo-auditable data (or, failing that, crate paths left in panic messages), and the npm and Python packages of packaged applications (below) are checked against OSV.dev (`UBEL_OSV_ENDPOINT`).
  - Only component names and versions leave the machine. A lookup that fails is reported as an incomplete analysis (exit 3), never as clean.

## Behavior inventory

The Behavior tab is the native counterpart of the Android tab of `ubel-mobile`: a summary of capabilities, **not a list of findings** (nearly every program opens files and sockets), shown next to the findings it bears on (for example *Process execution* links `binary.risky.cmd_exec`).

| Source | Where the names come from | Origin (the report's **Source** column) |
| --- | --- | --- |
| ELF imports | undefined dynamic symbols (`execve`, `fopen64` and `__isoc99_*` variants are normalised) | The library named by symbol versioning (`libc.so.6`). Unversioned symbols (musl, bionic) have no recorded library and are filed under `unattributed` |
| Mach-O imports | imported symbols of the preferred slice, including Objective-C classes (`_OBJC_CLASS_$_NSURLSession`, `NSTask`, `CLLocationManager`, …) | The dylib named by the symbol's library ordinal (two-level namespace) |
| PE imports | the import table by name; the `A` / `W` suffix is ignored; `WinHttp*`, `CreateProcess*`, `ShellExecute*`, `RegSetValue*`, `CreateService*`, `EVP_*`, `BCrypt*` are matched as families | The DLL of the import descriptor |
| Go | the function names of the **pclntab** (`os/exec.Command`, `net/http.(*Client).Do`, `golang.org/x/sys/unix.Ptrace`), also in stripped files; Go 1.18+ layout verified on a real binary, 1.2 and 1.16 layouts implemented from the runtime source | The module that **defines** the function: `Go standard library` or a dependency's module path (from the build info). It says who owns the function, not who calls it |
| Rust | `library/std/src/{fs,net,process}…` and `registry/src/…/<crate>-<version>/` paths left in panic messages, with a table of crate names | `Rust standard library` or the crate. Weaker than the others: only code that can panic leaves a path |
| Packaged applications | the text of the files read out of pkg, Node SEA, Bun and PyInstaller applications: `child_process`, `net` / `http`, `fs`, `vm` / `eval`, `crypto`, `os` (JavaScript); `subprocess`, `socket`, `urllib` / `requests`, `ctypes`, `importlib`, `shutil`, `hashlib` (Python) | The owner of the file: the `node_modules` package (pkg: the virtual path; SEA / Bun: the bundler's `// node_modules/…` markers), the PYZ top-level module, or `app`. A bundle without markers is one source, `bundle` |

What it is, and is not:

- **Call sites for ELF and PE imports (x86-64, arm64), presence for the rest.** `lib/callsites.js` resolves how code reaches an import (ELF: PLT stubs `jmp [GOT]` / `adrp+ldr+br` and GOT slots from `.rela.plt` / `.rela.dyn`; PE: IAT slots and `jmp [IAT]` thunks) and scans the executable sections for `call` / `jmp` / `bl` / `b` / `blr` that reach them. The import entry then carries its **direct call-site count** (`basis: 'calls'`; `0` = imported, no direct call found). arm64 is exact (fixed-width instructions); on x86-64 a byte pattern only counts when its target is exactly a known stub or slot, which filters almost all look-alikes but is not disassembly. Calls through function pointers, vtables or `dlsym` / `GetProcAddress` results are not seen, packed or obfuscated code can hide or invent sites, and ELF i386 / arm, PE for other machines, static files and files without section headers fall back to presence (`1` per function, with a note). Mach-O imports, Go functions, Rust paths and bundled text are always presence.
- **`ptrace(PTRACE_TRACEME)`.** With call sites, a `ptrace` call whose first argument is the constant 0 (`xor edi,edi` / `mov edi,0`, `mov w0,#0`) is listed under *Anti-analysis* as `ptrace(PTRACE_TRACEME)`; the other `ptrace` calls stay under *Debugging / process injection*. Without call sites `ptrace` can only be listed as injection.
- **Python is read as names.** PyInstaller modules are marshalled code, where `os.system(...)` leaves `os` and `system` as separate strings. Module names (`subprocess`, `socket`, `ctypes` …) are matched; `os.system` only where it is written out in text. Modules whose top-level name starts with an underscore (private standard-library helpers) are left out.
- **Short lists are not clean results.** Statically linked and stripped files import little or nothing, so the inventory is small or absent even when the program does a lot; a note says when the file is static or the import table is unreadable. Functions imported **by ordinal** (some old Windows binaries) have no name to classify and are counted in a note. Managed .NET assemblies are not inventoried.
- **Common functions are left out on purpose** (`sysconf`, `getuid`, `GetTickCount`, `GetModuleHandle`, …). A few that remain (`mprotect`, `GetProcAddress`, `LoadLibrary`, `OpenProcess`) are imported by ordinary programs as well. A name can sit in two categories (`SetWindowsHookEx`: persistence and input capture).
- A long *Debugging / process injection* or *Anti-analysis* list in a program that is neither a debugger nor a protected product is worth a closer look; so is a short import list combined with many *Dynamic loading* entries (functions resolved at run time do not appear in the table).

## Go, npm-based and Python-based binaries

A native file is often only the wrapper around an application written in another language. `ubel-binary` recognises three kinds by their own structure (never by file name), reads their payload in memory, and reports what is inside next to the usual hardening checks. The report's app metadata shows what was found (`go`, `packaging`, `runtimes`).

| Binary type | How it is recognised | What is inventoried | Checked against |
| --- | --- | --- | --- |
| **Go** (ELF, Mach-O, PE; stripped or not) | Build-info header, or the module-list sentinels when the header is gone | Toolchain version, every module with its exact version (replace directives applied), build settings (`CGO_ENABLED`, `-race`, `-trimpath`, `vcs.*`; `-ldflags` is never copied into the report). Go 1.18+ **and** 1.13-1.17 (pointer format) | OSV.dev (`pkg:golang/…`, `stdlib`) |
| **npm-based: pkg / @yao-pkg/pkg** | Bootstrap prelude + virtual filesystem at the end of the file | Every dependency's own `package.json`: exact name and version, also for `--compress GZip` / `Brotli` builds. The application's files are read for secrets under their virtual path (`/snapshot/app/index.js`) even when compressed | OSV.dev (`pkg:npm/…`), NVD for the bundled Node.js runtime |
| **npm-based: Node.js SEA** (`--experimental-sea-config` + postject) and **Bun `--compile`** | `NODE_SEA_BLOB` note / fuse, Bun trailer | The JavaScript bundle: packages from the bundler's `node_modules/…` path markers; a version when the path carries one (pnpm, Deno layouts), when `package.json` was inlined, or from the package's own `VERSION = "x.y.z"` constant (confidence `medium`). Packages whose version the bundler dropped are listed as *not queryable*, never as clean | OSV.dev; NVD for the Node.js runtime |
| **Python-based: PyInstaller** (one-file, ELF/PE/Mach-O) | Archive trailer (`MEI…` cookie) and its table of contents | Bundled `dist-info` / `egg-info` metadata (exact), `<package>.__version__`-style modules in the compressed PYZ archive (`medium`; standard library excluded, ambiguous versions not guessed), the interpreter (3.x.y from the bundled libpython), every bundled shared library's C/C++ version banner (OpenSSL, zlib, SQLite …). String constants of the script and of every PYZ module are scanned for secrets | OSV.dev (`pkg:pypi/…`), NVD for Python and the bundled C libraries |

Limits specific to these types:

- A packaged application is read, not run. For **pkg** the code is usually V8 bytecode: string constants (secrets) are still visible, logic is not analysed.
- **SEA / Bun** bundles keep package versions only sometimes. Where they do not, the package is in the Dependencies tab as *not queryable*, and a note says so; scan the project with `ubel-npm` for those. The Node.js / Bun runtime's own embedded packages (minimatch, undici …) are not reported as application dependencies.
- **PyInstaller** versions taken from a `__version__` module are `medium` confidence, from bundled metadata `high`. PyInstaller < 6 archives encrypted with `--key` cannot be read: reported as a gap (exit 3).
- Nuitka, cx_Freeze, py2exe and PyOxidizer executables are recognised by marker strings only and reported as *not inventoried* (a gap, exit 3); their packages are stored in formats this scanner does not read, or outside the executable.
- Mach-O / PE builds of pkg, SEA and PyInstaller use the same readers but were only exercised on ELF files; Go was exercised on ELF, Mach-O (arm64) and PE.
- When a payload is split off, the Node / Bun runtime image around it is checked for C library banners and the Node.js version but not scanned for secrets (a note says so).

## What it does not do

- It does not find unknown memory-corruption bugs; that needs disassembly and data-flow analysis.
- A version banner shows that library code is in the file, not that the vulnerable function is reachable. Components are reported with confidence `medium` (banner, crate path) or `high` (Go build info, cargo-auditable).
- Dynamically linked libraries are not followed: scan each library separately. A binary that only links `libssl.so` carries no OpenSSL banner itself.
- Go binaries built before modules (GOPATH mode, ≤ 1.17) have no module list, and a Go binary whose build info was removed on purpose yields no components. Stripped C/C++ binaries that removed their banners yield no components. Managed .NET assemblies get their PE header flags checked, not their IL.
- Static / stripped ELF files have no dynamic symbol table, so the canary and FORTIFY checks are skipped (and noted in the report).
