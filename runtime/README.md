# ubel-runtime — scan of the applications running on a Linux machine

`ubel-runtime` looks at what is **running now** — not at what is installed or configured — and writes a JSON and an HTML report with
**diffs against the previous scan, compliance mapping and detailed stats**: the same report model and runner as `ubel-vm`, plus
*Processes*, *Containers* and *Live data* tabs.

- **Zero third-party dependencies, no subprocesses.** Node.js built-ins only. It reads `/proc`, the applications' files on disk
  (`package.json`, `node_modules`) and — only when asked — the local container engine socket (read-only `GET`s), a loopback HTTP probe
  and the V8 inspector of Node.js processes. It never runs `ps`, `ss`, `lsof`, `docker` or any other program.
- **Linux only** (`/proc`). On another platform it exits with a usage error.
- **Honest coverage.** Every check ends as **passed**, **failed**, **not applicable** or **not assessed**. Anything the scanner could not
  read (other users' environments, mapped files and sockets without root) or look up (OSV.dev / NVD unreachable) is *not assessed* and the
  run exits `3` unless you pass `--allow-partial`. Run it as **root** for a complete result.

```bash
sudo ubel-runtime                                 # everything running on this machine, passive
sudo ubel-runtime --node-only --inspect           # + look inside the Node.js processes
sudo ubel-runtime --name /nginx|postgres/ --probe # selected programs, + loopback probe
ubel-runtime --pid 1234 --fail-on high --min-severity medium
ubel-runtime --list-checks
```

## What it checks

| Area | Checks |
|---|---|
| `processes` | program file deleted or replaced; running from an anonymous memory file (fileless); program or script in `/tmp`, `/var/tmp`, `/dev/shm`; network service as root; dangerous capabilities; being traced; debug interface enabled (`--inspect`, JDWP, …); network-facing without seccomp / `no_new_privs` |
| `exposure` | sensitive or clear-text service on a non-loopback address; services bound to all interfaces; with `--probe`: sensitive endpoints that answer on loopback (`/.env`, `/.git/HEAD`, actuator, pprof, metrics, inspector, …) |
| `libraries` | mapped library replaced or deleted on disk (stale after an upgrade); native code from a world-writable directory; `LD_PRELOAD` / `LD_LIBRARY_PATH` / `/etc/ld.so.preload` injection; executables and libraries with embedded vulnerable components (version banners → NVD, Go modules / Rust crates / bundled npm and Python packages → OSV.dev) |
| `components` | npm packages installed under each Node.js application (OSV.dev); the Node.js release and the libraries it bundles (NVD); Node.js end of life |
| `packages` | operating-system packages that the running programs and libraries belong to (SCA engine: platform mode on the host, docker mode on `/proc/<pid>/root` for a container; only the packages in use are reported); Python / Ruby / PHP packages under the application directory of each running process (SCA health scan). Findings are `sc_vuln` / `sc_infection` |
| `secrets` | credentials in process environments (UBEL's secret rules) and on command lines — values are always redacted |
| `containers` | privileged; host namespaces; sensitive host mounts; dangerous capabilities; confinement disabled; credentials in the configuration; sensitive ports published on all interfaces; root user; no limits; mutable image tag; with `--container-packages`: vulnerable packages inside the container (`sc_vuln`) |
| `inspection` | with `--inspect`: Node.js processes that could not be inspected; inspector left open; code loaded from a world-writable directory; files changed on disk after the process started |

`ubel-runtime --list-checks` prints the catalogue with severities.

## Options

| Option | Meaning |
|---|---|
| `--pid <n,..>` | Only these process ids |
| `--name <text\|/regex/>` | Only processes whose name, executable or command line matches (repeatable) |
| `--node-only` | Only Node.js processes |
| `--include-self` | Also assess the scanner's own process |
| `--libs app\|all\|none` | Which mapped native files are read for embedded component versions: outside the system library directories (default), all, or none |
| `--max-libs <n>` | Read at most `n` distinct executables / libraries (default 150) |
| `--packages host\|all\|none` | Packages used by running processes: this machine only, containers too (default `all`), or none |
| `--max-package-scopes <n>` | Read the packages of at most `n` container filesystems / application directories (default 20) |
| `--container-packages` | Also scan **every** package of each running container (SCA docker mode on `/proc/<pid>/root`), in use or not (best effort: containers whose root cannot be reached are reported as not assessed) |
| `--inspect` | Look inside Node.js processes — see below |
| `--inspect-max <n>` | Inspect at most `n` Node.js processes (default 25) |
| `--probe` | Loopback HTTP probe of the listening ports — see below |
| `--no-lookups` | Do not query OSV.dev / NVD (the advisory checks become *not applicable*) |
| `--no-threat-intel` | Do not fetch CISA KEV / FIRST EPSS data |
| `--only` / `--skip` / `--min-severity` / `--fail-on` / `--allow-partial` / `--working-dir` / `--verbose` / `--quiet` | As in `ubel-vm` |

Set `UBEL_OSV_ENDPOINT` / `UBEL_NVD_ENDPOINT` for an internal mirror.

## Packages in use (`packages`)

`ubel-vm` lists every installed package; `ubel-runtime` reports the ones **a running process uses**, through the SCA engine (`vm/lib/scascan.js`):

- **Operating-system packages.** The executable and every executable file a process has mapped (`/proc/<pid>/maps`) is matched to the package that owns it, using the package database on disk (dpkg file lists, apk, rpm; `/bin` ≡ `/usr/bin` is normalised). The SCA engine scans the host (**platform mode**) or the container's filesystem (**docker mode** on `/proc/<pid>/root`) and only the advisories of the packages in use are kept (`rt-pkg-os-vulnerable`). An upgrade does not replace code already loaded in a process, so the remediation is "update and restart".
- **Python, Ruby and PHP applications.** The application directory of each running interpreter process — its virtualenv (`VIRTUAL_ENV` or the interpreter's `pyvenv.cfg`), script directory or working directory, up to the nearest project marker (`requirements.txt`, `pyproject.toml`, `Gemfile.lock`, `composer.json`, `Cargo.lock`, …) — is scanned by the SCA **health scan (full stack)**: the venv's `site-packages`, Composer `vendor/`, lockfiles. A process on the system Python also gets the pip-installed `/usr/local/lib` (`rt-pkg-app-vulnerable`).
- Node.js applications keep their own check (`rt-comp-vulnerable-package`, with `--inspect` it knows which packages are loaded); Go and Rust programs carry their modules inside the binary, which the library check reads. **Java applications are not read.**

All of these findings carry the SCA vulnerability record and the type `sc_vuln` (`sc_infection` for malware advisories), so the report shows them in the **SCA vulnerability modal**, with the process or application that uses the package. `--no-lookups` makes them *not applicable*; a scan that cannot be completed is *not assessed*.

## `--inspect` — what a Node.js process has really loaded

Installed is not the same as used: a vulnerable package that sits in `node_modules` but is never `require`d is much less urgent than one
the process runs. With `--inspect` the scanner, for each Node.js process in scope:

1. **checks that the process handles `SIGUSR1`** (bit 10 of `SigCgt` in `/proc/<pid>/status`) — a process without a handler would be *killed* by
   the signal, so it is never sent; processes started with `--disable-sigusr1` are refused;
2. sends `SIGUSR1`, which makes Node.js open its inspector on loopback (the port is found from the process's own sockets, not assumed);
3. connects with a hand-rolled WebSocket client, enables the debugger (V8 replays the scripts it has compiled — CommonJS and ES modules),
   and runs **one read-only expression** that returns `process.versions` and the keys of the CommonJS module cache (V8 forgets the script of a
   CommonJS module once it has finished loading, so the cache fills the gap);
4. closes the inspector again (`process._debugEnd()`) **and verifies that the port is gone** — if it is not, `rt-insp-left-open` fails.

Effects the operator should know about: the target prints `Debugger listening on ws://127.0.0.1:…` / `Debugger attached.` to its standard
error, and the scanner needs the same user as the target (or root). An inspector the process already had open (`--inspect`) is used as it is
and left open. Nothing is evaluated that changes state.

With the result, `rt-comp-vulnerable-package` rates a vulnerable package the process **has loaded** at its own severity, and one that is only
installed **one level lower**. Without `--inspect` no reachability is claimed and nothing is downgraded.

## `--probe` — loopback only

For every port a process listens on, a handful of `GET` requests (`/`, `/.env`, `/.git/HEAD`, actuator, pprof, server-status, metrics, phpinfo,
the inspector's `/json/version`) is sent to `127.0.0.1`. It never leaves the machine and sends nothing but `GET`. It replaces the heavier
`ubel-host` pipeline for this purpose: that one is built for remote targets and refuses local addresses.

## Findings are stable between runs

Findings are named after the **program** (executable + script, no pid) and where it runs (`host` or `docker:<id>`), and processes of the same
program (cluster workers, forked children) are grouped into one finding. Restarting a service therefore does not turn its findings into new
ones in the **Diffs** tab.

## Reports

`latest.runtime.json` / `latest.runtime.html` under `.ubel/reports/` and `report.runtime.{json,html}` in the timestamped zip under
`$HOME/.ubel/history/<asset_id>/`. The JSON carries a `runtime` block (programs, listening sockets, containers, inspections). **Environment
values and command-line secrets are never written to a report.**

## Limitations

- A snapshot: processes that start and end between two scans are not seen.
- Without root only the scanner user's own processes are fully readable; the rest is reported as *not assessed*. A kernel rootkit that hides
  processes from `/proc` cannot be detected from `/proc`.
- Package and library versions are read from disk; where files changed after a process started, memory may differ (`rt-insp-stale-code`,
  `rt-lib-stale-mapped` flag it).
- Live inspection is limited to Node.js and to processes that handle `SIGUSR1`.
- Whether a port is reachable from the internet depends on firewalls and security groups outside the machine.
