# UBEL — Unified Bill / Enforced Law
### EASM — External Attack Surface Fingerprinting (`ubel-url`, `ubel-domain`, `ubel-host`, `ubel-easm`)

> ## ⚠ Authorized use only
> `ubel-url` sends live, unauthenticated HTTP(S) requests to every target you
> give it, then discloses what it fingerprints (product/version banners) to
> OSV.dev, NVD, and/or wpvulnerability.net to look up known vulnerabilities.
> `ubel-domain` does the same, but **discovers its own target list** from
> Certificate Transparency logs first — meaning it can end up scanning hosts
> you didn't explicitly name and may not have expected to exist. `ubel-host`
> goes further: it **connect-scans every port in a range (1-30000 by
> default) on one host**, probes whatever accepts a connection for HTTP(S),
> and fingerprints what answers — a live port sweep, not just a passive
> fingerprint request. `ubel-easm` combines all of it: it discovers a
> domain's subdomains the way `ubel-domain` does, resolves every one of them
> to an IP, then runs `ubel-host`'s full port sweep against **every distinct
> IP behind the domain**, and fingerprints the combined result — the most
> invasive of the four, and the one most likely to reach infrastructure you
> didn't intend to touch (see "Shared IPs" under
> [`ubel-easm`](#ubel-easm--discover-a-domain-resolve-to-ips-port-scan-each-then-fingerprint-everything)
> below). **Only ever run any of these four against infrastructure you own,
> or have explicit, documented authorization to test** — the same rule
> UBEL's own license already holds every module to (see
> [`../LICENSE.md`](../LICENSE.md), "Internal Use Only"). Scanning a system
> you don't own or lack authorization for can violate computer-fraud laws
> (e.g. the CFAA), the target's terms of service, and/or applicable
> regulations, regardless of intent — this applies whether the target is a
> third party's infrastructure or a system inside your own organization that
> you personally aren't authorized to test. UBEL and its authors accept no
> liability for misuse. This warning is repeated in each CLI's `--help`
> output, printed before every scan, embedded in every JSON report
> (`usage_notice`), and shown as a persistent banner on every tab of the HTML
> report — it isn't something you can accidentally miss or scan past.
>
> `ubel-domain`, `ubel-host`, and `ubel-easm` each accept `--list-only`,
> which stops **before a single request reaches a target you didn't name
> directly** — printing the discovered host list (`ubel-domain`), the
> open/HTTP(S) port list (`ubel-host`), or the discovered IP grouping
> (`ubel-easm`) and exiting, with nothing written to disk. Use it to review
> (and trim, with `--exclude`/`--exclude-ip`) what a real run would touch
> before you authorize it — this matters most for `ubel-easm`, whose
> discovery step can turn one domain into a port sweep of several unrelated
> IPs.

`ubel-url` passively fingerprints the software exposed on a domain/URL over
plain HTTP(S) — server banners, `X-Powered-By`/version headers, page markup,
a small set of well-known paths (`/health`, `/version`, `/graphql`, common
admin pages, etc.) — turns what it finds into candidate CPE 2.3 identifiers
(plus a purl where a scanner can name an exact registry package), and feeds
those through the exact same OSV.dev/NVD vulnerability-lookup primitives the
[SCA module](../sca/README.md) uses for dependency scanning.

`ubel-domain` is the same engine with the target list discovered for you:
give it a root domain, and it pulls every subdomain that a public CA has
logged a certificate for (via [crt.sh](https://crt.sh)), then fingerprints
all of them in one run. The flow end to end:

```
domain  →  crt.sh subdomain discovery  →  fingerprint every host
        →  group techs by name+version (with the host list for each)
        →  vulnerability lookup + misconfiguration checks  →  one report
```

The grouping step is a property of the shared scanning engine, not something
`ubel-domain` layers on top: the inventory is keyed by name+version, so
nginx 1.18.0 found on forty subdomains is **one** inventory item carrying a
forty-host list and **one** set of vulnerability findings — not forty
near-identical rows repeating the same CVEs. See "Known limitations" for how
that interacts with multi-id components.

`ubel-host` adds a step *before* fingerprinting instead of before discovery:
give it one host, and it connect-scans every port in range, probes whatever
accepts a connection for HTTP(S), and hands only the HTTP(S)-speaking ports
to the same fingerprint/lookup engine `ubel-url` uses — so you don't have to
already know which port a target's web app or admin panel lives on.

```
host  →  connect-scan port range  →  probe open ports for HTTP(S)
      →  fingerprint every host:port that answered  →  group by name+version
      →  vulnerability lookup + misconfiguration checks  →  one report
```

`ubel-easm` is `ubel-domain`'s discovery and `ubel-host`'s port sweep run
together across a whole domain: it discovers subdomains via crt.sh, resolves
every one of them to an IP, collapses that down to the **distinct** IPs
actually behind the domain (several subdomains commonly share one), then
runs `ubel-host`'s connect-scan-then-HTTP(S)-probe against each of those
IPs. Every IP's HTTP(S)-speaking ports are merged into one target list
before fingerprinting — a component seen on five IPs behind the domain is
still one inventory item, the same name+version dedup `ubel-domain` gets
across subdomains. It also fingerprints the discovered subdomains **by
name** (not just by IP:port), because a bare IP request carries no Host
header or TLS SNI and so can never see a name-based virtual host — see
[`ubel-easm`](#ubel-easm--discover-a-domain-resolve-to-ips-port-scan-each-then-fingerprint-everything)
below for `--subdomain-ports`.

```
domain  →  crt.sh subdomain discovery  →  resolve every hostname to an IP
        →  collapse to distinct IPs  →  port-scan + HTTP(S)-probe each IP
        →  fingerprint every ip:port AND every subdomain-by-name
        →  group by name+version  →  vulnerability lookup + misconfig checks
        →  one report
```

This document covers the **EASM module** — `ubel-url`, `ubel-domain`,
`ubel-host`, and `ubel-easm` — four of the CLIs shipped in the
`@arcane-spark/ubel-node` package alongside the SCA/firewall CLI
([../sca/README.md](../sca/README.md)), the AI-powered SAST/malware scanner
([../sast/README.md](../sast/README.md)), and the cloud misconfiguration
scanner ([../cloud/README.md](../cloud/README.md)). All four share one
scanning/lookup/reporting engine — `ubel-domain`, `ubel-host`, and
`ubel-easm` each only add a discovery step ahead of exactly what `ubel-url`
already does; see each entry point's own file for the precise delta
(`domain.js`, `host.js`, `easm.js`).

Written against **Node.js's standard library only** for the OSV/NVD/report
layer — the fingerprinting engine underneath ([`fingerprint/`](./fingerprint/),
see [its README](./fingerprint/README.md) and [NOTICE](./fingerprint/NOTICE.md))
is likewise zero-npm-dependency, stdlib-only HTTP.

---

## What this is, and isn't

`ubel-url` is a **known-vulnerability lookup against passively fingerprinted
software**, not a vulnerability scanner, exploitation tool, or brute-forcer.
It never authenticates, never sends anything beyond an ordinary GET request,
never attempts to exploit anything it finds, and never brute-forces logins
or paths beyond a small fixed list of well-known ones (see
[`fingerprint/NOTICE.md`](./fingerprint/NOTICE.md)). A finding here means
"this product/version has a publicly known CVE" — it says nothing about
whether that CVE is actually reachable, patched out-of-band, or mitigated by
something in front of it (a WAF, a reverse proxy stripping the banner that
would've disproved the version, etc.). Treat every finding as a lead to
verify, not a confirmed compromise. `ubel-domain` inherits this exactly —
its only addition is discovering the target list; it fingerprints each
discovered host with the same single-GET-plus-well-known-paths posture.

`ubel-host` and `ubel-easm` are **not** purely passive in the same sense:
before any fingerprinting happens, both run a live raw-TCP connect scan
across a port range (1-30000 by default) — a real, if unauthenticated and
non-exploitative, port scan, not just a fingerprint request. That scan does
nothing beyond attempting a TCP handshake on each port (no banner-grabbing,
no protocol negotiation beyond the HTTP(S) liveness probe that follows it),
and still never authenticates, exploits, or brute-forces anything — but it
is a materially more active reconnaissance step than `ubel-url`/
`ubel-domain`'s single GET per target, is likely to be logged/alerted on by
anything watching the target's network (an IDS, a cloud provider's port-scan
detection), and against a wide `--ports` range can generate a large number
of connection attempts in a short time. Treat "authorized use only" as
applying with extra weight to these two entry points.

Alongside that CVE lookup, every scan also runs a small, fixed set of
**misconfiguration checks** against each live host — exposed `.env`/`.git`,
WordPress-specific probes, TLS/certificate weaknesses, missing/weak security
headers and cookie flags, risky HTTP methods, CORS misconfiguration, and
SPF/DMARC/DKIM email-authentication gaps — see
[Misconfiguration checks](#misconfiguration-checks) below. These stay within
the same posture as everything else here: a single well-known path per HTTP
check (or one TLS handshake, or a short list of well-known DNS names for the
email-authentication checks), no exploitation, no brute-forcing. It's a
second, independent finding type layered on the same passive scan, not a
change to what the module does or how it behaves.

This is deliberately a **subset** of what the SCA module's report shows for
a dependency-tree scan, not a re-implementation of all of it. Specifically
excluded, and why:

- **License compliance** — there's no source/manifest to read a license
  declaration off of; a remote HTTP fingerprint has no license field.
- **Dependency sequences / a dependency graph** — fingerprinted components
  aren't resolved from a lockfile or manifest, so there's no "introduced by"
  chain, no direct-vs-transitive distinction, and no dependency tree to
  render. Every component is a flat, independent finding.
- **Reachability analysis** — that's static analysis over source code you
  have on disk (import-graph tracing). There's no source code here, only a
  remote host's HTTP responses.
- **SBOM (CycloneDX) and SARIF output** — this isn't a dependency-tree or
  code-scanning artifact; JSON and HTML only (see [Reports](#reports)).

What's **kept**, because it isn't specific to dependency-tree scanning:
CVSS scoring/vectors, fix-version recommendations, malicious-package-style
infection flags (in the rare case OSV ever returns one against a matched
identifier), and the same
[compliance framework mapping](../sca/README.md) (OWASP Top 10, PCI DSS,
HIPAA, SOC 2, ISO/IEC 27001, NIST SP 800-53, GDPR, CIS Controls v8) every
other UBEL module uses.

Every detected component's `scopes` is unconditionally `["prod"]` — nothing
this module can fingerprint over the network is a dev-only or build-only
dependency; if it's answering HTTP requests, it's running.

---

## Features

- Passive HTTP(S) fingerprinting across ~55 registered product/CMS/framework
  scanners (Nginx, Apache, WordPress, Jenkins, GitLab, Grafana, Elasticsearch,
  Django/Rails/Laravel/Express-style framework markers, and more — see
  [`fingerprint/README.md`](./fingerprint/README.md) for the full
  architecture) plus generic `Server`/`X-Powered-By` header parsing as a
  fallback for anything not explicitly registered
- Multi-target in one run (`ubel-url a.com b.com c.com` or `--targets-file`),
  with bounded concurrency for the fingerprinting step
- **Subdomain discovery** (`ubel-domain`, `ubel-easm`) — give it a root
  domain and it enumerates every subdomain with a logged certificate via
  crt.sh, then scans all of them in one run; `--list-only` prints the scope
  without touching a single discovered host
- **Port scanning** (`ubel-host`, `ubel-easm`) — a bounded-concurrency raw
  TCP connect scan across a port range (1-30000 by default) on one host
  (`ubel-host`) or on every distinct IP a domain's discovered subdomains
  resolve to (`ubel-easm`), followed by an HTTP(S) liveness probe of
  whatever accepted a connection, so you don't need to already know which
  port a target's web app lives on; `--list-only` prints the open/HTTP(S)
  port list (or, for `ubel-easm`, the IP grouping) without fingerprinting
  anything
- De-duplicated vulnerability lookups — the same product+version detected on
  many hosts is one query, not one per host; every affected host is still
  listed per finding. Inventory is grouped by name+version, so a domain-wide
  sweep that finds the same nginx on forty subdomains (or the same service
  on forty ports across several IPs, for `ubel-easm`) yields one component
  row carrying a forty-host list, not forty duplicate rows
- Reuses `../sca/engine.js`'s exact OSV.dev + NVD query, CVSS-parsing, and
  fix-version-recommendation logic — not a reimplementation, the same code
  path the SCA module's host/platform CPE-based scanning already uses —
  plus a dedicated [wpvulnerability.net](https://www.wpvulnerability.net)
  lookup for WordPress plugins/themes/core, across all four entry points
  (see [Vulnerability data sources](#vulnerability-data-sources))
- **Compliance framework mapping**, same shared engine as every other module
- Automatic report generation: timestamped **JSON** + interactive **HTML**,
  plus `latest.*` convenience copies
- `--fail-on` severity/count gate — same syntax as `ubel-cloud` — for CI use
- **Client-side secret detection** — each live host's inline `<script>`
  blocks and referenced `.js` files are fetched and scanned with the same
  rule set as `ubel-secrets`, reporting the exact URL and line:column of
  every hardcoded credential a visitor could read out of the page (values
  redacted in the report). Disable with `--no-secrets`
- **Web misconfiguration checks** — every live host is also probed for a
  fixed set of well-known issues: an exposed `.env` file (cross-referenced
  against the same secrets rule set), an exposed `.git` directory (readable
  `HEAD`, with a best-effort remote-URL read from `.git/config`), exposed
  `phpinfo()` output, and — only on hosts the fingerprinter already
  identified as WordPress — a reachable `xmlrpc.php` and unauthenticated
  user enumeration via `wp-json/wp/v2/users`. Every host is also checked for
  TLS/certificate weaknesses (expiry, untrusted/self-signed, hostname
  mismatch, weak negotiated protocol/cipher, explicit TLS 1.0/1.1 downgrade
  acceptance, or no working HTTPS listener at all), missing/weak HTTP
  security headers (HSTS, CSP, clickjacking protection via
  `X-Frame-Options`/`frame-ancestors`, `X-Content-Type-Options`,
  `Referrer-Policy`, `Permissions-Policy`), missing/weak `Set-Cookie`
  attributes (`Secure`/`HttpOnly`/`SameSite`), risky HTTP methods
  (`PUT`/`DELETE`/`TRACE`/`CONNECT` advertised in `Allow`, plus an actual
  Cross-Site Tracing probe), CORS misconfiguration (arbitrary-Origin
  reflection with/without credentials, a wildcard paired with credentials,
  the `null` Origin), and SPF/DMARC/DKIM email-authentication gaps (the one
  DNS-only check in the set — see below). Runs automatically on every
  scan — see [Misconfiguration checks](#misconfiguration-checks)
- **DNS pre-resolution** — every target is resolved before probing; a
  hostname with no DNS record is marked `dead` in the report and skipped
  rather than probed to a timeout, so "this host is gone" is never confused
  with "this host failed to scan"
- Built-in safety default: targets resolving to a private/RFC1918 address or
  to the scanning host's own public IP are skipped, not scanned, unless
  `--allow-private` is explicitly passed (see [Safety guard](#safety-guard))
- Zero external runtime dependencies (Node.js stdlib only, both here and in
  the vendored fingerprinting engine)

---

## Installation

```bash
npm install -g @arcane-spark/ubel-node
```

This installs `ubel-url`, `ubel-domain`, `ubel-host`, and `ubel-easm`
alongside every other UBEL binary. There's no separate package to install —
EASM ships as part of `@arcane-spark/ubel-node`.

---

## Requirements

- Node.js `>=18.0.0`
- Outbound network access to: the target(s) you're scanning — HTTP(S)
  requests for fingerprinting/misconfiguration checks, a raw TLS handshake
  to port 443 for the certificate/protocol checks, and outbound DNS TXT
  queries (to the target's own domain, `_dmarc.<host>`, and a short list of
  `_domainkey.<host>` selector names) for the email-authentication checks
  (see [Misconfiguration checks](#misconfiguration-checks)) — `api.osv.dev`,
  `services.nvd.nist.gov`, and `www.wpvulnerability.net` (plus `crt.sh` for
  `ubel-domain`/`ubel-easm`) — or your own internal mirrors, see
  [Vulnerability data sources](#vulnerability-data-sources)
- For `ubel-host`/`ubel-easm` specifically: outbound access to raw TCP
  connect attempts across the whole scanned port range (1-65535, default
  scan range 1-30000) on the target host(s)/IP(s) — a restrictive egress
  firewall on the scanning machine itself will silently look like "nothing
  is open" rather than error, since a blocked outbound connect and a closed
  remote port both just time out
- No credentials of any kind — this doesn't authenticate to anything

---

## Safety guard

By default, before probing anything, each target's IP is resolved and
checked against private/RFC1918 ranges and the scanning host's own public
IP. A match is **skipped, not scanned** — reported in the JSON/HTML Scan Info
tab with a `"skipped"` status and a reason, never silently dropped from the
target list, so a report never reads as "clean" for a target that was
actually never probed.

For `ubel-host` and `ubel-easm`, the same check runs **one stage earlier**:
before the port scan even starts (not just before fingerprinting), since a
full port sweep of an unintended target is a bigger deal than a single
fingerprint request. `ubel-host` checks the one host it's given directly;
`ubel-easm` checks every IP it resolves for itself, one entry in the report
per IP. Neither guard can detect the separate "shared/CDN IP" risk
`ubel-easm` carries — see
[`ubel-easm`](#ubel-easm--discover-a-domain-resolve-to-ips-port-scan-each-then-fingerprint-everything)
below.

`--allow-private` disables this guard entirely. It exists for lab/localhost
targets you own (`ubel-url localhost:8080 --allow-private`,
`ubel-url 10.0.4.12 --allow-private` against your own internal staging box)
— it is not a way around the authorized-use requirement above, and using it
against anything you don't own or aren't authorized to test is exactly the
misuse this README opens with.

---

## Usage

### `ubel-url` — scan hosts you already know

```bash
ubel-url example.com                                   # single target, https:// then http:// fallback
ubel-url a.example.com b.example.com api.example.com   # multiple targets in one run, one report
ubel-url --targets-file targets.txt                    # newline-separated targets; "#" comments/blank lines ignored
ubel-url staging.internal:8443 --allow-private          # a lab/internal target you own
ubel-url example.com --concurrency 8                    # fingerprint up to 8 targets in parallel
ubel-url example.com --working-dir /path/to/project     # reports written under <path>/.ubel/ instead of cwd
ubel-url example.com --min-severity high                # only list high/critical vulnerabilities in the report
ubel-url example.com --fail-on high                     # non-zero exit on high or critical (default: critical)
ubel-url example.com --fail-on 5:high                   # non-zero exit only once MORE than 5 high-or-above findings exist
ubel-url example.com --fail-on none                     # always exit 0 (reports are still written)
ubel-url example.com --verbose                          # per-target fingerprinting/NVD-query progress
ubel-url example.com --quiet                            # suppress the console summary; reports still written
ubel-url --help
```

A `<target>` is a bare domain (`example.com`), a `host:port` pair
(`example.com:8443`), or a full URL (`https://example.com:8443`). When no
scheme is given, the fingerprinter tries `https://` first and falls back to
`http://` only if that initial probe fails.

### `ubel-domain` — discover subdomains, then scan all of them

```bash
ubel-domain example.com                                 # discover via crt.sh, fingerprint every host found
ubel-domain example.com --list-only                     # print the discovered host list and exit — sends NOTHING to those hosts
ubel-domain example.com --exclude legacy.example.com    # skip a discovered host (repeatable)
ubel-domain example.com --include internal.example.com  # add a host crt.sh didn't return (repeatable)
ubel-domain example.com --concurrency 8                 # fingerprint up to 8 discovered hosts in parallel
ubel-domain example.com --min-severity high --fail-on high
ubel-domain example.com --verbose                       # per-host discovery/fingerprinting progress
ubel-domain --help
```

`<domain>` is a bare registrable domain — `example.com`, not a URL, a
`host:port` pair, or a wildcard; exactly one per run. It shares every
scanning/reporting flag with `ubel-url` (`--allow-private`, `--concurrency`,
`--working-dir`, `--min-severity`, `--fail-on`, `--verbose`, `--quiet`) and
behaves identically for all of them, because both drive the same engine.

Discovery is **passive** — Certificate Transparency logs only, via
`https://crt.sh/json?q=<domain>`. No DNS brute-forcing, no wordlists, no
zone-transfer attempts. Practical consequences:

- Wildcard entries (`*.example.com`) are not scannable hosts and are
  dropped; their non-wildcard siblings on the same certificate are kept.
- The apex domain itself is included whenever a certificate covers it.
- Anything crt.sh's loose search returns that isn't actually within the
  queried domain (e.g. `example.com.unrelated.net`) is rejected.
- A subdomain with no logged certificate — internal-only, HTTP-only — won't
  be found. `--include` exists for exactly that gap.
- If crt.sh is unreachable, rate-limiting, or returns nothing usable, the
  run exits `1` with an explanation rather than reporting a misleading
  "clean" result for a domain it never actually enumerated.

Start with `--list-only` on any domain you haven't swept before. It performs
discovery and prints the host list without sending a single request to any
discovered host, so you can confirm the scope (and trim it with
`--exclude`) before authorizing the real scan.

### `ubel-host` — port-scan one host, then scan whatever answers HTTP(S)

```bash
ubel-host example.com                                   # connect-scan ports 1-30000, fingerprint HTTP(S) ports found
ubel-host example.com --ports 1-1024                    # narrow the scanned range (well-known ports only)
ubel-host example.com --ports 1-65535                   # the full port space
ubel-host example.com --list-only                       # print open + HTTP(S) ports and exit — sends nothing further
ubel-host 203.0.113.10                                  # a bare IPv4 address works the same as a hostname
ubel-host staging.internal --allow-private               # a lab/internal host you own
ubel-host example.com --port-concurrency 200             # slower/gentler connect scan (default: 500)
ubel-host example.com --port-timeout 3000                 # more patient per-port connect timeout, ms (default: 1500)
ubel-host example.com --http-concurrency 10               # slower HTTP(S) liveness-probe stage (default: 20)
ubel-host example.com --concurrency 8                     # fingerprint up to 8 HTTP(S)-speaking ports in parallel
ubel-host example.com --min-severity high --fail-on high
ubel-host example.com --verbose                           # per-port/per-host progress
ubel-host --help
```

`<host>` is a single bare hostname or IPv4 address — not a URL, not a
`host:port` pair; exactly one per run. It shares every scanning/reporting
flag with `ubel-url` (`--allow-private`, `--concurrency`, `--working-dir`,
`--min-severity`, `--fail-on`, `--no-secrets`, `--verbose`, `--quiet`), plus
its own discovery-stage flags (`--ports`, `--port-concurrency`,
`--port-timeout`, `--http-concurrency`, `--http-timeout`).

Discovery is **active**, two stages, both against the one host:

1. Every port in `--ports` (default `1-30000`, inclusive) is connect-scanned
   in parallel. A port that accepts a TCP connection counts as "open" —
   nothing about what's actually listening on it is known yet.
2. Each open port is then probed with an HTTP(S) request (HTTPS first,
   falling back to plain HTTP) to filter that list down to the ones
   actually speaking HTTP(S) — most open ports on a typical host (SSH, a
   database, a message queue, ...) are not web servers, and only the
   HTTP(S)-speaking subset is handed to the fingerprinter.

Both lists are recorded in the report: the HTTP(S)-speaking subset becomes
the usual Targets/assets list (identical shape to a `ubel-url` run), and the
**full open-port list** is additionally shown in the Scan Info tab so the
report reflects the whole scanned range, not just the ports that went on to
be fingerprinted.

Start with `--list-only` on any host you haven't swept before — it runs both
discovery stages and prints the open-port and HTTP(S)-port lists, then exits
before a single fingerprinting request is sent.

### `ubel-easm` — discover a domain, resolve to IPs, port-scan each, then fingerprint everything

```bash
ubel-easm example.com                                    # crt.sh discovery -> resolve to IPs -> port-scan each -> fingerprint
ubel-easm example.com --list-only                        # discover, resolve, group by IP, print, exit — no port touched
ubel-easm example.com --exclude legacy.example.com       # drop a hostname before it's ever resolved (repeatable)
ubel-easm example.com --exclude-ip 198.51.100.7          # never port-scan this IP, even if a hostname resolves to it (repeatable)
ubel-easm example.com --include internal.example.com     # resolve+scan a hostname crt.sh didn't return (repeatable)
ubel-easm example.com --ports 1-1024                     # narrower port range, applied once per distinct IP
ubel-easm example.com --subdomain-ports none              # IP:port targets only; don't also fingerprint subdomains by name
ubel-easm example.com --subdomain-ports all                # + every other HTTP(S) port found on a subdomain's IP, by name
ubel-easm example.com --ip-concurrency 1                   # port-scan distinct IPs one at a time (default: 2)
ubel-easm example.com --concurrency 8                       # fingerprint up to 8 HTTP(S) targets in parallel, across all IPs
ubel-easm example.com --min-severity high --fail-on high
ubel-easm example.com --verbose                              # per-hostname/per-IP/per-port progress
ubel-easm --help
```

`<domain>` is a bare registrable domain, exactly one per run — same format
rule as `ubel-domain`. It shares every scanning/reporting flag with
`ubel-url`, `ubel-domain`'s own `--include`/`--exclude`, and `ubel-host`'s
own port-scan flags (`--ports`, `--port-concurrency`, `--port-timeout`,
`--http-concurrency`, `--http-timeout`), plus two flags unique to it:
`--exclude-ip` and `--subdomain-ports`.

This is the most invasive EASM entry point UBEL ships — think of it as "run
`ubel-domain`'s discovery, then run `ubel-host`'s full port sweep against
every IP that discovery turns up, and report on all of it together."
Discovery (crt.sh + DNS resolution) is passive; the port scan that follows
it is not — it's a live connect scan against every distinct IP found, same
as `ubel-host`. The flow:

1. Discover subdomains via crt.sh (same as `ubel-domain`), merge in
   `--include`, drop `--exclude`.
2. Resolve every remaining hostname to an IP and collapse the result onto
   the set of **distinct IPs** — several subdomains commonly share one
   origin IP (or one shared/CDN edge IP), and there's no reason to
   port-scan the same address twice. `--exclude-ip` drops an IP here even
   if a hostname resolved to it.
3. Connect-scan every port in `--ports` on **each** distinct IP, then
   HTTP(S)-probe whatever accepted a connection — `ubel-host`'s own two
   discovery stages, run once per IP, up to `--ip-concurrency` IPs at a
   time (default: 2, kept low because each IP's own scan already opens up
   to `--port-concurrency` connections at once).
4. Merge every IP's HTTP(S)-speaking ports into **one** target list and
   fingerprint it in a single pass — a component seen on five IPs behind
   the domain is still one inventory item, not five.
5. **Also** fingerprint the discovered subdomains **by name**, not just by
   IP:port: a request to a bare IP carries no Host header or TLS SNI, so it
   only ever reaches the server's default site and misses every name-based
   virtual host. Controlled by `--subdomain-ports`:
   - `none` — IP:port targets only; subdomains are used to find IPs and
     then not scanned by name.
   - `default` (the default) — each subdomain's own URL on the default web
     port (443, else 80), whenever the port scan found its IP answering
     there.
   - `all` — as `default`, plus `<subdomain>:<port>` for every *other*
     HTTP(S) port found on that subdomain's IP. Multiplies the target count
     by (subdomains per IP) × (web ports per IP) — on a shared IP with many
     subdomains and several web ports, that grows fast.

**Shared IPs — read before running unattended.** Several subdomains of a
domain frequently resolve to the same IP, sometimes because it's genuinely
the domain owner's own single origin server, and sometimes because it sits
behind a CDN, a load balancer, or shared hosting whose IP is **not**
exclusively the domain owner's infrastructure. `ubel-easm` only
de-duplicates identical IPs so it doesn't scan the same address twice — it
has no way to tell "my dedicated server" apart from "a shared edge IP
thousands of other sites also resolve to." Owning a domain does not by
itself authorize a full port sweep of every IP that domain's DNS happens to
point at. **Always review the IP list with `--list-only` first**, and use
`--exclude`/`--exclude-ip` to drop any host or IP you don't have standalone
authorization to port-scan. The private/self-IP safety guard (see [Safety
guard](#safety-guard)) does not and cannot detect this — it only catches
RFC1918/self addresses, not a third party's shared infrastructure.

### Shared behavior

`--min-severity` filters which vulnerabilities appear in the report's
Vulnerabilities tab (default: everything, i.e. `unknown` and above). It does
**not** change the Components tab or any component's `vulnerabilities_count`
— those always reflect the full, unfiltered scan, so a component never
silently looks "clean" just because its only known issue was filtered out
of the vulnerability list.

Exit code is `2` if the `--fail-on` condition is met (default: any
vulnerability at `critical` severity or an infection; pass `--fail-on none`
to always exit `0`, or `--fail-on <count>:<severity>` — e.g. `5:high` — to
fail only once MORE than `<count>` matches at or above `<severity>` exist,
for a CI gate that tolerates a known/accepted baseline), `0` otherwise, `1`
on a fatal/unexpected error (including `ubel-domain` finding no hosts or
`ubel-easm` finding no scannable IP for the domain). `--fail-on` gates only
on **vulnerabilities** (and infections) — a scan that finds nothing but
critical misconfigurations still exits `0`; misconfiguration severity isn't
part of the exit-code gate today (see [Known
limitations](#known-limitations--natural-next-steps)). `--list-only` (on
`ubel-domain`, `ubel-host`, and `ubel-easm`) always exits `0` on success,
independent of `--fail-on`, since it never reaches the vulnerability-lookup
stage the gate evaluates.

---

## Misconfiguration checks

All four entry points — `ubel-url`, `ubel-domain`, `ubel-host`, and
`ubel-easm` — run the same fixed set of misconfiguration probes against
every live host, in addition to the CVE lookup the rest of this document
describes — implemented in
[`lib/misconfig_scan.js`](./lib/misconfig_scan.js). This runs automatically
on every scan; there's currently no CLI flag to disable or retime it (see
[Known limitations](#known-limitations--natural-next-steps)).

Every HTTP-based check fetches one specific, well-known path with redirects
disabled (a redirect away from `/.env` means it isn't directly exposed,
which is the opposite of a finding). A single baseline request to a random,
guaranteed-nonexistent path is made per host first, so a target that returns
HTTP 200 for everything (a catch-all SPA route, for instance) can't be
misread as every probed path genuinely existing. The email-authentication
checks are the one exception to "HTTP-based" — they read DNS TXT records
instead; see **Email Security** below.

**Exposed File**
- `exposed-env-file` — a publicly readable `.env`. Cross-referenced against
  the same rule set `ubel-secrets` uses: `critical` if it matches a known
  credential pattern, `high` otherwise.
- `exposed-git-directory` — a publicly readable `.git/HEAD` (validated as an
  actual ref or commit hash, not just a 200 response), with a best-effort
  remote URL read from `.git/config` when available. Always `critical` — the
  entire repository history, including deleted branches, is typically
  reconstructable from this alone.
- `exposed-phpinfo` — `phpinfo()` output reachable at `/info.php` or
  `/phpinfo.php`, disclosing the PHP version, loaded extensions, and
  absolute server paths. `high`.

**WordPress** — only run on hosts the fingerprinter's own component
inventory already flagged as WordPress (`wp_kind` set on a detected
component); a WordPress install the fingerprinter didn't identify as such
won't get these two checks, even though every other check below still runs.
- `wp-xmlrpc-exposed` — `xmlrpc.php` reachable and responding as an XML-RPC
  server, usable for pingback-based DDoS amplification and for brute-forcing
  many password guesses in a single request. `medium`.
- `wp-user-enumeration` — `wp-json/wp/v2/users` publicly lists user
  accounts, disclosing usernames/slugs for targeted login brute-forcing.
  `medium`.

**TLS/SSL** — one raw TLS handshake to the host's HTTPS port (443, or the
target's own port when the resolved URL is already HTTPS) via Node's own
`tls` module — no external tool (nmap, testssl.sh, openssl CLI) and no
third-party TLS library.
- `tls-no-https` — no working TLS listener at all on an HTTP-only target.
  `medium`.
- `tls-broken` — the resolved URL is HTTPS, but the handshake itself fails —
  worse than no HTTPS, since clients try HTTPS first and hard-fail.
  `critical`.
- `tls-cert-expired` / `tls-cert-expiring-soon` — expired (`critical`), or
  expiring within 14 days (`high`) or 30 days (`medium`).
- `tls-cert-not-yet-valid` — the certificate's validity window hasn't
  started yet (usually clock skew). `medium`.
- `tls-cert-untrusted` — self-signed or otherwise fails chain verification.
  `high`.
- `tls-hostname-mismatch` — the certificate doesn't cover the hostname it's
  served on. `high`.
- `tls-weak-protocol-negotiated` — SSLv3/TLS 1.0 negotiated by default
  (`high`), or TLS 1.1 (`medium`).
- `tls-weak-cipher` — a legacy cipher (RC4, DES/3DES, export-grade,
  anonymous/NULL) negotiated by default. `medium`.
- `tls-legacy-protocol-supported` — the server still *accepts* an explicit
  TLS 1.0 (`high`) or TLS 1.1 (`medium`) request even when it doesn't
  negotiate one by default — a separate probe from the one above, since a
  downgrade attack would request the weak version explicitly rather than
  wait for it to be offered. A refused probe here isn't treated as proof of
  safety: it's equally consistent with the server correctly refusing and
  with this runtime's own OpenSSL build refusing to attempt the handshake at
  all — either way, nothing conclusive is reported for that specific outcome.

**Security Headers** — evaluated on one root-page fetch, over HTTPS when a
working listener was found (HSTS can only be observed over HTTPS; browsers
ignore it over plain HTTP) or HTTP otherwise.
- `missing-hsts` — no `Strict-Transport-Security` header on an HTTPS
  response, leaving an SSL-stripping window on the first request of every
  new session. `medium`.
- `hsts-disabled` — HSTS present but `max-age=0`, which actively tells
  browsers to discard any previously stored HSTS policy. `medium`.
- `hsts-short-max-age` — HSTS present with `max-age` below the ~6-month
  (15768000s) floor commonly recommended (and required for preload-list
  submission). `low`.
- `missing-clickjacking-protection` — neither a valid `X-Frame-Options`
  (`DENY`/`SAMEORIGIN`) nor a CSP `frame-ancestors` directive is set.
  `medium`.
- `weak-clickjacking-protection` — `X-Frame-Options` is set, but to a value
  modern browsers ignore (e.g. the deprecated `ALLOW-FROM`). `low`.
- `missing-csp` — no `Content-Security-Policy` header at all (independent of
  the frame-ancestors-specific clickjacking check above — a CSP present but
  missing only `frame-ancestors` is covered by that check, not re-flagged
  here). `low`.
- `missing-x-content-type-options` — no `X-Content-Type-Options` header, so
  browsers may MIME-sniff a response instead of trusting its declared
  content type. `low`.
- `invalid-x-content-type-options` — the header is set, but to something
  other than `nosniff`, the only value browsers act on. `low`.
- `missing-referrer-policy` — no `Referrer-Policy` header, so the browser's
  own (browser-dependent) default applies. `low`.
- `weak-referrer-policy` — `Referrer-Policy: unsafe-url`, which leaks the
  full referring URL — path and query string included — on every
  cross-origin request, even HTTPS→HTTP. `low`.
- `missing-permissions-policy` — no `Permissions-Policy` (or legacy
  `Feature-Policy`) header restricting powerful browser features (camera,
  microphone, geolocation, USB, payment, …). `low`.

**Cookies** — `Set-Cookie` attributes on the same root-page response the
header checks already fetched (no extra request), aggregated per host: a
site with ten cookies missing `HttpOnly` gets one finding naming all ten,
not ten.
- `cookie-missing-secure` — a cookie set on an HTTPS response lacks
  `Secure`, so it could still be sent over a plaintext downgrade. `medium`.
- `cookie-missing-httponly` — a cookie lacks `HttpOnly`, so client-side
  JavaScript (including an XSS payload) can read it. `medium` if the
  cookie's name looks session/auth-related (matches
  `/session|token|auth|jwt|\bsid\b|csrf/i`), `low` otherwise.
- `cookie-samesite-none-insecure` — `SameSite=None` set without `Secure`,
  which browsers reject outright but which signals the same
  not-really-configured cookie policy either way. `medium`.
- `cookie-missing-samesite` — no explicit `SameSite` attribute (browser
  defaults vary). `low`.

**HTTP Methods** — one `OPTIONS` request to the site root, plus a
non-destructive `TRACE` probe carrying a random marker header. `PUT`/
`DELETE` are read only from the `Allow` header and never actually sent —
see the note above `checkHttpMethods()` in the source for why.
- `risky-http-methods-allowed` — the `Allow` (or
  `Access-Control-Allow-Methods`) header advertises `PUT`, `DELETE`,
  `TRACE`, or `CONNECT` alongside the site's other supported methods.
  `high` if `PUT`/`DELETE` is among them, `medium` otherwise.
- `trace-method-enabled` — the server echoes a `TRACE` request back
  verbatim, including headers — the classic Cross-Site Tracing (XST)
  technique for reading otherwise-`HttpOnly` cookies via an XSS bug
  elsewhere on the site. `medium`.

**CORS** — the site root is requested with a fabricated, never-before-seen
`Origin` to distinguish "reflects any origin" from "has a real allowlist
that happens to include mine," then again with `Origin: null` (what
sandboxed iframes and `data:` URIs send).
- `cors-reflected-origin-with-credentials` — the fabricated origin is
  reflected back in `Access-Control-Allow-Origin` *and*
  `Access-Control-Allow-Credentials: true` is set — any other website can
  issue a credentialed cross-origin request here and read the response.
  `critical`.
- `cors-reflected-origin` — the same reflection, without credentials
  involved — still lets any site read non-credentialed responses
  cross-origin. `medium`.
- `cors-wildcard-with-credentials` — `Access-Control-Allow-Origin: *`
  combined with `Access-Control-Allow-Credentials: true`. Browsers reject
  this exact combination as invalid, but it signals a policy not built
  around a real allowlist, and some proxies rewrite `*` into a reflected
  origin, reintroducing the bypass. `medium`.
- `cors-null-origin-allowed` — `Access-Control-Allow-Origin: null` is set in
  response to `Origin: null`, allow-listing a value that untrusted sandboxed
  contexts send by design. `high`.

**Email Security** — the one set of checks here that reads DNS TXT records
instead of making an HTTP request; skipped entirely for a target that's a
bare IP address rather than a domain name. Implemented in
`checkSpf`/`checkDmarc`/`checkDkim` in `lib/misconfig_scan.js`.
- `email-spf-missing` — no `v=spf1` TXT record on the host's own name, so
  receivers have no way to verify a mail server claiming to send as this
  domain is actually authorized to. `medium`.
- `email-spf-multiple-records` — more than one `v=spf1` record published;
  RFC 7208 requires exactly one, and a receiver that finds more than one is
  required to treat SPF as a permanent error (i.e. ignore it). `medium`.
- `email-spf-permissive-all` — the SPF record ends in `+all`, explicitly
  authorizing *any* server on the internet to send mail as this domain and
  pass SPF. `high`.
- `email-dmarc-missing` — no TXT record at `_dmarc.<host>`. Without DMARC,
  nothing tells receivers what to do with mail that fails SPF/DKIM, and the
  domain gets no aggregate-report visibility into who's sending as it.
  `high`.
- `email-dmarc-multiple-records` — more than one `v=DMARC1` record at
  `_dmarc.<host>`; per RFC 7489 a domain must publish exactly one. `medium`.
- `email-dmarc-policy-none` — the DMARC policy is `p=none` (or the `p=` tag
  is missing, which defaults to `none`) — reports are generated, but
  nothing failing alignment is actually blocked or quarantined. `medium`.
- `email-dmarc-reduced-enforcement-pct` — an enforcing policy (`quarantine`/
  `reject`) is scoped to less than 100% of mail via `pct=`; the remainder is
  let through as if the policy were `none`. Normal while ramping up
  enforcement, a real gap if left there long-term. `low`.
- `email-dmarc-no-reports` — the DMARC record has no `rua=` aggregate-report
  address, so no one is notified which sources are sending mail as this
  domain or whether tightening the policy broke real mail flow. `low`.
- `email-dkim-not-found-common-selectors` — none of a short, curated list of
  commonly-used DKIM selectors (`default`, `google`, `selector1`/
  `selector2`, `k1`/`k2`, `pm`, `sendgrid`, `zoho`, `amazonses`, …) resolved
  a key under `<selector>._domainkey.<host>`. Deliberately **lower
  confidence** than the SPF/DMARC findings above: unlike SPF and DMARC,
  DKIM has no single well-known location — the selector is chosen by
  whoever configured outbound mail — so a miss here only rules out these
  specific selector names, not DKIM as a whole. `low`.

  These run per scanned host, the same granularity as every other check in
  this list — not deduplicated down to one call per organizational domain,
  since that would need public-suffix-list handling this module doesn't
  otherwise depend on. A finding on a subdomain that doesn't send mail
  directly (`www.example.com`, say) is real but lower-stakes: DMARC in
  particular is designed to be inherited from the organizational domain, so
  a missing record at a subdomain isn't necessarily actionable on its own —
  SPF, by contrast, is evaluated per-hostname by receivers regardless.

Findings are grouped by rule id in the report (not one row per host) — see
[Reports](#reports) — with a deduplicated "seen on" host list per rule, the
same shape Components/Vulnerabilities already use. A host contributes
entries to `misconfigurations_errors` (not a false "no findings") when a
probe fails outright — a timeout, a connection reset, an unparseable
response, or a real (non-"no record") DNS lookup failure — so a
clean-looking host and an unprobeable one are never conflated.

---

## Vulnerability data sources

These are the exact same env vars the SCA module already honors —
point them at an internal mirror or authenticated proxy for air-gapped
deployments or to get past NVD's public rate limit:

| Variable | Default | Used by |
|---|---|---|
| `UBEL_OSV_ENDPOINT` | `https://api.osv.dev` | all four |
| `UBEL_NVD_ENDPOINT` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | all four |
| `UBEL_WPVULNERABILITY_ENDPOINT` | `https://www.wpvulnerability.net` | all four |
| `UBEL_CRTSH_ENDPOINT` | `https://crt.sh` | `ubel-domain`, `ubel-easm` |

Whichever of these a run actually used is recorded in the report's Scan Info
tab and in the JSON payload, so a report always states where its findings
(and, for `ubel-domain`/`ubel-easm`, its target list) came from.

Most findings still come from NVD, since most fingerprinted components
(CMSes, admin panels, network services, ...) are identified by CPE
(vendor/product/version) with nothing resembling a registry package name to
build a purl from. OSV genuinely has coverage now, though: a handful of
scanners set a purl on top of their CPE for components they can name
precisely as a published package — see `component.purl` in
`fingerprint/src/scanners/js_dev_ecosystem/react.js` (and vuejs.js,
nextjs.js, gatsbyjs.js, nodered.js) and `buildPurlIds()` in
`fingerprint/src/core/componentId.js` for how that turns into a
`pkg:npm/...` id. Every id a component carries — CPE and purl alike — is
looked up independently (CPE ids against NVD, purl ids against OSV) and the
results are attributed back to the one inventory item that owns all of
those ids, so the same CVE surfacing via two different ids for what's
really one component shows up once, not twice; see "Known limitations"
below for the id-grouping details.

The one exception is WordPress: detected plugins, themes, and WordPress
core are routed to [wpvulnerability.net](https://www.wpvulnerability.net)
instead of NVD, not in addition to it. NVD's CPE dictionary rarely tracks
the wordpress.org slug the fingerprinter reads off the page, so CPE-based
NVD lookups miss most real plugin/theme CVEs; wpvulnerability.net is keyed
by exactly that slug (and by raw version for core), and its response is
filtered against the detected version and mapped into the same vuln shape
NVD/OSV findings use — same fix-version recommendation table, same
dedup/compliance handling, same report UI, just tagged `source:
"wpvulnerability"` in the report and filterable as such. See
`lib/wpvulnerability.js` for the mapping.

NVD's unauthenticated rate limit (~5 requests / 30s) is respected
internally with serial querying and backoff — a scan against many unique
components can take a while. Query time scales with the number of *unique*
product+version pairs across all targets, not the number of targets or
hosts (see [Features](#features) — de-duplication).

---

## Reports

All four CLIs follow the same reporting flow the SAST/malware scanners use:
the per-run timestamped copies are bundled into a **single `.zip`**, while
the always-current `latest.*` copies stay plain and unzipped so anything
watching them (a CI step, a dashboard, a browser tab left open on
`latest.*.html`) needs no unpacking step. Each of the four writes to its own
report family, named after the string each entry point passes to
`writeEasmReports()` in `lib/report_output.js` — which replaces the first
`-` in that string with `_` before building any path, so despite the
hyphenated labels used throughout this document and each CLI's own source
comments (`easm-url`, `easm-domain`, `easm-host`, `easm-full`), what
actually lands on disk uses an **underscore**:

`ubel-url` writes:

```
.ubel/reports/latest.easm_url.json     ← always current, unzipped
.ubel/reports/latest.easm_url.html     ← always current, unzipped

.ubel/local/reports/easm_url/<YYYY>/<MM>/<DD>/
    easm_url__<timestamp>.zip          ← contains report.json + report.html
```

`ubel-domain` writes the same, under its own `easm_domain` name:

```
.ubel/reports/latest.easm_domain.json
.ubel/reports/latest.easm_domain.html

.ubel/local/reports/easm_domain/<YYYY>/<MM>/<DD>/
    easm_domain__<timestamp>.zip
```

`ubel-host` writes under `easm_host`:

```
.ubel/reports/latest.easm_host.json
.ubel/reports/latest.easm_host.html

.ubel/local/reports/easm_host/<YYYY>/<MM>/<DD>/
    easm_host__<timestamp>.zip
```

`ubel-easm` writes under `easm_full` — not `easm_easm`: every sibling entry
point names its report family `easm_<word>` using a word that isn't the
module's own binary name, and `ubel-easm` keeps that convention instead of
doubling "easm", while still starting with `easm_` so all four report
families sort and namespace together on disk:

```
.ubel/reports/latest.easm_full.json
.ubel/reports/latest.easm_full.html

.ubel/local/reports/easm_full/<YYYY>/<MM>/<DD>/
    easm_full__<timestamp>.zip
```

They're kept separate so a domain-wide sweep, a port sweep, or a combined
run never overwrites another entry point's `latest` pointer — the four
answer different questions and you may want several on hand at once. The
payload format is identical across all four; a `ubel-domain` report
additionally carries `domain` (the root domain queried) and
`subdomain_endpoint`, with `targets` holding the discovered host list that
was actually fingerprinted. A `ubel-host` report additionally carries
`host`, `portRange`, and `openPorts` (the full scanned port list, not just
the HTTP(S)-speaking subset that became `targets`). A `ubel-easm` report
additionally carries `domain`, `subdomain_endpoint`, `hosts` (one entry per
distinct IP resolved and port-scanned — the plural counterpart to
`ubel-host`'s singular `host`/`portRange`/`openPorts`, each carrying its own
`resolvedFrom` hostname list, status, port range, and open/HTTP(S) port
lists), and `deadHostnames` (hostnames that never resolved to an IP).

Bundling keeps file count and storage down as runs accumulate — the same
reasoning (and the same `sca/zip_writer.js`) behind the SCA and SAST
bundles. Each piece only enters the bundle if it generated successfully: a
failed HTML render warns and still leaves a complete JSON report behind
rather than losing the whole run.

Every report also carries the same host/runtime provenance block the SAST
and SCA reports do — platform, arch, Node version, working directory, git
metadata, and OS metadata — surfaced in the Scan Info tab and stored in the
JSON. Both lookups are best-effort: a scan run outside a git checkout still
produces a complete report, just without that block.

JSON and HTML are the only output formats — no SBOM, no SARIF; see
[What this is, and isn't](#what-this-is-and-isnt) for why.

The HTML report is fully self-contained (no server required, no CDN calls
at view time — Tailwind/Chart.js/fonts are vendored the same way every
other UBEL report vendors them) and includes:

- A persistent authorized-use-only banner on every tab
- Dashboard with severity, component-state (safe/vulnerable/infected/
  undetermined), and per-host breakdown charts
- Searchable, filterable Components table (state + free-text search) with a
  per-component detail modal (every host/port it was seen on, its full CPE
  id, and every vulnerability that affects it)
- Searchable, filterable Vulnerabilities table (severity + source +
  free-text search) with a per-vulnerability detail modal (CVSS
  score/vector, description, fix-version recommendation, references,
  aliases, IOC table for the rare infection-flagged entry, and compliance
  framework mapping)
- **Secrets tab** — every credential found in the JavaScript the target
  serves, with its URL, line:column, source (inline block vs `.js` file),
  and a redacted preview; filterable by severity, source and free text,
  with a per-finding modal listing every page that referenced a shared
  script. A "not scanned" panel lists URLs that couldn't be fetched, so an
  empty result is never mistaken for a clean one
- **Misconfigurations tab** — findings from
  [Misconfiguration checks](#misconfiguration-checks), one row per rule id
  (e.g. `missing-hsts`, `exposed-git-directory`) rather than one per
  occurrence — each row shows severity, category (Exposed File / WordPress /
  TLS-SSL / Security Headers), and how many distinct hosts it was seen on.
  Filterable by severity, category, and free text; a per-finding modal lists
  every occurrence (host, URL, description, evidence, remediation). An
  errors panel lists probes that couldn't complete, same pattern as Secrets'
  "not scanned" panel
- Dedicated Compliance tab — one card per framework, same shape as every
  other UBEL module's compliance tab
- **Detailed Stats tab**, same idea as the SAST/SCA reports': target
  reachability (resolved vs dead vs scanned/skipped/errored), component
  counts broken out by state, low-confidence version, WordPress, purl and
  multi-id coverage, vulnerability counts by severity and fix availability,
  charts for findings-by-data-source and components-by-type, exposed-secret
  counts by severity with crawl coverage (pages, inline blocks, external
  scripts), misconfiguration counts (distinct rules and total occurrences,
  hosts checked/affected, hosts checked for the WordPress-only checks) with
  charts by severity and by category plus a per-host occurrence ranking, the
  full dead host list, and a busiest-hosts ranking by component count
- Scan Info tab: the full responsible-use notice, tool version,
  generated-at timestamp, `--allow-private`/endpoint configuration used for
  the run, host/runtime provenance (platform, arch, Node version), a
  resolved-vs-dead summary, and a per-target status list (scanned / skipped
  / error / **dead**, with the resolved IP, resolved URL and component
  count for each)

The JSON report is the full machine-readable equivalent — `stats` (including
`stats.resolution` with the dead-host list and `stats.misconfigurations`),
`compliance_summary`, `usage_notice`, `assets` (per-target status, resolved
IP), the complete `inventory` (fingerprinted components), the complete
`vulnerabilities` array, `secrets` / `secrets_errors` (exposed credentials
with URL and position), and `misconfigurations` / `misconfigurations_errors`
(one entry per rule id, each carrying its own occurrence list) — and can be
consumed by CI/CD tooling directly.

---

## Programmatic API

`easm/index.js` (`ubel-url`), `easm/domain.js` (`ubel-domain`),
`easm/host.js` (`ubel-host`), and `easm/easm.js` (`ubel-easm`) each export
`main` and `parseArgs` for scripting or CI wrappers that need argv control
beyond what the binaries expose:

```js
import { main } from "../easm/index.js";   // relative path within the ubel-node package tree

process.argv = ['node', 'ubel-url', 'example.com', '--fail-on', 'high'];
await main();
```

```js
import { main } from "../easm/domain.js";

process.argv = ['node', 'ubel-domain', 'example.com', '--fail-on', 'high'];
await main();
```

```js
import { main } from "../easm/host.js";

process.argv = ['node', 'ubel-host', 'example.com', '--ports', '1-1024', '--fail-on', 'high'];
await main();
```

```js
import { main } from "../easm/easm.js";

process.argv = ['node', 'ubel-easm', 'example.com', '--subdomain-ports', 'default', '--fail-on', 'high'];
await main();
```

`easm/easm.js` additionally exports `discoverIps` (domain → `{ip: [hostnames]}`
grouping, the crt.sh-discovery-plus-DNS-resolution step) and `buildTargets`
(per-IP port-scan results → the merged `ipTargets`/`hostnameTargets` list
`scanTargets()` is handed), for callers that want `ubel-easm`'s discovery
logic without going through its own argv parser.

For finer-grained programmatic use — driving the scan without going through
argv at all — `easm/lib/scan.js` exports `scanTargets(targets, opts)`
directly, and `easm/lib/html_report.js` exports `buildReportPayload` and
`generateHtmlReport` for building/rendering a report from that result:

```js
import { scanTargets } from "../easm/lib/scan.js";
import { buildReportPayload, generateHtmlReport } from "../easm/lib/html_report.js";

const result = await scanTargets(["example.com"], { allowPrivate: false });
const payload = buildReportPayload(result, { tool_version: "0.13.1", targets: ["example.com"] });
const html = await generateHtmlReport(payload);
```

Subdomain discovery is available on its own via `easm/lib/crtsh.js`, whose
two exports split cleanly along the network boundary — `queryCrtSh(domain)`
does the fetching, `extractSubdomains(entries, domain)` is a pure function
over the response, so the filtering/deduplication logic can be tested or
reused against a cached CT dump with no network involved:

```js
import { queryCrtSh, extractSubdomains } from "../easm/lib/crtsh.js";
import { discoverTargets } from "../easm/domain.js";   // adds --include/--exclude merging

const hosts = extractSubdomains(await queryCrtSh("example.com"), "example.com");
```

DNS resolution is likewise available standalone via `easm/lib/resolve.js` —
`resolveTargets(targets)` returns `{ alive, dead, byTarget }`, and
`hostnameOf(target)` pulls the bare hostname out of any accepted target form
(bare domain, `host:port`, full URL):

```js
import { resolveTargets } from "../easm/lib/resolve.js";

const { alive, dead } = await resolveTargets(hosts);
```

The port-scan/HTTP(S)-discovery pair `ubel-host` and `ubel-easm` both use is
likewise available standalone via `easm/lib/portscan.js` —
`scanPorts(host, {from, to}, opts)` runs the raw TCP connect scan
(`opts.concurrency` default 500, `opts.timeout` ms default 1500) and
`probeHttpPorts(host, openPorts, opts)` filters an open-port list down to
the HTTP(S)-speaking subset (`opts.concurrency` default 20, `opts.timeout`
ms default 5000); neither ever throws for an individual port — a closed,
filtered, or timed-out port is simply absent from the returned list:

```js
import { scanPorts, probeHttpPorts } from "../easm/lib/portscan.js";

const openPorts = await scanPorts("example.com", { from: 1, to: 1024 }, { concurrency: 200 });
const httpPorts = await probeHttpPorts("example.com", openPorts);
```

[Misconfiguration checks](#misconfiguration-checks) are available on their
own via `easm/lib/misconfig_scan.js`'s `scanMisconfigurations(assets,
inventory, opts)` — `assets` and `inventory` are the shapes `scanTargets()`
already returns (only `assets` entries with `status: "scanned"` are probed;
`inventory` is used solely to gate the WordPress-only checks on hosts whose
inventory carries a `wp_kind`), and `opts` accepts `concurrency`, `timeout`
(seconds per probe, default 8), and `log`:

```js
import { scanMisconfigurations } from "../easm/lib/misconfig_scan.js";

const { findings, errors, stats } = await scanMisconfigurations(assets, inventory, { timeout: 8 });
```

This is also the only way to skip or retime the misconfiguration checks
today — `scanTargets()`'s own `scanMisconfigs`/`misconfigTimeout` options
(see [Misconfiguration checks](#misconfiguration-checks)) aren't wired up to
any of the four CLIs' argv parsers yet.

Like `ubel-cloud`, none of this is yet wired into `package.json`'s `exports`
map (only `./sca` and `./sast` are) — reachable via a relative import within
the installed package's own file tree, or by invoking the `ubel-url` /
`ubel-domain` / `ubel-host` / `ubel-easm` binaries directly, which is the
supported path for CI and scripting alike.

---

## CI/CD Integration

All four EASM CLIs exit non-zero on vulnerabilities that clear the
configured `--fail-on` bar, making them native to any CI runner — **only
against infrastructure the pipeline itself owns/deploys**, e.g. a
post-deploy check against your own staging or production environment right
after a release:

```yaml
# GitHub Actions — post-deploy check against infrastructure this pipeline owns
- name: UBEL external attack surface scan
  run: ubel-url staging.our-own-domain.example --fail-on high

- name: UBEL domain-wide attack surface sweep (discovers subdomains first)
  run: ubel-domain our-own-domain.example --fail-on high

- name: UBEL port-scan + fingerprint one host
  run: ubel-host staging.our-own-domain.example --ports 1-1024 --fail-on high

- name: UBEL combined discovery + per-IP port sweep
  run: ubel-easm our-own-domain.example --subdomain-ports default --fail-on high
```

```dockerfile
# Dockerfile
RUN ubel-url our-own-domain.example --fail-on high
```

Nothing is written to disk beyond the report itself, and no credentials are
involved — there's nothing extra to clean up in a CI job or container layer.

`ubel-host` and `ubel-easm` are heavier CI citizens than `ubel-url`/
`ubel-domain`: a default `--ports 1-30000` connect scan (per host for
`ubel-host`, per distinct IP for `ubel-easm`) takes materially longer than
a single fingerprint request and can trip a runner's own outbound
connection-rate limits or a target-side IDS/port-scan alert — narrow
`--ports` to the range you actually care about (e.g. `1-1024` for
well-known services, or a short explicit web-port list) for a routine CI
gate, and reserve a full `1-65535` sweep for a scheduled, off-peak job
rather than every push.

---

## Known limitations / natural next steps

- Fingerprinting itself is entirely passive/banner-based (headers, page
  markup, a small fixed list of well-known paths) — a hardened target that
  suppresses version banners (custom `Server` header, stripped
  `X-Powered-By`) will under-report, not over-report; absence of a finding
  is not proof of absence of a vulnerability (also called out in the
  report's usage notice). The one exception is `ubel-host`/`ubel-easm`'s
  port-scan stage ahead of fingerprinting, which is a live TCP connect
  scan, not passive — see [What this is, and
  isn't](#what-this-is-and-isnt).
- The secrets crawl is one level deep: it fetches each live host's root
  document and the scripts that document references, and does not follow
  links, enumerate routes, or execute JavaScript. A credential that only
  appears in a lazily-imported chunk on some inner route, or that is
  injected at runtime, won't be found — and scripts that fail to fetch or
  exceed the size cap are listed in the report's "not scanned" panel rather
  than silently skipped. Findings are rule-based (the same
  `sca/secrets.js` rules `ubel-secrets` uses), so a value that merely looks
  like a credential can be a false positive; verify before rotating
  anything production-critical.
- `ubel-domain`'s and `ubel-easm`'s subdomain discovery is likewise passive:
  Certificate Transparency logs (crt.sh) and nothing else. A host with no
  logged certificate — internal-only, HTTP-only, or behind a CA that
  doesn't log to CT — won't be discovered, so an empty or short result is
  evidence about the CT record, not about what's actually deployed.
  `--include` covers known-but-undiscovered hosts by hand; DNS
  brute-forcing and alternate passive sources (Shodan InternetDB, other CT
  aggregators) are natural next steps but deliberately not here yet. CT
  logs are also append-only history rather than current state, so a
  long-decommissioned subdomain still appears in the discovered list —
  those are caught by the DNS pre-resolution step and reported as `dead`
  (`ubel-domain`) or excluded from `discovery.ips` with an entry in
  `deadHostnames` (`ubel-easm`) rather than probed, but they do still count
  toward the discovered total.
- A component whose disclosed version is under-specified (most commonly a
  bare major version, e.g. a target that only advertises `Python 3` rather
  than `Python 3.11.4`) is **not** queried against OSV/NVD — it's still
  listed in the Components tab with a "low-confidence" badge and
  `state: "undetermined"`, but no vulnerability lookup is attempted for it
  (see `isVersionSpecificEnough()` in `lib/scan.js`). This is deliberate:
  NVD's CPE range matching treats an under-specified version as sitting at
  the very start of that major line, which then satisfies almost every
  historical version-range recorded for the product — in practice this
  means a bare "3" for Python can match the *entire* multi-year CVE history
  across every maintained 3.x branch at once, with "fix" recommendations
  that list every branch's fix version because there's no way to tell which
  one applies. That's real NVD data, technically accurate and completely
  unactionable, so it's suppressed rather than shown as if it were as
  precise as, say, the SCA module's lockfile-derived findings.
- A detected component with multiple CPE vendor/product aliases (see
  `fingerprint/src/core/componentId.js`'s `buildCpeIds`), or with both a CPE
  and a purl (set by a handful of scanners that can name an exact registry
  package — see the next bullet), is one inventory row, not several: every
  id is queried independently (each alias genuinely can have a different
  CVE match set against NVD, and a purl is queried against OSV rather than
  NVD at all), but the results are attributed back to the single item that
  owns all of those ids and deduplicated there — so the same CVE surfacing
  via two aliases, or via both a CPE and a purl, is shown once. Grouping key
  is name+version (see `buildInventoryKey()` in `lib/scan.js`), not any one
  id, precisely so this holds regardless of how many ids an item carries.
- Purl support is opt-in per scanner, not derived automatically: most
  fingerprinted components (CMSes, admin panels, network services, ...)
  have no registry package to name and stay CPE-only, which is unaffected.
  A handful of `fingerprint/src/scanners/js_dev_ecosystem/*.js` scanners
  (React, Vue, Next.js, Gatsby, Node-RED at the time of writing) set
  `component.purl` because they detect an individually-versioned,
  registry-published package by name off the page itself — see
  `buildPurlIds()` in `componentId.js` for the format and why it's opt-in
  rather than guessed at for every scanner.
- No historical diffing between scan runs yet — each run is a fresh,
  point-in-time snapshot, same as `ubel-cloud`.
- No `--proxy` support — the vendored fingerprinting engine deliberately
  dropped the original tool's proxy plumbing (see
  [`fingerprint/NOTICE.md`](./fingerprint/NOTICE.md)) since it wasn't
  fingerprinting logic; reintroducing it for engagements that need to route
  through a specific egress point is a reasonable follow-up.
- No authenticated/credentialed scanning mode — everything is unauthenticated
  GETs by design (see [What this is, and isn't](#what-this-is-and-isnt)).
- [Misconfiguration checks](#misconfiguration-checks) run unconditionally on
  every scan. `scanTargets()` already accepts `scanMisconfigs`/
  `misconfigTimeout` options to disable or retime them, but — unlike
  `--no-secrets` for the client-side crawl — none of the four CLIs
  (`ubel-url`, `ubel-domain`, `ubel-host`, `ubel-easm`) expose a flag for
  either one yet; skipping or retiming them today means calling
  `scanTargets()` (or `scanMisconfigurations()` directly) programmatically
  instead of through the binaries.
- `--fail-on` only gates on vulnerabilities/infections, not on
  misconfiguration findings — a scan that turns up only critical
  misconfigurations (an exposed `.git` directory, say) with no matching
  vulnerability still exits `0`. The findings are still written to every
  report regardless; there's just no CI gate on them yet, unlike
  `ubel-cloud`'s misconfiguration checks.
- The console summary (`printScanSummary`, what prints to the terminal at
  the end of a run) reports vulnerability and secrets counts but not
  misconfiguration counts — nothing about them appears in stdout today; the
  HTML report's Misconfigurations tab or the JSON report's
  `misconfigurations`/`stats.misconfigurations` are the only places to see
  them short of `--verbose`'s per-host log line.
- The WordPress-gated checks (`wp-xmlrpc-exposed`, `wp-user-enumeration`)
  only run on hosts the fingerprinter's own inventory already identified as
  WordPress. A WordPress install the fingerprinter fails to recognize (e.g.
  a heavily customized theme that strips every usual marker) won't get
  those two checks, even though the ungated ones (exposed files, TLS,
  headers) still run against it like any other host.
- Every misconfiguration check probes exactly one well-known path (or, for
  TLS, one handshake; for email authentication, a short fixed list of DNS
  names) per host — the same fixed-list, no-wordlist posture as the rest of
  this module. A non-default `.env` location, a `.git` directory served from
  somewhere other than the web root, or any issue outside the fixed rule
  list in [Misconfiguration checks](#misconfiguration-checks) simply isn't
  checked for.
- The DKIM check (`email-dkim-not-found-common-selectors`) only queries a
  short, curated list of commonly-used selector names — it can positively
  confirm DKIM is configured under one of them, but a miss across the whole
  list is not proof DKIM is absent, only that it isn't published under any
  of these specific names. It's reported at lower severity than the SPF/
  DMARC findings for exactly this reason; see the note in
  [Misconfiguration checks](#misconfiguration-checks).
- SPF/DMARC/DKIM are checked per scanned host, not deduplicated to one check
  per organizational/registrable domain — that would need public-suffix-list
  handling this module doesn't otherwise carry. `ubel-domain`/`ubel-easm`
  sweeping a domain with many non-mail-sending subdomains (`www.`, `api.`,
  `cdn.`, …) will report the same SPF/DMARC gap once per such host rather
  than once for the domain as a whole.
- The port scan `ubel-host`/`ubel-easm` run is TCP-connect-only — no SYN/
  stealth scanning, no UDP. A UDP-only service (DNS, many game/VoIP
  protocols) is invisible to it regardless of `--ports`, and connect
  scanning is both noisier (a full three-way handshake per port, logged by
  most firewalls/IDS as a completed connection rather than a half-open
  probe) and slower than a raw SYN scan would be.
- The default `--ports` range is `1-30000`, not the full `1-65535` — a
  service listening above 30000 (common for some databases, message
  queues, and dev servers run on a high port) is silently out of scope
  unless `--ports` is widened explicitly.
- No scan-side rate limiting or backoff on the port-scan stage itself
  (`--port-concurrency`/`--http-concurrency` cap parallelism but don't
  pace requests over time) — unlike the NVD lookup stage, which already
  respects NVD's own published rate limit. A target's own IDS/WAF may
  still throttle or block a wide, fast scan mid-run; a port that stops
  responding partway through is simply reported as not open, with no
  distinction from a port that was never open at all.
- `ubel-easm`'s by-name subdomain targets (`--subdomain-ports`) resolve DNS
  again, independently, at fingerprinting time — the port scan itself
  worked from the IP resolved during discovery. On a hostname with several
  A/AAAA records (round-robin DNS, some CDN/load-balancer setups), the
  fingerprint request can land on a different IP than the one that was
  actually port-scanned, so the by-name finding and the by-IP finding for
  "the same" subdomain aren't guaranteed to describe the identical backend.
- In `ubel-easm`, a port-scan failure on one distinct IP (a network error,
  not a guard skip) is recorded as that IP's `status: "error"` and
  contributes no targets, but does not abort the run — the report's `hosts`
  array shows exactly which IPs errored and why (`skipReason`), so a
  partial run is distinguishable from a clean one, not silently merged into
  it.

---

## Quick-start examples

```bash
# One-off check of a domain you own
ubel-url app.your-company.example

# Post-deploy CI gate against your own staging environment
ubel-url staging.your-company.example --fail-on high --quiet

# A batch of internal assets from an inventory file, tolerating a known baseline
ubel-url --targets-file internal-assets.txt --fail-on 10:high

# A local dev/staging box, safety guard disabled since it's yours
ubel-url localhost:3000 --allow-private --verbose

# See what a domain-wide sweep WOULD touch, without touching anything
ubel-domain your-company.example --list-only

# Full sweep of a domain you own: discover every subdomain, scan them all
ubel-domain your-company.example --verbose

# Same, minus a host you don't want touched, plus one CT never logged
ubel-domain your-company.example \
  --exclude legacy.your-company.example \
  --include internal-only.your-company.example

# Scheduled attack-surface review, failing only on critical findings
ubel-domain your-company.example --fail-on critical --quiet

# See what ports are open on a host you own, without fingerprinting anything
ubel-host app.your-company.example --list-only

# Port-scan and fingerprint a host you own, well-known ports only
ubel-host app.your-company.example --ports 1-1024 --fail-on high

# Full 1-65535 sweep of a host you own, gentler connect-scan pace
ubel-host app.your-company.example --ports 1-65535 --port-concurrency 100 --verbose

# A local dev/staging box, safety guard disabled since it's yours
ubel-host localhost --allow-private --ports 1-10000

# Review the IP grouping a combined sweep would touch, before authorizing it
ubel-easm your-company.example --list-only

# Combined discovery + per-IP port sweep of a domain you own
ubel-easm your-company.example --fail-on high --quiet

# Same, but drop a shared/CDN IP identified via --list-only, and a host you don't own
ubel-easm your-company.example \
  --exclude legacy.your-company.example \
  --exclude-ip 198.51.100.7

# IP:port targets only — skip the by-name subdomain fingerprint pass
ubel-easm your-company.example --subdomain-ports none

# Narrower port range, one IP at a time, for a slow/sensitive network
ubel-easm your-company.example --ports 1-1024 --ip-concurrency 1
```