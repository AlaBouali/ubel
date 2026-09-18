# UBEL — Unified Bill / Enforced Law
### EASM — External Attack Surface Fingerprinting (`ubel-url`, `ubel-domain`)

> ## ⚠ Authorized use only
> `ubel-url` sends live, unauthenticated HTTP(S) requests to every target you
> give it, then discloses what it fingerprints (product/version banners) to
> OSV.dev and/or NVD to look up known vulnerabilities. `ubel-domain` does the
> same, but **discovers its own target list** from Certificate Transparency
> logs first — meaning it can end up scanning hosts you didn't explicitly
> name and may not have expected to exist. **Only ever run either against
> infrastructure you own, or have explicit, documented authorization
> to test** — the same rule UBEL's own license already holds every module to
> (see [`../LICENSE.md`](../LICENSE.md), "Internal Use Only"). Scanning a
> system you don't own or lack authorization for can violate computer-fraud
> laws (e.g. the CFAA), the target's terms of service, and/or applicable
> regulations, regardless of intent — this applies whether the target is a
> third party's infrastructure or a system inside your own organization that
> you personally aren't authorized to test. UBEL and its authors accept no
> liability for misuse. This warning is repeated in the CLI's `--help` output,
> printed before every scan, embedded in every JSON report (`usage_notice`),
> and shown as a persistent banner on every tab of the HTML report — it isn't
> something you can accidentally miss or scan past.
>
> For `ubel-domain` specifically, `--list-only` discovers and prints the
> target list **without sending a single request to any of those hosts** —
> use it to review (and trim with `--exclude`) what a sweep would touch
> before you authorize it.

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

This document covers the **EASM module** (`ubel-url` and `ubel-domain`), two
of the CLIs shipped in the `@arcane-spark/ubel-node` package alongside the
SCA/firewall CLI ([../sca/README.md](../sca/README.md)), the AI-powered
SAST/malware scanner ([../sast/README.md](../sast/README.md)), and the cloud
misconfiguration scanner ([../cloud/README.md](../cloud/README.md)).

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
verify, not a confirmed compromise.

Alongside that CVE lookup, every scan also runs a small, fixed set of
**misconfiguration checks** against each live host — exposed `.env`/`.git`,
WordPress-specific probes, TLS/certificate weaknesses, and missing security
headers — see [Misconfiguration checks](#misconfiguration-checks) below.
These stay within the same posture as everything else here: a single
well-known path per HTTP check (or one TLS handshake), no exploitation, no
brute-forcing. It's a second, independent finding type layered on the same
passive scan, not a change to what the module does or how it behaves.

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
- **Subdomain discovery** (`ubel-domain`) — give it a root domain and it
  enumerates every subdomain with a logged certificate via crt.sh, then
  scans all of them in one run; `--list-only` prints the scope without
  touching a single discovered host
- De-duplicated vulnerability lookups — the same product+version detected on
  many hosts is one NVD query, not one per host; every affected host is
  still listed per finding. Inventory is grouped by name+version, so a
  domain-wide sweep that finds the same nginx on forty subdomains yields one
  component row carrying a forty-host list, not forty duplicate rows
- Reuses `../sca/engine.js`'s exact OSV.dev + NVD query, CVSS-parsing, and
  fix-version-recommendation logic — not a reimplementation, the same code
  path the SCA module's host/platform CPE-based scanning already uses
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
  acceptance, or no working HTTPS listener at all) and missing/weak HTTP
  security headers (HSTS presence and `max-age`, clickjacking protection via
  `X-Frame-Options`/CSP `frame-ancestors`). Runs automatically on every
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

This installs `ubel-url` and `ubel-domain` alongside every other UBEL
binary. There's no separate package to install — EASM ships as part of
`@arcane-spark/ubel-node`.

---

## Requirements

- Node.js `>=18.0.0`
- Outbound network access to: the target(s) you're scanning — HTTP(S)
  requests for fingerprinting/misconfiguration checks, plus a raw TLS
  handshake to port 443 for the certificate/protocol checks (see
  [Misconfiguration checks](#misconfiguration-checks)) — `api.osv.dev`,
  `services.nvd.nist.gov`, and `www.wpvulnerability.net` (plus `crt.sh` for
  `ubel-domain`) — or your own internal mirrors, see
  [Vulnerability data sources](#vulnerability-data-sources)
- No credentials of any kind — this doesn't authenticate to anything

---

## Safety guard

By default, before probing anything, each target's IP is resolved and
checked against private/RFC1918 ranges and the scanning host's own public
IP. A match is **skipped, not scanned** — reported in the JSON/HTML Scan Info
tab with a `"skipped"` status and a reason, never silently dropped from the
target list, so a report never reads as "clean" for a target that was
actually never probed.

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
on a fatal/unexpected error (including `ubel-domain` finding no hosts).
`--fail-on` gates only on **vulnerabilities** (and infections) — a scan that
finds nothing but critical misconfigurations still exits `0`; misconfiguration
severity isn't part of the exit-code gate today (see [Known
limitations](#known-limitations--natural-next-steps)).

---

## Misconfiguration checks

Both `ubel-url` and `ubel-domain` run the same fixed set of misconfiguration
probes against every live host, in addition to the CVE lookup the rest of
this document describes — implemented in
[`lib/misconfig_scan.js`](./lib/misconfig_scan.js). This runs automatically
on every scan; there's currently no CLI flag to disable or retime it (see
[Known limitations](#known-limitations--natural-next-steps)).

Every check fetches one specific, well-known path with redirects disabled
(a redirect away from `/.env` means it isn't directly exposed, which is the
opposite of a finding). A single baseline request to a random, guaranteed-
nonexistent path is made per host first, so a target that returns HTTP 200
for everything (a catch-all SPA route, for instance) can't be misread as
every probed path genuinely existing.

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

Findings are grouped by rule id in the report (not one row per host) — see
[Reports](#reports) — with a deduplicated "seen on" host list per rule, the
same shape Components/Vulnerabilities already use. A host contributes
entries to `misconfigurations_errors` (not a false "no findings") when a
probe fails outright — a timeout, a connection reset, an unparseable
response — so a clean-looking host and an unprobeable one are never
conflated.

---

## Vulnerability data sources

Both endpoints are the exact same env vars the SCA module already honors —
point them at an internal mirror or authenticated proxy for air-gapped
deployments or to get past NVD's public rate limit:

| Variable | Default | Used by |
|---|---|---|
| `UBEL_OSV_ENDPOINT` | `https://api.osv.dev` | both |
| `UBEL_NVD_ENDPOINT` | `https://services.nvd.nist.gov/rest/json/cves/2.0` | both |
| `UBEL_WPVULNERABILITY_ENDPOINT` | `https://www.wpvulnerability.net` | both |
| `UBEL_CRTSH_ENDPOINT` | `https://crt.sh` | `ubel-domain` only |

Whichever of these a run actually used is recorded in the report's Scan Info
tab and in the JSON payload, so a report always states where its findings
(and, for `ubel-domain`, its target list) came from.

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

Both CLIs follow the same reporting flow the SAST/malware scanners use: the
per-run timestamped copies are bundled into a **single `.zip`**, while the
always-current `latest.*` copies stay plain and unzipped so anything
watching them (a CI step, a dashboard, a browser tab left open on
`latest.*.html`) needs no unpacking step.

`ubel-url` writes:

```
.ubel/reports/latest.easm.json     ← always current, unzipped
.ubel/reports/latest.easm.html     ← always current, unzipped

.ubel/local/reports/easm/<YYYY>/<MM>/<DD>/
    easm__<timestamp>.zip          ← contains report.json + report.html
```

`ubel-domain` writes the same, under its own `easm-domain` name:

```
.ubel/reports/latest.easm-domain.json
.ubel/reports/latest.easm-domain.html

.ubel/local/reports/easm-domain/<YYYY>/<MM>/<DD>/
    easm-domain__<timestamp>.zip
```

They're kept separate so a domain-wide sweep never overwrites a targeted
scan's `latest` pointer, or vice versa — the two answer different questions
and you'll usually want both on hand. The payload format is identical; a
`ubel-domain` report additionally carries `domain` (the root domain queried)
and `subdomain_endpoint`, with `targets` holding the discovered host list
that was actually fingerprinted.

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

`easm/index.js` (`ubel-url`) and `easm/domain.js` (`ubel-domain`) each
export `main` and `parseArgs` for scripting or CI wrappers that need argv
control beyond what the binaries expose:

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
either CLI's argv parser yet.

Like `ubel-cloud`, none of this is yet wired into `package.json`'s `exports`
map (only `./sca` and `./sast` are) — reachable via a relative import within
the installed package's own file tree, or by invoking the `ubel-url` /
`ubel-domain` binaries directly, which is the supported path for CI and
scripting alike.

---

## CI/CD Integration

`ubel-url` exits non-zero on vulnerabilities that clear the configured
`--fail-on` bar, making it native to any CI runner — **only against
infrastructure the pipeline itself owns/deploys**, e.g. a post-deploy check
against your own staging or production environment right after a release:

```yaml
# GitHub Actions — post-deploy check against infrastructure this pipeline owns
- name: UBEL external attack surface scan
  run: ubel-url staging.our-own-domain.example --fail-on high
```

```dockerfile
# Dockerfile
RUN ubel-url our-own-domain.example --fail-on high
```

Nothing is written to disk beyond the report itself, and no credentials are
involved — there's nothing extra to clean up in a CI job or container layer.

---

## Known limitations / natural next steps

- Detection is entirely passive/banner-based (headers, page markup, a small
  fixed list of well-known paths) — a hardened target that suppresses
  version banners (custom `Server` header, stripped `X-Powered-By`) will
  under-report, not over-report; absence of a finding is not proof of
  absence of a vulnerability (also called out in the report's usage notice).
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
- `ubel-domain`'s subdomain discovery is likewise passive: Certificate
  Transparency logs (crt.sh) and nothing else. A host with no logged
  certificate — internal-only, HTTP-only, or behind a CA that doesn't log
  to CT — won't be discovered, so an empty or short result is evidence
  about the CT record, not about what's actually deployed. `--include`
  covers known-but-undiscovered hosts by hand; DNS brute-forcing and
  alternate passive sources (Shodan InternetDB, other CT aggregators) are
  natural next steps but deliberately not here yet. CT logs are also
  append-only history rather than current state, so a long-decommissioned
  subdomain still appears in the discovered list — those are caught by the
  DNS pre-resolution step and reported as `dead` rather than probed, but
  they do still count toward the discovered total.
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
  `--no-secrets` for the client-side crawl — neither `ubel-url` nor
  `ubel-domain`'s CLI exposes a flag for either one yet; skipping or
  retiming them today means calling `scanTargets()` (or
  `scanMisconfigurations()` directly) programmatically instead of through
  the binaries.
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
  TLS, one handshake) per host — the same fixed-list, no-wordlist posture as
  the rest of this module. A non-default `.env` location, a `.git` directory
  served from somewhere other than the web root, or any issue outside the
  fixed rule list in [Misconfiguration checks](#misconfiguration-checks)
  simply isn't checked for.

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
```