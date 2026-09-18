easm/fingerprint — vendored detection engine
================================================================================

Vendoring note
================================================================================

Everything under `src/` in this directory is vendored as-is from a
stdlib-only, zero-dependency Node.js port of a Python service/CMS/framework
fingerprinting toolkit (see `README.md` in this directory for the original
component documentation, kept intact). It's consumed by `easm/lib/scan.js`
purely as a detection engine — it returns `{Ids, Name, Version, Host, Port}`
records (CPE 2.3 candidate ids), nothing more. It has no knowledge of OSV,
NVD, or vulnerability data at all; that lookup happens entirely in
`../../sca/engine.js` (see `../README.md`).

By the port's own README, the following were intentionally left out when it
was created, and remain out here:

  - Proxy / raw-socket plumbing (every scanner makes a normal HTTP(S)
    request — nothing routes through SOCKS4/5 or hand-rolled sockets).
  - `cms/wp.py`'s original vulnerability-lookup and exploitation code
    (third-party CVE-feed queries, XML-RPC/login brute force, an XML-RPC
    pingback SSRF, user enumeration) — only the passive
    version/theme/plugin-identification logic was ported.

Nothing in this directory performs authentication attempts, exploitation,
brute forcing, or denial-of-service — it issues plain, unauthenticated
HTTP(S) GET requests to a small, fixed list of well-known paths (health
endpoints, `/version`, `/graphql`, common admin/login pages, etc. — see
`src/core/webApplicationScanner.js`) and reads whatever the server hands
back (headers, banners, page markup) to guess product/version. Scanning any
target you do not own or have explicit authorization to test is your
responsibility, not this code's — see the warning in `../README.md`.

`DomainScanner.scan()` also carries its own safety default: it resolves the
target's IP first and silently skips scanning (returns no components)
against private/RFC1918 addresses and against the scanning host's own
public IP, unless the caller explicitly opts out (`skipVerification` /
`ubel-url`'s `--allow-private`) for lab/localhost targets. `easm/lib/scan.js`
surfaces that as a per-target `skipped` status rather than silently dropping
it, so a report never looks like "0 findings, all clear" when a target was
actually never scanned.
