# fingerprint-scanners (vendored)

> This directory is vendored, as-is, into UBEL as the detection engine behind
> `ubel-url` / the EASM module — see [`../README.md`](../README.md) for how
> it's wired up (OSV/NVD scanning, reporting, CLI usage, and the responsible-
> use requirements that apply to it) and [`NOTICE.md`](./NOTICE.md) for
> provenance. Everything below is the original component README, kept intact
> for reference.

A pure Node.js (ESM, stdlib-only, zero npm dependencies) port of a Python
service/CMS/framework fingerprinting toolkit. No proxying, no raw sockets -
every scanner talks plain HTTP(S) via Node's built-in `http`/`https` modules.

## Install / use

```js
import { DomainScanner } from "./src/index.js";

const [result] = await DomainScanner.scan("example.com");
console.log(result.components);
// [
//   { Ids: ["cpe:2.3:a:nginx:nginx:1.25.3:*:*:*:*:*:*:*"], Name: "Nginx", Version: "1.25.3", Host: "example.com", Port: 443 },
//   ...
// ]
```

`DomainScanner.scan(domain, skipVerification = false)` is the main entry
point (a direct port of `domain_scanner.py`). Set `skipVerification` to
`true` to bypass the private-IP/self-IP guard (useful for `localhost`/lab
targets). Every entry in `result.components` is `{Ids, Name, Version, Host,
Port}` - `Ids` is one or more candidate CPE 2.3 strings built from the
detected vendor/product/version (more than one when a product is known
under more than one vendor/product alias).

`WebApplicationScanner.scan(url, opts)` is the lower-level single-host
scanner it's built on (`web_general/web.py`); it also exposes a
`detected_packages` field in the same `{Ids, Name, Version, Host, Port}`
shape, alongside the raw internal `server`/`backend`/`application`/
`components` arrays if you want the unprocessed vendor/product/version data.

## Architecture

```
src/
  core/                    - the reconstructed "bane" surface + shared infra
    httpClient.js          - GET/POST over node:http/https, no proxy, TLS verify off
    html.js                - minimal BeautifulSoup-like find()/findAll() parser
    commonVariables.js     - user-agent pool + the global scanner registry
    technologyGuesser.js   - dispatches to the first registered scanner whose isValid() matches
    backendFingerprinter.js- port of backends.py (Server / X-Powered-By header parsing)
    cpeParser.js            - port of cpe_parser.py (+ a small stdlib XML reader replacing xmltodict)
    webApplicationScanner.js - port of web_general/web.py
    domainScanner.js        - port of domain_scanner.py
    net.js                  - DNS lookup + private-IP check (Domain_Info/IP_Info equivalents)
    productChecker.js       - component de-dup (Product_checker)
    componentId.js, normalize.js - build the {Ids, Name, Version, Host, Port} output shape
    scannerHelpers.js       - shared scaffolding most of the ~55 scanners are built from
  scanners/
    devops/ js_dev_ecosystem/ cms/ web_dev_frameworks/ databases/
    data_viz/ erp/ collaboration/ files_managers/ lms/ web_dev/
      - one file per original scanner, registered via registerScanner()
  index.js                  - imports every category (registers everything) + public exports
```

Every scanner module has the shape:

```js
{ application: "jenkins", async scan(url, opts) { ... }, isValid({data, headers, soup}) { ... } }
```

`TechnologyGuesser.analyze(text, headers)` walks the registry once, in
registration order, and returns `[application, scanFn]` for the first
`isValid()` match (or `["", defaultScan]`).

## What was intentionally left out

- **Proxying and raw sockets.** The original had HTTP/SOCKS4/SOCKS5 proxy
  plumbing threaded through nearly every function signature, and one scanner
  (Elasticsearch) hand-rolled a raw TCP+TLS socket just to issue a GET. None
  of that is fingerprinting logic, so it's gone - every scanner just makes a
  normal request.
- **`cms/wp.py`'s vulnerability-lookup and exploitation code.** The original
  file mixed WordPress fingerprinting with a large amount of code that
  actively queries wpvulnerability.net/wordfence.com/patchstack.com/
  wpscan.com/cve.mitre.org for CVEs, brute-forces XML-RPC and the admin
  login page, attempts an XML-RPC pingback SSRF, and enumerates site users.
  None of that identifies a product or version, so only the actual
  detection logic (WP core version, theme/plugin identification from page
  markup, and read-only XML-RPC method listing) was ported.
- **Two scanners that were never wired up.** `aspnet_scanner.py` and
  `php_scanner.py` defined no `application` key and no `is_valid()` in the
  original, so registering them would have crashed `TechnologyGuesser` the
  first time it reached them. Their `scan()` logic is preserved as
  standalone exports (`AspnetDastScanner`, `PhpDastScanner`) instead of
  being auto-registered.

## Bugs fixed vs. preserved

- **Fixed:** `graylog_scanner.py` and `wazuh_scanner.py` both registered
  themselves under `application: "jenkins"` with the class name
  `Graylog_Scanner` (evident copy/paste) - this would have made two
  unrelated products permanently undetectable via auto-dispatch. Corrected
  to `"graylog"` / `"wazuh"`.
- **Preserved:** a few version-extraction dead ends that don't affect
  detection accuracy, just leave `version` empty - e.g. `flutter.js`
  scanning for a `"Vue.js v"` marker, `sailsjs` reusing MeteorJS's marker.
  Noted inline in each file rather than guessing at a fix.

## Requirements

Node.js >= 18. No `npm install` needed - everything is stdlib.
