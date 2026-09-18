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