# Disclaimer for the extracted licenses in the reports:

The licenses are extracted raw whenever available. The tool hasn't yet implemented a normalization layer for them, but we are planning to in a future release.

# Disclaimer for the missing `hashes` in the `components` section of the generated `cyclonedx` files:

Package hashes are not consistently available across all supported ecosystems and package managers at scan time. It is impossible to provide the hashes consistently for all detected packages/dependencies across all stacks. So, for the sake of consistency, we chose to remove them entirely instead of generated inconsistent outputs across scans.

# Disclaimer for the SARIF files generated outside the scopes of repositories/Code editors:

The vulnerability/rules data are generated correctly, but some metadata like the `%SRCROOT%` and `originalUriBaseIds` can't be generated consistently since the scanned binaries are spread across the whole machine's filesystem. The vulnerability and rule data, CVSS vectors, affected package PURLs, etc.. are still valid.

# Disclaimer for `MAL-2022-4691` and `monorepo-symlink-test@0.0.0`

The function `filterFalsePositiveInfections` in this project suppresses
the detection of MAL-2022-4691 for `monorepo-symlink-test@0.0.0` when found
under specific path: `node_modules/resolve/test/resolver/multirepo`

THIS FILTER IS PROVIDED “AS IS” AND WITHOUT ANY WARRANTY OF ANY KIND,
EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, AND NONINFRINGEMENT.

IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES, OR OTHER
LIABILITY ARISING FROM THE USE OF THIS FILTER, INCLUDING BUT NOT LIMITED
TO THE SUPPRESSION OF GENUINE SECURITY VULNERABILITIES.

Users are solely responsible for reviewing the filter’s logic and
determining its suitability for their environment.