/*
 * WORKAROUND: Suppress likely false positive MAL-2022-4691
 * for pkg:npm/monorepo-symlink-test@0.0.0
 *
 * This identifier is flagged by multiple SCA tools due to a known
 * malicious package with the same name and version. In this context,
 * it appears only within test fixture paths of the "resolve" package:
 *
 *   node_modules/resolve/test/resolver/multirepo
 *
 * The upstream maintainer has chosen not to rename the fixture.
 *
 * This filter suppresses the finding only when matched under the
 * paths above.
 *
 * WARNING:
 * This is a heuristic and may hide true positives if a malicious
 * package is introduced under similar paths. This is a best-effort
 * workaround. No guarantee is made regarding detection accuracy.
 * Use with caution and consider making this behavior configurable.
 */
export function filterFalsePositiveInfections(inventory, vulnerabilities) {
    const filteredVulnerabilities = [];

    for (const vuln of vulnerabilities) {
        const IsPotentioalFalsePositive = vuln.id === "MAL-2022-4691" && vuln.affected_purl === "pkg:npm/monorepo-symlink-test@0.0.0";
        let isFalsePositive = false;
        for (const pkg of inventory) {
            if (pkg.id === vuln.affected_purl) {
                if (IsPotentioalFalsePositive) {
                    for (const path of pkg.paths) {
                        if (path.text.includes("node_modules\\resolve\\test\\resolver\\multirepo")|| path.text.includes("node_modules/resolve/test/resolver/multirepo")) {
                            isFalsePositive = true;
                            break;
                        }
                    }
                }
            }
        }
        if (!isFalsePositive) {
            filteredVulnerabilities.push(vuln);
            for (const pkg of inventory) {
                if (pkg.id === vuln.affected_purl) {
                    pkg.state = "safe";
                    break;
                }
            }
        }
    }

    return [filteredVulnerabilities, inventory];
}