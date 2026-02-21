def evaluate_policy(report: dict):
    stats = report.get("stats", {})
    policy = report.get("policy")

    if not policy:
        raise RuntimeError("No policy returned by API (fail-closed)")

    # Infections
    if policy.get("infections") == "block":
        if stats.get("total_infections", 0) > 0:
            return False, "Blocked by policy: infections detected"

    # KEV
    if policy.get("kev") == "block":
        kev_total = (
            stats.get("vulnerabilities_stats", {})
            .get("kev", {})
            .get("total", 0)
        )
        if kev_total > 0:
            return False, "Blocked by policy: KEV vulnerabilities detected"

    # Weaponized
    if policy.get("weaponized") == "block":
        weaponized = (
            stats.get("vulnerabilities_stats", {})
            .get("exploitability", {})
            .get("are_weaponized", 0)
        )
        if weaponized > 0:
            return False, "Blocked by policy: weaponized vulnerabilities detected"

    # Severity rules
    severity_policy = policy.get("severity", {})
    severity_stats = (
        stats.get("vulnerabilities_stats", {})
        .get("severity", {})
    )
    for sev, action in severity_policy.items():
        if action == "block":
            if severity_stats.get(sev.lower(), 0) > 0:
                return False, f"Blocked by policy: {sev} severity vulnerabilities detected"

    return True, "Policy passed"