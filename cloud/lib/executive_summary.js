// cloud/lib/executive_summary.js
//
// Builds the `executive_summary` section of a UBEL cloud-scanner report: a
// short, plain-language overview for non-technical readers (management, risk,
// compliance, product owners). It is the cloud counterpart of
// sca/executive_summary.js and easm/lib/executive_summary.js and follows the
// same rules:
//
//   - It is derived entirely from data already in the finished report payload
//     (findings, stats, compliance, scan coverage) — no network calls, no new
//     scanning — and is attached inside buildReportPayload() (see
//     ./html_report.js), so the JSON report and the HTML "Executive Summary"
//     tab always show exactly the same content.
//   - No check ids, ARNs or CLI commands in headline text; every number is
//     stated with what it means. Technical detail stays in the other tabs.
//   - A figure that was NOT checked is `null` ("not checked"), never 0, so
//     nobody reads a skipped cloud as a clean one.
//
// What differs from the SCA / EASM summaries, and why:
//   - No CVE, component or reachability concepts: findings here are
//     configuration rules failing on individual cloud resources, so the
//     "what to fix first" tables rank issue types and resources instead.
//   - Findings already carry a severity assigned by the scanner's own rules
//     (critical / high / medium / low / info), so the rating is a direct
//     roll-up of those, not a re-score.
//   - `info` findings are housekeeping notes, not risks. They are counted
//     separately and never drive the rating or the "top risks".
//   - Coverage is about which clouds / regions were actually scanned, so it
//     has its own section (a provider whose credentials were missing, or
//     whose scan stopped part-way, must never read as "clean").
//   - There is no pass/fail policy verdict: --fail-on only sets the process
//     exit code and is not part of the report.
//
// The rating and prioritization rules in buildMethodology() are a prose copy
// of overallRisk() / buildRiskAreas() / the action builder below — if those
// change, update that text too.

import { createHash } from "node:crypto";

const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Informational" };

const RISK_LABEL = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Minimal", not_assessed: "Not assessed",
};

const PROVIDER_LABEL = { aws: "AWS", gcp: "Google Cloud", azure: "Microsoft Azure" };

function providerLabel(p) {
  return PROVIDER_LABEL[p] || String(p || "unknown").toUpperCase();
}

function plural(n, one, many) {
  return n === 1 ? one : (many || one + "s");
}

function count(n, one, many) {
  return `${n} ${plural(n, one, many)}`;
}

// Same fallback as buildStats() in html_report.js: an unrecognised severity is
// treated as informational, so the summary's numbers tie out with the
// dashboard's.
function sevKey(s) {
  const k = String(s || "info").toLowerCase();
  return k in SEV_RANK ? k : "info";
}

function joinList(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}

// Coverage gaps are whole clauses that can contain their own "and" and
// parentheses, so they are separated with semicolons, not commas.
function joinGaps(gaps) {
  return gaps.join("; ");
}

function lcFirst(s) {
  return s ? s.charAt(0).toLowerCase() + s.slice(1) : s;
}

function trunc(s, n) {
  const t = String(s == null ? "" : s).replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

function resKey(f) {
  return `${f.provider}::${f.service}::${f.resource}`;
}

// Plain-language wording for each risk category the compliance mapping assigns
// to a check (see sca/compliance_mappings.js). A category this table does not
// know still gets a generic entry (see areaFor()).
//   plain — what the problem is, for the reader
//   fix   — the action in one imperative sentence
//   why   — why it matters / what to be careful of
//   owner — default suggestion only, not an assignment
const RISK_AREAS = {
  public_exposure: {
    title: "Resources open to the public internet",
    plain: "Storage, databases, servers or networks can be reached by anyone on the internet (or by any user of the cloud provider) instead of only by the people and systems that need them. This is the most common route to data leaks and break-ins.",
    fix: "Close public access to the exposed storage, databases and network ports, and allow only the people and networks that need them.",
    why: "Anything reachable from the internet is found by automated scanners within hours. Some public resources are intentional (for example a public website bucket), so confirm with the owner before closing access; for the rest, assume the data may already have been read.",
    owner: "Cloud / infrastructure team",
  },
  iam_misconfiguration: {
    title: "Overly broad or poorly protected access",
    plain: "User, role or policy settings give more access than needed, or accounts lack extra protection such as multi-factor sign-in or regular key rotation. One stolen password or key could then do wide damage.",
    fix: "Reduce permissions to what each person or system needs, switch on multi-factor sign-in, and replace old access keys.",
    why: "Access settings decide how far an attacker can go once they hold a single credential. Tightening them limits the damage of any later mistake or theft.",
    owner: "Cloud security / identity team",
  },
  cryptography: {
    title: "Data not encrypted, or weakly protected",
    plain: "Stored data or network connections are not encrypted, or use outdated protection, so anyone who gets hold of the underlying storage or traffic could read it.",
    fix: "Turn on encryption for the affected storage, databases and connections, and require current protection standards.",
    why: "Encryption is often a single setting, and it is frequently a stated requirement in audits and customer contracts. Existing data may need to be re-encrypted, so plan the change.",
    owner: "Cloud / infrastructure team",
  },
  logging_monitoring: {
    title: "Activity logging and threat detection gaps",
    plain: "Audit logs or threat-detection services are switched off or incomplete, so a break-in could go unnoticed and be hard to investigate afterwards.",
    fix: "Turn on audit logging and threat detection in every account and region in use, and keep the logs protected.",
    why: "Logs cannot be recreated after the fact. Without them an incident cannot be reliably scoped, and some regulations require them.",
    owner: "Security team",
  },
  data_protection_resilience: {
    title: "Weak backup and recovery protection",
    plain: "Safeguards such as versioning, retention or purge protection are missing, so data could be lost or destroyed by mistake or by an attacker, and be hard to recover.",
    fix: "Switch on versioning, backups and deletion protection for the affected data stores.",
    why: "These safeguards make accidental or malicious deletion recoverable. They cost little to enable and are very hard to add after data has been lost.",
    owner: "Cloud / infrastructure team",
  },
  security_misconfiguration: {
    title: "Other security settings below good practice",
    plain: "Settings fall short of recommended practice in ways that do not fit the other areas, such as outdated options or unused resources left in place.",
    fix: "Work through the remaining settings and bring them in line with the recommended configuration.",
    why: "Individually these are usually limited, but together they weaken the overall security posture and are quick to correct.",
    owner: "Cloud / infrastructure team",
  },
};

function areaFor(category) {
  return RISK_AREAS[category] || {
    title: "Other security configuration issues",
    plain: "Settings on these resources fall short of common security practice. See the Findings tab for the specific issues.",
    fix: "Review the remaining configuration issues and correct them.",
    why: "These settings are below recommended practice. The Findings tab lists each one with its recommended fix.",
    owner: "Cloud / infrastructure team",
  };
}

const BUSINESS_IMPACT = {
  critical:
    "At least one cloud resource is exposed or configured in a way that could lead directly to a serious incident, such as data open to the public or unrestricted control of an account. " +
    "Anyone who finds it can try to use it without special skill. Fix these before routine work and check whether the exposure has already been used.",
  high:
    "Settings were found that could let outsiders reach data or systems, or that give accounts far more power than they need. " +
    "They are not all immediately exploitable, but they are the kind of gap attackers look for, and they should be addressed first, before routine work.",
  medium:
    "The issues found are less likely to be exploited, or would cause limited damage if they were. " +
    "They can be handled through scheduled maintenance rather than emergency action.",
  low:
    "The issues found are minor and unlikely to cause meaningful harm on their own. They can be fixed during routine updates.",
  none:
    "No action is required based on this scan. Cloud environments change constantly (new resources, new permissions, new settings), " +
    "so they should still be re-checked regularly.",
  not_assessed:
    "This report does not say whether the cloud environment is secure, because no cloud account could be scanned. " +
    "Resolve why the scan could not run (usually missing or insufficient credentials), then run it again.",
};

// ── One-page summary helpers ─────────────────────────────────────────────────

// Deterministic, so the same report shows the same ID in the JSON and HTML.
function makeReportId(prefix, report, name) {
  const h = createHash("sha256")
    .update(`${report?.generated_at || ""}|${report?.tool || ""}|${name || ""}`)
    .digest("hex");
  return `${prefix}-${h.slice(0, 10).toUpperCase()}`;
}

// Highest severity first, stable otherwise. Findings flagged `info` (context,
// not a risk) only appear when nothing else does.
function pickTopRisks(findings, limit = 3) {
  const rank = (f) => SEV_RANK[sevKey(f.severity)];
  const order = (list) => list
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank(b.f) - rank(a.f) || a.i - b.i)
    .map((x) => x.f);
  const risks = order(findings.filter((f) => !f.info));
  const picked = risks.length ? risks : order(findings);
  return picked.slice(0, limit).map(({ severity, title, detail }) => ({ severity, title, detail }));
}

function figureTone(worstKey, total) {
  if (total == null) return "";
  return total > 0 ? worstKey : "none";
}

function worstOf(sev) {
  return ["critical", "high", "medium", "low"].find((k) => (sev?.[k] || 0) > 0) || null;
}

function sevSummary(sev) {
  return ["critical", "high", "medium", "low"]
    .filter((k) => (sev?.[k] || 0) > 0)
    .map((k) => `${sev[k]} ${k}`)
    .join(" / ");
}

// ── Scan coverage ────────────────────────────────────────────────────────────
// `provider_status` is written by index.js: one row per requested provider,
// status scanned | partial | skipped. A report built by a caller that does not
// pass it falls back to "every listed provider was scanned".
function normalizeProviderStatus(report) {
  const list = Array.isArray(report?.provider_status) ? report.provider_status : null;
  if (list && list.length) {
    return list.map((s) => ({
      provider: s.provider,
      status: ["scanned", "partial", "skipped"].includes(s.status) ? s.status : "skipped",
      reason: s.reason ? trunc(s.reason, 200) : null,
    }));
  }
  return (Array.isArray(report?.providers) ? report.providers : [])
    .map((p) => ({ provider: p, status: "scanned", reason: null }));
}

const STATUS_LABEL = { scanned: "Scanned", partial: "Incomplete", skipped: "Not scanned" };

function describeScope(report, status) {
  const accounts = report?.accounts || {};
  const parts = [];
  for (const s of status) {
    if (s.status === "skipped") continue;
    const label = providerLabel(s.provider);
    if (s.provider === "aws") {
      const n = (report?.regions?.aws || []).length;
      parts.push(n ? `${label} (${count(n, "region")})` : label);
    } else if (s.provider === "gcp" && accounts.gcp) {
      parts.push(`${label} (project ${accounts.gcp})`);
    } else if (s.provider === "azure" && accounts.azure) {
      parts.push(`${label} (subscription ${accounts.azure})`);
    } else {
      parts.push(label);
    }
  }
  return parts;
}

// Why the AWS region list is what it is. `region_source` is written by index.js.
function regionSourceText(src) {
  switch (src) {
    case "cli": return "The regions were chosen explicitly by the operator.";
    case "configured": return "The regions came from the operator's configured region settings.";
    case "discovered": return "Every region enabled on the account was discovered automatically and scanned.";
    case "fallback": return "Automatic region discovery failed, so only the default region (us-east-1) was scanned and resources in other regions were not examined.";
    default: return "";
  }
}

// ── Risk areas (findings grouped by kind of problem) ─────────────────────────
// Each non-informational finding is counted under the FIRST risk category its
// check maps to, so a finding never counts twice here. Findings with no
// mapping fall under "other".
function primaryCategory(f) {
  const c = f?.compliance?.categories;
  return Array.isArray(c) && c.length && typeof c[0] === "string" ? c[0] : "other";
}

function buildRiskAreas(riskFindings) {
  const map = new Map();
  for (const f of riskFindings) {
    const cat = primaryCategory(f);
    if (!map.has(cat)) {
      map.set(cat, { category: cat, issues: 0, resources: new Set(), providers: new Set(), worst: -1, worstKey: "info", titles: new Map() });
    }
    const t = map.get(cat);
    t.issues++;
    t.resources.add(resKey(f));
    t.providers.add(f.provider);
    const k = sevKey(f.severity);
    if (SEV_RANK[k] > t.worst) { t.worst = SEV_RANK[k]; t.worstKey = k; }
    const title = f.title || f.check || "Unnamed issue";
    t.titles.set(title, (t.titles.get(title) || 0) + 1);
  }
  return [...map.values()]
    .sort((a, b) => b.worst - a.worst || b.issues - a.issues || a.category.localeCompare(b.category))
    .map((t) => ({
      category: t.category,
      title: areaFor(t.category).title,
      plain: areaFor(t.category).plain,
      fix: areaFor(t.category).fix,
      why: areaFor(t.category).why,
      owner: areaFor(t.category).owner,
      issues: t.issues,
      resources_affected: t.resources.size,
      clouds: [...t.providers].sort().map(providerLabel),
      worst_severity: t.worstKey,
      worst_severity_label: SEV_LABEL[t.worstKey],
      examples: [...t.titles.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 2).map(([title]) => title),
      worst_rank: t.worst,
    }));
}

// ── Issue types to fix first ─────────────────────────────────────────────────
// One row per rule (check) that fired, ranked by worst severity, then by how
// many resources it fired on. The counterpart of "Components to fix first".
function buildIssuesToFixFirst(riskFindings, limit = 5) {
  const map = new Map();
  for (const f of riskFindings) {
    const key = `${f.provider}::${f.check}`;
    if (!map.has(key)) map.set(key, { check: f.check, title: f.title || f.check, provider: f.provider, service: f.service, category: primaryCategory(f), resources: new Set(), findings: 0, worst: -1, worstKey: "info" });
    const g = map.get(key);
    g.findings++;
    g.resources.add(resKey(f));
    const k = sevKey(f.severity);
    if (SEV_RANK[k] > g.worst) { g.worst = SEV_RANK[k]; g.worstKey = k; }
  }
  return [...map.values()]
    .sort((a, b) => b.worst - a.worst || b.resources.size - a.resources.size || String(a.title).localeCompare(String(b.title)))
    .slice(0, limit)
    .map((g) => ({
      title: g.title,
      cloud: providerLabel(g.provider),
      service: g.service,
      resources_affected: g.resources.size,
      worst_severity: g.worstKey,
      worst_severity_label: SEV_LABEL[g.worstKey],
      // Rule id, for tickets and auditors. Kept out of the plain-language text.
      reference: g.check,
      action: areaFor(g.category).fix,
    }));
}

// ── Resources to review first ────────────────────────────────────────────────
function buildResourcesToReview(riskFindings, limit = 5) {
  const map = new Map();
  for (const f of riskFindings) {
    const key = resKey(f);
    if (!map.has(key)) map.set(key, { name: f.resource, provider: f.provider, service: f.service, regions: new Set(), issues: 0, worst: -1, worstKey: "info" });
    const r = map.get(key);
    r.issues++;
    if (f.region) r.regions.add(f.region);
    const k = sevKey(f.severity);
    if (SEV_RANK[k] > r.worst) { r.worst = SEV_RANK[k]; r.worstKey = k; }
  }
  return [...map.values()]
    .sort((a, b) => b.worst - a.worst || b.issues - a.issues || String(a.name).localeCompare(String(b.name), undefined, { numeric: true }))
    .slice(0, limit)
    .map((r) => ({
      name: r.name,
      cloud: providerLabel(r.provider),
      service: r.service,
      region: [...r.regions].sort().join(", ") || null,
      issues: r.issues,
      worst_severity: r.worstKey,
      worst_severity_label: SEV_LABEL[r.worstKey],
    }));
}

// ── Overall risk ─────────────────────────────────────────────────────────────
// Highest applicable level wins. `m.hidden` is the number of findings the
// --min-severity filter removed from this report: their severity is unknown to
// the summary, so the rating is floored at Low rather than allowed to read as
// Minimal.
function overallRisk(m) {
  if (m.providers_scanned === 0) {
    return {
      level: "not_assessed",
      rationale: "No cloud account could be scanned (credentials were missing or the scan could not start), so no security rating can be given.",
    };
  }
  const gaps = m.gaps.length ? ` This is not a full all-clear: ${joinGaps(m.gaps)}.` : "";
  const gapsOnRisk = m.gaps.length ? ` Not everything was covered: ${joinGaps(m.gaps)}. The true rating could be higher.` : "";
  if (m.sev.critical > 0) {
    return {
      level: "critical",
      rationale: `Includes ${count(m.sev.critical, "Critical-severity issue")}: exposures or settings that could lead directly to data theft or loss of control of an account.${gapsOnRisk}`,
    };
  }
  if (m.sev.high > 0) {
    return {
      level: "high",
      rationale: `Includes ${count(m.sev.high, "High-severity issue")}. These could be used against the organization and should be fixed ahead of routine work.${gapsOnRisk}`,
    };
  }
  if (m.sev.medium > 0) {
    return { level: "medium", rationale: `Moderate issues were found that should be fixed as part of normal maintenance.${gapsOnRisk}` };
  }
  if (m.sev.low > 0) {
    return { level: "low", rationale: `Only low-severity issues were found.${gapsOnRisk}` };
  }
  if (m.hidden > 0) {
    return {
      level: "low",
      rationale: `${count(m.hidden, "finding")} below the report's minimum-severity filter ${plural(m.hidden, "was", "were")} left out of this report, so a Minimal rating cannot be given. The true rating could be higher.${gapsOnRisk}`,
    };
  }
  const notes = m.sev.info > 0 ? ` ${count(m.sev.info, "informational note")} ${plural(m.sev.info, "was", "were")} recorded; ${plural(m.sev.info, "it is", "they are")} not risks.` : "";
  return { level: "none", rationale: `No security issues were found in what could be checked.${notes}${gaps}` };
}

// ── Methodology ──────────────────────────────────────────────────────────────
// Describes how THIS report was produced. Steps are included only when the
// corresponding stage actually ran, so the text never claims work that wasn't
// done.
const SERVICES_COVERED = {
  aws: "storage (S3), servers, networks and disks (EC2), identities and permissions (IAM), databases (RDS), audit logging (CloudTrail), threat detection (GuardDuty), and messaging topics and queues (SNS, SQS)",
  gcp: "storage buckets, firewall rules, project-level permissions, virtual machines, Cloud SQL databases, BigQuery datasets, Cloud Run and Cloud Functions, and Kubernetes clusters (GKE)",
  azure: "storage accounts, network security groups, SQL servers, Key Vault, App Service and Function Apps, Container Registry, and Kubernetes clusters (AKS)",
};

function buildMethodology(report, ctx) {
  const { status, scannedProviders, minSeverity, hidden, hasCompliance, regionSource } = ctx;
  const steps = [];

  // 1. Scope and credentials
  const scopeParts = describeScope(report, status);
  const skipped = status.filter((s) => s.status === "skipped");
  const partial = status.filter((s) => s.status === "partial");
  let scope = scopeParts.length
    ? `This scan covered ${joinList(scopeParts)}, using read-only credentials supplied by the operator for this run. The tool does not store or reuse them.`
    : "No cloud account was scanned: the credentials needed were not available.";
  if (scannedProviders.includes("aws") && regionSourceText(regionSource)) scope += ` ${regionSourceText(regionSource)}`;
  if (skipped.length) scope += ` Not scanned: ${joinList(skipped.map((s) => `${providerLabel(s.provider)}${s.reason ? " (" + s.reason + ")" : ""}`))}.`;
  if (partial.length) scope += ` Stopped part-way: ${joinList(partial.map((s) => `${providerLabel(s.provider)}${s.reason ? " (" + s.reason + ")" : ""}`))}; results for ${plural(partial.length, "it is", "them are")} incomplete.`;
  steps.push({ step: "Scope and credentials", detail: scope });

  if (scannedProviders.length) {
    // 2. Read-only inventory
    steps.push({
      step: "Read-only inspection of live settings",
      detail: "For each scanned cloud, the tool called that provider's own read-only management interface to list resources and read their settings and access policies, so the findings describe the real state of the account rather than a template or plan. " +
        "Nothing was created, changed or deleted, and the contents of files and databases were not read.",
    });

    // 3. Services covered
    steps.push({
      step: "Services examined",
      detail: scannedProviders.map((p) => `${providerLabel(p)}: ${SERVICES_COVERED[p] || "the services the scanner supports for this cloud"}`).join(". ") + ".",
    });

    // 4. Rule evaluation
    steps.push({
      step: "Rule checks",
      detail: "Each resource's settings were compared with a fixed set of built-in rules for common and serious mistakes: public access, network ports open to the whole internet, missing multi-factor sign-in, missing encryption, and disabled logging or threat detection. " +
        "A rule that matches creates one finding for that resource, so the same mistake on ten resources is ten findings. " +
        "Some rules adjust severity for context: access that is limited by a restrictive condition ranks lower than unrestricted access, and a firewall rule limited to tagged machines ranks one level below an unscoped rule. " +
        "The rules are deterministic: the same account state always produces the same findings.",
    });

    // 5. Severity
    steps.push({
      step: "Severity",
      detail: "Each finding carries a severity from the scanner's own rules: Critical (could lead directly to data theft or loss of control), High (serious weakness), Medium, Low, or Informational (a housekeeping note, not a risk). " +
        "These describe the issue in general, not its effect on your business. Informational notes are counted separately and never raise the rating.",
    });
  } else {
    steps.push({
      step: "Rule checks (not performed)",
      detail: "No cloud account could be scanned, so no rule was evaluated. The absence of findings says nothing about the environment.",
    });
  }

  // 6. Filter
  if (minSeverity && minSeverity !== "info") {
    steps.push({
      step: "Severity filter",
      detail: `This scan was run with a minimum-severity filter of “${minSeverity}”, so findings below that level were left out of the findings list and of every figure in this summary` +
        (hidden > 0 ? ` (${count(hidden, "finding")} hidden)` : "") + ".",
    });
  }

  // 7. Compliance
  if (hasCompliance) {
    steps.push({
      step: "Compliance mapping",
      detail: "Each finding was linked to related controls in common security frameworks using fixed mapping tables. Findings are mapped by type of problem, not by how a control is actually implemented in your organization. This is guidance for an audit conversation, not an assessment of compliance.",
    });
  }

  const ratingRules = [
    { level: "Critical", rule: "At least one Critical-severity issue." },
    { level: "High", rule: "At least one High-severity issue and no Critical ones." },
    { level: "Medium", rule: "Medium-severity issues and nothing more serious." },
    { level: "Low", rule: "Only Low-severity issues, or only findings that a minimum-severity filter hid from the report." },
    { level: "Minimal", rule: "Nothing above informational notes was found in the checks that ran." },
    { level: "Not assessed", rule: "No cloud account could be scanned, so no rating is given instead of “Minimal”." },
  ];

  const prioritization =
    "“Issue types to fix first” ranks each rule that fired by (1) worst severity, (2) number of resources it fired on, and lists the top five. " +
    "“Resources to review first” ranks individual cloud resources by (1) worst severity, (2) number of issues on them. " +
    "“Issues by area” counts each finding once, under the first risk category its rule belongs to. " +
    "Informational notes are left out of all three.";

  const timeframes =
    "The timeframes in “Suggested actions” are default guidance built into the tool (Critical issues: immediately; High: within days; the rest: next maintenance cycle). " +
    "They are not taken from your organization's remediation policy or SLAs. The suggested owners are likewise generic defaults, not assignments. Replace both with your own where those differ.";

  const limitations = [
    "This is a point-in-time view of configuration settings. Cloud environments change constantly, and anything changed after the scan is not reflected.",
    "The scan reads settings; it does not test whether an exposure has been, or could be, exploited, and it cannot tell whether a given setting is intentional. A public website bucket and an accidentally public database look alike to it, so confirm each finding with the resource owner.",
    "Only mistakes covered by the scanner's built-in rules are looked for. Anything outside those rules, flaws in your own applications, and anything inside the data itself are out of scope. A clean result is not proof of safety.",
    "If the supplied credentials lack permission to read a setting, that rule cannot be evaluated and produces no finding. Use the read-only permissions listed in the tool's documentation so that nothing is silently skipped.",
    "Severity ratings come from the scanner's own rules and describe an issue in general, not its effect on your business. The recommended actions are generated from the counts in this report and do not account for what each resource does or how important it is.",
    "Only the accounts, projects, subscriptions and regions listed under Scope were scanned. Other accounts or regions are not covered.",
  ];
  if (scannedProviders.includes("aws")) {
    limitations.push("In AWS, public access on individual stored objects is checked on a bounded sample, not on every object, so a very large bucket can contain public objects that are not reported. Where an access policy carries a condition the tool cannot fully evaluate, it keeps the higher severity and asks for a manual review.");
  }
  if (scannedProviders.includes("aws") || scannedProviders.includes("gcp")) {
    limitations.push("Some areas are deliberately not covered: encryption-key rotation, the status of AWS Config and AWS Security Hub, AWS Lambda access policies, and use of customer-managed encryption keys in Google Cloud.");
  }
  if (partial.length) {
    limitations.push(`${joinList(partial.map((s) => providerLabel(s.provider)))} ${plural(partial.length, "was", "were")} only partly scanned, so absent findings there are not evidence of a clean result.`);
  }

  return { steps, rating_rules: ratingRules, prioritization, timeframes, limitations };
}

// ── Main ─────────────────────────────────────────────────────────────────────
export function buildExecutiveSummary(report) {
  const findings = Array.isArray(report?.findings) ? report.findings : [];
  const opts = report?.scan_options || {};
  const minSeverity = opts.min_severity || null;
  const hidden = Math.max(0, Number(opts.hidden_by_filter) || 0);
  const regionSource = report?.region_source || null;

  // ── Coverage ─────────────────────────────────────────────────────────────
  const status = normalizeProviderStatus(report);
  const scannedRows = status.filter((s) => s.status !== "skipped");
  const skippedRows = status.filter((s) => s.status === "skipped");
  const partialRows = status.filter((s) => s.status === "partial");
  const scannedProviders = scannedRows.map((s) => s.provider);
  const providersScanned = scannedRows.length;
  const requested = status.length;

  const gaps = [];
  for (const s of skippedRows) gaps.push(`${providerLabel(s.provider)} was not scanned${s.reason ? " (" + s.reason + ")" : ""}`);
  for (const s of partialRows) gaps.push(`the ${providerLabel(s.provider)} scan stopped part-way${s.reason ? " (" + s.reason + ")" : ""} and is incomplete`);
  const awsFallback = scannedProviders.includes("aws") && regionSource === "fallback";
  if (awsFallback) gaps.push("AWS region discovery failed and only us-east-1 was scanned");

  // ── Findings ─────────────────────────────────────────────────────────────
  const riskFindings = findings.filter((f) => sevKey(f.severity) !== "info");
  const infoFindings = findings.filter((f) => sevKey(f.severity) === "info");
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[sevKey(f.severity)]++;
  const riskTotal = riskFindings.length;
  const seriousTotal = sev.critical + sev.high;
  const lowerTotal = sev.medium + sev.low;
  const resources = new Set(riskFindings.map(resKey));
  const issueTypes = new Set(riskFindings.map((f) => `${f.provider}::${f.check}`));
  const seriousResources = new Set(riskFindings.filter((f) => ["critical", "high"].includes(sevKey(f.severity))).map(resKey));
  const areas = buildRiskAreas(riskFindings);

  const m = { providers_scanned: providersScanned, sev, hidden, gaps };
  const risk = overallRisk(m);
  const assessed = risk.level !== "not_assessed";
  const scopeParts = describeScope(report, status);
  const scopeText = scopeParts.length ? joinList(scopeParts.map((p) => p.replace(/ \(.*\)$/, ""))) : "the scanned clouds";

  // ── Headline ─────────────────────────────────────────────────────────────
  const drivers = [];
  if (sev.critical > 0) drivers.push(count(sev.critical, "Critical issue"));
  if (sev.high > 0) drivers.push(count(sev.high, "High-severity issue"));
  if (lowerTotal > 0) drivers.push(count(lowerTotal, "lower-severity issue"));

  let summary;
  if (!assessed) {
    summary = requested === 0
      ? "No cloud was selected for scanning."
      : `None of the ${count(requested, "cloud")} requested could be scanned` +
        (skippedRows.length ? ` (${joinList(skippedRows.map((s) => providerLabel(s.provider) + (s.reason ? ": " + s.reason : "")))}).` : ".");
  } else if (riskTotal > 0) {
    summary = `Found across ${scopeText}: ${joinList(drivers)}.` +
      (gaps.length ? ` Not everything was covered: ${joinGaps(gaps)}.` : "");
  } else if (hidden > 0) {
    summary = `No issues at or above the “${minSeverity || "set"}” filter were found across ${scopeText}; ${count(hidden, "finding")} below it ${plural(hidden, "was", "were")} left out.` +
      (gaps.length ? ` Not everything was covered: ${joinGaps(gaps)}.` : "");
  } else {
    summary = `No security issues were found across ${scopeText}` + (sev.info ? `, only ${count(sev.info, "informational note")}.` : ".") +
      (gaps.length ? ` This is not a full all-clear: ${joinGaps(gaps)}.` : "");
  }
  const headline = `${assessed ? RISK_LABEL[risk.level] + " risk" : "Risk not assessed"}. ${summary}`;

  // ── Key findings ─────────────────────────────────────────────────────────
  const keyFindings = [];

  if (!assessed) {
    keyFindings.push({
      severity: "medium",
      title: "No cloud account could be scanned",
      detail: (requested === 0 ? "No cloud was selected. " : `Of ${count(requested, "cloud")} requested, none could be scanned. `) +
        "This report says nothing about whether the cloud environment is secure.",
    });
  }
  for (const s of skippedRows.filter(() => assessed)) {
    keyFindings.push({
      severity: "medium",
      title: `${providerLabel(s.provider)} was not scanned`,
      detail: `${s.reason ? "Reason: " + s.reason + ". " : ""}Nothing in this report covers ${providerLabel(s.provider)}, so its absence from the findings does not mean it is secure.`,
    });
  }
  for (const s of partialRows) {
    keyFindings.push({
      severity: "medium",
      title: `The ${providerLabel(s.provider)} scan did not finish`,
      detail: `${s.reason ? "The scan stopped with: " + s.reason + ". " : ""}Findings already gathered for ${providerLabel(s.provider)} are included, but others may be missing. Resolve the cause and run the scan again.`,
    });
  }
  if (awsFallback) {
    keyFindings.push({
      severity: "medium",
      title: "Only one AWS region was scanned",
      detail: "The scanner could not list the account's enabled regions, so it fell back to us-east-1. Resources in every other region were not examined.",
    });
  }

  for (const t of areas.filter((x) => x.worst_rank >= SEV_RANK.high)) {
    keyFindings.push({
      severity: t.worst_severity,
      title: t.title,
      detail: `${t.plain} ${count(t.issues, "issue")} found on ${count(t.resources_affected, "resource")} (${joinList(t.clouds)}); the most serious is rated ${t.worst_severity_label}.` +
        (t.examples.length ? ` Examples: ${joinList(t.examples.map((e) => trunc(e, 90)))}.` : ""),
    });
  }

  const lowerAreas = areas.filter((x) => x.worst_rank < SEV_RANK.high);
  if (lowerAreas.length) {
    const lowerIssues = lowerAreas.reduce((n, t) => n + t.issues, 0);
    keyFindings.push({
      severity: lowerAreas[0].worst_severity,
      title: "Other security configuration gaps",
      detail: `${count(lowerIssues, "lower-severity issue")} across ${joinList(lowerAreas.map((t) => lcFirst(t.title)))}. ` +
        "Individually they are limited, but together they weaken the overall security posture. Details are in the Findings tab.",
    });
  }

  if (sev.info > 0) {
    keyFindings.push({
      severity: "low",
      title: "Informational notes",
      detail: `${count(sev.info, "housekeeping note")} ${plural(sev.info, "was", "were")} recorded (for example unused resources). They are context, not risks, and are not counted in the figures above.`,
      info: true,
    });
  }

  if (hidden > 0) {
    keyFindings.push({
      severity: "medium",
      title: "Some findings were left out by a severity filter",
      detail: `${count(hidden, "finding")} below the minimum-severity filter “${minSeverity || "set"}” ${plural(hidden, "was", "were")} removed from this report. ` +
        "The rating and counts here cover only what remains, so the true picture could be worse. Run again without the filter for the full list.",
    });
  }

  if (keyFindings.length === 0) {
    keyFindings.push({
      severity: "low",
      title: "No significant findings",
      detail: "The scan did not find security issues in the cloud accounts it could examine.",
      info: true,
    });
  }

  // ── Recommended actions ──────────────────────────────────────────────────
  const actions = [];
  // `owner` is a default suggestion of which team usually handles this kind of
  // action, not an assignment; adjust to your own organization.
  const push = (timeframe, action, why, owner) => actions.push({ priority: actions.length + 1, timeframe, action, why, owner });

  const themeTimeframe = (t) => t.worst_rank >= SEV_RANK.critical ? "Immediately"
    : t.worst_rank >= SEV_RANK.high ? "Within days"
    : "Next maintenance cycle";
  const pushTheme = (t) => push(themeTimeframe(t),
    `${t.fix} (${count(t.issues, "issue")} on ${count(t.resources_affected, "resource")}).`,
    t.why,
    t.owner);

  // Critical findings come first; coverage gaps follow immediately, ahead of
  // everything less urgent, so a reader acting on the top three sees both.
  for (const t of areas.filter((x) => themeTimeframe(x) === "Immediately")) pushTheme(t);

  if (!assessed) {
    push("Before relying on this report",
      "Find out why no cloud account could be scanned, then run the scan again.",
      "Missing or insufficient credentials produce an empty report that gives no assurance about security.",
      "Security team");
  }
  for (const s of skippedRows.filter(() => assessed)) {
    push("Before relying on this report",
      `Provide read-only credentials for ${providerLabel(s.provider)} and scan it, or confirm it is out of scope.`,
      `${providerLabel(s.provider)} is not covered by this report, so its absence from the findings gives no assurance.`,
      "Security team");
  }
  for (const s of partialRows) {
    push("Before relying on this report",
      `Resolve why the ${providerLabel(s.provider)} scan stopped and run it again.`,
      "Only part of that cloud was examined, so findings there may be missing.",
      "Security team");
  }
  if (awsFallback) {
    push("Before relying on this report",
      "Run the AWS scan again with the account's regions listed explicitly, or allow the region-listing permission.",
      "Only one region was examined, so resources elsewhere were not checked.",
      "Security team");
  }
  for (const t of areas.filter((x) => themeTimeframe(x) !== "Immediately")) pushTheme(t);
  if (hidden > 0) {
    push("Next maintenance cycle",
      "Re-run the scan without the minimum-severity filter to see every finding.",
      "The filtered findings are not part of this report.",
      "Security team");
  }
  push("Ongoing",
    "Re-run this scan on a schedule and after any significant change to the cloud environment.",
    "Accounts change daily: new resources, new permissions, new settings. A scan that was clean last month may not be today.",
    "Security team");

  // ── Compliance (best-effort, high level) ─────────────────────────────────
  // Counted here from the findings themselves, each finding once per
  // framework (the same finding can sit under several controls of one
  // framework). Informational notes are included, so these figures can exceed
  // the risk counts above.
  let complianceOverview = null;
  const fwMap = new Map();
  let mapped = 0;
  findings.forEach((f, i) => {
    const fws = f?.compliance?.frameworks;
    if (!Array.isArray(fws) || !fws.length) return;
    mapped++;
    for (const fw of fws) {
      if (!fw?.name) continue;
      if (!fwMap.has(fw.name)) fwMap.set(fw.name, new Set());
      fwMap.get(fw.name).add(i);
    }
  });
  if (fwMap.size) {
    const top = [...fwMap.entries()]
      .map(([framework, set]) => ({ framework, findings: set.size }))
      .sort((a, b) => b.findings - a.findings || a.framework.localeCompare(b.framework))
      .slice(0, 4);
    complianceOverview = {
      frameworks_touched: fwMap.size,
      most_affected: top,
      findings_mapped: mapped,
      findings_total: findings.length,
      statement: `The findings relate to controls in ${count(fwMap.size, "industry framework")}; ${mapped} of ${findings.length} findings map to at least one. ` +
        "Unresolved findings may need to be explained or remediated in a related audit. " +
        "The numbers shown count individual findings (one rule failing on one resource), each counted once per framework and including informational notes; the Compliance tab counts distinct rules and resources instead, so its figures can be lower.",
      disclaimer: report?.compliance_summary?.disclaimer || "Compliance mappings are best-effort guidance, not a certified assessment.",
    };
  }

  // ── Scope & caveats ──────────────────────────────────────────────────────
  const subjectName = scopeParts.length ? scopeParts.join(", ") : (requested ? `${joinList(status.map((s) => providerLabel(s.provider)))} (not scanned)` : "Cloud environment");
  const scope = {
    tool: report?.tool || "cloud-scanner",
    description: "This report is a read-only review of the live configuration of cloud accounts, checked against built-in security rules.",
    discovery: "Resources were listed through each provider's own management interface within the scope below; nothing was deployed, changed or deleted.",
    subject: subjectName,
    clouds_requested: requested,
    clouds_scanned: providersScanned,
    clouds_not_scanned: skippedRows.length,
    clouds_incomplete: partialRows.length,
    aws_regions: scannedProviders.includes("aws") ? (report?.regions?.aws || []) : null,
    aws_region_source: scannedProviders.includes("aws") ? regionSource : null,
    gcp_project: scannedProviders.includes("gcp") ? (report?.accounts?.gcp || null) : null,
    azure_subscription: scannedProviders.includes("azure") ? (report?.accounts?.azure || null) : null,
    min_severity: minSeverity,
    generated_at: report?.generated_at || null,
  };

  const notes = [];
  notes.push("Everything in this report is a read-only view of cloud settings at the time of the scan. It is not a penetration test, and nothing was exploited.");
  notes.push("Findings come from the scanner's built-in rules and can include intentional configurations (for example a deliberately public website bucket). Confirm a finding with the resource owner before acting on it.");
  notes.push("Compliance references are best-effort guidance and are not a substitute for a formal audit.");
  if (sev.info > 0) {
    notes.push("Informational notes are counted separately here, so “Issues found” can be lower than the total shown on the Findings tab.");
  }
  if (hidden > 0) {
    notes.push(`${count(hidden, "finding")} ${plural(hidden, "was", "were")} hidden by the minimum-severity filter and ${plural(hidden, "is", "are")} not counted in any figure.`);
  }
  for (const s of skippedRows) notes.push(`${providerLabel(s.provider)} was not scanned${s.reason ? ": " + s.reason : ""}.`);
  for (const s of partialRows) notes.push(`${providerLabel(s.provider)} was only partly scanned${s.reason ? ": " + s.reason : ""}.`);
  if (awsFallback) notes.push("AWS region discovery failed; only us-east-1 was scanned.");

  const glossary = [
    { term: "Cloud account", meaning: "The AWS account, Google Cloud project or Azure subscription where an organization's cloud resources live. This scan reads their settings." },
    { term: "Resource", meaning: "A single item in a cloud account, such as a storage bucket, a server, a database, a user or a firewall rule." },
    { term: "Issue (finding)", meaning: "One rule failing on one resource, for example one storage bucket that is open to the public. The same mistake on ten resources is ten findings." },
    { term: "Public exposure", meaning: "A resource that anyone on the internet, rather than only authorized people, can reach." },
    { term: "Access permissions (IAM)", meaning: "The settings that decide who may do what in a cloud account. Overly broad permissions let one stolen credential do wide damage." },
    { term: "Multi-factor sign-in (MFA)", meaning: "A second proof of identity, such as a phone prompt, required in addition to a password." },
    { term: "Encryption", meaning: "Scrambling data so that it is unreadable without the right key, both when stored and when sent over a network." },
    { term: "Audit logging / threat detection", meaning: "Records of who did what in the account, and services that watch for suspicious behavior. Needed to notice and investigate an incident." },
    { term: "Severity", meaning: "How serious an issue is, from Informational to Critical, according to the scanner's own rules." },
    { term: "Compliance framework", meaning: "A published set of security controls (for example PCI DSS or ISO/IEC 27001) that audits and contracts often refer to." },
  ];

  // Figures that depend on a scan that did not run are null ("not checked"),
  // never 0, so nobody reads them as a clean result.
  const na = (x) => (assessed ? x : null);
  const at_a_glance = {
    clouds_requested: requested,
    clouds_scanned: providersScanned,
    clouds_not_scanned: skippedRows.length,
    clouds_incomplete: partialRows.length,
    aws_regions_scanned: scannedProviders.includes("aws") ? (report?.regions?.aws || []).length : null,
    total_findings: na(findings.length),
    issues_found: na(riskTotal),
    by_severity: na(sev),
    informational_notes: na(sev.info),
    distinct_issue_types: na(issueTypes.size),
    resources_affected: na(resources.size),
    resources_with_serious_issues: na(seriousResources.size),
    hidden_by_severity_filter: hidden,
    compliance_frameworks_touched: complianceOverview ? complianceOverview.frameworks_touched : (assessed ? 0 : null),
  };

  // Ready-to-render figure cards. `value: null` means "not checked" and is
  // shown as n/a; `tone` is a severity key ("none" = good, "" = neutral).
  const cloudSub = `of ${count(requested, "cloud")} requested` +
    (skippedRows.length ? `, ${skippedRows.length} not scanned` : "") +
    (partialRows.length ? `, ${partialRows.length} incomplete` : "");
  const issuesSub = assessed ? (sevSummary(sev) || "None found") : "Not checked in this scan";
  const cloudTone = providersScanned === 0 ? "high" : (skippedRows.length || partialRows.length ? "medium" : "");
  const seriousTone = figureTone(sev.critical > 0 ? "critical" : "high", na(seriousTotal));

  const figures = [
    { label: "Clouds scanned", value: providersScanned, sub: cloudSub, tone: cloudTone },
    { label: "Critical / High issues", value: na(seriousTotal), sub: assessed ? `${sev.critical} critical, ${sev.high} high` : "Not checked in this scan", tone: seriousTone },
    { label: "Issues found", value: na(riskTotal), sub: issuesSub, tone: figureTone(worstOf(sev), na(riskTotal)) },
    { label: "Resources affected", value: na(resources.size), sub: assessed ? `${count(issueTypes.size, "distinct issue type")}` : "Not checked in this scan", tone: figureTone("medium", na(resources.size)) },
  ];

  const awsCount = scannedProviders.includes("aws") ? (report?.regions?.aws || []).length : null;
  const glance_cards = [
    { label: "Clouds scanned", value: providersScanned, sub: cloudSub, tone: cloudTone },
    { label: "AWS regions scanned", value: awsCount, sub: awsCount == null ? "AWS was not scanned" : (awsFallback ? "Region discovery failed; default only" : "Regions examined in AWS"), tone: awsFallback ? "medium" : "" },
    { label: "Issues found", value: na(riskTotal), sub: issuesSub, tone: figureTone(worstOf(sev), na(riskTotal)) },
    { label: "Critical", value: na(sev.critical), sub: "Could lead directly to a serious incident", tone: figureTone("critical", na(sev.critical)) },
    { label: "High", value: na(sev.high), sub: "Serious weaknesses", tone: figureTone("high", na(sev.high)) },
    { label: "Medium / Low", value: na(lowerTotal), sub: "Handle in routine maintenance", tone: figureTone("medium", na(lowerTotal)) },
    { label: "Resources affected", value: na(resources.size), sub: assessed ? `${seriousResources.size} with Critical or High issues` : "Not checked in this scan", tone: figureTone("medium", na(resources.size)) },
    { label: "Distinct issue types", value: na(issueTypes.size), sub: "Different rules that fired", tone: "" },
    { label: "Informational notes", value: na(sev.info), sub: "Housekeeping, not risks", tone: "" },
    { label: "Compliance frameworks", value: complianceOverview ? complianceOverview.frameworks_touched : (assessed ? 0 : null), sub: "With at least one related finding", tone: "" },
  ];
  if (hidden > 0) {
    glance_cards.push({ label: "Hidden by filter", value: hidden, sub: "Findings below the minimum-severity filter", tone: "medium" });
  }

  // ── Per-cloud coverage table ─────────────────────────────────────────────
  const cloudCoverage = status.map((s) => {
    const own = riskFindings.filter((f) => f.provider === s.provider);
    const ownSev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of own) ownSev[sevKey(f.severity)]++;
    const w = s.status === "skipped" ? null : (worstOf(ownSev) || "none");
    let scopeNote = null;
    if (s.status !== "skipped") {
      if (s.provider === "aws") scopeNote = (report?.regions?.aws || []).length ? count(report.regions.aws.length, "region") : null;
      else if (s.provider === "gcp") scopeNote = report?.accounts?.gcp ? `project ${report.accounts.gcp}` : null;
      else if (s.provider === "azure") scopeNote = report?.accounts?.azure ? `subscription ${report.accounts.azure}` : null;
    }
    return {
      cloud: providerLabel(s.provider),
      status: s.status,
      status_label: STATUS_LABEL[s.status],
      scope: scopeNote,
      reason: s.reason,
      issues: s.status === "skipped" ? null : own.length,
      worst_severity: w,
      worst_severity_label: w === "none" ? "None found" : (w ? SEV_LABEL[w] : null),
    };
  });

  // ── One-page summary ─────────────────────────────────────────────────────
  const cover = {
    title: "Cloud Security Posture — Executive Summary",
    subject: subjectName,
    report_id: makeReportId("UBEL-CLOUD", report, subjectName),
    generated_at: report?.generated_at || null,
    tool: report?.tool ? `${report.tool}${report.tool_version ? " " + report.tool_version : ""}` : null,
    classification: "Confidential — contains security findings; share only with authorized recipients.",
    statement: "Produced by a read-only review of cloud accounts the operator is authorized to access, using credentials supplied for that run. It reflects the state of those accounts at the time of the scan.",
  };
  const bottom_line = {
    risk_level: risk.level,
    risk_label: RISK_LABEL[risk.level],
    summary,
    top_risks: pickTopRisks(keyFindings, 3),
    do_first: actions.filter((a) => a.timeframe !== "Ongoing").slice(0, 3)
      .map(({ timeframe, action, owner }) => ({ timeframe, action, owner })),
    figures,
  };

  return {
    overall_risk: {
      level: risk.level,
      label: RISK_LABEL[risk.level],
      rationale: risk.rationale,
      business_impact: BUSINESS_IMPACT[risk.level],
      basis: "Ratings follow a scale defined by this tool, not CVSS or a regulatory standard. The impact text is general guidance for the rating level, not an assessment of your environment.",
    },
    cover,
    bottom_line,
    headline,
    at_a_glance,
    glance_cards,
    key_findings: keyFindings,
    cloud_coverage: cloudCoverage,
    risk_areas: areas.map(({ worst_rank, ...t }) => t),
    issues_to_fix_first: buildIssuesToFixFirst(riskFindings, 5),
    resources_to_review_first: buildResourcesToReview(riskFindings, 5),
    recommended_actions: actions,
    recommended_actions_basis: "Actions are generated from the counts in this report. Timeframes are general defaults built into the tool, not your organization's remediation policy; adjust them to your own standards.",
    compliance_overview: complianceOverview,
    scope,
    methodology: buildMethodology(report, {
      status, scannedProviders, minSeverity, hidden, regionSource,
      hasCompliance: Array.isArray(report?.compliance_summary?.frameworks),
    }),
    notes,
    glossary,
  };
}