// executive_summary.js
//
// Builds the `executive_summary` section of a UBEL SCA report: a short,
// plain-language overview for non-technical readers (management, risk,
// compliance, product owners). It is derived entirely from data that is
// already in the finished report object — no network calls, no new scanning —
// and is attached to the report before the JSON/HTML (and SBOM/SARIF) outputs
// are produced, so the JSON report and the HTML "Executive Summary" tab always
// show exactly the same content.
//
// Wording rules: no CVE/CVSS/PURL jargon in headline text, no raw advisory
// IDs in the narrative, every number is stated with what it means. Technical
// detail stays in the other tabs / report fields; this section only points
// readers there.

import { createHash } from "node:crypto";
import { findClosestFixVersions, _vr_purlToEcosystem } from "./version_recommender.js";

const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Unrated" };

const RISK_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Minimal", not_assessed: "Not assessed" };

function plural(n, one, many) {
  return n === 1 ? one : (many || one + "s");
}

function count(n, one, many) {
  return `${n} ${plural(n, one, many)}`;
}

function sevOf(v) {
  const s = String(v?.severity || "unknown").toLowerCase();
  return s in SEV_RANK ? s : "unknown";
}

function pct(part, whole) {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

// A finding counts as "confirmed unreachable" only when the reachability
// analyzer positively said so. A missing reachability object (analysis
// skipped or failed) is treated as "could be reachable" — the cautious choice
// for a summary meant to inform decisions.
//
// NOTE: this is the SUMMARY's own rule and it does NOT match the policy
// verdict. policy.js decides pass/fail from report.stats severity counts, which
// include findings regardless of reachability, and engine.js tags per-finding
// policy_decision before reachability enrichment has run, so no finding is
// ever exempted from blocking. The two are described separately in the
// methodology text on purpose.
function isConfirmedUnreachable(v) {
  return v?.reachability?.reachable === false;
}

// ── One-page summary helpers ─────────────────────────────────────────────────
// The first screen / printed page of the executive summary (`cover` and
// `bottom_line`) is built from the same data as everything below it, cut down
// to what a busy reader needs: the verdict, the three things that matter most,
// the three things to do first, and four numbers.

// Deterministic, so the same report shows the same ID in the JSON and HTML.
function makeReportId(prefix, report, name) {
  const h = createHash("sha256")
    .update(`${report?.generated_at || ""}|${report?.tool_info?.name || ""}|${name || ""}`)
    .digest("hex");
  return `${prefix}-${h.slice(0, 10).toUpperCase()}`;
}

// Highest severity first, stable otherwise. Findings flagged `info` (context,
// not a risk) only appear when nothing else does.
function pickTopRisks(findings, limit = 3) {
  const rank = (f) => SEV_RANK[String(f.severity || "unknown").toLowerCase()] ?? 0;
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
  return ["critical", "high", "medium", "low", "unknown"].find((k) => (sev?.[k] || 0) > 0) || null;
}

function sevSummary(sev) {
  return ["critical", "high", "medium", "low", "unknown"]
    .filter((k) => (sev?.[k] || 0) > 0)
    .map((k) => `${sev[k]} ${k === "unknown" ? "unrated" : k}`)
    .join(" / ");
}

function joinList(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}

function describeScan(report) {
  const type  = report?.scan_info?.type || "health";
  const scope = report?.scan_info?.scope || report?.scan_info?.scan_scope || "repository";
  const what = {
    health:  "an assessment of the software components currently installed",
    check:   "a pre-installation check of the software components that would be added or changed",
    install: "a gate check run before software components are installed",
  }[type] || "a software security assessment";
  const scopeText = {
    repository:          "a code repository",
    agent:               "an AI-agent workspace",
    cicd:                "a CI/CD build output",
    developer_platform:  "a developer machine / platform",
    editor_extension:    "an editor extension",
    cli_tool:            "a command-line tool",
    linux_machine:       "a Linux host",
    "container-image":   "a container image",
    container_image:     "a container image",
    license:             "a license inventory",
  }[scope] || null;
  return { type, what, scopeText };
}

// Suggest one upgrade target per component. For each vulnerability on the
// component we take the closest fixed version (already ranked by the engine),
// then, across all of them, the highest of those. That is a heuristic: it
// assumes the highest per-issue closest fix also covers the others, which is
// not verified (fix ranges can differ per release branch). Indicative only.
function suggestUpgrade(currentVersion, vulns, purl) {
  const picks = [];
  for (const v of vulns) {
    const rec = (v.fix_versions_ranked || []).find(r => r.recommended) || (v.fix_versions_ranked || [])[0];
    if (rec?.version) picks.push(rec.version);
  }
  const unique = [...new Set(picks)];
  if (!unique.length) return null;
  if (unique.length === 1) return unique[0];
  try {
    const ranked = findClosestFixVersions(currentVersion || "", unique, _vr_purlToEcosystem(purl || ""));
    if (ranked.length) return ranked[ranked.length - 1].version;
  } catch { /* fall through */ }
  return unique[unique.length - 1];
}

function buildPriorityComponents(vulns, limit = 5) {
  const byPkg = new Map();
  for (const v of vulns) {
    const key = v.affected_package_id || `${v.affected_dependency}@${v.affected_dependency_version}`;
    if (!byPkg.has(key)) {
      byPkg.set(key, {
        purl: v.affected_package_id || null,
        name: v.affected_dependency || "unknown",
        version: v.affected_dependency_version || "",
        vulns: [],
      });
    }
    byPkg.get(key).vulns.push(v);
  }

  const rows = [...byPkg.values()].map(p => {
    const malicious = p.vulns.some(v => v.is_infection);
    const nonInf    = p.vulns.filter(v => !v.is_infection);
    const worst     = nonInf.reduce((w, v) => Math.max(w, SEV_RANK[sevOf(v)]), -1);
    const worstKey  = Object.keys(SEV_RANK).find(k => SEV_RANK[k] === worst) || "unknown";
    const reachable = p.vulns.some(v => !isConfirmedUnreachable(v));
    const fixable   = nonInf.filter(v => v.has_fix || (v.fixed_versions || []).length > 0);
    const upgradeTo = malicious ? null : suggestUpgrade(p.version, fixable, p.purl);
    const blocked   = p.vulns.some(v => v.is_policy_violation);
    return {
      name: p.name,
      version: p.version,
      issue_count: p.vulns.length,
      worst_severity: malicious ? "malicious" : worstKey,
      worst_severity_label: malicious ? "Malicious" : SEV_LABEL[worstKey],
      likely_in_use: reachable,
      blocks_policy: blocked,
      // Advisory identifiers, most serious first, for tickets and auditors. Kept
      // out of the plain-language text on purpose.
      references: [...p.vulns]
        .sort((a, b) => (b.is_infection ? 5 : SEV_RANK[sevOf(b)]) - (a.is_infection ? 5 : SEV_RANK[sevOf(a)]))
        .map(v => v.id).filter(Boolean).slice(0, 5),
      more_references: Math.max(0, p.vulns.length - 5),
      action: malicious
        ? "Confirm the malicious-package match; if genuine, remove this component and investigate how it was introduced."
        : upgradeTo
          ? `Upgrade to version ${upgradeTo}${fixable.length < nonInf.length ? " (some issues have no fix yet; see technical details)" : ""}`
          : "No fixed version is published yet. Consider replacing or isolating the component.",
      _rank: [malicious ? 1 : 0, reachable ? 1 : 0, worst, p.vulns.length],
    };
  });

  rows.sort((a, b) => {
    for (let i = 0; i < a._rank.length; i++) {
      if (a._rank[i] !== b._rank[i]) return b._rank[i] - a._rank[i];
    }
    return a.name.localeCompare(b.name);
  });

  return rows.slice(0, limit).map(({ _rank, ...r }) => r);
}

function overallRisk(m) {
  // Highest applicable level wins. "Effective" counts exclude findings the
  // reachability analysis positively marked as not reachable from production.
  if (m.malicious_components > 0) {
    return {
      level: "critical",
      rationale: `${count(m.malicious_components, "component")} identified as deliberately malicious software.`,
    };
  }
  if (m.effective.critical > 0 || m.effective.high > 0 || m.secrets.serious > 0) {
    const parts = [];
    if (m.effective.critical) parts.push(`${count(m.effective.critical, "Critical-severity issue")}`);
    if (m.effective.high)     parts.push(`${count(m.effective.high, "High-severity issue")}`);
    if (m.secrets.serious)    parts.push(`${count(m.secrets.serious, "exposed credential")}`);
    return { level: "high", rationale: `Includes ${parts.join(", ")}. These could be used against the organization.` };
  }
  if (m.effective.medium > 0 || m.effective.unknown > 0 || m.secrets.total > 0 ||
      m.by_severity.critical > 0 || m.by_severity.high > 0) {
    const onlyUnreachableSerious = m.effective.medium === 0 && m.effective.unknown === 0 && m.secrets.total === 0;
    return {
      level: "medium",
      rationale: onlyUnreachableSerious
        ? "Serious issues exist, but the analysis indicates the affected code is not used in production paths."
        : "Medium-severity issues were found that should be fixed as part of normal maintenance.",
    };
  }
  if (m.total_vulnerabilities > 0) {
    const onlyLowSeverity = m.by_severity.medium === 0 && m.by_severity.unknown === 0;
    return {
      level: "low",
      rationale: onlyLowSeverity
        ? "Only low-severity issues were found."
        : "Only low-severity issues, or issues the analysis indicates are not used in production paths, were found.",
    };
  }
  if (!m.vulns_checked) {
    return {
      level: "not_assessed",
      rationale: "This scan did not look for security weaknesses, so no security rating can be given. It listed components and reviewed licenses only.",
    };
  }
  if (m.secrets.failed) {
    return {
      level: "none",
      rationale: "No known vulnerabilities or malicious components were found, but the search for exposed credentials did not complete, so this is not a full all-clear.",
    };
  }
  return { level: "none", rationale: "No known vulnerabilities, malicious components or exposed credentials were found." };
}

const BUSINESS_IMPACT = {
  critical:
    "The software contains components that match public malware advisories. Advisories occasionally name the wrong package or version, so first confirm the match is genuine. " +
    "If it is, running the software could give attackers direct access to systems and data, and it should not be deployed or used until the affected components are removed and the exposure has been investigated.",
  high:
    "Attackers could potentially exploit these weaknesses to steal data, disrupt services or gain unauthorized access. " +
    "These issues should be addressed before the next release, and urgently where they affect systems exposed to the internet.",
  medium:
    "The weaknesses found are less likely to be exploited, or would cause limited damage if they were. " +
    "They can be handled through scheduled maintenance rather than emergency action.",
  low:
    "The issues found are minor and unlikely to cause meaningful harm on their own. They can be fixed during routine updates.",
  none:
    "No action is required based on this scan. Security posture should still be re-checked regularly, because new weaknesses are published every day.",
  not_assessed:
    "This report does not say whether the software is secure. It lists the components and reviews their licenses only. Run a full security scan to assess weaknesses.",
};


// ── Scan subject (what was scanned) ──────────────────────────────────────────
// Git remotes can embed credentials (https://user:token@host/...), so userinfo
// is stripped from any URL before it is shown. The working directory is only
// used as a project name for scopes where it is meaningful; for container
// images, hosts and developer machines it is a temp or home directory.
function sanitizeRepoUrl(url) {
  if (typeof url !== "string" || !url.trim()) return null;
  return url.trim().replace(/^([a-z][a-z0-9+.-]*:\/\/)[^@\/\s]*@/i, "$1");
}

function buildSubject(report) {
  const git   = report?.git_metadata || {};
  const scope = report?.scan_info?.scan_scope || report?.scan_info?.scope || "repository";
  const repoUrl = sanitizeRepoUrl(git.url);

  let name = null;
  if (repoUrl) {
    const last = repoUrl.replace(/[\/\\]+$/, "").split(/[\/:]/).pop() || "";
    name = last.replace(/\.git$/i, "") || null;
  }
  const dirScopes = new Set(["repository", "agent", "cicd", "license", "editor_extension", "cli_tool"]);
  if (!name && dirScopes.has(scope) && typeof report?.runtime?.cwd === "string") {
    name = report.runtime.cwd.replace(/[\/\\]+$/, "").split(/[\/\\]/).pop() || null;
  }
  const commit = typeof git.latest_commit === "string" && git.latest_commit.trim()
    ? git.latest_commit.trim().slice(0, 8) : null;

  return {
    name,
    repository: repoUrl,
    branch: git.branch || null,
    commit,
    scanned_at: report?.generated_at || null,
    tool: report?.tool_info ? `${report.tool_info.name} ${report.tool_info.version}` : null,
  };
}

// ── Methodology ─────────────────────────────────────────────────────────────
// Describes how THIS report was produced. Steps are included only when the
// corresponding stage actually ran for this scan, so the text never claims
// work that wasn't done. The rating and prioritization rules below are a
// prose copy of overallRisk() / buildPriorityComponents() / the action
// builder in this file — if those change, update this text too.
function buildMethodology(report, ctx) {
  const { scan, vulns, secretsInfo, lic, componentsReviewed, vulnsChecked, undetermined } = ctx;
  const policy = report?.policy || {};
  const hasReach = vulns.some(v => v?.reachability);
  const hasCompliance = Array.isArray(report?.compliance_summary?.frameworks);

  const inventoryText = {
    health:  "Listed the software components already installed in the scanned location, including components pulled in indirectly by other components.",
    check:   "Worked out which components would be added or changed, including those they depend on, without installing anything.",
    install: "Worked out which components would be added or changed, including those they depend on, before deciding whether installation may proceed.",
  }[scan.type] || "Listed the software components in scope, including components pulled in indirectly.";

  const steps = [
    {
      step: "Inventory",
      detail: `${inventoryText} ${componentsReviewed} ${plural(componentsReviewed, "component was", "components were")} reviewed.` +
        (undetermined > 0 ? ` ${count(undetermined, "component")} had no determinable version and could not be checked for weaknesses.` : ""),
    },
  ];

  if (vulnsChecked) {
    steps.push(
      {
        step: "Known-weakness lookup",
        detail: "Each component with a known version was checked against public vulnerability databases (OSV.dev, and the U.S. National Vulnerability Database for operating-system and platform components) at the time of the scan. Only weaknesses published by then can be found.",
      },
      {
        step: "Malicious-software check",
        detail: "Components listed in public malware advisories (identifiers starting with “MAL-”) are reported separately and always count as blocking, regardless of policy settings.",
      },
    );
  } else {
    steps.push({
      step: "Known-weakness lookup (not run)",
      detail: "This scan was configured to skip vulnerability and malicious-software lookups. No security weaknesses were checked for, so the absence of findings below says nothing about them.",
    });
  }

  if (hasReach) {
    steps.push({
      step: "Usage estimate",
      detail: "For each weakness, an automated heuristic estimated whether the application is likely to use the affected component, based on how it is installed, whether it is only for development or testing, how deeply it is nested, and (where source files were available) whether the code imports it. This is an estimate, not proof. In this summary, issues judged not to be in use lower the overall risk rating and rank lower in the priority list, but they are still counted and listed. The pass/fail policy result ignores this estimate: it counts every weakness at or above the blocking severity, so a report can be rated Medium and still fail the policy.",
    });
  }
  if (secretsInfo.enabled) {
    steps.push({
      step: "Exposed-credential search",
      detail: "Source files were searched for patterns that look like passwords, access keys and tokens. Matches are pattern-based, so some may be false alarms and some real credentials may not match any pattern. Only a redacted preview of each match appears in the report; full credential values are never written to it.",
    });
  }
  if (lic) {
    steps.push({
      step: "License review",
      detail: "Each component’s declared license was matched against a list of known licenses and given a risk level based on the obligations it imposes. Components with missing or unreadable license information are counted as unknown, not as risky.",
    });
  }
  steps.push({
    step: "Policy check",
    detail: `Findings were compared with the configured security policy: block at severity “${policy.severity_threshold ?? "not set"}” or above; ` +
      `unrated issues ${policy.block_unknown_vulnerabilities === true ? "block" : policy.block_unknown_vulnerabilities === false ? "do not block" : "not configured"}` +
      (lic ? `; license risk ${!policy.license_risk_threshold || policy.license_risk_threshold === "none" ? "does not block" : `blocks at “${policy.license_risk_threshold}” or above`}; components with unrecognized licenses ${policy.block_unknown_license_risk === true ? "block" : "do not block"}` : "") +
      ". Malicious components" + (secretsInfo.enabled ? " and exposed credentials" : "") + " always block." +
      (hasReach ? " Weaknesses judged not in use still count toward the severity check." : ""),
  });
  if (hasCompliance) {
    steps.push({
      step: "Compliance mapping",
      detail: "Each finding was linked to related controls in common security frameworks using fixed mapping tables. This is guidance for an audit conversation, not an assessment of compliance.",
    });
  }

  const ratingRules = [
    { level: "Critical", rule: "At least one malicious component was found." },
    { level: "High", rule: "At least one Critical- or High-severity weakness that was not judged unused, or at least one exposed High/Critical credential." },
    { level: "Medium", rule: "Medium or unrated weaknesses, lower-severity credentials, or Critical/High weaknesses that were all judged unused." },
    { level: "Low", rule: "Only Low-severity weaknesses, or Medium/unrated ones that were all judged unused." },
    { level: "Minimal", rule: "Nothing found." },
  ];
  if (!vulnsChecked) {
    ratingRules.push({ level: "Not assessed", rule: "The scan skipped the weakness lookup and nothing else raised the rating, so no security rating is given instead of “Minimal”." });
  }

  const prioritization =
    "“Components to fix first” ranks components by: (1) malicious, (2) at least one issue not judged unused, (3) worst severity, (4) number of issues, and lists the top five. " +
    "The suggested version is the highest of the closest published fixes for that component’s issues; it is a starting point and has not been tested against your application.";

  const timeframes =
    "The timeframes in “Suggested actions” are default guidance built into the tool (credentials and malicious software: immediately; serious weaknesses: within days; the rest: next maintenance cycle). " +
    "They are not taken from your organization’s remediation policy or SLAs. The suggested owners are likewise generic defaults, not assignments. Replace both with your own where those differ.";

  const limitations = [
    "Severity ratings come from the public advisories. They describe the weakness in general, not its effect in your environment.",
    "The tool does not exploit weaknesses or test the running application. It identifies known issues in components.",
    "Weaknesses with no public advisory, flaws in your own code, and configuration problems are outside this scan.",
    "The recommended actions are generated from the counts above and are the same for any software with the same counts; they do not account for what the software does or how exposed it is.",
  ];

  if (undetermined > 0) {
    limitations.push("Components whose version could not be determined cannot be matched against vulnerability databases and are not covered.");
  }

  return { steps, rating_rules: ratingRules, prioritization, timeframes, limitations };
}

export function buildExecutiveSummary(report) {
  const vulns     = Array.isArray(report?.vulnerabilities) ? report.vulnerabilities : [];
  const inventory = Array.isArray(report?.inventory) ? report.inventory : [];
  const secrets   = report?.secrets || { enabled: false, findings: [] };
  const secretsList = Array.isArray(secrets.findings) ? secrets.findings : [];
  const decision  = report?.decision || { allowed: true, reason: "" };
  const stats     = report?.stats || {};
  const scan      = describeScan(report);
  // ubel-license (and any scan_vulns:false caller) skips OSV/NVD entirely. An
  // empty vulnerability list then means "not checked", not "nothing found".
  const vulnsChecked = report?.scan_info?.vulnerability_scan !== false;
  const undetermined = stats?.inventory_stats?.undetermined || 0;

  // ── Counts ────────────────────────────────────────────────────────────────
  const infections = vulns.filter(v => v.is_infection);
  const regular    = vulns.filter(v => !v.is_infection);

  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const effective  = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of regular) {
    const s = sevOf(v);
    bySeverity[s]++;
    if (!isConfirmedUnreachable(v)) effective[s]++;
  }

  const withFix       = regular.filter(v => v.has_fix || (v.fixed_versions || []).length > 0).length;
  const unreachable   = regular.filter(isConfirmedUnreachable).length;
  const blocking      = vulns.filter(v => v.is_policy_violation).length;

  const maliciousComponents = new Set(infections.map(v => v.affected_package_id || v.affected_dependency)).size;
  // Components affected = with a known weakness OR flagged as malicious, so the
  // figure agrees with the Inventory tab and does not silently leave out the
  // malicious ones (which are counted separately as well).
  const vulnerableComponents = stats?.inventory_stats
    ? (stats.inventory_stats.vulnerable || 0) + (stats.inventory_stats.infected || 0)
    : new Set(vulns.map(v => v.affected_package_id)).size;
  const componentsReviewed = stats?.inventory_size ?? inventory.length;

  const secretSev = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of secretsList) {
    const s = String(f.severity || "unknown").toLowerCase();
    secretSev[s in secretSev ? s : "unknown"]++;
  }
  // A secrets pass that threw is recorded as enabled:true, count:0, error:"...".
  // That must not read as "no credentials found".
  const secretsFailed = secrets.enabled !== false && !!secrets.error;
  const secretsInfo = {
    enabled: secrets.enabled !== false && !secretsFailed,
    failed: secretsFailed,
    total: secretsList.length,
    serious: secretSev.critical + secretSev.high,
    by_severity: secretSev,
  };

  const indirectVulnerable = inventory.filter(i =>
    (i.state === "vulnerable") && i.is_direct === false).length;

  const m = {
    total_vulnerabilities: regular.length,
    malicious_components: maliciousComponents,
    by_severity: bySeverity,
    effective,
    secrets: secretsInfo,
    vulns_checked: vulnsChecked,
  };

  const risk = overallRisk(m);

  // ── Verdict ───────────────────────────────────────────────────────────────
  const subject = scan.type === "health" ? "The scanned software" : "The proposed change";
  const verdict = decision.allowed
    ? {
        status: "pass",
        label: "Meets security policy",
        statement: `${subject} meets the organization's configured security policy.` +
          (blocking === 0 && regular.length + infections.length > 0
            ? " Some lower-priority issues remain and are listed below."
            : "") +
          (!vulnsChecked ? " Security weaknesses were not checked in this scan, so this result reflects the other checks only (such as license rules)." : ""),
      }
    : {
        status: "blocked",
        label: "Does not meet security policy",
        statement: (scan.type === "health"
          ? "The scanned software does not meet the organization's configured security policy. The blocking items must be resolved to pass."
          : "The change was stopped by the organization's security policy and should not go ahead until the blocking items are resolved.") +
          (decision.reason ? ` Reason given by the policy check: ${decision.reason}.` : ""),
      };

  // ── Headline ──────────────────────────────────────────────────────────────
  // Risk level first, then the (at most three) things driving it, in priority
  // order; everything else is "lower-priority issues" so the sentence stays
  // readable however long the findings list is. `summary` is the sentence shown
  // under the risk banner (which already names the level); `headline` is the same
  // sentence with the level in front, for the JSON and any consumer that shows it
  // on its own.
  const issueTotal = regular.length + infections.length;
  const seriousCount = bySeverity.critical + bySeverity.high;
  const lowerCount = regular.length - seriousCount;
  const drivers = [];
  if (maliciousComponents > 0) drivers.push(count(maliciousComponents, "malicious component"));
  if (seriousCount > 0) drivers.push(count(seriousCount, "serious weakness", "serious weaknesses"));
  if (secretsInfo.total > 0) drivers.push(count(secretsInfo.total, "exposed credential"));
  if (lowerCount > 0) drivers.push(count(lowerCount, "lower-severity weakness", "lower-severity weaknesses"));
  const shown = drivers.slice(0, 3);
  const more = drivers.length > 3;

  let summary;
  if (!vulnsChecked) {
    summary = `This scan listed ${count(componentsReviewed, "software component")} but did not check them for security weaknesses.` +
      (secretsInfo.total > 0 ? ` It did find ${count(secretsInfo.total, "exposed credential")} in the source files.` : "");
  } else if (issueTotal === 0 && secretsInfo.total === 0) {
    summary = `No known security weaknesses, malicious components or exposed credentials were found among ${count(componentsReviewed, "software component")}.` +
      (secretsInfo.failed ? " The search for exposed credentials did not complete, so this is not a full all-clear." : "");
  } else {
    summary = `Found among ${count(componentsReviewed, "software component")}: ${joinList(shown)}${more ? ", plus lower-priority issues" : ""}.`;
  }
  const headline = `${risk.level === "not_assessed" ? "Risk not assessed" : RISK_LABEL[risk.level] + " risk"}. ${summary}`;

  // ── Key findings (plain language, only those that apply) ─────────────────
  const keyFindings = [];

  if (!vulnsChecked) {
    keyFindings.push({
      severity: "medium",
      title: "Security weaknesses were not checked",
      detail: "This scan listed the components (and reviewed licenses) but did not look up known vulnerabilities or malicious software. It cannot show whether the software is secure.",
    });
  }
  if (secretsInfo.failed) {
    keyFindings.push({
      severity: "medium",
      title: "Credential search did not complete",
      detail: "The search for exposed passwords and access keys failed during this scan, so no result is available. The absence of credential findings here does not mean none exist.",
    });
  }

  if (maliciousComponents > 0) {
    keyFindings.push({
      severity: "critical",
      title: "Malicious software detected",
      detail: `${count(maliciousComponents, "component was", "components were")} flagged as deliberately harmful (for example, packages created to steal data or take control of systems). ` +
        "Unlike ordinary bugs, these are built to cause damage, so they are always treated as blocking. Advisories occasionally name the wrong package or version, so confirm the match before acting.",
    });
  }

  const seriousTotal = bySeverity.critical + bySeverity.high;
  if (seriousTotal > 0) {
    const seriousEffective = effective.critical + effective.high;
    keyFindings.push({
      severity: effective.critical > 0 ? "critical" : (seriousEffective > 0 ? "high" : "medium"),
      title: "Serious weaknesses in third-party software",
      detail: `${count(seriousTotal, "issue")} ${plural(seriousTotal, "is", "are")} rated Critical or High severity` +
        (bySeverity.critical ? ` (${bySeverity.critical} Critical, ${bySeverity.high} High)` : "") +
        ". " +
        (seriousEffective < seriousTotal
          ? `${seriousTotal - seriousEffective} of these ${plural(seriousTotal - seriousEffective, "appears", "appear")} not to be reachable from production code, so ${seriousTotal - seriousEffective === 1 ? "it is" : "they are"} lower priority.`
          : "None could be ruled out as unused, so all should be treated as relevant."),
    });
  }

  if (secretsInfo.total > 0) {
    keyFindings.push({
      severity: secretsInfo.serious > 0 ? "high" : "medium",
      title: "Passwords or access keys found in the source files",
      detail: `${count(secretsInfo.total, "credential")} ${plural(secretsInfo.total, "was", "were")} found stored in plain text. ` +
        "Anyone who can read these files could use them to access the related services. They should be treated as compromised and replaced, not just removed.",
    });
  }

  if (regular.length > 0) {
    const noFix = regular.length - withFix;
    let title, detail, severity;
    if (withFix === regular.length) {
      title = "Fixes are available";
      severity = "low";
      detail = `A fixed version already exists for ${regular.length === 1 ? "the issue" : `all ${regular.length} issues`}. Updating the affected components resolves ${regular.length === 1 ? "it" : "them"}.`;
    } else if (withFix === 0) {
      title = "No published fixes yet";
      severity = "medium";
      detail = `None of the ${count(regular.length, "issue")} has a published fix yet. Options are to replace the component, limit how it is used, or monitor for a patch.`;
    } else {
      title = pct(withFix, regular.length) >= 50 ? "Most issues can be fixed by updating" : "Only some issues can be fixed by updating";
      severity = "medium";
      detail = `A fixed version exists for ${withFix} of ${regular.length} issues (${pct(withFix, regular.length)}%). ` +
        `The other ${noFix} ${plural(noFix, "has", "have")} no published fix yet and may need a workaround or a replacement component.`;
    }
    // "Fixes are available" style findings are context, not a risk of their own,
    // so they never compete for the one-page top-three; "No published fixes" does.
    keyFindings.push({ severity, title, detail, info: withFix > 0 });
  }

  if (indirectVulnerable > 0 && vulnerableComponents > 0) {
    keyFindings.push({
      severity: "low",
      title: "Some weaknesses sit inside other components",
      detail: `${count(indirectVulnerable, "affected component")} ${plural(indirectVulnerable, "is", "are")} not chosen directly by the development team but pulled in by something else. ` +
        "Fixing these usually means updating the component that depends on them.",
      info: true,
    });
  }

  const lic = stats?.license_stats;
  if (lic && typeof lic === "object") {
    const high = lic.by_risk?.high || 0;
    const unk  = lic.by_risk?.unknown || 0;
    if (high > 0 || unk > 0) {
      keyFindings.push({
        severity: high > 0 ? "medium" : "low",
        title: "Software license review needed",
        detail:
          (high > 0
            ? `${count(high, "component")} ${plural(high, "uses a license", "use licenses")} with strong obligations or restrictions (such as copyleft or proprietary terms) that legal or procurement should review. `
            : "") +
          (unk > 0
            ? `${count(unk, "component")} ${plural(unk, "has", "have")} no recognizable license information, so the usage terms could not be confirmed.`
            : ""),
      });
    }
  }

  if (keyFindings.length === 0) {
    keyFindings.push({
      severity: "low",
      title: "No significant findings",
      detail: "The scan did not find known vulnerabilities, malicious components or exposed credentials.",
      info: true,
    });
  }

  // ── Recommended actions ───────────────────────────────────────────────────
  const actions = [];
  if (!vulnsChecked) {
    actions.push({
      priority: 1, timeframe: "Before relying on this report",
      action: "Run a full security scan of these components.",
      why: "This scan did not check for known weaknesses or malicious software, so it gives no assurance about security.",
      owner: "Security team",
    });
  }
  const seriousFixable = regular.filter(v => ["critical", "high"].includes(sevOf(v)) &&
    !isConfirmedUnreachable(v) && (v.has_fix || (v.fixed_versions || []).length > 0)).length;
  const seriousNoFix = regular.filter(v => ["critical", "high"].includes(sevOf(v)) &&
    !isConfirmedUnreachable(v) && !(v.has_fix || (v.fixed_versions || []).length > 0)).length;

  if (maliciousComponents > 0) {
    actions.push({
      priority: 1, timeframe: "Immediately",
      action: "Confirm the malicious-component match and, if genuine, remove the components and investigate.",
      why: "These components are designed to cause harm, but advisories occasionally name the wrong package or version, so verify first. If confirmed, check whether affected systems ran them, and rotate any credentials those systems could access.",
      owner: "Security team",
    });
  }
  if (secretsInfo.total > 0) {
    actions.push({
      priority: actions.length + 1, timeframe: "Immediately",
      action: "Replace every exposed password and access key, then move secrets out of the source files.",
      why: "Removing a secret from a file does not undo the exposure if it was ever shared or stored in history. Issue new credentials and revoke the old ones.",
      owner: "Development team",
    });
  }
  if (seriousFixable > 0) {
    actions.push({
      priority: actions.length + 1, timeframe: "Within days",
      action: `Update the components behind the ${count(seriousFixable, "Critical/High issue")} that already have a fix.`,
      why: "These are the weaknesses most likely to cause real damage, and the fix is already available. The “Components to fix first” list shows where to start.",
      owner: "Development team",
    });
  }
  if (seriousNoFix > 0) {
    actions.push({
      priority: actions.length + 1, timeframe: "Within days",
      action: `Decide how to handle the ${count(seriousNoFix, "serious issue")} with no published fix.`,
      why: "Choose between replacing the component, restricting how it is used, or accepting the risk with a documented sign-off and a date to review.",
      owner: "Security team with development team",
    });
  }
  // The policy blocks on every finding at/above the threshold (and unrated ones
  // if configured), including those the usage estimate judged unused, so the
  // "Critical/High that matter" actions above can leave the verdict unchanged.
  const regularBlocking = regular.filter(v => v.is_policy_violation).length;
  const blockingCovered = seriousFixable + seriousNoFix;
  if (!decision.allowed && regularBlocking > blockingCovered) {
    const blockingUnused = regular.filter(v => v.is_policy_violation && isConfirmedUnreachable(v)).length;
    actions.push({
      priority: actions.length + 1, timeframe: "To pass the policy",
      action: `Resolve the ${count(regularBlocking, "finding")} the security policy blocks on.`,
      why: (blockingUnused > 0
        ? `${blockingUnused} of them ${plural(blockingUnused, "was", "were")} judged not in use, but the policy still counts ${plural(blockingUnused, "it", "them")}. `
        : "") + "Update the affected components, or change the policy if your organization accepts the risk. The Vulnerabilities tab marks each blocking item.",
      owner: "Development team",
    });
  }
  const remainingFixable = withFix - seriousFixable;
  if (remainingFixable > 0) {
    actions.push({
      priority: actions.length + 1, timeframe: "Next maintenance cycle",
      action: "Apply the remaining updates as part of routine maintenance.",
      why: "Lower-severity issues add up over time. Batch them into regular dependency updates.",
      owner: "Development team",
    });
  } else if (effective.medium + effective.low + effective.unknown > 0) {
    actions.push({
      priority: actions.length + 1, timeframe: "Next maintenance cycle",
      action: "Keep an eye on the remaining lower-severity issues that have no published fix.",
      why: "There is nothing to update to yet. Check for new versions at each maintenance cycle.",
      owner: "Development team",
    });
  }
  if (lic && ((lic.by_risk?.high || 0) > 0 || (lic.by_risk?.unknown || 0) > 0)) {
    actions.push({
      priority: actions.length + 1, timeframe: "Next maintenance cycle",
      action: "Ask legal or procurement to review the flagged software licenses.",
      why: "Some licenses impose conditions on how software can be distributed or sold.",
      owner: "Legal / procurement",
    });
  }
  if (!decision.allowed && actions.length === 0) {
    actions.push({
      priority: 1, timeframe: "Before proceeding",
      action: "Review the blocking items listed in the Vulnerabilities tab.",
      why: decision.reason ? `Policy result: ${decision.reason}` : "The security policy blocked this result.",
      owner: "Development team",
    });
  }
  actions.push({
    priority: actions.length + 1, timeframe: "Ongoing",
    action: "Re-run this scan after changes and keep it in the regular build process.",
    why: "New weaknesses are published daily. A scan that was clean last month may not be today.",
    owner: "Security team",
  });

  // ── Compliance (best-effort, high level) ─────────────────────────────────
  let complianceOverview = null;
  const cs = report?.compliance_summary;
  if (cs && Array.isArray(cs.frameworks) && cs.frameworks.length) {
    const top = [...cs.frameworks]
      .sort((a, b) => (b.findings_count || 0) - (a.findings_count || 0))
      .slice(0, 4)
      .map(f => ({ framework: f.name, findings: f.findings_count || 0 }));
    complianceOverview = {
      frameworks_touched: cs.frameworks.length,
      most_affected: top,
      statement: `The findings relate to controls in ${count(cs.frameworks.length, "industry framework")}. ` +
        "Unresolved findings may need to be explained or remediated in a related audit. " +
        "The numbers shown count individual findings; the Compliance tab counts distinct CVEs and components, so its figures can be lower.",
      disclaimer: cs.disclaimer || "Compliance mappings are best-effort guidance, not a certified assessment.",
    };
  }

  // ── Scope & caveats ───────────────────────────────────────────────────────
  const scope = {
    scan_type: scan.type,
    description: `This report is ${scan.what}.`,
    target: scan.scopeText,
    subject: buildSubject(report),
    ecosystems: report?.scan_info?.ecosystems || [],
    components_reviewed: componentsReviewed,
    generated_at: report?.generated_at || null,
    tool: report?.tool_info ? `${report.tool_info.name} ${report.tool_info.version}` : null,
  };

  const notes = [];
  if (vulnsChecked) {
    notes.push("Findings come from public vulnerability databases (OSV.dev and the U.S. NVD) queried at the time of the scan. Weaknesses disclosed later will not appear until the next scan.");
    notes.push("“Likely in use” is an automated estimate of whether the affected code is used by the application. It helps prioritize but is not proof either way.");
  } else {
    notes.push("This scan did not look up vulnerabilities or malicious software. Figures for weaknesses, malicious components and fixes are shown as not checked, not as zero.");
  }
  notes.push("Compliance references are best-effort guidance and are not a substitute for a formal audit.");
  if (infections.length > 0) {
    notes.push("The Vulnerabilities tab also lists advisories for malicious components. In this summary they are counted separately, so “Known weaknesses” can be lower than the tab’s total.");
  }
  if (undetermined > 0) {
    notes.push(`${count(undetermined, "component")} had no determinable version, so ${undetermined === 1 ? "it was" : "they were"} not checked for weaknesses.`);
  }
  if (secretsInfo.failed) {
    notes.push("The search for exposed passwords and keys failed during this scan, so credential results are unavailable.");
  } else if (!secretsInfo.enabled) {
    notes.push("The search for exposed passwords and keys was not part of this scan.");
  }
  if (!lic) {
    notes.push("License checks run only on full health scans and were not part of this scan.");
  }

  const glossary = [
    { term: "Component", meaning: "A piece of third-party or open-source software the project relies on." },
    { term: "Vulnerability", meaning: "A known weakness in a component that an attacker could use to cause harm." },
    { term: "Malicious component", meaning: "Software built to do damage, such as stealing data. Not an accidental bug." },
    { term: "Exposed credential", meaning: "A password or access key stored in plain text where others could find it." },
    { term: "Severity", meaning: "How serious a weakness is, from Low to Critical, based on the potential damage." },
  ];

  // When vulnerabilities were not looked up, those figures are null ("not
  // checked") rather than 0, so nobody reads them as a clean result. Likewise
  // exposed_credentials is null when the credential search did not run/finish.
  const nv = x => (vulnsChecked ? x : null);
  const credsKnown = secretsInfo.enabled;
  const at_a_glance = {
    vulnerabilities_assessed: vulnsChecked,
    components_reviewed: componentsReviewed,
    components_with_issues: nv(vulnerableComponents),
    malicious_components: nv(maliciousComponents),
    total_vulnerabilities: nv(regular.length),
    by_severity: nv(bySeverity),
    fix_available: nv(withFix),
    fix_available_percent: nv(pct(withFix, regular.length)),
    likely_in_use: nv(regular.length - unreachable),
    not_in_use: nv(unreachable),
    blocking_policy: blocking,
    exposed_credentials: credsKnown ? secretsInfo.total : null,
  };

  // Ready-to-render figure cards. `value: null` means "not checked" and is shown
  // as n/a; `tone` is a severity key ("none" = good, "" = neutral).
  const weaknessSub = (vulnsChecked ? (sevSummary(bySeverity) || "None found") : "Not checked in this scan") +
    (maliciousComponents > 0 ? ` + ${count(maliciousComponents, "malicious component")}` : "");
  const weaknessTone = maliciousComponents > 0 ? "critical" : figureTone(worstOf(bySeverity), vulnsChecked ? regular.length : null);
  const credTotal = credsKnown ? secretsInfo.total : null;
  const credSub = credsKnown ? "Passwords / keys found in source files" : "Credential search did not run or did not complete";
  const policyValue = verdict.status === "pass" ? "Pass" : "Blocked";
  const policySub = verdict.status === "pass" ? "Meets the configured security policy" : (blocking > 0 ? `${count(blocking, "finding")} blocking` : "Does not meet the configured security policy");

  const figures = [
    { label: "Components reviewed", value: componentsReviewed, sub: undetermined > 0 ? `${count(undetermined, "component")} with unknown version` : "All had a checkable version", tone: "" },
    { label: "Known weaknesses", value: nv(regular.length), sub: weaknessSub, tone: vulnsChecked ? weaknessTone : "" },
    { label: "Exposed credentials", value: credTotal, sub: credSub, tone: figureTone(secretsInfo.serious > 0 ? "high" : "medium", credTotal) },
    { label: "Policy result", value: policyValue, sub: policySub, tone: verdict.status === "pass" ? "none" : "high" },
  ];

  const glance_cards = [
    { label: "Components reviewed", value: componentsReviewed, sub: undetermined > 0 ? `${count(undetermined, "component")} with unknown version` : "All had a checkable version", tone: "" },
    { label: "Components affected", value: nv(vulnerableComponents), sub: "With a known weakness or flagged as malicious", tone: figureTone("high", nv(vulnerableComponents)) },
    { label: "Malicious components", value: nv(maliciousComponents), sub: "Deliberately harmful software", tone: figureTone("critical", nv(maliciousComponents)) },
    { label: "Known weaknesses", value: nv(regular.length), sub: vulnsChecked ? sevSummary(bySeverity) : "Not checked in this scan", tone: figureTone("medium", nv(regular.length)) },
    { label: "Fix available", value: vulnsChecked ? `${pct(withFix, regular.length)}%` : null, sub: vulnsChecked ? `${withFix} of ${regular.length} can be fixed by updating` : "Not checked in this scan", tone: "" },
    { label: "Likely in use", value: nv(regular.length - unreachable), sub: vulnsChecked ? `${unreachable} judged not in use` : "Not checked in this scan", tone: "" },
    { label: "Blocking the policy", value: blocking, sub: "Findings the security policy blocks on", tone: blocking > 0 ? "high" : "none" },
    { label: "Exposed credentials", value: credTotal, sub: credSub, tone: figureTone("high", credTotal) },
  ];

  // ── One-page summary ─────────────────────────────────────────────────────
  const subjectInfo = buildSubject(report);
  const cover = {
    title: "Software Composition Analysis — Executive Summary",
    subject: subjectInfo.name || scan.scopeText || "Scanned software",
    report_id: makeReportId("UBEL-SCA", report, subjectInfo.name),
    generated_at: report?.generated_at || null,
    tool: subjectInfo.tool,
    classification: "Confidential — contains security findings; share only with authorized recipients.",
    statement: "Findings reflect the scanned software and the public vulnerability data available at the time of the scan.",
  };
  const bottom_line = {
    risk_level: risk.level,
    risk_label: RISK_LABEL[risk.level],
    summary,
    top_risks: pickTopRisks(keyFindings, 3),
    do_first: actions.filter(a => a.timeframe !== "Ongoing").slice(0, 3)
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
    verdict: { ...verdict, technical_reason: decision.reason || "" },
    at_a_glance,
    glance_cards,
    key_findings: keyFindings,
    components_to_fix_first: buildPriorityComponents(vulns, 5),
    recommended_actions: actions,
    recommended_actions_basis: "Actions are generated from the counts in this report. Timeframes are general defaults built into the tool, not your organization's remediation policy; adjust them to your own standards.",
    compliance_overview: complianceOverview,
    scope,
    methodology: buildMethodology(report, { scan, vulns, secretsInfo, lic, componentsReviewed, vulnsChecked, undetermined }),
    notes,
    glossary,
  };
}