// easm/lib/executive_summary.js
//
// Builds the `executive_summary` section of a UBEL EASM report (ubel-url,
// ubel-domain, ubel-host, ubel-easm): a short, plain-language overview for
// non-technical readers (management, risk, compliance, product owners). It is
// the EASM counterpart of sca/executive_summary.js and follows the same rules:
//
//   - It is derived entirely from data already in the finished report payload
//     — no network calls, no new scanning — and is attached inside
//     buildReportPayload() (see ./html_report.js), so the JSON report and the
//     HTML "Executive Summary" tab always show exactly the same content.
//   - No CVE/CVSS/CPE jargon in headline text, no raw advisory IDs in the
//     narrative, every number is stated with what it means. Technical detail
//     stays in the other tabs / report fields; this section only points there.
//   - A figure that was NOT checked is `null` ("not checked"), never 0, so
//     nobody reads a skipped check as a clean result.
//
// What differs from the SCA summary, and why:
//   - There is no reachability estimate: everything an EASM scan can see is, by
//     definition, already exposed to the internet, so no finding is ever
//     down-ranked as "probably not in use".
//   - There is no pass/fail policy verdict: EASM reports carry no policy
//     object. (--fail-on only sets the process exit code; it is not part of
//     the report.) The summary therefore gives a risk rating but no verdict.
//   - Three finding types feed the rating instead of two: known weaknesses in
//     fingerprinted software, web/DNS/TLS configuration gaps, and credentials
//     exposed in client-side JavaScript.
//   - Coverage matters more here (unreachable names, hosts skipped by the
//     safety guard, components whose version could not be pinned down, a
//     failed subdomain-discovery lookup), so it has its own section.
//
// Exploit intelligence and fixes (same inputs as the SCA summary): CISA KEV
// membership and FIRST EPSS scores (stamped on each vulnerability by the scan,
// see ./scan.js) feed the rating, the priority ranking and the figures, and
// each component's `suggested_fixes` (sca/suggested_fixes.js) supplies the
// upgrade paths listed under "Components to fix first". A feed that was down
// is "unknown" (null), never zero.
//
// The rating and prioritization rules in buildMethodology() are a prose copy of
// overallRisk() / buildPriorityComponents() / the action builder below — if
// those change, update that text too.

import { createHash } from "node:crypto";
import { findClosestFixVersions, _vr_purlToEcosystem } from "../../sca/version_recommender.js";

const SEV_RANK  = { critical: 4, high: 3, medium: 2, low: 1, unknown: 0 };
const SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low", unknown: "Unrated" };

const RISK_LABEL = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Minimal", not_assessed: "Not assessed",
};

function plural(n, one, many) {
  return n === 1 ? one : (many || one + "s");
}

function count(n, one, many) {
  return `${n} ${plural(n, one, many)}`;
}

function pct(part, whole) {
  return whole > 0 ? Math.round((part / whole) * 100) : 0;
}

function sevKey(s) {
  const k = String(s || "unknown").toLowerCase();
  return k in SEV_RANK ? k : "unknown";
}

function joinList(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}

function hasFix(v) {
  return !!(v?.has_fix || (v?.fixed_versions || []).length > 0);
}

// Which exploit feeds actually answered. Falls back to the data itself when the
// report carries no threat_intel block (older reports).
function intelState(report, vulns) {
  const ti = report?.threat_intel || null;
  const kevKnown = ti?.kev ? ti.kev.status === "ok" : vulns.some(v => typeof v.is_kev === "boolean");
  const epssStatus = ti?.epss?.status;
  const epssKnown = ti?.epss ? (epssStatus === "ok" || epssStatus === "partial") : vulns.some(v => typeof v.epss_score === "number");
  return { kevKnown, epssKnown, epssPartial: epssStatus === "partial" };
}

// Targets can be given as full URLs, and a URL can embed credentials
// (https://user:token@host/). Userinfo is stripped from anything this summary
// prints about the scan subject.
function stripUserinfo(value) {
  if (typeof value !== "string") return value;
  return value.trim().replace(/^([a-z][a-z0-9+.-]*:\/\/)[^@\/\s]*@/i, "$1");
}

// Plain-language wording for each misconfiguration category emitted by
// misconfig_scan.js. A category this table doesn't know still gets a sensible
// generic entry (see themeFor()).
const CONFIG_THEMES = {
  "Exposed File": {
    title: "Sensitive files reachable from the internet",
    plain: "Configuration, source-code or diagnostic files (such as environment files, version-control folders or PHP information pages) can be downloaded by anyone. They often contain passwords, keys and internal details.",
  },
  "Email Security": {
    title: "Email impersonation protections missing or weak",
    plain: "The domain's anti-spoofing email settings (SPF, DMARC, DKIM) are missing or weak, which makes it easier for attackers to send fake email that appears to come from the organization.",
  },
  "TLS/SSL": {
    title: "Problems with encrypted (HTTPS) connections",
    plain: "Some systems offer no working HTTPS, present certificates that are expired, untrusted or for the wrong name, or still accept outdated encryption. Visitors' data could be intercepted, or browsers will show warnings.",
  },
  "Security Headers": {
    title: "Standard browser protections not switched on",
    plain: "Websites do not tell browsers to enable common safeguards (such as forcing HTTPS or blocking the site from being embedded in another). Individually minor, they make other attacks easier.",
  },
  "Cookies": {
    title: "Session cookies missing standard safeguards",
    plain: "Cookies set by these systems lack common protections, which raises the chance that a visitor's session could be stolen or misused.",
  },
  "CORS": {
    title: "Overly permissive cross-site access",
    plain: "Some websites let other websites read their responses in ways that could expose the data of logged-in users.",
  },
  "HTTP Methods": {
    title: "Risky web-server features enabled",
    plain: "Some web servers accept request types that are rarely needed and can help attackers (for example to change or delete content, or to trick browsers into revealing data).",
  },
  "WordPress": {
    title: "WordPress features that help attackers",
    plain: "WordPress interfaces that let outsiders list user names or attempt automated password guessing are open to the internet.",
  },
};

function themeFor(category) {
  return CONFIG_THEMES[category] || {
    title: `Security configuration issues (${category})`,
    plain: "Settings on these systems fall short of common security practice. See the Misconfigurations tab for the specific issues.",
  };
}

const BUSINESS_IMPACT = {
  critical:
    "Software on an internet-facing system matches a public malware advisory. Advisories occasionally name the wrong package or version, so first confirm the match is genuine. " +
    "If it is, treat the affected system as potentially compromised: isolate it, investigate how the component got there, and rebuild from a trusted source before putting it back in service.",
  high:
    "These weaknesses are visible to anyone on the internet, and attackers do not need access to your network to try them. " +
    "They could lead to stolen data, disrupted services or unauthorized access, and should be addressed first, before routine work.",
  medium:
    "The issues found are less likely to be exploited, or would cause limited damage if they were. " +
    "They can be handled through scheduled maintenance rather than emergency action.",
  low:
    "The issues found are minor and unlikely to cause meaningful harm on their own. They can be fixed during routine updates.",
  none:
    "No action is required based on this scan. The internet-facing footprint changes constantly (new systems appear and new weaknesses are published daily), " +
    "so it should still be re-checked regularly.",
  not_assessed:
    "This report does not say whether the systems are secure, because none of them could be examined. " +
    "Resolve why the targets could not be reached, then run the scan again.",
};

// ── One-page summary helpers ─────────────────────────────────────────────────
// The first screen / printed page of the executive summary (`cover` and
// `bottom_line`) is built from the same data as everything below it, just cut
// down to what a busy reader needs: the verdict, the three things that matter
// most, the three things to do first, and four numbers.

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
  return ["critical", "high", "medium", "low", "unknown"].find((k) => (sev?.[k] || 0) > 0) || null;
}

function sevSummary(sev) {
  return ["critical", "high", "medium", "low", "unknown"]
    .filter((k) => (sev?.[k] || 0) > 0)
    .map((k) => `${sev[k]} ${k === "unknown" ? "unrated" : k}`)
    .join(" / ");
}

// ── What kind of scan this was ───────────────────────────────────────────────
const MODES = {
  "ubel-url": {
    what: "an outside-in check of the specific web addresses it was given",
    discovery: "The list of systems to examine was supplied directly; nothing was discovered automatically.",
  },
  "ubel-domain": {
    what: "an outside-in check of every public name found for a domain in public certificate records",
    discovery: "Public names under the domain were discovered passively from Certificate Transparency logs (the public record of every HTTPS certificate issued), through crt.sh. A name that never had a logged certificate is not found unless it was added by hand.",
  },
  "ubel-host": {
    what: "an outside-in check of the hosts it was given (names and/or network addresses), covering the network ports in the range scanned on each address they point to",
    discovery: "The hosts to examine were supplied directly. Each name was resolved to a network address, every distinct address was port-scanned across the configured range, and each open port was then tried with web (HTTP/HTTPS) requests. Open ports that answered as web servers were examined further, along with the supplied names whose address answered on the standard web ports.",
  },
  "ubel-easm": {
    what: "an outside-in check of a domain's internet-facing footprint: its public names, the addresses they point to, and the network ports open on those addresses",
    discovery: "Public names were discovered passively from Certificate Transparency logs through crt.sh, resolved to network addresses, and each address was port-scanned across the configured range. Open ports that answered as web servers were then examined, along with the public names whose address answered on the standard web ports.",
  },
};

function describeScan(report) {
  const tool = report?.tool || "ubel-url";
  const mode = MODES[tool] || MODES["ubel-url"];
  return { tool, what: mode.what, discovery: mode.discovery };
}

function buildSubject(report) {
  const targets = Array.isArray(report?.targets) ? report.targets : [];
  const inputHosts = Array.isArray(report?.input_hosts) ? report.input_hosts : [];
  let name = report?.domain || report?.host || null;
  if (!name && inputHosts.length === 1) name = inputHosts[0];
  if (!name && inputHosts.length > 1) name = `${inputHosts[0]} and ${inputHosts.length - 1} other ${plural(inputHosts.length - 1, "host")}`;
  if (!name && targets.length === 1) name = stripUserinfo(targets[0]);
  if (!name && targets.length > 1) name = `${stripUserinfo(targets[0])} and ${targets.length - 1} other ${plural(targets.length - 1, "target")}`;
  return {
    name,
    domain: report?.domain || null,
    host: report?.host || null,
    port_range: report?.host || (report?.hosts || []).length ? (report?.port_range || report?.hosts?.[0]?.port_range || null) : null,
    scanned_at: report?.generated_at || null,
    tool: report?.tool ? `${report.tool}${report.tool_version ? " " + report.tool_version : ""}` : null,
  };
}

// ── Secrets coverage ─────────────────────────────────────────────────────────
// scan.js leaves `stats.secrets` as `{total: 0}` when the crawl was disabled and
// as `{pages_crawled, ...}` when it ran, so an explicit scan_options flag is
// preferred and the stats shape is only the fallback for reports built by a
// caller that doesn't pass it.
function secretsCoverage(report) {
  const sstats = report?.stats?.secrets || {};
  const errors = Array.isArray(report?.secrets_errors) ? report.secrets_errors : [];
  const opt = report?.scan_options?.scan_secrets;
  const enabled = typeof opt === "boolean" ? opt : sstats.pages_crawled !== undefined;
  const pages = sstats.pages_crawled || 0;
  let status;
  if (!enabled) status = "not_run";
  else if (pages === 0 && errors.length > 0) status = "failed";
  else if (pages === 0) status = "nothing_to_crawl";
  else if (errors.length > 0) status = "partial";
  else status = "complete";
  return { status, enabled, pages, errors: errors.length, known: status === "complete" || status === "partial" };
}

// ── Systems that are most exposed ────────────────────────────────────────────
// One row per scanned scope entry (a public name or a network address) that has
// at least one finding. Counts weaknesses and configuration gaps only: exposed
// credentials are attributed to a URL, not to a scope entry, so they are not
// ranked here (they have their own finding and action).
function buildSystemsToReview(report, limit = 5) {
  const misconfigs = Array.isArray(report?.misconfigurations) ? report.misconfigurations : [];
  const rows = [];
  for (const s of report?.scope || []) {
    if (s.status !== "scanned") continue;
    const targets = new Set(s.targets || []);
    const vs = s.vulnerabilities || [];
    const malicious = vs.some(v => v.is_infection);
    const weaknessCount = vs.filter(v => !v.is_infection).length;
    let worst = -1;
    for (const v of vs) if (!v.is_infection) worst = Math.max(worst, SEV_RANK[sevKey(v.severity)]);

    let configIssues = 0;
    for (const g of misconfigs) {
      const here = (g.occurrences || []).filter(o => targets.has(o.target));
      if (!here.length) continue;
      configIssues++;
      for (const o of here) worst = Math.max(worst, SEV_RANK[sevKey(o.severity)]);
    }

    if (!malicious && weaknessCount === 0 && configIssues === 0) continue;
    const worstKey = Object.keys(SEV_RANK).find(k => SEV_RANK[k] === worst) || "unknown";
    rows.push({
      name: s.name,
      kind: s.type === "ip" ? "Network address" : "Public name",
      weaknesses: weaknessCount,
      configuration_issues: configIssues,
      malicious_components: malicious,
      worst_severity: malicious ? "malicious" : worstKey,
      worst_severity_label: malicious ? "Malicious" : SEV_LABEL[worstKey],
      _rank: [malicious ? 1 : 0, worst, weaknessCount + configIssues],
    });
  }
  rows.sort((a, b) => {
    for (let i = 0; i < a._rank.length; i++) {
      if (a._rank[i] !== b._rank[i]) return b._rank[i] - a._rank[i];
    }
    return String(a.name).localeCompare(String(b.name), undefined, { numeric: true });
  });
  return rows.slice(0, limit).map(({ _rank, ...r }) => r);
}

// ── Components to fix first ──────────────────────────────────────────────────
// Same upgrade heuristic as the SCA summary: for each weakness take the closest
// fixed version already ranked by the engine, then the highest of those. It
// assumes that version also covers the other weaknesses, which is not verified
// (fix ranges can differ per release branch). Indicative only.
function suggestUpgrade(currentVersion, vulns, id) {
  const picks = [];
  for (const v of vulns) {
    const rec = (v.fix_versions_ranked || []).find(r => r.recommended) || (v.fix_versions_ranked || [])[0];
    if (rec?.version) picks.push(rec.version);
  }
  const unique = [...new Set(picks)];
  if (!unique.length) return null;
  if (unique.length === 1) return unique[0];
  try {
    const ranked = findClosestFixVersions(currentVersion || "", unique, _vr_purlToEcosystem(id || ""));
    if (ranked.length) return ranked[ranked.length - 1].version;
  } catch { /* fall through */ }
  return unique[unique.length - 1];
}

// Upgrade target from the per-package `suggested_fixes` analysis. Its `fixes`
// are ordered closest-first (minor ranges, then major) and are branch-aware, so
// the best single upgrade is the closest one that resolves the most of the
// component's issues (ties keep the closer one). Returns null when the analysis
// is missing or failed, so the caller falls back to suggestUpgrade().
function planUpgrade(item, totalIssues) {
  const sf = item?.suggested_fixes;
  if (!sf || sf.error || !Array.isArray(sf.fixes)) return null;
  const real = list => (list || []).filter(x => !x?.is_infection).length;
  let best = null;
  for (const f of sf.fixes) {
    if (!f?.version) continue;
    const cleared = Array.isArray(f.vulnerabilities) ? real(f.vulnerabilities) : (f.count || 0);
    if (cleared > 0 && (!best || cleared > best.cleared)) best = { version: f.version, cleared, scope: f.range?.scope || null };
  }
  const unfixed = real(sf.unfixed);
  return best
    ? { ...best, total: totalIssues, unfixed }
    : { version: null, cleared: 0, scope: null, total: totalIssues, unfixed };
}

// Every upgrade path from `suggested_fixes`, closest first, for the "Possible
// fixes" list under a component: how many of its issues each version resolves
// and how many of the known-exploited ones. At most `limit` are listed; the
// recommended one is always kept.
const FIX_OPTIONS_LIMIT = 5;

function buildFixOptions(item, nonInf, bestVersion, limit = FIX_OPTIONS_LIMIT) {
  const sf = item?.suggested_fixes;
  if (!sf || sf.error || !Array.isArray(sf.fixes)) return { options: [], more: 0, noFixYet: 0 };
  const kevIds = new Set(nonInf.filter(v => v.is_kev === true).map(v => v.id));
  const all = [];
  for (const f of sf.fixes) {
    if (!f?.version) continue;
    const list = Array.isArray(f.vulnerabilities) ? f.vulnerabilities.filter(x => !x?.is_infection) : null;
    const resolves = list ? list.length : (f.count || 0);
    if (!resolves) continue;
    all.push({
      version: f.version,
      range: f.range?.label || null,
      scope: f.range?.scope || null,          // "minor" | "major" (may break things)
      resolves,
      of: nonInf.length,
      resolves_known_exploited: list ? list.filter(x => kevIds.has(x.id)).length : 0,
      known_exploited_total: kevIds.size,
      recommended: !!bestVersion && f.version === bestVersion,
    });
  }
  let options = all;
  if (all.length > limit) {
    options = all.slice(0, limit);
    const rec = all.find(o => o.recommended);
    if (rec && !options.includes(rec)) options = [...all.slice(0, limit - 1), rec];
  }
  const noFixYet = (sf.unfixed || []).filter(x => !x?.is_infection).length;
  return { options, more: all.length - options.length, noFixYet };
}

function describeUpgrade(plan) {
  let text = `Upgrade to version ${plan.version}`;
  if (plan.scope === "major") text += " (a major version change, so test for breaking changes)";
  text += ".";
  if (plan.cleared < plan.total) {
    const left = plan.total - plan.cleared;
    text += ` This resolves ${plan.cleared} of ${plan.total} issues; ` +
      (plan.unfixed >= left
        ? `${left === 1 ? "the other has" : `the other ${left} have`} no published fix yet.`
        : "the rest need a different upgrade path (see the possible fixes listed here or in the component's details).");
  }
  return text;
}

function hostsOfItem(item) {
  return [...new Set((item?.assets || []).map(a => a.host).filter(Boolean))];
}

function buildPriorityComponents(vulns, inventory, epssMin, limit = 5) {
  const itemById = new Map(inventory.map(i => [i.id, i]));
  const byPkg = new Map();
  for (const v of vulns) {
    const key = v.affected_package_id || `${v.affected_dependency}@${v.affected_dependency_version}`;
    if (!byPkg.has(key)) {
      const item = itemById.get(v.affected_package_id);
      byPkg.set(key, {
        id: v.affected_package_id || null,
        name: item?.name || v.affected_dependency || "unknown",
        version: item?.version || v.affected_dependency_version || "",
        hosts: hostsOfItem(item),
        vulns: [],
      });
    }
    byPkg.get(key).vulns.push(v);
  }

  const rows = [...byPkg.values()].map(p => {
    const malicious = p.vulns.some(v => v.is_infection);
    const nonInf = p.vulns.filter(v => !v.is_infection);
    const worst = nonInf.reduce((w, v) => Math.max(w, SEV_RANK[sevKey(v.severity)]), -1);
    const worstKey = Object.keys(SEV_RANK).find(k => SEV_RANK[k] === worst) || "unknown";
    const fixable = nonInf.filter(hasFix);
    const item = itemById.get(p.id);
    const plan = malicious ? null : planUpgrade(item, nonInf.length);
    const upgradeTo = malicious ? null : plan ? plan.version : suggestUpgrade(p.version, fixable, p.id);
    const fixOpts = malicious ? { options: [], more: 0, noFixYet: 0 } : buildFixOptions(item, nonInf, plan ? plan.version : null);
    // Exploit intelligence. Everything an EASM scan sees is exposed, so there is
    // no reachability discount: any KEV entry counts for ranking.
    const kevAll = p.vulns.filter(v => v.is_kev === true);
    const exploited = kevAll.length > 0;
    const epssVals = p.vulns.map(v => v.epss_score).filter(x => typeof x === "number");
    const maxEpss = epssVals.length ? Math.max(...epssVals) : null;
    const likelySoon = typeof epssMin === "number" && p.vulns.some(v => v.is_kev !== true && typeof v.epss_score === "number" && v.epss_score >= epssMin);
    return {
      name: p.name,
      version: p.version,
      issue_count: p.vulns.length,
      worst_severity: malicious ? "malicious" : worstKey,
      worst_severity_label: malicious ? "Malicious" : SEV_LABEL[worstKey],
      systems_affected: p.hosts.length,
      example_systems: p.hosts.slice(0, 3),
      known_exploited: kevAll.length,
      max_epss: maxEpss,
      upgrade_to: upgradeTo || null,
      // All possible upgrade paths (closest first), from sca/suggested_fixes.js.
      // Empty when that analysis is unavailable; `upgrade_to` / `action` still apply.
      fix_options: fixOpts.options,
      fix_options_more: fixOpts.more,
      no_fix_yet: fixOpts.noFixYet,
      // Advisory identifiers, most serious first, for tickets and auditors. Kept
      // out of the plain-language text on purpose.
      references: [...p.vulns]
        .sort((a, b) => (b.is_infection ? 5 : SEV_RANK[sevKey(b.severity)]) - (a.is_infection ? 5 : SEV_RANK[sevKey(a.severity)]))
        .map(v => v.id).filter(Boolean).slice(0, 5),
      more_references: Math.max(0, p.vulns.length - 5),
      action: malicious
        ? "Treat every system running this as potentially compromised: isolate it, investigate, and rebuild from a trusted source."
        : plan && plan.version
          ? describeUpgrade(plan)
          : upgradeTo
          ? `Upgrade to version ${upgradeTo}${fixable.length < nonInf.length ? " (some issues have no fix yet; see technical details)" : ""}`
          : "No fixed version is published yet. Consider restricting access to the system, adding protection in front of it, or replacing the software.",
      _rank: [malicious ? 1 : 0, exploited ? 1 : 0, worst, likelySoon ? 1 : 0, p.hosts.length, p.vulns.length],
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

// ── Overall risk ─────────────────────────────────────────────────────────────
// Highest applicable level wins. Unrated severities count as Medium, the same
// choice the SCA summary makes. `m.hidden` is the number of weaknesses the
// --min-severity filter removed from this report: their severity is unknown to
// the summary, so the rating is floored at Low rather than allowed to read as
// Minimal.
function overallRisk(m) {
  const r = overallRiskCore(m);
  // A low/medium rating can hide a known-exploited weakness when the exploit
  // feeds were down, so say so instead of letting the rating read as final.
  if (m.vulns_assessed && m.intel_incomplete && (r.level === "low" || r.level === "medium")) {
    r.rationale += " Exploit data was not fully available, so this rating could be understated.";
  }
  return r;
}

function overallRiskCore(m) {
  if (!m.reached) {
    return {
      level: "not_assessed",
      rationale: "No web system could be examined (targets did not resolve, were skipped by the safety guard, failed, or none answered as a web server), so no security rating can be given.",
    };
  }
  if (m.malicious_components > 0) {
    return {
      level: "critical",
      rationale: `${count(m.malicious_components, "component")} on an internet-facing system matches a public malware advisory.`,
    };
  }
  const seriousVuln = m.vuln.critical + m.vuln.high;
  const seriousCfg = m.cfg.critical + m.cfg.high;
  if (seriousVuln > 0 || seriousCfg > 0 || m.secrets.serious > 0 || m.kev > 0) {
    const parts = [];
    if (seriousVuln) parts.push(count(seriousVuln, "Critical/High-severity software weakness", "Critical/High-severity software weaknesses"));
    if (seriousCfg) parts.push(count(seriousCfg, "Critical/High-severity configuration gap"));
    if (m.secrets.serious) parts.push(count(m.secrets.serious, "exposed High/Critical credential"));
    // A known-exploited weakness is High however it is scored: attackers are already using it.
    if (m.kev) parts.push(count(m.kev, "weakness already exploited in real attacks", "weaknesses already exploited in real attacks"));
    return { level: "high", rationale: `Includes ${joinList(parts)}. These are reachable from the internet and could be used against the organization.` };
  }
  if (m.vuln.medium > 0 || m.vuln.unknown > 0 || m.cfg.medium > 0 || m.cfg.unknown > 0 || m.secrets.total > 0) {
    return { level: "medium", rationale: "Moderate issues were found that should be fixed as part of normal maintenance." };
  }
  if (m.vuln.low > 0 || m.cfg.low > 0) {
    return { level: "low", rationale: "Only low-severity issues were found." };
  }
  if (m.hidden > 0) {
    return {
      level: "low",
      rationale: `${count(m.hidden, "weakness", "weaknesses")} below the report's minimum-severity filter ${plural(m.hidden, "was", "were")} left out of this report, so a Minimal rating cannot be given. The true rating could be higher.`,
    };
  }
  const nothingChecked = !m.vulns_assessed && !m.cfg_checked && !m.secrets.known;
  if (nothingChecked) {
    return {
      level: "not_assessed",
      rationale: "None of the checks could run against the systems reached, so no security rating can be given.",
    };
  }
  const gaps = m.gaps.length ? ` This is not a full all-clear: ${joinList(m.gaps)}.` : "";
  return { level: "none", rationale: `No known weaknesses, configuration gaps or exposed credentials were found in what could be checked.${gaps}` };
}

// ── Methodology ──────────────────────────────────────────────────────────────
// Describes how THIS report was produced. Steps are included only when the
// corresponding stage actually ran, so the text never claims work that wasn't
// done.
function buildMethodology(report, ctx) {
  const { scan, secretsInfo, vulnsAssessed, cfgChecked, reached, notChecked, hidden, minSeverity, discovery, intel } = ctx;
  const opts = report?.scan_options || {};
  const hasCompliance = Array.isArray(report?.compliance_summary?.frameworks);
  const steps = [];

  // 1. Scope and discovery
  let disc = scan.discovery;
  if (discovery) {
    if (discovery.ok === false) {
      disc += " The public-record lookup FAILED during this scan, so the list of names is incomplete" +
        ((discovery.hosts_included || 0) > 0 ? " (only names added by hand were examined)." : " and may be empty.");
    } else if (typeof discovery.hosts_discovered === "number") {
      disc += ` It returned ${count(discovery.hosts_discovered, "name")}` +
        ((discovery.hosts_included || 0) > 0 ? `, plus ${count(discovery.hosts_included, "name")} added by hand` : "") +
        ((discovery.hosts_excluded || 0) > 0 ? `, with ${count(discovery.hosts_excluded, "name")} deliberately excluded` : "") + ".";
    }
  }
  steps.push({ step: "Scope and discovery", detail: disc });

  // 2. Name resolution and safety guard
  steps.push({
    step: "Name resolution and safety guard",
    detail: "Each name was looked up in DNS first. Names that no longer exist are listed as unreachable and are not probed. " +
      (report?.allow_private
        ? "The safety guard that normally skips private and internal addresses was switched OFF for this scan."
        : "Names or addresses that point to private networks, or to the machine running the scan, were skipped rather than scanned, and are reported as skipped."),
  });

  // 3. Fingerprinting
  const authBits = [];
  if (opts.used_cookie) authBits.push("a session cookie");
  if ((opts.custom_header_names || []).length) authBits.push(`custom request headers (${opts.custom_header_names.join(", ")})`);
  steps.push({
    step: "Software identification",
    detail: "For each reachable web system, the scanner sent ordinary web requests and recorded the software and versions the system discloses (server banners, response headers, page markup, and a small number of well-known paths). " +
      "No weakness was exploited. " +
      (authBits.length
        ? `The identification requests carried ${joinList(authBits)} supplied by the operator, so they reflect a signed-in view; the credential search and configuration checks below always run without them.`
        : "All requests were made without logging in."),
  });

  // 4. Known-weakness lookup
  if (vulnsAssessed) {
    steps.push({
      step: "Known-weakness lookup",
      detail: "Each identified component with a specific enough version was checked against public vulnerability sources at the time of the scan: the U.S. National Vulnerability Database (NVD) for most software, OSV.dev for packages it could name precisely, and wpvulnerability.net for WordPress core, plugins and themes. " +
        (report?.osv_endpoint || report?.nvd_endpoint || report?.wpvulnerability_endpoint ? "At least one source was replaced by a custom mirror for this scan. " : "") +
        "Only weaknesses published by then can be found. " +
        (notChecked > 0 ? `${count(notChecked, "component")} had a missing or too-vague version (for example just “3”) and ${plural(notChecked, "was", "were")} listed but not checked, because matching on a vague version produces misleading results.` : ""),
    });
    {
      const bits = [];
      bits.push(intel.kevKnown
        ? "each weakness was checked against the U.S. CISA Known Exploited Vulnerabilities catalog (weaknesses attackers are already using)"
        : "the CISA Known Exploited Vulnerabilities catalog could NOT be reached, so which weaknesses are already being exploited is unknown");
      bits.push(intel.epssKnown
        ? "and given a FIRST EPSS score, a statistical estimate of how likely it is to be exploited in the next 30 days" + (intel.epssPartial ? " (scores were missing for some)" : "")
        : "and the FIRST EPSS exploit-likelihood estimates could NOT be reached");
      steps.push({
        step: "Exploit intelligence",
        detail: "Weaknesses with a CVE identifier were enriched at the time of the scan: " + bits.join(", ") + ". " +
          "A known-exploited weakness raises the rating to at least High regardless of its severity score. EPSS is an estimate, not a finding, and only influences the order in which components are listed.",
      });
    }
    steps.push({
      step: "Malicious-software check",
      detail: "Components that match public malware advisories (identifiers starting with “MAL-”) are reported separately from ordinary weaknesses and always raise the rating to Critical.",
    });
  } else {
    steps.push({
      step: "Known-weakness lookup (not performed)",
      detail: reached
        ? "No identified component had a version specific enough to look up, so no weaknesses were checked for. The absence of weakness findings below says nothing about them."
        : "No system could be examined, so no weaknesses were checked for.",
    });
  }

  // 5. Configuration checks
  if (cfgChecked) {
    steps.push({
      step: "Configuration checks",
      detail: "Each reachable system was tested with a fixed set of well-known checks: exposed sensitive files, WordPress interfaces (where WordPress was detected), risky web-server methods, cross-site access settings, HTTPS certificate and encryption quality, standard browser protection settings, cookie safeguards, and email anti-spoofing records (SPF, DMARC, DKIM) in DNS. " +
        "Identical issues on many systems are grouped into one finding that lists where it was seen. These checks never log in.",
    });
  } else {
    steps.push({
      step: "Configuration checks (not performed)",
      detail: "No system was reachable, so no configuration checks were run.",
    });
  }

  // 6. Credential search
  if (secretsInfo.enabled) {
    steps.push({
      step: "Exposed-credential search",
      detail: "The JavaScript each reachable website serves (inline code and the script files it references, one level deep) was searched for patterns that look like passwords, access keys and tokens. " +
        "Matches are pattern-based, so some may be false alarms and some real credentials may not match any pattern. Only a redacted preview of each match appears in the report; full values are never written to it.",
    });
  }

  // 7. Filter
  if (minSeverity && minSeverity !== "unknown") {
    steps.push({
      step: "Severity filter",
      detail: `This scan was run with a minimum-severity filter of “${minSeverity}”, so weaknesses below that level were left out of the vulnerability list and of every weakness figure in this summary` +
        (hidden > 0 ? ` (${count(hidden, "weakness", "weaknesses")} hidden)` : "") +
        ". Software components and their per-component counts always reflect the full scan.",
    });
  }

  // 8. Compliance
  if (hasCompliance) {
    steps.push({
      step: "Compliance mapping",
      detail: "Each finding was linked to related controls in common security frameworks using fixed mapping tables. Configuration and credential findings are mapped by type of problem, not by how a control is actually implemented. This is guidance for an audit conversation, not an assessment of compliance.",
    });
  }

  const ratingRules = [
    { level: "Critical", rule: "At least one component matches a public malware advisory." },
    { level: "High", rule: "At least one Critical- or High-severity software weakness, a weakness listed by CISA as already exploited in real attacks (whatever its severity), Critical- or High-severity configuration gap, or exposed High/Critical credential." },
    { level: "Medium", rule: "Medium or unrated weaknesses or configuration gaps, or lower-severity exposed credentials." },
    { level: "Low", rule: "Only Low-severity weaknesses or configuration gaps." },
    { level: "Minimal", rule: "Nothing found in the checks that ran." },
    { level: "Not assessed", rule: "No system could be examined, or none of the checks could run, so no rating is given instead of “Minimal”." },
  ];

  const prioritization =
    "“Components to fix first” ranks software components by: (1) matches a malware advisory, (2) has a weakness already exploited in real attacks, (3) worst severity, (4) has a weakness with a high exploit-likelihood estimate, (5) number of systems running it, (6) number of issues, and lists the top five. " +
    "“Systems to review first” ranks public names and network addresses by the same first two factors, then by number of weaknesses plus configuration issues. " +
    "For each component the “possible fixes” list shows every upgrade path, closest release line first, with how many of its issues (and how many exploited ones) each version resolves; the one marked Best is the closest that resolves the most. Where that analysis is unavailable the suggestion is the highest of the closest published fixes. Either way it is a starting point and has not been tested against your systems. " +
    "Every finding is treated as exposed, because everything this scan can see is reachable from the internet; there is no “probably not in use” discount.";

  const timeframes =
    "The timeframes in “Suggested actions” are default guidance built into the tool (credentials, exposed files and malicious software: immediately; serious weaknesses and gaps: within days; the rest: next maintenance cycle). " +
    "They are not taken from your organization's remediation policy or SLAs. The suggested owners are likewise generic defaults, not assignments. Replace both with your own where those differ.";

  const limitations = [
    "This is an outside-in, point-in-time view of what each system chose to disclose. Anything an attacker could only learn from inside the network, or after logging in, is out of scope.",
    "Software is matched to weaknesses by the name and version it announces. A system that hides its version is not matched, and a system that applies fixes without changing its version number (common with Linux distributions) can be flagged for a weakness it no longer has. Verify each finding before acting on it.",
    "Severity ratings come from the public advisories (for software) or from this tool's own rules (for configuration and credentials). They describe the issue in general, not its effect on your business.",
    "Exploit data comes from two public feeds at the time of the scan. A CVE missing from the CISA catalog is not proof it is safe, EPSS is a probability rather than a fact, and weaknesses without a CVE identifier cannot be matched to either feed.",
    "The tool does not exploit weaknesses or test how the systems behave under attack. It identifies known issues and common mistakes.",
    "Weaknesses with no public advisory, flaws in your own code, and anything on systems that were not found or not reachable are outside this scan. A clean result is not proof of safety.",
    "The recommended actions are generated from the counts in this report; they do not account for what each system does or how important it is.",
  ];
  if (scan.tool === "ubel-domain" || scan.tool === "ubel-easm") {
    limitations.push("Certificate Transparency records are permanent history, so the discovered names include systems retired long ago, and omit systems that never had a publicly logged certificate.");
  }
  if (scan.tool === "ubel-host" || scan.tool === "ubel-easm") {
    limitations.push("Only network ports inside the configured range were tested, and only those that answered as web servers were examined for software and configuration issues. Other services on open ports are listed but not assessed.");
  }
  if (notChecked > 0) {
    limitations.push("Components whose version could not be determined cannot be matched against vulnerability sources and are not covered.");
  }

  return { steps, rating_rules: ratingRules, prioritization, timeframes, limitations };
}

// ── Main ─────────────────────────────────────────────────────────────────────
export function buildExecutiveSummary(report) {
  const vulns = Array.isArray(report?.vulnerabilities) ? report.vulnerabilities : [];
  const inventory = Array.isArray(report?.inventory) ? report.inventory : [];
  const assets = Array.isArray(report?.assets) ? report.assets : [];
  const secretsList = Array.isArray(report?.secrets) ? report.secrets : [];
  const misconfigs = Array.isArray(report?.misconfigurations) ? report.misconfigurations : [];
  const stats = report?.stats || {};
  const opts = report?.scan_options || {};
  const scan = describeScan(report);
  const discovery = report?.discovery || null;
  const minSeverity = opts.min_severity || null;

  // ── Coverage: which systems were actually examined ───────────────────────
  const statusCounts = { scanned: 0, skipped: 0, error: 0, dead: 0 };
  for (const a of assets) statusCounts[a.status in statusCounts ? a.status : "error"]++;
  const deadNames = new Set(assets.filter(a => a.status === "dead").map(a => String(a.target).toLowerCase()));
  for (const d of report?.dead_hostnames || []) if (d?.hostname) deadNames.add(String(d.hostname).toLowerCase());

  const hostScans = Array.isArray(report?.hosts) ? report.hosts : [];
  const ipSkipped = hostScans.filter(h => h.status === "skipped").length;
  const ipFailed = hostScans.filter(h => h.status === "error").length;
  const ipScanned = hostScans.filter(h => h.status === "scanned").length;
  const openPorts = hostScans.length
    ? hostScans.filter(h => h.status === "scanned").reduce((n, h) => n + (h.open_ports || []).length, 0)
    : (report?.host ? (report.open_ports || []).length : null);

  const reached = statusCounts.scanned;
  const skipped = statusCounts.skipped + ipSkipped;
  const failed = statusCounts.error + ipFailed;
  const unreachable = deadNames.size;
  const systemsTotal = assets.length + [...deadNames].filter(n => !assets.some(a => String(a.target).toLowerCase() === n)).length + ipSkipped + ipFailed;

  // ── Weaknesses ───────────────────────────────────────────────────────────
  const infections = vulns.filter(v => v.is_infection);
  const regular = vulns.filter(v => !v.is_infection);
  const bySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const v of regular) bySeverity[sevKey(v.severity)]++;

  const withFix = regular.filter(hasFix).length;

  // ── Exploit intelligence (CISA KEV + FIRST EPSS) ──────────────────────────
  const intel = intelState(report, vulns);
  const epssT = typeof opts.epss_threshold === "number" ? opts.epss_threshold : null;
  const kevVulns = regular.filter(v => v.is_kev === true);
  const kevCount = kevVulns.length;
  const epssHigh = epssT === null ? [] : regular.filter(v => v.is_kev !== true && typeof v.epss_score === "number" && v.epss_score >= epssT);
  const intelIncomplete = regular.length > 0 && (!intel.kevKnown || !intel.epssKnown || intel.epssPartial);
  const maliciousComponents = new Set(infections.map(v => v.affected_package_id || v.affected_dependency)).size;
  const componentsReviewed = stats.component_count ?? inventory.length;
  const notChecked = inventory.filter(i => i.low_confidence_version).length;
  const checked = inventory.length - notChecked;
  const vulnsAssessed = checked > 0;
  // Components affected = with a known weakness OR flagged as malicious. Taken
  // from the inventory state (not the possibly severity-filtered vulnerability
  // list) so it agrees with the Components tab.
  const vulnerableComponents = (stats?.state_counts
    ? (stats.state_counts.vulnerable || 0) + (stats.state_counts.infected || 0)
    : new Set(vulns.map(v => v.affected_package_id)).size);

  // --min-severity removes findings from the list but not from the per-item
  // counts the engine stamps on each inventory entry, so the difference is how
  // many were hidden.
  const unfilteredTotal = inventory.reduce((n, i) => n + (Number(i.vulnerabilities_count) || 0), 0);
  const hidden = Math.max(0, unfilteredTotal - vulns.length);

  // Systems running a Critical/High weakness
  const seriousIds = new Set(regular.filter(v => ["critical", "high"].includes(sevKey(v.severity))).map(v => v.affected_package_id));
  const seriousSystems = new Set();
  for (const item of inventory) if (seriousIds.has(item.id)) for (const h of hostsOfItem(item)) seriousSystems.add(h);

  const hostsOfVulns = list => {
    const ids = new Set(list.map(v => v.affected_package_id));
    const hosts = new Set();
    for (const item of inventory) if (ids.has(item.id)) for (const h of hostsOfItem(item)) hosts.add(h);
    return hosts;
  };
  const kevSystems = hostsOfVulns(kevVulns);
  const epssSystems = hostsOfVulns(epssHigh);

  // ── Configuration gaps ───────────────────────────────────────────────────
  const mstats = stats.misconfigurations || {};
  const cfgChecked = (mstats.hosts_checked || 0) > 0;
  const cfgBySeverity = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  const cfgSystems = new Set();
  for (const g of misconfigs) {
    cfgBySeverity[sevKey(g.severity)]++;
    for (const t of g.targets || []) cfgSystems.add(t);
  }
  const themeMap = new Map();
  for (const g of misconfigs) {
    const cat = g.category || "Other";
    if (!themeMap.has(cat)) themeMap.set(cat, { category: cat, issues: 0, targets: new Set(), worst: -1, worstKey: "unknown" });
    const t = themeMap.get(cat);
    t.issues++;
    for (const x of g.targets || []) t.targets.add(x);
    const k = sevKey(g.severity);
    if (SEV_RANK[k] > t.worst) { t.worst = SEV_RANK[k]; t.worstKey = k; }
  }
  const themes = [...themeMap.values()]
    .sort((a, b) => b.worst - a.worst || b.issues - a.issues || a.category.localeCompare(b.category))
    .map(t => ({
      category: t.category,
      title: themeFor(t.category).title,
      plain: themeFor(t.category).plain,
      issues: t.issues,
      systems_affected: t.targets.size,
      worst_severity: t.worstKey,
      worst_severity_label: SEV_LABEL[t.worstKey],
      worst_rank: t.worst,
    }));
  const cfgErrors = Array.isArray(report?.misconfigurations_errors) ? report.misconfigurations_errors.length : 0;

  // ── Credentials ──────────────────────────────────────────────────────────
  const secretSev = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const f of secretsList) secretSev[sevKey(f.severity)]++;
  const cov = secretsCoverage(report);
  const secretsInfo = {
    ...cov,
    total: secretsList.length,
    serious: secretSev.critical + secretSev.high,
    by_severity: secretSev,
    affected_urls: stats?.secrets?.affected_urls || new Set(secretsList.map(f => f.url)).size,
  };

  // ── Coverage gaps (used in the rating text, headline and notes) ──────────
  const gaps = [];
  if (discovery && discovery.ok === false) gaps.push("the lookup that discovers the domain's public names failed, so some systems may not have been examined");
  if (reached && checked === 0 && notChecked === 0) gaps.push("no software with a usable version was identified, so no weakness lookup was possible");
  if (notChecked > 0 && reached) gaps.push(`${count(notChecked, "software component")} could not be checked for weaknesses because its version is unknown or too vague`);
  if (secretsInfo.status === "failed") gaps.push("the search for exposed credentials failed");
  else if (secretsInfo.status === "partial") gaps.push(`the credential search could not read ${count(secretsInfo.errors, "page or script")}`);
  if (cfgErrors > 0) gaps.push(`${count(cfgErrors, "configuration check")} could not complete`);
  if (skipped > 0) gaps.push(`${count(skipped, "target")} ${plural(skipped, "was", "were")} skipped by the private-address safety guard`);
  if (failed > 0) gaps.push(`${count(failed, "target")} could not be examined because of an error`);

  const m = {
    reached,
    malicious_components: maliciousComponents,
    vuln: bySeverity,
    cfg: cfgBySeverity,
    secrets: secretsInfo,
    hidden,
    vulns_assessed: vulnsAssessed,
    cfg_checked: cfgChecked,
    kev: kevCount,
    intel_incomplete: intelIncomplete,
    gaps,
  };
  const risk = overallRisk(m);

  // ── Headline ─────────────────────────────────────────────────────────────
  // Risk level first, then the (at most three) things driving it, in priority
  // order. Everything else is summed up as "lower-priority issues" so the
  // sentence stays readable however long the findings list is.
  const issueTotal = regular.length + infections.length;
  const anyFinding = issueTotal > 0 || misconfigs.length > 0 || secretsInfo.total > 0 || hidden > 0;
  const seriousVulnCount = bySeverity.critical + bySeverity.high;
  const seriousCfgCount = cfgBySeverity.critical + cfgBySeverity.high;
  const lowerVulnCount = regular.length - seriousVulnCount;
  const lowerCfgCount = misconfigs.length - seriousCfgCount;
  const drivers = [];
  if (maliciousComponents > 0) drivers.push(count(maliciousComponents, "malicious component"));
  if (kevCount > 0) drivers.push(count(kevCount, "weakness already exploited in real attacks", "weaknesses already exploited in real attacks"));
  if (seriousVulnCount > 0) drivers.push(`${count(seriousVulnCount, "serious software weakness", "serious software weaknesses")}`);
  if (seriousCfgCount > 0) drivers.push(count(seriousCfgCount, "serious configuration issue"));
  if (secretsInfo.total > 0) drivers.push(count(secretsInfo.total, "exposed credential"));
  if (lowerVulnCount > 0) drivers.push(`${count(lowerVulnCount, "lower-severity weakness", "lower-severity weaknesses")}`);
  if (lowerCfgCount > 0) drivers.push(count(lowerCfgCount, "lower-severity configuration issue"));
  if (!drivers.length && hidden > 0) drivers.push(`${count(hidden, "weakness", "weaknesses")} hidden by the minimum-severity filter`);
  const shown = drivers.slice(0, 3);
  const more = drivers.length > 3;

  // `summary` is the sentence shown under the risk banner (which already names
  // the level); `headline` is the same sentence with the level in front, for the
  // JSON and any consumer that shows it on its own.
  let summary;
  if (risk.level === "not_assessed") {
    summary = systemsTotal === 0
      ? "No web system was found to examine."
      : `None of the ${count(systemsTotal, "target")} given could be examined` +
        (unreachable ? ` (${unreachable} no longer ${plural(unreachable, "exists", "exist")} in DNS).` : ".");
  } else if (!anyFinding) {
    summary = `No known weaknesses, configuration issues or exposed credentials were found across ${count(reached, "internet-facing system")}.` +
      (gaps.length ? ` This is not a full all-clear: ${joinList(gaps)}.` : "");
  } else {
    summary = `Found across ${count(reached, "internet-facing system")}: ${joinList(shown)}${more ? ", plus lower-priority issues" : ""}.`;
  }
  const headline = `${risk.level === "not_assessed" ? "Risk not assessed" : RISK_LABEL[risk.level] + " risk"}. ${summary}`;

  // ── Key findings ─────────────────────────────────────────────────────────
  const keyFindings = [];

  if (risk.level === "not_assessed") {
    keyFindings.push({
      severity: "medium",
      title: "No system could be examined",
      detail: (systemsTotal === 0
        ? "No target answered as a web server, so there was nothing to examine. "
        : `Of ${count(systemsTotal, "target")}, ${unreachable} did not exist in DNS, ${skipped} ${plural(skipped, "was", "were")} skipped by the safety guard and ${failed} failed. `) +
        "This report says nothing about whether the systems are secure.",
    });
  }
  if (discovery && discovery.ok === false) {
    keyFindings.push({
      severity: "medium",
      title: "Discovery of the domain's public names failed",
      detail: "The public-record lookup used to find the domain's systems did not succeed, so the list of systems examined may be incomplete or empty. A short list in this report does not mean a small footprint.",
    });
  }
  if (secretsInfo.status === "failed") {
    keyFindings.push({
      severity: "medium",
      title: "Credential search did not complete",
      detail: "The search for exposed passwords and access keys could not read any website, so no result is available. The absence of credential findings here does not mean none exist.",
    });
  }

  if (maliciousComponents > 0) {
    keyFindings.push({
      severity: "critical",
      title: "Malicious software detected",
      detail: `${count(maliciousComponents, "component was", "components were")} flagged as deliberately harmful (for example, packages created to steal data or take control of systems). ` +
        "Unlike ordinary bugs, these are built to cause damage. Advisories occasionally name the wrong package or version, so confirm the match before acting.",
    });
  }

  if (kevCount > 0) {
    keyFindings.push({
      severity: "high",
      title: "Weaknesses already being exploited by attackers",
      detail: `${count(kevCount, "weakness is", "weaknesses are")} on the U.S. government's list of vulnerabilities known to be exploited in real attacks, affecting ${count(kevSystems.size, "system")}. ` +
        "Whatever the severity score, these are the most urgent software fixes: attackers are not just able to use them, they already do.",
    });
  }
  if (epssHigh.length > 0) {
    keyFindings.push({
      severity: "medium",
      title: "Weaknesses with a high chance of being exploited soon",
      detail: `${count(epssHigh.length, "further weakness", "further weaknesses")}, on ${count(epssSystems.size, "system")}, ${plural(epssHigh.length, "has", "have")} a high statistical likelihood (at least ${parseFloat((epssT * 100).toFixed(2))}%) of being exploited in the next 30 days. ` +
        "This is an estimate, not a confirmed attack, but it is a good guide for what to patch first.",
    });
  }
  if (regular.length > 0 && intelIncomplete) {
    keyFindings.push({
      severity: "medium",
      title: "Exploit data was not fully available",
      detail: (!intel.kevKnown
        ? "The list of weaknesses known to be exploited could not be reached, so it is unknown whether any of the weaknesses found are already being attacked. "
        : "") +
        (!intel.epssKnown
          ? "The exploit-likelihood estimates could not be reached. "
          : intel.epssPartial ? "Exploit-likelihood estimates were missing for some weaknesses. " : "") +
        "The rating and priority order may understate the urgency; re-run the scan when the feeds are reachable.",
    });
  }

  const seriousTotal = bySeverity.critical + bySeverity.high;
  if (seriousTotal > 0) {
    keyFindings.push({
      severity: bySeverity.critical > 0 ? "critical" : "high",
      title: "Serious weaknesses in internet-facing software",
      detail: `${count(seriousTotal, "issue")} ${plural(seriousTotal, "is", "are")} rated Critical or High severity` +
        (bySeverity.critical ? ` (${bySeverity.critical} Critical, ${bySeverity.high} High)` : "") +
        `, affecting ${count(seriousSystems.size, "system")}. Because these systems are reachable from the internet, anyone can attempt to exploit them; ` +
        "the scan cannot tell whether a given weakness is actually exploitable in your setup.",
    });
  }

  for (const t of themes.filter(x => x.worst_rank >= SEV_RANK.high)) {
    keyFindings.push({
      severity: t.worst_severity,
      title: t.title,
      detail: `${t.plain} ${count(t.issues, "distinct issue")} found on ${count(t.systems_affected, "system")}; the most serious is rated ${t.worst_severity_label}.`,
    });
  }

  if (secretsInfo.total > 0) {
    keyFindings.push({
      severity: secretsInfo.serious > 0 ? "high" : "medium",
      title: "Passwords or access keys found in website code",
      detail: `${count(secretsInfo.total, "credential")} ${plural(secretsInfo.total, "was", "were")} found in JavaScript that any visitor can download. ` +
        "Anyone could use them to access the related services. They should be treated as compromised and replaced, not just removed.",
    });
  }

  const lowerThemes = themes.filter(x => x.worst_rank < SEV_RANK.high);
  if (lowerThemes.length) {
    const lowerIssues = lowerThemes.reduce((n, t) => n + t.issues, 0);
    const worstLower = lowerThemes[0].worst_severity;
    keyFindings.push({
      severity: worstLower,
      title: "Other security configuration gaps",
      detail: `${count(lowerIssues, "lower-severity issue")} across ${joinList(lowerThemes.map(t => t.title.charAt(0).toLowerCase() + t.title.slice(1)))}. ` +
        "Individually they are limited, but together they weaken the overall security posture. Details are in the Misconfigurations tab.",
    });
  }

  if (regular.length > 0) {
    const noFix = regular.length - withFix;
    let title, detail, severity;
    if (withFix === regular.length) {
      title = "Fixes are available";
      severity = "low";
      detail = `A fixed version already exists for ${regular.length === 1 ? "the weakness" : `all ${regular.length} weaknesses`}. Updating the affected software resolves ${regular.length === 1 ? "it" : "them"}.`;
    } else if (withFix === 0) {
      title = "No published fixes yet";
      severity = "medium";
      detail = `None of the ${count(regular.length, "weakness", "weaknesses")} has a published fix yet. Options are to replace the software, limit access to it, or monitor for a patch.`;
    } else {
      title = pct(withFix, regular.length) >= 50 ? "Most weaknesses can be fixed by updating" : "Only some weaknesses can be fixed by updating";
      severity = "medium";
      detail = `A fixed version exists for ${withFix} of ${regular.length} weaknesses (${pct(withFix, regular.length)}%). ` +
        `The remaining ${noFix} ${plural(noFix, "has", "have")} no published fix yet and may need a workaround or a replacement.`;
    }
    // "Fixes are available" style findings are context, not a risk of their own,
    // so they never compete for the one-page top-three; "No published fixes" does.
    keyFindings.push({ severity, title, detail, info: withFix > 0 });
  }

  if (hidden > 0) {
    keyFindings.push({
      severity: "medium",
      title: "Some weaknesses were left out by a severity filter",
      detail: `${count(hidden, "weakness", "weaknesses")} below the minimum-severity filter “${minSeverity || "set"}” ${plural(hidden, "was", "were")} removed from this report. ` +
        "The rating and counts here cover only what remains, so the true picture could be worse. Run again without the filter for the full list.",
    });
  }

  if (notChecked > 0 && reached) {
    keyFindings.push({
      severity: "low",
      title: "Some software could not be checked",
      detail: `${count(notChecked, "software component")} ${plural(notChecked, "was", "were")} identified but the version could not be pinned down, so ${notChecked === 1 ? "it was" : "they were"} not checked for weaknesses. ${plural(notChecked, "Its", "Their")} real status is unknown, not safe.`,
      info: true,
    });
  }

  if (unreachable > 0 && reached) {
    keyFindings.push({
      severity: "low",
      title: "Names that no longer exist",
      detail: `${count(unreachable, "name")} found during discovery ${plural(unreachable, "no longer resolves", "no longer resolve")} in DNS and ${plural(unreachable, "was", "were")} not examined. ` +
        "Public certificate records keep history, so this is common and usually harmless; stale DNS entries can still be worth cleaning up.",
      info: true,
    });
  }

  if (skipped > 0) {
    keyFindings.push({
      severity: "low",
      title: "Targets skipped by the safety guard",
      detail: `${count(skipped, "target")} pointed to a private network or to the machine running the scan, so ${plural(skipped, "it was", "they were")} not scanned. ` +
        `${plural(skipped, "It is", "They are")} not covered by this report.`,
      info: true,
    });
  }

  if (keyFindings.length === 0) {
    keyFindings.push({
      severity: "low",
      title: "No significant findings",
      detail: "The scan did not find known weaknesses, configuration gaps, malicious components or exposed credentials in the systems it could examine.",
      info: true,
    });
  }

  // ── Recommended actions ──────────────────────────────────────────────────
  const actions = [];
  // `owner` is a default suggestion of which team usually handles this kind of
  // action, not an assignment; adjust to your own organization.
  const push = (timeframe, action, why, owner) => actions.push({ priority: actions.length + 1, timeframe, action, why, owner });

  if (risk.level === "not_assessed") {
    push("Before relying on this report",
      "Find out why none of the targets could be examined, then run the scan again.",
      "Names that do not exist, addresses the safety guard skips, or network errors all produce an empty report that gives no assurance about security.",
      "Security team");
  }
  if (discovery && discovery.ok === false) {
    push("Before relying on this report",
      "Re-run the scan so the domain's public names can be discovered, or list the known systems explicitly.",
      "The lookup that finds the domain's systems failed, so systems may be missing from this report.",
      "Security team");
  }
  if (maliciousComponents > 0) {
    push("Immediately",
      "Confirm the malicious-component match and, if genuine, isolate the affected systems and investigate.",
      "These components are designed to cause harm, but advisories occasionally name the wrong package or version, so verify first. If confirmed, check what the affected systems could reach and rotate any credentials they held.",
      "Security team");
  }
  if (secretsInfo.total > 0) {
    push("Immediately",
      "Replace every exposed password and access key, then keep secrets out of website code.",
      "These values are visible to anyone who loads the site. Removing them from the page does not undo the exposure; issue new credentials and revoke the old ones.",
      "Development team");
  }
  if (kevCount > 0) {
    const kevFixable = kevVulns.filter(hasFix).length;
    push("Immediately",
      `Patch or isolate the ${count(kevCount, "weakness", "weaknesses")} already exploited in real attacks` +
        (kevFixable < kevCount ? ` (${kevFixable} ${plural(kevFixable, "has", "have")} a published fix; for the rest, restrict access or put protection in front of the system).` : "."),
      "Attackers are actively using these. They come ahead of everything else on the software side; the “Components to fix first” list marks the affected components.",
      "Web / infrastructure team");
  }
  const exposedFiles = misconfigs.filter(g => g.category === "Exposed File" && SEV_RANK[sevKey(g.severity)] >= SEV_RANK.high);
  if (exposedFiles.length) {
    push("Immediately",
      "Remove public access to the exposed sensitive files, and treat anything they contained as compromised.",
      "Environment files and version-control folders often hold passwords, keys and source code. If they were downloadable, assume someone has already copied them.",
      "Web / infrastructure team");
  }

  const seriousFixable = regular.filter(v => ["critical", "high"].includes(sevKey(v.severity)) && hasFix(v)).length;
  const seriousNoFix = regular.filter(v => ["critical", "high"].includes(sevKey(v.severity)) && !hasFix(v)).length;
  if (seriousFixable > 0) {
    push("Within days",
      `Update the software behind the ${count(seriousFixable, "Critical/High issue")} that already ${plural(seriousFixable, "has", "have")} a fix.`,
      "These are the weaknesses most likely to cause real damage, are visible from the internet, and the fix is already available. The “Components to fix first” list shows where to start.",
      "Web / infrastructure team");
  }
  if (seriousNoFix > 0) {
    push("Within days",
      `Decide how to handle the ${count(seriousNoFix, "serious issue")} with no published fix.`,
      "Choose between replacing the software, restricting who can reach it, or accepting the risk with a documented sign-off and a date to review.",
      "Security team with system owners");
  }
  const otherSeriousThemes = themes.filter(t => t.worst_rank >= SEV_RANK.high && !(t.category === "Exposed File" && exposedFiles.length));
  if (otherSeriousThemes.length) {
    push("Within days",
      `Fix the serious configuration issues: ${joinList(otherSeriousThemes.map(t => t.title.charAt(0).toLowerCase() + t.title.slice(1)))}.`,
      "These are settings problems rather than software bugs, and are usually quick to correct. The Misconfigurations tab lists each issue with its recommended fix.",
      "Web / infrastructure team");
  }

  const remainingFixable = withFix - seriousFixable;
  if (remainingFixable > 0) {
    push("Next maintenance cycle",
      "Apply the remaining software updates as part of routine maintenance.",
      "Lower-severity weaknesses add up over time. Batch them into regular update cycles.",
      "Web / infrastructure team");
  } else if (regular.length - withFix - seriousNoFix > 0) {
    push("Next maintenance cycle",
      "Keep an eye on the remaining lower-severity weaknesses that have no published fix.",
      "There is nothing to update to yet. Check for new versions at each maintenance cycle.",
      "Web / infrastructure team");
  }
  const lowerCfg = misconfigs.filter(g => SEV_RANK[sevKey(g.severity)] < SEV_RANK.high).length;
  if (lowerCfg > 0) {
    push("Next maintenance cycle",
      "Work through the remaining lower-severity configuration issues.",
      "Most are one-line settings changes (browser protection headers, cookie flags, email records) that raise the baseline for every system at once.",
      "Web / infrastructure team");
  }
  if (notChecked > 0 && reached) {
    push("Next maintenance cycle",
      `Confirm the software versions of the ${count(notChecked, "component")} the scan could not pin down.`,
      "A component with an unknown version might be vulnerable. Someone with access to the system can usually read the real version directly.",
      "Web / infrastructure team");
  }
  if (skipped > 0) {
    push("Next maintenance cycle",
      "Scan the skipped private or internal targets from inside the network, if they are in scope.",
      "They resolve to addresses an outside scan must not touch, so this report does not cover them.",
      "Security team");
  }
  if (unreachable > 0 && reached) {
    push("Next maintenance cycle",
      "Review the names that no longer resolve and remove stale DNS entries.",
      "Old entries can be taken over by others or confuse future scans.",
      "Web / infrastructure team");
  }
  if (hidden > 0) {
    push("Next maintenance cycle",
      "Re-run the scan without the minimum-severity filter to see every weakness.",
      "The filtered weaknesses are not part of this report.",
      "Security team");
  }
  push("Ongoing",
    "Re-run this scan on a schedule and after any change to the internet-facing systems.",
    "New systems appear and new weaknesses are published daily. A scan that was clean last month may not be today.",
    "Security team");

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
        "The numbers shown count individual findings (each weakness, each distinct configuration issue, each exposed credential); the Compliance tab counts distinct CVEs and components, so its figures can be lower.",
      disclaimer: cs.disclaimer || "Compliance mappings are best-effort guidance, not a certified assessment.",
    };
  }

  // ── Scope & caveats ──────────────────────────────────────────────────────
  const subject = buildSubject(report);
  const scope = {
    tool: scan.tool,
    description: `This report is ${scan.what}.`,
    discovery: scan.discovery,
    subject,
    targets_total: systemsTotal,
    systems_examined: reached,
    systems_unreachable: unreachable,
    systems_skipped: skipped,
    systems_failed: failed,
    components_identified: componentsReviewed,
    generated_at: report?.generated_at || null,
  };

  const notes = [];
  notes.push("Everything in this report is an outside-in view: what the systems disclosed to anyone on the internet at the time of the scan. It is not a penetration test.");
  if (vulnsAssessed) {
    notes.push("Weakness findings come from public vulnerability sources queried at the time of the scan. Weaknesses disclosed later will not appear until the next scan.");
  } else {
    notes.push("No identified component had a checkable version, so weakness figures are shown as not checked, not as zero.");
  }
  notes.push("Findings are matched on announced software versions and can include false alarms (for example where a fix was applied without changing the version number). Confirm a finding before acting on it.");
  notes.push("Compliance references are best-effort guidance and are not a substitute for a formal audit.");
  if (infections.length > 0) {
    notes.push("The Vulnerabilities tab also lists advisories for malicious components. In this summary they are counted separately, so “Known weaknesses” can be lower than the tab's total.");
  }
  if (hidden > 0) {
    notes.push(`${count(hidden, "weakness", "weaknesses")} ${plural(hidden, "was", "were")} hidden by the minimum-severity filter and ${plural(hidden, "is", "are")} not counted in any weakness figure.`);
  }
  if (notChecked > 0) {
    notes.push(`${count(notChecked, "component")} had an unknown or too-vague version and ${plural(notChecked, "was", "were")} not checked for weaknesses.`);
  }
  if (secretsInfo.status === "failed") {
    notes.push("The search for exposed credentials failed during this scan, so credential results are unavailable.");
  } else if (secretsInfo.status === "partial") {
    notes.push(`The credential search could not read ${count(secretsInfo.errors, "page or script")}; credentials in those files, if any, are not reported.`);
  } else if (secretsInfo.status === "not_run") {
    notes.push("The search for exposed credentials was switched off for this scan.");
  } else if (secretsInfo.status === "nothing_to_crawl") {
    notes.push("The credential search had no reachable website to read.");
  }
  if (opts.used_cookie || (opts.custom_header_names || []).length) {
    notes.push("Software identification used a session cookie or custom headers supplied by the operator. The configuration and credential checks did not.");
  }
  if (report?.allow_private) {
    notes.push("The private-address safety guard was switched off for this scan.");
  }

  const glossary = [
    { term: "Internet-facing system", meaning: "A server, website or service that anyone on the internet can reach. This scan only sees those." },
    { term: "Component", meaning: "A piece of software a system is running, such as a web server, a CMS or a JavaScript library." },
    { term: "Weakness (vulnerability)", meaning: "A known flaw in a component that an attacker could use to cause harm." },
    { term: "Known exploited (CISA KEV)", meaning: "A weakness the U.S. cybersecurity agency (CISA) has confirmed attackers are using in real attacks. These are the most urgent to fix." },
    { term: "Exploit likelihood (EPSS)", meaning: "A statistical estimate, from FIRST, of how likely a weakness is to be exploited in the next 30 days. A guide for ordering work, not a confirmed attack." },
    { term: "Malicious component", meaning: "Software built to do damage, such as stealing data. Not an accidental bug." },
    { term: "Configuration gap", meaning: "A setting that falls short of good practice, such as a missing HTTPS safeguard or weak email anti-spoofing records." },
    { term: "Exposed credential", meaning: "A password or access key sitting in website code where any visitor could read it." },
    { term: "Severity", meaning: "How serious an issue is, from Low to Critical, based on the potential damage." },
    { term: "Certificate Transparency", meaning: "A public record of every HTTPS certificate issued. Used here to discover a domain's public names without guessing." },
  ];

  // Figures that depend on a check that did not run are null ("not checked"),
  // never 0, so nobody reads them as a clean result.
  const nv = x => (vulnsAssessed ? x : null);
  const nc = x => (cfgChecked ? x : null);
  const at_a_glance = {
    vulnerabilities_assessed: vulnsAssessed,
    targets_total: systemsTotal,
    systems_examined: reached,
    systems_unreachable: unreachable,
    systems_skipped: skipped,
    systems_failed: failed,
    ip_addresses_port_scanned: hostScans.length ? ipScanned : null,
    open_ports_found: openPorts,
    components_identified: componentsReviewed,
    components_checked: checked,
    components_not_checked: notChecked,
    components_with_issues: nv(vulnerableComponents),
    malicious_components: nv(maliciousComponents),
    total_vulnerabilities: nv(regular.length),
    by_severity: nv(bySeverity),
    fix_available: nv(withFix),
    fix_available_percent: nv(pct(withFix, regular.length)),
    hidden_by_severity_filter: hidden,
    configuration_issues: nc(misconfigs.length),
    configuration_issues_by_severity: nc(cfgBySeverity),
    systems_with_configuration_issues: nc(cfgSystems.size),
    exposed_credentials: secretsInfo.known ? secretsInfo.total : null,
    // null = the exploit feed was unavailable, not "none".
    known_exploited: vulnsAssessed && intel.kevKnown ? kevCount : null,
    high_exploit_likelihood: vulnsAssessed && intel.epssKnown && epssT !== null ? epssHigh.length : null,
    exploit_data_complete: vulnsAssessed ? (intel.kevKnown && intel.epssKnown && !intel.epssPartial) : null,
  };

  // Ready-to-render figure cards. `value: null` means "not checked" and is shown
  // as n/a; `tone` is a severity key ("none" = good, "" = neutral).
  const sysSub = `of ${count(systemsTotal, "target")}` +
    (unreachable ? `, ${unreachable} no longer ${plural(unreachable, "exists", "exist")}` : "") +
    (skipped ? `, ${skipped} skipped` : "") +
    (failed ? `, ${failed} failed` : "");
  const weaknessSub = (vulnsAssessed
    ? (sevSummary(bySeverity) || "None found")
    : "Not checked in this scan") +
    (maliciousComponents > 0 ? ` + ${count(maliciousComponents, "malicious component")}` : "") +
    (kevCount > 0 ? ` + ${count(kevCount, "known-exploited weakness", "known-exploited weaknesses")}` : "");
  const cfgSub = cfgChecked
    ? ((sevSummary(cfgBySeverity) || "None found") + (cfgSystems.size ? ` on ${count(cfgSystems.size, "system")}` : ""))
    : "No system was reachable to check";
  const credSub = secretsInfo.known ? "Passwords / keys found in website code" : "Credential search did not run or did not complete";
  let weaknessTone = maliciousComponents > 0 ? "critical" : figureTone(worstOf(bySeverity), vulnsAssessed ? regular.length : null);
  if (kevCount > 0 && weaknessTone !== "critical") weaknessTone = "high";

  const figures = [
    { label: "Systems examined", value: reached, sub: sysSub, tone: reached > 0 ? "" : "high" },
    { label: "Known weaknesses", value: nv(regular.length), sub: weaknessSub, tone: vulnsAssessed ? weaknessTone : "" },
    { label: "Configuration issues", value: nc(misconfigs.length), sub: cfgSub, tone: figureTone(worstOf(cfgBySeverity), nc(misconfigs.length)) },
    { label: "Exposed credentials", value: secretsInfo.known ? secretsInfo.total : null, sub: credSub, tone: figureTone(secretsInfo.serious > 0 ? "high" : "medium", secretsInfo.known ? secretsInfo.total : null) },
  ];

  const glance_cards = [
    { label: "Systems examined", value: reached, sub: sysSub, tone: reached > 0 ? "" : "high" },
    { label: "Software components", value: componentsReviewed, sub: notChecked ? `${checked} checked, ${notChecked} with unknown version` : "All had a checkable version", tone: "" },
    { label: "Components affected", value: nv(vulnerableComponents), sub: "With a known weakness or flagged as malicious", tone: figureTone("high", nv(vulnerableComponents)) },
    { label: "Malicious components", value: nv(maliciousComponents), sub: "Deliberately harmful software", tone: figureTone("critical", nv(maliciousComponents)) },
    { label: "Known weaknesses", value: nv(regular.length), sub: vulnsAssessed ? sevSummary(bySeverity) : "Not checked in this scan", tone: figureTone("medium", nv(regular.length)) },
    { label: "Known exploited", value: vulnsAssessed && intel.kevKnown ? kevCount : null, sub: !vulnsAssessed ? "Not checked in this scan" : intel.kevKnown ? "Weaknesses on the CISA exploited-in-the-wild list" : "Exploit list unreachable — unknown", tone: vulnsAssessed && intel.kevKnown ? figureTone("high", kevCount) : "" },
    ...(epssT !== null ? [{ label: "High exploit likelihood", value: vulnsAssessed && intel.epssKnown ? epssHigh.length : null, sub: !vulnsAssessed ? "Not checked in this scan" : intel.epssKnown ? `EPSS estimate of ${parseFloat((epssT * 100).toFixed(2))}% or more` + (intel.epssPartial ? " (some scores missing)" : "") : "EPSS data unreachable — unknown", tone: vulnsAssessed && intel.epssKnown ? figureTone("medium", epssHigh.length) : "" }] : []),
    { label: "Fix available", value: vulnsAssessed ? `${pct(withFix, regular.length)}%` : null, sub: vulnsAssessed ? `${withFix} of ${regular.length} can be fixed by updating` : "No component had a checkable version", tone: "" },
    { label: "Configuration issues", value: nc(misconfigs.length), sub: cfgSub, tone: figureTone("medium", nc(misconfigs.length)) },
    { label: "Exposed credentials", value: secretsInfo.known ? secretsInfo.total : null, sub: credSub, tone: figureTone("high", secretsInfo.known ? secretsInfo.total : null) },
  ];
  if (openPorts != null) {
    glance_cards.push({ label: "Open network ports", value: openPorts, sub: hostScans.length ? `across ${count(ipScanned, "address", "addresses")} port-scanned` : "on the scanned host", tone: "" });
  }
  if (hidden > 0) {
    glance_cards.push({ label: "Hidden by filter", value: hidden, sub: "Weaknesses below the minimum-severity filter", tone: "medium" });
  }

  // ── One-page summary ─────────────────────────────────────────────────────
  const subjectInfo = buildSubject(report);
  const cover = {
    title: "External Attack Surface — Executive Summary",
    subject: subjectInfo.name || "Scanned systems",
    report_id: makeReportId("UBEL-EASM", report, subjectInfo.name),
    generated_at: report?.generated_at || null,
    tool: subjectInfo.tool,
    classification: "Confidential — contains security findings; share only with authorized recipients.",
    statement: "Produced by an outside-in scan of systems the scanning party owns or is explicitly authorized to test. It reflects what was visible from the internet at the time of the scan.",
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
    at_a_glance,
    glance_cards,
    key_findings: keyFindings,
    configuration_themes: themes.map(({ worst_rank, ...t }) => t),
    components_to_fix_first: buildPriorityComponents(vulns, inventory, epssT, 5),
    systems_to_review_first: buildSystemsToReview(report, 5),
    recommended_actions: actions,
    recommended_actions_basis: "Actions are generated from the counts in this report. Timeframes are general defaults built into the tool, not your organization's remediation policy; adjust them to your own standards.",
    compliance_overview: complianceOverview,
    scope,
    methodology: buildMethodology(report, {
      scan, secretsInfo, vulnsAssessed, cfgChecked, reached, notChecked, hidden, minSeverity, discovery, intel,
    }),
    notes,
    glossary,
  };
}