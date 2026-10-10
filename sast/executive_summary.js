// sast/executive_summary.js
//
// Builds the `executive_summary` section of a UBEL SAST report (`ubel-sast`)
// or malicious-code report (`ubel-mal`): a short, plain-language overview for
// non-technical readers (management, risk, compliance, product owners). It is
// the source-code counterpart of cloud/lib/executive_summary.js,
// sca/executive_summary.js and easm/lib/executive_summary.js and follows the
// same rules:
//
//   - It is derived entirely from data already in the finished scan
//     (chunk results, finding verdicts, scan metadata) — no network calls, no
//     new analysis. main.js builds it ONCE and hands the same object to the
//     JSON writer and to the HTML generator, so the JSON report and the HTML
//     "Executive Summary" tab always show exactly the same content.
//   - No code, rule ids or CLI flags in headline text; every number is stated
//     with what it means. Technical detail stays in the other tabs.
//   - A figure that was NOT checked is `null` ("not checked"), never 0, so
//     nobody reads a skipped pass as a clean result.
//
// What differs from the SCA / EASM / cloud summaries, and why:
//   - The findings are AI-proposed candidates, not rule hits, and each one has
//     a verdict from two later passes (verification, exploitability trace).
//     So the summary is built around triage state — confirmed exploitable /
//     confirmed real / blocked by other code / not cleared / unverified /
//     dismissed as a false alarm — and the rating is evidence-weighted, not a
//     plain roll-up of severity (see overallRisk()).
//   - Findings dismissed as false alarms are never counted as risk.
//   - The same module serves both scan types. `meta.scan_type === "malware"`
//     switches the wording and rules: there is no exploitability pass, and a
//     confirmed finding is code that is malicious by intent.
//   - Coverage is about code: unreadable AI replies, skipped passes, diff
//     mode and chunk limits all mean "not everything was checked", and must
//     never read as a clean result.
//
// The rating and prioritization rules in buildMethodology() are a prose copy
// of stateOf() / levelOf() / overallRisk() / the action builder below — if
// those change, update that text too. The pass/fail verdict is NOT computed here:
// it comes from sast_gate.js, the same function main.js uses for the exit code,
// so what page 1 says and what CI saw cannot differ.

import { createHash } from "node:crypto";
import { evaluateSastGate } from "./sast_gate.js";

const LEVEL_RANK  = { critical: 4, high: 3, medium: 2, low: 1 };
const LEVEL_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const RISK_LABEL  = { critical: "Critical", high: "High", medium: "Medium", low: "Low", none: "Minimal", not_assessed: "Not assessed" };
const LEVEL_OF_RANK = ["", "low", "medium", "high", "critical"];

const STATE_PHRASE = {
  exploitable: "confirmed exploitable",
  valid: "confirmed real",
  unresolved: "not cleared",
  unverified: "unverified",
};

function plural(n, one, many) { return n === 1 ? one : (many || one + "s"); }
function count(n, one, many)  { return `${n} ${plural(n, one, many)}`; }

function joinList(items) {
  if (items.length <= 1) return items[0] || "";
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1];
}
// Coverage gaps are whole clauses that can contain their own "and" and
// parentheses, so they are separated with semicolons, not commas.
function joinGaps(gaps) { return gaps.join("; "); }
function lcFirst(s) { return s ? s.charAt(0).toLowerCase() + s.slice(1) : s; }
function trunc(s, n) {
  const t = String(s == null ? "" : s).replace(/\s+/g, " ").trim();
  return t.length > n ? t.slice(0, n - 1) + "…" : t;
}

// Same normalisation main.js applies, so grouping ties out with the Findings tab.
function classOf(f) {
  const raw = String(f.vuln_class || f.vuln_name || "unknown");
  return raw.replace(/\s*\(CWE[^)]*\)\s*$/i, "").trim() || "unknown";
}

function sevKeyOf(f) {
  const s = String(f.severity || "").toLowerCase();
  return s in LEVEL_RANK ? s : "unknown";
}

function relFile(file, workingDir) {
  const f = String(file || "").replace(/\\/g, "/");
  const root = String(workingDir || "").replace(/\\/g, "/").replace(/\/+$/, "");
  if (root && f.startsWith(root + "/")) return f.slice(root.length + 1);
  return f || "(unknown file)";
}

function baseName(p) {
  const parts = String(p || "").replace(/\\/g, "/").replace(/\/+$/, "").split("/");
  return parts[parts.length - 1] || "";
}

// Remote URLs can carry credentials (https://user:token@host/...). Never copy
// those into a document meant to be forwarded.
function safeRemote(url) {
  return String(url || "").replace(/\/\/[^/@\s]*@/, "//");
}

// Name shown on the cover. Prefer the repository name from the git remote: it
// stays meaningful when the code was cloned into a temp or CI work folder. Fall
// back to the scanned folder's name, then to a generic label. Never "." or "".
function subjectOf(git, workingDir) {
  const url = safeRemote(git?.url).trim();
  if (url) {
    const last = url.replace(/[\/\\]+$/, "").split(/[\/:]/).pop() || "";
    const name = last.replace(/\.git$/i, "");
    if (name) return name;
  }
  const dir = baseName(workingDir);
  return dir && dir !== "." && dir !== ".." ? dir : "Source code";
}

// ── Triage state of one finding ──────────────────────────────────────────────
// Mutually exclusive, in this order. Mirrors the exit-code logic in main.js
// (writeAnalyzeReports / writeMalwareReports) so "not cleared" here is exactly
// what makes --fail-on exit non-zero there.
//   exploitable — the exploitability trace found attacker input reaching it
//   false_positive — verification judged it not a real issue
//   mitigated   — a real weakness, but the trace found it unreachable,
//                 sanitized or otherwise not exploitable
//   unresolved  — a pass errored or was inconclusive: NOT cleared, NOT confirmed
//   valid       — verification judged it real; exploitability not established
//   unverified  — a candidate from the first pass only (verification skipped)
function stateOf(f, mode, useTaint) {
  const t = mode === "malware" || !useTaint ? null : (f.taint || null);
  if (t && t.exploitable === true) return "exploitable";
  if (f.is_valid === false) return "false_positive";
  if (t && t.exploitable === false && f.is_valid === true) return "mitigated";
  if (f.verification_error || (t && (t.error || t.inconclusive_reason)) || f.is_valid === null) return "unresolved";
  if (t && t.exploitable === false) return "mitigated";
  if (f.is_valid === true) return "valid";
  return "unverified";
}

const isOpen = (state) => state === "exploitable" || state === "valid" || state === "unresolved" || state === "unverified";

// ── Priority: severity weighed by evidence ───────────────────────────────────
// A finding with no severity is treated as Medium. Then:
//   analyze: confirmed exploitable keeps its severity; anything not shown to be
//            exploitable (confirmed real, not cleared, unverified) counts at
//            most High; blocked-by-other-code counts as Low; false alarms
//            carry no priority.
//   malware: confirmed malicious code counts at least High (it is malicious by
//            intent, whatever its technical severity); not cleared / unverified
//            counts at most High; false alarms carry none.
function levelOf(state, sevKey, mode) {
  if (state === "false_positive") return null;
  const s = sevKey === "unknown" ? "medium" : sevKey;
  const rank = LEVEL_RANK[s];
  if (state === "mitigated") return "low";
  if (mode === "malware") {
    if (state === "valid") return LEVEL_OF_RANK[Math.max(rank, LEVEL_RANK.high)];
    return LEVEL_OF_RANK[Math.min(rank, LEVEL_RANK.high)];
  }
  if (state === "exploitable") return s;
  return LEVEL_OF_RANK[Math.min(rank, LEVEL_RANK.high)];
}

const isConfirmed = (state, mode) => mode === "malware" ? state === "valid" : state === "exploitable";

// ── Themes: findings grouped by kind of weakness ─────────────────────────────
// Each finding goes in exactly one theme, chosen by the first pattern that
// matches its risk category (from the compliance mapping) or its class name.
// Order matters: more specific patterns first. A class this table does not
// recognise lands in "other", never in the wrong group.
const THEMES = [
  {
    id: "xss", re: /\bxss\b|cross.?site script/,
    title: "Attackers can run scripts in users' browsers",
    plain: "Pages show untrusted input to users without cleaning it first, so an attacker can make a visitor's browser run the attacker's code, for example to steal a session or act as that user.",
    fix: "Encode or sanitize user-supplied content before displaying it, and use the framework's built-in output escaping.",
    why: "This is a common way to take over user accounts. Fixes are usually small and local to the page or component.",
    owner: "Application development team",
  },
  {
    id: "deserialization", re: /deserial|prototype pollution|unsafe (yaml|pickle|unmarshal)/,
    title: "Unsafe handling of incoming data structures",
    plain: "Code rebuilds objects or settings from untrusted data in an unsafe way, which can let an attacker run code or change behavior they should not control.",
    fix: "Avoid unsafe deserialization of untrusted data; use plain data formats with strict validation.",
    why: "These flaws can lead to complete takeover of the application server and are hard to spot from the outside.",
    owner: "Application development team",
  },
  {
    id: "injection", re: /inject|\bxxe\b|xml external|ldap|xpath|\beval\b|code execution|command exec|\bsqli?\b|nosql/,
    title: "Untrusted input reaches databases, commands or interpreters",
    plain: "Input from users or other systems is placed into a database query, system command or similar instruction without proper separation, so an attacker can change what it does, for example to read or alter data or run commands on the server.",
    fix: "Use parameterized queries and safe APIs instead of building commands from text, and validate input where it enters the system.",
    why: "Injection flaws are among the most damaging and most commonly exploited, and often give direct access to data or to the server.",
    owner: "Application development team",
  },
  {
    id: "secrets", re: /secret|credential|hard.?coded|api key|password|private key/,
    title: "Passwords or keys written into the code",
    plain: "Passwords, keys or tokens are stored directly in the source code, so anyone with access to the code or its history can use them.",
    fix: "Remove the secrets from the code, load them from a secrets manager or protected configuration, and replace every exposed credential.",
    why: "Deleting a secret from the code is not enough: it stays in version history, so it must be treated as compromised and replaced.",
    owner: "Development and security team",
  },
  {
    id: "crypto", re: /crypto|\bhash|cipher|encrypt|random|\btls\b|\bssl\b|certificate|\bmd5\b|\bsha-?1\b/,
    title: "Weak or misused encryption",
    plain: "Encryption, hashing or random-number handling is outdated or used incorrectly, so protected data or tokens could be guessed, forged or decrypted.",
    fix: "Replace weak algorithms and predictable random values with current, vetted ones from the platform's standard library.",
    why: "Weak cryptography often looks fine in testing and only fails under attack. Changing it can require re-protecting existing data, so plan the migration.",
    owner: "Application development team",
  },
  {
    id: "file_network", re: /ssrf|server.?side request|path traversal|directory traversal|file upload|file inclusion|zip slip|\blfi\b|\brfi\b|symlink|temp(orary)? file/,
    title: "Unsafe file and network access",
    plain: "The application can be steered to read or write files it should not, accept dangerous uploads, or make requests to internal systems on an attacker's behalf.",
    fix: "Validate and restrict file paths, uploads and outbound request targets to an allow-list.",
    why: "These flaws can expose internal files or services that are otherwise unreachable from the internet.",
    owner: "Application development team",
  },
  {
    id: "access_control", re: /access control|authori[sz]|authenticat|\bauth\b|session|csrf|cross.?site request|\bidor\b|privilege|permission|redirect/,
    title: "Weak sign-in, permission or session checks",
    plain: "Checks on who may do what are missing or can be bypassed, so a user might see or change things that belong to others, or an attacker might act as a signed-in user.",
    fix: "Enforce sign-in and permission checks on the server for every sensitive action, and protect sessions and forms against forgery.",
    why: "Access problems directly expose customer data and are a frequent audit finding.",
    owner: "Application development team",
  },
  {
    id: "memory", re: /buffer|use.after.free|overflow|out.of.bounds|memory|double free|null pointer|format string|dangling|uninitiali[sz]ed|integer/,
    title: "Memory-handling errors",
    plain: "Code reads or writes memory it should not, which can crash the program or let an attacker take control of it.",
    fix: "Fix the unsafe memory operations, add bounds checks, and prefer safe library functions.",
    why: "These flaws can lead to complete takeover and are harder to fix well, so involve an experienced developer.",
    owner: "Development team (systems code)",
  },
  {
    id: "infra_config", re: /container|\bpod\b|kubernetes|\bk8s\b|network polic|\biac\b|terraform|cloudformation|ansible|docker|privileged|public cloud|exposure|misconfig|segmentation|security context/,
    title: "Risky deployment and infrastructure settings",
    plain: "Container, Kubernetes or infrastructure-as-code definitions grant more power, or expose services more widely, than needed.",
    fix: "Tighten the deployment settings: remove unnecessary privileges, restrict network exposure and follow the platform's hardening guidance.",
    why: "Deployment settings decide how far an attacker can move once they gain a foothold, and they are cheap to correct before release.",
    owner: "Platform / DevOps team",
  },
  {
    id: "resource_race", re: /\brace\b|toctou|concurren|time.of.check|denial|\bdos\b|redos|regular expression|resource|exhaust|unbounded/,
    title: "Reliability and resource-abuse weaknesses",
    plain: "Timing gaps or unbounded work let an attacker slow down, exhaust or confuse the application, or exploit the gap between a check and the action that follows it.",
    fix: "Add limits and timeouts to expensive operations, and make check-then-act sequences atomic.",
    why: "These issues more often cause outages or unpredictable behavior than data theft, but they can also be used to bypass checks.",
    owner: "Application development team",
  },
  {
    id: "data_exposure", re: /information|disclos|sensitive data|leak|\blog(ging)?\b|verbose error|stack trace/,
    title: "Sensitive information shown or logged",
    plain: "Internal details or personal data are written to logs, error messages or responses where they should not appear.",
    fix: "Remove sensitive data from logs and error messages, and return generic errors to users.",
    why: "Leaked details help attackers and can breach privacy obligations.",
    owner: "Application development team",
  },
];

const THEME_MALICIOUS = {
  id: "malicious_code",
  title: "Code that appears to be intentionally malicious",
  plain: "Code that looks written on purpose to do something the project owner would not approve of, such as opening a hidden remote connection, stealing data, or staying on a machine after it is removed.",
  fix: "Treat the affected code as a possible compromise: isolate it, remove it, find out how it got in, and replace any credentials it could reach.",
  why: "Unlike an ordinary bug, malicious code means someone may already have had access. Establish quickly whether it is deliberate before treating it as a false alarm.",
  owner: "Security / incident response team",
};

const THEME_OTHER = {
  id: "other",
  title: "Other code weaknesses",
  plain: "Weaknesses that do not fit the other groups. The Findings tab lists each one with its location and recommended fix.",
  fix: "Review the remaining weaknesses and correct them.",
  why: "Individually these are usually limited, but together they weaken the overall security of the application.",
  owner: "Application development team",
};

function themeOf(f, mode) {
  if (mode === "malware") return THEME_MALICIOUS;
  const cats = Array.isArray(f?.compliance?.categories) ? f.compliance.categories : [];
  const hay = (cats.join(" ") + " " + classOf(f)).toLowerCase().replace(/_/g, " ");
  return THEMES.find((t) => t.re.test(hay)) || THEME_OTHER;
}

const BUSINESS_IMPACT = {
  analyze: {
    critical:
      "At least one weakness in the code was confirmed to be reachable by an attacker and is rated Critical, such as one that could expose data or give control of a system. " +
      "Fix these before routine work, and check whether the affected code has already been abused.",
    high:
      "Serious weaknesses were found: either confirmed attackable at High severity, or serious flaws that the checks could not rule out. " +
      "Address them ahead of routine work; those not yet confirmed need a developer to settle quickly whether they are real.",
    medium:
      "The weaknesses found are less likely to be exploited, or would cause limited damage if they were. They can be handled through scheduled maintenance rather than emergency action.",
    low:
      "The weaknesses found are minor, or are currently blocked by other code. They can be fixed during routine updates.",
    none:
      "No action is required based on this scan. Code changes constantly, so it should still be re-checked regularly, ideally on every change.",
    not_assessed:
      "This report does not say whether the code is secure, because no code could be analyzed. Resolve why, then run the scan again.",
  },
  malware: {
    critical:
      "Code that appears intentionally malicious was found and rated Critical. Treat it as a possible compromise: isolate the affected code and systems, and check what the code could have reached or sent out.",
    high:
      "Code that looks intentionally malicious, or suspicious code that could not be cleared, was found. Have a security engineer review it before it is built, shipped or run again.",
    medium:
      "Suspicious code was found that is less likely to be harmful. A reviewer should confirm its purpose.",
    low:
      "Only low-concern findings remain. A reviewer should still confirm them.",
    none:
      "No intentionally malicious code was found in what was checked. This does not prove the absence of a well-hidden implant, and the code should be re-checked regularly, especially when dependencies or build scripts change.",
    not_assessed:
      "This report does not say whether the code is free of malicious code, because no code could be analyzed. Resolve why, then run the scan again.",
  },
};

// ── helpers for the one-page summary ─────────────────────────────────────────
function makeReportId(prefix, generatedAt, tool, name) {
  const h = createHash("sha256").update(`${generatedAt || ""}|${tool || ""}|${name || ""}`).digest("hex");
  return `${prefix}-${h.slice(0, 10).toUpperCase()}`;
}

function pickTopRisks(findings, limit = 3) {
  const rank = (f) => LEVEL_RANK[f.severity] || 0;
  const order = (list) => list
    .map((f, i) => ({ f, i }))
    .sort((a, b) => rank(b.f) - rank(a.f) || a.i - b.i)
    .map((x) => x.f);
  const risks = order(findings.filter((f) => !f.info));
  return (risks.length ? risks : order(findings)).slice(0, limit).map(({ severity, title, detail }) => ({ severity, title, detail }));
}

function figureTone(worstKey, total) {
  if (total == null) return "";
  return total > 0 ? worstKey : "none";
}

function worstLevel(levelCounts) {
  return ["critical", "high", "medium", "low"].find((k) => (levelCounts?.[k] || 0) > 0) || null;
}

function sevSummary(sev) {
  return ["critical", "high", "medium", "low", "unknown"]
    .filter((k) => (sev?.[k] || 0) > 0)
    .map((k) => `${sev[k]} ${k === "unknown" ? "unrated" : k}`)
    .join(" / ");
}

// Some stages report their own setting; if the caller did not pass scan options
// (an older or programmatic caller) fall back to what the data itself shows,
// and say "unknown" rather than guess when there is nothing to go on.
function stageRan(setting, evidence) {
  if (typeof setting === "boolean") return setting;
  return evidence ? true : null;
}

// ── Overall risk ─────────────────────────────────────────────────────────────
// Highest priority level among all findings that were not dismissed. Priority
// is severity weighed by evidence (see levelOf). `m.unreadable` is the number of
// code units whose scan reply could not be read: nothing is known about them,
// so Minimal cannot be given.
function overallRisk(m) {
  const mal = m.mode === "malware";
  const noun = mal ? "finding" : "issue";
  if (!m.assessed) {
    return {
      level: "not_assessed",
      rationale: m.units === 0
        ? "No code was analyzed (nothing matched the scan scope, or the changed-code scope was empty), so no security rating can be given."
        : "Every code unit failed to produce a readable result, so no security rating can be given.",
    };
  }
  const gaps = m.gaps.length ? ` This is not a full all-clear: ${joinGaps(m.gaps)}.` : "";
  const gapsOnRisk = m.gaps.length ? ` Not everything was covered: ${joinGaps(m.gaps)}. The true rating could be higher.` : "";
  const L = m.levels;       // { level: { confirmed, other } }
  const n = (k) => (L[k].confirmed + L[k].other);

  if (L.critical.confirmed + L.critical.other > 0) {
    return {
      level: "critical",
      rationale: (mal
        ? `Includes ${count(n("critical"), "confirmed malicious-code finding")} rated Critical: code that appears written on purpose to harm or to give an outsider access.`
        : `Includes ${count(n("critical"), "Critical-severity issue")} confirmed as exploitable: a weakness an attacker can reach, which could lead directly to data theft or loss of control of a system.`) + gapsOnRisk,
    };
  }
  if (n("high") > 0) {
    const bits = [];
    if (L.high.confirmed) bits.push(mal ? `${count(L.high.confirmed, "confirmed malicious-code finding")}` : `${count(L.high.confirmed, "High-severity issue")} confirmed as exploitable`);
    if (L.high.other) bits.push(mal ? `${count(L.high.other, "suspicious finding")} that could not be cleared` : `${count(L.high.other, "serious " + noun)} not confirmed as exploitable but not ruled out`);
    return {
      level: "high",
      rationale: `Includes ${joinList(bits)}.${mal ? "" : " Nothing is rated Critical because that requires a finding confirmed exploitable."}${gapsOnRisk}`,
    };
  }
  if (n("medium") > 0) {
    return { level: "medium", rationale: `Moderate ${plural(n("medium"), noun)} found that should be fixed as part of normal maintenance.${gapsOnRisk}` };
  }
  if (n("low") > 0) {
    return { level: "low", rationale: `Only low-priority ${plural(n("low"), noun)} found${m.mitigated ? `, including ${count(m.mitigated, "real weakness", "real weaknesses")} currently blocked by other code` : ""}.${gapsOnRisk}` };
  }
  if (m.unreadable > 0 || (m.limits && m.limits.length > 0)) {
    const why = [];
    if (m.unreadable > 0) why.push(`${count(m.unreadable, "code unit")} could not be analyzed because the AI's reply was unreadable`);
    for (const l of (m.limits || [])) why.push(l);
    const others = m.gaps.filter((g) => !why.includes(g));
    return {
      level: "low",
      rationale: `${joinGaps(why)}, so a Minimal rating cannot be given. The true rating could be higher.` +
        (others.length ? ` Not everything was covered: ${joinGaps(others)}.` : ""),
    };
  }
  const dismissed = m.falsePositives > 0
    ? ` ${count(m.falsePositives, "candidate finding")} raised during the scan ${plural(m.falsePositives, "was", "were")} checked and dismissed as ${plural(m.falsePositives, "a false alarm", "false alarms")}.` : "";
  return { level: "none", rationale: `${mal ? "No malicious code was found" : "No security issues were found"} in what could be checked.${dismissed}${gaps}` };
}

// ── Methodology ──────────────────────────────────────────────────────────────
// Describes how THIS report was produced. Steps are included only when the
// corresponding pass actually ran, so the text never claims work that wasn't
// done.
function buildMethodology(ctx) {
  const { mode, units, files, languages, provider, model, verifyRan, taintRan, opts, unreadable, hasCompliance, gapsScope, gate } = ctx;
  const mal = mode === "malware";
  const steps = [];

  // 1. Scope
  let scope = `This scan covered ${count(units, "code unit")} (functions, classes and configuration blocks) in ${count(files, "file")}` +
    (languages.length ? `, written in ${joinList(languages)}` : "") + ".";
  scope += " Well-known folders of third-party and generated code (such as node_modules, vendor and dist) are skipped automatically.";
  if (gapsScope.length) scope += ` Scope limits set for this run: ${joinGaps(gapsScope)}.`;
  steps.push({ step: "Scope", detail: scope });

  // 2. First pass
  const who = provider || model
    ? `the AI model configured for this run (${[provider, model].filter(Boolean).join(" / ")})`
    : "the AI model configured for this run (provider and model were not recorded because defaults were used)";
  steps.push({
    step: mal ? "Reading the code for malicious intent" : "Reading the code for weaknesses",
    detail: `Each code unit was cleaned of comments and sent, together with a built-in catalog of ${mal ? "malicious-code patterns" : "weakness types relevant to its programming language"}, to ${who}. ` +
      `The model proposed candidate findings. Candidates are suggestions, not conclusions: the AI can be wrong in both directions. ` +
      `This means excerpts of the source code were sent to that AI provider.`,
  });

  // 3. Verification
  if (verifyRan === true) {
    steps.push({
      step: "Verification",
      detail: "Every candidate was shown to the AI again, with the code around it, and asked a narrower question: is this actually " + (mal ? "malicious" : "a real weakness") + " in context? " +
        "Each was judged real, a false alarm (dismissed and not counted as risk), or inconclusive (not cleared and not confirmed, so it stays on the list for a human to settle).",
    });
  } else if (verifyRan === false) {
    steps.push({
      step: "Verification (not performed)",
      detail: "This scan was run with verification switched off, so no candidate was double-checked. Some findings may be false alarms, and none are confirmed.",
    });
  } else {
    steps.push({ step: "Verification", detail: "Whether verification ran could not be determined from this report." });
  }

  // 4. Exploitability trace
  if (mal) {
    steps.push({
      step: "Exploitability check (not applicable)",
      detail: "This pass is not used for malicious-code scans: code that is malicious on purpose does not depend on an attacker reaching it.",
    });
  } else if (taintRan === true) {
    steps.push({
      step: "Exploitability check",
      detail: "For findings that need attacker-controlled input to be exploitable, the scanner followed the code's calls across files, up to a fixed depth, and asked the AI whether attacker input can really reach the flawed spot and whether anything cleans it on the way. " +
        "Result: confirmed exploitable, or not exploitable (unreachable, cleaned or otherwise blocked). Code that nothing calls and that is not an entry point cannot be traced and is left inconclusive.",
    });
  } else if (taintRan === false) {
    steps.push({
      step: "Exploitability check (not performed)",
      detail: "This scan was run with the exploitability check switched off, so no finding could be confirmed exploitable. The highest possible rating is therefore High.",
    });
  } else {
    steps.push({ step: "Exploitability check", detail: "Whether the exploitability check ran could not be determined from this report." });
  }

  if (unreadable > 0) {
    steps.push({
      step: "Unreadable results",
      detail: `For ${count(unreadable, "code unit")} the AI's reply could not be decoded, so those units were not analyzed. They are counted as a coverage gap, never as clean.`,
    });
  }

  // 5. Pass / fail
  if (gate) {
    steps.push({
      step: "Pass / fail check",
      detail: `${gate.rule} This is the same rule the scanner uses to decide whether a build or pipeline run is stopped. ` +
        "It is separate from the risk rating: a run can be rated Low and still fail, or be rated High and still pass if the configured rule does not count those findings.",
    });
  }

  // 6. Compliance
  if (hasCompliance) {
    steps.push({
      step: "Compliance mapping",
      detail: "Each finding was linked to related controls in common security frameworks using fixed mapping tables, by type of weakness. This is guidance for an audit conversation, not an assessment of compliance.",
    });
  }

  const ratingRules = mal ? [
    { level: "Critical", rule: "At least one confirmed malicious-code finding whose severity is Critical." },
    { level: "High", rule: "At least one confirmed malicious-code finding (these count at least High), or a suspicious finding that was not cleared and not dismissed." },
    { level: "Medium", rule: "Only lower-concern suspicious findings that were not cleared." },
    { level: "Low", rule: "Only low-concern findings, or no findings but some code units could not be analyzed." },
    { level: "Minimal", rule: "Nothing found, nothing left uncleared and every code unit analyzed." },
    { level: "Not assessed", rule: "No code could be analyzed, so no rating is given instead of “Minimal”." },
  ] : [
    { level: "Critical", rule: "At least one Critical-severity issue confirmed exploitable." },
    { level: "High", rule: "A High-severity issue confirmed exploitable, or a Critical or High finding that is real or not cleared but not confirmed exploitable (anything not confirmed exploitable counts at most High)." },
    { level: "Medium", rule: "Medium-priority issues and nothing more serious." },
    { level: "Low", rule: "Only low-priority issues, real weaknesses blocked by other code, or no issues but some code units could not be analyzed." },
    { level: "Minimal", rule: "Nothing open, nothing left uncleared and every code unit analyzed." },
    { level: "Not assessed", rule: "No code could be analyzed, so no rating is given instead of “Minimal”." },
  ];

  const severityNote = "A finding's severity (Critical to Low) comes from the scanner and describes the type of weakness in general, not its effect on your business. A finding with no severity is treated as Medium. " +
    "“Priority” in this summary is severity weighed by evidence: " +
    (mal
      ? "confirmed malicious code counts at least High; findings not cleared count at most High; dismissed false alarms carry no priority."
      : "a finding confirmed exploitable keeps its severity; anything not confirmed exploitable counts at most High; a real weakness blocked by other code counts as Low; dismissed false alarms carry no priority.");

  const prioritization =
    "“Issue types to fix first” ranks each kind of weakness by (1) worst priority, (2) number confirmed " + (mal ? "malicious" : "exploitable") + ", (3) number of occurrences, and lists the top five. " +
    "“Files to review first” ranks files by the same measures. " +
    "“Issues by area” counts each finding once, under the first area its type belongs to. " +
    "Findings dismissed as false alarms are left out of all three" + (mal ? "." : ", and so are real weaknesses currently blocked by other code, which are reported separately.");

  const timeframes =
    "The timeframes in “Suggested actions” are default guidance built into the tool (Critical: immediately; High: within days; the rest: next maintenance cycle). " +
    "They are not taken from your organization's remediation policy or SLAs. The suggested owners are likewise generic defaults, not assignments. Replace both with your own where those differ.";

  const limitations = [
    "This is a point-in-time view of the source code. Code changes constantly, and anything changed after the scan is not reflected.",
    "The analysis is performed by an AI model. It can miss real " + (mal ? "implants" : "weaknesses") + " and can raise false alarms, and running the scan again can give somewhat different results. " +
      "Verification and the exploitability check reduce false alarms but do not remove them, and neither can make the first pass find something it missed. A clean result is not proof of safety.",
    "Each code unit is analyzed on its own, plus a bounded set of related code for the exploitability check. Flaws that only emerge from the interaction of many parts of a system, from runtime behavior or from how the application is deployed can go unseen.",
    "Only the code and languages listed under Scope were examined. Third-party libraries and their known vulnerabilities, deployed infrastructure and live systems are not examined by this scan; a dependency (SCA) scan and a cloud or external scan cover those.",
    "Severity ratings describe a type of weakness in general, not its effect on your business. The suggested actions are generated from the counts in this report and do not account for what each piece of code does or how important it is.",
  ];
  if (!mal) {
    limitations.push("Compliance references count every finding mapped to a control and are best-effort guidance, not an audit.");
  }
  if (opts?.only_diff) {
    limitations.push("Because the scan was limited to changed code, weaknesses in code that was not changed are not covered, and a clean result applies only to the changes. If the change set could not be determined, the scanner scans everything instead; this report does not record which happened.");
  }
  if (verifyRan === false) limitations.push("Verification was off, so every finding in this report is an unconfirmed AI suggestion.");
  if (unreadable > 0) limitations.push(`${count(unreadable, "code unit")} could not be analyzed (unreadable AI reply), so absent findings there are not evidence of a clean result.`);

  return { steps, rating_rules: ratingRules, severity_note: severityNote, prioritization, timeframes, limitations };
}

// ── Main ─────────────────────────────────────────────────────────────────────
export function buildSastExecutiveSummary(results, meta = {}) {
  const chunks = Array.isArray(results) ? results : [];
  const mode = meta?.scan_type === "malware" ? "malware" : "analyze";
  const mal = mode === "malware";
  const opts = meta?.scan_options || {};
  const workingDir = meta?.workingDir || "";
  const git = meta?.gitMetadata || {};
  const noun = mal ? "finding" : "issue";

  // ── Which passes ran ─────────────────────────────────────────────────────
  // Decided before the findings are classified: if the exploitability trace is
  // known not to have run, any taint data in the input is ignored, so the
  // summary can never claim a confirmed-exploitable finding the report also
  // says it could not check for.
  const anyFinding = (fn) => chunks.some((c) => (Array.isArray(c?.findings) ? c.findings : []).some((f) => f && !f._parse_error && fn(f)));
  const verifyRan = stageRan(opts.verify, anyFinding((f) => f.is_valid === true || f.is_valid === false || f.is_valid === null));
  const taintRan = mal ? false : stageRan(opts.taint_trace, anyFinding((f) => f.taint));
  const taintApplicable = !mal;
  const useTaint = taintApplicable && taintRan !== false;

  // ── Records ──────────────────────────────────────────────────────────────
  const recs = [];
  const fileSet = new Set();
  const langUnits = new Map();
  let unreadable = 0;
  let parseErrors = 0;
  for (const chunk of chunks) {
    const all = Array.isArray(chunk?.findings) ? chunk.findings : [];
    const errs = all.filter((f) => f && f._parse_error);
    parseErrors += errs.length;
    if (errs.length) unreadable++;
    const file = relFile(chunk?.file, workingDir);
    if (chunk?.file) fileSet.add(file);
    const lang = chunk?.language || "unknown";
    if (!langUnits.has(lang)) langUnits.set(lang, { units: 0, open: 0 });
    langUnits.get(lang).units++;
    for (const f of all) {
      if (!f || f._parse_error) continue;
      const state = stateOf(f, mode, useTaint);
      const sev = sevKeyOf(f);
      recs.push({
        f, state, sev, file, lang,
        level: levelOf(state, sev, mode),
        theme: themeOf(f, mode),
        cls: classOf(f),
        cwe: Array.isArray(f.cwe) ? f.cwe : [],
      });
    }
  }

  const units = chunks.length;
  const files = fileSet.size;
  const assessed = units > 0 && unreadable < units;

  const S = { exploitable: 0, valid: 0, mitigated: 0, unresolved: 0, unverified: 0, false_positive: 0 };
  for (const r of recs) S[r.state]++;
  const open = recs.filter((r) => isOpen(r.state));
  const openTotal = open.length;
  const notCleared = S.unresolved + S.unverified;
  const confirmedTotal = mal ? S.valid : S.exploitable;
  for (const r of open) langUnits.get(r.lang).open++;

  // Rating inputs: every finding that was not dismissed
  const levels = { critical: { confirmed: 0, other: 0 }, high: { confirmed: 0, other: 0 }, medium: { confirmed: 0, other: 0 }, low: { confirmed: 0, other: 0 } };
  for (const r of recs) {
    if (!r.level) continue;
    levels[r.level][isConfirmed(r.state, mode) ? "confirmed" : "other"]++;
  }
  const levelTotals = {};
  for (const k of Object.keys(levels)) levelTotals[k] = levels[k].confirmed + levels[k].other;

  const sevOpen = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of open) sevOpen[r.sev]++;
  const sevConfirmed = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const r of open) if (isConfirmed(r.state, mode)) sevConfirmed[r.sev]++;

  // ── Scope limits and coverage gaps ───────────────────────────────────────
  const gapsScope = [];
  if (opts.only_diff) gapsScope.push(`only code changed since ${opts.diff_base || "the previous commit"} was scanned`);
  if (opts.chunks_start) gapsScope.push(`the first ${opts.chunks_start} code units were skipped`);
  // Only the legacy fallback: when the scanner measured truncation (chunks_dropped_by_cap)
  // the real, involuntary gap is reported below; a limit that was set but never reached
  // is not a gap at all.
  if (opts.max_chunks && typeof opts.chunks_dropped_by_cap !== "number") gapsScope.push(`at most ${opts.max_chunks} code units were scanned`);
  if (Array.isArray(opts.languages) && opts.languages.length) gapsScope.push(`only ${joinList(opts.languages)} code was scanned`);
  if (Array.isArray(opts.skip_folders) && opts.skip_folders.length) gapsScope.push(`folders excluded: ${opts.skip_folders.join(", ")}`);
  if (Array.isArray(opts.skip_files) && opts.skip_files.length) gapsScope.push(`files excluded: ${opts.skip_files.join(", ")}`);

  // Involuntary coverage gaps MEASURED by the scanner (not choices the user made):
  // the default code-unit cap, files over the size limit, and AI replies cut off
  // by the output limit. Each one means code that was not (fully) examined, so
  // each blocks a Minimal rating the same way an unreadable reply does.
  const gapsLimits = [];
  if (typeof opts.chunks_dropped_by_cap === "number" && opts.chunks_dropped_by_cap > 0) {
    gapsLimits.push(`${count(opts.chunks_dropped_by_cap, "code unit")}${opts.chunks_found ? ` (of ${opts.chunks_found})` : ""} ${plural(opts.chunks_dropped_by_cap, "was", "were")} never scanned because the limit of ${opts.max_chunks_effective || opts.max_chunks} code units per run was reached`);
  }
  if (typeof opts.files_skipped_too_large_count === "number" && opts.files_skipped_too_large_count > 0) {
    const kb = opts.max_file_size ? ` ${Math.round(opts.max_file_size / 1024)} KB` : "";
    gapsLimits.push(`${count(opts.files_skipped_too_large_count, "file")} larger than${kb} ${plural(opts.files_skipped_too_large_count, "was", "were")} skipped`);
  }
  if (typeof opts.chunks_partial_output === "number" && opts.chunks_partial_output > 0) {
    gapsLimits.push(`${count(opts.chunks_partial_output, "code unit")} had an AI reply that was cut off, so findings after the cut-off point may be missing`);
  }

  const gaps = [];
  if (unreadable > 0) gaps.push(`${count(unreadable, "code unit")} could not be analyzed because the AI's reply was unreadable`);
  for (const g of gapsLimits) gaps.push(g);
  if (verifyRan === false) gaps.push("verification was skipped, so no finding was double-checked");
  if (taintApplicable && taintRan === false) gaps.push("the exploitability check was skipped, so no finding could be confirmed exploitable");
  for (const g of gapsScope) gaps.push(g);

  const mitigated = S.mitigated;
  const m = { mode, assessed, units, unreadable, gaps, limits: gapsLimits, levels, mitigated, falsePositives: S.false_positive };
  const risk = overallRisk(m);
  const rated = risk.level !== "not_assessed";

  // ── Verdict (pass / blocked) ─────────────────────────────────────────────
  // Same function main.js uses for the exit code. Only stated when the run's
  // --fail-on setting was recorded; otherwise it is null ("not recorded"), never
  // a guess. A pass is never an all-clear: it says nothing about open findings
  // the rule does not count, or about code that was not covered.
  let gate = null;
  let verdict = null;
  if (typeof opts.fail_on === "string" && opts.fail_on) {
    gate = evaluateSastGate(chunks, { mode, failOn: opts.fail_on, verify: verifyRan !== false, taintTrace: taintRan !== false });
    const blockingTotal = gate.triggers.reduce((n, t) => n + t.count, 0);
    const pass = !gate.shouldFail;
    let statement;
    if (pass) {
      statement = "The scanned code meets the configured security policy." +
        (!rated ? " No code was analyzed, so this result gives no assurance about security."
          : openTotal > 0 ? " Some findings remain that the policy does not block on; they are listed in this report." : "") +
        (rated && gaps.length ? ` This result does not account for coverage gaps: ${joinGaps(gaps)}.` : "");
    } else {
      statement = "The scanned code does not meet the configured security policy" +
        (gate.triggers.length ? `: ${joinList(gate.triggers.map((t) => t.text))}.` : ".") +
        (!mal && mitigated > 0 && gate.failOn !== "exploitable"
          ? ` Real weaknesses that are currently blocked by other code count under this rule too (${mitigated}).` : "") +
        (gate.triggers.some((t) => t.key === "any_candidate")
          ? " This rule blocks on every candidate, including ones later dismissed as false alarms; relax the policy setting if that is not intended."
          : " The blocking items must be resolved or accepted by the policy owner to pass.");
    }
    verdict = {
      status: pass ? "pass" : "blocked",
      label: pass ? "Meets security policy" : "Does not meet security policy",
      statement,
      rule: gate.rule,
      blocking: pass ? 0 : blockingTotal,
      technical_reason: `--fail-on ${gate.failOn}: ${gate.rule}`,
    };
  }

  const scopeText = `${count(units, "code unit")} (${count(files, "file")})`;
  const dismissedAs = (n) => `${plural(n, "was", "were")} checked and dismissed as ${plural(n, "a false alarm", "false alarms")}`;
  const subject = subjectOf(git, workingDir);

  // ── Themes ───────────────────────────────────────────────────────────────
  const themeMap = new Map();
  for (const r of open) {
    const id = r.theme.id;
    if (!themeMap.has(id)) themeMap.set(id, { theme: r.theme, issues: 0, confirmed: 0, files: new Set(), worst: 0, classes: new Map() });
    const t = themeMap.get(id);
    t.issues++;
    if (isConfirmed(r.state, mode)) t.confirmed++;
    t.files.add(r.file);
    t.worst = Math.max(t.worst, LEVEL_RANK[r.level]);
    t.classes.set(r.cls, (t.classes.get(r.cls) || 0) + 1);
  }
  const areas = [...themeMap.values()]
    .sort((a, b) => b.worst - a.worst || b.confirmed - a.confirmed || b.issues - a.issues || a.theme.title.localeCompare(b.theme.title))
    .map((t) => {
      const pk = LEVEL_OF_RANK[t.worst];
      return {
        category: t.theme.id,
        title: t.theme.title,
        plain: t.theme.plain,
        fix: t.theme.fix,
        why: t.theme.why,
        owner: t.theme.owner,
        issues: t.issues,
        confirmed: t.confirmed,
        files_affected: t.files.size,
        priority: pk,
        priority_label: LEVEL_LABEL[pk],
        examples: [...t.classes.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, 2).map(([c]) => c),
        worst_rank: t.worst,
      };
    });

  // ── Issue types (by class) to fix first ──────────────────────────────────
  const clsMap = new Map();
  for (const r of open) {
    if (!clsMap.has(r.cls)) clsMap.set(r.cls, { cls: r.cls, theme: r.theme, n: 0, confirmed: 0, files: new Set(), worst: 0, cwe: new Set(), by: { exploitable: 0, valid: 0, unresolved: 0, unverified: 0 } });
    const c = clsMap.get(r.cls);
    c.n++;
    if (isConfirmed(r.state, mode)) c.confirmed++;
    c.files.add(r.file);
    c.worst = Math.max(c.worst, LEVEL_RANK[r.level]);
    r.cwe.forEach((x) => c.cwe.add(x));
    c.by[r.state]++;
  }
  const issuesToFixFirst = [...clsMap.values()]
    .sort((a, b) => b.worst - a.worst || b.confirmed - a.confirmed || b.n - a.n || a.cls.localeCompare(b.cls))
    .slice(0, 5)
    .map((c) => {
      const pk = LEVEL_OF_RANK[c.worst];
      return {
        title: c.cls,
        occurrences: c.n,
        files_affected: c.files.size,
        confirmed: c.confirmed,
        status: Object.entries(c.by).filter(([, v]) => v > 0).map(([k, v]) => `${v} ${STATE_PHRASE[k]}`).join(", "),
        priority: pk,
        priority_label: LEVEL_LABEL[pk],
        // Weakness ids, for tickets and auditors. Kept out of the plain-language text.
        reference: [...c.cwe].sort((a, b) => a - b).map((x) => `CWE-${x}`).join(", ") || null,
        action: c.theme.fix,
      };
    });

  // ── Files to review first ────────────────────────────────────────────────
  const fileMap = new Map();
  for (const r of open) {
    if (!fileMap.has(r.file)) fileMap.set(r.file, { file: r.file, lang: r.lang, n: 0, confirmed: 0, worst: 0 });
    const x = fileMap.get(r.file);
    x.n++;
    if (isConfirmed(r.state, mode)) x.confirmed++;
    x.worst = Math.max(x.worst, LEVEL_RANK[r.level]);
  }
  const filesToReview = [...fileMap.values()]
    .sort((a, b) => b.worst - a.worst || b.confirmed - a.confirmed || b.n - a.n || a.file.localeCompare(b.file, undefined, { numeric: true }))
    .slice(0, 5)
    .map((x) => ({
      file: x.file,
      language: x.lang === "unknown" ? null : x.lang,
      issues: x.n,
      confirmed: x.confirmed,
      priority: LEVEL_OF_RANK[x.worst],
      priority_label: LEVEL_LABEL[LEVEL_OF_RANK[x.worst]],
    }));

  // ── Headline ─────────────────────────────────────────────────────────────
  const parts = [];
  if (confirmedTotal > 0) {
    parts.push(mal
      ? `${count(confirmedTotal, "confirmed malicious-code finding")}`
      : `${count(confirmedTotal, "confirmed exploitable issue")}${sevSummary(sevConfirmed) ? " (" + sevSummary(sevConfirmed) + ")" : ""}`);
  }
  const unconfirmedOpen = openTotal - confirmedTotal;
  if (unconfirmedOpen > 0) {
    parts.push(mal
      ? `${count(unconfirmedOpen, "suspicious finding")} not confirmed`
      : `${count(unconfirmedOpen, "further issue")} not confirmed as exploitable`);
  }
  if (mitigated > 0) parts.push(`${count(mitigated, "real weakness", "real weaknesses")} currently blocked by other code`);

  let summary;
  if (!rated) {
    summary = units === 0
      ? "No code was analyzed, so nothing can be said about its security."
      : `None of the ${count(units, "code unit")} produced a readable result, so nothing can be said about its security.`;
  } else if (parts.length) {
    summary = `The analysis of ${scopeText} found ${joinList(parts)}.` +
      (S.false_positive ? ` ${count(S.false_positive, "other candidate")} ${dismissedAs(S.false_positive)}.` : "") +
      (gaps.length ? ` Not everything was covered: ${joinGaps(gaps)}.` : "");
  } else {
    summary = `${mal ? "No malicious code was found" : "No security issues were found"} in ${scopeText}` +
      (S.false_positive ? `; ${count(S.false_positive, "candidate finding")} raised during the scan ${dismissedAs(S.false_positive)}.` : ".") +
      (gaps.length ? ` This is not a full all-clear: ${joinGaps(gaps)}.` : "");
  }
  const headline = `${rated ? RISK_LABEL[risk.level] + " risk" : "Risk not assessed"}. ${summary}`;

  // ── Key findings ─────────────────────────────────────────────────────────
  const keyFindings = [];
  const gapFinding = (title, detail) => keyFindings.push({ severity: "medium", title, detail });

  if (!rated) {
    gapFinding(units === 0 ? "No code was analyzed" : "No code unit could be analyzed",
      (units === 0 ? "The scan scope matched no code (or the changed-code scope was empty). " : "Every AI reply was unreadable. ") +
      "This report says nothing about whether the code is secure.");
  }
  if (unreadable > 0 && rated) {
    gapFinding(`${count(unreadable, "code unit")} could not be analyzed`,
      "The AI's reply for these could not be decoded, so nothing is known about them. Findings there may be missing; run the scan again, or raise the response size limit.");
  }
  if (verifyRan === false) {
    gapFinding("Findings were not double-checked",
      "Verification was switched off, so every finding is an unconfirmed AI suggestion and some may be false alarms.");
  }
  if (taintApplicable && taintRan === false) {
    gapFinding("Exploitability was not checked",
      "The exploitability check was switched off, so no weakness could be confirmed as attackable and the rating cannot exceed High.");
  }
  if (gapsLimits.length) {
    gapFinding("Part of the code was not scanned", `${gapsLimits[0].charAt(0).toUpperCase() + gapsLimits[0].slice(1)}${gapsLimits.length > 1 ? "; " + joinGaps(gapsLimits.slice(1)) : ""}. Weaknesses in that code, if any, are not in this report.`);
  }
  if (gapsScope.length) {
    gapFinding("Only part of the code was scanned", `${gapsScope[0].charAt(0).toUpperCase() + gapsScope[0].slice(1)}${gapsScope.length > 1 ? "; " + joinGaps(gapsScope.slice(1)) : ""}. Code outside this scope is not covered by this report.`);
  }

  for (const t of areas.filter((x) => x.worst_rank >= LEVEL_RANK.high)) {
    const mix = t.confirmed ? `${t.confirmed} confirmed ${mal ? "malicious" : "exploitable"}, ${t.issues - t.confirmed} not confirmed` : `none confirmed ${mal ? "malicious" : "exploitable"} yet`;
    keyFindings.push({
      severity: t.priority,
      title: t.title,
      detail: `${t.plain} ${count(t.issues, noun)} found in ${count(t.files_affected, "file")} (${mix}); the highest priority is ${t.priority_label}.` +
        (t.examples.length ? ` Examples: ${joinList(t.examples.map((e) => trunc(e, 80)))}.` : ""),
    });
  }
  const lowerAreas = areas.filter((x) => x.worst_rank < LEVEL_RANK.high);
  if (lowerAreas.length) {
    const lowerIssues = lowerAreas.reduce((n, t) => n + t.issues, 0);
    keyFindings.push({
      severity: lowerAreas[0].priority,
      title: "Other code weaknesses",
      detail: `${count(lowerIssues, "lower-priority " + noun)} across ${joinList(lowerAreas.map((t) => lcFirst(t.title)))}. Individually they are limited, but together they weaken the overall security of the code. Details are in the Findings tab.`,
    });
  }
  if (notCleared > 0) {
    keyFindings.push({
      severity: "medium",
      title: `${count(notCleared, "finding")} not cleared either way`,
      detail: `${S.unresolved ? `${count(S.unresolved, "finding")} could not be settled because a check failed or was inconclusive. ` : ""}` +
        `${S.unverified ? `${count(S.unverified, "finding")} ${plural(S.unverified, "was", "were")} never verified. ` : ""}` +
        "They are neither confirmed nor dismissed, so a developer should review each before this run is treated as clean.",
    });
  }
  if (mitigated > 0) {
    keyFindings.push({
      severity: "low",
      title: "Real weaknesses currently blocked by other code",
      detail: `${count(mitigated, "weakness", "weaknesses")} ${plural(mitigated, "is", "are")} real but the exploitability check found no way for an attacker to reach ${plural(mitigated, "it", "them")} today (unreachable, cleaned on the way, or otherwise blocked). A later change elsewhere in the code could re-open ${plural(mitigated, "it", "them")}.`,
    });
  }
  if (S.false_positive > 0) {
    keyFindings.push({
      severity: "low",
      title: "False alarms dismissed",
      detail: `${count(S.false_positive, "candidate finding")} raised by the AI ${plural(S.false_positive, "was", "were")} checked and judged not to be real. They are not counted as risk, but remain listed in the Findings tab.`,
      info: true,
    });
  }
  if (keyFindings.length === 0) {
    keyFindings.push({ severity: "low", title: "No significant findings", detail: `The scan did not find ${mal ? "malicious code" : "security issues"} in the code it could analyze.`, info: true });
  }

  // ── Recommended actions ──────────────────────────────────────────────────
  const actions = [];
  const push = (timeframe, action, why, owner) => actions.push({ priority: actions.length + 1, timeframe, action, why, owner });
  // Confirmed malicious code is always urgent, whatever its technical severity.
  const themeTimeframe = (t) => (t.worst_rank >= LEVEL_RANK.critical || (mal && t.confirmed > 0)) ? "Immediately"
    : t.worst_rank >= LEVEL_RANK.high ? "Within days" : "Next maintenance cycle";
  const pushTheme = (t) => push(themeTimeframe(t),
    `${t.fix} (${count(t.issues, noun)} in ${count(t.files_affected, "file")}).`, t.why, t.owner);

  // Critical findings first; coverage gaps follow immediately, ahead of
  // everything less urgent, so a reader acting on the top three sees both.
  for (const t of areas.filter((x) => themeTimeframe(x) === "Immediately")) pushTheme(t);

  if (!rated) {
    push("Before relying on this report",
      "Find out why no code could be analyzed (scan scope, AI provider errors or response size), then run the scan again.",
      "An empty or unreadable result gives no assurance about security.",
      "Security team");
  }
  if (unreadable > 0 && rated) {
    push("Before relying on this report",
      `Run the scan again so the ${count(unreadable, "unreadable code unit")} can be analyzed (a larger response size limit usually fixes this).`,
      "Nothing is known about those code units, so absent findings there give no assurance.",
      "Security team");
  }
  if (verifyRan === false) {
    push("Before relying on this report",
      "Run the scan again with verification switched on.",
      "Without verification no finding is confirmed, and false alarms are not filtered out.",
      "Security team");
  }
  if (taintApplicable && taintRan === false) {
    push("Before relying on this report",
      "Run the scan again with the exploitability check switched on.",
      "Without it no weakness can be confirmed as attackable, so the most serious ones cannot be told apart from the rest.",
      "Security team");
  }
  if (gapsLimits.length) {
    push("Before relying on this report",
      "Run the scan again with higher size limits, or in several parts, so the code that was left out is covered.",
      "Code that hit a size or count limit was never examined, so its absence from the findings gives no assurance.",
      "Security team");
  }
  if (gapsScope.length) {
    push("Before relying on this report",
      "Run a full scan of the whole codebase, or confirm that the narrowed scope is intended.",
      "Code outside the scope was not examined, so its absence from the findings gives no assurance.",
      "Security team");
  }
  // Then everything due within days, with the review of uncleared findings
  // right after the confirmed ones, and the rest last.
  for (const t of areas.filter((x) => themeTimeframe(x) === "Within days")) pushTheme(t);
  if (notCleared > 0) {
    push(areas.some((x) => x.worst_rank >= LEVEL_RANK.high) ? "Within days" : "Next maintenance cycle",
      `Have a developer review the ${count(notCleared, "finding")} that ${plural(notCleared, "was", "were")} not cleared either way and decide whether ${plural(notCleared, "it is", "each is")} real.`,
      "These are neither confirmed nor dismissed. Some are likely false alarms, but until someone looks, none can be called safe.",
      mal ? "Security team" : "Application development team");
  }
  for (const t of areas.filter((x) => themeTimeframe(x) === "Next maintenance cycle")) pushTheme(t);
  if (mitigated > 0) {
    push("Next maintenance cycle",
      `Fix the ${count(mitigated, "weakness", "weaknesses")} currently blocked by other code.`,
      "They cannot be reached today, but a later change elsewhere could re-open them, and fixing them removes the dependence on that protection.",
      "Application development team");
  }
  push("Ongoing",
    "Run this scan on every significant code change (for example on each pull request), not only before a release.",
    "Code changes daily. A scan that was clean last month says little about today's code.",
    "Security team");

  // ── Compliance (best-effort, high level) ─────────────────────────────────
  // Each finding once per framework; findings dismissed as false alarms are
  // left out. The Compliance tab counts every candidate (including dismissed
  // ones) by distinct weakness type and chunk, so its figures differ.
  let complianceOverview = null;
  const fwMap = new Map();
  let mapped = 0;
  const considered = recs.filter((r) => r.state !== "false_positive");
  considered.forEach((r, i) => {
    const fws = r.f?.compliance?.frameworks;
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
      findings_total: considered.length,
      statement: `The findings relate to controls in ${count(fwMap.size, "industry framework")}; ${mapped} of ${considered.length} findings map to at least one. ` +
        "Unresolved findings may need to be explained or remediated in a related audit. " +
        "These figures leave out findings dismissed as false alarms and count individual findings, each once per framework; the Compliance tab counts every candidate by distinct weakness type, so its figures differ.",
      disclaimer: meta?.compliance_summary?.disclaimer || "Compliance mappings are best-effort guidance, not a certified assessment.",
    };
  }

  // ── Coverage ─────────────────────────────────────────────────────────────
  const pipeline = [
    {
      stage: mal ? "Read the code for malicious intent" : "Read the code for weaknesses",
      status: (unreadable > 0 || gapsLimits.length > 0) ? "partial" : (units > 0 ? "done" : "skipped"),
      detail: `${count(units, "code unit")} sent to the AI` + (unreadable > 0 ? `; ${unreadable} came back unreadable` : "") + ".",
    },
    {
      stage: "Verification",
      status: verifyRan === true ? "done" : verifyRan === false ? "skipped" : "unknown",
      detail: verifyRan === true ? `${count(recs.length, "candidate")} double-checked; ${S.false_positive} dismissed as false alarms.` : verifyRan === false ? "Switched off for this run." : "Could not be determined from this report.",
    },
    {
      stage: "Exploitability check",
      status: !taintApplicable ? "not_applicable" : taintRan === true ? "done" : taintRan === false ? "skipped" : "unknown",
      detail: !taintApplicable ? "Not used for malicious-code scans." : taintRan === true ? `${S.exploitable} confirmed exploitable; ${S.mitigated} blocked by other code.` : taintRan === false ? "Switched off for this run." : "Could not be determined from this report.",
    },
  ];
  const STATUS_LABEL = { done: "Completed", partial: "Incomplete", skipped: "Skipped", not_applicable: "Not applicable", unknown: "Unknown" };
  const scanCoverage = {
    pipeline: pipeline.map((p) => ({ ...p, status_label: STATUS_LABEL[p.status] })),
    languages: [...langUnits.entries()]
      .map(([language, v]) => ({ language, code_units: v.units, open_issues: v.open }))
      .sort((a, b) => b.code_units - a.code_units || a.language.localeCompare(b.language)),
    scope_limits: gapsScope,
    coverage_limits: gapsLimits,
  };

  // ── Scope & caveats ──────────────────────────────────────────────────────
  const languageNames = scanCoverage.languages.filter((l) => l.language !== "unknown").map((l) => l.language);
  const toolName = mal ? "ubel-mal" : "ubel-sast";
  const scope = {
    tool: toolName,
    scan_type: mode,
    description: mal
      ? "This report is an automated, AI-assisted review of source code for code that appears to have been written on purpose to do harm, such as backdoors, hidden remote connections and data theft."
      : "This report is an automated, AI-assisted review of source code for security weaknesses, with each candidate then double-checked and traced for exploitability.",
    discovery: "The code was read from disk and split into code units; nothing was run, built, deployed or changed.",
    subject,
    code_units: units,
    files,
    languages: languageNames,
    provider: meta?.provider || null,
    model: meta?.model || null,
    branch: git.branch || null,
    commit: git.latest_commit || null,
    repository: git.url ? safeRemote(git.url) : null,
    options: {
      verification: verifyRan,
      exploitability_check: taintApplicable ? taintRan : null,
      only_diff: !!opts.only_diff,
      diff_base: opts.only_diff ? (opts.diff_base || null) : null,
    },
    generated_at: meta?.generated_at || null,
  };

  const notes = [];
  notes.push("Everything in this report comes from automated analysis of the source code at the time of the scan. It is not a penetration test, and nothing was run or exploited.");
  notes.push("Findings are produced by an AI model and can include false alarms or miss real flaws. Confirm a finding with the code owner before acting on it" + (mal ? ", and treat a confirmed one as a possible compromise." : "."));
  notes.push(`The Findings tab lists every candidate (${recs.length}), including ${S.false_positive} dismissed as false alarms, so its total is higher than the open ${plural(openTotal, noun)} counted here.`);
  notes.push("Compliance references are best-effort guidance and are not a substitute for a formal audit.");
  if (meta?.provider || meta?.model) notes.push("Excerpts of the source code were sent to the AI provider named in this report.");
  else notes.push("Excerpts of the source code were sent to the AI provider configured for the run (the provider was not recorded because defaults were used).");
  for (const g of gaps) notes.push(`${g.charAt(0).toUpperCase() + g.slice(1)}.`);

  const glossary = [
    { term: "Code unit", meaning: "One function, class or configuration block. The scanner splits the code into these and examines each one." },
    { term: "Candidate finding", meaning: "A possible weakness proposed by the AI. It becomes a real finding only after the later checks agree." },
    { term: "Verification", meaning: "A second look by the AI at each candidate, asking whether it is genuinely a problem in context." },
    { term: "Confirmed exploitable", meaning: "The exploitability check found a path by which attacker-controlled input reaches the flawed code with nothing blocking it." },
    { term: "False alarm", meaning: "A candidate that the checks judged not to be a real issue. It is dismissed and not counted as risk." },
    { term: "Not cleared", meaning: "A finding that a check could not settle either way (an error or inconclusive result), or that was never verified. It needs a human decision." },
    { term: "Severity and priority", meaning: "Severity is how serious the type of weakness is in general. Priority is severity weighed by evidence: only a confirmed exploitable finding keeps its full severity." },
    { term: "CWE", meaning: "A public catalog number for a type of software weakness, shown on each finding so that tickets and audits can refer to it." },
    { term: "Static analysis", meaning: "Reviewing source code without running it, as opposed to testing a live system." },
    { term: "Compliance framework", meaning: "A published set of security controls (for example OWASP Top 10 or PCI DSS) that audits and contracts often refer to." },
  ];
  if (mal) glossary.splice(3, 1, { term: "Confirmed malicious", meaning: "Verification judged that the code was written on purpose to do something harmful or unauthorized, not merely that it is poorly written." });

  // Figures that depend on a pass that did not run are null ("not checked"),
  // never 0, so nobody reads them as a clean result.
  const na = (x) => (rated ? x : null);
  const confirmedKnown = mal ? verifyRan !== false : taintRan !== false;
  const confirmedVal = rated && confirmedKnown ? confirmedTotal : null;
  const confirmedLabel = mal ? "Confirmed malicious" : "Confirmed exploitable";
  const confirmedSkipNote = mal ? "Not checked: verification was skipped" : "Not checked: the exploitability check was skipped";

  const worstOpen = worstLevel(levelTotals);
  const policyFigure = verdict
    ? { label: "Policy result", value: verdict.status === "pass" ? "Pass" : "Blocked",
        sub: verdict.status === "pass" ? "Meets the configured security policy" : `${count(verdict.blocking, "finding")} blocking`,
        tone: verdict.status === "pass" ? "none" : "high" }
    : { label: "Policy result", value: null, sub: "The pass/fail setting was not recorded in this report", tone: "" };

  const figures = [
    { label: confirmedLabel, value: confirmedVal, sub: !rated ? "Not checked in this scan" : !confirmedKnown ? confirmedSkipNote : (confirmedTotal ? (mal ? "Verified as intentionally harmful" : (sevSummary(sevConfirmed) || "")) : "None confirmed"), tone: figureTone(confirmedTotal ? (LEVEL_OF_RANK[Math.max(...open.filter((r) => isConfirmed(r.state, mode)).map((r) => LEVEL_RANK[r.level]))] || "high") : "high", confirmedVal) },
    { label: mal ? "Open findings" : "Open issues", value: na(openTotal), sub: rated ? (sevSummary(sevOpen) || "None open") : "Not checked in this scan", tone: figureTone(worstOpen || "medium", na(openTotal)) },
    { label: "Need human review", value: na(notCleared), sub: rated ? "Not cleared either way" : "Not checked in this scan", tone: figureTone("medium", na(notCleared)) },
    policyFigure,
  ];

  const triage = {
    candidates: recs.length,
    confirmed: confirmedTotal,
    exploitable: mal ? null : S.exploitable,
    valid: S.valid,
    mitigated: S.mitigated,
    unresolved: S.unresolved,
    unverified: S.unverified,
    false_positives: S.false_positive,
    statement: `The AI proposed ${count(recs.length, "candidate finding")}. Each falls into exactly one group below; the groups add up to the total. Only the open groups count as risk.`,
  };

  const glanceCards = [
    { label: "Code units analyzed", value: units, sub: `in ${count(files, "file")}`, tone: units === 0 ? "high" : "" },
    { label: "Candidates raised", value: na(recs.length), sub: "Proposed by the AI", tone: "" },
    { label: confirmedLabel, value: confirmedVal, sub: confirmedKnown ? (mal ? "Judged malicious by verification" : "Attacker can reach it") : confirmedSkipNote, tone: figureTone("critical", confirmedVal) },
    ...(mal ? [] : [{ label: "Confirmed real, reach not checked", value: na(S.valid), sub: "Not shown to be exploitable", tone: figureTone("high", na(S.valid)) }]),
    { label: "Not cleared", value: na(S.unresolved), sub: "A check failed or was inconclusive", tone: figureTone("medium", na(S.unresolved)) },
    { label: "Unverified", value: verifyRan === false ? null : na(S.unverified), sub: verifyRan === false ? "Verification was skipped" : "Never double-checked", tone: figureTone("medium", verifyRan === false ? null : na(S.unverified)) },
    ...(mal ? [] : [{ label: "Blocked by other code", value: taintRan === false ? null : na(S.mitigated), sub: taintRan === false ? "Not checked: no exploitability check" : "Real, but not reachable today", tone: "" }]),
    { label: "Dismissed as false alarms", value: verifyRan === false ? null : na(S.false_positive), sub: verifyRan === false ? "Verification was skipped" : "Not counted as risk", tone: "" },
    { label: "Unreadable code units", value: na(unreadable), sub: "AI reply could not be decoded", tone: figureTone("medium", na(unreadable)) },
    { label: "Compliance frameworks", value: complianceOverview ? complianceOverview.frameworks_touched : (rated ? 0 : null), sub: "With at least one related finding", tone: "" },
  ];

  const atGlance = {
    code_units: units,
    files,
    unreadable_code_units: unreadable,
    candidates: na(recs.length),
    open_issues: na(openTotal),
    confirmed: confirmedVal,
    not_cleared: na(notCleared),
    mitigated: taintApplicable && taintRan === false ? null : na(S.mitigated),
    false_positives: verifyRan === false ? null : na(S.false_positive),
    by_severity_open: na(sevOpen),
    by_priority: na(levelTotals),
    compliance_frameworks_touched: complianceOverview ? complianceOverview.frameworks_touched : (rated ? 0 : null),
  };

  // ── One-page summary ─────────────────────────────────────────────────────
  const cover = {
    title: mal ? "Malicious Code Scan — Executive Summary" : "Application Code Security — Executive Summary",
    subject,
    report_id: makeReportId(mal ? "UBEL-MAL" : "UBEL-SAST", meta?.generated_at, toolName, subject),
    generated_at: meta?.generated_at || null,
    tool: `${toolName}${meta?.tool_version ? " " + meta.tool_version : ""}`,
    repository: git.url ? safeRemote(git.url) : null,
    code_version: [git.branch, git.latest_commit ? String(git.latest_commit).slice(0, 12) : null].filter(Boolean).join(" @ ") || null,
    classification: "Confidential — contains security findings; share only with authorized recipients.",
    statement: "Produced by an automated, AI-assisted review of source code the operator is authorized to scan. It reflects the code at the time of the scan; excerpts of the code were sent to the AI provider configured for the run.",
  };

  const bottomLine = {
    risk_level: risk.level,
    risk_label: RISK_LABEL[risk.level],
    summary,
    top_risks: pickTopRisks(keyFindings, 3),
    do_first: actions.filter((a) => a.timeframe !== "Ongoing").slice(0, 3).map(({ timeframe, action, owner }) => ({ timeframe, action, owner })),
    figures,
  };

  return {
    overall_risk: {
      level: risk.level,
      label: RISK_LABEL[risk.level],
      rationale: risk.rationale,
      business_impact: BUSINESS_IMPACT[mode][risk.level],
      basis: "Ratings follow a scale defined by this tool, not CVSS or a regulatory standard. The impact text is general guidance for the rating level, not an assessment of your code.",
    },
    cover,
    bottom_line: bottomLine,
    headline,
    verdict,
    at_a_glance: atGlance,
    triage,
    glance_cards: glanceCards,
    key_findings: keyFindings,
    scan_coverage: scanCoverage,
    risk_areas: areas.map(({ worst_rank, ...t }) => t),
    issues_to_fix_first: issuesToFixFirst,
    files_to_review_first: filesToReview,
    recommended_actions: actions,
    recommended_actions_basis: "Actions are generated from the counts in this report. Timeframes are general defaults built into the tool, not your organization's remediation policy; adjust them to your own standards.",
    compliance_overview: complianceOverview,
    scope,
    methodology: buildMethodology({
      mode, units, files, languages: languageNames,
      provider: meta?.provider || null, model: meta?.model || null,
      verifyRan, taintRan, opts, unreadable, gapsScope, gate,
      hasCompliance: Array.isArray(meta?.compliance_summary?.frameworks),
    }),
    notes,
    glossary,
  };
}