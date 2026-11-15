// vm/lib/executive_summary.js
//
// Builds the `executive_summary` section of a ubel-vm / ubel-k8s report: a plain-language overview for readers who
// will not open the Findings tab (management, risk, audit). It follows the rules of cloud/lib/executive_summary.js
// and sca/executive_summary.js and produces the same JSON shape, so the same HTML tab renders it:
//   - derived only from the finished report payload (findings, checks, coverage, compliance) — no new scanning;
//   - a figure that was not evaluated is `null` / "not assessed", never 0, so an unassessed baseline never reads as clean;
//   - `info` findings are notes, not risks: they never drive the rating or the "top risks".
// The rating rules in buildMethodology() are a prose copy of overallRisk() — change them together.

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Informational' };
const RISK_LABEL = { critical: 'Critical', high: 'High', medium: 'Moderate', low: 'Low', none: 'Minimal', unknown: 'Not fully assessed' };
const TIMEFRAME = { critical: 'Immediately', high: 'Within 7 days', medium: 'Within 30 days', low: 'Within 90 days', info: 'Ongoing' };
const BUSINESS_IMPACT = {
  critical: 'At least one issue could let an attacker take control or reach sensitive data with little effort. Treat it as an incident-level exposure.',
  high: 'Serious weaknesses are present that an attacker could realistically use to escalate access or move through the environment.',
  medium: 'Hardening gaps exist that, combined with another weakness, could be used against the environment. None is an immediate emergency.',
  low: 'Only minor hardening gaps were found. They are worth fixing as routine maintenance.',
  none: 'No issues were found in the checks that could be evaluated.',
  unknown: 'No issues were found, but part of the baseline could not be evaluated, so this is not evidence that the environment is clean.',
};

const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;
const sevKey = (s) => (SEV_RANK[s] === undefined ? 'info' : s);
const worstOf = (sev) => ['critical', 'high', 'medium', 'low'].find((k) => sev[k] > 0) || null;
const trunc = (s, n) => { s = String(s || ''); return s.length > n ? s.slice(0, n - 1).trimEnd() + '…' : s; };
const firstSentence = (s) => { const m = String(s || '').match(/^.*?[.!?](?:\s|$)/); return (m ? m[0] : String(s || '')).trim(); };
const resKey = (f) => `${f.area}::${f.scope || ''}::${f.resource}`;

function overallRisk(sev, riskTotal, notAssessed) {
  if (sev.critical) return { level: 'critical', rationale: `${plural(sev.critical, 'critical issue was', 'critical issues were')} found.` };
  if (sev.high) return { level: 'high', rationale: `${plural(sev.high, 'high-severity issue was', 'high-severity issues were')} found and no critical ones.` };
  if (sev.medium) return { level: 'medium', rationale: `${plural(sev.medium, 'medium-severity issue was', 'medium-severity issues were')} found and nothing more serious.` };
  if (sev.low) return { level: 'low', rationale: `Only ${plural(sev.low, 'low-severity issue was', 'low-severity issues were')} found.` };
  if (notAssessed) return { level: 'unknown', rationale: `No issues were found, but ${plural(notAssessed, 'check could', 'checks could')} not be evaluated.` };
  return { level: 'none', rationale: riskTotal ? 'Only informational notes were found.' : 'No issues were found.' };
}

export function buildExecutiveSummary(report) {
  const P = report.profile || {};
  const areasInfo = P.areas || {};
  const noun = P.subject_noun || 'environment';
  const findings = Array.isArray(report.findings) ? report.findings : [];
  const cov = report.coverage || {};
  const opts = report.scan_options || {};
  const riskFindings = findings.filter((f) => sevKey(f.severity) !== 'info');
  const sev = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) sev[sevKey(f.severity)]++;
  const riskTotal = riskFindings.length;
  const seriousTotal = sev.critical + sev.high;
  const resources = new Set(riskFindings.map(resKey));
  const areaLabel = (a) => (areasInfo[a] && areasInfo[a].label) || a;

  // ── issue types (one row per check id) ────────────────────────────────────
  const byCheck = new Map();
  for (const f of riskFindings) {
    if (!byCheck.has(f.check)) byCheck.set(f.check, { check: f.check, title: f.title, area: f.area, rank: 0, count: 0, res: new Set(), remediation: f.remediation, description: f.description });
    const e = byCheck.get(f.check);
    e.rank = Math.max(e.rank, SEV_RANK[f.severity]);
    e.count++;
    e.res.add(resKey(f));
  }
  const rankKey = (r) => ['info', 'low', 'medium', 'high', 'critical'][r];
  const issues = [...byCheck.values()].sort((a, b) => b.rank - a.rank || b.res.size - a.res.size || a.title.localeCompare(b.title));

  // ── areas ─────────────────────────────────────────────────────────────────
  const byArea = new Map();
  for (const f of riskFindings) {
    if (!byArea.has(f.area)) byArea.set(f.area, { area: f.area, issues: 0, res: new Set(), rank: 0 });
    const e = byArea.get(f.area);
    e.issues++; e.res.add(resKey(f)); e.rank = Math.max(e.rank, SEV_RANK[f.severity]);
  }
  const riskAreas = [...byArea.values()].sort((a, b) => b.rank - a.rank || b.issues - a.issues).map((e) => ({
    title: areaLabel(e.area), plain: (areasInfo[e.area] && areasInfo[e.area].plain) || '', issues: e.issues, resources_affected: e.res.size,
    worst_severity: rankKey(e.rank), worst_severity_label: SEV_LABEL[rankKey(e.rank)],
  }));

  // ── resources ─────────────────────────────────────────────────────────────
  const byRes = new Map();
  for (const f of riskFindings) {
    const k = resKey(f);
    if (!byRes.has(k)) byRes.set(k, { name: f.resource, area: areaLabel(f.area), scope: f.scope || '', issues: 0, rank: 0, weight: 0 });
    const e = byRes.get(k);
    e.issues++; e.rank = Math.max(e.rank, SEV_RANK[f.severity]); e.weight += Math.pow(4, SEV_RANK[f.severity]);
  }
  const topResources = [...byRes.values()].sort((a, b) => b.weight - a.weight || b.issues - a.issues).slice(0, 5).map((e) => ({
    name: e.name, area: e.area, scope: e.scope, issues: e.issues, worst_severity: rankKey(e.rank), worst_severity_label: SEV_LABEL[rankKey(e.rank)],
  }));

  // ── rating ────────────────────────────────────────────────────────────────
  const risk = overallRisk(sev, riskTotal, cov.not_assessed || 0);
  const subject = (report.target && report.target.subject) || (noun === 'cluster' ? 'Kubernetes cluster' : 'Virtual machine');
  const incomplete = cov.status === 'partial';
  const summary = riskTotal
    ? `${plural(riskTotal, 'issue was', 'issues were')} found on this ${noun}, of which ${seriousTotal} ${seriousTotal === 1 ? 'is' : 'are'} critical or high. ` +
      `${cov.evaluated ? `${cov.passed} of ${cov.evaluated} evaluated checks passed.` : ''}${incomplete ? ` ${plural(cov.not_assessed, 'check could', 'checks could')} not be evaluated, so the picture is incomplete.` : ''}`
    : (incomplete
      ? `No issues were found in the ${cov.evaluated || 0} checks that could be evaluated, but ${plural(cov.not_assessed, 'check could', 'checks could')} not be assessed. This is not evidence that the ${noun} is clean.`
      : `No issues were found in the ${cov.evaluated || 0} checks evaluated on this ${noun}.`);

  // ── actions ───────────────────────────────────────────────────────────────
  const actions = issues.slice(0, 8).map((e, i) => {
    const sk = rankKey(e.rank);
    const owner = (areasInfo[e.area] && areasInfo[e.area].owner) || null;
    return {
      priority: i + 1, timeframe: TIMEFRAME[sk], owner,
      action: `${e.title}${e.res.size > 1 ? ` (${e.res.size} affected)` : ''}`,
      why: trunc(firstSentence(e.description), 220) + ' ' + trunc(e.remediation, 240),
    };
  });
  if (incomplete) {
    actions.push({ priority: actions.length + 1, timeframe: 'Within 7 days', owner: 'Security team', action: 'Complete the assessment of the checks that could not be evaluated',
      why: `${plural(cov.not_assessed, 'check was', 'checks were')} not assessed (see the Scan Info tab). Re-run with the required access, or record why they are out of scope.` });
  }

  // ── figures ───────────────────────────────────────────────────────────────
  const tone = (k) => (k ? k : 'none');
  const worst = worstOf(sev);
  const figures = [
    { label: 'Issues found', value: riskTotal, tone: tone(worst), sub: riskTotal ? plural(resources.size, 'resource', 'resources') + ' affected' : null },
    { label: 'Critical or high', value: seriousTotal, tone: sev.critical ? 'critical' : (sev.high ? 'high' : 'none'), sub: seriousTotal ? 'need attention first' : 'none found' },
    { label: 'Checks passed', value: cov.evaluated ? `${cov.passed} / ${cov.evaluated}` : null, tone: 'none', sub: cov.pass_rate == null ? null : `${cov.pass_rate}% of evaluated` },
    { label: 'Not assessed', value: cov.not_assessed == null ? null : cov.not_assessed, tone: cov.not_assessed ? 'medium' : 'none', sub: cov.not_assessed ? 'could not be evaluated' : 'everything applicable ran' },
  ];
  const glance = [
    { label: 'Issue types', value: byCheck.size, sub: 'distinct checks failing' },
    { label: 'Areas affected', value: byArea.size, sub: `of ${Object.keys(cov.by_area || {}).length} areas checked` },
    { label: 'Not applicable', value: cov.not_applicable == null ? null : cov.not_applicable, sub: 'do not apply to this ' + noun },
    { label: 'Medium / low', value: sev.medium + sev.low, sub: 'hardening gaps' },
    { label: 'Informational notes', value: sev.info, sub: 'not counted as risks' },
    { label: 'Frameworks touched', value: (report.compliance_summary && report.compliance_summary.frameworks || []).length, sub: 'see the Compliance tab' },
  ];

  // ── coverage rows (one per area) ──────────────────────────────────────────
  const coverageRows = Object.keys(cov.by_area || {}).sort().map((a) => {
    const c = cov.by_area[a];
    const own = riskFindings.filter((f) => f.area === a);
    const ownSev = { critical: 0, high: 0, medium: 0, low: 0 };
    for (const f of own) ownSev[sevKey(f.severity)]++;
    const evald = (c.pass || 0) + (c.fail || 0);
    const status = c.unassessed ? (evald ? 'partial' : 'skipped') : 'scanned';
    const w = evald ? (worstOf(ownSev) || 'none') : null;
    return {
      name: areaLabel(a), status, status_label: status === 'scanned' ? 'Evaluated' : (status === 'partial' ? 'Incomplete' : (c.na && !c.unassessed ? 'Not applicable' : 'Not assessed')),
      scope: `${evald} evaluated, ${c.na || 0} n/a${c.unassessed ? `, ${c.unassessed} not assessed` : ''}`, reason: null,
      issues: evald ? own.length : null, worst_severity: w, worst_severity_label: w === 'none' ? 'None found' : (w ? SEV_LABEL[w] : null),
    };
  });

  // ── compliance ────────────────────────────────────────────────────────────
  const fws = (report.compliance_summary && report.compliance_summary.frameworks) || [];
  const complianceOverview = fws.length ? {
    statement: `${plural(riskTotal + sev.info, 'finding maps', 'findings map')} to ${plural(fws.length, 'compliance framework', 'compliance frameworks')}. The frameworks with the most affected findings are listed below.`,
    most_affected: fws.slice(0, 5).map((f) => ({ framework: f.name + (f.version ? ' ' + f.version : ''), findings: f.findings_count })),
    disclaimer: (report.compliance_summary && report.compliance_summary.disclaimer) || '',
  } : null;

  const keyFindings = issues.slice(0, 10).map((e) => ({
    severity: rankKey(e.rank), title: e.title,
    detail: `${plural(e.res.size, 'resource is', 'resources are')} affected. ${trunc(firstSentence(e.description), 260)}`,
  }));
  const topRisks = issues.slice(0, 3).map((e) => ({ severity: rankKey(e.rank), title: e.title, detail: trunc(firstSentence(e.description), 200) }));

  return {
    overall_risk: { level: risk.level, label: RISK_LABEL[risk.level], rationale: risk.rationale, business_impact: BUSINESS_IMPACT[risk.level],
      basis: 'Ratings follow a scale defined by this tool, not CVSS or a regulatory standard. The impact text is general guidance for the rating level, not an assessment of your environment.' },
    cover: {
      title: P.exec_title || 'Security Posture — Executive Summary', subject, report_id: report.report_id || null, generated_at: report.generated_at || null,
      tool: report.tool ? `${report.tool}${report.tool_version ? ' ' + report.tool_version : ''}` : null,
      classification: 'Confidential — contains security findings; share only with authorized recipients.',
      statement: P.statement || 'Produced by a read-only review of a system the operator is authorized to assess. It reflects its state at the time of the scan.',
    },
    bottom_line: {
      risk_level: risk.level, risk_label: RISK_LABEL[risk.level], summary,
      top_risks: topRisks,
      do_first: actions.filter((a) => a.timeframe !== 'Ongoing').slice(0, 3).map(({ timeframe, action, owner }) => ({ timeframe, action, owner })),
      figures,
    },
    headline: summary,
    glance_cards: glance,
    key_findings: keyFindings,
    coverage_rows: coverageRows,
    risk_areas: riskAreas,
    issues_to_fix_first: issues.slice(0, 5).map((e) => ({
      title: e.title, reference: e.check, area: areaLabel(e.area), resources_affected: e.res.size,
      worst_severity: rankKey(e.rank), worst_severity_label: SEV_LABEL[rankKey(e.rank)], action: trunc(e.remediation, 200),
    })),
    resources_to_review_first: topResources,
    recommended_actions: actions,
    recommended_actions_basis: 'Actions are generated from the counts in this report. Timeframes are general defaults built into the tool, not your organization\'s remediation policy; adjust them to your own standards.',
    compliance_overview: complianceOverview,
    scope: { description: P.scope_description || '', discovery: P.discovery || '' },
    methodology: {
      steps: P.method_steps || [],
      rating_rules: [
        { level: 'Critical', rule: 'At least one critical finding.' },
        { level: 'High', rule: 'No critical finding, at least one high.' },
        { level: 'Moderate', rule: 'No critical or high finding, at least one medium.' },
        { level: 'Low', rule: 'Only low findings.' },
        { level: 'Minimal', rule: 'No findings (informational notes excepted) and every applicable check was evaluated.' },
        { level: 'Not fully assessed', rule: 'No findings, but at least one applicable check could not be evaluated.' },
      ],
      prioritization: 'Issue types are ranked by their worst severity, then by how many resources they affect. Resources are ranked by a score that weights each finding by severity (a critical finding counts four times a high one).',
      timeframes: 'Critical: immediately. High: within 7 days. Medium: within 30 days. Low: within 90 days. These are defaults, not your organization\'s policy. Suggested owners are generic roles.',
      limitations: [
        ...(P.limitations || []),
        'Check outcomes are reported as passed, failed, not applicable or not assessed. "Not assessed" means the check applies but could not be evaluated (for example permission denied); it is never counted as a pass.',
        'Compliance references are best-effort guidance, not a certified assessment.',
        ...(opts.min_severity && opts.min_severity !== 'info' ? [`Findings below ${opts.min_severity} severity were hidden by --min-severity.`] : []),
      ],
    },
    notes: [
      ...(cov.notes || []),
      ...(sev.info ? [`${plural(sev.info, 'informational note is', 'informational notes are')} listed in the Findings tab and not counted as risks.`] : []),
    ],
    glossary: [
      ...(P.glossary || []),
      { term: 'Check', meaning: 'One test in the baseline, for example "SSH permits root login".' },
      { term: 'Finding', meaning: 'A check that failed on one resource. One check can produce several findings.' },
      { term: 'Not assessed', meaning: 'A check that applies but could not be evaluated, usually for lack of access.' },
      { term: 'Compliance framework', meaning: 'A published control catalogue (for example NIST SP 800-53 or the CIS Benchmarks) that findings are mapped to.' },
    ],
  };
}
