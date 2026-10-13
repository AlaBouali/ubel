// suggested_fixes.js — per-package upgrade suggestions
//
// For every inventory item, looks at all of its vulnerabilities and the fixed
// version of every affected range, then suggests upgrades PER RANGE:
//   - one group per minor range above the installed version (4.17.x, 4.18.x, ...)
//   - then one group per higher major range (5.x, 6.x, ...)
// Inside each range the fewest / highest versions that fix the most
// vulnerabilities are picked (greedy bulk cover). A vulnerability can therefore
// show up in several ranges: each range is an alternative upgrade path.
//
//   item.suggested_fixes = {
//     fixes: [                      // one entry per suggested version, ordered by range then version
//       { version: "4.17.21",
//         count: 3,
//         range: { key: "m:4.17", label: "4.17.x", scope: "minor" | "major" },
//         vulnerabilities: [{ id, finding_key, severity, severity_score, is_infection }, ...],
//         release_confidence?, release_confidence_reason? }   // OS packages only, see below
//     ],
//     unfixed: [{ id, finding_key, severity, severity_score, is_infection }, ...]   // no fix at all
//   }
//
// Vulnerabilities are ordered most severe first (infection, critical, high, ...).
//
// OS packages (deb/rpm/apk) also carry `release_confidence` ("high" | "medium" | "low"): how sure
// we are that the advisory — and therefore the suggested version — is for the installed distro
// release. A fix's confidence is the LOWEST of the vulnerabilities it covers, and is forced to
// "low" when the fix version is built for a different release than the installed one.

const SEV_RANK = { infection: 0, critical: 1, high: 2, medium: 3, low: 4, unknown: 5 };

function sevKey(v) {
  return v.is_infection ? "infection" : String(v.severity || "unknown").toLowerCase();
}

const CONF_RANK = { low: 0, medium: 1, high: 2 };

/** Release a package version is built for, when the version string says so ("el8", "deb12"); else null. */
function releaseTag(version) {
  const v = String(version ?? "");
  const el  = /\.el(\d+)(?![\d])/.exec(v);   if (el)  return `el${el[1]}`;       // rpm: 4.4.20-6.el8_10
  const deb = /\+deb(\d+)u\d+/.exec(v);       if (deb) return `deb${deb[1]}`;      // deb: 1.2-1+deb12u1
  return null;
}

/**
 * Release confidence of ONE upgrade version for an installed OS package.
 * Starts from the advisory's confidence and drops to "low" if the fix version is visibly built for
 * another release (installed 2.4.0-1.el8_10, fix 2.4.0-1.el10_2). Returns null when there is no
 * base confidence (non-OS packages).
 */
export function fixReleaseConfidence(installed, fixVersion, baseConfidence, baseReason) {
  if (!baseConfidence) return null;
  const a = releaseTag(installed), b = releaseTag(fixVersion);
  if (a && b && a !== b) {
    return { confidence: "low", reason: `Fix ${fixVersion} is built for ${b}, but the installed package is ${a}.` };
  }
  return { confidence: baseConfidence, reason: baseReason || "" };
}

function compactVuln(v) {
  return {
    id: v.id,
    // Unique per finding instance (advisory id + component): the same advisory id
    // can be reported against several versions of one package.
    finding_key: v.finding_key || `${v.id}::${v.affected_package_id || ""}`,
    severity: v.severity || "unknown",
    severity_score: v.severity_score != null && !isNaN(parseFloat(v.severity_score))
      ? parseFloat(v.severity_score) : null,
    is_infection: !!v.is_infection,
    ...(v.release_confidence ? { release_confidence: v.release_confidence } : {}),
  };
}

function sortVulns(list) {
  return list.sort((a, b) => {
    const ra = SEV_RANK[a.is_infection ? "infection" : String(a.severity).toLowerCase()] ?? 5;
    const rb = SEV_RANK[b.is_infection ? "infection" : String(b.severity).toLowerCase()] ?? 5;
    if (ra !== rb) return ra - rb;
    const sa = a.severity_score ?? -Infinity, sb = b.severity_score ?? -Infinity;
    if (sa !== sb) return sb - sa;
    return String(a.id).localeCompare(String(b.id));
  });
}

/**
 * Ecosystem-agnostic version comparison (semver / PEP 440 / deb / rpm-ish).
 * Numeric tokens compare numerically; a trailing alpha token (rc, beta, ...)
 * sorts BELOW the same version without it; missing tokens count as 0.
 * Returns -1 / 0 / 1.
 */
export function compareVersions(a, b) {
  a = String(a ?? "").trim().replace(/^v/i, "");
  b = String(b ?? "").trim().replace(/^v/i, "");
  const ea = /^(\d+):/.exec(a), eb = /^(\d+):/.exec(b);
  const epochA = ea ? parseInt(ea[1], 10) : 0, epochB = eb ? parseInt(eb[1], 10) : 0;
  if (epochA !== epochB) return epochA < epochB ? -1 : 1;
  if (ea) a = a.slice(ea[0].length);
  if (eb) b = b.slice(eb[0].length);
  a = a.split("+")[0]; b = b.split("+")[0];            // drop build metadata
  const ta = a.match(/\d+|[a-z]+/gi) || [], tb = b.match(/\d+|[a-z]+/gi) || [];
  const n = Math.max(ta.length, tb.length);
  for (let i = 0; i < n; i++) {
    const x = ta[i], y = tb[i];
    if (x === undefined && y === undefined) return 0;
    if (x === undefined) { if (/^\d+$/.test(y)) { if (parseInt(y, 10) === 0) continue; return -1; } return 1; }
    if (y === undefined) { if (/^\d+$/.test(x)) { if (parseInt(x, 10) === 0) continue; return 1; } return -1; }
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) {
      const d = parseInt(x, 10) - parseInt(y, 10);
      if (d !== 0) return d < 0 ? -1 : 1;
    } else if (nx !== ny) {
      return nx ? 1 : -1;                               // number beats pre-release tag
    } else {
      const c = x.toLowerCase().localeCompare(y.toLowerCase());
      if (c !== 0) return c < 0 ? -1 : 1;
    }
  }
  return 0;
}

/** Affected intervals for one vuln + package: [{ from, to, toInclusive }] and explicit version list. */
function affectedIntervals(vuln) {
  const intervals = [];
  const versions = new Set();
  const dep = String(vuln.affected_dependency || "").toLowerCase();
  let hasRangeData = false;

  for (const item of (vuln.affected || [])) {
    if (String(item.package?.name || "").toLowerCase() !== dep) continue;
    for (const v of (item.versions || [])) versions.add(String(v));
    for (const range of (item.ranges || [])) {
      if (String(range.type || "").toUpperCase() === "GIT") continue;   // commit hashes
      hasRangeData = true;
      const events = [...(range.events || [])].sort((x, y) => {
        const vx = x.introduced ?? x.fixed ?? x.last_affected ?? x.limit ?? "0";
        const vy = y.introduced ?? y.fixed ?? y.last_affected ?? y.limit ?? "0";
        return compareVersions(vx === "0" ? "0" : vx, vy === "0" ? "0" : vy);
      });
      let start = null;
      for (const e of events) {
        if (e.introduced !== undefined) start = e.introduced;
        else if (e.fixed !== undefined) {
          intervals.push({ from: start ?? "0", to: e.fixed, toInclusive: false }); start = null;
        } else if (e.last_affected !== undefined) {
          intervals.push({ from: start ?? "0", to: e.last_affected, toInclusive: true }); start = null;
        }
      }
      if (start !== null) intervals.push({ from: start, to: null, toInclusive: false });  // open-ended
    }
  }
  return { intervals, versions, hasRangeData };
}

/** Does installing `candidate` leave `vuln` fixed? */
function candidateFixes(candidate, vuln, info) {
  if (!info.hasRangeData) {
    // No range data to reason about branches: fixed if at/after any known fix.
    return (vuln.fixed_versions || []).some(f => compareVersions(candidate, f) >= 0);
  }
  if (info.versions.has(candidate)) return false;
  for (const iv of info.intervals) {
    const afterStart = compareVersions(candidate, iv.from) >= 0;
    const beforeEnd = iv.to === null ? true
      : (iv.toInclusive ? compareVersions(candidate, iv.to) <= 0 : compareVersions(candidate, iv.to) < 0);
    if (afterStart && beforeEnd) return false;
  }
  return true;
}

/** Leading major / minor numbers of a version (epoch and "v" prefix ignored). */
function majorMinor(v) {
  const s = String(v ?? "").trim().replace(/^v/i, "").replace(/^\d+:/, "");
  const m = s.match(/\d+/g) || [];
  return { major: m[0] !== undefined ? parseInt(m[0], 10) : 0, minor: m[1] !== undefined ? parseInt(m[1], 10) : 0 };
}

/**
 * Which range a candidate upgrade belongs to, relative to the installed version:
 *   same major  -> a "minor" range, one per major.minor line (4.17.x, 4.18.x)
 *   higher major -> a "major" range, one per major (5.x, 6.x)
 * `order` sorts minor ranges first (closest first), then major ranges.
 */
function rangeOf(candidate, installed) {
  const c = majorMinor(candidate), i = majorMinor(installed);
  if (c.major === i.major) {
    return { key: "m:" + c.major + "." + c.minor, label: c.major + "." + c.minor + ".x", scope: "minor", order: [0, c.major, c.minor] };
  }
  return { key: "M:" + c.major, label: c.major + ".x", scope: "major", order: [1, c.major, 0] };
}

function compareRangeOrder(a, b) {
  for (let i = 0; i < 3; i++) if (a.order[i] !== b.order[i]) return a.order[i] - b.order[i];
  return 0;
}

/**
 * Compute `suggested_fixes` for one package from its vulnerabilities.
 */
export function computeSuggestedFixes(item, vulnerabilities) {
  const vulns = vulnerabilities.filter(v => v.affected_package_id === item.id);
  const installed = item.version || "";

  const fixable = [];      // { vuln, info }
  const unfixed = [];
  const candidates = new Set();

  for (const v of vulns) {
    const ups = (v.fixed_versions || []).filter(f => !installed || compareVersions(f, installed) > 0);
    if (!ups.length) { unfixed.push(compactVuln(v)); continue; }
    fixable.push({ vuln: v, info: affectedIntervals(v) });
    ups.forEach(f => candidates.add(f));
  }

  // For each candidate: the set of fixable vulns it resolves.
  const cands = [...candidates].map(version => ({
    version,
    ids: new Set(fixable.filter(f => candidateFixes(version, f.vuln, f.info)).map(f => f.vuln.id)),
  }));

  // Group candidates by range (minor ranges first, then major ranges).
  const groups = new Map();
  for (const c of cands) {
    const r = rangeOf(c.version, installed);
    if (!groups.has(r.key)) groups.set(r.key, { range: r, cands: [] });
    groups.get(r.key).cands.push(c);
  }

  // Greedy bulk cover INSIDE each range: take the version that fixes the most
  // still-open vulns (ties -> highest version), repeat until nothing more can
  // be fixed in that range.
  const fixes = [];
  const coveredAnywhere = new Set();
  const remainingAll = new Map(fixable.map(f => [f.vuln.id, f.vuln]));   // id → full vuln (for reasons)
  for (const { range, cands: groupCands } of groups.values()) {
    const remaining = new Map(fixable.map(f => [f.vuln.id, f.vuln]));
    while (remaining.size) {
      let best = null, bestHits = 0;
      for (const c of groupCands) {
        let hits = 0;
        for (const id of c.ids) if (remaining.has(id)) hits++;
        if (hits > bestHits || (hits === bestHits && best && hits > 0 && compareVersions(c.version, best.version) > 0)) {
          best = c; bestHits = hits;
        }
      }
      if (!best || bestHits === 0) break;
      const covered = [];
      for (const id of best.ids) {
        if (remaining.has(id)) { covered.push(compactVuln(remaining.get(id))); remaining.delete(id); coveredAnywhere.add(id); }
      }
      // Lowest release confidence among the vulns this version covers (OS packages only).
      let lowest = null;
      for (const c of covered) {
        if (c.release_confidence && (!lowest || CONF_RANK[c.release_confidence] < CONF_RANK[lowest.release_confidence])) lowest = c;
      }
      const fc = lowest
        ? fixReleaseConfidence(installed, best.version, lowest.release_confidence,
            (remainingAll.get(lowest.id) || {}).release_confidence_reason)
        : null;
      fixes.push({
        version: best.version,
        count: covered.length,
        range: { key: range.key, label: range.label, scope: range.scope },
        order: range.order,
        vulnerabilities: sortVulns(covered),
        ...(fc ? { release_confidence: fc.confidence, release_confidence_reason: fc.reason } : {}),
      });
    }
  }
  // Anything a fix version was listed for but no candidate in any range actually
  // clears (e.g. inconsistent range data) is reported as unfixed, not dropped.
  for (const f of fixable) {
    if (!coveredAnywhere.has(f.vuln.id)) unfixed.push(compactVuln(f.vuln));
  }

  // Closest range first (minor ranges, then major ranges); highest version first inside a range.
  fixes.sort((a, b) => compareRangeOrder(a, b) || compareVersions(b.version, a.version));
  for (const f of fixes) delete f.order;
  return { fixes, unfixed: sortVulns(unfixed) };
}

/** Attach `suggested_fixes` to every inventory item (in place). */
export function attachSuggestedFixes(inventory, vulnerabilities) {
  for (const item of inventory) {
    try {
      item.suggested_fixes = computeSuggestedFixes(item, vulnerabilities);
    } catch (e) {
      item.suggested_fixes = { fixes: [], unfixed: [], error: e.message };
    }
  }
}