// version_recommender.js
// Zero-dependency version upgrade recommender.
// Supports semver, PEP 440, Maven, and Go version schemes.

const ECOSYSTEMS_VR = {
  semver: { parse: _vr_parseSemver,  gt: _vr_semverGt,  distance: _vr_semverDistance  },
  pep440: { parse: _vr_parsePep440,  gt: _vr_pep440Gt,  distance: _vr_pep440Distance  },
  maven:  { parse: _vr_parseMaven,   gt: _vr_mavenGt,   distance: _vr_mavenDistance   },
  go:     { parse: _vr_parseGo,      gt: _vr_goGt,      distance: _vr_goDistance      },
};

function _vr_purlToEcosystem(purl) {
  if (!purl) return "semver";
  if (purl.startsWith("pkg:pypi/"))    return "pep440";
  if (purl.startsWith("pkg:maven/"))   return "maven";
  if (purl.startsWith("pkg:golang/"))  return "go";
  return "semver"; // npm, cargo, nuget, gem, composer, unknown → semver
}

function _vr_compareDistances(a, b) {
  if (a.isBreaking !== b.isBreaking) return a.isBreaking ? 1 : -1;
  if (a.majorDiff  !== b.majorDiff)  return a.majorDiff - b.majorDiff;
  if (a.minorDiff  !== b.minorDiff)  return a.minorDiff - b.minorDiff;
  if (a.patchDiff  !== b.patchDiff)  return a.patchDiff - b.patchDiff;
  // securityDiff only ever set by the semver path's 4th-segment (Ruby gem
  // security release) comparison; ?? 0 makes this a no-op for maven/go,
  // which never populate it.
  if ((a.securityDiff ?? 0) !== (b.securityDiff ?? 0)) return (a.securityDiff ?? 0) - (b.securityDiff ?? 0);
  if ((a.postRank ?? 0) !== (b.postRank ?? 0)) return (a.postRank ?? 0) - (b.postRank ?? 0);
  if (a.isPreRelease !== b.isPreRelease) return a.isPreRelease ? 1 : -1;
  if ((a.qualifierRank ?? 0) !== (b.qualifierRank ?? 0)) return (a.qualifierRank ?? 0) - (b.qualifierRank ?? 0);
  return 0;
}

function _vr_compatLevel(dist) {
  if (dist.isBreaking) return "low";
  let level = dist.majorDiff > 0 ? "low" : dist.minorDiff > 0 ? "medium" : "high";
  if (dist.isPreRelease) {
    if (level === "high")   return "medium";
    if (level === "medium") return "low";
  }
  return level;
}

// ── semver ──
// optional v prefix, relaxed minor/patch, 4th security segment for Ruby gems (e.g. rack 2.2.6.3)
const _VR_SEMVER_RE = /^[vV]?(?<major>\d+)(?:\.(?<minor>\d+))?(?:\.(?<patch>\d+))?(?:\.(?<security>\d+))?(?:-(?<pre>[a-zA-Z0-9._-]+))?(?:\+(?<build>[^\s]+))?$/;
function _vr_parseSemver(v) {
  const m = _VR_SEMVER_RE.exec(v.trim());
  if (!m || !m.groups) return null;
  const { major, minor, patch, security, pre } = m.groups;
  // `patch` and `security` (the optional 4th segment used by Ruby gem
  // security releases, e.g. rack 2.2.6.3) are kept as SEPARATE fields and
  // compared as a true two-level tuple in _vr_semverGt/_vr_semverDistance
  // below — never combined into one number. An earlier version encoded
  // them as `patch * 1000 + security`, which silently inverts ordering as
  // soon as `security` reaches 1000 (e.g. 2.2.6.1000 encoded to the same
  // value as 2.2.7.0), which would have corrupted the fix-recommendation
  // comparison this function feeds. There is no upper bound on a version
  // segment, so any fixed-width encoding has the same failure mode —
  // comparing the fields directly removes the bound entirely.
  return { major: parseInt(major,10), minor: minor !== undefined ? parseInt(minor,10) : 0,
           patch: patch !== undefined ? parseInt(patch,10) : 0,
           security: security !== undefined ? parseInt(security,10) : 0,
           pre: pre ?? "" };
}
function _vr_cmpPre(a, b) {
  const ap = a.split("."), bp = b.split(".");
  for (let i = 0; i < Math.max(ap.length, bp.length); i++) {
    const ai = ap[i], bi = bp[i];
    if (ai === undefined) return -1;
    if (bi === undefined) return  1;
    const an = /^\d+$/.test(ai), bn = /^\d+$/.test(bi);
    if (an && bn) { const d = parseInt(ai,10) - parseInt(bi,10); if (d) return d; }
    else if (an) return -1;
    else if (bn) return  1;
    else { if (ai < bi) return -1; if (ai > bi) return 1; }
  }
  return 0;
}
function _vr_semverGt(a, b) {
  if (a.major !== b.major) return a.major > b.major;
  if (a.minor !== b.minor) return a.minor > b.minor;
  if (a.patch !== b.patch) return a.patch > b.patch;
  if (a.security !== b.security) return a.security > b.security;
  if (a.pre && !b.pre) return false;
  if (!a.pre && b.pre) return true;
  return _vr_cmpPre(a.pre, b.pre) > 0;
}
function _vr_semverDistance(cur, can) {
  const sm = can.major === cur.major, si = sm && can.minor === cur.minor;
  const sp = si && can.patch === cur.patch;
  return { isBreaking: false,
    majorDiff: can.major - cur.major,
    minorDiff: sm ? can.minor - cur.minor : can.minor,
    patchDiff: si ? can.patch - cur.patch : can.patch,
    // securityDiff carries the 4th-segment delta (e.g. Ruby gem security
    // releases) once major/minor/patch are already equal, so a recommender
    // sorting by "closest fix" still prefers 2.2.6.4 over 2.2.7.0 when both
    // are valid fix candidates for a version pinned at 2.2.6.3.
    securityDiff: sp ? can.security - cur.security : can.security,
    isPreRelease: Boolean(can.pre) && !Boolean(cur.pre) };
}

// ── pep440 ──
const _VR_PEP440_RE = new RegExp(
  "^(?:(?<epoch>\\d+)!)?" +
  "(?<release>\\d+(?:\\.\\d+)*)" +
  "(?:[-_.]?(?<pre>a|alpha|b|beta|c|rc|preview)[-_.]?(?<pre_n>\\d+)?)?" +
  "(?:[-_.]?(?:post|rev|r)[-_.]?(?<post>\\d+)?)?" +
  "(?:[-_.]?dev[-_.]?(?<dev>\\d+)?)?$", "i");
const _VR_PRE_ALIASES = { alpha:"a",a:"a",beta:"b",b:"b",preview:"rc",c:"rc",rc:"rc" };
function _vr_parsePep440(v) {
  const m = _VR_PEP440_RE.exec(v.trim());
  if (!m || !m.groups) return null;
  const { epoch, release, pre, pre_n, post, dev } = m.groups;
  const vl = v.toLowerCase();
  const preTag = pre ? _VR_PRE_ALIASES[pre.toLowerCase()] : null;
  return {
    epoch:   parseInt(epoch ?? "0", 10),
    release: release.split(".").map(n => parseInt(n, 10)),
    pre:     preTag ? [preTag, parseInt(pre_n ?? "0", 10)] : null,
    post:    post !== undefined ? parseInt(post,10) : (vl.includes("post")||vl.includes("rev") ? 0 : null),
    dev:     dev  !== undefined ? parseInt(dev, 10) : (vl.includes("dev") ? 0 : null),
  };
}
function _vr_pep440Key(v) {
  const [maj=0,min=0,pat=0] = v.release;
  const prk = v.pre === null ? 0 : ({a:-3,b:-2,rc:-1}[v.pre[0]]??0);
  const prn = v.pre === null ? 0 : v.pre[1];
  return [v.epoch, maj, min, pat, prk, prn, v.post !== null ? v.post : -1, v.dev !== null ? v.dev : Infinity];
}
function _vr_cmpArrays(a, b) {
  for (let i=0; i<Math.max(a.length,b.length); i++) {
    const ai=a[i]??0, bi=b[i]??0;
    if (ai<bi) return -1; if (ai>bi) return 1;
  }
  return 0;
}
function _vr_pep440Gt(a, b) { return _vr_cmpArrays(_vr_pep440Key(a), _vr_pep440Key(b)) > 0; }
function _vr_pep440Distance(cur, can) {
  const [cm=0,cmin=0,cp=0] = cur.release;
  const [nm=0,nmin=0,np=0] = can.release;
  const se = can.epoch === cur.epoch, sm = se && nm===cm, si = sm && nmin===cmin;
  const postRank = can.post === null ? 0 : can.post + 1;
  return { isBreaking: can.epoch !== cur.epoch,
    majorDiff: se ? Math.abs(nm-cm) : 999+(can.epoch-cur.epoch),
    minorDiff: sm ? Math.abs(nmin-cmin) : nmin,
    patchDiff: si ? Math.abs(np-cp) : np,
    postRank,
    isPreRelease: (can.pre !== null || can.dev !== null) && (cur.pre === null && cur.dev === null) };
}

// ── maven ──
const _VR_QUAL_ORDER = { alpha:-5,a:-5,beta:-4,b:-4,milestone:-3,m:-3,cr:-2,rc:-2,snapshot:-1,"":0,ga:0,final:0,release:0,sp:1 };
const _VR_MAVEN_RE = /^(?<major>\d+)(?:\.(?<minor>\d+))?(?:\.(?<patch>\d+))?(?:\.(?<incr>\d+))?(?:[.\-](?<qual>[a-zA-Z][a-zA-Z0-9\-]*))?$/;
function _vr_splitQual(q) {
  if (!q) return ["", 0];
  const m = /^([a-zA-Z]+(?:-[a-zA-Z]+)*)[-.]?(\d+)?$/.exec(q);
  if (!m) return [q.toLowerCase(), 0];
  const prefix = m[1].toLowerCase().replace(/-$/, "").replace(/\d+$/, "");
  return [prefix, m[2] !== undefined ? parseInt(m[2],10) : 0];
}
function _vr_qualRank(q) {
  const tier = q.toLowerCase().split("-")[0].replace(/\d+$/,"");
  return _VR_QUAL_ORDER[tier] ?? 0;
}
function _vr_parseMaven(v) {
  const m = _VR_MAVEN_RE.exec(v.trim());
  if (!m || !m.groups) return null;
  const { major, minor, patch, incr, qual } = m.groups;
  return { major: parseInt(major,10), minor: minor!==undefined?parseInt(minor,10):0,
           patch: patch!==undefined?parseInt(patch,10):0, incr: incr!==undefined?parseInt(incr,10):0,
           qualifier: qual ?? "" };
}
function _vr_mavenGt(a, b) {
  for (const [av,bv] of [[a.major,b.major],[a.minor,b.minor],[a.patch,b.patch],[a.incr,b.incr]]) {
    if (av !== bv) return av > bv;
  }
  const ar = _vr_qualRank(a.qualifier), br = _vr_qualRank(b.qualifier);
  if (ar !== br) return ar > br;
  const [,an] = _vr_splitQual(a.qualifier), [,bn] = _vr_splitQual(b.qualifier);
  return an > bn;
}
function _vr_mavenDistance(cur, can) {
  const sm = can.major===cur.major, si = sm && can.minor===cur.minor;
  const [,qn] = _vr_splitQual(can.qualifier);
  return { isBreaking: false,
    majorDiff: can.major-cur.major,
    minorDiff: sm ? can.minor-cur.minor : can.minor,
    patchDiff: si ? can.patch-cur.patch : can.patch,
    isPreRelease: _vr_qualRank(can.qualifier)<0 && _vr_qualRank(cur.qualifier)>=0,
    qualifierRank: _vr_qualRank(can.qualifier) + qn*0.001 };
}

// ── go ──
// optional v prefix — OSV stores installed versions without it
const _VR_GO_RE = /^v?(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)(?:-(?<pre>[a-zA-Z0-9.]+))?$/;
function _vr_parseGo(v) {
  const m = _VR_GO_RE.exec(v.trim());
  if (!m || !m.groups) return null;
  const { major, minor, patch, pre } = m.groups;
  return { major: parseInt(major,10), minor: parseInt(minor,10), patch: parseInt(patch,10), pre: pre ?? "" };
}
function _vr_goGt(a, b) {
  if (a.major!==b.major) return a.major>b.major;
  if (a.minor!==b.minor) return a.minor>b.minor;
  if (a.patch!==b.patch) return a.patch>b.patch;
  if (a.pre && !b.pre) return false; if (!a.pre && b.pre) return true;
  return a.pre > b.pre;
}
function _vr_goDistance(cur, can) {
  const isBreaking = can.major > 1 && can.major !== cur.major;
  const sm = can.major===cur.major, si = sm && can.minor===cur.minor;
  return { isBreaking,
    majorDiff: can.major-cur.major,
    minorDiff: sm ? can.minor-cur.minor : can.minor,
    patchDiff: si ? can.patch-cur.patch : can.patch,
    isPreRelease: Boolean(can.pre) && !Boolean(cur.pre) };
}

/**
 * Given an installed vulnerable version and candidate fix versions from OSV,
 * return an array of result objects sorted closest-first.
 * @param {string}   currentVersion
 * @param {string[]} candidateVersions
 * @param {string}   ecosystem  - "semver" | "pep440" | "maven" | "go"
 * @returns {{ version: string, recommended: boolean, compatibility_level: "low"|"medium"|"high" }[]}
 */
export default function findClosestFixVersions(currentVersion, candidateVersions, ecosystem = "semver") {
  const eco = ECOSYSTEMS_VR[ecosystem] || ECOSYSTEMS_VR.semver;
  const current = eco.parse(currentVersion);
  if (!current) return [];
  const ranked = [];
  for (const raw of candidateVersions) {
    const parsed = eco.parse(raw);
    if (!parsed || !eco.gt(parsed, current)) continue;
    ranked.push({ dist: eco.distance(current, parsed), raw });
  }
  ranked.sort((a, b) => _vr_compareDistances(a.dist, b.dist));
  return ranked.map(({ dist, raw }, idx) => ({
    version:             raw,
    recommended:         idx === 0,
    compatibility_level: _vr_compatLevel(dist),
  }));
}


// ── Self-test (run with: node version_recommender.js) ────────────────────────

function _runTests() {
  const PASS = "\x1b[92m✓\x1b[0m";
  const FAIL = "\x1b[91m✗\x1b[0m";
  let failures = 0;

  const versions = r => r.map(x => x.version);

  function check(label, got, expectedFirst) {
    const vs = versions(got);
    const ok = vs.length > 0 && vs[0] === expectedFirst;
    console.log(`  ${ok ? PASS : FAIL} ${label}`);
    if (!ok) { console.log(`      expected first=${JSON.stringify(expectedFirst)}, got=${JSON.stringify(vs)}`); failures++; }
  }

  function checkOrder(label, got, expected) {
    const vs = versions(got);
    const ok = JSON.stringify(vs) === JSON.stringify(expected);
    console.log(`  ${ok ? PASS : FAIL} ${label}`);
    if (!ok) { console.log(`      expected=${JSON.stringify(expected)}\n      got    =${JSON.stringify(vs)}`); failures++; }
  }

  // ── semver ────────────────────────────────────────────────────────────────
  console.log("\n[semver]");
  check(
    "basic: pick closest patch",
    findClosestFixVersions("1.2.3", ["1.4.0", "2.1.0", "1.2.5"]),
    "1.2.5",
  );
  checkOrder(
    "full sort order",
    findClosestFixVersions("1.2.3", ["2.1.0", "1.4.0", "1.2.5"]),
    ["1.2.5", "1.4.0", "2.1.0"],
  );
  check(
    "pre-release pushed after stable",
    findClosestFixVersions("1.2.3", ["1.2.5-beta.1", "1.2.5"]),
    "1.2.5",
  );
  check(
    "build metadata (+) is NOT pre-release",
    findClosestFixVersions("1.0.0", ["1.0.1+build.1", "1.0.2"]),
    "1.0.1+build.1",
  );
  check(
    "v-prefix stripped",
    findClosestFixVersions("v1.2.3", ["v1.2.5", "v1.4.0"]),
    "v1.2.5",
  );
  check(
    "candidates <= current excluded",
    findClosestFixVersions("1.2.3", ["1.2.3", "1.2.2", "1.2.4"]),
    "1.2.4",
  );
  check(
    "FIX1: pre-release patch preferred over stable major bump",
    findClosestFixVersions("1.2.3", ["2.0.0", "1.2.4-beta.1"]),
    "1.2.4-beta.1",
  );
  check(
    "FIX1: pre-release patch preferred over stable minor bump",
    findClosestFixVersions("1.2.3", ["1.3.0", "1.2.4-beta.1"]),
    "1.2.4-beta.1",
  );
  check(
    "ruby 4th segment: 2.2.6.4 closer than 2.2.7.0",
    findClosestFixVersions("2.2.6.3", ["2.2.7.0", "2.2.6.4"]),
    "2.2.6.4",
  );

  // ── pep440 ───────────────────────────────────────────────────────────────
  console.log("\n[pep440]");
  check(
    "basic patch pick",
    findClosestFixVersions("1.2.3", ["1.2.5", "1.4.0", "2.1.0"], "pep440"),
    "1.2.5",
  );
  check(
    "FIX2: plain release preferred over post-release of same version",
    findClosestFixVersions("1.2.3", ["1.2.4.post1", "1.2.4"], "pep440"),
    "1.2.4",
  );
  check(
    "epoch makes version breaking",
    findClosestFixVersions("1.9.0", ["1.9.1", "1!2.0.0"], "pep440"),
    "1.9.1",
  );
  check(
    "alpha is pre-release, pushed after stable",
    findClosestFixVersions("1.2.3", ["1.2.4a1", "1.2.4"], "pep440"),
    "1.2.4",
  );
  check(
    "dev release pushed after stable",
    findClosestFixVersions("1.0.0", ["1.0.1.dev1", "1.0.1"], "pep440"),
    "1.0.1",
  );

  // ── maven ─────────────────────────────────────────────────────────────────
  console.log("\n[maven]");
  check(
    "basic patch pick",
    findClosestFixVersions("1.2.3", ["1.2.5", "1.4.0", "2.0.0"], "maven"),
    "1.2.5",
  );
  check(
    "SNAPSHOT is pre-release",
    findClosestFixVersions("1.2.3", ["1.2.4-SNAPSHOT", "1.2.4"], "maven"),
    "1.2.4",
  );
  check(
    "Final qualifier is stable",
    findClosestFixVersions("1.2.3", ["1.2.4.Final", "1.2.5"], "maven"),
    "1.2.4.Final",
  );
  check(
    "SP (service pack) — GA preferred over SP when patch equal",
    findClosestFixVersions("1.2.3", ["1.2.4.SP1", "1.2.4"], "maven"),
    "1.2.4",
  );
  check(
    "alpha is pre-release",
    findClosestFixVersions("2.0.0", ["2.0.1-alpha", "2.0.1"], "maven"),
    "2.0.1",
  );
  checkOrder(
    "FIX3: beta numeric suffix ordering (beta-2 < beta-10)",
    findClosestFixVersions("1.0.0-beta-1", ["1.0.0-beta-10", "1.0.0-beta-2"], "maven"),
    ["1.0.0-beta-2", "1.0.0-beta-10"],
  );

  // ── go ────────────────────────────────────────────────────────────────────
  console.log("\n[go]");
  check(
    "basic patch pick",
    findClosestFixVersions("v1.2.3", ["v1.2.5", "v1.4.0", "v2.1.0"], "go"),
    "v1.2.5",
  );
  check(
    "v2 is breaking — pushed to end",
    findClosestFixVersions("v1.9.0", ["v1.9.1", "v2.0.0"], "go"),
    "v1.9.1",
  );
  checkOrder(
    "breaking upgrades sorted after non-breaking",
    findClosestFixVersions("v1.2.3", ["v2.1.0", "v1.2.5", "v1.4.0"], "go"),
    ["v1.2.5", "v1.4.0", "v2.1.0"],
  );
  check(
    "pre-release pushed after stable",
    findClosestFixVersions("v1.2.3", ["v1.2.4-beta1", "v1.2.4"], "go"),
    "v1.2.4",
  );

  // ── purl helper ───────────────────────────────────────────────────────────
  console.log("\n[_vr_purlToEcosystem]");
  const ecoTests = [
    ["pkg:pypi/requests@2.0.0",  "pep440"],
    ["pkg:maven/org.foo/bar@1.0", "maven"],
    ["pkg:golang/github.com/foo/bar@v1.0.0", "go"],
    ["pkg:npm/lodash@4.0.0",     "semver"],
    ["pkg:cargo/serde@1.0.0",    "semver"],
    [null,                        "semver"],
  ];
  for (const [purl, expected] of ecoTests) {
    const got = _vr_purlToEcosystem(purl);
    const ok = got === expected;
    console.log(`  ${ok ? PASS : FAIL} purlToEcosystem(${JSON.stringify(purl)}) → ${expected}`);
    if (!ok) { console.log(`      got=${JSON.stringify(got)}`); failures++; }
  }

  console.log(`\n${failures === 0 ? "All tests passed." : `${failures} test(s) FAILED.`}\n`);
}

// ── Demo ─────────────────────────────────────────────────────────────────────

function _runDemo() {
  console.log("─".repeat(50));
  console.log("Example — npm (semver):");
  let result = findClosestFixVersions("1.2.3", ["1.4.0", "2.1.0", "1.2.5"]);
  console.log(`  Input  : 1.2.3  candidates: ['1.4.0', '2.1.0', '1.2.5']`);
  console.log(`  Sorted : ${JSON.stringify(result.map(r => r.version))}`);
  console.log(`  Pick   : ${result[0].version}  (recommended=${result[0].recommended}, compat=${result[0].compatibility_level})`);

  console.log("\nExample — PyPI (pep440):");
  result = findClosestFixVersions("1.2.3", ["1.2.4a1", "1.2.4.post1", "1!2.0.0", "1.2.4"], "pep440");
  for (const r of result)
    console.log(`  ${r.version.padEnd(20)}  recommended=${r.recommended}  compat=${r.compatibility_level}`);

  console.log("\nExample — Go (breaking v2 pushed last):");
  result = findClosestFixVersions("v1.2.3", ["v2.1.0", "v1.4.0", "v1.2.5"], "go");
  for (const r of result)
    console.log(`  ${r.version.padEnd(20)}  recommended=${r.recommended}  compat=${r.compatibility_level}`);
}

// detect direct execution: node version_recommender.js
import { fileURLToPath as _fup } from "url";
if (process.argv[1] === _fup(import.meta.url)) {
  _runTests();
  _runDemo();
}