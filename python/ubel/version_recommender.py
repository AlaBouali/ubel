"""
Cross-ecosystem vulnerability fix version recommender.
Zero third-party dependencies.

Supported ecosystems:
  - semver    : npm, Cargo, NuGet, Composer, RubyGems
  - pep440    : PyPI (Python)
  - maven     : Maven (Java)
  - go        : Go modules (proxy.golang.org)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

class Ecosystem(str, Enum):
    SEMVER = "semver"   # npm, Cargo, NuGet, Composer, RubyGems
    PEP440 = "pep440"   # PyPI
    MAVEN  = "maven"    # Maven / Gradle (Java)
    GO     = "go"       # Go modules


@dataclass(frozen=True, order=False)
class VersionDistance:
    """
    Encodes how 'far' a candidate version is from the current one.
    Lower is closer. Used as a sort key; fields are compared left-to-right.
    """
    major_diff:     int
    minor_diff:     int
    patch_diff:     int
    is_pre_release: bool    # stable versions sort before pre-releases
    is_breaking:    bool    # e.g. Go v2+ requires import-path change

    def __lt__(self, other: VersionDistance) -> bool:
        return self._tuple() < other._tuple()

    def _tuple(self):
        # Numeric closeness dominates; is_pre_release is the final tiebreaker.
        # A pre-release patch is still less risky than a stable major bump.
        return (
            self.is_breaking,
            self.major_diff,
            self.minor_diff,
            self.patch_diff,
            self.is_pre_release,
        )


# ---------------------------------------------------------------------------
# 1. Semver  (npm · Cargo · NuGet · Composer · RubyGems)
# ---------------------------------------------------------------------------

@dataclass
class SemverVersion:
    major: int
    minor: int
    patch: int
    pre:   str   # empty string = stable
    build: str   # build metadata — ignored for ordering per spec

    @property
    def is_pre_release(self) -> bool:
        return bool(self.pre)

    def __gt__(self, other: SemverVersion) -> bool:
        if self.major != other.major:
            return self.major > other.major
        if self.minor != other.minor:
            return self.minor > other.minor
        if self.patch != other.patch:
            return self.patch > other.patch
        # pre-release has lower precedence than release
        if self.pre and not other.pre:
            return False
        if not self.pre and other.pre:
            return True
        return _compare_pre_release_identifiers(self.pre, other.pre) > 0


_SEMVER_RE = re.compile(
    r"^[vV]?"
    r"(?P<major>0|[1-9]\d*)"
    r"\.(?P<minor>0|[1-9]\d*)"
    r"\.(?P<patch>0|[1-9]\d*)"
    r"(?:-(?P<pre>[a-zA-Z0-9]+(?:\.[a-zA-Z0-9]+)*))?"
    r"(?:\+(?P<build>[^\s]+))?$"
)

# Relaxed: allow missing minor/patch (e.g. "1.2" or "1")
_SEMVER_RELAXED_RE = re.compile(
    r"^[vV]?"
    r"(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:\.(?P<security>\d+))?"   # 4th segment — Ruby gem security releases (e.g. 2.2.6.3)
    r"(?:-(?P<pre>[a-zA-Z0-9._-]+))?"
    r"(?:\+(?P<build>[^\s]+))?$"
)


def parse_semver(v: str) -> Optional[SemverVersion]:
    m = _SEMVER_RELAXED_RE.match(v.strip())
    if not m:
        return None
    # The 4th segment (security) is folded into patch as a decimal fraction so
    # that 2.2.6.3 > 2.2.6 and 2.2.6.3 > 2.2.6.2 under normal numeric comparison.
    # We encode it as patch = patch * 1000 + security, which preserves ordering
    # for all realistic Ruby gem version numbers.
    major    = int(m.group("major") or 0)
    minor    = int(m.group("minor") or 0)
    patch    = int(m.group("patch") or 0)
    security = int(m.group("security") or 0)
    return SemverVersion(
        major=major,
        minor=minor,
        patch=patch * 1000 + security,  # encode 4th segment
        pre=m.group("pre") or "",
        build=m.group("build") or "",
    )


def _compare_pre_release_identifiers(a: str, b: str) -> int:
    """Semver §11.4: compare dot-separated pre-release identifiers."""
    a_parts = a.split(".")
    b_parts = b.split(".")
    for ap, bp in zip(a_parts, b_parts):
        a_num = ap.isdigit()
        b_num = bp.isdigit()
        if a_num and b_num:
            diff = int(ap) - int(bp)
            if diff:
                return diff
        elif a_num:
            return -1   # numeric < alphanumeric
        elif b_num:
            return 1
        else:
            diff = (ap > bp) - (ap < bp)
            if diff:
                return diff
    return len(a_parts) - len(b_parts)


def _semver_distance(current: SemverVersion, candidate: SemverVersion) -> VersionDistance:
    return VersionDistance(
        major_diff=candidate.major - current.major,
        minor_diff=candidate.minor - current.minor if candidate.major == current.major else candidate.minor,
        patch_diff=candidate.patch - current.patch if (candidate.major == current.major and candidate.minor == current.minor) else candidate.patch,
        is_pre_release=candidate.is_pre_release and not current.is_pre_release,
        is_breaking=False,
    )


# ---------------------------------------------------------------------------
# 2. PEP 440  (PyPI)
# ---------------------------------------------------------------------------

@dataclass
class Pep440Version:
    epoch:    int
    release:  tuple[int, ...]   # e.g. (1, 2, 3)
    pre:      Optional[tuple[str, int]]   # ("a"|"b"|"rc", N)
    post:     Optional[int]
    dev:      Optional[int]

    @property
    def major(self) -> int:
        return self.release[0] if self.release else 0

    @property
    def minor(self) -> int:
        return self.release[1] if len(self.release) > 1 else 0

    @property
    def patch(self) -> int:
        return self.release[2] if len(self.release) > 2 else 0

    @property
    def is_pre_release(self) -> bool:
        # dev and pre-releases are pre-release; post-releases are NOT
        return self.pre is not None or self.dev is not None

    def _sort_key(self):
        # PEP 440 ordering
        pre_key = (0, 0) if self.pre is None else {
            "a":  (-3, self.pre[1]),
            "b":  (-2, self.pre[1]),
            "rc": (-1, self.pre[1]),
        }.get(self.pre[0], (0, 0))
        post_key = self.post if self.post is not None else -1
        dev_key  = self.dev  if self.dev  is not None else float("inf")
        return (self.epoch, self.release, pre_key, post_key, dev_key)

    def __gt__(self, other: Pep440Version) -> bool:
        return self._sort_key() > other._sort_key()


_PEP440_RE = re.compile(
    r"^(?:(?P<epoch>\d+)!)?"
    r"(?P<release>\d+(?:\.\d+)*)"
    r"(?:[-_\.]?(?P<pre>a|alpha|b|beta|c|rc|preview)[-_\.]?(?P<pre_n>\d+)?)?"
    r"(?:[-_\.]?(?:post|rev|r)[-_\.]?(?P<post>\d+)?)?"
    r"(?:[-_\.]?dev[-_\.]?(?P<dev>\d+)?)?$",
    re.IGNORECASE,
)

_PRE_ALIASES = {
    "alpha": "a", "a": "a",
    "beta": "b",  "b": "b",
    "preview": "rc", "c": "rc", "rc": "rc",
}


def parse_pep440(v: str) -> Optional[Pep440Version]:
    m = _PEP440_RE.match(v.strip())
    if not m:
        return None
    epoch   = int(m.group("epoch") or 0)
    release = tuple(int(x) for x in m.group("release").split("."))
    pre_tag = m.group("pre")
    pre     = (_PRE_ALIASES[pre_tag.lower()], int(m.group("pre_n") or 0)) if pre_tag else None
    post    = int(m.group("post")) if m.group("post") is not None else (0 if "post" in v.lower() or "rev" in v.lower() else None)
    dev     = int(m.group("dev")) if m.group("dev") is not None else (0 if "dev" in v.lower() else None)
    return Pep440Version(epoch=epoch, release=release, pre=pre, post=post, dev=dev)


@dataclass(frozen=True, order=False)
class Pep440VersionDistance:
    """Extends VersionDistance with post_rank for PEP 440.

    1.2.4 and 1.2.4.post1 share the same patch_diff, but post1 is a later
    (further) release and should sort after the plain version.
    post_rank: 0 = no post-release, N+1 = .postN.
    """
    major_diff:     int
    minor_diff:     int
    patch_diff:     int
    post_rank:      int
    is_pre_release: bool
    is_breaking:    bool

    def _tuple(self):
        return (
            self.is_breaking,
            self.major_diff,
            self.minor_diff,
            self.patch_diff,
            self.post_rank,
            self.is_pre_release,
        )

    def __lt__(self, other) -> bool:
        return self._tuple() < other._tuple()


def _pep440_distance(current: Pep440Version, candidate: Pep440Version) -> Pep440VersionDistance:
    same_epoch = candidate.epoch == current.epoch
    same_major = same_epoch and candidate.major == current.major
    same_minor = same_major and candidate.minor == current.minor
    # post=None -> rank 0 (plain release), post=0 -> rank 1, post=N -> rank N+1
    post_rank = 0 if candidate.post is None else candidate.post + 1
    return Pep440VersionDistance(
        major_diff=abs(candidate.major - current.major) if same_epoch else 999 + candidate.epoch - current.epoch,
        minor_diff=abs(candidate.minor - current.minor) if same_major else candidate.minor,
        patch_diff=abs(candidate.patch - current.patch) if same_minor else candidate.patch,
        post_rank=post_rank,
        is_pre_release=candidate.is_pre_release and not current.is_pre_release,
        is_breaking=candidate.epoch != current.epoch,
    )


# ---------------------------------------------------------------------------
# 3. Maven  (Java)
# ---------------------------------------------------------------------------

@dataclass
class MavenVersion:
    major:     int
    minor:     int
    patch:     int
    qualifier: str   # e.g. "SNAPSHOT", "Final", "beta-1", ""
    incremental: int  # 4th numeric segment if present

    _QUALIFIER_ORDER = {
        "alpha": -5, "a": -5,
        "beta": -4,  "b": -4,
        "milestone": -3, "m": -3,
        "cr": -2, "rc": -2,
        "snapshot": -1,
        "": 0,
        "ga": 0, "final": 0, "release": 0,
        "sp": 1,
    }

    @staticmethod
    def _split_qualifier(q: str) -> tuple:
        """Split qualifier into (prefix, numeric_suffix).
        'beta-10' -> ('beta', 10), 'SP2' -> ('sp', 2), 'Final' -> ('final', 0).
        Handles numeric suffix after hyphen or directly attached.
        """
        if not q:
            return ("", 0)
        q_lower = q.lower()
        # Try 'prefix-N' or 'prefixN' patterns
        m = re.match(r'^([a-zA-Z]+(?:-[a-zA-Z]+)*)[-.]?(\d+)?$', q)
        if not m:
            return (q_lower, 0)
        prefix = re.sub(r'\d+$', '', m.group(1).lower().rstrip('-'))
        num    = int(m.group(2)) if m.group(2) else 0
        return (prefix, num)

    @property
    def is_pre_release(self) -> bool:
        q = re.sub(r'\d+$', '', self.qualifier.lower().split("-")[0]) if self.qualifier else ""
        return self._QUALIFIER_ORDER.get(q, 0) < 0

    def _qualifier_rank(self) -> int:
        q = re.sub(r'\d+$', '', self.qualifier.lower().split("-")[0]) if self.qualifier else ""
        return self._QUALIFIER_ORDER.get(q, 0)

    def __gt__(self, other: "MavenVersion") -> bool:
        for a, b in [
            (self.major, other.major),
            (self.minor, other.minor),
            (self.patch, other.patch),
            (self.incremental, other.incremental),
        ]:
            if a != b:
                return a > b
        sr, or_ = self._qualifier_rank(), other._qualifier_rank()
        if sr != or_:
            return sr > or_
        # Same rank tier (e.g. both beta): compare numeric suffix (beta-10 > beta-2)
        _, sn = self._split_qualifier(self.qualifier)
        _, on = self._split_qualifier(other.qualifier)
        return sn > on


_MAVEN_RE = re.compile(
    r"^(?P<major>\d+)"
    r"(?:\.(?P<minor>\d+))?"
    r"(?:\.(?P<patch>\d+))?"
    r"(?:\.(?P<incremental>\d+))?"
    r"(?:[.\-](?P<qualifier>[a-zA-Z][a-zA-Z0-9\-]*))?$"
)


def parse_maven(v: str) -> Optional[MavenVersion]:
    m = _MAVEN_RE.match(v.strip())
    if not m:
        return None
    return MavenVersion(
        major=int(m.group("major") or 0),
        minor=int(m.group("minor") or 0),
        patch=int(m.group("patch") or 0),
        incremental=int(m.group("incremental") or 0),
        qualifier=m.group("qualifier") or "",
    )


@dataclass(frozen=True, order=False)
class MavenVersionDistance:
    """Extends VersionDistance with qualifier rank as a tiebreaker."""
    major_diff:     int
    minor_diff:     int
    patch_diff:     int
    is_pre_release: bool
    is_breaking:    bool
    qualifier_rank: float  # tier + numeric suffix encoded; lower = closer to GA

    def _tuple(self):
        return (
            self.is_breaking,
            self.major_diff,
            self.minor_diff,
            self.patch_diff,
            self.is_pre_release,
            self.qualifier_rank,
        )

    def __lt__(self, other) -> bool:
        return self._tuple() < other._tuple()


def _maven_distance(current: MavenVersion, candidate: MavenVersion) -> MavenVersionDistance:
    same_major = candidate.major == current.major
    same_minor = same_major and candidate.minor == current.minor
    # Encode both qualifier tier and numeric suffix so beta-2 < beta-10 within same tier
    _, q_num = MavenVersion._split_qualifier(candidate.qualifier)
    qual_sort = candidate._qualifier_rank() + q_num * 0.001
    return MavenVersionDistance(
        major_diff=candidate.major - current.major,
        minor_diff=candidate.minor - current.minor if same_major else candidate.minor,
        patch_diff=candidate.patch - current.patch if same_minor else candidate.patch,
        is_pre_release=candidate.is_pre_release and not current.is_pre_release,
        is_breaking=False,
        qualifier_rank=qual_sort,
    )


# ---------------------------------------------------------------------------
# 4. Go modules
# ---------------------------------------------------------------------------

@dataclass
class GoVersion:
    major: int   # the vN in module path, extracted from version tag
    minor: int
    patch: int
    pre:   str   # e.g. "beta1", "rc2"

    @property
    def is_pre_release(self) -> bool:
        return bool(self.pre)

    def __gt__(self, other: GoVersion) -> bool:
        for a, b in [(self.major, other.major), (self.minor, other.minor), (self.patch, other.patch)]:
            if a != b:
                return a > b
        if self.pre and not other.pre:
            return False
        if not self.pre and other.pre:
            return True
        return self.pre > other.pre


_GO_RE = re.compile(
    r"^v?(?P<major>\d+)"       # optional v prefix — OSV stores installed versions without it
    r"\.(?P<minor>\d+)"
    r"\.(?P<patch>\d+)"
    r"(?:-(?P<pre>[a-zA-Z0-9.]+))?$"
)


def parse_go(v: str) -> Optional[GoVersion]:
    m = _GO_RE.match(v.strip())
    if not m:
        return None
    return GoVersion(
        major=int(m.group("major")),
        minor=int(m.group("minor")),
        patch=int(m.group("patch")),
        pre=m.group("pre") or "",
    )


def _go_distance(current: GoVersion, candidate: GoVersion) -> VersionDistance:
    # Go v2+ is a BREAKING change — different import path required.
    is_breaking = candidate.major > 1 and candidate.major != current.major
    same_major  = candidate.major == current.major
    same_minor  = same_major and candidate.minor == current.minor
    return VersionDistance(
        major_diff=candidate.major - current.major,
        minor_diff=candidate.minor - current.minor if same_major else candidate.minor,
        patch_diff=candidate.patch - current.patch if same_minor else candidate.patch,
        is_pre_release=candidate.is_pre_release and not current.is_pre_release,
        is_breaking=is_breaking,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def find_closest_fix_versions(
    current_version: str,
    candidate_versions: list[str],
    ecosystem: Ecosystem | str = Ecosystem.SEMVER,
) -> list[str]:
    """
    Given an installed (vulnerable) version and a list of candidate fix
    versions from an OSV advisory, return the candidates sorted from
    closest to furthest — filtered to only those strictly greater than
    the current version.

    Parameters
    ----------
    current_version   : the installed vulnerable version string
    candidate_versions: fix versions from OSV affected[].ranges[].events[fixed]
    ecosystem         : one of Ecosystem.SEMVER / PEP440 / MAVEN / GO
                        (also accepts plain strings "semver", "pep440", etc.)

    Returns
    -------
    List of version strings sorted closest-first. Pre-releases and
    breaking upgrades (Go v2+) are pushed to the end.
    """
    eco = Ecosystem(ecosystem) if isinstance(ecosystem, str) else ecosystem

    parsers = {
        Ecosystem.SEMVER: (parse_semver, _semver_distance),
        Ecosystem.PEP440: (parse_pep440, _pep440_distance),
        Ecosystem.MAVEN:  (parse_maven,  _maven_distance),
        Ecosystem.GO:     (parse_go,     _go_distance),
    }
    parse_fn, distance_fn = parsers[eco]

    current = parse_fn(current_version)
    if current is None:
        return []

    ranked: list[tuple[VersionDistance, str]] = []
    for raw in candidate_versions:
        parsed = parse_fn(raw)
        if parsed is None:
            continue
        if not parsed.__gt__(current):   # keep only versions > current
            continue
        dist = distance_fn(current, parsed)
        ranked.append((dist, raw))

    ranked.sort(key=lambda x: x[0])
    return [v for _, v in ranked]


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def _run_tests() -> None:
    PASS = "\033[92m✓\033[0m"
    FAIL = "\033[91m✗\033[0m"
    failures = 0

    def check(label: str, got: list[str], expected_first: str) -> None:
        nonlocal failures
        ok = bool(got) and got[0] == expected_first
        print(f"  {PASS if ok else FAIL} {label}")
        if not ok:
            print(f"      expected first={expected_first!r}, got={got!r}")
            failures += 1

    def check_order(label: str, got: list[str], expected: list[str]) -> None:
        nonlocal failures
        ok = got == expected
        print(f"  {PASS if ok else FAIL} {label}")
        if not ok:
            print(f"      expected={expected!r}\n      got    ={got!r}")
            failures += 1

    # ---- semver -----------------------------------------------------------
    print("\n[semver]")
    check(
        "basic: pick closest patch",
        find_closest_fix_versions("1.2.3", ["1.4.0", "2.1.0", "1.2.5"], Ecosystem.SEMVER),
        "1.2.5",
    )
    check_order(
        "full sort order",
        find_closest_fix_versions("1.2.3", ["2.1.0", "1.4.0", "1.2.5"], Ecosystem.SEMVER),
        ["1.2.5", "1.4.0", "2.1.0"],
    )
    check(
        "pre-release pushed after stable",
        find_closest_fix_versions("1.2.3", ["1.2.5-beta.1", "1.2.5"], Ecosystem.SEMVER),
        "1.2.5",
    )
    check(
        "build metadata (+) is NOT pre-release",
        find_closest_fix_versions("1.0.0", ["1.0.1+build.1", "1.0.2"], Ecosystem.SEMVER),
        "1.0.1+build.1",
    )
    check(
        "v-prefix stripped",
        find_closest_fix_versions("v1.2.3", ["v1.2.5", "v1.4.0"], Ecosystem.SEMVER),
        "v1.2.5",
    )
    check(
        "candidates <= current excluded",
        find_closest_fix_versions("1.2.3", ["1.2.3", "1.2.2", "1.2.4"], Ecosystem.SEMVER),
        "1.2.4",
    )
    # FIX 1: pre-release patch must beat stable major bump (numeric diffs dominate)
    check(
        "FIX1: pre-release patch preferred over stable major bump",
        find_closest_fix_versions("1.2.3", ["2.0.0", "1.2.4-beta.1"], Ecosystem.SEMVER),
        "1.2.4-beta.1",
    )
    check(
        "FIX1: pre-release patch preferred over stable minor bump (same minor = closer)",
        find_closest_fix_versions("1.2.3", ["1.3.0", "1.2.4-beta.1"], Ecosystem.SEMVER),
        "1.2.4-beta.1",
    )

    # ---- pep440 -----------------------------------------------------------
    print("\n[pep440]")
    check(
        "basic patch pick",
        find_closest_fix_versions("1.2.3", ["1.2.5", "1.4.0", "2.1.0"], Ecosystem.PEP440),
        "1.2.5",
    )
    # FIX 2: plain 1.2.4 is closer than 1.2.4.post1 (post is a later release)
    check(
        "FIX2: plain release preferred over post-release of same version",
        find_closest_fix_versions("1.2.3", ["1.2.4.post1", "1.2.4"], Ecosystem.PEP440),
        "1.2.4",
    )
    check(
        "epoch makes version breaking",
        find_closest_fix_versions("1.9.0", ["1.9.1", "1!2.0.0"], Ecosystem.PEP440),
        "1.9.1",
    )
    check(
        "alpha is pre-release, pushed after stable",
        find_closest_fix_versions("1.2.3", ["1.2.4a1", "1.2.4"], Ecosystem.PEP440),
        "1.2.4",
    )
    check(
        "dev release pushed after stable",
        find_closest_fix_versions("1.0.0", ["1.0.1.dev1", "1.0.1"], Ecosystem.PEP440),
        "1.0.1",
    )

    # ---- maven ------------------------------------------------------------
    print("\n[maven]")
    check(
        "basic patch pick",
        find_closest_fix_versions("1.2.3", ["1.2.5", "1.4.0", "2.0.0"], Ecosystem.MAVEN),
        "1.2.5",
    )
    check(
        "SNAPSHOT is pre-release",
        find_closest_fix_versions("1.2.3", ["1.2.4-SNAPSHOT", "1.2.4"], Ecosystem.MAVEN),
        "1.2.4",
    )
    check(
        "Final qualifier is stable",
        find_closest_fix_versions("1.2.3", ["1.2.4.Final", "1.2.5"], Ecosystem.MAVEN),
        "1.2.4.Final",
    )
    check(
        "SP (service pack) — GA preferred over SP when patch equal",
        find_closest_fix_versions("1.2.3", ["1.2.4.SP1", "1.2.4"], Ecosystem.MAVEN),
        "1.2.4",
    )
    check(
        "alpha is pre-release",
        find_closest_fix_versions("2.0.0", ["2.0.1-alpha", "2.0.1"], Ecosystem.MAVEN),
        "2.0.1",
    )
    # FIX 3: beta-10 > beta-2 (numeric suffix ordering within same qualifier tier)
    check_order(
        "FIX3: beta numeric suffix ordering (beta-2 < beta-10)",
        find_closest_fix_versions("1.0.0-beta-1", ["1.0.0-beta-10", "1.0.0-beta-2"], Ecosystem.MAVEN),
        ["1.0.0-beta-2", "1.0.0-beta-10"],
    )

    # ---- go ---------------------------------------------------------------
    print("\n[go]")
    check(
        "basic patch pick",
        find_closest_fix_versions("v1.2.3", ["v1.2.5", "v1.4.0", "v2.1.0"], Ecosystem.GO),
        "v1.2.5",
    )
    check(
        "v2 is breaking — pushed to end",
        find_closest_fix_versions("v1.9.0", ["v1.9.1", "v2.0.0"], Ecosystem.GO),
        "v1.9.1",
    )
    check_order(
        "breaking upgrades sorted after non-breaking",
        find_closest_fix_versions("v1.2.3", ["v2.1.0", "v1.2.5", "v1.4.0"], Ecosystem.GO),
        ["v1.2.5", "v1.4.0", "v2.1.0"],
    )
    check(
        "pre-release pushed after stable",
        find_closest_fix_versions("v1.2.3", ["v1.2.4-beta1", "v1.2.4"], Ecosystem.GO),
        "v1.2.4",
    )

    # ---- string ecosystem arg --------------------------------------------
    print("\n[string ecosystem arg]")
    check(
        "accepts plain string 'semver'",
        find_closest_fix_versions("1.2.3", ["1.2.5", "2.0.0"], "semver"),
        "1.2.5",
    )

    print(f"\n{'All tests passed.' if failures == 0 else f'{failures} test(s) FAILED.'}\n")


if __name__ == "__main__":
    _run_tests()

    print("─" * 50)
    print("Example — npm (semver):")
    result = find_closest_fix_versions(
        "1.2.3",
        ["1.4.0", "2.1.0", "1.2.5"],
        Ecosystem.SEMVER,
    )
    print(f"  Input  : 1.2.3  candidates: ['1.4.0', '2.1.0', '1.2.5']")
    print(f"  Sorted : {result}")
    print(f"  Pick   : {result[0]}")

    print("\nExample — PyPI (pep440):")
    result = find_closest_fix_versions(
        "1.2.3",
        ["1.2.4a1", "1.2.4.post1", "1!2.0.0", "1.2.4"],
        Ecosystem.PEP440,
    )
    print(f"  Sorted : {result}")

    print("\nExample — Go (breaking v2 pushed last):")
    result = find_closest_fix_versions(
        "v1.2.3",
        ["v2.1.0", "v1.4.0", "v1.2.5"],
        Ecosystem.GO,
    )
    print(f"  Sorted : {result}")