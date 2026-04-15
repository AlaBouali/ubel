"""
package_scanner.py
==================
Lists all installed system packages for a Linux host,
a running Docker container, or a Docker image.

Supported ecosystems
--------------------
  debian / ubuntu   →  dpkg
  alpine            →  apk
  redhat / almalinux / rockylinux  →  rpm

Output
------
A list of dicts, one per package:

    {
        "id":           "pkg:deb/ubuntu/bash@5.2.21-2ubuntu4",
        "name":         "bash",
        "version":      "5.2.21-2ubuntu4",
        "ecosystem":    "ubuntu",
        "licence":      "unknown",
        "paths":        ["/usr/bin/bash", "/usr/bin/rbash"],
        "dependencies": ["pkg:deb/ubuntu/libc6@2.39-0ubuntu8.4", ...]
    }

``dependencies`` contains purls of packages that are themselves present in
the scanned set.  References to packages not found in the scan (virtual
packages, uninstalled optional deps, etc.) are omitted.

Usage
-----
  Edit the ENTRYPOINT section at the bottom, then:

      python package_scanner.py          # prints JSON to stdout

  Or import and call directly:

      from package_scanner import scan_host, scan_container, scan_image

      packages = scan_host()             # returns list[dict]
"""

import json
import os
import subprocess
import tarfile
import tempfile
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Generator, Optional

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
# Default to WARNING so this module is quiet when used as a library.
# Callers can lower the level:  logging.getLogger("package_scanner").setLevel(logging.DEBUG)
# Running as __main__ sets INFO automatically (see bottom of file).

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

ALLOWED: set[str] = {
    "debian",
    "ubuntu",
    "redhat",
    "almalinux",
    "alpine",
    "rockylinux",
}

SUBPROCESS_TIMEOUT = 120        # seconds — for rpm/snap/flatpak calls
DOCKER_EXPORT_TIMEOUT = 600    # seconds — docker export can be slow for large containers
DOCKER_SAVE_TIMEOUT = 600      # seconds — docker save can be slow for large images

# ---------------------------------------------------------------------------
# DATA MODEL
# ---------------------------------------------------------------------------


@dataclass(slots=True)
class PackageFile:
    ecosystem: str
    package: str
    version: str
    license: str          # SPDX expression or raw licence string; "unknown" if absent
    binary: str           # ,,,-separated list of executable paths owned by this package
    deps: str             # comma-separated list of direct dependency package names

    def __str__(self) -> str:
        return (
            f"{self.ecosystem}\t{self.package}\t{self.version}\t"
            f"{self.license}\t{self.binary}\t{self.deps}"
        )


BINARY_SEP = ",,,"   # separator used to join multiple binary paths in one record


def _group_by_package(
    records: Generator["PackageFile", None, None],
) -> Generator["PackageFile", None, None]:
    """
    Collapse multiple per-binary PackageFile records for the same package into
    a single record whose ``binary`` field contains all paths joined by
    ``BINARY_SEP`` (``",,,""``).

    Guarantees:
    - One output record per (ecosystem, package) pair — matches the full
      package inventory, equivalent to ``dpkg-query -W`` / ``rpm -qa`` /
      ``apk info``.
    - Binary paths are deduplicated and sorted.
    - Packages with no executable binaries are still emitted with an empty
      ``binary`` field so the package inventory is complete.
    - All other fields (version, license, deps) are taken from the first
      record seen for that package.
    """
    seen: dict[tuple[str, str], PackageFile] = {}

    for rec in records:
        key = (rec.ecosystem, rec.package)
        if key not in seen:
            seen[key] = rec
        else:
            existing = seen[key]
            existing_bins = set(existing.binary.split(BINARY_SEP)) if existing.binary else set()
            if rec.binary:
                existing_bins.add(rec.binary)
            object.__setattr__(existing, "binary", BINARY_SEP.join(sorted(existing_bins)))

    yield from seen.values()




# Conventional directories that contain runnable binaries.
# Used when we cannot call os.access() — i.e. image LayerFS scanning where
# we have path strings but no real inodes.
_BINARY_DIR_PREFIXES: tuple[str, ...] = (
    "/bin/",
    "/sbin/",
    "/usr/bin/",
    "/usr/sbin/",
    "/usr/local/bin/",
    "/usr/local/sbin/",
    "/usr/lib/",        # catches nested bin dirs e.g. /usr/lib/git-core/git
    "/usr/libexec/",
    "/opt/",
)


def _is_executable_path(path: str) -> bool:
    """
    Return True if *path* looks like a runnable binary.

    For host / container scans (real filesystem) we check the actual execute
    bit.  This function handles the path-convention check used for image scans
    where inodes are unavailable.  Callers that have a real path use
    ``os.access(path, os.X_OK)`` directly.
    """
    return path.startswith(_BINARY_DIR_PREFIXES) and not path.endswith("/")


def _is_executable_real(path: str) -> bool:
    """Check execute permission on a real filesystem path."""
    try:
        return os.path.isfile(path) and os.access(path, os.X_OK)
    except OSError:
        return False


# ---------------------------------------------------------------------------
# DEPENDENCY STRING HELPERS
# ---------------------------------------------------------------------------

import re as _re

_DEP_NAME_RE = _re.compile(r"^([A-Za-z0-9_.+\-]+)")


def _parse_dep_field(raw: str) -> str:
    """
    Parse a raw dependency field into a comma-separated list of package names.

    Handles:
      - version constraints:  ``libc6 (>= 2.17)``  →  ``libc6``
      - alternative deps:     ``awk | mawk``        →  ``awk,mawk``
      - multi-dep commas:     ``bash, libc6``       →  ``bash,libc6``
      - virtual/empty fields: returns ``""``
    """
    if not raw or raw.strip() == "":
        return ""

    names: list[str] = []
    # Split on commas first (AND-dependencies), then on pipes (OR-alternatives)
    for clause in raw.split(","):
        for alt in clause.split("|"):
            alt = alt.strip()
            m = _DEP_NAME_RE.match(alt)
            if m:
                names.append(m.group(1))

    return ",".join(dict.fromkeys(names))  # preserve order, deduplicate





# ---------------------------------------------------------------------------
# UTILITIES
# ---------------------------------------------------------------------------


def _normalize(v: str) -> str:
    """Lower-case, strip spaces and hyphens for ecosystem matching."""
    return v.lower().replace(" ", "").replace("-", "")


def _parse_os_release(content: str) -> str:
    """
    Parse /etc/os-release (or /usr/lib/os-release) and return a canonical
    ecosystem name from ALLOWED.  Raises RuntimeError if unsupported.
    """
    data: dict[str, str] = {}
    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        data[k.strip()] = v.strip().strip('"').strip("'")

    candidates: list[str] = []
    if "ID" in data:
        candidates.append(_normalize(data["ID"]))
    if "ID_LIKE" in data:
        for token in data["ID_LIKE"].split():
            candidates.append(_normalize(token))

    for c in candidates:
        if c in ALLOWED:
            return c

    raise RuntimeError(
        f"Unsupported OS ecosystem {candidates!r}. Allowed: {sorted(ALLOWED)}"
    )


# ---------------------------------------------------------------------------
# HOST OS DETECTION
# ---------------------------------------------------------------------------


def detect_host_ecosystem() -> str:
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        if os.path.exists(p):
            with open(p) as fh:
                return _parse_os_release(fh.read())
    raise RuntimeError("Cannot detect OS ecosystem: no os-release file found on host")


# ---------------------------------------------------------------------------
# CONTAINER OS DETECTION  (running container via docker exec)
# ---------------------------------------------------------------------------


def detect_container_ecosystem(container: str) -> str:
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            out = subprocess.check_output(
                ["docker", "exec", container, "cat", path],
                text=True,
                stderr=subprocess.DEVNULL,
                timeout=SUBPROCESS_TIMEOUT,
            )
            return _parse_os_release(out)
        except subprocess.CalledProcessError:
            pass
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timed out reading {path} from container {container!r}")
    raise RuntimeError(f"Cannot detect OS ecosystem in container {container!r}")


# ---------------------------------------------------------------------------
# LAYER FS  — stream a Docker image, extract package DB files only
# ---------------------------------------------------------------------------


class LayerFS:
    """
    Extract package database files from a Docker image by streaming its layers.

    Design
    ------
    Package managers (dpkg, apk, rpm) store the authoritative list of installed
    packages and their owned files in their own databases.  Those databases
    already reflect the final installed state: removed packages are absent,
    upgraded packages show the new file list.  We only need the DB files.

    Merge strategy: last write wins
    --------------------------------
    Layers are processed in order (base → top).  Each DB file found in a later
    layer simply overwrites whatever was stored from an earlier layer.  This
    correctly handles the one edge case that matters for DB files:

        layer 1: writes  /var/lib/dpkg/status   ← stored
        layer 2: deletes /var/lib/dpkg/status   ← key removed by whiteout
        layer 3: writes  /var/lib/dpkg/status   ← overwrites / re-adds

    Full OCI whiteout semantics (.wh. / .wh..wh..opq) are NOT implemented.
    This is intentional: whiteouts are only relevant for full filesystem
    reconstruction (file hashing, secrets scanning, licence detection).  For
    package inventory the DB files are self-consistent and authoritative.

    ⚠  Do not repurpose this class for full filesystem reconstruction without
    re-adding proper whiteout handling.
    """

    def __init__(self, image: str) -> None:
        self.files: dict[str, bytes] = {}
        self._load(image)

    # Paths we care about — only package database files and OS detection
    # files are stored.  Everything else is discarded immediately, keeping
    # peak RAM at O(package DB size) — typically a few MB per image.
    PACKAGE_DB_PREFIXES: tuple[str, ...] = (
        "/var/lib/dpkg/",           # Debian / Ubuntu
        "/lib/apk/db/",             # Alpine
        "/var/lib/rpm/",            # RedHat / AlmaLinux / RockyLinux ≤ 8
        "/usr/lib/sysimage/rpm/",   # RHEL / AlmaLinux / RockyLinux 9+ (migrated DB)
        "/etc/os-release",          # OS detection
        "/usr/lib/os-release",
    )

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _canonical(name: str) -> str:
        """
        Normalise a tar entry name to an absolute path with no trailing slash.

        tar archives store entries as bare relative paths (``etc/os-release``)
        or with a leading ``./`` (``./etc/os-release``).  We prepend ``/`` and
        run posixpath.normpath so that both forms — and any ``../`` components —
        are resolved safely to a canonical absolute path.

        posixpath.normpath is used instead of str.lstrip("./") because lstrip
        strips *any leading combination* of ``.`` and ``/`` characters, not the
        literal prefix ``./``, which can silently mangle valid filenames.
        """
        import posixpath
        return posixpath.normpath("/" + name)

    def _process_layer(self, layer_tar: tarfile.TarFile) -> None:
        """
        Apply one layer using last-write-wins merge.

        Whiteout entries are skipped entirely.  For package DB scanning this
        is safe: DB files are self-consistent and a later layer that re-writes
        a DB file will naturally overwrite any stale copy from a lower layer.
        See class docstring for full rationale.

        os-release symlink handling
        ---------------------------
        On RHEL / AlmaLinux / RockyLinux 9+, ``/etc/os-release`` is a symlink
        to ``/usr/lib/os-release``.  Minimal images may only ship the real file
        at ``/usr/lib/os-release``; the symlink entry is skipped by the
        ``member.isfile()`` guard.  We therefore record symlinks for the two
        os-release paths in a side-table and alias them after the main loop so
        that both ``/etc/os-release`` and ``/usr/lib/os-release`` are always
        resolvable in ``self.files``.
        """
        import posixpath as _pp

        # side-table: canonical symlink path → resolved target path
        os_release_symlinks: dict[str, str] = {}

        for member in layer_tar:
            path = self._canonical(member.name)

            # Track os-release symlinks before skipping non-files
            if member.issym() and path in ("/etc/os-release", "/usr/lib/os-release"):
                target = member.linkname
                if not target.startswith("/"):
                    target = _pp.normpath(_pp.join(_pp.dirname(path), target))
                os_release_symlinks[path] = target
                continue

            if not member.isfile():
                continue

            if not path.startswith(self.PACKAGE_DB_PREFIXES):
                continue

            try:
                fobj = layer_tar.extractfile(member)
                if fobj is not None:
                    self.files[path] = fobj.read()  # last write wins
            except Exception as exc:  # noqa: BLE001
                log.debug("LayerFS: skipping %s — %s", path, exc)

        # Resolve os-release symlinks: if the symlink path is not yet stored
        # but the target is, copy the bytes so both keys are available.
        for link_path, target_path in os_release_symlinks.items():
            if link_path not in self.files and target_path in self.files:
                self.files[link_path] = self.files[target_path]
                log.debug("LayerFS: aliased %s → %s", link_path, target_path)

    def _load(self, image: str) -> None:
        """
        Stream ``docker save`` output and process layers without buffering.

        Layer ordering
        --------------
        Docker's ``docker save`` always emits layers in the correct application
        order (base → top), matching the order in manifest.json.  We rely on
        this guarantee and process layers in stream order, which lets us avoid
        buffering any layer data at all.

        Memory profile
        --------------
        Peak RAM ≈ size of package DB files (a few MB), regardless of image
        size.  Previously each layer was fully buffered as a BytesIO object,
        meaning a 2 GB CUDA image would consume ~2 GB of RAM.  Now only the
        filtered files from PACKAGE_DB_PREFIXES are retained.

        Streaming constraint
        --------------------
        The outer tar is opened in streaming mode (``r|``), which is
        forward-only and non-seekable.  Inner layer tars are also opened in
        streaming mode (``r|``) directly from the outer stream entry's file
        object — no intermediate BytesIO.  This means we cannot seek back to
        re-read a layer; every decision must be made in a single forward pass.
        """
        proc = subprocess.Popen(
            ["docker", "save", image],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if proc.stdout is None:
            raise RuntimeError(f"docker save {image!r}: failed to open stdout pipe")

        try:
            outer = tarfile.open(fileobj=proc.stdout, mode="r|")

            for member in outer:
                if not member.isfile():
                    continue

                fobj = outer.extractfile(member)
                if fobj is None:
                    continue

                name = member.name

                if name == "manifest.json":
                    # Read for informational / future use; layer order is
                    # already correct in the stream so we don't need to
                    # reorder here.
                    _ = fobj.read()

                elif name.endswith(".tar"):
                    # Open the inner layer tar directly from the streaming
                    # file object — zero buffering, zero extra RAM.
                    layer_tar = tarfile.open(fileobj=fobj, mode="r|")
                    self._process_layer(layer_tar)

        finally:
            proc.stdout.close()
            proc.wait()

        if proc.returncode not in (0, None):
            stderr = proc.stderr.read().decode(errors="replace") if proc.stderr else ""
            raise RuntimeError(
                f"docker save {image!r} failed (rc={proc.returncode}): {stderr.strip()}"
            )


def detect_image_ecosystem(image: str) -> str:
    fs = LayerFS(image)
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        data = fs.files.get(p)
        if data:
            return _parse_os_release(data.decode(errors="replace"))
    raise RuntimeError(f"Cannot detect OS ecosystem in image {image!r}")


# ---------------------------------------------------------------------------
# DPKG SCANNER  (Debian / Ubuntu)
# ---------------------------------------------------------------------------


def _parse_dpkg_status(content: str) -> dict[str, tuple[str, str, str]]:
    """
    Return {package_name: (version, license, deps)} from dpkg status file.

    ``deps`` is a comma-separated string of direct dependency package names
    with version constraints and alternatives already resolved to plain names.
    ``license`` falls back to ``"unknown"`` — the License: field is rarely
    present in binary package status files.
    """
    packages: dict[str, tuple[str, str, str]] = {}
    pkg: Optional[str] = None
    ver: Optional[str] = None
    lic: Optional[str] = None
    dep: Optional[str] = None

    for line in content.splitlines():
        if line.startswith("Package:"):
            pkg = line.split(":", 1)[1].strip()
        elif line.startswith("Version:"):
            ver = line.split(":", 1)[1].strip()
        elif line.startswith("License:"):
            lic = line.split(":", 1)[1].strip()
        elif line.startswith("Depends:"):
            dep = line.split(":", 1)[1].strip()
        elif line.strip() == "":
            if pkg and ver:
                packages[pkg] = (
                    ver,
                    lic or "unknown",
                    _parse_dep_field(dep or ""),
                )
            pkg = None
            ver = None
            lic = None
            dep = None

    # flush last stanza
    if pkg and ver:
        packages[pkg] = (ver, lic or "unknown", _parse_dep_field(dep or ""))

    return packages


def _pkg_name_from_list_stem(stem: str) -> str:
    """
    dpkg .list files are named  <pkg>[:<arch>].list
    Strip the optional architecture suffix.
    """
    return stem.split(":")[0]


def scan_dpkg_root(
    root: Path, ecosystem: str
) -> Generator[PackageFile, None, None]:
    status_path = root / "var/lib/dpkg/status"
    info_dir = root / "var/lib/dpkg/info"

    if not status_path.exists():
        log.warning("dpkg status file not found at %s", status_path)
        return

    with open(status_path) as fh:
        packages = _parse_dpkg_status(fh.read())

    # Emit one seed record per known package (binary="" until we find executables)
    for pkg, (version, license_, deps) in packages.items():
        yield PackageFile(ecosystem, pkg, version, license_, "", deps)

    if not info_dir.exists():
        log.warning("dpkg info dir not found at %s", info_dir)
        return

    for list_file in info_dir.glob("*.list"):
        pkg = _pkg_name_from_list_stem(list_file.stem)
        version, license_, deps = packages.get(pkg, ("unknown", "unknown", ""))
        with open(list_file) as fh:
            for line in fh:
                filepath = line.strip()
                if filepath and _is_executable_real(str(root / filepath.lstrip("/"))):
                    yield PackageFile(ecosystem, pkg, version, license_, filepath, deps)


def scan_dpkg_layerfs(
    fs: LayerFS, ecosystem: str
) -> Generator[PackageFile, None, None]:
    status_data = fs.files.get("/var/lib/dpkg/status")
    if not status_data:
        log.warning("dpkg: /var/lib/dpkg/status not found in image")
        return

    packages = _parse_dpkg_status(status_data.decode(errors="replace"))

    # Seed one record per package so packages with no executables still appear
    for pkg, (version, license_, deps) in packages.items():
        yield PackageFile(ecosystem, pkg, version, license_, "", deps)

    for path, data in fs.files.items():
        if not path.startswith("/var/lib/dpkg/info/"):
            continue
        if not path.endswith(".list"):
            continue
        stem = Path(path).stem
        pkg = _pkg_name_from_list_stem(stem)
        version, license_, deps = packages.get(pkg, ("unknown", "unknown", ""))
        for line in data.decode(errors="replace").splitlines():
            filepath = line.strip()
            if filepath and _is_executable_path(filepath):
                yield PackageFile(ecosystem, pkg, version, license_, filepath, deps)


# ---------------------------------------------------------------------------
# APK SCANNER  (Alpine)
# ---------------------------------------------------------------------------


def _scan_apk_lines(
    lines: list[str], ecosystem: str
) -> Generator[PackageFile, None, None]:
    """
    Parse the Alpine apk installed database (flat text format).

    Key fields
    ----------
    P: package name
    V: version
    L: license (SPDX expression)
    D: dependencies (space-separated, may include version constraints)
    F: directory prefix for the following R: entries
    R: filename within F

    Emits one seed record per package (binary="") so packages with no
    executables still appear in the final output, then additional records
    for each executable binary found.
    """
    pkg: Optional[str] = None
    version: Optional[str] = None
    license_: str = "unknown"
    deps: str = ""
    prefix: str = ""
    pkg_seeded: bool = False

    for line in lines:
        line = line.rstrip("\n")

        if line.startswith("P:"):
            pkg = line[2:].strip()
            pkg_seeded = False

        elif line.startswith("V:"):
            version = line[2:].strip()

        elif line.startswith("L:"):
            license_ = line[2:].strip() or "unknown"

        elif line.startswith("D:"):
            raw_deps = line[2:].strip()
            dep_names: list[str] = []
            for d in raw_deps.split():
                name = _re.split(r"[><=~!]", d)[0].strip()
                name = name.removeprefix("so:")
                if name:
                    dep_names.append(name)
            deps = ",".join(dict.fromkeys(dep_names))

        elif line.startswith("F:"):
            prefix = line[2:].strip()
            if pkg and version and not pkg_seeded:
                yield PackageFile(ecosystem, pkg, version, license_, "", deps)
                pkg_seeded = True

        elif line.startswith("R:"):
            if pkg and version:
                if not pkg_seeded:
                    yield PackageFile(ecosystem, pkg, version, license_, "", deps)
                    pkg_seeded = True
                filename = line[2:].strip()
                filepath = f"/{prefix}/{filename}" if prefix else f"/{filename}"
                if _is_executable_path(filepath):
                    yield PackageFile(ecosystem, pkg, version, license_, filepath, deps)

        elif line == "":
            if pkg and version and not pkg_seeded:
                yield PackageFile(ecosystem, pkg, version, license_, "", deps)
            prefix = ""
            license_ = "unknown"
            deps = ""
            pkg_seeded = False

    # Flush final stanza
    if pkg and version and not pkg_seeded:
        yield PackageFile(ecosystem, pkg, version, license_, "", deps)


def scan_apk_root(
    root: Path, ecosystem: str
) -> Generator[PackageFile, None, None]:
    db = root / "lib/apk/db/installed"
    if not db.exists():
        log.warning("apk: database not found at %s", db)
        return
    with open(db) as fh:
        lines = fh.readlines()
    yield from _scan_apk_lines(lines, ecosystem)


def scan_apk_layerfs(
    fs: LayerFS, ecosystem: str
) -> Generator[PackageFile, None, None]:
    data = fs.files.get("/lib/apk/db/installed")
    if not data:
        log.warning("apk: /lib/apk/db/installed not found in image")
        return
    lines = data.decode(errors="replace").splitlines(keepends=True)
    yield from _scan_apk_lines(lines, ecosystem)


# ---------------------------------------------------------------------------
# RPM SCANNER  (RedHat / AlmaLinux / RockyLinux)
# ---------------------------------------------------------------------------
#
# Why not a single rpm -qa --qf '[%{NAME}\t%{FILENAMES}\n]'?
# -----------------------------------------------------------
# RPM's [] iterator only replicates *array-valued* tags per element.
# Mixing scalar tags (NAME, VERSION) with array tags (FILENAMES) inside []
# does NOT repeat the scalars per file — RPM concatenates all filenames onto
# one line instead, breaking tab-split parsing entirely.
#
# Correct fast approach — two subprocess calls total regardless of package count:
#
#   1. rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\n'
#      → dict of {name: version} in one call
#
#   2. rpm -ql pkg1 pkg2 pkg3 ...  (all packages in one invocation)
#      → all file paths, with a sentinel header per package
#
# rpm -ql accepts multiple package names and emits files grouped by package.
# We reconstruct the mapping using the package-name headers that rpm -ql
# prints when given more than one argument (visible with --qf or via the
# fact that rpm prints "package pkg-ver:" before each group when verbose).
#
# Actually the cleanest reliable method remains two passes but batched:
# rpm -qa gives us names+versions; rpm -ql $(rpm -qa) gives us all files in
# one call.  We correlate via rpm -ql --qf '[%{=NAME}\t%{FILENAMES}\n]' which
# IS valid because =NAME (the tag with = prefix) is treated as a scalar
# repeated for each array element within the context of a single package query.
#
# Final design: one rpm -qa call + one rpm -ql call with all package names
# passed as arguments. Output is correlated by running rpm -ql with
# --qf '[%{=NEVRA}\t%{FILENAMES}\n]' so each file line carries its package.

_RPM_QA_QF   = r"%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t[%{REQUIRENAME},]\n"
# %{=TAG} repeats the scalar TAG for every element in the array iteration —
# this is the documented RPM way to mix scalars into array expansion.
_RPM_QL_QF   = r"[%{=NAME}\t%{=VERSION}-%{=RELEASE}\t%{FILENAMES}\n]"


def _clean_rpm_deps(raw: str) -> str:
    """
    Clean a comma-separated RPM REQUIRENAME string into plain package names.

    RPM REQUIRENAME entries include:
      - real package names:   ``bash``, ``glibc``
      - shared-lib virtuals:  ``libc.so.6(GLIBC_2.4)(64bit)``
      - capability virtuals:  ``rpmlib(PayloadFilesHavePrefix)``
      - rpmlib internals:     ``rpmlib(...)``

    We keep only entries that look like real package names (start with a
    letter/digit, contain no parentheses, and are not rpmlib internals).
    """
    names: list[str] = []
    for token in raw.split(","):
        token = token.strip()
        if not token:
            continue
        if token.startswith("rpmlib("):
            continue
        if "(" in token:          # shared-lib or capability virtual
            continue
        if token.startswith("/"):  # file-path requirement
            continue
        if _re.match(r"^[A-Za-z0-9_.+\-]+$", token):
            names.append(token)
    return ",".join(dict.fromkeys(names))


def _rpm_query_all(
    extra_args: list[str],
) -> Optional[dict[str, tuple[str, str, str]]]:
    """
    Run ``rpm -qa`` and return {package_name: (version, license, deps)}.
    Returns None if rpm is not available or the query fails.
    """
    cmd = ["rpm"] + extra_args + ["-qa", "--qf", _RPM_QA_QF]
    try:
        out = subprocess.check_output(
            cmd, text=True, stderr=subprocess.PIPE, timeout=SUBPROCESS_TIMEOUT,
        )
    except FileNotFoundError:
        log.warning("rpm binary not found — skipping RPM scan")
        return None
    except subprocess.TimeoutExpired:
        log.error("rpm -qa timed out")
        return None
    except subprocess.CalledProcessError as exc:
        log.error("rpm -qa failed: %s", exc.stderr.strip())
        return None

    result: dict[str, tuple[str, str, str]] = {}
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split("\t", 3)
        if len(parts) == 4:
            name, version, license_, raw_deps = parts
            result[name] = (version, license_.strip() or "unknown",
                            _clean_rpm_deps(raw_deps))
        elif len(parts) == 3:
            name, version, license_ = parts
            result[name] = (version, license_.strip() or "unknown", "")
        elif len(parts) == 2:
            result[parts[0]] = (parts[1], "unknown", "")
    return result


def _rpm_query_files(
    extra_args: list[str],
    pkg_names: list[str],
) -> Generator[tuple[str, str, str], None, None]:
    """
    Run ``rpm -ql`` for all packages in a single call and yield
    (pkg_name, version, filepath) tuples.

    Uses %{=NAME} / %{=VERSION} scalar repetition inside [] so each output
    line carries its own package identity — no post-hoc correlation needed.
    """
    if not pkg_names:
        return

    cmd = ["rpm"] + extra_args + ["-ql", "--qf", _RPM_QL_QF] + pkg_names
    try:
        out = subprocess.check_output(
            cmd, text=True, stderr=subprocess.PIPE, timeout=SUBPROCESS_TIMEOUT,
        )
    except FileNotFoundError:
        log.warning("rpm binary not found")
        return
    except subprocess.TimeoutExpired:
        log.error("rpm -ql (batched) timed out")
        return
    except subprocess.CalledProcessError as exc:
        log.error("rpm -ql failed: %s", exc.stderr.strip())
        return

    for line in out.splitlines():
        line = line.strip()
        if not line or line == "(contains no files)":
            continue
        parts = line.split("\t", 2)
        if len(parts) == 3:
            pkg_name, version, filepath = parts
            filepath = filepath.strip()
            if filepath:
                yield pkg_name, version, filepath


def scan_rpm_host(ecosystem: str) -> Generator[PackageFile, None, None]:
    """Enumerate all RPM packages and their owned executable binaries on the host."""
    packages = _rpm_query_all([])
    if packages is None:
        return
    # Seed one record per package so library-only packages still appear
    for pkg_name, (version, license_, deps) in packages.items():
        yield PackageFile(ecosystem, pkg_name, version, license_, "", deps)
    pkg_names = list(packages.keys())
    for pkg_name, version, filepath in _rpm_query_files([], pkg_names):
        _, license_, deps = packages.get(pkg_name, (version, "unknown", ""))
        if _is_executable_real(filepath):
            yield PackageFile(ecosystem, pkg_name, version, license_, filepath, deps)


def scan_rpm_root(
    root: Path, ecosystem: str
) -> Generator[PackageFile, None, None]:
    """
    Enumerate RPM packages from an extracted filesystem root.
    Uses ``--dbpath`` so rpm reads the extracted DB, not the host DB.

    RHEL / AlmaLinux / RockyLinux 9 migrated the RPM database from
    ``/var/lib/rpm/`` to ``/usr/lib/sysimage/rpm/``.  The old path is now a
    symlink (which does not exist in the extracted LayerFS rootfs because
    symlinks are not followed during extraction).  We probe the new path first
    and fall back to the legacy path so both RHEL 8 and RHEL 9 images work.
    """
    rpm_db: Optional[Path] = None
    for _candidate in ("usr/lib/sysimage/rpm", "var/lib/rpm"):
        _p = root / _candidate
        if _p.exists():
            rpm_db = _p
            break
    if rpm_db is None:
        log.warning(
            "rpm: database not found under %s "
            "(tried usr/lib/sysimage/rpm and var/lib/rpm)",
            root,
        )
        return
    db_args = ["--dbpath", str(rpm_db)]
    packages = _rpm_query_all(db_args)
    if packages is None:
        return
    # Seed one record per package
    for pkg_name, (version, license_, deps) in packages.items():
        yield PackageFile(ecosystem, pkg_name, version, license_, "", deps)
    pkg_names = list(packages.keys())
    for pkg_name, version, filepath in _rpm_query_files(db_args, pkg_names):
        _, license_, deps = packages.get(pkg_name, (version, "unknown", ""))
        real_path = str(root / filepath.lstrip("/"))
        if _is_executable_real(real_path):
            yield PackageFile(ecosystem, pkg_name, version, license_, filepath, deps)


# ---------------------------------------------------------------------------
# SNAP / FLATPAK SCANNERS  (supplemental — host only)
# ---------------------------------------------------------------------------


def scan_snap_host(ecosystem: str) -> Generator[PackageFile, None, None]:
    """
    List installed snap packages.

    Each snap is mounted at /snap/<name>/<revision>/ at runtime.
    ``snap list`` reports the active revision number, so we use that as the
    path rather than the ``/current`` symlink (which may not exist when the
    snapd daemon is not running).
    """
    try:
        out = subprocess.check_output(
            ["snap", "list", "--unicode=never"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        return  # snap not installed or not usable — silently skip

    lines = out.splitlines()
    if not lines:
        return

    # Header: Name  Version  Rev  Tracking  Publisher  Notes
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 3:
            continue
        pkg_name = parts[0]
        version = parts[1]
        revision = parts[2]
        # Actual mount point uses the numeric revision, not "current"
        snap_dir = f"/snap/{pkg_name}/{revision}"
        yield PackageFile(ecosystem, pkg_name, version, "unknown", snap_dir, "")


def scan_flatpak_host(ecosystem: str) -> Generator[PackageFile, None, None]:
    """List installed flatpak applications (name + version only)."""
    try:
        out = subprocess.check_output(
            ["flatpak", "list", "--app", "--columns=application,version"],
            text=True,
            stderr=subprocess.DEVNULL,
            timeout=SUBPROCESS_TIMEOUT,
        )
    except (FileNotFoundError, subprocess.CalledProcessError,
            subprocess.TimeoutExpired):
        return

    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) >= 2:
            pkg_name, version = parts[0].strip(), parts[1].strip()
        elif len(parts) == 1 and parts[0]:
            pkg_name, version = parts[0].strip(), "unknown"
        else:
            continue
        flatpak_dir = f"/var/lib/flatpak/app/{pkg_name}/current/active"
        yield PackageFile(ecosystem, pkg_name, version, "unknown", flatpak_dir, "")


# ---------------------------------------------------------------------------
# HOST SCAN
# ---------------------------------------------------------------------------


def scan_host(
    include_snap: bool = True,
    include_flatpak: bool = True,
) -> list[dict]:
    """
    Scan the host system for installed packages.

    Returns a list of package dicts.  Each dict has keys:
    ``id``, ``name``, ``version``, ``ecosystem``, ``licence``,
    ``paths``, ``dependencies``.
    """
    ecosystem = detect_host_ecosystem()
    root = Path("/")
    log.info("Host ecosystem: %s", ecosystem)

    def _inner() -> Generator[PackageFile, None, None]:
        if ecosystem in {"debian", "ubuntu"}:
            yield from scan_dpkg_root(root, ecosystem)
        elif ecosystem == "alpine":
            yield from scan_apk_root(root, ecosystem)
        elif ecosystem in {"redhat", "almalinux", "rockylinux"}:
            yield from scan_rpm_host(ecosystem)
        else:
            raise RuntimeError(f"No scanner implemented for ecosystem {ecosystem!r}")
        if include_snap:
            yield from scan_snap_host(ecosystem)
        if include_flatpak:
            yield from scan_flatpak_host(ecosystem)

    return to_package_list(_group_by_package(_inner()))


# ---------------------------------------------------------------------------
# CONTAINER SCAN  (running container via docker export)
# ---------------------------------------------------------------------------


def scan_container(container: str) -> list[dict]:
    """
    Scan a running (or stopped) Docker container by exporting its filesystem.

    Returns a list of package dicts.
    """
    ecosystem = detect_container_ecosystem(container)
    log.info("Container %r ecosystem: %s", container, ecosystem)

    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / "fs.tar"

        log.info("Exporting container %r …", container)
        with open(tar_path, "wb") as fh:
            subprocess.run(
                ["docker", "export", container],
                stdout=fh,
                check=True,
                timeout=DOCKER_EXPORT_TIMEOUT,
            )

        root = Path(tmp) / "rootfs"
        root.mkdir()

        log.info("Extracting container filesystem …")
        with tarfile.open(tar_path) as tar:
            members = [
                m for m in tar.getmembers()
                if not (m.name.startswith("/") or ".." in m.name.split("/"))
            ]
            tar.extractall(root, members=members)

        def _inner() -> Generator[PackageFile, None, None]:
            if ecosystem in {"debian", "ubuntu"}:
                yield from scan_dpkg_root(root, ecosystem)
            elif ecosystem == "alpine":
                yield from scan_apk_root(root, ecosystem)
            elif ecosystem in {"redhat", "almalinux", "rockylinux"}:
                yield from scan_rpm_root(root, ecosystem)
            else:
                raise RuntimeError(
                    f"No scanner implemented for ecosystem {ecosystem!r}"
                )

        return to_package_list(_group_by_package(_inner()))


# ---------------------------------------------------------------------------
# IMAGE SCAN  (Docker image via docker save — no container needed)
# ---------------------------------------------------------------------------


def scan_image(image: str) -> list[dict]:
    print(f"Scanning image {image!r} …")
    """
    Scan a Docker image without running it.

    Returns a list of package dicts.
    """
    log.info("Loading image layers for %r …", image)
    fs = LayerFS(image)
    print(f"Loaded {len(fs.files)} files from image layers")
    for p in fs.files:
        log.debug("LayerFS file: %s", p)

    ecosystem: Optional[str] = None
    for p in ("/etc/os-release", "/usr/lib/os-release"):
        data = fs.files.get(p)
        if data:
            ecosystem = _parse_os_release(data.decode(errors="replace"))
            break

    if not ecosystem:
        raise RuntimeError(
            f"Cannot detect OS ecosystem in image {image!r}: "
            "no os-release file found"
        )

    log.info("Image %r ecosystem: %s", image, ecosystem)

    def _inner() -> Generator[PackageFile, None, None]:
        if ecosystem in {"debian", "ubuntu"}:
            yield from scan_dpkg_layerfs(fs, ecosystem)
        elif ecosystem == "alpine":
            yield from scan_apk_layerfs(fs, ecosystem)
        elif ecosystem in {"redhat", "almalinux", "rockylinux"}:
            with tempfile.TemporaryDirectory() as tmp:
                root = Path(tmp) / "rootfs"
                root.mkdir()
                log.info("Writing RPM image filesystem to %s …", root)
                for vpath, data in fs.files.items():
                    dest = root / vpath.lstrip("/")
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    try:
                        dest.write_bytes(data)
                    except OSError as exc:
                        log.debug("Skipping %s: %s", vpath, exc)
                yield from scan_rpm_root(root, ecosystem)
        else:
            raise RuntimeError(
                f"No scanner implemented for ecosystem {ecosystem!r}"
            )

    return to_package_list(_group_by_package(_inner()))


# ---------------------------------------------------------------------------
# PURL + OUTPUT CONVERSION
# ---------------------------------------------------------------------------

# Package URL type per ecosystem  (https://github.com/package-url/purl-spec)
_PURL_TYPE: dict[str, str] = {
    "debian":     "deb",
    "ubuntu":     "deb",
    "alpine":     "apk",
    "redhat":     "rpm",
    "almalinux":  "rpm",
    "rockylinux": "rpm",
}


def _make_purl(ecosystem: str, name: str, version: str) -> str:
    """
    Build a Package URL (purl) string.

    Format:  pkg:<type>/<namespace>/<name>@<version>

    Examples
    --------
    pkg:deb/ubuntu/bash@5.2.21-2ubuntu4
    pkg:apk/alpine/busybox@1.36.0-r0
    pkg:rpm/redhat/bash@5.2-1.el9
    """
    ptype = _PURL_TYPE.get(ecosystem, ecosystem)
    return f"pkg:{ptype}/{ecosystem}/{name}@{version}"


def to_package_list(records: Generator[PackageFile, None, None]) -> list[dict]:
    """
    Materialise a generator of PackageFile records into a list of dicts.

    Steps
    -----
    1. Consume all records, building a name → PackageFile map.
    2. Assign each package a purl as its ``id``.
    3. Resolve each package's dep names → purls, keeping only deps that are
       present in the scanned set (uninstalled virtuals / optional deps are
       silently dropped).
    4. Return the list ordered by package name.
    """
    # Materialise — records must all be in memory for cross-reference resolution
    by_name: dict[str, PackageFile] = {}
    for rec in records:
        by_name[rec.package] = rec

    # Build purl index
    purls: dict[str, str] = {
        name: _make_purl(rec.ecosystem, name, rec.version)
        for name, rec in by_name.items()
    }

    result: list[dict] = []
    for name in sorted(by_name):
        rec = by_name[name]
        purl = purls[name]

        # Resolve dep names → purls, drop any not in the scanned set
        dep_purls: list[str] = []
        if rec.deps:
            for dep_name in rec.deps.split(","):
                dep_name = dep_name.strip()
                if dep_name in purls:
                    dep_purls.append(purls[dep_name])

        result.append({
            "id":           purl,
            "name":         name,
            "version":      rec.version,
            "ecosystem":    rec.ecosystem,
            "licence":      rec.license,
            "paths":        [p for p in rec.binary.split(BINARY_SEP) if p] if rec.binary else [],
            "dependencies": dep_purls,
        })

    return result




if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO,
        format="%(levelname)s  %(message)s",
    )
    log.setLevel(logging.INFO)

    # ------------------------------------------------------------------ #
    #  Edit MODE and TARGET below, then run:  python package_scanner.py   #
    # ------------------------------------------------------------------ #

    MODE = "image"            # "host" | "container" | "image"
    TARGET = "almalinux:9-minimal"  # container name or image tag (ignored for host)

    # ------------------------------------------------------------------ #

    try:
        if MODE == "host":
            packages = scan_host()
        elif MODE == "container":
            packages = scan_container(TARGET)
        elif MODE == "image":
            packages = scan_image(TARGET)
        else:
            print(f"Unknown mode {MODE!r}. Use: host | container | image",
                  file=sys.stderr)
            sys.exit(1)

        data=json.dumps(packages, indent=2)
        with open("packages.json", "w") as fh:
            fh.write(data)
        log.info("Total packages: %d", len(packages))

    except RuntimeError as e:
        log.error("%s", e)
        sys.exit(1)
    except KeyboardInterrupt:
        sys.exit(0)