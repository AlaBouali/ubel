// linux_host_scanner.js
//
// Mirrors the output of package_scanner.py → scan_host() but runs entirely
// in Node.js.  Supports Debian/Ubuntu (dpkg), Alpine (apk), and
// RedHat/AlmaLinux/RockyLinux (rpm).  All package databases are read directly
// from disk (no dpkg/apk/rpm binaries required).
//
// Output format per package:
// {
//   id:           "pkg:deb/ubuntu/bash@5.2.21",
//   name:         "bash",
//   version:      "5.2.21",
//   type:         "library",
//   ecosystem:    "ubuntu",        // canonical distro id
//   license:      "unknown",
//   paths:        ["/usr/bin/bash"],
//   dependencies: ["pkg:deb/ubuntu/libc6@2.39"],
//   scopes:       ["prod"],
//   state:        "undetermined",
// }

import fs            from "fs";
import path          from "path";
import os            from "os";
import { spawnSync } from "child_process";
import { readRpmDb } from "./rpmdb_reader.js";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SUBPROCESS_TIMEOUT = 120_000;   // ms

const ALLOWED_ECOSYSTEMS = new Set([
  "debian", "ubuntu", "redhat", "almalinux", "rockylinux", "alpine",
  "rhel", "centos", "fedora",
]);

// Map ID_LIKE tokens that aren't direct ecosystem names to canonical ones
const ECOSYSTEM_ALIAS = {
  rhel:    "redhat",
  centos:  "redhat",
  fedora:  "redhat",
};

const PURL_TYPE = {
  debian:     "deb",
  ubuntu:     "deb",
  alpine:     "apk",
  redhat:     "rpm",
  almalinux:  "rpm",
  rockylinux: "rpm",
};

// ─────────────────────────────────────────────────────────────────────────────
// PURL helpers
// ─────────────────────────────────────────────────────────────────────────────

function makePurl(ecosystem, name, version) {
  const type = PURL_TYPE[ecosystem] ?? ecosystem;
  if (ecosystem === "rockylinux") {
    ecosystem = "rocky-linux";
  }
  return `pkg:${type}/${ecosystem}/${name}@${version ?? ""}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// OS detection  (/etc/os-release or /usr/lib/os-release)
// ─────────────────────────────────────────────────────────────────────────────

function parseOsRelease(content) {
  const data = {};
  for (const raw of content.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || !line.includes("=")) continue;
    const eq   = line.indexOf("=");
    const key  = line.slice(0, eq).trim();
    const val  = line.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
    data[key]  = val;
  }

  const normalise = v => v.toLowerCase().replace(/[\s-]/g, "");
  const candidates = [];
  if (data.ID)      candidates.push(normalise(data.ID));
  if (data.ID_LIKE) data.ID_LIKE.split(/\s+/).forEach(t => candidates.push(normalise(t)));

  for (const c of candidates) {
    if (ALLOWED_ECOSYSTEMS.has(c)) return ECOSYSTEM_ALIAS[c] ?? c;
  }
  throw new Error(`Unsupported OS ecosystem: ${JSON.stringify(candidates)}`);
}

function detectHostEcosystem(rootDir = "") {
  for (const p of ["/etc/os-release", "/usr/lib/os-release"]) {
    const fullPath = rootDir ? path.join(rootDir, p) : p;
    if (fs.existsSync(fullPath)) return parseOsRelease(fs.readFileSync(fullPath, "utf8"));
  }
  throw new Error(
    `Cannot detect OS ecosystem: no os-release file found${rootDir ? ` under ${rootDir}` : ""}`
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Dependency field parsers
// ─────────────────────────────────────────────────────────────────────────────

const DEP_NAME_RE = /^([A-Za-z0-9_.+\-]+)/;

/** Parse a dpkg Depends: field → array of package names. */
function parseDpkgDeps(raw) {
  if (!raw) return [];
  const names = [];
  for (const clause of raw.split(",")) {
    for (const alt of clause.split("|")) {
      const m = DEP_NAME_RE.exec(alt.trim());
      if (m) names.push(m[1]);
    }
  }
  return [...new Set(names)];
}

/** Parse an APK D: field → array of package names. */
function parseApkDeps(raw) {
  if (!raw) return [];
  const names = [];
  for (const d of raw.split(/\s+/)) {
    // strip version constraints and the so: provider prefix
    const name = d.split(/[><=~!]/)[0].replace(/^so:/, "").trim();
    if (name) names.push(name);
  }
  return [...new Set(names)];
}

/** Clean RPM REQUIRENAME tokens → array of plain package names. */
function cleanRpmDeps(raw) {
  if (!raw) return [];
  const names = [];
  for (const token of raw.split(",")) {
    const t = token.trim();
    if (!t)                          continue;
    if (t.startsWith("rpmlib("))     continue;
    if (t.includes("("))             continue;   // shared-lib / capability virtual
    if (t.startsWith("/"))           continue;   // file path requirement
    if (/^[A-Za-z0-9_.+\-]+$/.test(t)) names.push(t);
  }
  return [...new Set(names)];
}

// ─────────────────────────────────────────────────────────────────────────────
// Executable-path heuristic  (same prefixes as Python scanner)
// ─────────────────────────────────────────────────────────────────────────────

const BINARY_PREFIXES = [
  "/bin/", "/sbin/",
  "/usr/bin/", "/usr/sbin/",
  "/usr/local/bin/", "/usr/local/sbin/",
  "/usr/lib/", "/usr/libexec/", "/opt/",
];

function isExecutablePath(p) {
  return BINARY_PREFIXES.some(pfx => p.startsWith(pfx)) && !p.endsWith("/");
}

// ─────────────────────────────────────────────────────────────────────────────
// Build final package dict
// ─────────────────────────────────────────────────────────────────────────────

function buildPackage(ecosystem, name, version, license_, paths, depNames, purls) {
  const id = makePurl(ecosystem, name, version);
  const dependencies = depNames
    .map(d => purls.get(d))
    .filter(Boolean);

  return {
    id,
    name,
    version,
    type:         "application",
    ecosystem,
    license:      license_ || "unknown",
    state:        "undetermined",
    scopes:       ["prod"],
    paths,
    dependencies,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// DPKG scanner  (Debian / Ubuntu)
// ─────────────────────────────────────────────────────────────────────────────

function parseDpkgStatus(content) {
  // Returns Map<name, {version, license, deps[]}>
  // Only includes packages with "Status: install ok installed"
  const pkgs = new Map();
  let pkg, ver, lic, dep, installed;

  for (const raw of content.split("\n")) {
    const line = raw.trimEnd();
    if (line.startsWith("Package:")) {
      pkg = line.slice("Package:".length).trim();
    } else if (line.startsWith("Version:")) {
      ver = line.slice("Version:".length).trim();
    } else if (line.startsWith("Status:")) {
      installed = line.slice("Status:".length).trim() === "install ok installed";
    } else if (line.startsWith("License:")) {
      lic = line.slice("License:".length).trim();
    } else if (line.startsWith("Depends:")) {
      dep = line.slice("Depends:".length).trim();
    } else if (line.trim() === "") {
      if (pkg && ver && installed) {
        pkgs.set(pkg, {
          version: ver,
          license: lic || "unknown",
          deps:    parseDpkgDeps(dep || ""),
        });
      }
      pkg = ver = lic = dep = undefined;
      installed = false;
    }
  }
  // flush last stanza
  if (pkg && ver && installed) {
    pkgs.set(pkg, {
      version: ver,
      license: lic || "unknown",
      deps:    parseDpkgDeps(dep || ""),
    });
  }
  return pkgs;
}

/**
 * Build a Map<pkgName, licenseString> from /usr/share/doc/<pkg>/copyright.
 * Pure JS (no awk): takes the first token after the first "License:" line,
 * same as the old `/^License:/ {print pkg, $2}` script.  Best-effort overlay —
 * returns whatever it managed to read and never aborts the scan.
 */
function readDpkgLicenses(rootDir = "") {
  const licenses = new Map();
  const docDir = rootDir ? path.join(rootDir, "/usr/share/doc") : "/usr/share/doc";

  let entries;
  try { entries = fs.readdirSync(docDir); } catch { return licenses; }

  for (const entry of entries) {
    const cp = path.join(docDir, entry, "copyright");
    let content;
    try {
      // statSync follows symlinks and throws on dangling ones — skip those.
      if (!fs.statSync(cp).isFile()) continue;
      content = fs.readFileSync(cp, "utf8");
    } catch { continue; }

    for (const line of content.split("\n")) {
      const m = /^License:[ \t]+(\S+)/.exec(line);
      if (m) { licenses.set(entry, m[1]); break; }
    }
  }
  return licenses;
}

function scanDpkg(ecosystem, rootDir = "") {
  const statusPath = rootDir ? path.join(rootDir, "/var/lib/dpkg/status") : "/var/lib/dpkg/status";
  if (!fs.existsSync(statusPath)) {
    throw new Error(`dpkg: status file not found at ${statusPath}`);
  }

  const pkgs = parseDpkgStatus(fs.readFileSync(statusPath, "utf8"));

  // Overlay licenses from /usr/share/doc/*/copyright (more reliable than dpkg status)
  const copyrightLicenses = readDpkgLicenses(rootDir);
  for (const [name, info] of pkgs.entries()) {
    if (info.license === "unknown" || !info.license) {
      const lic = copyrightLicenses.get(name);
      if (lic) info.license = lic;
    }
  }

  // Build purl index for dep resolution
  const purls = new Map();
  for (const [name, { version }] of pkgs.entries()) {
    purls.set(name, makePurl(ecosystem, name, version));
  }

  // Collect executable paths from .list files
  const pathsByPkg = new Map();
  const infoDir = rootDir ? path.join(rootDir, "/var/lib/dpkg/info") : "/var/lib/dpkg/info";

  if (fs.existsSync(infoDir)) {
    for (const fname of fs.readdirSync(infoDir)) {
      if (!fname.endsWith(".list")) continue;
      const pkgName = path.basename(fname, ".list").split(":")[0];  // strip :arch
      if (!pkgs.has(pkgName)) continue;

      const listPath = path.join(infoDir, fname);
      try {
        for (const line of fs.readFileSync(listPath, "utf8").split("\n")) {
          // fp is the *logical* path as it exists inside the image (e.g.
          // /usr/bin/bash) — that's what we record. Only the on-disk stat
          // check below needs the rootDir-prefixed real path.
          const fp = line.trim();
          if (fp && isExecutablePath(fp)) {
            const realFp = rootDir ? path.join(rootDir, fp) : fp;
            if (fs.existsSync(realFp)) {
              try {
                const stat = fs.statSync(realFp);
                const mode = stat.mode;
                // Check execute bit (owner | group | other)
                if (stat.isFile() && (mode & 0o111)) {
                  if (!pathsByPkg.has(pkgName)) pathsByPkg.set(pkgName, []);
                  pathsByPkg.get(pkgName).push(fp);
                }
              } catch { /* skip unreadable */ }
            }
          }
        }
      } catch { /* skip unreadable list file */ }
    }
  }

  const result = [];
  for (const [name, { version, license: lic, deps }] of pkgs.entries()) {
    result.push(buildPackage(
      ecosystem, name, version, lic,
      pathsByPkg.get(name) ?? [],
      deps,
      purls,
    ));
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// APK scanner  (Alpine)
// ─────────────────────────────────────────────────────────────────────────────

function parseApkInstalled(content, ecosystem) {
  // Returns Map<name, {version, license, deps[], paths[]}>
  const pkgs  = new Map();
  let name, version, license_ = "unknown", deps = [], prefix = "", seeded = false;

  const flush = () => {
    if (name && version && !seeded) {
      pkgs.set(name, { version, license: license_, deps, paths: [] });
    }
    name = version = undefined;
    prefix = ""; license_ = "unknown"; deps = []; seeded = false;
  };

  for (const raw of content.split("\n")) {
    const line = raw.trimEnd();
    if (line.startsWith("P:")) {
      flush();
      name = line.slice(2).trim();
    } else if (line.startsWith("V:")) {
      version = line.slice(2).trim();
    } else if (line.startsWith("L:")) {
      license_ = line.slice(2).trim() || "unknown";
    } else if (line.startsWith("D:")) {
      deps = parseApkDeps(line.slice(2).trim());
    } else if (line.startsWith("F:")) {
      prefix = line.slice(2).trim();
      if (name && version && !seeded) {
        pkgs.set(name, { version, license: license_, deps, paths: [] });
        seeded = true;
      }
    } else if (line.startsWith("R:")) {
      if (name && version) {
        if (!seeded) {
          pkgs.set(name, { version, license: license_, deps, paths: [] });
          seeded = true;
        }
        const filename = line.slice(2).trim();
        const filepath = prefix ? `/${prefix}/${filename}` : `/${filename}`;
        if (isExecutablePath(filepath)) {
          pkgs.get(name).paths.push(filepath);
        }
      }
    } else if (line.trim() === "") {
      if (name && version && !seeded) {
        pkgs.set(name, { version, license: license_, deps, paths: [] });
      }
      seeded = false;
      prefix = ""; license_ = "unknown"; deps = [];
    }
  }
  flush();

  return pkgs;
}

function scanApk(ecosystem, rootDir = "") {
  const dbPath = rootDir ? path.join(rootDir, "/lib/apk/db/installed") : "/lib/apk/db/installed";
  if (!fs.existsSync(dbPath)) {
    throw new Error(`apk: database not found at ${dbPath}`);
  }

  const pkgs  = parseApkInstalled(fs.readFileSync(dbPath, "utf8"), ecosystem);

  const purls = new Map();
  for (const [name, { version }] of pkgs.entries()) {
    purls.set(name, makePurl(ecosystem, name, version));
  }

  const result = [];
  for (const [name, { version, license: lic, deps, paths }] of pkgs.entries()) {
    result.push(buildPackage(ecosystem, name, version, lic, paths, deps, purls));
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// RPM scanner  (RedHat / AlmaLinux / RockyLinux)
//
// Reads the rpm database (BDB Packages or rpmdb.sqlite) directly via
// rpmdb_reader.js — no `rpm` binary needed, works on Windows and on extracted
// image rootfs trees.
// ─────────────────────────────────────────────────────────────────────────────

const S_IFMT = 0o170000, S_IFLNK = 0o120000;

/**
 * Is `filepath` (logical in-image path) an executable file on disk?
 * `hdrMode` is the mode recorded in the rpm header.  On Windows the extracted
 * tree carries no POSIX permission bits, so the header mode is used instead.
 */
function isExecutableRpmFile(realPath, hdrMode) {
  let st;
  try { st = fs.statSync(realPath); } catch { return false; }
  if (!st.isFile()) return false;
  if (process.platform === "win32") {
    if (typeof hdrMode !== "number") return true;
    return (hdrMode & S_IFMT) === S_IFLNK || (hdrMode & 0o111) !== 0;
  }
  return (st.mode & 0o111) !== 0;
}

function scanRpm(ecosystem, rootDir = "") {
  const pkgs = new Map();            // name → record (last wins, like before)
  for (const p of readRpmDb(rootDir)) pkgs.set(p.name, p);

  const purls = new Map();
  for (const [name, { version }] of pkgs.entries()) {
    purls.set(name, makePurl(ecosystem, name, version));
  }

  const result = [];
  for (const [name, { version, license, requires, files }] of pkgs.entries()) {
    const paths = [];
    for (const { path: fp, mode } of files) {
      if (!isExecutablePath(fp)) continue;
      // fp is the logical in-image path (recorded as-is); only the on-disk
      // check needs the rootDir prefix.
      const realPath = rootDir ? path.join(rootDir, fp) : fp;
      if (isExecutableRpmFile(realPath, mode)) paths.push(fp);
    }
    result.push(buildPackage(
      ecosystem, name, version, license || "unknown", paths,
      cleanRpmDeps(requires.join(",")), purls,
    ));
  }
  return result;
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

export class LinuxHostScanner {

  /**
   * @param {string} [rootDir=""]  Absolute path to an extracted image
   *   rootfs. Omit (or pass "") to scan the live host — this preserves the
   *   original host-scanning behavior exactly.
   */
  constructor(rootDir = "") {
    this.inventoryData = [];
    this.rootDir = rootDir;
  }

  /**
   * Scan the running Linux host, or an extracted image rootfs when rootDir
   * was provided to the constructor.
   * Returns an array of PURL id strings (same contract as the other scanners).
   * Full records are available on LinuxHostScanner.inventoryData.
   */
  getInstalled() {

    this.inventoryData = [];

    const ecosystem = detectHostEcosystem(this.rootDir);

    let packages;
    if (ecosystem === "debian" || ecosystem === "ubuntu") {
      packages = scanDpkg(ecosystem, this.rootDir);
    } else if (ecosystem === "alpine") {
      packages = scanApk(ecosystem, this.rootDir);
    } else if (
      ecosystem === "redhat" ||
      ecosystem === "almalinux" ||
      ecosystem === "rockylinux"
    ) {
      packages = scanRpm(ecosystem, this.rootDir);
    } else {
      throw new Error(`No scanner implemented for ecosystem: ${ecosystem}`);
    }

    // Sort by name for deterministic output — mirrors to_package_list()
    packages.sort((a, b) => a.name.localeCompare(b.name));

    this.inventoryData = packages;

    return packages.map(p => p.id);
  }
}

export default LinuxHostScanner;

// ─────────────────────────────────────────────────────────────────────────────
// LinuxManagerInstance
//
// JS port of Linux_Manager (linux_runner.py) — adds pre-install firewalling
// (dry-run resolution + real install) on top of LinuxHostScanner's pure
// inventory scanning, so ubel-linux can gate `apt`/`dnf`/`yum` installs the
// same way ubel-npm gates `npm ci`. One fresh instance per invocation, no
// shared mutable state between scans (matches NodeManagerInstance/
// PypiManagerInstance conventions).
// ─────────────────────────────────────────────────────────────────────────────

// ── dnf / yum transaction-table parser ───────────────────────────────────────
// `dnf install --assumeno` / `yum install --assumeno` print a table:
//
//   Package      Architecture  Version          Repository   Size
//   Installing:
//    curl        x86_64        7.76.1-26.el9    baseos       297 k
//   Installing dependencies:
//    python3.11  x86_64        3.11.2-2.el9     appstream     27 k
//
// name, arch and version are SEPARATE columns. Very long names are printed on
// their own line with the remaining columns on the next. Every section that
// adds or changes packages (Installing / Upgrading / Updating / Downgrading /
// Reinstalling, including "dependencies" and "weak dependencies") is scanned.
// Anything inside such a section that doesn't parse throws: a package we could
// not read is a package we could not clear.
const RPM_ARCH_RE    = /^(noarch|x86_64|aarch64|i[3-6]86|ppc64(le)?|s390x?|armv\w+|riscv64|src)$/;
const RPM_NAME_RE    = /^[A-Za-z0-9_][A-Za-z0-9_.+-]*$/;
const RPM_SECTION_RE = /^(Installing|Upgrading|Updating|Downgrading|Reinstalling)\b[^:]*:$/;
// Section headers whose rows are not packages (module streams/profiles, group names).
// "Installing group/module packages:" is deliberately NOT here — its rows are real rpm
// packages (nodejs, postgresql, php ...) and must be scanned.
const RPM_NO_ROWS_HEADER_RE = /^(Installing (module profiles|groups|environment groups)|(Enabling|Disabling|Resetting|Switching) module streams)\b/i;
// The column header row that starts the transaction table (dnf4 "Architecture", dnf5/yum "Arch").
const RPM_TABLE_HEADER_RE = /^Package\s+Arch\w*\s+Version\b/i;

export function parseRpmTransaction(output, manager = "dnf") {
  const found = [];
  const rejected = [];
  let capture = false;
  let inTable = false; // true once the "Package Arch Version ..." column header has been seen
  let pendingName = null;

  for (const raw of String(output || "").split("\n")) {
    const line = raw.trim();
    if (!line) { pendingName = null; continue; }
    if (/^Transaction Summary/i.test(line)) break;
    if (/^=+$/.test(line)) { capture = false; pendingName = null; continue; }

    // Nothing before the table header is a package row. This also keeps dnf5's
    // "Updating and loading repositories:" progress block (which looks like an
    // "Updating:" section) from starting capture and failing to parse.
    if (!inTable) {
      if (RPM_TABLE_HEADER_RE.test(line)) inTable = true;
      continue;
    }

    if (/:$/.test(line) && !/\s\d/.test(line)) {
      // Section header. Only headers that carry no package rows are skipped;
      // removals never match RPM_SECTION_RE.
      capture = RPM_SECTION_RE.test(line) && !RPM_NO_ROWS_HEADER_RE.test(line);
      pendingName = null;
      continue;
    }
    if (!capture) continue;

    const tokens = line.split(/\s+/);
    if (tokens[0].toLowerCase() === "replacing") continue;
    if (tokens.length === 1) { pendingName = tokens[0]; continue; }

    const row = pendingName ? [pendingName, ...tokens] : tokens;
    pendingName = null;
    const [name, arch, version] = row;
    if (!RPM_NAME_RE.test(name) || !RPM_ARCH_RE.test(arch || "") || !/\d/.test(version || "")) {
      rejected.push(line);
      continue;
    }
    if (!found.some(p => p.name === name && p.version === version)) found.push({ name, version, arch });
  }

  if (rejected.length) {
    throw new Error(
      `Could not parse ${rejected.length} line(s) of ${manager}'s dry-run transaction table, so the resolved set is incomplete: ` +
      rejected.slice(0, 3).join(" | ")
    );
  }
  if (found.length === 0 && !/Nothing to do|already installed/i.test(output || "")) {
    throw new Error(`${manager} dry-run produced no installable packages and no "nothing to do" message — refusing to treat that as a clean scan.`);
  }
  return found;
}

export class LinuxManagerInstance {

  /**
   * @param {"apt"|"dnf"|"yum"} pkgManager — which native package manager this
   *   instance targets. Required and not auto-detected: mirrors
   *   ubel-npm/ubel-pnpm/ubel-bun being three distinct binaries each bound
   *   to one specific tool, rather than one binary that guesses. Each of
   *   ubel-apt/ubel-dnf/ubel-yum constructs its own instance with the
   *   matching value.
   */
  constructor(pkgManager) {
    if (!["apt", "dnf", "yum"].includes(pkgManager)) {
      throw new Error(`LinuxManagerInstance requires an explicit pkgManager ("apt"|"dnf"|"yum"), got: ${JSON.stringify(pkgManager)}`);
    }
    this.pkgManager          = pkgManager;
    this.inventoryData       = [];
    this.pkgManagerVersion   = null;
    this.engineVersion       = null; // set after resolvePackages(); mirrors NodeManagerInstance.engineVersion
    this._lastStderr         = "";   // stderr of the most recent runCommand(), surfaced in dry-run errors
  }

  // ── Engine version capture (no-op) ──────────────────────────────────────────
  // Version capture for linux happens inline inside resolvePackages()/
  // getLinuxPackages() once the active package manager is known, so the
  // generic pre-collect call in engine.js's scan() is a deliberate no-op here.
  _captureEngineVersion() {}

  // ── Dependency sequences (identical algorithm to NodeManagerInstance) ───────

  buildDependencySequences(inventory) {
    if (!Array.isArray(inventory)) inventory = Object.values(inventory || {});

    const byId = new Map();
    for (const comp of inventory) byId.set(comp.id, comp);

    const depended = new Set();
    for (const comp of inventory) {
      for (const dep of (comp.dependencies || [])) depended.add(dep);
    }

    const roots     = inventory.map(c => c.id).filter(id => !depended.has(id));
    const sequences = new Map();

    function dfs(node, path) {
      const nextPath = [...path, node];
      if (!sequences.has(node)) sequences.set(node, []);
      sequences.get(node).push(nextPath);
      for (const dep of (byId.get(node)?.dependencies || [])) {
        if (!path.includes(dep)) dfs(dep, nextPath);
      }
    }

    for (const root of roots) dfs(root, []);
    for (const comp of inventory) comp.dependency_sequences = sequences.get(comp.id) || [];

    return inventory;
  }

  buildIntroducedBy(inventory) {
    const reverse = new Map();
    for (const pkg of inventory) reverse.set(pkg.id, []);
    for (const pkg of inventory) {
      for (const dep of pkg.dependencies || []) {
        if (!reverse.has(dep)) reverse.set(dep, []);
        reverse.get(dep).push(pkg.id);
      }
    }
    for (const pkg of inventory) pkg.introduced_by = reverse.get(pkg.id) || [];
    return inventory;
  }

  buildParents(inventory) {
    const parents = new Map(inventory.map(c => [c.id, []]));
    for (const comp of inventory) {
      for (const depId of (comp.dependencies || [])) {
        if (parents.has(depId)) parents.get(depId).push(comp.id);
      }
    }
    for (const comp of inventory) comp.parents = (parents.get(comp.id) || []).sort();
    return inventory;
  }

  mergeInventoryByPurl(components) {
    const map = new Map();
    for (const comp of components) {
      if (!map.has(comp.id)) {
        map.set(comp.id, { ...comp, paths: [...(comp.paths || [])] });
        continue;
      }
      const existing = map.get(comp.id);
      for (const p of (comp.paths || [])) {
        if (p && !existing.paths.includes(p)) existing.paths.push(p);
      }
    }
    return [...map.values()];
  }

  // ── Shell helpers ────────────────────────────────────────────────────────────

  commandExists(cmd) {
    const r = spawnSync("which", [cmd], { encoding: "utf8" });
    return r.status === 0 && !!r.stdout.trim();
  }

  runCommand(cmd) {
    const [bin, ...args] = cmd;
    this._lastStderr = "";
    try {
      // Pin the locale: the dnf/yum table headers ("Installing:", "Nothing to
      // do") and apt's "N newly installed" summary are parsed as English text.
      // LANGUAGE is cleared because gettext lets it override LC_* on some hosts.
      const env = { ...process.env, LC_ALL: "C", LANG: "C" };
      delete env.LANGUAGE;
      const r = spawnSync(bin, args, { encoding: "utf8", env, timeout: SUBPROCESS_TIMEOUT, maxBuffer: 32 * 1024 * 1024 });
      if (r.error) throw r.error;
      this._lastStderr = (r.stderr || "").trim();
      // Mirror Python: return stdout on a clean run OR a non-zero exit that
      // still produced resolvable output (apt-get -s / dnf --assumeno exit
      // non-zero on purpose since nothing is actually installed).
      return (r.stdout || "").trim();
    } catch (e) {
      console.error(`[!] Command failed: ${cmd.join(" ")}`);
      console.error(e.message);
      this._lastStderr = e.message;
      return "";
    }
  }

  // Appends the last command's stderr (the real cause of a failed dry-run) to an error message.
  _withStderr(message) {
    const err = (this._lastStderr || "").trim();
    return err ? `${message}\n[${this._pmBinary()} stderr] ${err.slice(0, 2000)}` : message;
  }

  // dnf/yum dry-run. `install --assumeno` may refuse to run unprivileged ("This command has to be
  // run with superuser privileges"), which contradicts "no sudo needed" — so when that happens as a
  // non-root user, retry once via non-interactive sudo and fail with the real reason if that fails too.
  _runRpmDryRun(packages) {
    const base = [this.pkgManager, "install", "--assumeno", ...packages];
    let out = this.runCommand(base);
    const notRoot = typeof process.getuid === "function" && process.getuid() !== 0;
    if (notRoot && /superuser privileges|must be run as root|need to be root|permission denied/i.test(`${this._lastStderr}\n${out}`)) {
      console.error(`[~] ${this.pkgManager} refused to run unprivileged — retrying the dry-run with 'sudo -n'.`);
      // env re-pins the locale because sudo's env_reset would drop it and the table is parsed as English.
      out = this.runCommand(["sudo", "-n", "env", "LC_ALL=C", "LANG=C", ...base]);
    }
    return out;
  }

  // ── OS detection (stdlib-equivalent — no external distro package) ───────────

  _parseOsRelease() {
    const data = {};
    for (const candidate of ["/etc/os-release", "/usr/lib/os-release"]) {
      try {
        const content = fs.readFileSync(candidate, "utf8");
        for (const raw of content.split("\n")) {
          const line = raw.trim();
          if (!line || line.startsWith("#") || !line.includes("=")) continue;
          const eq  = line.indexOf("=");
          const key = line.slice(0, eq).trim().toLowerCase();
          let val   = line.slice(eq + 1).trim();
          val = val.replace(/^"/, "").replace(/"$/, "").replace(/^'/, "").replace(/'$/, "");
          data[key] = val;
        }
        return data;
      } catch { continue; }
    }
    return data;
  }

  getOsInfo() {
    const raw     = this._parseOsRelease();
    const os_id   = (raw.id || "").replace(/\s+/g, "");
    const name    = raw.pretty_name || raw.name || os_id;
    const version = raw.version_id || raw.version || "";
    const like    = raw.id_like || "";

    return {
      id:              os_id,
      name,
      version,
      like,
      package_manager: this.pkgManager,
      ...raw,
    };
  }

  // ── Package manager availability ────────────────────────────────────────────
  // apt-get is what's actually invoked for resolution/version probing even
  // when this.pkgManager === "apt" — apt's own CLI output is explicitly
  // documented as unstable across versions for scripting, apt-get's isn't.

  _pmBinary() {
    return this.pkgManager === "apt" ? "apt-get" : this.pkgManager;
  }

  assertAvailable() {
    const bin = this._pmBinary();
    if (!this.commandExists(bin)) {
      throw new Error(
        `'${bin}' was not found on PATH — ubel-${this.pkgManager} requires ` +
        `${this.pkgManager} to be installed and on PATH, the same way ` +
        `ubel-pnpm requires pnpm.`
      );
    }
  }

  getPkgManagerVersion() {
    const bin = this._pmBinary();
    if (!this.commandExists(bin)) return "unknown";
    try {
      const r = spawnSync(bin, ["--version"], { encoding: "utf8" });
      const firstLine = ((r.stdout || r.stderr || "").split("\n")[0] || "").trim();
      const parts = firstLine.split(/\s+/);
      for (const part of parts) {
        if (/^\d+\.\d+/.test(part)) return part;
      }
    } catch { /* fall through */ }
    return "unknown";
  }

  // ── PURL builder ──────────────────────────────────────────────────────────────

  packageToPurl(osInfo, pkg, version) {
    const os_id      = (osInfo.id || "").replace(/\s+/g, "").toLowerCase();
    const like       = (osInfo.like || "").toLowerCase();
    const pkgManager = osInfo.package_manager || "";

    if (pkgManager === "apt") {
      if (os_id.includes("ubuntu") || like.includes("ubuntu")) return `pkg:deb/ubuntu/${pkg}@${version}`;
      return `pkg:deb/debian/${pkg}@${version}`;
    }
    if (os_id.includes("almalinux"))  return `pkg:rpm/almalinux/${pkg}@${version}`;
    if (os_id.includes("redhat") || os_id.includes("rhel")) return `pkg:rpm/redhat/${pkg}@${version}`;
    if (os_id.includes("alpaquita"))  return `pkg:apk/alpaquita/${pkg}@${version}`;
    if (os_id.includes("rocky"))      return `pkg:rpm/rocky-linux/${pkg}@${version}`;
    if (os_id.includes("alpine"))     return `pkg:apk/alpine/${pkg}@${version}`;

    // Any other rpm distro (Fedora, CentOS, Amazon Linux, Oracle Linux, ...): use the
    // os-release ID as the purl namespace rather than refusing to scan.
    if ((pkgManager === "dnf" || pkgManager === "yum") && /^[a-z0-9][a-z0-9._-]*$/.test(os_id)) {
      return `pkg:rpm/${os_id}/${pkg}@${version}`;
    }

    throw new Error(`Unsupported Linux distribution: id=${os_id} like=${like}`);
  }

  // ── get_linux_packages (health scan, delegates to LinuxHostScanner) ─────────

  getLinuxPackages() {
    this.assertAvailable();
    const systemInfo = this.getOsInfo();

    const scanner = new LinuxHostScanner();
    scanner.getInstalled();
    const rawPackages = scanner.inventoryData;

    let components = rawPackages.map(pkg => ({
      id:           pkg.id,
      name:         pkg.name,
      version:      pkg.version,
      type:         "application",
      scopes:       ["prod"],
      license:      pkg.license || pkg.licence || "unknown",
      dependencies: pkg.dependencies || [],
      paths:        pkg.paths || [],
      ecosystem:    pkg.ecosystem,
      state:        "undetermined",
    }));

    components = this.mergeInventoryByPurl(components);
    components = this.buildDependencySequences(components);

    this.inventoryData = components;
    const purls = components.map(c => c.id);

    // Kernel component (apt-based distros only, matching Python behaviour)
    if (this.pkgManager === "apt") {
      const kernelVersion = os.release();
      const kernelPurl    = this.packageToPurl(systemInfo, "linux", kernelVersion);
      const kernelComponent = {
        id: kernelPurl, name: "linux", version: kernelVersion, type: "application",
        license: "unknown", paths: [], dependencies: [], ecosystem: systemInfo.id,
        state: "undetermined", dependency_sequences: [],
      };
      components.push(kernelComponent);
      purls.push(kernelPurl);
    }

    return purls;
  }

  // ── resolve_packages (dry-run via the native package manager) ───────────────

  resolvePackages(packages) {
    if (typeof packages === "string") packages = [packages];

    this.assertAvailable();
    const osInfo = this.getOsInfo();
    this.pkgManagerVersion = this.getPkgManagerVersion();

    const resolved = [];

    // ── APT (Debian / Ubuntu) ────────────────────────────────────────────────
    if (this.pkgManager === "apt") {
      const output = this.runCommand(["apt-get", "-s", "--no-install-recommends", "install", ...packages]);
      // e.g. "Inst curl (7.88.1-10ubuntu1 Ubuntu:22.04/jammy [amd64])"
      // An upgrade carries the installed version in brackets:
      //   "Inst curl [7.81.0-1] (7.88.1-10ubuntu1 Ubuntu:22.04/jammy [amd64])"
      // which the previous pattern did not match, so upgraded packages were
      // silently left out of the scan.
      const pattern = /^Inst\s+(\S+)(?:\s+\[[^\]]*\])?\s+\(([^ ]+)/;
      for (const line of output.split("\n")) {
        const m = pattern.exec(line.trim());
        if (m) {
          resolved.push({
            name: m[1], version: m[2], type: "application",
            ecosystem: osInfo.id, license: "unknown", paths: [], dependencies: [],
          });
        }
      }
      if (resolved.length === 0 && !/\b0 newly installed\b/.test(output) && !/\b0 upgraded, 0 newly installed\b/.test(output)) {
        throw new Error(this._withStderr("apt-get dry-run produced no 'Inst' lines and no '0 newly installed' summary — refusing to treat that as a clean scan (the simulation likely failed)."));
      }
      return resolved;
    }

    // ── DNF (RHEL 8+, AlmaLinux, Rocky) ────────────────────────────────────────
    if (this.pkgManager === "dnf") {
      const output = this._runRpmDryRun(packages);
      let parsed;
      try { parsed = parseRpmTransaction(output, "dnf"); }
      catch (e) { throw new Error(this._withStderr(e.message)); }
      for (const p of parsed) {
        resolved.push({
          name: p.name, version: p.version, type: "application",
          license: "unknown", paths: [], dependencies: [], ecosystem: osInfo.id,
        });
      }
      return resolved;
    }

    // ── YUM (RHEL 7) ────────────────────────────────────────────────────────────
    // this.pkgManager === "yum" — the only remaining option (validated in the
    // constructor), so no fallthrough error case is needed here anymore.
    const output = this._runRpmDryRun(packages);
    let parsed;
    try { parsed = parseRpmTransaction(output, "yum"); }
    catch (e) { throw new Error(this._withStderr(e.message)); }
    for (const p of parsed) {
      resolved.push({
        name: p.name, version: p.version, type: "application",
        ecosystem: osInfo.id, license: "unknown", paths: [], dependencies: [],
      });
    }
    return resolved;
  }

  // ── get_packages_purls ───────────────────────────────────────────────────────

  getPackagesPurls(packages) {
    const resolved   = this.resolvePackages(packages);
    const systemInfo = this.getOsInfo();
    const identified = resolved.map(pkg => ({ id: this.packageToPurl(systemInfo, pkg.name, pkg.version) }));
    this.inventoryData = identified;
    return identified.map(pkg => pkg.id);
  }

  // ── run_real_install ─────────────────────────────────────────────────────────
  // packagesList: array of [name, version] tuples (mirrors get_dependency_from_purl output).

  runRealInstall(packagesList) {
    this.assertAvailable();
    const pkgs = this.pkgManager === "apt"
      ? packagesList.map(([name, version]) => `${name}=${version}`)
      : packagesList.map(([name, version]) => `${name}-${version}`);

    // apt: the dry-run resolved with --no-install-recommends, so the real
    // install must too — otherwise Recommends are installed that were never
    // scanned. apt-get is also what the dry-run used.
    const cmd = this.pkgManager === "apt"
      ? ["sudo", "apt-get", "install", "-y", "--no-install-recommends", ...pkgs]
      : ["sudo", this.pkgManager, "install", "-y", ...pkgs];
    const r = spawnSync(cmd[0], cmd.slice(1), { stdio: "inherit" });
    if (r.status !== 0) {
      console.error(`[!] Package install failed (exit ${r.status}): ${cmd.join(" ")}`);
      throw new Error(`Package install failed (exit ${r.status})`);
    }
    return r;
  }
}