// linux_host_scanner.js
//
// Mirrors the output of package_scanner.py → scan_host() but runs entirely
// in Node.js using child_process.  Supports Debian/Ubuntu (dpkg), Alpine
// (apk), and RedHat/AlmaLinux/RockyLinux (rpm).
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
import { execFileSync, spawnSync } from "child_process";

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
 * Build a Map<pkgName, licenseString> by scanning /usr/share/doc/<pkg>/copyright
 * files with awk.  Returns an empty Map on any failure so the caller can
 * use it as a best-effort overlay without aborting the scan.
 */
function readDpkgLicenses(rootDir = "") {
  // execFileSync / shell glob never expand wildcards — enumerate files in JS.
  // We also:
  //   • Filter with statSync().isFile() because glob / readdirSync can surface
  //     dangling symlinks that make mawk abort with exit 2, silently skipping
  //     all subsequent files in the same invocation.
  //   • Use spawnSync (not execFileSync) so we always read stdout even when awk
  //     exits non-zero due to a missing file mid-run.
  //   • Chunk to 200 files to stay under ARG_MAX.
  const licenses = new Map();
  const docDir = rootDir ? path.join(rootDir, "/usr/share/doc") : "/usr/share/doc";
  if (!fs.existsSync(docDir)) return licenses;

  const files = [];
  try {
    for (const entry of fs.readdirSync(docDir)) {
      const cp = path.join(docDir, entry, "copyright");
      try {
        if (fs.statSync(cp).isFile()) files.push(cp);
      } catch { /* dangling symlink or permission error — skip */ }
    }
  } catch { return licenses; }

  if (!files.length) return licenses;

  // The gsub pattern strips the docDir prefix from awk's FILENAME so we get
  // back a bare package name — docDir now varies (rootDir-prefixed or not),
  // so it's escaped and built dynamically instead of hardcoded.
  const escapedDocDir = docDir.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const AWK_SCRIPT =
    String.raw`/^License:/ {pkg=FILENAME; gsub(/^` + escapedDocDir + String.raw`\/|\/copyright$/, "", pkg); print pkg, $2}`;

  const CHUNK = 200;
  for (let i = 0; i < files.length; i += CHUNK) {
    const chunk = files.slice(i, i + CHUNK);
    const result = spawnSync(
      "awk",
      [AWK_SCRIPT, ...chunk],
      { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, maxBuffer: 10 * 1024 * 1024 },
    );
    const out = result.stdout ?? "";
    for (const line of out.split("\n")) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      const sp = trimmed.indexOf(" ");
      if (sp === -1) continue;
      const pkg = trimmed.slice(0, sp).trim();
      const lic = trimmed.slice(sp + 1).trim();
      if (pkg && lic && !licenses.has(pkg)) licenses.set(pkg, lic);
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
// Strategy mirrors package_scanner.py exactly:
//   Pass 1 — rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t[%{REQUIRENAME},]\n'
//   Pass 2 — rpm -ql --qf '[%{=NAME}\t%{FILENAMES}\n]' <all packages>
// ─────────────────────────────────────────────────────────────────────────────

const RPM_QA_QF  = "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{LICENSE}\\t[%{REQUIRENAME},]\\n";
const RPM_QL_QF  = "[%{=NAME}\\t%{FILENAMES}\\n]";

function rpmQueryAll(rootDir = "") {
  const args = rootDir
    ? ["--root", rootDir, "-qa", "--qf", RPM_QA_QF]
    : ["-qa", "--qf", RPM_QA_QF];
  let out;
  try {
    out = execFileSync(
      "rpm",
      args,
      { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (e) {
    if (e.code === "ENOENT") throw new Error("rpm binary not found");
    throw new Error(`rpm -qa failed: ${e.stderr ?? e.message}`);
  }

  const pkgs = new Map();
  for (const line of out.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    const parts = trimmed.split("\t");
    const [name, version, license_, rawDeps = ""] = parts;
    if (!name || !version) continue;
    pkgs.set(name, {
      version,
      license: license_?.trim() || "unknown",
      deps:    cleanRpmDeps(rawDeps),
    });
  }
  return pkgs;
}

function* rpmQueryFilesChunk(pkgNames, rootDir = "") {
  const args = rootDir
    ? ["--root", rootDir, "-ql", "--qf", RPM_QL_QF, ...pkgNames]
    : ["-ql", "--qf", RPM_QL_QF, ...pkgNames];
  let out;
  try {
    out = execFileSync(
      "rpm",
      args,
      { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, stdio: ["ignore", "pipe", "pipe"] },
    );
  } catch (e) {
    if (e.code === "ENOENT") throw new Error("rpm binary not found");
    // Non-zero exit is common when some packages have no files; still parse stdout
    out = e.stdout ?? "";
  }

  for (const line of out.split("\n")) {
    const trimmed = line.trim();
    if (!trimmed || trimmed === "(contains no files)") continue;
    const tab = trimmed.indexOf("\t");
    if (tab === -1) continue;
    const pkgName  = trimmed.slice(0, tab);
    const filepath = trimmed.slice(tab + 1).trim();
    if (filepath) yield { pkgName, filepath };
  }
}

const RPM_CHUNK_SIZE = 200;

function* rpmQueryFiles(pkgNames, rootDir = "") {
  if (!pkgNames.length) return;
  for (let i = 0; i < pkgNames.length; i += RPM_CHUNK_SIZE) {
    yield* rpmQueryFilesChunk(pkgNames.slice(i, i + RPM_CHUNK_SIZE), rootDir);
  }
}

function scanRpm(ecosystem, rootDir = "") {
  const pkgs = rpmQueryAll(rootDir);

  const purls = new Map();
  for (const [name, { version }] of pkgs.entries()) {
    purls.set(name, makePurl(ecosystem, name, version));
  }

  const pathsByPkg = new Map();
  for (const { pkgName, filepath } of rpmQueryFiles([...pkgs.keys()], rootDir)) {
    if (!isExecutablePath(filepath)) continue;
    // Verify the execute bit on the real filesystem. rpm --root reports
    // filepath as the logical in-image path, so the on-disk check needs the
    // rootDir prefix while the recorded path stays logical.
    const realPath = rootDir ? path.join(rootDir, filepath) : filepath;
    try {
      const stat = fs.statSync(realPath);
      if (!stat.isFile() || !(stat.mode & 0o111)) continue;
    } catch { continue; }

    if (!pathsByPkg.has(pkgName)) pathsByPkg.set(pkgName, []);
    pathsByPkg.get(pkgName).push(filepath);
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