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
import os            from "os";
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
    try {
      const r = spawnSync(bin, args, { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, maxBuffer: 32 * 1024 * 1024 });
      if (r.error) throw r.error;
      // Mirror Python: return stdout on a clean run OR a non-zero exit that
      // still produced resolvable output (apt-get -s / dnf --assumeno exit
      // non-zero on purpose since nothing is actually installed).
      return (r.stdout || "").trim();
    } catch (e) {
      console.error(`[!] Command failed: ${cmd.join(" ")}`);
      console.error(e.message);
      return "";
    }
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
      const pattern = /^Inst\s+(\S+)\s+\(([^ ]+)/;
      for (const line of output.split("\n")) {
        const m = pattern.exec(line.trim());
        if (m) {
          resolved.push({
            name: m[1], version: m[2], type: "application",
            ecosystem: osInfo.id, license: "unknown", paths: [], dependencies: [],
          });
        }
      }
      return resolved;
    }

    // ── DNF (RHEL 8+, AlmaLinux, Rocky) ────────────────────────────────────────
    if (this.pkgManager === "dnf") {
      const output = this.runCommand(["dnf", "install", "--assumeno", ...packages]);
      let capture = false;
      for (let line of output.split("\n")) {
        line = line.trim();
        if (line.startsWith("Installing:")) { capture = true; continue; }
        if (capture) {
          if (!line) break;
          const parts = line.split(/\s+/);
          if (parts.length >= 2) {
            resolved.push({
              name: parts[0].split(".")[0], version: parts[1], type: "application",
              license: "unknown", paths: [], dependencies: [], ecosystem: osInfo.id,
            });
          }
        }
      }
      return resolved;
    }

    // ── YUM (RHEL 7) ────────────────────────────────────────────────────────────
    // this.pkgManager === "yum" — the only remaining option (validated in the
    // constructor), so no fallthrough error case is needed here anymore.
    const output = this.runCommand(["yum", "install", "--assumeno", ...packages]);
    let capture = false;
    for (let line of output.split("\n")) {
      line = line.trim();
      if (line.startsWith("Installing:")) { capture = true; continue; }
      if (capture) {
        if (!line) break;
        const parts = line.split(/\s+/);
        if (parts.length >= 2) {
          resolved.push({
            name: parts[0].split(".")[0], version: parts[1], type: "application",
            ecosystem: osInfo.id, license: "unknown", paths: [], dependencies: [],
          });
        }
      }
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

    const cmd = ["sudo", this.pkgManager, "install", "-y", ...pkgs];
    const r = spawnSync(cmd[0], cmd.slice(1), { stdio: "inherit" });
    if (r.status !== 0) {
      console.error(`[!] Package install failed (exit ${r.status}): ${cmd.join(" ")}`);
      throw new Error(`Package install failed (exit ${r.status})`);
    }
    return r;
  }
}