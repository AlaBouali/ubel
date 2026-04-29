// windows_host_scanner.js
//
// Mirrors the output contract of linux_runner.js → LinuxHostScanner.getInstalled()
// but runs on Windows, targeting a fixed set of well-known software components
// with proper CPE 2.3 output.
//
// Output format per package (identical to linux_runner.js):
// {
//   id:           "pkg:generic/windows/python@3.12.4",
//   name:         "python",
//   version:      "3.12.4",
//   type:         "application",
//   ecosystem:    "windows",
//   license:      "unknown",
//   paths:        ["C:\\Python312\\python.exe"],
//   dependencies: [],
//   scopes:       ["prod"],
//   state:        "undetermined",
//   cpe:          "cpe:2.3:a:python:python:3.12.4:*:*:*:*:*:*:*",
// }

import { spawnSync } from "child_process";

// ─────────────────────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────────────────────

const SUBPROCESS_TIMEOUT = 30_000; // ms

// ─────────────────────────────────────────────────────────────────────────────
// Helper functions
// ─────────────────────────────────────────────────────────────────────────────

/** Extract first dotted-version-like token from a string */
function extractVersionToken(text) {
  const m = text.match(/(\d+\.\d+[\d.]*)/);
  return m ? m[1] : null;
}

/** Parse Java version string from `java -version` (stderr) */
function parseJavaVersion(text) {
  const quoted = text.match(/"([\d._]+)"/);
  if (quoted) {
    let v = quoted[1];
    if (v.startsWith("1.")) {
      const parts = v.slice(2).split("_");
      return parts.join(".");
    }
    return v.replace(/_/g, ".");
  }
  return null;
}

/** Simple semver comparison */
function cmpSemver(a, b) {
  const pa = a.split(".").map(Number);
  const pb = b.split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] ?? 0) - (pb[i] ?? 0);
    if (d !== 0) return d;
  }
  return 0;
}

/** Map Visual Studio version (e.g., "17.10.4") → product year suffix */
function mapVisualStudioYear(version) {
  const major = parseInt(version.split(".")[0], 10);
  if (major >= 17) return "2022";
  if (major === 16) return "2019";
  if (major === 15) return "2017";
  if (major === 14) return "2015";
  return "2015"; // fallback
}

// ─────────────────────────────────────────────────────────────────────────────
// Strategy runners
// ─────────────────────────────────────────────────────────────────────────────

function runPowerShell(script) {
  try {
    const result = spawnSync(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-Command", script],
      { encoding: "utf8", timeout: SUBPROCESS_TIMEOUT, windowsHide: true ,shell: true}
    );
    if (result.status === 0 && result.stdout) return result.stdout.trim();
    return null;
  } catch {
    return null;
  }
}

function readRegistryValue(key, valueName) {
  const script = `(Get-ItemProperty '${key}' -ErrorAction SilentlyContinue).'${valueName}'`;
  const out = runPowerShell(script);
  return out || null;
}

function readRegistrySubKeys(key) {
  const script = `(Get-ChildItem '${key}' -ErrorAction SilentlyContinue).PSChildName | Sort-Object { [version]$_ } | Select-Object -Last 1`;
  const out = runPowerShell(script);
  return out || null;
}

function readFileVersion(paths) {
  for (const p of paths) {
    const script = `(Get-Item '${p.replace(/'/g, "''")}' -ErrorAction SilentlyContinue).VersionInfo.FileVersion`;
    const out = runPowerShell(script);
    if (out) return out.split(" ")[0].trim();
  }
  return null;
}

function runExec(bin, args, parse, captureStderr = false) {
  try {
    const result = spawnSync(bin, args, {
      encoding: "utf8",
      timeout: SUBPROCESS_TIMEOUT,
      windowsHide: true,
      shell: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    const stdout = result.stdout ? result.stdout.trim() : "";
    const combined = stdout + (captureStderr ? (result.stderr ?? "") : "");
    if (!combined.trim()) return null;
    return parse(combined);
  } catch {
    return null;
  }
}

function resolveExePath(pathCmd) {
  if (!pathCmd) return [];

  if (pathCmd.type === "where") {
    try {
      const result = spawnSync("where.exe", [pathCmd.bin], {
        encoding: "utf8",
        timeout: 10000,
        windowsHide: true,
        shell: true,
      });
      if (result.status === 0 && result.stdout) {
        return result.stdout.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      }
    } catch {}
    return [];
  }

  if (pathCmd.type === "literal") {
    return pathCmd.paths.filter(p => {
      try {
        const out = runPowerShell(`Test-Path '${p.replace(/'/g, "''")}'`);
        return out === "True";
      } catch {
        return false;
      }
    });
  }
  return [];
}

function detectVersion(cmds) {
  for (const cmd of cmds) {
    let raw = null;
    switch (cmd.type) {
      case "powershell": {
        const out = runPowerShell(cmd.script);
        if (out) raw = cmd.parse ? cmd.parse(out) : out.trim() || null;
        break;
      }
      case "exec": {
        raw = runExec(cmd.bin, cmd.args, cmd.parse, cmd.captureStderr ?? false);
        break;
      }
      case "registry": {
        if (cmd.enumSubKeys) {
          raw = readRegistrySubKeys(cmd.key);
        } else {
          const val = readRegistryValue(cmd.key, cmd.name);
          raw = val ? (cmd.parse ? cmd.parse(val) : val) : null;
        }
        break;
      }
      case "fileVersion": {
        raw = readFileVersion(cmd.paths);
        break;
      }
    }
    if (raw) return raw;
  }
  return null;
}

// ─────────────────────────────────────────────────────────────────────────────
// CPE builder (strict CPE 2.3)
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Build a CPE 2.3 string from a prefix or template.
 * - If prefix has 12+ colons, treat as template and replace version slot (index 5).
 * - Otherwise append version and wildcards to complete 13 fields.
 */
function buildCpe(cpePrefix, version) {
  const colonCount = (cpePrefix.match(/:/g) || []).length;
  if (colonCount >= 12) {
    // Full template: replace the version slot (index 5)
    const parts = cpePrefix.split(":");
    parts[5] = version;
    return parts.join(":");
  }
  // Normal prefix: append version + wildcards
  return `${cpePrefix}${version}:*:*:*:*:*:*:*`;
}

// ─────────────────────────────────────────────────────────────────────────────
// PURL builder
// ─────────────────────────────────────────────────────────────────────────────

function makePurl(name, version) {
  return `pkg:generic/windows/${encodeURIComponent(name)}@${version}`;
}

// ─────────────────────────────────────────────────────────────────────────────
// Multi‑entry runner for .NET runtimes
// ─────────────────────────────────────────────────────────────────────────────

/**
 * Execute a command that returns multiple lines, each describing a separate
 * installed component (e.g., `dotnet --list-runtimes`).
 * Returns an array of { version, paths, cpe, name } objects.
 */
function runMultiEntry(componentDef) {
  const cmds = componentDef.multiEntryCmds || componentDef.cmds;
  if (!cmds) return [];

  // Try each command until we get a non‑empty result
  let rawOutput = null;
  for (const cmd of cmds) {
    switch (cmd.type) {
      case "powershell": {
        const out = runPowerShell(cmd.script);
        if (out) {
          rawOutput = out;
          break;
        }
        break;
      }
      case "exec": {
        try {
          const result = spawnSync(cmd.bin, cmd.args, {
            encoding: "utf8",
            timeout: SUBPROCESS_TIMEOUT,
            windowsHide: true,
            shell: true,
            stdio: ["ignore", "pipe", "pipe"],
          });
          const combined = (result.stdout ?? "") + (cmd.captureStderr ? (result.stderr ?? "") : "");
          if (combined.trim()) {
            rawOutput = combined;
            break;
          }
        } catch {}
        break;
      }
    }
    if (rawOutput) break;
  }

  if (!rawOutput) return [];

  // Delegate parsing to the component’s custom parser
  return componentDef.parseMultiEntry(rawOutput);
}

// ─────────────────────────────────────────────────────────────────────────────
// Component catalogue
// ─────────────────────────────────────────────────────────────────────────────

const COMPONENTS = {

  // Windows OS (special: parseResult returns full CPE)
  windows: {
    cpe: "cpe:2.3:o:microsoft:windows_", // dummy, overridden by parseResult
    cmds: [{
      type: "exec",
      bin: "cmd.exe",
      args: ["/c", "ver"],
      parse: out => {
        // ver outputs: "Microsoft Windows [Version 10.0.22631.3447]"
        const m = out.match(/Version\s+([\d.]+)/i);
        if (!m) return null;
        const version = m[1]; // e.g. "10.0.22631.3447"
        const build = parseInt(version.split(".")[2] ?? "0", 10);
        const edition = build >= 22000 ? "11" : build >= 10240 ? "10" : "unknown";
        return `${edition}|${version}`;
      },
    }],
    parseResult: (raw) => {
      const [edition, version] = raw.split("|");
      return {
        version,
        cpeOverride: `cpe:2.3:o:microsoft:windows_${edition}:${version}:*:*:*:*:*:*:*`,
      };
    },
    nameOverride: "windows",
    pathCmd: null,
  },

  // Windows Defender
  windows_defender: {
    cpe: "cpe:2.3:a:microsoft:windows_defender:",
    cmds: [
      { type: "powershell", script: `(Get-MpComputerStatus).AMProductVersion`, parse: out => out.trim() || null },
      { type: "registry", key: "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender", name: "ProductVersion" },
    ],
    pathCmd: { type: "where", bin: "MpCmdRun.exe" },
  },

  // ===================== .NET RUNTIMES (MULTI‑ENTRY) =====================
  dotnet_runtimes: {
    // Not a real component – just a container for multi‑entry detection.
    // The scanner will add one package per runtime.
    multiEntry: true,
    multiEntryCmds: [
      {
        type: "exec",
        bin: "dotnet",
        args: ["--list-runtimes"],
        parse: out => out, // raw output
      },
      {
        type: "exec",
        bin: "C:\\Program Files\\dotnet\\dotnet.exe",
        args: ["--list-runtimes"],
        parse: out => out,
      },
      {
        type: "powershell",
        script: `& "C:\\Program Files\\dotnet\\dotnet.exe" --list-runtimes`,
        parse: out => out,
      },
    ],
    parseMultiEntry: (rawOutput) => {
      const entries = [];
      const lines = rawOutput.split(/\r?\n/);
      for (const line of lines) {
        // Format: "Microsoft.NETCore.App 6.0.26 [C:\Program Files\dotnet\shared\Microsoft.NETCore.App]"
        const match = line.match(/^(\S+(?:\s+\S+)?)\s+(\d+\.\d+\.\d+(?:-[\w.]+)?)\s+\[(.*?)\]$/);
        if (!match) continue;
        const [, runtimeName, version, installPath] = match;

        let cpeProduct;
        if (runtimeName === 'Microsoft.NETCore.App') cpeProduct = '.net_core_runtime';
        else if (runtimeName === 'Microsoft.WindowsDesktop.App') cpeProduct = 'windowsdesktop_runtime';
        else if (runtimeName === 'Microsoft.AspNetCore.App') cpeProduct = 'asp.net_core_runtime';
        else cpeProduct = runtimeName.toLowerCase().replace(/\s+/g, '_');

        const cpePrefix = `cpe:2.3:a:microsoft:${cpeProduct}:`;
        const cpe = buildCpe(cpePrefix, version);
        entries.push({
          version,
          paths: [installPath],
          cpe,
          name: cpeProduct,
          // Keep the original runtime name for potential future use
          rawName: runtimeName,
        });
      }
      return entries;
    },
    pathCmd: { type: "where", bin: "dotnet.exe" },
  },

  // PowerShell
  powershell: {
    cpe: "cpe:2.3:a:microsoft:powershell:",
    cmds: [
      {
        type: "exec",
        bin: "pwsh",
        args: ["-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"],
        parse: out => out.trim() || null,
      },
      {
        type: "powershell",
        script: `$PSVersionTable.PSVersion.ToString()`,
        parse: out => out.trim() || null,
      },
    ],
    pathCmd: { type: "where", bin: "pwsh.exe" },
  },

  // Python
  python: {
    cpe: "cpe:2.3:a:python:python:",
    cmds: [
      { type: "exec", bin: "python", args: ["--version"], parse: out => extractVersionToken(out) },
      { type: "exec", bin: "python3", args: ["--version"], parse: out => extractVersionToken(out) },
      { type: "registry", key: "HKLM:\\SOFTWARE\\Python\\PythonCore", enumSubKeys: true },
    ],
    pathCmd: { type: "where", bin: "python.exe" },
  },

  // Node.js
  nodejs: {
    cpe: "cpe:2.3:a:nodejs:node.js:",
    cmds: [
      { type: "exec", bin: "node", args: ["--version"], parse: out => out.trim().replace(/^v/, "") },
    ],
    nameOverride: "node.js",
    pathCmd: { type: "where", bin: "node.exe" },
  },

  // PHP
  php: {
    cpe: "cpe:2.3:a:php:php:",
    cmds: [
      { type: "exec", bin: "php", args: ["--version"], parse: out => extractVersionToken(out) },
    ],
    pathCmd: { type: "where", bin: "php.exe" },
  },

  // Rust
  rust: {
    cpe: "cpe:2.3:a:rust-lang:rust:",
    cmds: [
      { type: "exec", bin: "rustc", args: ["--version"], parse: out => extractVersionToken(out) },
    ],
    pathCmd: { type: "where", bin: "rustc.exe" },
  },

  // Go
  golang: {
    cpe: "cpe:2.3:a:golang:go:",
    cmds: [
      {
        type: "exec",
        bin: "go",
        args: ["version"],
        parse: out => { const m = out.match(/go([\d.]+)/); return m ? m[1] : null; },
      },
    ],
    nameOverride: "go",
    pathCmd: { type: "where", bin: "go.exe" },
  },

  // Ruby
  ruby: {
    cpe: "cpe:2.3:a:ruby-lang:ruby:",
    cmds: [
      { type: "exec", bin: "ruby", args: ["--version"], parse: out => extractVersionToken(out) },
    ],
    pathCmd: { type: "where", bin: "ruby.exe" },
  },

  // JRE
  jre: {
    cpe: "cpe:2.3:a:oracle:jre:",
    cmds: [
      { type: "exec", bin: "java", args: ["-version"], parse: parseJavaVersion, captureStderr: true },
      { type: "registry", key: "HKLM:\\SOFTWARE\\JavaSoft\\Java Runtime Environment", name: "CurrentVersion" },
      { type: "registry", key: "HKLM:\\SOFTWARE\\JavaSoft\\JRE", enumSubKeys: true },
    ],
    pathCmd: { type: "where", bin: "java.exe" },
  },

  // JDK
  jdk: {
    cpe: "cpe:2.3:a:oracle:jdk:",
    cmds: [
      { type: "exec", bin: "javac", args: ["-version"], parse: out => extractVersionToken(out) },
      { type: "registry", key: "HKLM:\\SOFTWARE\\JavaSoft\\Java Development Kit", name: "CurrentVersion" },
      { type: "registry", key: "HKLM:\\SOFTWARE\\JavaSoft\\JDK", enumSubKeys: true },
    ],
    pathCmd: { type: "where", bin: "javac.exe" },
  },

  // Microsoft Edge Chromium
  edge_chromium: {
    cpe: "cpe:2.3:a:microsoft:edge:",
    cmds: [
      {
        type: "powershell",
        script: `(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\{56EB18F8-8008-4CBD-B6D2-8C97FE7E9062}' -ErrorAction SilentlyContinue).pv`,
        parse: out => out.trim() || null,
      },
      {
        type: "fileVersion",
        paths: [
          "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
          "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        ],
      },
    ],
    nameOverride: "edge_chromium",
    pathCmd: {
      type: "literal",
      paths: [
        "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
      ],
    },
  },

  // Firefox
  firefox: {
    cpe: "cpe:2.3:a:mozilla:firefox:",
    cmds: [
      {
        type: "registry",
        key: "HKLM:\\SOFTWARE\\Mozilla\\Mozilla Firefox",
        name: "CurrentVersion",
        parse: out => out.split(" ")[0] || null,
      },
      {
        type: "fileVersion",
        paths: [
          "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
          "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
        ],
      },
    ],
    pathCmd: {
      type: "literal",
      paths: [
        "C:\\Program Files\\Mozilla Firefox\\firefox.exe",
        "C:\\Program Files (x86)\\Mozilla Firefox\\firefox.exe",
      ],
    },
  },

  // Google Chrome
  chrome: {
    cpe: "cpe:2.3:a:google:chrome:",
    cmds: [
      { type: "registry", key: "HKLM:\\SOFTWARE\\Google\\Update\\Clients\\{8A69D345-D564-463c-AFF1-A69D9E530F96}", name: "pv" },
      { type: "registry", key: "HKCU:\\SOFTWARE\\Google\\Update\\Clients\\{8A69D345-D564-463c-AFF1-A69D9E530F96}", name: "pv" },
      {
        type: "fileVersion",
        paths: [
          "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ],
      },
    ],
    pathCmd: {
      type: "literal",
      paths: [
        "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
      ],
    },
  },

  // Git for Windows
  git: {
    cpe: "cpe:2.3:a:gitforwindows:git:",
    cmds: [
      {
        type: "exec",
        bin: "git",
        args: ["--version"],
        parse: out => { const m = out.match(/([\d]+\.[\d]+\.[\d]+)/); return m ? m[1] : null; },
      },
      { type: "registry", key: "HKLM:\\SOFTWARE\\GitForWindows", name: "CurrentVersion" },
    ],
    pathCmd: { type: "where", bin: "git.exe" },
  },

  // Docker Desktop Windows
  docker_desktop: {
    cpe: "cpe:2.3:a:docker:desktop:*:*:*:*:*:windows:*:*", // full template
    cmds: [
      {
        type: "exec",
        bin: "docker",
        args: ["version", "--format", "{{.Client.Version}}"],
        parse: out => out.trim() || null,
      },
      { type: "registry", key: "HKLM:\\SOFTWARE\\Docker Inc.\\Docker Desktop", name: "Version" },
      {
        type: "powershell",
        script: `(Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Docker Desktop' -ErrorAction SilentlyContinue).DisplayVersion`,
        parse: out => out.trim() || null,
      },
    ],
    nameOverride: "docker_desktop",
    pathCmd: {
      type: "literal",
      paths: ["C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe"],
    },
  },

  // Visual Studio (with edition mapping)
  visual_studio: {
    cpe: " cpe:2.3:a:microsoft:visual_studio_code:", // incomplete, parseResult will replace
    cmds: [
      {
        type: "exec",
        bin: "code",
        args: ["--version"],
        parse: out => out.split("\n")[0].trim(),
      },
      {
        type: "powershell",
        script: `Get-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'Visual Studio 20' } | Select-Object -ExpandProperty DisplayVersion -First 1`,
        parse: out => out.trim() || null,
      },
    ],
    parseResult: (rawVersion) => {
      const year = mapVisualStudioYear(rawVersion);
      const cpeOverride = ` cpe:2.3:a:microsoft:visual_studio_code:${rawVersion}:*:*:*:*:*:*:*`;
      return { version: rawVersion, cpeOverride };
    },
    nameOverride: "visual_studio",
    pathCmd: null,
  },

  cursor: {
    cpe: "cpe:2.3:a:anysphere:cursor:",
    cmds: [
      {
        type: "exec",
        bin: "cursor",
        args: ["--version"],
        parse: out => out.split("\n")[0].trim(),
      },
    ],
    parseResult: (rawVersion) => {
      return { version: rawVersion };
    },
    nameOverride: "cursor",
    pathCmd: null,
  },
};

// ─────────────────────────────────────────────────────────────────────────────
// Package builder
// ─────────────────────────────────────────────────────────────────────────────

function buildPackage(key, componentDef, version, paths, cpeOverride = null) {
  const name = componentDef.nameOverride ?? key;
  const cpe = cpeOverride ?? buildCpe(componentDef.cpe, version);
  let sw_type = "application";
  if (cpe.startsWith("cpe:2.3:o:")) {
    sw_type = "operating_system";
  }
  return {
    id: cpe,
    cpe,
    name,
    version,
    type: sw_type,
    ecosystem: "windows",
    license: "unknown",
    state: "undetermined",
    scopes: ["prod"],
    paths,
    dependencies: [],
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// ENTRY POINT
// ─────────────────────────────────────────────────────────────────────────────

function detectPerPathVersions(componentDef) {
  const results = [];

  // Only makes sense if we can resolve paths
  const paths = resolveExePath(componentDef.pathCmd ?? null);
  if (!paths.length) return [];

  // Only attempt per-path if there is at least one exec command
  const execCmds = (componentDef.cmds || []).filter(c => c.type === "exec");
  if (!execCmds.length) return [];

  for (const p of paths) {
    for (const cmd of execCmds) {
      try {
        const res = spawnSync(p, cmd.args || [], {
          encoding: "utf8",
          timeout: SUBPROCESS_TIMEOUT,
          windowsHide: true,
          shell: true,
          stdio: ["ignore", "pipe", "pipe"],
        });

        const combined =
          (res.stdout ?? "") +
          (cmd.captureStderr ? (res.stderr ?? "") : "");

        if (!combined.trim()) continue;

        const version = cmd.parse ? cmd.parse(combined) : combined.trim();
        if (!version) continue;

        results.push({ version, path: p });
        break; // next path
      } catch {
        continue;
      }
    }
  }

  return results;
}

export class WindowsHostScanner {
  static inventoryData = [];

  static async getInstalled() {
    this.inventoryData = [];

    // ── Detect one component, returns array of package objects (may be empty) ──
    function detectComponent(key, componentDef) {
      const results = [];

      // ── 1) Multi-entry (e.g. .NET runtimes) ──
      if (componentDef.multiEntry) {
        const multiEntries = runMultiEntry(componentDef);
        for (const entry of multiEntries) {
          results.push({
            id: entry.cpe,
            name: entry.name,
            version: entry.version,
            type: "application",
            ecosystem: "windows",
            license: "unknown",
            state: "undetermined",
            scopes: ["prod"],
            paths: entry.paths,
            dependencies: [],
          });
        }
        return results;
      }

      // ── 2) Per-path detection ──
      const perPath = detectPerPathVersions(componentDef);
      if (perPath.length > 0) {
        for (const { version, path } of perPath) {
          results.push(buildPackage(key, componentDef, version, [path], null));
        }
        return results;
      }

      // ── 3) Scalar detection ──
      let version = null;
      let cpeOverride = null;

      try {
        const raw = detectVersion(componentDef.cmds);
        if (!raw) return results;

        if (componentDef.parseResult) {
          const parsed = componentDef.parseResult(raw);
          version = parsed.version;
          cpeOverride = parsed.cpeOverride ?? null;
        } else {
          version = raw;
        }
      } catch {
        return results;
      }

      if (!version) return results;

      const paths = resolveExePath(componentDef.pathCmd ?? null);
      results.push(buildPackage(key, componentDef, version, paths, cpeOverride));
      return results;
    }

    // ── Run all component detections in parallel using worker threads ──
    // spawnSync calls are CPU-bound/blocking, so we parallelize via
    // Promise.allSettled to maximally overlap I/O wait across PowerShell
    // and registry probes.
    const entries = Object.entries(COMPONENTS);
    const settled = await Promise.allSettled(
      entries.map(([key, def]) =>
        // Wrap the synchronous work in a Promise so all components are
        // dispatched before any result is awaited.
        Promise.resolve().then(() => detectComponent(key, def))
      )
    );

    const packages = [];
    for (const result of settled) {
      if (result.status === "fulfilled") {
        packages.push(...result.value);
      }
    }

    packages.sort((a, b) => a.name.localeCompare(b.name));
    for (const pkg of packages) {
      pkg.id = pkg.id.trim();
      delete pkg.cpe; // id now contains the full CPE, so we can remove the redundant cpe field
    }
    this.inventoryData = packages;
    return packages.map(p => p.id);
  }
}

export default WindowsHostScanner;