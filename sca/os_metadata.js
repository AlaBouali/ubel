import fs from "fs";
import os from "os";
import path from "path";
import { execSync, spawnSync } from "child_process";

/*
OUTPUT SCHEMA (identical everywhere — success AND error)

{
  os_id: string | undefined,
  os_name: string | undefined,
  os_version: string | undefined,   // full build: "10.0.19045.6466"  (Linux/macOS: VERSION_ID / ProductVersion)
  build: string | undefined,
  os_release: string | undefined,   // human-readable channel: "22H2" / "15.0" / VERSION string
  error?: string                    // present only when detection failed (fields above may still be partly filled)
}

getOSMetadata(rootDir):
  - no argument  -> the machine this process runs on
  - rootDir      -> the Linux filesystem extracted at rootDir (container-image scans). The host's own OS is
                    irrelevant there, so /etc/os-release is read from the image and never from the host.
*/

function emptyResult(extra = {}) {
  return { os_id: undefined, os_name: undefined, os_version: undefined, build: undefined, os_release: undefined, ...extra };
}

// ---------- Linux ----------
export function parseOsRelease(content) {
  const data = {};
  String(content).split("\n").forEach(raw => {
    const line = raw.trim();
    if (!line || line.startsWith("#")) return;

    const i = line.indexOf("=");
    if (i === -1) return;

    const key = line.slice(0, i).trim();
    let val = line.slice(i + 1).trim();
    val = val.replace(/^(["'])(.*)\1$/, "$2");

    data[key] = val;
  });
  return data;
}

/**
 * @param {string} [rootDir]  Extracted image root. Omit for the live host.
 */
export function getLinux(rootDir = "") {
  const candidates = ["/etc/os-release", "/usr/lib/os-release"];
  let content = null;
  let lastErr = null;
  for (const p of candidates) {
    try {
      content = fs.readFileSync(rootDir ? path.join(rootDir, p) : p, "utf8");
      break;
    } catch (e) { lastErr = e; }
  }
  if (content === null) {
    return emptyResult({
      os_id: rootDir ? undefined : "linux",
      error: `no os-release file found${rootDir ? " in the image" : ""}: ${lastErr ? lastErr.message : "unknown error"}`,
    });
  }

  const data = parseOsRelease(content);
  return emptyResult({
    os_id: data.ID,
    os_name: data.NAME,
    os_version: data.VERSION_ID || data.VERSION,
    /* build: not standardized in Linux */
    os_release: data.VERSION,
  });
}

// ---------- Windows ----------

/** "Microsoft Windows [Version 10.0.19045.6466]" -> "10.0.19045.6466". Locale-independent: matches the number, not the word "Version". */
export function parseWinVer(text) {
  const m = /\[[^\]\d]*(\d+\.\d+\.\d+(?:\.\d+)?)\s*\]/.exec(String(text ?? "")) || /(\d+\.\d+\.\d{3,}(?:\.\d+)?)/.exec(String(text ?? ""));
  return m ? m[1] : undefined;
}

/** Parses `reg query` output ("    Name    REG_SZ    Value") into { Name: "Value" }. */
export function parseRegQuery(output) {
  const reg = {};
  String(output ?? "").split(/\r?\n/).forEach(raw => {
    const line = raw.trim();
    if (!line || line.startsWith("HKEY")) return;
    const parts = line.split(/\s{2,}/);
    if (parts.length < 3) return;
    const [key, , value] = parts;
    reg[key] = value;
  });
  return reg;
}

/** reg.exe prints REG_DWORD as hex ("0x193a"); plain decimal passes through. */
function regNumber(v) {
  if (v === undefined || v === null || v === "") return undefined;
  const n = /^0x/i.test(v) ? parseInt(v, 16) : parseInt(v, 10);
  return Number.isFinite(n) ? n : undefined;
}

/** "10.0.<CurrentBuild>.<UBR>" from registry values, used when `ver` could not be parsed. */
export function windowsFullBuildFromRegistry(reg) {
  const currentBuild = reg.CurrentBuild;
  const ubr = regNumber(reg.UBR);
  if (!currentBuild) return undefined;
  return ubr !== undefined ? `10.0.${currentBuild}.${ubr}` : `10.0.${currentBuild}`;
}

/**
 * Windows 11 keeps "Windows 10 ..." in the ProductName registry value (it was never updated by
 * Microsoft). Build numbers >= 22000 are Windows 11.
 */
export function fixWindowsProductName(name, currentBuild) {
  const build = parseInt(currentBuild, 10);
  if (name && Number.isFinite(build) && build >= 22000) return name.replace(/^Windows 10\b/, "Windows 11");
  return name;
}

export function getWindows() {
  const result = emptyResult({ os_id: "windows" });
  const errors = [];

  // 1) Version string from `ver`. Failure here must not discard the registry data below.
  let verVersion;
  try {
    const r = spawnSync("cmd", ["/c", "ver"], { encoding: "utf8" });
    verVersion = parseWinVer(r.stdout);
    if (!verVersion) errors.push("could not parse `ver` output");
  } catch (e) { errors.push(`ver: ${e.message}`); }

  // 2) Registry.
  let reg = {};
  try {
    const output = execSync('reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"', { encoding: "utf8" });
    reg = parseRegQuery(output);
  } catch (e) { errors.push(`registry: ${e.message}`); }

  result.os_name = fixWindowsProductName(reg.ProductName || reg["Product Name"], reg.CurrentBuild);
  // os_version → full dotted build string used for CPE / vulnerability matching
  result.os_version = verVersion || windowsFullBuildFromRegistry(reg);
  // os_release → human-readable channel label (e.g. "22H2", "24H2")
  result.os_release = reg.DisplayVersion || reg.ReleaseId;

  if (errors.length && !result.os_version) result.error = errors.join("; ");
  return result;
}

// ---------- macOS ----------
export function getMacOS() {
  try {
    const output = execSync("sw_vers", { encoding: "utf8" });

    const data = {};
    output.split("\n").forEach(line => {
      const i = line.indexOf(":");
      if (i === -1) return;

      const key = line.slice(0, i).trim();
      const val = line.slice(i + 1).trim();
      data[key] = val;
    });

    return emptyResult({
      os_id: "macos",
      os_name: data.ProductName,
      os_version: data.ProductVersion,
      os_release: data.ProductVersion,
      /* build: data.BuildVersion, */
    });
  } catch (e) {
    return emptyResult({ os_id: "macos", error: e.message });
  }
}

// ---------- unified ----------
/**
 * @param {string} [rootDir]  Extracted container-image root. When given, the OS of the IMAGE is
 *                            reported (always Linux), regardless of the host platform.
 */
export function getOSMetadata(rootDir = "") {
  if (rootDir) return getLinux(rootDir);

  const platform = os.platform();

  if (platform === "linux") return getLinux();
  if (platform === "win32") return getWindows();
  if (platform === "darwin") return getMacOS();

  return emptyResult({ os_id: platform, error: `unsupported platform: ${platform}` });
}