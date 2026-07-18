import fs from "fs";
import os from "os";
import { execSync, spawnSync } from "child_process";

/*
OUTPUT SCHEMA (identical everywhere)

{
  os_id: string,
  os_name: string,
  os_version: string,   // full build: "10.0.19045.6466"  (Linux/macOS: VERSION_ID / ProductVersion)
  build: string | undefined,
  os_release: string | undefined  // human-readable channel: "22H2" / "15.0" / VERSION string
}
*/

// ---------- Linux ----------
export function getLinux() {
  try {
    const content = fs.readFileSync("/etc/os-release", "utf8");

    const data = {};
    content.split("\n").forEach(line => {
      if (!line || line.startsWith("#")) return;

      const i = line.indexOf("=");
      if (i === -1) return;

      const key = line.slice(0, i);
      let val = line.slice(i + 1);
      val = val.replace(/^"/, "").replace(/"$/, "");

      data[key] = val;
    });

    return {
      os_id: data.ID,
      os_name: data.NAME,
      os_version: data.VERSION_ID || data.VERSION,
      /* build: undefined, // not standardized in Linux */
      os_release: data.VERSION
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ---------- Windows ----------
export function getWindows() {
  try {
    const fullVersion = spawnSync("cmd", ["/c", "ver"], { encoding: "utf8" }).stdout.trim();
    // Example output: "Microsoft Windows [Version 10.0.19045.6466]"
    const os_version = fullVersion.split("ersion ")[1].replace("[","").replace("]","")
    const output = execSync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"',
      { encoding: "utf8" }
    );

    const reg = {};

    output.split("\n").forEach(line => {
      line = line.trim();
      if (!line || line.startsWith("HKEY")) return;

      // Registry lines: "    KeyName    REG_SZ    Value"
      // After trim: "KeyName    REG_SZ    Value"
      // Split on 2+ spaces → ["KeyName", "REG_SZ", "Value"]
      const parts = line.split(/\s{2,}/);
      if (parts.length < 3) return;

      const [key, , value] = parts;
      reg[key] = value;
    });

    // Full NT build: "10.0.<CurrentBuild>.<UBR>"
    // CurrentBuild  e.g. "19045"
    // UBR           e.g. "6466"  (Update Build Revision — the patch suffix)
    const currentBuild = reg.CurrentBuild;
    const ubr = reg.UBR;
    const fullBuild =
      currentBuild && ubr
        ? `10.0.${currentBuild}.${ubr}`
        : currentBuild
          ? `10.0.${currentBuild}`
          : undefined;
    return {
      os_id: "windows",
      os_name: reg.ProductName || reg["Product Name"],
      // os_version → full dotted build string used for CPE / vulnerability matching
      os_version: os_version,
      // os_release → human-readable channel label (e.g. "22H2", "24H2")
      os_release: reg.DisplayVersion || reg.ReleaseId,
    };
  } catch (e) {
    return {
      os_id: "windows",
      os_name: undefined,
      os_version: undefined,
      os_release: undefined,
      error: e.message,
    };
  }
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

    return {
      os_id: "macos",
      os_name: data.ProductName,
      os_version: data.ProductVersion,
      os_release: data.ProductVersion,
      /* build: data.BuildVersion, */
    };
  } catch (e) {
    return { error: e.message };
  }
}

// ---------- unified ----------
export function getOSMetadata() {
  const platform = os.platform();

  if (platform === "linux") return getLinux();
  if (platform === "win32") return getWindows();
  if (platform === "darwin") return getMacOS();

  return { error: "unsupported platform", platform };
}