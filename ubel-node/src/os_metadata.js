import fs from "fs";
import os from "os";
import { execSync } from "child_process";

/*
OUTPUT SCHEMA (identical everywhere)

{
  os_id: string,
  os_name: string,
  os_version: string,
  build: string | undefined,
  release: string | undefined
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
    const output = execSync(
      'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion"',
      { encoding: "utf8" }
    );

    const reg = {};

    output.split("\n").forEach(line => {
      line = line.trim();
      if (!line || line.startsWith("HKEY")) return;

      // split by multiple spaces (NOT regex with \S+)
      const parts = line.split(/\s{2,}/);
      if (parts.length < 3) return;

      const [key, , value] = parts;
      reg[key] = value;
    });

    return {
      os_id: "windows",
      os_name: reg.ProductName || reg["Product Name"],
      os_version: reg.DisplayVersion || reg.ReleaseId,
      /* build:
        reg.CurrentBuild && reg.UBR
          ? `${reg.CurrentBuild}.${reg.UBR}`
          : reg.CurrentBuild,*/
      release: reg.DisplayVersion || reg.ReleaseId
    };
  } catch (e) {
    return {
      os_id: "windows",
      os_name: undefined,
      os_version: undefined,
      //build: undefined,
      os_release: undefined
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