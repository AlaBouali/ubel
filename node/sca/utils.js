import fs   from "fs";
import path  from "path";
import { fileURLToPath } from "url";

/**
 * Load UBEL_API_KEY, UBEL_ASSET_ID, UBEL_ENDPOINT from .env or environment.
 * Mirrors Python load_environment().
 */
export function loadEnvironment() {
  // Minimal dotenv — read .env in cwd if it exists
  const envPath = path.join(process.cwd(), ".env");
  if (fs.existsSync(envPath)) {
    const lines = fs.readFileSync(envPath, "utf-8").split("\n");
    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith("#")) continue;
      const eq = trimmed.indexOf("=");
      if (eq === -1) continue;
      const key = trimmed.slice(0, eq).trim();
      const val = trimmed.slice(eq + 1).trim().replace(/^["']|["']$/g, "");
      if (!process.env[key]) process.env[key] = val;
    }
  }

  return {
    apiKey:   process.env.UBEL_API_KEY   || null,
    assetId:  process.env.UBEL_ASSET_ID  || null,
    endpoint: process.env.UBEL_ENDPOINT  || null,
  };
}

/**
 * Create and return the output directory, mirroring Python create_output_dir.
 */
export function createOutputDir(base = "./") {
  const now = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  const timestamp = `${now.getFullYear()}_${pad(now.getMonth()+1)}_${pad(now.getDate())}__${pad(now.getHours())}_${pad(now.getMinutes())}_${pad(now.getSeconds())}`;
  const datePath  = `${now.getFullYear()}/${pad(now.getMonth()+1)}/${pad(now.getDate())}`;
  const dir = path.join(base, ".ubel", "reports", "remote", datePath);
  fs.mkdirSync(dir, { recursive: true });
  return { dir, timestamp };
}

/**
 * Download a file from url to destination path.
 */
export async function downloadFile(url, destination) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`Download failed: ${res.status} ${url}`);
  const buf = await res.arrayBuffer();
  fs.writeFileSync(destination, Buffer.from(buf));
}

/**
 * Recursive pretty-print of an object — mirrors Python Ubel_Engine.dict_to_str.
 */
export function dictToStr(data, indent = 0, step = 4) {
  const lines = [];
  const pad = " ".repeat(indent);

  if (data && typeof data === "object" && !Array.isArray(data)) {
    for (const [key, value] of Object.entries(data)) {
      lines.push(`${pad}${key}:`);
      if (value && typeof value === "object") {
        lines.push(dictToStr(value, indent + step, step));
      } else {
        lines.push(" ".repeat(indent + step) + String(value));
      }
    }
  } else if (Array.isArray(data)) {
    for (const item of data) {
      if (item && typeof item === "object") {
        lines.push(dictToStr(item, indent + step, step));
      } else {
        lines.push(`${pad}- ${item}`);
      }
    }
  } else {
    lines.push(pad + String(data));
  }

  return lines.join("\n");
}
