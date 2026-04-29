#!/usr/bin/env node

import { scan_project } from "../src/main.js";

async function run() {
  const [, , targetPath] = process.argv;

  try {
    const result = await scan_project(targetPath || process.cwd(), {
      is_script: true,
      save_reports: true,
      scan_node: true,

      // critical flags
      full_stack: true,
      scan_os: true,

    });

    console.log(JSON.stringify(result, null, 2));
    process.exit(0);

  } catch (err) {
    console.error("[!] Agent scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

run();