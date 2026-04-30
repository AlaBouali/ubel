#!/usr/bin/env node

import { main } from "../src/main.js";

async function run() {
  const [, , targetPath] = process.argv;

  try {
    const result = await main({
      projectRoot : targetPath || process.cwd(),
      engine      : "npm",
      mode        : "health",
      is_script   : true,
      save_reports: true,
      full_stack  : true,
      scan_os     : true,
      scan_node   : true,
      scan_scope  : "agent",
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