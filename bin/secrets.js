#!/usr/bin/env node

import { SCA_scan } from "../sca/main.js";

async function run() {
  const [, , targetPath] = process.argv;

  try {
    const result = await SCA_scan({
      projectRoot : targetPath || process.cwd(),
      engine      : "npm",
      mode        : "health",
      is_script   : true,
      save_reports: true,
      full_stack  : false,
      scan_os     : false,
      scan_node   : false,
      scan_secrets: true,
      scan_scope  : "secrets",
    });

    console.log(JSON.stringify(result, null, 2));

    if (result && result.decision && result.decision.allowed === false) {
      console.error("[!] Secrets scan blocked by policy:", result.decision.reason);
      process.exit(1);
    }

    process.exit(0);

  } catch (err) {
    console.error("[!] Secrets scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

run();