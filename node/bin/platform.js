#!/usr/bin/env node

import { main }    from "../sca/main.js";
import { homedir } from "os";

async function run() {
  const [, , targetPath] = process.argv;

  try {
    const result = await main({
      projectRoot : targetPath || homedir(),
      engine      : "npm",
      mode        : "health",
      is_script   : true,
      save_reports: true,
      full_stack  : false,
      scan_os     : true,
      scan_node   : false,
      scan_scope  : "developer_platform",
    });

    console.log(JSON.stringify(result, null, 2));

    if (result && result.decision && result.decision.allowed === false) {
      console.error("[!] Platform scan blocked by policy:", result.decision.reason);
      process.exit(1);
    }

    process.exit(0);

  } catch (err) {
    console.error("[!] Platform scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

run();