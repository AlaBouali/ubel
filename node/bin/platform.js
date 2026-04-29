#!/usr/bin/env node

import { scan_project } from "../src/main.js";
import { homedir } from 'os';

async function run() {
  const [, , targetPath] = process.argv;
  try {
    const result = await scan_project(targetPath || process.homedir, {
      is_script: true,
      save_reports: true,
      scan_node: false,

      // critical flags
      full_stack: false,
      scan_os: true,

    });

    console.log(JSON.stringify(result, null, 2));
    process.exit(0);

  } catch (err) {
    console.error("[!] Platform scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

(async () => { run(); })();