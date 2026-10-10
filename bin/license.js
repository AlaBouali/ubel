#!/usr/bin/env node
import { runAssetCommand } from "../sca/asset_cli.js";
// asset-id / set-asset-id / version are commands of every ubel CLI, and --asset-id <id> is a flag of every one;
// handle them before any scan setup.
const assetCmd = runAssetCommand(process.argv.slice(2), { cli: "ubel-license" });
if (assetCmd !== null) process.exit(assetCmd);

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
      full_stack  : true,
      scan_os     : false,
      scan_node   : true,
      scan_vulns  : false,
      scan_secrets: false,
      scan_scope  : "license",
    });

    console.log(JSON.stringify(result, null, 2));

    if (result && result.decision && result.decision.allowed === false) {
      console.error("[!] License scan blocked by policy:", result.decision.reason);
      process.exit(1);
    }

    process.exit(0);

  } catch (err) {
    console.error("[!] License scan failed:", err.message);
    if (process.env.DEBUG) console.error(err.stack);
    process.exit(1);
  }
}

run();