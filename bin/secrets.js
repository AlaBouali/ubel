#!/usr/bin/env node
import { runProjectCommand } from "../sca/project_cli.js";
// project-id / set-project-id / version are commands of every ubel CLI; handle them before any scan setup.
const projectCmd = runProjectCommand(process.argv.slice(2), { cli: "ubel-secrets" });
if (projectCmd !== null) process.exit(projectCmd);

import { SCA_scan } from "../sca/main.js";
import { handleSecretsCli } from "../sca/secrets_cli.js";

async function run() {
  const args = process.argv.slice(2);

  // --history / --write-baseline (and their options) are handled by
  // secrets_cli.js: it prints its own results and sets process.exitCode
  // (0 clean, 1 findings, 2 error). Anything else falls through to the
  // full secrets-only scan below, unchanged.
  if (await handleSecretsCli(args)) {
    process.exit(process.exitCode ?? 0);
  }

  // First non-flag argument is the target path (so `ubel-secrets --foo /repo` works).
  const targetPath = args.find(a => !a.startsWith("-"));

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