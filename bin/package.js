#!/usr/bin/env node
'use strict';
import { runAssetCommand } from "../sca/asset_cli.js";
// asset-id / set-asset-id / version are commands of every ubel CLI, and --asset-id <id> is a flag of every one;
// handle them before any scan setup.
const assetCmd = runAssetCommand(process.argv.slice(2), { cli: "ubel-package" });
if (assetCmd !== null) process.exit(assetCmd);
import('../package/index.js').then(({ main }) => main()).catch((err) => {
  console.error('Fatal error:', err.stack || err.message);
  process.exitCode = 1;
});
