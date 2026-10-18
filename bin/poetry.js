#!/usr/bin/env node
import { runAssetCommand } from "../sca/asset_cli.js";
// asset-id / set-asset-id / version are commands of every ubel CLI, and --asset-id <id> is a flag of every one;
// handle them before any scan setup.
const assetCmd = runAssetCommand(process.argv.slice(2), { cli: "ubel-poetry" });
if (assetCmd !== null) process.exit(assetCmd);
process.argv.splice(2, 0, "poetry");
import("../sca/main.js").then(({ SCA_scan }) => SCA_scan());