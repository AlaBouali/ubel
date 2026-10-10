#!/usr/bin/env node
import { runAssetCommand } from "../sca/asset_cli.js";
// asset-id / set-asset-id / version are commands of every ubel CLI, and --asset-id <id> is a flag of every one;
// handle them before any scan setup.
const assetCmd = runAssetCommand(process.argv.slice(2), { cli: "ubel-sast" });
if (assetCmd !== null) process.exit(assetCmd);
const args = process.argv.slice(2);
if (!args.includes("--help") && !args.includes("-h")) {
  process.argv.splice(2, 0, "analyze");
}
import("../sast/main.js").then(({ main }) => main());