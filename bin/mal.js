#!/usr/bin/env node
import { runProjectCommand } from "../sca/project_cli.js";
// project-id / set-project-id / version are commands of every ubel CLI; handle them before any scan setup.
const projectCmd = runProjectCommand(process.argv.slice(2), { cli: "ubel-mal" });
if (projectCmd !== null) process.exit(projectCmd);
const args = process.argv.slice(2);
if (!args.includes("--help") && !args.includes("-h")) {
  process.argv.splice(2, 0, "malware");
}
import("../sast/main.js").then(({ main }) => main());