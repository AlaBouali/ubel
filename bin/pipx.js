#!/usr/bin/env node
import { runProjectCommand } from "../sca/project_cli.js";
// project-id / set-project-id / version are commands of every ubel CLI; handle them before any scan setup.
const projectCmd = runProjectCommand(process.argv.slice(2), { cli: "ubel-pipx" });
if (projectCmd !== null) process.exit(projectCmd);
process.argv.splice(2, 0, "pipx");
import("../sca/main.js").then(({ SCA_scan }) => SCA_scan());