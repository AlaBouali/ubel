#!/usr/bin/env node
'use strict';
import { runProjectCommand } from "../sca/project_cli.js";
// project-id / set-project-id / version are commands of every ubel CLI; handle them before any scan setup.
const projectCmd = runProjectCommand(process.argv.slice(2), { cli: "ubel-easm" });
if (projectCmd !== null) process.exit(projectCmd);
import('../easm/easm.js').then(({ main }) => main()).catch((err) => {
  console.error('Fatal error:', err.stack || err.message);
  process.exitCode = 1;
});