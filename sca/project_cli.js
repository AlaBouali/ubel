// ─────────────────────────────────────────────────────────────────────────────
// Project-identity / version commands, available under EVERY ubel CLI:
//
//   ubel-<cli> project-id [folder] [--json] [--machine]
//   ubel-<cli> set-project-id <project-id> [folder] [--name <name>] [--machine]
//   ubel-<cli> version [--json]
//
// (ubel-npm, ubel-pip, ubel-sast, ubel-cloud, ubel-url, ubel-apt, … — every file
// in bin/ calls runProjectCommand() first, before any scan setup, so these
// words never reach a scanner's own argument parsing.)
//
// runProjectCommand() returns an exit code (0 ok, 1 "nothing found", 2 usage /
// error) when args[0] is one of the commands, or null when it isn't — the bin
// wrapper then carries on with its normal scan. Same shape as secrets_cli.js.
//
// The apt/dnf/yum CLIs have no project folder: their id is the machine tag in
// $HOME/.ubel/ubel_project.json, so they pass { machine: true } and the
// commands act on that file without needing --machine.
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import {
  PROJECT_FILE_NAME, machineUbelDir, readProject, setProjectId, historyForProject, isValidProjectId,
} from "./report_naming.js";
import { TOOL_NAME, TOOL_VERSION } from "./info.js";

/** The words that are commands rather than scan arguments. */
export const PROJECT_COMMAND_NAMES = ["project-id", "set-project-id", "version"];

function setHelp(cli, machineOnly) {
  return `Usage: ${cli} set-project-id <project-id> ${machineOnly ? "" : "[folder] "}[options]

Connect ${machineOnly ? "this machine" : "a folder"} to an existing UBEL project id, so its scans are filed with the
project's earlier history ($HOME/.ubel/history/<mode>/<project-id>/) instead of
starting a new project. Writes ${machineOnly ? "$HOME/.ubel/ubel_project.json" : "<folder>/.ubel/ubel_project.json"}.

Arguments:
  <project-id>   the UUID to link to (see \`${cli} project-id\` in the original ${machineOnly ? "setup" : "folder"})
${machineOnly ? "" : "  [folder]       project folder (default: current directory)\n"}
Options:
  --name <name>  also set the readable project name (default: keep the current one)
${machineOnly ? "" : `  --machine      set the machine tag ($HOME/.ubel/ubel_project.json) used by
                 ubel-apt / ubel-dnf / ubel-yum instead of a folder
`}  -h, --help     show this help

Only the id (and, with --name, the name) is changed; created_at and any other
fields in the file are kept. Nothing else on disk is moved or rewritten.`;
}

function showHelp(cli, machineOnly) {
  return `Usage: ${cli} project-id ${machineOnly ? "" : "[folder] "}[options]

Print the project id stored in ${machineOnly ? "$HOME/.ubel/ubel_project.json" : "<folder>/.ubel/ubel_project.json"}. Read-only: it
never creates an id (the first scan ${machineOnly ? "on this machine" : "in a folder"} does that).
${machineOnly ? "" : `
Arguments:
  [folder]       project folder (default: current directory)
`}
Options:
  --json         print { project_id, project_name, created_at, file } as JSON
${machineOnly ? "" : `  --machine      show the machine tag ($HOME/.ubel/ubel_project.json) used by
                 ubel-apt / ubel-dnf / ubel-yum
`}  -h, --help     show this help

Exit codes: 0 found, 1 no project id there yet, 2 error.`;
}

function versionHelp(cli) {
  return `Usage: ${cli} version [--json]

Print the installed UBEL version.

  --json       print { name, version, node, platform } as JSON
  -h, --help   show this help`;
}

/**
 * Minimal flag parser: booleans in `bools`, value flags in `values`
 * (`--name x` or `--name=x`). Returns { flags, positionals } or { error }.
 */
function parseArgs(args, { bools = [], values = [] }) {
  const flags = {};
  const positionals = [];
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === "-h" || a === "--help") { flags.help = true; continue; }
    if (a.startsWith("--")) {
      const [key, inline] = a.slice(2).split(/=(.*)/s, 2);
      if (bools.includes(key)) { flags[key] = true; continue; }
      if (values.includes(key)) {
        const v = inline !== undefined ? inline : args[++i];
        if (v === undefined || (inline === undefined && v.startsWith("--"))) return { error: `--${key} needs a value` };
        flags[key] = v;
        continue;
      }
      return { error: `unknown option: ${a}` };
    }
    if (a.startsWith("-") && a.length > 1) return { error: `unknown option: ${a}` };
    positionals.push(a);
  }
  return { flags, positionals };
}

/** Resolve the .ubel folder a command acts on, or return { error }. */
function resolveUbelDir(cli, folderArg, machine, machineOnly) {
  if (machine) {
    if (folderArg) {
      return { error: machineOnly
        ? `${cli} has no project folder — its id is the machine tag in ${path.join(machineUbelDir(), PROJECT_FILE_NAME)}, so no folder argument is accepted`
        : "--machine and a folder are mutually exclusive" };
    }
    return { ubelDir: machineUbelDir(), label: "this machine" };
  }
  const folder = path.resolve(folderArg || process.cwd());
  let st;
  try { st = fs.statSync(folder); } catch { return { error: `folder not found: ${folder}` }; }
  if (!st.isDirectory()) return { error: `not a folder: ${folder}` };
  return { ubelDir: path.join(folder, ".ubel"), label: folder };
}

/**
 * @typedef {object} CliContext
 * @property {string}  [cli="ubel"]    command name shown in help/messages, e.g. "ubel-npm"
 * @property {boolean} [machine=false] true for ubel-apt / ubel-dnf / ubel-yum: act on the machine tag
 */

export function setProjectIdCli(args, { cli = "ubel", machine: machineOnly = false } = {}) {
  const help = setHelp(cli, machineOnly);
  const { flags, positionals, error } = parseArgs(args, { bools: ["machine"], values: ["name"] });
  if (error) { console.error(`[!] ${error}\n\n${help}`); return 2; }
  if (flags.help) { console.log(help); return 0; }

  const [projectId, folderArg, ...extra] = positionals;
  if (!projectId) { console.error(`[!] missing <project-id>\n\n${help}`); return 2; }
  if (extra.length) { console.error(`[!] unexpected argument: ${extra[0]}\n\n${help}`); return 2; }
  if (!isValidProjectId(projectId)) {
    console.error(`[!] not a valid project id (expected a UUID like 3f6c2a9e-1b7d-4c58-9a42-6e0d8b5f7a13): ${projectId}`);
    return 2;
  }

  const target = resolveUbelDir(cli, folderArg, machineOnly || flags.machine, machineOnly);
  if (target.error) { console.error(`[!] ${target.error}`); return 2; }

  let result;
  try {
    result = setProjectId(target.ubelDir, projectId, { name: flags.name });
  } catch (e) {
    console.error(`[!] could not write ${path.join(target.ubelDir, PROJECT_FILE_NAME)}: ${e.message}`);
    return 2;
  }

  const file = path.join(target.ubelDir, PROJECT_FILE_NAME);
  if (result.changed) {
    console.log(`Project id set: ${result.project_id}  (${result.project_name})`);
    if (result.previous_id) console.log(`  previous id:  ${result.previous_id}`);
  } else {
    console.log(`Project id already ${result.project_id}  (${result.project_name}) — nothing to change`);
  }
  console.log(`  file:         ${file}`);

  const history = historyForProject(result.project_id);
  if (history.length) {
    console.log(`  history here: ${history.map((h) => `${h.mode} (${h.zips})`).join(", ")}`);
  } else {
    console.error(`[!] no history for this id under ${path.join(machineUbelDir(), "history")} on this machine — `
      + `fine if the old zips live elsewhere, but check the id if you expected them here.`);
  }
  return 0;
}

export function showProjectIdCli(args, { cli = "ubel", machine: machineOnly = false } = {}) {
  const help = showHelp(cli, machineOnly);
  const { flags, positionals, error } = parseArgs(args, { bools: ["json", "machine"] });
  if (error) { console.error(`[!] ${error}\n\n${help}`); return 2; }
  if (flags.help) { console.log(help); return 0; }
  if (positionals.length > 1) { console.error(`[!] unexpected argument: ${positionals[1]}\n\n${help}`); return 2; }

  const target = resolveUbelDir(cli, positionals[0], machineOnly || flags.machine, machineOnly);
  if (target.error) { console.error(`[!] ${target.error}`); return 2; }

  const file = path.join(target.ubelDir, PROJECT_FILE_NAME);
  const project = readProject(target.ubelDir);
  if (!project) {
    console.error(`[!] no project id for ${target.label} yet (${file} is missing or invalid). `
      + `The first UBEL scan there creates one, or link it to an existing id with: ${cli} set-project-id <project-id>`);
    return 1;
  }

  if (flags.json) {
    console.log(JSON.stringify({
      project_id:   project.project_id,
      project_name: project.project_name ?? null,
      created_at:   project.created_at ?? null,
      file,
    }, null, 2));
  } else {
    console.log(project.project_id);
  }
  return 0;
}

export function versionCli(args, { cli = "ubel" } = {}) {
  const help = versionHelp(cli);
  const { flags, positionals, error } = parseArgs(args, { bools: ["json"] });
  if (error) { console.error(`[!] ${error}\n\n${help}`); return 2; }
  if (flags.help) { console.log(help); return 0; }
  if (positionals.length) { console.error(`[!] unexpected argument: ${positionals[0]}\n\n${help}`); return 2; }

  if (flags.json) {
    console.log(JSON.stringify({
      name: TOOL_NAME, version: TOOL_VERSION, node: process.version.replace(/^v/, ""), platform: `${process.platform}-${process.arch}`,
    }, null, 2));
  } else {
    console.log(TOOL_VERSION);
  }
  return 0;
}

const HANDLERS = {
  "project-id":     showProjectIdCli,
  "set-project-id": setProjectIdCli,
  "version":        versionCli,
};

/**
 * Entry point every bin/*.js calls first with its argv slice (process.argv.slice(2)).
 * If the first argument is one of the project commands, runs it and returns its
 * exit code; otherwise returns null and the caller proceeds with its normal scan.
 *
 * Only args[0] is looked at, so a scan can still target a folder that happens to
 * be called "version" (write it as ./version).
 *
 * @param {string[]} args
 * @param {CliContext} [ctx]
 * @returns {number|null}
 */
export function runProjectCommand(args, ctx = {}) {
  const handler = Object.hasOwn(HANDLERS, args[0]) ? HANDLERS[args[0]] : null;
  return handler ? handler(args.slice(1), ctx) : null;
}
