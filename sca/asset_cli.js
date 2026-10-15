// ─────────────────────────────────────────────────────────────────────────────
// Asset-identity / version commands and the run-time --asset-id flag, available
// under EVERY ubel CLI:
//
//   ubel-<cli> asset-id [folder] [--json] [--machine]
//   ubel-<cli> set-asset-id <asset-id> [folder] [--name <name>] [--machine]
//   ubel-<cli> get-machine-id [--json]
//   ubel-<cli> set-machine-id <asset-id> [--name <name>]
//   ubel-<cli> get-asset-id [folder] [--json]
//   ubel-<cli> version [--json]
//   ubel-<cli> <anything> --asset-id <asset-id>     (this run only, see below)
//
// (ubel-npm, ubel-pip, ubel-sast, ubel-cloud, ubel-url, ubel-apt, … — every file
// in bin/ calls runAssetCommand() first, before any scan setup, so these
// words never reach a scanner's own argument parsing.)
//
// An asset id is a UUID v4 without hyphens (32 hex characters).
//
// get-machine-id / set-machine-id are asset-id / set-asset-id pinned to the machine
// id file ($HOME/.ubel/ubel_machine.json — { machine_id, created_at }); they
// take no folder and no --machine. That id is also written into every report (machine_id), whatever the report is about.
// get-asset-id is asset-id pinned to a folder (default: current directory); it
// rejects --machine, and on the apt/dnf/yum CLIs (no asset folder) it is a usage error.
//
// --asset-id <asset-id> (or --asset-id=<asset-id>) may appear anywhere on the
// command line of any CLI. runAssetCommand() removes it from process.argv, so
// the scanners' own parsers never see it, and records it for the run: the
// report, SBOM, SARIF and history zip then carry that id instead of the one in
// ubel_asset.json, which is not created or changed. Use set-asset-id to make a
// folder's id permanent.
//
// Every CLI creates its asset id if it doesn't exist, when it starts (for the SCA CLIs
// that is engine.provisionAsset(), for sast/cloud/EASM report_naming.provisionAssetAt()),
// so `asset-id` below creates one too instead of reporting "none yet". `init` creates it
// explicitly and prints it. --asset-id and set-asset-id are the ways to NOT use a fresh id.
//
// runAssetCommand() returns an exit code (0 ok, 2 usage / error) when args[0] is one of the commands, or null when it isn't — the bin
// wrapper then carries on with its normal scan. Same shape as secrets_cli.js.
//
// The apt/dnf/yum CLIs have no asset folder: their id is the machine id in
// $HOME/.ubel/ubel_machine.json, so they pass { machine: true } and the
// commands act on that file without needing --machine.
// ─────────────────────────────────────────────────────────────────────────────

import fs from "fs";
import path from "path";
import {
  ASSET_FILE_NAME, MACHINE_FILE_NAME, MACHINE_IDENTITY, ASSET_ID_EXAMPLE, machineUbelDir, readAsset, ensureAsset, setAssetId,
  historyForAsset, isValidAssetId, setRuntimeAssetId,
} from "./report_naming.js";
import { TOOL_NAME, TOOL_VERSION } from "./info.js";

/** The words that are commands rather than scan arguments. */
export const ASSET_COMMAND_NAMES = [
  "asset-id", "set-asset-id", "version",
  "get-machine-id", "set-machine-id", "get-asset-id",
];

function setHelp(cli, cmd, machineOnly, getCmd) {
  return `Usage: ${cli} ${cmd} <asset-id> ${machineOnly ? "" : "[folder] "}[options]

Connect ${machineOnly ? "this machine" : "a folder"} to an existing UBEL ${machineOnly ? "machine" : "asset"} id, so its scans are filed with the
${machineOnly ? "machine" : "asset"}'s earlier history ($HOME/.ubel/history/<asset-id>/) instead of
starting a new ${machineOnly ? "machine id" : "asset"}. Writes ${machineOnly ? "$HOME/.ubel/ubel_machine.json" : "<folder>/.ubel/ubel_asset.json"}.

Arguments:
  <asset-id>   the id to link to, 32 hex characters (see \`${cli} ${getCmd}\` in the original ${machineOnly ? "setup" : "folder"})
${machineOnly ? "" : "  [folder]       asset folder (default: current directory)\n"}
Options:
  --name <name>  also set the readable asset name (default: keep the current one)
${machineOnly ? "" : `  --machine      set the machine id ($HOME/.ubel/ubel_machine.json) used by
                 ubel-apt / ubel-dnf / ubel-yum instead of a folder
`}  -h, --help     show this help

Only the id (and, with --name, the name) is changed; created_at and any other
fields in the file are kept. Nothing else on disk is moved or rewritten.`;
}

function showHelp(cli, cmd, machineOnly, allowMachineFlag) {
  return `Usage: ${cli} ${cmd} ${machineOnly ? "" : "[folder] "}[options]

Print the ${machineOnly ? "machine" : "asset"} id stored in ${machineOnly ? "$HOME/.ubel/ubel_machine.json" : "<folder>/.ubel/ubel_asset.json"}, creating it first
if ${machineOnly ? "this machine" : "the folder"} has none yet (every ${cli.replace(/-.*/, "")}-* CLI does the same when it starts, and \`${cli} init\` does it explicitly).
${machineOnly ? "" : `
Arguments:
  [folder]       asset folder (default: current directory)
`}
Options:
  --json         print { ${machineOnly ? "machine_id" : "asset_id, asset_name"}, created_at, file, created } as JSON
                 (created: true when this call minted the id)
${machineOnly || !allowMachineFlag ? "" : `  --machine      show the machine id ($HOME/.ubel/ubel_machine.json) used by
                 ubel-apt / ubel-dnf / ubel-yum
`}  -h, --help     show this help

Exit codes: 0 ok (the id existed or was just created), 2 error (bad arguments,
or the file could not be written).`;
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
function resolveUbelDir(cli, cmd, folderArg, machine, machineOnly) {
  if (machine) {
    if (folderArg) {
      return { error: machineOnly
        ? `${cli} ${cmd} acts on the machine id in ${path.join(machineUbelDir(), MACHINE_FILE_NAME)}, so no folder argument is accepted`
        : "--machine and a folder are mutually exclusive" };
    }
    return { ubelDir: machineUbelDir(), label: "this machine", spec: MACHINE_IDENTITY };
  }
  const folder = path.resolve(folderArg || process.cwd());
  let st;
  try { st = fs.statSync(folder); } catch { return { error: `folder not found: ${folder}` }; }
  if (!st.isDirectory()) return { error: `not a folder: ${folder}` };
  return { ubelDir: path.join(folder, ".ubel"), label: folder, spec: undefined };
}

/**
 * @typedef {object} CliContext
 * @property {string}  [cli="ubel"]    command name shown in help/messages, e.g. "ubel-npm"
 * @property {boolean} [machine=false] true for ubel-apt / ubel-dnf / ubel-yum: act on the machine id
 *
 * Internal, set by the command table (not by bin wrappers):
 * @property {string}  [cmd]           command word shown in help/messages (default: asset-id / set-asset-id)
 * @property {boolean} [forceMachine]  act on the machine id regardless of --machine (get/set-machine-id)
 * @property {boolean} [forbidMachine] reject --machine (get-asset-id)
 */

export function setAssetIdCli(args, ctx = {}) {
  const { cli = "ubel", cmd = "set-asset-id" } = ctx;
  const machineOnly = !!(ctx.machine || ctx.forceMachine);
  const getCmd = machineOnly ? "get-machine-id" : "asset-id";
  const help = setHelp(cli, cmd, machineOnly, getCmd);
  const { flags, positionals, error } = parseArgs(args, { bools: machineOnly ? [] : ["machine"], values: ["name"] });
  if (error) { console.error(`[!] ${error}\n\n${help}`); return 2; }
  if (flags.help) { console.log(help); return 0; }

  const [assetId, folderArg, ...extra] = positionals;
  if (!assetId) { console.error(`[!] missing <asset-id>\n\n${help}`); return 2; }
  if (extra.length) { console.error(`[!] unexpected argument: ${extra[0]}\n\n${help}`); return 2; }
  if (!isValidAssetId(assetId)) {
    console.error(`[!] not a valid asset id (expected 32 hex characters, like ${ASSET_ID_EXAMPLE}): ${assetId}`);
    return 2;
  }

  const target = resolveUbelDir(cli, cmd, folderArg, machineOnly || flags.machine, machineOnly);
  if (target.error) { console.error(`[!] ${target.error}`); return 2; }

  let result;
  try {
    result = setAssetId(target.ubelDir, assetId, { name: flags.name }, target.spec);
  } catch (e) {
    console.error(`[!] could not write ${path.join(target.ubelDir, target.spec ? target.spec.file : ASSET_FILE_NAME)}: ${e.message}`);
    return 2;
  }

  const file = path.join(target.ubelDir, target.spec ? target.spec.file : ASSET_FILE_NAME);
  const what = target.spec ? "Machine" : "Asset";
  if (result.changed) {
    console.log(`${what} id set: ${result.asset_id}${target.spec ? "" : `  (${result.asset_name})`}`);
    if (result.previous_id) console.log(`  previous id:  ${result.previous_id}`);
  } else {
    console.log(`${what} id already ${result.asset_id}${target.spec ? "" : `  (${result.asset_name})`} — nothing to change`);
  }
  console.log(`  file:         ${file}`);

  const history = historyForAsset(result.asset_id);
  if (history.length) {
    console.log(`  history here: ${history.map((h) => `${h.mode} (${h.zips})`).join(", ")}`);
  } else {
    console.error(`[!] no history for this id under ${path.join(machineUbelDir(), "history")} on this machine — `
      + `fine if the old zips live elsewhere, but check the id if you expected them here.`);
  }
  return 0;
}

export function showAssetIdCli(args, ctx = {}) {
  const { cli = "ubel", cmd = "asset-id" } = ctx;
  const machineOnly = !!(ctx.machine || ctx.forceMachine);
  const allowMachineFlag = !ctx.forbidMachine;
  const help = showHelp(cli, cmd, machineOnly, allowMachineFlag);
  const { flags, positionals, error } = parseArgs(args, {
    bools: machineOnly || !allowMachineFlag ? ["json"] : ["json", "machine"],
  });
  if (error) { console.error(`[!] ${error}\n\n${help}`); return 2; }
  if (flags.help) { console.log(help); return 0; }
  if (positionals.length > 1) { console.error(`[!] unexpected argument: ${positionals[1]}\n\n${help}`); return 2; }

  const target = resolveUbelDir(cli, cmd, positionals[0], machineOnly || flags.machine, machineOnly);
  if (target.error) { console.error(`[!] ${target.error}`); return 2; }

  const file = path.join(target.ubelDir, target.spec ? target.spec.file : ASSET_FILE_NAME);
  const isMachine = !!target.spec;
  let asset = readAsset(target.ubelDir, target.spec);
  const created = !asset;
  if (created) {
    // Create-if-missing, like every UBEL CLI does when it starts. A folder that doesn't exist was
    // already rejected by resolveUbelDir, so this never invents a folder.
    ensureAsset(target.ubelDir, target.spec);
    asset = readAsset(target.ubelDir, target.spec);
    if (!asset) {
      console.error(`[!] no ${isMachine ? "machine" : "asset"} id for ${target.label} and ${file} could not be written. `
        + `Link it to an existing id with: ${cli} ${machineOnly ? "set-machine-id" : "set-asset-id"} <asset-id>`);
      return 2;
    }
    console.error(`[+] New ${isMachine ? "machine" : "asset"} id created: ${asset.asset_id}${isMachine ? "" : `  (${asset.asset_name})`}  → ${file}`);
  }

  if (flags.json) {
    console.log(JSON.stringify({
      ...(isMachine
        ? { machine_id: asset.asset_id }
        : { asset_id: asset.asset_id, asset_name: asset.asset_name ?? null }),
      created_at: asset.created_at ?? null,
      file,
      created,
    }, null, 2));
  } else {
    console.log(asset.asset_id);
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
  "asset-id":       showAssetIdCli,
  "set-asset-id":   setAssetIdCli,
  "version":        versionCli,
  "get-machine-id": (args, ctx) => showAssetIdCli(args, { ...ctx, cmd: "get-machine-id", forceMachine: true }),
  "set-machine-id": (args, ctx) => setAssetIdCli(args, { ...ctx, cmd: "set-machine-id", forceMachine: true }),
  "get-asset-id": (args, ctx) => {
    const cli = ctx.cli || "ubel";
    if (ctx.machine) {
      console.error(`[!] ${cli} has no asset folder — use ${cli} get-machine-id for its machine id`);
      return 2;
    }
    return showAssetIdCli(args, { ...ctx, cmd: "get-asset-id", forbidMachine: true });
  },
};

/**
 * Pull `--asset-id <id>` / `--asset-id=<id>` out of an argument list, wherever it
 * appears. Last occurrence wins. Returns { args, assetId } (assetId null when the
 * flag is absent) or { error }.
 */
export function extractAssetIdFlag(args) {
  const rest = [];
  let assetId = null;
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    let value;
    if (a === "--asset-id") {
      value = args[++i];
      if (value === undefined || value.startsWith("--")) return { error: "--asset-id needs a value" };
    } else if (a.startsWith("--asset-id=")) {
      value = a.slice("--asset-id=".length);
    } else {
      rest.push(a);
      continue;
    }
    if (!isValidAssetId(value)) {
      return { error: `not a valid asset id (expected 32 hex characters, like ${ASSET_ID_EXAMPLE}): ${value}` };
    }
    assetId = value.trim().toLowerCase();
  }
  return { args: rest, assetId };
}

/**
 * Entry point every bin/*.js calls first with its argv slice (process.argv.slice(2)).
 *
 * 1. Handles the run-time `--asset-id <id>` flag: removes it from process.argv
 *    (so no scanner's own parser ever sees it) and records the id for this run.
 *    An invalid or valueless flag is a usage error (returns 2).
 * 2. If the first remaining argument is one of the asset commands, runs it and
 *    returns its exit code; otherwise returns null and the caller proceeds with
 *    its normal scan.
 *
 * Only args[0] is looked at for commands, so a scan can still target a folder that
 * happens to be called "version" (write it as ./version).
 *
 * @param {string[]} args  process.argv.slice(2)
 * @param {CliContext} [ctx]
 * @returns {number|null}
 */
export function runAssetCommand(args, ctx = {}) {
  const cli = ctx.cli || "ubel";
  // --redact-paths: boolean flag, any position. Removed from argv like --asset-id and
  // carried to the report writers as UBEL_REDACT_PATHS=1 (see redact.js).
  if (args.includes("--redact-paths")) {
    process.env.UBEL_REDACT_PATHS = "1";
    args = args.filter(a => a !== "--redact-paths");
    process.argv.splice(2, process.argv.length - 2, ...args);
  }
  const extracted = extractAssetIdFlag(args);
  if (extracted.error) { console.error(`[!] ${extracted.error}\n    usage: ${cli} <args> --asset-id <asset-id>`); return 2; }
  if (extracted.assetId) {
    setRuntimeAssetId(extracted.assetId);
    process.argv.splice(2, process.argv.length - 2, ...extracted.args);
  }
  const rest = extracted.args;
  const handler = Object.hasOwn(HANDLERS, rest[0]) ? HANDLERS[rest[0]] : null;
  return handler ? handler(rest.slice(1), ctx) : null;
}