/**
 * secrets_cli.js — extra `ubel-secrets` flags: git history, pre-commit, baselining.
 *
 *   ubel-secrets [path] --history [--rev=<range>] [--since=<date>] [--max-commits=<n>]
 *   ubel-secrets [path] --staged                 scan what is staged for commit
 *   ubel-secrets [path] --install-hook [--force] install the git pre-commit hook (the one ubel hook:
 *                                                secrets scan on every commit, plus the dependency
 *                                                scan if `ubel-<engine> install-hook` added it)
 *   ubel-secrets [path] --uninstall-hook         remove that hook again
 *   ubel-secrets [path] --write-baseline         accept current findings (also works with --staged/--history)
 *
 * Shared options: --include-dir=<name>  --exclude-dir=<name>  --unallow=<id>
 *                 --ignore-file=<path>  --include-env  --json
 *
 * This module never touches .gitignore / .dockerignore: keeping `.ubel/` and
 * `.ubelignore` out of git and docker contexts is done once, up front, by the
 * entry point (main.js: ensureUbelIgnoreFilesForSecrets) before this runs.
 *
 * handleSecretsCli(argv) returns true if it handled the invocation (and set
 * process.exitCode), false if argv has none of the flags above — the caller
 * then falls through to its existing behavior. Exit codes: 0 clean, 1 findings,
 * 2 error.
 */

import fs from "node:fs";
import path from "node:path";
import { scanSecrets } from "./secrets.js";
import { scanStaged } from "./secrets_git.js";
import { installHook, uninstallHook } from "./secrets_hook.js";

// A scan that could not cover everything it was given (e.g. a file larger than
// the per-file cap) is reported as a warning; with UBEL_HOOK_STRICT=1 it fails
// the scan (exit 2) instead, so the commit is blocked.
const strictMode = () => process.env.UBEL_HOOK_STRICT === "1";

// The shared options are listed too: on their own they used to fall through to
// the full pipeline scan, which ignores them — so `--include-dir=packages`
// silently did nothing.
const HANDLED_FLAGS = [
  "--history", "--write-baseline", "--staged", "--install-hook", "--uninstall-hook",
  "--include-dir", "--exclude-dir", "--unallow", "--ignore-file", "--include-env",
];

function parseArgs(argv) {
  const opts = {
    path: null, history: false, writeBaseline: false, json: false, includeEnv: false,
    staged: false, installHook: false, uninstallHook: false, force: false,
    rev: [], since: undefined, maxCommits: undefined,
    includeDirs: [], ignoreDirs: [], unallow: [], ignoreFile: undefined,
  };
  for (const arg of argv) {
    const [flag, ...rest] = arg.split("=");
    const value = rest.join("=");
    switch (flag) {
      case "--history": opts.history = true; break;
      case "--write-baseline": opts.writeBaseline = true; break;
      case "--staged": opts.staged = true; break;
      case "--install-hook": opts.installHook = true; break;
      case "--uninstall-hook": opts.uninstallHook = true; break;
      case "--force": opts.force = true; break;
      case "--json": opts.json = true; break;
      case "--include-env": opts.includeEnv = true; break;
      case "--rev": opts.rev.push(value); break;
      case "--since": opts.since = value; break;
      case "--max-commits": opts.maxCommits = Number(value); break;
      case "--include-dir": opts.includeDirs.push(value); break;
      case "--exclude-dir": opts.ignoreDirs.push(value); break;
      case "--unallow": opts.unallow.push(value); break;
      case "--ignore-file": opts.ignoreFile = value; break;
      default:
        if (arg.startsWith("-")) throw new Error(`Unknown option: ${arg}`);
        if (opts.path) throw new Error(`Unexpected argument: ${arg}`);
        opts.path = arg;
    }
  }
  if (opts.staged && opts.history) throw new Error("--staged and --history cannot be combined");
  if ((opts.installHook || opts.uninstallHook) &&
      (opts.staged || opts.history || opts.writeBaseline)) {
    throw new Error("--install-hook / --uninstall-hook cannot be combined with a scan option");
  }
  if (opts.installHook && opts.uninstallHook) throw new Error("--install-hook and --uninstall-hook are mutually exclusive");
  if (opts.force && !opts.installHook) throw new Error("--force only applies to --install-hook");
  return opts;
}

function printFindings(findings, out) {
  const order = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 };
  const sorted = [...findings].sort((a, b) =>
    (order[a.severity] ?? 9) - (order[b.severity] ?? 9) ||
    a.file_path.localeCompare(b.file_path) || a.line - b.line);
  for (const f of sorted) {
    const where = `${f.file_path}:${f.line}:${f.column_start}`;
    const origin = f.commit ? `  [${f.commit.slice(0, 10)} ${f.commit_date?.slice(0, 10) ?? ""}${f.history_only ? ", history only" : ""}]` : "";
    out(`  ${f.severity.padEnd(8)} ${f.id.padEnd(28)} ${where}  ${f.match_preview}${origin}`);
  }
}

function appendBaseline(root, findings, ignoreFile) {
  const file = ignoreFile ? path.resolve(ignoreFile) : path.join(root, ".ubelignore");
  let existing = "";
  try { existing = fs.readFileSync(file, "utf8"); } catch { /* new file */ }
  const known = new Set([...existing.matchAll(/^fingerprint:([0-9a-f]+)/gim)].map(m => m[1].toLowerCase()));

  const lines = [];
  for (const f of findings) {
    if (known.has(f.fingerprint)) continue;
    known.add(f.fingerprint);
    lines.push(`fingerprint:${f.fingerprint}  # ${f.id} ${f.file_path}:${f.line}`);
  }
  if (!lines.length) return { file, added: 0 };

  const header = existing.includes("# baseline") ? "" :
    `${existing && !existing.endsWith("\n") ? "\n" : ""}# baseline — findings accepted on ${new Date().toISOString().slice(0, 10)}; review before committing\n`;
  fs.appendFileSync(file, header + lines.join("\n") + "\n");
  return { file, added: lines.length };
}

export async function handleSecretsCli(argv) {
  if (!argv.some(a => HANDLED_FLAGS.includes(a.split("=")[0]))) return false;

  try {
    const opts = parseArgs(argv);
    const root = path.resolve(opts.path || process.cwd());

    if (opts.installHook) {
      const r = await installHook(root, { force: opts.force });
      console.log(`${r.replaced ? "Updated" : "Installed"} pre-commit hook: ${r.hookFile}`);
      if (r.migrated) console.log("Merged an older ubel hook (pre-commit.local) into this one and removed it.");
      if (r.chained) console.log(`Your existing hook was moved to ${r.localFile}; it still runs after the ubel scans.`);
      if (r.portable) {
        console.log("This hooks directory is outside .git (core.hooksPath), so the hook finds `ubel-secrets` on PATH\n" +
                    "instead of embedding this machine's paths. Every contributor needs it installed.");
      }
      console.log("\nThe hook runs `ubel-secrets --staged` on every commit" +
                  (r.sca ? `, and \`${r.sca} health\` (dependency scan) when a manifest or lockfile is staged.`
                         : ".\nAdd the dependency scan to the same hook with `ubel-<engine> install-hook` (e.g. ubel-npm)."));
      console.log("Skip once with `git commit --no-verify`; hooks are local, so also run --history in CI.");
      process.exitCode = 0;
      return true;
    }
    if (opts.uninstallHook) {
      const r = await uninstallHook(root);
      console.log(r.removed
        ? `Removed ${r.hookFile}${r.restored ? " and restored your previous hook." : "."}`
        : `No pre-commit hook at ${r.hookFile}; nothing to remove.`);
      process.exitCode = 0;
      return true;
    }

    // Keep stdout clean for --json: scanSecrets logs a progress line via console.log.
    const log = opts.json ? () => {} : console.log;
    const realLog = console.log;
    if (opts.json) console.log = () => {};

    let result;
    try {
      result = await (opts.staged ? scanStaged : scanSecrets)(root, {
        // A staged .env is about to be committed, so it is always scanned.
        includeEnvFiles: opts.includeEnv || opts.staged,
        includeHistory: opts.history,
        history: {
          rev: opts.rev.length ? opts.rev : undefined,
          since: opts.since,
          maxCommits: opts.maxCommits,
        },
        includeDirs: opts.includeDirs,
        ignoreDirs: opts.ignoreDirs,
        unallow: opts.unallow,
        ignoreFile: opts.ignoreFile,
      });
    } finally {
      console.log = realLog;
    }

    // Incomplete coverage is never silent. (--staged runs on every commit, so
    // clean output stays quiet, but a warning always prints.)
    const incomplete = Array.isArray(result.warnings) && result.warnings.length > 0 && result.incomplete === true;
    if (!opts.json) for (const w of result.warnings ?? []) if (!result.history) console.error(`[!] ${w}`);

    if (opts.writeBaseline) {
      const { file, added } = appendBaseline(root, result.findings, opts.ignoreFile);
      log(`Baselined ${added} finding(s) into ${file}. Review the diff before committing it.`);
      return true; // accepting the current state is a success, exit 0
    }

    if (opts.json) {
      process.stdout.write(JSON.stringify(result, null, 2) + "\n");
    } else {
      const h = result.history;
      if (h) {
        log(`Scanned ${h.commits_scanned} commit(s).`);
        for (const w of h.warnings ?? []) console.error(`[!] ${w}`);
      }
      if (result.count === 0) {
        // Silent on a clean staged scan: it runs on every commit.
        if (!opts.staged) log(`No secrets found${result.suppressed ? ` (${result.suppressed} suppressed)` : ""}.`);
      } else {
        log(`${result.count} potential secret(s)${opts.staged ? " in staged changes" : ""}${result.suppressed ? ` (${result.suppressed} suppressed)` : ""}:`);
        printFindings(result.findings, log);
        log("\nTo suppress a false positive: add `ubel:ignore` on the line, or a\n" +
            "`fingerprint:<hex>` / glob entry to .ubelignore (or run --write-baseline).");
        if (result.findings.some(f => f.commit)) {
          log("Secrets found in git history are compromised even if deleted: rotate them.");
        }
      }
    }
    if (result.count > 0) process.exitCode = 1;
    else if (incomplete && strictMode()) {
      console.error("[!] ubel-secrets: scan was incomplete and UBEL_HOOK_STRICT=1 is set; treating as a failed scan.");
      process.exitCode = 2;
    } else process.exitCode = 0;
  } catch (err) {
    console.error(`[!] ubel-secrets: ${err.message}`);
    if (process.env.DEBUG) console.error(err.stack);
    process.exitCode = 2;
  }
  return true;
}

export default handleSecretsCli;