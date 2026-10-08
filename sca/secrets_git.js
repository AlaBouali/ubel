/**
 * secrets_git.js — scan git history for secrets.
 *
 * Original code (not ported from Trivy). Reuses scanText() from secrets.js, so
 * history scans apply exactly the same rules, allow-lists, entropy gates and
 * .ubelignore suppressions as a working-tree scan, and produce the same
 * finding shape (plus commit metadata).
 *
 * Two entry points share one diff parser:
 *   scanGitHistory()  every commit reachable from the given revisions
 *   scanStaged()      only what is in the index right now (the pre-commit hook)
 *
 * How it works: it streams `git log -p -U0` and scans only the ADDED lines of
 * each hunk — a secret that was committed and later deleted is still added in
 * some commit, so it is found; unchanged code is never rescanned. Contiguous added lines are scanned
 * together, so multi-line PEM blocks are caught.
 *
 * Only `git` is used (no libraries), via spawn()/execFile() with argument
 * arrays — never through a shell. Nothing is written to disk.
 *
 * Remediation note: a secret in history is compromised even if it is no longer
 * in the working tree. Rotate/revoke it; rewriting history alone is not enough.
 */

import { spawn, execFile } from "node:child_process";
import readline from "node:readline";
import path from "node:path";
import { scanText, classifyForScan, loadIgnoreConfig } from "./secrets.js";

const MAX_HUNK_BYTES = 5 * 1024 * 1024; // same cap as a whole file in a tree scan
const PEM_PRIVATE_HEADER = /-----BEGIN [A-Z0-9 ]*PRIVATE KEY/;

const GIT_ENV = { ...process.env, GIT_TERMINAL_PROMPT: "0", LC_ALL: "C" };

// ── git plumbing ────────────────────────────────────────────────────────────

export function git(args, cwd) {
  return new Promise((resolve, reject) => {
    execFile("git", args, { cwd, env: GIT_ENV, maxBuffer: 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        if (err.code === "ENOENT") return reject(new Error("git not found on PATH"));
        return reject(new Error((stderr || err.message).trim()));
      }
      resolve(stdout.trim());
    });
  });
}

export async function assertRepo(root) {
  try {
    await git(["rev-parse", "--is-inside-work-tree"], root);
  } catch (e) {
    if (/git not found/.test(e.message)) throw e;
    throw new Error(`Not a git repository: ${root}`);
  }
}

async function isShallow(root) {
  try {
    return (await git(["rev-parse", "--is-shallow-repository"], root)) === "true";
  } catch {
    return false; // git < 2.15: can't tell
  }
}

/** Spawn git and expose its stdout as lines. `exited` rejects on non-zero exit. */
function streamGit(args, cwd) {
  const child = spawn("git", args, { cwd, env: GIT_ENV, stdio: ["ignore", "pipe", "pipe"] });
  let stderr = "";
  child.stderr.on("data", (d) => { if (stderr.length < 65536) stderr += d; });
  const exited = new Promise((resolve, reject) => {
    child.on("error", (e) => reject(e.code === "ENOENT" ? new Error("git not found on PATH") : e));
    child.on("close", (code) =>
      code === 0 ? resolve() : reject(new Error(`git ${args.find(a => !a.startsWith("-") && a !== "core.quotepath=off")} failed: ${stderr.trim()}`)));
  });
  exited.catch(() => {}); // surfaced when awaited below; avoid an unhandled rejection meanwhile
  const rl = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
  return { rl, exited, kill: () => child.kill() };
}

// ── diff parsing ────────────────────────────────────────────────────────────

function parseDiffPath(raw) {
  let p = raw.replace(/\t$/, ""); // git appends a tab to names containing spaces
  if (p === "/dev/null") return null;
  if (p.startsWith('"') && p.endsWith('"')) {
    try { p = JSON.parse(p); } catch { p = p.slice(1, -1); }
  }
  return p;
}

/**
 * Turn a `git log -p` / `git diff` stream (produced with -U0 --no-prefix and a
 * leading \x01 commit marker line per commit) into hunks of added lines:
 *   { commit, path, startLine, lines[] }
 */
async function* parseDiff(rl, onCommit) {
  let commit = null;
  let filePath = null;
  let inHeader = false;
  let hunk = null;
  const take = () => {
    const h = hunk;
    hunk = null;
    return h && h.lines.length && !h.tooBig ? h : null;
  };

  for await (const raw of rl) {
    if (raw.charCodeAt(0) === 1) { // commit marker
      const h = take(); if (h) yield h;
      const [hash, name, email, date] = raw.slice(1).split("\0");
      commit = { hash, author: email ? `${name} <${email}>` : name, date };
      filePath = null;
      inHeader = false;
      onCommit?.(commit);
      continue;
    }
    if (raw.startsWith("diff --git ")) {
      const h = take(); if (h) yield h;
      filePath = null;
      inHeader = true;
      continue;
    }
    if (inHeader) {
      // Only here are "--- "/"+++ " headers; after the first @@ they are content.
      if (raw.startsWith("+++ ")) { filePath = parseDiffPath(raw.slice(4)); continue; }
      if (!raw.startsWith("@@")) continue;
      inHeader = false;
    }
    if (raw.startsWith("@@")) {
      const h = take(); if (h) yield h;
      const m = /^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/.exec(raw);
      if (m && filePath) hunk = { commit, path: filePath, startLine: Number(m[1]), lines: [], bytes: 0, tooBig: false };
      continue;
    }
    if (hunk && raw.charCodeAt(0) === 43 /* "+" */) {
      if (hunk.bytes > MAX_HUNK_BYTES) { hunk.tooBig = true; continue; }
      hunk.lines.push(raw.slice(1).replace(/\r$/, ""));
      hunk.bytes += raw.length;
    }
  }
  const h = take(); if (h) yield h;
}

async function scanHunks(hunks, { ignore, includeEnvFiles }) {
  const findings = [];
  const seen = new Set();
  const classCache = new Map();

  for await (const h of hunks) {
    let cls = classCache.get(h.path);
    if (cls === undefined) {
      cls = classifyForScan(h.path, { includeEnvFiles, ignore });
      classCache.set(h.path, cls);
    }
    if (cls === "skip") continue;
    if (cls === "sniff" && !h.lines.some(l => PEM_PRIVATE_HEADER.test(l))) continue;

    for (const f of scanText(h.lines, h.path, { lineOffset: h.startLine - 1, ignore })) {
      // Oldest commit that introduced this (rule, path, secret) wins; later
      // re-additions (reverts, cherry-picks, merges of the same content) are noise.
      if (seen.has(f.fingerprint)) continue;
      seen.add(f.fingerprint);
      if (h.commit) {
        f.commit = h.commit.hash;
        f.commit_date = h.commit.date;
        f.author = h.commit.author;
      }
      findings.push(f);
    }
  }
  return findings;
}

const BASE_ARGS = [
  "-c", "core.quotepath=off",
];
const DIFF_ARGS = [
  "--no-color", "--no-ext-diff", "--no-textconv", "--no-renames",
  "-U0", "--no-prefix",
  "--relative", // paths relative to `root`, matching a working-tree scan of the same dir
];

// Staged scans want rename detection (-M): a renamed file's pre-existing
// content is not "added", so moving a file never re-flags secrets it already had.
const STAGED_DIFF_ARGS = [...DIFF_ARGS.filter(a => a !== "--no-renames"), "-M"];

// ── public API ──────────────────────────────────────────────────────────────

/**
 * Scan every commit reachable from the given revisions for added secrets.
 *
 * @param {string} projectRoot
 * @param {object} [options]
 * @param {string|string[]} [options.rev]   Revisions/ranges to walk (default: all refs),
 *   e.g. "origin/main..HEAD" to scan only a branch's new commits.
 * @param {string}  [options.since]         Only commits after this date (git date syntax).
 * @param {number}  [options.maxCommits]    Limit to the N most recent commits.
 * @param {boolean} [options.includeEnvFiles=true]  A .env in history WAS committed, so it is
 *   scanned by default (the working-tree scan skips them).
 * @param {IgnoreConfig|object} [options.ignore] Pre-built IgnoreConfig, or options for loadIgnoreConfig.
 * @returns {Promise<{findings: object[], count: number, commitsScanned: number,
 *   shallow: boolean, warnings: string[], projectRoot: string, suppressed: number}>}
 */
export async function scanGitHistory(projectRoot, options = {}) {
  const root = path.resolve(projectRoot || process.cwd());
  const { rev, since, maxCommits, includeEnvFiles = true } = options;
  const ignore = loadIgnoreConfig(root, options);

  await assertRepo(root);
  const shallow = await isShallow(root);
  const warnings = [];
  if (shallow) {
    warnings.push(
      "Shallow clone: commits before the shallow boundary were not scanned. " +
      "Fetch full history first (`git fetch --unshallow`, or `fetch-depth: 0` in GitHub Actions)."
    );
  }

  const revs = rev === undefined ? ["--all"] : [].concat(rev).map(String);
  for (const r of revs) {
    // Revisions are positional; a leading "-" would be parsed as a git option.
    if (r !== "--all" && (r.startsWith("-") || r.includes("\0"))) {
      throw new Error(`Invalid revision: ${JSON.stringify(r)}`);
    }
  }
  const limits = [];
  if (since) limits.push(`--since=${String(since)}`);
  if (maxCommits !== undefined) {
    const n = Math.floor(Number(maxCommits));
    if (!Number.isFinite(n) || n < 1) throw new Error("maxCommits must be a positive integer");
    limits.push(`--max-count=${n}`);
  }

  let commitsScanned = 0;
  const args = [
    ...BASE_ARGS, "log", "--reverse", ...DIFF_ARGS, "-p",
    "--format=%x01%H%x00%an%x00%ae%x00%aI",
    ...limits, ...revs, "--",
  ];
  const { rl, exited } = streamGit(args, root);
  const findings = await scanHunks(parseDiff(rl, () => { commitsScanned++; }), { ignore, includeEnvFiles });
  await exited;

  return {
    findings, count: findings.length, commitsScanned, shallow, warnings,
    projectRoot: root, suppressed: ignore.suppressed,
  };
}

/**
 * Scan what is staged for commit (index vs HEAD) for added secrets. This is
 * what the pre-commit hook runs. It reads the INDEX, not the working tree, so
 * it scans exactly the content that is about to be committed — unstaged edits
 * are ignored, and a secret you staged but then deleted from the file on disk
 * is still caught. Works before the first commit (diffs against the empty tree).
 *
 * @param {string} projectRoot
 * @param {object} [options]
 * @param {boolean} [options.includeEnvFiles=true]  A staged .env IS about to be committed.
 * @param {IgnoreConfig|object} [options.ignore]   Pre-built IgnoreConfig, or loadIgnoreConfig options.
 * @returns {Promise<{findings: object[], count: number, projectRoot: string, suppressed: number}>}
 */
export async function scanStaged(projectRoot, options = {}) {
  const root = path.resolve(projectRoot || process.cwd());
  const { includeEnvFiles = true } = options;
  const ignore = loadIgnoreConfig(root, options);

  await assertRepo(root);
  const args = [...BASE_ARGS, "diff", "--cached", ...STAGED_DIFF_ARGS, "--"];
  const { rl, exited } = streamGit(args, root);
  const findings = await scanHunks(parseDiff(rl), { ignore, includeEnvFiles });
  await exited;

  return { findings, count: findings.length, projectRoot: root, suppressed: ignore.suppressed };
}