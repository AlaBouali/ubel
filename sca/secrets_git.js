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
 * Large additions are never dropped: a hunk is scanned in slices of about
 * SLICE_BYTES (each slice re-scans the tail of the previous one, so a multi-line
 * key straddling a boundary is still found), and a single huge line is split
 * with an overlap. Only a file adding more than MAX_FILE_ADDED_BYTES in one
 * diff is cut short, and that is reported as a warning (result.warnings /
 * result.incomplete) rather than silently ignored.
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
import { scanText, classifyForScan, classifyStaged, loadIgnoreConfig } from "./secrets.js";

const MB = 1024 * 1024;
const BINARY_SNIFF_BYTES = 8000;
const SLICE_BYTES = 1 * MB;            // scan a long run of added lines in slices of about this size
const SLICE_OVERLAP_BYTES = 64 * 1024; // tail carried into the next slice (a PEM key is a few KB)
const MAX_LINE_CHARS = 1 * MB;         // one line longer than this is split into overlapping pieces
const LINE_OVERLAP_CHARS = 16 * 1024;  // tokens are far shorter than this
// Hard stop per file per diff, so a multi-GB blob cannot stall `git commit`.
// Anything past it is reported, not hidden. Override: UBEL_STAGED_MAX_FILE_MB.
const MAX_FILE_ADDED_BYTES = (() => {
  const mb = Number(process.env.UBEL_STAGED_MAX_FILE_MB);
  return (Number.isFinite(mb) && mb > 0 ? mb : 128) * MB;
})();
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
 * leading \x01 commit marker line per commit) into slices of added lines:
 *   { commit, path, startLine, lines[] }
 * Added lines are contiguous within a hunk, so line numbers are startLine + index.
 * Nothing is dropped for size: see the header comment for how big hunks are cut.
 *
 * @param {AsyncIterable<string>} rl
 * @param {{onCommit?: (c: object) => void, onSkip?: (info: object) => void}} [hooks]
 */
async function* parseDiff(rl, { onCommit, onSkip } = {}) {
  let commit = null;
  let filePath = null;
  let inHeader = false;
  let hunk = null;       // { commit, path, startLine, lines, bytes, fresh }
  let fileBytes = 0;     // added bytes seen for the current file in this diff
  let fileCapped = false;
  let fileBinary = false; // staged scans diff with --text; real binaries are recognised here

  const out = (h) => ({ commit: h.commit, path: h.path, startLine: h.startLine, lines: h.lines });
  // `fresh` counts lines not yet handed out, so a carried-over overlap is never emitted on its own.
  const take = () => {
    const h = hunk;
    hunk = null;
    return h && h.fresh > 0 ? out(h) : null;
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
      fileBytes = 0;
      fileCapped = false;
      fileBinary = false;
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
      if (m && filePath && !fileCapped && !fileBinary) hunk = { commit, path: filePath, startLine: Number(m[1]), lines: [], bytes: 0, fresh: 0 };
      continue;
    }
    if (!hunk || raw.charCodeAt(0) !== 43 /* "+" */) continue;

    const text = raw.slice(1).replace(/\r$/, "");
    // Same test git uses for "binary": a NUL byte in the first 8000 bytes of content.
    if (fileBytes < BINARY_SNIFF_BYTES && text.slice(0, BINARY_SNIFF_BYTES - fileBytes).includes("\0")) {
      fileBinary = true;
      hunk = null;
      continue;
    }
    fileBytes += text.length + 1;
    if (fileBytes > MAX_FILE_ADDED_BYTES) {
      // Scan what was collected, then stop reading this file and say so.
      fileCapped = true;
      onSkip?.({ commit, path: hunk.path, limit: MAX_FILE_ADDED_BYTES });
      const h = take(); if (h) yield h;
      continue;
    }

    if (text.length > MAX_LINE_CHARS) {
      // One enormous line (minified bundle, data blob): flush what precedes it,
      // then scan it in overlapping pieces. Pieces share the line number.
      const lineNo = hunk.startLine + hunk.lines.length;
      if (hunk.fresh > 0) yield out(hunk);
      const step = MAX_LINE_CHARS - LINE_OVERLAP_CHARS;
      for (let i = 0; i < text.length; i += step) {
        yield { commit: hunk.commit, path: hunk.path, startLine: lineNo, lines: [text.slice(i, i + MAX_LINE_CHARS)] };
        if (i + MAX_LINE_CHARS >= text.length) break;
      }
      hunk = { commit: hunk.commit, path: hunk.path, startLine: lineNo + 1, lines: [], bytes: 0, fresh: 0 };
      continue;
    }

    hunk.lines.push(text);
    hunk.bytes += text.length + 1;
    hunk.fresh++;
    if (hunk.bytes >= SLICE_BYTES) {
      yield out(hunk);
      // Keep the tail of this slice as the head of the next one.
      let keep = 0, kept = 0;
      for (let i = hunk.lines.length - 1; i > 0 && kept < SLICE_OVERLAP_BYTES; i--) {
        kept += hunk.lines[i].length + 1;
        keep++;
      }
      hunk.startLine += hunk.lines.length - keep;
      hunk.lines = hunk.lines.slice(hunk.lines.length - keep);
      hunk.bytes = kept;
      hunk.fresh = 0;
    }
  }
  const h = take(); if (h) yield h;
}

async function scanHunks(hunks, { ignore, classify }) {
  const findings = [];
  const seen = new Set();
  const classCache = new Map();

  for await (const h of hunks) {
    let cls = classCache.get(h.path);
    if (cls === undefined) {
      cls = classify(h.path);
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

function oversizeWarning({ path: p, limit }) {
  return `${p}: more than ${Math.round(limit / MB)} MB added - only the first ${Math.round(limit / MB)} MB was scanned ` +
         "(raise UBEL_STAGED_MAX_FILE_MB to scan more).";
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
//
// --text: scan every staged file as text. Without it, git emits NO hunks for a
// file its attributes mark as binary or -diff (`*.min.js -diff`, `*.svg binary`,
// `package-lock.json -diff` are all common), and a token in such a file would
// pass the hook unseen. True binaries are then dropped by parseDiff (NUL sniff)
// and classifyStaged (extension), exactly as git itself would have done.
const STAGED_DIFF_ARGS = [...DIFF_ARGS.filter(a => a !== "--no-renames"), "-M", "--text"];

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
  const skipped = [];
  const findings = await scanHunks(
    parseDiff(rl, { onCommit: () => { commitsScanned++; }, onSkip: (i) => skipped.push(i) }),
    { ignore, classify: (p) => classifyForScan(p, { includeEnvFiles, ignore }) });
  await exited;
  for (const i of skipped) warnings.push(oversizeWarning(i));

  return {
    findings, count: findings.length, commitsScanned, shallow, warnings,
    projectRoot: root, suppressed: ignore.suppressed,
    incomplete: skipped.length > 0, skipped,
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
 * @param {IgnoreConfig|object} [options.ignore]   Pre-built IgnoreConfig, or loadIgnoreConfig options.
 *   (Staged .env files are always scanned; see classifyStaged in secrets.js for what else is.)
 * @returns {Promise<{findings: object[], count: number, projectRoot: string, suppressed: number,
 *   warnings: string[], incomplete: boolean, skipped: object[]}>}
 */
export async function scanStaged(projectRoot, options = {}) {
  const root = path.resolve(projectRoot || process.cwd());
  const ignore = loadIgnoreConfig(root, options);

  await assertRepo(root);
  const args = [...BASE_ARGS, "diff", "--cached", ...STAGED_DIFF_ARGS, "--"];
  const { rl, exited } = streamGit(args, root);
  const skipped = [];
  // Staged files use the inclusive classifier (classifyStaged): a file being
  // committed is scanned wherever it lives and whatever it is called.
  const findings = await scanHunks(
    parseDiff(rl, { onSkip: (i) => skipped.push(i) }),
    { ignore, classify: (p) => classifyStaged(p, { ignore }) });
  await exited;

  const warnings = skipped.map(oversizeWarning);
  return {
    findings, count: findings.length, projectRoot: root, suppressed: ignore.suppressed,
    warnings, incomplete: skipped.length > 0, skipped,
  };
}