'use strict';

import path from 'path';
import { execFileSync } from 'child_process';

/**
 * Resolve the set of files that `--only-diff` should scan.
 *
 * Contract (this is what callers rely on — see analyzeSast.js / analyzeMalware.js):
 *
 *   - Returns a Set of absolute paths when the diff was RESOLVED. An empty Set
 *     means "git compared the two sides and nothing changed" — nothing else.
 *   - Returns null whenever the diff could NOT be resolved (not a git repo, git
 *     missing, base ref unknown, shallow clone without the base commit, ...).
 *     Callers treat null as "scan everything". An unresolvable diff must never
 *     be reported as an empty one: that would make the scan pass without
 *     looking at a single changed file.
 *
 * What is diffed:
 *   - 'staged'      → the index against HEAD (what is about to be committed).
 *   - anything else → the union of
 *                       (a) `git diff <diffBase> HEAD`  — commits since the base, and
 *                       (b) `git diff HEAD`             — uncommitted (staged + unstaged)
 *                           changes in the working tree.
 *                     In a clean CI checkout (b) is empty; on a developer machine it
 *                     makes `--only-diff` cover the edits you have not committed yet.
 *
 * Paths are reported relative to `workingDir` (`--relative`) and NUL-delimited
 * (`-z`) so that (1) they line up with the paths the chunker produces for
 * `workingDir` even when it is a subdirectory of the repository, and (2) file
 * names containing non-ASCII characters, spaces or quotes are not C-quoted by
 * git (a quoted name never matches the real path, so that file would be skipped).
 *
 * git is invoked without a shell, and `diffBase` is rejected if it could be read
 * as an option (leading '-') or contains whitespace / control characters.
 *
 * @param {string} workingDir
 * @param {string} diffBase   git ref, or the literal 'staged'
 * @param {(msg: string) => void} [log]
 * @returns {Set<string>|null}
 */
function resolveGitDiffFiles(workingDir, diffBase, log) {
  const root = path.resolve(workingDir);
  const say = (msg) => { if (log) log(`[ubel-sast] --only-diff: ${msg}`); };

  const git = (args) =>
    execFileSync('git', args, {
      cwd: root,
      stdio: ['ignore', 'pipe', 'pipe'],
      maxBuffer: 256 * 1024 * 1024,
    }).toString();

  // ── 1. Are we inside a git repository (and is git runnable)? ────────────
  try {
    git(['rev-parse', '--git-dir']);
  } catch {
    say('not a git repository (or git is not installed)');
    return null;
  }

  // ── 2. Diff command(s) ──────────────────────────────────────────────────
  const diffArgs = (...refs) => ['diff', '--name-only', '-z', '--relative', ...refs, '--'];
  let commands;

  if (diffBase === 'staged') {
    commands = [diffArgs('--cached')];
  } else {
    if (
      typeof diffBase !== 'string' ||
      diffBase.length === 0 ||
      diffBase.startsWith('-') ||
      /[\s\x00-\x1f\x7f]/.test(diffBase)
    ) {
      say(`"${String(diffBase)}" is not a usable git ref`);
      return null;
    }

    // The base must resolve to a commit. In a shallow clone (the default for
    // actions/checkout, fetch-depth: 1) HEAD^ and origin/<branch> usually do
    // not exist — that is exactly the case where we must NOT pretend the diff
    // is empty.
    try {
      git(['rev-parse', '--verify', '--quiet', `${diffBase}^{commit}`]);
    } catch {
      let hint = '';
      try {
        if (git(['rev-parse', '--is-shallow-repository']).trim() === 'true') {
          hint = ' — this is a shallow clone; fetch more history (e.g. actions/checkout with fetch-depth: 0, or `git fetch --deepen`)';
        }
      } catch { /* older git: no --is-shallow-repository, hint omitted */ }
      say(`base ref "${diffBase}" does not resolve to a commit${hint}`);
      return null;
    }

    commands = [
      diffArgs(diffBase, 'HEAD'),
      diffArgs('HEAD'),
    ];
  }

  // ── 3. Run them; any failure makes the whole diff unresolved ────────────
  const rel = new Set();
  for (const args of commands) {
    let stdout;
    try {
      stdout = git(args);
    } catch (err) {
      const first = String(err.stderr || err.message || '').trim().split('\n')[0].slice(0, 120);
      say(`"git ${args.join(' ')}" failed (${first})`);
      return null;
    }
    for (const name of stdout.split('\0')) {
      if (name) rel.add(name);
    }
  }

  return new Set([...rel].map((r) => path.resolve(root, r)));
}

export { resolveGitDiffFiles };
