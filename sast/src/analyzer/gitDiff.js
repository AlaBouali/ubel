'use strict';

import path from 'path';
import { execSync } from 'child_process';

/**
 * Run `git diff --name-only <diffBase>` (or `git diff --name-only --cached` for
 * the special value 'staged') inside workingDir and return a Set of resolved
 * absolute paths to modified files.
 *
 * Returns null on any error (git not found, not a repo, etc.).
 * Returns an empty Set when the diff is clean.
 */
function resolveGitDiffFiles(workingDir, diffBase, log) {
  const root = path.resolve(workingDir);

  try {
    // First verify we're inside a git repository.
    execSync('git rev-parse --git-dir', { cwd: root, stdio: 'pipe' });
  } catch {
    if (log) log('[ubel-sast] --only-diff: not a git repository');
    return null;
  }

  // Build the git diff command.
  // 'staged'  → diff index against HEAD (uncommitted staged changes)
  // anything else → diff working tree + index against the given ref
  let cmd;
  if (diffBase === 'staged') {
    cmd = 'git diff --name-only --cached HEAD';
  } else {
    // Diff between diffBase and the current working tree (including staged).
    // Using HEAD for the right side captures both staged and unstaged changes
    // relative to the base ref.
    cmd = `git diff --name-only ${diffBase} HEAD`;
  }

  let stdout;
  try {
    stdout = execSync(cmd, { cwd: root, stdio: 'pipe' }).toString();
  } catch (err) {
    // diffBase ref may not exist (e.g. first commit, shallow clone).
    // Fall back to listing all tracked files so the first run still works.
    if (log) {
      log(`[ubel-sast] --only-diff: "${cmd}" failed (${err.message.slice(0, 80).trim()})`);
      log('[ubel-sast] --only-diff: falling back to git diff --name-only HEAD (unstaged)');
    }
    try {
      stdout = execSync('git diff --name-only HEAD', { cwd: root, stdio: 'pipe' }).toString();
    } catch {
      return null;
    }
  }

  const files = stdout
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .map(rel => path.resolve(root, rel));

  return new Set(files);
}

export { resolveGitDiffFiles };