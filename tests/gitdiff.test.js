// Regression tests for sast/src/analyzer/gitDiff.js (--only-diff).
//
// The bug these guard against: in a shallow clone (actions/checkout default) the
// base ref HEAD^ does not exist; the old code then fell back to `git diff HEAD`
// (empty on a clean CI checkout) and returned an EMPTY Set, so callers logged
// "no modified files found — nothing to scan" and the scan passed without
// looking at anything. An unresolvable diff must return null (=> full scan).
//
// Run: node --test tests/gitdiff.test.js

import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { resolveGitDiffFiles } from '../sast/src/analyzer/gitDiff.js';

const GIT_ID = ['-c', 'user.name=t', '-c', 'user.email=t@example.com', '-c', 'commit.gpgsign=false'];
const git = (cwd, ...args) => execFileSync('git', [...GIT_ID, ...args], { cwd, stdio: 'pipe' }).toString();

function tmp(label) {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), `ubel-gd-${label}-`)));
}
function write(dir, rel, content = 'x') {
  const p = path.join(dir, rel);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, content);
  return p;
}
function twoCommitRepo() {
  const dir = tmp('repo');
  git(dir, 'init', '-q');
  write(dir, 'a.js', 'a');
  git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'c1');
  return dir;
}

test('shallow clone: unresolvable base returns null, never an empty Set', () => {
  const src = twoCommitRepo();
  write(src, 'evil.js', 'eval(x)');
  git(src, 'add', '.'); git(src, 'commit', '-qm', 'c2');

  const clone = path.join(tmp('clone'), 'c');
  execFileSync('git', ['clone', '-q', '--depth', '1', `file://${src}`, clone], { stdio: 'pipe' });

  const logs = [];
  const result = resolveGitDiffFiles(clone, 'HEAD^', (m) => logs.push(m));
  assert.equal(result, null);
  assert.ok(logs.some((l) => /shallow clone/.test(l)), `expected a shallow-clone hint, got: ${logs.join(' | ')}`);
});

test('unknown base ref returns null', () => {
  const dir = twoCommitRepo();
  assert.equal(resolveGitDiffFiles(dir, 'origin/does-not-exist'), null);
});

test('not a git repository returns null', () => {
  assert.equal(resolveGitDiffFiles(tmp('nogit'), 'HEAD^'), null);
});

test('resolved diff lists the files changed since the base', () => {
  const dir = twoCommitRepo();
  const evil = write(dir, 'evil.js', 'eval(x)');
  git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'c2');
  const result = resolveGitDiffFiles(dir, 'HEAD^');
  assert.deepEqual([...result], [evil]);
});

test('a genuinely clean diff is an empty Set (and only then)', () => {
  const dir = twoCommitRepo();
  const result = resolveGitDiffFiles(dir, 'HEAD');
  assert.ok(result instanceof Set);
  assert.equal(result.size, 0);
});

test('uncommitted working-tree changes are included', () => {
  const dir = twoCommitRepo();
  const a = write(dir, 'a.js', 'changed');
  const result = resolveGitDiffFiles(dir, 'HEAD');
  assert.ok(result.has(a));
});

test("'staged' lists only what is in the index", () => {
  const dir = twoCommitRepo();
  const staged = write(dir, 'staged.js');
  write(dir, 'unstaged.js');
  git(dir, 'add', 'staged.js');
  const result = resolveGitDiffFiles(dir, 'staged');
  assert.deepEqual([...result], [staged]);
});

test('working directory inside a repo: paths resolve under that directory', () => {
  // git prints repo-root-relative paths; resolving them against a subdirectory
  // used to produce paths that matched nothing, so nothing was scanned.
  const dir = twoCommitRepo();
  write(dir, 'pkg/one/index.js', '1');
  const other = write(dir, 'elsewhere.js', '2');
  git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'c2');

  const sub = path.join(dir, 'pkg', 'one');
  const result = resolveGitDiffFiles(sub, 'HEAD^');
  assert.deepEqual([...result], [path.join(sub, 'index.js')]);
  assert.ok(!result.has(other), 'files outside the working directory are out of scope');
});

test('non-ASCII and space-containing file names are not C-quoted away', () => {
  // Without -z git prints "r\303\251sum\303\251.js" (quoted), which never matches
  // the real path, so the changed file was silently skipped.
  const dir = twoCommitRepo();
  const f1 = write(dir, 'résumé.js', '1');
  const f2 = write(dir, 'with space.js', '2');
  git(dir, 'add', '.'); git(dir, 'commit', '-qm', 'c2');
  const result = resolveGitDiffFiles(dir, 'HEAD^');
  assert.ok(result.has(f1), 'non-ASCII name present');
  assert.ok(result.has(f2), 'name with space present');
});

test('a base that looks like a git option is rejected, not executed', () => {
  const dir = twoCommitRepo();
  const sentinel = path.join(tmp('sentinel'), 'pwned.txt');
  assert.equal(resolveGitDiffFiles(dir, `--output=${sentinel}`), null);
  assert.equal(fs.existsSync(sentinel), false, 'git must not have been run with an injected --output');
  assert.equal(resolveGitDiffFiles(dir, 'HEAD^; touch x'), null);
});
