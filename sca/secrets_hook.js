/**
 * secrets_hook.js — install / remove the git pre-commit hook.
 *
 * Original code (not ported from Trivy).
 *
 * The hook is a small POSIX sh script that runs `ubel-secrets --staged` and
 * blocks the commit on a non-zero exit (1 = findings, 2 = scan error).
 *
 *   - Idempotent: re-installing replaces our own hook (recognised by HOOK_MARKER).
 *   - Never clobbers someone else's hook: without `force` it refuses. With
 *     `force` the existing hook is moved to `pre-commit.local`, and our hook
 *     runs it after a clean scan. Uninstalling moves it back.
 *   - Respects `core.hooksPath` and git worktrees (the directory comes from
 *     `git rev-parse --git-path hooks`).
 *   - If the hooks directory lives OUTSIDE the git dir (a committed
 *     `.githooks/` or husky-style path), the script is written without
 *     machine-specific absolute paths and finds `ubel-secrets` on PATH only,
 *     so it is safe to commit and share.
 *   - If the tool cannot be found the hook warns loudly and lets the commit
 *     through (set UBEL_HOOK_STRICT=1 to block instead). If the tool runs and
 *     fails, the commit is blocked — a broken scan must not look like a clean one.
 *
 * Bypass once with `git commit --no-verify`. Hooks are client-side, so also
 * run `ubel-secrets --history` in CI.
 */

import fs from "node:fs";
import path from "node:path";
import { git, assertRepo } from "./secrets_git.js";

export const HOOK_MARKER = "# ubel-secrets pre-commit hook";

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;

function realpathOrEmpty(p) {
  if (!p) return "";
  try { return fs.realpathSync(p); } catch { return ""; }
}

export function buildHookScript({ nodePath = "", binPath = "" } = {}) {
  return `#!/bin/sh
${HOOK_MARKER}
# Installed by \`ubel-secrets --install-hook\`; remove with \`ubel-secrets --uninstall-hook\`.
# Scans the changes you are about to commit. Skip once with: git commit --no-verify

UBEL_NODE=${shq(nodePath)}
UBEL_BIN=${shq(binPath)}

run_scan() {
  if [ -n "$UBEL_BIN" ] && [ -f "$UBEL_BIN" ] && [ -x "$UBEL_NODE" ]; then
    "$UBEL_NODE" "$UBEL_BIN" --staged
  elif command -v ubel-secrets >/dev/null 2>&1; then
    ubel-secrets --staged
  else
    echo "ubel-secrets: command not found - staged changes were NOT scanned." >&2
    if [ "$UBEL_HOOK_STRICT" = "1" ]; then return 3; fi
    return 0
  fi
}

run_scan
status=$?
if [ "$status" -ne 0 ]; then
  echo "" >&2
  if [ "$status" -eq 1 ]; then
    echo "ubel-secrets: commit blocked - possible secret(s) in the staged changes." >&2
    echo "Remove them, or suppress a false positive (see the hint above). Bypass once: git commit --no-verify" >&2
  else
    echo "ubel-secrets: scan did not complete (exit $status); commit blocked. Bypass once: git commit --no-verify" >&2
  fi
  exit "$status"
fi

# Chain to a pre-existing hook that --force moved aside.
LOCAL_HOOK="$(dirname "$0")/pre-commit.local"
if [ -x "$LOCAL_HOOK" ]; then
  exec "$LOCAL_HOOK" "$@"
fi
exit 0
`;
}

async function resolveHooksDir(root) {
  await assertRepo(root);
  const hooks = path.resolve(root, await git(["rev-parse", "--git-path", "hooks"], root));
  const common = path.resolve(root, await git(["rev-parse", "--git-common-dir"], root));
  const rel = path.relative(common, hooks);
  const insideGitDir = !rel.startsWith("..") && !path.isAbsolute(rel);
  return { dir: hooks, insideGitDir };
}

/**
 * @param {string} root
 * @param {object} [opts]
 * @param {boolean} [opts.force=false]  Move an existing foreign pre-commit hook aside and chain to it.
 * @param {string}  [opts.binPath]      CLI entry script to embed (default: the running script).
 * @param {string}  [opts.nodePath]     node binary to embed (default: the running node).
 * @returns {Promise<{hookFile: string, replaced: boolean, chained: boolean, localFile: string, portable: boolean}>}
 */
export async function installHook(root, { force = false, binPath = process.argv[1], nodePath = process.execPath } = {}) {
  const { dir, insideGitDir } = await resolveHooksDir(root);
  const hookFile = path.join(dir, "pre-commit");
  const localFile = path.join(dir, "pre-commit.local");

  let existing = null;
  try { existing = fs.readFileSync(hookFile, "utf8"); } catch { /* none yet */ }
  const ours = existing !== null && existing.includes(HOOK_MARKER);

  let chained = false;
  if (existing !== null && !ours) {
    if (!force) {
      throw new Error(
        `A pre-commit hook already exists at ${hookFile}. Re-run with --force to keep it ` +
        `(it is moved to pre-commit.local and still runs after the secrets scan), or add ` +
        "`ubel-secrets --staged || exit 1` to it yourself."
      );
    }
    if (fs.existsSync(localFile)) {
      throw new Error(`${localFile} already exists; resolve it before using --force.`);
    }
    fs.renameSync(hookFile, localFile);
    chained = true;
  }

  // A shared hooks dir (committed to the repo) must not embed this machine's paths.
  const portable = !insideGitDir;
  const script = buildHookScript(portable
    ? {}
    : { nodePath: realpathOrEmpty(nodePath), binPath: realpathOrEmpty(binPath) });

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(hookFile, script, { mode: 0o755 });
  fs.chmodSync(hookFile, 0o755); // writeFile's mode is masked by umask and ignored on overwrite

  return { hookFile, replaced: ours, chained, localFile, portable };
}

/**
 * Remove our hook (and restore a hook that --force moved aside).
 * Refuses to touch a pre-commit hook it did not install.
 * @returns {Promise<{hookFile: string, removed: boolean, restored: boolean}>}
 */
export async function uninstallHook(root) {
  const { dir } = await resolveHooksDir(root);
  const hookFile = path.join(dir, "pre-commit");
  const localFile = path.join(dir, "pre-commit.local");

  let existing;
  try { existing = fs.readFileSync(hookFile, "utf8"); }
  catch { return { hookFile, removed: false, restored: false }; }

  if (!existing.includes(HOOK_MARKER)) {
    throw new Error(`${hookFile} was not installed by ubel-secrets; leaving it alone.`);
  }
  fs.rmSync(hookFile);
  let restored = false;
  if (fs.existsSync(localFile)) {
    fs.renameSync(localFile, hookFile);
    restored = true;
  }
  return { hookFile, removed: true, restored };
}