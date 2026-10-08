/**
 * sca_hook.js — `ubel-<engine> install-hook` / `uninstall-hook`.
 *
 * Original code.
 *
 * There is ONE ubel pre-commit hook (see precommit_hook.js): it runs
 * `ubel-secrets --staged` on every commit, and `<engine> health` (dependency
 * scan only — scan_os is off by construction, and `health` never writes or
 * reverts a lockfile) on every commit (UBEL_HOOK_SCA=auto: only when a
 * dependency manifest/lockfile is staged).
 * Installing from here sets the dependency step and keeps the secrets step, so
 * this and secrets_hook.js can be run in either order without --force and
 * without chaining into each other.
 *
 * Kept as a module of its own so existing imports keep working.
 */

import { installHook as installUnified, uninstallHook, buildHookScript, HOOK_MARKER, DEP_FILES_PATTERN } from "./precommit_hook.js";

export { uninstallHook, buildHookScript, HOOK_MARKER, DEP_FILES_PATTERN };

/**
 * @param {string} root
 * @param {object} [opts]
 * @param {boolean} [opts.force=false]         Move an existing foreign pre-commit hook aside and chain to it.
 * @param {string}  [opts.binPath]             CLI entry script to embed (default: the running script).
 * @param {string}  [opts.nodePath]            node binary to embed (default: the running node).
 * @param {string}  [opts.binName="ubel-npm"]  Binary name to find on PATH for portable installs.
 */
export function installHook(root, { force = false, binPath = process.argv[1], nodePath = process.execPath, binName = "ubel-npm" } = {}) {
  return installUnified(root, { force, sca: { binPath, nodePath, binName } });
}