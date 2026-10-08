/**
 * secrets_hook.js — `ubel-secrets --install-hook` / `--uninstall-hook`.
 *
 * Original code (not ported from Trivy).
 *
 * There is ONE ubel pre-commit hook (see precommit_hook.js): it runs
 * `ubel-secrets --staged` on every commit and, once a dependency engine has
 * been installed with `ubel-<engine> install-hook`, the dependency scan too.
 * Installing from here sets the secrets step and keeps whatever dependency
 * step is already in the hook, so this and sca_hook.js can be run in either
 * order without --force and without chaining into each other.
 *
 * Kept as a module of its own so existing imports keep working.
 */

import { installHook as installUnified, uninstallHook, buildHookScript, HOOK_MARKER } from "./precommit_hook.js";

export { uninstallHook, buildHookScript, HOOK_MARKER };

/**
 * @param {string} root
 * @param {object} [opts]
 * @param {boolean} [opts.force=false]  Move an existing foreign pre-commit hook aside and chain to it.
 * @param {string}  [opts.binPath]      CLI entry script to embed (default: the running script).
 * @param {string}  [opts.nodePath]     node binary to embed (default: the running node).
 */
export function installHook(root, { force = false, binPath = process.argv[1], nodePath = process.execPath } = {}) {
  return installUnified(root, { force, secrets: { binPath, nodePath } });
}