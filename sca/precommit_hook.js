/**
 * precommit_hook.js — the ONE git pre-commit hook for ubel: secrets + dependency scan.
 *
 * Original code (not ported from Trivy).
 *
 * Why one hook: the secrets hook and the dependency hook used to be two
 * separate scripts fighting over .git/hooks/pre-commit. Installing the second
 * one needed --force, which moved the first to pre-commit.local and chained to
 * it, and both generated scripts then did `exec "$(dirname "$0")/pre-commit.local"`
 * — which, once a hook has BEEN moved to pre-commit.local, is itself: an
 * infinite loop. The dependency script also exited early when no manifest was
 * staged, before it ever reached the chain, so the secrets hook silently never
 * ran. Now there is a single script that does both jobs and never chains to
 * itself.
 *
 * What the hook does, on EVERY commit:
 *   1. secrets      `ubel-secrets --staged`   always (it reads the index)
 *   2. dependency   `<engine> health`         when a dependency manifest/lockfile
 *                                             is staged (UBEL_HOOK_SCA=always|off|auto)
 * then chains to a foreign pre-commit hook that --force moved aside.
 *
 * Who installs it: `ubel-secrets --install-hook` and `ubel-<engine> install-hook`
 * both write this same script. Each installer sets its own part and KEEPS the
 * other's, so running both in any order leaves one hook with both steps. The
 * secrets step is always present; the dependency step exists once an engine has
 * been installed. The settings live in a `# ubel-hook-config:` line inside the
 * script, which is how a later install merges instead of overwriting.
 *
 *   - Idempotent: re-installing replaces our own hook (recognised by HOOK_MARKER).
 *   - Migrates the old two-hook layout: hooks written by earlier versions
 *     (markers `# ubel-secrets pre-commit hook` / `# ubel-sca pre-commit hook`),
 *     including a pre-commit.local that is itself one of ours, are folded into
 *     the single hook and the stale pre-commit.local is removed.
 *   - Never clobbers someone else's hook: without `force` it refuses. With
 *     `force` the foreign hook is moved to `pre-commit.local` and run after the
 *     scans pass. Uninstalling moves it back.
 *   - Respects `core.hooksPath` and git worktrees (the directory comes from
 *     `git rev-parse --git-path hooks`).
 *   - If the hooks directory lives OUTSIDE the git dir (a committed
 *     `.githooks/` or husky-style path), the script embeds no machine-specific
 *     paths and finds the binaries on PATH only, so it is safe to commit.
 *   - If a binary cannot be found the hook warns loudly and lets the commit
 *     through (UBEL_HOOK_STRICT=1 blocks instead). If a scan runs and fails,
 *     the commit is blocked — a broken scan must not look like a clean one.
 *
 * Bypass once with `git commit --no-verify`. Hooks are client-side, so also
 * run the scans in CI.
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { git, assertRepo } from "./secrets_git.js";

export const HOOK_MARKER = "# ubel pre-commit hook";
// Markers written by the previous two-hook layout. Still recognised as "ours".
const LEGACY_MARKERS = ["# ubel-secrets pre-commit hook", "# ubel-sca pre-commit hook"];
const CONFIG_PREFIX = "# ubel-hook-config: ";

const SECRETS_BIN_NAME = "ubel-secrets";
const DEFAULT_SCA_BIN_NAME = "ubel-npm";

const shq = (s) => `'${String(s).replace(/'/g, `'\\''`)}'`;
const unshq = (s) => s.replace(/'\\''/g, "'");

function realpathOrEmpty(p) {
  if (!p) return "";
  try { return fs.realpathSync(p); } catch { return ""; }
}

function readOrNull(file) {
  try { return fs.readFileSync(file, "utf8"); } catch { return null; }
}

const isOurs = (text) =>
  text !== null && (text.includes(HOOK_MARKER) || LEGACY_MARKERS.some(m => text.includes(m)));

/** bin/secrets.js next to this package's sca/ dir, if it exists. */
function defaultSecretsBin() {
  try {
    const p = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "bin", "secrets.js");
    return fs.existsSync(p) ? p : "";
  } catch { return ""; }
}

// ── dependency-step trigger ──────────────────────────────────────────────────

/**
 * Files whose staged presence makes the dependency step run (in "auto" mode).
 * Extended regex (grep -E), matched against each staged path anywhere in the
 * tree, so monorepo sub-package manifests count too.
 */
export const DEP_FILES_PATTERN = [
  // JS
  "(^|/)(package\\.json|package-lock\\.json|npm-shrinkwrap\\.json|pnpm-lock\\.yaml|pnpm-workspace\\.yaml|bun\\.lockb?|yarn\\.lock",
  // PHP
  "composer\\.(json|lock)",
  // Python: pip / pip-tools / uv / poetry / pdm / pipenv / conda
  "requirements([-_.][^/]*)?\\.(txt|in)|constraints([-_.][^/]*)?\\.txt|pyproject\\.toml|Pipfile(\\.lock)?|setup\\.py|setup\\.cfg",
  "poetry\\.lock|uv\\.lock|pdm\\.lock|conda-lock\\.ya?ml|environment\\.ya?ml",
  // Rust / Go
  "Cargo\\.(toml|lock)|go\\.(mod|sum|work)",
  // Java / Gradle
  "pom\\.xml|build\\.gradle(\\.kts)?|gradle\\.lockfile|libs\\.versions\\.toml",
  // Ruby
  "Gemfile(\\.lock)?",
  // Swift / Dart / .NET
  "Package\\.(swift|resolved)|Cartfile(\\.resolved)?|Podfile(\\.lock)?|pubspec\\.(yaml|lock)",
  "packages\\.config|packages\\.lock\\.json|Directory\\.Packages\\.props|[^/]+\\.csproj)$",
  // requirements/*.txt (any depth)
  "(^|/)requirements/.*\\.(txt|in)$",
].join("|"); // one flat alternation; the first and ninth entries open/close the shared (...) group

// ── script ───────────────────────────────────────────────────────────────────

/**
 * @param {object} cfg
 * @param {{node: string, bin: string, name: string}} cfg.secrets
 * @param {{node: string, bin: string, name: string}|null} cfg.sca  null = no dependency step
 */
export function buildHookScript({ secrets, sca = null }) {
  const config = JSON.stringify({ v: 1, secrets, sca });
  return `#!/bin/sh
${HOOK_MARKER}
${CONFIG_PREFIX}${config}
# Installed by 'ubel-secrets --install-hook' or 'ubel-<engine> install-hook';
# remove with 'ubel-secrets --uninstall-hook' or 'ubel-<engine> uninstall-hook'.
#
# One hook, on every commit:
#   1. secrets     ubel-secrets --staged   (always; scans exactly what is staged)
#   2. dependency  <engine> health         (when a dependency manifest or lockfile is staged)
# Skip once with: git commit --no-verify
#
#   UBEL_HOOK_STRICT=1             block when a scanner binary is missing (default: warn, continue)
#   UBEL_HOOK_SCA=auto|always|off  when to run the dependency step (default: auto = manifest staged)

UBEL_SECRETS_NODE=${shq(secrets.node)}
UBEL_SECRETS_BIN=${shq(secrets.bin)}
UBEL_SECRETS_NAME=${shq(secrets.name)}
UBEL_SCA_NODE=${shq(sca?.node ?? "")}
UBEL_SCA_BIN=${shq(sca?.bin ?? "")}
UBEL_SCA_NAME=${shq(sca?.name ?? "")}

# run_tool <label> <node> <bin> <name> <args...>
# Prefers the embedded node + script; falls back to <name> on PATH.
run_tool() {
  label=$1; node=$2; bin=$3; name=$4
  shift 4
  if [ -n "$bin" ] && [ -f "$bin" ] && [ -n "$node" ] && [ -x "$node" ]; then
    "$node" "$bin" "$@"
  elif command -v "$name" >/dev/null 2>&1; then
    "$name" "$@"
  else
    echo "$label: $name not found - this scan was NOT run." >&2
    if [ "$UBEL_HOOK_STRICT" = "1" ]; then return 3; fi
    return 0
  fi
}

# ── 1. secrets: every commit ─────────────────────────────────────────────────
run_tool ubel-secrets "$UBEL_SECRETS_NODE" "$UBEL_SECRETS_BIN" "$UBEL_SECRETS_NAME" --staged
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

# ── 2. dependency scan: when a manifest/lockfile is staged ───────────────────
if [ -n "$UBEL_SCA_NAME" ]; then
  run_sca=0
  case "$UBEL_HOOK_SCA" in
    off) ;;
    always) run_sca=1 ;;
    *)
      # -z + quotepath=off: exact paths, so a manifest in a non-ASCII directory still matches.
      if git -c core.quotepath=off diff --cached --name-only -z --diff-filter=ACMRT 2>/dev/null \\
           | tr '\\0' '\\n' | LC_ALL=C grep -Eq '${DEP_FILES_PATTERN}'; then
        run_sca=1
      fi
      ;;
  esac

  if [ "$run_sca" -eq 1 ]; then
    run_tool "$UBEL_SCA_NAME" "$UBEL_SCA_NODE" "$UBEL_SCA_BIN" "$UBEL_SCA_NAME" health
    status=$?
    if [ "$status" -ne 0 ]; then
      echo "" >&2
      if [ "$status" -eq 1 ]; then
        echo "$UBEL_SCA_NAME: commit blocked - dependency policy violation detected." >&2
        echo "Fix the findings, adjust policy, or bypass once: git commit --no-verify" >&2
      else
        echo "$UBEL_SCA_NAME: scan did not complete (exit $status); commit blocked. Bypass once: git commit --no-verify" >&2
      fi
      exit "$status"
    fi
  fi
fi

# ── chain to a pre-existing hook that --force moved aside ────────────────────
# Never chain from the chained hook itself (that would re-run it forever).
case "$0" in
  *pre-commit.local) exit 0 ;;
esac
LOCAL_HOOK="$(dirname "$0")/pre-commit.local"
if [ -x "$LOCAL_HOOK" ]; then
  exec "$LOCAL_HOOK" "$@"
fi
exit 0
`;
}

// ── reading an installed hook back ───────────────────────────────────────────

/**
 * Recover the settings of an installed ubel hook, current or legacy.
 * @returns {{secrets?: object, sca?: object|null}}
 */
function readConfig(text) {
  if (!text) return {};
  for (const line of text.split("\n")) {
    if (!line.startsWith(CONFIG_PREFIX)) continue;
    try {
      const c = JSON.parse(line.slice(CONFIG_PREFIX.length));
      return { secrets: c.secrets ?? undefined, sca: c.sca ?? undefined };
    } catch { return {}; }
  }
  // Legacy single-purpose scripts: pull the embedded paths back out of the sh variables.
  const v = (name) => {
    const m = new RegExp(`^${name}=('(?:[^']|'\\\\'')*')`, "m").exec(text);
    return m ? unshq(m[1].slice(1, -1)) : "";
  };
  if (text.includes("# ubel-secrets pre-commit hook")) {
    return { secrets: { node: v("UBEL_NODE"), bin: v("UBEL_BIN"), name: SECRETS_BIN_NAME } };
  }
  if (text.includes("# ubel-sca pre-commit hook")) {
    return { sca: { node: v("UBEL_NODE"), bin: v("UBEL_BIN"), name: v("UBEL_BIN_NAME") || DEFAULT_SCA_BIN_NAME } };
  }
  return {};
}

async function resolveHooksDir(root) {
  await assertRepo(root);
  const hooks = path.resolve(root, await git(["rev-parse", "--git-path", "hooks"], root));
  const common = path.resolve(root, await git(["rev-parse", "--git-common-dir"], root));
  const rel = path.relative(common, hooks);
  const insideGitDir = !rel.startsWith("..") && !path.isAbsolute(rel);
  return { dir: hooks, insideGitDir };
}

// ── install / uninstall ──────────────────────────────────────────────────────

/**
 * Install (or update) the single ubel pre-commit hook.
 *
 * Pass `secrets` and/or `sca` to set that step's binary; whatever you leave out
 * is kept from the hook already installed (or defaulted: the secrets step is
 * always present, the dependency step only exists once an engine installed it).
 *
 * @param {string} root
 * @param {object} [opts]
 * @param {boolean} [opts.force=false]  Move an existing foreign pre-commit hook aside and chain to it.
 * @param {{binPath?: string, nodePath?: string}} [opts.secrets]
 * @param {{binPath?: string, nodePath?: string, binName?: string}} [opts.sca]
 * @returns {Promise<{hookFile: string, replaced: boolean, chained: boolean, localFile: string,
 *   portable: boolean, sca: string|null, migrated: boolean}>}
 */
export async function installHook(root, { force = false, secrets, sca } = {}) {
  const { dir, insideGitDir } = await resolveHooksDir(root);
  const hookFile = path.join(dir, "pre-commit");
  const localFile = path.join(dir, "pre-commit.local");

  const existing = readOrNull(hookFile);
  const local = readOrNull(localFile);
  const ours = isOurs(existing);
  const localOurs = isOurs(local);

  if (existing !== null && !ours) {
    if (!force) {
      throw new Error(
        `A pre-commit hook already exists at ${hookFile}. Re-run with --force to keep it ` +
        "(it is moved to pre-commit.local and still runs after the ubel scans), or add " +
        "`ubel-secrets --staged || exit 1` to it yourself."
      );
    }
    if (local !== null && !localOurs) {
      throw new Error(`${localFile} already exists; resolve it before using --force.`);
    }
  }

  // Settings already on disk: the hook itself wins over a stale pre-commit.local of ours.
  const prior = { ...(localOurs ? readConfig(local) : {}), ...(ours ? readConfig(existing) : {}) };

  const portable = !insideGitDir;
  const part = (given, saved, defaultName, defaults = {}) => {
    const name = given?.binName ?? saved?.name ?? defaultName;
    if (portable) return { node: "", bin: "", name };
    if (given) {
      return {
        node: realpathOrEmpty(given.nodePath ?? process.execPath),
        bin: realpathOrEmpty(given.binPath ?? defaults.binPath),
        name,
      };
    }
    if (saved) return { node: saved.node ?? "", bin: saved.bin ?? "", name };
    return { node: realpathOrEmpty(process.execPath), bin: defaults.binPath ?? "", name };
  };

  const cfg = {
    secrets: part(secrets, prior.secrets, SECRETS_BIN_NAME, { binPath: defaultSecretsBin() }),
    sca: (sca || prior.sca) ? part(sca, prior.sca, DEFAULT_SCA_BIN_NAME) : null,
  };
  if (cfg.secrets.name !== SECRETS_BIN_NAME) cfg.secrets.name = SECRETS_BIN_NAME;

  // The old layout may have left one of our own hooks sitting at pre-commit.local; the new
  // script replaces it, so it must go before a foreign hook is parked in that slot.
  const foreignMoved = existing !== null && !ours;
  let chained = local !== null && !localOurs;
  if (foreignMoved) {
    if (localOurs) fs.rmSync(localFile);
    fs.renameSync(hookFile, localFile);
    chained = true;
  }

  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(hookFile, buildHookScript(cfg), { mode: 0o755 });
  fs.chmodSync(hookFile, 0o755); // writeFile's mode is masked by umask and ignored on overwrite

  // Stale half of the old two-hook layout; its settings were merged above. (When a foreign
  // hook was just parked in that slot it was already cleared, and must not be touched.)
  if (localOurs && !foreignMoved) fs.rmSync(localFile);

  return {
    hookFile, replaced: ours, chained, localFile, portable,
    sca: cfg.sca ? cfg.sca.name : null, migrated: localOurs,
  };
}

/**
 * Remove our hook (and restore a hook that --force moved aside).
 * Refuses to touch a pre-commit hook it did not install. A pre-commit.local
 * that is itself one of ours (old two-hook layout) is deleted, not restored.
 * @returns {Promise<{hookFile: string, removed: boolean, restored: boolean}>}
 */
export async function uninstallHook(root) {
  const { dir } = await resolveHooksDir(root);
  const hookFile = path.join(dir, "pre-commit");
  const localFile = path.join(dir, "pre-commit.local");

  const existing = readOrNull(hookFile);
  if (existing === null) return { hookFile, removed: false, restored: false };

  if (!isOurs(existing)) {
    throw new Error(`${hookFile} was not installed by ubel; leaving it alone.`);
  }
  fs.rmSync(hookFile);
  let restored = false;
  const local = readOrNull(localFile);
  if (local !== null) {
    if (isOurs(local)) {
      fs.rmSync(localFile);
    } else {
      fs.renameSync(localFile, hookFile);
      restored = true;
    }
  }
  return { hookFile, removed: true, restored };
}