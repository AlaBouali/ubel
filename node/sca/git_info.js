import { execSync } from "child_process";

/*
OUTPUT:

{
  url: string | undefined,
  branch: string | undefined,
  commit: string | undefined
}
*/

function run(cmd) {
  try {
    return execSync(cmd, {
      shell: true,
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return "";
  }
}

/**
 * CLI binaries each editor ships on PATH.
 * Cursor ships `cursor` on macOS/Linux; on Windows it may not add itself to
 * PATH at all — we fall back to `code` in that case since Cursor's CLI wrapper
 * responds to it on Windows.
 * VSCodium ships `codium` everywhere.
 */
const EDITOR_CLI = {
  cursor  : ["cursor", "code"],   // try cursor first, fall back to code (Windows)
  vscodium: ["codium"],
  vscode  : ["code"],
};

/**
 * Returns the version string of the editor identified by `editorKind`.
 * Tries each candidate CLI binary in order and returns the first that succeeds.
 * Falls back to `undefined` if none respond.
 *
 * @param {"vscode"|"cursor"|"vscodium"|string} editorKind
 * @returns {string|undefined}
 */
export function getEditorVersion(editorKind) {
  let bin="";
  if (editorKind==="vscode") {bin="code"}
  if (editorKind==="cursor") {bin="cursor"}
  if (editorKind==="vscodium") {bin="codium"}
  if (bin!==""){
    const out = run(`${bin} --version`);
    if (out) return out.split("\n")[0];
  }
  return ""
}

/**
 * @deprecated Use getEditorVersion("vscode") instead.
 * Kept so any callers that haven't been updated yet continue to work.
 */
export function getvscodeversion() {
  return getEditorVersion("vscode");
}

export function getGitVersion() {
  return run("git --version").split("\n")[0].replace("git version ", "");
}

export function getGitMetadata() {
  // check if inside a git repo
  const inside = run("git rev-parse --is-inside-work-tree");
  if (inside !== "true") {
    return {
      version: getGitVersion(),
      url: undefined,
      branch: undefined,
      commit: undefined
    };
  }

  // remote URL (origin)
  let url = run("git config --get remote.origin.url");

  // normalize ssh → https (optional but cleaner)
  if (url && url.startsWith("git@")) {
    // git@github.com:user/repo.git → https://github.com/user/repo.git
    const match = url.match(/^git@(.*?):(.*)$/);
    if (match) {
      url = `https://${match[1]}/${match[2]}`;
    }
  }

  // branch
  let branch = run("git rev-parse --abbrev-ref HEAD");

  // detached HEAD fix → use fallback
  if (branch === "HEAD") {
    branch = run("git branch --show-current") || undefined;
  }

  // latest commit
  const latest_commit = run("git rev-parse HEAD");

  return {
    version: getGitVersion(),
    url:url,
    branch:branch,
    latest_commit:latest_commit
  };
}