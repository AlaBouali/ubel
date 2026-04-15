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
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"]
    }).trim();
  } catch {
    return undefined;
  }
}

export function getGitMetadata() {
  // check if inside a git repo
  const inside = run("git rev-parse --is-inside-work-tree");
  if (inside !== "true") {
    return {
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
    url:url,
    branch:branch,
    latest_commit:latest_commit
  };
}
