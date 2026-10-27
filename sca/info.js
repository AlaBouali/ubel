export const TOOL_VERSION = "0.23.0";
export const TOOL_NAME = "@arcane-spark/ubel-node";
export const TOOL_LICENSE = "SEE LICENSE IN LICENSE.md";
export const AUTHOR = "Ala Bouali";
//export const COMPANY = "Arcane-Spark";
export const GITHUB = "https://github.com/AlaBouali/ubel";

export const TOOL_NAME_ASCII = `
 ██    ██  ██████▒   ████████  ██       
 ██    ██  ███████▓  ████████  ██       
 ██    ██  ██   ▒██  ██        ██       
 ██    ██  ██    ██  ██        ██       
 ██    ██  ██   ▒██  ██        ██       
 ██    ██  ███████░  ███████   ██       
 ██    ██  ███████░  ███████   ██       
 ██    ██  ██   ▒██  ██        ██       
 ██    ██  ██    ██  ██        ██       
 ██▓  ▓██  ██   ▒██  ██        ██       
 ▒██████▒  ████████  ████████  ████████ 
  ▒████▒   ██████▓   ████████  ████████ 
                                        
`;

export const banner = `${TOOL_NAME_ASCII}

        ${TOOL_NAME} v${TOOL_VERSION}

        Author: ${AUTHOR}

        GitHub: ${GITHUB}

        License: ${TOOL_LICENSE}
`;

// ── the banner every CLI shows when it is started ───────────────────────────────────────────────────────────
// Printed once per process, whichever module gets there first: bin/*.js ask for it through runAssetCommand() (so every CLI shows it, the
// SCA / firewall family included), and the SCA engine's own calls become no-ops once it is out.
//   • stdout, like the SCA CLIs always did — except for a CLI whose stdout IS its result (ubel-agent / -cicd / -platform / -license print
//     their result as JSON): there it goes to stderr, so `ubel-agent . | jq` keeps working.
//   • not shown for --json or --quiet runs, nor when UBEL_NO_BANNER is set (CI logs).
//   • not shown by the asset-id / set-asset-id / version commands: those print a value a script may read.
const STDERR_CLIS = new Set(["ubel-agent", "ubel-cicd", "ubel-platform", "ubel-license"]);

/** Prints the banner unless it was already printed (or deliberately skipped) in this process. @returns {boolean} true when it printed */
export function printBanner({ toStderr = false } = {}) {
  if (globalThis.__ubelBannerHandled) return false;
  globalThis.__ubelBannerHandled = true;
  (toStderr ? console.error : console.log)(banner);
  return true;
}

/**
 * The startup banner of a CLI run: called by runAssetCommand() for every run that is not an asset command.
 * @param {string[]} args  the command line after the program name
 * @param {string} cli     "ubel-npm", "ubel-sast", …
 */
export function bannerForRun(args, cli) {
  const off = (process.env.UBEL_NO_BANNER || "") !== "" && process.env.UBEL_NO_BANNER !== "0";
  if (off || args.includes("--json") || args.includes("--quiet")) { globalThis.__ubelBannerHandled = true; return false; }   // handled: a later call must not print it either
  return printBanner({ toStderr: STDERR_CLIS.has(cli) });
}
