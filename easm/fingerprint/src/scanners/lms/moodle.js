import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

function getVersion(text) {
  for (const line of text.split("\n")) {
    if ((line.match(/===/g) || []).length === 2) {
      return line.split("===")[1].split("===")[0].trim();
    }
  }
  return "";
}

const MOODLE_PATHS = ["", "moodle"];
const VERSION_PATHS = ["/lib/upgrade.txt", "/question/upgrade.txt"];

export const MoodleScanner = registerScanner({
  application: "moodle",
  async scan(u, opts = {}) {
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", phpVersion = "", lastResponse = null;
    try {
      outer: for (const rootPath of opts.moodlePaths || MOODLE_PATHS) {
        for (const path of opts.versionsPaths || VERSION_PATHS) {
          lastResponse = await httpClient.get(`${u}/${rootPath}${path}`, { headers: hed, timeout });
          version = getVersion(lastResponse.text);
          if (version !== "") break outer;
        }
      }
      phpVersion = lastResponse.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    return {
      application: { product: "moodle", vendor: "moodle", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) => data.includes('<meta name="keywords" content="moodle') || data.includes("/moodle/"),
});
