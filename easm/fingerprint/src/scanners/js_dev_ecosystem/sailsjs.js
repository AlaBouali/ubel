import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

// NB: the original (sailsjs_scanner.py) reuses MeteorJS's version-extraction
// marker verbatim (`__meteor_runtime_config__`), which a Sails app will never
// emit - an apparent copy/paste leftover. Preserved as-is; detection
// (isValid, via the Sails X-Powered-By banner) is unaffected and reliable.
const METEOR_MARKER = '__meteor_runtime_config__ = JSON.parse(decodeURIComponent("%7B%22meteorRelease%22%3A%22METEOR%40';

export const SailsJsScanner = registerScanner({
  application: "sailsjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = res.text.split(METEOR_MARKER)[1].split("%")[0].trim();
    } catch {
      version = "";
    }
    return { application: { product: "sails", vendor: "sailsjs", version, purl: { ecosystem: "npm", name: "sails" } }, components: [] };
  },
  isValid: ({ headers }) => headers.get("X-Powered-By", "") === "Sails <sailsjs.org>",
});
