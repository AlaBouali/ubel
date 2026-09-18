import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

const MARKER = '__meteor_runtime_config__ = JSON.parse(decodeURIComponent("%7B%22meteorRelease%22%3A%22METEOR%40';

export const MeteorJsScanner = registerScanner({
  application: "meteorjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = res.text.split(MARKER)[1].split("%")[0].trim();
    } catch {
      version = "";
    }
    return { application: { product: "meteor", vendor: "meteor", version, purl: { ecosystem: "npm", name: "meteor" } }, components: [] };
  },
  isValid: ({ data }) => data.includes('__meteor_runtime_config__ = JSON.parse(decodeURIComponent("'),
});
