import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

export const FastApiScanner = registerScanner({
  application: "fastapi",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u) + "/_wdt/" + (opts.debugToken || "");
    const hed = buildHeaders(opts);
    let version = "";
    try {
      await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = "";
    } catch {
      version = "";
    }
    return { application: { product: "fastapi", vendor: "fastapi_project", version }, components: [] };
  },
  isValid: ({ data, headers }) => {
    if (
      data.includes('<link rel="shortcut icon" href="https://fastapi.tiangolo.com/img/favicon.png">') &&
      data.includes("url: '/openapi.json',")
    ) {
      return true;
    }
    return headers.get("Set-Cookie", "").includes("fastapi-csrf-token=");
  },
});
