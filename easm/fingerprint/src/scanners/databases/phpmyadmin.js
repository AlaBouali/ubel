import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

export const PhpMyAdminScanner = registerScanner({
  application: "phpmyadmin",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    let res;
    try {
      res = await httpClient.get(u, { headers: hed, timeout });
    } catch {
      version = "";
    }
    if (res && version === "") {
      try {
        version = between(res.text, "?v=", '"').trim();
      } catch {
        version = "";
      }
    }
    if (res && version === "") {
      try {
        version = between(res.text.toLowerCase(), "<title>phpmyadmin", "<").trim().split(/\s+/)[0].trim();
      } catch {
        try {
          version = between(res.text, '",version:"', '"').trim();
        } catch {
          // leave version as ""
        }
      }
    }
    let phpVersion = "";
    try {
      phpVersion = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1];
      if (phpVersion === undefined) throw new Error("no php version token");
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    return {
      application: { product: "phpmyadmin", vendor: "phpmyadmin", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) => {
    const lower = data.toLowerCase();
    return lower.includes("<title>phpmyadmin") && ["server", "table", "db", "common_query", "opendb_url"].every((x) => lower.includes(x));
  },
});
