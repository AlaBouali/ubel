import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

export const OpenCartScanner = registerScanner({
  application: "opencart",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", res;
    try {
      res = await httpClient.get(u, { headers: hed, timeout });
      version = "";
    } catch {
      version = "";
    }
    let phpVersion = "";
    try {
      phpVersion = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    return {
      application: { product: "opencart", vendor: "simple_machines", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) =>
    [
      "<!-- Theme designed by TemplateTrip on OpenCart",
      "OpenCart is open source software and you are free to remove the powered by OpenCart if you want, but its generally accepted practise to make a small donation.",
    ].every((x) => data.includes(x)),
});
