import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

const MARKER = '<div class="login_table_title center" title="Dolibarr';

export const DolibarrScanner = registerScanner({
  application: "dolibarr",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", phpVersion = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout });
      version = between(res.text, MARKER, '"').trim();
      phpVersion = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    return {
      application: { product: "dolibarr", vendor: "dolibarr", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) =>
    data.includes(MARKER) ||
    (data.includes("<!-- Includes CSS for Dolibarr theme -->") && data.includes("<!-- Includes JS of Dolibarr -->")),
});
