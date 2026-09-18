import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

export const PgAdminScanner = registerScanner({
  application: "pgadmin",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let product = "pgadmin_4", version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      if (res.text.includes("Loading pgAdmin 4 v")) {
        product = "pgadmin_4";
        version = between(res.text, "Loading pgAdmin 4 v", "<").split("...")[0];
      } else {
        product = "pgadmin";
        version = between(res.text, "Loading pgAdmin v", "<").split("...")[0];
      }
    } catch {
      product = "pgadmin_4";
      version = "";
    }
    return { application: { product, vendor: "pgadmin", version }, components: [] };
  },
  isValid: ({ data }) => {
    const lower = data.toLowerCase();
    return lower.includes("<title>pgadmin") && (lower.includes("loading pgadmin") || lower.includes("'pgadmin.browser.utils'"));
  },
});
