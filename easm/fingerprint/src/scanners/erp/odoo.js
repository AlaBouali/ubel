import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

export const OdooScanner = registerScanner({
  application: "odoo",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "", pyVersion = "";
    let res;
    try {
      res = await httpClient.post(u + "/xmlrpc/2/common", "", { headers: hed, timeout: opts.timeout ?? 10 });
      version = "";
    } catch {
      version = "";
    }
    try {
      pyVersion = res.text.toLowerCase().split("/python")[1].split("/")[0].trim();
    } catch {
      pyVersion = "";
    }
    return {
      application: { product: "odoo", vendor: "odoo", version },
      components: [],
      backend_technology: [{ product: "python", vendor: "python", version: pyVersion, tags: ["backend"] }],
    };
  },
  isValid: ({ data }) => data.includes("<title>Odoo</title>") || data.includes('odoo.__session_info__ = {"is_admin":'),
});
