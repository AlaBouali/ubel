import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

const LEGACY_VERSIONS = { "2006-": "1.9", 2013: "1.8", 2012: "1.7", 2011: "1.6", 2010: "1.5", 2009: "1.4.0", 2008: "1.3" };

export const MagentoScanner = registerScanner({
  application: "magento",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const res = await httpClient.get(u + "/magento_version", { headers: hed, timeout });
      version = res.text.split("Magento/")[1].split(/\s+/)[0].trim();
    } catch {
      version = "";
    }
    if (version === "") {
      try {
        const res = await httpClient.get(u + "/skin/frontend/default/default/css/styles.css", { headers: hed, timeout });
        for (const [year, ver] of Object.entries(LEGACY_VERSIONS)) {
          if (res.text.includes(`Copyright (c) ${year}`)) {
            version = ver;
            break;
          }
        }
      } catch {
        version = "";
      }
    }
    let res;
    try {
      res = await httpClient.get(u, { headers: hed, timeout });
    } catch {
      // fall through - php version lookup below will fail gracefully too
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
      application: { product: "magento", vendor: "magento", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) => ["Equity Facebook Pixel for Magento -->", "/skin/frontend/"].some((x) => data.includes(x)),
});
