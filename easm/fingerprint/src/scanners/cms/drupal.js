import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

export const DrupalScanner = registerScanner({
  application: "drupal",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", phpVersion = "", res;
    try {
      res = await httpClient.get(u + "/CHANGELOG.txt", { headers: hed, timeout });
      const firstLine = res.text.toLowerCase().split("\n")[0];
      if (firstLine.startsWith("drupal ")) {
        try {
          version = firstLine.split("drupal ")[1].split(",")[0].trim();
        } catch {
          // leave version as ""
        }
      }
      if (version === "") {
        res = await httpClient.get(u, { headers: hed, timeout });
        try {
          version = res.text.toLowerCase().split('<meta name="generator" content="drupal')[1].split("(")[0].trim();
        } catch {
          // leave version as ""
        }
      }
      phpVersion = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    return {
      application: { product: "drupal", vendor: "drupal", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  isValid: ({ data }) =>
    ['data-drupal-link-system-path="', '<meta name="Generator" content="Drupal', "<div data-drupal-messages-fallback"].some((x) => data.includes(x)),
});
