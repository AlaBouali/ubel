import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

export const JoomlaScanner = registerScanner({
  application: "joomla",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", res;
    try {
      res = await httpClient.get(u + "/language/en-GB/en-GB.xml", { headers: hed, timeout });
      version = between(res.text, "<version>", "</version>").trim();
    } catch {
      version = "";
    }
    if (version === "") {
      try {
        res = await httpClient.get(u + "/administrator/manifests/files/joomla.xml", { headers: hed, timeout });
        version = between(res.text, "<version>", "</version>").trim();
      } catch {
        version = "";
      }
    }
    try {
      res = await httpClient.get(u, { headers: hed, timeout });
      if (version === "") {
        version = between(res.text, '<meta name="generator" content="Joomla! ', undefined).split(/\s+/)[0].trim();
      }
    } catch {
      // leave version as whatever was already found
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
      application: { product: "joomla!", vendor: "joomla", version },
      components: [{ product: "php", vendor: "php", version: phpVersion }],
    };
  },
  // NB: the third marker here ("drupal-messages-fallback") is copied verbatim
  // from drupal.py in the original - harmless (Joomla pages simply never
  // contain it) but clearly a copy/paste leftover. Preserved as-is.
  isValid: ({ data }) =>
    ['<meta name="description" content="Joomla', '<meta name="generator" content="Joomla!', "<div data-drupal-messages-fallback"].some((x) => data.includes(x)),
});
