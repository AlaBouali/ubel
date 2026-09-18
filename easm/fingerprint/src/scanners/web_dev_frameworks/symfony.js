import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

function getVersion(html) {
  try {
    const symfonyVersion = html.split("Read Symfony")[1].split("Docs")[0].trim();
    const phpVersion = html.split("<b>PHP version</b>")[1].trim().split("span>")[1].split("&nbsp;")[0].trim();
    return { symfonyVersion, phpVersion };
  } catch {
    return {};
  }
}

export const SymfonyScanner = registerScanner({
  application: "symfony",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = {};
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const debugToken = first.headers.get("X-Debug-Token", "");
      const res = await httpClient.get(u + "/_wdt/" + debugToken, { headers: hed, timeout });
      version = getVersion(res.text);
    } catch {
      version = {};
    }
    const cms = { product: "symfony", vendor: "sensiolabs", version: version.symfonyVersion || "" };
    const php = { product: "php", vendor: "php", version: version.phpVersion || "" };
    if (php.version === "") php.version = await fetchPhpVersionFallback(u, hed, timeout);
    return { application: cms, components: [php] };
  },
  isValid: ({ data, headers }) => {
    if (data.includes("Symfony\\Component\\HttpKernel\\Exception")) return true;
    if (headers.has("X-Symfony-Cache") || headers.has("X-Debug-Token")) return true;
    if (data.includes('<input type="hidden" name="_csrf_token" value="') || data.includes('[_csrf_token]" value="')) return true;
    if (headers.get("Set-Cookie", "").includes("symfony=")) return true;
    try {
      JSON.parse(data);
      if (data.includes('"symfony/')) return true;
    } catch {
      // not JSON - fall through
    }
    return false;
  },
});
