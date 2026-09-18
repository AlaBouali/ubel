import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

function getVersion(html) {
  try {
    const laravelVersion = html.split(',"framework_version":"')[1].split('"')[0].trim();
    const phpVersion = html.split(',"language_version":"')[1].trim().split('"')[0].trim();
    return { laravelVersion, phpVersion };
  } catch {
    return {};
  }
}

export const LaravelScanner = registerScanner({
  application: "laravel",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u) + "/_ignition/execute-solution";
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = {};
    try {
      const res = await httpClient.get(u, { headers: hed, timeout });
      version = getVersion(res.text);
    } catch {
      version = {};
    }
    const laravel = { product: "laravel", vendor: "laravel", version: version.laravelVersion || "" };
    const php = { product: "php", vendor: "php", version: version.phpVersion || "" };
    if (php.version === "") php.version = await fetchPhpVersionFallback(u, hed, timeout);
    return { application: laravel, components: [php] };
  },
  isValid: ({ headers }) => headers.get("Set-Cookie", "").includes("XSRF-TOKEN=ey"),
});
