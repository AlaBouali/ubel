import { httpClient } from "../../core/httpClient.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

// Same situation as AspnetDastScanner - no `application`/`is_valid` in the
// original, so it's kept out of the auto-detect registry (see aspnetDast.js).
export const PhpDastScanner = {
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout });
      version = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
    }
    if (version === "") {
      try {
        const res = await httpClient.get(u + "/info.php", { headers: hed, timeout });
        version = between(res.text, '<h1 class="p">PHP Version', "<").trim();
      } catch {
        version = "";
      }
    }
    return { application: { product: "php", vendor: "php", version }, components: [] };
  },
};
