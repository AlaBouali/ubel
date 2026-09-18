import { httpClient } from "../../core/httpClient.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

// NB: the original (aspnet_scanner.py) defines no `application` key and no
// `is_valid()`, yet the module still appended the class to the global
// scanner registry - which would make TechnologyGuesser crash the moment it
// reached this entry (it calls `.is_valid()` on every registered scanner).
// That's kept as a standalone helper instead of wired into the registry.
export const AspnetDastScanner = {
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = res.headers.get("X-AspNet-Version", "");
    } catch {
      version = "";
    }
    return { application: { product: "asp.net", vendor: "microsoft", version }, components: [] };
  },
};
