import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

// get_version() in the original always returns "" - the debug-toolbar version
// extraction was apparently never finished. Preserved as-is.
function getVersion() {
  return "";
}

export const DjangoScanner = registerScanner({
  application: "django",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u) + "/_wdt/" + (opts.debugToken || "");
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = getVersion(res.text);
    } catch {
      version = "";
    }
    return { application: { product: "django", vendor: "django_project", version }, components: [] };
  },
  isValid: ({ data }) => data.includes('<input type="hidden" name="csrfmiddlewaretoken" value="'),
});
