import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const AngularJsScanner = registerScanner({
  application: "angularjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of page.findAll("script")) {
        if (script.get("src", "").endsWith("angular.js")) {
          const res = await httpClient.get(u + "/" + script.get("src", ""), { headers: hed, timeout });
          version = res.text.split("AngularJS v")[1].split(/\s+/)[0].trim();
          break;
        }
      }
    } catch {
      version = "";
    }
    return { application: { product: "angularjs", vendor: "angularjs", version }, components: [] };
  },
  isValid: ({ soup }) => soup.findAll("script").some((s) => s.get("src", "").endsWith("angular.js")),
});
