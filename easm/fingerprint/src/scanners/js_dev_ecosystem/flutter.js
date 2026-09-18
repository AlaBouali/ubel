import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const FlutterScanner = registerScanner({
  application: "flutter",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        if (script.get("src", script.get("href", "")).endsWith("flutter.js") && first.text.includes("main.dart.js")) {
          const res = await httpClient.get(u + "/" + script.get("src", script.get("href", "")), { headers: hed, timeout });
          // NB: the original searches flutter.js for the marker "Vue.js v" -
          // an apparent copy/paste leftover from the Vue scanner. It will
          // essentially never match; preserved as-is rather than guessed at.
          break;
        }
      }
    } catch {
      version = "";
    }
    return { application: { product: "flutter", vendor: "flutter", version }, components: [] };
  },
  isValid: ({ data, soup }) => soup.findAll("script").some((s) => s.get("src", "").endsWith("flutter.js") && data.includes("main.dart.js")),
});
