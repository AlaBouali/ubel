import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const VueJsScanner = registerScanner({
  application: "vuejs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        if (script.get("src", script.get("href", "")).endsWith("vue.js")) {
          const res = await httpClient.get(u + "/" + script.get("src", script.get("href", "")), { headers: hed, timeout });
          version = res.text.split("Vue.js v")[1].split(/\s+/)[0].trim();
          break;
        }
      }
    } catch {
      version = "";
    }
    return { application: { vendor: "vue.js", product: "vue", version, purl: { ecosystem: "npm", name: "vue" } }, components: [] };
  },
  isValid: ({ data, soup }) => soup.findAll("script").some((s) => s.get("src", s.get("href", "")).endsWith("vue.js") && data.includes("var app = new Vue({")),
});
