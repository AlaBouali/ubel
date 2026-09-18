import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const NuxtJsScanner = registerScanner({
  application: "nuxtjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        if (script.get("src", script.get("href", "")).includes("/_nuxt/entry.")) {
          const res = await httpClient.get(u + "/" + script.get("src", script.get("href", "")), { headers: hed, timeout });
          const candidates = res.text.split('(){return"').slice(1);
          for (const c of candidates) {
            const v = c.split('"')[0].trim();
            if (!["", "undefined"].includes(v.toLowerCase())) {
              version = v;
              break;
            }
          }
          break;
        }
      }
    } catch {
      version = "";
    }
    return { application: { product: "nuxt.js", vendor: "nuxtjs", version, purl: { ecosystem: "npm", name: "nuxt" } }, components: [] };
  },
  isValid: ({ soup }) => soup.findAll("script").some((s) => s.get("src", "").includes("/_nuxt/")),
});
