import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const StrapiJsScanner = registerScanner({
  application: "strapijs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    const components = [];
    let version = "";
    try {
      const first = await httpClient.get(u + "/admin", { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        if (script.get("src", script.get("href", "")).startsWith("/admin/main.")) {
          const res = await httpClient.get(u + script.get("src", script.get("href", "")), { headers: hed, timeout });
          try {
            version = res.text.split('devDependencies:{"@strapi/strapi":"')[1].split('"')[0].trim();
          } catch {
            // version marker not present in this build
          }
          let reactVersion = "";
          try {
            reactVersion = res.text.split(',bundleType:0,version:"')[1].split('"')[0].trim();
          } catch {
            reactVersion = "";
          }
          components.push({ product: "react", vendor: "facebook", version: reactVersion, purl: { ecosystem: "npm", name: "react-dom" } });
          break;
        }
      }
    } catch {
      version = "";
    }
    return { application: { product: "strapi", vendor: "strapi", version, purl: { ecosystem: "npm", name: "strapi" } }, components };
  },
  isValid: ({ data, headers }) => {
    if (headers.get("X-Powered-By", "") === "Strapi <strapi.io>") return true;
    return data.includes("#strapi {") && data.includes(".strapi--no-js") && data.includes('<div id="strapi"></div>');
  },
});
