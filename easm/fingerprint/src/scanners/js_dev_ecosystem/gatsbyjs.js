import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const GatsbyJsScanner = registerScanner({
  application: "gatsbyjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    const components = [];
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      try {
        version = between(first.text, '<meta name="generator" content="Gatsby ', '"');
      } catch {
        // no generator meta tag present
      }
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        if (script.get("src", script.get("href", "")).startsWith("/framework-")) {
          const res = await httpClient.get(u + script.get("src", script.get("href", "")), { headers: hed, timeout });
          let reactVersion = "";
          try {
            reactVersion = res.text.split(',bundleType:0,version:"')[1].split('"')[0].trim();
          } catch {
            reactVersion = "";
          }
          components.push({ product: "react", vendor: "facebook", version: reactVersion, purl: { ecosystem: "npm", name: "react-dom" } });
        }
      }
    } catch {
      version = "";
    }
    return { application: { product: "gatsby", vendor: "gatsbyjs", version, purl: { ecosystem: "npm", name: "gatsby" } }, components };
  },
  isValid: ({ data }) => data.includes('<div id="___gatsby">') || data.includes('<meta name="generator" content="Gatsby '),
});
