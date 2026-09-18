import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const NextJsScanner = registerScanner({
  application: "nextjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    const components = [];
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        const src = script.get("src", script.get("href", ""));
        if (src.endsWith(".js")) {
          try {
            const res = await httpClient.get(u + "/" + src, { headers: hed, timeout });
            version = res.text.split('window.next={version:"')[1].split('"')[0].trim();
            break;
          } catch {
            // try the next script tag
          }
        }
        if (src.includes("/_next/static/chunks/framework")) {
          const res = await httpClient.get(u + "/" + src, { headers: hed, timeout });
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
    return { application: { product: "next.js", vendor: "vercel", version, purl: { ecosystem: "npm", name: "next" } }, components };
  },
  isValid: ({ data, soup }) => {
    if (soup.findAll("script").some((s) => s.get("src", "").includes("/_next/static/"))) return true;
    return data.includes('<div id="__next"></div>');
  },
});
