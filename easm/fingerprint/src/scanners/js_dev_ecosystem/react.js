import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const ReactJsScanner = registerScanner({
  application: "reactjs",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      let base = first.url;
      if (base.endsWith("/")) base = base.slice(0, -1);
      const page = parseHTML(first.text);
      for (const script of [...page.findAll("script"), ...page.findAll("link")]) {
        try {
          let jsPath = script.get("src", "");
          if (!jsPath) jsPath = script.get("href", "");
          if (!jsPath) continue;
          if (!jsPath) continue;
          if (!jsPath.startsWith("/")) jsPath = "/" + jsPath;
          const res = await httpClient.get(base + jsPath, { headers: hed, timeout });
          const body = res.text ?? res.body ?? "";
          const match = body.match(/bundleType:0,version:"([^"]+)"/);
          if (match && match[1] && match[1]!==null) {
            version = match[1];
            break;                                  // only stop once we actually found it
          }
        } catch (err) {
          // try the next script tag
        }
      }
    } catch (err) {
      console.error(`[*] Failed to scan ${u} — ${err.message}`);
      version = "";
    }
    return { application: { product: "react", vendor: "facebook", version, purl: { ecosystem: "npm", name: "react-dom" } }, components: [] };
  },
  isValid: ({ data, soup }) => {
    for (const meta of soup.findAll("meta")) {
      if (meta.get("content", "").toLowerCase().includes("created using create-react-app")) return true;
    }
    const jsSrcList = soup.findAll("script").map((s) => s.get("src", "")).filter((s) => s !== "");
    const isPotentialReactjs = jsSrcList.some((f) => f.includes("static/js/main."));
    if (data.includes('<div id="root"><') && isPotentialReactjs) return true;
    const rootDivs = soup.findAll("div", { id: "root" });
    if (rootDivs.length > 0) {
      const div = rootDivs[0];
      if (div.text.trim() === "") return true;
    }
    return soup.findAll("script").some((s) => s.get("src", "").endsWith("react.js"));
  },
});