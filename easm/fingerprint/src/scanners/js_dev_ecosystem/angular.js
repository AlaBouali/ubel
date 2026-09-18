import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const AngularScanner = registerScanner({
  application: "angular",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "";
    try {
      const first = await httpClient.get(u, { headers: hed, timeout });
      const match = /src="(main\..*?\.js)"/.exec(first.text);
      const res = await httpClient.get(u + "/" + match[1], { headers: hed, timeout });
      version = res.text.split("{this.full=")[1].split("=new")[1].split('"')[1].split('"')[0].trim();
    } catch {
      version = "";
    }
    if (version === "") {
      try {
        const first = await httpClient.get(u, { headers: hed, timeout });
        const page = parseHTML(first.text);
        for (const script of page.findAll("script")) {
          if (script.get("src", "").includes("vendor")) {
            const res = await httpClient.get(u + "/" + script.get("src", ""), { headers: hed, timeout });
            version = res.text.split("@license Angular v")[1].split(/\s+/)[0].trim();
            break;
          }
        }
      } catch {
        version = "";
      }
    }
    return { application: { vendor: "angularjs", product: "angular", version, purl: { ecosystem: "npm", name: "%40angular/core" } }, components: [] };
  },
  isValid: ({ soup }) => soup.findAll("app-root").length > 0,
});
