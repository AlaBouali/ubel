import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

export const NexusScanner = registerScanner({
  application: "nexus",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      const soup = parseHTML(res.text);
      for (const script of soup.findAll("script")) {
        try {
          version = script.get("src", "").split("?_v=")[1].split("&")[0];
          break;
        } catch {
          // try the next script tag
        }
      }
    } catch {
      version = "";
    }
    return {
      application: { product: "nexus", vendor: "sonatype", version },
      components: [{ product: "maven", vendor: "apache", version: "" }],
    };
  },
  isValid: ({ data }) => data.includes('<meta name="description" content="Nexus Repository Manager"/>'),
});
