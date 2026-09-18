import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

export const NodeRedScanner = registerScanner({
  application: "node_red",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    hed.Accept = "application/json";
    let version = "";
    try {
      const res = await httpClient.get(u + "/nodes", { headers: hed, timeout: opts.timeout ?? 10 });
      for (const x of res.json()) {
        if (x.module === "node-red") version = x.version;
      }
    } catch {
      version = "";
    }
    return { application: { product: "node-red", vendor: "nodered", version, purl: { ecosystem: "npm", name: "node-red" } }, components: [] };
  },
  isValid: ({ soup }) => {
    const jsSrcList = soup.findAll("script").map((s) => s.get("src", "")).filter((s) => s !== "");
    return JSON.stringify(jsSrcList) === JSON.stringify(["vendor/vendor.js", "red/red.min.js", "red/main.min.js"]);
  },
});
