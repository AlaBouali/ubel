import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

// NB: the original (wazuh_scanner.py) is a copy of the Graylog scanner with the
// detection logic swapped in but the class name/product/application left as
// "Graylog_Scanner" / "jenkins" - an evident copy/paste bug. Fixed here.
export const WazuhScanner = registerScanner({
  application: "wazuh",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let opensearchVersion = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      opensearchVersion = between(res.text, "{&quot;version&quot;:&quot;", "&quot;");
    } catch {
      opensearchVersion = "";
    }
    return {
      application: { product: "wazuh", vendor: "wazuh", version: "" },
      components: [{ product: "opensearch", vendor: "amazon", version: opensearchVersion }],
    };
  },
  isValid: ({ headers }) => headers.get("osd-name", "") === "wazuh.dashboard",
});
