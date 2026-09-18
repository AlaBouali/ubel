import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

// NB: the original (graylog_scanner.py) registered this under application "jenkins"
// with the class name `Graylog_Scanner` - an evident copy/paste bug. Fixed here.
export const GraylogScanner = registerScanner({
  application: "graylog",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const res = await httpClient.get(u + "/api", { headers: hed, timeout: opts.timeout ?? 10 });
      version = res.json().version || "";
      if (version.includes("+")) version = version.split("+")[0];
    } catch {
      version = "";
    }
    return { application: { product: "graylog", vendor: "graylog", version }, components: [] };
  },
  isValid: ({ data, headers }) =>
    headers.has("X-Graylog-Node-ID") || data.includes('<script src="/assets/plugin/org.graylog.plugins'),
});
