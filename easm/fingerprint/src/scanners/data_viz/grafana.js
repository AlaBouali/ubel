import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

const MARKER = '"buildInfo":{"hideVersion":false,"version":"';

function getVersion(text) {
  try {
    return between(text, MARKER, '"');
  } catch {
    return "";
  }
}

export const GrafanaScanner = registerScanner({
  application: "grafana",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "";
    try {
      for (const path of opts.grafanaPaths || ["", "grafana"]) {
        const res = await httpClient.get(`${u}/${path}`, { headers: hed, timeout: opts.timeout ?? 10 });
        version = getVersion(res.text);
        if (version !== "") break;
      }
    } catch {
      version = "";
    }
    return { application: { product: "grafana", vendor: "grafana", version }, components: [] };
  },
  isValid: ({ data }) => data.includes(',"isGrafanaAdmin":'),
});
