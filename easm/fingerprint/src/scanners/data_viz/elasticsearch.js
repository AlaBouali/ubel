import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders } from "../../core/scannerHelpers.js";

// The original did this over a raw socket (manual GET / + optional TLS wrap)
// purely to reach the ES root endpoint - a plain HTTP(S) GET returns the same
// JSON, so that's all this does now (see the no-proxy/no-socket scope note).
export const ElasticSearchScanner = registerScanner({
  application: "elasticsearch",
  async scan(u, opts = {}) {
    const hed = buildHeaders(opts);
    let version = "";
    try {
      const target = u.startsWith("http") ? u : `https://${u}`;
      const res = await httpClient.get(target, { headers: hed, timeout: opts.timeout ?? 5 });
      version = res.json()?.version?.number || "";
    } catch {
      version = "";
    }
    return { application: { product: "elasticsearch", vendor: "elastic", version }, components: [] };
  },
  isValid: ({ data, headers }) =>
    headers.has("X-elastic-product") ||
    (data.includes('"minimum_wire_compatibility_version"') &&
      data.includes('"minimum_index_compatibility_version"') &&
      data.includes('"cluster_name"')),
});
