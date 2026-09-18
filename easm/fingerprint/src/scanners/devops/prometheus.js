import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

const MARKER = 'node_exporter_build_info{branch="HEAD",goversion="go';

export const PrometheusScanner = registerScanner({
  application: "prometheus",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const components = [];
    let version = "";
    try {
      const res = await httpClient.get(u + "/metrics", { headers: hed, timeout: opts.timeout ?? 10 });
      const goVersion = between(res.text, MARKER, '"');
      version = res.text.split(MARKER)[1].split('",version="')[1].split('"')[0];
      components.push({ product: "go", vendor: "golang", version: goVersion });
    } catch {
      version = "";
      components.push({ product: "go", vendor: "golang", version: "" });
    }
    return { application: { product: "prometheus", vendor: "prometheus", version }, components };
  },
  isValid: ({ data }) =>
    data === '<html>\n\t\t\t<head><title>Node Exporter</title></head>\n\t\t\t<body>\n\t\t\t<h1>Node Exporter</h1>\n\t\t\t<p><a href="/metrics">Metrics</a></p>\n\t\t\t</body>\n\t\t\t</html>' ||
    data.includes(MARKER),
});
