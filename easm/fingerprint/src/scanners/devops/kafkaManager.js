import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, between } from "../../core/scannerHelpers.js";

export const KafkaManagerScanner = registerScanner({
  application: "kafka_manager",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "", backboneVersion = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = between(res.text, '"kafka-manager":"', '"');
      backboneVersion = between(res.text, '"backbonejs":"', '"');
    } catch {
      version = "";
      backboneVersion = "";
    }
    return {
      application: { product: "kafka_manager", version },
      components: [{ product: "backbone_project", vendor: "backbone", version: backboneVersion }],
    };
  },
  isValid: ({ data }) => data.includes('versions: {"backbonejs":"') && data.includes('"kafka-manager":"'),
});
