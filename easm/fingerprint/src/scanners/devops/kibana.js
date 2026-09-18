import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

const MARKER = '<kbn-injected-metadata data="{&quot;version&quot;:&quot;';

export const KibanaScanner = makeSimpleScanner({
  application: "kibana",
  product: "kibana",
  vendor: "elastic",
  extractVersion: (res) => between(res.text, MARKER, "&quot;"),
  isValid: ({ data, headers }) =>
    (headers.has("kbn-name") && headers.has("kbn-xpack-sig")) ||
    (data.includes('<kbn-injected-metadata data="') && data.includes('<kbn-csp data="')),
});
