import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

export const SplunkScanner = makeSimpleScanner({
  application: "splunk",
  product: "splunk",
  vendor: "splunk",
  extractVersion: (res) => between(res.text, '" version="', '"'),
  isValid: ({ data, headers }) => {
    if (headers.get("Server", "").includes("Splunkd") || headers.get("Set-Cookie", "").includes("splunkweb_uid=")) return true;
    if (data.includes("__splunkd_partials__['/configs/conf-web'].entry[0].content.root_endpoint || '';")) return true;
    return data.includes("<title>splunkd</title>") && data.includes("<name>Splunk</name>");
  },
});
