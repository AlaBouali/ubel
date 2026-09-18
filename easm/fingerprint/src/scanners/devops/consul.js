import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const ConsulScanner = makeSimpleScanner({
  application: "consul",
  product: "consul",
  vendor: "hashicorp",
  path: "/v1/agent/self",
  extractVersion: (res) => res.json().Config.Version,
  isValid: ({ data }) => data === "Consul Agent",
});
