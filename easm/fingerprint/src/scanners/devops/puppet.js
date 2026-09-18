import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const PuppetScanner = makeSimpleScanner({
  application: "puppet",
  product: "puppet",
  vendor: "puppetlabs",
  extractVersion: (res) => res.headers.get("X-Puppet-Version", ""),
  isValid: ({ headers }) => headers.has("X-Puppet-Version"),
});
