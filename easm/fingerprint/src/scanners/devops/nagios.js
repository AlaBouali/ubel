import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const NagiosScanner = makeSimpleScanner({
  application: "nagios",
  product: "nagios",
  vendor: "nagios",
  extractVersion: () => "",
  isValid: ({ headers }) => headers.get("WWW-Authenticate", "").includes('realm="Nagios'),
});
