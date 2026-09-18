import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const JenkinsScanner = makeSimpleScanner({
  application: "jenkins",
  product: "jenkins",
  vendor: "jenkins",
  extractVersion: (res) => res.headers.get("X-Jenkins", ""),
  isValid: ({ headers }) => headers.has("X-Jenkins"),
});
