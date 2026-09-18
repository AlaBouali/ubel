import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

const MARKER = '<a href="http://supervisord.org">Supervisor</a> <span>';

export const SupervisorScanner = makeSimpleScanner({
  application: "supervisor",
  product: "supervisor",
  vendor: "supervisord",
  extractVersion: (res) => between(res.text, MARKER, "<"),
  isValid: ({ data }) => data.includes("<title>Supervisor Status</title>") && data.includes('<a href="http://supervisord.org">Supervisor</a>'),
});
