import { makeSimpleScanner } from "../../core/scannerHelpers.js";

const MARKER = '<meta name="description" content=""/><meta name="author" content="Portainer.io"/>';

export const PortainerScanner = makeSimpleScanner({
  application: "portainer",
  product: "portainer",
  vendor: "portainer",
  path: "/api/status",
  extractVersion: (res) => res.json().Version || "",
  isValid: ({ data }) => data.includes(MARKER),
});
