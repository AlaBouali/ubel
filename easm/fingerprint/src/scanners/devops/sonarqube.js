import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const SonarQubeScanner = makeSimpleScanner({
  application: "sonarqube",
  product: "sonarqube",
  vendor: "sonarsource",
  path: "/api/server/version",
  extractVersion: (res) => res.text.trim(),
  isValid: ({ data }) =>
    data.includes('<meta name="application-name" content="SonarQube" />') ||
    (data.includes("window.instance = 'SonarQube';") && data.includes("window.official = true;")),
});
