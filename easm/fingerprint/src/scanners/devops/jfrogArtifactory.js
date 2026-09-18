import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const JFrogArtifactoryScanner = makeSimpleScanner({
  application: "jfrog_artifactory",
  product: "artifactory",
  vendor: "jfrog",
  extractVersion: () => "",
  isValid: ({ data, headers, soup }) => {
    if (headers.has("X-Artifactory-Id") || data.includes('<meta http-equiv="refresh" content="0;URL=/artifactory">')) return true;
    return soup.findAll("script").some((s) => s.get("src", "").includes("artifactory_core"));
  },
});
