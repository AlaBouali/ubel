import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

export const NextcloudScanner = makeSimpleScanner({
  application: "nextcloud",
  product: "nextcloud_server",
  vendor: "nextcloud",
  path: "/login",
  extractVersion: (res) => between(res.text, '","versionstring":"', '"'),
  isValid: ({ data }) => data.includes('<meta property="og:site_name" content="Nextcloud"/>'),
});
