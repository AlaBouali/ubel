import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

export const OnlyOfficeScanner = makeSimpleScanner({
  application: "onlyoffice",
  product: "document_server",
  vendor: "onlyoffice",
  extractVersion: (res) => between(res.text, '","versionstring":"', '"'),
  isValid: ({ data }) => data.includes("<title>ONLYOFFICE Docs "),
});
