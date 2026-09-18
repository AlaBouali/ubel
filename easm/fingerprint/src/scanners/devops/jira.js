import { makeSimpleScanner, between } from "../../core/scannerHelpers.js";

const MARKER = '<meta name="ajs-version-number" content="';

export const JiraScanner = makeSimpleScanner({
  application: "jira",
  product: "jira",
  vendor: "atlassian",
  extractVersion: (res) => between(res.text.toLowerCase(), MARKER, '"'),
  isValid: ({ data }) => data.includes(MARKER),
});
