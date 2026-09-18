import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const GraphQLScanner = makeSimpleScanner({
  application: "graphql",
  product: "graphql",
  vendor: "graphql",
  extractVersion: () => "",
  isValid: ({ data, headers }) => {
    if (headers.has("x-graphql-exception-statuses")) return true;
    return (
      data.includes('{"errors":[{"message":"Must provide query string."}]}') ||
      data.includes('{"errors":[{"message":"Either the parameter query or the parameter id has to be set."')
    );
  },
});
