import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";
import { parseHTML } from "../../core/html.js";

function firstTable(text) {
  return parseHTML(text).find("table");
}
function tableCell(table, rowIndex, cellIndex) {
  try {
    return table.findAll("tr")[rowIndex].findAll("td")[cellIndex].text;
  } catch {
    return "";
  }
}
function getRubyVersion(text) {
  const table = firstTable(text);
  return table ? tableCell(table, 0, 1) : "";
}
function getRailsVersion(text) {
  const table = firstTable(text);
  return table ? tableCell(table, 3, 1) : "";
}
function getRubyGemsVersion(text) {
  const table = firstTable(text);
  return table ? tableCell(table, 1, 1) : "";
}

export const RubyDastScanner = registerScanner({
  application: "ruby",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "", responseText = "", responseHeaders = null;
    try {
      const res = await httpClient.get(u + "/rails/info/properties", { headers: hed, timeout: opts.timeout ?? 10 });
      responseText = res.text;
      responseHeaders = res.headers;
      version = getRailsVersion(responseText);
    } catch {
      version = "";
    }
    const backend = [
      { product: "ruby-lang", vendor: "ruby-lang", version: getRubyVersion(responseText), tags: ["backend"] },
      { product: "rubygems", vendor: "rubygems", version: getRubyGemsVersion(responseText), tags: ["backend"] },
    ];
    return {
      backend_technology: backend,
      application: { product: "ruby_on_rails", vendor: "rubyonrails", version },
      components: [],
    };
  },
  isValid: ({ headers }) => headers.has("X-Runtime"),
});
