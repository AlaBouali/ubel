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
  const t = firstTable(text);
  return t ? tableCell(t, 0, 1) : "";
}
function getRailsVersion(text) {
  const t = firstTable(text);
  return t ? tableCell(t, 3, 1) : "";
}
function getRubyGemsVersion(text) {
  const t = firstTable(text);
  return t ? tableCell(t, 1, 1) : "";
}

export const ShopifyScanner = registerScanner({
  application: "shopify",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", railsPropsText = "";
    try {
      await httpClient.get(u, { headers: hed, timeout });
      version = "";
    } catch {
      version = "";
    }
    let railsVersion = "";
    try {
      const res = await httpClient.get(u + "/rails/info/properties", { headers: hed, timeout });
      railsPropsText = res.text;
      railsVersion = getRailsVersion(railsPropsText);
    } catch {
      railsVersion = "";
    }
    const components = [
      { product: "ruby-lang", vendor: "ruby-lang", version: getRubyVersion(railsPropsText), tags: ["backend"] },
      { product: "rubygems", vendor: "rubygems", version: getRubyGemsVersion(railsPropsText), tags: ["backend"] },
      { product: "ruby_on_rails", vendor: "rubyonrails", version: railsVersion },
    ];
    return { application: { product: "shopify", version }, components };
  },
  isValid: ({ data }) => ["var Shopify = Shopify || {};", 'Shopify.shop = "'].every((x) => data.includes(x)),
});
