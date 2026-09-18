import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash, fetchPhpVersionFallback } from "../../core/scannerHelpers.js";

function getExtensions(text) {
  const re = /\/(modules?|themes?)\/([^/]+)\//g;
  const out = [];
  let m;
  while ((m = re.exec(text))) out.push(`/${m[1]}/${m[2]}/`);
  return out;
}

async function getModule(url, name) {
  let version = "";
  try {
    const res = await httpClient.get(`${url}/modules/${name}/config.xml`);
    if (res.status_code === 200) {
      for (const line of res.text.split("\n")) {
        if (line.startsWith("version: ")) {
          version = res.text.split("version: ")[1].trim();
          break;
        }
      }
    }
  } catch {
    // module has no reachable config.xml
  }
  return { product: name, version, tags: ["prestashop module"] };
}

async function getTheme(url, name) {
  let version = "";
  try {
    const res = await httpClient.get(`${url}/themes/${name}/config/theme.yml`);
    if (res.status_code === 200) {
      version = res.text.split("<version><![CDATA[")[1].split("]")[0].trim();
    }
  } catch {
    // theme has no reachable theme.yml
  }
  return { product: name, version, tags: ["prestashop theme"] };
}

export const PrestaShopScanner = registerScanner({
  application: "prestashop",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const timeout = opts.timeout ?? 10;
    let version = "", res;
    try {
      res = await httpClient.get(u, { headers: hed, timeout });
      version = "";
    } catch {
      version = "";
    }
    let phpVersion = "";
    try {
      phpVersion = res.headers.get("X-Powered-By", "").toLowerCase().split("php/")[1] || "";
    } catch {
      version = "";
      phpVersion = "";
    }
    if (phpVersion === "") phpVersion = await fetchPhpVersionFallback(u, hed, timeout);
    const components = [{ product: "php", vendor: "php", version: phpVersion }];
    const extensions = getExtensions(res ? res.text : "");
    for (const entry of extensions) {
      const name = entry.split("/")[2];
      components.push(entry.startsWith("/module") ? await getModule(u, name) : await getTheme(u, name));
    }
    return { application: { product: "prestashop", vendor: "prestashop", version }, components };
  },
  isValid: ({ data }) => ['var prestashop = {"cart":{"', "/module/ps_"].every((x) => data.includes(x)),
});
