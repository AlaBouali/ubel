import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

export const SpringBootScanner = registerScanner({
  application: "spring_boot",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    const components = [];
    let version = "";
    try {
      const res = await httpClient.get(u, { headers: hed, timeout: opts.timeout ?? 10 });
      version = "";
      if (res.headers.get("Set-Cookie", "") !== "" || (opts.headers?.["WWW-Authenticate"] || "").includes('Basic realm="Spring Security')) {
        components.push({ product: "spring_security", vendor: "vmware", version });
      }
    } catch {
      version = "";
    }
    return { application: { product: "spring_boot", vendor: "vmware", version }, components };
  },
  isValid: ({ headers }) => {
    const setCookie = headers.get("Set-Cookie", "");
    if (setCookie.includes("JSESSIONID=")) {
      if (setCookie.split("JSESSIONID=")[1].split(";")[0].length === 32) return true;
    }
    if (setCookie.includes("SPRING_SECURITY_REMEMBER_ME_COOKIE_CRA=")) return true;
    return headers.get("WWW-Authenticate", "").includes('Basic realm="Spring Security');
  },
});
