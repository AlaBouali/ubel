import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

const REQUIRED_KEYS = ["major", "minor", "gitVersion", "gitCommit", "gitTreeState", "buildDate", "goVersion", "compiler", "platform"];

export const KubernetesHttpApiScanner = registerScanner({
  application: "kubernetes",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    // version is deliberately left "" here, matching the original: it computes
    // gitVersion but never assigns it to the application record.
    let version = "", goVersion = "", gitVersion = "";
    try {
      const res = await httpClient.get(u + "/version", { headers: hed, timeout: opts.timeout ?? 10 });
      const body = res.json();
      goVersion = body.goVersion.replace("go", "");
      gitVersion = body.gitVersion;
      if (gitVersion.startsWith("v")) gitVersion = gitVersion.split("v").slice(1).join("v");
    } catch {
      goVersion = "";
      version = "";
      gitVersion = "";
    }
    return {
      application: { product: "kubernetes", vendor: "kubernetes", version },
      components: [
        { product: "go", vendor: "golang", version: goVersion },
        { product: "git", vendor: "git", version: gitVersion },
      ],
    };
  },
  isValid: ({ data, headers }) => {
    if (headers.has("X-Kubernetes-Pf-Flowschema-Uid") && headers.has("X-Kubernetes-Pf-Prioritylevel-Uid")) return true;
    try {
      const obj = JSON.parse(data);
      return REQUIRED_KEYS.every((k) => k in obj);
    } catch {
      return false;
    }
  },
});
