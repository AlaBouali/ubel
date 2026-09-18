import { httpClient } from "../../core/httpClient.js";
import { registerScanner } from "../../core/commonVariables.js";
import { buildHeaders, stripTrailingSlash } from "../../core/scannerHelpers.js";

const REQUIRED_KEYS = [
  "Platform", "Components", "Version", "ApiVersion", "MinAPIVersion",
  "GitCommit", "GoVersion", "Os", "Arch", "KernelVersion", "BuildTime",
];

export const DockerHttpApiScanner = registerScanner({
  application: "docker_http_api",
  async scan(u, opts = {}) {
    u = stripTrailingSlash(u);
    const hed = buildHeaders(opts);
    let version = "", goVersion = "";
    try {
      const res = await httpClient.get(u + "/version", { headers: hed, timeout: opts.timeout ?? 10 });
      const body = res.json();
      version = body.Version;
      goVersion = body.GoVersion.replace("go", "");
    } catch {
      version = "";
      goVersion = "";
    }
    return {
      application: { product: "docker", vendor: "docker", version },
      components: [{ product: "go", vendor: "golang", version: goVersion }],
    };
  },
  isValid: ({ data }) => {
    try {
      const obj = JSON.parse(data);
      return REQUIRED_KEYS.every((k) => k in obj);
    } catch {
      return false;
    }
  },
});
