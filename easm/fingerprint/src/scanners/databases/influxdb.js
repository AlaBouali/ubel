import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const InfluxDbScanner = makeSimpleScanner({
  application: "influxdb",
  product: "influxdb",
  vendor: "influxdata",
  extractVersion: (res) => {
    let version = res.headers.get("X-Influxdb-Version", "");
    if (version === "") version = res.json().version || "";
    return version.toLowerCase().replace("v", "");
  },
  isValid: ({ data, headers }) => {
    if (headers.has("X-Influxdb-Version")) return true;
    try {
      return JSON.parse(data).name === "influxdb";
    } catch {
      return false;
    }
  },
});
