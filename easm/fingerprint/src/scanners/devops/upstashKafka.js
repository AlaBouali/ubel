import { makeSimpleScanner } from "../../core/scannerHelpers.js";

export const UpstashKafkaServerScanner = makeSimpleScanner({
  application: "upstash_kafka",
  product: "kafka_server",
  vendor: "upstash",
  extractVersion: (res) => res.json().version,
  isValid: ({ data, headers }) => {
    if (headers.get("server", "").includes("Upstash Kafka Server")) return true;
    try {
      const obj = JSON.parse(data);
      const keys = Object.keys(obj);
      return keys.length === 4 && ["name", "version", "buildTime", "commit"].every((k) => keys.includes(k));
    } catch {
      return false;
    }
  },
});
