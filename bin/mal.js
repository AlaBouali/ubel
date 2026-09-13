#!/usr/bin/env node
const args = process.argv.slice(2);
if (!args.includes("--help") && !args.includes("-h")) {
  process.argv.splice(2, 0, "malware");
}
import("../sast/main.js").then(({ main }) => main());