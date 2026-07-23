#!/usr/bin/env node
process.argv.splice(2, 0, "npm");
import("../sca/main.js").then(({ SCA_scan }) => SCA_scan());