#!/usr/bin/env node
process.argv.splice(2, 0, "pipx");
import("../sca/main.js").then(({ SCA_scan }) => SCA_scan());