#!/usr/bin/env node
process.argv.splice(2, 0, "yarn");
import("../sca/main.js").then(({ main }) => main());