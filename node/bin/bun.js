#!/usr/bin/env node
process.argv.splice(2, 0, "bun");
import("../sca/main.js").then(({ main }) => main());