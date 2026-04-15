#!/usr/bin/env node
process.argv.splice(2, 0, "bun");
import("../src/main.js");
