#!/usr/bin/env node
process.argv.splice(2, 0, "pnpm");
import("../src/main.js");
