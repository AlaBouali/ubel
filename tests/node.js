import { main } from "../node/src/main.js";

const report = await main({
  projectRoot  : ".",
  engine       : "npm",
  mode         : "install",
  packages     : [],
  is_script    : true,
  save_reports : true,
  scan_os      : false,
  full_stack   : true,
  scan_node    : true,
  scan_scope   : "repository",
});

console.log(JSON.stringify(report, null, 2));