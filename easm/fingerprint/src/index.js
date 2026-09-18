// Public entry point. Importing this module registers every ported scanner
// into the shared registry (see core/commonVariables.js) as a side effect,
// then TechnologyGuesser/WebApplicationScanner/DomainScanner can dispatch to
// any of them.

import "./scanners/devops/index.js";
import "./scanners/collaboration/index.js";
import "./scanners/files_managers/index.js";
import "./scanners/lms/index.js";
import "./scanners/web_dev/index.js";
import "./scanners/web_dev_frameworks/index.js";
import "./scanners/databases/index.js";
import "./scanners/data_viz/index.js";
import "./scanners/erp/index.js";
import "./scanners/js_dev_ecosystem/index.js";
import "./scanners/cms/index.js";

export { DomainScanner } from "./core/domainScanner.js";
export { WebApplicationScanner } from "./core/webApplicationScanner.js";
export { BackendFingerprinter } from "./core/backendFingerprinter.js";
export { CpeParser, parseSimpleXml } from "./core/cpeParser.js";
export { ProductChecker } from "./core/productChecker.js";
export { TechnologyGuesser } from "./core/technologyGuesser.js";
export { DomainInfo, IpInfo } from "./core/net.js";
export { httpClient, request, Headers, HttpResponse } from "./core/httpClient.js";
export { parseHTML } from "./core/html.js";
export { normalizeComponent, normalizeComponents } from "./core/normalize.js";
export { buildCpeIds } from "./core/componentId.js";
export { globalScannersList, userAgentsList, randomUserAgent, registerScanner } from "./core/commonVariables.js";

// Standalone scanners that are NOT in the auto-detect registry - see their
// own files for why (aspnetDast.js / phpDast.js).
export { AspnetDastScanner } from "./scanners/web_dev/aspnetDast.js";
export { PhpDastScanner } from "./scanners/web_dev/phpDast.js";
