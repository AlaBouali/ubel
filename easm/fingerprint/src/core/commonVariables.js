// Equivalent of bane's Common_Variables: a shared user-agent pool plus the
// global registry every scanner module appends itself to. TechnologyGuesser
// walks this same list to figure out which scanner matches a response.

export const userAgentsList = [
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
  "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:125.0) Gecko/20100101 Firefox/125.0",
  "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
];

/**
 * @typedef {Object} ScannerModule
 * @property {string} application - short product key, e.g. "jenkins"
 * @property {(url: string, opts?: object) => Promise<{application: object, components: object[]}>} scan
 * @property {(ctx: {data: string, headers: import("./httpClient.js").Headers, soup: import("./html.js").Node}) => boolean} isValid
 */

/** @type {ScannerModule[]} */
export const globalScannersList = [];

export function registerScanner(scannerModule) {
  globalScannersList.push(scannerModule);
  return scannerModule;
}

export function randomUserAgent() {
  return userAgentsList[Math.floor(Math.random() * userAgentsList.length)];
}

export const CommonVariables = { userAgentsList, globalScannersList, randomUserAgent };
