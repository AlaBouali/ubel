import { parseHTML } from "./html.js";
import { globalScannersList } from "./commonVariables.js";

async function defaultScan() {
  return { application: {}, components: [] };
}

export class TechnologyGuesser {
  /**
   * @param {string} responseText
   * @param {import("./httpClient.js").Headers} headers
   * @returns {[string, Function]} [applicationKey, scanFn] - the first registered scanner
   *   whose isValid() matches, or ["", defaultScan] if nothing does.
   */
  static analyze(responseText, headers) {
    const soup = parseHTML(responseText || "");
    for (const scannerModule of globalScannersList) {
      if (scannerModule.isValid({ data: responseText || "", headers, soup })) {
        return [scannerModule.application, scannerModule.scan];
      }
    }
    return ["", defaultScan];
  }
}
