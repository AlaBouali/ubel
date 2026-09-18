// Nearly every scanner in the original codebase follows the same shape:
// build headers -> GET one URL -> pull a version out of it -> return
// {application, components} -> and separately declare isValid(). This
// factory captures that shape so each ported scanner file can stay a short,
// readable declaration instead of ~60 lines of repeated boilerplate.
//
// Scanners with genuinely different control flow (multiple requests, POST
// bodies, component lists, etc.) are written by hand instead of through this
// helper - see the category files for which is which.

import { httpClient } from "./httpClient.js";
import { randomUserAgent, registerScanner } from "./commonVariables.js";

export function buildHeaders({ userAgent, cookie, headers = {} } = {}) {
  const hed = { "User-Agent": userAgent || randomUserAgent() };
  if (cookie) hed.Cookie = cookie;
  Object.assign(hed, headers);
  return hed;
}

export function stripTrailingSlash(u) {
  return u.endsWith("/") ? u.slice(0, -1) : u;
}

/**
 * @param {object} cfg
 * @param {string} cfg.application - registry key, e.g. "jenkins"
 * @param {string} cfg.product
 * @param {string} cfg.vendor
 * @param {string} [cfg.path] - appended to the (slash-trimmed) target URL before the GET
 * @param {(res: import("./httpClient.js").HttpResponse) => string} cfg.extractVersion
 *   Throw (or let a lookup throw) to signal "couldn't find a version" - caught and treated as "".
 * @param {(ctx: {data: string, headers: import("./httpClient.js").Headers, soup: import("./html.js").Node}) => boolean} cfg.isValid
 * @param {number} [cfg.timeout]
 */
export function makeSimpleScanner(cfg) {
  const { application, product = application, vendor, path = "", extractVersion, isValid, timeout: defaultTimeout = 10 } = cfg;

  return registerScanner({
    application,
    async scan(u, opts = {}) {
      u = stripTrailingSlash(u);
      const hed = buildHeaders(opts);
      const timeout = opts.timeout ?? defaultTimeout;
      let version = "";
      try {
        const response = await httpClient.get(u + path, { headers: hed, timeout });
        version = extractVersion(response) || "";
      } catch {
        version = "";
      }
      return { application: { product, vendor, version }, components: [] };
    },
    isValid,
  });
}

/** Pull `text.split(marker)[1].split(stop)[0]`, mirroring the very common Python idiom throughout these scanners. */
export function between(text, marker, stop) {
  const after = text.split(marker)[1];
  if (after === undefined) return "";
  return stop === undefined ? after : after.split(stop)[0];
}

/**
 * A handful of PHP-app scanners (Moodle, WordPress) fall back to probing
 * `/info.php` for a `phpinfo()` page when the `X-Powered-By` header doesn't
 * carry a PHP version. Shared here since the logic is identical in both.
 */
export async function fetchPhpVersionFallback(u, headers, timeout) {
  try {
    const res = await httpClient.get(u + "/info.php", { headers, timeout });
    return between(res.text, '<h1 class="p">PHP Version', "<").trim();
  } catch {
    return "";
  }
}
