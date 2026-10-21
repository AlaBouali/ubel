// Port of domain_scanner.py (Domain_Scanner), given verbatim by the user.

import { WebApplicationScanner } from "./webApplicationScanner.js";
import { ProductChecker } from "./productChecker.js";
import { DomainInfo, IpInfo, extractHostname, runWithAddressGuard } from "./net.js";
import { httpClient } from "./httpClient.js";
import { randomUserAgent } from "./commonVariables.js";
import { normalizeComponents } from "./normalize.js";

export class DomainScanner {
  static blackListDomains = [];

  /**
   * @param {string} domain
   * @param {boolean} [skipVerification]
   * @param {object} [opts]
   * @param {string} [opts.cookie]   sent as the Cookie header on every request this
   *   scan makes, including the initial scheme-detection probe below.
   * @param {object} [opts.headers] additional custom headers, merged in on top of
   *   (and able to override) the default User-Agent/Cookie.
   * @returns {Promise<object[]>}
   */
  static async scan(domain, skipVerification = false, opts = {}) {
    const { cookie = null, headers = {} } = opts;

    if (!skipVerification) {
      // `domain` may be a bare host, "host:port", or a full URL — classify the HOSTNAME it
      // names (parsed the same way the HTTP client parses it), not the raw string. A target
      // we can't extract a host from is refused: we can't say what it would contact.
      const host = extractHostname(domain);
      if (!host) return [];
      if (DomainScanner.blackListDomains.includes(domain) || DomainScanner.blackListDomains.includes(host)) return [];
      // Every address the name resolves to, IPv4 and IPv6. Private ranges, plus any address
      // bound to one of this machine's own interfaces (checked locally - no third-party
      // "what is my IP" lookup). This early exit only avoids pointless work: the enforcement
      // is the connect-time guard below, which re-validates whatever address each socket
      // actually uses.
      const addrs = await DomainInfo.resolveAll(host);
      if (addrs.some((ip) => IpInfo.isBlocked(ip))) return [];
    }

    // With verification on, every request this scan makes - the scheme probe, each fingerprint
    // probe, every redirect hop - is checked against the same restriction when it connects
    // (see runWithAddressGuard in ./net.js).
    return runWithAddressGuard(!skipVerification, () => DomainScanner.#scanTarget(domain, cookie, headers));
  }

  static async #scanTarget(domain, cookie, headers) {
    const data = { asset: domain, type: "domain", url: null, components: [] };

    // The same Cookie/custom headers a caller supplied apply here too, not just
    // to WebApplicationScanner.scan() below - otherwise a domain that behaves
    // differently unauthenticated (e.g. redirects to a login page on one scheme
    // but not the other) could have its scheme picked off the wrong response.
    const probeHeaders = { "User-Agent": randomUserAgent() };
    if (cookie) probeHeaders.Cookie = cookie;
    Object.assign(probeHeaders, headers);

    let u;
    if (!domain.includes("://")) {
      u = `https://${domain}`;
      try {
        await httpClient.get(u, { headers: probeHeaders, timeout: 30 });
      } catch {
        u = `http://${domain}`;
      }
    } else {
      u = domain;
    }

    // The scheme chosen above is the one fact every downstream check (misconfig,
    // TLS, security headers, secrets crawl) needs; `asset` is just the input string.
    data.url = u;

    const appData = await WebApplicationScanner.scan(u, { cookie, headers });

    for (const component of appData.backend || []) {
      if (!ProductChecker.productExistsInList(component, data.components)) data.components.push(component);
    }
    for (const component of appData.components || []) {
      if (!ProductChecker.productExistsInList(component, data.components)) data.components.push(component);
    }
    for (const component of appData.server || []) {
      if (!ProductChecker.productExistsInList(component, data.components)) data.components.push(component);
    }
    if (appData.application && Object.keys(appData.application).length > 0) {
      if (!ProductChecker.productExistsInList(appData.application, data.components)) {
        data.components.push(appData.application);
      }
    }

    // Final output shape: each detected package as {Id, Name, Version, Host, Port}
    data.components = normalizeComponents(data.components);

    return [data];
  }
}