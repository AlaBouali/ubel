// Port of domain_scanner.py (Domain_Scanner), given verbatim by the user.

import { WebApplicationScanner } from "./webApplicationScanner.js";
import { ProductChecker } from "./productChecker.js";
import { DomainInfo, IpInfo } from "./net.js";
import { httpClient } from "./httpClient.js";
import { randomUserAgent } from "./commonVariables.js";
import { normalizeComponents } from "./normalize.js";

export class DomainScanner {
  static blackListDomains = [];
  static #blackListIpsPromise = null;

  /** Lazily resolves and caches this host's own public IP, mirroring the
   *  Python original's `black_list_ips=[IP_Info.my_ip()]` class attribute -
   *  done lazily here instead of at import time. */
  static #getBlackListIps() {
    if (!DomainScanner.#blackListIpsPromise) {
      DomainScanner.#blackListIpsPromise = IpInfo.myIp().then((ip) => (ip ? [ip] : []));
    }
    return DomainScanner.#blackListIpsPromise;
  }

  /**
   * @param {string} domain
   * @param {boolean} [skipVerification]
   * @returns {Promise<object[]>}
   */
  static async scan(domain, skipVerification = false) {
    if (!skipVerification) {
      if (DomainScanner.blackListDomains.includes(domain)) return [];
      const domainIp = await DomainInfo.getIpFromDomain(domain);
      const blackListIps = await DomainScanner.#getBlackListIps();
      if (IpInfo.ipIsPrivate(domainIp) || blackListIps.includes(domainIp)) return [];
    }

    const data = { asset: domain, type: "domain", components: [] };
    let u;
    if (!domain.includes("://")) {
      u = `https://${domain}`;
      try {
        await httpClient.get(u, { headers: { "User-Agent": randomUserAgent() }, timeout: 30 });
      } catch {
        u = `http://${domain}`;
      }
    } else {
      u = domain;
    }

    const appData = await WebApplicationScanner.scan(u);

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
