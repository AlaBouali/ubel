// Port of web_general/web.py (Web_Application_Scanner).

import { httpClient, Headers } from "./httpClient.js";
import { randomUserAgent } from "./commonVariables.js";
import { BackendFingerprinter } from "./backendFingerprinter.js";
import { TechnologyGuesser } from "./technologyGuesser.js";
import { normalizeComponents } from "./normalize.js";

const DIRECTORIES_LIST = [
  "/",
  "/health",
  "/composer.json",
  "/graphql",
  "/docs",
  "/explorer",
  "/version",
  "/admin",
  "/moodle",
  "/metrics",
  "/artifactory/webapp/",
  "/browser",
  "/phpmyadmin",
  "/web/login",
];

export class WebApplicationScanner {
  static directoriesList = DIRECTORIES_LIST;

  /**
   * @param {string} domain - bare host, or a full URL with scheme
   * @param {object} [opts]
   * @param {string} [opts.userAgent]
   * @param {boolean} [opts.startFromRoot]
   * @param {string} [opts.cookie]
   * @param {object} [opts.headers]
   * @param {number} [opts.timeout]
   * @param {boolean} [opts.enableDast]
   */
  static async scan(domain, opts = {}) {
    const { userAgent = null, startFromRoot = true, cookie = null, headers = {}, timeout = 20, enableDast = false } = opts;
    const us = userAgent || randomUserAgent();
    const hed = { "User-Agent": us };

    let u;
    if (!domain.includes("://")) {
      u = `https://${domain}`;
      try {
        await httpClient.get(u, { headers: hed, timeout });
      } catch {
        u = `http://${domain}`;
      }
    } else {
      u = domain;
    }

    let directoriesList;
    if (startFromRoot) {
      if (u.endsWith("/")) u = u.slice(0, -1);
      directoriesList = WebApplicationScanner.directoriesList;
    } else {
      directoriesList = [""];
    }

    const host = u.split("://")[1].split("/")[0].split(":")[0];
    let port;
    if (u.startsWith("http://")) {
      port = parseInt(u.split("://")[1].split("/")[0].split(":")[1], 10) || 80;
    } else {
      port = parseInt(u.split("://")[1].split("/")[0].split(":")[1], 10) || 443;
    }

    if (cookie) hed.Cookie = cookie;
    Object.assign(hed, headers);

    let responseText = "";
    let responseHeaders = new Headers();
    let guessedTechnology = ["", async () => ({ application: {}, components: [] })];

    for (const directory of directoriesList) {
      try {
        const responseFull = await httpClient.get(u + directory, { headers: hed, timeout });
        if (responseFull.url.startsWith("http://")) {
          port = parseInt(responseFull.url.split("://")[1].split("/")[0].split(":")[1], 10) || 80;
        } else {
          port = parseInt(responseFull.url.split("://")[1].split("/")[0].split(":")[1], 10) || 443;
        }
        responseText = responseFull.text;
        responseHeaders = responseFull.headers;
      } catch {
        // matches the original's bare `pass` - probe the next directory
      }
      guessedTechnology = TechnologyGuesser.analyze(responseText, responseHeaders);
      if (guessedTechnology[0] !== "") break;
    }

    const responseFull = await httpClient.get(u, { headers: hed, timeout });
    const backendFingerprints = BackendFingerprinter.analyze(responseFull.headers);

    const data = await guessedTechnology[1](u, { timeout, enableDast, headers, cookie, userAgent });

    backendFingerprints.backend = [...backendFingerprints.backend, ...(data.backend_technology || [])];

    const products = [];
    for (const server of backendFingerprints.server) products.push(server);
    for (const backend of backendFingerprints.backend) products.push(backend);

    if (data.application && Object.keys(data.application).length > 0) {
      data.application.source = host;
      products.push(data.application);
    }
    for (const component of data.components || []) {
      component.source = host;
      products.push(component);
    }
    for (const product of products) {
      product.source = host;
      product.port = port;
    }

    return {
      host,
      application_type: guessedTechnology[0],
      server: backendFingerprints.server,
      backend: backendFingerprints.backend,
      application: data.application,
      components: data.components,
      products,
      detected_packages: normalizeComponents(products),
    };
  }
}