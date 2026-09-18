// Minimal HTTP(S) client built on Node's stdlib http/https modules only.
// Mirrors the subset of Python's `requests` behaviour the original scanners relied on:
// headers, timeout, TLS verification disabled, redirect following,
// .text / .json() / .headers.get(name, default) / .status_code / .url
//
// Deliberately has NO proxy support and NO raw-socket layer - fingerprinting only.

import http from "node:http";
import https from "node:https";
import { URL } from "node:url";
import zlib from "node:zlib";

export function decompress(buf, encoding) {
  const enc = String(encoding || "").toLowerCase().trim();
  if (!enc || enc === "identity") return buf;
  try {
    if (enc.includes("gzip"))    return zlib.gunzipSync(buf);
    if (enc.includes("deflate")) return zlib.inflateSync(buf);
    if (enc.includes("br"))      return zlib.brotliDecompressSync(buf);
  } catch {
    // fall through and return the raw buffer
  }
  return buf;
}

/** Case-insensitive header lookup, mirrors requests' `response.headers.get(name, default)`. */
export class Headers {
  constructor(raw = {}) {
    this._map = new Map();
    for (const [k, v] of Object.entries(raw || {})) {
      this._map.set(String(k).toLowerCase(), Array.isArray(v) ? v.join(", ") : String(v ?? ""));
    }
  }
  get(name, fallback = "") {
    const v = this._map.get(String(name).toLowerCase());
    return v === undefined ? fallback : v;
  }
  has(name) {
    return this._map.has(String(name).toLowerCase());
  }
  /** Plain object form, e.g. for passing into Backend_Fingerprinter.analyze() */
  toObject() {
    return Object.fromEntries(this._map.entries());
  }
}

export class HttpResponse {
  constructor({ statusCode, headers, body, url }) {
    this.status_code = statusCode;
    this.headers = new Headers(headers);
    this.url = url;
    this._body = body;
  }
  get text() {
    return this._body.toString("utf-8");
  }
  json() {
    return JSON.parse(this.text);
  }
}

/**
 * @param {string} targetUrl
 * @param {object} [opts]
 * @param {"GET"|"POST"} [opts.method]
 * @param {object} [opts.headers]
 * @param {string} [opts.data] request body for POST
 * @param {number} [opts.timeout] seconds - matches the `timeout=` convention used throughout the original scanners
 * @param {number} [opts.maxRedirects]
 * @returns {Promise<HttpResponse>}
 */
export function request(targetUrl, opts = {}) {
  const { method = "GET", headers = {}, data = null, timeout = 20, maxRedirects = 5 } = opts;

  return new Promise((resolve, reject) => {
    let redirectsLeft = maxRedirects;

    const doRequest = (currentUrl) => {
      let parsed;
      try {
        parsed = new URL(currentUrl);
      } catch (e) {
        reject(e);
        return;
      }
      const lib = parsed.protocol === "https:" ? https : http;
      const reqOptions = {
        hostname: parsed.hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers,
        timeout: Math.max(1, timeout) * 1000,
        // verify=False equivalent - scanners intentionally probe self-signed/expired certs
        rejectUnauthorized: false,
      };

      const req = lib.request(reqOptions, (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          const status = res.statusCode || 0;
          if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && redirectsLeft > 0) {
            redirectsLeft -= 1;
            doRequest(new URL(res.headers.location, currentUrl).toString());
            return;
          }
          const raw = Buffer.concat(chunks);
          const body = decompress(raw, res.headers["content-encoding"]);
          resolve(new HttpResponse({
            statusCode: status,
            headers: res.headers,
            body,
            url: currentUrl,
          }));
        });
      });

      req.on("timeout", () => req.destroy(new Error(`Request timed out after ${timeout}s`)));
      req.on("error", reject);

      if (data) req.write(data);
      req.end();
    };

    doRequest(targetUrl);
  });
}

export const httpClient = {
  get: (url, opts = {}) => request(url, { ...opts, method: "GET" }),
  post: (url, data, opts = {}) => request(url, { ...opts, method: "POST", data }),
};
