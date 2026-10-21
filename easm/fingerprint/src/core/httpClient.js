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
import { addressGuardActive, assertHostAllowed, guardedLookup, stripBrackets } from "./net.js";

// Default ceilings for one response. A body larger than this is aborted while it
// streams in (rather than buffered whole and rejected afterwards), and so is a
// compressed body that inflates past it.
const DEFAULT_MAX_BYTES = 50 * 1024 * 1024;

export function decompress(buf, encoding, maxOutputLength = DEFAULT_MAX_BYTES) {
  const enc = String(encoding || "").toLowerCase().trim();
  if (!enc || enc === "identity") return buf;
  const zopts = { maxOutputLength };
  try {
    if (enc.includes("gzip"))    return zlib.gunzipSync(buf, zopts);
    if (enc.includes("deflate")) return zlib.inflateSync(buf, zopts);
    if (enc.includes("br"))      return zlib.brotliDecompressSync(buf, zopts);
  } catch {
    // fall through and return the raw buffer
  }
  return buf;
}

/** Case-insensitive header lookup, mirrors requests' `response.headers.get(name, default)`. */
export class Headers {
  constructor(raw = {}) {
    this._map = new Map();
    // Set-Cookie is the one header that must never be comma-joined: an Expires
    // attribute ("Wed, 21 Oct 2026 ...") contains commas of its own, so a joined
    // string cannot be split back reliably. Keep the original values separately.
    this._setCookie = [];
    for (const [k, v] of Object.entries(raw || {})) {
      const key = String(k).toLowerCase();
      this._map.set(key, Array.isArray(v) ? v.join(", ") : String(v ?? ""));
      if (key === "set-cookie") {
        this._setCookie = (Array.isArray(v) ? v : [v]).filter((x) => x != null && x !== "").map(String);
      }
    }
  }
  get(name, fallback = "") {
    const v = this._map.get(String(name).toLowerCase());
    return v === undefined ? fallback : v;
  }
  has(name) {
    return this._map.has(String(name).toLowerCase());
  }
  /** Every Set-Cookie header value, one entry per cookie, exactly as received (never comma-joined). */
  getSetCookie() {
    return [...this._setCookie];
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
 * @param {number} [opts.timeout] seconds of socket inactivity - matches the `timeout=` convention used throughout the original scanners
 * @param {number} [opts.totalTimeout] seconds for the whole request incl. redirects and body (default 5x timeout);
 *   `timeout` alone never fires on a server that keeps trickling bytes
 * @param {number} [opts.maxBytes] abort once the response body exceeds this many bytes (default 50 MiB)
 * @param {number} [opts.maxRedirects]
 * @returns {Promise<HttpResponse>} always settles: a dropped connection, a body that stops short of its
 *   Content-Length, an oversized body, a malformed redirect target or the overall deadline either resolve
 *   or reject - none of them throw out of an event handler or leave the promise pending.
 */
export function request(targetUrl, opts = {}) {
  const {
    method = "GET", headers = {}, data = null, timeout = 20, maxRedirects = 5,
    maxBytes = DEFAULT_MAX_BYTES,
  } = opts;
  const totalTimeout = opts.totalTimeout ?? Math.max(1, timeout) * 5;
  // Read once, here, in the caller's async context (see runWithAddressGuard in net.js) and
  // reused for every redirect hop — response callbacks don't reliably carry that context.
  const guardOn = addressGuardActive();

  return new Promise((resolve, reject) => {
    let redirectsLeft = maxRedirects;
    let settled = false;
    let activeReq = null;
    let deadline = null;

    const fail = (err) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      try { if (activeReq) activeReq.destroy(); } catch { /* already gone */ }
      reject(err instanceof Error ? err : new Error(String(err)));
    };
    const done = (response) => {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      resolve(response);
    };

    deadline = setTimeout(() => fail(new Error(`Request exceeded ${totalTimeout}s overall`)), totalTimeout * 1000);

    const doRequest = (currentUrl) => {
      let parsed;
      try {
        parsed = new URL(currentUrl);
      } catch (e) {
        fail(e);
        return;
      }
      if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
        fail(new Error(`Unsupported protocol ${parsed.protocol}`));
        return;
      }
      // NOTE: the scheme in the URL is authoritative. Do not "correct" it based on the
      // port: URL#port is "" for a default port, so any port-based rewrite silently
      // turns every plain https://host into http://host:80.
      const lib = parsed.protocol === "https:" ? https : http;
      // URL#hostname keeps the brackets of an IPv6 literal ("[::1]"); a socket needs it bare.
      const hostname = stripBrackets(parsed.hostname);
      // Private/self-address guard, applied to EVERY hop (the first request, each redirect
      // target, each probe): an IP literal is checked here; a name is checked by
      // guardedLookup at connect time, against the very address the socket then uses.
      if (guardOn) {
        try {
          assertHostAllowed(hostname);
        } catch (e) {
          fail(e);
          return;
        }
      }
      const reqOptions = {
        hostname,
        port: parsed.port || (parsed.protocol === "https:" ? 443 : 80),
        path: parsed.pathname + parsed.search,
        method,
        headers,
        timeout: Math.max(1, timeout) * 1000,
        // verify=False equivalent - scanners intentionally probe self-signed/expired certs
        rejectUnauthorized: false,
        ...(guardOn ? { lookup: guardedLookup } : {}),
      };

      const req = lib.request(reqOptions, (res) => {
        const chunks = [];
        let size = 0;

        res.on("data", (c) => {
          size += c.length;
          if (size > maxBytes) {
            fail(new Error(`Response body exceeded ${maxBytes} bytes`));
            res.destroy();
            return;
          }
          chunks.push(c);
        });
        // A connection dropped mid-body surfaces on the response, not the request. Without these
        // handlers the promise never settled (or, on some Node versions, the unhandled 'error'
        // event killed the process) - either way the whole scan stalled or died.
        res.on("error", fail);
        res.on("aborted", () => fail(new Error("Connection closed before the response completed")));
        res.on("close", () => {
          if (!res.complete) fail(new Error("Connection closed before the response completed"));
        });
        res.on("end", () => {
          try {
            const status = res.statusCode || 0;
            if ([301, 302, 303, 307, 308].includes(status) && res.headers.location && redirectsLeft > 0) {
              let next = null;
              try {
                next = new URL(res.headers.location, currentUrl);
              } catch {
                next = null; // malformed Location: hand back the 3xx itself instead of throwing
              }
              if (next && (next.protocol === "http:" || next.protocol === "https:")) {
                redirectsLeft -= 1;
                doRequest(next.toString());
                return;
              }
            }
            const raw = Buffer.concat(chunks);
            const body = decompress(raw, res.headers["content-encoding"], maxBytes);
            done(new HttpResponse({
              statusCode: status,
              headers: res.headers,
              body,
              url: currentUrl,
            }));
          } catch (e) {
            fail(e);
          }
        });
      });
      activeReq = req;

      req.on("timeout", () => req.destroy(new Error(`Request timed out after ${timeout}s`)));
      req.on("error", fail);

      try {
        if (data) req.write(data);
        req.end();
      } catch (e) {
        fail(e);
      }
    };

    doRequest(targetUrl);
  });
}

export const httpClient = {
  get: (url, opts = {}) => request(url, { ...opts, method: "GET" }),
  post: (url, data, opts = {}) => request(url, { ...opts, method: "POST", data }),
};