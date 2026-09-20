// easm/lib/portscan.js
//
// Discovery for ubel-host (see ../host.js), in two steps:
//
//   1. scanPorts()      — a bounded-concurrency raw TCP connect scan across
//                          a port range on one host. This only establishes
//                          which ports accept a connection at all; it says
//                          nothing about what's actually listening on them.
//   2. probeHttpPorts() — for each open port, a bounded-concurrency
//                          liveness probe (HTTPS first, falling back to
//                          plain HTTP on failure — the same order
//                          DomainScanner.scan() itself already uses for a
//                          scheme-less target, see
//                          ../fingerprint/src/core/domainScanner.js) to
//                          filter that raw port list down to the ones
//                          actually speaking HTTP(S). Most open ports on a
//                          typical host (SSH, a database, a message queue,
//                          ...) are not web servers, and there's no point
//                          queuing a fingerprint pass, a secrets crawl, and
//                          a misconfiguration probe for one that isn't.
//
// Deliberately NOT decided here: which scheme a port actually answers on.
// The target handed onward by ../host.js is bare "host:port" — exactly
// like ubel-domain hands scanTargets() a bare discovered hostname — so
// scanTargets()/DomainScanner re-derive the scheme themselves on the real
// fingerprinting pass. Duplicating that choice here would just be a second
// place for the two to drift apart.

import net from "node:net";
import http from "node:http";
import https from "node:https";
import { mapLimit } from "../../cloud/lib/concurrency.js";

/**
 * One raw TCP connect attempt. Never rejects: a closed port, a filtered
 * port, and a timeout are all indistinguishable from the outside and all
 * just mean "not open" here.
 *
 * @returns {Promise<boolean>}
 */
function probePort(host, port, timeoutMs) {
  return new Promise((resolve) => {
    let settled = false;
    let socket;
    const finish = (open) => {
      if (settled) return;
      settled = true;
      if (socket) socket.destroy();
      resolve(open);
    };
    try {
      socket = new net.Socket();
      socket.setTimeout(timeoutMs);
      socket.once("connect", () => finish(true));
      socket.once("timeout", () => finish(false));
      socket.once("error", () => finish(false));
      socket.connect(port, host);
    } catch {
      finish(false);
    }
  });
}

/**
 * @param {string} host
 * @param {{from: number, to: number}} portRange  inclusive
 * @param {{concurrency?: number, timeout?: number, log?: (msg:string)=>void}} [opts]
 * @returns {Promise<number[]>} open ports, ascending
 */
export async function scanPorts(host, portRange, opts = {}) {
  const { concurrency = 500, timeout = 1500, log = () => {} } = opts;
  const ports = [];
  for (let p = portRange.from; p <= portRange.to; p++) ports.push(p);

  log(`[*] Connect-scanning ${ports.length} port(s) on ${host} (concurrency ${concurrency}, ${timeout}ms timeout)...`);
  const results = await mapLimit(ports, concurrency, (port) =>
    probePort(host, port, timeout).then((open) => ({ port, open }))
  );

  const open = [];
  for (const r of results) {
    if (r.ok && r.value.open) open.push(r.value.port);
  }
  open.sort((a, b) => a - b);
  log(`[*] ${open.length} of ${ports.length} port(s) accepted a connection on ${host}.`);
  return open;
}

/** One GET, no redirect following — we only care whether a response with a
 *  status line came back at all, not what's in it. `rejectUnauthorized:
 *  false` on the HTTPS attempt mirrors DomainScanner's own tolerance for a
 *  target with a self-signed/expired cert: a broken cert doesn't mean
 *  nothing is listening. */
function probeScheme(mod, scheme, host, port, timeoutMs) {
  return new Promise((resolve, reject) => {
    const req = mod.get(
      `${scheme}://${host}:${port}/`,
      { timeout: timeoutMs, rejectUnauthorized: false },
      (res) => {
        res.resume(); // drain and discard — liveness only, not content
        resolve(res.statusCode);
      }
    );
    req.on("timeout", () => req.destroy(new Error("timeout")));
    req.on("error", reject);
  });
}

/**
 * @param {string} host
 * @param {number} port
 * @param {number} timeoutMs
 * @returns {Promise<boolean>} true if either scheme returned any HTTP
 *   response at all (any status code counts — this is a liveness check,
 *   not a success check)
 */
async function httpProbe(host, port, timeoutMs) {
  try {
    await probeScheme(https, "https", host, port, timeoutMs);
    return true;
  } catch {
    // fall through to plain HTTP
  }
  try {
    await probeScheme(http, "http", host, port, timeoutMs);
    return true;
  } catch {
    return false;
  }
}

/**
 * @param {string} host
 * @param {number[]} openPorts
 * @param {{concurrency?: number, timeout?: number, log?: (msg:string)=>void}} [opts]
 * @returns {Promise<number[]>} the subset of openPorts that answered an
 *   HTTP(S) request, ascending
 */
export async function probeHttpPorts(host, openPorts, opts = {}) {
  const { concurrency = 20, timeout = 5000, log = () => {} } = opts;
  if (!openPorts.length) return [];

  log(`[*] Probing ${openPorts.length} open port(s) on ${host} for HTTP(S) (concurrency ${concurrency})...`);
  const results = await mapLimit(openPorts, concurrency, (port) =>
    httpProbe(host, port, timeout).then((ok) => ({ port, ok }))
  );

  const httpPorts = [];
  for (const r of results) {
    if (r.ok && r.value.ok) httpPorts.push(r.value.port);
  }
  httpPorts.sort((a, b) => a - b);
  log(`[*] ${httpPorts.length} of ${openPorts.length} open port(s) answered an HTTP(S) request.`);
  return httpPorts;
}