// Minimal stand-ins for bane's Domain_Info / IP_Info, covering only what
// domain_scanner.py actually calls: resolving a domain, and checking whether
// an address is private/self so the scanner can skip it.
//
// Nothing in this file makes a network request other than the DNS lookup of the
// target itself. In particular the "is this my own address?" check is answered
// from the machine's own network interfaces — it used to ask a third-party
// service (api.ipify.org) for this machine's public IP on every scan.

import dns from "node:dns/promises";
import dnsCb from "node:dns";
import net from "node:net";
import os from "node:os";
import { AsyncLocalStorage } from "node:async_hooks";

export class DomainInfo {
  /** @returns {Promise<string|null>} first resolved IPv4 address, or null */
  static async getIpFromDomain(domain) {
    try {
      const { address } = await dns.lookup(domain, { family: 4 });
      return address;
    } catch {
      return null;
    }
  }

  /**
   * Every address `hostname` resolves to (IPv4 and IPv6), or [] when it does not
   * resolve. An IP literal resolves to itself. Used to classify ALL of a name's
   * addresses, not just the first IPv4 one.
   * @returns {Promise<string[]>}
   */
  static async resolveAll(hostname) {
    const host = stripBrackets(hostname);
    if (net.isIP(host)) return [host];
    try {
      const addrs = await dns.lookup(host, { all: true, verbatim: true });
      return addrs.map((a) => a.address);
    } catch {
      return [];
    }
  }
}

/** "[::1]" -> "::1"; anything else unchanged. */
export function stripBrackets(host) {
  const h = String(host ?? "");
  return h.startsWith("[") && h.endsWith("]") ? h.slice(1, -1) : h;
}

/**
 * The hostname of a scan target in any form the CLI accepts: "example.com",
 * "example.com:8443", "http://example.com:8080/path", "[::1]:8080", "10.0.0.5:80",
 * "user:pw@host". Parsed with the WHATWG URL parser — the same one the HTTP client
 * uses to decide what to connect to — so the host classified here is the host
 * connected to (including its normalisation of "2130706433", "0x7f.1", "127.1" to
 * dotted-quad). Returns null when the target cannot be parsed or has no host.
 * @returns {string|null} lower-case hostname, IPv6 literals without brackets
 */
export function extractHostname(target) {
  const raw = String(target ?? "").trim();
  if (!raw) return null;
  try {
    const u = new URL(raw.includes("://") ? raw : `http://${raw}`);
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const h = stripBrackets(u.hostname);
    return h ? h.toLowerCase() : null;
  } catch {
    return null;
  }
}

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => !Number.isInteger(p) || p < 0 || p > 255)) return null;
  return ((parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3]) >>> 0;
}

function inRange(ip, cidr) {
  const [base, bits] = cidr.split("/");
  const mask = bits === "32" ? 0xffffffff : (0xffffffff << (32 - Number(bits))) >>> 0;
  const ipInt = ipToInt(ip);
  const baseInt = ipToInt(base);
  if (ipInt === null || baseInt === null) return false;
  return (ipInt & mask) === (baseInt & mask);
}

const PRIVATE_RANGES = [
  "10.0.0.0/8",
  "172.16.0.0/12",
  "192.168.0.0/16",
  "127.0.0.0/8",
  "169.254.0.0/16",
  "0.0.0.0/8",
];

/** Parses an IPv6 literal (zone id and embedded dotted-quad tail allowed) into 16 bytes, or null. */
function parseIPv6(str) {
  let s = String(str).split("%")[0];
  if (net.isIP(s) !== 6) return null;
  // Embedded IPv4 tail ("::ffff:1.2.3.4") -> two hex groups.
  const tail = /^(.*:)(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  if (tail) {
    const v4 = ipToInt(tail[2]);
    if (v4 === null) return null;
    s = `${tail[1]}${(v4 >>> 16).toString(16)}:${(v4 & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - left.length - right.length;
  if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
  const groups = [...left, ...Array(halves.length === 2 ? missing : 0).fill("0"), ...right];
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 8; i++) {
    const g = parseInt(groups[i], 16);
    if (!Number.isInteger(g) || g < 0 || g > 0xffff) return null;
    bytes[i * 2] = g >> 8;
    bytes[i * 2 + 1] = g & 0xff;
  }
  return bytes;
}

const v4FromBytes = (b, o) => `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`;

function isPrivateIPv6(b) {
  const allZero = (from, to) => { for (let i = from; i < to; i++) if (b[i] !== 0) return false; return true; };
  // :: and ::1
  if (allZero(0, 15) && (b[15] === 0 || b[15] === 1)) return true;
  // IPv4-mapped (::ffff:a.b.c.d) and deprecated IPv4-compatible (::a.b.c.d): judged by the IPv4 inside.
  if (allZero(0, 10) && b[10] === 0xff && b[11] === 0xff) return IpInfo.ipIsPrivate(v4FromBytes(b, 12));
  if (allZero(0, 12)) return IpInfo.ipIsPrivate(v4FromBytes(b, 12));
  // NAT64 (64:ff9b::/96): judged by the embedded IPv4. Local-use NAT64 (64:ff9b:1::/48): never public.
  if (b[0] === 0x00 && b[1] === 0x64 && b[2] === 0xff && b[3] === 0x9b) {
    if (allZero(4, 12)) return IpInfo.ipIsPrivate(v4FromBytes(b, 12));
    if (b[4] === 0x00 && b[5] === 0x01) return true;
  }
  // 6to4 (2002::/16): the IPv4 address is in bytes 2-5.
  if (b[0] === 0x20 && b[1] === 0x02) return IpInfo.ipIsPrivate(v4FromBytes(b, 2));
  if ((b[0] & 0xfe) === 0xfc) return true;                    // fc00::/7  unique local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0x80) return true;   // fe80::/10 link-local
  if (b[0] === 0xfe && (b[1] & 0xc0) === 0xc0) return true;   // fec0::/10 site-local (deprecated)
  if (b[0] === 0xff) return true;                             // ff00::/8  multicast
  return false;
}

/**
 * Normal form used to compare two addresses for equality: dotted-quad for IPv4
 * (and for IPv4-mapped IPv6), 32 lower-case hex digits for IPv6. Null if not an IP.
 */
function canonicalIp(ip) {
  const s = stripBrackets(ip);
  if (net.isIPv4(s)) return s;
  const b = parseIPv6(s);
  if (!b) return null;
  if (b.slice(0, 10).every((x) => x === 0) && b[10] === 0xff && b[11] === 0xff) return v4FromBytes(b, 12);
  return Buffer.from(b).toString("hex");
}

export class IpInfo {
  /** True for loopback, RFC 1918, link-local, unspecified and (for IPv6) unique-local/multicast addresses,
   *  including IPv4 ones carried inside IPv6 (mapped, NAT64, 6to4). */
  static ipIsPrivate(ip) {
    if (!ip) return false;
    const s = stripBrackets(ip);
    if (net.isIPv4(s)) return PRIVATE_RANGES.some((cidr) => inRange(s, cidr));
    const b = parseIPv6(s);
    return b ? isPrivateIPv6(b) : false;
  }

  /**
   * True when `ip` is assigned to one of THIS machine's own network interfaces
   * (e.g. a VPS / bare-metal host whose public address is bound directly to the
   * NIC). Purely local: no network request is made.
   *
   * Limitation: a public address that lives only on a router/NAT in front of
   * this machine (a typical home or office egress IP, or a cloud VM with a NAT'd
   * elastic IP) is not on any local interface and is not detected here.
   *
   * @param {string|null|undefined} ip
   * @returns {boolean}
   */
  static isLocalAddress(ip) {
    if (!ip) return false;
    const want = canonicalIp(ip);
    if (!want) return false;
    for (const addrs of Object.values(os.networkInterfaces())) {
      for (const a of addrs || []) {
        if (a.address === ip || canonicalIp(a.address) === want) return true;
      }
    }
    return false;
  }

  /** The scanner's single "must not be contacted" test: private/loopback/link-local, or this machine's own address. */
  static isBlocked(ip) {
    return IpInfo.ipIsPrivate(ip) || IpInfo.isLocalAddress(ip);
  }
}

// ── Connect-time enforcement ────────────────────────────────────────────────
//
// Checking a name once, up front, is not enough: the HTTP client resolves it
// again when it connects (DNS can answer differently the second time), and
// every redirect or probe may name a different host. So while a scan runs with
// the guard on, the HTTP/TLS clients are handed `guardedLookup` as their DNS
// `lookup` hook: the addresses it validates are exactly the ones the socket
// connects to, for every request, redirect hop and probe. IP literals never
// reach a `lookup` hook, so they are checked directly with `assertHostAllowed`.

const guardStore = new AsyncLocalStorage();

/** Runs `fn` with the private/self-address guard on (enforce = true) or off. Applies to every request made inside it. */
export function runWithAddressGuard(enforce, fn) {
  return guardStore.run({ enforce: !!enforce }, fn);
}

/** True when the current async context is running with the guard on. */
export function addressGuardActive() {
  return guardStore.getStore()?.enforce === true;
}

function blockedError(host, ip) {
  const err = new Error(
    `Refusing to contact ${host}${ip && ip !== host ? ` (${ip})` : ""}: private or local address ` +
    "(pass --allow-private only for lab/localhost targets you own)"
  );
  err.code = "EBLOCKED";
  return err;
}

/** Throws EBLOCKED if `host` is an IP literal in a blocked range. No-op for names (see guardedLookup).
 *  Callers decide whether the guard applies (see addressGuardActive) — this always checks. */
export function assertHostAllowed(host) {
  const h = stripBrackets(host);
  if (net.isIP(h) && IpInfo.isBlocked(h)) throw blockedError(h, h);
}

/**
 * DNS `lookup` hook for http(s).request / tls.connect. Resolves with getaddrinfo like
 * the default, then refuses the whole name if ANY returned address is blocked
 * (a name with one public and one private record is an attacker-controlled answer,
 * not a host to guess between).
 */
export function guardedLookup(hostname, options, callback) {
  if (typeof options === "function") { callback = options; options = {}; }
  const opts = typeof options === "number" ? { family: options } : { ...(options || {}) };
  dnsCb.lookup(hostname, { ...opts, all: true }, (err, addrs) => {
    if (err) return callback(err);
    const bad = addrs.find((a) => IpInfo.isBlocked(a.address));
    if (bad) return callback(blockedError(hostname, bad.address));
    if (opts.all) return callback(null, addrs);
    return callback(null, addrs[0].address, addrs[0].family);
  });
}
