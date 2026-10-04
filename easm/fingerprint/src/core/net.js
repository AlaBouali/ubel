// Minimal stand-ins for bane's Domain_Info / IP_Info, covering only what
// domain_scanner.py actually calls: resolving a domain, and checking whether
// an address is private/self so the scanner can skip it.
//
// Nothing in this file makes a network request other than the DNS lookup of the
// target itself. In particular the "is this my own address?" check is answered
// from the machine's own network interfaces — it used to ask a third-party
// service (api.ipify.org) for this machine's public IP on every scan.

import dns from "node:dns/promises";
import os from "node:os";

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
}

function ipToInt(ip) {
  const parts = ip.split(".").map(Number);
  if (parts.length !== 4 || parts.some((p) => Number.isNaN(p))) return null;
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

export class IpInfo {
  static ipIsPrivate(ip) {
    if (!ip) return false;
    if (ip === "::1" || ip.startsWith("fe80:") || ip.startsWith("fc") || ip.startsWith("fd")) return true;
    return PRIVATE_RANGES.some((cidr) => inRange(ip, cidr));
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
    for (const addrs of Object.values(os.networkInterfaces())) {
      for (const a of addrs || []) {
        if (a.address === ip) return true;
      }
    }
    return false;
  }
}
