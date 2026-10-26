'use strict';
// hosts.js — "remote hosts": the IP addresses and domain names a program names in its own strings, i.e. the places it may try to reach.
//
// Shared by ubel-binary and ubel-mobile (DEX strings, resources, native libraries, Mach-O strings, packaged-application text). It reads
// text only; nothing is resolved or contacted. A host in this list shows that the file REFERS to it. It does not show that the code
// connects there, when, or with what data: addresses that are assembled at run time, read from a config file or fetched from a server
// are not visible to a static scan.
//
// What counts as a host
//   url      `scheme://host[:port]/…` for a network scheme (http, https, ws, wss, ftp, ssh, mqtt, redis, postgres …). Highest confidence.
//   ip       an IPv4 address with a port, or (in `bare: 'all'` mode) on its own; an IPv6 address in brackets inside a URL.
//   domain   a lower-case DNS name without a scheme (`update.vendor.com`, `api.vendor.com:8443`). Only with a real top-level domain.
// What is left out, because it is not somewhere the program reaches: XML / schema namespaces and licence URLs, reserved example and test
// names (example.com, *.test, *.invalid), loopback and unspecified addresses, template placeholders (`https://%s`, `https://{host}`),
// e-mail addresses, Go / Rust module paths (`github.com/user/repo`), reverse-DNS class names (`java.net`), OIDs and version numbers.

import net from 'node:net';

const NETWORK_SCHEMES = new Set([
  'http', 'https', 'ws', 'wss', 'ftp', 'ftps', 'sftp', 'ssh', 'telnet', 'tcp', 'udp', 'tls', 'ssl', 'quic', 'mqtt', 'mqtts', 'amqp', 'amqps', 'redis', 'rediss',
  'mongodb', 'mongodb+srv', 'postgres', 'postgresql', 'mysql', 'mariadb', 'mssql', 'sqlserver', 'jdbc', 'smtp', 'smtps', 'imap', 'imaps', 'pop3', 'pop3s', 'ldap', 'ldaps',
  'grpc', 'grpcs', 'rtsp', 'rtsps', 'rtmp', 'rtmps', 'sip', 'sips', 'stun', 'stuns', 'turn', 'turns', 'git', 'nats', 'kafka', 'irc', 'ircs', 'vnc', 'rdp', 'socks',
  'socks4', 'socks5', 'socks5h', 'smb', 'nfs', 'coap', 'coaps', 'xmpp', 'amqp+ssl', 'wss+tls',
]);
// Schemes that carry data without TLS.
const CLEARTEXT_SCHEMES = new Set(['http', 'ws', 'ftp', 'telnet', 'ldap', 'mqtt', 'amqp', 'redis', 'smtp', 'imap', 'pop3', 'rtsp', 'rtmp', 'vnc', 'tcp', 'udp', 'git', 'irc', 'socks', 'socks4', 'socks5', 'sip', 'nats', 'coap']);

// Top-level domains that are safe to accept for a two-label name without a scheme (`vendor.com`).
const BARE_TLD = new Set(['com', 'net', 'org', 'io', 'co', 'gov', 'edu']);
// Other generic and internal top-level domains: known, so a URL with them is believed, but a bare name needs 3+ labels (`f32.store`, `this.dev` are code).
const MORE_TLD = new Set(['ai', 'info', 'biz', 'xyz', 'cloud', 'dev', 'mil', 'int', 'app', 'asia', 'mobi', 'tv', 'fm', 'gg', 'local', 'internal', 'lan', 'corp', 'home', 'intranet', 'localdomain', 'onion', 'arpa']);
// (a URL with any other top-level domain and a path is still believed: see dnsName)
const SAFE_CC = new Set(['de', 'fr', 'nl', 'ru', 'cn', 'jp', 'kr', 'br', 'au', 'eu', 'ch', 'se', 'dk', 'fi', 'cz', 'hu', 'ro', 'gr', 'tr', 'tw', 'hk', 'sg', 'za', 'mx', 'ie', 'be', 'uk', 'ua']);
// Other two-letter country codes are also file extensions or common words (sh, py, rs, md, cc, so, pl, id, is, in, it, no, me, to, as, at …): accepted with 3+ labels only.
const OTHER_CC = new Set(('ac ad ae af ag al am ao aq ar as at aw ax az ba bb bd bf bg bh bi bj bm bn bo bs bt bw by bz cd cf cg ci ck cl cm co cr cu cv cw cx cy dj dm do dz ec ee eg er es et fj fk fm fo ga gd ge gf gg gh gi gl gm gn gp gq gs gt gu gw gy ' +
  'hn hr ht id il im in iq ir is it je jm jo ke kg kh ki km kn kp kw ky kz la lb lc li lk lr ls lt lu lv ly ma mc me mg mh mk ml mm mn mo mp mq mr ms mt mu mv mw my mz na nc ne nf ng ni no np nr nu nz om pa pe pf pg ph pk pm pn pr ps pt pw py qa re rs rw sa sb sc sd si sk sl sm sn so sr ss st sv sx sy sz tc td tf tg th tj tk tl tm tn to tt tv tz ug us uy uz va vc ve vg vi vn vu wf ws ye yt zm zw').split(' '));
// First labels that make a two-label `x.net` / `x.io` / `x.org` / `x.com` a package name rather than a host.
const PACKAGE_ROOTS = new Set(['java', 'javax', 'android', 'androidx', 'kotlin', 'kotlinx', 'sun', 'jdk', 'dalvik', 'libcore', 'junit', 'scala', 'akka', 'okhttp3', 'okio', 'retrofit2', 'flutter', 'dart', 'std', 'core', 'alloc', 'tokio', 'system', 'microsoft', 'windows', 'mono', 'node', 'npm', 'org', 'com', 'net', 'io', 'www']);
const RESERVED = /(?:^|\.)(?:example\.(?:com|net|org|edu)|example|test|invalid|localhost|localdomain|home\.arpa)$/;
// Hosts that name a standard, a schema or a licence, not a server.
const NAMESPACE_HOST = /(?:^|\.)(?:w3\.org|xmlpull\.org|purl\.org|xmlsoap\.org|openxmlformats\.org|json-schema\.org|ns\.adobe\.com|java\.sun\.com|xml\.org|relaxng\.org|opengis\.net|iana\.org|ietf\.org|spdx\.org|creativecommons\.org|gnu\.org|opensource\.org|schemas\.android\.com|schemas\.microsoft\.com|xmlns\.com|oasis-open\.org|ecma-international\.org|unicode\.org|iso\.org|dublincore\.org|schema\.org|ogp\.me)$/;
const NAMESPACE_URL = /^[a-z+.-]+:\/\/(?:[^/]*\.)?(?:apache\.org\/(?:licenses|xml)|mozilla\.org\/(?:MPL|en-US\/MPL)|eclipse\.org\/(?:legal|org\/documents)|sun\.com\/|oracle\.com\/(?:technetwork|java\/technologies\/javase)|android\.com\/(?:apk|tools))/i;

const MAX_HOSTS_KEPT = 20000, MAX_HOSTS_LISTED = 500, MAX_SEEN_IN = 6, MAX_EXAMPLES = 3;

// `scheme://[user:pass@]host[:port]tail`. Group 1 scheme, 2 host (or [ipv6]), 3 port, 4 the rest of the token.
const URL_RE = /\b([a-z][a-z0-9+.-]{1,15}):\/\/(?:[^\s/?#@"'<>\\]{0,100}@)?(\[[0-9a-f:.]{2,45}\]|[a-z0-9][a-z0-9._-]{0,252})(?::(\d{1,5}))?([^\s"'<>\\]{0,200})/gi;
const IPV4_RE = /(?<![\w.:-])((?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})(?::(\d{1,5}))?(?![\w]|\.\d)/g;
const DOMAIN_RE = /(?<![\w.@/-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+([a-z]{2,24}))(?::(\d{2,5}))?(?![\w-]|\.[a-z0-9]|\/[^\s])/g;
const LABEL = /^(?:xn--)?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;

const validPort = p => { const n = Number(p); return Number.isInteger(n) && n >= 1 && n <= 65535 ? n : null; };

function ipv4Info(ip) {
  const o = ip.split('.').map(Number);
  if (o[0] === 0 || o[0] === 127 || o[0] >= 240) return { skip: true };                       // unspecified, loopback, reserved, broadcast
  const priv = o[0] === 10 || (o[0] === 172 && o[1] >= 16 && o[1] <= 31) || (o[0] === 192 && o[1] === 168) || (o[0] === 100 && o[1] >= 64 && o[1] <= 127) || (o[0] === 169 && o[1] === 254 && ip !== '169.254.169.254');
  return { skip: false, priv };
}
/** A dotted quad on its own (no port, no scheme) is only believed when it does not look like a version number or an OID. */
function bareIpPlausible(ip) {
  const o = ip.split('.').map(Number);
  if (ip === '1.1.1.1' || ip === '1.0.0.1') return true;
  if ((o[0] === 1 && (o[1] === 2 || o[1] === 3 || o[1] === 0)) || (o[0] === 2 && (o[1] === 5 || o[1] === 16)) || (o[0] <= 2 && o[1] <= 40 && o[2] <= 40)) return false;   // OIDs, 1.0.0.0
  if (o.filter(x => x === 0).length >= 2) return false;
  return true;
}

// A scheme-less host or bare IP is believed only when the string is nothing but that address (a constant such as "update.vendor.com", "10.1.2.3:8080")
// or when it follows a key that names a host (`host=`, `server:`, `Host: `). In running text, comments and identifiers it is noise.
const HOST_KEY = /(?:\b(?:host(?:name)?|server|endpoint|domain|url|addr(?:ess)?|proxy|dns|origin|remote|peer|ip)\s*[=:]\s*["']?|\bhost:\s*|\b(?:nameserver|resolver|ping|connect(?:ing|ed)? to)\s+["']?|@)$/i;
function standalone(text, at, len) {
  const before = text.slice(0, at), after = text.slice(at + len);
  if (/^\s*$/.test(before) && /^\/?\s*$/.test(after)) return true;                      // the whole string
  return HOST_KEY.test(before.slice(-24)) && /^(?:["'\s,;)/]|$)/.test(after);              // after a key that names a host
}

/** Normalises a host name: lower case, no trailing dot. Returns null when it is not a usable DNS name. */
function dnsName(raw, { fromUrl, pathy = false }) {
  let h = String(raw).toLowerCase().replace(/[.-]+$/, '');
  if (!h || h.length > 253 || h.includes('..')) return null;
  const labels = h.split('.');
  if (!labels.every(l => LABEL.test(l))) return null;
  if (labels.length < 2) return null;
  const tld = labels[labels.length - 1];
  if (!/^(?:[a-z]{2,24}|xn--[a-z0-9-]{2,20})$/.test(tld)) return null;                      // `1.2.3` is not a host
  const known = BARE_TLD.has(tld) || MORE_TLD.has(tld) || SAFE_CC.has(tld) || OTHER_CC.has(tld);
  if (fromUrl) return known || pathy ? h : null;                          // `http://www.css` is a glued string; `https://x.technology/path` is a URL
  // a name without a scheme must be convincing
  if (BARE_TLD.has(tld) || SAFE_CC.has(tld)) {
    if (labels.length === 2 && (PACKAGE_ROOTS.has(labels[0]) || /^(?:dll|exe|so|lib|sys|drv)$/.test(labels[0]))) return null;
    return h;
  }
  if (MORE_TLD.has(tld) || OTHER_CC.has(tld)) return labels.length >= 3 && !PACKAGE_ROOTS.has(labels[0]) ? h : null;
  return null;
}

export class RemoteHostCollector {
  constructor() { this.map = new Map(); this.ignored = 0; this.dropped = 0; this.scanned = 0; }

  _entry(host, type, priv) {
    let e = this.map.get(host);
    if (!e) {
      if (this.map.size >= MAX_HOSTS_KEPT) { this.dropped++; return null; }
      e = { host, type, private: priv, refs: 0, ports: new Set(), schemes: new Set(), seen: new Map(), examples: new Set() };
      this.map.set(host, e);
    }
    return e;
  }

  /** @param {{scheme?:string, port?:number|null, example?:string}} [info] */
  addHost(host, type, where, { scheme = null, port = null, example = null, priv = false } = {}) {
    const e = this._entry(host, type, priv);
    if (!e) return;
    e.refs++;
    if (port) e.ports.add(port);
    if (scheme) e.schemes.add(scheme);
    if (where) e.seen.set(where, (e.seen.get(where) || 0) + 1);
    if (example && e.examples.size < MAX_EXAMPLES) e.examples.add(example.length > 200 ? `${example.slice(0, 200)}…` : example);
  }

  /**
   * Reads one string. `bare`: 'all' also takes IP addresses and lower-case domain names without a scheme (strings of a compiled program),
   * 'ip-port' only `IPv4:port` (source text of a packaged application, where `req.id` or `1.2.3.4` is code, not a host), 'none' only URLs.
   */
  addText(text, where, { bare = 'all' } = {}) {
    const s = String(text);
    if (s.length < 5 || s.length > 4096) return;
    this.scanned++;
    let rest = s;
    if (s.indexOf('://') > 0) {
      URL_RE.lastIndex = 0;
      let m, any = false;
      while ((m = URL_RE.exec(s))) {
        any = true;
        const scheme = m[1].toLowerCase();
        if (!NETWORK_SCHEMES.has(scheme)) continue;
        const token = `${m[1]}://${m[2]}${m[3] ? `:${m[3]}` : ''}${m[4]}`;
        const port = m[3] ? validPort(m[3]) : null;
        if (m[3] && !port) continue;
        let host = m[2], type, priv = false;
        if (host.startsWith('[')) {
          host = host.slice(1, -1).toLowerCase();
          if (!net.isIPv6(host) || host === '::1' || host === '::') continue;
          type = 'ipv6'; priv = /^(?:f[cd]|fe[89ab])/.test(host);
        } else if (net.isIPv4(host)) {
          const info = ipv4Info(host);
          if (info.skip) continue;
          type = 'ipv4'; priv = info.priv;
        } else {
          const name = dnsName(host, { fromUrl: true, pathy: m[4].startsWith('/') });
          // a single-label name is a host only with an explicit port (`tcp://broker:1883`)
          const single = !name && port && LABEL.test(host.toLowerCase()) && host.length > 2 && !/^(?:localhost|host|hostname|server|domain|example|your|my)$/.test(host.toLowerCase());
          if (!name && !single) continue;
          host = name || host.toLowerCase(); type = 'domain';
        }
        if (RESERVED.test(host) || (type === 'domain' && NAMESPACE_HOST.test(host)) || NAMESPACE_URL.test(token) || (type === 'domain' && /^schemas\./.test(host))) { this.ignored++; continue; }
        this.addHost(host, type, where, { scheme, port, example: token, priv });
      }
      if (any) rest = s.replace(/\b[a-z][a-z0-9+.-]{1,15}:\/\/[^\s"'<>\\]*/gi, ' ');
    }
    if (bare === 'none' || rest.length < 5) return;
    if (rest.indexOf('.') < 0) return;
    IPV4_RE.lastIndex = 0;
    let m;
    while ((m = IPV4_RE.exec(rest))) {
      const port = m[2] ? validPort(m[2]) : null;
      if (bare === 'ip-port' && !port) continue;
      const info = ipv4Info(m[1]);
      if (info.skip || (!port && (!bareIpPlausible(m[1]) || !standalone(rest, m.index, m[0].length)))) continue;
      this.addHost(m[1], 'ipv4', where, { port, priv: info.priv });
    }
    if (bare !== 'all') return;
    DOMAIN_RE.lastIndex = 0;
    while ((m = DOMAIN_RE.exec(rest))) {
      if (!standalone(rest, m.index, m[0].length)) continue;
      const name = dnsName(m[1], { fromUrl: false });
      if (!name) continue;
      if (RESERVED.test(name) || NAMESPACE_HOST.test(name)) { this.ignored++; continue; }
      this.addHost(name, 'domain', where, { port: m[3] ? validPort(m[3]) : null });
    }
  }

  addStrings(list, where, opts) { for (const s of list) this.addText(s, where, opts); }

  /** The `app.remote_hosts` summary, or null when no host was found. */
  summary() {
    if (!this.map.size) return null;
    const all = [...this.map.values()].sort((a, b) => b.refs - a.refs || a.host.localeCompare(b.host));
    const hosts = all.slice(0, MAX_HOSTS_LISTED).map(e => ({
      host: e.host, type: e.type, refs: e.refs, private: e.private,
      cleartext: [...e.schemes].some(x => CLEARTEXT_SCHEMES.has(x)),
      ports: [...e.ports].sort((a, b) => a - b).slice(0, 8), schemes: [...e.schemes].sort().slice(0, 8),
      seen_in: [...e.seen].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, MAX_SEEN_IN).map(x => x[0]),
      examples: [...e.examples],
    }));
    return {
      total: this.map.size + this.dropped, domains: all.filter(e => e.type === 'domain').length, ips: all.filter(e => e.type !== 'domain').length,
      private: all.filter(e => e.private).length, cleartext: all.filter(e => [...e.schemes].some(x => CLEARTEXT_SCHEMES.has(x))).length,
      ignored: this.ignored, listed: hosts.length, hosts,
    };
  }
}

/** Folds the remote-host summary of another App Bundle module into the base module's summary (refs add up; the lists are capped). */
export function mergeRemoteHosts(a, b) {
  if (!a) return b || null;
  if (!b) return a;
  const by = new Map();
  for (const h of [...a.hosts, ...b.hosts]) {
    const x = by.get(h.host);
    if (!x) { by.set(h.host, { ...h, ports: [...h.ports], schemes: [...h.schemes], seen_in: [...h.seen_in], examples: [...h.examples] }); continue; }
    x.refs += h.refs; x.cleartext = x.cleartext || h.cleartext; x.private = x.private || h.private;
    x.ports = [...new Set([...x.ports, ...h.ports])].sort((p, q) => p - q).slice(0, 8);
    x.schemes = [...new Set([...x.schemes, ...h.schemes])].sort().slice(0, 8);
    x.seen_in = [...new Set([...x.seen_in, ...h.seen_in])].slice(0, MAX_SEEN_IN);
    x.examples = [...new Set([...x.examples, ...h.examples])].slice(0, MAX_EXAMPLES);
  }
  const all = [...by.values()].sort((p, q) => q.refs - p.refs || p.host.localeCompare(q.host));
  const hosts = all.slice(0, MAX_HOSTS_LISTED);
  const extra = Math.max(0, a.total - a.hosts.length) + Math.max(0, b.total - b.hosts.length);
  return {
    total: all.length + extra, domains: all.filter(h => h.type === 'domain').length, ips: all.filter(h => h.type !== 'domain').length,
    private: all.filter(h => h.private).length, cleartext: all.filter(h => h.cleartext).length, ignored: (a.ignored || 0) + (b.ignored || 0), listed: hosts.length, hosts,
  };
}
