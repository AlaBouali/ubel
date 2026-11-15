'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';

// port → [label, severity, why]
const RISKY = {
  21: ['FTP', 'high', 'sends credentials and data in clear text'], 23: ['Telnet', 'high', 'sends credentials and data in clear text'],
  69: ['TFTP', 'high', 'has no authentication'], 111: ['rpcbind', 'medium', 'exposes RPC services and is used for amplification'],
  139: ['NetBIOS/SMB', 'medium', 'exposes file-sharing to the network'], 161: ['SNMP', 'medium', 'is often configured with default community strings'],
  389: ['LDAP', 'medium', 'is clear text unless wrapped in TLS'], 445: ['SMB', 'medium', 'exposes file-sharing to the network'],
  512: ['rexec', 'high', 'is an obsolete clear-text remote shell'], 513: ['rlogin', 'high', 'is an obsolete clear-text remote shell'], 514: ['rsh/syslog', 'high', 'is an obsolete clear-text remote shell (or unauthenticated syslog)'],
  873: ['rsync', 'medium', 'often runs without authentication'], 1433: ['Microsoft SQL Server', 'medium', 'database should not be reachable from every network'],
  1521: ['Oracle DB', 'medium', 'database should not be reachable from every network'], 2049: ['NFS', 'medium', 'exposes file systems to the network'],
  2375: ['Docker API (unencrypted)', 'critical', 'gives unauthenticated root-equivalent control of the host'], 2379: ['etcd', 'high', 'holds cluster secrets and is often unauthenticated'],
  2380: ['etcd peer', 'high', 'is the cluster-internal etcd port'], 3306: ['MySQL/MariaDB', 'medium', 'database should not be reachable from every network'],
  5432: ['PostgreSQL', 'medium', 'database should not be reachable from every network'], 5984: ['CouchDB', 'medium', 'database should not be reachable from every network'],
  6379: ['Redis', 'high', 'is unauthenticated by default and allows code execution'], 9042: ['Cassandra', 'medium', 'database should not be reachable from every network'],
  9200: ['Elasticsearch', 'high', 'is frequently exposed without authentication'], 9300: ['Elasticsearch transport', 'high', 'is the cluster-internal Elasticsearch port'],
  11211: ['Memcached', 'high', 'has no authentication and is used for amplification'], 27017: ['MongoDB', 'high', 'is frequently exposed without authentication'],
  10250: ['kubelet API', 'low', 'is meant for the control plane only'],
};
for (let p = 5900; p <= 5910; p++) RISKY[p] = ['VNC', 'high', 'remote desktop with weak authentication'];
for (let p = 6000; p <= 6010; p++) RISKY[p] = ['X11', 'high', 'exposes the display server to the network'];

const VIRTUAL_NIC = /^(veth|docker|br-|virbr|cni|flannel|cali|tap|vnet|lo$|cilium|vxlan|weave|tun)/;

export default [
  rule({
    id: 'vm-net-risky-listeners', area: 'network', severity: 'medium', title: 'Sensitive or clear-text service listens on a non-loopback address',
    description: 'A service known to be unauthenticated, clear-text or frequently attacked accepts connections on an address other than loopback. Whether it is reachable from the internet depends on the surrounding firewall / security group.',
    remediation: 'Bind the service to 127.0.0.1 or a private interface, put it behind authentication and TLS, and restrict the port with a host firewall or security group.',
    cap: 100,
    evaluate(ctx) {
      const ls = ctx.listeners();
      if (ls === null) return na('needs a live Linux host (/proc/net)');
      const hits = ls.filter((l) => !l.loopback && RISKY[l.port]);
      const owners = ctx.socketOwners(hits.map((l) => l.inode));
      return hits.map((l) => {
        const [label, severity, why] = RISKY[l.port];
        const o = owners.get(l.inode);
        return { resource: `${l.proto}/${l.addr}:${l.port}`, severity, detail: `${label} ${why}.${o ? ` Process: ${o.comm} (pid ${o.pid}).` : ''}` };
      });
    },
  }),

  rule({
    id: 'vm-net-no-firewall', area: 'network', severity: 'low', title: 'No host firewall configuration was found',
    description: 'No ufw, firewalld, nftables or iptables-persistent configuration is active on this machine. If it is protected only by a perimeter (cloud security group, network firewall), a single mistake there exposes every listening service.',
    remediation: 'Enable a host firewall (ufw, firewalld or nftables) with a default-deny inbound policy and allow only the ports you need.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; the host decides');
      const fw = [];
      const ufw = ctx.fs.lines('/etc/ufw/ufw.conf');
      if (ufw && ufw.some((l) => /^ENABLED\s*=\s*yes/i.test(l))) fw.push('ufw');
      if (ctx.serviceState('firewalld').enabled || ctx.serviceState('firewalld').running) fw.push('firewalld');
      const nft = ctx.fs.lines('/etc/nftables.conf') || [];
      if ((ctx.serviceState('nftables').enabled || ctx.serviceState('nftables').running) && nft.some((l) => /\bchain\b/.test(l))) fw.push('nftables');
      for (const f of ['/etc/iptables/rules.v4', '/etc/sysconfig/iptables', '/etc/iptables/iptables.rules']) {
        if ((ctx.fs.lines(f) || []).some((l) => /^-A\s|^:INPUT\s+(DROP|REJECT)/.test(l))) fw.push('iptables rules file');
      }
      if (ctx.serviceState('shorewall', 'ferm', 'csf').enabled) fw.push('firewall service');
      if (ctx.live) {
        const t = ctx.fs.read('/proc/net/ip_tables_names');
        if (t && /filter/.test(t)) fw.push('iptables (filter table active)');
        const t6 = ctx.fs.read('/proc/net/ip6_tables_names');
        if (t6 && /filter/.test(t6)) fw.push('ip6tables (filter table active)');
        const mods = ctx.fs.read('/proc/modules') || '';
        if (/^nf_tables\s/m.test(mods) && /^nft_(chain|ct|counter|reject)/m.test(mods)) fw.push('nftables (modules loaded)');
      }
      return fw.length ? [] : [{ resource: 'firewall', detail: 'No firewall service, rules file or active netfilter table detected.' }];
    },
  }),

  rule({
    id: 'vm-net-promiscuous-interface', area: 'network', severity: 'medium', title: 'A network interface is in promiscuous mode',
    description: 'A NIC in promiscuous mode captures all traffic on its segment. It is used by sniffers and some intrusion tools; legitimate causes are monitoring agents and bridges.',
    remediation: 'Identify the process that set the flag (tcpdump, an IDS, a bridge); remove it if it is not expected: ip link set <if> promisc off.',
    evaluate(ctx) {
      if (!ctx.live) return na('needs a live host (/sys/class/net)');
      const out = [];
      for (const n of ctx.fs.readdir('/sys/class/net') || []) {
        if (VIRTUAL_NIC.test(n)) continue;
        const f = parseInt((ctx.fs.read(`/sys/class/net/${n}/flags`) || '0').trim(), 16);
        if (f & 0x100) out.push({ resource: `iface:${n}`, detail: `Interface ${n} has the PROMISC flag set.` });
      }
      return out;
    },
  }),
];
