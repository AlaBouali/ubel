'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';

// [label, [unit/process names], severity, why]
const LEGACY = [
  ['Telnet server', ['telnet', 'telnetd', 'in.telnetd', 'inetutils-telnetd'], 'high', 'sends logins in clear text'],
  ['rsh / rlogin / rexec server', ['rsh', 'rshd', 'rlogin', 'rlogind', 'rexec', 'rexecd', 'in.rshd', 'in.rlogind', 'in.rexecd'], 'high', 'is an obsolete clear-text remote shell with host-based trust'],
  ['TFTP server', ['tftp', 'tftpd', 'tftpd-hpa', 'in.tftpd', 'atftpd'], 'high', 'has no authentication'],
  ['talk / finger daemon', ['talk', 'ntalk', 'talkd', 'finger', 'fingerd', 'in.fingerd'], 'high', 'leaks user information and is obsolete'],
  ['NIS server/client', ['ypserv', 'ypbind', 'yppasswdd', 'nis'], 'medium', 'sends account data over the network without strong protection'],
  ['inetd / xinetd super-server', ['xinetd', 'inetd', 'openbsd-inetd'], 'medium', 'starts legacy network services on demand'],
  ['FTP server', ['vsftpd', 'proftpd', 'pure-ftpd', 'pureftpd', 'ftpd', 'in.ftpd'], 'medium', 'sends credentials in clear text unless FTPS is enforced'],
  ['SNMP agent', ['snmpd'], 'medium', 'is often reachable with default community strings'],
  ['Samba file server', ['smbd', 'nmbd', 'samba', 'smb'], 'low', 'exposes file sharing to the network'],
  ['NFS / rpcbind', ['nfs-server', 'nfs-kernel-server', 'rpcbind', 'rpc.mountd'], 'low', 'exposes file systems or RPC services to the network'],
  ['Avahi (mDNS) daemon', ['avahi-daemon'], 'low', 'advertises the host on the local network'],
  ['CUPS print service', ['cups', 'cupsd', 'cups-browsed'], 'low', 'is rarely needed on a server and has a history of vulnerabilities'],
  ['Bluetooth service', ['bluetooth', 'bluetoothd'], 'low', 'is unnecessary on a server'],
  ['DHCP server', ['isc-dhcp-server', 'dhcpd', 'dhcpd6'], 'low', 'should only run on hosts that serve DHCP'],
  ['LDAP server', ['slapd'], 'low', 'should only run on directory servers'],
];

const LEGACY_PKGS = /^(telnetd|inetutils-telnetd|telnet-server|rsh-server|rsh-redone-server|inetutils-rshd|rsh-client|tftpd|tftpd-hpa|atftpd|talkd|nis|ypserv|xinetd|openbsd-inetd|inetutils-inetd|finger|fingerd|inetutils-ftpd|ftpd)$/;

function dockerDaemonHosts(ctx) {
  const out = [];
  const cfg = ctx.fs.read('/etc/docker/daemon.json');
  if (cfg) {
    try {
      const j = JSON.parse(cfg);
      const tcp = (j.hosts || []).filter((h) => /^tcp:\/\//.test(h));
      if (tcp.length) out.push({ where: '/etc/docker/daemon.json', hosts: tcp, tls: !!j.tlsverify });
    } catch { /* malformed config: nothing to evaluate */ }
  }
  const unitFiles = [...ctx.fs.glob('/etc/systemd/system/docker.service.d/*.conf'), '/etc/systemd/system/docker.service', '/usr/lib/systemd/system/docker.service', '/lib/systemd/system/docker.service'];
  for (const f of unitFiles) {
    const t = ctx.fs.read(f);
    if (!t) continue;
    for (const l of t.split(/\r?\n/)) {
      if (!/^\s*ExecStart\s*=/.test(l)) continue;
      const hosts = [...l.matchAll(/(?:-H|--host)[ =](tcp:\/\/\S+)/g)].map((m) => m[1]);
      if (hosts.length) out.push({ where: f, hosts, tls: /--tlsverify/.test(l) });
    }
  }
  return out;
}

export default [
  rule({
    id: 'vm-svc-legacy-enabled', area: 'services', severity: 'medium', title: 'Legacy or unnecessary network service is enabled',
    description: 'The service is enabled at boot or currently running. Services that send credentials in clear text, have no authentication, or are simply not needed enlarge the attack surface.',
    remediation: 'Disable and stop it (systemctl disable --now <unit>) or uninstall the package if the host does not need it.',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; services belong to the host');
      const out = [];
      for (const [label, names, severity, why] of LEGACY) {
        const st = ctx.serviceState(...names);
        if (st.enabled || st.running) out.push({ resource: `service:${names[0]}`, severity, detail: `${label} ${why}. State: ${[st.enabled ? 'enabled' : null, st.running ? 'running' : null].filter(Boolean).join(', ')}.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-pkg-legacy-installed', area: 'services', severity: 'medium', title: 'Legacy network-service package is installed',
    description: 'Packages for Telnet, rsh, TFTP, NIS, xinetd, finger and similar services are obsolete and insecure; even if the service is disabled today, installing the package invites it back.',
    remediation: 'Remove the package (apt purge / dnf remove / apk del <package>).',
    evaluate(ctx) {
      const p = ctx.packages();
      if (!p) return na('no readable package database (only dpkg and apk are read; rpm databases are not)');
      return p.list.filter((x) => LEGACY_PKGS.test(x.name)).map((x) => ({ resource: `package:${x.name}`, detail: `${x.name} ${x.version || ''} is installed.` }));
    },
  }),

  rule({
    id: 'vm-docker-exposure', area: 'services', severity: 'high', title: 'Docker daemon is exposed beyond local root',
    description: 'The Docker API gives root-equivalent control of the host. It must not listen on an unauthenticated TCP socket, the Unix socket must not be world-accessible, and membership of the docker group should be tightly controlled.',
    remediation: 'Remove tcp:// hosts (or require --tlsverify with client certificates), keep /var/run/docker.sock at 660 root:docker, and review docker group members.',
    evaluate(ctx) {
      const installed = ctx.fs.exists('/usr/bin/dockerd') || ctx.fs.exists('/etc/docker') || ctx.fs.exists('/lib/systemd/system/docker.service') || ctx.fs.exists('/usr/lib/systemd/system/docker.service');
      if (!installed) return na('Docker is not installed');
      const out = [];
      for (const h of dockerDaemonHosts(ctx)) {
        out.push({ resource: h.where, severity: h.tls ? 'medium' : 'critical', detail: `Docker listens on ${h.hosts.join(', ')}${h.tls ? ' (TLS client verification configured).' : ' with no TLS client verification — unauthenticated remote root.'}` });
      }
      for (const p of ['/var/run/docker.sock', '/run/docker.sock']) {
        const st = ctx.fs.stat(p);
        if (st && (st.mode & 0o006)) out.push({ resource: p, detail: `The Docker socket is accessible to every user (mode ${(st.mode & 0o777).toString(8)}).` });
      }
      const g = (ctx.groups() || []).find((x) => x.name === 'docker');
      if (g && g.members.length) out.push({ resource: 'group:docker', severity: 'low', detail: `Members of the docker group have root-equivalent access: ${g.members.join(', ')}.` });
      return out;
    },
  }),
];
