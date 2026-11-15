'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';

const ge = (n) => (v) => Number(v) >= n;
const eq = (s) => (v) => v === s;

// id, keys, test, expected, severity (string | fn(value)), title, description
const SYSCTLS = [
  ['kernel-randomize-va-space', ['kernel.randomize_va_space'], eq('2'), '2', (v) => (v === '0' ? 'high' : 'medium'), 'Address-space layout randomisation (ASLR) is not fully enabled', 'Without full ASLR, memory-corruption exploits can rely on predictable addresses.'],
  ['kernel-kptr-restrict', ['kernel.kptr_restrict'], ge(1), '1 or 2', 'low', 'Kernel pointers are exposed to unprivileged users', 'Kernel addresses in /proc help attackers defeat ASLR when exploiting the kernel.'],
  ['kernel-dmesg-restrict', ['kernel.dmesg_restrict'], eq('1'), '1', 'low', 'Unprivileged users can read the kernel log', 'dmesg can leak kernel addresses and hardware details useful to an attacker.'],
  ['kernel-yama-ptrace-scope', ['kernel.yama.ptrace_scope'], ge(1), '1 or higher', 'low', 'Any process may ptrace its siblings', 'With ptrace_scope 0, a compromised process can read the memory of other processes of the same user (credentials, keys).'],
  ['kernel-sysrq', ['kernel.sysrq'], (v) => v !== '1', '0 (or a restricted bitmask)', 'low', 'All magic SysRq functions are enabled', 'Full SysRq access allows rebooting, killing processes and remounting from a local console.'],
  ['kernel-unprivileged-bpf', ['kernel.unprivileged_bpf_disabled'], ge(1), '1 or 2', 'low', 'Unprivileged users can load eBPF programs', 'Unprivileged eBPF has been the source of many kernel privilege-escalation bugs.'],
  ['kernel-kexec-load', ['kernel.kexec_load_disabled'], eq('1'), '1', 'low', 'kexec can load a replacement kernel at runtime', 'A privileged attacker could load an unsigned kernel; disable kexec when it is not used.'],
  ['kernel-perf-event-paranoid', ['kernel.perf_event_paranoid'], ge(2), '2 or higher', 'low', 'Unprivileged users can use perf events broadly', 'perf_event_paranoid below 2 exposes kernel and process profiling data and a larger attack surface.'],
  ['fs-protected-links', ['fs.protected_hardlinks', 'fs.protected_symlinks'], eq('1'), '1', 'medium', 'Hard-link / symlink protections are off', 'Without protected_hardlinks and protected_symlinks, local users can abuse links in world-writable directories to attack privileged programs.'],
  ['fs-protected-fifos-regular', ['fs.protected_fifos', 'fs.protected_regular'], ge(1), '1 or 2', 'low', 'FIFO / regular-file creation protections are off', 'These settings stop privileged programs being tricked into opening attacker-planted files in sticky directories.'],
  ['fs-suid-dumpable', ['fs.suid_dumpable'], eq('0'), '0', 'medium', 'Set-uid programs may write core dumps', 'Core dumps of privileged programs can contain secrets and are readable by the invoking user.'],
  ['vm-mmap-min-addr', ['vm.mmap_min_addr'], ge(65536), '65536 or higher', 'low', 'Low memory addresses can be mapped by users', 'A low mmap_min_addr makes kernel NULL-pointer dereference bugs exploitable.'],
  ['net-ipv4-source-route', ['net.ipv4.conf.all.accept_source_route', 'net.ipv4.conf.default.accept_source_route'], eq('0'), '0', 'medium', 'IPv4 source-routed packets are accepted', 'Source routing lets a sender dictate the path of a packet and can bypass network controls.'],
  ['net-ipv4-accept-redirects', ['net.ipv4.conf.all.accept_redirects', 'net.ipv4.conf.default.accept_redirects'], eq('0'), '0', 'medium', 'ICMP redirects are accepted', 'Accepting ICMP redirects lets a nearby host alter this machine\'s routing table.'],
  ['net-ipv4-secure-redirects', ['net.ipv4.conf.all.secure_redirects', 'net.ipv4.conf.default.secure_redirects'], eq('0'), '0', 'low', 'Redirects from gateways are accepted', 'Even "secure" ICMP redirects from listed gateways should not change routing on a server.'],
  ['net-ipv4-send-redirects', ['net.ipv4.conf.all.send_redirects', 'net.ipv4.conf.default.send_redirects'], eq('0'), '0', 'medium', 'The host sends ICMP redirects', 'Only routers should send redirects; a host that does can be used to steer traffic.', (ctx) => ctx.sysctl('net.ipv4.ip_forward') === '1'],
  ['net-ipv4-log-martians', ['net.ipv4.conf.all.log_martians', 'net.ipv4.conf.default.log_martians'], eq('1'), '1', 'low', 'Packets with impossible source addresses are not logged', 'Logging martian packets helps detect spoofing and misrouting.'],
  ['net-ipv4-rp-filter', ['net.ipv4.conf.all.rp_filter', 'net.ipv4.conf.default.rp_filter'], (v) => v === '1' || v === '2', '1 (or 2)', 'low', 'Reverse-path filtering is off', 'Without rp_filter the host accepts spoofed source addresses arriving on the wrong interface.'],
  ['net-ipv4-icmp-broadcast', ['net.ipv4.icmp_echo_ignore_broadcasts'], eq('1'), '1', 'low', 'The host answers broadcast pings', 'Responding to broadcast ICMP echo enables Smurf-style amplification.'],
  ['net-ipv4-icmp-bogus', ['net.ipv4.icmp_ignore_bogus_error_responses'], eq('1'), '1', 'low', 'Bogus ICMP error responses are not ignored', 'Ignoring bogus ICMP errors avoids log flooding and some spoofing tricks.'],
  ['net-ipv4-tcp-syncookies', ['net.ipv4.tcp_syncookies'], eq('1'), '1', 'medium', 'TCP SYN cookies are disabled', 'SYN cookies protect against SYN-flood denial of service.'],
  ['net-ipv6-redirects-source-route', ['net.ipv6.conf.all.accept_redirects', 'net.ipv6.conf.default.accept_redirects', 'net.ipv6.conf.all.accept_source_route', 'net.ipv6.conf.default.accept_source_route'], eq('0'), '0', 'medium', 'IPv6 redirects or source routing are accepted', 'Accepting IPv6 redirects or source-routed packets lets neighbours alter routing for this host.', (ctx) => ctx.sysctl('net.ipv6.conf.all.disable_ipv6') === '1'],
  ['net-ip-forward', ['net.ipv4.ip_forward'], eq('0'), '0', (v, ctx) => (ctx.hasContainerRuntime ? 'info' : 'low'), 'IP forwarding is enabled', 'A host that is not a router, VPN gateway or container host should not forward packets between networks.'],
];

const sysctlRules = SYSCTLS.map(([id, keys, test, expected, severity, title, description, skipWhen]) => rule({
  id: `vm-sysctl-${id}`, area: 'kernel', severity: typeof severity === 'string' ? severity : 'medium', title, description,
  remediation: `Set ${keys.map((k) => `${k} = ${expected.split(' ')[0]}`).join(', ')} in /etc/sysctl.d/99-hardening.conf and apply with sysctl --system.`,
  evaluate(ctx) {
    if (skipWhen && skipWhen(ctx)) return na('not applicable on this host (IPv6 disabled, or the machine routes traffic)');
    const out = [];
    let seen = 0;
    for (const k of keys) {
      const v = ctx.sysctl(k);
      if (v === null) continue;
      seen++;
      if (!test(v)) out.push({
        resource: `sysctl:${k}`,
        severity: typeof severity === 'function' ? severity(v, ctx) : undefined,
        detail: `${k} is ${v}; expected ${expected}.${id === 'net-ip-forward' && ctx.hasContainerRuntime ? ' A container runtime is present, which normally needs forwarding.' : ''}`,
      });
    }
    if (!seen) return na(ctx.live ? 'the kernel does not expose this parameter' : 'not set in the image\'s sysctl configuration (the kernel default applies)');
    return out;
  },
}));

export default [
  ...sysctlRules,

  rule({
    id: 'vm-cpu-vulnerabilities', area: 'kernel', severity: 'medium', title: 'CPU vulnerability is not mitigated',
    description: 'The kernel reports that this CPU is vulnerable to a speculative-execution or related hardware flaw and no mitigation is active. On a virtual machine this also depends on the hypervisor exposing the mitigation.',
    remediation: 'Update the kernel and microcode, remove "mitigations=off" from the kernel command line, and make sure the hypervisor / instance type exposes the CPU features needed.',
    evaluate(ctx) {
      if (!ctx.live) return na('needs a live host (/sys/devices/system/cpu/vulnerabilities)');
      const dir = '/sys/devices/system/cpu/vulnerabilities';
      const names = ctx.fs.readdir(dir);
      if (!names) return na('the kernel does not report CPU vulnerabilities');
      const out = [];
      for (const n of names) {
        const v = (ctx.fs.read(`${dir}/${n}`) || '').trim();
        if (/^Vulnerable/i.test(v)) out.push({ resource: `cpu:${n}`, detail: `${n}: ${v}` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-kernel-unneeded-modules', area: 'kernel', severity: 'low', title: 'Rarely needed kernel modules are loaded',
    description: 'Obscure network protocols and filesystems (DCCP, SCTP, RDS, TIPC, cramfs, …) have a long history of kernel vulnerabilities and are unused on most servers.',
    remediation: 'Blacklist them: echo "install <module> /bin/false" > /etc/modprobe.d/<module>.conf, then unload the module.',
    evaluate(ctx) {
      if (!ctx.live) return na('needs a live host (/proc/modules)');
      const t = ctx.fs.read('/proc/modules');
      if (t === null) return na('/proc/modules is not available');
      const loaded = new Set(t.split('\n').map((l) => l.split(' ')[0]));
      return ['dccp', 'sctp', 'rds', 'tipc', 'cramfs', 'freevxfs', 'jffs2', 'hfs', 'hfsplus', 'udf'].filter((m) => loaded.has(m)).map((m) => ({ resource: `module:${m}` }));
    },
  }),

  rule({
    id: 'vm-mac-not-enforcing', area: 'kernel', severity: 'low', title: 'No mandatory access control (SELinux / AppArmor) is enforcing',
    description: 'SELinux or AppArmor confines services so a compromised daemon cannot freely read or modify the rest of the system. None is active or enforcing here.',
    remediation: 'Enable SELinux in enforcing mode (RHEL family: SELINUX=enforcing in /etc/selinux/config) or AppArmor (Debian/Ubuntu/SUSE: install apparmor and enable the service).',
    evaluate(ctx) {
      if (ctx.inContainer) return na('running inside a container; the host decides');
      const rhel = ctx.family === 'rhel';
      if (ctx.live) {
        const se = ctx.fs.read('/sys/fs/selinux/enforce');
        if (se !== null) {
          return se.trim() === '1' ? [] : [{ resource: 'selinux', severity: 'medium', detail: 'SELinux is loaded but in permissive mode.' }];
        }
        const aa = ctx.fs.read('/sys/module/apparmor/parameters/enabled');
        if (aa && aa.trim() === 'Y') return [];
        return [{ resource: 'mac', severity: rhel ? 'medium' : 'low', detail: 'Neither SELinux nor AppArmor is active in the running kernel.' }];
      }
      const cfg = (ctx.fs.lines('/etc/selinux/config') || []).map((l) => l.match(/^SELINUX\s*=\s*(\w+)/i)).find(Boolean);
      if (cfg) return /enforcing/i.test(cfg[1]) ? [] : [{ resource: '/etc/selinux/config', severity: 'medium', detail: `SELINUX=${cfg[1]}.` }];
      if (ctx.fs.exists('/etc/apparmor.d')) return [];
      return [{ resource: 'mac', severity: rhel ? 'medium' : 'low', detail: 'No SELinux configuration or AppArmor profile directory in the image.' }];
    },
  }),
];
