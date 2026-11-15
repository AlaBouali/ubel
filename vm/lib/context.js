'use strict';
// context.js — the lazily-evaluated view of one machine that ubel-vm's rules read from.
//
// Everything is derived from files (an FsView over "/" or over a mounted image root) and, on a live Linux host,
// from /proc and /sys. No command is run and no package manager is invoked. Each accessor is memoised, so a
// rule that needs /etc/passwd or the listening-socket table asks for it and every other rule shares the result.

import fs from 'node:fs';
import { FsView } from './fsview.js';

const VIRTUAL_FS = new Set([
  'proc', 'sysfs', 'devtmpfs', 'devpts', 'cgroup', 'cgroup2', 'securityfs', 'debugfs', 'tracefs', 'bpf', 'pstore',
  'configfs', 'fusectl', 'mqueue', 'hugetlbfs', 'binfmt_misc', 'autofs', 'nfs', 'nfs4', 'cifs', 'smb3', 'fuse.lxcfs',
  'fuse.gvfsd-fuse', 'fuse.portal', '9p', 'overlay', 'squashfs', 'iso9660', 'ecryptfs', 'rpc_pipefs', 'nsfs', 'efivarfs',
]);
const SKIP_DIRS = ['/proc', '/sys', '/dev', '/run', '/var/lib/docker', '/var/lib/containerd', '/var/lib/kubelet',
  '/var/lib/lxd', '/var/lib/lxc', '/var/lib/snapd', '/var/snap', '/snap', '/var/lib/libvirt/images', '/mnt', '/media'];

const hex = (n) => n.toString(16);
function hexIp(h) {
  if (h.length === 8) return [3, 2, 1, 0].map((i) => parseInt(h.slice(i * 2, i * 2 + 2), 16)).join('.');
  const words = h.match(/.{8}/g).map((w) => w.match(/../g).reverse().join(''));
  const g = words.join('').match(/.{4}/g);
  if (g.slice(0, 5).every((x) => x === '0000') && g[5] === 'ffff') {
    return `::ffff:${parseInt(g[6].slice(0, 2), 16)}.${parseInt(g[6].slice(2), 16)}.${parseInt(g[7].slice(0, 2), 16)}.${parseInt(g[7].slice(2), 16)}`;
  }
  return g.map((x) => x.replace(/^0+(?=.)/, '')).join(':').replace(/(?:^|:)0(?::0)+(?::|$)/, '::');
}
const isAny = (a) => a === '0.0.0.0' || a === '::' || a === '::ffff:0.0.0.0';
const isLoopback = (a) => /^127\./.test(a) || a === '::1' || /^::ffff:127\./.test(a);

class VmContext {
  /**
   * @param {{root?:string, skipFsWalk?:boolean, fsMaxEntries?:number, fsTimeoutMs?:number, now?:Date}} [opts]
   */
  constructor(opts = {}) {
    this.fs = new FsView(opts.root || '/');
    this.live = this.fs.live;
    this.root = this.fs.root;
    this.opts = { skipFsWalk: false, fsMaxEntries: 3_000_000, fsTimeoutMs: 90_000, ...opts };
    this.now = opts.now || new Date();
    this.notes = [];              // coverage caveats collected while scanning (truncated walks, …)
    this._m = new Map();
  }

  _memo(key, fn) {
    if (!this._m.has(key)) this._m.set(key, fn());
    return this._m.get(key);
  }

  // ── identity ───────────────────────────────────────────────────────────────
  get osRelease() {
    return this._memo('os', () => {
      const text = this.fs.read('/etc/os-release') ?? this.fs.read('/usr/lib/os-release');
      if (text === null) return null;
      const kv = {};
      for (const line of text.split(/\r?\n/)) {
        const m = line.match(/^([A-Z_]+)=(.*)$/);
        if (m) kv[m[1]] = m[2].trim().replace(/^["']|["']$/g, '');
      }
      return {
        id: (kv.ID || '').toLowerCase(), idLike: (kv.ID_LIKE || '').toLowerCase().split(/\s+/).filter(Boolean),
        versionId: kv.VERSION_ID || '', name: kv.NAME || '', prettyName: kv.PRETTY_NAME || kv.NAME || '', codename: kv.VERSION_CODENAME || '',
      };
    });
  }

  /** 'debian' | 'rhel' | 'alpine' | 'suse' | 'arch' | 'other' */
  get family() {
    const o = this.osRelease;
    if (!o) return 'other';
    const all = [o.id, ...o.idLike];
    if (all.some((x) => ['debian', 'ubuntu'].includes(x))) return 'debian';
    if (all.some((x) => ['rhel', 'fedora', 'centos', 'rocky', 'almalinux', 'ol', 'amzn'].includes(x))) return 'rhel';
    if (all.includes('alpine')) return 'alpine';
    if (all.some((x) => x.includes('suse') || x === 'sles')) return 'suse';
    if (all.includes('arch')) return 'arch';
    return 'other';
  }

  get hostname() {
    return this._memo('host', () => {
      const t = (this.live ? this.fs.read('/proc/sys/kernel/hostname') : null) ?? this.fs.read('/etc/hostname');
      return t ? t.trim() : null;
    });
  }

  get environment() {
    return this._memo('env', () => {
      const dmi = (n) => { try { const t = this.fs.read('/sys/class/dmi/id/' + n); return t ? t.trim() : null; } catch { return null; } };
      const out = { hostname: this.hostname, os: this.osRelease ? this.osRelease.prettyName : null, mode: this.live ? 'live' : 'offline-root', root: this.root };
      if (this.live) {
        const k = this.fs.read('/proc/sys/kernel/osrelease');
        out.kernel = k ? k.trim() : null;
        const vendor = dmi('sys_vendor'), product = dmi('product_name'), bios = dmi('bios_vendor'), tag = dmi('chassis_asset_tag');
        const cpu = this.fs.read('/proc/cpuinfo') || '';
        const hv = /^flags\s*:.*\bhypervisor\b/m.test(cpu);
        const sig = `${vendor || ''} ${product || ''} ${bios || ''} ${tag || ''}`.toLowerCase();
        let virt = null, cloud = null;
        if (/vmware/.test(sig)) virt = 'VMware';
        else if (/virtualbox|innotek/.test(sig)) virt = 'VirtualBox';
        else if (/microsoft/.test(sig) && /virtual/.test(sig)) virt = 'Hyper-V';
        else if (/xen/.test(sig)) virt = 'Xen';
        else if (/amazon ec2|nitro/.test(sig)) { virt = 'AWS Nitro / Xen'; cloud = 'AWS'; }
        else if (/google/.test(sig)) { virt = 'KVM (Google Compute Engine)'; cloud = 'GCP'; }
        else if (/qemu|kvm|bochs|seabios|openstack|digitalocean|hetzner|ovh/.test(sig)) virt = 'KVM / QEMU';
        else if (hv) virt = 'unidentified hypervisor';
        if (/oraclecloud/.test(sig)) cloud = 'Oracle Cloud';
        if (/microsoft/.test(sig) && /virtual/.test(sig) && /7783-7084-3265-9085-8269-3286-77/.test(tag || '')) cloud = 'Azure';
        if (/digitalocean/.test(sig)) cloud = 'DigitalOcean';
        out.virtualization = virt || (hv ? 'hypervisor flag set' : 'none detected (bare metal or hidden)');
        if (cloud) out.cloud_provider = cloud;
        if (vendor) out.system_vendor = vendor;
        if (product) out.product_name = product;
      }
      out.container = this.inContainer;
      return out;
    });
  }

  get inContainer() {
    return this._memo('incont', () => {
      if (!this.live) return false;
      if (this.fs.exists('/.dockerenv') || this.fs.exists('/run/.containerenv')) return true;
      const cg = this.fs.read('/proc/1/cgroup') || '';
      return /(docker|kubepods|containerd|lxc)/.test(cg);
    });
  }

  get hasContainerRuntime() {
    return this._memo('crt', () => ['/usr/bin/dockerd', '/usr/bin/containerd', '/usr/bin/podman', '/usr/bin/crio', '/usr/local/bin/containerd',
      '/var/lib/kubelet', '/usr/bin/kubelet', '/usr/local/bin/kubelet', '/etc/kubernetes'].some((p) => this.fs.exists(p)));
  }

  // ── accounts ───────────────────────────────────────────────────────────────
  passwd() {
    return this._memo('passwd', () => {
      const t = this.fs.read('/etc/passwd');
      if (t === null) return null;
      return t.split(/\r?\n/).filter((l) => l && !l.startsWith('#')).map((l) => {
        const f = l.split(':');
        return { name: f[0], pw: f[1], uid: Number(f[2]), gid: Number(f[3]), gecos: f[4], home: f[5], shell: f[6] || '', raw: l };
      }).filter((u) => u.name && Number.isInteger(u.uid));
    });
  }

  /** Map name → { hash, lastChange, ... }; throws EACCES when /etc/shadow cannot be read, null when it does not exist. */
  shadow() {
    return this._memo('shadow', () => {
      const t = this.fs.read('/etc/shadow');
      if (t === null) return null;
      const m = new Map();
      for (const l of t.split(/\r?\n/)) {
        if (!l || l.startsWith('#')) continue;
        const f = l.split(':');
        m.set(f[0], { hash: f[1], lastChange: f[2], min: f[3], max: f[4], warn: f[5], inactive: f[6], expire: f[7] });
      }
      return m;
    });
  }

  groups() {
    return this._memo('groups', () => {
      const t = this.fs.read('/etc/group');
      if (t === null) return null;
      return t.split(/\r?\n/).filter((l) => l && !l.startsWith('#')).map((l) => {
        const f = l.split(':');
        return { name: f[0], gid: Number(f[2]), members: (f[3] || '').split(',').filter(Boolean) };
      });
    });
  }

  loginDefs() {
    return this._memo('logindefs', () => {
      const m = new Map();
      for (const l of this.fs.lines('/etc/login.defs') || []) {
        const mm = l.match(/^(\S+)\s+(.*)$/);
        if (mm) m.set(mm[1].toUpperCase(), mm[2].trim());
      }
      return m;
    });
  }

  validShells() {
    return this._memo('shells', () => new Set(this.fs.lines('/etc/shells') || ['/bin/sh', '/bin/bash']));
  }

  /** Accounts a person can log in as: has a real shell and (uid >= UID_MIN or root). */
  interactiveUsers() {
    return this._memo('interactive', () => {
      const min = Number(this.loginDefs().get('UID_MIN')) || 1000;
      const noLogin = /(nologin|false|sync|shutdown|halt)$/;
      return (this.passwd() || []).filter((u) => (u.uid === 0 || (u.uid >= min && u.uid < 65534)) && u.shell && !noLogin.test(u.shell));
    });
  }

  // ── packages ───────────────────────────────────────────────────────────────
  /** { source, list:[{name, version, arch?}] } from dpkg / apk metadata; null when no readable package database. */
  packages() {
    return this._memo('pkgs', () => {
      const dpkg = this.fs.read('/var/lib/dpkg/status', 64 * 1024 * 1024);
      if (dpkg !== null) {
        const list = [];
        for (const block of dpkg.split(/\n\n+/)) {
          if (!/^Status:.*\binstalled\b/m.test(block) || /^Status:.*(not-installed|config-files)/m.test(block)) continue;
          const name = (block.match(/^Package:\s*(.+)$/m) || [])[1];
          const version = (block.match(/^Version:\s*(.+)$/m) || [])[1];
          const arch = (block.match(/^Architecture:\s*(.+)$/m) || [])[1];
          const source = (block.match(/^Source:\s*(\S+)/m) || [])[1];
          if (name) list.push({ name, version, arch, source: source || name });
        }
        return { source: 'dpkg', list };
      }
      const apk = this.fs.read('/lib/apk/db/installed', 64 * 1024 * 1024);
      if (apk !== null) {
        const list = [];
        for (const block of apk.split(/\n\n+/)) {
          const name = (block.match(/^P:(.+)$/m) || [])[1];
          const version = (block.match(/^V:(.+)$/m) || [])[1];
          if (name) list.push({ name, version });
        }
        return { source: 'apk', list };
      }
      return null;
    });
  }

  /** True when a package whose name matches (string = exact, RegExp = test) is installed. null when the package database cannot be read (rpm). */
  hasPackage(match) {
    const p = this.packages();
    if (!p) return null;
    return p.list.some((x) => (match instanceof RegExp ? match.test(x.name) : x.name === match));
  }

  // ── services ───────────────────────────────────────────────────────────────
  _unitIndex() {
    return this._memo('units', () => {
      const wanted = new Set();         // unit names linked from a *.wants / *.requires directory
      const masked = new Set();
      const present = new Set();        // unit files that exist
      for (const base of ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system', '/run/systemd/system']) {
        const names = this.fs.readdir(base) || [];
        for (const n of names) {
          if (/\.(wants|requires)$/.test(n)) {
            for (const u of this.fs.readdir(`${base}/${n}`) || []) wanted.add(u);
          } else if (/\.(service|socket|timer)$/.test(n)) {
            present.add(n);
            if (base === '/etc/systemd/system' && this.fs.readlink(`${base}/${n}`) === '/dev/null') masked.add(n);
          }
        }
      }
      return { wanted, masked, present };
    });
  }

  _initScripts() {
    return this._memo('initd', () => new Set(this.fs.readdir('/etc/init.d') || []));
  }

  _rcLinks() {
    return this._memo('rc', () => {
      const s = new Set();
      for (let i = 0; i <= 6; i++) for (const n of this.fs.readdir(`/etc/rc${i}.d`) || []) if (/^S\d+/.test(n)) s.add(n.replace(/^S\d+/, ''));
      return s;
    });
  }

  /**
   * State of a service by its base name (no ".service"): { installed, enabled, masked, running (null offline) }.
   * `names` may list alternative unit names (sshd/ssh, chronyd/chrony).
   */
  serviceState(...names) {
    const idx = this._unitIndex();
    let installed = false, enabled = false, masked = false;
    for (const n of names) {
      for (const suf of ['.service', '.socket']) {
        const u = n + suf;
        if (idx.present.has(u)) installed = true;
        if (idx.wanted.has(u)) enabled = true;
        if (idx.masked.has(u)) masked = true;
      }
      if (this._initScripts().has(n)) { installed = true; if (this._rcLinks().has(n)) enabled = true; }
    }
    const running = this.live ? this.processes().some((p) => names.includes(p.comm) || names.some((n) => p.comm === n.slice(0, 15))) : null;
    if (running) { installed = true; }
    return { installed, enabled: enabled && !masked, masked, running };
  }

  /** Live process table [{pid, comm, cmdline, uid}] (null off a live host). */
  processes() {
    return this._memo('procs', () => {
      if (!this.live) return [];
      const out = [];
      for (const d of this.fs.readdir('/proc') || []) {
        if (!/^\d+$/.test(d)) continue;
        try {
          const comm = (this.fs.read(`/proc/${d}/comm`) || '').trim();
          if (!comm) continue;
          const cmdline = (this.fs.read(`/proc/${d}/cmdline`) || '').replace(/\0/g, ' ').trim();
          const st = this.fs.lstat(`/proc/${d}`);
          out.push({ pid: Number(d), comm, cmdline, uid: st ? st.uid : null });
        } catch { /* process exited, or not readable */ }
      }
      return out;
    });
  }

  // ── kernel parameters ──────────────────────────────────────────────────────
  _sysctlFiles() {
    return this._memo('sysctlf', () => {
      const dirs = ['/etc/sysctl.d', '/run/sysctl.d', '/usr/local/lib/sysctl.d', '/usr/lib/sysctl.d', '/lib/sysctl.d'];
      const byName = new Map();
      for (const d of dirs) for (const n of this.fs.readdir(d) || []) if (/\.conf$/.test(n) && !byName.has(n)) byName.set(n, `${d}/${n}`);
      const ordered = [...byName.keys()].sort().map((n) => byName.get(n));
      ordered.push('/etc/sysctl.conf');
      const values = new Map();
      for (const f of ordered) {
        for (const l of this.fs.lines(f) || []) {
          if (l.startsWith(';')) continue;
          const m = l.match(/^-?\s*([^=\s]+)\s*=\s*(.*)$/);
          if (m) values.set(m[1].replace(/\//g, '.'), m[2].trim().replace(/\s+/g, ' '));
        }
      }
      return values;
    });
  }

  /** Effective value of a sysctl ("net.ipv4.ip_forward"): the live kernel value on a live host, the configured value offline; null when unknown. */
  sysctl(key) {
    if (this.live) {
      const t = this.fs.read('/proc/sys/' + key.replace(/\./g, '/'));
      return t === null ? null : t.trim().replace(/\s+/g, ' ');
    }
    const v = this._sysctlFiles().get(key);
    return v === undefined ? null : v;
  }

  // ── mounts ─────────────────────────────────────────────────────────────────
  mounts() {
    return this._memo('mounts', () => {
      const out = [];
      const src = this.live ? this.fs.read('/proc/self/mounts') : this.fs.read('/etc/fstab');
      for (const l of (src || '').split(/\r?\n/)) {
        if (!l.trim() || l.trim().startsWith('#')) continue;
        const f = l.trim().split(/\s+/);
        if (f.length < 4) continue;
        out.push({ device: f[0], mountpoint: f[1].replace(/\\040/g, ' '), fstype: f[2], options: new Set(f[3].split(',')) });
      }
      return out;
    });
  }

  mountFor(mountpoint) { return this.mounts().find((m) => m.mountpoint === mountpoint) || null; }

  // ── sshd ───────────────────────────────────────────────────────────────────
  /**
   * Effective sshd_config (global section only: everything before the first Match). OpenSSH keeps the FIRST value it
   * sees for a keyword, and Include is expanded where it appears, so this does the same.
   * @returns {{present:boolean, files:string[], get:(k:string)=>string|undefined, all:(k:string)=>string[], hasMatch:boolean}|null}
   */
  sshd() {
    return this._memo('sshd', () => {
      if (!this.fs.exists('/etc/ssh/sshd_config')) return null;
      const values = new Map();
      const files = [];
      let hasMatch = false;
      let stop = false;
      const parse = (file, depth) => {
        if (depth > 8 || stop) return;
        const t = this.fs.read(file);
        if (t === null) return;
        files.push(file);
        for (const raw of t.split(/\r?\n/)) {
          const line = raw.trim();
          if (!line || line.startsWith('#')) continue;
          const m = line.match(/^(\S+?)(?:\s*=\s*|\s+)(.*)$/);
          if (!m) continue;
          const key = m[1].toLowerCase();
          const val = m[2].trim().replace(/^"(.*)"$/, '$1');
          if (key === 'include') {
            for (const pat of val.split(/\s+/)) {
              const p = pat.startsWith('/') ? pat : '/etc/ssh/' + pat;
              for (const f of this.fs.glob(p)) parse(f, depth + 1);
            }
          } else if (key === 'match') { hasMatch = true; stop = true; return; }
          else if (!values.has(key)) values.set(key, [val]);
          else if (['hostkey', 'listenaddress', 'port', 'subsystem', 'allowusers', 'allowgroups', 'denyusers', 'denygroups', 'authorizedkeysfile'].includes(key)) values.get(key).push(val);
        }
      };
      parse('/etc/ssh/sshd_config', 0);
      return { present: true, files, hasMatch, get: (k) => (values.get(k.toLowerCase()) || [])[0], all: (k) => values.get(k.toLowerCase()) || [] };
    });
  }

  // ── network ────────────────────────────────────────────────────────────────
  /** Listening TCP sockets and bound UDP sockets (live Linux only): [{proto, addr, port, inode, wildcard, loopback}]. */
  listeners() {
    return this._memo('listeners', () => {
      if (!this.live) return null;
      const out = [];
      for (const [file, proto, want] of [['tcp', 'tcp', '0A'], ['tcp6', 'tcp6', '0A'], ['udp', 'udp', '07'], ['udp6', 'udp6', '07']]) {
        const t = this.fs.read('/proc/net/' + file);
        if (!t) continue;
        for (const line of t.split('\n').slice(1)) {
          const f = line.trim().split(/\s+/);
          if (f.length < 10 || f[3] !== want) continue;
          const [lh, lp] = f[1].split(':');
          const addr = hexIp(lh);
          const remote = f[2].split(':');
          if (proto.startsWith('udp') && parseInt(remote[1], 16) !== 0) continue;   // connected UDP socket, not a server
          out.push({ proto, addr, port: parseInt(lp, 16), inode: f[9], wildcard: isAny(addr), loopback: isLoopback(addr) });
        }
      }
      return out;
    });
  }

  /** inode → { pid, comm } for the given socket inodes (needs root to see other users' processes). */
  socketOwners(inodes) {
    const want = new Set(inodes);
    const found = new Map();
    if (!this.live || !want.size) return found;
    const comms = new Map();
    for (const d of this.fs.readdir('/proc') || []) {
      if (!/^\d+$/.test(d)) continue;
      let fds;
      try { fds = fs.readdirSync(`/proc/${d}/fd`); } catch { continue; }
      for (const fd of fds) {
        let l;
        try { l = fs.readlinkSync(`/proc/${d}/fd/${fd}`); } catch { continue; }
        const m = l.match(/^socket:\[(\d+)\]$/);
        if (m && want.has(m[1]) && !found.has(m[1])) {
          if (!comms.has(d)) { try { comms.set(d, (fs.readFileSync(`/proc/${d}/comm`, 'utf8') || '').trim()); } catch { comms.set(d, '?'); } }
          found.set(m[1], { pid: Number(d), comm: comms.get(d) });
        }
      }
      if (found.size === want.size) break;
    }
    return found;
  }

  // ── filesystem scan (one shared pass) ──────────────────────────────────────
  /**
   * One walk of the whole tree collecting the things several rules need.
   * @returns {{worldWritableFiles:string[], worldWritableDirsNoSticky:string[], setuid:{path:string,mode:number,uid:number}[], setgid:{path:string,mode:number,gid:number}[], visited:number, truncated:boolean}|null}
   */
  fsScan() {
    return this._memo('fsscan', () => {
      if (this.opts.skipFsWalk) return null;
      const skipMounts = new Set();
      if (this.live) for (const m of this.mounts()) if (VIRTUAL_FS.has(m.fstype) || m.fstype.startsWith('fuse.')) skipMounts.add(m.mountpoint);
      const skipPrefix = [...SKIP_DIRS, ...skipMounts].filter((d) => d !== '/');
      const skip = (p) => skipPrefix.some((d) => p === d || p.startsWith(d + '/'));
      const tmpish = (p) => /^\/(tmp|var\/tmp|dev\/shm|var\/crash|var\/lock|run)(\/|$)/.test(p);
      const res = { worldWritableFiles: [], worldWritableDirsNoSticky: [], setuid: [], setgid: [], visited: 0, truncated: false };
      const w = this.fs.walk(['/'], { skip, maxEntries: this.opts.fsMaxEntries, deadline: Date.now() + this.opts.fsTimeoutMs }, (p, st) => {
        if (st.isSymlink) return;
        if (st.isFile) {
          if ((st.mode & 0o002) && !tmpish(p) && res.worldWritableFiles.length < 5000) res.worldWritableFiles.push(p);
          if (st.mode & 0o4000) res.setuid.push({ path: p, mode: st.mode, uid: st.uid });
          if (st.mode & 0o2000) res.setgid.push({ path: p, mode: st.mode, gid: st.gid });
        } else if (st.isDir && (st.mode & 0o002) && !(st.mode & 0o1000) && res.worldWritableDirsNoSticky.length < 5000) {
          res.worldWritableDirsNoSticky.push(p);
        }
      });
      res.visited = w.visited; res.truncated = w.truncated;
      if (w.truncated) this.notes.push(`The filesystem walk stopped after ${w.visited} entries (limit or --fs-timeout reached); file-permission findings may be incomplete.`);
      return res;
    });
  }
}

export { VmContext, hexIp, isAny, isLoopback, VIRTUAL_FS };
