'use strict';
import { rule, fmtMode, octal } from './util.js';
import { na } from '../lib/engine.js';

// path, most permissive acceptable mode, kind
const PERMS = [
  ['/etc/passwd', 0o644], ['/etc/passwd-', 0o644], ['/etc/group', 0o644], ['/etc/group-', 0o644],
  ['/etc/shadow', 0o640, 'secret'], ['/etc/shadow-', 0o640, 'secret'], ['/etc/gshadow', 0o640, 'secret'], ['/etc/gshadow-', 0o640, 'secret'],
  ['/etc/sudoers', 0o640, 'secret'], ['/etc/crontab', 0o644], ['/etc/fstab', 0o644], ['/etc/hosts', 0o644], ['/etc/ld.so.conf', 0o644],
  ['/boot/grub/grub.cfg', 0o644], ['/boot/grub2/grub.cfg', 0o644], ['/etc/cron.d', 0o755], ['/etc/cron.hourly', 0o755], ['/etc/cron.daily', 0o755],
  ['/etc/cron.weekly', 0o755], ['/etc/cron.monthly', 0o755], ['/etc/sudoers.d', 0o750], ['/etc/pam.d', 0o755], ['/etc/systemd/system', 0o755],
  ['/etc/init.d', 0o755], ['/etc/profile.d', 0o755], ['/etc/ssl/private', 0o750, 'secret'],
];

const GTFO = new Set(['bash', 'sh', 'dash', 'zsh', 'csh', 'tcsh', 'ksh', 'python', 'python2', 'python3', 'perl', 'ruby', 'node', 'php', 'lua', 'tclsh', 'awk', 'gawk',
  'mawk', 'find', 'vim', 'vi', 'nano', 'ed', 'less', 'more', 'man', 'cp', 'mv', 'dd', 'tar', 'zip', 'unzip', 'env', 'nmap', 'tee', 'expect', 'gdb', 'strace',
  'ltrace', 'socat', 'nc', 'ncat', 'netcat', 'curl', 'wget', 'docker', 'xargs', 'base64', 'od', 'xxd', 'cat', 'head', 'tail', 'cut', 'sort', 'diff', 'taskset',
  'nice', 'time', 'timeout', 'busybox', 'rsync', 'scp', 'ssh', 'openssl', 'git', 'make', 'gcc', 'cc', 'ionice', 'setarch', 'stdbuf', 'sed', 'tclsh']);

const SUID_OK = new Set(['su', 'sudo', 'sudoedit', 'passwd', 'chsh', 'chfn', 'newgrp', 'gpasswd', 'mount', 'umount', 'ping', 'ping6', 'pkexec', 'fusermount', 'fusermount3',
  'ssh-keysign', 'dbus-daemon-launch-helper', 'polkit-agent-helper-1', 'unix_chkpwd', 'chage', 'expiry', 'write', 'wall', 'ssh-agent', 'at', 'crontab', 'staprun',
  'pam_timestamp_check', 'mount.nfs', 'userhelper', 'Xorg.wrap', 'snap-confine', 'vmware-user-suid-wrapper', 'locate', 'mlocate', 'plocate', 'utempter', 'dotlockfile',
  'postdrop', 'postqueue', 'lockfile', 'mount.cifs', 'umount.nfs', 'newuidmap', 'newgidmap', 'bwrap', 'pt_chown', 'traceroute6.iputils', 'mtr-packet', 'sg', 'ksu',
  'unix2_chkpwd', 'ubuntu-core-launcher', 'authbind', 'chrome-sandbox', 'unix_update', 'passwd.shadow', 'crontab.cron', 'ssh-keysign', 'screen', 'wall.sysvinit',
  'mount.ecryptfs_private', 'umount.ecryptfs_private', 'ecryptfs-find', 'vmware-vmx', 'Xorg', 'X', 'lppasswd', 'cockpit-session', 'mount.fuse', 'abrt-action-install-debuginfo-to-abrt-cache']);

const WRITABLE_SENSITIVE = (p) => /^\/(etc|usr|bin|sbin|lib|lib64|lib32|boot|opt|root)(\/|$)/.test(p) || /^\/var\/(spool|lib\/dpkg|www)(\/|$)/.test(p);

function parseUnitExec(text) {
  const out = [];
  for (const l of text.split(/\r?\n/)) {
    const m = l.match(/^\s*Exec(?:Start|StartPre|StartPost|Stop|Reload)\s*=\s*[-@+!:|]*\s*(\/\S+)/);
    if (m) out.push(m[1]);
  }
  return out;
}

export default [
  rule({
    id: 'vm-fs-critical-permissions', area: 'filesystem', severity: 'high', title: 'Critical system file has overly permissive access',
    description: 'Files such as /etc/shadow, /etc/sudoers and the cron directories control authentication and privileged execution; they must be owned by root and not writable (or, for secrets, readable) by others.',
    remediation: 'chown root:root <path> and chmod to the recommended mode (see the path in this finding).',
    evaluate(ctx) {
      const out = [];
      for (const [p, max, kind] of PERMS) {
        const st = ctx.fs.stat(p);
        if (!st) continue;
        const extra = st.mode & ~max & 0o7777;
        const notRoot = st.uid !== 0;
        if (!extra && !notRoot) continue;
        let severity = 'medium';
        if (st.mode & 0o002) severity = 'critical';
        else if (st.mode & 0o020 || notRoot) severity = 'high';
        else if (kind === 'secret' && (st.mode & 0o004)) severity = 'critical';
        out.push({ resource: p, severity, detail: `${fmtMode(st)}; expected at most ${octal(max)} owned by root.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-fs-world-writable-files', area: 'filesystem', severity: 'high', title: 'World-writable file in a system or application directory',
    description: 'Any local user can modify this file. Writable files under /etc, /usr, /bin, /opt and similar locations are a direct route to privilege escalation.',
    remediation: 'chmod o-w <file> after confirming nothing relies on it (or fix the package/installer that created it).',
    cap: 100,
    evaluate(ctx) {
      const scan = ctx.fsScan();
      if (!scan) return na('filesystem walk skipped (--skip-fs-walk)');
      return scan.worldWritableFiles.filter(WRITABLE_SENSITIVE).map((p) => ({ resource: p }));
    },
  }),

  rule({
    id: 'vm-fs-world-writable-dirs', area: 'filesystem', severity: 'medium', title: 'World-writable directory without the sticky bit',
    description: 'Without the sticky bit any user can delete or rename other users\' files in the directory, enabling symlink and replacement attacks.',
    remediation: 'chmod +t <dir> (or remove world-write permission: chmod o-w <dir>).',
    cap: 100,
    evaluate(ctx) {
      const scan = ctx.fsScan();
      if (!scan) return na('filesystem walk skipped (--skip-fs-walk)');
      return scan.worldWritableDirsNoSticky.map((p) => ({ resource: p }));
    },
  }),

  rule({
    id: 'vm-fs-suid-risky', area: 'filesystem', severity: 'high', title: 'Set-uid/set-gid bit on a general-purpose program',
    description: 'Interpreters, shells, editors and file utilities with the set-uid or set-gid bit let any user run them with the owner\'s privileges and read or write arbitrary files or spawn a shell.',
    remediation: 'chmod u-s,g-s <file> unless this is a deliberate, reviewed configuration.',
    cap: 100,
    evaluate(ctx) {
      const scan = ctx.fsScan();
      if (!scan) return na('filesystem walk skipped (--skip-fs-walk)');
      const out = [];
      for (const f of [...scan.setuid, ...scan.setgid]) {
        const base = f.path.split('/').pop();
        if (GTFO.has(base) || GTFO.has(base.replace(/[\d.]+$/, ''))) out.push({ resource: f.path, detail: `${f.mode & 0o4000 ? 'set-uid' : 'set-gid'} ${octal(f.mode)}${(f.uid === 0 || f.gid === 0) ? ' (root)' : ''}.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-fs-suid-unexpected', area: 'filesystem', severity: 'low', title: 'Set-uid/set-gid program that is not a well-known system binary',
    description: 'Set-uid programs run with their owner\'s privileges and are a common privilege-escalation target. This one is not in the list of binaries normally shipped by distributions; review whether it is needed.',
    remediation: 'Verify the file belongs to an installed package and is required; otherwise remove the bit (chmod u-s,g-s) or the file.',
    cap: 50,
    evaluate(ctx) {
      const scan = ctx.fsScan();
      if (!scan) return na('filesystem walk skipped (--skip-fs-walk)');
      const out = [];
      for (const f of scan.setuid) {
        const base = f.path.split('/').pop();
        if (SUID_OK.has(base) || GTFO.has(base)) continue;
        out.push({ resource: f.path, detail: `set-uid ${octal(f.mode)}, owner uid ${f.uid}.` });
      }
      return out;
    },
  }),

  rule({
    id: 'vm-fs-tmp-mount-options', area: 'filesystem', severity: 'low', title: 'Temporary directories are not hardened with mount options',
    description: 'World-writable temp locations should be mounted nosuid and nodev (and ideally noexec) so attackers cannot run set-uid files or device nodes from them.',
    remediation: 'Mount /tmp (and /dev/shm) with nodev,nosuid,noexec, e.g. via /etc/fstab or systemd tmp.mount.',
    evaluate(ctx) {
      const out = [];
      const tmp = ctx.mountFor('/tmp');
      if (!tmp) {
        const unit = ctx._unitIndex().wanted.has('tmp.mount');
        if (!unit) out.push({ resource: '/tmp', detail: 'No dedicated /tmp mount; it shares the root filesystem.' });
      } else {
        const miss = ['nosuid', 'nodev', 'noexec'].filter((o) => !tmp.options.has(o));
        if (miss.length) out.push({ resource: '/tmp', detail: `Mounted without: ${miss.join(', ')}.` });
      }
      if (ctx.live) {
        const shm = ctx.mountFor('/dev/shm');
        if (shm) {
          const miss = ['nosuid', 'nodev', 'noexec'].filter((o) => !shm.options.has(o));
          if (miss.length) out.push({ resource: '/dev/shm', detail: `Mounted without: ${miss.join(', ')}.` });
        }
      }
      return out;
    },
  }),

  rule({
    id: 'vm-fs-ld-so-preload', area: 'filesystem', severity: 'medium', title: '/etc/ld.so.preload is in use',
    description: 'Libraries listed in /etc/ld.so.preload are injected into every dynamically linked process. Legitimate uses exist, but it is also a standard technique for user-space rootkits.',
    remediation: 'Confirm each listed library belongs to software you installed; remove the file if it does not.',
    evaluate(ctx) {
      const l = ctx.fs.lines('/etc/ld.so.preload');
      return l && l.length ? [{ resource: '/etc/ld.so.preload', detail: `Lists: ${l.join(', ').slice(0, 200)}` }] : [];
    },
  }),

  rule({
    id: 'vm-cron-writable', area: 'filesystem', severity: 'high', title: 'Scheduled job can be modified by non-root users',
    description: 'A cron file, or a script a cron job runs, is writable by group or others. Whoever can edit it gets code execution as the job\'s user (often root).',
    remediation: 'chown root:root and chmod go-w the file or script.',
    evaluate(ctx) {
      const files = ['/etc/crontab', ...ctx.fs.glob('/etc/cron.d/*'), ...['hourly', 'daily', 'weekly', 'monthly'].flatMap((p) => ctx.fs.glob(`/etc/cron.${p}/*`))];
      for (const d of ['/var/spool/cron', '/var/spool/cron/crontabs']) for (const n of ctx.fs.readdir(d) || []) if (ctx.fs.stat(`${d}/${n}`)?.isFile) files.push(`${d}/${n}`);
      const out = [];
      const seen = new Set();
      for (const f of files) {
        const st = ctx.fs.stat(f);
        if (!st || !st.isFile) continue;
        if (st.mode & 0o022) out.push({ resource: f, detail: `Job file is ${fmtMode(st)}.` });
        const isScriptDir = /^\/etc\/cron\.(hourly|daily|weekly|monthly)\//.test(f);
        const refs = isScriptDir ? [] : (ctx.fs.lines(f) || []).flatMap((l) => (l.match(/(?:^|\s)(\/[^\s;|&><"']+)/g) || []).map((x) => x.trim()));
        for (const r of refs) {
          if (seen.has(r)) continue;
          seen.add(r);
          const rs = ctx.fs.stat(r);
          if (rs && rs.isFile && (rs.mode & 0o022)) out.push({ resource: r, detail: `Run by ${f}; ${fmtMode(rs)}.` });
        }
      }
      return out;
    },
  }),

  rule({
    id: 'vm-systemd-unit-writable', area: 'filesystem', severity: 'high', title: 'systemd unit or the program it runs is writable by non-root users',
    description: 'If a service\'s unit file or its ExecStart program can be modified by group or others, they can run code as that service (usually root) at the next start.',
    remediation: 'chown root:root and chmod go-w the unit file or program.',
    evaluate(ctx) {
      const out = [];
      const seen = new Set();
      for (const dir of ['/etc/systemd/system', '/usr/lib/systemd/system', '/lib/systemd/system']) {
        for (const n of ctx.fs.readdir(dir) || []) {
          if (!/\.(service|socket|timer)$/.test(n)) continue;
          const p = `${dir}/${n}`;
          const lst = ctx.fs.lstat(p);
          if (!lst || lst.isSymlink) continue;
          if (lst.mode & 0o022) out.push({ resource: p, detail: `Unit file is ${fmtMode(lst)}.` });
          const text = ctx.fs.read(p);
          if (!text) continue;
          for (const exe of parseUnitExec(text)) {
            if (seen.has(exe)) continue;
            seen.add(exe);
            const st = ctx.fs.stat(exe);
            if (st && st.isFile && (st.mode & 0o022)) out.push({ resource: exe, detail: `Started by ${n}; ${fmtMode(st)}.` });
          }
        }
      }
      return out;
    },
  }),
];
