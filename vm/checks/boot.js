'use strict';
import { rule } from './util.js';
import { na } from '../lib/engine.js';

export default [
  rule({
    id: 'vm-boot-grub-password', area: 'boot', severity: 'low', title: 'Boot loader is not password-protected',
    description: 'Without a GRUB superuser password anyone with console access can edit kernel parameters at boot (for example init=/bin/bash) and obtain a root shell. Mainly relevant where the console is reachable by untrusted people.',
    remediation: 'Create a GRUB superuser with grub-mkpasswd-pbkdf2 and add set superusers / password_pbkdf2 to /etc/grub.d/40_custom, then update-grub (grub2-mkconfig).',
    evaluate(ctx) {
      const cfg = ['/boot/grub/grub.cfg', '/boot/grub2/grub.cfg', '/boot/efi/EFI/redhat/grub.cfg', '/boot/efi/EFI/centos/grub.cfg'].find((f) => ctx.fs.exists(f));
      if (!cfg) return na('no GRUB configuration found');
      const files = [cfg, ...ctx.fs.glob('/etc/grub.d/*')];
      const has = files.some((f) => /^\s*set\s+superusers\s*=/m.test(ctx.fs.read(f) || '')) || ctx.fs.exists('/boot/grub2/user.cfg');
      return has ? [] : [{ resource: cfg, detail: 'No "set superusers" found.' }];
    },
  }),
];
