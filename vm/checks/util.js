'use strict';
import { octal } from '../lib/fsview.js';
export { octal };

export const rule = (r) => r;
export const SSHD = '/etc/ssh/sshd_config';
export const bad = (mode, maxMode) => (mode & ~maxMode & 0o7777) !== 0;
export const fmtMode = (st) => `mode ${octal(st.mode)}, owner uid ${st.uid}, group gid ${st.gid}`;

/** Home directories worth inspecting: root plus every interactive account that has an existing home. */
export function homes(ctx) {
  const seen = new Set();
  const out = [];
  for (const u of ctx.interactiveUsers()) {
    if (!u.home || u.home === '/' || seen.has(u.home)) continue;
    if (!ctx.fs.lstat(u.home)) continue;
    seen.add(u.home);
    out.push(u);
  }
  return out;
}
