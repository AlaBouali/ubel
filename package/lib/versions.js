'use strict';
// versions.js — a tolerant version comparator (semver, PEP 440-ish, NuGet / Composer four-part) used to pick "latest" and to rank fix versions.
// Not a resolver: it only orders versions of ONE package.

const norm = v => String(v ?? '').trim().replace(/^[vV=]\s*/, '');

/** @returns {{nums:number[], pre:string[]|null}} */
export function parseVersion(v) {
  let s = norm(v).replace(/\+.*$/, '');
  let pre = null;
  const m = /^(\d+(?:\.\d+)*)(?:[-.]?((?:a|b|c|rc|alpha|beta|pre|preview|dev|post)\.?\d*.*|-.*))?$/i.exec(s);
  let numsPart = s;
  if (m) { numsPart = m[1]; if (m[2]) pre = m[2].replace(/^[-.]/, '').split(/[.\-_]/).filter(Boolean); }
  else { const mm = /^(\d+(?:\.\d+)*)[-.]?(.*)$/.exec(s); if (mm) { numsPart = mm[1]; if (mm[2]) pre = mm[2].split(/[.\-_]/).filter(Boolean); } else return { nums: [], pre: s ? [s] : null };
  }
  return { nums: numsPart.split('.').map(Number), pre };
}

export const isPrerelease = v => {
  const { pre } = parseVersion(v);
  if (!pre) return false;
  return !/^post\d*$/i.test(pre[0]);
};

function cmpPre(a, b) {
  if (!a && !b) return 0;
  if (!a) return 1;            // a release is newer than its pre-release
  if (!b) return -1;
  for (let i = 0; i < Math.max(a.length, b.length); i++) {
    const x = a[i], y = b[i];
    if (x === undefined) return -1;
    if (y === undefined) return 1;
    const nx = /^\d+$/.test(x), ny = /^\d+$/.test(y);
    if (nx && ny) { if (Number(x) !== Number(y)) return Number(x) < Number(y) ? -1 : 1; }
    else if (nx !== ny) return nx ? -1 : 1;
    else { const c = x.toLowerCase().localeCompare(y.toLowerCase()); if (c) return c < 0 ? -1 : 1; }
  }
  return 0;
}

export function compareVersions(a, b) {
  const x = parseVersion(a), y = parseVersion(b);
  for (let i = 0; i < Math.max(x.nums.length, y.nums.length); i++) {
    const p = x.nums[i] ?? 0, q = y.nums[i] ?? 0;
    if (p !== q) return p < q ? -1 : 1;
  }
  return cmpPre(x.pre, y.pre);
}

/** Highest version, preferring releases over pre-releases. */
export function latestOf(versions) {
  const list = [...versions].filter(Boolean);
  if (!list.length) return null;
  const stable = list.filter(v => !isPrerelease(v));
  return (stable.length ? stable : list).sort(compareVersions).pop();
}
