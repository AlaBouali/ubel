// distro_versions.js — package-manager version comparison for OS packages.
//
// compareVersions() in suggested_fixes.js is a generic tokenizer and cannot order
// Debian/Ubuntu or RPM versions correctly (it drops everything after "+", which is
// where Debian puts the security patch level: 2.36-9+deb12u3 vs 2.36-9+deb12u4).
// These are straight ports of the reference algorithms:
//   dpkgCompare — Debian Policy §5.6.12  (epoch : upstream - revision, "~" sorts before everything)
//   rpmCompare  — rpmvercmp(3), epoch / version / release compared separately, "~" and "^" supported
// Both return -1 / 0 / 1.

const isDigit = c => c !== undefined && c >= "0" && c <= "9";
const isAlpha = c => c !== undefined && /[A-Za-z]/.test(c);

// ---- dpkg (Debian/Ubuntu) ----
const dpkgOrder = c => c === undefined || isDigit(c) ? 0 : isAlpha(c) ? c.charCodeAt(0) : c === "~" ? -1 : c.charCodeAt(0) + 256;
function dpkgPart(a, b) {
  let i = 0, j = 0;
  while (i < a.length || j < b.length) {
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = dpkgOrder(a[i]), bc = dpkgOrder(b[j]);
      if (ac !== bc) return ac < bc ? -1 : 1;
      i++; j++;
    }
    while (a[i] === "0") i++;
    while (b[j] === "0") j++;
    let first = 0;
    while (isDigit(a[i]) && isDigit(b[j])) { if (!first) first = a.charCodeAt(i) - b.charCodeAt(j); i++; j++; }
    if (isDigit(a[i])) return 1;
    if (isDigit(b[j])) return -1;
    if (first) return first < 0 ? -1 : 1;
  }
  return 0;
}
function splitDeb(v) {
  v = String(v ?? "").trim();
  const e = /^(\d+):/.exec(v); const epoch = e ? parseInt(e[1], 10) : 0; if (e) v = v.slice(e[0].length);
  const k = v.lastIndexOf("-");
  return { epoch, up: k < 0 ? v : v.slice(0, k), rev: k < 0 ? "" : v.slice(k + 1) };
}
export function dpkgCompare(a, b) {
  const x = splitDeb(a), y = splitDeb(b);
  if (x.epoch !== y.epoch) return x.epoch < y.epoch ? -1 : 1;
  return dpkgPart(x.up, y.up) || dpkgPart(x.rev, y.rev);
}

// ---- rpm ----
function rpmvercmp(a, b) {
  if (a === b) return 0;
  let i = 0, j = 0;
  const sep = c => !/[A-Za-z0-9~^]/.test(c);
  while (i < a.length || j < b.length) {
    while (i < a.length && sep(a[i])) i++;
    while (j < b.length && sep(b[j])) j++;
    if (a[i] === "~" || b[j] === "~") {
      if (a[i] !== "~") return 1; if (b[j] !== "~") return -1; i++; j++; continue;
    }
    if (a[i] === "^" || b[j] === "^") {
      if (i >= a.length) return -1; if (j >= b.length) return 1;
      if (a[i] !== "^") return 1; if (b[j] !== "^") return -1; i++; j++; continue;
    }
    if (!(i < a.length && j < b.length)) break;
    const si = i, sj = j, num = isDigit(a[i]);
    if (num) { while (isDigit(a[i])) i++; while (isDigit(b[j])) j++; }
    else { while (isAlpha(a[i])) i++; while (isAlpha(b[j])) j++; }
    let sa = a.slice(si, i), sb = b.slice(sj, j);
    if (!sb) return num ? 1 : -1;
    if (num) { sa = sa.replace(/^0+/, ""); sb = sb.replace(/^0+/, ""); if (sa.length !== sb.length) return sa.length < sb.length ? -1 : 1; }
    if (sa !== sb) return sa < sb ? -1 : 1;
  }
  if (i >= a.length && j >= b.length) return 0;
  return i >= a.length ? -1 : 1;
}

export function rpmCompare(a, b) {
  const sp = v => { v = String(v ?? "").trim(); const e = /^(\d+):/.exec(v); const ep = e ? +e[1] : 0; if (e) v = v.slice(e[0].length); const k = v.lastIndexOf("-"); return { ep, ver: k < 0 ? v : v.slice(0, k), rel: k < 0 ? "" : v.slice(k + 1) }; };
  const x = sp(a), y = sp(b);
  if (x.ep !== y.ep) return x.ep < y.ep ? -1 : 1;
  return rpmvercmp(x.ver, y.ver) || rpmvercmp(x.rel, y.rel);
}