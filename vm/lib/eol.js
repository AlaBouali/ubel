'use strict';
// eol.js — end-of-support dates for common Linux releases (and a parser for the "osImage" strings Kubernetes
// reports for a node). The table is embedded, so it ages: a release that is not listed is simply not judged,
// and nothing here is fetched at scan time. Dates are the end of the vendor's *standard* security maintenance;
// paid / extended programmes (Ubuntu Pro ESM, RHEL ELS, Debian ELTS, Amazon Linux extended support) can keep a
// release patched past them, which the findings say.

const EOL = {
  ubuntu: {
    '16.04': '2021-04-30', '18.04': '2023-05-31', '20.04': '2025-05-31', '22.04': '2027-04-30', '24.04': '2029-04-30',
    '20.10': '2021-07-22', '21.04': '2022-01-20', '21.10': '2022-07-14', '22.10': '2023-07-20', '23.04': '2024-01-25',
    '23.10': '2024-07-11', '24.10': '2025-07-10', '25.04': '2026-01-15',
  },
  debian: { '8': '2020-06-30', '9': '2022-06-30', '10': '2024-06-30', '11': '2026-08-31', '12': '2028-06-30', '13': '2030-06-30' },
  rhel: { '6': '2020-11-30', '7': '2024-06-30', '8': '2029-05-31', '9': '2032-05-31', '10': '2035-05-31' },
  centos: { '6': '2020-11-30', '7': '2024-06-30', '8': '2021-12-31' },
  centos_stream: { '8': '2024-05-31', '9': '2027-05-31' },
  rocky: { '8': '2029-05-31', '9': '2032-05-31' },
  almalinux: { '8': '2029-05-31', '9': '2032-05-31' },
  ol: { '7': '2024-12-31', '8': '2029-07-31', '9': '2032-06-30' },
  fedora: { '37': '2023-12-05', '38': '2024-05-21', '39': '2024-11-26', '40': '2025-05-13', '41': '2025-12-15' },
  amzn: { '2018.03': '2023-12-31', '2': '2026-06-30' },
  alpine: { '3.14': '2023-05-01', '3.15': '2023-11-01', '3.16': '2024-05-23', '3.17': '2024-11-22', '3.18': '2025-05-09', '3.19': '2025-11-01', '3.20': '2026-04-01', '3.21': '2026-11-01' },
};

const PRODUCT = {
  ubuntu: 'Ubuntu', debian: 'Debian', rhel: 'Red Hat Enterprise Linux', centos: 'CentOS Linux', centos_stream: 'CentOS Stream',
  rocky: 'Rocky Linux', almalinux: 'AlmaLinux', ol: 'Oracle Linux', fedora: 'Fedora', amzn: 'Amazon Linux', alpine: 'Alpine Linux',
};

const EXTENDED = {
  ubuntu: 'Ubuntu Pro (ESM) can extend security patching',
  debian: 'Debian LTS / ELTS can extend security patching',
  rhel: 'a Red Hat extended-life subscription can extend patching',
  centos: 'CentOS Linux has no vendor-supported extension; migrate to a supported distribution',
  centos_stream: 'migrate to a supported release',
  ol: 'Oracle Extended Support can extend patching',
  amzn: 'AWS may offer extended support for some releases',
};

/** Normalises {id, versionId, name} (os-release fields) to a key of EOL and a version string, or null. */
function normaliseRelease({ id, versionId, name }) {
  id = String(id || '').toLowerCase();
  let v = String(versionId || '');
  if (id === 'centos' && /stream/i.test(name || '')) return { key: 'centos_stream', version: v.split('.')[0] };
  if (id === 'rhel') return { key: 'rhel', version: v.split('.')[0] };
  if (id === 'centos') return { key: 'centos', version: v.split('.')[0] };
  if (id === 'rocky' || id === 'almalinux' || id === 'ol') return { key: id, version: v.split('.')[0] };
  if (id === 'debian') return { key: 'debian', version: v.split('.')[0] };
  if (id === 'fedora') return { key: 'fedora', version: v };
  if (id === 'amzn') return { key: 'amzn', version: v };
  if (id === 'ubuntu') return { key: 'ubuntu', version: v.split('.').slice(0, 2).join('.') };
  if (id === 'alpine') return { key: 'alpine', version: v.split('.').slice(0, 2).join('.') };
  return null;
}

/**
 * @param {{id?:string, versionId?:string, name?:string}} rel
 * @param {Date} [now]
 * @returns {{product:string, version:string, end:string, daysLeft:number, ended:boolean, extended?:string}|null}
 */
function eolFor(rel, now = new Date()) {
  const n = normaliseRelease(rel || {});
  if (!n) return null;
  const end = (EOL[n.key] || {})[n.version];
  if (!end) return null;
  const daysLeft = Math.floor((Date.parse(end + 'T23:59:59Z') - now.getTime()) / 86400000);
  return { product: PRODUCT[n.key], version: n.version, end, daysLeft, ended: daysLeft < 0, extended: EXTENDED[n.key] };
}

/** Parses a Kubernetes node's status.nodeInfo.osImage ("Ubuntu 20.04.6 LTS", "Debian GNU/Linux 11 (bullseye)", …). */
function parseOsImage(osImage) {
  const s = String(osImage || '');
  let m;
  if ((m = s.match(/^Ubuntu (\d{2}\.\d{2})/i))) return { id: 'ubuntu', versionId: m[1], name: 'Ubuntu' };
  if ((m = s.match(/^Debian GNU\/Linux (\d+)/i))) return { id: 'debian', versionId: m[1], name: 'Debian' };
  if ((m = s.match(/^Red Hat Enterprise Linux(?: Server)? (\d+)/i))) return { id: 'rhel', versionId: m[1], name: 'RHEL' };
  if ((m = s.match(/^CentOS Stream (\d+)/i))) return { id: 'centos', versionId: m[1], name: 'CentOS Stream' };
  if ((m = s.match(/^CentOS Linux (\d+)/i))) return { id: 'centos', versionId: m[1], name: 'CentOS Linux' };
  if ((m = s.match(/^Rocky Linux (\d+)/i))) return { id: 'rocky', versionId: m[1], name: 'Rocky' };
  if ((m = s.match(/^AlmaLinux (\d+)/i))) return { id: 'almalinux', versionId: m[1], name: 'AlmaLinux' };
  if ((m = s.match(/^Oracle Linux (?:Server )?(\d+)/i))) return { id: 'ol', versionId: m[1], name: 'Oracle Linux' };
  if ((m = s.match(/^Amazon Linux (\d+(?:\.\d+)?)/i))) return { id: 'amzn', versionId: m[1], name: 'Amazon Linux' };
  if ((m = s.match(/^Alpine Linux v?(\d+\.\d+)/i))) return { id: 'alpine', versionId: m[1], name: 'Alpine' };
  if ((m = s.match(/^Fedora(?: Linux)? (\d+)/i))) return { id: 'fedora', versionId: m[1], name: 'Fedora' };
  return null;
}

export { eolFor, parseOsImage, normaliseRelease };
