'use strict';
// pkginfo.js — the descriptive details of an installed package that the inventory modal shows next to the SCA data (state, licence, paths,
// dependencies, fixes): what the package IS, who maintains it, where it came from, when it was installed and where to read more.
//
//   operating-system packages  read by the SCA package readers (sca/linux_runner.js) from dpkg / apk / rpm and carried on the inventory item as
//                              `package_info` (description, section, architecture, maintainer, homepage, installed size, relationships, file
//                              count, installed as dependency or manually …) plus `source_name` / `source_version` (the source package the
//                              advisories are keyed by). Here they get reference links (distribution tracker, advisories).
//   application packages       the SCA scanners give name / version / licence / paths only. The package's own manifest is read from its
//                              install location (npm package.json, Python METADATA / PKG-INFO) for the description, homepage, repository,
//                              author, install-time scripts (a supply-chain signal) and so on; every ecosystem gets its registry page and the
//                              install time (modification time of its directory).
// Reads files only, never runs anything; every read is bounded and failure-tolerant (a manifest that cannot be read just adds nothing).

import fs from 'node:fs';
import path from 'node:path';
import { purlType, pathsOf } from './scascan.js';

const MAX_MANIFEST = 512 * 1024;
const str = (v, n = 300) => (typeof v === 'string' && v.trim() ? v.trim().slice(0, n) : undefined);
const list = (a, n = 25) => (Array.isArray(a) && a.length ? a.slice(0, n).map((x) => String(x).slice(0, 200)) : undefined);
const clean = (o) => { const out = {}; for (const [k, v] of Object.entries(o)) if (v !== undefined && v !== null && v !== '' && !(Array.isArray(v) && !v.length) && !(typeof v === 'object' && !Array.isArray(v) && !Object.keys(v).length)) out[k] = v; return out; };

function readJson(file) {
  try { const st = fs.statSync(file); if (!st.isFile() || st.size > MAX_MANIFEST) return null; return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return null; }
}
function readText(file) {
  try { const st = fs.statSync(file); if (!st.isFile() || st.size > MAX_MANIFEST) return null; return fs.readFileSync(file, 'utf8'); } catch { return null; }
}

/** RFC-822 style headers (Python METADATA / PKG-INFO) up to the first blank line; repeated headers are collected. */
function parseHeaders(text) {
  const h = {};
  for (const line of text.split('\n')) {
    if (!line.trim()) break;
    if (/^\s/.test(line)) continue;
    const i = line.indexOf(':');
    if (i <= 0) continue;
    const k = line.slice(0, i).trim().toLowerCase();
    (h[k] ||= []).push(line.slice(i + 1).trim());
  }
  return h;
}

const repoUrl = (r) => str(typeof r === 'string' ? r : r && r.url, 300);
const nameOf = (a) => str(typeof a === 'string' ? a : a && [a.name, a.email && `<${a.email}>`].filter(Boolean).join(' '), 200);

function npmInfo(dir) {
  const j = readJson(path.join(dir, 'package.json'));
  if (!j) return {};
  const scripts = j.scripts && typeof j.scripts === 'object' ? j.scripts : {};
  const hooks = ['preinstall', 'install', 'postinstall', 'prepare'].filter((k) => scripts[k]);
  return {
    description: str(j.description), homepage: str(j.homepage, 300), repository: repoUrl(j.repository), author: nameOf(j.author),
    maintainers: list((Array.isArray(j.maintainers) ? j.maintainers : []).map(nameOf).filter(Boolean), 10),
    main: str(j.main, 120), engines: j.engines && typeof j.engines === 'object' ? Object.entries(j.engines).map(([k, v]) => `${k} ${v}`).slice(0, 6) : undefined,
    executables: j.bin ? list(typeof j.bin === 'string' ? [j.name] : Object.keys(j.bin), 12) : undefined,
    install_scripts: hooks.length ? hooks.map((k) => `${k}: ${String(scripts[k]).slice(0, 120)}`) : undefined,
    runtime_dependencies: j.dependencies && typeof j.dependencies === 'object' ? Object.keys(j.dependencies).length : undefined,
    optional_dependencies: j.optionalDependencies && typeof j.optionalDependencies === 'object' ? Object.keys(j.optionalDependencies).length : undefined,
    deprecated: str(j.deprecated, 200),
    package_manager: 'npm',
  };
}

function pythonInfo(dir) {
  const text = readText(path.join(dir, 'METADATA')) || readText(path.join(dir, 'PKG-INFO'));
  if (!text) return {};
  const h = parseHeaders(text);
  const one = (k) => str((h[k] || [])[0]);
  const urls = (h['project-url'] || []).map((u) => u.replace(/\s*,\s*/, ': ')).slice(0, 6);
  return {
    description: one('summary'), homepage: one('home-page') || str((urls.find((u) => /^home/i.test(u)) || '').replace(/^[^:]+:\s*/, '')),
    author: one('author') || one('author-email'), maintainers: list([one('maintainer') || one('maintainer-email')].filter(Boolean), 3),
    license_declared: one('license-expression') || (one('license') && one('license').length < 120 ? one('license') : undefined),
    requires_python: one('requires-python'), project_urls: urls, runtime_dependencies: (h['requires-dist'] || []).filter((r) => !/extra\s*==/.test(r)).length || undefined,
    package_manager: 'pip',
  };
}

const REGISTRY = {
  npm: (n) => `https://www.npmjs.com/package/${n}`,
  pypi: (n) => `https://pypi.org/project/${n}/`,
  gem: (n) => `https://rubygems.org/gems/${n}`,
  golang: (n) => `https://pkg.go.dev/${n}`,
  composer: (n) => `https://packagist.org/packages/${n}`,
  cargo: (n) => `https://crates.io/crates/${n}`,
  nuget: (n) => `https://www.nuget.org/packages/${n}`,
  maven: (n) => `https://central.sonatype.com/artifact/${String(n).replace(':', '/')}`,
  pub: (n) => `https://pub.dev/packages/${n}`,
};
const REGISTRY_NAME = { npm: 'npm', pypi: 'PyPI', gem: 'RubyGems', golang: 'pkg.go.dev', composer: 'Packagist', cargo: 'crates.io', nuget: 'NuGet', maven: 'Maven Central', pub: 'pub.dev' };

/** Reference links for an operating-system package, by distribution. */
function osLinks(c, src) {
  const eco = String(c.ecosystem || '');
  const s = encodeURIComponent(src);
  if (eco === 'ubuntu') return [{ label: 'Ubuntu source package', url: `https://launchpad.net/ubuntu/+source/${s}` }, { label: 'Ubuntu security notices (CVEs)', url: `https://ubuntu.com/security/cves?package=${s}` }];
  if (eco === 'debian') return [{ label: 'Debian package tracker', url: `https://tracker.debian.org/pkg/${s}` }, { label: 'Debian security tracker', url: `https://security-tracker.debian.org/tracker/source-package/${s}` }];
  if (eco === 'alpine') return [{ label: 'Alpine package', url: `https://pkgs.alpinelinux.org/packages?name=${encodeURIComponent(c.name)}` }, { label: 'Alpine security tracker', url: `https://security.alpinelinux.org/srcpkg/${s}` }];
  if (eco === 'almalinux') return [{ label: 'AlmaLinux errata', url: `https://errata.almalinux.org/` }];
  if (eco === 'rockylinux') return [{ label: 'Rocky Linux errata', url: `https://errata.rockylinux.org/` }];
  if (eco === 'redhat') return [{ label: 'Red Hat CVE database', url: `https://access.redhat.com/security/security-updates/#/cve` }];
  return [];
}

/**
 * The `package_info` of one inventory item: what the SCA readers carried on it plus the manifest / registry details described above.
 * @param {object} c     SCA inventory item
 * @param {string} base  mount point of a --root image ('' on the live host), added to the item's paths to read the files
 * @returns {object|null} null when there is nothing to show
 */
export function buildPackageInfo(c, base = '') {
  const type = purlType(c.id);
  const isOs = ['deb', 'apk', 'rpm'].includes(type);
  const carried = c.package_info && typeof c.package_info === 'object' ? { ...c.package_info } : {};
  let info = carried;

  if (isOs) {
    const src = c.source_name || c.name;
    info = { ...carried, source_package: carried.source_package || src, source_version: carried.source_version || c.source_version || c.version };
    const links = osLinks(c, src);
    if (str(carried.homepage)) links.unshift({ label: 'Upstream homepage', url: carried.homepage });
    if (links.length) info.links = links;
    return clean(info);
  }

  // application package: read its own manifest from the first install location that has one
  const paths = pathsOf(c);
  const real = (p) => (base && !p.startsWith(base) ? path.join(base, p) : p);
  let manifest = {};
  for (const p of paths.slice(0, 3)) {
    const dir = real(p);
    manifest = type === 'npm' ? npmInfo(dir) : type === 'pypi' ? pythonInfo(dir) : {};
    if (Object.keys(manifest).length) break;
  }
  info = { ...manifest, ...carried };
  if (paths[0]) {
    try { info.installed_at = fs.statSync(real(paths[0])).mtime.toISOString(); } catch { /* location not readable */ }
    info.location = paths[0];
    if (paths.length > 1) info.locations = paths.length;
  }
  const links = [];
  if (REGISTRY[type]) links.push({ label: `${REGISTRY_NAME[type]} page`, url: REGISTRY[type](type === 'maven' ? c.name : encodeURI(c.name)) });
  if (str(info.homepage) && /^https?:\/\//i.test(info.homepage)) links.unshift({ label: 'Homepage', url: info.homepage });
  const repo = str(info.repository) && String(info.repository).replace(/^git\+/, '').replace(/^git:\/\//, 'https://').replace(/\.git$/, '');
  if (repo && /^https?:\/\//i.test(repo)) { links.push({ label: 'Source repository', url: repo }); delete info.repository; }     // shown as a link
  if (links.length) info.links = links;
  return clean(info);
}
