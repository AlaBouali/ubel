'use strict';
// ecosystems.js — the package ecosystems `ubel-package` can fetch and analyse: the ones UBEL's install firewall gates (npm / pnpm / bun / yarn,
// pip / uv / pipx / poetry, Cargo, Go, Bundler, .NET, Dart / Flutter, Composer). One entry per REGISTRY protocol; the package-manager names are aliases.
// Not covered: conda (.conda / .tar.bz2 archives need bzip2 / zstd, which Node's built-ins do not provide on every supported version), SwiftPM (no
// registry: a package is a git repository) and the OS package managers (apt / dnf / yum) — `ubel-package` says so instead of guessing.

import { npmPurl, pypiPurl } from '../../binary/lib/records.js';

export const ECOSYSTEMS = {
  npm:      { id: 'npm',      label: 'npm',                 osv: 'npm',       defaultRegistry: 'https://registry.npmjs.org',                    aliases: ['npm', 'pnpm', 'yarn', 'bun', 'node', 'nodejs', 'javascript', 'js'] },
  pypi:     { id: 'pypi',     label: 'PyPI',                osv: 'PyPI',      defaultRegistry: 'https://pypi.org',                              aliases: ['pypi', 'pip', 'pipx', 'uv', 'poetry', 'python', 'py'] },
  cargo:    { id: 'cargo',    label: 'crates.io',           osv: 'crates.io', defaultRegistry: 'https://index.crates.io',                       aliases: ['cargo', 'crates', 'crates.io', 'crate', 'rust'] },
  go:       { id: 'go',       label: 'Go modules',          osv: 'Go',        defaultRegistry: 'https://proxy.golang.org',                      aliases: ['go', 'golang', 'gomod', 'go-mod'] },
  gem:      { id: 'gem',      label: 'RubyGems',            osv: 'RubyGems',  defaultRegistry: 'https://rubygems.org',                          aliases: ['gem', 'gems', 'rubygems', 'bundler', 'bundle', 'ruby'] },
  nuget:    { id: 'nuget',    label: 'NuGet',               osv: 'NuGet',     defaultRegistry: 'https://api.nuget.org/v3/index.json',           aliases: ['nuget', 'dotnet', '.net', 'csharp', 'c#'] },
  composer: { id: 'composer', label: 'Packagist (Composer)', osv: 'Packagist', defaultRegistry: 'https://repo.packagist.org',                    aliases: ['composer', 'packagist', 'php'] },
  pub:      { id: 'pub',      label: 'pub.dev',             osv: 'Pub',       defaultRegistry: 'https://pub.dev',                               aliases: ['pub', 'pub.dev', 'dart', 'flutter'] },
};

const ALIAS = new Map();
for (const e of Object.values(ECOSYSTEMS)) for (const a of e.aliases) ALIAS.set(a, e.id);

/** Ecosystems that exist in UBEL's firewall but that this tool cannot read, with the reason. */
export const UNSUPPORTED = {
  conda: 'conda packages are .conda / .tar.bz2 archives (zstd / bzip2), which are not readable with Node built-ins on every supported Node version; analyse the PyPI release of the package instead',
  swift: 'a SwiftPM package is a git repository, not a registry artifact; check it out and scan the source with ubel-sast / ubel-mal',
  swiftpm: 'a SwiftPM package is a git repository, not a registry artifact; check it out and scan the source with ubel-sast / ubel-mal',
  carthage: 'a Carthage dependency is a git repository, not a registry artifact',
  apt: 'OS packages (.deb) are not language packages; use ubel-apt for an install-time scan',
  dnf: 'OS packages (.rpm) are not language packages; use ubel-dnf for an install-time scan',
  yum: 'OS packages (.rpm) are not language packages; use ubel-yum for an install-time scan',
  maven: 'Maven artifacts are not supported by ubel-package yet',
};

/** @returns {string|null} canonical ecosystem id, or null when unknown */
export function resolveEcosystem(name) {
  return ALIAS.get(String(name || '').trim().toLowerCase()) || null;
}

export const ecosystemNames = () => [...new Set(Object.values(ECOSYSTEMS).flatMap(e => [e.id, ...e.aliases]))].sort();

/** Package URL of a package (the identity OSV.dev is queried with). Names follow each ecosystem's own normalisation. */
export function packagePurl(eco, name, version) {
  if (!name || !version) return null;
  const v = encodeURIComponent(String(version)).replace(/%2B/g, '+');
  switch (eco) {
    case 'npm': return npmPurl(name, version);
    case 'pypi': return pypiPurl(name, version);
    case 'cargo': return `pkg:cargo/${String(name).toLowerCase()}@${v}`;
    case 'go': return `pkg:golang/${String(name).toLowerCase()}@${String(version)}`;
    case 'gem': return `pkg:gem/${String(name).toLowerCase()}@${v}`;
    case 'nuget': return `pkg:nuget/${String(name).toLowerCase()}@${v}`;
    case 'composer': return `pkg:composer/${String(name).toLowerCase()}@${v}`;
    case 'pub': return `pkg:pub/${String(name).toLowerCase()}@${v}`;
    default: return null;
  }
}
