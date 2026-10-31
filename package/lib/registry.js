'use strict';
// registry.js — resolves one package release on its registry and downloads the archive(s) to analyse. One resolver per registry protocol:
//   npm       GET <registry>/<name>/<version>   (the version manifest; falls back to the packument)   → dist.tarball + dist.integrity / shasum
//   PyPI      GET <registry>/pypi/<name>/<version>/json, else the Simple API (PEP 691 JSON, PEP 503 HTML) → sdist + wheels, sha256 digests
//   crates    sparse index <registry>/<prefix>/<name> + config.json `dl`                        → .crate, cksum (sha256)
//   Go        GOPROXY protocol <proxy>/<module>/@v/<version>.zip; checked against sum.golang.org (h1: dirhash)
//   RubyGems  GET <registry>/api/v2/rubygems/<name>/versions/<version>.json                      → .gem, sha (sha256)
//   NuGet     service index → PackageBaseAddress                                                 → .nupkg (+ catalog packageHash when reachable)
//   Composer  Packagist v2 metadata (<registry>/p2/<vendor>/<name>.json) or a repository's packages.json → dist zip
//   pub.dev   GET <registry>/api/packages/<name>                                                 → .tar.gz, archive_sha256
// Every download is checked against the digest the registry published for it. A mismatch is returned as `integrity.state = 'mismatch'`
// (the caller reports it as critical); a registry that publishes no digest gives `unverified`, never `verified`.

import crypto from 'node:crypto';
import { httpGet, HttpError } from './http.js';
import { ECOSYSTEMS } from './ecosystems.js';
import { latestOf, compareVersions } from './versions.js';

export class RegistryError extends Error {}

const strip = u => String(u).replace(/\/+$/, '');
const hash = (algo, buf, enc = 'hex') => crypto.createHash(algo).update(buf).digest(enc);

/** @returns {{state:'verified'|'mismatch'|'unverified', algo:string|null, expected:string|null, actual:string|null, source:string|null}} */
export function verifyDigest(buf, expected) {
  if (!expected || !expected.value) return { state: 'unverified', algo: null, expected: null, actual: null, source: null };
  const { algo, value, encoding = 'hex', source = 'registry' } = expected;
  const actual = hash(algo, buf, encoding);
  const ok = encoding === 'hex' ? actual.toLowerCase() === String(value).toLowerCase() : actual === value;
  return { state: ok ? 'verified' : 'mismatch', algo, expected: value, actual, source };
}

/** Subresource-integrity string (`sha512-<base64>[ sha1-…]`) → the strongest supported {algo, value, encoding:'base64'}. */
export function parseSri(sri) {
  const rank = { sha512: 4, sha384: 3, sha256: 2, sha1: 1 };
  let best = null;
  for (const part of String(sri || '').split(/\s+/)) {
    const m = /^(sha512|sha384|sha256|sha1)-([A-Za-z0-9+/=]+)/.exec(part);
    if (m && (!best || rank[m[1]] > rank[best.algo])) best = { algo: m[1], value: m[2], encoding: 'base64' };
  }
  return best;
}

class Ctx {
  constructor(o) {
    Object.assign(this, { headers: {}, authHeaders: {}, allowHttp: false, maxBytes: 256 * 1048576, notes: [], log: () => {}, artifact: 'all', maxWheels: 2 }, o);
    this.registry = strip(o.registry || ECOSYSTEMS[o.ecosystem].defaultRegistry);
    if (/^http:\/\//i.test(this.registry)) this.allowHttp = true;      // the user named an http registry: its own links may be http too
    this.authOrigin = new URL(this.registry).origin;
  }
  get(url, extra = {}) {
    return httpGet(url, { headers: this.headers, authHeaders: this.authHeaders, authOrigin: this.authOrigin, allowHttp: this.allowHttp, maxBytes: 64 * 1048576, ...extra });
  }
  async json(url, extra = {}) { const r = await this.get(url, { as: 'json', ...extra }); return r.body; }
  async download(url, extra = {}) { const r = await this.get(url, { as: 'buffer', maxBytes: this.maxBytes, timeoutMs: 120000, ...extra }); return r.body; }
}

const isLatest = v => !v || String(v).toLowerCase() === 'latest';
const notFound = (what, where) => new RegistryError(`${what} was not found on ${where}`);

// ── npm ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async function npm(c) {
  const enc = encodeURIComponent(c.name).replace(/^%40/, '@');
  let doc = null, time = null;
  const ver = isLatest(c.version) ? 'latest' : c.version;
  const one = await c.json(`${c.registry}/${enc}/${encodeURIComponent(ver)}`, { allow404: true }).catch(e => { if (e instanceof HttpError && (e.status === 405 || e.status === 400)) return null; throw e; });
  if (one && one.version) doc = one;
  if (!doc) {                                                    // registries without the per-version endpoint serve the packument
    const pack = await c.json(`${c.registry}/${enc}`, { allow404: true });
    if (!pack) throw notFound(`package ${c.name}`, c.registry);
    const v = ver === 'latest' ? pack['dist-tags']?.latest : ver;
    doc = pack.versions?.[v];
    if (!doc) throw notFound(`${c.name}@${ver}`, c.registry);
    time = pack.time?.[v] || null;
  }
  const version = doc.version;
  const dist = doc.dist || {};
  let url = dist.tarball;
  if (!url) url = `${c.registry}/${c.name}/-/${c.name.split('/').pop()}-${version}.tgz`;
  const sri = parseSri(dist.integrity);
  const expected = sri ? { ...sri, source: 'dist.integrity' } : dist.shasum ? { algo: 'sha1', value: dist.shasum, encoding: 'hex', source: 'dist.shasum' } : null;
  const maintainers = (doc.maintainers || []).map(m => (typeof m === 'string' ? m : m.name)).filter(Boolean);
  return {
    version,
    artifacts: [{ kind: 'tarball', filename: `${c.name.replace(/^@/, '').replace('/', '-')}-${version}.tgz`, url, expected }],
    meta: {
      published_at: time, deprecated: typeof doc.deprecated === 'string' ? doc.deprecated : doc.deprecated ? 'deprecated' : null, license: typeof doc.license === 'string' ? doc.license : doc.license?.type || null,
      repository: typeof doc.repository === 'string' ? doc.repository : doc.repository?.url || null, homepage: doc.homepage || null, maintainers, published_by: doc._npmUser?.name || null,
      has_install_script: doc.hasInstallScript ?? null, file_count: dist.fileCount ?? null, unpacked_size: dist.unpackedSize ?? null,
      signatures: Array.isArray(dist.signatures) ? dist.signatures.length : 0, provenance: Boolean(dist.attestations),
      declared: { scripts: doc.scripts || null, dependencies: doc.dependencies || {}, optionalDependencies: doc.optionalDependencies || {}, peerDependencies: doc.peerDependencies || {}, devDependencies: doc.devDependencies || null, bundledDependencies: doc.bundledDependencies || doc.bundleDependencies || null, bin: doc.bin || null },
    },
  };
}

// ── PyPI ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const normPy = n => String(n).toLowerCase().replace(/[-_.]+/g, '-');

export function parseDistFilename(fn) {
  if (/\.whl$/i.test(fn)) { const p = fn.slice(0, -4).split('-'); return p.length >= 5 ? { kind: 'wheel', name: p[0], version: p[1], tags: p.slice(-3) } : null; }
  const m = /^(.+)-([^-]+?)\.(?:tar\.gz|tgz|zip|tar\.bz2|tar\.xz|tar)$/i.exec(fn);
  return m ? { kind: 'sdist', name: m[1], version: m[2], tags: null } : null;
}

function wheelScore(tags) {
  const [py, abi, plat] = tags;
  let s = 0;
  if (plat === 'any') s = 100;
  else if (/manylinux/.test(plat) && /x86_64/.test(plat)) s = 80;
  else if (/musllinux/.test(plat) && /x86_64/.test(plat)) s = 60;
  else if (/win_amd64|win32/.test(plat)) s = 50;
  else if (/macosx/.test(plat) && /(arm64|x86_64|universal2)/.test(plat)) s = 40;
  else s = 10;
  const cp = /^cp(\d)(\d+)/.exec(py); if (cp) s += Math.min(Number(cp[2]), 30) / 100;
  if (abi === 'abi3') s += 0.5;
  return s;
}
const wheelFamily = tags => (tags[2] === 'any' ? 'any' : /linux/.test(tags[2]) ? 'linux' : /win/.test(tags[2]) ? 'win' : /macosx/.test(tags[2]) ? 'mac' : 'other');

export function chooseArtifacts(files, { artifact = 'all', maxWheels = 2 } = {}) {
  const sdists = files.filter(f => f.kind === 'sdist');
  const wheels = files.filter(f => f.kind === 'wheel').map(f => ({ ...f, score: wheelScore(f.tags) })).sort((a, b) => b.score - a.score || a.filename.localeCompare(b.filename));
  const out = [];
  const gz = f => (/\.tar\.gz$|\.tgz$/.test(f.filename) ? 1 : 0);
  if (artifact !== 'wheel') out.push(...[...sdists].sort((a, b) => gz(b) - gz(a)).slice(0, 1));
  if (artifact !== 'sdist') {
    const used = new Set();
    let n = 0;
    for (const w of wheels) {
      const fam = wheelFamily(w.tags);
      if (used.has(fam)) continue;
      used.add(fam); out.push(w);
      if (++n >= maxWheels) break;
    }
  }
  return out;
}

async function pypi(c) {
  const base = c.registry.replace(/\/simple$/i, '');
  const wanted = isLatest(c.version) ? null : c.version;
  let files = [], version = wanted, meta = {}, yanked = false, yankedReason = null;
  const j = await c.json(`${base}/pypi/${encodeURIComponent(c.name)}/${wanted ? `${encodeURIComponent(wanted)}/` : ''}json`, { allow404: true }).catch(e => { if (e instanceof HttpError && e.status && e.status !== 404 && e.status < 500) return null; throw e; });
  if (j && j.info) {
    version = j.info.version;
    files = (j.urls || []).map(u => ({ kind: u.packagetype === 'bdist_wheel' ? 'wheel' : u.packagetype === 'sdist' ? 'sdist' : 'other', filename: u.filename, url: u.url, expected: u.digests?.sha256 ? { algo: 'sha256', value: u.digests.sha256, source: 'digests.sha256' } : null, published_at: u.upload_time_iso_8601 || null, yanked: Boolean(u.yanked), tags: u.packagetype === 'bdist_wheel' ? (parseDistFilename(u.filename)?.tags || ['', '', '']) : null }));
    yanked = Boolean(j.info.yanked); yankedReason = j.info.yanked_reason || null;
    meta = { license: j.info.license_expression || j.info.license || null, repository: j.info.project_urls?.Source || j.info.project_urls?.Repository || j.info.home_page || null, homepage: j.info.home_page || null, maintainers: [j.info.author, j.info.maintainer].filter(Boolean), requires_python: j.info.requires_python || null, requires_dist: j.info.requires_dist || null };
  } else {
    // a private index: the Simple API
    const url = `${/\/simple$/i.test(c.registry) ? c.registry : `${c.registry}/simple`}/${normPy(c.name)}/`;
    const r = await c.get(url, { headers: { ...c.headers, accept: 'application/vnd.pypi.simple.v1+json, application/vnd.pypi.simple.v1+html;q=0.2, text/html;q=0.1' }, allow404: true, as: 'text' });
    if (!r || r.status === 404) throw notFound(`package ${c.name}`, c.registry);
    let list = [];
    if (/json/.test(r.headers.get('content-type') || '') || /^\s*\{/.test(r.body)) {
      const doc = JSON.parse(r.body);
      list = (doc.files || []).map(f => ({ filename: f.filename, url: new URL(f.url, r.url).href, sha256: f.hashes?.sha256 || null, yanked: Boolean(f.yanked) }));
    } else {
      for (const m of r.body.matchAll(/<a\s+([^>]*)>([^<]+)<\/a>/gi)) {
        const href = /href="([^"]+)"/i.exec(m[1])?.[1]; if (!href) continue;
        const u = new URL(href.replace(/&amp;/g, '&'), r.url);
        list.push({ filename: m[2].trim(), url: u.href.replace(/#.*$/, ''), sha256: /sha256=([0-9a-f]{64})/i.exec(u.hash)?.[1] || null, yanked: /data-yanked/i.test(m[1]) });
      }
    }
    const parsed = list.map(f => ({ ...f, p: parseDistFilename(f.filename) })).filter(f => f.p && normPy(f.p.name) === normPy(c.name));
    if (!version) version = latestOf(parsed.filter(f => !f.yanked).map(f => f.p.version)) || latestOf(parsed.map(f => f.p.version));
    files = parsed.filter(f => f.p.version === version).map(f => ({ kind: f.p.kind, filename: f.filename, url: f.url, expected: f.sha256 ? { algo: 'sha256', value: f.sha256, source: 'simple index hash' } : null, yanked: f.yanked, tags: f.p.tags }));
    yanked = files.length > 0 && files.every(f => f.yanked);
  }
  if (!files.length) throw notFound(`${c.name}==${version || 'latest'}`, c.registry);
  const chosen = chooseArtifacts(files.filter(f => f.kind !== 'other'), c);
  if (!chosen.length) throw new RegistryError(`${c.name}==${version} has no ${c.artifact === 'all' ? 'sdist or wheel' : c.artifact} on ${c.registry}`);
  const times = files.map(f => f.published_at).filter(Boolean).sort();
  return { version, artifacts: chosen.map(f => ({ kind: f.kind, filename: f.filename, url: f.url, expected: f.expected })), meta: { ...meta, published_at: times[0] || null, yanked, yanked_reason: yankedReason, other_artifacts: files.length - chosen.length } };
}

// ── crates.io ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function crateIndexPath(name) {
  const n = name.toLowerCase();
  if (n.length === 1) return `1/${n}`;
  if (n.length === 2) return `2/${n}`;
  if (n.length === 3) return `3/${n[0]}/${n}`;
  return `${n.slice(0, 2)}/${n.slice(2, 4)}/${n}`;
}

async function cargo(c) {
  const idx = c.registry.replace(/^sparse\+/, '');
  const text = await c.get(`${idx}/${crateIndexPath(c.name)}`, { as: 'text', allow404: true });
  if (!text || text.status === 404) throw notFound(`crate ${c.name}`, idx);
  const rows = text.body.split('\n').filter(l => l.trim()).map(l => { try { return JSON.parse(l); } catch { return null; } }).filter(Boolean);
  let row;
  if (isLatest(c.version)) { const v = latestOf(rows.filter(r => !r.yanked).map(r => r.vers)) || latestOf(rows.map(r => r.vers)); row = rows.find(r => r.vers === v); }
  else row = rows.find(r => r.vers === c.version);
  if (!row) throw notFound(`${c.name}@${c.version}`, idx);
  let dl;
  try {
    const cfg = await c.json(`${idx}/config.json`);
    dl = cfg.dl;
  } catch (e) { if (!/crates\.io/.test(idx)) throw e; dl = 'https://static.crates.io/crates'; c.notes.push('config.json of the index could not be read; the default crates.io download location was used.'); }
  const lower = row.name.toLowerCase();
  const prefix = crateIndexPath(row.name).replace(/\/[^/]+$/, '');
  let url;
  if (/\{(?:crate|version|prefix|lowerprefix|sha256-checksum)\}/.test(dl)) url = dl.replace('{crate}', row.name).replace('{version}', row.vers).replace('{prefix}', prefix).replace('{lowerprefix}', prefix.toLowerCase()).replace('{sha256-checksum}', row.cksum);
  else url = `${strip(dl)}/${row.name}/${row.vers}/download`;
  return {
    version: row.vers,
    artifacts: [{ kind: 'crate', filename: `${lower}-${row.vers}.crate`, url, expected: row.cksum ? { algo: 'sha256', value: row.cksum, source: 'index cksum' } : null }],
    meta: { yanked: Boolean(row.yanked), rust_version: row.rust_version || null, links: row.links || null, declared: { dependencies: row.deps || [], features: row.features || {} } },
  };
}

// ── Go modules ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export const goEscape = p => p.replace(/[A-Z]/g, ch => `!${ch.toLowerCase()}`);

async function go(c) {
  const mod = goEscape(c.name);
  let version = c.version;
  let info = null;
  if (isLatest(version)) {
    info = await c.json(`${c.registry}/${mod}/@latest`, { allow404: true });
    if (!info) throw notFound(`module ${c.name}`, c.registry);
    version = info.Version;
  } else {
    if (!/^v/.test(version)) version = `v${version}`;
    info = await c.json(`${c.registry}/${mod}/@v/${encodeURIComponent(goEscape(version))}.info`, { allow404: true });
    if (!info) throw notFound(`${c.name}@${version}`, c.registry);
  }
  return { version, artifacts: [{ kind: 'zip', filename: `${c.name.replace(/\//g, '_')}@${version}.zip`, url: `${c.registry}/${mod}/@v/${encodeURIComponent(goEscape(version))}.zip`, expected: null, goSum: true }], meta: { published_at: info.Time || null } };
}

/** go.sum `h1:` hash of a module zip (golang.org/x/mod/sumdb/dirhash.Hash1): sha256 over "<sha256 of file>  <module@version/path>\n" lines, sorted by path. */
export function goDirHash(files) {
  const rows = files.filter(f => f.type === 'file').map(f => ({ p: f.rawPath, l: `${hash('sha256', f.read())}  ${f.rawPath}\n` })).sort((a, b) => (a.p < b.p ? -1 : a.p > b.p ? 1 : 0));
  return `h1:${hash('sha256', Buffer.from(rows.map(r => r.l).join(''), 'utf8'), 'base64')}`;
}

// ── RubyGems ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async function gem(c) {
  let version = c.version;
  if (isLatest(version)) {
    const l = await c.json(`${c.registry}/api/v1/versions/${encodeURIComponent(c.name)}/latest.json`, { allow404: true });
    if (!l || !l.version) throw notFound(`gem ${c.name}`, c.registry);
    version = l.version;
  }
  const j = await c.json(`${c.registry}/api/v2/rubygems/${encodeURIComponent(c.name)}/versions/${encodeURIComponent(version)}.json`, { allow404: true });
  if (!j) throw notFound(`${c.name}@${version}`, c.registry);
  const plat = j.platform && j.platform !== 'ruby' ? `-${j.platform}` : '';
  const url = j.gem_uri || `${c.registry}/gems/${c.name}-${version}${plat}.gem`;
  return {
    version: j.version || version,
    artifacts: [{ kind: 'gem', filename: `${c.name}-${version}${plat}.gem`, url, expected: j.sha ? { algo: 'sha256', value: j.sha, source: 'versions api sha' } : null }],
    meta: { published_at: j.created_at || null, license: (j.licenses || []).join(', ') || null, repository: j.source_code_uri || j.homepage_uri || null, homepage: j.homepage_uri || null, maintainers: j.authors ? String(j.authors).split(/,\s*/) : [], yanked: false, declared: { dependencies: j.dependencies || {} }, downloads: j.downloads ?? null },
  };
}

// ── NuGet ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async function nuget(c) {
  const index = /\.json$/i.test(c.registry) ? c.registry : `${c.registry}/v3/index.json`;
  const svc = await c.json(index);
  const res = svc.resources || [];
  const pick = re => res.find(r => re.test([].concat(r['@type']).join(' ')));
  const baseRes = pick(/PackageBaseAddress/);
  if (!baseRes) throw new RegistryError(`${index} is not a NuGet v3 service index (no PackageBaseAddress resource)`);
  const base = strip(baseRes['@id']);
  const id = c.name.toLowerCase();
  let version = c.version;
  if (isLatest(version)) {
    const list = await c.json(`${base}/${id}/index.json`, { allow404: true });
    if (!list) throw notFound(`package ${c.name}`, index);
    version = latestOf(list.versions || []);
  }
  const ver = String(version).toLowerCase().replace(/\+.*$/, '');
  const url = `${base}/${id}/${ver}/${id}.${ver}.nupkg`;
  // the catalog entry carries the package hash (SHA512, base64); best effort — a private feed may not have a registration hive
  let expected = null, published = null, listed = null;
  const regRes = pick(/RegistrationsBaseUrl/);
  if (regRes) {
    try {
      const leaf = await c.json(`${strip(regRes['@id'])}/${id}/${ver}.json`, { allow404: true });
      const entryRef = leaf?.catalogEntry;
      const entry = typeof entryRef === 'string' ? await c.json(entryRef, { allow404: true }) : entryRef;
      if (entry) {
        published = entry.published || null; listed = entry.listed ?? null;
        if (entry.packageHash) expected = { algo: String(entry.packageHashAlgorithm || 'SHA512').toLowerCase().replace('-', ''), value: entry.packageHash, encoding: 'base64', source: 'catalog packageHash' };
      }
    } catch (e) { c.notes.push(`The NuGet registration for ${c.name} ${ver} could not be read (${e.message}); the package hash was not checked.`); }
  }
  return { version: ver, artifacts: [{ kind: 'nupkg', filename: `${id}.${ver}.nupkg`, url, expected }], meta: { published_at: published, unlisted: listed === false ? true : null } };
}

// ── Composer / Packagist ─────────────────────────────────────────────────────────────────────────────────────────────────────────
/** Expands Composer's minified v2 metadata (each version lists only the keys that changed; "__unset" removes one). */
export function expandComposer(list) {
  const out = []; let prev = {};
  for (const v of list || []) {
    const cur = { ...prev };
    for (const [k, val] of Object.entries(v)) { if (val === '__unset') delete cur[k]; else cur[k] = val; }
    out.push(cur); prev = cur;
  }
  return out;
}
const composerNorm = v => { const m = /^v?(\d+(?:\.\d+){0,3})/.exec(String(v)); if (!m) return String(v); const p = m[1].split('.'); while (p.length < 4) p.push('0'); return p.join('.'); };

async function composer(c) {
  if (!/^[a-z0-9_.-]+\/[a-z0-9_.-]+$/i.test(c.name)) throw new RegistryError(`a Composer package is named <vendor>/<package>, got "${c.name}"`);
  const name = c.name.toLowerCase();
  let versions = null;
  const rootDoc = /packagist\.org$/i.test(new URL(c.registry).host) ? null : await c.json(`${c.registry}/packages.json`, { allow404: true }).catch(() => null);
  if (rootDoc && rootDoc['metadata-url']) {
    const u = new URL(rootDoc['metadata-url'].replace('%package%', name), `${c.registry}/`).href;
    const d = await c.json(u, { allow404: true });
    versions = d && expandComposer(d.packages?.[name]);
  } else if (rootDoc && rootDoc.packages && rootDoc.packages[name]) {
    const p = rootDoc.packages[name];
    versions = Array.isArray(p) ? p : Object.entries(p).map(([k, v]) => ({ version: k, ...v }));
  } else {
    const d = await c.json(`${c.registry}/p2/${name}.json`, { allow404: true });
    versions = d && expandComposer(d.packages?.[name]);
  }
  if (!versions || !versions.length) throw notFound(`package ${c.name}`, c.registry);
  let row;
  if (isLatest(c.version)) { const v = latestOf(versions.filter(x => !/^dev-|-dev$/.test(x.version)).map(x => x.version)) || versions[0].version; row = versions.find(x => x.version === v); }
  else row = versions.find(x => x.version === c.version) || versions.find(x => x.version === `v${c.version}`) || versions.find(x => x.version_normalized === composerNorm(c.version)) || versions.find(x => composerNorm(x.version) === composerNorm(c.version));
  if (!row) throw notFound(`${c.name}@${c.version}`, c.registry);
  const dist = row.dist;
  if (!dist || !dist.url) throw new RegistryError(`${c.name} ${row.version} has no dist archive (source-only release)`);
  return {
    version: row.version,
    artifacts: [{ kind: 'zip', filename: `${name.replace('/', '-')}-${row.version}.zip`, url: dist.url, expected: dist.shasum ? { algo: 'sha1', value: dist.shasum, source: 'dist.shasum' } : null }],
    meta: { published_at: row.time || null, license: [].concat(row.license || []).join(', ') || null, repository: row.source?.url || null, homepage: row.homepage || null, abandoned: row.abandoned ? (typeof row.abandoned === 'string' ? `abandoned, use ${row.abandoned}` : 'abandoned') : null, type: row.type || null, reference: dist.reference || row.source?.reference || null, declared: { require: row.require || {}, scripts: row.scripts || null, bin: row.bin || null } },
  };
}

// ── pub.dev ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
async function pub(c) {
  const d = await c.json(`${c.registry}/api/packages/${encodeURIComponent(c.name)}`, { headers: { ...c.headers, accept: 'application/vnd.pub.v2+json' }, allow404: true });
  if (!d) throw notFound(`package ${c.name}`, c.registry);
  const versions = d.versions || [];
  let row;
  if (isLatest(c.version)) row = (d.latest && versions.find(v => v.version === d.latest.version)) || versions.find(v => v.version === latestOf(versions.filter(x => !x.retracted).map(x => x.version)));
  else row = versions.find(v => v.version === c.version);
  if (!row) throw notFound(`${c.name}@${c.version}`, c.registry);
  return {
    version: row.version,
    artifacts: [{ kind: 'tarball', filename: `${c.name}-${row.version}.tar.gz`, url: row.archive_url, expected: row.archive_sha256 ? { algo: 'sha256', value: row.archive_sha256, source: 'archive_sha256' } : null }],
    meta: { published_at: row.published || null, yanked: Boolean(row.retracted), deprecated: d.isDiscontinued ? 'discontinued' : null, repository: row.pubspec?.repository || row.pubspec?.homepage || null, homepage: row.pubspec?.homepage || null },
  };
}

const RESOLVERS = { npm, pypi, cargo, go, gem, nuget, composer, pub };

// ── Go checksum database ─────────────────────────────────────────────────────────────────────────────────────────────────────────
async function sumdbLine(c, mod, version, sumdb) {
  const url = `${strip(sumdb)}/lookup/${goEscape(mod)}@${encodeURIComponent(version)}`;
  const r = await c.get(url, { as: 'text', authHeaders: {}, headers: {} });
  const line = r.body.split('\n').find(l => l.startsWith(`${mod} ${version} h1:`));
  const m = line && /\sh1:(\S+)$/.exec(line);
  return m ? `h1:${m[1]}` : null;
}

/**
 * Resolves and downloads a package release.
 * @param {object} o {ecosystem, name, version, registry?, headers?, authHeaders?, allowHttp?, maxBytes?, artifact?, maxWheels?, sumdb?, log?}
 * @returns {Promise<{ecosystem:string, name:string, version:string, registry:string, artifacts:object[], meta:object, notes:string[]}>}
 */
export async function fetchPackage(o) {
  const resolver = RESOLVERS[o.ecosystem];
  if (!resolver) throw new RegistryError(`unsupported ecosystem: ${o.ecosystem}`);
  const c = new Ctx(o);
  const plan = await resolver(c);
  const artifacts = [];
  for (const a of plan.artifacts) {
    o.log?.(`[*] Downloading ${a.url}`);
    let buf;
    try { buf = await c.download(a.url); }
    catch (e) { if (plan.artifacts.length === 1) throw e; c.notes.push(`${a.filename}: could not be downloaded (${e.message}); it was not analysed.`); continue; }
    const integrity = a.goSum ? { state: 'unverified', algo: 'h1', expected: null, actual: null, source: null } : verifyDigest(buf, a.expected);
    artifacts.push({ kind: a.kind, filename: a.filename, url: a.url, buf, size: buf.length, sha256: hash('sha256', buf), goSum: Boolean(a.goSum), integrity });
  }
  if (!artifacts.length) throw new RegistryError('no archive could be downloaded');
  const sumdb = o.sumdb === undefined ? (o.ecosystem === 'go' && !o.registry ? 'https://sum.golang.org' : null) : o.sumdb;
  return { ecosystem: o.ecosystem, name: o.name, version: plan.version, registry: c.registry, artifacts, meta: plan.meta || {}, notes: c.notes, _ctx: c, _sumdb: sumdb };
}

/** Go modules: checks the zip's dirhash against the checksum database once the archive has been opened. Fills `integrity` of the artifact. */
export async function verifyGoSum(pkg, artifact, files) {
  const actual = goDirHash(files);
  const sumdb = pkg._sumdb;
  if (!sumdb) { artifact.integrity = { state: 'unverified', algo: 'h1', expected: null, actual, source: null }; return; }
  try {
    const expected = await sumdbLine(pkg._ctx, pkg.name, pkg.version, sumdb);
    artifact.integrity = !expected ? { state: 'unverified', algo: 'h1', expected: null, actual, source: null }
      : { state: expected === actual ? 'verified' : 'mismatch', algo: 'h1', expected, actual, source: 'sum.golang.org' };
  } catch (e) {
    artifact.integrity = { state: 'unverified', algo: 'h1', expected: null, actual, source: null };
    pkg.notes.push(`The Go checksum database (${sumdb}) could not be reached (${e.message}); the module zip was not verified against it.`);
  }
}

export { compareVersions };
