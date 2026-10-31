'use strict';
// manifests_more.js — manifest readers for Go, RubyGems, NuGet, Composer and pub (see manifests.js for the result shape), and the dispatcher.

import { parseYaml } from './yaml.js';
import { parseXml, findAll, childText } from './xml.js';
import { classifyGo, classifyGem, classifyNuget, classifyComposer, classifyPub } from './pinning.js';
import { mkDep, addInstallFile, analyzeNpm, analyzePypi, analyzeCargo, Files } from './manifests.js';

const emptyResult = () => ({ info: {}, deps: [], hooks: [], installFiles: [], bundled: [], issues: [], manifestFiles: [] });
const objectOf = v => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});
const isHttp = u => /^http:\/\//i.test(String(u)) && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(String(u));
const mismatch = (res, key, detail, file) => res.issues.push({ rule: 'package.metadata.name_mismatch', key, detail, file });

// ── Go ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function parseGoMod(text) {
  const out = { module: null, go: null, toolchain: null, require: [], replace: [], exclude: [], retract: [] };
  let block = null;
  for (const raw of String(text).split(/\r?\n/)) {
    const indirect = /\/\/\s*indirect\b/.test(raw);
    const line = raw.replace(/\/\/.*$/, '').trim();
    if (!line) continue;
    if (block) {
      if (line === ')') { block = null; continue; }
      pushGo(out, block, line, indirect);
      continue;
    }
    const m = /^(module|go|toolchain|require|replace|exclude|retract)\s*(\()?\s*(.*)$/.exec(line);
    if (!m) continue;
    if (m[2]) { block = m[1]; if (m[3] && m[3] !== ')') pushGo(out, m[1], m[3], indirect); continue; }
    pushGo(out, m[1], m[3], indirect);
  }
  return out;
}
function pushGo(out, kind, rest, indirect) {
  const unq = s => String(s).replace(/^["`]|["`]$/g, '');
  if (kind === 'module') out.module = unq(rest);
  else if (kind === 'go') out.go = rest;
  else if (kind === 'toolchain') out.toolchain = rest;
  else if (kind === 'require') { const [p, v] = rest.split(/\s+/); if (p && v) out.require.push({ path: unq(p), version: v, indirect }); }
  else if (kind === 'replace') { const [l, r] = rest.split(/\s*=>\s*/); if (l && r) { const a = l.split(/\s+/), b = r.split(/\s+/); out.replace.push({ from: unq(a[0]), fromVersion: a[1] || null, to: unq(b[0]), toVersion: b[1] || null }); } }
  else if (kind === 'exclude') { const [p, v] = rest.split(/\s+/); if (p && v) out.exclude.push({ path: unq(p), version: v }); }
  else if (kind === 'retract') out.retract.push(rest);
}

export function analyzeGo(fx, pkg) {
  const res = emptyResult();
  const t = fx.textOf('go.mod');
  if (t == null) { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: 'the module zip has no go.mod at its root (a pre-modules repository)', file: null }); }
  else {
    res.manifestFiles.push('go.mod');
    const g = parseGoMod(t);
    res.info = { name: g.module, go: g.go, toolchain: g.toolchain, replaces: g.replace.length, excludes: g.exclude.length, retracts: g.retract.length };
    const wanted = pkg.name.toLowerCase().replace(/\/v\d+$/, '');
    if (g.module && g.module.toLowerCase().replace(/\/v\d+$/, '') !== wanted) mismatch(res, 'name', `go.mod declares the module path "${g.module}" but the module was requested as "${pkg.name}"`, 'go.mod');
    for (const r of g.require) res.deps.push(mkDep({ name: r.path, spec: r.version, kind: 'runtime', cls: classifyGo(r.version), file: 'go.mod', extra: { indirect: r.indirect } }));
    for (const r of g.replace) {
      const local = /^(?:\.{1,2}\/|\/)/.test(r.to);
      res.deps.push(mkDep({ name: r.from, spec: `=> ${r.to}${r.toVersion ? ` ${r.toVersion}` : ''}`, kind: 'runtime', installed: false, cls: { pin: 'non_registry', version: null, source: local ? 'path' : 'replace', immutable: !local && Boolean(r.toVersion), detail: `replace directive${local ? ' to a local path' : ''}; only honoured when this is the main module, so a consumer ignores it` }, file: 'go.mod' }));
    }
  }
  const goFiles = fx.findAll(/\.go$/).filter(f => !/_test\.go$/.test(f.path));
  const cgo = goFiles.filter(f => /^\s*import\s+"C"|^\s*"C"\s*$|^\/\/\s*#cgo\b/m.test(fx.text(f, 512 * 1024) || ''));
  const nativeSrc = fx.findAll(/\.(?:c|cc|cpp|cxx|h|hpp|s|S)$/).filter(f => !/(?:^|\/)(?:testdata|test|tests)\//.test(f.path));
  if (cgo.length) {
    res.hooks.push({ id: 'cgo', phase: 'build', trigger: 'go build', command: `cgo in ${cgo.length} file${cgo.length > 1 ? 's' : ''}`, file: cgo[0].path, runsFiles: [], consumer: true, note: 'cgo compiles C code with the consumer\'s C toolchain; `#cgo` directives pass flags to it. `go get` itself runs nothing.' });
    for (const f of cgo.slice(0, 20)) addInstallFile(res, f.path, 'cgo source, compiled with the consumer\'s C compiler', 'build');
    for (const f of nativeSrc.slice(0, 40)) addInstallFile(res, f.path, 'native source compiled by cgo', 'build');
  }
  const vend = fx.textOf('vendor/modules.txt');
  if (vend) for (const m of vend.matchAll(/^#\s+(\S+)\s+(v\S+)(?:\s|$)/gm)) res.bundled.push({ name: m[1], version: m[2], path: 'vendor', declaredBundled: true, scripts: [] });
  return res;
}

// ── RubyGems ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function analyzeGem(fx, pkg) {
  const res = emptyResult();
  const meta = fx.gem?.metadata;
  const y = meta ? parseYaml(meta) : null;
  if (!y || typeof y !== 'object') { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: 'the .gem has no readable metadata.gz (gemspec)', file: 'metadata.gz' }); return res; }
  res.manifestFiles.push('metadata.gz');
  const ver = typeof y.version === 'object' ? y.version?.version : y.version;
  res.info = { name: y.name ?? null, version: ver ?? null, description: y.summary ?? y.description ?? null, license: [].concat(y.licenses || []).join(', ') || null, homepage: y.homepage ?? null, repository: objectOf(y.metadata).source_code_uri ?? null, platform: y.platform ?? null, authors: [].concat(y.authors || []), executables: [].concat(y.executables || []), extensions: [].concat(y.extensions || []), required_ruby_version: y.required_ruby_version?.requirements ? y.required_ruby_version.requirements.map(r => `${r[0]} ${r[1]?.version ?? r[1]}`).join(', ') : null, post_install_message: y.post_install_message ?? null, signed: Array.isArray(y.cert_chain) && y.cert_chain.length > 0 };
  if (y.name && String(y.name).toLowerCase() !== pkg.name.toLowerCase()) mismatch(res, 'name', `the gemspec says the name is "${y.name}" but the gem was requested as "${pkg.name}"`, 'metadata.gz');
  if (ver && String(ver) !== pkg.version && !String(pkg.version).startsWith(`${ver}-`)) mismatch(res, 'version', `the gemspec says the version is "${ver}" but the registry served it as "${pkg.version}"`, 'metadata.gz');
  for (const d of [].concat(y.dependencies || [])) {
    if (!d || typeof d !== 'object' || !d.name) continue;
    const reqs = d.requirement?.requirements || [];
    const spec = reqs.map(r => `${r[0]} ${r[1]?.version ?? r[1]}`).join(', ');
    const dev = /development/.test(String(d.type));
    res.deps.push(mkDep({ name: d.name, spec, kind: dev ? 'dev' : 'runtime', cls: classifyGem(reqs), file: 'metadata.gz' }));
  }
  for (const e of [].concat(y.extensions || [])) {
    const p = String(e).replace(/^\.\//, '');
    res.hooks.push({ id: 'gem-extension', phase: 'install', trigger: 'gem install', command: p, file: 'metadata.gz', runsFiles: [p], consumer: true, note: /extconf\.rb$|mkrf_conf\.rb$/.test(p) ? 'RubyGems runs this Ruby file at install time to generate a Makefile, then runs `make`' : /Rakefile$/.test(p) ? 'RubyGems runs `rake` with this Rakefile at install time' : /CMakeLists\.txt$/.test(p) ? 'RubyGems runs cmake at install time' : 'native extension built at install time' });
    addInstallFile(res, p, 'gem native-extension build file', 'install');
    const dir = p.includes('/') ? p.slice(0, p.lastIndexOf('/') + 1) : '';
    for (const f of fx.findAll(/\.(?:rb|c|cc|cpp|h|rs|go|sh)$/)) if (dir && f.path.startsWith(dir) && res.installFiles.length < 60) addInstallFile(res, f.path, 'native-extension source', 'install');
  }
  const plugin = fx.findAll(/^lib\/rubygems_plugin\.rb$/)[0];
  if (plugin) {
    res.hooks.push({ id: 'rubygems-plugin', phase: 'startup', trigger: 'every `gem` command', command: plugin.path, file: plugin.path, runsFiles: [plugin.path], consumer: true, note: 'RubyGems loads lib/rubygems_plugin.rb of every installed gem each time the `gem` command (or Bundler) starts' });
    addInstallFile(res, plugin.path, 'loaded automatically by RubyGems', 'startup');
  }
  return res;
}

// ── NuGet ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function analyzeNuget(fx, pkg) {
  const res = emptyResult();
  const spec = fx.findAll(/^[^/]+\.nuspec$/)[0];
  if (!spec) mismatch(res, 'no-manifest', 'the .nupkg has no .nuspec at its root', null);
  else {
    res.manifestFiles.push(spec.path);
    const root = parseXml(fx.text(spec) || '');
    const md = root && findAll(root, 'metadata')[0];
    if (md) {
      const id = childText(md, 'id'), version = childText(md, 'version');
      const lic = md.children.find(c => c.name.toLowerCase() === 'license');
      const repo = md.children.find(c => c.name.toLowerCase() === 'repository');
      const types = findAll(md, 'packageType').map(x => x.attrs.name).filter(Boolean);
      res.info = { name: id, version, description: childText(md, 'description'), license: lic ? (lic.text.trim() || null) : childText(md, 'licenseUrl'), homepage: childText(md, 'projectUrl'), repository: repo?.attrs.url ?? null, authors: childText(md, 'authors'), package_types: types, development_dependency: childText(md, 'developmentDependency') === 'true', min_client_version: md.attrs.minClientVersion ?? null };
      if (id && id.toLowerCase() !== pkg.name.toLowerCase()) mismatch(res, 'name', `the .nuspec says the id is "${id}" but the package was requested as "${pkg.name}"`, spec.path);
      if (version && version.toLowerCase().replace(/\+.*$/, '') !== pkg.version.toLowerCase().replace(/\+.*$/, '') && version.replace(/(\.0)+$/, '') !== pkg.version.replace(/(\.0)+$/, '')) mismatch(res, 'version', `the .nuspec says the version is "${version}" but the registry served it as "${pkg.version}"`, spec.path);
      for (const d of findAll(md, 'dependency')) {
        if (!d.attrs.id) continue;
        const grp = d.attrs.exclude || '';
        res.deps.push(mkDep({ name: d.attrs.id, spec: d.attrs.version || '', kind: 'runtime', cls: classifyNuget(d.attrs.version), file: spec.path, extra: { framework: null } }));
        if (/all/i.test(grp)) res.deps[res.deps.length - 1].note = 'excluded from the consumer';
      }
      // tag the target framework group
      for (const g of findAll(md, 'group')) for (const d of g.children) { const dep = res.deps.find(x => x.name === d.attrs.id && x.framework === null); if (dep) dep.framework = g.attrs.targetFramework || 'any'; }
      for (const r of findAll(md, 'dependency')) { const dep = res.deps.find(x => x.name === r.attrs.id && x.framework === null); if (dep) dep.framework = 'any'; }
      // de-duplicate the same dependency repeated per target framework
      const seen = new Set();
      res.deps = res.deps.filter(d => { const k = `${d.name.toLowerCase()}|${d.spec}`; if (seen.has(k)) return false; seen.add(k); return true; });
    }
  }
  for (const f of fx.findAll(/^tools\/(?:install|init|uninstall)\.ps1$/i)) {
    const base = f.path.split('/').pop().toLowerCase();
    res.hooks.push({ id: 'nuget-script', phase: base.replace('.ps1', ''), trigger: 'Visual Studio / Package Manager Console', command: f.path, file: f.path, runsFiles: [f.path], consumer: 'conditional', note: base === 'init.ps1' ? 'run by Visual Studio when the solution opens / package installs in the Package Manager Console; `dotnet restore` does not run it' : 'run by Visual Studio for packages.config projects; `dotnet restore` / PackageReference does not run it' });
    addInstallFile(res, f.path, `NuGet ${base}`, base.replace('.ps1', ''));
  }
  const msb = fx.findAll(/^(?:build|buildTransitive|buildMultiTargeting)\/.*\.(?:targets|props)$/i).concat(fx.findAll(/^Sdk\/.*\.(?:targets|props)$/i));
  for (const f of msb) {
    res.hooks.push({ id: 'msbuild', phase: 'build', trigger: 'every build of a project that references the package', command: f.path, file: f.path, runsFiles: [f.path], consumer: true, note: 'MSBuild imports this file automatically into the consuming project; targets in it (Exec, inline tasks, DownloadFile) run on every build' });
    addInstallFile(res, f.path, 'imported into the consumer\'s MSBuild', 'build');
  }
  const analyzers = fx.findAll(/^analyzers\/.*\.dll$/i);
  if (analyzers.length) res.hooks.push({ id: 'analyzer', phase: 'build', trigger: 'compiler (Roslyn)', command: `${analyzers.length} analyzer / source-generator assembl${analyzers.length === 1 ? 'y' : 'ies'}`, file: analyzers[0].path, runsFiles: [], consumer: true, note: 'analyzers and source generators are loaded into the C# compiler process of every project that references the package' });
  if (fx.find('.signature.p7s')) res.info.signed = true;
  return res;
}

// ── Composer ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
function psr4File(fx, cls, autoload) {
  const psr4 = objectOf(objectOf(autoload)['psr-4']);
  for (const [prefix, dir] of Object.entries(psr4).sort((a, b) => b[0].length - a[0].length)) {
    if (cls.startsWith(prefix)) {
      for (const d of [].concat(dir)) { const p = `${String(d).replace(/^\.\//, '').replace(/\/+$/, '')}/${cls.slice(prefix.length).replace(/\\/g, '/')}.php`.replace(/^\//, ''); if (fx.find(p)) return p; }
    }
  }
  return null;
}

export function analyzeComposer(fx, pkg) {
  const res = emptyResult();
  const j = fx.json('composer.json');
  if (!j) { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: j === undefined ? 'composer.json is not valid JSON' : 'the archive has no composer.json at its root', file: 'composer.json' }); return res; }
  res.manifestFiles.push('composer.json');
  res.info = { name: j.name ?? null, version: j.version ?? null, description: j.description ?? null, license: [].concat(j.license || []).join(', ') || null, homepage: j.homepage ?? null, type: j.type ?? 'library', bin: j.bin ?? null };
  if (j.name && j.name.toLowerCase() !== pkg.name.toLowerCase()) mismatch(res, 'name', `composer.json says the name is "${j.name}" but the package was requested as "${pkg.name}"`, 'composer.json');
  const platform = [];
  for (const [n, v] of Object.entries(objectOf(j.require))) {
    if (n === 'php' || /^(?:ext|lib)-/.test(n) || n === 'composer-plugin-api' || n === 'composer-runtime-api' || n === 'hhvm') { platform.push(`${n} ${v}`); continue; }
    res.deps.push(mkDep({ name: n, spec: v, kind: 'runtime', cls: classifyComposer(v), file: 'composer.json' }));
  }
  for (const [n, v] of Object.entries(objectOf(j['require-dev']))) { if (/^(?:ext|lib)-|^php$/.test(n)) continue; res.deps.push(mkDep({ name: n, spec: v, kind: 'dev', cls: classifyComposer(v), file: 'composer.json' })); }
  res.info.platform_requires = platform;
  const type = String(j.type || 'library');
  const extra = objectOf(j.extra);
  if (type === 'composer-plugin' || type === 'composer-installer') {
    const classes = [].concat(extra.class || []).filter(x => typeof x === 'string');
    res.hooks.push({ id: 'composer-plugin', phase: 'plugin', trigger: 'composer install / update (plugin activation)', command: classes.join(', ') || type, file: 'composer.json', runsFiles: [], consumer: true, note: 'Composer loads and runs a plugin\'s PHP code inside the Composer process as soon as it is installed (it must be allowed by `config.allow-plugins` in the consumer\'s composer.json)' });
    for (const c of classes) { const f = psr4File(fx, c, j.autoload); if (f) addInstallFile(res, f, 'Composer plugin class', 'plugin'); }
  }
  const af = [].concat(objectOf(j.autoload).files || []).filter(x => typeof x === 'string');
  if (af.length) {
    res.hooks.push({ id: 'composer-autoload-files', phase: 'import', trigger: 'Composer autoloader (every request / CLI run)', command: af.join(', '), file: 'composer.json', runsFiles: af, consumer: true, note: '`autoload.files` are `require`d by the consumer\'s autoloader on every request, before any class is used' });
    for (const f of af) addInstallFile(res, f.replace(/^\.\//, ''), 'listed in autoload.files', 'import');
  }
  for (const [ev, v] of Object.entries(objectOf(j.scripts))) {
    const cmds = [].concat(v).filter(x => typeof x === 'string');
    if (!cmds.length) continue;
    res.hooks.push({ id: 'composer-script', phase: ev, trigger: 'composer (root project only)', command: cmds.join(' && '), file: 'composer.json', runsFiles: [], consumer: false, note: 'Composer runs `scripts` only for the root project, not for a dependency' });
  }
  const cfg = objectOf(j.config);
  if (cfg['secure-http'] === false) res.issues.push({ rule: 'package.config.insecure_registry', key: 'secure-http', detail: 'composer.json sets config.secure-http to false (allows HTTP repositories)', file: 'composer.json' });
  for (const r of [].concat(Array.isArray(j.repositories) ? j.repositories : Object.values(objectOf(j.repositories)))) {
    if (r && typeof r === 'object' && typeof r.url === 'string' && isHttp(r.url)) res.issues.push({ rule: 'package.config.insecure_registry', key: `repo:${r.url}`, detail: `a repository is declared over unencrypted HTTP (${r.url})`, file: 'composer.json' });
  }
  return res;
}

// ── pub ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function analyzePub(fx, pkg) {
  const res = emptyResult();
  const t = fx.textOf('pubspec.yaml');
  const y = t ? parseYaml(t) : null;
  if (!y || typeof y !== 'object') { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: 'the archive has no readable pubspec.yaml', file: 'pubspec.yaml' }); return res; }
  res.manifestFiles.push('pubspec.yaml');
  res.info = { name: y.name ?? null, version: y.version != null ? String(y.version) : null, description: y.description ?? null, homepage: y.homepage ?? null, repository: y.repository ?? null, publish_to: y.publish_to ?? null, environment: y.environment ?? null, executables: Object.keys(objectOf(y.executables)), platforms: Object.keys(objectOf(objectOf(objectOf(y.flutter).plugin).platforms)) };
  if (y.name && String(y.name) !== pkg.name) mismatch(res, 'name', `pubspec.yaml says the name is "${y.name}" but the package was requested as "${pkg.name}"`, 'pubspec.yaml');
  if (y.version != null && String(y.version).replace(/\+.*$/, '') !== pkg.version.replace(/\+.*$/, '')) mismatch(res, 'version', `pubspec.yaml says the version is "${y.version}" but the registry served it as "${pkg.version}"`, 'pubspec.yaml');
  for (const [n, d] of Object.entries(objectOf(y.dependencies))) res.deps.push(mkDep({ name: n, spec: typeof d === 'string' ? d : d?.version ?? (d?.git ? (typeof d.git === 'string' ? d.git : d.git.url) : d?.path ?? ''), kind: 'runtime', cls: classifyPub(d), file: 'pubspec.yaml' }));
  for (const [n, d] of Object.entries(objectOf(y.dev_dependencies))) res.deps.push(mkDep({ name: n, spec: typeof d === 'string' ? d : d?.version ?? '', kind: 'dev', cls: classifyPub(d), file: 'pubspec.yaml' }));
  for (const [n, d] of Object.entries(objectOf(y.dependency_overrides))) res.deps.push(mkDep({ name: n, spec: typeof d === 'string' ? d : d?.version ?? '', kind: 'dev', installed: false, cls: classifyPub(d), file: 'pubspec.yaml', extra: { note: 'dependency_overrides are ignored when this package is a dependency' } }));
  for (const d of res.deps) {
    const url = typeof d.detail === 'string' && /hosted at (http:\/\/\S+)/.exec(d.detail)?.[1];
    if (url && isHttp(url)) res.issues.push({ rule: 'package.config.insecure_registry', key: `dep:${d.name}`, detail: `dependency "${d.name}" is hosted at an unencrypted HTTP URL (${url})`, file: 'pubspec.yaml' });
  }
  for (const f of fx.findAll(/^hook\/[^/]+\.dart$/)) {
    res.hooks.push({ id: 'pub-hook', phase: 'build', trigger: 'dart run / flutter build (native-assets build hook)', command: f.path, file: f.path, runsFiles: [f.path], consumer: true, note: 'build hooks are Dart programs that the toolchain runs while building an application that depends on this package; they can download and compile native code' });
    addInstallFile(res, f.path, 'native-assets build hook', 'build');
  }
  const native = fx.findAll(/^(?:android\/build\.gradle(?:\.kts)?|android\/settings\.gradle(?:\.kts)?|(?:ios|macos)\/[^/]+\.podspec|linux\/CMakeLists\.txt|windows\/CMakeLists\.txt|(?:ios|macos|linux|windows|android)\/[^/]*\.(?:sh|rb|cmake))$/);
  for (const f of native) {
    res.hooks.push({ id: 'plugin-native-build', phase: 'build', trigger: 'the consuming app\'s platform build (Gradle / CocoaPods / CMake)', command: f.path, file: f.path, runsFiles: [f.path], consumer: true, note: 'a plugin\'s platform build file is executed by the consumer\'s Gradle / CocoaPods / CMake run' });
    addInstallFile(res, f.path, 'plugin platform build script', 'build');
  }
  return res;
}

const ANALYZERS = { npm: analyzeNpm, pypi: analyzePypi, cargo: analyzeCargo, go: analyzeGo, gem: analyzeGem, nuget: analyzeNuget, composer: analyzeComposer, pub: analyzePub };

/**
 * @param {string} ecosystem
 * @param {Array<{artifact:object, archive:object, gem?:object}>} archives opened archives of the package
 * @param {{name:string, version:string, meta:object}} pkg
 */
export function analyzeManifests(ecosystem, archives, pkg) {
  const fx = new Files(archives);
  fx.gem = archives.find(a => a.gem)?.gem || null;
  const fn = ANALYZERS[ecosystem];
  if (!fn) throw new Error(`no manifest analyzer for ${ecosystem}`);
  const res = fn(fx, pkg);
  for (const k of ['locked', 'lockfiles', 'requirementsFiles', 'notes', 'bundledUnversioned']) res[k] ||= [];
  res.files = fx;
  return res;
}
