'use strict';
// manifests.js — reads a package's own metadata files (package.json, PKG-INFO / pyproject.toml / setup.py, Cargo.toml, go.mod, gemspec,
// .nuspec, composer.json, pubspec.yaml) and answers, per ecosystem:
//
//   info      name, version, description, licence, repository … as the ARCHIVE says (not as the registry says: the two are compared)
//   deps      every declared dependency with its pin class (pinning.js) and whether a consumer installs it
//   hooks     everything that runs code on the CONSUMER's machine because the package was installed, built against or imported
//   installFiles  local files those hooks execute or load (they are analysed with install-time severity)
//   bundled   dependencies shipped inside the archive (node_modules/, vendor/, vendored wheels) with their versions
//   issues    metadata problems (name mismatch, manifest confusion, insecure URLs, tool configuration that alters the consumer's build …)
//
// Nothing here runs a package manager, a build script or a hook. Ecosystems added in manifests_more.js: Go, RubyGems, NuGet, Composer, pub.

import { parseToml } from './toml.js';
import { analyzeCommand, NPM_CONSUMER_HOOKS, NPM_OTHER_HOOKS } from './installscripts.js';
import { classifyNpm, parsePep508, classifyPypi, classifyCargo } from './pinning.js';
import { collectPython } from './python.js';

export const MAX_MANIFEST = 4 * 1048576;

/** Archive helpers shared by every ecosystem reader. */
export class Files {
  constructor(archives) { this.archives = archives; }
  all() { return this.archives.flatMap(a => a.archive.files.filter(f => f.type === 'file').map(f => ({ ...f, artifact: a.artifact }))); }
  find(path) { for (const a of this.archives) { const f = a.archive.files.find(x => x.type === 'file' && x.path === path); if (f) return f; } return null; }
  findAll(re) { return this.all().filter(f => re.test(f.path)); }
  text(file, max = MAX_MANIFEST) { try { return file.read(max).toString('utf8').replace(/^\uFEFF/, ''); } catch { return null; } }
  textOf(path) { const f = this.find(path); return f ? this.text(f) : null; }
  json(path) { const t = this.textOf(path); if (t == null) return null; try { return JSON.parse(t); } catch { return undefined; } }
}

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);
const objectOf = v => (v && typeof v === 'object' && !Array.isArray(v) ? v : {});

export function mkDep({ name, spec, kind = 'runtime', cls, file, installed, extra }) {
  const installedByDefault = installed ?? !['dev', 'extra', 'optional-extra'].includes(kind);
  return { name: String(name), spec: spec == null ? '' : String(spec), kind, pin: cls.pin, version: cls.version, source: cls.source, immutable: cls.immutable, detail: cls.detail, alias: cls.alias || null, file, installed: installedByDefault, ...extra };
}

const emptyResult = () => ({ info: {}, deps: [], hooks: [], installFiles: [], bundled: [], issues: [], manifestFiles: [], locked: [], lockfiles: [], requirementsFiles: [], notes: [], bundledUnversioned: [] });

export function addInstallFile(res, path, reason, phase) {
  if (!path || res.installFiles.some(f => f.path === path)) return;
  res.installFiles.push({ path, reason, phase });
}

const isHttp = u => /^http:\/\//i.test(u) && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(u);

// ── npm ───────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function analyzeNpm(fx, pkg) {
  const res = emptyResult();
  const raw = fx.textOf('package.json');
  if (raw == null) { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: 'the tarball has no package.json at its root', file: null }); return res; }
  let j; try { j = JSON.parse(raw); } catch { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'bad-manifest', detail: 'package.json is not valid JSON', file: 'package.json' }); return res; }
  res.manifestFiles.push('package.json');
  res.info = { name: j.name ?? null, version: j.version ?? null, description: j.description ?? null, license: typeof j.license === 'string' ? j.license : j.license?.type ?? null, repository: typeof j.repository === 'string' ? j.repository : j.repository?.url ?? null, homepage: j.homepage ?? null, main: j.main ?? null, type: j.type ?? null, engines: j.engines ?? null, bin: j.bin ?? null, os: j.os ?? null, cpu: j.cpu ?? null };
  if (j.name && j.name !== pkg.name) res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'name', detail: `package.json says the name is "${j.name}" but the package was requested as "${pkg.name}"`, file: 'package.json' });
  if (j.version && j.version !== pkg.version) res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'version', detail: `package.json says the version is "${j.version}" but the registry served it as "${pkg.version}"`, file: 'package.json' });

  const scripts = objectOf(j.scripts);
  const hasGyp = Boolean(fx.find('binding.gyp'));
  for (const h of NPM_CONSUMER_HOOKS) {
    if (typeof scripts[h] !== 'string') continue;
    const a = analyzeCommand(scripts[h]);
    res.hooks.push({ id: 'npm-script', phase: h, trigger: 'npm install', command: scripts[h], file: 'package.json', runsFiles: a.files, consumer: true, note: null });
    for (const f of a.files) addInstallFile(res, f, `run by the ${h} script`, h);
  }
  if (hasGyp && typeof scripts.install !== 'string' && typeof scripts.preinstall !== 'string') {
    res.hooks.push({ id: 'node-gyp', phase: 'install', trigger: 'npm install', command: 'node-gyp rebuild', file: 'binding.gyp', runsFiles: [], consumer: true, note: 'npm runs `node-gyp rebuild` by itself when binding.gyp exists and no install / preinstall script is declared' });
  }
  for (const h of NPM_OTHER_HOOKS) {
    if (typeof scripts[h] !== 'string') continue;
    const forGit = h === 'prepare';
    res.hooks.push({ id: 'npm-script', phase: h, trigger: forGit ? 'npm install from git / local path' : 'publisher or uninstall only', command: scripts[h], file: 'package.json', runsFiles: [], consumer: false, note: forGit ? '`prepare` runs for consumers only when the package is installed from a git URL or a directory' : 'not run when a consumer installs this release from the registry' });
  }

  const depBlock = (obj, kind) => { for (const [n, v] of Object.entries(objectOf(obj))) res.deps.push(mkDep({ name: n, spec: v, kind, cls: classifyNpm(v), file: 'package.json', installed: kind === 'dev' ? false : true })); };
  depBlock(j.dependencies, 'runtime'); depBlock(j.optionalDependencies, 'optional'); depBlock(j.peerDependencies, 'peer'); depBlock(j.devDependencies, 'dev');
  const bundledNames = [].concat(j.bundledDependencies ?? j.bundleDependencies ?? []).filter(x => typeof x === 'string');
  if (j.bundledDependencies === true || j.bundleDependencies === true) bundledNames.push(...Object.keys(objectOf(j.dependencies)));
  for (const f of fx.findAll(/^node_modules\/(?:@[^/]+\/)?[^/]+\/package\.json$/)) {
    const bj = (() => { try { return JSON.parse(fx.text(f)); } catch { return null; } })();
    const bn = f.path.split('/').slice(1, -1).join('/');
    if (bj && bj.version) res.bundled.push({ name: bj.name || bn, version: bj.version, path: `node_modules/${bn}`, declaredBundled: bundledNames.includes(bn), scripts: NPM_CONSUMER_HOOKS.filter(h => typeof bj.scripts?.[h] === 'string') });
  }
  // dependencies that bypass the registry or use clear-text transport
  for (const d of res.deps) {
    if (d.source === 'url' && isHttp(d.spec)) res.issues.push({ rule: 'package.config.insecure_registry', key: `dep:${d.name}`, detail: `dependency "${d.name}" is fetched over unencrypted HTTP (${d.spec})`, file: 'package.json' });
  }
  const pc = objectOf(j.publishConfig);
  if (typeof pc.registry === 'string' && isHttp(pc.registry)) res.issues.push({ rule: 'package.config.insecure_registry', key: 'publishConfig', detail: `publishConfig.registry uses unencrypted HTTP (${pc.registry})`, file: 'package.json' });

  // manifest confusion: the registry's copy of the manifest is what `npm install` trusts for dependencies and scripts, the tarball's is what runs
  const reg = pkg.meta?.declared;
  if (reg) {
    const diffs = [];
    for (const h of NPM_CONSUMER_HOOKS) {
      const a = objectOf(reg.scripts)[h] ?? null, b = typeof scripts[h] === 'string' ? scripts[h] : null;
      if (a !== b) diffs.push(`${h} script: registry ${a == null ? 'declares none' : `"${a.slice(0, 80)}"`}, tarball ${b == null ? 'declares none' : `"${b.slice(0, 80)}"`}`);
    }
    // the registry copies optionalDependencies into the `dependencies` of its version document (legacy behaviour); that is not a difference
    const regDeps = Object.fromEntries(Object.entries(objectOf(reg.dependencies)).filter(([n, v]) => objectOf(reg.optionalDependencies)[n] !== v || objectOf(j.dependencies)[n] === v));
    for (const [kind, rb, tb] of [['dependencies', regDeps, j.dependencies], ['optionalDependencies', reg.optionalDependencies, j.optionalDependencies]]) {
      const A = objectOf(rb), B = objectOf(tb);
      const names = new Set([...Object.keys(A), ...Object.keys(B)]);
      const bad = [...names].filter(n => A[n] !== B[n]);
      if (bad.length) diffs.push(`${kind}: ${bad.slice(0, 5).map(n => `${n} (registry ${A[n] ?? 'absent'}, tarball ${B[n] ?? 'absent'})`).join('; ')}${bad.length > 5 ? ` and ${bad.length - 5} more` : ''}`);
    }
    if (diffs.length) res.issues.push({ rule: 'package.manifest_confusion', key: 'diff', detail: `the manifest the registry shows differs from the package.json inside the tarball: ${diffs.join(' | ')}`, file: 'package.json' });
  }
  const npmrc = fx.find('.npmrc');
  if (npmrc) res.issues.push({ rule: 'package.config.tool_config', key: '.npmrc', detail: '.npmrc is shipped inside the package (it configures npm — registry, scripts, tokens — if it is ever copied into a project)', file: '.npmrc' });
  return res;
}

// ── PyPI ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
const normPy = n => String(n).toLowerCase().replace(/[-_.]+/g, '-');

function parseHeaders(text) {
  const out = {}, multi = {};
  const head = text.split(/\r?\n\r?\n/)[0];
  for (const line of head.split(/\r?\n/)) {
    const m = /^([A-Za-z][A-Za-z0-9-]*):\s*(.*)$/.exec(line);
    if (!m) continue;
    const k = m[1].toLowerCase();
    (multi[k] ||= []).push(m[2]);
    if (!(k in out)) out[k] = m[2];
  }
  return { first: out, all: multi };
}

export function analyzePypi(fx, pkg) {
  const res = emptyResult();
  const seen = new Set();
  const addDep = (line, kindDefault, file) => {
    const p = parsePep508(line);
    if (!p) return;
    const extra = /extra\s*==\s*['"]([^'"]+)['"]/.exec(p.marker || '');
    const kind = kindDefault === 'build' ? 'build' : extra ? 'extra' : kindDefault;
    const key = `${normPy(p.name)}|${p.spec}|${kind}`;
    if (seen.has(key)) return;
    seen.add(key);
    res.deps.push(mkDep({ name: p.name, spec: p.spec, kind, cls: classifyPypi(p), file, extra: { marker: p.marker, extras: p.extras.length ? p.extras : undefined, extraName: extra?.[1] } }));
  };

  // sdist metadata
  const pkgInfo = fx.textOf('PKG-INFO');
  const metas = [];
  if (pkgInfo) metas.push(['PKG-INFO', pkgInfo]);
  for (const f of fx.findAll(/^[^/]+\.dist-info\/METADATA$/)) metas.push([f.path, fx.text(f)]);
  for (const [file, text] of metas) {
    res.manifestFiles.push(file);
    const h = parseHeaders(text);
    if (!res.info.name) res.info = { name: h.first.name ?? null, version: h.first.version ?? null, description: h.first.summary ?? null, license: h.first['license-expression'] || h.first.license || null, homepage: h.first['home-page'] ?? null, repository: (h.all['project-url'] || []).find(x => /^(?:source|repository|code|github)/i.test(x))?.split(/,\s*/)[1] ?? null, requires_python: h.first['requires-python'] ?? null };
    for (const l of h.all['requires-dist'] || []) addDep(l, 'runtime', file);
    if (res.info.name && normPy(res.info.name) !== normPy(pkg.name)) res.issues.push({ rule: 'package.metadata.name_mismatch', key: `name:${file}`, detail: `${file} says the name is "${res.info.name}" but the package was requested as "${pkg.name}"`, file });
    if (h.first.version && normPyVersion(h.first.version) !== normPyVersion(pkg.version)) res.issues.push({ rule: 'package.metadata.name_mismatch', key: `version:${file}`, detail: `${file} says the version is "${h.first.version}" but the registry served it as "${pkg.version}"`, file });
  }

  // pyproject.toml
  const pyp = fx.textOf('pyproject.toml');
  let backend = null, backendPath = null;
  if (pyp) {
    res.manifestFiles.push('pyproject.toml');
    const { data } = parseToml(pyp);
    const bs = objectOf(data['build-system']);
    backend = typeof bs['build-backend'] === 'string' ? bs['build-backend'] : null;
    backendPath = [].concat(bs['backend-path'] || []).filter(x => typeof x === 'string');
    for (const r of [].concat(bs.requires || [])) addDep(String(r), 'build', 'pyproject.toml');
    const project = objectOf(data.project);
    for (const r of [].concat(project.dependencies || [])) addDep(String(r), 'runtime', 'pyproject.toml');
    for (const [extra, arr] of Object.entries(objectOf(project['optional-dependencies']))) for (const r of [].concat(arr || [])) addDep(`${r}${/;/.test(String(r)) ? ' and' : ';'} extra == "${extra}"`, 'runtime', 'pyproject.toml');
    const poetry = objectOf(objectOf(data.tool).poetry);
    for (const [n, v] of Object.entries(objectOf(poetry.dependencies))) {
      if (n === 'python') continue;
      const spec = typeof v === 'string' ? v : typeof v?.version === 'string' ? v.version : '';
      if (v && typeof v === 'object' && (v.git || v.path || v.url)) res.deps.push(mkDep({ name: n, spec: v.git || v.path || v.url, kind: 'runtime', cls: { pin: 'non_registry', version: null, source: v.git ? 'git' : v.path ? 'path' : 'url', immutable: Boolean(v.rev && /^[0-9a-f]{40}$/.test(v.rev)), detail: 'direct reference' }, file: 'pyproject.toml' }));
      else res.deps.push(mkDep({ name: n, spec, kind: 'runtime', cls: classifyPypi({ spec: poetrySpec(spec), url: null }), file: 'pyproject.toml' }));
    }
    res.info.entry_points = { scripts: Object.keys(objectOf(project.scripts)), gui: Object.keys(objectOf(project['gui-scripts'])), groups: Object.keys(objectOf(project['entry-points'])) };
    res.info.build_backend = backend;
    if (!res.info.name && project.name) res.info = { ...res.info, name: project.name, version: project.version ?? null, description: project.description ?? null };
    const KNOWN = /^(?:setuptools\.build_meta|setuptools\.build_meta:__legacy__|flit_core\.buildapi|flit\.buildapi|hatchling\.build|poetry\.core\.masonry\.api|poetry\.masonry\.api|pdm\.backend|pdm\.pep517\.api|maturin|scikit_build_core\.build|mesonpy|setuptools_scm|whey|trampolim|enscons\.api|sipbuild\.api|jupyter_packaging\.build_api|pybind11_build)$/;
    if (backendPath.length || (backend && !KNOWN.test(backend))) {
      res.hooks.push({ id: 'build-backend', phase: 'build', trigger: 'pip install (build)', command: backend || '(in-tree backend)', file: 'pyproject.toml', runsFiles: [], consumer: true, note: `an ${backendPath.length ? 'in-tree' : 'unrecognised'} build backend runs arbitrary Python while the package is built` });
      const mod = (backend || '').split(':')[0].split('.')[0];
      for (const bp of backendPath) {
        const dir = bp === '.' || bp === './' ? '' : `${bp.replace(/^\.\//, '').replace(/\/+$/, '')}/`;
        for (const f of fx.findAll(/\.py$/)) if (f.path.startsWith(dir) && (!mod || f.path.slice(dir.length).startsWith(`${mod}.py`) || f.path.slice(dir.length).startsWith(`${mod}/`))) addInstallFile(res, f.path, 'in-tree PEP 517 build backend', 'build');
      }
    }
  }
  // setup.cfg
  const cfg = fx.textOf('setup.cfg');
  if (cfg) {
    res.manifestFiles.push('setup.cfg');
    const cmd = /^cmdclass\s*=/m.test(cfg);
    if (cmd) res.hooks.push({ id: 'setup-py', phase: 'install', trigger: 'pip install', command: 'setup.cfg cmdclass', file: 'setup.cfg', runsFiles: [], consumer: true, note: 'custom setuptools command classes run code during build / install' });
  }
  // setup.py: arbitrary code at build time for every sdist install
  const setup = fx.find('setup.py');
  if (setup) {
    res.manifestFiles.push('setup.py');
    const t = fx.text(setup) || '';
    res.hooks.push({ id: 'setup-py', phase: 'install', trigger: 'pip install (sdist build)', command: 'python setup.py', file: 'setup.py', runsFiles: [], consumer: true, note: 'setup.py is executed by the build backend whenever the sdist is installed; wheels (pip\'s default when one exists) do not run it' });
    addInstallFile(res, 'setup.py', 'executed when the sdist is built', 'install');
    for (const m of t.matchAll(/\bcmdclass\s*=\s*\{([^}]*)\}/g)) for (const c of m[1].matchAll(/['"](install|develop|build_py|build_ext|egg_info|bdist_wheel|sdist)['"]\s*:\s*(\w+)/g)) res.hooks.push({ id: 'setup-py', phase: c[1], trigger: 'pip install', command: `cmdclass ${c[1]} → ${c[2]}`, file: 'setup.py', runsFiles: [], consumer: true, note: 'a setuptools command is overridden with custom code' });
    if (/\bext_modules\s*=/.test(t) || /\bExtension\s*\(/.test(t)) res.hooks.push({ id: 'native-build', phase: 'build', trigger: 'pip install (sdist build)', command: 'compile C / C++ extension', file: 'setup.py', runsFiles: [], consumer: true, note: 'compiles native code on the consumer machine' });
  }
  // wheel specifics: .pth files run at EVERY interpreter start; sitecustomize likewise
  for (const f of fx.findAll(/^[^/]+\.pth$/)) {
    const t = fx.text(f, 256 * 1024) || '';
    const execLines = t.split(/\r?\n/).filter(l => /^\s*import[\s(]/.test(l) || /^\s*exec\s*\(/.test(l));
    res.manifestFiles.push(f.path);
    if (execLines.length) {
      res.hooks.push({ id: 'pth-file', phase: 'startup', trigger: 'every Python start', command: execLines[0].trim().slice(0, 240), file: f.path, runsFiles: [], consumer: true, note: '.pth lines that begin with `import` are executed by site.py each time any Python process starts, with no import of this package needed' });
      addInstallFile(res, f.path, '.pth import line, run at interpreter start', 'startup');
    }
  }
  for (const f of fx.findAll(/^(?:sitecustomize|usercustomize)\.py$/)) {
    res.hooks.push({ id: 'sitecustomize', phase: 'startup', trigger: 'every Python start', command: f.path, file: f.path, runsFiles: [], consumer: true, note: 'a top-level sitecustomize / usercustomize module is imported automatically by site.py' });
    addInstallFile(res, f.path, 'imported automatically at interpreter start', 'startup');
  }
  const ep = fx.findAll(/^[^/]+\.dist-info\/entry_points\.txt$/)[0];
  if (ep) {
    const t = fx.text(ep) || '';
    const groups = [...t.matchAll(/^\[([^\]]+)\]/gm)].map(m => m[1]);
    res.info.entry_point_groups = groups;
    const cs = /\[console_scripts\]([^[]*)/.exec(t);
    if (cs) res.info.console_scripts = [...cs[1].matchAll(/^\s*([^=\s#]+)\s*=/gm)].map(m => m[1]);
    for (const g of groups.filter(g => /^(?:distutils\.commands|setuptools\.finalize_distribution_options|pytest11|flake8\.extension|babel\.extractors|setuptools\.installation)$/.test(g))) {
      res.hooks.push({ id: 'entry-point', phase: 'plugin', trigger: `loaded by ${g.split('.')[0]}`, command: `entry-point group [${g}]`, file: ep.path, runsFiles: [], consumer: 'conditional', note: 'a plugin entry point: the host tool imports it whenever that tool runs' });
    }
  }
  const scriptsData = fx.findAll(/^[^/]+\.data\/scripts\/[^/]+$/);
  if (scriptsData.length) res.info.data_scripts = scriptsData.map(f => f.path.split('/').pop());
  // every other dependency source: setup.py (evaluated, not run), setup.cfg, pyproject groups, requirements files, Pipfile, conda, egg-info and lockfiles
  const py = collectPython(fx, { pkg });
  for (const l of py.lines) addDep(l.line, l.kind, l.file);
  for (const d of py.direct) {
    const src = d.source || (d.url ? 'url' : null);
    if (d.url) {
      const key = `${normPy(d.name)}|${d.url}|${d.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const immutable = Boolean(d.ref && /^[0-9a-f]{40}$/.test(d.ref)) || /@[0-9a-f]{40}(?:$|[#?])/.test(d.url) || /#sha256=[0-9a-f]{64}/i.test(d.url);
      res.deps.push(mkDep({ name: d.name, spec: d.url, kind: d.kind, cls: { pin: 'non_registry', version: null, source: src, immutable, detail: `${src === 'git' ? 'git repository' : src === 'path' ? 'local path' : 'direct URL'}${d.ref ? ` @ ${d.ref}` : ''}` }, file: d.file, extra: { marker: d.marker || undefined, extraName: d.extraName } }));
      if (isHttp(String(d.url).replace(/^[a-z+]*\+/, ''))) res.issues.push({ rule: 'package.config.insecure_registry', key: `dep:${d.name}`, detail: `dependency "${d.name}" is fetched over unencrypted HTTP (${d.url})`, file: d.file });
    } else if (d.poetry) {
      const key = `${normPy(d.name)}|${d.spec}|${d.kind}`;
      if (seen.has(key)) continue;
      seen.add(key);
      res.deps.push(mkDep({ name: d.name, spec: d.spec, kind: d.kind, cls: classifyPypi({ spec: poetrySpec(d.spec), url: null }), file: d.file, extra: { marker: d.marker || undefined, extraName: d.extraName } }));
    } else if (d.conda) {
      const key = `${d.name}|${d.spec}|conda`;
      if (seen.has(key)) continue;
      seen.add(key);
      res.deps.push(mkDep({ name: d.name, spec: d.spec, kind: 'dev', cls: classifyPypi({ spec: d.spec.replace(/^=(?!=)/, '=='), url: null }), file: d.file, installed: false }));
    }
  }
  for (const l of py.locked) {
    res.locked.push({ name: l.name, version: l.version || null, source: l.source || 'registry', url: l.url || null, ref: l.ref || null, group: l.group || null, hashes: Boolean(l.hashes && (Array.isArray(l.hashes) ? l.hashes.length : l.hashes)), file: l.file, marker: l.marker || null });
  }
  res.lockfiles = py.lockfiles; res.requirementsFiles = py.requirementsFiles;
  res.issues.push(...py.issues);
  for (const f of py.manifestFiles) if (!res.manifestFiles.includes(f)) res.manifestFiles.push(f);
  res.manifestFiles = [...new Set(res.manifestFiles)];
  res.notes.push(...py.notes);
  for (const b of py.bundled) {                                          // the sdist and the wheel both carry the same copy: one row, every path kept
    const same = res.bundled.find(x => x.name.toLowerCase() === b.name.toLowerCase() && x.version === b.version && x.source);
    if (same) (same.paths ||= [same.path]).push(b.path); else res.bundled.push({ ...b });
  }
  res.bundledUnversioned = py.unversioned;
  if (py.lockfiles.length) res.info.lockfiles = py.lockfiles.map(l => l.file);
  // an archive that yields nothing at all: the registry's own copy of the requirement list is the fallback
  const regReq = pkg.meta?.requires_dist;
  if (!res.deps.some(d => d.kind === 'runtime' || d.kind === 'extra') && Array.isArray(regReq) && regReq.length) {
    for (const l of regReq) addDep(String(l), 'runtime', 'registry metadata');
    res.notes.push('the archive did not state its dependencies; they come from the registry\'s metadata (Requires-Dist)');
  }
  return res;
}
const normPyVersion = v => String(v).toLowerCase().replace(/^v/, '').replace(/[-_]/g, '.').replace(/(?:\.0+)+$/, '');
function poetrySpec(s) {
  const t = String(s || '').trim();
  if (!t || t === '*') return '';
  if (/^\^/.test(t)) return `~=${t.slice(1)}`;
  if (/^~[^=]/.test(t)) return `~=${t.slice(1)}`;
  if (/^[0-9]/.test(t) && !/[,*<>=!~^]/.test(t)) return `==${t}`;
  return t;
}

// ── Cargo ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
export function analyzeCargo(fx, pkg) {
  const res = emptyResult();
  const t = fx.textOf('Cargo.toml');
  if (t == null) { res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'no-manifest', detail: 'the crate has no Cargo.toml at its root', file: null }); return res; }
  res.manifestFiles.push('Cargo.toml');
  const { data } = parseToml(t);
  const p = objectOf(data.package);
  res.info = { name: p.name ?? null, version: typeof p.version === 'string' ? p.version : null, description: p.description ?? null, license: p.license ?? p['license-file'] ?? null, repository: p.repository ?? null, homepage: p.homepage ?? null, links: p.links ?? null, edition: p.edition ?? null, rust_version: p['rust-version'] ?? null };
  if (p.name && p.name.toLowerCase().replace(/_/g, '-') !== pkg.name.toLowerCase().replace(/_/g, '-')) res.issues.push({ rule: 'package.metadata.name_mismatch', key: 'name', detail: `Cargo.toml says the name is "${p.name}" but the crate was requested as "${pkg.name}"`, file: 'Cargo.toml' });
  const block = (tbl, kind, file = 'Cargo.toml') => {
    for (const [k, decl] of Object.entries(objectOf(tbl))) {
      const optional = decl && typeof decl === 'object' && decl.optional === true;
      const name = decl && typeof decl === 'object' && decl.package ? decl.package : k;
      const cls = classifyCargo(decl);
      res.deps.push(mkDep({ name, spec: typeof decl === 'string' ? decl : decl?.version ?? (decl?.git || decl?.path || ''), kind: optional ? 'optional' : kind, cls, file, installed: kind === 'dev' ? false : !optional }));
      if (decl && typeof decl === 'object' && decl.git && isHttp(String(decl.git))) res.issues.push({ rule: 'package.config.insecure_registry', key: `dep:${name}`, detail: `dependency "${name}" is cloned over unencrypted HTTP (${decl.git})`, file });
    }
  };
  block(data.dependencies, 'runtime'); block(data['build-dependencies'], 'build'); block(data['dev-dependencies'], 'dev');
  for (const [cfg, tt] of Object.entries(objectOf(data.target))) { block(objectOf(tt).dependencies, 'runtime'); block(objectOf(tt)['build-dependencies'], 'build'); block(objectOf(tt)['dev-dependencies'], 'dev'); }
  // build script: built and RUN by cargo on the consumer's machine, with the consumer's privileges, for every build
  const declared = p.build;
  const buildPath = declared === false ? null : typeof declared === 'string' ? declared.replace(/^\.\//, '') : fx.find('build.rs') ? 'build.rs' : null;
  if (buildPath) {
    res.hooks.push({ id: 'build-rs', phase: 'build', trigger: 'cargo build / cargo install', command: buildPath, file: buildPath, runsFiles: [buildPath], consumer: true, note: 'cargo compiles and runs the build script on the machine that builds a project depending on this crate' });
    addInstallFile(res, buildPath, 'cargo build script', 'build');
  }
  if (objectOf(data.lib)['proc-macro'] === true || objectOf(data.lib)['proc_macro'] === true) {
    res.hooks.push({ id: 'proc-macro', phase: 'build', trigger: 'rustc (macro expansion)', command: 'procedural macro crate', file: 'Cargo.toml', runsFiles: [], consumer: true, note: 'a procedural macro is compiled and executed inside the compiler of every crate that uses it' });
    for (const f of fx.findAll(/^src\/.*\.rs$/)) addInstallFile(res, f.path, 'procedural-macro source, runs at compile time', 'build');
  }
  for (const f of fx.findAll(/^\.cargo\/(?:config|config\.toml)$/)) res.issues.push({ rule: 'package.config.tool_config', key: f.path, detail: `${f.path} is shipped in the crate (it can change registries, linkers, rustflags and runners if it is ever used by a project)`, file: f.path });
  return res;
}

export { analyzeCommand };
