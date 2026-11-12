'use strict';
// launcher.js — turns a stdio server's `command` + `args` into a description of what is actually started: the package a runner (npx, uvx, pipx …)
// fetches, the container image, or the local script — after looking through `sh -c`, `cmd /c`, `env`, `sudo`. The command is only read, never run.

import path from 'node:path';

/** POSIX-style splitter: quotes group, backslash escapes a quote / space / backslash (other backslashes stay, so Windows paths survive). */
export function shellSplit(s) {
  const out = [];
  let cur = '', q = null, has = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    if (q) {
      if (c === q) q = null;
      else if (c === '\\' && q === '"' && /["\\$`]/.test(s[i + 1] || '')) cur += s[++i];
      else cur += c;
    } else if (c === '"' || c === "'") { q = c; has = true; }
    else if (c === '\\' && /[\s"'\\]/.test(s[i + 1] || '')) cur += s[++i];
    else if (/\s/.test(c)) { if (cur || has) out.push(cur); cur = ''; has = false; }
    else cur += c;
  }
  if (cur || has) out.push(cur);
  return out;
}

const base = p => path.basename(String(p).replace(/\\/g, '/')).toLowerCase().replace(/\.(?:exe|cmd|bat|ps1)$/, '');
const EXACT = /^v?\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const SHELLS = new Set(['sh', 'bash', 'zsh', 'dash', 'ksh', 'fish', 'ash']);
const COMPLEX = /[|;&`<>]|\$\(|\$\{|\|\|/;

/** Splits "name@version" (npm, scoped names included). */
export function splitNpmSpec(spec) {
  const at = spec.indexOf('@', 1);
  return at > 0 ? { name: spec.slice(0, at), version: spec.slice(at + 1) } : { name: spec, version: '' };
}

export function npmPackage(spec, autoInstall) {
  if (/^(?:https?:)\/\//i.test(spec)) return { ecosystem: 'npm', name: spec, version: null, spec, pinClass: 'none', source: 'url', insecure: /^http:/i.test(spec), autoInstall };
  if (/^(?:file:|\.{0,2}[\\/]|~[\\/]|[A-Za-z]:[\\/])/.test(spec)) return { ecosystem: 'npm', name: spec, version: null, spec, pinClass: 'exact', source: 'path', autoInstall };
  if (/^(?:github|gitlab|bitbucket|gist):|^git(?:\+|:\/\/|@)|\.git(?:#|$)/i.test(spec)) {
    const ref = (spec.split('#')[1] || '');
    return { ecosystem: 'npm', name: spec, version: null, spec, pinClass: /^[0-9a-f]{40}$/i.test(ref) ? 'commit' : 'none', source: 'git', insecure: /^git:\/\/|^http:/i.test(spec), autoInstall };
  }
  const { name, version } = splitNpmSpec(spec);
  const pinClass = !version ? 'none' : EXACT.test(version) ? 'exact' : /^[\^~<>=*xX]|\s|\|\||^\d+(?:\.\d+)?(?:\.[xX*])?$/.test(version) ? 'range' : 'tag';
  return { ecosystem: 'npm', name, version: pinClass === 'exact' ? version.replace(/^v/, '') : null, spec, pinClass, source: 'registry', autoInstall };
}

export function pyPackage(spec, autoInstall) {
  if (/^(?:git\+|https?:\/\/|file:|\.{0,2}[\\/])/i.test(spec) || /\s@\s/.test(spec)) {
    const git = /^git\+/i.test(spec) || /\s@\s*git\+/i.test(spec);
    const ref = (spec.match(/@([0-9A-Za-z._/-]+)(?:#|$)/g) || []).pop() || '';
    return { ecosystem: 'pypi', name: spec, version: null, spec, pinClass: git && /@[0-9a-f]{40}\b/i.test(ref) ? 'commit' : git ? 'none' : 'exact', source: git ? 'git' : /^https?:/i.test(spec) ? 'url' : 'path', insecure: /(?:^|\+|@\s*)http:\/\//i.test(spec), autoInstall };
  }
  const m = spec.match(/^([A-Za-z0-9][A-Za-z0-9._-]*)(\[[^\]]*\])?\s*(.*)$/);
  if (!m) return { ecosystem: 'pypi', name: spec, version: null, spec, pinClass: 'none', source: 'registry', autoInstall };
  const rest = m[3].replace(/^@/, '==').trim();           // uvx name@1.2.3
  const ex = rest.match(/^===?\s*([0-9][^\s,;*]*)$/);
  const pinClass = !rest ? 'none' : ex && EXACT.test(ex[1]) ? 'exact' : rest === '==latest' || /^==\s*latest$/i.test(rest) ? 'tag' : 'range';
  return { ecosystem: 'pypi', name: m[1], version: pinClass === 'exact' ? ex[1] : null, spec, pinClass, source: 'registry', autoInstall };
}

// ── runners ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

function parseNpx(rest) {
  const pkgs = []; let yes = false, call = null, i = 0, bin = null;
  for (; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') { i++; break; }
    if (a === '-y' || a === '--yes') yes = true;
    else if (a === '-p' || a === '--package') pkgs.push(rest[++i]);
    else if (a.startsWith('--package=')) pkgs.push(a.slice(10));
    else if (a === '-c' || a === '--call') call = rest[++i];
    else if (/^--?(?:registry|cache|prefix|userconfig|node-options|loglevel|shell|workspace|w)(?:=|$)/.test(a) && !a.includes('=')) i++;
    else if (a.startsWith('-')) { /* boolean flag */ }
    else break;
  }
  if (!call) { const head = rest[i]; if (head !== undefined) { if (!pkgs.length) pkgs.push(head); else bin = head; i++; } }
  return { packages: pkgs.filter(Boolean), yes, call, bin, restArgs: rest.slice(i) };
}

function parseUvx(rest) {
  const withSpecs = []; let from = null, i = 0;
  const VAL = new Set(['--from', '--with', '-w', '--python', '-p', '--index', '--index-url', '-i', '--extra-index-url', '--default-index', '--with-requirements', '--with-editable', '--constraint', '-c', '--overrides', '--env-file', '--directory', '--project', '--config-file', '--find-links', '-f', '--index-strategy', '--resolution', '--prerelease', '--exclude-newer', '--refresh-package', '--reinstall-package', '--upgrade-package', '-P', '--cache-dir']);
  for (; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') { i++; break; }
    if (a === '--from') from = rest[++i];
    else if (a.startsWith('--from=')) from = a.slice(7);
    else if (a === '--with' || a === '-w') withSpecs.push(rest[++i]);
    else if (a.startsWith('--with=')) withSpecs.push(a.slice(7));
    else if (VAL.has(a)) i++;
    else if (a.startsWith('-')) { /* boolean or inline-valued flag */ }
    else break;
  }
  const head = rest[i];
  return { head, from, withSpecs: withSpecs.filter(Boolean), restArgs: rest.slice(i + 1) };
}

const DOCKER_VALUE = new Set(['-e', '--env', '-v', '--volume', '--mount', '-p', '--publish', '-u', '--user', '-w', '--workdir', '--name', '--network', '--net', '-l', '--label', '--entrypoint', '--cap-add', '--cap-drop', '--device', '--security-opt', '--pid', '--ipc', '--uts', '--userns', '--memory', '-m', '--cpus', '--env-file', '--add-host', '--dns', '--restart', '--platform', '--pull', '--hostname', '-h', '--group-add', '--tmpfs', '--gpus', '--ulimit', '--log-driver', '--shm-size', '--cgroupns', '--annotation', '--cidfile', '--expose', '--ip', '--mac-address', '--runtime', '--stop-signal', '--stop-timeout', '--sysctl', '--volumes-from', '--health-cmd', '--label-file', '--link', '--oom-score-adj', '--pids-limit', '--cpu-shares', '--blkio-weight', '--storage-opt', '--read-only-tmpfs']);

function parseDocker(rest) {
  const d = { privileged: false, capAdd: [], securityOpt: [], env: [], volumes: [], devices: [], network: null, pid: null, ipc: null, uts: null, user: null, entrypoint: null };
  let i = 0;
  while (i < rest.length && rest[i].startsWith('-')) i++;                 // docker -H … run
  const sub = rest[i]; if (sub !== 'run' && sub !== 'create') return null;
  i++;
  for (; i < rest.length; i++) {
    const a = rest[i];
    if (a === '--') { i++; break; }
    if (!a.startsWith('-')) break;
    let flag = a, val = null;
    const eq = a.indexOf('=');
    if (a.startsWith('--') && eq > 0) { flag = a.slice(0, eq); val = a.slice(eq + 1); }
    else if (DOCKER_VALUE.has(a)) val = rest[++i] ?? '';
    else if (/^-[ev]./.test(a)) { flag = a.slice(0, 2); val = a.slice(2); }          // -eKEY=v  -v/a:/b
    if (flag === '--privileged') d.privileged = val === null || val === 'true';
    else if (flag === '--cap-add') d.capAdd.push(val);
    else if (flag === '--security-opt') d.securityOpt.push(val);
    else if (flag === '-e' || flag === '--env') d.env.push(val);
    else if (flag === '-v' || flag === '--volume') d.volumes.push({ spec: val, ...volumeParts(val) });
    else if (flag === '--mount') d.volumes.push(mountParts(val));
    else if (flag === '--device') d.devices.push(val);
    else if (flag === '--network' || flag === '--net') d.network = val;
    else if (flag === '--pid') d.pid = val;
    else if (flag === '--ipc') d.ipc = val;
    else if (flag === '--uts') d.uts = val;
    else if (flag === '-u' || flag === '--user') d.user = val;
    else if (flag === '--entrypoint') d.entrypoint = val;
  }
  const image = rest[i];
  if (!image) return null;
  const at = image.indexOf('@');
  const digest = at > 0 ? image.slice(at + 1) : null;
  const ref = at > 0 ? image.slice(0, at) : image;
  const colon = ref.lastIndexOf(':');
  const tag = colon > ref.lastIndexOf('/') ? ref.slice(colon + 1) : null;
  return { ...d, image, imageName: colon > ref.lastIndexOf('/') ? ref.slice(0, colon) : ref, tag, digest, containerArgs: rest.slice(i + 1) };
}
function volumeParts(spec) {
  const parts = String(spec).split(':');
  if (parts.length >= 2 && /^[A-Za-z]$/.test(parts[0])) { parts.splice(0, 2, `${parts[0]}:${parts[1]}`); }    // Windows drive
  return { source: parts[0], target: parts[1] || '', readonly: /(?:^|,)ro(?:,|$)/.test(parts[2] || '') };
}
function mountParts(spec) {
  const kv = Object.fromEntries(String(spec).split(',').map(p => { const k = p.indexOf('='); return k < 0 ? [p, 'true'] : [p.slice(0, k), p.slice(k + 1)]; }));
  return { spec, type: kv.type || 'volume', source: kv.source || kv.src || '', target: kv.target || kv.dst || kv.destination || '', readonly: kv.readonly === 'true' || kv.ro === 'true' };
}

/**
 * @param {{command?:string, args?:string[]}} server
 * @returns {{argv:string[], commandLine:string, wrapper:object|null, privilegedPrefix:boolean, kind:string, runner:string|null, packages:object[], image:object|null, script:object|null, restArgs:string[]}}
 */
export function describeLaunch(server) {
  const args = server.args || [];
  const original = [server.command, ...args].filter(v => v != null && v !== '');
  let argv = server.command && !args.length && /\s/.test(server.command) && !/^[A-Za-z]:[\\/]|^\//.test(server.command) ? shellSplit(server.command) : original.map(String);
  const out = { argv, commandLine: original.join(' '), wrapper: null, privilegedPrefix: false, kind: 'unknown', runner: null, packages: [], image: null, script: null, restArgs: [] };
  // look through wrappers
  for (let n = 0; n < 5 && argv.length; n++) {
    const b = base(argv[0]);
    if (b === 'env') { let i = 1; while (i < argv.length && (argv[i].startsWith('-') || /^[A-Za-z_]\w*=/.test(argv[i]))) i++; argv = argv.slice(i); continue; }
    if (b === 'sudo' || b === 'doas') { out.privilegedPrefix = true; let i = 1; while (i < argv.length && argv[i].startsWith('-')) i++; argv = argv.slice(i); continue; }
    if (b === 'cmd' && /^\/[ck]$/i.test(argv[1] || '')) { const inner = argv.slice(2).join(' '); out.wrapper = { kind: 'cmd /c', inner, complex: COMPLEX.test(inner.replace(/^"|"$/g, '')) }; argv = shellSplit(inner); continue; }
    if (SHELLS.has(b)) {
      const ci = argv.findIndex((a, i) => i > 0 && /^-[a-z]*c[a-z]*$/.test(a));
      if (ci > 0 && argv[ci + 1] !== undefined) { const inner = argv.slice(ci + 1).join(' '); out.wrapper = { kind: `${b} -c`, inner, complex: COMPLEX.test(argv[ci + 1]) }; argv = shellSplit(argv[ci + 1]); continue; }
    }
    if (b === 'powershell' || b === 'pwsh') {
      const ci = argv.findIndex((a, i) => i > 0 && /^-(?:c|command)$/i.test(a));
      if (ci > 0) { const inner = argv.slice(ci + 1).join(' '); out.wrapper = { kind: `${b} -Command`, inner, complex: COMPLEX.test(inner) }; argv = shellSplit(inner.replace(/^&\s*/, '')); continue; }
    }
    break;
  }
  out.argv = argv;
  if (!argv.length) return out;
  const head = base(argv[0]);
  const rest = argv.slice(1);
  out.runner = head;

  const nodeRunner = () => {
    const r = parseNpx(rest);
    if (r.call) out.restArgs = [r.call];
    for (const p of r.packages) out.packages.push(npmPackage(p, r.yes));
    out.restArgs = r.restArgs; out.kind = out.packages.length ? 'package' : 'unknown';
    if (r.call) out.inlineCall = r.call;
  };
  if (head === 'npx' || head === 'bunx') nodeRunner();
  else if (head === 'pnpm' && (rest[0] === 'dlx')) { const r = parseNpx(rest.slice(1)); r.packages.forEach(p => out.packages.push(npmPackage(p, true))); out.restArgs = r.restArgs; out.kind = out.packages.length ? 'package' : 'unknown'; }
  else if (head === 'yarn' && rest[0] === 'dlx') { const r = parseNpx(rest.slice(1)); r.packages.forEach(p => out.packages.push(npmPackage(p, true))); out.restArgs = r.restArgs; out.kind = out.packages.length ? 'package' : 'unknown'; }
  else if ((head === 'npm' && (rest[0] === 'exec' || rest[0] === 'x')) || (head === 'bun' && rest[0] === 'x')) { const r = parseNpx(rest.slice(1)); r.packages.forEach(p => out.packages.push(npmPackage(p, r.yes))); out.restArgs = r.restArgs; out.kind = out.packages.length ? 'package' : 'unknown'; }
  else if (head === 'deno') {
    const i = rest.findIndex(a => /^(?:npm|jsr):/.test(a));
    if (i >= 0) { const spec = rest[i].replace(/^npm:/, ''); out.packages.push(rest[i].startsWith('jsr:') ? { ecosystem: 'jsr', name: rest[i], version: null, spec: rest[i], pinClass: /@\d/.test(rest[i]) ? 'exact' : 'none', source: 'registry', unsupported: true } : npmPackage(spec, true)); out.restArgs = rest.slice(i + 1); out.kind = 'package'; }
    else { const s = rest.find(a => !a.startsWith('-') && a !== 'run'); if (s) { out.script = { path: s, interpreter: 'deno' }; out.kind = 'script'; } }
  }
  else if (head === 'uvx' || (head === 'uv' && rest[0] === 'tool' && rest[1] === 'run')) {
    const r = parseUvx(head === 'uvx' ? rest : rest.slice(2));
    const spec = r.from || r.head;
    if (spec) out.packages.push(pyPackage(spec, true));
    for (const w of r.withSpecs) out.packages.push({ ...pyPackage(w, true), extra: true });
    out.restArgs = r.restArgs; out.kind = out.packages.length ? 'package' : 'unknown';
  }
  else if (head === 'pipx' && rest[0] === 'run') {
    let from = null, i = 1;
    for (; i < rest.length; i++) { const a = rest[i]; if (a === '--spec') from = rest[++i]; else if (a.startsWith('--spec=')) from = a.slice(7); else if (a === '--python' || a === '--index-url' || a === '-i') i++; else if (a.startsWith('-')) continue; else break; }
    const spec = from || rest[i];
    if (spec) out.packages.push(pyPackage(spec, true));
    out.restArgs = rest.slice(i + (from ? 0 : 1)); out.kind = out.packages.length ? 'package' : 'unknown';
  }
  else if (head === 'uv' && rest[0] === 'run') {
    let i = 1;
    for (; i < rest.length; i++) { const a = rest[i]; if (a === '--with' || a === '-w') out.packages.push({ ...pyPackage(rest[++i] || '', true), extra: true }); else if (a.startsWith('--with=')) out.packages.push({ ...pyPackage(a.slice(7), true), extra: true }); else if (['--project', '--directory', '--python', '-p', '--env-file', '--with-requirements'].includes(a)) i++; else if (a.startsWith('-')) continue; else break; }
    const tgt = rest[i];
    if (tgt && /\.py$/.test(tgt)) { out.script = { path: tgt, interpreter: 'python' }; out.kind = 'script'; }
    else if (tgt) { out.kind = 'script'; out.script = { path: null, interpreter: 'uv', command: tgt }; }
  }
  else if (head === 'docker' || head === 'podman' || head === 'nerdctl') {
    const d = parseDocker(rest);
    if (d) { out.image = d; out.kind = 'image'; }
  }
  else if (/^(?:node|nodejs|tsx|ts-node|bun|deno)$/.test(head)) {
    let i = 0;
    if (head === 'bun' && rest[0] === 'run') i = 1;
    for (; i < rest.length && rest[i].startsWith('-'); i++) if (/^--(?:require|import|loader|experimental-loader|env-file|r)$|^-r$/.test(rest[i])) i++;
    if (rest[i]) { out.script = { path: rest[i], interpreter: head }; out.kind = 'script'; out.restArgs = rest.slice(i + 1); }
  }
  else if (/^(?:python[0-9.]*|py|pypy[0-9]*)$/.test(head)) {
    const mi = rest.findIndex(a => a === '-m');
    if (mi >= 0 && rest[mi + 1]) { out.script = { module: rest[mi + 1], path: null, interpreter: head }; out.kind = 'module'; out.restArgs = rest.slice(mi + 2); }
    else { const s = rest.find(a => !a.startsWith('-')); if (s) { out.script = { path: s, interpreter: head }; out.kind = 'script'; out.restArgs = rest.slice(rest.indexOf(s) + 1); } }
  }
  else if (head === 'java') { const j = rest.indexOf('-jar'); if (j >= 0 && rest[j + 1]) { out.script = { path: rest[j + 1], interpreter: 'java' }; out.kind = 'binary'; } }
  else if (/[\\/]/.test(argv[0]) || /\.(?:js|mjs|cjs|py|sh|ps1|rb|php)$/i.test(argv[0])) { out.script = { path: argv[0], interpreter: null }; out.kind = /\.(?:js|mjs|cjs|ts|py)$/i.test(argv[0]) ? 'script' : 'binary'; out.restArgs = rest; }
  else out.kind = 'binary';
  return out;
}

/** "npm:name[@version]" or "pypi:name[==version]" (the form --package takes) → a package record, or null. */
export function parsePackageSpec(s) {
  const m = String(s).match(/^(npm|pypi|pip):(.+)$/i);
  if (!m || !m[2].trim()) return null;
  return /^npm$/i.test(m[1]) ? npmPackage(m[2].trim(), false) : pyPackage(m[2].trim(), false);
}
