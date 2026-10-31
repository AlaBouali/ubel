'use strict';
// scan.js — the analysis of ONE downloaded package release. `analyzePackage(pkg, opts)` takes what registry.js fetched (or a local archive
// wrapped the same way) and returns what the report is built from: findings, apps, component records (looked up later by resolveAdvisories),
// notes and coverage gaps. Nothing is installed, built, imported or run; the network is not touched here.

import crypto from 'node:crypto';
import { openArchive, openGem, ArchiveError } from './archive.js';
import { verifyGoSum } from './registry.js';
import { packagePurl, ECOSYSTEMS } from './ecosystems.js';
import { analyzeManifests } from './manifests_more.js';
import { analyzeCommand, NPM_CONSUMER_HOOKS } from './installscripts.js';
import { analyzeSource, detectLang } from './sourcebehavior.js';
import { analyzeMsbuild } from './msbuild.js';
import { classifyHead, fileRole, isDisguised, sensitiveName, isToolConfig, isLockfile, hostSearchable, hostFlags, EXFIL_FLAGS } from './files.js';
import './rules.js';
import { Findings } from '../../mobile/lib/findings.js';
import { SecretScanner } from '../../mobile/lib/secrets.js';
import { Notes, gap } from '../../mobile/lib/coverage.js';
import { BehaviorBuilder } from '../../binary/lib/behavior.js';
import { RemoteHostCollector } from '../../binary/lib/hosts.js';
import { scanBinaryBuffer } from '../../binary/index.js';
import { purlRecord, inventoryRecord } from '../../binary/lib/records.js';
import { scanBinaryDependencies } from '../../binary/lib/deps.js';
import { addAdvisoryFindings } from '../../binary/lib/advisories.js';

const MB = 1024 * 1024;
export const DEFAULTS = { maxTextKb: 2048, maxBinaryMb: 64, maxBinaries: 25, maxTotalReadMb: 512 };

const sha256 = buf => crypto.createHash('sha256').update(buf).digest('hex');
const sample = (list, n = 12) => list.slice(0, n);

// install-time risk id → rule suffix; the same ids outside install-time files map to package.code.* (only those listed there)
const INSTALL_RULE = { obfuscated: 'obfuscated', reverse_shell: 'reverse_shell', credential_access: 'credential_access', persistence: 'persistence', download_exec: 'download_exec', insecure_tls: 'insecure_tls', crypto_mining: 'crypto_mining', destructive: 'destructive', exfiltration: 'exfiltration', runtime_install: 'runtime_install', remote_fetch: 'remote_fetch', privilege: 'privilege', shell_inline: 'shell_exec' };
const CODE_RULE = new Set(['obfuscated', 'reverse_shell', 'credential_access', 'persistence', 'download_exec', 'insecure_tls', 'crypto_mining', 'destructive', 'exfiltration']);
const SIGNAL_RULE = { reverse_shell: 'reverse_shell', crypto_mining: 'crypto_mining', download_exec: 'download_exec', fetch: 'remote_fetch', runtime_install: 'runtime_install', shell_inline: 'shell_exec', obfuscated_inline: 'obfuscated', credential_access: 'credential_access', persistence: 'persistence', destructive: 'destructive', privilege: 'privilege', native_build: 'native_build' };
const TYPED_SRC = /\.(?:pyi?|tsx?|dart|kt|swift|cs|java|rs|go)$/i;
const ANNOTATION = /^\s*(?:\*\s*)?[A-Za-z_]\w*\s*:\s*(?:[A-Za-z_][\w.]*(?:\[[^\]'"=]*\])?(?:\s*\|\s*[A-Za-z_][\w.]*(?:\[[^\]'"=]*\])?)*)\??\s*[,;)=]?\s*(?:#.*|\/\/.*)?$/;
const NATIVE_HOOKS = new Set(['cgo', 'node-gyp', 'native-build', 'analyzer', 'proc-macro']);
const LEGIT_PTH = /(?:-nspkg\.pth|distutils-precedence\.pth|^_virtualenv\.pth|easy-install\.pth|^__editable__[^/]*\.pth)$/;

const ARCHIVE_PROBLEM_RULE = { path_traversal: 'package.archive.path_traversal', symlink_escape: 'package.archive.symlink_escape', special_file: 'package.archive.special_file', setuid: 'package.archive.setuid', world_writable: 'package.archive.world_writable', duplicate_entry: 'package.archive.duplicate_entry' };

function openArtifact(pkg, artifact, notes) {
  let opened;
  if (pkg.ecosystem === 'gem') { const g = openGem(artifact.buf); opened = { artifact, archive: g.archive, gem: g }; }
  else opened = { artifact, archive: openArchive(artifact.buf) };
  return opened;
}

/**
 * @param {object} pkg  result of fetchPackage() (or the same shape for a local file): {ecosystem, name, version, registry, artifacts[], meta, notes}
 * @param {object} [opts] {maxTextKb, maxBinaryMb, maxBinaries, log}
 */
export async function analyzePackage(pkg, opts = {}) {
  const o = { ...DEFAULTS, ...opts };
  const log = o.log || (() => {});
  const eco = ECOSYSTEMS[pkg.ecosystem];
  const appName = `${pkg.name}@${pkg.version}`;
  const findings = new Findings();
  const notes = new Notes();
  const base = { app: appName };
  const add = (rule, f) => findings.add(rule, { ...base, ...f });
  for (const n of pkg.notes || []) notes.push(n);

  // ── 1. open the archives, verify digests ───────────────────────────────────────────────────────────────────────────────────────
  const opened = [];
  for (const a of pkg.artifacts) {
    try { opened.push(openArtifact(pkg, a, notes)); }
    catch (e) { gap(notes, `${a.filename}: the archive could not be read (${e.message}); it was not analysed.`); }
  }
  if (!opened.length) throw new ArchiveError('no archive of this package could be read');
  if (pkg.ecosystem === 'go' && opened[0]) {
    const files = opened[0].archive.files.map(f => ({ ...f, rawPath: f.rawPath }));
    try { await verifyGoSum(pkg, opened[0].artifact, files.filter(f => f.type === 'file')); } catch (e) { notes.push(`Go checksum verification failed to run: ${e.message}`); }
  }
  for (const { artifact } of opened) {
    const i = artifact.integrity || { state: 'unverified' };
    if (i.state === 'mismatch') add('package.integrity.mismatch', { artifact: artifact.filename, key: `mismatch:${artifact.filename}`, description: `The ${i.algo} digest of ${artifact.filename} is ${i.actual}, but ${i.source || 'the registry'} published ${i.expected}. The bytes that were downloaded are not the bytes the registry says it holds for this release.`, evidence: [`expected ${i.algo}: ${i.expected}`, `actual   ${i.algo}: ${i.actual}`, `url: ${artifact.url}`] });
    else if (i.state === 'unverified' && !opts.local) add('package.integrity.unverified', { artifact: artifact.filename, key: `unverified:${artifact.filename}`, description: `${eco.label} published no digest for ${artifact.filename} that this tool can check${pkg.ecosystem === 'go' ? ' (the Go checksum database could not confirm the module)' : ''}, so the download was not verified. sha256: ${artifact.sha256}.`, evidence: [`sha256: ${artifact.sha256}`] });
  }
  const worst = ['mismatch', 'unverified', 'verified'].find(s => pkg.artifacts.some(a => (a.integrity?.state || 'unverified') === s)) || 'unverified';
  const integrityInfo = (pkg.artifacts.find(a => a.integrity?.state === worst)?.integrity) || { state: worst };

  // ── 2. archive-level problems ──────────────────────────────────────────────────────────────────────────────────────────────────
  const archiveProblems = [];
  for (const { artifact, archive } of opened) {
    const by = new Map();
    for (const p of archive.problems) { (by.get(p.kind) || by.set(p.kind, []).get(p.kind)).push(p); archiveProblems.push({ ...p, artifact: artifact.filename }); }
    for (const [kind, list] of by) {
      const rule = ARCHIVE_PROBLEM_RULE[kind];
      if (!rule) continue;
      add(rule, { artifact: artifact.filename, key: `${kind}:${artifact.filename}`, description: `${list.length} entr${list.length === 1 ? 'y' : 'ies'} of ${artifact.filename}: ${list[0].detail}.`, evidence: sample(list, 15).map(p => `${p.path} — ${p.detail}`), evidence_total: list.length });
    }
  }

  // ── 3. registry metadata ───────────────────────────────────────────────────────────────────────────────────────────────────────
  const m = pkg.meta || {};
  if (m.yanked) add('package.metadata.yanked', { artifact: appName, key: 'yanked', description: `${eco.label} marks ${appName} as ${pkg.ecosystem === 'cargo' ? 'yanked' : pkg.ecosystem === 'pub' ? 'retracted' : 'yanked / withdrawn'}${m.yanked_reason ? `: ${m.yanked_reason}` : ''}.`, evidence: m.yanked_reason ? [m.yanked_reason] : [] });
  if (m.deprecated) add('package.metadata.deprecated', { artifact: appName, key: 'deprecated', description: `The registry flags this ${pkg.ecosystem === 'npm' ? 'version' : 'package'} as deprecated: ${m.deprecated}.`, evidence: [String(m.deprecated).slice(0, 300)] });
  if (m.abandoned) add('package.metadata.deprecated', { artifact: appName, key: 'abandoned', description: `Packagist marks the package as ${m.abandoned}.`, evidence: [String(m.abandoned)] });
  if (m.unlisted) notes.push(`${appName} is unlisted on the registry (hidden from search, still installable).`);

  // ── 4. manifests: deps, hooks, bundled, issues ─────────────────────────────────────────────────────────────────────────────────
  const man = analyzeManifests(pkg.ecosystem, opened, pkg);
  const fx = man.files;
  for (const iss of man.issues) add(iss.rule, { artifact: iss.file || appName, key: `${iss.rule}:${iss.key}`, description: `${iss.detail}.`, evidence: [iss.detail] });
  const installPaths = new Map(man.installFiles.map(f => [f.path, f]));
  const vendoredPaths = [...man.bundled, ...(man.bundledUnversioned || [])].flatMap(b => (b.paths || [b.path]).filter(Boolean).map(pa => [`${pa.replace(/\/+$/, '')}/`, `${b.name}${b.version ? `@${b.version}` : ''}`])).sort((a, b) => b[0].length - a[0].length);
  for (const n of man.notes || []) notes.push(n);

  // hooks: one finding per hook that reaches a consumer; the command line of npm lifecycle scripts is read for what it does
  const hooks = [];
  const installs = [];
  for (const h of man.hooks) {
    const hook = { ...h, signals: [] };
    const reaches = h.consumer === true || h.consumer === 'conditional';
    const conf = h.consumer === 'conditional' ? 'medium' : 'high';
    if (h.id === 'npm-script' && reaches) {
      const a = analyzeCommand(h.command);
      hook.signals = [...a.signals.keys()];
      hook.urls = a.urls;
      for (const [sig, e] of a.signals) {
        const rule = SIGNAL_RULE[sig];
        if (!rule) continue;
        if (rule === 'native_build') continue;
        if (sig === 'fetch' && a.signals.has('download_exec')) continue;
        add(`package.install.${rule}`, { artifact: 'package.json', key: `hook:${h.phase}:${sig}`, description: `The ${h.phase} script of the package ${e.detail}. It runs on every machine that installs this release (\`${h.command.slice(0, 200)}\`).`, evidence: e.commands.map(c => `${h.phase}: ${c}`), confidence: sig === 'fetch' ? 'low' : conf });
        if (sig === 'runtime_install') installs.push({ hook: `${h.phase}`, command: e.commands[0], what: e.detail });
      }
      if (a.signals.size === 1 && a.signals.has('native_build')) hook.native = true;
    }
    hooks.push(hook);
    if (!reaches) continue;
    const isNative = NATIVE_HOOKS.has(h.id) || hook.native;
    const rule = h.id === 'pth-file' ? 'package.install.pth_file' : isNative ? 'package.install.native_build' : 'package.install.hook';
    const legit = h.id === 'pth-file' && LEGIT_PTH.test(h.file || '');
    add(rule, { artifact: h.file || appName, key: `hook:${h.id}:${h.phase}:${h.command}`, description: `${h.note ? `${h.note}. ` : ''}Hook: ${h.id}, phase ${h.phase}, runs when ${h.trigger}${h.command ? ` (${h.command.slice(0, 200)})` : ''}.`, evidence: [`${h.id}/${h.phase}: ${String(h.command).slice(0, 200)}`], confidence: legit ? 'low' : conf });
  }

  // ── 5. walk every file ─────────────────────────────────────────────────────────────────────────────────────────────────────────
  const appScanner = new SecretScanner(findings, { ...base, origin: 'app' });
  const libScanner = new SecretScanner(findings, { ...base, origin: 'library' }, { maxLines: 150000 });
  const behavior = new BehaviorBuilder();
  const hosts = new RemoteHostCollector();
  const installHosts = new Set(), installNet = new Set(); // installNet: where-labels of install-time files whose code has network capability
  const natives = [], nativeApps = [], nativeRecords = [], interest = [], compiled = [];
  const seenSha = new Map(), seenPath = new Map();
  const maxText = o.maxTextKb * 1024;
  let bytesRead = 0, fileCount = 0, unpacked = 0, skippedBig = 0, filesAnalysed = 0, binScanned = 0;
  const installSeen = new Set();
  const pyStems = new Set(), javaStems = new Set();
  for (const { archive } of opened) for (const f of archive.files) { if (f.type !== 'file') continue; if (/\.py$/i.test(f.path)) pyStems.add(f.path.replace(/\.py$/i, '')); if (/\.(?:java|kt|scala)$/i.test(f.path)) javaStems.add(f.path.replace(/\.[a-z]+$/i, '')); }
  const multi = opened.length > 1;
  let readBudgetNoted = false;

  for (const { artifact, archive } of opened) {
    for (const f of archive.files) {
      if (f.type !== 'file') continue;
      fileCount++; unpacked += f.size;
      if (f.size === 0) continue;
      const isInstall = installPaths.has(f.path);
      const role = fileRole(f.path, vendoredPaths);
      const textCap = isInstall ? Math.max(maxText, 8 * MB) : maxText;
      const wanted = f.size <= o.maxBinaryMb * MB ? f.size : 0;
      let buf = null;
      if (bytesRead + Math.min(f.size, wanted || 8192) > o.maxTotalReadMb * MB) {
        if (!readBudgetNoted) { gap(notes, `The read budget of ${o.maxTotalReadMb} MB was used up; the remaining files of the archive were not analysed.`); readBudgetNoted = true; }
        continue;
      }
      try { buf = f.read(Math.max(f.size, 1) + 1024); } catch (e) { gap(notes, `${f.path}: could not be read (${e.message}).`); continue; }
      bytesRead += buf.length;
      const head = buf.subarray(0, 8192);
      const kind = classifyHead(f.path, head);
      const digest = sha256(buf);
      const prior = seenPath.get(f.path);
      if (prior === digest) continue;                                           // the same file in the sdist and the wheel
      seenPath.set(f.path, digest);
      const label = prior && multi ? `${artifact.filename}!/${f.path}` : f.path;
      filesAnalysed++;

      // — native executables and libraries
      if (['elf', 'macho', 'pe'].includes(kind)) {
        const entry = { path: label, format: kind, size: buf.length, sha256: digest, scanned: false, skipped: null, arch: null, role: role.role };
        natives.push(entry);
        if (isDisguised(f.path, kind)) {
          interest.push({ kind: 'disguised native binary', path: label, detail: `a ${kind.toUpperCase()} executable named like a non-binary file` });
          add('package.files.disguised_binary', { artifact: label, key: label, description: `${label} is a ${kind === 'pe' ? 'Windows PE' : kind === 'elf' ? 'Linux ELF' : 'Mach-O'} executable, but its name (${f.path.split('/').pop()}) says it is not.`, evidence: [`magic bytes: ${kind}`, `size: ${buf.length} bytes`, `sha256: ${digest}`] });
        }
        if (seenSha.has(digest)) { entry.skipped = `same file as ${seenSha.get(digest)}`; continue; }
        seenSha.set(digest, label);
        if (buf.length > o.maxBinaryMb * MB) { entry.skipped = 'over the size limit'; gap(notes, `${label}: ${Math.round(buf.length / MB)} MB native file is over the ${o.maxBinaryMb} MB limit (--max-binary-mb); it was not analysed.`); continue; }
        if (binScanned >= o.maxBinaries) { entry.skipped = 'over the file-count limit'; if (binScanned === o.maxBinaries) gap(notes, `More than ${o.maxBinaries} distinct native files; the rest were listed but not analysed (--max-binaries).`); binScanned++; continue; }
        binScanned++;
        try {
          const r = scanBinaryBuffer(buf, label);
          entry.scanned = true; entry.arch = r.apps[0].arch || null;
          for (const bf of r.findings.list) { if (!findings._seen.has(bf.fingerprint)) { findings._seen.add(bf.fingerprint); findings.list.push({ ...bf, ...(role.role !== 'code' ? { origin: 'library' } : {}) }); } }
          const bapp = r.apps[0];
          bapp.in_package = true; bapp.package_path = label;
          nativeApps.push(bapp);
          for (const rec of r.dependencies) nativeRecords.push({ ...rec, sources: (rec.sources || []).map(s => `${label}: ${s}`), role: 'native' });
          for (const n of r.notes) { if (/^Scope: /.test(n)) continue; if (r.notes.gaps?.includes(n)) gap(notes, n); else notes.push(n); }
        } catch (e) { entry.skipped = `not readable: ${e.message}`; gap(notes, `${label}: native file not analysed (${e.message}).`); }
        continue;
      }
      if (kind === 'wasm') { interest.push({ kind: 'WebAssembly module', path: label, detail: `${buf.length} bytes; not analysed` }); continue; }
      if (kind === 'pyc' || kind === 'class') {
        let stem;
        if (kind === 'pyc') stem = f.path.includes('__pycache__/') ? f.path.replace(/__pycache__\/([^/.]+)\..*$/, '$1') : f.path.replace(/\.pyc$/i, '');
        else stem = f.path.replace(/\.class$/i, '').replace(/\$.*$/, '');
        if (!(kind === 'pyc' ? pyStems : javaStems).has(stem)) compiled.push(label);
        continue;
      }
      if (['zip', 'gzip', 'tar', 'xz', 'bzip2', 'zstd', '7z', 'rar'].includes(kind)) {
        const expected = /\.(?:gz|tgz|zip|jar|whl|nupkg|egg|xz|bz2|zst|7z|rar|tar)$/i.test(f.path) && (role.role === 'test' || role.role === 'docs');
        if (!expected && !(kind === 'gzip' && !/\.t(?:ar\.)?gz$/i.test(f.path)) && !(kind === 'zip' && /\.(?:jar|docx|xlsx|pptx|odt|epub|apk|aar|war|nupkg|whl)$/i.test(f.path) && role.role !== 'code')) interest.push({ kind: 'nested archive', path: label, detail: `${kind} archive, ${buf.length} bytes (not unpacked)`, role: role.role });
        continue;
      }
      if (kind === 'binary' || kind === 'image' || kind === 'pdf') continue;

      // — sensitive names and tool configuration
      const why = sensitiveName(f.path);
      if (why && role.role !== 'docs') { interest.push({ kind: 'sensitive file', path: label, detail: why }); add('package.files.sensitive', { artifact: label, key: label, description: `${label}: ${why}.`, evidence: [`${buf.length} bytes`], origin: role.role === 'code' ? 'app' : 'library' }); }
      if (isToolConfig(f.path) && role.role !== 'docs' && role.role !== 'vendored' && !man.issues.some(i => i.rule === 'package.config.tool_config' && i.key === f.path)) { interest.push({ kind: 'tool configuration', path: label, detail: 'configures the package manager / build tool' }); add('package.config.tool_config', { artifact: label, key: label, description: `${label} configures a package manager or build tool and is shipped inside the package.`, evidence: [`${buf.length} bytes`] }); }

      // — text
      if (buf.length > textCap) { skippedBig++; if (isInstall) gap(notes, `${label}: install-time file of ${Math.round(buf.length / 1024)} KB is over the ${Math.round(textCap / 1024)} KB text limit and was not analysed.`); continue; }
      const text = buf.toString('utf8');
      const lines = text.split(/\r?\n/);
      const lockfile = isLockfile(f.path);
      // a type annotation (`private_key: CertificateIssuerPrivateKeyTypes,`) is not a key-value credential: blank those lines in typed source files (line numbers stay)
      const scanLines = TYPED_SRC.test(f.path) ? lines.map(l => (ANNOTATION.test(l) ? '' : l)) : lines;
      if (!lockfile) (role.role === 'code' ? appScanner : libScanner).add(label, scanLines);
      const lang = detectLang(f.path, text.slice(0, 200));
      const originName = isInstall ? 'install-time code' : role.role === 'vendored' ? `bundled: ${role.owner}` : role.role === 'test' || role.role === 'docs' ? 'tests / examples / docs' : 'package code';
      if (isInstall) installSeen.add(f.path);
      const where = isInstall ? `install-time: ${label}` : role.role === 'vendored' ? `bundled: ${role.owner}` : label;
      if (hostSearchable(f.path) && role.role !== 'docs' && role.role !== 'test') {
        hosts.addStrings(lines, where, { bare: 'ip-port' });
        if (isInstall) { const tmp = new RemoteHostCollector(); tmp.addStrings(lines, where, { bare: 'ip-port' }); for (const h of tmp.map.keys()) installHosts.add(h); }
      }
      if (!lang || /\.nuspec$/i.test(f.path)) continue;
      const r = lang === 'msbuild' ? analyzeMsbuild(text) : analyzeSource(text, lang);
      for (const b of r.behaviors.values()) behavior.add(b.cat, b.label, originName, 'source', b.count, 'refs');
      if (isInstall && [...r.behaviors.values()].some(b => b.cat === 'network')) installNet.add(where);
      const fileOrigin = role.role === 'code' ? 'app' : 'library';
      for (const rk of r.risks) {
        const ruleSuffix = isInstall ? INSTALL_RULE[rk.id] : CODE_RULE.has(rk.id) ? rk.id : null;
        if (!ruleSuffix) continue;
        const rule = `package.${isInstall ? 'install' : 'code'}.${ruleSuffix}`;
        const ctxText = isInstall ? ` This file runs on the consumer's machine: ${installPaths.get(f.path).reason}.` : role.role === 'vendored' ? ` The file is a bundled copy of ${role.owner}.` : role.role === 'test' ? ' The file is a test / example file.' : '';
        add(rule, { artifact: label, line: rk.line || undefined, key: `${rule}|${label}|${rk.label}|${rk.line}`, description: `${rk.label}${rk.line ? ` (line ${rk.line})` : ''}.${ctxText}`, evidence: [rk.snippet], confidence: rk.confidence, origin: fileOrigin });
      }
    }
  }
  if (appScanner.truncated || libScanner.truncated) gap(notes, 'More text than the secret scanner\'s line budget; the rest of the package was not scanned for secrets.');
  appScanner.run(); libScanner.run();
  if (skippedBig) notes.push(`${skippedBig} text file(s) larger than ${o.maxTextKb} KB were not read for source behavior or secrets (--max-text-kb).`);
  for (const p of installPaths.keys()) if (!installSeen.has(p) && !natives.some(n => n.path === p)) notes.push(`Install-time file ${p} (${installPaths.get(p).reason}) is not in the archive or could not be read as text.`);
  if (compiled.length) { interest.push(...sample(compiled, 20).map(p => ({ kind: 'compiled code without source', path: p, detail: 'bytecode with no matching source in the archive' }))); add('package.files.compiled_code', { artifact: appName, key: 'compiled', description: `${compiled.length} compiled bytecode file(s) have no source file next to them in the archive, so they cannot be reviewed.`, evidence: sample(compiled, 15), evidence_total: compiled.length }); }
  const nested = interest.filter(x => x.kind === 'nested archive' && x.role !== 'test' && x.role !== 'docs');
  if (nested.length) add('package.files.nested_archive', { artifact: appName, key: 'nested', description: `${nested.length} archive file(s) are shipped inside the package.`, evidence: sample(nested, 15).map(x => `${x.path} — ${x.detail}`), evidence_total: nested.length });
  const realNatives = natives.filter(n => n.role === 'code' || n.role === 'vendored');
  if (realNatives.length) add('package.files.native_binary', { artifact: appName, key: 'native', description: `${realNatives.length} native executable / library file(s) ship inside the package. They were analysed like ubel-binary does where possible.`, evidence: sample(realNatives, 20).map(n => `${n.path} (${n.format}${n.arch ? `, ${n.arch}` : ''}, ${Math.round(n.size / 1024)} KB)`), evidence_total: realNatives.length });

  // ── 6. remote hosts ────────────────────────────────────────────────────────────────────────────────────────────────────────────
  for (const h of man.hooks) if ((h.consumer === true || h.consumer === 'conditional') && h.command && h.id === 'npm-script') {
    const a = analyzeCommand(h.command);
    for (const u of a.urls) { installNet.add(`install-time: ${h.id} ${h.phase}`); hosts.addText(u, `install-time: ${h.id} ${h.phase}`, { bare: 'none' }); const t = new RemoteHostCollector(); t.addText(u, 'x', { bare: 'none' }); for (const k of t.map.keys()) installHosts.add(k); }
  }
  let remote = hosts.summary();
  if (remote) {
    for (const h of remote.hosts) {
      const flags = hostFlags(h.host, h.type);
      if (h.type !== 'domain' && !h.private) flags.push('public_ip');
      if (h.cleartext) flags.push('cleartext');
      const inst = installHosts.has(h.host) || h.seen_in.some(s => /^install-time:/.test(s));
      if (inst) flags.push('install_time');
      h.flags = [...new Set(flags)];
    }
    remote.flagged = remote.hosts.filter(h => h.flags.length).length;
    for (const h of remote.hosts) {
      const f = h.flags;
      const exfil = f.some(x => EXFIL_FLAGS.has(x)) && (f.includes('chat_webhook') ? h.examples.some(e => /webhooks?\/|\/bot\d+:|hooks\.slack\.com\/services/i.test(e)) : true);
      const where = h.seen_in.slice(0, 4).join(', ');
      const hard = exfil || f.includes('public_ip') || f.includes('raw_code_host') || f.includes('url_shortener');
      // a host named in an install-time file is only a finding when it is a kind of host that matters, or the file can actually reach the network (a project URL in setup.py metadata or a doc comment is not a fetch)
      const netBacked = h.seen_in.some(x => installNet.has(x));
      if (f.includes('install_time') && !h.private && (hard || netBacked)) {
        add('package.install.remote_fetch', { artifact: h.seen_in.find(s => /^install-time:/.test(s))?.replace(/^install-time: /, '') || appName, key: `host:${h.host}`, description: `Code that runs at install / build time refers to ${h.host}${f.filter(x => x !== 'install_time').length ? ` (${f.filter(x => x !== 'install_time').join(', ').replace(/_/g, ' ')})` : ''}.`, evidence: [...h.examples, `seen in: ${where}`], severity: hard ? 'high' : undefined, confidence: hard ? 'high' : 'low' });
      } else if (exfil && !h.seen_in.every(s => /^bundled:/.test(s))) {
        add('package.code.exfiltration', { artifact: h.seen_in[0] || appName, key: `host:${h.host}`, description: `The package's code refers to ${h.host} (${f.filter(x => EXFIL_FLAGS.has(x)).join(', ').replace(/_/g, ' ')}), a kind of host that is used to receive stolen data or to relay access.`, evidence: [...h.examples, `seen in: ${where}`], severity: 'medium', confidence: 'low', confidenceCap: false });
      }
    }
  }

  // ── 7. dependencies: pin classes, advisories-to-be, bundled ─────────────────────────────────────────────────────────────────────
  const records = [];
  const ecoLabel = eco.label;
  const selfPurl = packagePurl(pkg.ecosystem, pkg.name, pkg.version);
  if (selfPurl) records.push({ ...purlRecord({ name: pkg.name, version: pkg.version, ecosystem: ecoLabel, purl: selfPurl, source: `${ecoLabel} release under analysis`, sourceType: 'package under analysis', confidence: 'high' }), role: 'package' });
  const pins = {};
  const installed = man.deps.filter(d => d.installed);
  for (const d of installed) pins[d.pin] = (pins[d.pin] || 0) + 1;
  for (const d of man.deps) {
    if (!d.installed) continue;
    const purl = (d.pin === 'exact' || d.pin === 'floor') && d.version ? packagePurl(pkg.ecosystem, d.alias || d.name, d.version) : null;
    if (purl) records.push({ ...purlRecord({ name: d.alias || d.name, version: d.version, ecosystem: ecoLabel, purl, source: `${d.file}: ${d.name} ${d.spec}`.trim(), sourceType: 'declared dependency', confidence: 'high' }), role: 'dependency' });
    else records.push({ ...inventoryRecord({ name: d.name, ecosystem: ecoLabel, source: `${d.file}: ${d.name} ${d.spec}`.trim(), sourceType: 'declared dependency', reason: d.pin === 'non_registry' ? `Installed from ${d.source}, not from the registry; the registry's advisories do not cover it.` : `Declared as ${d.pin === 'open' ? 'an unbounded requirement' : 'a version range'} (${d.spec || 'any version'}); the installed version is chosen at install time, so it cannot be looked up from the package alone.` }), role: 'dependency' });
  }
  for (const b of man.bundled) {
    const purl = packagePurl(pkg.ecosystem, b.name, b.version);
    if (purl) records.push({ ...purlRecord({ name: b.name, version: b.version, ecosystem: ecoLabel, purl, source: `bundled copy in ${b.path}`, sourceType: 'bundled dependency', confidence: 'high' }), role: 'bundled' });
  }
  // lockfile entries shipped inside the archive: they pin what the publisher's own tests used. A consumer's installer ignores them, so they are
  // looked up (a vulnerable pin in a published lockfile is still a signal) but kept apart from the declared dependencies.
  const lockSeen = new Set();
  for (const l of (man.locked || []).slice(0, 5000)) {
    if (!l.version || l.source !== 'registry') continue;
    const k = `${String(l.name).toLowerCase()}@${l.version}`;
    if (lockSeen.has(k)) continue;
    lockSeen.add(k);
    const purl = packagePurl(pkg.ecosystem, l.name, l.version);
    if (purl) records.push({ ...purlRecord({ name: l.name, version: l.version, ecosystem: ecoLabel, purl, source: `${l.file}: ${l.name} ${l.version}`, sourceType: 'lockfile entry', confidence: 'high' }), role: 'locked' });
  }
  if ((man.locked || []).length > 5000) gap(notes, `${man.locked.length} lockfile entries are shipped; only the first 5000 were looked up.`);
  records.push(...nativeRecords);
  if (man.bundledUnversioned?.length) notes.push(`${man.bundledUnversioned.length} vendored copy(ies) have no version that can be read from the archive (${man.bundledUnversioned.slice(0, 6).map(u => u.name || u).join(', ')}); they are listed but not looked up in the advisory databases.`);

  const depFinding = (rule, deps, text, extra = {}) => { if (deps.length) add(rule, { artifact: appName, key: `${rule}:${extra.k || ''}`, description: text, evidence: sample(deps.map(d => `${d.name}: ${d.spec || 'any'} (${d.kind}${d.detail ? `; ${d.detail}` : ''})`), 20), evidence_total: deps.length, ...extra.f }); };
  const runtimeish = installed.filter(d => ['runtime', 'optional', 'build', 'peer'].includes(d.kind));
  depFinding('package.dep.unpinned', runtimeish.filter(d => d.pin === 'open'), `${runtimeish.filter(d => d.pin === 'open').length} installed dependenc${runtimeish.filter(d => d.pin === 'open').length === 1 ? 'y has' : 'ies have'} no upper version bound, so whatever is newest on the registry at install time is installed.`);
  depFinding('package.dep.non_registry', installed.filter(d => d.pin === 'non_registry' && d.immutable !== true && d.source !== 'sdk' && !(pkg.ecosystem === 'go' && d.source === 'replace')), 'Dependencies are fetched from a git repository, URL or path instead of the registry, with a reference that can change (branch, tag, plain URL, local path).');
  depFinding('package.dep.range', runtimeish.filter(d => d.pin === 'range'), `${runtimeish.filter(d => d.pin === 'range').length} installed dependenc${runtimeish.filter(d => d.pin === 'range').length === 1 ? 'y is' : 'ies are'} declared as version ranges; a new release inside the range changes what is installed.`);
  if (man.bundled.length) add('package.dep.bundled', { artifact: appName, key: 'bundled', description: `${man.bundled.length} dependenc${man.bundled.length === 1 ? 'y is' : 'ies are'} shipped inside the archive. They are checked against advisories at the version found in the archive.`, evidence: sample(man.bundled.map(b => `${b.name}@${b.version} (${b.path})${b.source ? ` — ${b.source}` : b.declaredBundled ? '' : ' — not declared as bundled'}${b.scripts?.length ? ` — has ${b.scripts.join(' / ')} script` : ''}`), 20), evidence_total: man.bundled.length });
  if (pkg.ecosystem === 'npm' && man.hooks.some(h => h.consumer === true) && installed.some(d => d.kind === 'optional') && installed.filter(d => d.kind === 'optional').length > 4) notes.push('Platform-specific optional dependencies (prebuilt binaries) are listed but were not downloaded; run ubel-package on one of them to analyse its binary.');
  notes.push('Dependencies are listed with their pin class and looked up by exact version; they were not downloaded or analysed. Run ubel-package on any of them for the same analysis.');
  if (m.other_artifacts > 0) notes.push(`${m.other_artifacts} further file(s) of this release (other wheels / platforms) were not downloaded; use --artifact all and --max-wheels to analyse more.`);

  // ── 8. the app record ──────────────────────────────────────────────────────────────────────────────────────────────────────────
  const beh = behavior.summary();
  const app = {
    platform: 'package', ecosystem: pkg.ecosystem, ecosystem_label: ecoLabel, name: pkg.name, version: pkg.version, registry: pkg.registry, size_bytes: pkg.artifacts.reduce((n, a) => n + a.size, 0),
    ...(beh ? { behavior: beh } : {}), ...(remote ? { remote_hosts: remote } : {}),
    package: {
      info: man.info, artifacts: pkg.artifacts.map(a => ({ filename: a.filename, kind: a.kind, url: a.url, size: a.size, sha256: a.sha256, integrity: a.integrity })), integrity: integrityInfo,
      hooks: hooks.map(h => ({ id: h.id, phase: h.phase, trigger: h.trigger, command: String(h.command ?? '').slice(0, 500), file: h.file, consumer: h.consumer, note: h.note, signals: h.signals, runs_files: h.runsFiles })),
      dependencies: man.deps.map(d => ({ name: d.name, spec: d.spec, kind: d.kind, pin: d.pin, version: d.version, source: d.source, immutable: d.immutable, detail: d.detail, installed: d.installed, file: d.file })),
      dependency_total: man.deps.length, pin_summary: pins, bundled: man.bundled, bundled_unversioned: man.bundledUnversioned || [], install_installs: installs,
      lockfiles: man.lockfiles || [], locked_total: (man.locked || []).length, locked_sample: (man.locked || []).slice(0, 300).map(l => ({ name: l.name, version: l.version, source: l.source, group: l.group, hashes: l.hashes, file: l.file })), requirements_files: man.requirementsFiles || [], manifest_files: man.manifestFiles || [],
      native_files: natives.map(n => ({ path: n.path, format: n.format, arch: n.arch, size: n.size, scanned: n.scanned, skipped: n.skipped })), files_of_interest: interest.slice(0, 200).map(({ role: _r, ...x }) => x),
      archive_problems: archiveProblems.slice(0, 100), file_count: fileCount, unpacked_bytes: unpacked,
      published_at: m.published_at || null, publisher: m.published_by || null, maintainers: m.maintainers || [], yanked: Boolean(m.yanked), yanked_reason: m.yanked_reason || null, deprecated: m.deprecated || null,
      provenance: m.provenance ?? null, signatures: m.signatures ?? null, license: man.info.license ?? m.license ?? null,
    },
  };
  if (!app.package.info.license && m.license) app.package.info.license = m.license;
  if (!app.package.info.repository && m.repository) app.package.info.repository = m.repository;
  if (!app.package.info.homepage && m.homepage) app.package.info.homepage = m.homepage;
  notes.push('Scope: install / build / import-time hooks, source behavior, remote hosts, secrets, dependencies and their pinning, bundled components, native binaries and archive integrity. The package was never installed, built or run; a pattern match shows the code refers to something, not that it is reachable.');

  const sha = pkg.artifacts[0].sha256;
  return {
    findings, apps: [app, ...nativeApps], dependencies: records, dependencySummary: null, notes,
    target: { file: appName, kind: pkg.ecosystem, size_bytes: app.size_bytes, sha256: sha, registry: pkg.registry },
    appName, stats: { files: fileCount, analysed: filesAnalysed, hooks: hooks.length },
  };
}

/** Looks up the advisories of the collected components and files them under the package rules. */
export async function resolveAdvisories(scan, { log = () => {} } = {}) {
  const result = await scanBinaryDependencies(scan.dependencies || [], { log });
  scan.dependencies = result.dependencies;
  scan.dependencySummary = result.summary;
  if (result.lookup_error) gap(scan.notes, `Advisory lookup was incomplete: ${result.lookup_error}`);
  if (result.summary.lookup_errors) gap(scan.notes, `${result.summary.lookup_errors} component(s) could not be fully checked against OSV.dev / NVD; see the Dependencies tab.`);
  return fileAdvisories(scan);
}

/** Turns the advisories already attached to scan.dependencies into findings (split from the lookup so it can be tested without the network). */
export function fileAdvisories(scan) {
  const role = dep => dep.role || (dep.cpe ? 'native' : 'dependency');
  const added = addAdvisoryFindings(scan.findings, scan.dependencies, {
    app: scan.appName,
    ruleFor: (dep, v) => {
      const r = role(dep);
      if (r === 'native') return 'binary.component.vulnerable';
      if (r === 'package') return v.is_infection ? 'package.malicious' : 'package.vulnerable';
      if (r === 'locked') return v.is_infection ? 'package.dep.malicious' : 'package.dep.vulnerable';
      return v.is_infection ? 'package.dep.malicious' : 'package.dep.vulnerable';
    },
    describe: (dep, v, text) => {
      const r = role(dep);
      if (r === 'native') return null;
      const where = r === 'package' ? 'this package' : r === 'bundled' ? 'a copy bundled in this package' : r === 'locked' ? 'a lockfile shipped in this package (the publisher\'s pin; a consumer\'s installer does not use it)' : 'a dependency of this package';
      const out = { description: `${text} ${r === 'package' ? 'The advisory applies to the exact version that was analysed.' : `The affected version is ${dep.version}, found in ${where}.`}` };
      if (r === 'locked' && !v.is_infection) out.severity = 'low';                // a pin in a shipped lockfile / dev requirements list is not installed by consumers
      if (v.is_infection) { out.severity = 'critical'; out.title = `${dep.name} ${dep.version} is a known malicious package (${v.id})`; }
      return out;
    },
  });
  return added;
}
