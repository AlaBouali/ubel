'use strict';
// frameworks.js — cross-platform framework analysis. A Flutter, React Native, Unity or Xamarin app keeps almost all of its logic (and
// its hardcoded secrets) outside DEX / Mach-O, in framework-specific containers that a generic string scan reads badly or not at all:
//   React Native   JS bundle: plain JS, or Hermes bytecode whose string table is read through its own index (hermes.js)
//   Flutter        Dart AOT snapshot in libapp.so / App.framework, plus flutter_assets (debug JIT snapshots are flagged)
//   Unity          IL2CPP global-metadata.dat (exact C# literals), Mono assemblies, boot.config, serialized .assets / scene files,
//                  and UnityFS asset bundles (LZ4 / uncompressed; LZMA-compressed ones are reported as not inspected)
//   Xamarin/.NET   managed assemblies — plain, XALZ/LZ4-compressed, or packed in an assembly store — read through their #US literal heap
// analyzeFrameworks() adds findings and secret-scan input, and returns which package entries it consumed so the generic file walk
// does not scan them again (compressed assemblies, for instance, are noise to a string scan).

import { asciiStrings, utf16Strings, isLikelyBinary } from './strings.js';
import { isHermes, parseHermes } from './hermes.js';
import { parseDotnet, assemblyBytes, isXalz, readAssemblyStore, parseAssemblyManifest, lz4Block } from './dotnet.js';
import { isIl2cppMetadata, parseIl2cppMetadata } from './il2cpp.js';
import { gap } from './coverage.js';

const MB = 1024 * 1024;
const IOS_APP = '^Payload\\/[^/]+\\.app\\/';

// Assemblies of the platform / SDK / well-known libraries: they define the APIs the app calls, they do not hold the app's secrets.
const FRAMEWORK_ASSEMBLY = /^(System(\.|$)|mscorlib|netstandard|Mono\.|Java\.Interop|Microsoft\.(Maui|Extensions|CSharp|Win32|NETCore|Bcl|iOS|Android|AspNetCore)|Xamarin\.(AndroidX|Google|Kotlin|Forms|Essentials|iOS|Android|Firebase)|UnityEngine|Unity\.|Newtonsoft|I18N|Boo\.|UnityScript|WindowsBase|Accessibility|Windows\.|SkiaSharp|SQLitePCL|Mono\.Android|GoogleGson)/i;
const TLS_BYPASS_STRONG = ['DangerousAcceptAnyServerCertificateValidator'];
const TLS_BYPASS_WEAK = ['ServerCertificateValidationCallback', 'ServerCertificateCustomValidationCallback'];
const SECRET_KEY_LITERAL = /^(access[_-]?token|refresh[_-]?token|auth[_-]?token|id[_-]?token|session[_-]?token|jwt|password|passwd|user[_-]?password|api[_-]?key|secret|client[_-]?secret|private[_-]?key)$/i;
const SECURE_STORE = /(react-native-keychain|expo-secure-store|SecureStore|react-native-sensitive-info|react-native-encrypted-storage|EncryptedStorage|RNKeychain|react-native-mmkv)/;

const esc = s => String(s).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"');
const base = p => p.slice(p.lastIndexOf('/') + 1);

/** Pulls `key: "value"` pairs and bare string literals out of (possibly minified, single-line) JavaScript. */
export function jsLiterals(text, { max = 400000 } = {}) {
  const out = [], seen = new Set();
  const add = s => { if (!seen.has(s) && out.length < max) { seen.add(s); out.push(s); } };
  const pair = /([A-Za-z_$][\w$]{1,40})\s*[:=]\s*(?:"((?:[^"\\\n]|\\.){6,2000})"|'((?:[^'\\\n]|\\.){6,2000})')/g;
  for (let m; (m = pair.exec(text)) && out.length < max;) add(`${m[1]} = "${esc(m[2] ?? m[3])}"`);
  const lit = /"((?:[^"\\\n]|\\.){8,2000})"|'((?:[^'\\\n]|\\.){8,2000})'/g;
  for (let m; (m = lit.exec(text)) && out.length < max;) add(m[1] ?? m[2]);
  return out;
}

export function analyzeFrameworks(zip, ctx) {
  const { platform, findings, base: fbase, scanner, notes, at, addUrl = () => {} } = ctx;
  const handled = new Set();
  const list = [];
  const P = platform === 'ios' ? IOS_APP : '^';
  const find = re => zip.entries.filter(e => !e.isDir && re.test(e.name));
  const read = (e, cap = 128 * MB) => zip.tryRead(e, cap);
  const budget = { left: 600 * MB };
  const take = (e, cap) => { if (e.usize > budget.left) return null; const b = read(e, cap); if (b) budget.left -= b.length; return b; };
  const urls = strs => { for (const s of strs) if (s.length < 400 && /^https?:\/\//i.test(s)) addUrl(s, ''); };
  const add = (rule, f) => findings.add(rule, { ...fbase, ...f });

  // ── React Native ──────────────────────────────────────────────────────────────────────────────
  const rnBundles = find(platform === 'ios' ? new RegExp(`${IOS_APP}[^/]+\\.(jsbundle|bundle|hbc)$`) : /^assets\/([^/]+\.(bundle|jsbundle|hbc)|index\.android\.bundle)$/);
  const rnNative = find(/(^|\/)(libreactnativejni|libhermes|libjsc|libjscexecutor|libreact_featureflags|libfabricjni)\.so$|\/hermes\.framework\/hermes$/);
  if (rnBundles.length || rnNative.length) {
    const rn = { name: 'React Native', engine: rnNative.some(e => /hermes/i.test(e.name)) ? 'Hermes' : (rnNative.some(e => /jsc/i.test(e.name)) ? 'JavaScriptCore' : null), bundles: [] };
    for (const e of rnBundles) {
      handled.add(e.name);
      const data = take(e, 256 * MB);
      if (!data) { gap(notes, `${at(e.name)}: JavaScript bundle could not be read (${e.usize > 256 * MB ? 'over the size limit' : 'encrypted, corrupt or unsupported compression'}).`); continue; }
      let strings = [], kind = 'plain JS', jsText = '';
      if (isHermes(data)) {
        const h = parseHermes(data);
        kind = `Hermes bytecode v${h.version}`; rn.engine = 'Hermes'; rn.bytecode_version = h.version;
        if (h.strings) strings = h.strings;
        else { strings = asciiStrings(data, { min: 6, max: 4000, limit: 500000 }); notes.push(`${at(e.name)}: Hermes bytecode v${h.version} has a string-table layout this scanner does not recognise; printable runs were scanned instead (adjacent strings may be fused).`); }
        scanner.add(at(e.name), strings.filter(s => s.length >= 6).map(esc));
      } else {
        const text = jsText = data.toString('utf8');
        if (isLikelyBinary(data.subarray(0, 4096))) { strings = asciiStrings(data, { min: 8, max: 4000, limit: 500000 }); kind = 'binary'; scanner.add(at(e.name), strings.map(esc)); }
        else {
          strings = jsLiterals(text);
          scanner.add(at(e.name), strings);
          if (/__DEV__\s*=\s*(true|!0)\b/.test(text.slice(0, 200000))) add('rn.dev_bundle', { artifact: at(e.name), description: 'The JavaScript bundle was built with __DEV__ = true (development mode): extra logging, the dev menu and remote debugging hooks are enabled.', evidence: ['__DEV__ = true'] });
          add('rn.plain_bundle', { artifact: at(e.name), description: `The app logic ships as readable JavaScript (${(data.length / MB).toFixed(1)} MB). Compiling to Hermes bytecode is not protection (it decompiles readily), but the source is otherwise open to anyone with the package.`, evidence: [] , key: e.name });
        }
      }
      urls(strings);
      // AsyncStorage keeps values in an unencrypted SQLite/XML store; secret-looking keys written to it are worth a look.
      const hasAsync = strings.some(s => /AsyncStorage|async-storage/.test(s)) || /AsyncStorage|async-storage/.test(jsText);
      if (hasAsync) {
        const keys = [...new Set(strings.filter(s => s.length < 40 && SECRET_KEY_LITERAL.test(s)))].slice(0, 12);
        const secure = strings.some(s => SECURE_STORE.test(s)) || SECURE_STORE.test(jsText);
        const plainCall = kind === 'plain JS' && /AsyncStorage\s*\.\s*(setItem|multiSet)\s*\(\s*["'`][^"'`]*(token|password|secret|jwt|auth|credential)/i.test(jsText);
        if (plainCall || keys.length) add('rn.async_storage_secrets', { artifact: at(e.name), evidence: plainCall ? ['AsyncStorage.setItem(<secret-looking key>, …)', ...keys] : keys,
          description: `The bundle uses AsyncStorage and contains key names that suggest credentials or tokens are stored in it${secure ? ' (a secure-storage library is also present, so it may only be used for part of them)' : ''}. AsyncStorage is not encrypted.`,
          confidence: plainCall && !secure ? 'medium' : 'low', key: e.name });
      }
      rn.bundles.push({ file: e.name, kind, bytes: data.length, strings: strings.length });
    }
    if (rnNative.length && !rnBundles.length) notes.push('React Native runtime found but no JavaScript bundle at the usual locations (assets/index.android.bundle, main.jsbundle): the app may load its bundle from elsewhere or over the air.');
    list.push(rn);
  }

  // ── Flutter ───────────────────────────────────────────────────────────────────────────────────
  const flutterAssets = find(platform === 'ios' ? new RegExp(`${IOS_APP}Frameworks\\/App\\.framework\\/flutter_assets\\/`) : /^assets\/flutter_assets\//);
  const libflutter = find(platform === 'ios' ? new RegExp(`${IOS_APP}Frameworks\\/Flutter\\.framework\\/Flutter$`) : /^lib\/[^/]+\/libflutter\.so$/);
  const libapp = find(platform === 'ios' ? new RegExp(`${IOS_APP}Frameworks\\/App\\.framework\\/App$`) : /^lib\/[^/]+\/libapp\.so$/);
  if (flutterAssets.length || libflutter.length || libapp.length) {
    const fl = { name: 'Flutter', mode: null, dart_version: null, dart_packages: [] };
    const jit = flutterAssets.filter(e => /\/flutter_assets\/(kernel_blob\.bin|isolate_snapshot_data|vm_snapshot_data)$/.test(e.name));
    fl.mode = jit.length ? 'debug (JIT kernel snapshot)' : (libapp.length ? 'release (AOT snapshot)' : 'unknown');
    if (libflutter.length) {
      const b = read(libflutter[0], 160 * MB);
      if (b) {
        const m = /(\d+\.\d+\.\d+(?:-[\w.]+)?) \((stable|beta|dev|main)\) \([A-Z][a-z]{2} [A-Z][a-z]{2} +\d+ \d\d:\d\d:\d\d \d{4} [+-]\d{4}\)/.exec(b.latin1Slice());
        if (m) fl.dart_version = `${m[1]} (${m[2]})`;
      }
    }
    const pkgs = new Set();
    // every ABI carries the same Dart program: scan the preferred one (arm64 first) and mark the rest handled
    const ordered = [...libapp].sort((a, b) => (/arm64/.test(a.name) ? 0 : 1) - (/arm64/.test(b.name) ? 0 : 1));
    for (const e of libapp) handled.add(e.name);
    for (const e of ordered.slice(0, 1)) {
      const b = take(e, 256 * MB);
      if (!b) { gap(notes, `${at(e.name)}: Dart snapshot could not be read (${e.usize > 256 * MB ? 'over the size limit' : 'encrypted, corrupt or unsupported compression'}).`); continue; }
      const strs = asciiStrings(b, { min: 6, max: 2000, limit: 700000 });
      const wide = utf16Strings(b, { min: 8, limit: 100000 });
      scanner.add(at(e.name), [...strs, ...wide].map(esc));
      urls(strs);
      for (const s2 of strs) { const m = /^package:([a-z_][a-z0-9_]*)\//.exec(s2); if (m) pkgs.add(m[1]); }
    }
    fl.dart_packages = [...pkgs].sort().slice(0, 300);
    if (flutterAssets.length && !libapp.length && !jit.length) notes.push('Flutter assets found but no libapp.so / App.framework: the Dart code was not located.');
    notes.push('Flutter: Dart HTTP traffic does not consult the Android network security config (cleartext, user-CA and pin-set rules) nor the system proxy; those settings affect only WebView and native-plugin traffic. A pinning or TLS-bypass review needs the Dart code itself, which this scan cannot decompile.');
    list.push(fl);
  }

  // ── Unity ─────────────────────────────────────────────────────────────────────────────────────
  const unityData = platform === 'ios' ? new RegExp(`${IOS_APP}Data\\/`) : /^assets\/bin\/Data\//;
  const unityFiles = find(unityData);
  const libunity = find(/^lib\/[^/]+\/libunity\.so$|\/UnityFramework\.framework\/UnityFramework$/);
  if (unityFiles.length || libunity.length) {
    const un = { name: 'Unity', backend: null, unity_version: null, assemblies: [], asset_bundles: 0 };
    const meta = unityFiles.find(e => /\/Managed\/Metadata\/global-metadata\.dat$/.test(e.name));
    const managed = unityFiles.filter(e => /\/Managed\/[^/]+\.dll$/.test(e.name));
    un.backend = meta ? 'IL2CPP' : (managed.length ? 'Mono' : null);
    for (const e of libunity.slice(0, 1)) {
      const b = read(e, 160 * MB);
      const m = b && /\b((?:20\d\d|[5-6])\.\d+\.\d+[fpab]\d+)\b/.exec(b.latin1Slice());
      if (m) un.unity_version = m[1];
    }
    if (meta) {
      handled.add(meta.name);
      const data = take(meta, 512 * MB);
      const md = data && parseIl2cppMetadata(data);
      if (md) {
        un.il2cpp_metadata_version = md.version;
        scanner.add(at(meta.name), md.literals.filter(s => s.length >= 6).map(esc));
        urls(md.literals);
        const ids = new Set(md.identifiers);
        if (ids.has('CertificateHandler') && ids.has('ValidateCertificate')) add('unity.certificate_handler', { artifact: at(meta.name), description: 'The code defines a CertificateHandler with a ValidateCertificate override. That is how Unity apps implement certificate pinning, and also how they switch certificate checks off (override returning true); IL2CPP metadata does not show which.', evidence: ['CertificateHandler', 'ValidateCertificate'], confidence: 'low' });
      } else if (data) {
        scanner.add(at(meta.name), asciiStrings(data, { min: 8, max: 2000, limit: 400000 }).map(esc));
        gap(notes, `${at(meta.name)}: not valid IL2CPP metadata (encrypted or custom-packed); C# string literals could only be read as printable runs and may be incomplete.`);
      } else gap(notes, `${at(meta.name)}: could not be read.`);
    }
    for (const e of managed) {
      handled.add(e.name);
      if (FRAMEWORK_ASSEMBLY.test(base(e.name))) continue;
      const b = take(e, 128 * MB);
      if (b) dotnetAssembly(at(e.name), base(e.name), b);
      else gap(notes, `${at(e.name)}: assembly could not be read.`);
    }
    const boot = unityFiles.find(e => /\/boot\.config$/.test(e.name));
    if (boot) {
      handled.add(boot.name);
      const t = (read(boot, 1 * MB) || Buffer.alloc(0)).toString('utf8');
      scanner.add(at(boot.name), t.split(/\r?\n/).filter(Boolean));
      if (/^player-connection-debug=1\s*$/m.test(t)) add('unity.development_build', { artifact: at(boot.name), description: 'boot.config enables player-connection-debug: this is a Unity Development Build. The profiler and managed debugger can attach over the network, and development-only code paths are compiled in.', evidence: ['player-connection-debug=1'] });
    }
    // serialized files (scenes, globalgamemanagers, *.assets) hold MonoBehaviour fields — where inspector-entered API keys end up
    let serialized = 0, unity3dSkipped = 0;
    // Addressables / StreamingAssets bundles live outside Data/ (assets/aa/…); only files that really are UnityFS get claimed.
    const unityBundles = find(platform === 'ios' ? new RegExp(`${IOS_APP}.*\\.(bundle|unity3d)$`) : /^assets\/.*\.(bundle|unity3d)$/).filter(e => !unityFiles.includes(e) && !handled.has(e.name));
    for (const e of [...unityFiles, ...unityBundles]) {
      if (handled.has(e.name) || e.isDir || e.usize === 0) continue;
      const name = base(e.name);
      if (/\.(unity3d|bundle)$/.test(name) || /^[0-9a-f]{20,}$/.test(name)) {
        const head = take(e, 256 * MB);
        if (!head) { gap(notes, `${at(e.name)}: asset bundle could not be read (${e.usize > 256 * MB ? 'over the size limit' : 'corrupt or unsupported compression'}).`); continue; }
        if (head.length > 8 && head.latin1Slice(0, 7) === 'UnityFS') {
          handled.add(e.name); un.asset_bundles++;
          const r = unityFsStrings(head, un);
          if (r.strings) { scanner.add(at(e.name), r.strings); urls(r.strings); } else if (r.reason) gap(notes, `${at(e.name)}: UnityFS bundle not unpacked (${r.reason}); its embedded assets were not scanned.`);
        }
        continue;
      }
      if (/^(globalgamemanagers(\.assets)?|level\d+|sharedassets\d+\.assets|resources\.assets|unity default resources|unity_builtin_extra|mainData|RuntimeInitializeOnLoads\.json|ScriptingAssemblies\.json)$/.test(name) || /\.assets$/.test(name)) {
        if (/^(RuntimeInitializeOnLoads|ScriptingAssemblies)\.json$/.test(name)) continue;
        handled.add(e.name);
        if (serialized >= 400) continue;
        const b = take(e, 128 * MB);
        if (!b) { gap(notes, `${at(e.name)}: serialized Unity file could not be read.`); continue; }
        serialized++;
        const strs = asciiStrings(b, { min: 8, max: 2000, limit: 200000 });
        scanner.add(at(e.name), strs.map(esc)); urls(strs);
      }
    }
    if (serialized >= 400) gap(notes, 'More than 400 Unity serialized files: the rest were not scanned.');
    list.push(un);
  }

  // ── Xamarin / .NET MAUI (and any other managed assemblies outside Unity) ──────────────────────
  const dlls = find(platform === 'ios' ? new RegExp(`${IOS_APP}[^/]+\\.dll$`) : /^assemblies\/(?:[^/]+\/)?[^/]+\.dll$/).filter(e => !handled.has(e.name));
  const blobs = find(/^assemblies\/[^/]*\.blob$/);
  const stores = find(/^lib\/[^/]+\/libassembly-store\.so$/);
  const manifestEntry = zip.entry('assemblies/assemblies.manifest');
  const monoNative = find(/^lib\/[^/]+\/(libmonodroid|libxamarin-app|libmonosgen-2\.0|libmono-android\.release|libmono-android\.debug|libassembly-store)\.so$/);
  if (dlls.length || blobs.length || stores.length || monoNative.length) {
    const names = manifestEntry ? parseAssemblyManifest((read(manifestEntry, 8 * MB) || Buffer.alloc(0)).toString('utf8')).sort((a, b) => a.idx - b.idx).map(r => r.name) : [];
    const xa = { name: 'Xamarin / .NET', flavour: null, assemblies: 0, compressed: 0, packed_in_store: false, app_assemblies: [] };
    const units = [];                                   // { path, name, data }
    for (const e of dlls) { handled.add(e.name); const b = take(e, 128 * MB); if (b) units.push({ path: e.name, name: base(e.name), data: b }); else gap(notes, `${at(e.name)}: assembly could not be read.`); }
    for (const e of [...blobs, ...stores]) {
      handled.add(e.name);
      const b = take(e, 512 * MB);
      if (!b) { gap(notes, `${at(e.name)}: assembly store could not be read.`); continue; }
      const st = readAssemblyStore(b, names);
      if (!st) { gap(notes, `${at(e.name)}: assembly store layout not recognised; the assemblies inside were not analysed (printable strings only).`); scanner.add(at(e.name), [...asciiStrings(b, { min: 8, max: 1000, limit: 100000 }), ...utf16Strings(b, { min: 8, limit: 100000 })].map(esc)); continue; }
      xa.packed_in_store = true;
      for (const a of st) units.push({ path: `${e.name}!${a.name}`, name: a.name, data: a.data });
    }
    let debugRuntime = monoNative.filter(e => /libmono-android\.debug\.so$/.test(e.name));
    if (debugRuntime.length) add('bundle.debug_build', { artifact: at(debugRuntime[0].name), description: 'libmono-android.debug.so is the Xamarin.Android debug runtime (fast deployment, debugger and profiler support); it only ships in Debug builds.', evidence: [debugRuntime[0].name], key: 'xa-debug' });
    const debugPaths = [], leakPaths = [];
    for (const u of units.slice(0, 1500)) {
      xa.assemblies++;
      if (isXalz(u.data)) xa.compressed++;
      const bytes = assemblyBytes(u.data);
      if (!bytes) { gap(notes, `${at(u.path)}: assembly is ${isXalz(u.data) ? 'XALZ-compressed but could not be decompressed' : 'not a managed assembly'}; not analysed.`); continue; }
      if (/^(Mono\.Android|Microsoft\.Maui(\.|$)|Xamarin\.Forms\.Core|Xamarin\.iOS|Microsoft\.iOS)/i.test(u.name)) xa.flavour = /Maui/i.test(u.name) ? '.NET MAUI' : (xa.flavour === '.NET MAUI' ? xa.flavour : (/Forms/i.test(u.name) ? 'Xamarin.Forms' : xa.flavour));
      if (FRAMEWORK_ASSEMBLY.test(u.name)) continue;
      dotnetAssembly(at(u.path), u.name, bytes, { debugPaths, leakPaths });
      xa.app_assemblies.push(u.name);
    }
    if (units.length > 1500) gap(notes, 'More than 1500 managed assemblies: the rest were not analysed.');
    if (debugPaths.length) add('dotnet.debug_build', { artifact: at(debugPaths[0].split(' ← ')[1] || ''), description: `${debugPaths.length} assembl${debugPaths.length === 1 ? 'y was' : 'ies were'} built in the Debug configuration (the PDB path under obj/Debug): unoptimised code with full debug information.`, evidence: debugPaths.slice(0, 10).map(x => x.split(' ← ')[0]), evidence_total: debugPaths.length });
    if (leakPaths.length) add('dotnet.build_path_leak', { artifact: at(leakPaths[0].split(' ← ')[1] || ''), description: 'The assemblies embed the absolute path of the build machine\'s PDB file, which discloses developer user names and directory layout.', evidence: leakPaths.slice(0, 5).map(x => x.split(' ← ')[0]), evidence_total: leakPaths.length, confidence: 'high' });
    if (xa.compressed) notes.push(`${xa.compressed} of ${xa.assemblies} assemblies were XALZ-compressed (Xamarin.Android release default) and were decompressed in memory for analysis.`);
    if (!list.some(f => f.name === 'Unity') || units.length) list.push(xa);
  }

  return { list, handled };

  // .NET assembly → secrets input + TLS findings (closure over scanner/findings)
  function dotnetAssembly(path, name, bytes, acc = null) {
    const d = parseDotnet(bytes);
    if (!d) { gap(notes, `${path}: not a readable managed assembly.`); return; }
    const lits = d.userStrings.filter(s => s.length >= 6).map(esc);
    scanner.add(path, lits); urls(d.userStrings);
    const hits = TLS_BYPASS_STRONG.filter(n => d.identifiers.has(n));
    const weak = TLS_BYPASS_WEAK.filter(n => d.identifiers.has(n));
    if (hits.length) add('dotnet.tls_validation_disabled', { artifact: path, evidence: hits, confidence: 'medium', description: `${name} references HttpClientHandler.DangerousAcceptAnyServerCertificateValidator, the stock "accept every certificate" validator.`, key: `${path}:strong` });
    else if (weak.length) add('dotnet.tls_validation_disabled', { artifact: path, evidence: weak, severity: 'medium', confidence: 'low', description: `${name} sets a custom server-certificate validation callback. That is how pinning is implemented in .NET and also how checks are disabled (callback returning true); the compiled code was not decompiled, so review the callback.`, key: `${path}:weak` });
    if (d.pdbPath) {
      if (acc && /[\\/]Debug[\\/]/i.test(d.pdbPath)) acc.debugPaths.push(`${d.pdbPath} ← ${path}`);
      if (acc && /^([A-Za-z]:\\|\/(home|Users)\/)/.test(d.pdbPath)) acc.leakPaths.push(`${d.pdbPath} ← ${path}`);
    }
  }
}

// ── UnityFS ─────────────────────────────────────────────────────────────────────────────────────
/** Unpacks a UnityFS bundle (uncompressed / LZ4 / LZ4HC blocks) and returns printable strings of its data. LZMA is reported, not read. */
export function unityFsStrings(buf, info = {}) {
  try {
    let p = 8;
    const version = buf.readUInt32BE(p); p += 4;
    const cstr = () => { const e = buf.indexOf(0, p); const s = buf.toString('latin1', p, e); p = e + 1; return s; };
    cstr(); const rev = cstr();
    if (rev && !info.unity_version) info.unity_version = rev;
    p += 8;                                                                // total size
    const cSize = buf.readUInt32BE(p), uSize = buf.readUInt32BE(p + 4), flags = buf.readUInt32BE(p + 8); p += 12;
    if (version >= 7) p = (p + 15) & ~15;
    const infoAtEnd = (flags & 0x80) !== 0;
    const infoStart = infoAtEnd ? buf.length - cSize : p;
    if (infoStart < 0 || infoStart + cSize > buf.length || uSize > 64 * MB) return { reason: 'block table out of range' };
    const decode = (data, type, size) => {
      if (type === 0) return data;
      if (type === 2 || type === 3) return lz4Block(data, size);
      throw new Error(type === 1 ? 'LZMA-compressed' : `unknown compression ${type}`);
    };
    let table;
    try { table = decode(buf.subarray(infoStart, infoStart + cSize), flags & 0x3f, uSize); } catch (e) { return { reason: e.message }; }
    const nBlocks = table.readInt32BE(16);
    if (nBlocks < 0 || nBlocks > 200000) return { reason: 'implausible block count' };
    let dp = infoAtEnd ? p : p + cSize;
    const parts = []; let total = 0;
    for (let i = 0; i < nBlocks; i++) {
      const u = table.readUInt32BE(20 + i * 10), c = table.readUInt32BE(24 + i * 10), f = table.readUInt16BE(28 + i * 10);
      if (dp + c > buf.length) return { reason: 'block overruns the file' };
      total += u; if (total > 512 * MB) return { reason: 'unpacks beyond the size limit' };
      try { parts.push(decode(buf.subarray(dp, dp + c), f & 0x3f, u)); } catch (e) { return { reason: e.message }; }
      dp += c;
    }
    const data = Buffer.concat(parts);
    return { strings: asciiStrings(data, { min: 8, max: 2000, limit: 200000 }).map(esc) };
  } catch (e) { return { reason: `unreadable header (${e.message})` }; }
}
