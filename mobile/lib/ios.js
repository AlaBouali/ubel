'use strict';
// ios.js — everything ubel-mobile checks in an iOS package (.ipa): Info.plist (ATS, URL schemes, file sharing),
// embedded.mobileprovision, entitlements, Mach-O hardening and imported symbols, strings, frameworks and bundled files.
// Pure Node: no otool, codesign, class-dump or plutil.

import path from 'path';
import { parsePlist, extractEmbeddedPlist, plistToLines } from './plist.js';
import { isMachO, parseMachO, sectionBuffers } from './macho.js';
import { asciiStrings, utf16Strings } from './strings.js';
import { scanBundledFiles } from './files.js';
import { Aggregator } from './findings.js';

const MB = 1024 * 1024;
const URL_HTTP = /^http:\/\/[^\s"'<>\\]{4,300}$/i;
const NAMESPACE_URL = /(w3\.org|apache\.org|xmlpull\.org|schemas\.|sun\.com|xml\.org|ietf\.org|iana\.org|purl\.org|ns\.adobe\.com|apple\.com\/DTDs|apple\.com\/dtd|opengis\.net|iso\.org|xmlsoap\.org|openxmlformats\.org|json-schema\.org|mozilla\.org|gnu\.org|example\.(com|org)|localhost|127\.0\.0\.1|0\.0\.0\.0)/i;
const SECRET_KEY_NAME = /^(password|passwd|pwd|pin|secret|api_?key|access_?token|auth_?token|refresh_?token|session_?(id|token)|client_?secret|private_?key)$/i;
const PIN_STRINGS = ['TrustKit', 'AFSecurityPolicy', 'pinnedCertificates', 'PinnedCertificatesTrustEvaluator', 'ServerTrustManager', 'PublicKeyPinning', 'SSLPinning'];
const AUTH_CHALLENGE = ['URLSession:didReceiveChallenge:completionHandler:', 'connection:willSendRequestForAuthenticationChallenge:', 'URLSession:task:didReceiveChallenge:completionHandler:'];
const TLS_OFF_STRINGS = ['allowsAnyHTTPSCertificateForHost:', 'setAllowsAnyHTTPSCertificate:forHost:', 'setAllowInvalidCertificates:', 'DisabledTrustEvaluator'];

const SYMBOL_RULES = [
  ['ios.code.weak_hash', ['_CC_MD5', '_CC_MD5_Init', '_CC_MD2', '_CC_MD4', '_CC_SHA1', '_CC_SHA1_Init', '_MD5_Init', '_SHA1_Init'], 'MD5/SHA-1 primitives are imported.'],
  ['ios.code.weak_cipher', ['_DES_ecb_encrypt', '_DES_cbc_encrypt', '_DES_ncbc_encrypt', '_DES_ede3_cbc_encrypt', '_RC4', '_RC4_set_key', '_BF_set_key', '_BF_cbc_encrypt', '_EVP_des_cbc', '_EVP_des_ecb', '_EVP_des_ede3_cbc', '_EVP_rc4', '_EVP_rc2_cbc'], 'Broken ciphers are linked in.'],
  ['ios.code.ecb', ['_EVP_aes_128_ecb', '_EVP_aes_192_ecb', '_EVP_aes_256_ecb', '_AES_ecb_encrypt'], 'AES-ECB primitives are linked in.'],
  ['ios.code.insecure_random', ['_rand', '_srand', '_random', '_srandom', '_drand48'], 'rand()/random() are not cryptographically secure.'],
  ['ios.code.keychain_always', ['_kSecAttrAccessibleAlways', '_kSecAttrAccessibleAlwaysThisDeviceOnly'], 'Keychain items using this attribute can be read while the device is locked or freshly booted.'],
  ['ios.code.file_protection_none', ['_NSFileProtectionNone'], 'Files written with NSFileProtectionNone are never encrypted with the device passcode key.'],
  ['ios.code.uiwebview', ['_OBJC_CLASS_$_UIWebView'], 'UIWebView is deprecated and has weaker isolation than WKWebView.'],
  ['ios.code.tls_validation_disabled', ['_kCFStreamSSLValidatesCertificateChain'], 'kCFStreamSSLValidatesCertificateChain is referenced; setting it to false turns certificate validation off.'],
  ['ios.code.unsafe_c', ['_strcpy', '_strcat', '_sprintf', '_vsprintf', '_gets', '_stpcpy'], 'Unbounded C string functions are imported.'],
  ['ios.code.nslog', ['_NSLog'], 'NSLog output is visible in the device console and to anyone with physical access.'],
];

const verMajor = v => parseInt(String(v || '0').split('.')[0], 10) || 0;

export function findAppDir(zip) {
  for (const e of zip.entries) {
    const m = /^(Payload\/[^/]+\.app\/)/.exec(e.name);
    if (m) return m[1];
  }
  return null;
}

/** @returns {object} app summary */
export function analyzeIpa(zip, ctx) {
  const { findings, notes } = ctx;
  const dir = findAppDir(zip);
  if (!dir) throw new Error('no Payload/*.app found — not an IPA');
  const infoEntry = zip.entry(`${dir}Info.plist`);
  if (!infoEntry) throw new Error(`${dir}Info.plist not found`);
  const info = parsePlist(zip.read(infoEntry, 16 * MB));
  if (!info || typeof info !== 'object' || Array.isArray(info)) throw new Error(`${infoEntry.name} is not a property-list dictionary`);
  const bundleId = String(info.CFBundleIdentifier || 'unknown');
  const base = { app: bundleId };
  const scanner = ctx.newScanner(base);
  const app = {
    platform: 'ios', bundle_id: bundleId, name: info.CFBundleDisplayName || info.CFBundleName || null,
    version: info.CFBundleShortVersionString ?? null, build: info.CFBundleVersion ?? null, min_os: info.MinimumOSVersion ?? null,
    executable: info.CFBundleExecutable || null, sdk: info.DTSDKName ?? null, provisioning: null, entitlements: null,
    architectures: [], frameworks: [], extensions: [], url_schemes: [], binary: null,
  };
  const art = `${dir}Info.plist`;
  plistChecks(info, { findings, base, art, app });
  scanner.add(art, plistToLines(info));

  // provisioning profile → distribution type, expiry, entitlements
  let profileEnt = null;
  const prov = zip.entry(`${dir}embedded.mobileprovision`);
  if (prov) {
    try {
      const p = extractEmbeddedPlist(zip.read(prov, 4 * MB));
      if (p) profileEnt = provisioningChecks(p, { findings, base, art: prov.name, app });
    } catch { notes.push(`${prov.name}: could not be parsed.`); }
  }

  // Mach-O: main executable, embedded frameworks, app extensions
  const agg = new Aggregator(findings, base);
  const state = { urls: new Set(), pinned: false, hasSwiftOnly: false, machoPaths: new Set() };
  const targets = [];
  if (app.executable) targets.push({ name: `${dir}${app.executable}`, label: app.executable, main: true, origin: 'app' });
  for (const e of zip.entries) {
    let m;
    if ((m = /^(Payload\/[^/]+\.app\/Frameworks\/([^/]+)\.framework\/)Info\.plist$/.exec(e.name))) {
      const fi = safePlist(zip, e);
      if (fi) {
        app.frameworks.push({ name: m[2], id: fi.CFBundleIdentifier || null, version: fi.CFBundleShortVersionString || fi.CFBundleVersion || null });
        targets.push({ name: `${m[1]}${fi.CFBundleExecutable || m[2]}`, label: `${m[2]}.framework`, main: false, origin: 'library' });
      }
    } else if ((m = /^(Payload\/[^/]+\.app\/PlugIns\/([^/]+)\.appex\/)Info\.plist$/.exec(e.name))) {
      const pi = safePlist(zip, e);
      if (pi) {
        app.extensions.push({ name: m[2], id: pi.CFBundleIdentifier || null });
        targets.push({ name: `${m[1]}${pi.CFBundleExecutable || m[2]}`, label: `${m[2]}.appex`, main: false, origin: 'app' });
      }
    } else if (/^Payload\/[^/]+\.app\/Frameworks\/[^/]+\.dylib$/.test(e.name)) targets.push({ name: e.name, label: path.posix.basename(e.name), main: false, origin: 'library' });
  }
  let mainEnt = null;
  for (const t of targets.slice(0, 200)) {
    const entry = zip.entry(t.name);
    if (!entry) { if (t.main) notes.push(`${t.name}: main executable missing from the package.`); continue; }
    state.machoPaths.add(t.name);
    const buf = zip.tryRead(entry, 1024 * MB);
    if (!buf || !isMachO(buf)) { if (t.main) notes.push(`${t.name}: not a readable Mach-O executable.`); continue; }
    try {
      const r = analyzeMachO(buf, t, { agg, findings, base, scanner, state, notes, app });
      if (t.main) mainEnt = r.entitlements;
    } catch (e) { notes.push(`${t.name}: Mach-O not analysed (${e.message}).`); }
  }
  agg.flush(app.executable ? `${dir}${app.executable}` : dir);

  // entitlements (the signed binary's own are authoritative; the profile is the fallback)
  const ent = mainEnt || profileEnt;
  if (ent) {
    app.entitlements = summariseEntitlements(ent);
    if (ent['get-task-allow'] === true) findings.add('ios.profile.get_task_allow', { ...base, artifact: `${dir}${app.executable || ''}`, description: 'get-task-allow lets any debugger attach to the app; it is set on development builds and must be absent from distribution builds.', evidence: ['get-task-allow = true'], key: 'gta' });
    if (ent['aps-environment'] === 'development') findings.add('ios.profile.push_dev', { ...base, artifact: `${dir}${app.executable || ''}`, description: 'The push-notification entitlement points at the APNs sandbox.', evidence: ['aps-environment = development'], key: 'aps' });
  }

  // cleartext URLs / pinning
  const http = [...state.urls].filter(u => URL_HTTP.test(u) && !NAMESPACE_URL.test(u));
  if (http.length) findings.add('ios.code.cleartext_urls', { ...base, artifact: `${dir}${app.executable || ''}`, description: `${http.length} http:// endpoint(s) are hardcoded; traffic to them is unencrypted unless ATS blocks it.`, evidence: http.slice(0, 25), evidence_total: http.length, confidence: 'medium' });
  const certFiles = zip.entries.some(e => /\.(cer|crt|der)$/i.test(e.name) && e.name.startsWith(dir));
  if (!state.pinned && !certFiles) findings.add('ios.code.no_pinning', { ...base, artifact: `${dir}${app.executable || ''}`, description: 'No pinning library, pinned-certificate file or SecTrust evaluation with a pinned key was found.', evidence: [], confidence: 'low', key: 'nopin' });

  // everything else in the bundle
  const skip = e => state.machoPaths.has(e.name) || /^Payload\/[^/]+\.app\/(_CodeSignature\/|SC_Info\/|embedded\.mobileprovision$)/.test(e.name) ||
    /\/_CodeSignature\//.test(e.name) || e.name === infoEntry.name || /^(Symbols|SwiftSupport|BCSymbolMaps)\//.test(e.name) || /\.(car|nib|storyboardc|momd?)(\/|$)/i.test(e.name);
  scanBundledFiles(zip, zip.entries.filter(e => !e.isDir && !skip(e)), { findings, scanner, base, notes, limits: ctx.limits });
  scanner.run();
  if (scanner.truncated) notes.push(`${bundleId}: secret scanning stopped at its line budget; some strings were not scanned.`);
  return app;
}

function safePlist(zip, entry) { try { return parsePlist(zip.read(entry, 4 * MB)); } catch { return null; } }

function summariseEntitlements(ent) {
  const keep = ['get-task-allow', 'aps-environment', 'application-identifier', 'com.apple.developer.team-identifier', 'keychain-access-groups',
    'com.apple.security.application-groups', 'com.apple.developer.associated-domains', 'com.apple.developer.icloud-services', 'com.apple.developer.healthkit',
    'com.apple.developer.networking.wifi-info', 'com.apple.developer.applesignin'];
  return Object.fromEntries(Object.entries(ent).filter(([k]) => keep.includes(k)));
}

// ── Info.plist ─────────────────────────────────────────────────────────────────────────────────────
function plistChecks(info, { findings, base, art, app }) {
  const ats = info.NSAppTransportSecurity;
  if (ats && typeof ats === 'object') {
    if (ats.NSAllowsArbitraryLoads === true) findings.add('ios.plist.ats_arbitrary', { ...base, artifact: art, description: 'NSAllowsArbitraryLoads turns App Transport Security off for the whole app: plain HTTP and weak TLS are allowed everywhere.', evidence: ['NSAllowsArbitraryLoads = true'] });
    if (ats.NSAllowsArbitraryLoadsInWebContent === true) findings.add('ios.plist.ats_web', { ...base, artifact: art, description: 'Web views may load insecure content.', evidence: ['NSAllowsArbitraryLoadsInWebContent = true'] });
    const ex = ats.NSExceptionDomains && typeof ats.NSExceptionDomains === 'object' ? ats.NSExceptionDomains : {};
    const insecure = [], oldTls = [];
    for (const [d, cfg] of Object.entries(ex)) {
      if (!cfg || typeof cfg !== 'object') continue;
      if (cfg.NSExceptionAllowsInsecureHTTPLoads === true || cfg.NSThirdPartyExceptionAllowsInsecureHTTPLoads === true) insecure.push(d);
      const v = cfg.NSExceptionMinimumTLSVersion || cfg.NSThirdPartyExceptionMinimumTLSVersion;
      if (v === 'TLSv1.0' || v === 'TLSv1.1') oldTls.push(`${d} (${v})`);
    }
    if (insecure.length) findings.add('ios.plist.ats_exceptions', { ...base, artifact: art, description: `${insecure.length} domain(s) are exempt from the HTTPS requirement.`, evidence: insecure.slice(0, 30), evidence_total: insecure.length });
    if (oldTls.length) findings.add('ios.plist.ats_tls', { ...base, artifact: art, description: 'These domains may be reached over TLS 1.0/1.1.', evidence: oldTls });
  }
  if (info.UIFileSharingEnabled === true) findings.add('ios.plist.file_sharing', { ...base, artifact: art, description: 'The app’s Documents folder is exposed through Files / iTunes file sharing.', evidence: ['UIFileSharingEnabled = true'] });
  const schemes = (Array.isArray(info.CFBundleURLTypes) ? info.CFBundleURLTypes : []).flatMap(t => (t && Array.isArray(t.CFBundleURLSchemes) ? t.CFBundleURLSchemes : [])).map(String);
  app.url_schemes = schemes;
  if (schemes.length) findings.add('ios.plist.url_schemes', { ...base, artifact: art, description: 'Any app can register the same custom scheme and intercept links meant for this one.', evidence: schemes.map(s => `${s}://`) });
  const min = verMajor(info.MinimumOSVersion);
  if (min && min < 14) findings.add('ios.plist.min_os', { ...base, artifact: art, severity: min < 12 ? 'medium' : 'low', description: `MinimumOSVersion is ${info.MinimumOSVersion}; older iOS releases lack newer platform protections.`, evidence: [`MinimumOSVersion = ${info.MinimumOSVersion}`] });
  if (info.DTPlatformName === 'iphonesimulator') findings.add('ios.plist.simulator', { ...base, artifact: art, description: 'DTPlatformName says this build targets the iOS Simulator.', evidence: ['DTPlatformName = iphonesimulator'] });
}

// ── provisioning profile ───────────────────────────────────────────────────────────────────────────
function provisioningChecks(p, { findings, base, art, app }) {
  const ent = p.Entitlements && typeof p.Entitlements === 'object' ? p.Entitlements : {};
  const type = p.ProvisionsAllDevices === true ? 'enterprise' : Array.isArray(p.ProvisionedDevices) ? (ent['get-task-allow'] === true ? 'development' : 'ad-hoc') : 'app-store';
  app.provisioning = { name: p.Name || null, team: p.TeamName || null, type, expires: p.ExpirationDate || null, devices: Array.isArray(p.ProvisionedDevices) ? p.ProvisionedDevices.length : 0 };
  if (type === 'enterprise') findings.add('ios.profile.all_devices', { ...base, artifact: art, description: 'ProvisionsAllDevices is set: this is an enterprise (in-house) build that can be installed on any device outside the App Store.', evidence: [p.Name || '(unnamed profile)'] });
  else if (type === 'development' || type === 'ad-hoc') findings.add('ios.profile.dev_devices', { ...base, artifact: art, description: `The profile is a ${type} profile bound to ${app.provisioning.devices} device(s).`, evidence: [p.Name || '(unnamed profile)'] });
  if (p.ExpirationDate && Date.parse(p.ExpirationDate) < Date.now()) findings.add('ios.profile.expired', { ...base, artifact: art, description: `The provisioning profile expired on ${p.ExpirationDate}.`, evidence: [String(p.ExpirationDate)] });
  return ent;
}

// ── Mach-O ─────────────────────────────────────────────────────────────────────────────────────────
function analyzeMachO(buf, t, { agg, findings, base, scanner, state, notes, app }) {
  const { slices, preferred } = parseMachO(buf);
  if (t.main) app.architectures = slices.map(s => s.arch);
  if (t.main) app.binary = { arch: preferred.arch, pie: preferred.pie, encrypted: preferred.encrypted, signed: preferred.signed, min_os: preferred.minOS, sdk: preferred.sdk, swift: preferred.dylibs.some(d => /libswift/.test(d)) };
  const art = t.name;
  const origin = t.origin;
  const label = t.label;
  if (t.main) {
    for (const s of slices) {
      if (s.filetype === 2 && !s.pie) agg.hit('ios.macho.no_pie', { origin, evidence: `${s.arch}: MH_PIE not set`, description: 'The executable loads at a fixed address, which defeats ASLR.' });
      if (s.allowStackExec) agg.hit('ios.macho.stack_exec', { origin, evidence: `${s.arch}: MH_ALLOW_STACK_EXECUTION`, description: 'The executable allows code to run from the stack.' });
    }
    if (!preferred.signed) findings.add('ios.macho.unsigned', { ...base, artifact: art, description: 'The main executable has no LC_CODE_SIGNATURE.', evidence: [], key: 'unsigned' });
    if (preferred.encrypted) {
      findings.add('ios.macho.encrypted', { ...base, artifact: art, description: `LC_ENCRYPTION_INFO cryptid=${preferred.cryptid}: the code pages are FairPlay-encrypted (normal for an App Store download). Imported symbols and the Info.plist were still analysed; strings inside the binary could not be.`, evidence: [`cryptid = ${preferred.cryptid}`], key: 'cryptid' });
      notes.push(`${art}: FairPlay-encrypted — string-based checks and the secrets scan of the main binary were skipped. Scan a decrypted or development-signed build for full coverage.`);
    }
  }
  const imports = preferred.imports;
  for (const [rule, syms, why] of SYMBOL_RULES) {
    const hit = syms.filter(s => imports.has(s));
    if (hit.length) agg.hit(rule, { origin, evidence: `${hit.join(', ')} (${label})`, description: why, confidence: 'medium' });
  }
  if (imports.has('_SecTrustEvaluate') || imports.has('_SecTrustEvaluateWithError') || imports.has('_SecTrustEvaluateAsyncWithError')) {
    if (imports.has('_SecTrustGetCertificateAtIndex') || imports.has('_SecTrustCopyCertificateChain') || imports.has('_SecTrustCopyKey') || imports.has('_SecTrustCopyPublicKey')) state.pinned = true;
  }
  const swift = preferred.dylibs.some(d => /libswiftCore/.test(d));
  if (t.main && imports.has('_objc_msgSend')) {
    if (!swift && !imports.has('___stack_chk_fail')) agg.hit('ios.macho.no_canary', { origin, evidence: label, description: 'The Objective-C/C code is built without stack-smashing protection.', confidence: 'medium' });
    if (!['_objc_retain', '_objc_release', '_objc_autoreleaseReturnValue', '_objc_storeStrong', '_objc_retainAutoreleasedReturnValue'].some(s => imports.has(s))) {
      agg.hit('ios.macho.no_arc', { origin, evidence: label, description: 'No ARC runtime entry points are imported, which suggests manual retain/release.', confidence: 'low' });
    }
  }
  if (preferred.encrypted && t.main) return { entitlements: preferred.entitlements };

  // strings
  const strings = new Set();
  const lines = [];
  for (const part of sectionBuffers(buf, preferred)) {
    const list = part.name === '__ustring' ? utf16Strings(part.data, { min: 6 }) : asciiStrings(part.data, { min: part.name.startsWith('__objc') ? 4 : 6, max: 800, limit: 200000 });
    for (const s of list) { strings.add(s); if (part.name !== '__objc_methname' && part.name !== '__objc_classname' && s.length >= 8) lines.push(s); }
  }
  if (lines.length && (t.main || buf.length < 64 * MB)) scanner.add(art, lines);
  const has = s => strings.has(s);
  for (const s of strings) { if (s.startsWith('http://')) state.urls.add(s); }
  if (PIN_STRINGS.some(has) || [...strings].some(s => /sha(256|1)\/[A-Za-z0-9+/]{27,44}={0,2}/.test(s))) state.pinned = true;
  const tlsOff = TLS_OFF_STRINGS.filter(has);
  if (tlsOff.length) agg.hit('ios.code.tls_validation_disabled', { origin, evidence: `${tlsOff.join(', ')} (${label})`, description: 'API names that switch certificate validation off are present.', confidence: 'low' });
  if (has('allowFileAccessFromFileURLs') || has('allowUniversalAccessFromFileURLs')) agg.hit('ios.code.wkwebview_file_access', { origin, evidence: label, description: 'WKWebView preferences that open file:// access are set through KVC.', confidence: 'low' });
  if (t.main && AUTH_CHALLENGE.some(has) && has('credentialForTrust:') && !['_SecTrustEvaluate', '_SecTrustEvaluateWithError', '_SecTrustEvaluateAsyncWithError'].some(s => imports.has(s))) {
    agg.hit('ios.code.custom_auth_challenge', { origin, evidence: label, description: 'The app answers server-trust challenges with credentialForTrust: but never evaluates the trust; this is the classic "accept any certificate" pattern.', confidence: 'medium' });
  }
  if (t.main && imports.has('_OBJC_CLASS_$_NSUserDefaults')) {
    const keys = [...strings].filter(s => SECRET_KEY_NAME.test(s)).slice(0, 15);
    if (keys.length) agg.hit('ios.code.userdefaults_secrets', { origin, evidence: keys.join(', '), description: 'The binary uses NSUserDefaults and contains key names that suggest credentials are stored there; verify, since this is based on names only.', confidence: 'low' });
  }
  return { entitlements: preferred.entitlements };
}
