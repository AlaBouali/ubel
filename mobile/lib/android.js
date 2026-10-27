'use strict';
// android.js — everything ubel-mobile checks in an Android package (.apk):
// manifest, network security config, signing, DEX (strings, constants, API calls, TLS bypasses),
// native libraries, string resources and bundled files. Pure Node: no aapt, apktool, jadx or smali.

import { findAll, axmlToLines } from './axml.js';
import { parseBinaryXml, isBinaryXml, parseResourceTableStrings } from './aab.js';
import { gap } from './coverage.js';
import { DexProtectionCollector, detectProtections } from './protections.js';
import { analyzeFrameworks } from './frameworks.js';
import { parseArscStrings } from './arsc.js';
import { Dex, isDex } from './dex.js';
import { isElf, parseElf } from './elf.js';
import { hardeningRecord, evaluateRecords, groupFailures, summarizeHardening, isVendorNative } from './elf_hardening.js';
import { asciiStrings } from './strings.js';
import { certsFromPkcs7, describeCert, parseApkSigningBlock, WEAK_SIG } from './der.js';
import { scanBundledFiles } from './files.js';
import { Aggregator, mask } from './findings.js';
import { ResilienceCollector, MIN_INDICATORS, RESILIENCE_CALLS, RUNTIME_EXEC, classifyResilienceString } from './resilience.js';
import { BehaviorCollector, BEHAVIOR, NativeBehavior } from './behavior.js';
import { RemoteHostCollector } from '../../binary/lib/hosts.js';
import { elfCallSites } from '../../binary/lib/callsites.js';
import { captureFirebaseResource, collectVerifyHosts, onlineData, FIREBASE_DB_URL } from './online.js';
import { MethodSignals, SIGNAL_KEYS, sensitiveLabel, schemaSensitive, credentialConstant, maskedConstant, isJwtLiteral, classifyJwt, constantSecretArg } from './signals.js';

const MB = 1024 * 1024;

// ── knowledge tables ───────────────────────────────────────────────────────────────────────────────
const DANGEROUS_PERMS = new Set(['READ_CALENDAR', 'WRITE_CALENDAR', 'CAMERA', 'READ_CONTACTS', 'WRITE_CONTACTS', 'GET_ACCOUNTS', 'ACCESS_FINE_LOCATION',
  'ACCESS_COARSE_LOCATION', 'ACCESS_BACKGROUND_LOCATION', 'RECORD_AUDIO', 'READ_PHONE_STATE', 'READ_PHONE_NUMBERS', 'CALL_PHONE', 'READ_CALL_LOG',
  'WRITE_CALL_LOG', 'ADD_VOICEMAIL', 'USE_SIP', 'ANSWER_PHONE_CALLS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_SMS', 'RECEIVE_WAP_PUSH', 'RECEIVE_MMS',
  'READ_EXTERNAL_STORAGE', 'WRITE_EXTERNAL_STORAGE', 'BODY_SENSORS', 'ACTIVITY_RECOGNITION', 'READ_MEDIA_IMAGES', 'READ_MEDIA_VIDEO', 'READ_MEDIA_AUDIO',
  'BLUETOOTH_CONNECT', 'BLUETOOTH_SCAN', 'NEARBY_WIFI_DEVICES', 'POST_NOTIFICATIONS']);
const RISKY_PERMS = new Set(['MANAGE_EXTERNAL_STORAGE', 'READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'READ_CALL_LOG', 'WRITE_CALL_LOG', 'PROCESS_OUTGOING_CALLS',
  'SYSTEM_ALERT_WINDOW', 'REQUEST_INSTALL_PACKAGES', 'INSTALL_PACKAGES', 'READ_LOGS', 'WRITE_SECURE_SETTINGS', 'BIND_DEVICE_ADMIN', 'BIND_ACCESSIBILITY_SERVICE',
  'QUERY_ALL_PACKAGES', 'ACCESS_BACKGROUND_LOCATION', 'CHANGE_COMPONENT_ENABLED_STATE', 'DISABLE_KEYGUARD', 'WRITE_SETTINGS', 'REQUEST_DELETE_PACKAGES']);
const SYSTEM_ACTION = /^(android\.(intent\.action|net|provider|bluetooth|app\.action|hardware|location|nfc|telephony|media)\.|com\.google\.android\.c2dm\.)/;

const LIB_PREFIXES = ['Landroid/', 'Landroidx/', 'Lcom/android/', 'Ljava/', 'Ljavax/', 'Lkotlin/', 'Lkotlinx/', 'Lcom/google/', 'Lcom/facebook/', 'Lokhttp3/', 'Lokio/',
  'Lretrofit2/', 'Lcom/squareup/', 'Lio/reactivex/', 'Lio/flutter/', 'Lorg/apache/', 'Lorg/bouncycastle/', 'Lorg/conscrypt/', 'Lcom/bumptech/', 'Lcom/airbnb/',
  'Lcom/unity3d/', 'Lcom/adjust/', 'Lcom/appsflyer/', 'Lcom/amazonaws/', 'Lcom/fasterxml/', 'Lorg/jetbrains/', 'Ldagger/', 'Lio/sentry/', 'Lcom/crashlytics/',
  'Lcom/onesignal/', 'Lcom/mixpanel/', 'Lorg/greenrobot/', 'Lcom/microsoft/', 'Lcom/ironsource/', 'Lcom/applovin/', 'Lcom/vungle/', 'Lcom/chartboost/', 'Lio/grpc/',
  'Lorg/slf4j/', 'Lorg/json/', 'Lorg/chromium/', 'Lcom/tencent/', 'Lcom/baidu/', 'Lcom/alipay/', 'Lcom/umeng/', 'Lcom/huawei/', 'Lcom/xiaomi/', 'Lio/realm/',
  'Lcom/reactnative/', 'Lcom/swmansion/', 'Lorg/xmlpull/', 'Lorg/w3c/', 'Lorg/xml/', 'Lbolts/', 'Lcom/braze/', 'Lcom/segment/', 'Lcom/stripe/', 'Lcom/paypal/'];
const isLibraryClass = t => LIB_PREFIXES.some(p => t.startsWith(p));

/**
 * R8/ProGuard renames third-party library classes just like app classes (Material becomes `Lc/c/a/a/…`),
 * so a package-prefix list alone cannot tell them apart. A class is "obfuscated-looking" when its leading
 * package segment is a single character, or a two-character one followed by another short segment
 * (`Lio/flutter/…` is a real package; `Lio/a/b;` is not). Default-package classes with a 1–2 character
 * name count too.
 */
export function looksObfuscated(type) {
  const segs = String(type).replace(/^L|;$/g, '').split('/');
  if (segs.length === 1) return segs[0].length <= 2;
  if (segs[0].length === 1) return true;
  return segs[0].length === 2 && segs[1].length <= 2;
}

/**
 * Package directories ("com/foo/app") that belong to the app itself: the manifest package plus the package
 * of every component the manifest names. Components contributed by library manifests (androidx, Firebase …)
 * are skipped so they cannot turn a library package into "app" code.
 */
export function appNamespaces(pkg, application) {
  const dirs = new Set();
  const add = fqn => {
    const t = `L${String(fqn).replace(/\./g, '/')};`;
    if (isLibraryClass(t)) return;
    const dir = String(fqn).split('.').slice(0, -1).join('/');
    if (dir.includes('/')) dirs.add(dir);
  };
  if (pkg && pkg !== 'unknown') { const d = pkg.replace(/\./g, '/'); if (d.includes('/') && !isLibraryClass(`L${d}/`)) dirs.add(d); }
  const qualify = n => (String(n).startsWith('.') ? pkg + n : String(n).includes('.') ? String(n) : `${pkg}.${n}`);
  for (const c of [application, ...(application.children || []).filter(x => ['activity', 'activity-alias', 'service', 'receiver', 'provider'].includes(x.tag))]) {
    if (c && c.attrs && typeof c.attrs.name === 'string' && c.attrs.name) add(qualify(c.attrs.name));
  }
  return [...dirs].map(d => `L${d}/`);
}

/**
 * 'library' (known prefix) | 'app' (under an app namespace, or an ordinary non-obfuscated package) |
 * 'unknown' (renamed class outside the app namespace: most likely renamed library code, but not provable).
 * 'unknown' is never downgraded in severity, so a renamed class cannot hide a finding.
 */
export function classOrigin(type, namespaces = []) {
  if (isLibraryClass(type)) return 'library';
  if (namespaces.some(n => type.startsWith(n))) return 'app';
  return looksObfuscated(type) ? 'unknown' : 'app';
}

const DEBUG_LIBS = [['Lcom/facebook/stetho/', 'Stetho'], ['Lcom/squareup/leakcanary/', 'LeakCanary'], ['Lleakcanary/', 'LeakCanary'],
  ['Lcom/readystatesoftware/chuck/', 'Chuck'], ['Lcom/chuckerteam/chucker/', 'Chucker'], ['Lcom/facebook/flipper/', 'Flipper'], ['Lcom/amitshekhar/', 'Android-Debug-Database']];

const TRUST_MANAGERS = new Set(['Ljavax/net/ssl/X509TrustManager;', 'Ljavax/net/ssl/X509ExtendedTrustManager;', 'Ljavax/net/ssl/TrustManager;']);
const HOST_VERIFIERS = new Set(['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']);
const CONTEXT_CLASSES = ['Landroid/content/Context;', 'Landroid/content/ContextWrapper;', 'Landroid/app/Activity;', 'Landroid/app/Service;', 'Landroid/app/Application;', 'Landroid/view/ContextThemeWrapper;'];

const NAMESPACE_URL = /(w3\.org|apache\.org|xmlpull\.org|schemas\.|sun\.com|xml\.org|ietf\.org|iana\.org|purl\.org|ns\.adobe\.com|sax\.|jboss\.org|sourceforge\.net|oracle\.com|java\.com|opengis\.net|iso\.org|relaxng\.org|xmlsoap\.org|openxmlformats\.org|json-schema\.org|mozilla\.org|gnu\.org|eclipse\.org|jcp\.org|android\.com\/apk|googleapis\.com\/auth|google\.com\/schemas|example\.(com|org)|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2)/i;
const URL_HTTP = /^http:\/\/[^\s"'<>\\]{4,300}$/i;
const URL_FIREBASE = FIREBASE_DB_URL;       // shared with the --online probe; covers regional <db>.<region>.firebasedatabase.app instances
const PIN = /sha(256|1)\/[A-Za-z0-9+/]{27,44}={0,2}/;
const TYPE_DESC = /^\[*L[\w/$-]+;$|^[VZBSCIJFDL]{1,12}$/;

const pretty = t => t.replace(/^L|;$/g, '').replace(/\//g, '.');
const esc = s => String(s).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"');

/**
 * A string-pool entry that is base64 (standard or URL-safe) and decodes to ≥90 % printable ASCII is returned decoded so it can go through
 * the secrets engine (wrapped API keys, URLs, JSON config). Binary results — ciphertext, or a second obfuscation layer such as XOR — are
 * not text and are deliberately not recovered here.
 */
export function decodeBase64Text(s) {
  if (s.length < 24 || s.length > 2000 || !/^[A-Za-z0-9+/_-]+={0,2}$/.test(s)) return null;
  const b = Buffer.from(s, 'base64');
  if (b.length < 16) return null;
  let printable = 0;
  for (const c of b) if ((c >= 0x20 && c < 0x7f) || c === 9 || c === 10 || c === 13) printable++;
  return printable / b.length >= 0.9 ? b.toString('latin1').replace(/\r?\n|\r/g, ' ') : null;
}

// ── DEX API call rules ─────────────────────────────────────────────────────────────────────────────
const CALLS = new Map();
const on = (key, fn) => { if (!CALLS.has(key)) CALLS.set(key, []); CALLS.get(key).push(fn); };
const str = a => (a && a.k === 'str' ? a.v : null);
const num = a => (a && a.k === 'int' ? a.v : null);

on('Ljavax/crypto/Cipher;->getInstance', ([t]) => {
  const v = str(t); if (v === null) return;
  const out = [];
  if (/^(DES|DESede|TripleDES|3DES|RC2|RC4|ARCFOUR|Blowfish)(\/|$)/i.test(v)) out.push({ rule: 'android.dex.weak_cipher', evidence: `Cipher.getInstance("${v}")`, description: 'A broken or weak cipher is requested.' });
  if (/^AES$/i.test(v) || (/\/ECB\//i.test(v) && !/^RSA/i.test(v))) out.push({ rule: 'android.dex.ecb_mode', evidence: `Cipher.getInstance("${v}")`, description: 'ECB mode (or the provider default for a bare "AES", which is ECB) leaks plaintext patterns.' });
  return out;
});
on('Ljava/security/MessageDigest;->getInstance', ([t]) => {
  const v = str(t);
  if (v !== null && /^(MD2|MD4|MD5|SHA-?1)$/i.test(v)) return [{ rule: 'android.dex.weak_hash', evidence: `MessageDigest.getInstance("${v}")`, description: 'A collision-prone hash is used; fine for checksums, not for security decisions.', confidence: 'medium' }];
});
on('Ljavax/net/ssl/SSLContext;->getInstance', ([t]) => {
  const v = str(t);
  if (v !== null && /^(SSL|SSLv2|SSLv3|TLSv1|TLSv1\.0|TLSv1\.1)$/i.test(v)) return [{ rule: 'android.dex.weak_tls_protocol', evidence: `SSLContext.getInstance("${v}")`, description: 'An outdated protocol version is requested.' }];
});
on('Ljavax/crypto/spec/SecretKeySpec;-><init>', a => {
  if (a[1] && a[1].k === 'bytes') return [{ rule: 'android.dex.hardcoded_key', evidence: `new SecretKeySpec("${mask(a[1].v)}", …)`, description: 'The key bytes come from a string literal in the code.' }];
});
on('Ljavax/crypto/spec/IvParameterSpec;-><init>', a => {
  if (a[1] && a[1].k === 'bytes') return [{ rule: 'android.dex.static_iv', evidence: `new IvParameterSpec("${mask(a[1].v)}")`, description: 'The IV comes from a string literal, so it repeats on every encryption.' }];
});
on('Ljavax/crypto/spec/GCMParameterSpec;-><init>', a => {
  if (a[2] && a[2].k === 'bytes') return [{ rule: 'android.dex.static_gcm_nonce', evidence: `new GCMParameterSpec(…, "${mask(a[2].v)}")`, description: 'A constant GCM nonce breaks GCM completely when reused with a key.' }];
});
on('Ljava/security/SecureRandom;->setSeed', () => [{ rule: 'android.dex.insecure_random', evidence: 'SecureRandom.setSeed(…)', description: 'Seeding can make output predictable.', confidence: 'medium' }]);
for (const m of ['setAllowFileAccessFromFileURLs', 'setAllowUniversalAccessFromFileURLs']) {
  on(`Landroid/webkit/WebSettings;->${m}`, a => num(a[1]) === 1 ? [{ rule: 'android.dex.webview_file_access', evidence: `WebSettings.${m}(true)`, description: 'JavaScript loaded from file:// can read arbitrary local files or other origins.' }] : undefined);
}
on('Landroid/webkit/WebSettings;->setMixedContentMode', a => num(a[1]) === 0 ? [{ rule: 'android.dex.webview_mixed_content', evidence: 'WebSettings.setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW)', description: 'HTTP sub-resources may load inside HTTPS pages.' }] : undefined);
on('Landroid/webkit/WebView;->setWebContentsDebuggingEnabled', a => num(a[0]) === 1 ? [{ rule: 'android.dex.webview_debugging', evidence: 'WebView.setWebContentsDebuggingEnabled(true)', description: 'Any page in the WebView can be inspected and scripted over USB.', confidence: 'medium' }] : undefined);
on('Landroid/webkit/WebView;->addJavascriptInterface', () => [{ rule: 'android.dex.webview_js_interface', evidence: 'WebView.addJavascriptInterface(…)', description: 'Page JavaScript can call into the app; dangerous if untrusted content is ever loaded.', confidence: 'medium' }]);
on('Landroid/webkit/SslErrorHandler;->proceed', (a, c) => c.method === 'onReceivedSslError' ? [{ rule: 'android.dex.webview_ssl_proceed', evidence: `${pretty(c.cls)}#onReceivedSslError`, description: 'The WebViewClient continues loading after a TLS error, defeating certificate validation.' }] : undefined);
for (const cls of CONTEXT_CLASSES) {
  for (const m of ['openFileOutput', 'getSharedPreferences', 'getDir', 'openOrCreateDatabase']) {
    on(`${cls}->${m}`, a => {
      const mode = num(a[2]);
      return mode !== null && (mode & 3) ? [{ rule: 'android.dex.world_accessible_storage', evidence: `${m}(…, mode=${mode})`, description: 'MODE_WORLD_READABLE/WRITEABLE makes the file reachable by every other app.' }] : undefined;
    });
  }
}
for (const m of ['getExternalStorageDirectory', 'getExternalStoragePublicDirectory']) {
  on(`Landroid/os/Environment;->${m}`, () => [{ rule: 'android.dex.external_storage', evidence: `Environment.${m}()`, description: 'Data written here is readable by other apps (and users); review what is stored.', confidence: 'medium' }]);
}
for (const c of ['DexClassLoader', 'InMemoryDexClassLoader']) {
  on(`Ldalvik/system/${c};-><init>`, () => [{ rule: 'android.dex.dynamic_code_loading', evidence: `new ${c}(…)`, description: 'Code is loaded at runtime; if the source is writable or remote it can be replaced.', confidence: 'medium' }]);
}
// PathClassLoader is how Android (and every multidex / split / plugin framework) loads the app's own installed code,
// so the constructor alone is not a signal. Report it only when the constant path is outside app-private storage.
on('Ldalvik/system/PathClassLoader;-><init>', ([, path]) => {
  const v = str(path);
  if (v === null || !/^(\/sdcard\/|\/storage\/|\/mnt\/|\/data\/local\/tmp|https?:)/i.test(v)) return;
  return [{ rule: 'android.dex.dynamic_code_loading', evidence: `new PathClassLoader("${esc(v).slice(0, 80)}", …)`, description: 'Code is loaded at runtime from a location other apps or the network can write to; it can be replaced.', confidence: 'medium' }];
});
on('Ljava/lang/Runtime;->exec', () => [{ rule: 'android.dex.runtime_exec', evidence: 'Runtime.exec(…)', description: 'Shell commands are executed.', confidence: 'medium' }]);
for (const m of ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number']) {
  on(`Landroid/telephony/TelephonyManager;->${m}`, () => [{ rule: 'android.dex.device_identifiers', evidence: `TelephonyManager.${m}()`, description: 'Persistent hardware/subscriber identifiers are read.' }]);
}
// JWT / HMAC signing secrets passed as constants (existing SecretKeySpec rule covers hand-rolled HMAC).
for (const [key, from, short] of [
  ['Lio/jsonwebtoken/JwtBuilder;->signWith', 1, 'JwtBuilder.signWith'],
  ['Lio/jsonwebtoken/JwtParser;->setSigningKey', 1, 'JwtParser.setSigningKey'],
  ['Lio/jsonwebtoken/JwtParserBuilder;->setSigningKey', 1, 'JwtParserBuilder.setSigningKey'],
  ['Lio/jsonwebtoken/security/Keys;->hmacShaKeyFor', 0, 'Keys.hmacShaKeyFor'],
  ['Lcom/auth0/jwt/algorithms/Algorithm;->HMAC256', 0, 'Algorithm.HMAC256'],
  ['Lcom/auth0/jwt/algorithms/Algorithm;->HMAC384', 0, 'Algorithm.HMAC384'],
  ['Lcom/auth0/jwt/algorithms/Algorithm;->HMAC512', 0, 'Algorithm.HMAC512'],
  ['Lcom/nimbusds/jose/crypto/MACSigner;-><init>', 1, 'MACSigner'],
  ['Lcom/nimbusds/jose/crypto/MACVerifier;-><init>', 1, 'MACVerifier'],
]) {
  on(key, args => {
    const a = constantSecretArg(args, from);
    return a ? [{ rule: 'android.dex.hardcoded_jwt_secret', evidence: `${short}("${mask(a.v)}")`, description: 'The signing secret is a string literal in the code, so anyone with the app can forge tokens.' }] : undefined;
  });
}
// Resilience and behavior indicators are not findings by themselves (see resilience.js / behavior.js), so they have no CALLS rule; they only need to be watched.
const WATCH = new Set([...CALLS.keys(), ...SIGNAL_KEYS.keys(), ...RESILIENCE_CALLS.keys(), ...BEHAVIOR.keys(), RUNTIME_EXEC]);

/** Runs every single-call rule registered for a callee key (exported so rules can be tested without a DEX fixture). */
export function applyCallRules(key, args, current = {}) {
  const out = [];
  for (const fn of CALLS.get(key) || []) { const hits = fn(args, current); if (hits) out.push(...hits); }
  return out;
}

// ── entry point ────────────────────────────────────────────────────────────────────────────────────
/**
 * @param {import('./zip.js').ZipArchive} zip
 * @param {{findings:import('./findings.js').Findings, notes:string[], newScanner:(base:object)=>import('./secrets.js').SecretScanner, prefix?:string, limits?:object}} ctx
 * @returns {object} app summary
 */
export function analyzeApk(zip, ctx) {
  const { findings, notes } = ctx;
  const pre = ctx.prefix || '';
  const at = n => `${pre}${n}`;
  const manifestEntry = zip.entry('AndroidManifest.xml');
  if (!manifestEntry) throw new Error('AndroidManifest.xml not found — not an APK');
  const raw = zip.read(manifestEntry, 32 * MB);
  // Binary XML (APK) or aapt2 protobuf XML (App Bundle modules); both decode to the same element tree.
  const manifest = parseBinaryXml(raw);
  if (!manifest) throw new Error('AndroidManifest.xml is neither Android binary XML nor an aapt2 protobuf manifest (is this an unpacked project?)');
  if (manifest.tag !== 'manifest') throw new Error('AndroidManifest.xml has no <manifest> element');
  const featureModule = !!ctx.featureModule;   // a non-base bundle module: app-level manifest defaults do not apply to it, they come from the base module

  const pkg = String(manifest.attrs.package || 'unknown');
  const base = { app: pkg };
  const scanner = ctx.newScanner(base);
  const usesSdk = manifest.children.find(c => c.tag === 'uses-sdk');
  const minSdk = usesSdk && Number.isFinite(usesSdk.attrs.minSdkVersion) ? usesSdk.attrs.minSdkVersion : null;
  const targetSdk = usesSdk && Number.isFinite(usesSdk.attrs.targetSdkVersion) ? usesSdk.attrs.targetSdkVersion : null;
  const application = manifest.children.find(c => c.tag === 'application') || { attrs: {}, children: [] };
  const app = {
    platform: 'android', package: pkg, version_name: manifest.attrs.versionName ?? null, version_code: manifest.attrs.versionCode ?? null,
    min_sdk: minSdk, target_sdk: targetSdk, debuggable: application.attrs.debuggable === true,
    permissions: [], components: { activity: 0, service: 0, receiver: 0, provider: 0 }, dex_files: [], native_libs: [], native_hardening: null, libraries: [],
    signing: null, frameworks: [], protections: [], _detected_dependencies: [],
    ...(ctx.module ? { module: ctx.module } : {}),
  };
  const namespaces = appNamespaces(pkg, application);
  const urls = new Map();          // url -> artifact
  const addUrl = (u, a) => { if (!urls.has(u)) urls.set(u, a); };
  const hosts = new RemoteHostCollector();       // remote hosts: every URL / IP / domain in the strings of the package (binary/lib/hosts.js)
  let pinning = false;

  manifestChecks({ manifest, application, app, base, findings, at, targetSdk, minSdk, scanner, featureModule });
  const xmlRoots = resourceXml(zip, at, scanner, notes);
  networkSecurityChecks({ xmlRoots, base, findings, at, hosts, flags: { setPinned: () => { pinning = true; } } });
  hybridChecks({ xmlRoots, base, findings, at });

  // string resources
  const arsc = zip.entry('resources.arsc') || zip.entry('resources.pb');       // resources.pb: the App Bundle (protobuf) form of the same table
  if (arsc) {
    try {
      const buf = zip.read(arsc, 128 * MB);
      const seen = new Set(); const lines = [];
      for (const s of (arsc.name === 'resources.pb' ? parseResourceTableStrings(buf) : parseArscStrings(buf))) {
        const k = `${s.name}\0${s.value}`;
        if (seen.has(k) || !s.value) continue;
        seen.add(k);
        if (s.value.length >= 8 || /key|secret|token|pass|pwd|auth|_id$/i.test(s.name)) lines.push(`${s.name} = "${esc(s.value)}"`);
        hosts.addText(s.value, at(arsc.name));
        if (/^https?:\/\//i.test(s.value)) addUrl(s.value, at(arsc.name));
        captureFirebaseResource(app, s.name, s.value);
      }
      scanner.add(at('res/values/strings.xml'), lines);
    } catch (e) { gap(notes, `${at(arsc.name)}: string resources not analysed (${e.message}).`); }
  }

  // code
  const behavior = new BehaviorCollector();
  const dexProtections = new DexProtectionCollector();
  for (const e of zip.find(/^classes\d*\.dex$/).slice(0, 30)) {
    try {
      const dex = new Dex(zip.read(e, 160 * MB), e.name);
      app.dex_files.push(e.name);
      dexProtections.add(dex);
      collectThirdPartyNamespaces(dex, e.name, app._detected_dependencies);
      if (analyzeDex(dex, { findings, base, at, scanner, addUrl, namespaces, behavior, hosts })) pinning = true;
    } catch (err) { gap(notes, `${at(e.name)}: code not analysed (${err.message}).`); }
  }
  if (!app.dex_files.length && !featureModule) notes.push(`${at('classes.dex')}: no DEX code found.`);
  if (app.dex_files.length) app.behavior = behavior.summary();

  nativeLibraries(zip, { findings, base, at, scanner, notes, app, hosts, components: ctx.components || null });
  protectionChecks(zip, { dex: app.dex_files.length ? dexProtections : null, app, base, findings, at, notes });
  if (!ctx.module) signing(zip, { findings, base, at, app, minSdk });      // bundle modules carry no signature of their own
  libraries(zip, app);

  // cross-platform frameworks: React Native / Hermes, Flutter, Unity, Xamarin / .NET (runs before URL aggregation: it feeds addUrl)
  const fw = analyzeFrameworks(zip, { platform: 'android', findings, base, scanner, notes, at, addUrl: (u, a) => { addUrl(u, a); hosts.addText(u, 'cross-platform framework code'); } });
  app.cross_platform = fw.list;
  const remoteHosts = hosts.summary();
  if (remoteHosts) app.remote_hosts = remoteHosts;

  // cleartext endpoints / firebase / pinning (collected from DEX + resources)
  const http = [], firebase = [];
  for (const [u, a] of urls) {
    if (URL_FIREBASE.test(u)) firebase.push(u);
    else if (URL_HTTP.test(u) && !NAMESPACE_URL.test(u)) http.push(u);
    if (PIN.test(u)) pinning = true;
  }
  // Severity follows what the platform enforces: from targetSdk 28 cleartext is blocked unless the manifest or the network security config allows it.
  const cleartextAllowed = application.attrs.usesCleartextTraffic === true ||
    (application.attrs.usesCleartextTraffic === undefined && application.attrs.networkSecurityConfig === undefined && targetSdk !== null && targetSdk < 28) ||
    findings.list.some(f => f.app === pkg && f.rule === 'android.nsc.cleartext');
  if (http.length) findings.add('android.dex.cleartext_urls', { ...base, artifact: at('classes.dex'), severity: cleartextAllowed ? 'medium' : 'low',
    description: `${http.length} http:// endpoint(s) are hardcoded; traffic to them is unencrypted.${cleartextAllowed ? ' The app permits cleartext traffic, so nothing stops these requests.' : ' The platform blocks cleartext traffic for this app by default, so these requests fail unless a library or the code opts out; many such strings are documentation or SDK URLs.'}`, evidence: http.slice(0, 25), evidence_total: http.length, confidence: 'medium' });
  for (const u of firebase) onlineData(app).dbUrls.add(u);
  if (firebase.length) findings.add('android.dex.firebase_urls', { ...base, artifact: at('resources.arsc'), description: 'The app talks to Firebase Realtime Database. Misconfigured rules are a very common source of data leaks; ubel-mobile does not contact the network unless --online is given, so the rules were not tested.', evidence: [...new Set(firebase)].slice(0, 10) });
  if (!pinning && !featureModule) findings.add('android.network.no_pinning', { ...base, artifact: at('AndroidManifest.xml'), description: 'No pin-set, OkHttp CertificatePinner, TrustKit or hardcoded pin hash was found.', evidence: [], confidence: 'low', key: 'nopin' });

  // everything else shipped in the package
  const handled = /^(assets\/(?:[^/]+\/)*lib\/[^/]+\/[^/]+\.so$|classes\d*\.dex|AndroidManifest\.xml|resources\.(arsc|pb)|META-INF\/|lib\/|res\/(?!raw\/)|r\/|kotlin\/|okhttp3\/|DebugProbesKt\.bin)/;
  const rest = zip.entries.filter(e => !e.isDir && !handled.test(e.name) && !fw.handled.has(e.name));
  scanBundledFiles(zip, rest, { findings, scanner, base, notes, relName: at, limits: ctx.limits });
  detectFrameworks(zip, app);
  scanner.run();
  if (scanner.truncated) gap(notes, `${pkg}: secret scanning stopped at its line budget; some strings were not scanned.`);
  return app;
}

// ── manifest ───────────────────────────────────────────────────────────────────────────────────────
function manifestChecks({ manifest, application, app, base, findings, at, targetSdk, minSdk, scanner, featureModule = false }) {
  const art = at('AndroidManifest.xml');
  const A = application.attrs;
  if (A.debuggable === true) findings.add('android.manifest.debuggable', { ...base, artifact: art, description: 'android:debuggable="true" lets anyone attach a debugger, read the app’s private files with run-as and bypass many protections.', evidence: ['android:debuggable="true"'] });
  if (A.testOnly === true) findings.add('android.manifest.test_only', { ...base, artifact: art, description: 'android:testOnly="true" marks a development build.', evidence: ['android:testOnly="true"'] });
  if (!featureModule && A.allowBackup !== false) {
    const hasCfg = A.fullBackupContent !== undefined || A.dataExtractionRules !== undefined;
    // adb backup excludes app data by default for apps targeting Android 12 (API 31)+; what remains is the encrypted cloud / device-transfer backup.
    const adbOpen = targetSdk === null || targetSdk < 31;
    const severity = !hasCfg && adbOpen ? 'medium' : hasCfg && !adbOpen ? 'info' : 'low';
    findings.add('android.manifest.backup', { ...base, artifact: art, severity,
      description: `allowBackup is ${A.allowBackup === true ? 'true' : 'not set (defaults to true)'}; app data can be copied off the device with ${adbOpen ? 'adb backup / ' : ''}cloud backup.${adbOpen ? '' : ' The app targets Android 12+, where adb backup excludes app data by default.'}${hasCfg ? ' A backup-rules file is configured: check it excludes tokens, databases and preferences that hold secrets.' : ''}`,
      evidence: [`android:allowBackup=${A.allowBackup === true ? '"true"' : '(default)'}`] });
  }
  if (A.usesCleartextTraffic === true) findings.add('android.manifest.cleartext', { ...base, artifact: art, description: 'usesCleartextTraffic="true" allows plain HTTP for the whole app.', evidence: ['android:usesCleartextTraffic="true"'] });
  else if (!featureModule && A.usesCleartextTraffic === undefined && A.networkSecurityConfig === undefined && targetSdk !== null && targetSdk < 28) {
    findings.add('android.manifest.cleartext_default', { ...base, artifact: art, description: `targetSdkVersion ${targetSdk} permits cleartext traffic by default and no network security config overrides it.`, evidence: [`targetSdkVersion=${targetSdk}`] });
  }
  if (A.requestLegacyExternalStorage === true) findings.add('android.manifest.legacy_storage', { ...base, artifact: art, description: 'requestLegacyExternalStorage="true" keeps broad access to shared storage.', evidence: ['android:requestLegacyExternalStorage="true"'] });
  if (manifest.attrs.sharedUserId) findings.add('android.manifest.shared_user_id', { ...base, artifact: art, description: `sharedUserId="${manifest.attrs.sharedUserId}" runs this app in the same sandbox as every app signed with the same key and sharing the id.`, evidence: [String(manifest.attrs.sharedUserId)] });
  if (!featureModule && minSdk !== null && minSdk < 24) findings.add('android.manifest.min_sdk', { ...base, artifact: art, severity: minSdk < 21 ? 'medium' : 'low', description: `minSdkVersion is ${minSdk}; devices running such releases miss years of security fixes and sandbox hardening.`, evidence: [`minSdkVersion=${minSdk}`] });
  if (!featureModule && targetSdk !== null && targetSdk < 33) findings.add('android.manifest.target_sdk', { ...base, artifact: art, severity: targetSdk < 29 ? 'medium' : 'low', description: `targetSdkVersion is ${targetSdk}; newer API levels enforce stricter defaults (exported components, scoped storage, cleartext, background limits) that this app opts out of.`, evidence: [`targetSdkVersion=${targetSdk}`] });

  // permissions
  const perms = manifest.children.filter(c => c.tag === 'uses-permission' || c.tag === 'uses-permission-sdk-23').map(c => String(c.attrs.name || ''));
  app.permissions = [...new Set(perms)];
  const short = p => p.replace(/^android\.permission\./, '');
  const risky = app.permissions.filter(p => RISKY_PERMS.has(short(p)));
  const dangerous = app.permissions.filter(p => p.startsWith('android.permission.') && DANGEROUS_PERMS.has(short(p)));
  if (risky.length) findings.add('android.manifest.risky_permissions', { ...base, artifact: art, description: 'These permissions give the app unusually broad power over the device or the user’s data.', evidence: risky });
  if (dangerous.length) findings.add('android.manifest.permissions', { ...base, artifact: art, description: `${dangerous.length} runtime (dangerous) permission(s) requested.`, evidence: dangerous.map(short) });

  const weak = manifest.children.filter(c => c.tag === 'permission' && Number.isFinite(c.attrs.protectionLevel) && (c.attrs.protectionLevel & 0xf) <= 1).map(c => `${c.attrs.name} (protectionLevel=${c.attrs.protectionLevel & 0xf ? 'dangerous' : 'normal'})`);
  if (weak.length) findings.add('android.manifest.weak_permission', { ...base, artifact: art, description: 'Any app can request a "normal" permission and the user can be prompted into granting a "dangerous" one, so these do not protect the components that rely on them.', evidence: weak });

  // components
  const qualify = n => (n ? (String(n).startsWith('.') ? app.package + n : String(n).includes('.') ? String(n) : `${app.package}.${n}`) : '(unnamed)');
  const exportedActs = [], deepLinks = [], unverified = [];
  for (const tag of ['activity', 'activity-alias', 'service', 'receiver', 'provider']) {
    for (const c of application.children.filter(x => x.tag === tag)) {
      const key = tag === 'activity-alias' ? 'activity' : tag;
      app.components[key]++;
      const filters = c.children.filter(x => x.tag === 'intent-filter');
      const exp = c.attrs.exported === true || (c.attrs.exported === undefined && (tag === 'provider' ? (targetSdk ?? 99) < 17 : filters.length > 0));
      const name = qualify(c.attrs.name);
      const actions = filters.flatMap(f => f.children.filter(x => x.tag === 'action').map(x => String(x.attrs.name || '')));
      const cats = filters.flatMap(f => f.children.filter(x => x.tag === 'category').map(x => String(x.attrs.name || '')));
      const launcher = actions.includes('android.intent.action.MAIN') && cats.includes('android.intent.category.LAUNCHER');
      for (const f of filters) {
        if (!f.children.some(x => x.tag === 'category' && x.attrs.name === 'android.intent.category.BROWSABLE')) continue;
        if (f.attrs.autoVerify === true) {        // remembered for the opt-in --online assetlinks.json check
          const datas = f.children.filter(x => x.tag === 'data');
          if (datas.some(d => /^https?$/i.test(String(d.attrs.scheme || '')))) collectVerifyHosts(app, datas.filter(d => d.attrs.host).map(d => d.attrs.host));
        }
        for (const d of f.children.filter(x => x.tag === 'data' && x.attrs.scheme)) {
          const entry = `${d.attrs.scheme}://${d.attrs.host || ''}${d.attrs.pathPrefix || d.attrs.path || ''} → ${name}`;
          deepLinks.push(entry);
          if (/^https?$/i.test(String(d.attrs.scheme)) && f.attrs.autoVerify !== true) unverified.push(entry);
        }
      }
      if (!exp) continue;
      if (tag === 'provider') {
        const guarded = c.attrs.permission || (c.attrs.readPermission && c.attrs.writePermission);
        if (!guarded) findings.add('android.manifest.exported_provider', { ...base, artifact: art, key: name,
          description: `${name} (authorities: ${c.attrs.authorities || 'n/a'}) is exported with no permission${c.attrs.grantUriPermissions === true ? ' and grantUriPermissions="true"' : ''}; any app can query it${c.attrs.readPermission || c.attrs.writePermission ? ' (only one direction is guarded)' : ''}.`,
          evidence: [name] });
      } else if (!c.attrs.permission) {
        if (tag === 'service') findings.add('android.manifest.exported_service', { ...base, artifact: art, key: name, description: `${name} is exported with no permission; any app can start or bind to it.`, evidence: [name] });
        else if (tag === 'receiver') {
          const sys = actions.length > 0 && actions.every(a => SYSTEM_ACTION.test(a));
          findings.add('android.manifest.exported_receiver', { ...base, artifact: art, key: name, severity: sys ? 'low' : 'medium',
            description: `${name} is exported with no permission${sys ? ' (it listens to system broadcasts only, which is normal, but explicit intents from other apps still reach it)' : '; any app can send it broadcasts'}.`, evidence: [name] });
        } else if (!launcher) exportedActs.push(name);
      }
    }
  }
  if (exportedActs.length) findings.add('android.manifest.exported_activity', { ...base, artifact: art, description: `${exportedActs.length} exported activit${exportedActs.length === 1 ? 'y is' : 'ies are'} reachable by other apps and by links.`, evidence: exportedActs.slice(0, 30), evidence_total: exportedActs.length });
  if (deepLinks.length) findings.add('android.manifest.deeplinks', { ...base, artifact: art, severity: unverified.length ? 'low' : 'info',
    description: `${deepLinks.length} browsable link(s) open the app.${unverified.length ? ` ${unverified.length} http(s) link(s) lack android:autoVerify, so another app can claim them.` : ''}`, evidence: deepLinks.slice(0, 30), evidence_total: deepLinks.length });

  // meta-data → secrets
  const lines = [];
  const walkMeta = n => { for (const c of n.children) { if (c.tag === 'meta-data' && typeof c.attrs.value === 'string' && c.attrs.name) lines.push(`${c.attrs.name} = "${esc(c.attrs.value)}"`); walkMeta(c); } };
  walkMeta(application);
  scanner.add(art, lines);
}

// ── res/xml: network security config, backup rules, Cordova config ─────────────────────────────────
// Resource-obfuscation tools (Redex "resource file renaming", AndResGuard …) move and rename res/ files: res/xml/network_security_config.xml
// becomes res/Ab.xml, res/xml/a.xml or r/a.xml. The root element identifies the file whatever it is called, so every binary XML under res/ and
// r/ is opened and kept when its root is one the checks below use; only files in a real res/xml*/ directory are also secret-scanned.
const RES_XML_ROOTS = new Set(['network-security-config', 'widget', 'full-backup-content', 'data-extraction-rules', 'automotive-app', 'paths']);
const MAX_RES_XML_PROBES = 6000, MAX_RES_XML_PROBE_BYTES = 256 * 1024;

function resourceXml(zip, at, scanner, notes) {
  const roots = [];
  // layouts, drawables, menus … keep their directory and never hold these configs, so they are not probed
  const entries = zip.find(/^(res|r)\/(?:.+\/)?[^/]+\.xml$/i).filter(e => !/^res\/(raw|anim|animator|color|drawable|font|interpolator|layout|menu|mipmap|navigation|transition)[^/]*\//i.test(e.name));
  const inXmlDir = e => /^res\/xml[^/]*\/[^/]+\.xml$/i.test(e.name) || /^r\/[^/]+\.xml$/i.test(e.name);
  const ordered = [...entries.filter(inXmlDir), ...entries.filter(e => !inXmlDir(e))];
  let probes = 0;
  for (const e of ordered) {
    const known = inXmlDir(e);
    if (known ? roots.length >= 400 : (probes >= MAX_RES_XML_PROBES || e.usize > MAX_RES_XML_PROBE_BYTES)) continue;
    if (!known) probes++;
    const buf = zip.tryRead(e, known ? 4 * MB : MAX_RES_XML_PROBE_BYTES);
    if (!buf || !isBinaryXml(buf)) continue;
    try {
      const root = parseBinaryXml(buf);
      if (!root) continue;
      if (!known && !RES_XML_ROOTS.has(root.tag)) continue;
      roots.push({ name: e.name, root });
      const lines = axmlToLines(root);
      if (lines.length < 5000) scanner.add(at(e.name), lines);
    } catch { if (known) gap(notes, `${at(e.name)}: unreadable binary XML.`); }
  }
  return roots;
}

function networkSecurityChecks({ xmlRoots, base, findings, at, flags, hosts = null }) {
  const nsc = xmlRoots.find(x => x.root.tag === 'network-security-config');
  if (!nsc) return;
  const art = at(nsc.name);
  const r = nsc.root;
  const baseCfg = r.children.find(c => c.tag === 'base-config');
  const domains = r.children.filter(c => c.tag === 'domain-config');
  const hostsOf = d => findAll(d, 'domain').map(x => x.text.trim()).filter(Boolean);
  if (hosts) for (const d of domains) for (const h of hostsOf(d)) hosts.addText(h, `${art} (network security config)`);      // domains the app declares rules for
  if (baseCfg && baseCfg.attrs.cleartextTrafficPermitted === true) findings.add('android.nsc.cleartext', { ...base, artifact: art, key: 'base', description: 'base-config permits cleartext HTTP for every domain without its own rule.', evidence: ['<base-config cleartextTrafficPermitted="true">'] });
  const clearDomains = domains.filter(d => d.attrs.cleartextTrafficPermitted === true).flatMap(hostsOf);
  if (clearDomains.length) findings.add('android.nsc.cleartext', { ...base, artifact: art, key: 'domains', severity: 'low', description: 'These domains are allowed cleartext HTTP.', evidence: clearDomains });
  const userCa = [];
  for (const cfg of [baseCfg, ...domains].filter(Boolean)) {
    for (const ta of cfg.children.filter(c => c.tag === 'trust-anchors')) {
      if (ta.children.some(c => c.tag === 'certificates' && c.attrs.src === 'user')) userCa.push(cfg.tag === 'base-config' ? 'base-config' : hostsOf(cfg).join(', ') || 'domain-config');
    }
  }
  if (userCa.length) findings.add('android.nsc.user_ca', { ...base, artifact: art, description: 'Certificates the user (or malware, or a corporate proxy) installed are trusted, so TLS can be intercepted.', evidence: userCa });
  const now = Date.now();
  for (const ps of findAll(r, 'pin-set')) {
    flags.setPinned();
    const exp = ps.attrs.expiration;
    if (typeof exp === 'string' && Date.parse(exp) < now) findings.add('android.nsc.pin_expired', { ...base, artifact: art, key: exp, description: `A pin-set expired on ${exp}; once expired, pinning is silently ignored.`, evidence: [exp] });
  }
}

function hybridChecks({ xmlRoots, base, findings, at }) {
  const cfg = xmlRoots.find(x => x.root.tag === 'widget');
  if (!cfg) return;
  const open = [...findAll(cfg.root, 'access').filter(a => a.attrs.origin === '*').map(() => '<access origin="*">'),
    ...findAll(cfg.root, 'allow-navigation').filter(a => a.attrs.href === '*').map(() => '<allow-navigation href="*">')];
  if (open.length) findings.add('android.cordova.access_origin', { ...base, artifact: at(cfg.name), description: 'The hybrid app may talk to, and navigate to, any origin; one XSS or malicious link exposes every Cordova plugin to attacker script.', evidence: [...new Set(open)] });
}

// ── DEX ────────────────────────────────────────────────────────────────────────────────────────────
export function analyzeDex(dex, { findings, base, at, scanner, addUrl, namespaces = [], behavior = null, hosts = null }) {
  const agg = new Aggregator(findings, base);
  const resil = new ResilienceCollector();
  const users = new Map();                       // string idx -> first class that loads it
  let current = null;
  const constLines = [], constWhere = [];
  const debugLibs = new Set();
  const customTm = new Set();
  let pinned = false;
  const signals = new MethodSignals();
  const strInfo = new Map();                     // string idx -> { label, jwt, schema } (memoised: const-string runs in every method)
  const info = idx => {
    let v = strInfo.get(idx);
    if (!v) {
      const str = dex.string(idx), c0 = str.charCodeAt(0);
      v = { res: classifyResilienceString(str), label: sensitiveLabel(str), jwt: isJwtLiteral(str) ? str : null, schema: (c0 === 99 || c0 === 67) ? schemaSensitive(str) : null };
      strInfo.set(idx, v);
    }
    return v;
  };
  // A JWT literal is only a leaked credential if its claims say so: public client keys (role "anon") and expired tokens go to a lower rule.
  const jwtHit = (origin, token, evidence, description) => {
    const j = classifyJwt(token);
    if (j.state === 'live') return agg.hit('android.dex.hardcoded_jwt', { origin, evidence, description });
    const why = j.state === 'public' ? `its role claim is "${j.role}", a public client role` : `it expired on ${new Date(j.exp * 1000).toISOString().slice(0, 10)}`;
    agg.hit('android.dex.hardcoded_jwt_public', { origin, evidence, description: `${description} It is probably not a live credential: ${why}.`, confidence: 'medium' });
  };
  // Encryption libraries make the plaintext-storage heuristics weaker evidence: the same API may be backed by them.
  let encryptedPrefs = false, sqlCipher = false;
  for (const def of dex.classes()) {
    if (def.type.startsWith('Landroidx/security/crypto/')) encryptedPrefs = true;
    else if (def.type.startsWith('Lnet/sqlcipher/') || def.type.startsWith('Lnet/zetetic/')) sqlCipher = true;
  }
  const storageNote = rule => (rule === 'android.dex.plaintext_prefs' && encryptedPrefs ? ' This app also ships androidx.security.crypto, so the preferences may be an EncryptedSharedPreferences instance.'
    : rule === 'android.dex.plaintext_database' && sqlCipher ? ' This app also ships SQLCipher, so the database may be encrypted.' : '');

  for (const def of dex.classes()) {
    const type = def.type;
    const origin = classOrigin(type, namespaces);
    resil.begin(type);
    for (const [p, label] of DEBUG_LIBS) if (type.startsWith(p)) debugLibs.add(label);
    let data;
    try { data = dex.classData(def); } catch { continue; }
    if (type.startsWith('Lcom/datatheorem/android/trustkit/') || type === 'Lokhttp3/CertificatePinner;') pinned = true;
    if (def.staticValuesOff) {
      try {
        for (const c of dex.staticConstants(def, data)) {
          if (c.kind === 'string' && c.value.length >= 6) {
            constLines.push(`${c.field} = "${esc(c.value)}"`); constWhere.push(pretty(type));
            if (credentialConstant(c.field, c.value)) agg.hit('android.dex.hardcoded_credential', { origin, evidence: `${pretty(type)}.${maskedConstant(c.field, c.value)}`, description: 'A constant whose name says password, secret or token holds what looks like a real value.', confidence: 'medium' });
            if (isJwtLiteral(c.value)) jwtHit(origin, c.value, `${pretty(type)}.${c.field} = JWT "${mask(c.value)}"`, 'A complete JSON Web Token is embedded as a constant; it may carry a valid identity or session.');
          }
          if (c.kind === 'bool' && c.value === true && c.field === 'DEBUG' && type.endsWith('/BuildConfig;')) {
            agg.hit('android.dex.build_debug', { origin, evidence: `${pretty(type)}.DEBUG = true`, description: 'A compiled BuildConfig says this is a debug build.' });
          }
        }
      } catch { /* malformed static values: skip */ }
    }
    const ifaces = dex.interfaces(def);
    const isTm = ifaces.some(i => TRUST_MANAGERS.has(i)) || def.superType === 'Ljavax/net/ssl/X509ExtendedTrustManager;';
    const isHv = ifaces.some(i => HOST_VERIFIERS.has(i));
    for (const m of data.methods) {
      if (!m.codeOff || m.idx >= dex.nMeth) continue;
      const key = dex.methodKey(m.idx);
      const name = key.slice(key.indexOf('->') + 2);
      if (isTm && (name === 'checkServerTrusted' || name === 'checkClientTrusted')) {
        const kind = dex.trivialKind(m.codeOff);
        if (kind === 'return-void' && name === 'checkServerTrusted') agg.hit('android.dex.trust_all_certs', { origin, evidence: pretty(type), description: 'checkServerTrusted is empty, so the TrustManager accepts any certificate chain.' });
        else if (name === 'checkServerTrusted' && origin === 'app') customTm.add(pretty(type));
      }
      if (isHv && name === 'verify') {
        const kind = dex.trivialKind(m.codeOff);
        if (kind === 'return-true' || kind === 'return-void') agg.hit('android.dex.allow_all_hostnames', { origin, evidence: pretty(type), description: 'verify() always succeeds, so any certificate is accepted for any host name.' });
      }
      current = { cls: type, method: name, origin };
      signals.reset();
      try {
        dex.walk(m.codeOff, {
          onString: idx => {
            if (!users.has(idx)) users.set(idx, type);
            const v = info(idx);
            if (v.res) resil.string(v.res);
            if (v.label) signals.label(v.label);
            if (v.jwt) jwtHit(origin, v.jwt, `JWT "${mask(v.jwt)}" in ${pretty(type)}#${name}`, 'A complete JSON Web Token is embedded in the code; it may carry a valid identity or session.');
            if (v.schema) agg.hit('android.dex.plaintext_database', { origin, evidence: `CREATE TABLE with a "${v.schema}" column in ${pretty(type)}`, description: `A table definition has a sensitive-looking column ("${v.schema}"); SQLite files are unencrypted unless SQLCipher or similar is used.${storageNote('android.dex.plaintext_database')}`, confidence: sqlCipher ? 'low' : 'medium' });
          },
          onField: fi => { if (origin !== 'library') resil.field(dex.fieldKey(fi)); },
          onInvoke: (k, args, mi) => {
            signals.call(k, args);
            resil.call(k, args);
            if (behavior) behavior.call(k, args, origin, () => dex.methodProto(mi));
            for (const h of applyCallRules(k, args, current)) agg.hit(h.rule, { origin: current.origin, evidence: `${h.evidence} in ${pretty(current.cls)}#${current.method}`, description: h.description, confidence: h.confidence });
          },
        }, WATCH);
      } catch { /* malformed code item: skip this method */ }
      // Heuristic verdicts for this method. Known library code is not the app's own logging/storage choice, so it is
      // skipped; renamed (unknown-origin) code is reported at low confidence because it may well be a library.
      if (origin !== 'library') {
        for (const h of signals.evaluate()) {
          const weak = origin === 'unknown' || (h.rule === 'android.dex.plaintext_prefs' && encryptedPrefs) || (h.rule === 'android.dex.plaintext_database' && sqlCipher);
          agg.hit(h.rule, { origin, evidence: `${h.evidence} in ${pretty(type)}#${name}`, description: `${h.description}${storageNote(h.rule)}`, confidence: weak ? 'low' : h.confidence });
        }
      }
    }
  }
  for (const f of dex.allFieldRefs()) {
    if (f.name === 'ALLOW_ALL_HOSTNAME_VERIFIER') agg.hit('android.dex.allow_all_hostnames', { origin: 'app', evidence: `${pretty(f.cls)}.ALLOW_ALL_HOSTNAME_VERIFIER`, description: 'The Apache "allow all" hostname verifier is referenced.' });
  }
  if (customTm.size) findings.add('android.dex.custom_trust_manager', { ...base, artifact: at(dex.name), description: `${customTm.size} custom TrustManager implementation(s) with a non-empty checkServerTrusted. Review them for complete chain and host-name validation.`, evidence: [...customTm].slice(0, 20), confidence: 'low' });
  if (debugLibs.size) findings.add('android.dex.debug_libraries', { ...base, artifact: at(dex.name), description: 'Development-time inspection libraries are packaged in this build.', evidence: [...debugLibs] });
  // Anti-debug / anti-emulator / root-detection: only a cluster of distinct indicators in one class counts (resilience.js); library code is skipped.
  for (const r of resil.results()) {
    const o = classOrigin(r.cls, namespaces);
    if (o === 'library') continue;
    agg.hit('android.dex.anti_analysis', { origin: o, evidence: `${pretty(r.cls)}: ${r.text}`, confidence: o === 'unknown' ? 'low' : 'medium',
      description: `A class combines several environment checks (${MIN_INDICATORS}+ distinct indicators: debugger, emulator, root or hooking-framework detection). The app tries to resist analysis; this is an inventory item, not a weakness, and such checks can be bypassed.` });
  }
  agg.flush(at(dex.name));

  // strings → secrets, URLs, pins
  const idxs = [], lines = [], b64Idx = [], b64Lines = [];
  for (let i = 0; i < dex.nStr; i++) {
    const s = dex.string(i);
    if (s.length < 8 || s.length > 2000) continue;
    if (hosts && s.indexOf('.') > 0) {
      const o = users.has(i) ? classOrigin(users.get(i), namespaces) : null;
      hosts.addText(s, `${at(dex.name)} · ${o === 'app' ? 'app code' : o === 'library' ? 'library code' : o === 'unknown' ? 'renamed classes' : 'not loaded by code'}`);
    }
    if (s.startsWith('http')) { if (URL_HTTP.test(s) || URL_FIREBASE.test(s)) addUrl(s, at(dex.name)); }
    if (!pinned && PIN.test(s)) pinned = true;
    const dec = b64Lines.length < 20000 ? decodeBase64Text(s) : null;       // base64-wrapped keys, URLs, JSON: scan what is inside
    if (dec) { b64Idx.push(i); b64Lines.push(dec); if (hosts) hosts.addText(dec, `${at(dex.name)} · base64 string`); if (URL_HTTP.test(dec.trim()) || URL_FIREBASE.test(dec.trim())) addUrl(dec.trim(), at(dex.name)); }
    if (TYPE_DESC.test(s)) continue;
    idxs.push(i); lines.push(s);
  }
  scanner.add(at(dex.name), lines, i => (users.has(idxs[i]) ? `string used by ${pretty(users.get(idxs[i]))}` : null));
  scanner.add(at(dex.name), constLines, i => `constant in ${constWhere[i]}`);
  scanner.add(at(dex.name), b64Lines, i => `base64-decoded string${users.has(b64Idx[i]) ? ` used by ${pretty(users.get(b64Idx[i]))}` : ''}`);
  return pinned;
}

// ── protections / obfuscation (APKiD-class) ────────────────────────────────────────────────────────
function protectionChecks(zip, { dex, app, base, findings, at, notes }) {
  const found = detectProtections(zip, dex);
  app.protections = found;
  if (!found.length) return;
  const packers = found.filter(p => p.kind === 'packer');
  for (const p of packers) if (p.confidence === 'high') gap(notes, `${p.name} packer detected: the original code is only available at runtime, so the DEX analysis covers the loader stub (${p.evidence[0]}).`);
  findings.add('android.protection.detected', { ...base, artifact: at('classes.dex'), key: 'protections',
    description: `This package was built with: ${found.map(p => `${p.name} [${p.kind}, ${p.confidence} confidence]`).join('; ')}.${found.some(p => p.note) ? ` ${[...new Set(found.map(p => p.note).filter(Boolean))].join(' ')}` : ''}`,
    evidence: found.map(p => `${p.name}: ${p.evidence[0]}`), confidence: 'medium', confidenceCap: false });
}

// ── native libraries ───────────────────────────────────────────────────────────────────────────────
const ABI_ORDER = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86', 'armeabi'];
const SKIP_STRINGS = /^(libapp\.so|libassembly-store|libxamarin-app|libmonodroid|libflutter|libc\+\+_shared|libhermes|libjsc|libmonosgen|libreactnativejni|libfbjni|libjscexecutor|libunity|libil2cpp|libmain|libbitmaps|libimagepipeline|libgifimage|libwebp|libyoga|libglog|libfolly|libv8)/;

const MAX_NATIVE_LIBS = 150;                 // distinct library names analysed (unchanged)
const MAX_NATIVE_BINARIES = 600;             // ABI copies analysed in total
const EXTRA_ABI_BUDGET = 512 * MB;           // bytes read for ABI copies other than the preferred one (those are only hardening-checked)

/**
 * Native libraries: hardening of EVERY ABI copy (lib/<abi>/<name>.so), and secret-scanning strings of the preferred copy.
 * An APK carries a separately built copy per ABI, so each is checked on its own; a library that is hardened for arm64-v8a can still
 * be missing its canary or PIE in x86. Findings name the exact `abi/library`; `app.native_hardening` holds the per-ABI table.
 * Exported so the policy can be exercised against a small archive without a full APK.
 */
export function nativeLibraries(zip, { findings, base, at, scanner, notes, app, hosts = null, components = null }) {
  const byName = new Map();                  // library key -> its ABI copies, preferred ABI first
  // Besides lib/<abi>/*.so, apps ship libraries under assets/…/lib/<abi>/ (loaded at runtime with System.load / a custom loader, which the
  // platform never inspects), so those are analysed as well; the copies keep their own group so lib/ and assets/ binaries never merge.
  for (const e of zip.find(/^(?:assets\/(?:[^/]+\/)*)?lib\/[^/]+\/[^/]+\.so$/)) {
    const [, loc, abi, name] = e.name.match(/^((?:assets\/(?:[^/]+\/)*)?lib)\/([^/]+)\/([^/]+)$/);
    const rank = ABI_ORDER.indexOf(abi) < 0 ? 99 : ABI_ORDER.indexOf(abi);
    const key = loc === 'lib' ? name : `${loc}/${name}`;
    if (!byName.has(key)) byName.set(key, []);
    byName.get(key).push({ e, abi, rank, name, loc });
  }
  for (const copies of byName.values()) copies.sort((a, b) => a.rank - b.rank || a.abi.localeCompare(b.abi));
  app.native_libs = [...new Set([...byName.values()].map(c => c[0].name))].sort().slice(0, 300);

  const records = [];
  const native = new NativeBehavior();
  const analyse = ({ e, abi, loc }, name, { strings }) => {
    const where = at(`${loc}/${abi}/${name}`);
    const buf = zip.tryRead(e, 128 * MB);
    if (!buf) { gap(notes, `${where}: native library could not be read (encrypted, corrupt or over the size limit).`); return 0; }
    if (!isElf(buf)) { notes.push(`${where}: not an ELF file; hardening flags not checked.`); return buf.length; }
    // components bundled in the library (version banners, Go modules, Rust crates): the preferred ABI copy of each library, whatever the
    // secret scan skips — a framework library such as libflutter.so is exactly where an embedded OpenSSL / SQLite / curl lives
    if (strings && components) components.add(buf, { name, where, notes });
    try {
      const elf = parseElf(buf);
      const rec = hardeningRecord(elf, { abi, library: name, path: where, size: buf.length });
      if (loc !== 'lib') rec.location = loc;       // runtime-loaded copy under assets/: named in the evidence so it is told apart from lib/<abi>/
      records.push(rec);
      // behavior of the preferred copy: imported functions, with call sites where the code can be scanned (ELF x86-64 / arm64, up to 96 MB)
      if (strings && elf.symbolsReadable) {
        try { native.add({ binary: name, origin: isVendorNative(name) ? 'library' : 'app', imports: elf.imports, providers: elf.importProviders, sites: buf.length <= 96 * MB ? elfCallSites(buf) : null }); }
        catch (err) { notes.push(`${where}: behavior inventory not built (${err.message}).`); }
      }
      if (!elf.symbolsReadable) notes.push(`${where}: dynamic symbol table not readable; stack canary and FORTIFY indicators were not assessed.`);
    } catch (err) { gap(notes, `${where}: ELF not readable (${err.message}); hardening flags not checked.`); }
    if (strings && !SKIP_STRINGS.test(name)) {
      const text = asciiStrings(buf, { min: 8, max: 400, limit: 40000 });
      scanner.add(where, text);
      if (hosts) hosts.addStrings(text, `${loc}/${abi}/${name}`);
    }
    return buf.length;
  };

  // pass 1 — the preferred ABI of every library: hardening + strings, exactly the coverage the scan always had
  let n = 0;
  const analysed = [];
  for (const [key, copies] of byName) {
    const name = copies[0].name;
    if (++n > MAX_NATIVE_LIBS) { gap(notes, `More than ${MAX_NATIVE_LIBS} native libraries: the rest were not analysed.`); break; }
    analysed.push([name, copies]);
    analyse(copies[0], name, { strings: true });
  }
  // pass 2 — the other ABI copies: hardening only, within a read budget so a large multi-ABI package cannot exhaust the archive's inflate limit
  let budget = EXTRA_ABI_BUDGET, total = analysed.length;
  const skipped = [];
  for (const [name, copies] of analysed) {
    for (const copy of copies.slice(1)) {
      if (total >= MAX_NATIVE_BINARIES || copy.e.usize > budget) { skipped.push(`${copy.loc === 'lib' ? '' : `${copy.loc}/`}${copy.abi}/${name}`); continue; }
      total++;
      budget -= analyse(copy, name, { strings: false });
    }
  }
  if (skipped.length) gap(notes, `Hardening of ${skipped.length} further ABI cop${skipped.length === 1 ? 'y' : 'ies'} was not assessed (read budget reached): ${skipped.slice(0, 5).join(', ')}${skipped.length > 5 ? ', …' : ''}.`);

  const order = abi => (ABI_ORDER.indexOf(abi) < 0 ? 99 : ABI_ORDER.indexOf(abi));
  records.sort((a, b) => a.library.localeCompare(b.library) || order(a.abi) - order(b.abi) || a.abi.localeCompare(b.abi));
  const evaluated = evaluateRecords(records);
  for (const g of groupFailures(evaluated)) {
    // Same attribution rule as DEX code: one finding per rule; it is about the app's own libraries when any are affected, and only when every
    // affected library is a framework / SDK binary is it reported one level lower.
    const own = g.records.map((r, i) => (isVendorNative(r.library) ? -1 : i)).filter(i => i >= 0);
    const vendorOnly = own.length === 0;
    const idx = vendorOnly ? g.records.map((_, i) => i) : own;
    const entries = idx.map(i => g.entries[i]), libs = idx.map(i => g.libraries[i]);
    const abis = [...new Set(idx.map(i => g.records[i].abi))].sort();
    const nb = entries.length, vendorExtra = g.records.length - nb;
    findings.add(g.rule, {
      ...base, artifact: at(`lib/…/${libs[0]}`), key: g.rule, origin: vendorOnly ? 'library' : 'app',
      description: `${g.text} (${nb} binar${nb === 1 ? 'y' : 'ies'} in ${abis.length} ABI${abis.length === 1 ? '' : 's'}: ${abis.join(', ')}).${vendorExtra > 0 ? ` ${vendorExtra} further binar${vendorExtra === 1 ? 'y is' : 'ies are'} framework or third-party SDK libraries that the app build does not control.` : ''}${vendorOnly ? ' All affected binaries are framework or third-party SDK libraries (severity lowered one level).' : ''}`,
      evidence: entries.slice(0, 30), evidence_total: nb,
      ...(g.confidence ? { confidence: g.confidence } : {}),
    });
  }
  app.native_hardening = records.length ? summarizeHardening(records, evaluated) : null;
  const behavior = native.into(app.behavior);
  if (behavior) app.behavior = behavior;
}

// ── signing ────────────────────────────────────────────────────────────────────────────────────────
export function bundleSigning(zip, ctx) { return signing(zip, { ...ctx, minSdk: null, bundle: true }); }

function signing(zip, { findings, base, at, app, minSdk, bundle = false }) {
  const certs = new Map();
  const schemes = new Set();
  const v1 = zip.find(/^META-INF\/[^/]+\.(RSA|DSA|EC)$/i);
  if (v1.length) schemes.add('v1');
  for (const e of v1.slice(0, 5)) {
    const buf = zip.tryRead(e, 1 * MB);
    if (!buf) continue;
    try { for (const der of certsFromPkcs7(buf)) { const c = describeCert(der); certs.set(c.sha256, c); } } catch { /* skip */ }
  }
  try {
    const blk = parseApkSigningBlock((o, l) => zip._read(o, l), zip.cdOffset);
    blk.schemes.forEach(s => schemes.add(s));
    for (const der of blk.certs) { try { const c = describeCert(der); certs.set(c.sha256, c); } catch { /* skip */ } }
  } catch { /* no signing block */ }
  app.signing = { schemes: [...schemes], certificates: [...certs.values()].map(c => ({ subject: c.subject, issuer: c.issuer, valid_to: c.valid_to, key: `${c.key_type}${c.key_bits ? ` ${c.key_bits}` : ''}`, signature_algorithm: c.signature_algorithm, sha256: c.sha256 })) };
  const art = at('META-INF/');
  if (!schemes.size) { if (!bundle) findings.add('android.signing.unsigned', { ...base, artifact: at('AndroidManifest.xml'), description: 'No v1, v2 or v3 signature was found; Android will refuse to install an unsigned package. Expected for a CI artifact that is signed in a later step; a problem only if this is the file that is distributed.', evidence: [] , key: 'unsigned' }); return; }
  for (const c of certs.values()) {
    if (/CN=Android Debug\b/i.test(c.subject)) findings.add('android.signing.debug_cert', { ...base, artifact: art, key: c.sha256, description: 'The certificate is the well-known Android debug certificate; its private key is public knowledge (or generated on every developer machine), so anyone can sign an update that Android treats as coming from this developer.', evidence: [c.subject, `sha256 ${c.sha256}`] });
    if (WEAK_SIG.test(c.signature_algorithm)) findings.add('android.signing.weak_algorithm', { ...base, artifact: art, key: c.sha256, description: `The certificate itself is signed with ${c.signature_algorithm}. Android pins an app to the signing key, not to the certificate's own signature, so this is hygiene rather than an exploitable weakness; the digest algorithm of the APK signature is what protects the package.`, evidence: [c.subject, c.signature_algorithm] });
    if ((c.key_type === 'rsa' || c.key_type === 'dsa') && typeof c.key_bits === 'number' && c.key_bits < 2048) findings.add('android.signing.weak_key', { ...base, artifact: art, key: c.sha256, description: `The signing key is ${c.key_type.toUpperCase()}-${c.key_bits}.`, evidence: [c.subject, `${c.key_type}-${c.key_bits}`] });
    if (c.expired) findings.add('android.signing.expired', { ...base, artifact: art, key: c.sha256, description: `The certificate expired on ${c.valid_to}. Android does not enforce certificate validity dates when installing or updating an app, so this does not stop the app working; Google Play and some enterprise stores do require a long validity.`, evidence: [c.subject, c.valid_to] });
  }
  const modern = ['v2', 'v3', 'v3.1'].some(s => schemes.has(s));
  if (bundle) return;                                  // an .aab is jar-signed with the upload key; the APK scheme rules below do not apply
  if (schemes.has('v1') && !modern) findings.add('android.signing.v1_only', { ...base, artifact: art, severity: minSdk !== null && minSdk >= 27 ? 'low' : undefined,
    description: `Only the JAR (v1) signature is present; it does not cover the whole file and is vulnerable to Janus-style tampering on Android 5.0–8.0.${minSdk !== null && minSdk >= 27 ? ` minSdkVersion is ${minSdk}, so the affected releases are not supported and only the missing v2+ integrity protection remains.` : ''}`, evidence: ['v1'], key: 'v1only' });
  else if (schemes.has('v1') && minSdk !== null && minSdk < 24) findings.add('android.signing.janus', { ...base, artifact: art, description: `minSdkVersion ${minSdk} keeps Android 5.0–8.0 devices in scope, where the v1 signature is what gets checked and can be bypassed (Janus).`, evidence: [`minSdkVersion=${minSdk}`], key: 'janus' });
}


// Class namespace evidence helps inventory popular Android dependencies when build-time
// dependency metadata was stripped from the APK. It does not reveal the installed version,
// so these entries are only eligible for OSV lookup if exact Maven metadata is also present.
const THIRD_PARTY_CLASS_NAMESPACES = [
  { re: /^okhttp3\./, coordinate: 'com.squareup.okhttp3:okhttp', name: 'OkHttp' },
  { re: /^okio\./, coordinate: 'com.squareup.okio:okio', name: 'Okio' },
  { re: /^com\.google\.gson\./, coordinate: 'com.google.code.gson:gson', name: 'Gson' },
  { re: /^com\.squareup\.retrofit2\./, coordinate: 'com.squareup.retrofit2:retrofit', name: 'Retrofit' },
  { re: /^com\.squareup\.moshi\./, coordinate: 'com.squareup.moshi:moshi', name: 'Moshi' },
  { re: /^kotlinx\.coroutines\./, coordinate: 'org.jetbrains.kotlinx:kotlinx-coroutines-core', name: 'Kotlinx Coroutines Core' },
  { re: /^com\.facebook\.react\./, coordinate: 'com.facebook.react:react-android', name: 'React Native Android' },
  { re: /^io\.sentry\./, coordinate: 'io.sentry:sentry-android', name: 'Sentry Android' },
  { re: /^com\.bugsnag\.android\./, coordinate: 'com.bugsnag:bugsnag-android', name: 'Bugsnag Android' },
  { re: /^com\.google\.firebase\./, name: 'Firebase Android SDK' },
  { re: /^com\.google\.android\.gms\./, name: 'Google Play Services' },
  { re: /^androidx\./, name: 'AndroidX libraries' },
  { re: /^org\.bouncycastle\./, name: 'Bouncy Castle' },
  { re: /^org\.apache\.commons\./, name: 'Apache Commons libraries' },
  { re: /^io\.grpc\./, name: 'gRPC Java' },
  { re: /^com\.google\.protobuf\./, name: 'Protocol Buffers Java' },
];

function collectThirdPartyNamespaces(dex, source, out) {
  const found = new Map();
  for (const cls of dex.classes()) {
    const dotted = String(cls.type || '').replace(/^L/, '').replace(/;$/, '').replace(/\//g, '.');
    if (!dotted) continue;
    for (const item of THIRD_PARTY_CLASS_NAMESPACES) {
      if (!item.re.test(dotted)) continue;
      const key = item.coordinate || item.name;
      if (!found.has(key)) found.set(key, {
        name: item.name,
        ecosystem: 'Maven',
        coordinate: item.coordinate || null,
        version: null,
        purl: null,
        source,
        reason: 'A third-party class namespace was detected, but the package version is not embedded in a reliable form; it was not queried by version against OSV.',
      });
      break;
    }
  }
  out.push(...found.values());
}

// ── inventory ──────────────────────────────────────────────────────────────────────────────────────
function libraries(zip, app) {
  const libs = new Map();
  for (const e of zip.find(/^META-INF\/[^/]+\.version$/).slice(0, 400)) {
    const b = zip.tryRead(e, 256);
    const v = b && b.toString('utf8').trim().split(/\s/)[0];
    if (v && /^\d/.test(v) && v.length < 40) libs.set(e.name.slice(9, -8), v);
  }
  for (const e of zip.find(/^META-INF\/maven\/[^/]+\/[^/]+\/pom\.properties$/).slice(0, 400)) {
    const b = zip.tryRead(e, 4096); if (!b) continue;
    const t = b.toString('utf8');
    const g = /groupId=(.+)/.exec(t), a = /artifactId=(.+)/.exec(t), v = /version=(.+)/.exec(t);
    if (g && a && v) libs.set(`${g[1].trim()}:${a[1].trim()}`, v[1].trim());
  }
  app.libraries = [...libs].map(([name, version]) => ({ name, version })).sort((x, y) => x.name.localeCompare(y.name));
}

function detectFrameworks(zip, app) {
  const has = re => zip.entries.some(e => re.test(e.name));
  for (const f of app.cross_platform || []) {
    const detail = [f.engine, f.backend, f.mode, f.flavour, f.dart_version && `Dart ${f.dart_version}`, f.unity_version].filter(Boolean).join(', ');
    app.frameworks.push(detail ? `${f.name} (${detail})` : f.name);
  }
  if (has(/^assets\/www\//) || has(/^assets\/public\//)) app.frameworks.push('Cordova / Capacitor / Ionic');
}
