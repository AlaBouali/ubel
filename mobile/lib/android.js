'use strict';
// android.js — everything ubel-mobile checks in an Android package (.apk):
// manifest, network security config, signing, DEX (strings, constants, API calls, TLS bypasses),
// native libraries, string resources and bundled files. Pure Node: no aapt, apktool, jadx or smali.

import { isAxml, parseAxml, findAll, axmlToLines } from './axml.js';
import { parseArscStrings } from './arsc.js';
import { Dex, isDex } from './dex.js';
import { isElf, parseElf } from './elf.js';
import { asciiStrings } from './strings.js';
import { certsFromPkcs7, describeCert, parseApkSigningBlock, WEAK_SIG } from './der.js';
import { scanBundledFiles } from './files.js';
import { Aggregator, mask } from './findings.js';

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

const DEBUG_LIBS = [['Lcom/facebook/stetho/', 'Stetho'], ['Lcom/squareup/leakcanary/', 'LeakCanary'], ['Lleakcanary/', 'LeakCanary'],
  ['Lcom/readystatesoftware/chuck/', 'Chuck'], ['Lcom/chuckerteam/chucker/', 'Chucker'], ['Lcom/facebook/flipper/', 'Flipper'], ['Lcom/amitshekhar/', 'Android-Debug-Database']];

const TRUST_MANAGERS = new Set(['Ljavax/net/ssl/X509TrustManager;', 'Ljavax/net/ssl/X509ExtendedTrustManager;', 'Ljavax/net/ssl/TrustManager;']);
const HOST_VERIFIERS = new Set(['Ljavax/net/ssl/HostnameVerifier;', 'Lorg/apache/http/conn/ssl/X509HostnameVerifier;']);
const CONTEXT_CLASSES = ['Landroid/content/Context;', 'Landroid/content/ContextWrapper;', 'Landroid/app/Activity;', 'Landroid/app/Service;', 'Landroid/app/Application;', 'Landroid/view/ContextThemeWrapper;'];

const NAMESPACE_URL = /(w3\.org|apache\.org|xmlpull\.org|schemas\.|sun\.com|xml\.org|ietf\.org|iana\.org|purl\.org|ns\.adobe\.com|sax\.|jboss\.org|sourceforge\.net|oracle\.com|java\.com|opengis\.net|iso\.org|relaxng\.org|xmlsoap\.org|openxmlformats\.org|json-schema\.org|mozilla\.org|gnu\.org|eclipse\.org|jcp\.org|android\.com\/apk|googleapis\.com\/auth|google\.com\/schemas|example\.(com|org)|localhost|127\.0\.0\.1|0\.0\.0\.0|10\.0\.2\.2)/i;
const URL_HTTP = /^http:\/\/[^\s"'<>\\]{4,300}$/i;
const URL_FIREBASE = /^https:\/\/[a-z0-9-]+\.(firebaseio\.com|firebasedatabase\.app)\b/i;
const PIN = /sha(256|1)\/[A-Za-z0-9+/]{27,44}={0,2}/;
const TYPE_DESC = /^\[*L[\w/$-]+;$|^[VZBSCIJFDL]{1,12}$/;

const pretty = t => t.replace(/^L|;$/g, '').replace(/\//g, '.');
const esc = s => String(s).replace(/\r?\n|\r/g, ' ').replace(/"/g, '\\"');

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
  if (a[2] && a[2].k === 'bytes') return [{ rule: 'android.dex.static_iv', evidence: `new GCMParameterSpec(…, "${mask(a[2].v)}")`, description: 'A constant GCM nonce breaks GCM completely when reused with a key.' }];
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
for (const c of ['DexClassLoader', 'PathClassLoader', 'InMemoryDexClassLoader']) {
  on(`Ldalvik/system/${c};-><init>`, () => [{ rule: 'android.dex.dynamic_code_loading', evidence: `new ${c}(…)`, description: 'Code is loaded at runtime; if the source is writable or remote it can be replaced.', confidence: 'medium' }]);
}
on('Ljava/lang/Runtime;->exec', () => [{ rule: 'android.dex.runtime_exec', evidence: 'Runtime.exec(…)', description: 'Shell commands are executed.', confidence: 'medium' }]);
for (const m of ['getDeviceId', 'getImei', 'getMeid', 'getSubscriberId', 'getSimSerialNumber', 'getLine1Number']) {
  on(`Landroid/telephony/TelephonyManager;->${m}`, () => [{ rule: 'android.dex.device_identifiers', evidence: `TelephonyManager.${m}()`, description: 'Persistent hardware/subscriber identifiers are read.' }]);
}
const WATCH = new Set(CALLS.keys());

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
  if (!isAxml(raw)) throw new Error('AndroidManifest.xml is not binary XML (App Bundles / protobuf manifests are not supported — scan the APKs built from the bundle)');
  const manifest = parseAxml(raw);
  if (!manifest || manifest.tag !== 'manifest') throw new Error('AndroidManifest.xml has no <manifest> element');

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
    permissions: [], components: { activity: 0, service: 0, receiver: 0, provider: 0 }, dex_files: [], native_libs: [], libraries: [],
    signing: null, frameworks: [], _detected_dependencies: [],
  };
  const urls = new Map();          // url -> artifact
  const addUrl = (u, a) => { if (!urls.has(u)) urls.set(u, a); };
  let pinning = false;

  manifestChecks({ manifest, application, app, base, findings, at, targetSdk, minSdk, scanner });
  const xmlRoots = resourceXml(zip, at, scanner, notes);
  networkSecurityChecks({ xmlRoots, base, findings, at, flags: { setPinned: () => { pinning = true; } } });
  hybridChecks({ xmlRoots, base, findings, at });

  // string resources
  const arsc = zip.entry('resources.arsc');
  if (arsc) {
    try {
      const buf = zip.read(arsc, 128 * MB);
      const seen = new Set(); const lines = [];
      for (const s of parseArscStrings(buf)) {
        const k = `${s.name}\0${s.value}`;
        if (seen.has(k) || !s.value) continue;
        seen.add(k);
        if (s.value.length >= 8 || /key|secret|token|pass|pwd|auth|_id$/i.test(s.name)) lines.push(`${s.name} = "${esc(s.value)}"`);
        if (/^https?:\/\//i.test(s.value)) addUrl(s.value, at('resources.arsc'));
      }
      scanner.add(at('res/values/strings.xml'), lines);
    } catch (e) { notes.push(`${at('resources.arsc')}: not analysed (${e.message}).`); }
  }

  // code
  for (const e of zip.find(/^classes\d*\.dex$/).slice(0, 30)) {
    try {
      const dex = new Dex(zip.read(e, 160 * MB), e.name);
      app.dex_files.push(e.name);
      collectThirdPartyNamespaces(dex, e.name, app._detected_dependencies);
      if (analyzeDex(dex, { findings, base, at, scanner, addUrl })) pinning = true;
    } catch (err) { notes.push(`${at(e.name)}: not analysed (${err.message}).`); }
  }
  if (!app.dex_files.length) notes.push(`${at('classes.dex')}: no DEX code found.`);

  nativeLibraries(zip, { findings, base, at, scanner, notes, app });
  signing(zip, { findings, base, at, app, minSdk });
  libraries(zip, app);

  // cleartext endpoints / firebase / pinning (collected from DEX + resources)
  const http = [], firebase = [];
  for (const [u, a] of urls) {
    if (URL_FIREBASE.test(u)) firebase.push(u);
    else if (URL_HTTP.test(u) && !NAMESPACE_URL.test(u)) http.push(u);
    if (PIN.test(u)) pinning = true;
  }
  if (http.length) findings.add('android.dex.cleartext_urls', { ...base, artifact: at('classes.dex'), description: `${http.length} http:// endpoint(s) are hardcoded; traffic to them is unencrypted.`, evidence: http.slice(0, 25), evidence_total: http.length, confidence: 'medium' });
  if (firebase.length) findings.add('android.dex.firebase_urls', { ...base, artifact: at('resources.arsc'), description: 'The app talks to Firebase Realtime Database. Misconfigured rules are a very common source of data leaks; ubel-mobile does not contact the network, so the rules were not tested.', evidence: [...new Set(firebase)].slice(0, 10) });
  if (!pinning) findings.add('android.network.no_pinning', { ...base, artifact: at('AndroidManifest.xml'), description: 'No pin-set, OkHttp CertificatePinner, TrustKit or hardcoded pin hash was found.', evidence: [], confidence: 'low', key: 'nopin' });

  // everything else shipped in the package
  const handled = /^(classes\d*\.dex|AndroidManifest\.xml|resources\.arsc|META-INF\/|lib\/|res\/(?!raw\/)|r\/|kotlin\/|okhttp3\/|DebugProbesKt\.bin)/;
  const rest = zip.entries.filter(e => !e.isDir && !handled.test(e.name));
  scanBundledFiles(zip, rest, { findings, scanner, base, notes, relName: at, limits: ctx.limits });
  detectFrameworks(zip, app);
  scanner.run();
  if (scanner.truncated) notes.push(`${pkg}: secret scanning stopped at its line budget; some strings were not scanned.`);
  return app;
}

// ── manifest ───────────────────────────────────────────────────────────────────────────────────────
function manifestChecks({ manifest, application, app, base, findings, at, targetSdk, minSdk, scanner }) {
  const art = at('AndroidManifest.xml');
  const A = application.attrs;
  if (A.debuggable === true) findings.add('android.manifest.debuggable', { ...base, artifact: art, description: 'android:debuggable="true" lets anyone attach a debugger, read the app’s private files with run-as and bypass many protections.', evidence: ['android:debuggable="true"'] });
  if (A.testOnly === true) findings.add('android.manifest.test_only', { ...base, artifact: art, description: 'android:testOnly="true" marks a development build.', evidence: ['android:testOnly="true"'] });
  if (A.allowBackup !== false) {
    const hasCfg = A.fullBackupContent !== undefined || A.dataExtractionRules !== undefined;
    findings.add('android.manifest.backup', { ...base, artifact: art, severity: hasCfg ? 'low' : 'medium',
      description: `allowBackup is ${A.allowBackup === true ? 'true' : 'not set (defaults to true)'}; app data can be copied off the device with adb backup / cloud backup.${hasCfg ? ' A backup-rules file is configured: check it excludes tokens, databases and preferences that hold secrets.' : ''}`,
      evidence: [`android:allowBackup=${A.allowBackup === true ? '"true"' : '(default)'}`] });
  }
  if (A.usesCleartextTraffic === true) findings.add('android.manifest.cleartext', { ...base, artifact: art, description: 'usesCleartextTraffic="true" allows plain HTTP for the whole app.', evidence: ['android:usesCleartextTraffic="true"'] });
  else if (A.usesCleartextTraffic === undefined && A.networkSecurityConfig === undefined && targetSdk !== null && targetSdk < 28) {
    findings.add('android.manifest.cleartext_default', { ...base, artifact: art, description: `targetSdkVersion ${targetSdk} permits cleartext traffic by default and no network security config overrides it.`, evidence: [`targetSdkVersion=${targetSdk}`] });
  }
  if (A.requestLegacyExternalStorage === true) findings.add('android.manifest.legacy_storage', { ...base, artifact: art, description: 'requestLegacyExternalStorage="true" keeps broad access to shared storage.', evidence: ['android:requestLegacyExternalStorage="true"'] });
  if (manifest.attrs.sharedUserId) findings.add('android.manifest.shared_user_id', { ...base, artifact: art, description: `sharedUserId="${manifest.attrs.sharedUserId}" runs this app in the same sandbox as every app signed with the same key and sharing the id.`, evidence: [String(manifest.attrs.sharedUserId)] });
  if (minSdk !== null && minSdk < 24) findings.add('android.manifest.min_sdk', { ...base, artifact: art, severity: minSdk < 21 ? 'medium' : 'low', description: `minSdkVersion is ${minSdk}; devices running such releases miss years of security fixes and sandbox hardening.`, evidence: [`minSdkVersion=${minSdk}`] });
  if (targetSdk !== null && targetSdk < 33) findings.add('android.manifest.target_sdk', { ...base, artifact: art, severity: targetSdk < 29 ? 'medium' : 'low', description: `targetSdkVersion is ${targetSdk}; newer API levels enforce stricter defaults (exported components, scoped storage, cleartext, background limits) that this app opts out of.`, evidence: [`targetSdkVersion=${targetSdk}`] });

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
function resourceXml(zip, at, scanner, notes) {
  const roots = [];
  for (const e of zip.find(/^(res\/xml[^/]*\/[^/]+|r\/[^/]+)\.xml$/i).slice(0, 400)) {
    const buf = zip.tryRead(e, 4 * MB);
    if (!buf || !isAxml(buf)) continue;
    try {
      const root = parseAxml(buf);
      if (!root) continue;
      roots.push({ name: e.name, root });
      const lines = axmlToLines(root);
      if (lines.length < 5000) scanner.add(at(e.name), lines);
    } catch { notes.push(`${at(e.name)}: unreadable binary XML.`); }
  }
  return roots;
}

function networkSecurityChecks({ xmlRoots, base, findings, at, flags }) {
  const nsc = xmlRoots.find(x => x.root.tag === 'network-security-config');
  if (!nsc) return;
  const art = at(nsc.name);
  const r = nsc.root;
  const baseCfg = r.children.find(c => c.tag === 'base-config');
  const domains = r.children.filter(c => c.tag === 'domain-config');
  const hostsOf = d => findAll(d, 'domain').map(x => x.text.trim()).filter(Boolean);
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
function analyzeDex(dex, { findings, base, at, scanner, addUrl }) {
  const agg = new Aggregator(findings, base);
  const users = new Map();                       // string idx -> first class that loads it
  let current = null;
  const constLines = [], constWhere = [];
  const debugLibs = new Set();
  const customTm = new Set();
  let pinned = false;

  for (const def of dex.classes()) {
    const type = def.type;
    const origin = isLibraryClass(type) ? 'library' : 'app';
    for (const [p, label] of DEBUG_LIBS) if (type.startsWith(p)) debugLibs.add(label);
    let data;
    try { data = dex.classData(def); } catch { continue; }
    if (type.startsWith('Lcom/datatheorem/android/trustkit/') || type === 'Lokhttp3/CertificatePinner;') pinned = true;
    if (def.staticValuesOff) {
      try {
        for (const c of dex.staticConstants(def, data)) {
          if (c.kind === 'string' && c.value.length >= 6) { constLines.push(`${c.field} = "${esc(c.value)}"`); constWhere.push(pretty(type)); }
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
      try {
        dex.walk(m.codeOff, {
          onString: idx => { if (!users.has(idx)) users.set(idx, type); },
          onInvoke: (k, args) => {
            const fns = CALLS.get(k);
            if (!fns) return;
            for (const fn of fns) {
              const hits = fn(args, current);
              if (hits) for (const h of hits) agg.hit(h.rule, { origin: current.origin, evidence: `${h.evidence} in ${pretty(current.cls)}#${current.method}`, description: h.description, confidence: h.confidence });
            }
          },
        }, WATCH);
      } catch { /* malformed code item: skip this method */ }
    }
  }
  for (const f of dex.allFieldRefs()) {
    if (f.name === 'ALLOW_ALL_HOSTNAME_VERIFIER') agg.hit('android.dex.allow_all_hostnames', { origin: 'app', evidence: `${pretty(f.cls)}.ALLOW_ALL_HOSTNAME_VERIFIER`, description: 'The Apache "allow all" hostname verifier is referenced.' });
  }
  if (customTm.size) findings.add('android.dex.custom_trust_manager', { ...base, artifact: at(dex.name), description: `${customTm.size} custom TrustManager implementation(s) with a non-empty checkServerTrusted. Review them for complete chain and host-name validation.`, evidence: [...customTm].slice(0, 20), confidence: 'low' });
  if (debugLibs.size) findings.add('android.dex.debug_libraries', { ...base, artifact: at(dex.name), description: 'Development-time inspection libraries are packaged in this build.', evidence: [...debugLibs] });
  agg.flush(at(dex.name));

  // strings → secrets, URLs, pins
  const idxs = [], lines = [];
  for (let i = 0; i < dex.nStr; i++) {
    const s = dex.string(i);
    if (s.length < 8 || s.length > 2000) continue;
    if (s.startsWith('http')) { if (URL_HTTP.test(s) || URL_FIREBASE.test(s)) addUrl(s, at(dex.name)); }
    if (!pinned && PIN.test(s)) pinned = true;
    if (TYPE_DESC.test(s)) continue;
    idxs.push(i); lines.push(s);
  }
  scanner.add(at(dex.name), lines, i => (users.has(idxs[i]) ? `string used by ${pretty(users.get(idxs[i]))}` : null));
  scanner.add(at(dex.name), constLines, i => `constant in ${constWhere[i]}`);
  return pinned;
}

// ── native libraries ───────────────────────────────────────────────────────────────────────────────
const ABI_ORDER = ['arm64-v8a', 'armeabi-v7a', 'x86_64', 'x86', 'armeabi'];
const SKIP_STRINGS = /^(libflutter|libc\+\+_shared|libhermes|libjsc|libmonosgen|libreactnativejni|libfbjni|libjscexecutor|libunity|libil2cpp|libmain|libbitmaps|libimagepipeline|libgifimage|libwebp|libyoga|libglog|libfolly|libv8)/;

function nativeLibraries(zip, { findings, base, at, scanner, notes, app }) {
  const byName = new Map();
  for (const e of zip.find(/^lib\/[^/]+\/[^/]+\.so$/)) {
    const [, abi, name] = e.name.match(/^lib\/([^/]+)\/([^/]+)$/);
    const cur = byName.get(name);
    const rank = ABI_ORDER.indexOf(abi) < 0 ? 99 : ABI_ORDER.indexOf(abi);
    if (!cur || rank < cur.rank) byName.set(name, { e, abi, rank });
  }
  app.native_libs = [...byName.keys()].sort().slice(0, 300);
  const props = { exec_stack: [], no_relro: [], partial_relro: [], textrel: [], no_canary: [], rpath: [] };
  let n = 0;
  for (const [name, { e, abi }] of byName) {
    if (++n > 150) { notes.push('More than 150 native libraries: the rest were not analysed.'); break; }
    const buf = zip.tryRead(e, 128 * MB);
    if (!buf || !isElf(buf)) continue;
    const label = `${abi}/${name}`;
    try {
      const elf = parseElf(buf);
      if (elf.execStack) props.exec_stack.push(label);
      if (elf.relro === 'none') props.no_relro.push(label); else if (elf.relro === 'partial') props.partial_relro.push(label);
      if (elf.textrel) props.textrel.push(label);
      if (elf.rpath) props.rpath.push(`${label} (${elf.rpath})`);
      if (!elf.canary && elf.imports.some(s => /^(strcpy|strcat|sprintf|gets|memcpy)$/.test(s))) props.no_canary.push(label);
    } catch { /* unreadable ELF */ }
    if (!SKIP_STRINGS.test(name)) scanner.add(at(`lib/${abi}/${name}`), asciiStrings(buf, { min: 8, max: 400, limit: 40000 }));
  }
  const emit = (rule, list, text) => list.length && findings.add(rule, { ...base, artifact: at(`lib/…/${list[0].split('/').pop().split(' ')[0]}`), description: `${text} (${list.length} librar${list.length === 1 ? 'y' : 'ies'}).`, evidence: list.slice(0, 30), evidence_total: list.length, key: rule });
  emit('android.native.exec_stack', props.exec_stack, 'The stack of these libraries is marked executable.');
  emit('android.native.textrel', props.textrel, 'Text relocations force writable code pages.');
  emit('android.native.no_relro', props.no_relro, 'The GOT is writable at runtime.');
  emit('android.native.partial_relro', props.partial_relro, 'Lazy binding leaves the GOT writable.');
  emit('android.native.no_canary', props.no_canary, 'The library imports unsafe C functions but has no stack canary.');
  emit('android.native.rpath', props.rpath, 'A search path is baked into the library.');
}

// ── signing ────────────────────────────────────────────────────────────────────────────────────────
function signing(zip, { findings, base, at, app, minSdk }) {
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
  if (!schemes.size) { findings.add('android.signing.unsigned', { ...base, artifact: at('AndroidManifest.xml'), description: 'No v1, v2 or v3 signature was found; Android will refuse to install an unsigned package.', evidence: [] , key: 'unsigned' }); return; }
  for (const c of certs.values()) {
    if (/CN=Android Debug\b/i.test(c.subject)) findings.add('android.signing.debug_cert', { ...base, artifact: art, key: c.sha256, description: 'The certificate is the well-known Android debug certificate; its private key is public knowledge (or generated on every developer machine), so anyone can sign an update that Android treats as coming from this developer.', evidence: [c.subject, `sha256 ${c.sha256}`] });
    if (WEAK_SIG.test(c.signature_algorithm)) findings.add('android.signing.weak_algorithm', { ...base, artifact: art, key: c.sha256, description: `The certificate is signed with ${c.signature_algorithm}.`, evidence: [c.subject, c.signature_algorithm] });
    if ((c.key_type === 'rsa' || c.key_type === 'dsa') && typeof c.key_bits === 'number' && c.key_bits < 2048) findings.add('android.signing.weak_key', { ...base, artifact: art, key: c.sha256, description: `The signing key is ${c.key_type.toUpperCase()}-${c.key_bits}.`, evidence: [c.subject, `${c.key_type}-${c.key_bits}`] });
    if (c.expired) findings.add('android.signing.expired', { ...base, artifact: art, key: c.sha256, description: `The certificate expired on ${c.valid_to}.`, evidence: [c.subject, c.valid_to] });
  }
  const modern = ['v2', 'v3', 'v3.1'].some(s => schemes.has(s));
  if (schemes.has('v1') && !modern) findings.add('android.signing.v1_only', { ...base, artifact: art, description: 'Only the JAR (v1) signature is present; it does not cover the whole file and is vulnerable to Janus-style tampering on Android 5.0–8.0.', evidence: ['v1'], key: 'v1only' });
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
  if (has(/^assets\/index\.android\.bundle$/)) app.frameworks.push('React Native');
  if (has(/^lib\/[^/]+\/libflutter\.so$/)) app.frameworks.push('Flutter');
  if (has(/^assets\/www\//) || has(/^assets\/public\//)) app.frameworks.push('Cordova / Capacitor / Ionic');
  if (has(/^assemblies\/|^assets\/bin\/Data\/Managed\//)) app.frameworks.push('Xamarin / .NET / Unity (Mono)');
  if (has(/^lib\/[^/]+\/libunity\.so$/)) app.frameworks.push('Unity');
}
