'use strict';
// rules.js — the catalog of every rule ubel-mobile can raise: default severity, title, OWASP MASVS
// control, CWE and a one-line remediation. Analyzers only supply what is specific to the finding
// (artifact, evidence, a description); everything else comes from here, so SARIF rule metadata
// and the HTML report stay consistent.

export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'];
export const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

const R = (severity, title, masvs, cwe, remediation) => ({ severity, title, masvs, cwe, remediation });

export const RULES = {
  // ── Android manifest ───────────────────────────────────────────────────────
  'android.manifest.debuggable':       R('high',   'App is debuggable (android:debuggable="true")', 'MASVS-RESILIENCE', 489, 'Remove android:debuggable from release builds; let the build system set it.'),
  'android.manifest.test_only':        R('medium', 'App is marked testOnly', 'MASVS-CODE', 489, 'Do not ship builds with android:testOnly="true".'),
  'android.manifest.backup':           R('medium', 'App data can be extracted by backup (android:allowBackup)', 'MASVS-STORAGE-2', 530, 'Set android:allowBackup="false", or restrict what is backed up with dataExtractionRules / fullBackupContent.'),
  'android.manifest.cleartext':        R('medium', 'Cleartext (HTTP) traffic permitted app-wide', 'MASVS-NETWORK-1', 319, 'Remove usesCleartextTraffic="true"; use HTTPS everywhere.'),
  'android.manifest.cleartext_default':R('low',    'Cleartext traffic permitted by default (targetSdk < 28)', 'MASVS-NETWORK-1', 319, 'Raise targetSdkVersion to 28+ or add a network security config that forbids cleartext.'),
  'android.manifest.min_sdk':          R('low',    'Supports old Android versions (minSdkVersion)', 'MASVS-CODE-1', 1104, 'Raise minSdkVersion; old releases lack platform security fixes and sandbox hardening.'),
  'android.manifest.target_sdk':       R('low',    'Targets an old Android API level (targetSdkVersion)', 'MASVS-CODE-1', 1104, 'Raise targetSdkVersion so the app gets the current platform security behaviour.'),
  'android.manifest.shared_user_id':   R('medium', 'sharedUserId shares the app sandbox with other apps', 'MASVS-PLATFORM-1', 266, 'Remove android:sharedUserId (deprecated); use explicit, permission-guarded IPC.'),
  'android.manifest.legacy_storage':   R('low',    'Opts out of scoped storage (requestLegacyExternalStorage)', 'MASVS-STORAGE-2', 922, 'Remove requestLegacyExternalStorage and use scoped storage.'),
  'android.manifest.exported_provider':R('high',   'Content provider reachable by other apps without a permission', 'MASVS-PLATFORM-1', 926, 'Set android:exported="false", or guard it with a signature-level permission; keep grantUriPermissions narrow.'),
  'android.manifest.exported_service':  R('medium', 'Service reachable by other apps without a permission', 'MASVS-PLATFORM-1', 926, 'Set android:exported="false" or require a signature-level permission.'),
  'android.manifest.exported_receiver': R('medium', 'Broadcast receiver reachable by other apps without a permission', 'MASVS-PLATFORM-1', 926, 'Set android:exported="false" or require a signature-level permission; validate every incoming Intent.'),
  'android.manifest.exported_activity': R('low',    'Exported activities (other than the launcher)', 'MASVS-PLATFORM-1', 926, 'Export only what must be reachable; treat every Intent extra and deep-link parameter as untrusted input.'),
  'android.manifest.weak_permission':   R('medium', 'Custom permission has a weak protectionLevel', 'MASVS-PLATFORM-1', 276, 'Use protectionLevel="signature" for permissions that guard sensitive components.'),
  'android.manifest.risky_permissions': R('medium', 'High-impact permissions requested', 'MASVS-PRIVACY-1', 250, 'Remove permissions the app does not strictly need; review the Play policy for each.'),
  'android.manifest.permissions':       R('info',   'Dangerous permissions requested', 'MASVS-PRIVACY-1', 250, 'Confirm each permission is needed and requested at the point of use.'),
  'android.manifest.deeplinks':         R('info',   'Deep links / custom URL schemes', 'MASVS-PLATFORM-1', 939, 'Prefer verified App Links (autoVerify) over custom schemes; validate all link parameters.'),
  // ── Android network security config / hybrid config ────────────────────────
  'android.nsc.cleartext':             R('medium', 'Network security config permits cleartext traffic', 'MASVS-NETWORK-1', 319, 'Set cleartextTrafficPermitted="false" (base-config and every domain-config).'),
  'android.nsc.user_ca':               R('medium', 'Network security config trusts user-installed CAs', 'MASVS-NETWORK-1', 295, 'Remove <certificates src="user"/> outside debug-overrides.'),
  'android.nsc.pin_expired':           R('low',    'Certificate pin-set has expired', 'MASVS-NETWORK-2', 295, 'Rotate the pins and update the expiration date.'),
  'android.network.no_pinning':        R('info',   'No certificate pinning detected', 'MASVS-NETWORK-2', 295, 'Consider pinning for apps handling highly sensitive data (network-security-config pin-set or OkHttp CertificatePinner).'),
  'android.cordova.access_origin':     R('medium', 'Cordova/WebView config allows any origin', 'MASVS-PLATFORM-2', 346, 'Restrict <access origin> and <allow-navigation> to the hosts the app actually needs.'),
  // ── Android signing ────────────────────────────────────────────────────────
  'android.signing.unsigned':          R('high',   'Package carries no signature', 'MASVS-RESILIENCE', 347, 'Sign release builds with a release key.'),
  'android.signing.debug_cert':        R('high',   'Signed with a debug certificate', 'MASVS-RESILIENCE', 321, 'Sign release builds with a protected release key, never the Android debug keystore.'),
  'android.signing.weak_algorithm':    R('medium', 'Signing certificate uses a weak signature algorithm', 'MASVS-RESILIENCE', 327, 'Re-issue the signing certificate with SHA-256 or better.'),
  'android.signing.weak_key':          R('medium', 'Signing key is too short', 'MASVS-RESILIENCE', 326, 'Use RSA ≥ 2048 bits or an EC key.'),
  'android.signing.expired':           R('medium', 'Signing certificate has expired', 'MASVS-RESILIENCE', 298, 'Use a certificate valid for the life of the app (25+ years is customary).'),
  'android.signing.v1_only':           R('medium', 'Only the legacy v1 (JAR) signature is present', 'MASVS-RESILIENCE', 347, 'Sign with APK Signature Scheme v2/v3 as well.'),
  'android.signing.janus':             R('low',    'v1 signature on an app that supports Android 5.0–8.0 (Janus, CVE-2017-13156)', 'MASVS-RESILIENCE', 347, 'Raise minSdkVersion to 24+ (v2+ signing only), or ensure v2/v3 signatures are present and old devices are unsupported.'),
  // ── Android code (DEX) ─────────────────────────────────────────────────────
  'android.dex.weak_cipher':           R('high',   'Broken or weak cipher in use', 'MASVS-CRYPTO-1', 327, 'Use AES-GCM (or ChaCha20-Poly1305); never DES/3DES/RC2/RC4/Blowfish.'),
  'android.dex.ecb_mode':              R('medium', 'ECB mode (or default AES mode) in use', 'MASVS-CRYPTO-1', 327, 'Use an authenticated mode such as AES/GCM/NoPadding with a fresh random IV.'),
  'android.dex.weak_hash':             R('low',    'MD5 / SHA-1 in use', 'MASVS-CRYPTO-1', 328, 'Use SHA-256 or better for anything security-relevant.'),
  'android.dex.hardcoded_key':         R('high',   'Cryptographic key built from a constant in code', 'MASVS-CRYPTO-2', 321, 'Generate keys at runtime and keep them in the Android Keystore; never embed key material.'),
  'android.dex.static_iv':             R('medium', 'Constant IV / nonce in code', 'MASVS-CRYPTO-1', 329, 'Generate a fresh random IV per encryption.'),
  'android.dex.insecure_random':       R('low',    'SecureRandom is seeded explicitly', 'MASVS-CRYPTO-1', 335, 'Do not call setSeed on SecureRandom; let the platform seed it.'),
  'android.dex.weak_tls_protocol':     R('medium', 'Outdated SSL/TLS protocol requested', 'MASVS-NETWORK-1', 327, 'Request "TLS" (or TLSv1.2 / TLSv1.3) and let the platform choose.'),
  'android.dex.trust_all_certs':       R('high',   'TrustManager accepts every certificate', 'MASVS-NETWORK-1', 295, 'Remove the custom TrustManager or make checkServerTrusted validate the chain.'),
  'android.dex.allow_all_hostnames':   R('high',   'Hostname verification disabled', 'MASVS-NETWORK-1', 297, 'Use the default HostnameVerifier.'),
  'android.dex.custom_trust_manager':  R('info',   'Custom TrustManager implementations', 'MASVS-NETWORK-1', 295, 'Review each implementation for complete chain and hostname validation.'),
  'android.dex.webview_ssl_proceed':   R('high',   'WebView ignores TLS errors (SslErrorHandler.proceed)', 'MASVS-NETWORK-1', 295, 'Call handler.cancel() in onReceivedSslError.'),
  'android.dex.webview_js_interface':  R('medium', 'WebView exposes a Java object to JavaScript', 'MASVS-PLATFORM-2', 749, 'Load only trusted content, annotate exposed methods with @JavascriptInterface, expose as little as possible.'),
  'android.dex.webview_file_access':   R('high',   'WebView allows file:// content to read other files / origins', 'MASVS-PLATFORM-2', 200, 'Set setAllowFileAccessFromFileURLs / setAllowUniversalAccessFromFileURLs to false.'),
  'android.dex.webview_mixed_content': R('medium', 'WebView allows mixed (HTTP in HTTPS) content', 'MASVS-NETWORK-1', 319, 'Use MIXED_CONTENT_NEVER_ALLOW.'),
  'android.dex.webview_debugging':     R('medium', 'WebView remote debugging enabled', 'MASVS-PLATFORM-2', 489, 'Enable setWebContentsDebuggingEnabled only in debug builds.'),
  'android.dex.logging_sensitive':     R('medium', 'Sensitive-looking data may be written to the system log', 'MASVS-STORAGE-2', 532, 'Remove Log.* calls that handle credentials, tokens or personal data, strip logging from release builds (R8 -assumenosideeffects) and never log request or response bodies.'),
  'android.dex.plaintext_prefs':       R('medium', 'Sensitive-looking values stored in plaintext SharedPreferences', 'MASVS-STORAGE-1', 312, 'Do not persist session tokens or credentials unprotected; keep secrets in the Android Keystore and use EncryptedSharedPreferences / DataStore with Tink for anything that must persist.'),
  'android.dex.plaintext_database':    R('medium', 'Sensitive-looking data stored in an unencrypted SQLite database', 'MASVS-STORAGE-1', 312, 'Encrypt the database (SQLCipher) or the sensitive columns with Keystore-backed keys; never store passwords (store a salted hash server-side).'),
  'android.dex.hardcoded_credential':  R('high',   'Hardcoded credential in code (constant named like a password, secret or token)', 'MASVS-CRYPTO-2', 798, 'Remove the value from the package, rotate it, and fetch credentials at runtime from a backend or the Android Keystore.'),
  'android.dex.hardcoded_jwt_secret':  R('high',   'JWT / HMAC signing secret hardcoded in code', 'MASVS-CRYPTO-2', 798, 'Never sign or verify tokens with a secret that ships in the app; sign on the server and verify with a public key.'),
  'android.dex.hardcoded_jwt':         R('high',   'JWT literal embedded in code', 'MASVS-AUTH-1', 798, 'Remove the token from the package and revoke it; obtain tokens at runtime through the login flow.'),
  'android.dex.world_accessible_storage': R('high','World-readable / world-writable files or preferences', 'MASVS-STORAGE-2', 276, 'Use MODE_PRIVATE; share data through a FileProvider.'),
  'android.dex.external_storage':      R('medium', 'Writes to shared external storage', 'MASVS-STORAGE-2', 922, 'Keep app data in internal storage; shared storage is readable by other apps.'),
  'android.dex.dynamic_code_loading':  R('medium', 'Loads code at runtime (DexClassLoader & co.)', 'MASVS-CODE-4', 494, 'Do not load code from writable or remote locations; verify integrity if it is unavoidable.'),
  'android.dex.runtime_exec':          R('low',    'Executes shell commands (Runtime.exec)', 'MASVS-CODE-4', 78, 'Avoid shell execution; never pass user-controlled input.'),
  'android.dex.device_identifiers':    R('low',    'Reads hardware identifiers (IMEI, subscriber id, …)', 'MASVS-PRIVACY-1', 359, 'Avoid persistent device identifiers; use resettable IDs.'),
  'android.dex.build_debug':           R('medium', 'BuildConfig.DEBUG is true in this build', 'MASVS-CODE', 489, 'Ship release variants only.'),
  'android.dex.debug_libraries':       R('low',    'Debug / inspection libraries present', 'MASVS-CODE', 489, 'Use debugImplementation for Stetho, LeakCanary, Chucker, Flipper, …'),
  'android.dex.cleartext_urls':        R('medium', 'Hardcoded http:// endpoints', 'MASVS-NETWORK-1', 319, 'Switch these endpoints to HTTPS.'),
  'android.dex.firebase_urls':         R('info',   'Firebase Realtime Database URLs', 'MASVS-STORAGE-1', 284, 'Confirm the database rules deny unauthenticated reads and writes (ubel-mobile does not contact the network).'),
  // ── Android native libraries ──────────────────────────────────────────────
  'android.native.exec_stack':         R('high',   'Native library requests an executable stack', 'MASVS-CODE-4', 119, 'Link with -z noexecstack.'),
  'android.native.no_relro':           R('medium', 'Native library has no RELRO', 'MASVS-CODE-4', 693, 'Link with -z relro -z now.'),
  'android.native.partial_relro':      R('low',    'Native library has only partial RELRO', 'MASVS-CODE-4', 693, 'Link with -z now for full RELRO.'),
  'android.native.textrel':            R('medium', 'Native library has text relocations', 'MASVS-CODE-4', 693, 'Build position-independent code (-fPIC) without text relocations.'),
  'android.native.no_canary':          R('low',    'Native library has no stack canary', 'MASVS-CODE-4', 693, 'Build with -fstack-protector-strong.'),
  'android.native.rpath':              R('low',    'Native library sets RPATH/RUNPATH', 'MASVS-CODE-4', 426, 'Remove RPATH/RUNPATH from Android libraries.'),
  // ── Files shipped inside the package (both platforms) ─────────────────────
  'bundle.private_key':                R('high',   'Keystore / private key file bundled in the app', 'MASVS-CRYPTO-2', 321, 'Remove it; anything in the package can be extracted by anyone.'),
  'bundle.sensitive_file':             R('medium', 'Sensitive-looking file bundled in the app', 'MASVS-STORAGE-1', 538, 'Remove env/credential/VCS files from the package.'),
  'bundle.backup_file':                R('low',    'Backup / temporary files bundled in the app', 'MASVS-STORAGE-1', 530, 'Exclude them from packaging.'),
  'bundle.database':                   R('low',    'Pre-populated database bundled in the app', 'MASVS-STORAGE-1', 312, 'Check the database for personal data or secrets; encrypt it if it holds any.'),
  'bundle.embedded_code':              R('medium', 'Executable code bundled as data (apk/dex/jar)', 'MASVS-CODE-4', 494, 'Review why code is shipped as an asset and how it is loaded.'),
  'bundle.debug_build':                R('high',   'Debug (JIT/kernel) build artifacts shipped', 'MASVS-RESILIENCE', 489, 'Build in release/AOT mode.'),
  'bundle.source_maps':                R('low',    'Source maps / debug symbols shipped', 'MASVS-RESILIENCE', 540, 'Do not package source maps or dSYM/PDB files.'),
  // ── Cross-platform frameworks (React Native, Flutter, Unity, Xamarin / .NET) ──────────────────────────
  'rn.dev_bundle':                     R('high',   'React Native bundle built in development mode (__DEV__ = true)', 'MASVS-RESILIENCE', 489, 'Build the release bundle with --dev false (the release Gradle / Xcode build phases do this).'),
  'rn.plain_bundle':                   R('info',   'React Native app logic ships as readable JavaScript', 'MASVS-RESILIENCE', 540, 'Compile the bundle to Hermes bytecode and keep secrets out of it; neither is protection against a determined reader.'),
  'rn.async_storage_secrets':          R('medium', 'Credential-looking keys used with unencrypted AsyncStorage', 'MASVS-STORAGE-1', 312, 'Keep tokens and credentials in the Keychain / Keystore (react-native-keychain, expo-secure-store), not AsyncStorage.'),
  'unity.development_build':           R('high',   'Unity Development Build (player-connection-debug)', 'MASVS-RESILIENCE', 489, 'Ship release builds: untick "Development Build" and "Script Debugging" in the Unity build settings.'),
  'unity.certificate_handler':         R('info',   'Custom Unity CertificateHandler (pinning or validation bypass)', 'MASVS-NETWORK-2', 295, 'Review ValidateCertificate: it must verify the chain or a pinned key, never return true unconditionally.'),
  'dotnet.tls_validation_disabled':    R('high',   'Managed code disables or overrides TLS certificate validation', 'MASVS-NETWORK-1', 295, 'Remove DangerousAcceptAnyServerCertificateValidator; if a validation callback is needed, verify the chain or a pinned key inside it.'),
  'dotnet.debug_build':                R('medium', 'Managed assemblies built in the Debug configuration', 'MASVS-RESILIENCE', 489, 'Build and ship the Release configuration.'),
  'dotnet.build_path_leak':            R('info',   'Build machine paths embedded in managed assemblies', 'MASVS-CODE', 200, 'Build with deterministic paths (PathMap) or strip the PDB path from release assemblies.'),
  // ── iOS ────────────────────────────────────────────────────────────────────
  'ios.plist.ats_arbitrary':           R('high',   'App Transport Security disabled (NSAllowsArbitraryLoads)', 'MASVS-NETWORK-1', 319, 'Remove NSAllowsArbitraryLoads; add narrowly scoped exceptions only where unavoidable.'),
  'ios.plist.ats_web':                 R('medium', 'ATS disabled for web content (NSAllowsArbitraryLoadsInWebContent)', 'MASVS-NETWORK-1', 319, 'Remove NSAllowsArbitraryLoadsInWebContent.'),
  'ios.plist.ats_exceptions':          R('medium', 'ATS exception domains allow insecure HTTP', 'MASVS-NETWORK-1', 319, 'Move these domains to HTTPS and remove the exceptions.'),
  'ios.plist.ats_tls':                 R('medium', 'ATS exception allows an outdated TLS version', 'MASVS-NETWORK-1', 327, 'Require TLS 1.2 or later.'),
  'ios.plist.file_sharing':            R('low',    'File sharing enabled (UIFileSharingEnabled)', 'MASVS-STORAGE-2', 552, 'Disable it unless users must reach the Documents folder, and keep nothing sensitive there.'),
  'ios.plist.url_schemes':             R('info',   'Custom URL schemes registered', 'MASVS-PLATFORM-1', 939, 'Prefer Universal Links; validate everything arriving through a custom scheme.'),
  'ios.plist.min_os':                  R('low',    'Supports old iOS versions (MinimumOSVersion)', 'MASVS-CODE-1', 1104, 'Raise the deployment target.'),
  'ios.plist.simulator':               R('medium', 'Built for the iOS Simulator', 'MASVS-CODE', 489, 'Distribute device builds only.'),
  'ios.profile.get_task_allow':        R('high',   'Debugging entitlement set (get-task-allow = true)', 'MASVS-RESILIENCE', 489, 'Distribution builds must not carry get-task-allow.'),
  'ios.profile.all_devices':           R('medium', 'Enterprise (in-house) distribution profile', 'MASVS-CODE', 1104, 'Use App Store / TestFlight distribution unless in-house distribution is intended.'),
  'ios.profile.dev_devices':           R('low',    'Development/ad-hoc profile bound to specific devices', 'MASVS-CODE', 489, 'Do not ship development or ad-hoc builds to production users.'),
  'ios.profile.expired':               R('medium', 'Provisioning profile has expired', 'MASVS-CODE', 298, 'Re-sign with a current profile.'),
  'ios.profile.push_dev':              R('low',    'Push environment is "development"', 'MASVS-CODE', 489, 'Use the production APNs environment for release builds.'),
  'ios.macho.no_pie':                  R('high',   'Executable is not position independent (no PIE)', 'MASVS-CODE-4', 693, 'Build with PIE (the default on current Xcode).'),
  'ios.macho.stack_exec':              R('high',   'Executable allows an executable stack', 'MASVS-CODE-4', 119, 'Remove -allow_stack_execute.'),
  'ios.macho.encrypted':               R('info',   'Binary is FairPlay-encrypted: code analysis was skipped', 'MASVS-RESILIENCE', null, 'Scan a decrypted / development-signed build to analyse the binary itself.'),
  'ios.macho.unsigned':                R('medium', 'Executable carries no code signature', 'MASVS-RESILIENCE', 347, 'Sign the app.'),
  'ios.macho.no_canary':               R('low',    'No stack-smashing protection in an Objective-C/C binary', 'MASVS-CODE-4', 693, 'Build with -fstack-protector-all.'),
  'ios.macho.no_arc':                  R('low',    'Objective-C code without ARC', 'MASVS-CODE-4', 416, 'Compile with ARC.'),
  'ios.code.weak_hash':                R('low',    'MD5 / SHA-1 / MD2 / MD4 in use', 'MASVS-CRYPTO-1', 328, 'Use SHA-256 or better (CryptoKit / CC_SHA256).'),
  'ios.code.weak_cipher':              R('high',   'Broken or weak cipher primitives imported (DES/RC4/RC2/Blowfish)', 'MASVS-CRYPTO-1', 327, 'Use AES-GCM (CryptoKit) or ChaCha20-Poly1305.'),
  'ios.code.ecb':                      R('medium', 'ECB-mode primitives imported', 'MASVS-CRYPTO-1', 327, 'Use an authenticated mode such as GCM.'),
  'ios.code.insecure_random':          R('low',    'rand()/random() used', 'MASVS-CRYPTO-1', 338, 'Use SecRandomCopyBytes or SystemRandomNumberGenerator.'),
  'ios.code.keychain_always':          R('high',   'Keychain items readable while the device is locked (kSecAttrAccessibleAlways)', 'MASVS-STORAGE-1', 922, 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or AfterFirstUnlock where background access is required).'),
  'ios.code.file_protection_none':     R('medium', 'Files written without data protection (NSFileProtectionNone)', 'MASVS-STORAGE-1', 311, 'Use NSFileProtectionComplete.'),
  'ios.code.uiwebview':                R('medium', 'Deprecated UIWebView in use', 'MASVS-PLATFORM-2', 1104, 'Migrate to WKWebView.'),
  'ios.code.wkwebview_file_access':    R('medium', 'WKWebView file-URL access preferences referenced', 'MASVS-PLATFORM-2', 200, 'Do not enable allowFileAccessFromFileURLs / allowUniversalAccessFromFileURLs.'),
  'ios.code.tls_validation_disabled':  R('high',   'TLS certificate validation appears to be disabled', 'MASVS-NETWORK-1', 295, 'Remove the override; keep default evaluation or implement full trust evaluation (SecTrustEvaluateWithError).'),
  'ios.code.custom_auth_challenge':    R('medium', 'Custom server-trust handling without a trust evaluation', 'MASVS-NETWORK-1', 295, 'In didReceiveChallenge evaluate the trust (SecTrustEvaluateWithError) before creating the credential.'),
  'ios.code.unsafe_c':                 R('low',    'Unsafe C string functions imported', 'MASVS-CODE-4', 120, 'Replace strcpy/strcat/sprintf/gets with bounded variants.'),
  'ios.code.nslog':                    R('info',   'NSLog used (logs readable on the device/console)', 'MASVS-STORAGE-2', 532, 'Strip logging from release builds and never log secrets.'),
  'ios.code.userdefaults_secrets':     R('low',    'Secret-looking keys alongside NSUserDefaults', 'MASVS-STORAGE-1', 312, 'Keep credentials/tokens in the Keychain, not NSUserDefaults (low confidence: key names only).'),
  'ios.code.no_pinning':               R('info',   'No certificate pinning detected', 'MASVS-NETWORK-2', 295, 'Consider pinning for apps handling highly sensitive data.'),
  'ios.code.cleartext_urls':           R('medium', 'Hardcoded http:// endpoints', 'MASVS-NETWORK-1', 319, 'Switch these endpoints to HTTPS.'),
  // ── Secrets (rule ids come from the shared secrets engine: secret.<ruleId>) ─
};

export const SECRET_RULE = R('high', 'Hardcoded secret', 'MASVS-CRYPTO-2', 798, 'Remove the secret from the package, rotate it, and fetch credentials at runtime from a backend.');

export function ruleMeta(id) {
  if (RULES[id]) return RULES[id];
  if (id.startsWith('secret.')) return SECRET_RULE;
  throw new Error(`unknown mobile rule: ${id}`);
}

export function lowerSeverity(sev) {
  const i = SEVERITIES.indexOf(sev);
  return i < 0 ? sev : SEVERITIES[Math.min(i + 1, SEVERITIES.length - 1)];
}
