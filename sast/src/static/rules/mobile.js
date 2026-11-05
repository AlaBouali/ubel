'use strict';

import { call, pattern, custom } from './helpers.js';
import { x } from './injection.js';
import { inFile } from './helpers.js';

const MOB = ['dart', 'swift'];
const SENSITIVE_KEY = /(?:token|password|passwd|secret|api_?key|apikey|auth|jwt|session|credential|pin\b|private_?key|refresh|bearer|otp|cvv|card|ssn)/i;

// ═══ Insecure local data storage ═════════════════════════════════════════════
const ST = { cls: 'insecure local data storage (mobile)', sev: 'medium', conf: 'medium', group: 'storage', fix: 'Keep tokens, passwords and keys in the platform secure store (Keychain with kSecAttrAccessibleWhenUnlockedThisDeviceOnly / Android Keystore via flutter_secure_storage), not in preferences, plain files or an unencrypted database.' };
const STORAGE_RULES = [
  call({ ...ST, id: 'storage-dart-prefs', langs: ['dart'], need: 'always', title: 'Sensitive value stored in unencrypted preferences', what: 'stores a credential in SharedPreferences, which is plain text on disk', args: 'any',
    callee: /(?:^|\.)(?:setString|setStringList|setInt|setBool|setDouble|write|put|putString)$/,
    when: (c, f) => SENSITIVE_KEY.test(c.args[0]?.lit || '') && /SharedPreferences|prefs|preferences|Hive|box\b|GetStorage|storage/i.test(c.callee + f.ctx.literal.slice(0, 2000)) && !/FlutterSecureStorage|secure_storage|EncryptedSharedPreferences/.test(c.callee) && !/FlutterSecureStorage|_secureStorage|secureStorage/.test(c.callee),
    desc: 'A credential-like value is written to SharedPreferences / Hive / GetStorage, which store plain text readable on rooted devices and in backups.' }),
  call({ ...ST, id: 'storage-swift-defaults', langs: ['swift'], need: 'always', title: 'Sensitive value stored in UserDefaults', what: 'stores a credential in UserDefaults, which is a plain property list on disk', args: 'any',
    callee: /(?:^|\.)(?:set|setValue|setObject|setPersistentDomain)$/, when: (c) => /UserDefaults|NSUserDefaults|defaults/i.test(c.callee + c.text.slice(0, 40)) && SENSITIVE_KEY.test(c.lit),
    desc: 'A credential-like value is written to UserDefaults, an unencrypted plist that is included in backups.' }),
  pattern({ ...ST, id: 'storage-swift-keychain-always', langs: ['swift'], title: 'Keychain item accessible while the device is locked', sev: 'medium', conf: 'high',
    re: /\bkSecAttrAccessibleAlways(?:ThisDeviceOnly)?\b|\bkSecAttrAccessibleAfterFirstUnlock\b(?!ThisDeviceOnly)/,
    desc: 'A Keychain item uses an accessibility class that keeps it readable while the device is locked (or migrates it to other devices).', fix: 'Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly (or WhenPasscodeSetThisDeviceOnly).' }),
  pattern({ ...ST, id: 'storage-swift-nofileprotection', langs: ['swift'], title: 'File written without data protection', conf: 'medium', sev: 'low',
    re: /\.noFileProtection\b|\bNSFileProtectionNone\b|\.completeFileProtectionUnlessOpen\b(?=[^\n]*(?:token|password|secret|key))/i,
    desc: 'A file is written with data protection disabled, so it stays readable while the device is locked.', fix: 'Use .completeFileProtection for sensitive data.' }),
  call({ ...ST, id: 'storage-dart-file', langs: ['dart'], need: 'always', title: 'Sensitive value written to a plain file', what: 'writes a credential to a plain file', args: 'any',
    callee: /(?:^|\.)(?:writeAsString|writeAsStringSync|writeAsBytes|writeAsBytesSync)$/, when: (c, f) => { const name = (c.callee.split('.')[0] || '') + (c.args[0]?.text || ''); return /(?:token|password|secret|apikey|api_key|credential|jwt)/i.test(name); },
    desc: 'A credential-like value is written to an unencrypted file on device storage.' }),
];

// ═══ Insecure TLS / certificate validation ═══════════════════════════════════
const TL = { cls: 'insecure TLS / certificate validation (mobile)', sev: 'high', conf: 'high', group: 'tls', fix: 'Do not override certificate validation. Trust the system store (or pin the expected certificate/public key) and keep ATS / cleartext restrictions on.' };
const TLS_RULES = [
  pattern({ ...TL, id: 'tls-dart', langs: ['dart'], title: 'Certificate validation disabled',
    re: /\bbadCertificateCallback\s*=\s*\([^)]*\)\s*(?:=>\s*true|\{\s*return\s+true\s*;?\s*\})|\bbadCertificateCallback\s*:\s*\([^)]*\)\s*=>\s*true|\bHttpOverrides\.global\s*=|\ballowBadCertificates\s*[:=]\s*true|\bonBadCertificate\s*[:=]\s*\([^)]*\)\s*=>\s*true|\bSecurityContext\s*\(\s*withTrustedRoots\s*:\s*false|\bvalidateCertificate\s*[:=]\s*false|\bignoreBadCertificate\s*[:=]\s*true/,
    check: (mm, flow, text) => !/HttpOverrides\.global\s*=/.test(mm[0]) || /badCertificateCallback[^;\n]*=>\s*true/.test(text),
    desc: 'The HTTP client accepts any TLS certificate (badCertificateCallback returns true), so a network attacker can read and modify all traffic.' }),
  custom({ ...TL, id: 'tls-swift-trustall', langs: ['swift'], title: 'Server trust accepted without evaluation',
    run(flow, emit) {
      const code = flow.ctx.literal;
      const re = /\bcompletionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(\s*trust\s*:\s*[\w.!?]*serverTrust|\bcompletionHandler\s*\(\s*\.useCredential\s*,\s*URLCredential\s*\(\s*trust/g; let mm;
      while ((mm = re.exec(code)) !== null) {
        const before = code.slice(Math.max(0, mm.index - 700), mm.index);
        if (/SecTrustEvaluate(?:WithError)?|\.evaluate\s*\(|SecTrustGetTrustResult|pinned|pinning|isValid|compare\s*\(|SecCertificate|serverTrust\s*\)\s*(?:==|!=)|policy\.evaluate/.test(before)) continue;
        emit(mm.index, { desc: 'The URLSession delegate accepts the server trust (.useCredential) without evaluating it, so any certificate is trusted.' });
      }
    } }),
  pattern({ ...TL, id: 'tls-swift-flags', langs: ['swift'], title: 'Certificate validation disabled',
    re: /\bkCFStreamSSLValidatesCertificateChain\b[^\n]{0,40}(?:false|kCFBooleanFalse|NSNumber\s*\(\s*value\s*:\s*false)|\ballowsAnyHTTPSCertificate\b|\bNSAllowsArbitraryLoads\b[^\n]{0,20}true|\bkCFStreamSSLAllowsAnyRoot\b|\bsetAllowsAnyHTTPSCertificate\b/i,
    desc: 'TLS certificate chain validation is disabled for this connection.' }),
  pattern({ ...TL, id: 'tls-cleartext', langs: MOB, title: 'Cleartext HTTP endpoint', sev: 'medium', conf: 'medium',
    re: /["'`]http:\/\/(?!localhost\b|127\.0\.0\.1\b|10\.0\.2\.2\b|0\.0\.0\.0\b|192\.168\.|\[::1\]|www\.w3\.org|schemas\.|xmlns|example\.(?:com|org)|ns\.adobe)[\w.\-]+(?::\d+)?[^"'`\s]*["'`]/,
    check: (mm, flow, text) => /(?:get|post|put|delete|patch|http|dio|client|request|url|uri|endpoint|api|base)/i.test(text.slice(Math.max(0, mm.index - 120), mm.index + 60)),
    desc: 'A plain-HTTP (not HTTPS) URL is used for a network call, so the traffic can be read and modified on the network path.', fix: 'Use https:// for every remote endpoint and keep App Transport Security / cleartext-traffic restrictions enabled.' }),
];

// ═══ Insecure WebView / JS bridge ═══════════════════════════════════════════
const WV = { cls: 'insecure WebView or JavaScript bridge (mobile)', sev: 'medium', conf: 'medium', group: 'webview', fix: 'Enable JavaScript only for content you control, disable file access and universal access from file URLs, restrict navigation to an allowlist of HTTPS origins, and expose only minimal, validated bridge handlers.' };
const WEBVIEW_RULES = [
  pattern({ ...WV, id: 'webview-dart', langs: ['dart'], title: 'WebView with unrestricted JavaScript / file access',
    re: /\bJavaScriptMode\.unrestricted\b|\bjavascriptMode\s*:\s*JavascriptMode\.unrestricted\b|\bjavaScriptEnabled\s*[:=]\s*true\b|\ballowFileAccess(?:FromFileURLs)?\s*[:=]\s*true\b|\ballowUniversalAccessFromFileURLs\s*[:=]\s*true\b|\bsetJavaScriptEnabled\s*\(\s*true\s*\)|\bsetAllowFileAccess(?:FromFileURLs)?\s*\(\s*true\s*\)|\baddJavaScriptChannel\s*\(|\bJavascriptChannel\s*\(|\binitialSettings\s*:[^\n]*javaScriptEnabled\s*:\s*true/,
    desc: 'A WebView runs with JavaScript unrestricted, file access, or a JavaScript channel (native bridge). If it loads any untrusted content, page script can call into the app or read local files.' }),
  pattern({ ...WV, id: 'webview-swift', langs: ['swift'], title: 'WebView with permissive settings / native bridge',
    re: /\bjavaScriptCanOpenWindowsAutomatically\s*=\s*true\b|\ballowFileAccessFromFileURLs\b|\ballowUniversalAccessFromFileURLs\b|setValue\s*\(\s*true\s*,\s*forKey\s*:\s*["'](?:allowFileAccessFromFileURLs|allowUniversalAccessFromFileURLs)["']\s*\)|\.addScriptMessageHandler\s*\(|\bUIWebView\b|\bjavaScriptEnabled\s*=\s*true\b|\.allowsInlineMediaPlayback\b(?=[^\n]*false)|\bloadFileURL\s*\([^)]*allowingReadAccessTo\s*:\s*(?:URL\s*\(\s*fileURLWithPath\s*:\s*["']\/["']\s*\)|\w*[Rr]oot\w*)/,
    desc: 'A WKWebView is configured with permissive file/script settings or exposes a native message handler; untrusted page content could reach native code or local files.' }),
];

// ═══ Unvalidated deep link / URL scheme / platform channel ═══════════════════
const DL = { cls: 'unvalidated deep link / URL scheme / platform channel input (mobile)', sev: 'medium', group: 'deeplink', fix: 'Treat deep-link / platform-channel data as untrusted: validate the scheme and host against an allowlist, parse parameters into typed values, and never pass them straight to a WebView, file path or navigation call.' };
const DL_SINKS_DART = x('launchUrl|launch|launchUrlString|(?:\\w+\\.)?(?:loadRequest|loadUrl|loadHtmlString)|(?:Navigator\\.(?:of\\(\\w+\\)\\.)?|\\w+\\.)?(?:pushNamed|pushReplacementNamed|pushNamedAndRemoveUntil)|(?:\\w+\\.)?(?:go|push|pushReplacement|goNamed)|File|Directory|Process\\.run|Process\\.start|(?:\\w+\\.)?(?:rawQuery|execute|rawInsert|rawUpdate|rawDelete)');
const DEEPLINK_RULES = [
  call({ ...DL, id: 'deeplink-dart', langs: ['dart'], what: 'is passed from a deep link / platform channel into navigation, a WebView, a file path or a database query', args: 'any', callee: DL_SINKS_DART, }),
  call({ ...DL, id: 'deeplink-swift', langs: ['swift'], what: 'is passed from a URL scheme / universal link / notification into navigation, a WebView, a file path or a query', args: 'any',
    callee: /^(?:UIApplication\.shared\.open|(?:\w+\.)?(?:load|loadHTMLString|loadFileURL|evaluateJavaScript)|(?:\w+\.)?(?:performSegue|present|pushViewController|setValue)|FileManager\.default\.\w+|(?:\w+\.)?(?:openURL|open)|URLRequest|(?:\w+\.)?(?:executeQuery|executeUpdate|execute))$/,
    when: (c) => c.callee !== 'setValue' }),
];

// ═══ Client-side-only biometric / local authentication ══════════════════════
const BIO = { cls: 'client-side-only biometric / local authentication gate (mobile)', sev: 'medium', conf: 'low', group: 'biometric', fix: 'Bind the biometric check to a cryptographic key or secret that the OS only releases after authentication (Keychain item with SecAccessControl .biometryCurrentSet / Android Keystore key requiring user authentication) or verify a server-issued challenge; do not rely on a boolean result.' };
const BIOMETRIC_RULES = [
  call({ ...BIO, id: 'biometric-dart', langs: ['dart'], need: 'always', title: 'Biometric check returns only a boolean', what: 'authenticates locally and only returns true/false, which can be bypassed with runtime instrumentation', args: 'any', allowNoArgs: true,
    callee: /(?:^|\.)(?:authenticate|authenticateWithBiometrics)$/, when: (c, f) => /local_auth|LocalAuthentication|auth\b/i.test(c.callee + f.ctx.literal.slice(0, 3000)),
    verify: (cand, flow) => (inFile(flow, /FlutterSecureStorage|flutter_secure_storage|biometric_storage|BiometricStorage|AndroidOptions|encryptedSharedPreferences|authenticationRequired|signature|challenge/) ? { valid: false, reason: 'the result is tied to secure storage / a cryptographic operation in this file' } : null) }),
  call({ ...BIO, id: 'biometric-swift', langs: ['swift'], need: 'always', title: 'Biometric check returns only a boolean', what: 'authenticates locally with LAContext and only returns true/false, which can be bypassed with runtime instrumentation', args: 'any', allowNoArgs: true,
    callee: /(?:^|\.)evaluatePolicy$/,
    verify: (cand, flow) => (inFile(flow, /SecAccessControl|kSecAttrAccessControl|\.biometryCurrentSet|\.biometryAny|\.userPresence|kSecUseAuthenticationContext|SecKeyCreateSignature|kSecAccessControl/) ? { valid: false, reason: 'a Keychain item / key protected by SecAccessControl is used in this file' } : null) }),
];

export const MOBILE_RULES = [...STORAGE_RULES, ...TLS_RULES, ...WEBVIEW_RULES, ...DEEPLINK_RULES, ...BIOMETRIC_RULES];
