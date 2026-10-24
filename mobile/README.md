# UBEL Mobile — Android / iOS App Scanning

`ubel-mobile` statically analyses an Android **`.apk`** or **`.aab`** (App Bundle) or an iOS **`.ipa`** (and split bundles: `.xapk`, `.apks`, `.apkm`) for

- **hardcoded secrets** — API keys, tokens, private keys, connection strings … found in code, string resources, plists, bundled files and native libraries;
- **insecure storage and data handling** — backups enabled, world-readable files, weak or constant crypto keys/IVs, bundled keystores and databases, Keychain / data-protection attributes;
- **misconfigurations** — debuggable builds, cleartext traffic, ATS exceptions, exported components, WebView settings, TLS-validation bypasses, weak signing, missing binary hardening.

Nothing in the app is executed or uploaded. **No third-party libraries and no external binaries** are used — ZIP, Android binary XML, `resources.arsc`, DEX, plist (XML and binary), Mach-O, ELF and PKCS#7/X.509 are read by UBEL's own code on Node built-ins (`zlib`, `crypto`, `fs`). When exact supported package identities and versions can be extracted, the scanner sends only those package URLs (PURLs) to OSV.dev via UBEL's shared `sca/engine.js` lookup/enrichment functions. App source, binaries, manifests, and secret values are not uploaded. There is no `aapt`, `apktool`, `jadx`, `otool` or `codesign` to install.

```bash
ubel-mobile app-release.apk
ubel-mobile app-release.aab
ubel-mobile Bank.ipa --fail-on high --min-severity medium
ubel-mobile app.xapk --working-dir ./reports-dir
```

## Options

| Option | Default | Meaning |
|---|---|---|
| `<package>` | — | `.apk`, `.aab`, `.ipa`, `.xapk`, `.apks` or `.apkm` (detected from the content, not the extension) |
| `--working-dir <path>` | cwd | Directory whose `.ubel/` folder receives the reports |
| `--min-severity <s>` | `info` | Drop issues below `critical` / `high` / `medium` / `low` / `info` from the **report**. Display only: the `--fail-on` gate always sees every finding |
| `--fail-on <s>` | `critical` | Exit `2` when issues (vulnerabilities, secrets, misconfigurations) or dependency advisories at or above the severity exist; `none` disables the gate (always exit `0`); `5:high` tolerates five. Anything else is a usage error |
| `--online` | off | Also run the checks that need the network: `assetlinks.json` of every `android:autoVerify` host against the signing certificate, one unauthenticated shallow read of a Firebase Realtime Database, one Remote Config fetch with the app's own API key (see [Online checks](#online-checks---online)) |
| `--allow-partial` | off | Accept an incomplete analysis (exit `0` instead of `3`) |
| `--max-entry-mb <n>` | `256` | Largest single file inside the package that is inflated and scanned |
| `--verbose` / `--quiet` | | More / less console output |

### Exit codes (for CI)

| Code | Meaning |
|---|---|
| `0` | the gate passed **and** the analysis was complete (or `--fail-on none`, or `--allow-partial` accepted the gaps) |
| `1` | the scan failed: file missing, unreadable or not a supported package, or the report could not be written |
| `2` | the `--fail-on` gate tripped, **or** bad arguments (a one-line reason is printed to stderr either way) |
| `3` | nothing tripped the gate, but part of the package **could not be analysed** (a DEX that failed to parse, an unreadable or oversized file, an exhausted scan budget, a FairPlay-encrypted binary, an LZMA-compressed Unity bundle, an unrecognised assembly store, a failed OSV lookup …). A clean result over partial coverage is not a pass; `--allow-partial` accepts it |

How the gate decides, so a green build means something: it counts **every** finding and dependency advisory, whatever `--min-severity` hides from the report (that option only shapes what you read; the stderr line says how many were hidden). Gaps are listed in the report (`analysis.gaps`, and in the HTML notes), the machine-readable verdict is in `gate` in the JSON (`tripped`, `hits`, `incomplete`, `exit_code`), and the executive summary says "No issues found (analysis incomplete)" instead of "No issues found". Advisories OSV gives no severity for are reported (`unrated_advisories`) and count only against `--fail-on info`. Bad arguments share exit `2` with a tripped gate, as in the other UBEL CLIs; the stderr message tells them apart.

Like every UBEL CLI it also accepts `asset-id`, `set-asset-id <id>`, `version` and `--asset-id <id>`.

## Output

JSON and HTML only. The HTML report includes a **Dependencies** tab with extracted package evidence, package URLs, OSV lookup state, and advisory details/fix versions where OSV provides them. Android Maven identities are recovered from `pom.properties` and Maven-style `META-INF/*.version` markers when present; iOS checks use embedded Swift Package Manager pins and CocoaPods lock metadata when present. Native `.so` / `.dylib` binaries and embedded native frameworks are excluded from dependency enumeration and are never queried against OSV. Separate native binary hardening and secret checks are unchanged.

- `.ubel/reports/latest.mobile.json` and `.ubel/reports/latest.mobile.html` — overwritten on every run;
- `$HOME/.ubel/history/<asset_id>/<timestamp>.mobile.zip` — `report.mobile.json` + `report.mobile.html`, kept for the asset's history.

The report carries the standard UBEL identity fields (`asset_id`, `asset_name`, `asset_type: "mobile"`, `machine_id`, `report_id`), the scanned file's SHA-256, one summary object per app (package/bundle id, versions, SDK levels, permissions, signing certificates, embedded libraries and frameworks), a plain-language **executive summary** (risk rating, what it means, most important issues, next steps), the issues, analysis notes and — when an earlier mobile report exists for the same app — a **Diffs** section (new / fixed / unchanged).

Issues are split into three **separate, non-overlapping** lists — `vulnerabilities`, `secrets` and `misconfigurations` in the JSON, one tab each in the HTML report. Every issue is in exactly one of them (its `category` field says which): `secret` for rules `secret.*`; `misconfiguration` for manifest / network-security-config / plist / provisioning / signing / native-hardening rules and the TLS, WebView, cleartext and debug-build checks in the DEX and Mach-O scans (the pattern is `MISCONFIG_RULE` in `lib/report.js`); `vulnerability` for everything else (weak crypto, constant keys/IVs, insecure storage and data handling, bundled keystores and databases …). `summary.total` / `summary.counts` cover all three lists together and `summary.by_category` gives the split. The Diffs section uses the same three groups; it still compares against reports written before the split. Dependency advisories from OSV.dev are separate and live on the Dependencies tab (`dependencies`). Each issue carries a rule id, severity, OWASP MASVS control, CWE, evidence, remediation, `confidence` and `origin` (`app`, `unknown` or `library`: issues found only inside known third-party library code are reported one severity level lower; `unknown` marks renamed/obfuscated classes outside the app's own package, which are most likely library code but cannot be proven to be, so they keep their full severity).

Secrets are never written to a report: only a masked preview (`ghp_…(40 chars)`). All app-controlled text is HTML-escaped in the HTML report.

## What is analysed

**Android (`.apk`)**

| Area | What is read |
|---|---|
| `AndroidManifest.xml` (binary XML) | debuggable / testOnly / allowBackup / cleartext flags, min/target SDK, sharedUserId, exported activities, services, receivers and content providers without a permission, weak custom permissions, risky permissions, deep links without `autoVerify`, `meta-data` values (scanned for secrets) |
| `res/xml/*` | network security config (cleartext, user CAs, expired pin-sets, pinning), Cordova `config.xml` open origins, all values scanned for secrets |
| `resources.arsc` | every string resource (e.g. `google_api_key`) scanned with its resource name |
| `classes*.dex` | all strings, `static final` constants, `BuildConfig.DEBUG`, class hierarchy and a constant-tracking bytecode walk: weak/ECB ciphers, constant keys and IVs, weak hashes/TLS protocols, empty `checkServerTrusted`, allow-all `HostnameVerifier`, `SslErrorHandler.proceed`, WebView file access / mixed content / debugging / JavaScript interfaces, world-accessible storage, external storage, sensitive-looking data in `Log.*` calls, plaintext `SharedPreferences` / SQLite storage, hardcoded credentials in constants, JWT literals and JWT/HMAC signing secrets, dynamic code loading, `Runtime.exec`, device identifiers, debug libraries, `http://` endpoints, Firebase URLs, pinning markers |
| signing | v1 (JAR/PKCS#7) and v2/v3/v3.1 (APK Signing Block) certificates: debug certificate, weak algorithm, short key, expiry, v1-only / Janus exposure |
| `lib/**/*.so` | **per-ABI ELF hardening** — every `lib/<abi>/<name>.so` copy is checked on its own for PIE, NX (executable stack, missing `PT_GNU_STACK`, writable+executable segments), RELRO, stack canary, FORTIFY_SOURCE indicators, text relocations and RPATH/RUNPATH (see [Native library hardening](#native-library-hardening)); printable strings of the preferred-ABI copy are scanned for secrets |
| everything else | keystores/private keys, `.env`/credential/VCS files, backups, bundled databases, embedded `.apk`/`.dex`/`.jar`, Flutter debug kernels, source maps; text files, React Native / Hermes bundles, Xamarin/Unity DLLs (UTF-16) scanned for secrets |

**Android App Bundles (`.aab`)** — every module (base, dynamic features, asset packs) is analysed with the same checks as an APK, through the bundle's protobuf manifest, `res/xml` files and `resources.pb`. The bundle is reported as one app (`modules` lists the parts); feature modules do not repeat app-level defaults such as backup or SDK levels. `BUNDLE-METADATA/…/dependencies.pb` supplies the build's exact Maven coordinates, which go to the OSV lookup. Signing is read from the bundle's own jar signature (debug certificate, weak algorithm, expiry); APK-only signature-scheme findings do not apply to a bundle.

**Cross-platform frameworks (Android and iOS)** — their code does not live in DEX or Mach-O, so each gets a reader of its own format instead of a printable-string pass:

| Framework | What is read |
|---|---|
| React Native | `index.android.bundle` / `main.jsbundle` / `*.hbc`. **Hermes bytecode**: the string table is read through its own index (every literal and identifier as a separate, complete string; layout validated against real `hermesc` output, falls back to printable runs with a note if the layout is unknown). **Plain JS**: string literals and `key: "value"` pairs are extracted from minified code. Flags a development bundle (`__DEV__ = true`), readable source, and credential-looking keys used with unencrypted `AsyncStorage`. (Before this, `index.android.bundle` was not scanned at all.) |
| Flutter | `libapp.so` / `App.framework` Dart AOT snapshot (ASCII and UTF-16 strings, `package:` names → Dart package list), the Dart/engine version from `libflutter.so`, debug JIT snapshots (`kernel_blob.bin`, `isolate_snapshot_data`) flagged. The report notes that Dart HTTP traffic ignores the Android network-security config and system proxy |
| Unity | **IL2CPP** `global-metadata.dat`: the exact C# string literals and the identifier table (a `CertificateHandler` / `ValidateCertificate` pair is flagged for review). **Mono** `Managed/*.dll` through the .NET reader. `boot.config` (`player-connection-debug=1` = Development Build), serialized scene/asset files (inspector-entered keys end up there), and **UnityFS** bundles (stored and LZ4/LZ4HC; LZMA-compressed bundles are reported as not inspected) |
| Xamarin / .NET MAUI | Managed assemblies, plain or **XALZ/LZ4-compressed** (the Xamarin.Android release default; LZ4 only removes repeats, so a raw string scan still sees some unique text but in fragments, and cannot read the identifier heap or PDB path the checks below depend on) or packed in an **assembly store** (`assemblies.blob`, `libassembly-store.so`). The `#US` heap gives the exact C# literals; the identifier heap flags `DangerousAcceptAnyServerCertificateValidator` (and, at low confidence, custom validation callbacks); the PDB path flags Debug builds and leaked build-machine paths. SDK assemblies (`System.*`, `Mono.*`, `Xamarin.AndroidX.*`, …) are skipped |

**iOS (`.ipa`)**

| Area | What is read |
|---|---|
| `Info.plist` (XML or binary) | App Transport Security (arbitrary loads, insecure exception domains, old TLS), `UIFileSharingEnabled`, URL schemes, `MinimumOSVersion`, simulator builds; every value scanned for secrets |
| `embedded.mobileprovision` | distribution type (enterprise / ad hoc / development), expiry, entitlements |
| code signature | entitlements embedded in the Mach-O (`get-task-allow`, `aps-environment`, …) |
| main binary, frameworks, extensions (Mach-O) | PIE, executable stack, code signature, FairPlay encryption, stack canary, ARC; imported symbols (`CC_MD5`, `kSecAttrAccessibleAlways`, `NSFileProtectionNone`, `UIWebView`, `rand`, unsafe C functions, `NSLog`, …); strings (secrets, `http://` endpoints, TLS-bypass selectors, auth-challenge handling without trust evaluation, pinning libraries, secret-looking `NSUserDefaults` keys) |
| everything else | the same bundled-file checks and secret scan as on Android (plists and `.strings` files included) |

**Anti-analysis inventory.** A class that combines at least three *distinct* environment-check indicators — debugger (`Debug.isDebuggerConnected`, `TracerPid`), emulator (`goldfish`, `ranchu`, `/dev/qemu_pipe`, `Build.*` properties), root (`su`, Magisk, `test-keys`) or hooking framework (Frida, Xposed) — is reported as `android.dex.anti_analysis` (info, MASVS-RESILIENCE). One indicator never counts: all `Build.*` reads together are a single indicator, so an analytics SDK reading `Build.MODEL` cannot reach the threshold. One check is one indicator: `exec("su")` and the `"su"` literal it runs, or `Build.TAGS` and the `"test-keys"` it is compared with, count once. Known library code is skipped; renamed classes outside the app package are reported at low confidence.

**Behavior inventory (`app.behavior`).** What the code does, as counts per API reference split by class origin (`app` / `unknown` / `library`): file access, network, inter-app communication, process execution, reflection, native code loading and sensitive device APIs (location, camera, microphone, SMS, clipboard, installed packages). It is a summary on the app record, **not** findings: nearly every app does all of this. Action-based (implicit) intents are read from the `Intent(String …)` constructor, whose first parameter type is checked in the DEX proto table; the constant actions are listed in `intent_actions`, explicit `Intent(Context, Class)` constructions are counted in `explicit_intents`. Actions built at runtime are not visible.

**Base64 decode pass.** String-pool entries of 24+ characters that are valid base64 and decode to at least 90 % printable ASCII are decoded and passed through the secrets engine (wrapped API keys, URLs, JSON config). Decoded `http://` URLs join the cleartext-endpoint check. A blob that decodes to binary — ciphertext, or a second obfuscation layer such as a repeating-key XOR — is deliberately not recovered: that needs the key and the decode routine from the app's own code, which differs per app.

### Online checks (`--online`)

Off by default; without it nothing leaves the machine except the OSV.dev dependency lookup. With it, `ubel-mobile` contacts hosts **named by the app**. The checks are read-only, never follow redirects, never send credentials, refuse IP addresses and private/internal host *names* (the name is checked, not what DNS answers for it), and a request that fails is a coverage gap (exit `3` unless `--allow-partial`), not a pass. Only use it on apps you are allowed to test.

| Check | Request | Rule |
|---|---|---|
| App Links | `GET https://<host>/.well-known/assetlinks.json` per `android:autoVerify` host (`*.` stripped), compared with the package name and the signing certificate's SHA-256 (skipped for `.aab`: Play re-signs with its own key) | `android.online.assetlinks_missing`, `android.online.assetlinks_mismatch` |
| Firebase Realtime Database | one `GET <db>/.json?shallow=true` for each database URL found in the app (`<db>.firebaseio.com`, and regional `<db>.<region>.firebasedatabase.app` instances such as `europe-west1`): HTTP 200 means the root is world-readable. No data is read and nothing is written | `android.online.firebase_db_open` |
| Firebase Remote Config | one fetch with `google_api_key` / `google_app_id` from the app's resources, exactly what the Firebase SDK sends. Parameter values are scanned for secrets; a restricted key (HTTP 400/403) is reported as `restricted` in `app.online_checks`, never bypassed | `android.online.remote_config_exposed` |

Results are also summarised in `app.online_checks`; the API key is masked there.

### Native library hardening

An APK ships a separately built copy of each native library per ABI (`lib/arm64-v8a`, `lib/armeabi-v7a`, `lib/x86`, `lib/x86_64`, …), so the same library can be hardened in one ABI and not in another. ubel-mobile checks **every copy**, and each finding names the exact `abi/library` pair (for example `x86/libtool-checker.so`). The report's **Native Binaries** tab shows the full per-ABI table, and the JSON carries it as `apps[].native_hardening` (`total`, `libraries`, `abis`, `failing` counts, and one record per binary with the checks it fails).

| Check | How it is decided | Rule(s) |
|---|---|---|
| **PIE** | `ET_DYN` is position independent; `ET_EXEC` is not. A library with text relocations (`DT_TEXTREL`, or `DF_TEXTREL` in `DT_FLAGS`) loads but is not truly position independent code, so that is reported separately. A `ET_DYN` with `PT_INTERP` / `DF_1_PIE` is an executable shipped as `lib*.so` and is labelled `exe` | `no_pie`, `textrel` |
| **NX** | `PT_GNU_STACK` present and not executable. An executable `PT_GNU_STACK`, a *missing* `PT_GNU_STACK` header (NX not asserted) and any `PT_LOAD` that is both writable and executable are reported separately | `exec_stack`, `no_gnu_stack`, `wx_segment` |
| **RELRO** | `PT_GNU_RELRO` gives partial RELRO; full RELRO also needs immediate binding (`DT_BIND_NOW`, `DF_BIND_NOW` or `DF_1_NOW`) | `no_relro`, `partial_relro` |
| **Stack canary** | an import of `__stack_chk_fail` / `__stack_chk_guard`. A library with no stack buffers legitimately has none, so the finding needs a reason to expect one: the library imports unbounded copy functions (`strcpy`, `strncpy`, `stpcpy`, `strcat`, `strncat`, `sprintf`, `vsprintf`, `gets`, `memcpy`, `memmove`), **or another ABI copy of the same library has a canary** (the same source built without the protector for one ABI) | `no_canary` |
| **FORTIFY** | imports of the checked libc variants (`__memcpy_chk`, `__strcpy_chk`, `__sprintf_chk`, `__open_2`, …) next to the plain ones: `yes` (only checked), `partial` (both, which is normal for a fortified build), `no` (fortifiable functions imported, no checked variant), `n/a`. Only `no` raises a finding | `no_fortify` |
| **RPATH / RUNPATH** | `DT_RPATH` / `DT_RUNPATH` present | `rpath` |

How the ELF is read:

- Symbols and strings are located **the way the dynamic loader finds them**, through `DT_SYMTAB` / `DT_STRTAB` and the `DT_HASH` / `DT_GNU_HASH` table, with the section headers only as a fallback. A library whose section table was stripped or zeroed (typical of packed or obfuscated builds) is therefore still assessed instead of looking "clean" or "unhardened".
- When no symbol table can be found at all (for example a statically linked binary), the canary and FORTIFY columns show `unknown`, the library is noted in the analysis notes, and **no finding is raised from missing evidence**.
- The preferred ABI of each library (arm64-v8a first) is checked and string-scanned first. The other ABI copies are hardening-checked afterwards under a 512 MB read budget (and at most 600 binaries in total); anything skipped is reported as a coverage gap, never silently dropped.
- Little-endian ELF only (every Android ABI is). A big-endian ELF is a coverage gap; a `.so` that is not an ELF at all is noted.

Canary and FORTIFY are **indicators, not proof**. The canary check is inferred from imports; Rust, Go and other non-C toolchains typically do not use the stack protector at all, so a missing canary there is a toolchain property rather than a build flag. A fortified build still imports plain `memcpy` wherever the compiler could not prove the destination size, and a statically linked libc would hide both. Severities reflect that: `no_fortify` is low severity and low confidence, `no_canary` is low severity and medium confidence, while PIE, NX and RELRO are read straight from the ELF headers.

## Limits

- **Static only.** Nothing in the app runs. By default the only network requests are the OSV.dev lookups for extracted, versioned package URLs; backend behavior, Firebase database rules, and the validity of a found key are *not* tested. `--online` adds the three read-only checks listed above and nothing else: it does not test keys against other services or write anything.
- **No decompiler.** Findings come from configuration, constant tables, API references and call arguments, and binary metadata — not data-flow analysis. The DEX walker tracks constants straight-line within a method, so it sees `Cipher.getInstance("DES/ECB/…")` and constant keys, but not values assembled at runtime. Findings marked `confidence: low|medium` are leads to verify.
- **Obfuscation.** R8/ProGuard renames app classes but not framework calls or string constants, so most checks still work. It also renames *library* classes (Material becomes `c.c.a.a.…`), so package prefixes alone cannot separate app from library code: a class is `app` when it sits under the manifest package or a manifest component's package, `library` when it matches a known library prefix, and `unknown` when it is renamed and outside the app's package; packers, DexGuard-style string encryption, Hermes bytecode and code downloaded at runtime are only partly visible.
- **App Store IPAs are FairPlay-encrypted** (`cryptid=1`): `Info.plist`, provisioning, entitlements, bundled files and imported symbols are analysed, but strings inside the binary are not. Scan a development-signed or decrypted build for full coverage. The report says so.
- **Framework code is read as data, not decompiled.** Hermes bytecode, Dart snapshots, IL2CPP binaries and .NET IL are not decompiled, so logic (a certificate callback that returns `true`, a token written to storage) cannot be proven from them. What is found is what the containers expose: string literals, identifiers, configuration, build flags. Dart-side TLS handling in particular is invisible; Dart package *versions* are not shipped, so Flutter dependencies are listed by name only and are not looked up in OSV. Unreadable layouts are reported as coverage gaps (exit `3`), not skipped silently.
- **Bundle caveats.** Unity LZMA-compressed UnityFS bundles and encrypted/custom-packed `global-metadata.dat` are not read (reported). The `.aab` assembly-store and Hermes layouts are version-dependent: they are validated before use and a mismatch is reported rather than guessed. Bundle modules are analysed from the `.aab`; an `.aab` that is not jar-signed simply has no signature findings.
- **Limits protect the scanner:** per-file and total inflated-size caps, a ratio check, a bounded string budget for the secrets scan. When a budget is hit the report says what was skipped.
- **Sensitive-data rules are heuristics.** There is no data-flow analysis, so `logging_sensitive`, `plaintext_prefs` and `plaintext_database` work from what is visible in one method: *direct* evidence (a constant tag, message, preference key or `ContentValues` key that names something sensitive; confidence `medium`) or *nearby* evidence (the same method also loads a sensitive-looking label such as `"accesstoken"`, because the logged/stored text is built at runtime; confidence `low`). Prose such as SDK error messages and class-name log tags are ignored, known library code is skipped, and renamed (`unknown`-origin) code is always reported at `low` confidence. If `androidx.security.crypto` or SQLCipher is packaged the storage rules drop to `low`, since the same APIs may be encrypted. Treat them as pointers for manual review.
- **Hardcoded-credential rules are name-plus-value checks.** `hardcoded_credential` needs a constant whose *name* says password/secret/token/key **and** a value that looks like a secret (not a placeholder, key name, identifier or URL); an all-lowercase word such as `"letmein"` is deliberately not reported. Secrets with a known vendor format, long key/value pairs and `Bearer`/`Basic` headers are still caught by the shared secrets engine. JWT signing-secret detection recognises jjwt, java-jwt and Nimbus calls with constant arguments; hand-rolled `SecretKeySpec` is covered by `android.dex.hardcoded_key`. Bypassing root/emulator detection is runtime behaviour and out of scope for a static scan; the *presence* of such checks is reported by `android.dex.anti_analysis`.
- **Dependency lookup covers only exact identities.** A component is sent to OSV.dev only when a versioned package URL could be extracted (e.g. from `META-INF/*.version` files). Anything else (for example "Firebase Android SDK" or "Google Play Services" detected by namespace only) is reported as `not_queryable`, never as clean; failed lookups are `lookup_error` / `lookup_incomplete`.
- It scans the package you give it, not the app's backend.

## Programmatic use

```js
import { scanPackage, scanMobileDependencies } from '@arcane-spark/ubel-node/mobile';
const scan = scanPackage('/path/app.apk', { maxEntryMb: 256 });
const checked = await scanMobileDependencies(scan.dependencies);
scan.findings.sorted();   // [{ rule, severity, title, description, remediation, masvs, cwe, artifact, evidence, confidence, origin, fingerprint, ... }]
checked.dependencies;      // inventory entries with OSV lookup status and advisory details
checked.summary;           // counts for queryable, vulnerable, clean, not-queryable, and failed lookups
```

`scanPackage` reads the package and returns the findings and dependency inventory candidates; it writes no files and does not itself perform network lookups (the CLI does that before writing reports). For programmatic OSV lookup, `scanMobileDependencies` is also exported from `@arcane-spark/ubel-node/mobile` and returns the inventory, lookup statuses, advisory details, and summary.

## Rules

| Rule | Default severity | MASVS | What |
|---|---|---|---|
| `android.manifest.debuggable` | high | MASVS-RESILIENCE | App is debuggable (android:debuggable="true") |
| `android.manifest.test_only` | medium | MASVS-CODE | App is marked testOnly |
| `android.manifest.backup` | medium | MASVS-STORAGE-2 | App data can be extracted by backup (android:allowBackup) |
| `android.manifest.cleartext` | medium | MASVS-NETWORK-1 | Cleartext (HTTP) traffic permitted app-wide |
| `android.manifest.cleartext_default` | low | MASVS-NETWORK-1 | Cleartext traffic permitted by default (targetSdk < 28) |
| `android.manifest.min_sdk` | low | MASVS-CODE-1 | Supports old Android versions (minSdkVersion) |
| `android.manifest.target_sdk` | low | MASVS-CODE-1 | Targets an old Android API level (targetSdkVersion) |
| `android.manifest.shared_user_id` | medium | MASVS-PLATFORM-1 | sharedUserId shares the app sandbox with other apps |
| `android.manifest.legacy_storage` | low | MASVS-STORAGE-2 | Opts out of scoped storage (requestLegacyExternalStorage) |
| `android.manifest.exported_provider` | high | MASVS-PLATFORM-1 | Content provider reachable by other apps without a permission |
| `android.manifest.exported_service` | medium | MASVS-PLATFORM-1 | Service reachable by other apps without a permission |
| `android.manifest.exported_receiver` | medium | MASVS-PLATFORM-1 | Broadcast receiver reachable by other apps without a permission |
| `android.manifest.exported_activity` | low | MASVS-PLATFORM-1 | Exported activities (other than the launcher) |
| `android.manifest.weak_permission` | medium | MASVS-PLATFORM-1 | Custom permission has a weak protectionLevel |
| `android.manifest.risky_permissions` | medium | MASVS-PRIVACY-1 | High-impact permissions requested |
| `android.manifest.permissions` | info | MASVS-PRIVACY-1 | Dangerous permissions requested |
| `android.manifest.deeplinks` | info (low when an http(s) link has no `autoVerify`) | MASVS-PLATFORM-1 | Deep links / custom URL schemes |
| `android.nsc.cleartext` | medium | MASVS-NETWORK-1 | Network security config permits cleartext traffic |
| `android.nsc.user_ca` | medium | MASVS-NETWORK-1 | Network security config trusts user-installed CAs |
| `android.nsc.pin_expired` | low | MASVS-NETWORK-2 | Certificate pin-set has expired |
| `android.network.no_pinning` | info | MASVS-NETWORK-2 | No certificate pinning detected |
| `android.cordova.access_origin` | medium | MASVS-PLATFORM-2 | Cordova/WebView config allows any origin |
| `android.signing.unsigned` | high | MASVS-RESILIENCE | Package carries no signature |
| `android.signing.debug_cert` | high | MASVS-RESILIENCE | Signed with a debug certificate |
| `android.signing.weak_algorithm` | medium | MASVS-RESILIENCE | Signing certificate uses a weak signature algorithm |
| `android.signing.weak_key` | medium | MASVS-RESILIENCE | Signing key is too short |
| `android.signing.expired` | medium | MASVS-RESILIENCE | Signing certificate has expired |
| `android.signing.v1_only` | medium | MASVS-RESILIENCE | Only the legacy v1 (JAR) signature is present |
| `android.signing.janus` | low | MASVS-RESILIENCE | v1 signature on an app that supports Android 5.0–8.0 (Janus, CVE-2017-13156) |
| `android.dex.weak_cipher` | high | MASVS-CRYPTO-1 | Broken or weak cipher in use |
| `android.dex.ecb_mode` | medium | MASVS-CRYPTO-1 | ECB mode (or default AES mode) in use |
| `android.dex.weak_hash` | low | MASVS-CRYPTO-1 | MD5 / SHA-1 in use |
| `android.dex.hardcoded_key` | high | MASVS-CRYPTO-2 | Cryptographic key built from a constant in code |
| `android.dex.static_iv` | medium | MASVS-CRYPTO-1 | Constant IV / nonce in code |
| `android.dex.insecure_random` | low | MASVS-CRYPTO-1 | SecureRandom is seeded explicitly |
| `android.dex.weak_tls_protocol` | medium | MASVS-NETWORK-1 | Outdated SSL/TLS protocol requested |
| `android.dex.trust_all_certs` | high | MASVS-NETWORK-1 | TrustManager accepts every certificate |
| `android.dex.allow_all_hostnames` | high | MASVS-NETWORK-1 | Hostname verification disabled |
| `android.dex.custom_trust_manager` | info | MASVS-NETWORK-1 | Custom TrustManager implementations |
| `android.dex.webview_ssl_proceed` | high | MASVS-NETWORK-1 | WebView ignores TLS errors (SslErrorHandler.proceed) |
| `android.dex.webview_js_interface` | medium | MASVS-PLATFORM-2 | WebView exposes a Java object to JavaScript |
| `android.dex.webview_file_access` | high | MASVS-PLATFORM-2 | WebView allows file:// content to read other files / origins |
| `android.dex.webview_mixed_content` | medium | MASVS-NETWORK-1 | WebView allows mixed (HTTP in HTTPS) content |
| `android.dex.webview_debugging` | medium | MASVS-PLATFORM-2 | WebView remote debugging enabled |
| `android.dex.world_accessible_storage` | high | MASVS-STORAGE-2 | World-readable / world-writable files or preferences |
| `android.dex.logging_sensitive` | medium | MASVS-STORAGE-2 | Sensitive-looking data may be written to the system log (`Log.*`) |
| `android.dex.plaintext_prefs` | medium | MASVS-STORAGE-1 | Sensitive-looking values stored in plaintext `SharedPreferences` |
| `android.dex.plaintext_database` | medium | MASVS-STORAGE-1 | Sensitive-looking data stored in an unencrypted SQLite database |
| `android.dex.hardcoded_credential` | high | MASVS-CRYPTO-2 | Constant named like a password / secret / token holds a real-looking value |
| `android.dex.hardcoded_jwt_secret` | high | MASVS-CRYPTO-2 | JWT / HMAC signing secret hardcoded (jjwt, java-jwt, Nimbus) |
| `android.dex.hardcoded_jwt` | high | MASVS-AUTH-1 | Complete JWT embedded in code |
| `android.dex.external_storage` | medium | MASVS-STORAGE-2 | Writes to shared external storage |
| `android.dex.dynamic_code_loading` | medium | MASVS-CODE-4 | Loads code at runtime (`DexClassLoader`, `InMemoryDexClassLoader`; `PathClassLoader` only for constant paths on external storage or URLs) |
| `android.dex.runtime_exec` | low | MASVS-CODE-4 | Executes shell commands (Runtime.exec) |
| `android.dex.device_identifiers` | low | MASVS-PRIVACY-1 | Reads hardware identifiers (IMEI, subscriber id, …) |
| `android.dex.build_debug` | medium | MASVS-CODE | BuildConfig.DEBUG is true in this build |
| `android.dex.debug_libraries` | low | MASVS-CODE | Debug / inspection libraries present |
| `android.dex.cleartext_urls` | medium | MASVS-NETWORK-1 | Hardcoded http:// endpoints |
| `android.dex.firebase_urls` | info | MASVS-STORAGE-1 | Firebase Realtime Database URLs |
| `android.dex.anti_analysis` | info | MASVS-RESILIENCE | Anti-debug / anti-emulator / root-detection logic present (cluster of ≥3 distinct indicators in one class) |
| `android.online.assetlinks_missing` | low | MASVS-PLATFORM-1 | App Link host serves no usable `assetlinks.json` (`--online`) |
| `android.online.assetlinks_mismatch` | medium | MASVS-PLATFORM-1 | `assetlinks.json` does not authorise this package / signing certificate (`--online`) |
| `android.online.firebase_db_open` | high | MASVS-STORAGE-1 | Firebase Realtime Database readable without authentication (`--online`) |
| `android.online.remote_config_exposed` | info | MASVS-STORAGE-1 | Firebase Remote Config readable with the embedded API key (`--online`) |
| `android.native.no_pie` | high | MASVS-CODE-4 | Native binary is not position independent (no PIE) |
| `android.native.exec_stack` | high | MASVS-CODE-4 | Native library requests an executable stack |
| `android.native.no_gnu_stack` | low | MASVS-CODE-4 | Native library has no `PT_GNU_STACK` header (NX not asserted) |
| `android.native.wx_segment` | medium | MASVS-CODE-4 | Native library has a writable and executable segment |
| `android.native.no_relro` | medium | MASVS-CODE-4 | Native library has no RELRO |
| `android.native.partial_relro` | low | MASVS-CODE-4 | Native library has only partial RELRO |
| `android.native.textrel` | medium | MASVS-CODE-4 | Native library has text relocations |
| `android.native.no_canary` | low (medium confidence) | MASVS-CODE-4 | Native library has no stack canary |
| `android.native.no_fortify` | low (low confidence) | MASVS-CODE-4 | Native library shows no FORTIFY_SOURCE indicators |
| `android.native.rpath` | low | MASVS-CODE-4 | Native library sets RPATH/RUNPATH |
| `bundle.private_key` | high | MASVS-CRYPTO-2 | Keystore / private key file bundled in the app |
| `bundle.sensitive_file` | medium | MASVS-STORAGE-1 | Sensitive-looking file bundled in the app |
| `bundle.backup_file` | low | MASVS-STORAGE-1 | Backup / temporary files bundled in the app |
| `bundle.database` | low | MASVS-STORAGE-1 | Pre-populated database bundled in the app |
| `bundle.embedded_code` | medium | MASVS-CODE-4 | Executable code bundled as data (apk/dex/jar) |
| `bundle.debug_build` | high | MASVS-RESILIENCE | Debug (JIT/kernel) build artifacts shipped |
| `bundle.source_maps` | low | MASVS-RESILIENCE | Source maps / debug symbols shipped |
| `ios.plist.ats_arbitrary` | high | MASVS-NETWORK-1 | App Transport Security disabled (NSAllowsArbitraryLoads) |
| `ios.plist.ats_web` | medium | MASVS-NETWORK-1 | ATS disabled for web content (NSAllowsArbitraryLoadsInWebContent) |
| `ios.plist.ats_exceptions` | medium | MASVS-NETWORK-1 | ATS exception domains allow insecure HTTP |
| `ios.plist.ats_tls` | medium | MASVS-NETWORK-1 | ATS exception allows an outdated TLS version |
| `ios.plist.file_sharing` | low | MASVS-STORAGE-2 | File sharing enabled (UIFileSharingEnabled) |
| `ios.plist.url_schemes` | info | MASVS-PLATFORM-1 | Custom URL schemes registered |
| `ios.plist.min_os` | low | MASVS-CODE-1 | Supports old iOS versions (MinimumOSVersion) |
| `ios.plist.simulator` | medium | MASVS-CODE | Built for the iOS Simulator |
| `ios.profile.get_task_allow` | high | MASVS-RESILIENCE | Debugging entitlement set (get-task-allow = true) |
| `ios.profile.all_devices` | medium | MASVS-CODE | Enterprise (in-house) distribution profile |
| `ios.profile.dev_devices` | low | MASVS-CODE | Development/ad-hoc profile bound to specific devices |
| `ios.profile.expired` | medium | MASVS-CODE | Provisioning profile has expired |
| `ios.profile.push_dev` | low | MASVS-CODE | Push environment is "development" |
| `ios.macho.no_pie` | high | MASVS-CODE-4 | Executable is not position independent (no PIE) |
| `ios.macho.stack_exec` | high | MASVS-CODE-4 | Executable allows an executable stack |
| `ios.macho.encrypted` | info | MASVS-RESILIENCE | Binary is FairPlay-encrypted: code analysis was skipped |
| `ios.macho.unsigned` | medium | MASVS-RESILIENCE | Executable carries no code signature |
| `ios.macho.no_canary` | low | MASVS-CODE-4 | No stack-smashing protection in an Objective-C/C binary |
| `ios.macho.no_arc` | low | MASVS-CODE-4 | Objective-C code without ARC |
| `ios.code.weak_hash` | low | MASVS-CRYPTO-1 | MD5 / SHA-1 / MD2 / MD4 in use |
| `ios.code.weak_cipher` | high | MASVS-CRYPTO-1 | Broken or weak cipher primitives imported (DES/RC4/RC2/Blowfish) |
| `ios.code.ecb` | medium | MASVS-CRYPTO-1 | ECB-mode primitives imported |
| `ios.code.insecure_random` | low | MASVS-CRYPTO-1 | rand()/random() used |
| `ios.code.keychain_always` | high | MASVS-STORAGE-1 | Keychain items readable while the device is locked (kSecAttrAccessibleAlways) |
| `ios.code.file_protection_none` | medium | MASVS-STORAGE-1 | Files written without data protection (NSFileProtectionNone) |
| `ios.code.uiwebview` | medium | MASVS-PLATFORM-2 | Deprecated UIWebView in use |
| `ios.code.wkwebview_file_access` | medium | MASVS-PLATFORM-2 | WKWebView file-URL access preferences referenced |
| `ios.code.tls_validation_disabled` | high | MASVS-NETWORK-1 | TLS certificate validation appears to be disabled |
| `ios.code.custom_auth_challenge` | medium | MASVS-NETWORK-1 | Custom server-trust handling without a trust evaluation |
| `ios.code.unsafe_c` | low | MASVS-CODE-4 | Unsafe C string functions imported |
| `ios.code.nslog` | info | MASVS-STORAGE-2 | NSLog used (logs readable on the device/console) |
| `ios.code.userdefaults_secrets` | low | MASVS-STORAGE-1 | Secret-looking keys alongside NSUserDefaults |
| `ios.code.no_pinning` | info | MASVS-NETWORK-2 | No certificate pinning detected |
| `ios.code.cleartext_urls` | medium | MASVS-NETWORK-1 | Hardcoded http:// endpoints |

Hardcoded secrets are reported as `secret.<rule id>` (for example `secret.github-pat`) with the severity of the shared secrets rule. Severity is lowered one level when every occurrence is inside third-party library code.

## Tests

`node --test tests/mobile-frameworks.test.js` — `.aab` support (proto XML, modules, dependency list), Hermes / IL2CPP / UnityFS / XALZ / assembly-store readers, per-framework scans (RN, Flutter, Unity, Xamarin), and the exit-code contract (gate maths plus the real CLI: pass, missing file, gate, bad arguments, incomplete, `--allow-partial`, `--min-severity` not hiding gate failures). The parsers were also checked against real files: a bundletool sample `.aab`, `hermesc` output (bytecode v94), a real managed DLL and a real LZ4 compressor.

`node --test tests/mobile.test.js` — builds Android binary XML, `resources.arsc`, DEX, binary plists, Mach-O and ELF fixtures in memory (`tests/helpers/mobile_fixtures.js`) plus real PKCS#7 signatures, and checks parsers, whole-package scans and the CLI (outputs, exit codes, HTML escaping, diffs). The fixtures follow the file-format specifications; they are not real apps, so run the scanner against your own builds as well.

Native ELF hardening (per-ABI PIE / NX / RELRO / canary / FORTIFY, symbol lookup without section headers, report table): `node --test tests/mobile-elf-hardening.test.js`. Besides in-memory ELF fixtures it compiles real binaries with `gcc` and compares the reader with `readelf`; that part is skipped when neither is installed.

Anti-analysis clusters, behavior inventory, base64 decode pass and the `--online` checks (assembled DEX in memory, mock `fetch`): `node --test tests/mobile-detections.test.js`.

Accuracy-fix regression tests (dependency status, origin attribution, class-loader rule): `node --test tests/mobile-fixes.test.js`.

Sensitive-data rules (logging, plaintext storage, hardcoded credentials / JWT): `node --test tests/mobile-signals.test.js`; set `DVBA_APK=/path/to/dvba.apk` to also run the end-to-end check against a real APK.