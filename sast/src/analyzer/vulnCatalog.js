'use strict';

// ═════════════════════════════════════════════════════════════════════════════
// VULNERABILITY CLASSES & CATALOG BUILDER
// ═════════════════════════════════════════════════════════════════════════════

// Canonical language-family codes — must match constants.js FAMILY_LABELS.
const ALL_LANGUAGES = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'dart', 'swift', 'csharp', 'c'];

// "Web"-shaped languages: everything except C, which essentially never hosts
// the request/response, ORM, templating, or session-cookie code these
// classes are about. Used for the many web-app-flavoured classes below.
const WEB_LANGUAGES = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp'];

// Dart (Flutter) and Swift (iOS/macOS) are deliberately NOT in WEB_LANGUAGES:
// they are overwhelmingly client/mobile code, and sending ~25 server-side
// classes (CSRF, cookie attributes, CORS, GraphQL, host-header …) with every
// Flutter/iOS chunk would add cost and noise. They receive the generic
// ALL_LANGUAGES classes, a handful of web-adjacent classes opted in by name
// below (XSS via WebView/templating, JWT handling, code injection, ReDoS), and
// the dedicated mobile classes scoped to MOBILE_LANGUAGES.
const MOBILE_LANGUAGES = ['dart', 'swift'];

// Each entry: { name, cwe, needsUserInput, languages, signals }
//   name         — canonical label used in vuln_name output field
//   cwe          — primary CWE for reference (not emitted in output)
//   needsUserInput — true  = only report when attacker-controlled input is visible
//                    false = report even without a visible taint source (e.g. hardcoded secrets)
//   languages    — language-family codes (see constants.js FAMILY_LABELS) this
//                  class can realistically apply to. Used to drop irrelevant
//                  classes from a chunk's prompt before it's sent to the LLM.
//   signals      — concrete patterns the LLM should look for, listed as prose bullets
const DEFAULT_VULN_CLASSES = [
  {
    name: 'hardcoded secret or credential',
    cwe: 'CWE-798',
    needsUserInput: false,
    languages: ALL_LANGUAGES,
    signals: [
      'String literal assigned to a variable whose name contains: password, passwd, pwd, secret, token, api_key, apikey, auth, credential, private_key, access_key, client_secret, bearer',
      'Base64-encoded blobs or hex strings of 20+ chars directly assigned to such variables',
      'Cryptographic key material (PEM headers, raw byte arrays) embedded as literals',
      'Connection strings or DSN literals that include a password component',
      'Private keys or certificates embedded in source (BEGIN PRIVATE KEY, BEGIN RSA PRIVATE KEY, etc.)',
      'OAuth/JWT secrets, HMAC signing keys, or encryption keys as string literals',
      'Dart/Flutter: API keys, tokens or passwords as `const` / `static final` String literals, or as the `defaultValue:` of `String.fromEnvironment(...)`; secrets loaded from a `.env` file bundled as a Flutter asset (flutter_dotenv) still ship inside the app and are extractable by anyone who unpacks it',
      'Swift/iOS: API keys, client secrets or tokens in `static let` constants, string literals passed to request headers or SDK initialisers; any secret compiled into the app binary is recoverable by a user with the IPA',
    ],
  },
  {
    name: 'SQL injection',
    cwe: 'CWE-89',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'String concatenation or interpolation used to build a SQL query: "SELECT … " + userVar, f"… {param}", `… ${req.body.x}`',
      'ORM raw() / execute() / query() called with a non-parameterized string built from user input',
      'Dynamic ORDER BY / table name / column name constructed from user-supplied values without allowlist validation',
      'Second-order injection: user input stored to DB then later read back and used in another query without re-sanitisation',
      'Dart: sqflite / drift / sqlite3 `rawQuery`, `rawInsert`, `rawUpdate`, `rawDelete`, `execute`, or drift `customSelect` / `customStatement` built with string interpolation (`$var`, `${expr}`) or `+` concatenation instead of `?` placeholders with an arguments list',
      'Swift: `sqlite3_exec` / `sqlite3_prepare` with an interpolated string, GRDB or SQLite.swift raw SQL built with string interpolation instead of `arguments:`, or `NSPredicate(format:)` assembled by concatenating user input',
    ],
  },
  {
    name: 'command injection',
    cwe: 'CWE-78',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'child_process.exec / execSync / spawn with shell:true / os.system / subprocess.run(shell=True) receiving user input',
      'Template string or concatenation used to build a shell command',
      'User input passed as an argument that is later interpreted by a shell (pipes, semicolons, backticks not sanitised)',
      'Indirect: user-controlled value flows into a function that internally calls a shell command',
      'Dart: `Process.run` / `Process.start` / `Process.runSync` with `runInShell: true`, or an executable or argument list assembled from user input (`sh -c`, `cmd /c`)',
      'Swift: `Process` / `NSTask` launching `/bin/sh -c` with an interpolated command string, or `posix_spawn`, `system()`, `popen()` with user-controlled input (macOS and server-side Swift)',
    ],
  },
  {
    name: 'path traversal',
    cwe: 'CWE-22',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'File path constructed by joining a user-supplied value without resolving and validating the result stays inside the intended root (path.join / os.path.join alone is not safe)',
      'Direct use of user input as a filename in fs.readFile, open(), File(), readFileSync, etc.',
      'Zip/archive extraction without validating that each entry\'s path stays within the destination directory (Zip Slip)',
      'Static file serving with user-controlled path segments that are not normalized with path.resolve + startsWith check',
      'Dart: `File(path)`, `Directory(path)`, `File.copy` / `rename` where `path` includes user input without normalising it and checking it stays inside the intended directory; archive extraction (`ZipDecoder`, `TarDecoder`) that writes entries using `file.name` without rejecting `..` components (zip-slip)',
      'Swift: `FileManager`, `URL(fileURLWithPath:)` or `Data(contentsOf:)` using user input without standardising the path and confirming it stays inside the intended directory; archive extraction (ZIPFoundation, SSZipArchive) that writes entries without rejecting `..` components',
    ],
  },
  {
    name: 'unsafe deserialization',
    cwe: 'CWE-502',
    needsUserInput: true,
    languages: ['python', 'java', 'kotlin', 'php', 'csharp', 'ruby', 'js', 'swift'],
    signals: [
      'pickle.loads / pickle.load / yaml.load (without Loader=yaml.SafeLoader) / marshal.loads on user-controlled data',
      'Java ObjectInputStream.readObject on data arriving from the network or a user-supplied file',
      'PHP unserialize() on user input',
      'C# / .NET: BinaryFormatter.Deserialize, NetDataContractSerializer, LosFormatter.Deserialize, ObjectStateFormatter.Deserialize, or JavaScriptSerializer (with SimpleTypeResolver) called on user-supplied data',
      'C# / .NET: Newtonsoft.Json.JsonConvert.DeserializeObject with TypeNameHandling.Objects or TypeNameHandling.Auto without a custom SerializationBinder or type allowlist',
      'Ruby: Marshal.load or YAML.load called on user-controlled input, allowing arbitrary code execution',
      'Node.js node-serialize / serialize-javascript eval path on untrusted data',
      'Deserialization of JSON/XML with class mapping that can instantiate arbitrary types (e.g. Jackson polymorphic typing enabled globally)',
      'Swift: `NSKeyedUnarchiver.unarchiveObject(with:)` / `unarchiveTopLevelObjectWithData` or `NSCoding` decoding without `requiresSecureCoding = true` or a class allow-list (`unarchivedObject(ofClasses:from:)`) on data from the network, a file, the pasteboard or a URL scheme',
    ],
  },
  {
    name: 'XSS / template injection',
    cwe: 'CWE-79 / CWE-94',
    needsUserInput: true,
    languages: [...WEB_LANGUAGES, ...MOBILE_LANGUAGES],
    signals: [
      'User input rendered into HTML without escaping: innerHTML, document.write, dangerouslySetInnerHTML, v-html, [innerHTML]=',
      'Server-side template engines (Jinja2, Twig, Pebble, Velocity, Freemarker, Handlebars, EJS) receiving user input in the template string rather than only in the context variables',
      'React/Vue/Angular bypassing the framework\'s auto-escaping via raw HTML APIs',
      'eval() or new Function() called with a template string that contains user data',
      'DOM clobbering: user-controlled HTML inserted adjacent to code that reads named DOM properties',
      'Dart/Swift: HTML assembled from user input and passed to a WebView (`loadHtmlString`, `loadData`, `loadHTMLString`) or to a server-side template (Vapor Leaf `#unsafeHTML`, mustache `{{{ }}}`) without escaping',
    ],
  },
  {
    name: 'open redirect',
    cwe: 'CWE-601',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'HTTP redirect (res.redirect, header("Location:…"), HttpServletResponse.sendRedirect) target built from user input without allowlist validation',
      'window.location / location.href / location.replace set from user-controlled query param or hash fragment',
      'next / return_to / redirect_url / continue parameter used directly in a redirect without origin validation',
    ],
  },
  {
    name: 'XXE injection',
    cwe: 'CWE-611',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'XML parsed with external entity resolution enabled (DOCTYPE not disabled, FEATURE_SECURE_PROCESSING not set, resolve_entities=True)',
      'libxml2 / lxml / DOMParser / SAXParser / XMLReader processing user-supplied XML without disabling DTD loading',
      'C# / .NET: XmlReaderSettings.DtdProcessing set to Parse or Prohibit (instead of Ignore) when parsing untrusted XML',
      'XSLT or XPath evaluated against user-supplied XML',
    ],
  },
  {
    name: 'SSRF',
    cwe: 'CWE-918',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'HTTP client (fetch, axios, requests.get, urllib.request, curl, HttpClient) receiving a URL built from user input without hostname allowlist validation',
      'User-supplied URL passed to internal service calls, webhooks, or file loaders (e.g. PDF renderer, image fetcher)',
      'DNS lookup / socket connection target derived from user input',
      'Cloud metadata endpoint (169.254.169.254) reachable via redirect from a user-supplied URL',
    ],
  },
  {
    name: 'missing authentication check',
    cwe: 'CWE-306',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'Route or endpoint handler that performs a privileged action (data mutation, admin operation, user management) with no visible call to an authentication/session check before acting',
      'Internal API function that assumes the caller already validated identity but is itself exposed as a public route',
      'Authentication middleware registered only on some routes while sensitive routes are left unprotected',
      'JWT/session token accepted but never verified for signature or expiry before granting access',
    ],
  },
  {
    name: 'broken access control / privilege escalation',
    cwe: 'CWE-269',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'Role or permission value read from a user-controlled source (cookie, request body, query param) and trusted without server-side validation',
      'Horizontal privilege escalation: authenticated user can access another user\'s resources by changing an identifier in the request',
      'Mass assignment: ORM model created/updated directly from request body without an allowlist of permitted fields',
      'Ruby on Rails: update_attributes, assign_attributes, or direct assignment of params to a model without strong parameters (permit/require) or a whitelisted_attributes mechanism',
      'Vertical privilege escalation: a lower-privileged role can reach an admin-only code path because the authorization check is missing or checks the wrong claim',
    ],
  },
  {
    name: 'prototype pollution',
    cwe: 'CWE-1321',
    needsUserInput: true,
    languages: ['js'],
    signals: [
      'Recursive merge / deep clone / object assign function that does not block __proto__, constructor, or prototype keys',
      'User-controlled JSON key path used to set nested object properties (e.g. lodash _.set, custom path-based setters)',
      'Object.assign or spread ({...obj}) on user-supplied objects that may carry __proto__ overrides',
    ],
  },
  {
    name: 'code injection / dangerous eval',
    cwe: 'CWE-95',
    needsUserInput: true,
    languages: ['js', 'python', 'ruby', 'php', 'dart', 'swift'],
    signals: [
      'eval(), new Function(), setTimeout/setInterval with a string argument, execScript receiving user data',
      'Python exec() / compile() / eval() on user-supplied code strings',
      'Ruby eval / instance_eval / class_eval on user input',
      'PHP eval(), preg_replace with /e modifier, assert() with a string argument on user data',
      'Server-side template rendered from a string built with user content (distinct from XSS — focuses on server execution)',
      'Dynamic require() / import() with a user-controlled module path',
      'Dart: `WebViewController.runJavaScript` / `runJavaScriptReturningResult`, flutter_inappwebview `evaluateJavascript`, or `Isolate.spawnUri` executing script text or a URI built from user input',
      'Swift: `WKWebView.evaluateJavaScript` or `JSContext.evaluateScript` called with a string that interpolates user-controlled data',
    ],
  },
  {
    name: 'unsafe file upload',
    cwe: 'CWE-434',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'Uploaded file saved to disk using the original client-supplied filename without sanitisation',
      'File type validated only by MIME type header or file extension, not by magic bytes',
      'Uploaded file stored inside a web-accessible directory without randomising the filename',
      'No validation on file size, allowing denial-of-service via large uploads',
      'Zip file extracted server-side without checking entry paths (Zip Slip — also covered under path traversal)',
    ],
  },
  {
    name: 'sensitive data exposure / information disclosure',
    cwe: 'CWE-200',
    needsUserInput: false,
    languages: ALL_LANGUAGES,
    signals: [
      'Stack traces, internal error messages, or exception objects returned in API responses or rendered to the user',
      'Logging statements (console.log, logger.debug, print) that output passwords, tokens, PII, or full request bodies',
      'Sensitive fields included in serialised API responses without an explicit exclusion list',
      'Directory listing or source file exposure through misconfigured static file serving',
      'Dart: `print`, `debugPrint`, `log()` (dart:developer) or logger calls that output tokens, passwords, PII or full request / response bodies — `print` is not stripped from release builds',
      'Swift: `print`, `NSLog`, `os_log` / `Logger` with `privacy: .public` (or legacy `%{public}@`) on tokens, passwords or PII; `dump()` of objects holding credentials',
    ],
  },
  {
    name: 'cryptographic weakness',
    cwe: 'CWE-327',
    needsUserInput: false,
    languages: ALL_LANGUAGES,
    signals: [
      'Use of broken or weak algorithms: MD5, SHA-1, DES, 3DES, RC4, ECB mode for encryption',
      'Hardcoded or static IV/nonce used with AES-CBC or AES-GCM',
      'Math.random() / rand() / random.random() used for security-sensitive purposes (token generation, nonce, salt)',
      'Insufficient key length: RSA < 2048 bits, AES-128 for highly sensitive data, ECDSA curves below P-256',
      'Password stored with a non-password-hashing algorithm (plain SHA-*/MD5 without salt, or reversible encryption)',
      'TLS/SSL version pinned to TLSv1.0 or TLSv1.1, or certificate verification disabled (verify=False, rejectUnauthorized: false)',
      'Dart: `Random()` (instead of `Random.secure()`) used for tokens, keys, IVs, nonces or OTPs; `md5` / `sha1` from package:crypto used for passwords or integrity; package:encrypt AES with `AESMode.ecb`, a hardcoded `Key.fromUtf8(...)`, or a static / all-zero IV (`IV.fromLength(16)`) reused across messages',
      'Swift: CommonCrypto `CC_MD5` / `CC_SHA1` / `kCCAlgorithmDES` / `kCCOptionECBMode`; CryptoKit `Insecure.MD5` / `Insecure.SHA1` used for security purposes; `random()` / `rand()` / `drand48()` for tokens (use `SecRandomCopyBytes` or `SystemRandomNumberGenerator`); hardcoded keys or IVs passed to AES.GCM / `CCCrypt`',
    ],
  },
  {
    name: 'integer overflow / underflow',
    cwe: 'CWE-190',
    needsUserInput: true,
    languages: ['c', 'rust', 'go', 'java', 'kotlin', 'swift', 'csharp'],
    signals: [
      'Arithmetic on user-supplied numeric values used as buffer sizes, array indices, or loop bounds without range checks',
      'Signed/unsigned integer conversion where user input could produce a negative buffer size',
      'Multiplication of user-controlled values used to allocate memory (e.g. width * height without overflow check)',
      'Swift: `+`, `-`, `*` or `Int(...)` conversions on attacker-controlled integers trap at runtime on overflow (crash / denial of service); `Int32(truncatingIfNeeded:)`, `&+`, `&*` or `unsafeBitCast` silently wrap or reinterpret values later used as sizes or indices',
    ],
  },
  {
    name: 'null / nil dereference',
    cwe: 'CWE-476',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'Return value of a function that can return null/None/nil used without a null check before member access',
      'Optional chaining absent where an API result, database query result, or map lookup could be absent',
      'Unchecked array/slice index access on a result that may be empty',
      'Kotlin: use of the `!!` (not-null assertion) operator on a nullable type that could reasonably be null based on control flow or external input',
      'Kotlin: accessing a `lateinit` property before it has been initialized without using `::property.isInitialized`',
      'Kotlin: Java interop where a nullable Java type is treated as non-nullable in Kotlin without explicit null checks',
      'Dart: the `!` null-assertion operator on a value that can be null from external input, a map lookup, a failed parse or an async result; `late` fields read before initialisation (LateInitializationError); unchecked `as` casts of decoded JSON or platform-channel values that throw on unexpected types',
      'Swift: force-unwrap `!`, implicitly unwrapped optionals, `try!`, or `as!` applied to values from the network, user input, files, URL / deep-link components or JSON decoding — a crash an attacker can trigger repeatedly (denial of service)',
    ],
  },
  {
    name: 'use after free / memory safety',
    cwe: 'CWE-416',
    needsUserInput: false,
    languages: ['c', 'rust', 'go'],
    signals: [
      'Pointer or reference used after it has been freed / deleted / invalidated',
      'Buffer passed to a function after the underlying memory has gone out of scope',
      'Rust: use of a value after it has been moved without re-binding',
      'Go: use of unsafe.Pointer for type conversions that bypass Go\'s type safety, especially when interacting with C libraries via cgo',
      'Go: arithmetic operations on unsafe.Pointer that could lead to out-of-bounds access',
      'Rust: casting raw pointers obtained from FFI calls to Rust references without proper validation of alignment, validity, and lifetime',
    ],
  },
  {
    name: 'buffer overflow / out-of-bounds access',
    cwe: 'CWE-120',
    needsUserInput: true,
    languages: ['c'],
    signals: [
      'C/C++: strcpy/strcat/sprintf/gets/scanf("%s") writing attacker- or caller-controlled data into a fixed-size stack or heap buffer with no length check',
      'memcpy/memmove/memset where the length argument is derived from user input or a different buffer than the one being written to',
      'Array or pointer indexed with an attacker-influenced or unchecked index/offset (no bounds check against the buffer\'s actual size)',
      'malloc/calloc size computed from an addition or multiplication of user-controlled values without an overflow check before allocation',
      'Off-by-one risk: loop or copy bound uses <= against a buffer size, or omits space for a null terminator',
    ],
  },
  {
    name: 'format string vulnerability',
    cwe: 'CWE-134',
    needsUserInput: true,
    languages: ['c'],
    signals: [
      'printf/fprintf/sprintf/syslog (or similar) called with a user-controlled string as the format argument instead of a fixed format string',
      'A variable, not a string literal, used directly as the first argument to a *printf-family function',
    ],
  },
  {
    name: 'race condition / TOCTOU',
    cwe: 'CWE-362',
    needsUserInput: false,
    languages: ALL_LANGUAGES,
    signals: [
      'File existence or permission checked (os.path.exists, access()) and then the file acted on in a separate step without atomic OS primitives',
      'Shared mutable state accessed from multiple goroutines / threads without synchronisation',
      'TOCTOU: check-then-act on a resource whose state can change between the check and the act',
      'Go: goroutine spawned without an exit condition (e.g., missing context cancellation, no timeout on channel operations), leading to resource leaks',
      'Go: shared mutable state accessed by multiple goroutines without synchronization (mutex, channel), leading to data races',
      'Kotlin: shared mutable state accessed by multiple coroutines without proper synchronization (Mutex, synchronized), leading to race conditions',
      'Kotlin: coroutine scope not properly managed, causing coroutines to outlive their parent scope and consume resources',
      'Swift: mutable state shared across threads / GCD queues / Tasks without an actor, serial queue, lock or `@MainActor` isolation',
      'Dart: check-then-act across an `await` where state can change between the check and the act (async re-entrancy), e.g. a balance / token / permission check followed by an awaited call and then the action',
    ],
  },
  {
    name: 'insecure direct object reference (IDOR)',
    cwe: 'CWE-639',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'Database record fetched by a user-supplied ID without verifying the authenticated user owns that record',
      'File or resource path constructed from a user-supplied identifier with no ownership check',
      'Sequential or predictable resource identifiers (auto-increment IDs) exposed in URLs with no access control',
    ],
  },
  {
    name: 'HTTP header injection / response splitting',
    cwe: 'CWE-113',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'User input written directly into an HTTP response header (Set-Cookie, Location, Content-Disposition, custom headers) without stripping CR/LF characters',
      'Filename from user input used in Content-Disposition without encoding newlines',
    ],
  },
  {
    name: 'regex denial of service (ReDoS)',
    cwe: 'CWE-1333',
    needsUserInput: true,
    // Go's regexp and Rust's regex crate both use RE2-style finite-automaton
    // engines that are immune to catastrophic backtracking, so they're
    // excluded here.
    languages: ['js', 'python', 'php', 'ruby', 'java', 'kotlin', 'dart', 'swift', 'csharp', 'c'],
    signals: [
      'User-controlled input matched against a regular expression that contains catastrophic backtracking patterns: nested quantifiers, alternation inside repetition (e.g. (a+)+, (a|aa)+)',
      'User-supplied string used as the regex pattern itself (RegExp(userInput))',
    ],
  },
  {
    name: 'cross-site request forgery (CSRF)',
    cwe: 'CWE-352',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'State‑changing HTTP endpoint (POST, PUT, DELETE, PATCH) that does not include a CSRF token in the request (e.g., missing `_csrf`, `X‑CSRF‑Token`, or `state` param)',
      'Cookie‑based session authentication used without a double‑submit cookie or synchronizer token pattern on mutating actions',
      'Global CSRF protection middleware is applied to some routes but explicitly disabled or omitted on sensitive operations',
      'GraphQL mutations that perform writes without checking a CSRF token in the request headers',
    ],
  },
  {
    name: 'NoSQL injection',
    cwe: 'CWE-943',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'MongoDB query built by concatenating user input directly into a filter object (e.g., `{ username: req.body.username }` with no type validation, allowing `$where` or `$ne` injection)',
      'User‑supplied JSON is parsed and used as a query/filter without sanitising operators (`$gt`, `$regex`, `$where`, `$or`)',
      'Dynamic field names or collection names derived from user input without allowlist validation',
      'Use of `$where` with a string that contains user‑controlled JavaScript code, or `mapReduce` with a user‑controlled function',
    ],
  },
  {
    name: 'LDAP / XPath injection',
    cwe: 'CWE-90 / CWE-643',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'LDAP filter or search base constructed by concatenating user input (e.g., `(uid=` + user + `)`) without escaping special characters',
      'XPath query built by string interpolation and passed to `evaluate()` or similar, with user input inserted directly',
      'User‑controlled value used as a DN (Distinguished Name) without proper escaping',
    ],
  },
  {
    name: 'insecure session cookie attributes',
    cwe: 'CWE-614 / CWE-1004',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'Session cookie (e.g., `connect.sid`, `JSESSIONID`) set without `HttpOnly` flag – allowing client‑side scripts to read it',
      'Session cookie missing `Secure` flag – transmitted over non‑HTTPS connections (when used over HTTP)',
      'Session cookie missing `SameSite` attribute, or set to `None` without `Secure`',
      'Cookie with `Domain` set too broadly (e.g., `.example.com` when not needed) or `Path` set to `/` with no restriction',
    ],
  },
  {
    name: 'missing / misconfigured security headers',
    cwe: 'CWE-693',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'NOTE: applies only when header-setting code or web-server config files are present in the scanned repo (e.g. helmet() setup, custom middleware, nginx.conf, web.config) — not inferred from any live response',
      'Header-configuration code omits Content-Security-Policy entirely, or sets it to a permissive `default-src *`',
      'No call configuring X-Frame-Options / frameguard, or it is explicitly set to ALLOWALL, in the security-header middleware setup',
      'X-Content-Type-Options: nosniff not set anywhere in the response-header configuration code',
      'Strict-Transport-Security not configured, or max-age set below one year, in the HTTPS server setup code',
      'Referrer-Policy or Permissions-Policy absent from the header configuration for routes serving sensitive pages',
    ],
  },
  {
    name: 'insecure CORS policy',
    cwe: 'CWE-942',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'CORS middleware configuration in code (cors(), custom Access-Control-* header-setting logic) sets Access-Control-Allow-Origin to "*" while Access-Control-Allow-Credentials is set true',
      'CORS origin allowlist implemented by echoing the incoming Origin value back unconditionally, or via an unanchored substring/regex match (e.g. matching ".example.com" without anchoring), instead of an explicit allowlist comparison',
      'Access-Control-Allow-Methods or Access-Control-Allow-Headers hardcoded to "*" in the CORS configuration code',
      'NOTE: applies only when CORS middleware/header-setting code is present in the scanned repo (e.g., cors() setup, custom middleware, WebApi config). Do not infer from live responses.',
    ],
  },
  {
    name: 'host header injection / cache poisoning',
    cwe: 'CWE-20',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'URL generation using `req.headers.host` or `Host` header without validating against a whitelist, used in redirects, links, or webhooks',
      '`Host` header passed to internal APIs or used to construct file paths without validation',
      'Password reset emails or password recovery links built with the `Host` header from the incoming request',
    ],
  },
  {
    name: 'log injection / forged log entries',
    cwe: 'CWE-117',
    needsUserInput: true,
    languages: ALL_LANGUAGES,
    signals: [
      'User input written directly into log statements (e.g., `console.log(req.body)`, `logger.info(userInput)`) without stripping newline characters (`\n`, `\r`)',
      'Logs that contain unsanitised user input, enabling an attacker to inject fake log entries or exploit log viewers',
      'Structured logging (JSON) where user input is embedded in a field without escaping newlines or control characters',
    ],
  },
  {
    name: 'debug / verbose error mode enabled in production',
    cwe: 'CWE-489',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'Environment variable `NODE_ENV=development` or `DEBUG=*` present in production configuration',
      '`app.use(express.errorHandler({ dumpExceptions: true, showStack: true }))` or similar in a production setting',
      'Stack traces or exception details returned in HTTP responses for unhandled exceptions',
      '`debug` or `dev` mode enabled in frameworks (e.g., `flask debug=True`, `django DEBUG=True`) in deployed code',
    ],
  },
  {
    name: 'insecure file permissions (world‑writable or executable)',
    cwe: 'CWE-276',
    needsUserInput: false,
    languages: ALL_LANGUAGES,
    signals: [
      '`chmod` or `os.Chmod` called with mode `0666` or `0777` on sensitive files (configuration, credentials, logs)',
      'Sensitive files created with default permissions that are too permissive (e.g., `umask` set to `0`)',
      'Uploaded files stored with execute permission (`0755`) or world‑writable (`0666`) without need',
    ],
  },
  {
    name: 'GraphQL injection / query abuse',
    cwe: 'CWE-943 / CWE-770',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'User‑controlled GraphQL arguments (e.g., `args.id`, `args.filter`) used directly to build database queries without parameterisation or sanitisation',
      'Resolver code that concatenates user input into a SQL/NoSQL query string or filter object (e.g., `{ $where: userInput }`)',
      '`info` field (field selection set) parsed and used to dynamically construct queries without whitelisting allowed fields',
      'Missing `maxDepth` or `maxAliases` limits on the GraphQL server, allowing deep nested queries or alias bombing that can cause DoS',
      'User‑controlled `__typename` or field names used in ORM `orderBy` / `groupBy` clauses without allowlist validation',
      'Batch queries where an attacker can request thousands of related records in a single request without pagination or rate limiting',
    ],
  },
  {
    name: 'JWT / token validation weakness',
    cwe: 'CWE-347',
    needsUserInput: false,
    languages: [...WEB_LANGUAGES, ...MOBILE_LANGUAGES],
    signals: [
      'JWT decoded/parsed without signature verification, or verification called with `verify: false` / equivalent',
      'Signing algorithm not pinned server-side, allowing `alg: none` or RS256→HS256 confusion (public key reused as the HMAC secret)',
      'Token `exp`, `nbf`, `iss`, or `aud` claims not checked after signature verification, allowing expired or wrong-audience tokens to be accepted',
      'Refresh token, password-reset token, or email-verification token generated without sufficient entropy, or not invalidated/rotated after use',
      'Token revocation not enforced server-side (e.g., logout only deletes the client-side cookie, no server-side blocklist or short-lived token design)',
      'Dart/Swift: JWT payload decoded on the device (`JwtDecoder.decode`, manual base64 split) and trusted for authorisation decisions (isAdmin, role, expiry) without signature verification',
    ],
  },
  {
    name: 'missing rate limiting / brute force exposure',
    cwe: 'CWE-307',
    needsUserInput: false,
    languages: WEB_LANGUAGES,
    signals: [
      'Login, password-reset, OTP/2FA verification, or token-verification route handler has no call to a rate-limiting/throttling middleware or decorator anywhere in its middleware chain',
      'Code returns two distinctly different hardcoded error strings or response shapes for "user not found" vs "wrong password" on the same authentication endpoint',
      'No attempt counter, lockout flag, or CAPTCHA check present in the authentication code path for an endpoint guarding a guessable secret (PIN, short OTP, invite code)',
      'NOTE: applies only when examining the route handler and its immediate middleware chain in code. Do not infer from external observations.',
    ],
  },
  {
    name: 'Expression Language (EL) / SpEL / OGNL injection',
    cwe: 'CWE-917',
    needsUserInput: true,
    languages: ['java', 'kotlin'],
    signals: [
      '`SpelExpressionParser.parseExpression(userInput).getValue()` or `.setValue()` called with user-controlled input (Spring)',
      '`@Value` annotations or Spring Cloud Gateway predicates that interpolate user-supplied values into SpEL expressions',
      '`JexlEngine.createExpression(userInput)` or `MVEL.compileExpression(userInput)` evaluated with user data',
      '`Ognl.getValue(userInput, context)` invoked on user-controlled strings (OGNL)',
      '`javax.el.ELProcessor.eval()` or `javax.el.ValueExpression` with a string built from untrusted data',
    ],
  },
  {
    name: 'double free',
    cwe: 'CWE-415',
    needsUserInput: false,
    languages: ['c', 'rust'],
    signals: [
      '`free(ptr)`, `delete ptr`, or `delete[] ptr` called on a pointer that has already been freed earlier in the same code path without being reassigned or reallocated in between',
      '`free` called on a pointer that is a function parameter or global, where control flow could reach two different `free` calls without a `NULL` assignment between them',
      'C++: `std::unique_ptr` / `shared_ptr` manually reset or released, then the raw pointer is freed explicitly afterwards',
      'Custom allocators or cleanup functions that free a user-supplied pointer without checking if it is already freed',
    ],
  },
  {
    name: 'uninitialized variable / memory read',
    cwe: 'CWE-457',
    needsUserInput: false,
    languages: ['c', 'rust'],
    signals: [
      'Local variable declared but not initialised before being read or passed to a function that reads it (e.g., `int x; if (cond) x=5; use(x);`)',
      '`malloc()` or `alloca()` allocated memory used directly without a preceding `memset()` or assignment to all bytes',
      'C++: object of a trivial type created with default initialisation (e.g., `MyStruct s;`) and used before its fields are set',
      'Stack-allocated arrays or structs read from before all fields are assigned',
      '`memcpy`/`memmove` used to read from a buffer that may not have been fully written to',
    ],
  },
  {
    name: 'local / remote file inclusion (LFI/RFI)',
    cwe: 'CWE-98',
    needsUserInput: true,
    languages: ['php'],
    signals: [
      "PHP: `include()`, `require()`, `include_once()`, `require_once()` called with a user‑controlled value (e.g., `$_GET['page']`, `$_REQUEST['file']`) without proper allowlist validation",
      'Dynamic file path built from user input and passed to any of the above inclusion functions',
      "Allowlist missing: no check that the resolved path is within a predefined set of allowed files (e.g., `allowed_pages = ['home', 'about']`)",
      'Remote inclusion: user‑supplied URL passed to `include()` when `allow_url_include=On` – allowing loading of external PHP code',
    ],
  },
  {
    name: 'PHP type juggling / loose comparison',
    cwe: 'CWE-697 / CWE-843',
    needsUserInput: true,
    languages: ['php'],
    signals: [
      'PHP loose comparison operator `==` used to compare a user‑controlled value against a secret (password, token, hash, HMAC) instead of strict `===`',
      'Magic hash vulnerability: user‑supplied string starting with `0e` followed by digits compared with `==` against a hash that also starts with `0e` – causing them to evaluate as equal',
      '`in_array()` used with the third parameter `false` (or omitted) to check user input against a list of values, allowing type‑juggling bypass',
      '`switch()` statement using loose comparison on user‑controlled input',
    ],
  },
  {
    name: 'unsafe Rust block without safety justification',
    cwe: 'CWE-1236',
    needsUserInput: false,
    languages: ['rust'],
    signals: [
      'Rust: any `unsafe { }` block, `unsafe fn`, or `unsafe trait` implementation present in the code',
      '`unsafe` block that does not have an immediately preceding or inline `// SAFETY:` comment explaining why the invariants are upheld',
      '`unsafe` block used for trivial operations that could be rewritten in safe Rust (e.g., indexing with `get_unchecked` without a bounds check)',
      'Rust: unsafe block performing operations (e.g., `get_unchecked`, `set_len`) that violate documented invariants without clear justification or runtime checks',
      'Rust: FFI calls that allocate memory on the C side without a corresponding deallocation mechanism in Rust',
    ],
  },
  {
    name: 'business logic flaw',
    cwe: 'CWE-840',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'User‑supplied price, quantity, discount, or tax value used in a server‑side transaction calculation without being re‑validated against a known list or previous state',
      'Multi‑step process (e.g., checkout, account creation, password reset) where state transitions are not strictly validated, allowing an attacker to skip steps or submit out‑of‑order operations',
      'Authorization checks that are missing or inconsistent across different endpoints that perform the same or related sensitive actions (e.g., one endpoint allows admin action, another does not)',
      'User‑controlled `step`, `stage`, or `status` values that bypass workflow validation without server‑side checks',
      'Business constraints (e.g., maximum order quantity, minimum age, unique email) not enforced server‑side before completing an operation',
    ],
  },
  // ─── Mobile (Flutter / Dart and Swift / iOS) ────────────────────────────
  {
    name: 'insecure local data storage (mobile)',
    cwe: 'CWE-922',
    needsUserInput: false,
    languages: MOBILE_LANGUAGES,
    signals: [
      'Dart: tokens, passwords, session IDs, private keys or PII written to `SharedPreferences`, a `Hive` / `GetStorage` box without encryption, a plain file in the documents directory, or an unencrypted `sqflite` database instead of `flutter_secure_storage`',
      'Dart: `flutter_secure_storage` configured with overly permissive keychain accessibility, or secrets mirrored into `SharedPreferences` as a cache',
      'Swift: tokens, passwords or PII stored in `UserDefaults`, a plist, a plain file in Documents / Caches / tmp, Core Data or SQLite without file protection, instead of the Keychain',
      'Swift: Keychain items saved with `kSecAttrAccessibleAlways` / `kSecAttrAccessibleAlwaysThisDeviceOnly` (readable while the device is locked), or files written with `.noFileProtection`',
      'Sensitive values copied to the system clipboard (`Clipboard.setData`, `UIPasteboard.general`) where other apps can read them',
    ],
  },
  {
    name: 'insecure TLS / certificate validation (mobile)',
    cwe: 'CWE-295',
    needsUserInput: false,
    languages: MOBILE_LANGUAGES,
    signals: [
      'Dart: `HttpClient.badCertificateCallback = (cert, host, port) => true`, dio `onHttpClientCreate` / `validateCertificate` that accepts every certificate, or an `HttpOverrides.global` that disables certificate checks',
      'Dart: plain `http://` URLs for authentication, token or personal-data endpoints (cleartext traffic)',
      'Swift: a `URLSessionDelegate` `urlSession(_:didReceive:completionHandler:)` that answers `.useCredential` with `URLCredential(trust: challenge.protectionSpace.serverTrust!)` without evaluating the trust (`SecTrustEvaluateWithError`) or pinning',
      'Swift: Alamofire `ServerTrustManager` using `DisabledTrustEvaluator`, `NSAllowsArbitraryLoads` / `NSExceptionAllowsInsecureHTTPLoads` set from code, or plain `http://` endpoints carrying sensitive data',
      'Certificate / public-key pinning that is implemented but ineffective: the comparison result is ignored, always true, or only enforced in debug builds',
    ],
  },
  {
    name: 'insecure WebView or JavaScript bridge (mobile)',
    cwe: 'CWE-749',
    needsUserInput: false,
    languages: MOBILE_LANGUAGES,
    signals: [
      'Dart: `WebViewController.loadRequest(Uri.parse(...))`, `InAppWebView` `initialUrlRequest` or `launchUrl` with a URL taken from a deep link, push payload, or query parameter with no scheme / host allow-list',
      'Dart: `JavaScriptMode.unrestricted` combined with `addJavaScriptChannel` / `addJavaScriptHandler` handlers that perform sensitive actions (token access, file read, payment, navigation) for any page origin, including remote or user-supplied content',
      'Dart: WebView settings enabling `allowFileAccess`, `allowFileAccessFromFileURLs` or `allowUniversalAccessFromFileURLs` while loading remote content',
      'Swift: `WKWebView.load` / `loadHTMLString(_:baseURL:)` with a user-controlled URL or `baseURL`; a `WKScriptMessageHandler` acting on `message.body` without validating `message.frameInfo.securityOrigin` or the message schema',
      'Swift: `allowFileAccessFromFileURLs` / `allowUniversalAccessFromFileURLs` enabled through `setValue(_:forKey:)`, or use of the deprecated `UIWebView`',
    ],
  },
  {
    name: 'unvalidated deep link / URL scheme / platform channel input (mobile)',
    cwe: 'CWE-939',
    needsUserInput: true,
    languages: MOBILE_LANGUAGES,
    signals: [
      'Swift: `application(_:open:options:)`, `scene(_:openURLContexts:)` or `application(_:continue:restorationHandler:)` (universal links) acting on URL components (login tokens, redirect targets, file paths, action parameters) without validating the scheme, host, source application or parameter values',
      'Swift: a custom URL scheme that triggers sensitive actions (sign-in, payment, account change, file import) with no user confirmation or re-authentication',
      'Dart: `go_router` / `app_links` / `uni_links` / `Uri.base` parameters (token, redirect, url, path) used to authenticate, navigate to arbitrary routes, open a WebView or read files without validation',
      'Dart: `MethodChannel` / `EventChannel` handlers (`setMethodCallHandler`) trusting `call.arguments` for file paths, URLs or privileged operations without validation',
      'OAuth / login callback received through a custom URL scheme without a `state` check or PKCE, allowing another app to intercept the authorisation code',
    ],
  },
  {
    name: 'client-side-only biometric / local authentication gate (mobile)',
    cwe: 'CWE-287',
    needsUserInput: false,
    languages: MOBILE_LANGUAGES,
    signals: [
      'Dart: the boolean result of `LocalAuthentication.authenticate()` used as the only gate to unlock secrets or sensitive actions, instead of protecting the secret with biometric-bound secure storage',
      'Swift: the `LAContext.evaluatePolicy` reply used as the only gate to reveal data (bypassable by hooking the callback); Keychain items not protected with a `SecAccessControl` policy such as `.biometryCurrentSet` or `.userPresence`',
      'A fallback path that skips authentication when biometrics are unavailable or error out, or when a debug / feature flag is set',
    ],
  },
  // ─── Docker (Dockerfile / Compose) ──────────────────────────────────────
  {
    name: 'container running as root',
    cwe: 'CWE-250',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'Dockerfile has no USER instruction, so the container runs as root (UID 0) by default',
      'USER instruction is present but sets `root` or `0` explicitly, or a USER that switches back to root later in the file',
      'Compose service defines `user: root` / `user: "0"`, or omits `user:` for an image that itself defaults to root',
      'RUN steps create a non-root user/group but no USER instruction ever switches to it before CMD/ENTRYPOINT',
    ],
  },
  {
    name: 'privileged container / excessive Docker capabilities',
    cwe: 'CWE-250',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'Compose service sets `privileged: true`',
      'Compose service sets `cap_add: [ALL]` or adds dangerous capabilities individually (SYS_ADMIN, NET_ADMIN, SYS_PTRACE, SYS_MODULE)',
      'Compose service shares the host namespace: `network_mode: host`, `pid: host`, `ipc: host`',
      'Compose service bind-mounts the Docker socket into the container (`/var/run/docker.sock:/var/run/docker.sock`), granting effective host root',
      'Compose service sets `security_opt: [seccomp:unconfined]` or disables AppArmor/SELinux confinement',
    ],
  },
  {
    name: 'hardcoded secret in Docker image or Compose file',
    cwe: 'CWE-798',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'ENV or ARG instruction assigns a literal password, API key, token, or private key value baked permanently into the image layer history',
      'RUN instruction echoes or writes credentials into a file inside the image instead of mounting them at runtime',
      'COPY of a credentials file (.env, .npmrc, id_rsa, credentials.json, .aws/credentials) into the image without a corresponding multi-stage step that discards it before the final stage',
      'Compose `environment:`/`env_file:` blocks contain literal secret values (as opposed to referencing an external secret store or `secrets:` mechanism)',
      'ARG used to pass a secret at build time without `--secret`/BuildKit secret mounts, leaving it recoverable from `docker history`',
    ],
  },
  {
    name: 'unpinned or unsafe base image',
    cwe: 'CWE-1104',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'FROM instruction with no tag (defaults to `:latest`) or an explicit `:latest` tag, making builds non-reproducible and silently pulling in new vulnerabilities over time',
      'FROM instruction pulling from an unofficial, unverified, or third-party registry/namespace with no digest pin (`@sha256:...`) for a base image handling sensitive workloads',
      'Compose `image:` reference with no tag or `:latest`',
    ],
  },
  {
    name: 'insecure ADD / untrusted remote content',
    cwe: 'CWE-494',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'ADD instruction fetching a remote URL directly into the image without any checksum/signature verification step afterward',
      'ADD used instead of COPY for local files with no archive-extraction need — masks intent and, for tar archives, auto-extracts (potential Zip-Slip-style path traversal if the archive is untrusted)',
      'Remote script fetched via ADD/RUN curl|wget and piped directly into `sh`/`bash` without pinning a version or verifying a hash/signature',
    ],
  },
  {
    name: 'sensitive Docker volume or bind mount exposure',
    cwe: 'CWE-732',
    needsUserInput: false,
    languages: ['docker'],
    signals: [
      'Compose bind-mounts the host root, `/etc`, `/proc`, `/var/run/docker.sock`, or another sensitive host path into the container',
      'Volume mounted read-write where the container only needs read access (missing `:ro` on a mount that should be read-only)',
      'Compose service exposes ports by binding `0.0.0.0` (or omitting a host IP, which defaults to all interfaces) for a service that should only be reachable internally (e.g. a database with no `expose`-only / internal network restriction)',
    ],
  },
  // ─── Infrastructure as Code (Terraform / Kubernetes / CloudFormation / Ansible) ───
  {
    name: 'publicly exposed cloud resource',
    cwe: 'CWE-284',
    needsUserInput: false,
    languages: ['iac', 'k8s'],
    signals: [
      'Storage bucket / blob container resource with public-read or public-read-write ACL, or a bucket policy with `Principal: "*"` and no condition restricting it',
      'Security group / firewall rule with ingress `cidr_blocks = ["0.0.0.0/0"]` (or `::/0`) on a sensitive port (22, 3389, 3306, 5432, 6379, 9200, 27017)',
      'Database or cache instance resource with `publicly_accessible = true` and no compensating network ACL',
      'Kubernetes Service of `type: LoadBalancer` or `NodePort` exposing an internal-only workload (databases, admin panels) without an accompanying NetworkPolicy',
    ],
  },
  {
    name: 'hardcoded secret in IaC template or variable',
    cwe: 'CWE-798',
    needsUserInput: false,
    languages: ['iac', 'k8s'],
    signals: [
      'Terraform resource argument or `variable` block `default` containing a literal password, API key, private key, or connection string instead of referencing a secrets manager / `sensitive = true` variable with no default',
      'Kubernetes Secret manifest with `data`/`stringData` containing a real-looking credential checked into source rather than sealed/external-secret referenced',
      'CloudFormation template parameter with `Default` set to a literal secret instead of using `NoEcho` + external injection, or a resource property embedding a credential directly',
      'Ansible playbook/vars file with a plaintext password/token instead of Ansible Vault or a lookup against an external secret store',
    ],
  },
  {
    name: 'disabled encryption at rest or in transit (IaC)',
    cwe: 'CWE-311',
    needsUserInput: false,
    languages: ['iac'],
    signals: [
      'Storage/database/queue resource explicitly setting `encrypted = false` / `storage_encrypted = false`, or omitting encryption entirely for a resource type where it defaults to off',
      'Load balancer / API Gateway / ingress resource allowing plain HTTP (no `redirect to HTTPS`, no `tls:` block, or `require_ssl`/`ssl_enforcement` disabled)',
      'CloudFormation/Terraform resource for a data store missing a KMS key / `kms_key_id` where encryption is configured but with default/weak key management',
    ],
  },
  {
    name: 'overly permissive IAM policy or RBAC',
    cwe: 'CWE-269',
    needsUserInput: false,
    languages: ['iac', 'k8s'],
    signals: [
      'IAM policy document with `Action: "*"` and/or `Resource: "*"` (wildcard privilege escalation risk), or `AdministratorAccess` attached to a role/user that does not need it',
      'Trust policy (assume-role) with an overly broad Principal (e.g. `*` or an entire AWS account) instead of a scoped role/service principal',
      'Kubernetes ClusterRoleBinding/RoleBinding granting `cluster-admin` (or a Role with wildcard `verbs`/`resources`/`apiGroups`) to a workload ServiceAccount that does not need it',
      'Ansible task running with `become: true` unconditionally for the whole play rather than the specific task that needs elevation',
    ],
  },
  {
    name: 'insecure Kubernetes pod security context',
    cwe: 'CWE-250',
    needsUserInput: false,
    languages: ['k8s'],
    signals: [
      'Pod/container spec missing `securityContext` or explicitly setting `allowPrivilegeEscalation: true`, `privileged: true`, or `runAsNonRoot: false`/omitted (defaults to root)',
      'Container spec sets `hostNetwork: true`, `hostPID: true`, or `hostIPC: true`, breaking namespace isolation from the node',
      'Container `capabilities.add` includes `SYS_ADMIN`, `NET_ADMIN`, or `ALL` without justification',
      'Pod mounts the host filesystem via `hostPath` volume (especially `/`, `/var/run/docker.sock`, or `/etc`) instead of a scoped PVC/ConfigMap',
      'No `resources.limits` set (missing CPU/memory limits), allowing a single pod to exhaust node resources',
    ],
  },
  {
    name: 'missing Kubernetes network segmentation',
    cwe: 'CWE-284',
    needsUserInput: false,
    languages: ['k8s'],
    signals: [
      'Namespace or workload with no default-deny `NetworkPolicy` at all, leaving pod-to-pod traffic unrestricted cluster-wide',
      '`NetworkPolicy` with an empty `podSelector: {}` combined with an `Egress` rule of `- {}` (allow-all egress), permitting unrestricted exfiltration from any matched pod',
      '`Ingress` resource routing to a backend Service with no corresponding `NetworkPolicy` restricting which namespaces/pods may reach it',
      '`NetworkPolicy` restricting ingress but not egress for a workload that handles sensitive data, leaving exfiltration paths open',
    ],
  },
  {
    name: 'insecure Kubernetes workload supply-chain hygiene',
    cwe: 'CWE-1104',
    needsUserInput: false,
    languages: ['k8s'],
    signals: [
      'Container image reference with no tag (defaults to `:latest`) or an explicit `:latest` tag — mutable, not pinned to a digest or immutable version',
      '`imagePullPolicy: Always` paired with a mutable tag pulling from a registry the cluster does not otherwise restrict via an admission policy',
      '`automountServiceAccountToken` not explicitly set to `false` for a workload that never calls the Kubernetes API, leaving an unused, exfiltratable token mounted by default',
      'Container spec missing `readOnlyRootFilesystem: true` for a workload with no legitimate need to write to its own filesystem',
      'Pod spec referencing a `ServiceAccount` with no `imagePullSecrets` scoping, or a default ServiceAccount left with its auto-mounted token in a namespace running third-party workloads',
    ],
  },
  {
    name: 'insecure network exposure or unencrypted state (Terraform)',
    cwe: 'CWE-200',
    needsUserInput: false,
    languages: ['iac'],
    signals: [
      'Terraform `backend` configuration storing state locally or in an unencrypted remote backend for a project handling secrets, with no `encrypt = true` (S3 backend) or equivalent',
      'Output blocks or resource attributes marked to output sensitive values (passwords, keys, connection strings) without `sensitive = true`',
      'Provider or resource configuration disabling TLS/certificate validation (`insecure = true`, `skip_tls_verify = true`, `verify_ssl = false`)',
    ],
  },
];

// Maps the human-readable language label attached to chunks (see
// analyzeSast.js's EXT_LANG table, e.g. "Python", "C++", "C#") to the
// language-family codes used in each catalog entry's `languages` array.
// Family codes themselves (e.g. "python", "c") pass through unchanged so
// callers can supply either form.
const DISPLAY_LANG_TO_FAMILY = {
  python:     'python',
  javascript: 'js',
  typescript: 'js',
  php:        'php',
  ruby:       'ruby',
  go:         'go',
  rust:       'rust',
  java:       'java',
  kotlin:     'kotlin',
  dart:       'dart',
  swift:      'swift',
  'c#':       'csharp',
  c:          'c',
  'c++':      'c',
  // Docker/IaC — keys match KIND_LABEL values (chunker/configDetect.js),
  // lowercased, as set on chunk.language by analyzeSast.js/analyzeMalware.js.
  dockerfile:       'docker',
  'docker compose': 'docker',
  terraform:        'iac',
  kubernetes:       'k8s',
  cloudformation:   'iac',
  ansible:          'iac',
};

// Filter the catalog down to the classes relevant to a given chunk's language.
//
// `language` may be the chunk's human-readable label ("Python", "C++", as set
// by analyzeSast.js) or a family code ("python", "c") directly — both are
// accepted. Unrecognised or missing languages (e.g. "unknown") fail open and
// return the full, unfiltered catalog rather than silently losing coverage.
function filterVulnClassesForLanguage(vulnClasses, language) {
  if (!language) return vulnClasses;

  const key    = String(language).toLowerCase().trim();
  const family = DISPLAY_LANG_TO_FAMILY[key] || key;

  const filtered = vulnClasses.filter(v => !v.languages || v.languages.includes(family));
  return filtered.length > 0 ? filtered : vulnClasses;
}

// Build the numbered vulnerability catalog block for the prompt.
// Each class gets its own numbered section with detection signals so the
// model knows exactly what to look for — instead of a flat comma-joined list.
//
// includeSignals: when false, omits the "Detect when you see" bullets to cut
// prompt tokens. Name, CWE, and scope rule are always kept.
function buildVulnCatalog(vulnClasses, includeSignals = true) {
  return vulnClasses.map((v, idx) => {
    const header = `${idx + 1}. ${v.name} (${v.cwe})`;
    const scope  = v.needsUserInput
      ? '   Scope    : Report ONLY when attacker-controlled input visibly reaches this sink.'
      : '   Scope    : Report regardless of whether a taint source is visible.';
    if (!includeSignals) {
      return `${header}\n${scope}`;
    }
    const sigs   = v.signals.map(s => `   - ${s}`).join('\n');
    return `${header}\n${scope}\n   Detect when you see:\n${sigs}`;
  }).join('\n\n');
}

export {
  DEFAULT_VULN_CLASSES,
  ALL_LANGUAGES,
  WEB_LANGUAGES,
  MOBILE_LANGUAGES,
  DISPLAY_LANG_TO_FAMILY,
  filterVulnClassesForLanguage,
  buildVulnCatalog,
};