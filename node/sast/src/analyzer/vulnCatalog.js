'use strict';

// ═════════════════════════════════════════════════════════════════════════════
// VULNERABILITY CLASSES & CATALOG BUILDER
// ═════════════════════════════════════════════════════════════════════════════

// Canonical language-family codes — must match constants.js FAMILY_LABELS.
const ALL_LANGUAGES = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp', 'c'];

// "Web"-shaped languages: everything except C, which essentially never hosts
// the request/response, ORM, templating, or session-cookie code these
// classes are about. Used for the many web-app-flavoured classes below.
const WEB_LANGUAGES = ['js', 'python', 'php', 'ruby', 'go', 'rust', 'java', 'kotlin', 'csharp'];

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
    ],
  },
  {
    name: 'unsafe deserialization',
    cwe: 'CWE-502',
    needsUserInput: true,
    languages: ['python', 'java', 'kotlin', 'php', 'csharp', 'ruby', 'js'],
    signals: [
      'pickle.loads / pickle.load / yaml.load (without Loader=yaml.SafeLoader) / marshal.loads on user-controlled data',
      'Java ObjectInputStream.readObject on data arriving from the network or a user-supplied file',
      'PHP unserialize() on user input',
      'C# / .NET: BinaryFormatter.Deserialize, NetDataContractSerializer, LosFormatter.Deserialize, ObjectStateFormatter.Deserialize, or JavaScriptSerializer (with SimpleTypeResolver) called on user-supplied data',
      'C# / .NET: Newtonsoft.Json.JsonConvert.DeserializeObject with TypeNameHandling.Objects or TypeNameHandling.Auto without a custom SerializationBinder or type allowlist',
      'Ruby: Marshal.load or YAML.load called on user-controlled input, allowing arbitrary code execution',
      'Node.js node-serialize / serialize-javascript eval path on untrusted data',
      'Deserialization of JSON/XML with class mapping that can instantiate arbitrary types (e.g. Jackson polymorphic typing enabled globally)',
    ],
  },
  {
    name: 'XSS / template injection',
    cwe: 'CWE-79 / CWE-94',
    needsUserInput: true,
    languages: WEB_LANGUAGES,
    signals: [
      'User input rendered into HTML without escaping: innerHTML, document.write, dangerouslySetInnerHTML, v-html, [innerHTML]=',
      'Server-side template engines (Jinja2, Twig, Pebble, Velocity, Freemarker, Handlebars, EJS) receiving user input in the template string rather than only in the context variables',
      'React/Vue/Angular bypassing the framework\'s auto-escaping via raw HTML APIs',
      'eval() or new Function() called with a template string that contains user data',
      'DOM clobbering: user-controlled HTML inserted adjacent to code that reads named DOM properties',
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
    languages: ['js', 'python', 'ruby', 'php'],
    signals: [
      'eval(), new Function(), setTimeout/setInterval with a string argument, execScript receiving user data',
      'Python exec() / compile() / eval() on user-supplied code strings',
      'Ruby eval / instance_eval / class_eval on user input',
      'PHP eval(), preg_replace with /e modifier, assert() with a string argument on user data',
      'Server-side template rendered from a string built with user content (distinct from XSS — focuses on server execution)',
      'Dynamic require() / import() with a user-controlled module path',
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
    ],
  },
  {
    name: 'integer overflow / underflow',
    cwe: 'CWE-190',
    needsUserInput: true,
    languages: ['c', 'rust', 'go', 'java', 'kotlin', 'csharp'],
    signals: [
      'Arithmetic on user-supplied numeric values used as buffer sizes, array indices, or loop bounds without range checks',
      'Signed/unsigned integer conversion where user input could produce a negative buffer size',
      'Multiplication of user-controlled values used to allocate memory (e.g. width * height without overflow check)',
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
    languages: ['js', 'python', 'php', 'ruby', 'java', 'kotlin', 'csharp', 'c'],
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
    languages: WEB_LANGUAGES,
    signals: [
      'JWT decoded/parsed without signature verification, or verification called with `verify: false` / equivalent',
      'Signing algorithm not pinned server-side, allowing `alg: none` or RS256→HS256 confusion (public key reused as the HMAC secret)',
      'Token `exp`, `nbf`, `iss`, or `aud` claims not checked after signature verification, allowing expired or wrong-audience tokens to be accepted',
      'Refresh token, password-reset token, or email-verification token generated without sufficient entropy, or not invalidated/rotated after use',
      'Token revocation not enforced server-side (e.g., logout only deletes the client-side cookie, no server-side blocklist or short-lived token design)',
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
  'c#':       'csharp',
  c:          'c',
  'c++':      'c',
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
  DISPLAY_LANG_TO_FAMILY,
  filterVulnClassesForLanguage,
  buildVulnCatalog,
};