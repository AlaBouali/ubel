'use strict';

// ─── Language knowledge for the static engine ─────────────────────────────────
//
// Pure data + small parsers. Nothing here knows about rules or findings:
//   SOURCES        expressions whose value an attacker controls, per family
//   LIT_SOURCES    the same, for sources that need string-literal text to
//                  recognise (php://input, event['body'], …) — matched on the
//                  `literal` view
//   OUT_SOURCES    calls that WRITE attacker data into one of their arguments
//                  (fgets(buf, …), recv(fd, buf, …), scanf("%s", buf))
//   SANITIZERS     calls that neutralise a value for a class of sink
//   parseParams()  the parameters of the function a chunk holds, and which of
//                  them the framework fills with request data

const src = (...parts) => new RegExp(parts.map(p => `(?:${p})`).join('|'), 'g');

// ── Taint sources (matched on the `code` view; string text is blanked there) ──
export const SOURCES = {
  js: src(
    String.raw`\b(?:req|request)\s*\.\s*(?:body|query|params|headers|cookies|signedCookies|files?|hostname|originalUrl|baseUrl|rawBody|payload|url|path|ip|ips|subdomains)\b`,
    String.raw`\b(?:req|request)\s*\.\s*(?:get|header|param|accepts\w*)\s*\(`,
    String.raw`\bctx\s*\.\s*(?:request|query|params|headers|cookies|req|path|url|querystring|href|origin)\b`,
    String.raw`\bevent\s*\.\s*(?:body|queryStringParameters|multiValueQueryStringParameters|pathParameters|headers|rawPath|rawQueryString)\b`,
    String.raw`\b(?:window\s*\.\s*|document\s*\.\s*)?location\s*\.\s*(?:search|hash|href|pathname|host|hostname|origin)\b`,
    String.raw`\bdocument\s*\.\s*(?:URL|documentURI|baseURI|referrer|cookie)\b`,
    String.raw`\bwindow\s*\.\s*name\b`,
    String.raw`\bprocess\s*\.\s*(?:argv|stdin)\b`,
    String.raw`\bsearchParams\s*\.\s*get(?:All)?\s*\(`,
    String.raw`\bnew\s+URLSearchParams\s*\([^)]*\)\s*\.\s*get(?:All)?\s*\(`,
    String.raw`\bcontext\s*\.\s*(?:query|params|req|request)\b`,
    String.raw`\b(?:localStorage|sessionStorage)\s*\.\s*getItem\s*\(`,
  ),
  python: src(
    String.raw`\brequest\s*\.\s*(?:args|form|values|json|data|files|cookies|headers|GET|POST|COOKIES|FILES|META|body|query_params|path_params|query_string|environ|full_path|url|path|host|referrer|authorization|stream|view_args|rel_url|match_info|query|post|text|content|multipart)\b`,
    String.raw`\brequest\s*\.\s*(?:get_json|get_data|getlist|read|json|post|text|body)\s*\(`,
    String.raw`\bself\s*\.\s*request\s*\.`,
    String.raw`\bself\s*\.\s*(?:get_argument|get_query_argument|get_body_argument|get_arguments|get_cookie|get_secure_cookie)\s*\(`,
    String.raw`\binput\s*\(`,
    String.raw`\bsys\s*\.\s*(?:argv|stdin)\b`,
    String.raw`\bflask\s*\.\s*request\b`,
    String.raw`\b(?:sock|socket|conn|client|connection)\s*\.\s*recv(?:from)?\s*\(`,
    String.raw`\b(?:ws|websocket)\s*\.\s*(?:receive|recv)\w*\s*\(`,
  ),
  php: src(
    String.raw`\$_(?:GET|POST|REQUEST|COOKIE|FILES|SERVER|ENV)\b`,
    String.raw`\$request\s*->\s*\w+`,
    String.raw`\$this\s*->\s*request\s*->\s*(?:data|query|getData|getQuery|input|params|header)\w*`,
    String.raw`\b(?:Input|Request)\s*::\s*(?:get|input|query|all|post|only|except|cookie|header|file|json|segment)\w*\s*\(`,
    String.raw`\bfilter_input(?:_array)?\s*\(`,
    String.raw`\bgetallheaders\s*\(|\bapache_request_headers\s*\(`,
    String.raw`\bget_query_var\s*\(|\bget_query_arg\s*\(`,
    String.raw`\bwp_get_(?:raw_)?referer\s*\(|\$wp(?:_query)?\s*->\s*query_vars\b|\$wp_query\s*->\s*get\s*\(`,
    String.raw`\$request\s*\[`,
    String.raw`\brequest\s*\(\s*\)\s*->\s*\w+|(?<![\w$>:.\\])request\s*\(\s*['"]`,
    String.raw`\bYii\s*::\s*\$app\s*->\s*request\s*->\s*\w+`,
    String.raw`\$this\s*->\s*input\s*->\s*(?:get|post|get_post|post_get|cookie|server|raw_input_stream|get_request_header|input_stream)\w*\s*\(`,
    String.raw`\$this\s*->\s*request\s*->\s*(?:getQuery|getData|getParam|getCookie|getParsedBody|getQueryParams|getUploadedFiles)\w*`,
    String.raw`\$(?:argv|argc)\b|\bSTDIN\b|\breadline\s*\(`,
  ),
  ruby: src(
    String.raw`\bparams\b`,
    String.raw`\brequest\s*\.\s*(?:params|query_parameters|request_parameters|GET|POST|body|headers|env|cookies|raw_post|referer|referrer|url|host|original_url|fullpath|query_string|path_info|user_agent|authorization)\b`,
    String.raw`\bcookies\s*(?:\[|\.)`,
    String.raw`\bARGV\b|\bSTDIN\b|\bARGF\b|\bgets\b`,
  ),
  go: src(
    String.raw`\b(?:r|req|request)\s*\.\s*(?:URL|Form|PostForm|MultipartForm|Header|Body|Host|RequestURI|FormValue|PostFormValue|FormFile|Cookie|Cookies|ParseForm|PathValue|Referer|UserAgent)\b`,
    String.raw`\b(?:c|ctx|e)\s*\.\s*Request\s*\(?\s*\)?\s*\.\s*(?:URL|Form|PostForm|Header|Body|Host|FormValue|Cookie)\b`,
    String.raw`\bmux\s*\.\s*Vars\s*\(|\bchi\s*\.\s*URLParam\s*\(|\bhttprouter\s*\.\s*ParamsFromContext\s*\(`,
    String.raw`\bos\s*\.\s*Args\b`,
    String.raw`\bbufio\s*\.\s*New(?:Reader|Scanner)\s*\(\s*os\s*\.\s*Stdin`,
    String.raw`\.\s*ReadMessage\s*\(`,
  ),
  rust: src(
    String.raw`\breq(?:uest)?\s*\.\s*(?:query_string|match_info|headers|uri|path|cookie|cookies|connection_info|param|body)\b`,
    String.raw`\b(?:std\s*::\s*)?env\s*::\s*args\b`,
    String.raw`\b(?:std\s*::\s*)?io\s*::\s*stdin\b|\bstdin\s*\(\s*\)`,
    String.raw`\.\s*read_line\s*\(`,
  ),
  java: src(
    String.raw`\b(?:request|req|httpRequest|servletRequest|httpServletRequest)\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getParameterNames|getHeader|getHeaders|getHeaderNames|getCookies|getQueryString|getRequestURI|getRequestURL|getPathInfo|getPathTranslated|getInputStream|getReader|getParts?|getAttribute|getServletPath|getRemoteHost|getRemoteUser|getContentType)\s*\(`,
    String.raw`\bSystem\s*\.\s*in\b`,
    String.raw`\bargs\s*\[`,
    String.raw`\b(?:ctx|context)\s*\.\s*(?:queryParam|queryParams|pathParam|formParam|body|bodyAsClass|header|cookie|param|queryParamMap|formParamMap|uploadedFile)\w*\s*\(`,
    String.raw`\b(?:req|request)\s*\.\s*(?:queryParams|params|body|headers|cookie|attribute|splat|uri|url|pathInfo)\s*\(`,
    String.raw`\.\s*(?:getQueryParameters|getPathParameters|getHeaderString|getRequestHeader|getRequestURI|getRequestBody)\s*\(`,
    String.raw`\bgetOriginalFilename\s*\(`,
  ),
  kotlin: src(
    String.raw`\b(?:request|req|httpRequest|servletRequest)\s*\.\s*(?:getParameter|getParameterValues|getParameterMap|getHeader|getHeaders|getCookies|getQueryString|getRequestURI|getRequestURL|getPathInfo|getInputStream|getReader|getParts?|getAttribute)\s*\(`,
    String.raw`\b(?:request|req)\s*\.\s*(?:parameter|queryParams|header|cookie|queryString|requestURI|inputStream|reader)\b`,
    String.raw`\bcall\s*\.\s*(?:receive\w*|parameters|request\s*\.\s*(?:queryParameters|headers|cookies|uri|local|origin))\b`,
    String.raw`\bcall\s*\.\s*(?:receive\w*)\s*[<(]`,
    String.raw`\b(?:ctx|context)\s*\.\s*(?:queryParam|pathParam|formParam|body|header|cookie|param)\w*\s*\(`,
    String.raw`\breadLine(?:OrNull)?\s*\(|\bSystem\s*\.\s*in\b|\bargs\s*\[`,
    String.raw`\bgetOriginalFilename\s*\(|\boriginalFilename\b`,
  ),
  csharp: src(
    String.raw`\bRequest\s*\.\s*(?:Query|Form|Headers|Cookies|Params|QueryString|RouteValues|Body|Path|PathBase|Host|Url|RawUrl|Files|InputStream|UserAgent|ServerVariables|Item|ContentType|AcceptTypes|UrlReferrer|Unvalidated)\b`,
    String.raw`\bRequest\s*\[`,
    String.raw`\b(?:HttpContext|context|ctx|httpContext)\s*\.\s*Request\s*\.`,
    String.raw`\bRouteData\s*\.\s*(?:Values|GetRequiredString)\b`,
    String.raw`\bConsole\s*\.\s*(?:ReadLine|Read|In)\b`,
    String.raw`\bEnvironment\s*\.\s*GetCommandLineArgs\b|\bargs\s*\[`,
    String.raw`\bHttpUtility\s*\.\s*ParseQueryString\s*\(`,
    String.raw`\.\s*(?:ReadAsStringAsync|ReadFromJsonAsync|ReadAsStreamAsync)\s*\(`,
  ),
  c: src(
    String.raw`\bargv\b`,
    String.raw`\bgetenv\s*\(`,
    String.raw`\bstd\s*::\s*cin\b|\bcin\s*>>`,
    String.raw`\bQUERY_STRING\b`,
  ),
  dart: src(
    String.raw`\b(?:request|req)\s*\.\s*(?:uri|url|requestedUri|headers|body|params|queryParameters|queryParametersAll|cookies|readAsString|read|json|formData|stream|pathSegments|query)\b`,
    String.raw`\bUri\s*\.\s*base\b`,
    String.raw`\b(?:uri|link|deepLink|initialLink|incomingUri)\s*\.\s*(?:queryParameters|queryParametersAll|query|fragment|pathSegments)\b`,
    String.raw`\bstdin\s*\.\s*(?:readLineSync|readLine|readByteSync)\b`,
    String.raw`\b\w*[cC]ontroller\s*\.\s*text\b`,
    String.raw`\b(?:call|methodCall)\s*\.\s*arguments\b`,
    String.raw`\bmessage\s*\.\s*message\b`,
    String.raw`\bClipboard\s*\.\s*getData\b`,
    String.raw`\b(?:settings|routeSettings)\s*\.\s*(?:name|arguments)\b`,
    String.raw`\bgetInitialLink\s*\(|\buriLinkStream\b|\blinkStream\b`,
  ),
  swift: src(
    String.raw`\b(?:req|request)\s*\.\s*(?:query|content|parameters|headers|body|url|cookies|uri)\b`,
    String.raw`\.\s*queryItems\b`,
    String.raw`\bUIPasteboard\s*\.\s*general\s*\.\s*(?:string|strings|url|items)\b`,
    String.raw`\b\w*(?:[tT]extField|[sS]earchBar|[tT]extView)\w*\s*\??\s*\.\s*text\b`,
    String.raw`\bCommandLine\s*\.\s*arguments\b|\breadLine\s*\(`,
    String.raw`\buserActivity\s*\.\s*(?:webpageURL|userInfo|referrerURL)\b|\bnotification\s*\.\s*userInfo\b|\blaunchOptions\b`,
    String.raw`\bmessage\s*\.\s*body\b`,
  ),
};

// Sources recognised from literal text (the `literal` view).
export const LIT_SOURCES = {
  php:    src(String.raw`php:\/\/input`, String.raw`HTTP_RAW_POST_DATA`),
  python: src(String.raw`\bevent\s*\[\s*['"](?:body|queryStringParameters|pathParameters|headers|multiValueQueryStringParameters)['"]\s*\]`,
              String.raw`\bevent\s*\.\s*get\s*\(\s*['"](?:body|queryStringParameters|pathParameters|headers)['"]`),
  js:     src(String.raw`\bevent\s*\[\s*['"](?:body|queryStringParameters|pathParameters|headers)['"]\s*\]`),
};

// Calls that put attacker data into one of their arguments: { callee, args }.
export const OUT_SOURCES = {
  c: [
    { callee: /^(?:fgets|gets|fread|read|recv|recvfrom|pread|getdelim|getline|readlink|fscanf_s|gets_s|getcwd)$/, args: [0, 1], pick: { fgets: [0], gets: [0], fread: [0], read: [1], recv: [1], recvfrom: [1], pread: [1], getline: [0], getdelim: [0], readlink: [1], getcwd: [0], gets_s: [0], fscanf_s: [] } },
    { callee: /^(?:scanf|sscanf|fscanf|vscanf|scanf_s|sscanf_s)$/, args: 'rest' },
    { callee: /^(?:std::getline|getline)$/, args: [1] },
  ],
};

// ── Sanitizers ────────────────────────────────────────────────────────────────
// A tainted value that is the argument of one of these calls is clean for the
// listed groups. Group "all" = numeric/identity conversion: nothing injectable
// survives it. Matching is on the normalised callee path (`a . b` → `a.b`).
const ALL = ['all'];
const NUM = ['num'];   // numeric conversion: not injectable, but the magnitude is still attacker-chosen (memory / integer classes)
export const SANITIZER_CALLS = [
  // identity / boolean conversions → clean for every class
  { re: /^(?:bool|len|hash|bytes\.fromhex|uuid\.UUID|UUID|ipaddress\.\w+)$/, groups: ALL },
  // Go hash / MAC constructors and one-shot digests: fixed output size, hex/binary digest
  { re: /^(?:hmac\.New|sha(?:1|256|512|224|384)\.(?:New\w*|Sum\w*)|sha3\.\w+|md5\.(?:New|Sum)|blake2[bs]\.\w+|crc(?:32|64)\.\w+|fnv\.New\w+)$/, groups: ALL },
  { re: /^(?:Boolean|isNaN|isFinite|ObjectId|mongoose\.Types\.ObjectId|Types\.ObjectId|uuid\.validate|validator\.is(?:Int|Float|UUID|Numeric|Boolean|MongoId|Alphanumeric|Hexadecimal|IP))$/, groups: ALL },
  { re: /^(?:boolval|is_numeric|ctype_digit|ctype_alnum|ctype_xdigit|filter_var|settype)$/, groups: ALL },
  { re: /^(?:UUID\.fromString|Boolean\.parseBoolean|Enum\.valueOf|Guid\.Parse|Guid\.TryParse|bool\.Parse|Enum\.Parse|Enum\.TryParse|Convert\.ToBoolean|uuid\.(?:Parse|MustParse)|net\.ParseIP|url\.ParseRequestURI|strconv\.ParseBool)$/, groups: ALL },
  { re: /^(?:Bool|UUID)$/, groups: ALL },
  // numeric conversions → not injectable, magnitude still attacker-chosen
  { re: /^(?:int|float|abs|round|ord|Decimal|decimal\.Decimal)$/, groups: NUM },
  { re: /^(?:parseInt|parseFloat|Number|BigInt|Math\.\w+)$/, groups: NUM },
  { re: /^(?:intval|floatval|absint)$/, groups: NUM },
  { re: /^(?:Integer\.parseInt|Integer\.valueOf|Long\.parseLong|Long\.valueOf|Double\.parseDouble|Float\.parseFloat|Short\.parseShort|BigDecimal|BigInteger)$/, groups: NUM },
  { re: /^(?:int\.Parse|int\.TryParse|long\.Parse|long\.TryParse|Int32\.Parse|Int64\.Parse|Convert\.ToInt32|Convert\.ToInt64|Convert\.ToDouble|decimal\.Parse|double\.Parse)$/, groups: NUM },
  { re: /^strconv\.(?:Atoi|ParseInt|ParseUint|ParseFloat)$/, groups: NUM },
  { re: /^(?:Integer|Float|Rational|Complex)$/, groups: NUM },
  { re: /^(?:Int|Double|Float|CGFloat|Int32|Int64|UInt|NSNumber)$/, groups: NUM },
  { re: /^(?:int\.parse|int\.tryParse|double\.parse|double\.tryParse|num\.parse|num\.tryParse|BigInt\.parse)$/, groups: NUM },
  { re: /^(?:toInt|toLong|toDouble|toIntOrNull|toLongOrNull|toDoubleOrNull|atoi|atol|atoll|atof|strtol|strtoul|strtoll|strtoull|strtod|strtof)$/, groups: NUM },
  { re: /^toBoolean$/, groups: ALL },
  // SQL
  { re: /(?:^|\.)(?:escape|escapeId|escape_string|real_escape_string|mysql_real_escape_string|mysqli_real_escape_string|pg_escape_string|pg_escape_literal|pg_escape_identifier|sqlite_escape_string|quote_identifier|quote_ident|sanitize_sql\w*|QuotedString|quoteIdentifier|escapeLiteral|escapeIdentifier)$/, groups: ['sql'] },
  { re: /^(?:sql\.Identifier|sql\.Literal|Prisma\.sql|sqlstring\.escape|SqlString\.escape|mysql\.escape|pool\.escape|connection\.escape|db\.escape|pgFormat\.\w+|format\.ident|format\.literal)$/, groups: ['sql'] },
  // HTML / template output
  { re: /(?:^|\.)(?:escapeHtml|escapeHTML|escape_html|escapeHtml4|escapeHtml3|escapeXml|escapeXml10|escapeXml11|htmlspecialchars|htmlentities|html_escape|h|sanitize|sanitizeHtml|sanitize_html|strip_tags|bleach\.clean|clean|forHtml|forHtmlContent|forHtmlAttribute|forJavaScript|htmlEscape|htmlEncode|HtmlEncode|Encode|escapeJs|escape_javascript|j|e|xss|filterXSS|DOMPurify\.sanitize|he\.encode|he\.escape|encodeForHTML|EscapeString|HTMLEscapeString|JSEscapeString|escapeMarkup|markupsafe\.escape|Markup\.escape|conditional_escape|format_html|mark_safe_escape|html\.escape|cgi\.escape|CGI\.escapeHTML|ERB::Util\.html_escape|Rack::Utils\.escape_html|WebUtility\.HtmlEncode|HttpUtility\.HtmlEncode|HtmlEncoder\.Default\.Encode|AntiXssEncoder\.\w+|Server\.HtmlEncode|Html\.Encode)$/, groups: ['html', 'log'] },
  // shell
  { re: /(?:^shlex\.quote|^pipes\.quote|(?:^|\.)(?:escapeshellarg|escapeshellcmd|shellescape|Shellwords\.escape|Shellwords\.shellescape|shell_escape|shellEscape|shell-escape|shell-quote|ShellEscape))$/, groups: ['shell'] },
  // filesystem paths
  { re: /(?:^|\.)(?:basename|secure_filename|sanitize_filename|sanitizeFilename|sanitize-filename|FilenameUtils\.getName|GetFileName|GetFileNameWithoutExtension|filepath\.Base|path\.basename|os\.path\.basename|File\.basename|Path\.GetFileName|getName|get_valid_filename|safe_join|realpath|Path\.GetFullPath|canonicalize|toRealPath|getCanonicalPath|getCanonicalFile)$/, groups: ['path'] },
  // URL encoding: neutralises injection into a single URL component, header or log line, not the host
  { re: /(?:^|\.)(?:encodeURIComponent|encodeURI|parse\.quote|quote_plus|urllib\.quote|urlencode|rawurlencode|url_for|reverse|reverse_lazy|QueryEscape|PathEscape|EscapeDataString|EscapeUriString|URLEncoder\.encode|escape_uri|url_encode|UrlEncode|percentEncode|addingPercentEncoding|http_build_query)$/, groups: ['header', 'log', 'html', 'redirect_param'] },
  // regex metacharacter escaping
  { re: /(?:^|\.)(?:escapeRegExp|escapeRegex|escape_regex|re\.escape|Regexp\.escape|Regexp\.quote|Pattern\.quote|regexp\.QuoteMeta|preg_quote|Regex\.Escape|escapeStringRegexp|lodash\.escapeRegExp|_\.escapeRegExp)$/, groups: ['regexp'] },
  // LDAP / XPath
  { re: /(?:^|\.)(?:escape_filter_chars|escape_dn_chars|escapeLDAPSearchFilter|escapeLdap|escapeDN|forLDAP|forLdap|forDN|encodeForLDAP|ldap\.escape|ldap3\.utils\.conv\.escape_filter_chars|ldap_escape|XPathVariableResolver|escapeXPath)$/, groups: ['ldap', 'xpath'] },
  // NoSQL operator injection
  { re: /^(?:String|mongoSanitize|mongoSanitize\.sanitize|sanitize|express-mongo-sanitize|bson\.ObjectId|toString|str)$/, groups: ['nosql'] },
  // ══ WordPress ═══════════════════════════════════════════════════════════════
  // "Sanitise on input, escape on output": both families are recognised, and each entry clears only the classes its
  // result is safe for. `minArg` / `maxArg` limit an entry to the arguments the function really cleans.
  // Tag-stripping sanitisers (sanitize_text_field …) are treated as HTML-safe, like strip_tags above; they do NOT
  // encode quotes, so output inside an HTML attribute still needs esc_attr().
  // Fixed-alphabet results ([a-z0-9_-], #hex, true/false): nothing injectable survives.
  { re: /^(?:sanitize_key|sanitize_html_class|sanitize_hex_color(?:_no_hash)?|tag_escape|wp_parse_slug_list|wp_validate_boolean|rest_sanitize_boolean)$/, groups: ALL },
  { re: /^sanitize_title(?:_with_dashes|_for_query)?$/, groups: ALL, maxArg: 0 },
  { re: /^wp_parse_id_list$/, groups: NUM },
  // file names / MIME types: path separators and shell/SQL/HTML metacharacters are stripped
  { re: /^sanitize_file_name$/, groups: ['path', 'html', 'shell', 'sql', 'header', 'log', 'ssrf'] },
  { re: /^sanitize_mime_type$/, groups: ['html', 'sql', 'shell', 'header', 'log', 'ssrf'] },
  { re: /^wp_basename$/, groups: ['path'] },
  // predicates / guards: they only inspect the value, nothing derived from it is returned (`isset($_GET['x']) ? … : …`)
  { re: /^(?:isset|empty|array_key_exists|in_array|is_array|is_string|is_null|is_bool|is_int|is_integer|is_float|is_scalar|is_object|strlen|mb_strlen|count|sizeof|wp_verify_nonce|check_admin_referer|check_ajax_referer|current_user_can|user_can|username_exists|email_exists|term_exists|post_type_exists|taxonomy_exists)$/, groups: ALL },
  // text sanitisers: tags stripped, line breaks / tabs / %xx octets removed (textarea variant keeps line breaks)
  { re: /^(?:sanitize_text_field|sanitize_email|sanitize_user)$/, groups: ['html', 'header', 'log'] },
  { re: /^sanitize_textarea_field$/, groups: ['html'] },
  // output escaping and HTML filtering
  { re: /^(?:esc_html|esc_attr|esc_textarea|esc_js|esc_xml|esc_html__|esc_attr__|esc_html_e|esc_attr_e|esc_html_x|esc_attr_x|_wp_specialchars|wp_specialchars|wp_strip_all_tags|wp_filter_nohtml_kses|wp_filter_kses|wp_filter_post_kses|wp_kses_post|wp_kses_post_deep|wp_kses_data)$/, groups: ['html', 'log'] },
  { re: /^(?:wp_kses|wp_kses_one_attr)$/, groups: ['html', 'log'], maxArg: 0 },          // arg 1 is the allow-list, not the data
  // URLs: esc_url also encodes quotes/ampersands (safe in an attribute); esc_url_raw is for storing/redirecting and
  // checks the scheme only, so neither makes a redirect or an outbound request safe
  { re: /^esc_url$/, groups: ['html', 'log', 'header', 'redirect_param'] },
  { re: /^(?:esc_url_raw|wp_sanitize_redirect)$/, groups: ['header', 'log'] },
  { re: /^wp_validate_redirect$/, groups: ['redirect'], maxArg: 0 },                    // arg 1 is the trusted fallback
  { re: /^wp_http_validate_url$/, groups: ['ssrf'] },
  // SQL: esc_sql / wpdb::_real_escape are only safe inside a quoted literal (same assumption as mysqli_real_escape_string)
  { re: /^esc_sql$|(?:^|\.)\$?\w*wpdb\w*\.(?:_real_escape|_escape|escape_by_ref)$/, groups: ['sql'] },
  // $wpdb->prepare($query, $values…): values after the query are bound; the query string itself is NOT cleaned
  { re: /(?:^|\.)\$?\w*wpdb\w*\.prepare$/, groups: ['sql'], minArg: 1 },

  // ══ Other frameworks ════════════════════════════════════════════════════════
  // SQL: bound parameters, driver quoting, identifier quoting (Doctrine/Yii/CodeIgniter/Rails/Django/ESAPI/pq/mysql)
  { re: /(?:^|[.:])(?:createNamedParameter|createPositionalParameter|quoteValue|quoteColumnName|quoteTableName|quote_name|quote_table_name|quote_column_name|quote_string|quoteInto|escape_str|escape_like_str|escape_identifiers|protect_identifiers|encodeForSQL|QuoteLiteral|QuoteIdentifier)$/, groups: ['sql'] },
  { re: /^\$[\w.]*(?:pdo|dbh|db|conn|connection|mysqli|link|adapter|driver)\w*\.quote$|(?:^|[.:])connection\.quote$/i, groups: ['sql'] },
  { re: /(?:^|\.)(?:mysql|SqlString|sqlstring|connection|pool|db|conn)\.format$/, groups: ['sql'], minArg: 1 },
  // HTML / template output: OWASP Java Encoder + ESAPI, Spring, Laminas Escaper, Handlebars, Django, Rails, Twig/Smarty,
  // AntiXSS / HtmlSanitizer (.NET), bluemonday (Go), Yii, CodeIgniter, HTMLPurifier
  { re: /(?:^|[.:])(?:escapeHtmlAttr|escapeCss|escapeUrl|encodeForHTMLAttribute|encodeForXML|encodeForXMLAttribute|encodeForCSS|encodeForJavaScript|forXml|forXmlContent|forXmlAttribute|forXmlComment|forCssString|forCssUrl|forJavaScriptAttribute|forJavaScriptBlock|forJavaScriptSource|forHtmlUnquotedAttribute|htmlEscapeDecimal|htmlEscapeHex|javaScriptEscape|escapeEcmaScript|escapeExpression|escapeXML|encodeHTML|encodeXML|striptags|stripTags|escape_once|html_escape_once|escape_javascript|escapejs|force_escape|conditional_escape|twig_escape_filter|twig_escape|smarty_modifier_escape|HtmlAttributeEncode|JavaScriptStringEncode|JavaScriptEncode|HTMLEscaper|JSEscaper|GetSafeHtmlFragment|Sanitize|SanitizeHtml|SanitizeBytes|SanitizeReader|clean_html|xss_clean|purify|esc)$/, groups: ['html', 'log'] },
  { re: /(?:^|[.:])(?:Html::(?:encode|encodeAttribute)|(?:HtmlPurifier|Purifier)::(?:process|clean))$/, groups: ['html', 'log'] },
  { re: /^(?:escape|(?:django\.utils\.html|flask|jinja2|jinja2\.utils)\.escape|(?:_|lodash|validator|he)\.escape)$/, groups: ['html', 'log'] },
  { re: /(?:^|[.:])(?:html_escape|htmlescape)::\w+$/, groups: ['html', 'log'] },
  // slugs: [a-z0-9-] only
  { re: /(?:^|[.:])(?:Str::slug|slugify)$/, groups: ALL },
  // URL encoding of a component
  { re: /(?:^|[.:])(?:encode_www_form_component|encode_uri_component|escapeURIComponent|url_encode|forUri|forUriComponent|encodeForURL|encodePathSegment|encodeQueryParam|UrlPathEncode|URLQueryEscaper|percent_encode|utf8_percent_encode|byte_serialize|generateUrl|urlencoding::encode)$|^quote$|^CGI\.escape$/, groups: ['header', 'log', 'html', 'redirect_param'] },
  // shell / XPath
  { re: /(?:^|[.:])(?:encodeForOS|shell_escape::(?:unix|windows)::escape|shlex::(?:try_)?quote)$/, groups: ['shell'] },
  { re: /(?:^|[.:])encodeForXPath$/, groups: ['xpath'] },
  // typed conversions / validators
  { re: /(?:^|[.:])(?:NumberUtils\.(?:toInt|toLong|toDouble|toFloat|createInteger|createLong|createDouble)|validator\.(?:toInt|toFloat)|govalidator\.(?:ToInt|ToFloat))$/, groups: NUM },
  { re: /(?:^|[.:])(?:validator\.toBoolean|Uuid::(?:parse_str|from_str)|Ulid::fromString)$/, groups: ALL },
];

// Method/property applied AFTER a tainted value: `x.to_i`, `x.length`.
export const SANITIZER_SUFFIX = [
  { re: /^\s*\.\s*(?:to_i|to_f|toInt|toLong|toDouble|toIntOrNull)\b/, groups: NUM },
  { re: /^\s*\.\s*(?:to_sym|toBoolean|length|size|count|isEmpty|isBlank|empty\?|nil\?|hashCode|bit_length|isdigit|isnumeric|isalnum|isalpha)\b/, groups: ALL },
  { re: /^\s*\.\s*parse\s*(?:::\s*)?<\s*(?:i|u)\d+|^\s*\.\s*parse\s*::\s*<\s*(?:f32|f64|usize|isize)/, groups: NUM },
  { re: /^\s*\.\s*parse\s*::\s*<\s*bool/, groups: ALL },
  { re: /^\s*\.\s*(?:replace|replaceAll|sub|gsub|translate|strip|rstrip|trim|Replace|ReplaceAll)\w*\s*\([^)]*\\[rn]/, groups: ['header', 'log'] },
  { re: /^\s*\.\s*(?:escapeHtml|escapeHTML|sanitize|encode|htmlEscape)\s*\(/, groups: ['html', 'log'] },
  // typed accessors on a request/parameter bag: Symfony ParameterBag (`$request->query->getInt('id')`), Flask/werkzeug
  // (`request.args.get('page', 1, type=int)`)
  { re: /^\s*(?:\.|->)\s*(?:getInt|integer|float)\s*\(/, groups: NUM },
  { re: /^\s*(?:\.|->)\s*(?:getBoolean|boolean|getDigits|getAlpha|getAlnum|getEnum|enum|uuid|ulid)\s*\(/, groups: ALL },
  { re: /^\s*\.\s*(?:get|getlist)\s*\([^()]*\btype\s*=\s*(?:int|float)\b/, groups: NUM },
];

// A cast directly in front of the value: `(int) x`, `(long)x`.
export const SANITIZER_CAST_GROUP = 'num';
export const SANITIZER_CAST = /\(\s*(?:int|long|short|unsigned(?:\s+(?:int|long))?|size_t|ssize_t|double|float|bool|byte|char|Integer|Long|uint\d*|int\d*|u?int(?:8|16|32|64)_t)\s*\)\s*$/;

// Calls that apply a callback to data: `array_map('absint', $ids)`, Python `map(int, xs)`, WordPress `map_deep($v, 'sanitize_text_field')`.
// When the callback is a sanitizer, the data that passes through is sanitised. `cb` = callback argument;
// `data` = the one data argument (default: every argument after the callback).
export const CALLBACK_WRAPPERS = [
  { re: /^array_map$/, cb: 0 },
  { re: /^map$/, cb: 0 },
  { re: /^map_deep$/, cb: 1, data: 0 },
];

// Typed request accessors that return a clean value by themselves (the call, not what follows it):
// Laravel `$request->integer('id')`, PHP `filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT)`.
// `origin` is the matched source text with whitespace removed, `tail` the code view right after it.
const SOURCE_TYPED = [
  { re: /^(?:\$request|request\(\))->(?:integer|float)$/, groups: NUM },
  { re: /^(?:\$request|request\(\))->(?:boolean|date|enum|uuid|ulid)$/, groups: ALL },
  { re: /^filter_input(?:_array)?\($/, tail: /^[^)]*\bFILTER_VALIDATE_(?:INT|FLOAT)\b/, groups: NUM },
  { re: /^filter_input(?:_array)?\($/, tail: /^[^)]*\bFILTER_SANITIZE_NUMBER_(?:INT|FLOAT)\b/, groups: NUM },
  { re: /^filter_input(?:_array)?\($/, tail: /^[^)]*\bFILTER_VALIDATE_(?:BOOL(?:EAN)?|IP)\b/, groups: ALL },
  { re: /^filter_input(?:_array)?\($/, tail: /^[^)]*\bFILTER_SANITIZE_(?:SPECIAL_CHARS|FULL_SPECIAL_CHARS|STRING|ENCODED)\b/, groups: ['html', 'log'] },
];
export function sourceClears(origin, tail = '') {
  const out = new Set();
  for (const r of SOURCE_TYPED) if (r.re.test(origin) && (!r.tail || r.tail.test(tail))) r.groups.forEach(g => out.add(g));
  return out;
}

// ── Parameters the framework fills from the request ───────────────────────────
const JAVA_FRAMEWORK_TYPES = /\b(?:HttpServletRequest|HttpServletResponse|ServletRequest|ServletResponse|Model|ModelMap|Principal|Authentication|BindingResult|Errors|Locale|HttpSession|RedirectAttributes|SessionStatus|WebRequest|NativeWebRequest|UriComponentsBuilder|Pageable|Sort|SecurityContext|UriInfo|HttpHeaders|Request|Response|Context|Logger|CancellationToken|ILogger|IConfiguration|ISession|IMapper|ClaimsPrincipal|HttpContext|Session|Cookie|ActionContext|ModelStateDictionary)\b/;
const ROUTE_ANNOTATION_JAVA = /@(?:(?:Get|Post|Put|Delete|Patch|Request)Mapping|GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Path|MessageMapping|RabbitListener|KafkaListener|JmsListener|SqsListener)\b/;
const PARAM_ANNOTATION_JAVA = /@(?:RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|RequestPart|ModelAttribute|MatrixVariable|QueryParam|PathParam|FormParam|HeaderParam|CookieParam|MatrixParam|BeanParam|FormDataParam|Query|Body|Param|Header|Payload|DefaultValue|RequestAttribute)\b/;
const ROUTE_ATTR_CS = /\[\s*(?:Http(?:Get|Post|Put|Delete|Patch|Head|Options)|Route|ApiController|AcceptVerbs|HttpMethod)\b/;
const PARAM_ATTR_CS = /\[\s*From(?:Query|Body|Route|Form|Header|Services)\b/;
const ROUTE_DECORATOR_PY = /^\s*@\s*[\w.]+\s*\.\s*(?:route|get|post|put|delete|patch|head|options|websocket|api_route|list_route|detail_route|action|on_event|task|consumer|subscribe)\s*\(/m;

// Parameter names that carry a framework object, never the raw value.
const FRAMEWORK_PARAM_NAMES = new Set([
  'self', 'this', 'cls', 'klass', 'req', 'res', 'resp', 'response', 'request', 'ctx', 'context', 'next', 'done',
  'cb', 'callback', 'err', 'error', 'e', 'w', 'r', 'db', 'conn', 'connection', 'session', 'logger', 'log',
  'cursor', 'client', 'app', 'config', 'cfg', 'settings', 'env', 'user', 'current_user', 'principal',
  'db_session', 'session_factory', 'tx', 'trx', 'transaction', 'em', 'entityManager', 'dispatch', 'state',
  'store', 'props', 'children', 'ref', 'signal', 'token', 'cancellationToken', 'ct', 'stoppingToken',
]);

function splitTop(text, sep = ',') {
  const out = []; let depth = 0, cur = '';
  for (const ch of text) {
    if ('([{<'.includes(ch)) depth++;
    else if (')]}>'.includes(ch)) depth = Math.max(0, depth - 1);
    if (ch === sep && depth === 0) { out.push(cur); cur = ''; continue; }
    cur += ch;
  }
  if (cur.trim() !== '' || out.length) out.push(cur);
  return out;
}
export { splitTop };

// Finds the text between the parentheses of the function this chunk holds.
function signatureText(chunkName, code, family) {
  const name = chunkName ? chunkName.replace(/^.*[.:#]/, '') : null;
  const esc = name ? name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') : null;
  let from = -1;
  const tryRe = (re) => { const m = re.exec(code); if (m) { from = m.index + m[0].length - 1; return true; } return false; };

  if (esc) {
    if (family === 'ruby' && tryRe(new RegExp(String.raw`\bdef\s+(?:self\.)?${esc}\b[ \t]*\(`))) {/* parens */}
    else if (family === 'ruby') {
      const m = new RegExp(String.raw`\bdef\s+(?:self\.)?${esc}\b[ \t]+([^\n(]+)`).exec(code);
      if (m) return m[1];
    }
    if (from < 0) {
      tryRe(new RegExp(String.raw`(?:\bdef|\bfunction|\bfun|\bfn|\bfunc)\s*\*?\s*(?:\([^)]*\)\s*)?${esc}\b\s*(?:<[^>(]*>)?\s*\(`)) ||
      tryRe(new RegExp(String.raw`\b${esc}\s*[:=]\s*(?:async\s+)?(?:function\s*\*?\s*\w*\s*)?(?:<[^>(]*>\s*)?\(`)) ||
      tryRe(new RegExp(String.raw`(?:^|[\s.;>])${esc}\s*(?:<[^>(]*>)?\s*\(`, 'm'));
    }
  }
  if (from < 0) {
    const m = /\(/.exec(code); if (!m) return '';
    from = m.index;
  }
  let depth = 0, k = from;
  for (; k < code.length; k++) {
    if (code[k] === '(') depth++;
    else if (code[k] === ')') { depth--; if (depth === 0) break; }
  }
  return code.slice(from + 1, k);
}

const IDENT = /[A-Za-z_$][\w$]*/;

function paramNamesOf(raw, family) {
  const text = raw.trim();
  if (!text) return [];
  // strip default values and decorators/annotations
  let t = text.replace(/\s*=\s*[\s\S]*$/, '');
  switch (family) {
    case 'python': {
      t = t.replace(/^\s*[*]{1,2}/, '').replace(/:[\s\S]*$/, '').trim();
      return IDENT.test(t) ? [IDENT.exec(t)[0]] : [];
    }
    case 'js': {
      t = t.replace(/^\s*(?:public|private|protected|readonly)\s+/g, '').replace(/^\s*\.\.\./, '');
      t = t.replace(/@\w+\s*\([^)]*\)\s*/g, '');
      if (/^[{[]/.test(t.trim())) return (t.match(/[A-Za-z_$][\w$]*/g) || []).filter(x => !/^(?:string|number|boolean|any|void)$/.test(x));
      t = t.replace(/\??\s*:[\s\S]*$/, '').trim();
      return IDENT.test(t) ? [IDENT.exec(t)[0]] : [];
    }
    case 'php': {
      const m = /\$([A-Za-z_]\w*)/.exec(t); return m ? [m[1]] : [];
    }
    case 'ruby': {
      t = t.replace(/^[*&]{1,2}/, '').replace(/:\s*[\s\S]*$/, '').trim();
      return IDENT.test(t) ? [IDENT.exec(t)[0]] : [];
    }
    case 'go': {
      const parts = t.trim().split(/\s+/);
      if (parts.length >= 2) return [parts[0].replace(/^\.\.\./, '')];
      // `a, b string` — a bare name shares the type of the parameter after it
      return /^[A-Za-z_]\w*$/.test(parts[0]) ? [parts[0]] : [];
    }
    case 'rust': {
      const pm = /\(\s*(?:mut\s+)?([A-Za-z_]\w*)\s*\)\s*:/.exec(t);   // Query(params): Query<T>
      if (pm) return [pm[1]];
      t = t.replace(/^\s*(?:mut\s+)/, '');
      const m = /^([A-Za-z_]\w*)\s*:/.exec(t.trim());
      return m && m[1] !== 'self' ? [m[1]] : [];
    }
    case 'kotlin': {
      t = t.replace(/@\w+(?:\s*\([^)]*\))?\s*/g, '').replace(/^\s*(?:vararg|val|var|noinline|crossinline)\s+/g, '');
      const m = /^([A-Za-z_]\w*)\s*:/.exec(t.trim()); return m ? [m[1]] : [];
    }
    case 'swift': {
      const m = /^\s*(?:[A-Za-z_]\w*\s+)?([A-Za-z_]\w*)\s*:/.exec(t.replace(/@\w+\s*/g, '')); return m ? [m[1]] : [];
    }
    default: {   // java, csharp, dart, c
      t = t.replace(/@\w+(?:\s*\([^)]*\))?\s*/g, '').replace(/\[\s*\w+(?:\s*\([^)]*\))?\s*\]\s*/g, '');
      t = t.replace(/\[\s*\]\s*$/g, '').replace(/\[[^\]]*\]\s*$/, '').replace(/\s*:[\s\S]*$/, '');
      const ids = t.match(/[A-Za-z_$][\w$]*/g);
      if (!ids || ids.length < 2) return family === 'c' && ids && ids.length === 1 && ids[0] !== 'void' ? [] : [];
      return [ids[ids.length - 1]];
    }
  }
}

/**
 * @returns { params: [{ name, index, source: boolean, cleared: string[] }], routeHandler: boolean }
 *   source — the framework fills it from request data, so it is attacker input;
 *   cleared — groups the declared type already neutralises (`id: int`, `<int:id>`).
 */
export function parseParams(chunk, family) {
  const sig = signatureText(chunk.name, chunk.code, family);
  const head = chunk.code.slice(0, Math.max(0, chunk.code.indexOf(sig)) + sig.length + 200);
  const rawParams = splitTop(sig);
  const out = [];
  let routeHandler = false;

  const javaRoute = (family === 'java' || family === 'kotlin') && ROUTE_ANNOTATION_JAVA.test(head);
  const csRoute   = family === 'csharp' && ROUTE_ATTR_CS.test(chunk.code.slice(0, 600));
  const pyRoute   = family === 'python' && ROUTE_DECORATOR_PY.test(chunk.code.slice(0, 800));
  const lambdaFn  = /(?:^|[_.])(?:handler|lambda_handler)$/i.test(chunk.name || '');
  const firstIsRequest = family === 'python' && /^\s*(?:self\s*,\s*)?request\b/.test(sig);
  if (javaRoute || csRoute || pyRoute) routeHandler = true;

  // Flask-style converters in the route: <int:id> <uuid:x> <float:y> are not injectable strings
  const intNames = new Set();
  if (pyRoute) for (const m of chunk.code.slice(0, 800).matchAll(/<\s*(?:int|float|uuid|number)\s*:\s*(\w+)\s*>/g)) intNames.add(m[1]);

  rawParams.forEach((raw, index) => {
    const names = paramNamesOf(raw, family);
    for (const name of names) {
      let source = false; const cleared = [];
      const annotated =
        ((family === 'java' || family === 'kotlin') && PARAM_ANNOTATION_JAVA.test(raw)) ||
        (family === 'csharp' && PARAM_ATTR_CS.test(raw)) ||
        (family === 'js' && /@(?:Body|Query|Param|Headers|Req|UploadedFiles?|Ip|Cookies|Session)\s*\(/.test(raw)) ||
        (family === 'rust' && /\b(?:web\s*::\s*)?(?:Query|Json|Path|Form|Multipart|Payload|Bytes)\b/.test(raw)) ||
        (family === 'python' && /=\s*(?:Query|Body|Form|Path|Header|Cookie|File|Depends\(\s*get_current)\b|=\s*(?:Query|Body|Form|Path|Header|Cookie|File)\s*\(/.test(raw));
      if (annotated) source = true;
      else if (javaRoute && !JAVA_FRAMEWORK_TYPES.test(raw)) source = true;
      else if (csRoute && !JAVA_FRAMEWORK_TYPES.test(raw)) source = true;
      else if (pyRoute && !FRAMEWORK_PARAM_NAMES.has(name)) source = true;
      else if (firstIsRequest && index > 0 && !FRAMEWORK_PARAM_NAMES.has(name)) source = true;
      else if (lambdaFn && /^(?:event|payload|body|message|record)$/.test(name)) source = true;

      // declared numeric-ish types neutralise injection
      if (/:\s*(?:bool|UUID|datetime|date|Bool|boolean)\b/.test(raw) ||
          /\b(?:boolean|bool|Boolean|Guid|DateTime|UUID)\s+\w+\s*$/.test(raw.replace(/=[\s\S]*$/, '').trim())) {
        cleared.push('all');
      } else if (/:\s*(?:int|float|Decimal|PositiveInt|conint|number|Int|Double|UInt|i\d+|u\d+|f\d+|usize)\b/.test(raw) ||
          (family !== 'c' && /\b(?:int|long|short|double|float|Integer|Long|Double|BigDecimal|byte|decimal|int\d+|uint\d+|uint|size_t)\s+\w+\s*$/.test(raw.replace(/=[\s\S]*$/, '').trim()))) {
        cleared.push('num');
      }
      if (family === 'js') {          // NestJS: @Param('id', ParseIntPipe) id
        if (/\bParse(?:Int|Float)Pipe\b/.test(raw)) cleared.push('num');
        else if (/\bParse(?:Bool|UUID|Enum|Date)Pipe\b/.test(raw)) cleared.push('all');
      }
      if (intNames.has(name)) cleared.push('num');
      out.push({ name, index, source, cleared, raw: raw.trim() });
    }
  });
  return { params: out, routeHandler };
}

/** Python/JS/… parameter-name based framework sources that need the chunk's name (see parseParams). */
export function isFrameworkParamName(name) { return FRAMEWORK_PARAM_NAMES.has(name); }

// Go: names that hold a request/context object, derived from parameter types.
export function goRequestNames(sig) {
  const names = new Set(['r', 'req', 'request']);
  const m = [...sig.matchAll(/([A-Za-z_]\w*)\s+\*?\s*(?:http\s*\.\s*Request|gin\s*\.\s*Context|echo\s*\.\s*Context|fiber\s*\.\s*Ctx|fasthttp\s*\.\s*RequestCtx|chi\s*\.\s*Context|iris\s*\.\s*Context|buffalo\s*\.\s*Context|\w+\s*\.\s*Context)/g)];
  for (const x of m) names.add(x[1]);
  return names;
}


// ── Locality: who controls the value? ────────────────────────────────────────
// Command-line arguments, stdin and the environment belong to whoever runs the program. They are
// attacker input for classes where running attacker-chosen code/queries/memory operations is the harm
// (shell, code, SQL, deserialization, memory safety), but NOT for "the user passed a file path to their
// own CLI" (path traversal, SSRF, log injection, …). A contributor whose origin matches this is `local`.
export const LOCAL_ORIGIN = /^(?:process\.argv|process\.stdin|process\.env|sys\.argv|sys\.stdin|os\.environ|os\.getenv|input\(|os\.Args|bufio\.New(?:Reader|Scanner)\(os\.Stdin|argv|std::cin|cin>>|env::args|io::stdin|stdin\(\)|read_line|Console\.|Environment\.|args\[|System\.in|readLine|CommandLine\.arguments|stdin\.|STDIN|ARGV|ARGF|gets\b|\$argv|\$argc|\$_ENV|getenv\(|ENV\[|fgets\(|scanf|sscanf|fscanf|getline|getdelim|getchar|fgetc|getc\(|readline|System\.getenv|System\.getProperty|\bgets\()/;
// Sink groups for which a local source still matters.
export const LOCAL_OK_GROUPS = new Set(['shell', 'code', 'sql', 'deser', 'mem', 'int', 'fmt', 'proto']);

// Request-object sources (`req.query`, `request.args`, `params`, `Request.Query`) only mean something in a web
// context. A function elsewhere that happens to have a parameter called `req` is not an HTTP handler.
export const WEB_CONTEXT = {
  js: /\b(?:express|fastify|koa|restify|@hapi\/|@nestjs\/|next\/(?:server|router|navigation|headers)|createServer|\.listen\s*\(|[Rr]outer\s*\(|\brouter\.|app\.(?:get|post|put|delete|patch|use|all|route)\s*\(|exports\.handler|aws-lambda|serverless|polka|sails|loopback|feathers|\bhttp2?\b|\bres\.(?:send|json|render|redirect|status|end|write)\b|\bresponse\.(?:send|json|status|end)\b|getServerSideProps|NextApiRequest)/,
  python: /\b(?:flask|django|fastapi|starlette|bottle|tornado|aiohttp|falcon|pyramid|sanic|quart|cherrypy|werkzeug|webapp2|web\.py|HttpRequest|wsgi|asgi|BaseHTTPRequestHandler|http\.server|@app\.route|@router\.|@bp\.|@blueprint\.)\b|@\w+\.(?:route|get|post|put|delete|patch)\(/i,
  ruby: /\b(?:Rails|ActionController|Sinatra|Rack|Grape|Hanami|Roda|Cuba|Padrino)\b|<\s*ApplicationController|controllers\//,
  go: /net\/http|gin-gonic|labstack\/echo|gofiber|go-chi|gorilla\/mux|valyala\/fasthttp|julienschmidt|gobuffalo|kataras\/iris|beego|http\.Handle|http\.ResponseWriter/,
  csharp: /Microsoft\.AspNetCore|System\.Web|\bHttpContext\b|\bController(?:Base)?\b|\bIActionResult\b|\bIHttpContextAccessor\b|\[ApiController\]|Nancy|ServiceStack/,
};
// What still counts as a source in a non-web file.
export const NON_WEB_SOURCES = {
  js: src(String.raw`\bprocess\s*\.\s*(?:argv|stdin)\b`),
  python: src(String.raw`\binput\s*\(`, String.raw`\bsys\s*\.\s*(?:argv|stdin)\b`),
  ruby: src(String.raw`\bARGV\b|\bSTDIN\b|\bARGF\b|\bgets\b`),
  go: src(String.raw`\bos\s*\.\s*Args\b`, String.raw`\bbufio\s*\.\s*New(?:Reader|Scanner)\s*\(\s*os\s*\.\s*Stdin`),
  csharp: src(String.raw`\bConsole\s*\.\s*(?:ReadLine|Read|In)\b`, String.raw`\bEnvironment\s*\.\s*GetCommandLineArgs\b|\bargs\s*\[`),
};
// postMessage-style sources are only real in files that listen for messages.
export const JS_MESSAGE_SOURCE = /\b(?:e|evt|event|msg|message)\s*\.\s*data\b/;
export const JS_MESSAGE_CONTEXT = /addEventListener\s*\(\s*['"]message['"]|\bonmessage\b|\bpostMessage\b|\bBroadcastChannel\b/;
