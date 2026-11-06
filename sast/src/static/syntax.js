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
    String.raw`\bget_query_var\s*\(|\bget_query_arg\s*\(|\bwp_get_raw_referer\s*\(`,
    String.raw`\$(?:wp|wp_query)\s*->\s*query_vars\b`,
    String.raw`\$request\s*\[`,                       // WP_REST_Request / Laravel Request are ArrayAccess
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
const URLG = ['header', 'log', 'html', 'redirect_param'];   // URL-component encoding
const PHP = ['php'];
const JVMG = ['java', 'kotlin'];
//
// Entry options (all optional):
//   langs    only for these language families (default: every family)
//   argFrom  the call cleans a value only when it sits in argument position >= argFrom
//            ($wpdb->prepare($sql, ...$values): the SQL text in position 0 is NOT cleaned, the bound values are)
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

  // ── WordPress / WooCommerce ───────────────────────────────────────────────────────────────────
  // esc_* neutralise a value for the output context they are named after. sanitize_* are input filters: they
  // remove what they are documented to remove and nothing else. Quotes survive sanitize_text_field /
  // sanitize_email / sanitize_user, so those never clear `sql` (only esc_sql, $wpdb->prepare placeholders and
  // numeric casts do).
  { langs: PHP, re: /^(?:esc_html|esc_attr|esc_textarea|esc_xml|esc_html__|esc_attr__|esc_html_x|esc_attr_x|esc_html_e|esc_attr_e|tag_escape|wp_specialchars|_wp_specialchars|format_to_edit)$/, groups: ['html', 'log'] },
  { langs: PHP, re: /^esc_js$/, groups: ['html', 'log', 'header'] },
  { langs: PHP, re: /^esc_url$/, groups: ['html', 'header', 'log'] },
  { langs: PHP, re: /^(?:esc_url_raw|sanitize_url|wp_sanitize_redirect)$/, groups: ['header', 'log'] },
  // tag / attribute allow-listing and tag stripping: newlines survive
  { langs: PHP, re: /^(?:wp_kses|wp_kses_post|wp_kses_data|wp_kses_one_attr|wp_kses_post_deep|wp_filter_kses|wp_filter_post_kses|wp_filter_nohtml_kses|wp_strip_all_tags|wp_trim_words|wp_html_excerpt|sanitize_textarea_field|wc_sanitize_textarea)$/, groups: ['html'] },
  // single-line text filters: tags and line breaks are removed
  { langs: PHP, re: /^(?:sanitize_text_field|sanitize_user|sanitize_email|wc_clean)$/, groups: ['html', 'log', 'header'] },
  { langs: PHP, re: /^sanitize_mime_type$/, groups: ['html', 'sql', 'shell', 'header', 'log'] },
  // slugs: only [a-z0-9 _-%] survive: no ':' or '/', so the result cannot be a URL either
  { langs: PHP, re: /^(?:sanitize_title|sanitize_title_for_query|sanitize_title_with_dashes|wc_sanitize_taxonomy_name)$/, groups: ['html', 'sql', 'path', 'shell', 'header', 'log', 'nosql', 'ldap', 'xpath', 'ssrf', 'redirect'] },
  // directory separators, quotes and shell metacharacters are removed from file names
  { langs: PHP, re: /^sanitize_file_name$/, groups: ['path', 'html', 'sql', 'shell', 'header', 'log', 'ssrf', 'redirect'] },
  { langs: PHP, re: /^wp_basename$/, groups: ['path'] },
  // identifiers / digests: nothing injectable survives
  { langs: PHP, re: /^(?:sanitize_key|sanitize_html_class|sanitize_hex_color|sanitize_hex_color_no_hash|rest_sanitize_boolean|wp_validate_boolean|wp_generate_uuid4|wp_unique_id|wp_hash|md5|sha1|crc32|hash_hmac|bin2hex|strlen|mb_strlen|count|sizeof|str_word_count)$/, groups: ALL },
  { langs: PHP, re: /^(?:wp_parse_id_list|number_format|floor|ceil|array_sum|wc_stock_amount|wc_format_decimal)$/, groups: NUM },
  // SQL: esc_sql / $wpdb->_real_escape escape string content; prepare() binds every argument AFTER the query text
  { langs: PHP, re: /^esc_sql$|(?:^|[.:])(?:_real_escape|_escape|escape_by_ref)$/, groups: ['sql'] },
  { langs: PHP, re: /(?:^|[.:])prepare$/, groups: ['sql'], argFrom: 1 },
  // redirects / outbound requests
  { langs: PHP, re: /^wp_validate_redirect$/, groups: ['redirect', 'header', 'log'] },
  { langs: PHP, re: /^wp_http_validate_url$/, groups: ['ssrf', 'redirect', 'header', 'log'] },
  // URL builders that put the value after a fixed site host: it can change the path / query, not the host
  { langs: PHP, re: /^(?:admin_url|site_url|home_url|get_home_url|get_site_url|get_admin_url|network_home_url|network_site_url|network_admin_url|content_url|plugins_url|includes_url|rest_url|get_rest_url|get_permalink|get_the_permalink|get_post_permalink|get_page_link|get_edit_post_link|get_term_link|get_author_posts_url|wp_login_url|wp_logout_url|wp_lostpassword_url|wp_registration_url)$/, groups: ['redirect', 'ssrf'] },

  // Lookups and predicates: the request value is only the KEY / operand. What comes back is data fetched by it
  // (a plugin-API record, a post object, a row) or a boolean / integer, never the key echoed back.
  { langs: PHP, re: /^(?:plugins_api|themes_api|get_post|get_posts|get_pages|get_page_by_path|get_page_by_title|get_user_by|get_userdata|get_users|get_term|get_term_by|get_terms|get_comment|get_comments|get_category|get_categories|get_tag|get_taxonomy|get_post_type_object|get_post_status|get_post_type|get_blog_details|get_site|get_sites|get_option|get_site_option|get_transient|get_site_transient|get_post_meta|get_user_meta|get_term_meta|get_comment_meta|wp_cache_get|wp_get_current_user|url_to_postid|attachment_url_to_postid|post_exists|term_exists|username_exists|email_exists|wp_get_attachment_image_src)$/, groups: ALL },
  { langs: PHP, re: /^(?:isset|empty|defined|is_(?!email\b)\w+|in_array|array_key_exists|key_exists|function_exists|class_exists|method_exists|property_exists|file_exists|post_type_exists|taxonomy_exists|current_user_can|user_can|wp_verify_nonce|check_admin_referer|check_ajax_referer|version_compare|hash_equals|password_verify|wp_check_password|preg_match|preg_match_all|strcmp|strcasecmp|strncmp|strncasecmp|substr_count|strpos|stripos|strrpos|mb_strpos)$/, groups: ALL },

  // ── Auto-escaping template renderers ──────────────────────────────────────────────────────────────
  // The CONTEXT arguments (argFrom: 1) are HTML-escaped by the engine; the template itself (argument 0) is not cleaned,
  // so a template-injection sink still sees it. Plain Jinja2 `Template(src).render(...)` is not listed: its autoescape is off by default.
  { langs: ['python'], re: /^(?:render_template|render_template_string|render_to_string|stream_template|stream_template_string|render)$|(?:^|\.)TemplateResponse$/, groups: ['html', 'log'], argFrom: 1 },
  { langs: ['js'], re: /^(?:ejs|pug|jade|nunjucks|swig|dust|hogan|Hogan|eta|Eta|Mustache|mustache|Handlebars|handlebars)\.(?:render|renderString|renderFile)$/, groups: ['html', 'log'], argFrom: 1 },
  { langs: PHP, re: /(?:^|[.:])render$|^(?:view|View[.:]+make|View[.:]+first)$/, groups: ['html', 'log'], argFrom: 1 },

  // ── Other PHP frameworks / CMSs ────────────────────────────────────────────────────────────────
  // Laravel, Symfony / Doctrine, CodeIgniter, Yii, CakePHP, Drupal, Joomla, Magento, Laminas, PrestaShop, Twig
  { langs: PHP, re: /^Str[.:]+slug$/, groups: ALL },
  { langs: PHP, re: /(?:^|[.:])quote$|^(?:pSQL|bqSQL|db_escape_table|db_escape_field)$/, groups: ['sql'] },           // PDO::quote, DBAL Connection::quote, Joomla/Cake $db->quote
  { langs: PHP, re: /^(?:esc|html_escape|form_prep|xss_clean|check_plain|filter_xss|filter_xss_admin|twig_escape_filter)$|(?:^|[.:])(?:xss_clean|sanitizeFor|purify|purifyArray)$/, groups: ['html', 'log'] },
  { langs: PHP, re: /(?:^|[.:])(?:Html[.:]+(?:encode|escape)|Xss[.:]+(?:filter|filterAdmin)|HtmlPurifier[.:]+process|Tools[.:]+(?:safeOutput|htmlentitiesUTF8|purifyHTML))$/, groups: ['html', 'log'] },
  { re: /(?:^|[.:])(?:escapeHtmlAttr|escapeHtmlAttribute|escapeJs|escapeJsQuote|escapeCss|escapeUrl|escapeXssInUrl|escapeQuote)$/, groups: ['html', 'log'] },
  // named-route URL builders: the host comes from the application, the value only fills route parameters
  { langs: PHP, re: /(?:^|[.:])(?:route|to_route|generateUrl|base_url|route_to|url_to)$|(?:router|urlGenerator|generator)\.generate$|(?:^|[.:])Url[.:]+toRoute$/, groups: ['redirect'] },

  // ── Python (Django / Flask / Jinja2 / stdlib) ─────────────────────────────────────────────────
  { langs: ['python'], re: /^escape$|(?:^|[.:])(?:html|cgi|saxutils|markupsafe|jinja2|flask)\.escape$|(?:^|[.:])(?:escapejs|quoteattr)$/, groups: ['html', 'log'] },
  { langs: ['python'], re: /^(?:quote|quote_plus|urlquote|urlquote_plus|iri_to_uri)$/, groups: URLG },
  { langs: ['python'], re: /^(?:reverse|reverse_lazy|url_for)$/, groups: ['redirect'] },
  { langs: ['python'], re: /^shlex\.join$/, groups: ['shell'] },

  // ── Ruby (Rails / Rack / CGI) ─────────────────────────────────────────────────────────────────
  { langs: ['ruby'], re: /(?:^|[.:])(?:quote|quote_string)$/, groups: ['sql'] },
  { langs: ['ruby'], re: /^(?:CGI\.escape(?:URIComponent)?|URI\.encode_www_form(?:_component)?|ERB::Util\.u(?:rl_encode)?|Rack::Utils\.(?:escape|escape_path|build_query|build_nested_query)|Addressable::URI\.encode_component)$/, groups: URLG },
  { langs: ['ruby'], re: /^\w+_path$|(?:^|[.:])polymorphic_path$/, groups: ['redirect'] },     // *_path helpers build same-host paths (not *_url / url_for(string))

  // ── Java / Kotlin (OWASP Encoder, ESAPI, Spring, commons-text, commons-lang) ──────────────────────
  { langs: JVMG, re: /(?:^|[.:])(?:forUri|forUriComponent|forCssString|forCssUrl|forXml|forXmlContent|forXmlAttribute|forXmlComment|forCDATA|forJavaScriptAttribute|forJavaScriptBlock|forJavaScriptSource|forHtmlUnquotedAttribute|javaScriptEscape|escapeEcmaScript|escapeJava|escapeJson|escapeCsv|encodeForJavaScript|encodeForCSS|encodeForURL|encodeForXML|encodeForXMLAttribute|encodeForHTMLAttribute)$/, groups: ['html', 'log'] },
  { langs: JVMG, re: /(?:^|[.:])UriUtils[.:]+encode\w*$/, groups: URLG },
  { langs: JVMG, re: /(?:^|[.:])encodeForSQL$/, groups: ['sql'] },
  { langs: JVMG, re: /(?:^|[.:])encodeForOS$/, groups: ['shell'] },
  { langs: JVMG, re: /(?:^|[.:])encodeFor(?:XPath|DN)$/, groups: ['ldap', 'xpath'] },
  { langs: JVMG, re: /(?:^|[.:])(?:NumberUtils[.:]+(?:toInt|toLong|toDouble|toFloat|toShort|toByte|create\w+)|Ints[.:]+tryParse|Longs[.:]+tryParse|Doubles[.:]+tryParse)$/, groups: NUM },

  // ── C# / Go / JavaScript ──────────────────────────────────────────────────────────────────────
  { langs: ['csharp'], re: /(?:^|[.:])(?:HtmlAttributeEncode|JavaScriptStringEncode|Sanitize)$/, groups: ['html', 'log'] },
  { langs: ['csharp'], re: /(?:^|[.:])UrlPathEncode$/, groups: URLG },
  { langs: ['go'], re: /(?:^|[.:])(?:Sanitize|SanitizeBytes|SanitizeReader)$/, groups: ['html', 'log'] },        // bluemonday policies
  { langs: ['go'], re: /^pq\.Quote(?:Identifier|Literal)$/, groups: ['sql'] },
  { langs: ['go'], re: /^path\.Base$/, groups: ['path'] },
  { langs: ['js'], re: /^(?:_|lodash|validator|he)\.escape$/, groups: ['html', 'log'] },
  { langs: ['js'], re: /^(?:validator\.to(?:Int|Float)|Number\.(?:parseInt|parseFloat))$/, groups: NUM },
  { langs: ['js'], re: /^validator\.to(?:Boolean|Date)$/, groups: ALL },

  // ── identifier quoting / slugs, any language ─────────────────────────────────────────────────
  { re: /(?:^|[.:])(?:quote_name|quote_table_name|quote_column_name|quoteName|quoteValue|quoteColumnName|quoteTableName|quoteSimpleColumnName|quoteSimpleTableName|quote_literal)$/, groups: ['sql'] },
  { re: /(?:^|[.:])(?:slugify|parameterize)$/, groups: ALL },
];

// Method/property applied AFTER a tainted value: `x.to_i`, `x.length`.
export const SANITIZER_SUFFIX = [
  { re: /^\s*\.\s*(?:to_i|to_f|toInt|toLong|toDouble|toIntOrNull)\b/, groups: NUM },
  { re: /^\s*\.\s*(?:to_sym|toBoolean|length|size|count|isEmpty|isBlank|empty\?|nil\?|hashCode|bit_length|isdigit|isnumeric|isalnum|isalpha)\b/, groups: ALL },
  { re: /^\s*\.\s*parse\s*(?:::\s*)?<\s*(?:i|u)\d+|^\s*\.\s*parse\s*::\s*<\s*(?:f32|f64|usize|isize)/, groups: NUM },
  { re: /^\s*\.\s*parse\s*::\s*<\s*bool/, groups: ALL },
  { re: /^\s*\.\s*(?:replace|replaceAll|sub|gsub|translate|strip|rstrip|trim|Replace|ReplaceAll)\w*\s*\([^)]*\\[rn]/, groups: ['header', 'log'] },
  { re: /^\s*\.\s*(?:escapeHtml|escapeHTML|sanitize|encode|htmlEscape)\s*\(/, groups: ['html', 'log'] },
  // Symfony ParameterBag / Joomla Input typed getters:  $request->query->getInt('id')  ->getAlnum('k')  ->getBoolean('f')
  { re: /^\s*(?:->|::)\s*(?:getInt|getUint|getFloat)\b/, groups: NUM },
  { re: /^\s*(?:->|::)\s*(?:getBoolean|getBool|getDigits|getAlpha|getAlnum|getWord|getCmd)\b/, groups: ALL },
];

// A cast directly in front of the value: `(int) x`, `(long)x`.
export const SANITIZER_CAST_GROUP = 'num';
export const SANITIZER_CAST = /\(\s*(?:int|long|short|unsigned(?:\s+(?:int|long))?|size_t|ssize_t|double|float|bool|byte|char|Integer|Long|uint\d*|int\d*|u?int(?:8|16|32|64)_t)\s*\)\s*$/;

/**
 * Groups cleaned by a call to `callee` for a value sitting in argument position `argIndex`.
 * Honours the `langs` and `argFrom` options of SANITIZER_CALLS entries.
 */
export function sanitizerGroups(callee, argIndex = 0, family = null) {
  const out = [];
  for (const s of SANITIZER_CALLS) {
    if (s.langs && !(family && s.langs.includes(family))) continue;
    if (s.argFrom !== undefined && argIndex < s.argFrom) continue;
    if (s.re.test(callee)) out.push(...s.groups);
  }
  return out;
}

// Calls that apply a callback, named by a string literal, to every element of the array they are given:
//   array_map('sanitize_text_field', $_POST['ids'])   map_deep($_POST, 'sanitize_text_field')
// `cb` is the argument position of the callback name.
export const CALLBACK_MAPPERS = [
  { re: /^array_map$/, cb: 0, langs: PHP },
  { re: /^map_deep$/, cb: 1, langs: PHP },
];

// Request accessors whose NAME already converts the value: Laravel  $request->integer('id')  ->boolean('flag')
// The accessor is part of the source match, so it is recognised on the source text itself.
export const TYPED_ACCESSORS = [
  { re: /(?:->|::)\s*(?:integer|float|getInt|getUint|getFloat)$/, groups: NUM, langs: PHP },
  { re: /(?:->|::)\s*(?:boolean|getBool|getBoolean|getDigits|getAlpha|getAlnum|getWord|getCmd)$/, groups: ALL, langs: PHP },
];
export function typedAccessorGroups(origin, family) {
  const out = [];
  for (const t of TYPED_ACCESSORS) if (t.langs.includes(family) && t.re.test(origin)) out.push(...t.groups);
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
  js: /\b(?:express|fastify|koa|restify|@hapi\/|@nestjs\/|next\/(?:server|router|navigation|headers)|createServer|\.listen\s*\(|[Rr]outer\s*\(|\brouter\.|app\.(?:get|post|put|delete|patch|use|all|route)\s*\(|exports\.handler|aws-lambda|serverless|polka|sails|loopback|feathers|\bhttp2?\b|\bres\.(?:send|json|render|redirect|status|end|write)\b|\bresponse\.(?:send|json|status|end)\b|getServerSideProps|NextApiRequest)|<script\b|\bdocument\s*\.\s*(?:getElementById|getElementsBy\w+|querySelector(?:All)?|write(?:ln)?|createElement|body|documentElement|forms|location|cookie|URL|referrer|addEventListener)\b|\bwindow\s*\.\s*(?:location|name|addEventListener|onload|onmessage|open|history)\b|\blocation\s*\.\s*(?:search|hash|href|assign|replace|pathname)\b|\bjQuery\b|\$\s*\(\s*(?:document|window)\b/,
  python: /\b(?:flask|django|fastapi|starlette|bottle|tornado|aiohttp|falcon|pyramid|sanic|quart|cherrypy|werkzeug|webapp2|web\.py|HttpRequest|wsgi|asgi|BaseHTTPRequestHandler|http\.server|@app\.route|@router\.|@bp\.|@blueprint\.)\b|@\w+\.(?:route|get|post|put|delete|patch)\(/i,
  ruby: /\b(?:Rails|ActionController|Sinatra|Rack|Grape|Hanami|Roda|Cuba|Padrino)\b|\brequire\s+['"](?:sinatra|roda|cuba|grape|hanami|padrino|rack)\b|<\s*ApplicationController|controllers\//,
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
