'use strict';
// files.js — what each file of a package IS, from its path and its first bytes (never from the extension alone): text or binary, native
// executable (ELF / Mach-O / PE), WebAssembly, compiled bytecode, nested archive; and who it belongs to (the package's own code, a vendored or
// bundled dependency, tests, documentation). Also the lists of host names that matter in install-time code.

import { sniffFormat } from '../../binary/index.js';
import { isLikelyBinary } from '../../mobile/lib/strings.js';

const u32 = (b, o) => (b.length >= o + 4 ? b.readUInt32BE(o) : -1);

/** @returns {'elf'|'macho'|'pe'|'wasm'|'pyc'|'class'|'zip'|'gzip'|'bzip2'|'xz'|'zstd'|'7z'|'rar'|'tar'|'pdf'|'image'|null} */
export function magicKind(buf) {
  if (!buf || buf.length < 4) return null;
  if (buf[0] === 0xCA && buf[1] === 0xFE && buf[2] === 0xBA && buf[3] === 0xBE) {
    const v = u32(buf, 4);
    if (v >= 45 && v <= 80) return 'class';                                       // 0xCAFEBABE is also the fat Mach-O magic; a Java class has major version 45+ at byte 6
  }
  const native = sniffFormat(buf);
  if (native) return native;
  if (buf[0] === 0 && buf[1] === 0x61 && buf[2] === 0x73 && buf[3] === 0x6D) return 'wasm';
  if (buf[0] === 0x50 && buf[1] === 0x4B && (buf[2] === 3 || buf[2] === 5) && (buf[3] === 4 || buf[3] === 6)) return 'zip';
  if (buf[0] === 0x1F && buf[1] === 0x8B) return 'gzip';
  if (buf[0] === 0x42 && buf[1] === 0x5A && buf[2] === 0x68) return 'bzip2';
  if (buf[0] === 0xFD && buf[1] === 0x37 && buf[2] === 0x7A && buf[3] === 0x58) return 'xz';
  if (buf[0] === 0x28 && buf[1] === 0xB5 && buf[2] === 0x2F && buf[3] === 0xFD) return 'zstd';
  if (buf[0] === 0x37 && buf[1] === 0x7A && buf[2] === 0xBC && buf[3] === 0xAF) return '7z';
  if (buf[0] === 0x52 && buf[1] === 0x61 && buf[2] === 0x72 && buf[3] === 0x21) return 'rar';
  if (buf.length >= 262 && buf.toString('latin1', 257, 262) === 'ustar') return 'tar';
  if (buf[0] === 0x25 && buf[1] === 0x50 && buf[2] === 0x44 && buf[3] === 0x46) return 'pdf';
  if ((buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) || (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) || buf.toString('latin1', 0, 4) === 'GIF8' || (buf.toString('latin1', 0, 4) === 'RIFF' && buf.toString('latin1', 8, 12) === 'WEBP')) return 'image';
  return null;
}
const PYC_MAGIC = b => b.length > 16 && b[2] === 0x0D && b[3] === 0x0A && b[1] >= 0x0A && b[0] >= 0x30;

/** Kind of a file from its path and head bytes; `text` when it should be read as source / config. */
export function classifyHead(path, head) {
  const k = magicKind(head);
  if (k) return k;
  if (/\.pyc$/i.test(path) && PYC_MAGIC(head)) return 'pyc';
  if (isLikelyBinary(head)) return 'binary';
  return 'text';
}

const VENDOR = /(?:^|\/)(?:node_modules|vendor|vendors|third_party|third-party|thirdparty|bower_components|site-packages|extern|external|deps|_vendor|_vendored|vendored|Pods|Carthage|packages\/[^/]+\/node_modules)\//i;
const TESTS = /(?:^|\/)(?:tests?|__tests__|__mocks__|spec|specs|testdata|test_data|fixtures?|e2e|integration|benchmarks?|bench|examples?|samples?|demos?|playground)\//i;
const TEST_FILE = /(?:\.(?:test|spec|bench)\.[cm]?[jt]sx?$|_test\.(?:go|py|rb|rs|dart)$|(?:^|\/)test_[^/]+\.py$|Tests?\.cs$|_spec\.rb$)/i;
const DOCS = /(?:^|\/)(?:docs?|documentation|man|manpages?|\.github|\.vscode|\.idea|changelog|licenses?)\/|(?:^|\/)(?:README|CHANGELOG|CHANGES|HISTORY|LICENSE|LICENCE|NOTICE|AUTHORS|CONTRIBUTING|CODE_OF_CONDUCT|SECURITY)(?:\.[A-Za-z]+)?$|\.(?:md|markdown|rst|adoc|txt|rdoc)$/i;

/** @returns {{role:'vendored'|'test'|'docs'|'code', owner:string|null}} owner = the bundled package or vendor folder the file belongs to */
export function fileRole(path, vendoredPaths = null) {
  if (vendoredPaths) for (const [prefix, owner] of vendoredPaths) if (path.startsWith(prefix)) return { role: 'vendored', owner };
  const nm = [...path.matchAll(/(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\//g)];
  if (nm.length) return { role: 'vendored', owner: nm[nm.length - 1][1] };
  const v = VENDOR.exec(path);
  if (v) return { role: 'vendored', owner: v[0].replace(/^\/|\/$/g, '') };
  if (TESTS.test(path) || TEST_FILE.test(path)) return { role: 'test', owner: null };
  if (DOCS.test(path)) return { role: 'docs', owner: null };
  return { role: 'code', owner: null };
}

// extensions that are expected to hold native code
const NATIVE_EXT = /\.(?:so(?:\.\d+)*|dll|exe|dylib|node|bin|a|lib|o|obj|sys|ocx|pyd|bundle|jnilib|framework|elf|out|run|com|scr|cpl|efi|ko|axf|dbg|debug)$/i;
const SCRIPTY_EXT = /\.(?:txt|md|markdown|rst|json|ya?ml|toml|ini|cfg|conf|js|mjs|cjs|jsx|ts|tsx|css|scss|less|html?|svg|xml|py|pyi|rb|php|pl|sh|bash|lua|go|rs|java|kt|cs|c|h|cpp|hpp|png|jpe?g|gif|ico|bmp|webp|woff2?|ttf|otf|eot|pdf|csv|tsv|map|lock|log|gz|tgz|zip|tar|sig|asc|pem|crt|cer|sample|example|tpl|template|ejs|hbs|vue|svelte|snap|d\.ts)$/i;

/** True when a native executable has a name that says it is something else. */
export function isDisguised(path, kind) {
  if (!['elf', 'macho', 'pe'].includes(kind)) return false;
  const base = path.split('/').pop();
  if (NATIVE_EXT.test(base)) return false;
  if (!/\.[A-Za-z0-9]{1,8}$/.test(base)) return false;                                // no extension: normal for an executable
  return SCRIPTY_EXT.test(base);
}

const SENSITIVE = [
  [/(?:^|\/)\.env(?:\.(?!example$|sample$|template$|dist$|defaults?$)[\w.-]+)?$/i, 'environment file (usually holds secrets)'],
  [/(?:^|\/)(?:id_rsa|id_dsa|id_ecdsa|id_ed25519)(?:\.pem)?$/, 'SSH private key file name'],
  [/(?:^|\/)(?:\.ssh|\.aws|\.azure|\.kube|\.gnupg|\.docker)\//, 'credential directory'],
  [/(?:^|\/)\.(?:netrc|pypirc|git-credentials|htpasswd|pgpass|my\.cnf|s3cfg|boto|dockercfg)$/, 'credential file'],
  [/(?:^|\/)(?:credentials|secrets?|service[-_]?account)(?:[-_.][\w.-]+)?\.(?:json|ya?ml|toml|ini|xml|txt)$/i, 'credentials / secrets file'],
  [/\.(?:p12|pfx|jks|keystore|ppk|kdbx|key)$/i, 'key store / private key file'],
  [/(?:^|\/)\.git\//, 'git metadata (history, remotes and possibly credentials)'],
  [/(?:^|\/)(?:terraform\.tfstate(?:\.backup)?|\.terraform\/)/, 'terraform state'],
  [/(?:^|\/)(?:wp-config\.php|config\/secrets\.yml|appsettings\.(?:Production|Development)\.json|local\.settings\.json)$/i, 'application configuration with secrets'],
];
/** @returns {string|null} why the file name suggests a secret; `.pem` / `.key` text files are checked by content by the caller */
export function sensitiveName(path) {
  for (const [re, why] of SENSITIVE) if (re.test(path)) return why;
  return null;
}

const TOOL_CONFIG = /(?:^|\/)(?:\.npmrc|\.yarnrc(?:\.yml)?|\.pnpmrc|bunfig\.toml|pip\.conf|pip\.ini|\.pypirc|NuGet\.[Cc]onfig|nuget\.config|\.cargo\/config(?:\.toml)?|\.bundle\/config|\.gemrc|Directory\.Build\.(?:props|targets|rsp)|global\.json|\.mvn\/[\w.-]+|settings\.xml|\.config\/dotnet-tools\.json)$/;
export const isToolConfig = path => TOOL_CONFIG.test(path);

const LOCKFILE = /(?:^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|yarn\.lock|pnpm-lock\.yaml|bun\.lockb?|Cargo\.lock|composer\.lock|Gemfile\.lock|poetry\.lock|Pipfile\.lock|pdm\.lock|uv\.lock|go\.sum|packages\.lock\.json|pubspec\.lock)$/;
export const isLockfile = path => LOCKFILE.test(path);

// files whose URLs are metadata, not behaviour (homepage / repository / license links): they are not searched for remote hosts
const HOST_SKIP = /(?:^|\/)(?:package\.json|composer\.json|pubspec\.yaml|Cargo\.toml|pyproject\.toml|setup\.cfg|PKG-INFO|METADATA|[^/]+\.nuspec|[^/]+\.gemspec|go\.mod|go\.sum|WHEEL|RECORD|top_level\.txt|entry_points\.txt|SOURCES\.txt|requires\.txt|\.npmignore|\.gitignore|\.editorconfig|tsconfig[^/]*\.json|\.eslintrc[^/]*|\.prettierrc[^/]*|\.babelrc[^/]*)$|\.(?:map|d\.ts|lock|md|markdown|rst|txt|adoc|svg|html?|css|scss|less|snap|pem|crt|cer|csv|tsv)$/i;
export const hostSearchable = path => !HOST_SKIP.test(path) && !isLockfile(path);

// ── remote hosts that deserve a flag ──────────────────────────────────────────────────────────────────────────────────────────────
const FLAGS = [
  ['paste_site', /(?:^|\.)(?:pastebin\.com|paste\.ee|hastebin\.com|ghostbin\.\w+|dpaste\.\w+|rentry\.co|controlc\.com|privatebin\.\w+|ix\.io|termbin\.com|0x0\.st|transfer\.sh|file\.io|anonfiles\.\w+|temp\.sh|catbox\.moe|gofile\.io|bashupload\.com|pastes\.io|justpaste\.it|paste\.rs|cl1p\.net)$/i],
  ['callback_service', /(?:^|\.)(?:webhook\.site|requestbin\.\w+|pipedream\.net|interact\.sh|oast\.\w+|oastify\.com|burpcollaborator\.net|canarytokens\.com|dnslog\.\w+|ceye\.io|beeceptor\.com|requestcatcher\.com|hookbin\.com|mockbin\.\w+|postb\.in|eo[a-z0-9]+\.m\.pipedream\.net)$/i],
  ['tunnel', /(?:^|\.)(?:ngrok(?:-free)?\.(?:io|app|dev)|ngrok\.com|trycloudflare\.com|serveo\.net|localhost\.run|loca\.lt|lhr\.life|tunnelmole\.net|telebit\.\w+|portmap\.io|pagekite\.me|playit\.gg|bore\.pub|ssh\.cloud\.google\.com)$/i],
  ['chat_webhook', /(?:^|\.)(?:discord(?:app)?\.com|hooks\.slack\.com|api\.telegram\.org|api\.pushover\.net|ntfy\.sh|hooks\.zapier\.com|outlook\.office\.com|webhook\.office\.com)$/i],
  ['dynamic_dns', /(?:^|\.)(?:duckdns\.org|no-ip\.\w+|ddns\.net|hopto\.org|zapto\.org|sytes\.net|myftp\.\w+|servehttp\.com|dyndns\.\w+|freedns\.afraid\.org|changeip\.com|ddnsking\.com|serveblog\.net|redirectme\.net)$/i],
  ['url_shortener', /(?:^|\.)(?:bit\.ly|tinyurl\.com|t\.co|goo\.gl|is\.gd|cutt\.ly|rb\.gy|shorturl\.at|tiny\.cc|ow\.ly|buff\.ly|t\.ly|v\.gd|s\.id)$/i],
  ['raw_code_host', /(?:^|\.)(?:raw\.githubusercontent\.com|gist\.githubusercontent\.com|gitlab\.com\/[^/]+\/[^/]+\/-\/raw|bitbucket\.org\/[^/]+\/[^/]+\/raw|cdn\.discordapp\.com|media\.discordapp\.net|objects\.githubusercontent\.com)$/i],
];
/** Flags of one host name (see FLAGS) — a host is flagged by what it IS, not by where it is seen. */
export function hostFlags(host, type) {
  const out = [];
  for (const [flag, re] of FLAGS) if (re.test(host)) out.push(flag);
  return out;
}
export const EXFIL_FLAGS = new Set(['paste_site', 'callback_service', 'tunnel', 'chat_webhook', 'dynamic_dns']);
