'use strict';
// sourcebehavior.js — what a package's SOURCE FILES can do, in JavaScript / TypeScript, Python, Ruby, Rust, Go, C#, PowerShell, PHP, Dart and
// shell / build files (Makefile, CMake, Gradle, podspec, batch). Pattern based, line by line: no parser, nothing is run.
//
// Two outputs per file:
//   behaviors  an inventory (what the code refers to: process execution, network, file access, dynamic code, credentials, persistence …) filed
//              under the same categories as `ubel-binary`'s Behavior tab. It is a capability list, not a list of findings.
//   risks      patterns that are rarely innocent in a dependency: encoded payloads fed to eval / exec, reverse shells, miners, reading credential
//              stores or dumping the whole environment, persistence, "download and run", TLS verification switched off, destructive commands.
//              Each carries a confidence; the caller turns them into findings and raises the severity when the file runs at install time.
//
// A pattern match shows the code REFERS to something, not that the line is reachable or that it runs with attacker data. Minified, packed and
// encrypted code is only partly visible, and the report says so.

import { analyzeCommand } from './installscripts.js';

export const LANGS = {
  js: /\.(?:[cm]?[jt]sx?|vue|svelte)$/i, py: /\.(?:py|pyw|pth|pyi)$/i, rb: /(?:\.(?:rb|rake|gemspec|podspec)$|(?:^|\/)(?:Rakefile|Gemfile|Podfile|Fastfile|Vagrantfile)$)/i,
  rs: /\.rs$/i, go: /\.go$/i, cs: /\.(?:cs|csx|vb|fs)$/i, ps: /\.(?:ps1|psm1|psd1)$/i, php: /\.(?:php[0-9]?|phtml|inc)$/i, dart: /\.dart$/i,
  sh: /(?:\.(?:sh|bash|zsh|ksh|bat|cmd|mk|cmake|gradle|kts|command)$|(?:^|\/)(?:Makefile|makefile|GNUmakefile|CMakeLists\.txt|Dockerfile|configure|install|postinstall|preinstall)$)/i,
  msbuild: /\.(?:targets|props|csproj|vbproj|fsproj|vcxproj|nuspec|proj)$/i,
};
const SHEBANG = [[/^#!.*\b(?:node|nodejs|deno|bun|tsx|ts-node)\b/, 'js'], [/^#!.*\bpython[0-9.]*\b/, 'py'], [/^#!.*\bruby\b/, 'rb'], [/^#!.*\b(?:ba|z|da|k)?sh\b/, 'sh'], [/^#!.*\bpwsh\b|^#!.*\bpowershell\b/, 'ps'], [/^#!.*\bphp\b/, 'php']];

/** Language of a file from its path (and first line for extension-less scripts); null for text this scanner has no rules for. */
export function detectLang(path, head = '') {
  for (const [lang, re] of Object.entries(LANGS)) if (re.test(path)) return lang;
  if (!/\.[A-Za-z0-9]{1,6}$/.test(path) || /\/(?:bin|scripts?)\/[^./]+$/.test(path)) for (const [re, lang] of SHEBANG) if (re.test(head)) return lang;
  return null;
}

const CRED_FILE = /(?:\.ssh[\\/]|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.aws[\\/](?:credentials|config)|\.npmrc\b|\.pypirc\b|\.netrc\b|\.git-credentials\b|\.docker[\\/]config\.json|\.kube[\\/]config|\.config[\\/]gcloud|\.azure[\\/]|Login Data\b|Web Data\b|Local State\b|[\\/]Cookies\b|Chrome[\\/]User Data|Mozilla[\\/]Firefox[\\/]Profiles|\blogins\.json\b|\bkey[34]\.db\b|\bwallet\.dat\b|\.bitcoin\b|\.ethereum\b|\bExodus\b|\bMetaMask\b|\bElectrum\b|\.solana\b|\.gnupg\b|\.gem[\\/]credentials|\.cargo[\\/]credentials|\.composer[\\/]auth\.json|\.config[\\/]gh[\\/]hosts\.yml|\.vault-token|\.terraform\.d[\\/]credentials|login\.keychain|Library[\\/]Keychains|\/etc\/(?:shadow|sudoers)|\.bash_history|\.zsh_history|discord[\\/]Local Storage|\bleveldb\b|\bcredentials\.json\b|\bsecrets\.(?:json|ya?ml)\b)/i;
const SECRET_NAME = /\b[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH(?:ORIZATION)?)[A-Z0-9_]*\b/;
const MINER = /stratum\+(?:tcp|ssl)|\b(?:xmrig|coinhive|cryptonight|cryptoloot|minexmr|nanopool|supportxmr|moneroocean|nicehash|randomx|coin-?imp|webminer)\b|--donate-level/i;
const REVSHELL = /\/dev\/tcp\/|\bnc(?:at)?\s+(?:-[a-z]*e\b|[^\n]*\s-e\s+\/bin\/(?:ba)?sh)|\bbash\s+-i\s*>&|\bsh\s+-i\s*<&|\bsocat\s+[^\n]*exec:|\bmkfifo\s+[^\n]*\bnc\b|\b0<&\d+|\bpty\.spawn\(\s*['"]\/bin\/(?:ba)?sh|python[0-9.]*\s+-c\s+['"]import\s+socket|new\s+ActiveXObject\(\s*['"]WScript\.Shell/i;
const PERSIST = /\bcrontab\b|\/etc\/cron|\bsystemctl\s+(?:--user\s+)?(?:enable|daemon-reload)|\/etc\/systemd\/|\.config\/systemd|\blaunchctl\b|\bLaunchAgents\b|\bLaunchDaemons\b|\bschtasks\b|CurrentVersion[\\/]+Run|\bStartup[\\/]|[\\/]\.(?:bashrc|bash_profile|zshrc|profile|zprofile)\b|\/etc\/(?:profile|rc\.local)|\bauthorized_keys\b|\.git[\\/]hooks[\\/]|\bnew-scheduledtask\b|\bRegisterTaskDefinition\b|\bupdate-rc\.d\b|\bsitecustomize\b|\busercustomize\b/i;
const DESTRUCT = /\brm\s+(?:-[a-z]*[rf][a-z]*\s+)+(?:--no-preserve-root\s+)?(?:\/|~|\$HOME|\$\{HOME\}|\*)(?:["'\s]|$)|\bdd\s+[^\n]*\bof=\/dev\/|\bmkfs\b|\bshred\s+-[a-z]*[uz]|\bwipefs\b|\bformat\s+[a-z]:|:\(\)\s*\{\s*:\|:&\s*\};:/i;
const INSECURE_TLS = /rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['"]?\s*[\]=:,]\s*['"]?0|strictSSL\s*:\s*false|\bverify\s*=\s*False\b|\bssl\._create_unverified_context|\bCERT_NONE\b|\bcheck_hostname\s*=\s*False|InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFY(?:PEER|HOST)['"]?\s*,\s*(?:false|0)|\bVERIFY_NONE\b|\bverify_mode\s*=\s*OpenSSL::SSL::VERIFY_NONE|danger_accept_invalid_(?:certs|hostnames)\(\s*true|ServerCertificateValidationCallback\s*[+]?=\s*[^;]*(?:true|delegate)|\bServerCertificateCustomValidationCallback\b[^;\n]*(?:true|DangerousAcceptAnyServerCertificateValidator)|badCertificateCallback\s*[:=]\s*\([^)]*\)\s*(?:=>|\{\s*return)\s*true|--no-check-certificate|\bcurl\s+[^\n]*\s(?:-k|--insecure)\b|\bstrict-ssl\s*=\s*false|\bGIT_SSL_NO_VERIFY\b|http\.sslVerify\s*false|PYTHONHTTPSVERIFY['"]?\s*[\]=:,]\s*['"]?0|-SkipCertificateCheck/i;

// ── behavior tables: [category, label, regex, {needs?: flag}] ───────────────────────────────────────────────────────────────────
const Q = '[\'"`]';
const imp = names => `(?:require\\(\\s*|from\\s*|import\\(\\s*|import\\s+)${Q}(?:node:)?(?:${names})${Q}`;
const JS = [
  ['process', 'child_process', new RegExp(imp('child_process'))],
  ['process', 'child_process exec / spawn', /\bchild_process\.\w+\s*\(|\b(?:execSync|spawnSync|execFileSync|execFile|exec|spawn|fork)\s*\(/, { needs: 'child_process' }],
  ['process', 'Deno / Bun process API', /\b(?:Deno\.(?:run|Command)|Bun\.(?:spawn|spawnSync))\b|\bBun\.\$`/],
  ['network', 'http / https / http2', new RegExp(`${imp('https?2?')}|\\b(?:https?|http2)\\.(?:request|get|createServer)\\(`)],
  ['network', 'net / tls / dgram / dns', new RegExp(imp('net|tls|dgram|dns(?:\\/promises)?'))],
  ['network', 'fetch / XMLHttpRequest / WebSocket', /\bfetch\(\s*[A-Za-z_$'"`]|\bnew\s+XMLHttpRequest\b|\bnew\s+WebSocket(?:Server)?\(|\bnavigator\.sendBeacon\(/],
  ['network', 'HTTP / socket client library', new RegExp(imp('axios|got|node-fetch|undici|superagent|request|needle|ky|cross-fetch|isomorphic-fetch|ws|socket\\.io-client|node-ipc|ssh2|ssh2-sftp-client|basic-ftp|nodemailer|follow-redirects|bent|phin|tcp-port-used'))],
  ['file_io', 'fs', new RegExp(`${imp('fs(?:\\/promises)?|graceful-fs|fs-extra')}|\\bfs\\.(?:readFile|writeFile|appendFile|unlink|rm|rmdir|mkdir|rename|copyFile|createWriteStream|createReadStream|readdir|chmod|chown|symlink)(?:Sync)?\\(`)],
  ['dynamic_loading', 'eval / new Function / vm', new RegExp(`(?:^|[^\\w.$])eval\\s*\\(|\\bnew\\s+Function\\s*\\(|\\bFunction\\s*\\(\\s*${Q}|${imp('vm')}|\\bvm\\.(?:runIn\\w+|Script|compileFunction)\\b|\\bsetTimeout\\(\\s*${Q}[^'"\`]+${Q}`)],
  ['dynamic_loading', 'dynamic require / import', /\brequire\(\s*(?!['"`])[^)\s]|\bimport\(\s*(?!['"`])[^)\s]|\bModule\._load\b|\bmodule\.constructor\b|\bprocess\.mainModule\b/],
  ['dynamic_loading', 'native addon / process.dlopen', /\bprocess\.dlopen\(|\brequire\(\s*['"`][^'"`]+\.node['"`]\s*\)|\bnode-gyp-build\b|\bprocess\.binding\(/],
  ['crypto', 'crypto', new RegExp(`${imp('crypto|tweetnacl|libsodium-wrappers|node-forge|crypto-js|bcrypt(?:js)?|argon2|jsonwebtoken')}|\\bcrypto\\.(?:createCipheriv|createDecipheriv|createHash|createHmac|createSign|privateEncrypt|publicEncrypt|subtle|randomBytes|scrypt|pbkdf2)\\b`)],
  ['system_info', 'os / process info', new RegExp(`${imp('os')}|\\bos\\.(?:hostname|userInfo|networkInterfaces|cpus|platform|release|homedir|tmpdir|totalmem|uptime)\\(|\\bprocess\\.(?:getuid|getgid|geteuid)\\(`)],
  ['privilege', 'process.setuid / setgid', /\bprocess\.(?:setuid|setgid|seteuid|setegid|setgroups|initgroups|chroot)\(/],
  ['input_capture', 'clipboard / screen / keyboard', new RegExp(`${imp('clipboardy|copy-paste|screenshot-desktop|robotjs|iohook|node-global-key-listener|desktop-screenshot|node-key-sender|active-win|systeminformation')}|\\bnavigator\\.(?:clipboard|mediaDevices|geolocation)\\b`)],
  ['credentials', 'environment: serialised', /JSON\.stringify\(\s*process\.env\s*\)|Object\.(?:keys|entries|values|fromEntries)\(\s*process\.env\s*\)/],
  ['credentials', 'environment: passed on or copied', /\.\.\.process\.env\b|Object\.assign\(\s*\{\s*\}\s*,\s*process\.env\s*\)|\benv:\s*process\.env\b|\bprocess\.env\s*,/],
  ['credentials', 'environment: secret-named variable', /\bprocess\.env(?:\.|\[\s*['"`])[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*/],
  ['obfuscation', 'eval of decoded data', new RegExp(`(?:^|[^\\w.$])eval\\s*\\(\\s*(?:atob|unescape|decodeURIComponent|String\\.fromCharCode|Buffer\\.from|require\\(\\s*${Q}zlib|[a-z_$][\\w$]*\\(\\s*${Q}[A-Za-z0-9+/=]{40,})|\\bnew\\s+Function\\s*\\(\\s*(?:atob|Buffer\\.from|unescape)|\\bFunction\\s*\\(\\s*atob`)],
  ['obfuscation', 'packer / obfuscator output', /eval\(function\(p,a,c,k,e,[dr]\)|\b_0x[0-9a-f]{4,6}\s*=\s*_0x[0-9a-f]{4,6}\b|var\s+_0x[0-9a-f]{4,6}\s*=\s*\[|\(function\(_0x[0-9a-f]{4,6},_0x[0-9a-f]{4,6}\)|\bjsfuck\b|\[\]\[\(!\[\]\+\[\]\)\[\+\[\]\]/],
];

const PY = [
  ['process', 'subprocess / os.system / os.popen', /\bsubprocess\.(?:Popen|run|call|check_call|check_output|getoutput|getstatusoutput)\b|\bos\.(?:system|popen|exec[lv]p?e?|spawn[lv]p?e?|startfile)\s*\(|\bpty\.spawn\b|\bcommands\.getoutput\b|\basyncio\.create_subprocess_(?:exec|shell)\b|\bos\.posix_spawn\b/],
  ['network', 'socket / ssl / dns', /(?:^|\s)(?:import|from)\s+(?:socket|socketserver|ssl|ipaddress|dns|dnspython)\b|\bsocket\.(?:socket|create_connection|getaddrinfo|gethostbyname)\b/],
  ['network', 'HTTP / FTP / SMTP client', /(?:^|\s)(?:import|from)\s+(?:urllib(?:2|3)?|http\.client|httplib|requests|httpx|aiohttp|ftplib|smtplib|telnetlib|paramiko|websockets?|pycurl|urllib3|poplib|imaplib|xmlrpc)\b|\burlopen\s*\(|\burlretrieve\s*\(/],
  ['file_io', 'os / shutil file operations', /\bos\.(?:remove|unlink|rmdir|removedirs|rename|renames|replace|makedirs|mkdir|chmod|chown|symlink|link|truncate)\s*\(|\bshutil\.(?:rmtree|copy\w*|move|make_archive|unpack_archive)\b|\bPath\([^)]*\)\.(?:write_text|write_bytes|unlink|rmdir|chmod)\b|\bopen\([^)]*,\s*['"][wa]b?\+?['"]/],
  ['dynamic_loading', 'exec / eval / compile / __import__', /(?:^|[^\w.])(?:exec|eval|compile)\s*\(|\b__import__\s*\(|\bimportlib\.(?:import_module|util\.(?:spec_from_file_location|module_from_spec))\b|\bimp\.load_(?:source|module|dynamic)\b|\brunpy\.run_(?:path|module)\b|\bzipimport\b|\btypes\.(?:CodeType|FunctionType)\b/],
  ['dynamic_loading', 'ctypes / cffi / native loading', /(?:^|\s)(?:import|from)\s+(?:ctypes|cffi)\b|\bctypes\.(?:CDLL|WinDLL|windll|cdll|cast|CFUNCTYPE|pythonapi)\b|\bos\.add_dll_directory\b/],
  ['dynamic_loading', 'marshal / pickle loading', /\b(?:marshal|pickle|cPickle|dill|cloudpickle|shelve)\.(?:loads?|Unpickler)\b|\byaml\.(?:load|unsafe_load)\s*\((?![^)]*Loader\s*=\s*(?:yaml\.)?SafeLoader)/],
  ['crypto', 'hashlib / hmac / cryptography', /(?:^|\s)(?:import|from)\s+(?:hashlib|hmac|secrets|cryptography|Crypto|Cryptodome|nacl|OpenSSL|bcrypt|argon2|jwt)\b/],
  ['system_info', 'platform / getpass / host info', /(?:^|\s)(?:import|from)\s+(?:platform|getpass|psutil|netifaces|uuid)\b|\bsocket\.gethostname\b|\bgetpass\.getuser\b|\bos\.(?:getlogin|getuid|uname|cpu_count|getlogin)\s*\(|\bplatform\.(?:node|uname|system|platform)\s*\(|\buuid\.getnode\s*\(/],
  ['input_capture', 'keyboard / clipboard / screen', /(?:^|\s)(?:import|from)\s+(?:pynput|pyperclip|pyautogui|keyboard|mouse|PIL\.ImageGrab|pyaudio|sounddevice|cv2|win32clipboard|mss)\b|\bImageGrab\.grab\b/],
  ['privilege', 'os.setuid / chroot', /\bos\.(?:setuid|setgid|seteuid|setegid|setgroups|chroot|seteuid)\s*\(|\bctypes\.windll\.shell32\.IsUserAnAdmin\b/],
  ['persistence', 'winreg / registry', /(?:^|\s)(?:import|from)\s+(?:winreg|_winreg)\b|\bwinreg\.(?:SetValueEx|CreateKey)\b/],
  ['credentials', 'environment: serialised', /\b(?:dict|str|repr|json\.dumps|list)\(\s*os\.environ\s*\)|\bos\.environ\.(?:items|keys|values)\(\)/],
  ['credentials', 'environment: passed on or copied', /\bos\.environ\.copy\(\)|\bos\.environ\s*\)|\*\*os\.environ\b|\benv\s*=\s*os\.environ\b|\bos\.environb\b/],
  ['credentials', 'environment: secret-named variable', /\bos\.(?:environ(?:\.get)?|getenv)\s*[\[(]\s*['"][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*/],
  ['obfuscation', 'exec of decoded data', /\b(?:exec|eval)\s*\(\s*(?:compile\s*\(\s*)?(?:base64\.(?:b64|b32|b16|a85|b85)decode|zlib\.decompress|bz2\.decompress|lzma\.decompress|codecs\.decode|bytes\.fromhex|marshal\.loads|binascii\.unhexlify|binascii\.a2b_\w+|__import__\(\s*['"](?:base64|zlib|codecs)['"]\)|\(lambda|str\(|bytes\(|''\.join|"\.join)/],
  ['obfuscation', 'obfuscator runtime', /\b__pyarmor__\b|\bpyarmor_runtime\b|\bpytransform\b|\bPyArmor\b|\bpyobfuscate\b|\bexec\(\s*['"]\\x[0-9a-f]{2}|\bfrom\s+\w+\s+import\s+\*\s*#\s*pyc?\b|\bmarshal\.loads\(\s*b?['"]/],
];

const RB = [
  ['process', 'system / exec / backticks / Open3', /(?:^|[^\w.:])(?:system|exec|spawn|fork|syscall)\s*[(\s]['"%$#a-zA-Z]|%x[{(\[]|`[^`\n]{2,}`|\bOpen3\.\w+|\bIO\.popen\b|\bKernel\.(?:system|exec|spawn)\b|\bPTY\.(?:spawn|open)\b|\bProcess\.spawn\b/],
  ['network', 'Net::HTTP / open-uri / sockets / HTTP clients', /\bNet::(?:HTTP|FTP|SMTP|IMAP|POP3|Telnet)\b|\bURI\.open\b|\brequire\s+['"](?:open-uri|net\/http|socket|httparty|faraday|rest-client|typhoeus|excon|curb)['"]|\b(?:TCPSocket|TCPServer|UDPSocket|UNIXSocket|Socket)\.(?:new|open|tcp)\b|\bHTTParty\.\w+|\bFaraday\.\w+|\bRestClient\.\w+/],
  ['file_io', 'File / FileUtils / Dir', /\bFile\.(?:write|binwrite|delete|unlink|rename|chmod|chown|symlink|open)\b|\bFileUtils\.(?:rm|rm_r|rm_rf|rmdir|mv|cp|chmod|chown|mkdir_p|ln_s|touch|remove\w*)\b|\bDir\.(?:rmdir|mkdir|glob|entries|chdir)\b|\bIO\.(?:write|binwrite)\b/],
  ['dynamic_loading', 'eval / instance_eval / send / Marshal', /(?:^|[^\w.])(?:eval|instance_eval|class_eval|module_eval|instance_exec)\b|\bKernel\.eval\b|\bBinding\b|\bMarshal\.load\b|\bYAML\.(?:load|unsafe_load)\b|\.(?:public_)?send\(\s*[a-z@]|\bconst_get\b|\brequire\s+[^'"\s]|\bload\s+[^'"\s]|\bObjectSpace\b|\bFiddle\b|\bDL\.dlopen\b/],
  ['crypto', 'OpenSSL / Digest', /\bOpenSSL::(?:Cipher|PKey|Digest|HMAC|KDF)\b|\bDigest::(?:MD5|SHA1|SHA2|SHA256)\b|\bSecureRandom\b|\brequire\s+['"](?:openssl|digest|bcrypt|rbnacl)['"]/],
  ['system_info', 'host / user info', /\bEtc\.(?:getlogin|getpwuid|nprocessors)\b|\bSocket\.gethostname\b|\bRbConfig::CONFIG\b|\bRUBY_PLATFORM\b/],
  ['credentials', 'environment: serialised', /\bENV\.(?:inspect|to_a|keys|values|each|each_pair|map|select)\b|JSON\.(?:generate|dump)\(\s*ENV\b|\bENV\.to_h\.to_json\b/],
  ['credentials', 'environment: passed on or copied', /\bENV\.(?:to_h|to_hash|dup|clone)\b|\bENV\)\s*|\bENV\s*,/],
  ['credentials', 'environment: secret-named variable', /\bENV\[\s*['"][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*/],
  ['obfuscation', 'eval of decoded data', /\b(?:eval|instance_eval|class_eval)\s*\(?\s*(?:Base64\.(?:decode64|strict_decode64|urlsafe_decode64)|Zlib::(?:Inflate|GzipReader)|\[[^\]]*\]\.pack\(['"]m|.*\.unpack\(['"]m|.*\.unpack1\(['"]m|.*\.hex|.*\.reverse\b)/],
];

const RS = [
  ['process', 'std::process::Command', /\b(?:std::)?process::Command\b|\bCommand::new\s*\(|\buse\s+(?:duct|subprocess|shared_child|command_group)\b/],
  ['network', 'std::net / HTTP clients', /\bstd::net::\w+|\b(?:TcpStream|TcpListener|UdpSocket)::\w+|\buse\s+(?:reqwest|ureq|hyper|surf|isahc|attohttpc|curl|tungstenite|tokio_tungstenite|tonic|socket2|lettre|ssh2|russh|suppaftp)\b|\b(?:reqwest|ureq|hyper|attohttpc)::\w+/],
  ['file_io', 'std::fs', /\b(?:std::)?fs::(?:write|remove_file|remove_dir_all|remove_dir|rename|copy|create_dir_all|set_permissions|File::create|OpenOptions)\b|\bFile::create\b|\bOpenOptions::new\b/],
  ['dynamic_loading', 'libloading / dlopen / transmute', /\buse\s+(?:libloading|dlopen2?)\b|\bLibrary::new\b|\bmem::transmute\b|\bextern\s+"C"\s*\{|\bunsafe\s+extern\b/],
  ['crypto', 'crypto crates', /\buse\s+(?:ring|rustls|openssl|native_tls|aes|aes_gcm|chacha20poly1305|rsa|sha2|sha1|md5|hmac|argon2|bcrypt|ed25519_dalek|rand_core)\b/],
  ['system_info', 'host / env info', /\buse\s+(?:sysinfo|hostname|whoami|machine_uid|os_info|mac_address|get_if_addrs|local_ip_address)\b|\b(?:whoami|hostname)::\w+|\bstd::env::(?:consts|current_dir|home_dir|temp_dir|current_exe)\b|\benv::(?:current_dir|home_dir|temp_dir|current_exe)\b/],
  ['credentials', 'environment: enumerated', /\b(?:std::)?env::vars(?:_os)?\s*\(\s*\)/],
  ['credentials', 'environment: secret-named variable', /\benv::var(?:_os)?\s*\(\s*"[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*"|\benv!\(\s*"[A-Z0-9_]*(?:TOKEN|SECRET|KEY)/],
  ['obfuscation', 'decoded payload', /\b(?:base64::decode|general_purpose::STANDARD\.decode|hex::decode)\s*\([^)]*\)[^;\n]*(?:Command|exec|transmute|spawn)/],
];

const GO = [
  ['process', 'os/exec', /\bexec\.Command(?:Context)?\s*\(|\bsyscall\.(?:Exec|ForkExec|StartProcess)\b|\bos\.StartProcess\b|\bgolang\.org\/x\/sys\/(?:unix|windows)\b[^\n]*Exec/],
  ['network', 'net / net/http', /\bnet\.(?:Dial\w*|Listen\w*|LookupHost|LookupIP|ResolveTCPAddr)\s*\(|\bhttp\.(?:Get|Post|PostForm|Head|NewRequest\w*|ListenAndServe\w*|Client|DefaultClient)\b|\btls\.(?:Dial|Listen)\b|"(?:net\/http|net\/smtp|net\/rpc|golang\.org\/x\/net\/websocket|github\.com\/gorilla\/websocket)"/],
  ['file_io', 'os file operations', /\bos\.(?:Remove|RemoveAll|WriteFile|Rename|Chmod|Chown|OpenFile|Create|MkdirAll|Symlink|Truncate)\s*\(|\bioutil\.(?:WriteFile|TempFile)\b/],
  ['dynamic_loading', 'plugin / cgo / unsafe', /\bplugin\.Open\b|^import\s+"C"|^\s*"C"\s*$|#cgo\s+(?:LDFLAGS|CFLAGS|pkg-config)|\bunsafe\.Pointer\b|\bsyscall\.(?:LoadLibrary|NewLazyDLL|GetProcAddress)\b|\bpurego\.\w+/],
  ['crypto', 'crypto', /"crypto\/(?:aes|cipher|des|rc4|rsa|ecdsa|ed25519|md5|sha1|sha256|sha512|tls|x509|rand|hmac)"|"golang\.org\/x\/crypto/],
  ['system_info', 'host / user info', /\bos\.(?:Hostname|UserHomeDir|Getuid|Geteuid|Getpid|Executable|Getwd)\s*\(|\buser\.Current\s*\(|\bnet\.Interfaces\s*\(|\bruntime\.GOOS\b/],
  ['credentials', 'environment: enumerated', /\bos\.Environ\s*\(\s*\)/],
  ['credentials', 'environment: secret-named variable', /\bos\.(?:Getenv|LookupEnv)\s*\(\s*"[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*"/],
  ['obfuscation', 'decoded payload', /\b(?:base64\.(?:Std|URL|RawStd)Encoding\.DecodeString|hex\.DecodeString)\s*\([^)]*\)[^\n]*(?:exec\.Command|syscall\.|unsafe\.)/],
];

const CS = [
  ['process', 'Process.Start', /\bProcess\.Start\s*\(|\bProcessStartInfo\b|\bnew\s+Process\s*\(|\bShell32\.ShellExecute\b|\bWScript\.Shell\b|\bCreateProcess\w*\b/],
  ['network', 'HttpClient / WebClient / sockets', /\b(?:HttpClient|WebClient|HttpWebRequest|WebRequest|TcpClient|UdpClient|Socket|SmtpClient|FtpWebRequest|ClientWebSocket|WebSocketClient)\b|\bDns\.(?:GetHostEntry|GetHostAddresses)\b|\bDownloadString\b|\bDownloadFile\b|\bUploadString\b|\bUploadData\b/],
  ['file_io', 'File / Directory', /\b(?:File|Directory)\.(?:Delete|WriteAll\w+|Move|Copy|Create|SetAttributes|SetAccessControl|AppendAll\w+|Replace)\b|\bnew\s+(?:FileStream|StreamWriter)\s*\(/],
  ['dynamic_loading', 'Assembly.Load / Reflection / P/Invoke', /\bAssembly\.(?:Load|LoadFrom|LoadFile|ReflectionOnlyLoad)\w*\s*\(|\bActivator\.CreateInstance\b|\bType\.GetType\s*\(|\bCSharpScript\b|\bReflection\.Emit\b|\bDynamicMethod\b|\[DllImport\b|\bMarshal\.(?:GetDelegateForFunctionPointer|GetFunctionPointerForDelegate)\b|\bNativeLibrary\.Load\b|\bCSharpCodeProvider\b|\bCodeDomProvider\b|\bExpression\.Lambda\b/],
  ['crypto', 'System.Security.Cryptography', /\bSystem\.Security\.Cryptography\b|\b(?:Aes|RSA|SHA1|SHA256|MD5|DES|TripleDES|RC2|HMACSHA\w+|Rfc2898DeriveBytes|ProtectedData)\.(?:Create|Encrypt|Decrypt|Protect|Unprotect|ComputeHash)\b/],
  ['system_info', 'host / user info', /\bEnvironment\.(?:MachineName|UserName|UserDomainName|OSVersion|GetFolderPath|ProcessorCount|SystemDirectory)\b|\bNetworkInterface\.GetAllNetworkInterfaces\b|\bManagementObjectSearcher\b|\bWindowsIdentity\.GetCurrent\b/],
  ['persistence', 'registry / services / tasks', /\bRegistry(?:Key)?\.(?:CurrentUser|LocalMachine|SetValue|CreateSubKey)\b|\bServiceController\b|\bTaskScheduler\b|\bsc\.exe\s+create\b/],
  ['credentials', 'environment: enumerated', /\bEnvironment\.GetEnvironmentVariables\s*\(\s*\)/],
  ['credentials', 'environment: secret-named variable', /\bEnvironment\.GetEnvironmentVariable\s*\(\s*"[A-Za-z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Za-z0-9_]*"/i],
  ['obfuscation', 'decoded payload', /\bAssembly\.Load\s*\(\s*(?:Convert\.FromBase64String|new\s+byte\[\]|Decompress|Decrypt)|\bConvert\.FromBase64String\s*\([^)]*\)[^;\n]*(?:Assembly\.Load|Process\.Start|CSharpScript)/],
];

const PS = [
  ['process', 'Start-Process / cmd / call operator', /\bStart-Process\b|\bInvoke-Command\b|\bcmd(?:\.exe)?\s+\/[ck]\b|\bInvoke-Item\b|\bStart-Job\b|\[Diagnostics\.Process\]::Start/i],
  ['network', 'Invoke-WebRequest / WebClient / sockets', /\b(?:Invoke-WebRequest|Invoke-RestMethod|iwr|irm|Start-BitsTransfer|Test-NetConnection)\b|\bNet\.WebClient\b|\bDownload(?:String|File|Data)\b|\bNet\.Sockets\.TcpClient\b|\bSystem\.Net\.\w+/i],
  ['file_io', 'file operations', /\b(?:Remove-Item|Set-Content|Out-File|Add-Content|Copy-Item|Move-Item|New-Item|Rename-Item|Set-Acl|Expand-Archive|Compress-Archive)\b/i],
  ['dynamic_loading', 'Invoke-Expression / Add-Type / reflection', /\b(?:Invoke-Expression|iex)\b|\bAdd-Type\b|\[Reflection\.Assembly\]::Load|\bInvoke-Method\b|\[System\.Runtime\.InteropServices\.Marshal\]/i],
  ['persistence', 'registry / scheduled tasks / services', /\b(?:New-ScheduledTask\w*|Register-ScheduledTask|schtasks|New-Service|Set-ItemProperty[^\n]*\\Run\b|New-ItemProperty[^\n]*\\Run\b|Register-WmiEvent|Set-WmiInstance)\b/i],
  ['credentials', 'credential / environment access', /\bGet-ChildItem\s+(?:env:|Env:)|\$env:(?:[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|API_?KEY|ACCESS_?KEY))|\bGet-Credential\b|\bConvertFrom-SecureString\b|\bvaultcmd\b|\bcmdkey\b|\bmimikatz\b|\bSecretManagement\b|\[System\.Environment\]::GetEnvironmentVariables/i],
  ['obfuscation', 'encoded command / payload', /\s-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{20,}|\bFromBase64String\b|\b-bxor\b|\bConvertTo-SecureString\b[^\n]*-Key\b|\[char\]\s*\(?\s*\d+\s*\)?\s*\+\s*\[char\]|\bIO\.Compression\.(?:GzipStream|DeflateStream)\b[^\n]*FromBase64/i],
];

const PHP = [
  ['process', 'exec / system / shell_exec / proc_open', /\b(?:exec|shell_exec|system|passthru|popen|proc_open|pcntl_exec|pcntl_fork|expect_popen)\s*\(|`[^`\n]{2,}`/],
  ['network', 'curl / sockets / HTTP clients', /\b(?:curl_init|curl_exec|fsockopen|pfsockopen|stream_socket_client|stream_socket_server|socket_create|socket_connect|gethostbyname|dns_get_record|mail)\s*\(|\bfile_get_contents\s*\(\s*['"]https?:|\bnew\s+(?:SoapClient|GuzzleHttp\\Client)\b|\bGuzzleHttp\\\w+|\bfopen\s*\(\s*['"]https?:/],
  ['file_io', 'file operations', /\b(?:unlink|file_put_contents|rename|chmod|chown|rmdir|mkdir|copy|move_uploaded_file|symlink|touch|tempnam)\s*\(|\bfopen\s*\([^)]*,\s*['"][wa]/],
  ['dynamic_loading', 'eval / include variable / call_user_func', /\b(?:eval|assert|create_function|call_user_func(?:_array)?|forward_static_call|preg_replace_callback|array_map|usort)\s*\(\s*(?:\$|['"]\s*\$)|(?:^|[^\w])(?:include|require)(?:_once)?\s*\(?\s*\$|\beval\s*\(|\bpreg_replace\s*\(\s*['"][^'"]*\/[a-z]*e[a-z]*['"]|\$\$\w+\s*\(|\bReflectionFunction\b|\bdl\s*\(|\bFFI::\w+/],
  ['crypto', 'openssl / hash / sodium', /\b(?:openssl_\w+|mcrypt_\w+|sodium_\w+|hash_hmac|password_hash|md5|sha1|crypt)\s*\(/],
  ['system_info', 'host / php info', /\b(?:phpinfo|php_uname|gethostname|get_current_user|posix_getpwuid|getmyuid|sys_get_temp_dir|disk_free_space)\s*\(/],
  ['credentials', 'environment: serialised', /\bprint_r\s*\(\s*\$_(?:ENV|SERVER)|\bvar_dump\s*\(\s*\$_(?:ENV|SERVER)|json_encode\s*\(\s*\$_(?:ENV|SERVER)/],
  ['credentials', 'environment: enumerated', /\bgetenv\s*\(\s*\)|\$_ENV\s*\)|\$_SERVER\s*\)/],
  ['credentials', 'environment: secret-named variable', /\b(?:getenv\s*\(\s*['"]|\$_(?:ENV|SERVER)\s*\[\s*['"])[A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*/],
  ['obfuscation', 'eval of decoded data / webshell', /\b(?:eval|assert)\s*\(\s*(?:base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13|strrev|rawurldecode|urldecode|hex2bin|convert_uudecode|pack)\s*\(|\b(?:eval|assert|system|exec|shell_exec|passthru)\s*\(\s*\$_(?:POST|GET|REQUEST|COOKIE|SERVER)\b|\beval\s*\(\s*\$\w+\s*\(\s*\$\w+\s*\(|\$\w+\s*=\s*['"](?:ba|as|ev|sy)[a-z0-9_]*['"]\s*\.\s*['"]/],
];

const DART = [
  ['process', 'dart:io Process', /\bProcess\.(?:run|runSync|start)\s*\(|\bShell\(\)\.run\b|\brun\(\s*['"][^'"]+['"]\s*\)\s*;?\s*\/\/\s*shell/],
  ['network', 'HttpClient / http / sockets', /\bHttpClient\s*\(|\bhttp\.(?:get|post|put|delete|read|Client)\b|\bDio\s*\(|\bSocket\.connect\b|\bRawSocket\.connect\b|\bWebSocket\.connect\b|\bSecureSocket\.connect\b|package:(?:http|dio|web_socket_channel|chopper|retrofit)\//],
  ['file_io', 'File / Directory', /\bFile\([^)]*\)\.(?:writeAs\w+|delete\w*|rename\w*|create\w*|copy\w*)\b|\bDirectory\([^)]*\)\.(?:delete\w*|create\w*)\b|\bLink\([^)]*\)\.create\b/],
  ['dynamic_loading', 'mirrors / Isolate.spawnUri / FFI', /\bdart:mirrors\b|\bIsolate\.spawn(?:Uri)?\b|\bDynamicLibrary\.(?:open|process|executable)\b|\bdart:ffi\b|\bpackage:ffi\//],
  ['system_info', 'Platform info', /\bPlatform\.(?:operatingSystem|localHostname|numberOfProcessors|executable|script|localeName|version)\b/],
  ['credentials', 'environment: enumerated', /\bPlatform\.environment\s*[,);.]|\bPlatform\.environment\.(?:entries|keys|values|toString)\b/],
  ['credentials', 'environment: secret-named variable', /\bPlatform\.environment\s*\[\s*['"][A-Z0-9_]*(?:TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIALS?|AUTH)[A-Z0-9_]*/],
  ['obfuscation', 'decoded payload', /\bbase64(?:Url)?\.decode\s*\([^)]*\)[^;\n]*(?:Process\.|Isolate\.|DynamicLibrary)/],
];

const LANG_TABLES = { js: JS, py: PY, rb: RB, rs: RS, go: GO, cs: CS, ps: PS, php: PHP, dart: DART };

// lines that EXECUTE a command string: handed to the command analyser (installscripts.js) so `exec("curl x | sh")` is read like a script line
const EXEC_LINE = {
  js: /\b(?:exec|execSync|spawn|spawnSync|execFile|execFileSync)\s*\(|`[^`]*(?:curl|wget|sh\s+-c)[^`]*`/,
  py: /\b(?:os\.system|os\.popen|subprocess\.\w+|commands\.getoutput|check_output|getoutput)\s*\(|\bos\.exec\w*\(/,
  rb: /\bsystem\s*\(?\s*['"]|`[^`]+`|%x[{(\[]|\bexec\s*\(?\s*['"]|\bOpen3\.\w+|\bIO\.popen\b/,
  rs: /\bCommand::new\s*\(|\.arg\(\s*"/, go: /\bexec\.Command(?:Context)?\s*\(/, cs: /\bProcess\.Start\s*\(|\bProcessStartInfo\b|\.Arguments\s*=|\.FileName\s*=/,
  php: /\b(?:exec|shell_exec|system|passthru|popen|proc_open)\s*\(|`[^`]+`/, dart: /\bProcess\.(?:run|runSync|start)\s*\(/,
};

const COMMENT = { js: /^\s*(?:\/\/|\*|\/\*)/, rs: /^\s*(?:\/\/|\*|\/\*)/, go: /^\s*(?:\/\/(?!go:)|\*|\/\*)/, cs: /^\s*(?:\/\/|\*|\/\*)/, dart: /^\s*(?:\/\/|\*|\/\*)/, php: /^\s*(?:\/\/|#|\*|\/\*)/, py: /^\s*#/, rb: /^\s*#/, ps: /^\s*#/, sh: /^\s*(?:#|rem\b|::)/i };

const MAX_LINE = 4096;

function* pieces(line) {
  if (line.length <= MAX_LINE) { yield line; return; }
  for (let i = 0; i < line.length; i += MAX_LINE - 256) yield line.slice(i, i + MAX_LINE);
}

const snip = s => { const t = s.trim().replace(/\s+/g, ' '); return t.length > 160 ? `${t.slice(0, 157)}…` : t; };

/**
 * @param {string} text   file content
 * @param {string} lang   one of LANGS (not 'msbuild': see analyzeMsbuild)
 * @returns {{behaviors:Map<string,{cat:string,label:string,count:number,line:number,snippet:string}>, risks:object[], stats:{lines:number, longest:number}}}
 */
export function analyzeSource(text, lang) {
  const behaviors = new Map();
  const risks = [];
  const add = (cat, label, n, line) => {
    const k = `${cat}\0${label}`;
    const e = behaviors.get(k);
    if (e) e.count++; else behaviors.set(k, { cat, label, count: 1, line: n, snippet: snip(line) });
  };
  const risk = (id, label, n, line, confidence = 'medium') => {
    if (risks.some(r => r.id === id && r.line === n)) return;
    if (risks.filter(r => r.id === id).length >= 5) return;
    risks.push({ id, label, line: n, snippet: snip(line), confidence });
  };
  const lines = String(text).split(/\r?\n/);
  const flags = { child_process: /(?:require\(\s*|from\s*|import\(\s*|import\s+)['"`](?:node:)?child_process['"`]/.test(text) };
  const isShell = lang === 'sh';
  const table = LANG_TABLES[lang] || [];
  const comment = COMMENT[lang];
  let longest = 0, hexEsc = 0, hex0x = 0, longB64 = 0, envBulk = false, credFile = false, netSeen = false, decodeSeen = false, evalSeen = false;
  for (let n = 0; n < lines.length; n++) {
    const raw = lines[n];
    if (raw.length > longest) longest = raw.length;
    if (!raw.trim() || (comment && comment.test(raw))) continue;
    for (const line of pieces(raw)) {
      if (!isShell) {
        for (const [cat, label, re, opt] of table) {
          if (opt?.needs && !flags[opt.needs]) continue;
          if (re.test(line)) {
            add(cat, label, n + 1, line);
            if (cat === 'network') netSeen = true;
            if (cat === 'credentials' && /serialised/.test(label)) { envBulk = true; risk('credential_access', 'serialises the whole environment (a dump of every variable, which a library has no reason to produce)', n + 1, line, 'medium'); }
            if (cat === 'credentials' && /secret-named/.test(label)) risk('credential_access', 'reads a secret-named environment variable', n + 1, line, 'low');
            if (cat === 'obfuscation') risk('obfuscated', label, n + 1, line, /packer|obfuscator/.test(label) ? 'medium' : 'high');
            if (cat === 'dynamic_loading' && /eval|exec/.test(label)) evalSeen = true;
          }
        }
        if (CRED_FILE.test(line) && /['"`]/.test(line)) { credFile = true; add('credentials', 'credential-store path', n + 1, line); risk('credential_access', 'refers to a credential store', n + 1, line, 'medium'); }
        if (PERSIST.test(line) && /['"`]/.test(line)) { add('persistence', 'autostart / scheduler / shell-profile path', n + 1, line); risk('persistence', 'refers to an autostart location', n + 1, line, 'low'); }
        const ex = EXEC_LINE[lang];
        if (ex && ex.test(line)) commandSignals(analyzeCommand(line), (id, detail) => riskFromCommand(id, detail, n + 1, line, risk, add));
      } else {
        const t = line.trim().replace(/^@/, '');
        if (t && !/^(?:fi|done|then|else|esac|\}|\{)$/.test(t) && !/^[A-Za-z_][A-Za-z0-9_]*=/.test(t)) {
          const a = analyzeCommand(t);
          commandSignals(a, (id, detail) => riskFromCommand(id, detail, n + 1, line, risk, add));
        }
      }
      if (REVSHELL.test(line)) risk('reverse_shell', 'reverse-shell construct', n + 1, line, 'high');
      if (MINER.test(line) && !/^\s*(?:\/\/|#|\*)/.test(line)) risk('crypto_mining', 'cryptocurrency-miner reference', n + 1, line, 'medium');
      if (DESTRUCT.test(line)) risk('destructive', 'destructive command', n + 1, line, 'medium');
      if (INSECURE_TLS.test(line)) risk('insecure_tls', 'TLS certificate verification disabled', n + 1, line, 'high');
      const hx = line.match(/\\x[0-9a-f]{2}/gi); if (hx) hexEsc += hx.length;
      const h0 = line.match(/\b_0x[0-9a-f]{4,6}\b/g); if (h0) hex0x += h0.length;
      if (/['"`][A-Za-z0-9+/]{1500,}={0,2}['"`]/.test(line)) longB64++;
      if (/\b(?:atob|b64decode|base64_decode|Base64\.decode64|FromBase64String|Buffer\.from)\b/.test(line)) decodeSeen = true;
    }
  }
  // file-level patterns (a single line says little; the combination says more)
  if (hex0x >= 30) risk('obfuscated', 'obfuscator-style identifiers (_0x…)', 0, `${hex0x} identifiers of the form _0x1a2b`, 'medium');
  if (hexEsc >= 60 && lang !== 'sh') risk('obfuscated', 'heavy \\x escaping of strings', 0, `${hexEsc} \\xNN escapes`, 'medium');
  if (longB64 > 0 && (decodeSeen || evalSeen) && lang !== 'sh') risk('obfuscated', 'very long encoded string that the file decodes', 0, `${longB64} string literal(s) of 1500+ base64 characters`, 'medium');
  if ((envBulk || credFile) && netSeen) risk('exfiltration', 'collects secrets and has network access in the same file', 0, envBulk ? 'whole-environment dump + network code' : 'credential-store path + network code', 'low');
  if (lang === 'js' && /\b(?:spawn|exec)\s*\(\s*['"`](?:\/bin\/)?(?:ba|z)?sh|\bcmd(?:\.exe)?['"`]|powershell/i.test(text) && /\bnet\.(?:Socket|connect|createConnection)|\.connect\(\s*\d{2,5}\s*,/.test(text) && /\.pipe\(/.test(text)) risk('reverse_shell', 'socket piped to a spawned shell', 0, 'net socket + spawned shell + pipe()', 'high');
  if (lang === 'py' && /\bsocket\b/.test(text) && /\bdup2\b|\bsubprocess\b[^\n]*(?:\/bin\/(?:ba)?sh|cmd\.exe)/.test(text) && /\.connect\(\s*\(/.test(text) && /\bos\.dup2\b|\bstdin\s*=\s*\w+\b|\bsubprocess\.call\(\s*\[\s*['"]\/bin\/(?:ba)?sh/.test(text)) risk('reverse_shell', 'socket wired to a spawned shell', 0, 'socket.connect + dup2 / subprocess shell', 'high');
  return { behaviors, risks, stats: { lines: lines.length, longest } };
}

function commandSignals(a, fn) { for (const [id, e] of a.signals) fn(id, e.detail); }

const SIGNAL_TO_CAT = { fetch: 'network', download_exec: 'network', runtime_install: 'process', shell_inline: 'process', native_build: 'process', privilege: 'privilege', credential_access: 'credentials', persistence: 'persistence', destructive: 'file_io', obfuscated_inline: 'obfuscation' };
const SIGNAL_LABEL = { fetch: 'command: downloads / contacts a host', download_exec: 'command: downloads and runs code', runtime_install: 'command: installs packages', shell_inline: 'command: inline script', native_build: 'command: native build', privilege: 'command: changes privileges', credential_access: 'command: reads credentials / environment', persistence: 'command: persistence', destructive: 'command: destructive', obfuscated_inline: 'command: encoded payload' };

function riskFromCommand(id, detail, n, line, risk, add) {
  const cat = SIGNAL_TO_CAT[id];
  if (cat) add(cat, SIGNAL_LABEL[id], n, line);
  if (id === 'download_exec') risk('download_exec', detail, n, line, 'high');
  else if (id === 'obfuscated_inline') risk('obfuscated', detail, n, line, 'medium');
  else if (id === 'credential_access') risk('credential_access', detail, n, line, 'medium');
  else if (id === 'persistence') risk('persistence', detail, n, line, 'medium');
  else if (id === 'destructive') risk('destructive', detail, n, line, 'medium');
  else if (id === 'runtime_install') risk('runtime_install', detail, n, line, 'medium');
  else if (id === 'fetch') risk('remote_fetch', detail, n, line, 'low');
  else if (id === 'privilege') risk('privilege', detail, n, line, 'low');
  else if (id === 'shell_inline') risk('shell_inline', detail, n, line, 'low');
}

export { snip };
