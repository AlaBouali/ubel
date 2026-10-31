'use strict';
// behavior.js (binary) — a capability inventory of a native executable or library: what it can do (file access, network, process
// execution, dynamic loading, debugging / injection, anti-analysis, privilege, persistence, input capture and sensitive devices,
// cryptography, system fingerprinting).
//
// Same idea as mobile/lib/behavior.js. The Android collector counts call SITES reported by the DEX walker. Here an entry says that a function is
// PRESENT (linked or referenced, value 1), except for ELF / PE imports of x86-64 and arm64 files, where lib/callsites.js counts the direct call
// sites that reach the import (`basis: 'calls'`, 0 = imported but no direct call found). Either way the result is an inventory, not proof that
// code runs. It is a summary on the app record (`app.behavior`), never a rule hit: nearly every program does file and network I/O.
//
// Counting. Every entry has a count and a BASIS that says what the count is: `sites` (direct call sites found in the code; 0 = imported, no call
// found), `refs` (lines of bundled source text that mention the module) or `present` (the function is linked or referenced; the count is 1).
// An origin's summary carries `functions` (how many distinct entries it has, counted BEFORE the list is cut to MAX_APIS), `calls` (the sum of
// the counts, for old consumers) and `basis`. Only `sites` are call sites: refs and presence are never added to a call-site total.
//
// Sources, each filed under an ORIGIN (the library, module or owner the entry belongs to):
//   imports  the import table. Origin = the library that provides the function: PE the DLL of the import descriptor, ELF the file named by
//            symbol versioning (libc.so.6), Mach-O the dylib named by the symbol's library ordinal. Imports without a recorded provider
//            (unversioned ELF symbols, flat-namespace Mach-O symbols) go under one origin, `unattributed`.
//   go       function names of the pclntab (Go binaries import nothing). Origin = the module that DEFINES the function (`Go standard
//            library`, or a dependency's module path). This is who owns the function, not who calls it: there is no call graph.
//   rust     std source paths and crate paths left in panic messages. Origin = `Rust standard library` or the crate.
//   source   text of a package's own source files (ubel-package): modules and calls the code refers to. Origin = where the file runs or lives.
//   bundle   text of packaged applications (Node pkg / SEA / Bun, PyInstaller). Origin = the owner of the file or module.
//
// Import names are normalised before matching: `@GLIBC_2.2.5` version suffixes, the leading underscore of Mach-O symbols, glibc's `64` /
// `_chk` / `__isoc99_` variants and, for PE, the ANSI/wide `A` / `W` suffix, so CreateProcessW, _CreateProcessA and `execve@GLIBC_2.2.5`
// all land on the same table entry.

import { splitGoName } from './gosyms.js';

export const NATIVE_BEHAVIOR_LABELS = {
  file_io: 'File access',
  network: 'Network',
  process: 'Process execution',
  dynamic_loading: 'Dynamic loading / resolution',
  injection: 'Debugging / process injection',
  anti_analysis: 'Anti-analysis',
  privilege: 'Privilege',
  persistence: 'Persistence',
  input_capture: 'Input capture / sensitive devices',
  crypto: 'Cryptography',
  system_info: 'System information',
  credentials: 'Credentials / secrets access',
  obfuscation: 'Obfuscation / encoded payloads',
};

export const NATIVE_BEHAVIOR_INFO = {
  file_io: { about: 'Creates, opens, moves and deletes files and directories. Check that sensitive data is not written to shared or predictable locations; together with Cryptography and mass deletion calls it is also the shape of ransomware.',
    rules: /^binary\.risky\.insecure_tmp$/ },
  network: { about: 'Opens sockets, resolves names and uses HTTP / TLS client APIs. Check which hosts are contacted, that TLS is verified, and that nothing sensitive leaves in clear text.',
    rules: null },
  process: { about: 'Starts other programs or hands a string to a shell. Rare in libraries, common in installers and launchers; check that no external input reaches the command line.',
    rules: /^binary\.risky\.cmd_exec$/ },
  dynamic_loading: { about: 'Loads libraries and resolves functions by name at run time (dlopen / dlsym, LoadLibrary / GetProcAddress). Also how a program hides what it calls from the import table: a short import list next to many of these is worth a closer look.',
    rules: /^binary\.(rpath|no_relro|partial_relro)$/ },
  injection: { about: 'Debugger and cross-process memory APIs (ptrace, WriteProcessMemory, CreateRemoteThread, task_for_pid) and calls that make memory executable. Normal for debuggers and security tools; in anything else it is the toolset of code injection.',
    rules: /^binary\.(wx_segment|exec_stack|macho\.(get_task_allow|dangerous_entitlement))$/ },
  anti_analysis: { about: 'Checks whether a debugger is attached (IsDebuggerPresent, NtQueryInformationProcess, ...). Used by copy protection and by malware to change behaviour under analysis.',
    rules: null },
  privilege: { about: 'Changes user or group identity, adjusts tokens and privileges, changes the root directory or namespaces. Check that each use is expected for a program of this kind.',
    rules: null },
  persistence: { about: 'Installs services, writes registry values (autorun keys), registers launch items or hooks. Check that each use is expected for a program of this kind, and that the file is signed.',
    rules: /^binary\.(unsigned|macho\.adhoc_signed)$/ },
  input_capture: { about: 'Reads keystrokes, the clipboard, the screen, camera, microphone or location. Each should match a feature the user can see.',
    rules: null },
  crypto: { about: 'Imports cryptographic primitives and key-management APIs. Check algorithm choice and key handling; weak primitives are reported separately as findings.',
    rules: /^binary\.risky\.weak_crypto$/ },
  system_info: { about: 'Reads host, user and network-interface identity. Normal for diagnostics and licensing; also the first step of reconnaissance and host fingerprinting.',
    rules: null },
  credentials: { about: 'Reads credential stores (SSH keys, cloud and registry tokens, browser profiles, wallets), secret-named environment variables or the whole environment. Filled by the source scanner of `ubel-package`; a build tool reading its own token is normal, a library collecting every variable is not.',
    rules: /^package\.code\.credential_access$/ },
  obfuscation: { about: 'Evaluates or executes decoded data (base64 / hex / zlib into eval, exec or Function) and ships packer or obfuscator output. Filled by the source scanner of `ubel-package`. Legitimate for a few minified bundles; in an install-time script it is the usual way to hide a payload.',
    rules: /^package\.code\.obfuscated$/ },
};

// ── tables ────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
// category -> names. A name is listed once; PE names are written without the A / W suffix.
const TABLE = {
  file_io: [
    'open', 'openat', 'creat', 'fopen', 'freopen', 'unlink', 'unlinkat', 'remove', 'rename', 'renameat', 'mkdir', 'mkdirat', 'rmdir', 'opendir', 'readdir',
    'chmod', 'fchmod', 'chown', 'fchown', 'truncate', 'ftruncate', 'symlink', 'link', 'realpath',
    'CreateFile', 'CreateFile2', 'DeleteFile', 'MoveFile', 'MoveFileEx', 'CopyFile', 'CopyFileEx', 'FindFirstFile', 'FindFirstFileEx', 'FindNextFile', 'RemoveDirectory',
    'CreateDirectory', 'CreateDirectoryEx', 'SetFileAttributes', 'NtCreateFile', 'NtOpenFile', 'NtDeleteFile', 'SHFileOperation', 'ZwCreateFile', 'OBJC_CLASS_$_NSFileManager',
  ],
  network: [
    'socket', 'connect', 'bind', 'listen', 'accept', 'accept4', 'send', 'sendto', 'sendmsg', 'recv', 'recvfrom', 'recvmsg', 'getaddrinfo', 'gethostbyname', 'gethostbyname2',
    'getnameinfo', 'getpeername', 'inet_pton', 'inet_addr', 'curl_easy_init', 'curl_easy_perform', 'SSL_connect', 'SSL_accept', 'SSL_CTX_new', 'gnutls_handshake', 'tls_connect',
    'WSAStartup', 'WSASocket', 'WSAConnect', 'WSASend', 'WSARecv', 'WSAAccept', 'DnsQuery', 'DnsQuery_', 'InternetOpen', 'InternetOpenUrl', 'InternetConnect', 'InternetReadFile',
    'HttpOpenRequest', 'HttpSendRequest', 'URLDownloadToFile', 'URLDownloadToCacheFile', 'WinHttpOpen', 'WinHttpConnect', 'WinHttpOpenRequest', 'WinHttpSendRequest',
    'WinHttpReadData', 'WinHttpWebSocketCompleteUpgrade', 'GetAddrInfoEx', 'WSALookupServiceBegin', 'InternetCrackUrl',
    'OBJC_CLASS_$_NSURLSession', 'OBJC_CLASS_$_NSURLConnection', 'OBJC_CLASS_$_NSURLRequest', 'CFStreamCreatePairWithSocketToHost', 'CFReadStreamCreateWithSocket',
    'nw_connection_create', 'nw_connection_start',
  ],
  process: [
    'execve', 'execv', 'execvp', 'execvpe', 'execl', 'execlp', 'execle', 'fexecve', 'execveat', 'fork', 'vfork', 'posix_spawn', 'posix_spawnp', 'system', 'popen', 'wordexp',
    'CreateProcess', 'CreateProcessAsUser', 'CreateProcessWithLogon', 'CreateProcessWithToken', 'ShellExecute', 'ShellExecuteEx', 'WinExec', 'NtCreateUserProcess', 'NtCreateProcess',
    '_popen', '_wpopen', '_system', '_wsystem', '_spawnl', '_spawnv', '_spawnlp', '_spawnvp', '_execl', '_execv', '_wspawnl', '_wspawnv', '_wexecl', '_wexecv',
    'OBJC_CLASS_$_NSTask', 
  ],
  dynamic_loading: [
    'dlopen', 'dlsym', 'dlmopen', 'dlvsym', 'NSAddImage', 'NSLookupSymbolInImage',
    'LoadLibrary', 'LoadLibraryEx', 'GetProcAddress', 'LdrLoadDll', 'LdrGetProcedureAddress', 'LdrGetDllHandle', 
    
  ],
  injection: [
    'ptrace', 'process_vm_writev', 'process_vm_readv', 'memfd_create', 'mprotect', 'pkey_mprotect', 'userfaultfd', 'kcmp',
    'VirtualAllocEx', 'VirtualProtect', 'VirtualProtectEx', 'WriteProcessMemory', 'ReadProcessMemory', 'CreateRemoteThread', 'CreateRemoteThreadEx', 'NtWriteVirtualMemory', 'NtReadVirtualMemory',
    'NtCreateThreadEx', 'NtProtectVirtualMemory', 'NtMapViewOfSection', 'NtUnmapViewOfSection', 'ZwUnmapViewOfSection', 'ZwWriteVirtualMemory', 'QueueUserAPC', 'NtQueueApcThread',
    'SetThreadContext', 'GetThreadContext', 'OpenProcess', 'NtOpenProcess', 'DebugActiveProcess', 'WaitForDebugEvent', 'ContinueDebugEvent',
    'task_for_pid', 'mach_vm_write', 'mach_vm_read', 'mach_vm_protect', 'mach_vm_allocate', 'vm_write', 'vm_protect', 'thread_create_running', 'thread_set_state',
  ],
  anti_analysis: [
    'IsDebuggerPresent', 'CheckRemoteDebuggerPresent', 'NtQueryInformationProcess', 'ZwQueryInformationProcess', 'NtSetInformationThread', 'OutputDebugString', 'DebugBreak',
    'NtQuerySystemInformation', 
  ],
  privilege: [
    'setuid', 'setgid', 'seteuid', 'setegid', 'setreuid', 'setregid', 'setresuid', 'setresgid', 'setgroups', 'initgroups', 'chroot', 'capset', 'unshare', 'setns', 'pivot_root', 'mount', 'umount2',
    'seccomp', 'AuthorizationExecuteWithPrivileges',
    'AdjustTokenPrivileges', 'OpenProcessToken', 'ImpersonateLoggedOnUser', 'DuplicateToken', 'DuplicateTokenEx', 'LogonUser', 'SetTokenInformation', 'LookupPrivilegeValue', 'RtlAdjustPrivilege',
  ],
  persistence: [
    'SMJobBless', 'SMLoginItemSetEnabled', 'launch_msg',
    'RegSetValue', 'RegSetValueEx', 'RegSetKeyValue', 'RegCreateKey', 'RegCreateKeyEx', 'RegDeleteKey', 'RegDeleteValue', 'NtSetValueKey', 'ZwSetValueKey',
    'CreateService', 'OpenSCManager', 'OpenService', 'StartService', 'ChangeServiceConfig', 'ControlService', 'DeleteService', 'SetWindowsHookEx',
  ],
  input_capture: [
    'GetAsyncKeyState', 'GetKeyboardState', 'SetWindowsHookEx', 'RegisterRawInputDevices', 'GetRawInputData', 'GetClipboardData', 'OpenClipboard', 'SetClipboardData',
    'PrintWindow', 'waveInOpen', 'mciSendString', 'capCreateCaptureWindow', 
    'XGrabKeyboard', 'XQueryKeymap', 'XGetImage', 'XRecordEnableContext', 'XTestFakeKeyEvent', 'xcb_get_image', 'snd_pcm_open', 'pa_simple_new', 'v4l2_open', 'pa_stream_new',
    'CGEventTapCreate', 'CGWindowListCreateImage', 'CGDisplayCreateImage', 'IOHIDManagerCreate', 'AudioQueueNewInput', 'AudioUnitInitialize',
    'OBJC_CLASS_$_AVCaptureDevice', 'OBJC_CLASS_$_AVCaptureSession', 'OBJC_CLASS_$_CLLocationManager', 'OBJC_CLASS_$_UIPasteboard', 'OBJC_CLASS_$_NSPasteboard', 'OBJC_CLASS_$_CBCentralManager',
    'OBJC_CLASS_$_CNContactStore', 'OBJC_CLASS_$_PHPhotoLibrary', 'OBJC_CLASS_$_ABAddressBook',
  ],
  crypto: [
    'EVP_EncryptInit_ex', 'EVP_DecryptInit_ex', 'EVP_CipherInit_ex', 'EVP_CIPHER_CTX_new', 'EVP_aes_128_cbc', 'EVP_aes_256_cbc', 'EVP_aes_256_gcm', 'EVP_aes_128_gcm', 'EVP_chacha20_poly1305',
    'EVP_PKEY_encrypt', 'EVP_PKEY_decrypt', 'EVP_PKEY_derive', 'EVP_SignFinal', 'EVP_DigestSignInit', 'EVP_DigestVerifyInit', 'AES_encrypt', 'AES_decrypt', 'AES_set_encrypt_key', 'RSA_public_encrypt',
    'RSA_private_decrypt', 'RSA_generate_key_ex', 'RAND_bytes', 'gcry_cipher_open', 'gnutls_cipher_init', 'mbedtls_aes_crypt_cbc', 'mbedtls_gcm_crypt_and_tag', 'mbedtls_pk_parse_key',
    'crypto_secretbox_easy', 'crypto_aead_chacha20poly1305_ietf_encrypt', 'crypto_box_easy', 'crypto_sign', 'nettle_aes_encrypt', 'getrandom',
    'CryptAcquireContext', 'CryptEncrypt', 'CryptDecrypt', 'CryptGenKey', 'CryptImportKey', 'CryptDeriveKey', 'CryptProtectData', 'CryptUnprotectData', 'CryptGenRandom', 'CryptCreateHash',
    'BCryptEncrypt', 'BCryptDecrypt', 'BCryptGenerateSymmetricKey', 'BCryptOpenAlgorithmProvider', 'BCryptGenRandom', 'BCryptGenerateKeyPair', 'NCryptEncrypt', 'NCryptOpenStorageProvider', 'RtlGenRandom',
    'CCCrypt', 'CCCryptorCreate', 'CCKeyDerivationPBKDF', 'SecKeyCreateEncryptedData', 'SecKeyCreateDecryptedData', 'SecKeyCreateSignature', 'SecKeyGeneratePair', 'SecRandomCopyBytes', 'SecItemAdd',
    'SecItemCopyMatching',
  ],
  system_info: [
    'gethostname', 'uname', 'getlogin', 'getlogin_r', 'getpwuid', 'getpwnam', 'getpwuid_r', 'sysinfo', 'getifaddrs', 'gethostid', 'getdomainname', 
    'GetComputerName', 'GetComputerNameEx', 'GetUserName', 'GetUserNameEx', 'GetSystemInfo', 'GetNativeSystemInfo', 'GetVersionEx', 'RtlGetVersion', 'GetAdaptersInfo', 'GetAdaptersAddresses',
    'GetVolumeInformation', 'GetSystemDefaultLangID', 'GetKeyboardLayout', 'GlobalMemoryStatusEx', 'NetWkstaGetInfo', 'NetUserEnum', 'NetShareEnum', 'WNetEnumResource', 'GetLogicalDrives',
    'OBJC_CLASS_$_UIDevice', 'OBJC_CLASS_$_NSHost', 'OBJC_CLASS_$_ASIdentifierManager', 'IOServiceGetMatchingService', 'IORegistryEntryCreateCFProperty',
  ],
};

// The table leaves out functions nearly every program imports for housekeeping (sysconf, getuid, GetTickCount, GetModuleHandle ...). A few
// that remain (mprotect, GetProcAddress, LoadLibrary, OpenProcess) are imported by ordinary programs too, which is why the report presents
// the result as an inventory next to the findings and never as a finding of its own.

// A name can belong to more than one category (SetWindowsHookEx installs hooks that persist and hooks that read keystrokes).
const EXTRA = { SetWindowsHookEx: ['input_capture'] };
const LOOKUP = new Map();
for (const [cat, names] of Object.entries(TABLE)) for (const n of names) { const l = LOOKUP.get(n); if (!l) LOOKUP.set(n, [cat]); else if (!l.includes(cat)) l.push(cat); }
for (const [n, cats] of Object.entries(EXTRA)) { const l = LOOKUP.get(n) || []; for (const c of cats) if (!l.includes(c)) l.push(c); LOOKUP.set(n, l); }

// Whole families that are listed as a prefix instead of name by name (WinHttp*, CreateProcess*, EVP_* ...). Tried only when no exact
// name matched. The Windows ones apply to PE imports only.
const PREFIXES = [
  ['EVP_', 'crypto'], ['BCrypt', 'crypto'], ['NCrypt', 'crypto'], ['CCCrypt', 'crypto'],
];
const WINDOWS_PREFIXES = [
  ['WinHttp', 'network'], ['Internet', 'network'], ['WSA', 'network'], ['CreateProcess', 'process'], ['ShellExecute', 'process'],
  ['RegSetValue', 'persistence'], ['CreateService', 'persistence'],
];

/** Candidate table keys for one imported symbol name, most specific first. */
export function nameCandidates(raw, { windows = false } = {}) {
  let n = String(raw || '').replace(/@.*$/, '').replace(/^\.+/, '');         // `execve@GLIBC_2.2.5`, `.memcpy`
  if (!n) return [];
  const out = new Set([n]);
  const bare = n.replace(/^_+/, '');                                          // Mach-O `_socket`, `__imp_` is handled below
  out.add(bare);
  out.add(n.replace(/^__imp_/, '').replace(/^_+/, ''));
  out.add(bare.replace(/^isoc99_|^isoc23_/, ''));                             // __isoc99_sscanf, __isoc23_strtol
  out.add(bare.replace(/_chk$/, ''));                                         // __printf_chk -> printf
  out.add(bare.replace(/64$/, ''));                                           // open64, fopen64
  if (windows) {
    for (const x of [n, bare]) {
      out.add(x.replace(/(?:A|W)$/, ''));                                     // CreateProcessW -> CreateProcess
      out.add(x.replace(/(?:ExA|ExW)$/, 'Ex'));                               // MoveFileExW -> MoveFileEx
    }
  }
  return [...out].filter(Boolean);
}

/** Categories of one imported function name (usually one), or []. */
export function categoriesOf(raw, opts = {}) {
  const cands = nameCandidates(raw, opts);
  for (const c of cands) { const cats = LOOKUP.get(c); if (cats) return cats; }
  for (const c of cands) for (const [p, cat] of PREFIXES) if (c.startsWith(p)) return [cat];
  if (opts.windows) for (const c of cands) for (const [p, cat] of WINDOWS_PREFIXES) if (c.startsWith(p)) return [cat];
  return [];
}

/** First category of one imported function name, or null. */
export function categoryOf(raw, opts = {}) { return categoriesOf(raw, opts)[0] || null; }

const MAX_APIS = 60;
const UNATTRIBUTED = 'unattributed';

// ── Go: functions of the pclntab ───────────────────────────────────────────────────────────────────────────────────────────────
// [category, test over `pkg` and `fn` (receiver folded: `(*Cmd).Start` is `Cmd.Start`)]. Entries name the function that DOES the thing, so
// a hit says that this function is linked; with no call graph it cannot say who calls it. The linker drops functions nothing references,
// which is what makes the list informative, but the standard library itself references some of them (os.Open, for time zones and root
// certificates), so a short list from the `os` package alone is normal.
const PKG = 2;                                                                       // a rule that returns PKG lists the package, not each of its functions
const pkgIs = re => p => (re.test(p) ? PKG : 0);
const GO_RULES = [
  ['file_io', (p, f) => (p === 'os' && /^(Open|OpenFile|Create|CreateTemp|Remove|RemoveAll|Rename|Mkdir|MkdirAll|MkdirTemp|ReadFile|WriteFile|ReadDir|Chmod|Chown|Chtimes|Symlink|Link|Truncate)$/.test(f))
    || (p === 'io/ioutil' && /^(ReadFile|WriteFile|ReadDir|TempFile|TempDir)$/.test(f)) || (p === 'path/filepath' && /^(Walk|WalkDir|Glob)$/.test(f))],
  ['network', (p, f) => (p === 'net' && /^(Dial|DialTimeout|DialTCP|DialUDP|DialIP|DialUnix|Listen|ListenTCP|ListenUDP|ListenPacket|ListenUnix|LookupHost|LookupIP|LookupAddr|LookupCNAME|LookupMX|LookupTXT|LookupSRV|ResolveTCPAddr|ResolveUDPAddr|Dialer\.Dial(Context)?|ListenConfig\.Listen(Packet)?|Resolver\.Lookup\w+)$/.test(f))
    || (p === 'net/http' && /^(Get|Post|PostForm|Head|ListenAndServe|ListenAndServeTLS|Serve|NewRequest|NewRequestWithContext|Client\.(Do|Get|Post|Head)|Server\.(ListenAndServe|ListenAndServeTLS|Serve)|Transport\.RoundTrip)$/.test(f))
    || (p === 'crypto/tls' && /^(Dial|DialWithDialer|Client|Server|Listen)$/.test(f)) || (p === 'net/smtp' && /^(SendMail|Dial)$/.test(f)) || pkgIs(/^(net\/rpc|net\/http\/httputil|golang\.org\/x\/net\/websocket|github\.com\/gorilla\/websocket|nhooyr\.io\/websocket|github\.com\/miekg\/dns|github\.com\/quic-go\/quic-go|google\.golang\.org\/grpc)$/)(p)],
  ['process', (p, f) => (p === 'os/exec' && /^(Command|CommandContext|Cmd\.(Start|Run|Output|CombinedOutput))$/.test(f)) || (p === 'os' && /^(StartProcess|Exec)$/.test(f))
    || (/^(syscall|golang\.org\/x\/sys\/(unix|windows))$/.test(p) && /^(Exec|ForkExec|StartProcess|CreateProcess|CreateProcessAsUser|ShellExecute)$/.test(f))],
  ['dynamic_loading', (p, f) => (p === 'plugin' && /^(Open|Plugin\.Lookup)$/.test(f)) || (/^(syscall|golang\.org\/x\/sys\/windows)$/.test(p) && /^(LoadLibrary|LoadLibraryEx|LoadDLL|MustLoadDLL|NewLazyDLL|NewLazySystemDLL|GetProcAddress|DLL\.FindProc|LazyDLL\.NewProc|LazyProc\.Call|Proc\.Call)$/.test(f))
    || (p === 'github.com/ebitengine/purego' && /^(Dlopen|Dlsym|OpenLibrary|RegisterLibFunc|RegisterFunc)$/.test(f))],
  ['injection', (p, f) => (/^(syscall|golang\.org\/x\/sys\/unix)$/.test(p) && /^(Ptrace\w*|Mprotect|MemfdCreate|ProcessVMWritev|ProcessVMReadv|PtraceAttach|PtraceSyscall)$/.test(f))
    || (p === 'golang.org/x/sys/windows' && /^(VirtualAllocEx|VirtualProtect|VirtualProtectEx|WriteProcessMemory|ReadProcessMemory|CreateRemoteThread|CreateRemoteThreadEx|OpenProcess|QueueUserAPC|NtCreateThreadEx|SetThreadContext|DebugActiveProcess)$/.test(f))],
  ['privilege', (p, f) => (/^(syscall|golang\.org\/x\/sys\/unix)$/.test(p) && /^(Setuid|Setgid|Seteuid|Setegid|Setreuid|Setregid|Setresuid|Setresgid|Setgroups|Chroot|Unshare|Setns|PivotRoot|Mount|Unmount|Capset|Prctl)$/.test(f))
    || (p === 'golang.org/x/sys/windows' && /^(AdjustTokenPrivileges|OpenProcessToken|LookupPrivilegeValue|DuplicateTokenEx|ImpersonateSelf|SetTokenInformation|CreateProcessAsUser)$/.test(f))],
  ['persistence', (p, f) => (p === 'golang.org/x/sys/windows/registry' && /^(Key\.(SetStringValue|SetDWordValue|SetQWordValue|SetBinaryValue|SetExpandStringValue|SetStringsValue|DeleteValue)|CreateKey)$/.test(f))
    || (p === 'golang.org/x/sys/windows/svc/mgr' && /^(Mgr\.CreateService|Service\.UpdateConfig|Service\.Delete)$/.test(f)) || pkgIs(/^(github\.com\/kardianos\/service|github\.com\/emersion\/go-autostart|github\.com\/ProtonMail\/go-autostart)$/)(p)],
  ['input_capture', (p, f) => pkgIs(/^(github\.com\/atotto\/clipboard|golang\.design\/x\/clipboard|github\.com\/kbinani\/screenshot|github\.com\/go-vgo\/robotgo|github\.com\/robotn\/gohook|github\.com\/MarinX\/keylogger|github\.com\/moutend\/go-hook|github\.com\/gen2brain\/malgo|github\.com\/gordonklaus\/portaudio|github\.com\/vladimirvivien\/go4vl|github\.com\/blackjack\/webcam)(?:\/.*)?$/)(p)],
  ['crypto', (p) => pkgIs(/^(crypto\/(aes|cipher|des|rc4|rsa|ecdsa|ecdh|ed25519|elliptic|hmac|md5|sha1|sha256|sha512|sha3|subtle|rand|x509|tls|dsa|hkdf|pbkdf2)|golang\.org\/x\/crypto(\/.*)?|github\.com\/(ProtonMail\/go-crypto|cloudflare\/circl|aead\/chacha20poly1305|minio\/sio)(\/.*)?|filippo\.io\/(age|edwards25519)(\/.*)?)$/)(p)],
  ['system_info', (p, f) => (p === 'os' && /^(Hostname|UserHomeDir|UserCacheDir|UserConfigDir|Getuid|Geteuid|Getgid|Getpid|Getppid|Executable|Environ)$/.test(f)) || (p === 'os/user' && /^(Current|Lookup|LookupId|LookupGroup)$/.test(f))
    || (p === 'net' && /^(Interfaces|InterfaceAddrs|Interface\.Addrs)$/.test(f)) || (/^(syscall|golang\.org\/x\/sys\/unix)$/.test(p) && /^(Uname|Sysinfo)$/.test(f))
    || pkgIs(/^(github\.com\/shirou\/gopsutil(\/v\d+)?(\/.*)?|github\.com\/denisbrodbeck\/machineid|github\.com\/zcalusic\/sysinfo|github\.com\/elastic\/go-sysinfo(\/.*)?)$/)(p)],
];
const GO_STD = 'Go standard library';

/** Which module of the build owns a package: a module of the build info (longest path prefix), else the standard library, else the package itself. */
function goOwner(pkg, modules) {
  let best = null;
  for (const m of modules) if ((pkg === m || pkg.startsWith(`${m}/`)) && (!best || m.length > best.length)) best = m;
  if (best) return best;
  const first = pkg.split('/')[0];
  return first === 'vendor' || !first.includes('.') ? GO_STD : pkg;           // the first path element of a standard-library package has no dot
}

// ── Rust: std and crate paths left in panic messages ─────────────────────────────────────────────────────────────────────────────
const RUST_STD = [
  ['file_io', 'std::fs', /(?:^|\/)(?:fs|fs\/[\w.]+|sys\/(?:pal\/)?[a-z]+\/fs|os\/[a-z]+\/fs)\.rs$/],
  ['network', 'std::net', /(?:^|\/)(?:net(?:\/[\w.]+)?|sys\/(?:pal\/)?[a-z]+\/net|os\/[a-z]+\/net(?:\/[\w.]+)?)\.rs$/],
  ['process', 'std::process', /(?:^|\/)(?:process|sys\/(?:pal\/)?[a-z]+\/process(?:\/[\w.]+)?|os\/[a-z]+\/process)\.rs$/],
  ['system_info', 'std::env', /^sys\/(?:pal\/)?[a-z]+\/os\.rs$/],
];
const RUST_CRATES = {
  network: ['reqwest', 'hyper', 'hyper-util', 'ureq', 'surf', 'isahc', 'curl', 'attohttpc', 'tungstenite', 'tokio-tungstenite', 'tonic', 'socket2', 'h2', 'quinn', 'trust-dns-resolver', 'hickory-resolver', 'actix-web', 'axum', 'warp', 'rocket', 'lettre', 'suppaftp', 'ssh2', 'russh', 'libp2p'],
  process: ['duct', 'subprocess', 'shared_child', 'command-group'],
  dynamic_loading: ['libloading', 'dlopen', 'dlopen2'],
  injection: ['region', 'process-memory', 'proc-maps', 'memflow', 'pete'],
  privilege: ['privdrop', 'caps'],
  persistence: ['winreg', 'auto-launch', 'service-manager', 'windows-service', 'daemonize'],
  input_capture: ['rdev', 'device_query', 'arboard', 'clipboard', 'clipboard-win', 'screenshots', 'scrap', 'xcap', 'inputbot', 'cpal', 'nokhwa', 'rscam'],
  crypto: ['ring', 'rustls', 'openssl', 'openssl-sys', 'native-tls', 'aes', 'aes-gcm', 'chacha20poly1305', 'chacha20', 'rsa', 'sodiumoxide', 'orion', 'sha2', 'sha1', 'md-5', 'hmac', 'argon2', 'pbkdf2', 'scrypt', 'bcrypt', 'ed25519-dalek', 'x25519-dalek', 'p256', 'k256', 'age'],
  system_info: ['sysinfo', 'hostname', 'whoami', 'machine-uid', 'os_info', 'mac_address', 'get_if_addrs', 'local-ip-address', 'if-addrs', 'sys-info'],
  file_io: ['walkdir', 'tempfile', 'fs_extra', 'notify', 'remove_dir_all', 'trash'],
};
const RUST_CRATE = new Map();
for (const [cat, names] of Object.entries(RUST_CRATES)) for (const n of names) if (!RUST_CRATE.has(n)) RUST_CRATE.set(n, cat);
const RUST_STD_NAME = 'Rust standard library';

// ── packaged applications: text of the bundled sources ─────────────────────────────────────────────────────────────────────────
// [category, label, regex over one line of text]. A line is a string that was read from the application's own files, so a hit shows that
// the code refers to the module or call, not that the line runs.
const Q = '[\'"`]';
const JS_RULES = [
  ['process', 'child_process', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?child_process${Q}|\\bchild_process\\.\\w+|\\bprocess\\.binding\\(${Q}spawn_sync${Q}\\)`)],
  ['network', 'net / tls / dgram', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?(?:net|tls|dgram)${Q}`)],
  ['network', 'http / https / http2', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?https?2?${Q}|\\b(?:https?|http2)\\.(?:request|get|createServer|connect)\\(`)],
  ['network', 'dns', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?dns(?:\\/promises)?${Q}`)],
  ['network', 'WebSocket', /\bnew\s+WebSocket(?:Server)?\(/],
  ['file_io', 'fs', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?fs(?:\\/promises)?${Q}|\\bfs\\.(?:readFile|writeFile|appendFile|unlink|rm|rmdir|mkdir|rename|createWriteStream|createReadStream|readdir)(?:Sync)?\\(`)],
  ['dynamic_loading', 'process.dlopen', /\bprocess\.dlopen\(/],
  ['dynamic_loading', 'vm', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?vm${Q}|\\bvm\\.(?:runIn\\w+|Script)\\b`)],
  ['dynamic_loading', 'eval / new Function', /(?:^|[^\w.$])eval\(|\bnew\s+Function\(/],
  ['crypto', 'crypto', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?crypto${Q}|\\bcrypto\\.(?:createCipheriv|createDecipheriv|createHash|createHmac|createSign|privateEncrypt|publicEncrypt|subtle)\\b`)],
  ['system_info', 'os', new RegExp(`(?:require\\(\\s*|from\\s*|import\\(\\s*)${Q}(?:node:)?os${Q}|\\bos\\.(?:hostname|userInfo|networkInterfaces|cpus|platform)\\(`)],
  ['privilege', 'process.setuid / setgid', /\bprocess\.(?:setuid|setgid|seteuid|setegid|setgroups|initgroups)\(/],
  ['input_capture', 'clipboard / screen capture', new RegExp(`${Q}(?:clipboardy|copy-paste|screenshot-desktop|robotjs|iohook|node-global-key-listener|desktop-screenshot)${Q}`)],
];
// Python modules ship as marshalled code objects, which hold names as separate short strings: `import socket` leaves the string `socket`,
// and `os.system(...)` leaves `os` and `system` apart. So each rule has a text regex (source text, or a string constant that spells the call out)
// and a list of module NAMES matched against those short strings. `os.system` is therefore only seen where it is written out in text.
const PY_RULES = [
  ['process', 'subprocess', /(?:import\s+subprocess|from\s+subprocess\s+import|subprocess\.(?:Popen|run|call|check_call|check_output|getoutput))\b/, ['subprocess']],
  ['process', 'os.system / os.popen / os.exec*', /\bos\.(?:system|popen|execv\w*|execl\w*|spawn\w+|startfile)\b|\bpty\.spawn\b/, []],
  ['network', 'socket', /(?:import\s+socket|from\s+socket\s+import|socket\.(?:socket|create_connection|getaddrinfo|gethostbyname))\b/, ['socket', 'socketserver']],
  ['network', 'urllib / requests / ssl / ftplib / smtplib', /(?:import|from)\s+(?:urllib|http\.(?:client|server)|requests|httpx|aiohttp|ssl|ftplib|smtplib|telnetlib|paramiko)\b/, ['urllib', 'requests', 'httpx', 'aiohttp', 'ssl', 'ftplib', 'smtplib', 'telnetlib', 'paramiko']],
  ['dynamic_loading', 'ctypes / cffi', /(?:import\s+ctypes|from\s+ctypes\s+import|ctypes\.(?:CDLL|WinDLL|windll|cdll|cast|CFUNCTYPE)|import\s+cffi)\b/, ['ctypes', 'cffi']],
  ['dynamic_loading', 'importlib / __import__ / exec / eval', /(?:^|[^\w.])(?:__import__|importlib\.import_module|exec|eval)\(/, ['importlib', '__import__']],
  ['file_io', 'os / shutil file operations', /\b(?:os\.(?:remove|unlink|rmdir|rename|makedirs|chmod|chown|symlink)|shutil\.(?:rmtree|copy\w*|move))\b/, ['shutil']],
  ['crypto', 'hashlib / cryptography', /(?:import|from)\s+(?:hashlib|hmac|secrets|cryptography|Crypto|nacl)\b/, ['hashlib', 'hmac', 'cryptography', 'Crypto', 'nacl']],
  ['system_info', 'platform / getpass', /(?:import|from)\s+(?:platform|getpass)\b|\bsocket\.gethostname\b|\bgetpass\.getuser\b/, ['platform', 'getpass']],
  ['input_capture', 'pynput / pyperclip / pyautogui', /(?:import|from)\s+(?:pynput|pyperclip|pyautogui|PIL\.ImageGrab|pyaudio)\b/, ['pynput', 'pyperclip', 'pyautogui', 'pyaudio']],
  ['privilege', 'os.setuid / setgid', /\bos\.(?:setuid|setgid|seteuid|setegid|setgroups|chroot)\b/, []],
  ['persistence', 'winreg', /(?:import|from)\s+(?:winreg|_winreg)\b/, ['winreg', '_winreg']],
];
// A marshalled name is followed by the next object's type byte (and maybe the first printable bytes of its index): `socketr!` is `socket`.
const tokenIs = (tok, name) => tok === name || (tok.length > name.length && tok.length <= name.length + 4 && tok.startsWith(name) && /^[rZzaAtu)(\]][\x21-\x7e]{0,3}$/.test(tok.slice(name.length)));

/** `// node_modules/@scope/pkg/lib/x.js` → the package name of a bundler marker comment, or null for an application file marker. */
const MARKER = /^\s*\/\/\s+((?:[\w@.~+\-]+\/)*[\w@.~+\-]+\.(?:[cm]?[jt]sx?|json|node))\s*$/;
const NM = /(?:^|\/)node_modules\/((?:@[^/]+\/)?[^/]+)\//g;
/** Package that owns a path (the innermost node_modules directory), or null. */
const npmOwner = path => { let last = null; for (const m of String(path).replace(/\\/g, '/').matchAll(NM)) last = m[1]; return last; };

/**
 * Owner of a source the packagers return, from its report path (`app.exe!/snapshot/app/node_modules/express/index.js`, `app!PYZ/requests.api`).
 * @returns {{lang:'js'|'py', owner:string|null, skip?:boolean}} owner null = a whole bundle that is split by its own markers; skip = leave the source out
 */
export function sourceOwner(path, lang) {
  const rest = String(path).slice(String(path).indexOf('!') + 1);
  // A top-level module with a leading underscore is a private helper of the standard library (`_compat_pickle` spells out `socket`, `subprocess`
  // and `winreg` as data) or a compiled extension; its text says nothing about what the application does, so it is skipped.
  if (lang === 'py') { const m = /^PYZ\/([^./\\]+)/.exec(rest); return { lang, owner: m ? m[1] : 'app', skip: Boolean(m && m[1].startsWith('_')) }; }
  if (/^(?:Node SEA blob|Bun module graph)$/.test(rest)) return { lang, owner: null };
  return { lang, owner: npmOwner(rest) || 'app' };
}

export class BehaviorBuilder {
  constructor() { this.found = new Map(); this.kinds = new Map(); this.sources = new Set(); this.imports = 0; this.counted = false; }

  /** Records one function under a category and an origin (a repeat is one entry). `kind`: what `n` counts (see the header: sites / refs / present). */
  add(cat, api, origin, source, n = 1, kind = 'present') {
    if (!NATIVE_BEHAVIOR_LABELS[cat]) return;
    const o = String(origin || UNATTRIBUTED).slice(0, 120), a = String(api).slice(0, 200);
    const byOrigin = this.found.get(cat) || this.found.set(cat, new Map()).get(cat);
    const apis = byOrigin.get(o) || byOrigin.set(o, new Map()).get(o);
    apis.set(a, (apis.get(a) || 0) + n);
    const key = `${cat}\0${o}`;
    (this.kinds.get(key) || this.kinds.set(key, new Set()).get(key)).add(kind);
    if (source) this.sources.add(source);
  }

  /**
   * Import table. `providers`: imported name -> the library that provides it (PE DLL, ELF versioned file, Mach-O dylib).
   * `sites`: the result of lib/callsites.js (direct call sites per imported name), or null; with it every entry carries its call-site count (0 =
   * imported, no direct call found), without it an entry is 1 (present). `ptrace(PTRACE_TRACEME)` is told apart from other ptrace calls only
   * with call sites: the request is the constant 0.
   * @returns {number} how many distinct names were recognised
   */
  addImports(imports, { windows = false, macho = false, providers = null, sites = null } = {}) {
    let hit = 0;
    if (sites) this.counted = true;
    const names = new Set(imports || []);
    this.imports += names.size;
    for (const raw of names) {
      const cats = categoriesOf(raw, { windows });
      if (!cats.length) continue;
      const shown = macho ? String(raw).replace(/@.*$/, '').replace(/^_/, '') : String(raw).replace(/@.*$/, '');
      const from = providers && providers.get(raw);
      let n = sites ? sites.counts.get(raw) || 0 : 1;
      if (sites && raw === 'ptrace' && sites.traceme > 0) {
        this.add('anti_analysis', 'ptrace(PTRACE_TRACEME)', from, 'imports', sites.traceme, 'sites');   // a process that traces itself: no debugger can attach
        if (n === 0) { hit++; continue; }                                                       // every ptrace call is the anti-debug one
      }
      for (const cat of cats) this.add(cat, shown, from, 'imports', n, sites ? 'sites' : 'present');
      hit++;
    }
    return hit;
  }

  /**
   * Function names of a Go pclntab. @param {string[]} names @param {{path?:string|null, modules?:{path:string}[]}} [build] Go build info
   * @returns {number} distinct functions or packages recorded
   */
  addGoFunctions(names, build = {}) {
    const modules = [...(build.modules || []).map(m => m.path), ...(build.path ? [build.path] : []), ...(build.main?.path ? [build.main.path] : [])].filter(Boolean);
    const seen = new Set();
    let n = 0;
    for (const name of names) {
      const sp = splitGoName(name);
      if (!sp) continue;
      for (const [cat, test] of GO_RULES) {
        const hit = test(sp.pkg, sp.fn);
        if (!hit) continue;
        const label = hit === PKG ? sp.pkg : `${sp.pkg}.${sp.fn}`;
        const key = `${cat}\0${label}`;
        if (seen.has(key)) break;
        seen.add(key);
        this.add(cat, label, goOwner(sp.pkg, modules), 'go', 1, 'present');
        n++;
        break;
      }
    }
    return n;
  }

  /** Std paths and crate paths from Rust panic messages. @param {string[]} strings @param {{name:string}[]} crates crates found in the paths */
  addRust(strings, crates = []) {
    let n = 0;
    const seen = new Set();
    for (const s of strings) {
      const at = s.length <= 8192 ? s.indexOf('library/std/src/') : -1;
      if (at < 0) continue;
      const rel = s.slice(at + 16).replace(/[:\s].*$/, '');
      for (const [cat, label, re] of RUST_STD) {
        if (!re.test(rel) || seen.has(label)) continue;
        seen.add(label); this.add(cat, label, RUST_STD_NAME, 'rust', 1, 'present'); n++;
      }
    }
    for (const c of crates) {
      const cat = RUST_CRATE.get(c.name);
      if (cat) { this.add(cat, c.name, c.name, 'rust', 1, 'present'); n++; }
    }
    return n;
  }

  /**
   * Text of one packaged application's file or module.
   * @param {{lang:'js'|'py', owner?:string|null, lines:string[], tokens?:string[]}} src `owner` names the file's owner; without one a JavaScript bundle is split by its
   *   bundler markers (`// node_modules/pkg/…`)
   * @returns {number} entries recorded
   */
  addBundleText({ lang, owner = null, skip = false, lines = [], tokens = [] }) {
    if (skip) return 0;
    const rules = lang === 'py' ? PY_RULES : JS_RULES;
    let n = 0, current = owner;
    const scan = (text, who) => { for (const [cat, label, re] of rules) if (re.test(text)) { this.add(cat, label, who, 'bundle', 1, 'refs'); n++; } };
    const names = lang === 'py' ? rules.map(r => r[3]) : [];
    for (const line of lines) {
      if (line.length > 4096) continue;
      if (!owner && lang === 'js') {
        const m = MARKER.exec(line);
        if (m) { current = npmOwner(m[1]) || 'app'; continue; }
      }
      scan(line, current || (lang === 'js' ? 'bundle' : 'app'));
    }
    if (lang === 'py') {
      rules.forEach(([cat, label], i) => { if (names[i].length && tokens.some(t => names[i].some(nm => tokenIs(t, nm)))) { this.add(cat, label, owner || 'app', 'bundle', 1, 'refs'); n++; } });
    }
    return n;
  }

  /** The `app.behavior` summary, or null when nothing was recognised. */
  summary() {
    if (!this.found.size) return null;
    const categories = {};
    for (const cat of Object.keys(NATIVE_BEHAVIOR_LABELS)) {
      const byOrigin = this.found.get(cat);
      if (!byOrigin) continue;
      categories[cat] = {};
      const weight = m => [...m.values()].reduce((t, v) => t + v, 0);
      for (const [origin, m] of [...byOrigin].sort((x, y) => weight(y[1]) - weight(x[1]) || x[0].localeCompare(y[0]))) {
        const apis = [...m].sort((x, y) => y[1] - x[1] || x[0].localeCompare(y[0])).slice(0, MAX_APIS);
        const kinds = this.kinds.get(`${cat}\0${origin}`) || new Set();
        categories[cat][origin] = { calls: weight(m), functions: m.size, basis: kinds.size === 1 ? [...kinds][0] : 'mixed', apis: Object.fromEntries(apis) };
      }
    }
    let functions = 0, callSites = 0;
    for (const byOrigin of Object.values(categories)) for (const o of Object.values(byOrigin)) { functions += o.functions; if (o.basis === 'sites') callSites += o.calls; }
    const order = ['imports', 'go', 'rust', 'bundle', 'source'];
    return { basis: this.counted ? 'calls' : 'presence', counted: this.counted, functions, call_sites: this.counted ? callSites : null, sources: order.filter(x => this.sources.has(x)), categories, intent_actions: {}, intent_actions_total: {}, explicit_intents: {} };
  }
}
