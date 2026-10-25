'use strict';
// behavior.js (binary) — a capability inventory of a native executable or library: what its import table says it can do (file access,
// network, process execution, dynamic loading, debugging / injection, anti-analysis, privilege and persistence, input capture and
// sensitive devices, cryptography, system fingerprinting).
//
// Same idea as mobile/lib/behavior.js, with one difference that matters when reading the result. The Android collector counts call
// SITES reported by the DEX walker. A native file has no such walker here, so this module only knows which functions are IMPORTED: a
// function in the import table is linked and callable, not proven to be called or reachable. The summary therefore counts distinct
// imported functions per category (`calls` = number of distinct imports, every api = 1) and says so (`basis: 'imports'`).
// It is a summary on the app record (`app.behavior`), never a rule hit: nearly every program does file and network I/O.
//
// Names are normalised before matching: `@GLIBC_2.2.5` version suffixes, the leading underscore of Mach-O symbols, glibc's `64` / `_chk`
// / `__isoc99_` variants and, for PE, the ANSI/wide `A` / `W` suffix, so CreateProcessW, _CreateProcessA and `execve@GLIBC_2.2.5` all
// land on the same table entry.

export const NATIVE_BEHAVIOR_LABELS = {
  file_io: 'File access',
  network: 'Network',
  process: 'Process execution',
  dynamic_loading: 'Dynamic loading / resolution',
  injection: 'Debugging / process injection',
  anti_analysis: 'Anti-analysis',
  privilege: 'Privilege and persistence',
  input_capture: 'Input capture / sensitive devices',
  crypto: 'Cryptography',
  system_info: 'System information',
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
  privilege: { about: 'Changes user or group identity, adjusts tokens and privileges, installs services or writes autorun registry keys. Check that each use is expected for a program of this kind.',
    rules: /^binary\.(unsigned|macho\.adhoc_signed)$/ },
  input_capture: { about: 'Reads keystrokes, the clipboard, the screen, camera, microphone or location. Each should match a feature the user can see.',
    rules: null },
  crypto: { about: 'Imports cryptographic primitives and key-management APIs. Check algorithm choice and key handling; weak primitives are reported separately as findings.',
    rules: /^binary\.risky\.weak_crypto$/ },
  system_info: { about: 'Reads host, user and network-interface identity. Normal for diagnostics and licensing; also the first step of reconnaissance and host fingerprinting.',
    rules: null },
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
    'seccomp', 'AuthorizationExecuteWithPrivileges', 'SMJobBless', 'SMLoginItemSetEnabled', 'launch_msg',
    'AdjustTokenPrivileges', 'OpenProcessToken', 'ImpersonateLoggedOnUser', 'DuplicateToken', 'DuplicateTokenEx', 'LogonUser', 'SetTokenInformation', 'LookupPrivilegeValue', 'RtlAdjustPrivilege',
    'RegSetValue', 'RegSetValueEx', 'RegCreateKey', 'RegCreateKeyEx', 'RegDeleteKey', 'RegDeleteValue', 'CreateService', 'OpenSCManager', 'OpenService', 'StartService', 'ChangeServiceConfig',
    'ControlService', 'DeleteService', 'SetWindowsHookEx', 'NtSetValueKey', 'ZwSetValueKey',
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

const LOOKUP = new Map();
for (const [cat, names] of Object.entries(TABLE)) for (const n of names) if (!LOOKUP.has(n)) LOOKUP.set(n, cat);

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

/** Category of one imported function name, or null. */
export function categoryOf(raw, opts = {}) {
  for (const c of nameCandidates(raw, opts)) { const cat = LOOKUP.get(c); if (cat) return cat; }
  return null;
}

const MAX_APIS = 60;

/**
 * @param {Iterable<string>} imports imported function names
 * @param {{windows?: boolean, providers?: Map<string,string>|null}} [opts] `providers`: import name -> the library that provides it (PE: the DLL)
 * @returns the `app.behavior` summary, or null when the import table holds nothing recognisable
 */
export function collectBehavior(imports, { windows = false, providers = null } = {}) {
  const found = new Map();                                                      // category -> Map(display name -> 1)
  let total = 0;
  for (const raw of new Set(imports || [])) {
    const cat = categoryOf(raw, { windows });
    if (!cat) continue;
    const from = providers && providers.get(raw);
    const label = String(raw).replace(/@.*$/, '') + (from ? ` (${from})` : '');
    const m = found.get(cat) || found.set(cat, new Map()).get(cat);
    if (!m.has(label)) { m.set(label, 1); total++; }
  }
  if (!total) return null;
  const categories = {};
  for (const cat of Object.keys(NATIVE_BEHAVIOR_LABELS)) {
    const m = found.get(cat);
    if (!m) continue;
    const apis = Object.fromEntries([...m.keys()].sort().slice(0, MAX_APIS).map(k => [k, 1]));
    categories[cat] = { app: { calls: m.size, apis } };
  }
  return { basis: 'imports', categories, intent_actions: {}, intent_actions_total: {}, explicit_intents: {} };
}
