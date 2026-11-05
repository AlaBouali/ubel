'use strict';

import { call, pattern, custom, JVM } from './helpers.js';
import { isCleared, isUsable } from '../taint.js';
import { fileText as fileTextOf } from './helpers.js';
import { accessPaths } from '../context.js';
import { m, x } from './injection.js';

const stmtOf = (flow, off) => flow.ctx.logical.find(l => off >= l.start && off < l.end);
const isLiteralOnly = (t) => !/[A-Za-z_$]/.test(t.replace(/\b(?:sizeof|NULL|true|false)\b/g, ''));

// ═══ Buffer overflow / out-of-bounds (C) ═════════════════════════════════════
const BO = { cls: 'buffer overflow / out-of-bounds access', group: 'mem', sev: 'high', fix: 'Use bounded APIs (snprintf, strlcpy/strncpy with an explicit terminator, fgets with sizeof, memcpy with a validated length) and check every length and index against the destination size before use.' };
const BOF_RULES = [
  call({ ...BO, id: 'bof-gets', langs: ['c'], need: 'always', noTaint: true, sev: 'critical', conf: 'high', args: 'any', allowNoArgs: true, callee: x('gets|_getws|getwd|tmpnam|tempnam|mktemp'), when: (c) => !/^(?:getwd|tmpnam|tempnam|mktemp)$/.test(c.callee) || true,
    title: 'Use of inherently unsafe function', desc: 'gets() (and getwd/tmpnam-style APIs) cannot be used safely: gets() has no length limit and always allows a stack/heap buffer overflow.', fix: 'Replace gets() with fgets(buf, sizeof buf, stdin); replace tmpnam/mktemp with mkstemp.' }),
  call({ ...BO, id: 'bof-strcpy', langs: ['c'], need: 'dynamic', what: 'copies into a fixed buffer with no length check', callee: x('strcpy|strcat|stpcpy|wcscpy|wcscat|lstrcpy|lstrcat|lstrcpyA|lstrcpyW|StrCpy|StrCat'),
    argsFn: (c) => [1], title: 'Unbounded string copy',
    desc: (cand) => `${cand.call.callee}() copies a string of unknown length into a buffer without a bound; if the source is longer than the destination the buffer overflows.`, sev: 'high' }),
  call({ ...BO, id: 'bof-sprintf', langs: ['c'], need: 'dynamic', what: 'formats into a fixed buffer with no length limit', callee: x('sprintf|vsprintf|swprintf_unbounded|wsprintf|wsprintfA|wsprintfW'), argsFn: (c) => c.args.map((_, i) => i).filter(i => i >= 1), title: 'Unbounded formatted write',
    when: (c) => c.args.slice(1).some(a => /%[-+ #0]*(?:\*|\d*)(?:\.\d+)?[sS]/.test(a.lit) || !/^["'][^%]*["']$/.test(a.lit.trim()) || c.args.length > 2),
    desc: (cand) => `${cand.call.callee}() writes formatted data without a size limit; a long %s argument overflows the destination buffer.` }),
  pattern({ ...BO, id: 'bof-scanf-s', langs: ['c'], noTaint: true, title: 'Unbounded %s in scanf',
    re: /\b(?:scanf|fscanf|sscanf|vscanf|vsscanf|vfscanf)\s*\([^;]*?"[^"]*%(?!\*)(?:\d*[lh]?)?s(?![^"]*%\d)[^"]*"/, check: (mm) => !/%\d+s/.test(mm[0]) && !/%\d+\[/.test(mm[0]),
    desc: 'scanf-family %s / %[ conversion without a field width writes an unbounded string into the destination buffer.', fix: 'Add a width (e.g. "%63s" for a 64-byte buffer) or read with fgets and parse.' }),
  call({ ...BO, id: 'bof-size', langs: ['c'], what: 'uses an attacker-controlled length for a memory operation', callee: x('memcpy|memmove|bcopy|strncpy|strncat|read|recv|recvfrom|pread|fread|memset|wmemcpy|memccpy|CopyMemory|RtlCopyMemory'),
    argsFn: (c) => c.name === 'fread' ? [1, 2] : c.name === 'bcopy' ? [2] : c.name === 'memccpy' ? [3] : [2], title: 'Attacker-controlled length in memory operation' }),
  custom({ ...BO, id: 'bof-index', langs: ['c'], title: 'Attacker-controlled array index',
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        if (/^\s*(?:if|while|for|switch|else)\b/.test(ll.text)) continue;
        const re = /\b[A-Za-z_]\w*(?:\s*(?:\.|->)\s*\w+)*\s*\[\s*([A-Za-z_]\w*)\s*\]/g; let mm;
        while ((mm = re.exec(ll.text)) !== null) {
          const idx = mm[1]; const v = flow.vars.get(idx); if (!v) continue;
          const src = v.contribs.find(c => c.kind === 'src' && !isCleared(c, 'mem')); if (!src) continue;
          // a bounds check on the index earlier in the function?
          const before = flow.ctx.code.slice(0, ll.start);
          const guard = new RegExp(String.raw`\b${idx}\s*(?:<|<=|>|>=|!=)\s*[\w(]|[\w)]\s*(?:<|<=|>|>=)\s*${idx}\b|\bMIN\s*\(|\bmin\s*\(|\bMAX\b|\bsizeof\b[^;]*${idx}|\b${idx}\s*%\s*\w+|\b${idx}\s*&\s*(?:0x|\d)`).test(before);
          if (guard) continue;
          emit(ll.start + mm.index, { desc: `Array index "${idx}" derives from ${src.origin} and is used without a visible bounds check.`, flowInfo: { kind: 'src', origin: src.origin }, snippet: ll.lit.trim() });
          break;
        }
      }
    } }),
];

// ═══ Format string (C) ═══════════════════════════════════════════════════════
const FS = { cls: 'format string vulnerability', group: 'fmt', sev: 'high', fix: 'Always pass a constant format string: printf("%s", user) instead of printf(user).' };
const FMT_IDX = { printf: 0, vprintf: 0, wprintf: 0, warn: 0, fprintf: 1, dprintf: 1, sprintf: 1, vsprintf: 1, vfprintf: 1, syslog: 1, err: 1, errx: 1, warnx: 0, asprintf: 1, vasprintf: 1, snprintf: 2, vsnprintf: 2, fwprintf: 1, swprintf: 2, NSLog: 0, g_printerr: 0, g_print: 0, error: 2, xasprintf: 0 };
const FORMAT_RULES = [
  call({ ...FS, id: 'fmt-c', langs: ['c'], need: 'dynamic', what: 'uses it as the format string, so %n / %s directives in the input read or write memory',
    callee: x(Object.keys(FMT_IDX).join('|')), argsFn: (c) => [FMT_IDX[c.name] ?? 0], title: 'Non-constant format string',
    when: (c) => { const a = c.args[FMT_IDX[c.name] ?? 0]; return !!a && !/^["']/.test(a.lit.trim()) },
    desc: (cand) => `${cand.call.callee}() is called with a format string that is not a literal, so any % directive inside it is interpreted (information leak or memory write via %n).` }),
];

// ═══ Integer overflow / underflow ════════════════════════════════════════════
const IO = { cls: 'integer overflow / underflow', group: 'int', sev: 'high', fix: 'Validate sizes against an upper bound and use overflow-checked arithmetic (checked_mul, Math.multiplyExact, reallocarray, __builtin_mul_overflow) before allocating or indexing.' };
const ALLOC_ARITH = (c) => c.args.some(a => /[*+]|<</.test(a.text.replace(/sizeof\s*\([^)]*\)/g, 'S')) && /[A-Za-z_]/.test(a.text.replace(/sizeof/g, '')));
const INT_RULES = [
  call({ ...IO, id: 'int-c-alloc', langs: ['c'], what: 'sizes an allocation with arithmetic on an attacker-controlled value that can wrap around', args: 'any',
    callee: x('malloc|realloc|alloca|g_malloc|g_malloc0|xmalloc|OPENSSL_malloc|kmalloc|vmalloc|av_malloc|HeapAlloc|LocalAlloc|VirtualAlloc|operator\\s*new|_alloca'), when: ALLOC_ARITH, title: 'Integer overflow in allocation size' }),
  call({ ...IO, id: 'int-rust', langs: ['rust'], what: 'uses an attacker-controlled size for an unchecked operation or allocation', args: 'any', sev: 'medium',
    callee: x('Vec::with_capacity|String::with_capacity|vec!|(?:\\w+\\.)?(?:reserve|reserve_exact|resize|unchecked_add|unchecked_sub|unchecked_mul|unchecked_shl|set_len)'), title: 'Attacker-controlled size / unchecked arithmetic' }),
  call({ ...IO, id: 'int-go', langs: ['go'], what: 'allocates or converts using an attacker-controlled size', args: 'any', sev: 'medium',
    callee: x('make|int8|int16|int32|uint8|uint16|uint32'), when: (c) => c.callee !== 'make' || c.args.length >= 2, argsFn: (c) => c.callee === 'make' ? c.args.map((_, i) => i).filter(i => i >= 1) : [0], title: 'Attacker-controlled size / narrowing conversion' }),
  call({ ...IO, id: 'int-jvm', langs: JVM, what: 'allocates a collection or buffer with an attacker-controlled size', args: [0], sev: 'medium',
    callee: x('ArrayList|StringBuilder|StringBuffer|HashMap|HashSet|ByteBuffer\\.allocate|ByteBuffer\\.allocateDirect|ByteArray|IntArray|CharArray|LongArray|ShortArray|DoubleArray|Array|Arrays\\.copyOf|Arrays\\.copyOfRange|(?:\\w+\\.)?ensureCapacity'),
    title: 'Attacker-controlled allocation size' }),
  custom({ ...IO, id: 'int-newarray', langs: ['java', 'csharp'], sev: 'medium', title: 'Attacker-controlled allocation size',
    run(flow, emit) {
      const re = /\bnew\s+(?:byte|int|char|long|short|float|double|bool|boolean|String|Object|\w+)\s*\[\s*([^\]\n]+?)\s*\]/g; let mm;
      while ((mm = re.exec(flow.ctx.code)) !== null) {
        const st = flow.state(mm[1], '', flow.ctx.lineAt(mm.index)).filter(s => !isCleared(s, 'int'));
        const src = st.find(s => s.kind === 'src') || st[0];
        if (src) emit(mm.index, { desc: `An array is allocated with a size derived from ${src.origin || 'parameter "' + src.param + '"'}, allowing huge allocations (denial of service) or size-arithmetic overflow.`, flowInfo: src.kind === 'src' ? { kind: 'src', origin: src.origin } : { kind: 'param', params: [src] } });
      }
    } }),
  call({ ...IO, id: 'int-csharp', langs: ['csharp'], what: 'allocates with an attacker-controlled size', args: [0], sev: 'medium', callee: x('Marshal\\.AllocHGlobal|Marshal\\.AllocCoTaskMem|Array\\.CreateInstance|List<[\\w.]+>|StringBuilder|MemoryStream|\\w+\\.SetLength'), when: (c) => !/^(?:List<|StringBuilder|MemoryStream)/.test(c.callee) || c.isNew, title: 'Attacker-controlled allocation size' }),
  call({ ...IO, id: 'int-swift', langs: ['swift'], what: 'allocates with an attacker-controlled size', args: 'any', sev: 'medium', callee: x('Array|Data|ContiguousArray|(?:Unsafe\\w*Pointer(?:<[\\w.]+>)?\\.allocate)|UnsafeMutablePointer<\\w+>\\.allocate|\\w+\\.allocate'), when: (c) => /(?:count|capacity|repeating)\s*:/.test(c.text), title: 'Attacker-controlled allocation size' }),
];

// ═══ Use after free / double free (C, C++, Rust) ═════════════════════════════
const UAF = { cls: 'use after free / memory safety', group: 'uaf', sev: 'high', fix: 'Set the pointer to NULL immediately after freeing it, never touch memory after release, and prefer ownership types (smart pointers, RAII, Rust ownership).' };
const DF = { cls: 'double free', group: 'uaf', sev: 'high', fix: 'Free each allocation exactly once; null the pointer after free and use RAII / ownership to track a single owner.' };
const FREE_C = /^\s*(?:\(void\)\s*)?(?:free|kfree|g_free|xfree|OPENSSL_free|av_free|av_freep|CRYPTO_free|talloc_free|delete\s*\[\s*\]|delete)\s*\(?\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?([A-Za-z_][\w]*(?:\s*(?:\.|->)\s*\w+)*)\s*\)?\s*;?\s*$/;
const FREE_RUST = /^\s*(?:unsafe\s*\{\s*)?(?:libc::free|std::ptr::drop_in_place|ptr::drop_in_place|dealloc|alloc::dealloc|std::alloc::dealloc|Box::from_raw)\s*\(\s*(?:\w+\s*\(\s*)?([A-Za-z_]\w*)/;
function freeRule(id, cls, kind) {
  return custom({ ...(kind === 'uaf' ? UAF : DF), id, cls, langs: ['c', 'rust'], title: kind === 'uaf' ? 'Use after free' : 'Double free',
    run(flow, emit) {
      const re = flow.family === 'rust' ? FREE_RUST : FREE_C;
      const L = flow.ctx.logical;
      const freed = new Map();
      const reported = new Set();
      const norm = (s) => s.replace(/\s+/g, '').replace(/->/g, '.');
      for (let i = 0; i < L.length; i++) {
        const t = L[i].text;
        const fm = re.exec(t);
        if (fm) {
          const name = norm(fm[1]);
          if (freed.has(name)) {
            if (kind === 'df') emit(L[i].start, { desc: `"${fm[1].trim()}" is freed again at this point; it was already freed on line ${freed.get(name).abs}. A double free corrupts the allocator state.`, snippet: L[i].lit.trim() });
            freed.delete(name);
          } else {
            const next = L[i + 1]?.text || '';
            if (!/^\s*(?:return|goto|break|continue|exit|abort|panic|_exit|longjmp)\b/.test(next)) freed.set(name, { line: L[i].line, abs: flow.absLine ? flow.absLine(L[i].line, L[i].lit.trim()) : L[i].line, end: L[i].end });
          }
          continue;
        }
        const am = /^\s*([A-Za-z_]\w*(?:\s*(?:\.|->)\s*\w+)*)\s*=[^=]/.exec(t);
        if (am) freed.delete(norm(am[1]));
        for (const [name, info] of [...freed]) {
          const esc = name.split('.').map(p => p.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('\\s*(?:\\.|->)\\s*');
          if (!new RegExp(String.raw`(?<![\w.>])${esc}(?![\w])`).test(am ? t.slice(t.indexOf('=') + 1) : t)) continue;
          // freed in a conditional block that closed before this use?
          const between = flow.ctx.code.slice(info.end, L[i].start);
          let depth = 0, closed = false;
          for (const ch of between) { if (ch === '{') depth++; else if (ch === '}') { depth--; if (depth < 0) { closed = true; break; } } }
          if (closed) { freed.delete(name); continue; }
          if (kind === 'uaf' && !reported.has(name)) { reported.add(name); emit(L[i].start, { desc: `"${name.replace(/\./g, '->')}" is used here after it was freed on line ${info.abs}.`, snippet: L[i].lit.trim() }); }
        }
      }
    } });
}
const UAF_RULES = [freeRule('uaf-c', UAF.cls, 'uaf'), freeRule('df-c', DF.cls, 'df'),
  call({ ...UAF, id: 'uaf-rust-unchecked', langs: ['rust'], what: 'indexes or builds a slice without bounds checks using an attacker-controlled value', args: 'any', sev: 'high',
    callee: m('get_unchecked|get_unchecked_mut|from_raw_parts|from_raw_parts_mut|offset|add|sub|copy_nonoverlapping|copy_from_slice_unchecked'), when: (c) => /^(?:get_unchecked|get_unchecked_mut|from_raw_parts|from_raw_parts_mut|copy_nonoverlapping|slice::from_raw_parts)/.test(c.name) || /(?:ptr|raw|p)\./.test(c.callee), title: 'Unchecked memory access with attacker-controlled value', group: 'mem' }),
];

// ═══ Race condition / TOCTOU ═════════════════════════════════════════════════
const RC = { cls: 'race condition / TOCTOU', group: 'race', sev: 'low', conf: 'medium', fix: 'Do not check then act on a path. Perform the operation directly and handle the error (open with O_EXCL / "x" mode / CreateNew, use file descriptors, or atomic rename) so the check and the use cannot be separated.' };
const TOCTOU = {
  python: [/\bos\.path\.(?:exists|isfile|isdir|islink|lexists)\s*\(\s*([^)]+?)\s*\)/, /\bos\.access\s*\(\s*([^,)]+)/, /\bos\.stat\s*\(\s*([^)]+?)\s*\)/, /\bPath\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:exists|is_file|is_dir)\s*\(/],
  js: [/\bfs\.(?:existsSync|accessSync|statSync|lstatSync|access|stat|exists)\s*\(\s*([^,)]+?)\s*[,)]/],
  php: [/\b(?:file_exists|is_file|is_dir|is_readable|is_writable|is_writeable|is_link)\s*\(\s*([^)]+?)\s*\)/],
  ruby: [/\bFile\.(?:exist\?|exists\?|file\?|directory\?|readable\?|writable\?|symlink\?)\s*\(?\s*([^)\s]+)/],
  go: [/\bos\.(?:Stat|Lstat)\s*\(\s*([^)]+?)\s*\)/],
  rust: [/\b(?:Path::new|PathBuf::from)\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:exists|is_file|is_dir|metadata)\s*\(/, /\bfs::metadata\s*\(\s*([^)]+?)\s*\)/],
  java: [/\bnew\s+File\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:exists|isFile|isDirectory|canRead|canWrite)\s*\(/, /\bFiles\.(?:exists|notExists|isRegularFile|isDirectory|isReadable|isWritable)\s*\(\s*([^),]+?)\s*[,)]/, /\b(\w+)\s*\.\s*(?:exists|isFile|canRead|canWrite)\s*\(\s*\)/],
  kotlin: [/\bFile\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:exists|isFile|isDirectory|canRead|canWrite)\s*\(/, /\bFiles\.(?:exists|notExists|isRegularFile|isDirectory|isReadable|isWritable)\s*\(\s*([^),]+?)\s*[,)]/, /\b(\w+)\s*\.\s*(?:exists|isFile|canRead|canWrite)\s*\(\s*\)/],
  csharp: [/\b(?:File|Directory)\.Exists\s*\(\s*([^)]+?)\s*\)/],
  c: [/\b(?:access|stat|lstat)\s*\(\s*([^,)]+?)\s*,/],
  dart: [/\bFile\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:existsSync|exists)\s*\(/],
  swift: [/\bfileExists\s*\(\s*atPath\s*:\s*([^)]+?)\s*\)/],
};
const TOCTOU_USE = {   // operations that CHANGE the file system (a stale check then lets an attacker redirect the write/delete)
  python: [/\b(?:os\.remove|os\.unlink|os\.rename|os\.replace|os\.rmdir|os\.chmod|os\.chown|os\.makedirs|os\.mkdir|os\.symlink|shutil\.(?:move|rmtree|copy|copy2|copyfile|copytree))\s*\(\s*([^,)]+?)\s*[,)]/, /\bopen\s*\(\s*([^,)]+?)\s*,\s*["'](?:[^"']*[wax+][^"']*)["']/],
  js: [/\bfs\.(?:writeFile|writeFileSync|unlink|unlinkSync|appendFile|appendFileSync|rename|renameSync|createWriteStream|rm|rmSync|rmdir|rmdirSync|mkdir|mkdirSync|chmod|chmodSync|chown|copyFile|copyFileSync|symlink|truncate)\s*\(\s*([^,)]+?)\s*[,)]/],
  php: [/\b(?:file_put_contents|unlink|rename|copy|mkdir|chmod|include|require|include_once|require_once|touch|rmdir|move_uploaded_file)\s*\(?\s*([^,;)]+?)\s*[,;)]/, /\bfopen\s*\(\s*([^,)]+?)\s*,\s*["'][^"']*[wax+]/],
  ruby: [/\bFile\.(?:write|binwrite|delete|unlink|rename|chmod|symlink)\s*\(?\s*([^,)\s]+)/, /\bFile\.(?:open|new)\s*\(?\s*([^,)\s]+)\s*,\s*["'][^"']*[wax+]/, /\bFileUtils\.(?:rm|rm_rf|rm_r|mv|cp|mkdir|mkdir_p|touch|chmod)\s*\(?\s*([^,)\s]+)/],
  go: [/\bos\.(?:OpenFile|Create|WriteFile|Remove|RemoveAll|Rename|Mkdir|MkdirAll|Chmod|Symlink|Truncate)\s*\(\s*([^,)]+?)\s*[,)]/],
  rust: [/\b(?:File::create|fs::(?:write|remove_file|remove_dir|remove_dir_all|rename|copy|create_dir(?:_all)?|set_permissions|hard_link))\s*\(\s*([^,)]+?)\s*[,)]/],
  java: [/\bnew\s+(?:FileOutputStream|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*([^),]+?)\s*[,)]/, /\bFiles\.(?:write\w*|delete\w*|copy|move|newOutputStream|newBufferedWriter|createFile|createDirectories|createDirectory|setPosixFilePermissions)\s*\(\s*([^),]+?)\s*[,)]/, /\b(\w+)\s*\.\s*(?:delete|renameTo|createNewFile|mkdir|mkdirs|setWritable|setReadable|setExecutable)\s*\(/],
  kotlin: [/\b(?:FileOutputStream|FileWriter|RandomAccessFile|PrintWriter)\s*\(\s*([^),]+?)\s*[,)]/, /\bFiles\.(?:write\w*|delete\w*|copy|move|newOutputStream|newBufferedWriter|createFile|createDirectories|createDirectory)\s*\(\s*([^),]+?)\s*[,)]/, /\b(\w+)\s*\.\s*(?:delete|renameTo|createNewFile|mkdir|mkdirs|writeText|writeBytes|appendText|deleteRecursively)\s*\(/],
  csharp: [/\bFile\.(?:WriteAll\w+|AppendAll\w+|Delete|Copy|Move|Create|OpenWrite|Replace|SetAttributes)\s*\(\s*([^,)]+?)\s*[,)]/, /\bnew\s+(?:StreamWriter)\s*\(\s*([^,)]+?)\s*[,)]/, /\bDirectory\.(?:Delete|CreateDirectory|Move)\s*\(\s*([^,)]+?)\s*[,)]/],
  c: [/\b(?:unlink|remove|rename|chmod|chown|mkdir|rmdir|truncate|symlink|creat)\s*\(\s*([^,)]+?)\s*[,)]/, /\bfopen\s*\(\s*([^,)]+?)\s*,\s*"[^"]*[wa+]/, /\bopen\s*\(\s*([^,)]+?)\s*,[^)]*O_(?:WRONLY|RDWR|CREAT|TRUNC|APPEND)/],
  dart: [/\bFile\s*\(\s*([^)]+?)\s*\)\s*\.\s*(?:writeAs\w+|openWrite|delete(?:Sync)?|rename|copy|create(?:Sync)?)/],
  swift: [/\bFileManager\.default\.(?:removeItem|moveItem|copyItem|createFile|createDirectory)\s*\(\s*(?:atPath\s*:\s*)?([^,)]+?)\s*[,)]/],
};
const firstGroup = (m) => (m ? m.slice(1).find(g => g !== undefined) : undefined);
const normPath = (s) => s.replace(/\s+/g, '').replace(/^&|^\*/, '');
const RACE_RULES = [custom({ ...RC, id: 'toctou', langs: Object.keys(TOCTOU), title: 'Time-of-check to time-of-use race on a file path',
  run(flow, emit) {
    const checks = TOCTOU[flow.family], uses = TOCTOU_USE[flow.family]; if (!checks || !uses) return;
    const L = flow.ctx.logical;
    for (let i = 0; i < L.length; i++) {
      let path = null;
      for (const re of checks) { const mm = re.exec(L[i].text); const g = firstGroup(mm); if (g) { path = normPath(g); break; } }
      if (!path || path.length < 1) continue;
      for (let j = i; j < Math.min(L.length, i + 14); j++) {
        let hit = null;
        for (const re of uses) { const mm = re.exec(L[j].text); const g = firstGroup(mm); if (g && normPath(g) === path) { hit = mm; break; } }
        if (!hit || (j === i && !(checks.length && true))) continue;
        if (j === i) continue;
        const checkLine = flow.absLine ? flow.absLine(L[i].line, L[i].lit.trim()) : L[i].line;
        emit(L[j].start, { desc: `The path ${path} is checked on line ${checkLine} and then modified here; between the two operations another process can replace the file (for example with a symlink), so the check no longer holds.`, snippet: L[j].lit.trim() });
        break;
      }
    }
  } })];

// ═══ ReDoS ═══════════════════════════════════════════════════════════════════
const RD = { cls: 'regex denial of service (ReDoS)', group: 'redos', sev: 'medium', conf: 'medium', fix: 'Rewrite the pattern to remove nested/overlapping quantifiers (use atomic groups / possessive quantifiers where supported), cap the input length before matching, or use a linear-time engine (RE2).' };
// A pattern is exponential only when two ways of splitting the input are both possible. A mandatory delimiter
// at the start or end of a repeated group (`(\.\d+)+`, `([\w-]+/)*`) removes that ambiguity.
function evilRegex(src) {
  const s = src.replace(/\\./g, 'x').replace(/\[(?:[^\]\\]|\\.)*\]/g, 'c');       // escapes and classes become single atoms
  const UNB = '(?:[+*]|\\{\\d+,\\d*\\})';
  const g = new RegExp(String.raw`\((?:\?:)?([^()|]+)\)${UNB}`, 'g'); let m;
  while ((m = g.exec(s)) !== null) {
    const body = m[1];
    const startsQuantified = new RegExp(String.raw`^(?:[^\\*+?{}]|c|\.)${UNB}`).test(body);
    const endsQuantified = /(?:[+*?]|\{\d+,\d*\})$/.test(body);
    if (startsQuantified && endsQuantified) return 'a group that can repeat a variable-length match is itself repeated (nested quantifiers)';
  }
  const alt = new RegExp(String.raw`\(\??:?([^()|]+)\|([^()|]+)\)${UNB}`).exec(s);
  if (alt) { const [a, b] = [alt[1], alt[2]]; if ((a[0] === b[0] && a[0] !== undefined) || /^[.cx]\+?$/.test(a) || /^[.cx]\+?$/.test(b) || a.startsWith(b) || b.startsWith(a)) return 'a repeated alternation has overlapping branches'; }
  if (/(?:\.\*|\.\+){2,}|\.\*[^|()]*\.\*[^|()]*\$/.test(s)) return 'adjacent wildcards followed by an anchor can backtrack quadratically or worse';
  return null;
}
const REGEX_LITERAL_RE = /(?:^|[=(,:\[!&|?;{}\s])\/(?![*\/])((?:[^\/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)\/[a-z]*/g;
const REDOS_RULES = [custom({ ...RD, id: 'redos', langs: ['js', 'python', 'php', 'ruby', 'java', 'kotlin', 'csharp', 'go', 'rust', 'dart', 'swift'], title: 'Regular expression with catastrophic backtracking',
  run(flow, emit) {
    const fam = flow.family;
    const evilVars = new Map();            // name → { pat, why } for regexes stored in a variable
    const note = (name, pat) => { const why = evilRegex(pat); if (why) evilVars.set(name, { pat, why }); };
    const text = (flow.chunk.file && fileTextOf(flow)) || flow.ctx.literal;
    if (fam === 'js') for (const mm of text.matchAll(/\b(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*\/((?:[^\/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)\/[a-z]*/g)) note(mm[1], mm[2]);
    if (fam === 'python') for (const mm of text.matchAll(/\b([A-Za-z_]\w*)\s*=\s*(?:re|regex)\.compile\s*\(\s*(?:r|u|b)?(["'])((?:(?!\2)[^\\\n]|\\.)+)\2/g)) note(mm[1], mm[3]);
    if (fam === 'ruby') for (const mm of text.matchAll(/\b([A-Za-z_]\w*)\s*=\s*\/((?:[^\/\\\n]|\\.)+)\/[a-z]*/g)) note(mm[1], mm[2]);
    if (fam === 'java' || fam === 'kotlin') for (const mm of text.matchAll(/\b([A-Za-z_]\w*)\s*=\s*Pattern\.compile\s*\(\s*"((?:[^"\\\n]|\\.)+)"/g)) note(mm[1], mm[2].replace(/\\\\/g, '\\'));
    const report = (off, pat, why, subject, callLine) => {
      const st = flow.state(subject.text, subject.lit, callLine).filter(x => isUsable(x, 'redos'));
      const src = st.find(x => x.kind === 'src') || st.find(x => x.kind === 'param'); if (!src) return;
      emit(off, { desc: `The regular expression /${pat.slice(0, 80)}/ has ${why}, and it is matched against ${src.origin || 'parameter "' + src.param + '"'}; a crafted input makes matching take exponential time and can hang the process.`,
        flowInfo: src.kind === 'src' ? { kind: 'src', origin: src.origin } : { kind: 'param', params: [src] } });
    };
    for (const c of flow.ctx.calls) {
      const parts = c.callee.split(/[.:]+/); const method = parts[parts.length - 1]; const recv = parts.slice(0, -1).join('.');
      if (fam === 'js') {
        // /re/.test(x)  re.test(x)  x.match(re)  x.replace(/re/, …)
        if (/^(?:test|exec)$/.test(method) && c.args[0]) {
          const prior = flow.ctx.code.slice(Math.max(0, c.start - 1), c.start);
          let pat = null;
          if (recv && evilVars.has(recv)) pat = evilVars.get(recv);
          else if (!recv && prior === '.') { const before = flow.ctx.literal.slice(0, c.start - 1); const lm = /\/((?:[^\/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)\/[a-z]*$/.exec(before); if (lm) { const why = evilRegex(lm[1]); if (why) pat = { pat: lm[1], why }; } }
          if (pat) report(c.start, pat.pat, pat.why, c.args[0], c.line);
        } else if (/^(?:match|matchAll|replace|replaceAll|split|search)$/.test(method) && c.args[0]) {
          let pat = null; const a0 = c.args[0].text.trim(), l0 = c.args[0].lit.trim();
          if (evilVars.has(a0)) pat = evilVars.get(a0);
          else { const lm = /^\/((?:[^\/\\\n\[]|\\.|\[(?:[^\]\\\n]|\\.)*\])+)\/[a-z]*$/.exec(l0); if (lm) { const why = evilRegex(lm[1]); if (why) pat = { pat: lm[1], why }; } }
          if (pat && recv) report(c.start, pat.pat, pat.why, { text: recv, lit: recv }, c.line);
        }
      } else if (fam === 'python') {
        let patLit = null, subj = null;
        if (/^(?:re|regex)$/.test(recv) && /^(?:match|search|fullmatch|findall|finditer|sub|subn|split)$/.test(method)) { patLit = c.args[0]?.lit.trim(); subj = c.args[method === 'sub' || method === 'subn' ? 2 : 1]; }
        else if (evilVars.has(recv) && /^(?:match|search|fullmatch|findall|finditer|sub|subn|split)$/.test(method)) { subj = c.args[method === 'sub' || method === 'subn' ? 1 : 0]; const v = evilVars.get(recv); if (subj) report(c.start, v.pat, v.why, subj, c.line); continue; }
        if (patLit && subj) { const lm = /^(?:r|u|b|rb|br)?(["'])([\s\S]*)\1$/i.exec(patLit); if (lm) { const why = evilRegex(lm[2]); if (why) report(c.start, lm[2], why, subj, c.line); } }
      } else if (fam === 'php') {
        if (/^preg_(?:match|match_all|replace|replace_callback|split|grep)$/.test(c.callee)) { const lm = /^(["'])\/([\s\S]*)\/[a-zA-Z]*\1$/.exec(c.args[0]?.lit.trim() || ''); const subj = c.args[c.callee === 'preg_replace' || c.callee === 'preg_replace_callback' ? 2 : 1]; if (lm && subj) { const why = evilRegex(lm[2]); if (why) report(c.start, lm[2], why, subj, c.line); } }
      } else if (fam === 'java' || fam === 'kotlin') {
        if (evilVars.has(recv) && /^matcher$/.test(method) && c.args[0]) { const v = evilVars.get(recv); report(c.start, v.pat, v.why, c.args[0], c.line); }
        else if (/^Pattern\.matches$|^matches$/.test(c.callee) && c.args[0]) { const lm = /^"((?:[^"\\\n]|\\.)+)"$/.exec(c.args[0].lit.trim()); if (lm && c.args[1]) { const why = evilRegex(lm[1].replace(/\\\\/g, '\\')); if (why) report(c.start, lm[1], why, c.args[1], c.line); } }
      } else if (fam === 'csharp') {
        if (/^(?:Regex\.(?:IsMatch|Match|Matches|Replace|Split))$/.test(c.callee)) { const lm = /^@?"((?:[^"\\\n]|\\.)+)"$/.exec(c.args[1]?.lit.trim() || ''); if (lm && c.args[0]) { const why = evilRegex(lm[1]); if (why) report(c.start, lm[1], why, c.args[0], c.line); } }
      } else if (fam === 'ruby') {
        if (evilVars.has(recv) && /^(?:match|match\?|=~|scan)$/.test(method) && c.args[0]) { const v = evilVars.get(recv); report(c.start, v.pat, v.why, c.args[0], c.line); }
      } else if (fam === 'go') {
        if (/^regexp\.(?:MatchString|Match)$/.test(c.callee)) { const lm = /^`([\s\S]*)`$|^"((?:[^"\\\n]|\\.)*)"$/.exec(c.args[0]?.lit.trim() || ''); const pat = lm && (lm[1] ?? lm[2]); if (pat && c.args[1]) { const why = evilRegex(pat); if (why) report(c.start, pat, why, c.args[1], c.line); } }
      }
    }
    if (fam === 'ruby') for (const ll of flow.ctx.logical) {                       // subject =~ /re/
      for (const mm of ll.lit.matchAll(/([\w@$.\[\]]+)\s*=~\s*\/((?:[^\/\\\n]|\\.)+)\//g)) { const why = evilRegex(mm[2]); if (why) report(ll.start + mm.index, mm[2], why, { text: mm[1], lit: mm[1] }, ll.line); }
    }
  } })];

// ═══ PHP type juggling ═══════════════════════════════════════════════════════
const TJ = { cls: 'PHP type juggling / loose comparison', group: 'juggle', sev: 'high', fix: 'Compare secrets, hashes and tokens with === / hash_equals(), cast request values to the expected type, and pass true as the strict flag to in_array / array_search.' };
const SECRET_NAME = /(?:token|hash|password|passwd|secret|key|digest|signature|otp|pin|nonce|csrf|auth|code|checksum|hmac)/i;
const JUGGLE_RULES = [
  pattern({ ...TJ, id: 'juggle-hash', langs: ['php'], title: 'Loose comparison of a hash value',
    re: /\b(?:md5|sha1|hash|crc32|hash_hmac|sha256|password_hash)\s*\([^()]*(?:\([^()]*\)[^()]*)*\)\s*(?:==|!=)(?!=)|(?:==|!=)(?!=)\s*(?:md5|sha1|hash|crc32|hash_hmac)\s*\(/, view: 'code',
    desc: 'A hash is compared with == / !=. PHP converts "0e…" strings to the number 0, so different "magic hash" values compare as equal and authentication can be bypassed.' }),
  pattern({ ...TJ, id: 'juggle-strcmp', langs: ['php'], title: 'strcmp() result compared loosely', view: 'code',
    re: /\bstrcmp\s*\([^;{]*\)\s*(?:==|!=)(?!=)\s*0\b|\bstrcmp\s*\([^;{]*\)\s*(?:==|!=)(?!=)\s*(?:false|null)\b|\bstrcmp\s*\([^;{]*\)\s*\)?\s*(?:==|!=)(?!=)\s*0/,
    desc: 'strcmp() returns NULL when given an array, and NULL == 0 is true, so a request parameter sent as an array (x[]=1) bypasses the comparison.' }),
  custom({ ...TJ, id: 'juggle-loose-input', langs: ['php'], title: 'Loose comparison involving request input',
    run(flow, emit) {
      for (const ll of flow.ctx.logical) {
        if (!/^\s*(?:if|elseif|while|return|\$\w+\s*=)\b|^\s*\}\s*else\s*if/.test(ll.text)) continue;
        const mm = /([^=!<>&|(]+?)\s*(==|!=)(?!=)\s*([^=&|)]+)/.exec(ll.text.replace(/^\s*(?:if|elseif|while|return)\s*\(?/, ''));
        if (!mm) continue;
        const l = mm[1], r = mm[3];
        const ls = flow.state(l, '', ll.line).filter(s => s.kind === 'src' && !isCleared(s, 'juggle'));
        const rs = flow.state(r, '', ll.line).filter(s => s.kind === 'src' && !isCleared(s, 'juggle'));
        const tainted = ls[0] || rs[0]; if (!tainted) continue;
        const other = ls[0] ? r : l;
        if (!(SECRET_NAME.test(other) || /^\s*(?:0|"0"|'0'|true|false|null|\d+(?:e\d+)?|0x[0-9a-f]+)\s*$/i.test(other) || /\b(?:md5|sha1|hash|crypt)\s*\(/.test(other))) continue;
        emit(ll.start, { desc: `Request input (${tainted.origin}) is compared with ${mm[2]} (loose comparison) against a secret/number; PHP type juggling can make unequal values compare equal ("0e1" == "0", "abc" == 0 in PHP < 8).`, flowInfo: { kind: 'src', origin: tainted.origin }, snippet: ll.lit.trim() });
      }
    } }),
  call({ ...TJ, id: 'juggle-inarray', langs: ['php'], title: 'in_array / array_search without strict comparison', what: 'compares with loose equality, so type juggling can make an unexpected value match', args: [0], callee: x('in_array|array_search'), when: (c) => c.args.length < 3 || !/true/i.test(c.args[2].text) }),
];

// ═══ Unsafe Rust without justification ═══════════════════════════════════════
const UR = { cls: 'unsafe Rust block without safety justification', group: 'unsafe', sev: 'low', conf: 'medium', fix: 'Document the invariants that make the block sound in a "// SAFETY:" comment immediately above it, and keep unsafe blocks as small as possible.' };
const UNSAFE_RULES = [custom({ ...UR, id: 'rust-unsafe', langs: ['rust'], title: 'unsafe block without a SAFETY comment',
  run(flow, emit) {
    const code = flow.ctx.code, raw = flow.chunk.code;
    const re = /\bunsafe\b\s*(\{|fn\b|impl\b|trait\b)/g; let mm;
    while ((mm = re.exec(code)) !== null) {
      const before = raw.slice(Math.max(0, mm.index - 400), mm.index);
      const prevLines = before.split('\n').slice(-4).join('\n');
      const after = raw.slice(mm.index, mm.index + 300).split('\n').slice(0, 3).join('\n');
      if (/SAFETY\s*:|#\s*Safety|Safety\s*:/i.test(prevLines) || /SAFETY\s*:/i.test(after)) continue;
      const kind = mm[1] === '{' ? 'block' : mm[1];
      emit(mm.index, { desc: `An unsafe ${kind} has no "// SAFETY:" comment explaining why the operations inside are sound.` });
    }
  } })];

export const NATIVE_RULES = [...BOF_RULES, ...FORMAT_RULES, ...INT_RULES, ...UAF_RULES, ...RACE_RULES, ...REDOS_RULES, ...JUGGLE_RULES, ...UNSAFE_RULES];
