'use strict';
// elf_hardening.js — turns parsed ELF binaries into per-ABI hardening records and decides which findings they raise.
//
// An APK ships one copy of each native library per ABI (lib/arm64-v8a, lib/armeabi-v7a, lib/x86, lib/x86_64 …), each built
// separately, so the same library can be hardened in one ABI and not in another. Every copy gets its own record; findings
// name the exact `abi/library` pair. Pure functions: no I/O, so the policy can be tested without a package.
//
// Checks (all read from the ELF itself, nothing is executed):
//   PIE      ET_DYN image (a shared object is position independent); ET_EXEC is not. Text relocations are reported separately,
//            because a library with DT_TEXTREL is loadable but is not really position independent code.
//   NX       PT_GNU_STACK present and not executable. A missing PT_GNU_STACK leaves the stack permission to the loader's default.
//            Writable + executable PT_LOAD segments are reported too (a W^X violation).
//   RELRO    PT_GNU_RELRO, and BIND_NOW (DT_BIND_NOW / DF_BIND_NOW / DF_1_NOW) for "full".
//   canary   an import of __stack_chk_fail / __stack_chk_guard. A library without any stack buffers legitimately has none, so the
//            finding needs a reason to expect one: it imports unbounded copy functions, or another ABI of the same library has one.
//   FORTIFY  imports of the checked libc variants (__memcpy_chk …) next to the plain ones. An indicator, not proof (see elf.js).

/** Unbounded or easily-misused copy functions: a library that imports one and has no canary is the case worth flagging. */
export const UNSAFE_COPY = new Set(['strcpy', 'strncpy', 'stpcpy', 'strcat', 'strncat', 'sprintf', 'vsprintf', 'gets', 'memcpy', 'memmove']);

/** Check ids, in report order, with the rule each one raises. */
export const CHECKS = [
  ['no_pie', 'android.native.no_pie'],
  ['exec_stack', 'android.native.exec_stack'],
  ['no_gnu_stack', 'android.native.no_gnu_stack'],
  ['wx_segment', 'android.native.wx_segment'],
  ['textrel', 'android.native.textrel'],
  ['no_relro', 'android.native.no_relro'],
  ['partial_relro', 'android.native.partial_relro'],
  ['no_canary', 'android.native.no_canary'],
  ['no_fortify', 'android.native.no_fortify'],
  ['rpath', 'android.native.rpath'],
];

const TEXT = {
  no_pie: 'These binaries are not position independent (ET_EXEC), so ASLR cannot relocate them.',
  exec_stack: 'The stack of these libraries is marked executable.',
  no_gnu_stack: 'These libraries carry no PT_GNU_STACK header, so whether their stack is executable is left to the loader default.',
  wx_segment: 'These libraries map a segment that is both writable and executable.',
  textrel: 'Text relocations force writable code pages and mean the library is not truly position independent.',
  no_relro: 'The GOT is writable at runtime.',
  partial_relro: 'Lazy binding leaves the GOT writable.',
  no_canary: 'These libraries have no stack canary although they are expected to need one.',
  no_fortify: 'These libraries import fortifiable libc functions (memcpy, strcpy, …) but none of their checked `_chk` variants, which suggests they were built without _FORTIFY_SOURCE. This is an indicator: the compiler only emits checked calls where it can prove the buffer size.',
  rpath: 'A search path is baked into the library.',
};

/** Confidence of each check: the structural ones are exact; canary and FORTIFY are inferred from imports. */
const CONFIDENCE = { no_canary: 'medium', no_gnu_stack: 'medium', no_fortify: 'low' };

/**
 * One record per binary. Plain JSON: these are the entries of `native_hardening.binaries` in the report.
 * @param {ReturnType<import('./elf.js').parseElf>} elf
 * @param {{abi:string, library:string, path:string, size?:number}} where
 */
export function hardeningRecord(elf, { abi, library, path, size }) {
  const readable = !!elf.symbolsReadable;
  const unsafe = [...new Set(elf.imports.filter(s => UNSAFE_COPY.has(s)))].sort();
  return {
    library, abi, path, ...(size != null ? { size_bytes: size } : {}),
    arch: elf.arch, bits: elf.bits, kind: elf.kind,
    pie: elf.pie, textrel: elf.textrel,
    nx: elf.nx, wx_segments: elf.wxSegments,
    relro: elf.relro,
    canary: readable ? elf.canary : null,             // null = the symbol table could not be read, so the canary is unknown
    unsafe_calls: unsafe.slice(0, 12),
    fortify: readable ? elf.fortify.state : 'unknown',
    fortified_functions: readable ? elf.fortify.fortified.length : 0,
    unfortified_functions: readable ? elf.fortify.unfortified.slice(0, 12) : [],
    rpath: elf.rpath || null,
    symbols: elf.symbols,
  };
}

/**
 * Which checks each record fails. Cross-ABI context: a library whose other ABI(s) have a stack canary is expected to have one here too.
 * @returns {Array<{record:object, fails:Object<string, string|true>}>} `fails[check]` is a short qualifier for the evidence line, or true
 */
export function evaluateRecords(records) {
  const canaryElsewhere = new Map();                  // library -> ABIs that have a canary
  for (const r of records) if (r.canary === true) (canaryElsewhere.get(r.library) || canaryElsewhere.set(r.library, []).get(r.library)).push(r.abi);
  return records.map(record => {
    const f = {};
    if (!record.pie) f.no_pie = true;
    if (record.nx === 'disabled') f.exec_stack = true;
    if (record.nx === 'missing') f.no_gnu_stack = true;
    if (record.wx_segments > 0) f.wx_segment = true;
    if (record.textrel) f.textrel = true;
    if (record.relro === 'none') f.no_relro = true;
    else if (record.relro === 'partial') f.partial_relro = true;
    if (record.canary === false) {
      const others = (canaryElsewhere.get(record.library) || []).filter(a => a !== record.abi);
      if (record.unsafe_calls.length) f.no_canary = `imports ${record.unsafe_calls.slice(0, 4).join(', ')}`;
      else if (others.length) f.no_canary = `${others.join(', ')} build${others.length === 1 ? '' : 's'} of this library ${others.length === 1 ? 'has' : 'have'} one`;
    }
    if (record.fortify === 'no') f.no_fortify = `imports ${record.unfortified_functions.slice(0, 4).join(', ')}`;
    if (record.rpath) f.rpath = record.rpath;
    return { record, fails: f };
  });
}

/**
 * Groups the failures by check for finding emission.
 * @returns {Array<{check:string, rule:string, text:string, confidence:string|undefined, entries:string[], libraries:string[], abis:string[]}>} only checks that failed, in CHECKS order
 */
export function groupFailures(evaluated) {
  const out = [];
  for (const [check, rule] of CHECKS) {
    const hits = evaluated.filter(e => e.fails[check] !== undefined);
    if (!hits.length) continue;
    out.push({
      check, rule, text: TEXT[check], confidence: CONFIDENCE[check],
      entries: hits.map(e => `${e.record.abi}/${e.record.library}${typeof e.fails[check] === 'string' ? ` (${e.fails[check]})` : ''}`),
      libraries: hits.map(e => e.record.library),
      abis: [...new Set(hits.map(e => e.record.abi))].sort(),
    });
  }
  return out;
}

/** The `app.native_hardening` block: the per-ABI table plus roll-up counts. */
export function summarizeHardening(records, evaluated = evaluateRecords(records)) {
  const failing = Object.fromEntries(CHECKS.map(([c]) => [c, 0]));
  for (const e of evaluated) for (const c of Object.keys(e.fails)) failing[c]++;
  return {
    total: records.length,
    libraries: new Set(records.map(r => r.library)).size,
    abis: [...new Set(records.map(r => r.abi))].sort(),
    unknown_symbols: records.filter(r => r.canary === null).length,
    failing,
    // each record also names the checks it fails, so the report can colour the table without repeating the policy
    binaries: evaluated.map(e => ({ ...e.record, failed: Object.keys(e.fails) })),
  };
}

/** Folds another module's block into `into` (App Bundle feature modules), recomputing the roll-up. */
export function mergeHardening(into, other) {
  if (!other || !other.binaries?.length) return into;
  if (!into || !into.binaries?.length) return other;
  return summarizeHardening([...into.binaries, ...other.binaries]);
}
