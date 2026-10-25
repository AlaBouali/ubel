#!/usr/bin/env node
'use strict';
// ubel-binary — static security scan of a native executable or library (ELF, Mach-O).
// Build-hardening misconfigurations and hardcoded secrets, reported like ubel-mobile (report.binary.json + report.binary.html).
// Reuses the ELF / Mach-O readers, rules, findings, secret scanner, report and --fail-on gate of ubel-mobile.
// Pure Node built-ins: no third-party libraries and no external binaries. Nothing is executed or loaded.

import fs from 'fs';
import path from 'path';
import crypto from 'crypto';
import { fileURLToPath, pathToFileURL } from 'url';
import { isElf, parseElf } from '../mobile/lib/elf.js';
import { hardeningRecord, evaluateRecords, groupFailures, summarizeHardening, UNSAFE_COPY } from '../mobile/lib/elf_hardening.js';
import { isMachO, parseMachO, sectionBuffers } from '../mobile/lib/macho.js';
import { isPe, parsePe } from './lib/pe.js';
import { elfSections } from './lib/elfsections.js';
import { detectBanners, goBuildInfo, goRecords, cargoAuditable, cargoRecords, cratesFromStrings } from './lib/components.js';
import { scanBinaryDependencies } from './lib/deps.js';
import { asciiStrings, utf16Strings } from '../mobile/lib/strings.js';
import { SecretScanner } from '../mobile/lib/secrets.js';
import { Findings } from '../mobile/lib/findings.js';
import { Notes, gap } from '../mobile/lib/coverage.js';
import { SEVERITY_RANK, SEVERITIES } from '../mobile/lib/rules.js';
import { buildPayload, buildHtml, flattenFindings } from '../mobile/lib/report.js';
import { parseFailOn, evaluateGate, diffReports } from '../mobile/index.js';
import { loadPreviousReport } from '../cloud/lib/previous_report.js';
import { buildZip } from '../sca/zip_writer.js';
import { reportTimestamp, reportFileName, historyZipPath, updateLatestReportZip, atomicWriteFile, assetFor, generateReportId, provisionAssetAt } from '../sca/report_naming.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const TOOL_VERSION = JSON.parse(fs.readFileSync(path.join(__dirname, '../package.json'), 'utf8')).version;
const TAG = 'binary';
const MB = 1024 * 1024;

const HELP = `
ubel-binary — static security scan of a native binary (no third-party libraries, no external tools)

Usage:
  ubel-binary <binary> [--working-dir <path>]
              [--min-severity critical|high|medium|low|info]
              [--fail-on critical|high|medium|low|info|none|<count>:<severity>]
              [--allow-partial] [--max-size-mb <n>] [--verbose] [--quiet]

Supported: ELF (Linux, Android), Mach-O (macOS, iOS; thin and fat) and PE (Windows .exe/.dll). The format is detected from the file's magic bytes.

Looks for:
  • missing build hardening — ELF: PIE, NX, W+X segments, RELRO, canary, FORTIFY, text relocations, RPATH, stripped / static ·
    Mach-O: PIE, executable stack, canary, code signature, hardened runtime, dangerous entitlements (get-task-allow …) ·
    PE: ASLR, high-entropy ASLR, DEP, CFG, SafeSEH, /GS cookie, W+X sections, Authenticode presence
  • risky imports (gets, strcpy, system, mktemp, MD5/SHA-1/DES/RC4 …) — heuristics from the import table
  • hardcoded secrets in the binary's strings
  • known-vulnerable components: version banners of C/C++ libraries (OpenSSL, zlib, libcurl, SQLite, libpng, FFmpeg …) are checked
    against NVD; Go build info and cargo-auditable / Rust crate paths against OSV.dev. Only the component names and versions are sent.

It does NOT look for unknown memory-corruption bugs (that needs disassembly and data-flow analysis). A version banner shows that
library code is in the file, not that the vulnerable function is reachable. Nothing is executed.

Every run writes report.binary.json + report.binary.html into a timestamped zip under
$HOME/.ubel/history/<asset_id>/<timestamp>.binary.zip and always-overwritten copies to
.ubel/reports/latest.binary.json and .ubel/reports/latest.binary.html.

Exit codes: 0 gate passed and analysis complete · 1 scan failed (file missing, unreadable or unsupported format) ·
            2 --fail-on gate tripped, or bad arguments · 3 gate passed but the analysis was incomplete (--allow-partial accepts it)
`;

const VALID_SEVERITIES = new Set(SEVERITIES);

export function parseArgs(argv) {
  const args = { minSeverity: 'info', failOn: 'critical', verbose: false, quiet: false, allowPartial: false, maxSizeMb: 512, file: null };
  const bad = msg => { console.error(`${msg}\n`); console.log(HELP); process.exit(2); };
  const value = (flag, i) => { const v = argv[i + 1]; if (v === undefined || v.startsWith('--')) bad(`${flag} requires a value`); return v; };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--help' || a === '-h') { console.log(HELP); process.exit(0); }
    else if (a === '--working-dir') args.workingDir = value(a, i++);
    else if (a === '--min-severity') args.minSeverity = value(a, i++);
    else if (a === '--fail-on') args.failOn = value(a, i++);
    else if (a === '--max-size-mb') args.maxSizeMb = Number(value(a, i++));
    else if (a === '--verbose') args.verbose = true;
    else if (a === '--quiet') args.quiet = true;
    else if (a === '--allow-partial') args.allowPartial = true;
    else if (a.startsWith('--')) bad(`Unknown argument: ${a}`);
    else if (args.file === null) args.file = a;
    else bad(`Unexpected extra argument: ${a}`);
  }
  if (!args.file) bad('A binary to scan is required (ELF or Mach-O)');
  if (!VALID_SEVERITIES.has(args.minSeverity)) bad(`--min-severity must be one of: ${SEVERITIES.join(', ')}`);
  if (!Number.isFinite(args.maxSizeMb) || args.maxSizeMb < 1 || args.maxSizeMb > 2048) bad('--max-size-mb must be a number between 1 and 2048');
  args.failOnParsed = parseFailOn(args.failOn);
  if (!args.failOnParsed) bad(`--fail-on must be "none", one of: ${SEVERITIES.join(', ')}, or "<count>:<severity>" (got "${args.failOn}")`);
  return args;
}

/** 'elf' | 'macho' | 'pe' | null, from the magic bytes only (the extension is never trusted). */
export function sniffFormat(buf) {
  if (isElf(buf)) return 'elf';
  if (isMachO(buf)) return 'macho';
  if (isPe(buf)) return 'pe';
  return null;
}

function sha256(buf) { return crypto.createHash('sha256').update(buf).digest('hex'); }
const STR_OPTS = { min: 8, max: 2048, limit: 400000 };

// ── risky imports: heuristics from the import table (presence of a call is not proof of an exploitable call site) ──────────────
const RISKY = [
  ['binary.risky.gets',           'gets() cannot be used safely: it has no length limit.',                                  'high',   n => n === 'gets' || n === '_getws'],
  ['binary.risky.unbounded_copy', 'Unbounded string copy / format functions are imported; each call site must be checked.',  'medium', n => /^(strcpy|strcat|stpcpy|sprintf|vsprintf|wcscpy|wcscat|_mbscpy|_mbscat|(lstrcpy|lstrcat|wsprintf|StrCpy|StrCat)[AW]?)$/.test(n)],
  ['binary.risky.cmd_exec',       'Functions that hand a string to a shell are imported.',                                   'medium', n => /^(system|popen|_popen|_wsystem|_wpopen|WinExec)$/.test(n)],
  ['binary.risky.insecure_tmp',   'Predictable temporary-file name functions are imported (race / symlink attacks).',        'medium', n => /^(mktemp|tmpnam|tempnam|_mktemp|_wmktemp)$/.test(n)],
  ['binary.risky.weak_crypto',    'Broken or weak cryptographic primitives are imported.',                                   'medium', n => /^(MD4|MD4_Init|MD5|MD5_Init|MD5_Update|MD5_Final|SHA1|SHA1_Init|SHA1_Update|SHA1_Final|DES_\w+|RC4|RC4_set_key|RC2_\w+|BF_\w+|EVP_(md4|md5|sha1|rc4|rc2|des_\w+|bf_\w+)|CC_MD5|CC_MD5_Init|CC_SHA1|CC_SHA1_Init)$/.test(n)],
];
function riskyImports(importNames, { findings, base, name, stripUnderscore = false }) {
  const names = [...new Set([...importNames].map(n => (stripUnderscore ? n.replace(/^_/, '') : n)))];
  for (const [rule, text, confidence, test] of RISKY) {
    const hit = names.filter(test).sort();
    if (hit.length) findings.add(rule, { ...base, artifact: name, key: rule, description: text, confidence, evidence: hit.slice(0, 12).map(h => `imports ${h}`) });
  }
}

// ── components (version banners, Go build info, Rust crates) ───────────────────────────────────
function componentRecords(buf, strings, { notes, name, dep0 }) {
  const records = [...detectBanners(strings)];
  const go = goBuildInfo(buf);
  if (go && go.unsupported) gap(notes, `${name}: ${go.unsupported}`);
  else if (go) records.push(...goRecords(go));
  const exact = dep0 ? cargoAuditable(dep0) : null;
  if (dep0 && !exact) gap(notes, `${name}: the cargo-auditable data (.dep-v0) could not be decoded; Rust crates are taken from embedded paths instead.`);
  const crates = exact || cratesFromStrings(strings);
  records.push(...cargoRecords(crates, { exact: Boolean(exact) }));
  return records;
}

// ── ELF ──────────────────────────────────────────────────────────────────────────────────────────
function analyzeElf(buf, ctx) {
  const { name, findings, base, notes, scanner, app } = ctx;
  const elf = parseElf(buf);
  const record = hardeningRecord(elf, { abi: elf.arch, library: name, path: name, size: buf.length });
  const evaluated = evaluateRecords([record]);
  const secs = elfSections(buf);
  const isStatic = elf.kind === 'executable' && !elf.interp && elf.needed.length === 0;
  Object.assign(app, { format: 'elf', arch: elf.arch, bits: elf.bits, kind: elf.kind, needed: elf.needed.slice(0, 200), symbols: elf.symbols, static: isStatic, stripped: !secs.hasSymtab });
  app.native_hardening = summarizeHardening([record], evaluated);
  for (const g of groupFailures(evaluated)) {
    findings.add(g.rule.replace(/^android\.native\./, 'binary.'), {
      ...base, artifact: name, key: g.rule, description: g.text, evidence: g.entries, ...(g.confidence ? { confidence: g.confidence } : {}),
    });
  }
  if (secs.hasSymtab || secs.hasDebug) findings.add('binary.not_stripped', { ...base, artifact: name, key: 'not_stripped', description: 'The file still carries its full symbol table and/or DWARF debug sections, which eases reverse engineering.', evidence: [secs.hasSymtab && '.symtab present', secs.hasDebug && '.debug_* sections present'].filter(Boolean) });
  if (isStatic) findings.add('binary.static_linked', { ...base, artifact: name, key: 'static_linked', description: 'The executable has no dynamic dependencies, so every library it uses is compiled in and only a rebuild picks up security fixes.', evidence: ['no PT_INTERP and no DT_NEEDED'] });
  if (!elf.symbolsReadable) notes.push(`${name}: no readable dynamic symbol table (statically linked or stripped); stack canary and FORTIFY indicators were not assessed.`);
  riskyImports(elf.imports || [], { findings, base, name });
  const strings = asciiStrings(buf, STR_OPTS);
  if (strings.length >= STR_OPTS.limit) gap(notes, `${name}: more than ${STR_OPTS.limit} strings; the rest were neither scanned for secrets nor for component versions.`);
  scanner.add(name, strings);
  const dep = secs.sections.find(x => x.name === '.dep-v0' && x.size > 0 && x.off + x.size <= buf.length);
  return componentRecords(buf, strings, { notes, name, dep0: dep ? buf.subarray(dep.off, dep.off + dep.size) : null });
}

// ── Mach-O ───────────────────────────────────────────────────────────────────────────────────────
const MACHO_RISKY_ENTITLEMENTS = [
  'com.apple.security.cs.disable-library-validation', 'com.apple.security.cs.allow-dyld-environment-variables', 'com.apple.security.cs.allow-unsigned-executable-memory',
  'com.apple.security.cs.disable-executable-page-protection', 'com.apple.security.cs.debugger',
];
function analyzeMachO(buf, ctx) {
  const { name, findings, base, notes, scanner, app } = ctx;
  const { slices, preferred } = parseMachO(buf);
  Object.assign(app, { format: 'macho', arch: preferred.arch, bits: preferred.is64 ? 64 : 32, kind: ({ 2: 'executable', 6: 'shared', 8: 'bundle' })[preferred.filetype] || `filetype_${preferred.filetype}`,
    architectures: slices.map(s => s.arch), needed: preferred.dylibs.slice(0, 200), signed: preferred.signed, min_os: preferred.minOS, macos: preferred.platform === 1 });
  const hits = {};
  const hit = (rule, line) => (hits[rule] ||= []).push(line);
  const FILETYPE = { 2: 'executable', 6: 'shared', 8: 'bundle' };
  const failing = { no_pie: 0, exec_stack: 0, no_canary: 0, unsigned: 0, adhoc_signed: 0, no_hardened_runtime: 0, get_task_allow: 0, dangerous_entitlement: 0 };
  const rows = [];
  for (const s of slices) {
    const failed = [];
    const fail = (key, rule, line) => { hit(rule, line); failed.push(key); failing[key]++; };
    if (s.filetype === 2 && !s.pie) fail('no_pie', 'binary.no_pie', `${s.arch}: MH_PIE not set`);
    if (s.allowStackExec) fail('exec_stack', 'binary.exec_stack', `${s.arch}: MH_ALLOW_STACK_EXECUTION`);
    const hasCanary = s.imports.has('___stack_chk_fail') || s.imports.has('___stack_chk_guard');
    const unsafe = [...s.imports].map(i => i.replace(/^_/, '')).filter(i => UNSAFE_COPY.has(i));
    const noCanary = unsafe.length > 0 && !hasCanary;
    if (noCanary) fail('no_canary', 'binary.no_canary', `${s.arch}: imports ${[...new Set(unsafe)].slice(0, 4).join(', ')}`);
    if (!s.signed) fail('unsigned', 'binary.unsigned', `${s.arch}: no LC_CODE_SIGNATURE`);
    const runtimeApplies = s.signed && s.filetype === 2 && s.platform === 1 && s.cdFlags !== null;
    const runtimeOn = runtimeApplies && (s.cdFlags & 0x10000) !== 0;
    if (runtimeApplies && !runtimeOn) fail('no_hardened_runtime', 'binary.macho.no_hardened_runtime', `${s.arch}: code-directory flags 0x${s.cdFlags.toString(16)} (CS_RUNTIME not set)`);
    if (s.signed && s.adhoc) fail('adhoc_signed', 'binary.macho.adhoc_signed', `${s.arch}: ad-hoc code signature`);
    const ent = s.entitlements && typeof s.entitlements === 'object' ? s.entitlements : null;
    const riskyEnt = [];
    if (ent) {
      for (const k of ['com.apple.security.get-task-allow', 'get-task-allow']) if (ent[k] === true) { fail('get_task_allow', 'binary.macho.get_task_allow', `${s.arch}: ${k} = true`); riskyEnt.push(k); }
      for (const k of MACHO_RISKY_ENTITLEMENTS) if (ent[k] === true) { fail('dangerous_entitlement', 'binary.macho.dangerous_entitlement', `${s.arch}: ${k} = true`); riskyEnt.push(k); }
    }
    rows.push({
      library: name, arch: s.arch, bits: s.is64 ? 64 : 32, kind: FILETYPE[s.filetype] || `filetype_${s.filetype}`, pie: s.pie, stack_exec: s.allowStackExec,
      canary: hasCanary ? 'yes' : noCanary ? 'no' : 'none', signature: !s.signed ? 'none' : s.adhoc ? 'adhoc' : 'signed',
      hardened_runtime: !runtimeApplies ? 'n/a' : runtimeOn ? 'yes' : 'no', entitlements: riskyEnt, min_os: s.minOS || null, failed,
    });
  }
  app.native_hardening = { format: 'macho', total: rows.length, libraries: 1, abis: [...new Set(slices.map(s => s.arch))].sort(), unknown_symbols: 0, failing, binaries: rows };
  const text = {
    'binary.no_pie': 'The executable loads at a fixed address, which defeats ASLR.',
    'binary.exec_stack': 'The binary allows code to run from the stack.',
    'binary.no_canary': 'The binary imports unbounded copy functions but no stack-protector runtime hook, which suggests it was built without stack canaries.',
    'binary.unsigned': 'The binary has no LC_CODE_SIGNATURE.',
    'binary.macho.no_hardened_runtime': 'The macOS executable is signed without the hardened-runtime flag, so the OS does not enforce library validation or block code injection and DYLD_* environment variables.',
    'binary.macho.adhoc_signed': 'The signature is ad-hoc: it is not tied to a signing identity.',
    'binary.macho.get_task_allow': 'Another process of the same user can attach to this binary and read or alter its memory.',
    'binary.macho.dangerous_entitlement': 'The signature grants an entitlement that lifts a hardened-runtime protection.',
  };
  for (const [rule, evidence] of Object.entries(hits)) findings.add(rule, { ...base, artifact: name, key: rule, description: text[rule], evidence, ...(rule === 'binary.no_canary' ? { confidence: 'medium' } : {}) });
  riskyImports(preferred.imports, { findings, base, name, stripUnderscore: true });
  if (preferred.encrypted) { gap(notes, `${name}: FairPlay-encrypted — secrets and component scans were skipped. Scan a decrypted build for full coverage.`); return []; }
  const lines = [];
  for (const part of sectionBuffers(buf, preferred)) {
    const list = part.name === '__ustring' ? utf16Strings(part.data, { min: 6 }) : asciiStrings(part.data, { min: 6, max: 2048, limit: 200000 });
    for (const x of list) if (x.length >= 8) lines.push(x);
  }
  if (lines.length) scanner.add(name, lines);
  const dep = preferred.sections.find(x => x.name === '.dep-v0' && x.size > 0 && x.off + x.size <= buf.length);
  return componentRecords(buf, lines, { notes, name, dep0: dep ? buf.subarray(dep.off, dep.off + dep.size) : null });
}

// ── PE ───────────────────────────────────────────────────────────────────────────────────────────
function analyzePe(buf, ctx) {
  const { name, findings, base, notes, scanner, app } = ctx;
  const pe = parsePe(buf);
  Object.assign(app, { format: 'pe', arch: pe.arch, bits: pe.bits, kind: pe.kind, needed: pe.needed.slice(0, 200), signed: pe.signed, managed: pe.managed, subsystem: pe.subsystem });
  const add = (rule, description, evidence, extra = {}) => findings.add(rule, { ...base, artifact: name, key: rule, description, evidence, ...extra });
  if (!pe.aslr) add('binary.pe.no_aslr', 'The image does not set IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE, so it always loads at its preferred base address.', ['DllCharacteristics: DYNAMIC_BASE not set']);
  else if (pe.relocsStripped) add('binary.pe.relocs_stripped', 'DYNAMIC_BASE is set but the file header says relocations were stripped, so the loader cannot move the image.', ['IMAGE_FILE_RELOCS_STRIPPED']);
  if (pe.bits === 64 && pe.aslr && !pe.highEntropyVa && !pe.managed) add('binary.pe.no_high_entropy_va', 'A 64-bit image without HIGH_ENTROPY_VA is randomised within a much smaller address range.', ['DllCharacteristics: HIGH_ENTROPY_VA not set']);
  if (!pe.nx) add('binary.pe.no_nx', 'The image does not declare DEP / NX compatibility, so the loader may leave its stack and heap executable.', ['DllCharacteristics: NX_COMPAT not set']);
  if (!pe.managed) {
    if (!pe.cfg && ['x86', 'x86_64', 'arm64'].includes(pe.arch)) add('binary.pe.no_cfg', 'Control Flow Guard is not enabled, so indirect calls are not checked against the set of valid targets.', ['DllCharacteristics: GUARD_CF not set']);
    if (pe.arch === 'x86' && !pe.noSeh && pe.safeSeh !== true) add('binary.pe.no_safeseh', 'The 32-bit image has no SafeSEH handler table and is not flagged NO_SEH, so SEH handler addresses are not validated.', [pe.loadConfig ? 'load configuration has no SE handler table' : 'no load configuration directory']);
    if (!pe.loadConfig || pe.securityCookie === false) add('binary.pe.no_gs', 'No /GS security cookie was found in the load configuration, which suggests the code was built without stack buffer checks.', [pe.loadConfig ? 'SecurityCookie is 0' : 'no load configuration directory'], { confidence: 'medium' });
  } else notes.push(`${name}: managed (.NET) assembly. Only the native header flags were assessed; the IL code was not analysed.`);
  if (pe.wxSections.length) add('binary.wx_segment', 'A section is both writable and executable.', pe.wxSections.map(n => `section ${n}: IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_EXECUTE`));
  if (!pe.signed) add('binary.unsigned', 'The file has no Authenticode signature (only the presence of a signature is checked, never its validity).', []);
  if (!pe.importsReadable && pe.kind === 'executable') notes.push(`${name}: the import table could not be read; risky-import checks were skipped.`);
  riskyImports(pe.imports, { findings, base, name });
  const strings = asciiStrings(buf, STR_OPTS);
  if (strings.length >= STR_OPTS.limit) gap(notes, `${name}: more than ${STR_OPTS.limit} strings; the rest were neither scanned for secrets nor for component versions.`);
  scanner.add(name, strings);
  const dep = pe.sections.find(x => x.name === '.dep-v0' && x.size > 0 && x.off + x.size <= buf.length);
  return componentRecords(buf, strings, { notes, name, dep0: dep ? buf.subarray(dep.off, dep.off + dep.size) : null });
}

const ANALYZERS = { elf: analyzeElf, macho: analyzeMachO, pe: analyzePe };
const FORMAT_LABEL = { elf: 'ELF', macho: 'Mach-O', pe: 'PE' };

/** Scans one binary. Never writes reports and never touches the network (component records are looked up later). */
export function scanBinary(file, opts = {}) {
  const st = fs.statSync(file);
  if (!st.isFile()) throw new Error(`${file} is not a file`);
  const maxBytes = (opts.maxSizeMb || 512) * MB;
  if (st.size > maxBytes) throw new Error(`file is ${Math.round(st.size / MB)} MB, over the ${Math.round(maxBytes / MB)} MB limit (--max-size-mb)`);
  const buf = fs.readFileSync(file);
  const format = sniffFormat(buf);
  if (!format) throw new Error('unsupported format: not ELF, Mach-O or PE (checked by magic bytes)');
  const name = path.basename(file);
  const findings = new Findings();
  const notes = new Notes();
  const base = { app: name };
  const scanner = new SecretScanner(findings, base);
  const app = { platform: 'binary', name, size_bytes: buf.length };
  let records;
  try { records = ANALYZERS[format](buf, { name, findings, base, notes, scanner, app }); }
  catch (err) { throw new Error(`${FORMAT_LABEL[format]} not readable: ${err.message}`); }
  scanner.run();
  if (scanner.truncated) gap(notes, `${name}: more strings than the secret scanner's line budget; the rest were not scanned.`);
  notes.push('Scope: build hardening, imported-API use, hardcoded secrets and known-vulnerable components. Unknown memory-corruption bugs are not detected, and a component version banner shows the code is present, not that the vulnerable function is reachable.');
  return { findings, apps: [app], dependencies: records, dependencySummary: null, notes, target: { file: name, kind: format, size_bytes: buf.length, sha256: sha256(buf) } };
}

async function resolveDependencies(scan, notes, args) {
  const result = await scanBinaryDependencies(scan.dependencies || [], { log: args.quiet ? () => {} : m => console.log(m) });
  scan.dependencies = result.dependencies;
  scan.dependencySummary = result.summary;
  // A failed advisory lookup is a coverage gap, not a clean result (same fail-closed rule as the rest of UBEL).
  if (result.lookup_error) gap(notes, `Binary component advisory lookup was incomplete: ${result.lookup_error}`);
  if (result.summary.lookup_errors) gap(notes, `${result.summary.lookup_errors} component(s) could not be fully checked against NVD / OSV.dev; see the Dependencies tab.`);
}

async function writeReports(meta, scan, notes, args) {
  const ts = reportTimestamp(new Date());
  const workingDir = args.workingDir ? path.resolve(args.workingDir) : process.cwd();
  const latestDir = path.join(workingDir, '.ubel', 'reports');
  fs.mkdirSync(latestDir, { recursive: true });
  const asset = assetFor(TAG, path.join(workingDir, '.ubel'));
  const zipPath = historyZipPath(ts, TAG, asset.asset_id);
  const jsonName = reportFileName('report', TAG, 'json'), htmlName = reportFileName('report', TAG, 'html');
  const base = {
    schema: 'ubel-binary/1', tool: 'ubel-binary',
    generated_at: new Date().toISOString(), tool_version: TOOL_VERSION, min_severity: args.minSeverity, hidden_by_filter: meta.hidden, gate: meta.gate,
    report_id: generateReportId(TAG, asset.asset_id), asset_id: asset.asset_id, asset_name: asset.asset_name, asset_type: asset.asset_type, machine_id: asset.machine_id,
  };
  const build = diffs => buildPayload({ meta: base, target: scan.target, apps: scan.apps, findings: scan.findings, dependencies: scan.dependencies, dependencySummary: scan.dependencySummary, notes, diffs });
  let payload = build(null);
  payload = build(diffReports(loadPreviousReport(zipPath, TAG, jsonName), payload));
  const json = JSON.stringify(payload, null, 2);
  const html = await buildHtml(payload);
  const latestJson = path.join(latestDir, reportFileName('latest', TAG, 'json'));
  const latestHtml = path.join(latestDir, reportFileName('latest', TAG, 'html'));
  atomicWriteFile(latestJson, json);
  atomicWriteFile(latestHtml, html);
  atomicWriteFile(zipPath, buildZip([{ name: jsonName, data: json }, { name: htmlName, data: html }]));
  updateLatestReportZip(zipPath, TAG);
  console.log(`\n[ubel-binary] JSON report : ${latestJson}`);
  console.log(`[ubel-binary] HTML report : ${latestHtml}`);
  console.log(`[ubel-binary] Bundle      : ${zipPath}`);
  return payload;
}

export async function main() {
  const args = parseArgs(process.argv.slice(2));
  const file = path.resolve(args.file);
  if (!fs.existsSync(file)) { console.error(`File not found: ${file}`); process.exitCode = 1; return; }
  provisionAssetAt(args.workingDir);
  let scan;
  try { scan = scanBinary(file, { maxSizeMb: args.maxSizeMb }); }
  catch (e) { console.error(`[ubel-binary] ${e.message}`); process.exitCode = 1; return; }
  if (args.verbose) console.log(`[ubel-binary] ${FORMAT_LABEL[scan.target.kind]} detected: ${scan.target.file}; ${scan.dependencies.length} component(s) identified`);

  // The gate is evaluated on EVERY finding; --min-severity only decides what the report shows.
  const everything = scan.findings.list.slice();
  const rank = SEVERITY_RANK[args.minSeverity];
  scan.findings.list = everything.filter(f => (SEVERITY_RANK[f.severity] ?? 4) <= rank);
  const hidden = everything.length - scan.findings.list.length;
  await resolveDependencies(scan, scan.notes, args);
  const gate = evaluateGate({ failOn: args.failOnParsed, findings: everything, dependencies: scan.dependencies, gaps: scan.notes.gaps || [], allowPartial: args.allowPartial });
  const payload = await writeReports({ hidden, gate }, scan, scan.notes, args);

  if (!args.quiet) {
    const c = payload.summary.counts, bc = payload.summary.by_category;
    console.log(`\n=== Binary security scan: ${scan.target.file} ===`);
    console.log(`Issues: ${payload.summary.total}  (critical ${c.critical}, high ${c.high}, medium ${c.medium}, low ${c.low}, info ${c.info})`);
    console.log(`  Vulnerabilities: ${bc.vulnerabilities}  ·  Secrets: ${bc.secrets}  ·  Misconfigurations: ${bc.misconfigurations}`);
    const ds = payload.dependency_summary || {};
    console.log(`Components: ${ds.total || 0} detected, ${ds.queryable || 0} queried, ${ds.vulnerable_dependencies || 0} with known vulnerabilities (${ds.vulnerabilities || 0} advisory matches)`);
    for (const f of flattenFindings(payload).filter(x => x.severity !== 'info').slice(0, 40)) console.log(`  [${f.severity.toUpperCase()}] ${f.title} -- ${f.artifact}`);
    for (const n of payload.analysis_notes) console.log(`  note: ${n}`);
  }
  if (gate.exit_code === 2) console.error(`[ubel-binary] gate FAILED: ${gate.hits} issue(s) at or above ${args.failOnParsed.severity}${gate.tolerated ? ` (${gate.tolerated} tolerated)` : ''} (--fail-on ${gate.fail_on})${hidden ? `; ${hidden} lower-severity finding(s) are hidden from the report by --min-severity` : ''}.`);
  else if (gate.exit_code === 3) console.error(`[ubel-binary] gate INCOMPLETE: nothing tripped --fail-on ${gate.fail_on}, but ${gate.gaps} part(s) could not be analysed, so a clean result is not proof of a clean binary (exit 3; --allow-partial accepts this).`);
  else if (gate.incomplete && gate.exit_code === 0 && args.failOnParsed.mode !== 'none') console.error(`[ubel-binary] note: analysis incomplete in ${gate.gaps} place(s); accepted via --allow-partial.`);
  if (gate.unrated_advisories) console.error(`[ubel-binary] note: ${gate.unrated_advisories} component advisor${gate.unrated_advisories === 1 ? 'y has' : 'ies have'} no severity and only count against --fail-on info.`);
  process.exitCode = gate.exit_code;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().catch(err => { console.error('Fatal error:', err.stack || err.message); process.exitCode = 1; });
}
