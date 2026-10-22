'use strict';
// files.js — checks that apply to every file shipped in a package, on both platforms:
// name-based rules (keystores, env files, VCS folders, databases, embedded code, debug artifacts) and
// extraction of scannable text (JSON/XML/plist/JS/… and printable strings of opaque binaries).

import { isLikelyBinary, asciiStrings, utf16Strings } from './strings.js';
import { parsePlist, plistToLines } from './plist.js';
import { isAxml, parseAxml, axmlToLines } from './axml.js';

const KEYSTORE = /\.(jks|keystore|bks|p12|pfx|p8|ppk)$/i;
const PRIVKEY_NAME = /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/;
const SENSITIVE = [
  /(^|\/)\.env(\.[\w.-]+)?$/i, /(^|\/)\.(git|svn|hg)(\/|$)/, /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|dockercfg)$/i,
  /(^|\/)credentials?\.(json|xml|plist|ya?ml|properties|txt)$/i, /(^|\/)secrets?\.(json|xml|plist|ya?ml|properties|txt|dart|js)$/i,
  /(^|\/)service[-_]?account[\w.-]*\.json$/i, /(^|\/)\.DS_Store$/, /(^|\/)(wp-config\.php|config\.inc\.php)$/i,
];
const BACKUP = /(\.(bak|old|orig|swp|swo|tmp)|~)$/i;
const DATABASE = /\.(db|sqlite3?|db3|realm|mdb)$/i;
const EMBEDDED_CODE = /\.(apk|dex|jar|aar|odex|vdex)$/i;
const DEBUG_SYMBOLS = /(\.js\.map|\.css\.map|\.pdb|\.dSYM(\/|$))/i;
const FLUTTER_DEBUG = /(^|\/)flutter_assets\/kernel_blob\.bin$/;

const BINARY_EXT = /\.(png|jpe?g|gif|webp|bmp|ico|heic|heif|tiff?|mp[34]|m4[av]|mov|avi|webm|ogg|oga|wav|aac|flac|mid|ttf|otf|woff2?|eot|pdf|car|nib|storyboardc|momd?|omo|ktx|astc|pvr|dds|atlas|riv|lottie|tgs|zip|gz|tgz|bz2|xz|7z|rar|lz4|zst|obj|fbx|glb|bin|pak|dat|data|bundle\/.*\.nib)$/i;
const STRINGS_EXT = /\.(so|dll|dylib|a|hbc|exe|pyc|wasm|db|sqlite3?|realm|mdb|dex|jar|class|o)$/i;
const TEXT_EXT = /\.(json|xml|plist|strings|properties|txt|js|mjs|cjs|jsx|ts|tsx|html?|css|ya?ml|ini|cfg|conf|config|env|sh|md|csv|tsv|map|pem|key|crt|cer|pub|toml|gradle|kts?|java|swift|m|mm|h|py|rb|php|sql|graphql|gql|xcconfig|entitlements|jsbundle|rtf|log|dart|lua|gs|plist\.json|mobileconfig)$/i;

/**
 * @param {string} p path inside the package
 * @returns {{rule:string, key:string}|null}
 */
export function classifyBundledFile(p) {
  const lower = p.toLowerCase();
  if (KEYSTORE.test(lower) || PRIVKEY_NAME.test(lower)) return { rule: 'bundle.private_key' };
  if (SENSITIVE.some(re => re.test(p))) return { rule: 'bundle.sensitive_file' };
  if (FLUTTER_DEBUG.test(p)) return { rule: 'bundle.debug_build' };
  if (DEBUG_SYMBOLS.test(p)) return { rule: 'bundle.source_maps' };
  if (BACKUP.test(lower)) return { rule: 'bundle.backup_file' };
  if (DATABASE.test(lower)) return { rule: 'bundle.database' };
  if (EMBEDDED_CODE.test(lower)) return { rule: 'bundle.embedded_code' };
  return null;
}

/**
 * Walks candidate entries, raises the name-based findings and hands scannable text to `scanner`.
 * @param {import('./zip.js').ZipArchive} zip
 * @param {Array<{name:string,usize:number}>} entries  already filtered to the files this call is responsible for
 * @param {{findings:object, scanner:object, base:object, notes:string[], isEmbeddedCodeOk?:(n:string)=>boolean, limits?:object, relName?:(n:string)=>string}} ctx
 */
export function scanBundledFiles(zip, entries, ctx) {
  const { findings, scanner, base, notes } = ctx;
  const limits = { maxTextBytes: 5 * 1024 * 1024, maxTotalBytes: 400 * 1024 * 1024, maxFiles: 20000, maxStringsBytes: 64 * 1024 * 1024, ...(ctx.limits || {}) };
  const rel = ctx.relName || (n => n);
  const grouped = new Map();
  let total = 0, files = 0, skippedLarge = 0, unreadable = 0;
  for (const e of entries) {
    const shown = rel(e.name);
    const cls = classifyBundledFile(shown);
    if (cls) {
      if (cls.rule === 'bundle.private_key') {
        findings.add(cls.rule, { ...base, artifact: shown, description: `${shown} looks like a keystore or private key. Everything inside an app package can be extracted by anyone who downloads it.`, evidence: [shown] });
      } else {
        if (!grouped.has(cls.rule)) grouped.set(cls.rule, []);
        grouped.get(cls.rule).push(shown);
      }
    }
    if (files >= limits.maxFiles || total >= limits.maxTotalBytes) continue;
    const isText = TEXT_EXT.test(e.name) || !/\.[A-Za-z0-9]{1,8}$/.test(e.name);
    const isStrings = STRINGS_EXT.test(e.name);
    if (BINARY_EXT.test(e.name) && !isStrings) continue;
    if (!isText && !isStrings) continue;
    const cap = isStrings ? limits.maxStringsBytes : limits.maxTextBytes;
    if (e.usize > cap) { skippedLarge++; continue; }
    if (e.usize === 0) continue;
    const data = zip.tryRead(e, cap);
    if (!data) { unreadable++; continue; }
    files++; total += data.length;
    try { collectText(shown, e.name, data, scanner); } catch { /* one odd file must not stop the scan */ }
  }
  for (const [rule, paths] of grouped) {
    findings.add(rule, {
      ...base, artifact: paths[0],
      description: `${paths.length} file(s) matched: ${paths.slice(0, 3).join(', ')}${paths.length > 3 ? ', …' : ''}.`,
      evidence: paths.slice(0, 30), evidence_total: paths.length,
    });
  }
  if (skippedLarge) notes.push(`${skippedLarge} bundled file(s) larger than the scan limit were not scanned for secrets.`);
  if (unreadable) notes.push(`${unreadable} bundled file(s) could not be read (encrypted, corrupt or unsupported compression).`);
  if (files >= limits.maxFiles || total >= limits.maxTotalBytes) notes.push('Bundled-file scan stopped at its file/size budget; later files were not scanned.');
}

/** Turns one file's bytes into lines for the secrets engine. */
export function collectText(shown, name, data, scanner) {
  if (/\.(plist|strings|entitlements|mobileconfig)$/i.test(name) || (data.length > 8 && data.toString('latin1', 0, 6) === 'bplist')) {
    try { scanner.add(shown, plistToLines(parsePlist(data))); return; } catch { /* not a plist: fall through to plain text */ }
  }
  if (isAxml(data)) { const root = parseAxml(data); if (root) scanner.add(shown, axmlToLines(root)); return; }
  if (data.length >= 8 && data.readBigUInt64LE(0) === 0x1f1903c103bc1fc6n) {          // Hermes bytecode: JS source is gone, string table is plain
    scanner.add(shown, asciiStrings(data, { min: 8 }));
    return;
  }
  if (STRINGS_EXT.test(name) || isLikelyBinary(data)) {
    const a = asciiStrings(data, { min: 8, max: 600 });
    const u = /\.(dll|exe)$/i.test(name) ? utf16Strings(data, { min: 8 }) : [];
    scanner.add(shown, [...a, ...u]);
    return;
  }
  scanner.add(shown, data.toString('utf8').split(/\r\n|\r|\n/));
}
