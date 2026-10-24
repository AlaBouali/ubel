'use strict';
// files.js — checks that apply to every file shipped in a package, on both platforms:
// name-based rules (keystores, env files, VCS folders, databases, embedded code, debug artifacts) and
// extraction of scannable text (JSON/XML/plist/JS/… and printable strings of opaque binaries).

import { isLikelyBinary, asciiStrings, utf16Strings } from './strings.js';
import { gap } from './coverage.js';
import { isHermes, parseHermes } from './hermes.js';
import { parsePlist, plistToLines } from './plist.js';
import { isAxml, parseAxml, axmlToLines } from './axml.js';

const KEYSTORE = /\.(jks|keystore|bks|p12|pfx|p8|ppk)$/i;
const PRIVKEY_NAME = /(^|\/)id_(rsa|dsa|ecdsa|ed25519)$/;
const SENSITIVE = [
  /(^|\/)\.env(\.[\w.-]+)?$/i, /(^|\/)\.(git|svn|hg)(\/|$)/, /(^|\/)\.(npmrc|pypirc|netrc|htpasswd|dockercfg)$/i,
  /(^|\/)credentials?\.(json|xml|plist|ya?ml|properties|txt)$/i, /(^|\/)secrets?\.(json|xml|plist|ya?ml|properties|txt|dart|js)$/i,
  /(^|\/)service[-_]?account[\w.-]*\.json$/i, /(^|\/)(wp-config\.php|config\.inc\.php)$/i,
];
const OS_METADATA = /(^|\/)(\.DS_Store|Thumbs\.db|desktop\.ini|__MACOSX\/.*)$/i;
const BACKUP = /(\.(bak|old|orig|swp|swo|tmp)|~)$/i;
const DATABASE = /\.(db|sqlite3?|db3|realm|mdb)$/i;
const EMBEDDED_CODE = /\.(apk|dex|jar|aar|odex|vdex)$/i;
const DEBUG_SYMBOLS = /(\.js\.map|\.css\.map|\.(bundle|jsbundle|hbc)\.map|\.pdb|\.mdb|\.dSYM(\/|$))/i;
const FLUTTER_DEBUG = /(^|\/)flutter_assets\/(kernel_blob\.bin|isolate_snapshot_data|vm_snapshot_data)$/;

const BINARY_EXT = /\.(png|jpe?g|gif|webp|bmp|ico|heic|heif|tiff?|mp[34]|m4[av]|mov|avi|webm|ogg|oga|wav|aac|flac|mid|ttf|otf|woff2?|eot|pdf|car|nib|storyboardc|momd?|omo|ktx|astc|pvr|dds|atlas|riv|lottie|tgs|zip|gz|tgz|bz2|xz|7z|rar|lz4|zst|obj|fbx|glb|bin|pak|dat|data|bundle\/.*\.nib)$/i;
const STRINGS_EXT = /\.(so|dll|dylib|a|hbc|exe|pyc|wasm|db|sqlite3?|realm|mdb|dex|jar|class|o)$/i;
const TEXT_EXT = /\.(json|xml|plist|strings|properties|txt|js|mjs|cjs|jsx|ts|tsx|html?|css|ya?ml|ini|cfg|conf|config|env|sh|md|csv|tsv|map|pem|key|crt|cer|pub|toml|gradle|kts?|java|swift|m|mm|h|py|rb|php|sql|graphql|gql|xcconfig|entitlements|jsbundle|bundle|rtf|log|dart|lua|gs|plist\.json|mobileconfig)$/i;

// ── keystore / private-key content check ─────────────────────────────────────────────────────────
// A file called *.bks / *.jks / *.p12 is as often a TRUSTSTORE (public CA or pinned certificates) as a keystore with a private key, so the
// name alone proves nothing. The content is looked at: only a file that really holds private or secret key material keeps the
// rule's full severity; a certificates-only store is reported as information; anything that cannot be read stays "unknown".
const PEM_PRIVATE = /-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----/;
const OID_PKCS12_KEYBAG = Buffer.from('2a864886f70d010c0a0101', 'hex');             // 1.2.840.113549.1.12.10.1.1  keyBag
const OID_PKCS12_SHROUDED = Buffer.from('2a864886f70d010c0a0102', 'hex');           // 1.2.840.113549.1.12.10.1.2  pkcs8ShroudedKeyBag

class Reader {
  constructor(buf, pos = 0) { this.b = buf; this.p = pos; }
  need(n) { if (n < 0 || this.p + n > this.b.length) throw new RangeError('truncated keystore'); }
  skip(n) { this.need(n); this.p += n; }
  u8() { this.need(1); return this.b[this.p++]; }
  u16() { this.need(2); const v = this.b.readUInt16BE(this.p); this.p += 2; return v; }
  i32() { this.need(4); const v = this.b.readInt32BE(this.p); this.p += 4; return v; }
  utf() { this.skip(this.u16()); }
}

function javaKeystore(buf) {           // JKS (0xFEEDFEED) and JCEKS (0xCECECECE)
  const r = new Reader(buf);
  const magic = r.i32() >>> 0, jceks = magic === 0xcececece;
  const version = r.i32();
  if (version !== 1 && version !== 2) return { kind: 'unknown' };
  const count = r.i32();
  if (count < 0 || count > 100000) return { kind: 'unknown' };
  for (let i = 0; i < count; i++) {
    const tag = r.i32();
    r.utf(); r.skip(8);                                              // alias, creation time
    if (tag === 1) return { kind: 'private', detail: `${jceks ? 'JCEKS' : 'JKS'} private-key entry` };
    if (tag === 3 && jceks) return { kind: 'private', detail: 'JCEKS secret-key entry' };
    if (tag !== 2) return { kind: 'unknown' };
    if (version === 2) r.utf();                                      // certificate type
    r.skip(r.i32());
  }
  return { kind: 'certs', detail: `${jceks ? 'JCEKS' : 'JKS'} store with ${count} certificate(s) and no keys` };
}

function bouncyCastleKeystore(buf) {   // BKS: version, salt, iterations, then entries; any entry that is not a plain certificate is key material
  const r = new Reader(buf);
  const version = r.i32();
  if (version < 0 || version > 2) return { kind: 'unknown' };
  r.skip(r.i32()); r.i32();                                          // salt, iteration count
  let certs = 0;
  for (let type = r.u8(); type !== 0; type = r.u8()) {
    if (type !== 1) return { kind: 'private', detail: type === 3 ? 'BKS secret-key entry' : 'BKS key entry' };
    r.utf(); r.skip(8);                                              // alias, date
    for (let n = r.i32(); n > 0; n--) { r.utf(); r.skip(r.i32()); }  // certificate chain
    r.utf(); r.skip(r.i32());                                        // the certificate itself
    certs++;
  }
  return { kind: 'certs', detail: `BKS store with ${certs} certificate(s) and no keys` };
}

/**
 * Looks inside a bundled keystore / key file.
 * @param {string} name path inside the package
 * @param {Buffer|null} data file content (null when it could not be read)
 * @returns {{kind:'private'|'certs'|'unknown', detail?:string}}
 *   private  — private or secret key material is present
 *   certs    — parsed completely and holds only certificates (a truststore)
 *   unknown  — encrypted, unrecognised or truncated: the file may or may not hold a key
 */
export function inspectKeyMaterial(name, data) {
  if (!data || !data.length) return { kind: 'unknown' };
  try {
    const head = data.toString('latin1', 0, Math.min(data.length, 64 * 1024));
    if (PEM_PRIVATE.test(head)) return { kind: 'private', detail: 'PEM private key' };
    if (/^PuTTY-User-Key-File-\d/.test(head)) return { kind: 'private', detail: 'PuTTY private key' };
    if (/-----BEGIN CERTIFICATE-----/.test(head) && !/PRIVATE KEY/.test(data.toString('latin1'))) return { kind: 'certs', detail: 'PEM certificate(s) only' };
    if (data.length > 12) {
      const magic = data.readUInt32BE(0);
      if (magic === 0xfeedfeed || magic === 0xcececece) return javaKeystore(data);
      if (/\.bks$/i.test(name)) return bouncyCastleKeystore(data);
    }
    if (data[0] === 0x30 && (data.includes(OID_PKCS12_SHROUDED) || data.includes(OID_PKCS12_KEYBAG))) return { kind: 'private', detail: 'PKCS#12 key bag' };
  } catch { /* truncated or malformed: fall through */ }
  return { kind: 'unknown' };
}

/**
 * @param {string} p path inside the package
 * @returns {{rule:string, key:string}|null}
 */
export function classifyBundledFile(p) {
  const lower = p.toLowerCase();
  if (KEYSTORE.test(lower) || PRIVKEY_NAME.test(lower)) return { rule: 'bundle.private_key' };
  if (OS_METADATA.test(p)) return { rule: 'bundle.os_metadata' };
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
        const data = e.usize <= 8 * 1024 * 1024 ? zip.tryRead(e, 8 * 1024 * 1024) : null;
        const k = inspectKeyMaterial(e.name, data);
        if (k.kind === 'private') {
          findings.add(cls.rule, { ...base, artifact: shown, description: `${shown} holds private or secret key material (${k.detail}). Everything inside an app package can be extracted by anyone who downloads it.`, evidence: [shown] });
        } else if (k.kind === 'certs') {
          findings.add(cls.rule, { ...base, artifact: shown, severity: 'info', title: 'Truststore (certificates only) bundled in the app', description: `${shown} was read completely and holds only public certificates (${k.detail}); no private key is exposed. Fine for certificate pinning or a custom trust anchor.`, evidence: [shown] });
        } else {
          findings.add(cls.rule, { ...base, artifact: shown, severity: 'medium', confidence: 'low', confidenceCap: false, description: `${shown} has the name of a keystore or private key, but its content could not be read (encrypted, unrecognised or truncated), so it is not known whether a private key is inside. Confirm that it is only a truststore.`, evidence: [shown] });
        }
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
  if (skippedLarge) gap(notes, `${skippedLarge} bundled file(s) larger than the scan limit were not scanned for secrets.`);
  if (unreadable) gap(notes, `${unreadable} bundled file(s) could not be read (encrypted, corrupt or unsupported compression).`);
  if (files >= limits.maxFiles || total >= limits.maxTotalBytes) gap(notes, 'Bundled-file scan stopped at its file/size budget; later files were not scanned.');
}

/** Turns one file's bytes into lines for the secrets engine. */
export function collectText(shown, name, data, scanner) {
  if (/\.(plist|strings|entitlements|mobileconfig)$/i.test(name) || (data.length > 8 && data.toString('latin1', 0, 6) === 'bplist')) {
    try { scanner.add(shown, plistToLines(parsePlist(data))); return; } catch { /* not a plist: fall through to plain text */ }
  }
  if (isAxml(data)) { const root = parseAxml(data); if (root) scanner.add(shown, axmlToLines(root)); return; }
  if (isHermes(data)) {                                                                  // Hermes bytecode: JS source is gone, the string table is plain
    const h = parseHermes(data);
    scanner.add(shown, h.strings ? h.strings.filter(s => s.length >= 6).map(s => s.replace(/\r?\n|\r/g, ' ')) : asciiStrings(data, { min: 8 }));
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
