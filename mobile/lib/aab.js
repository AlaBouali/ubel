'use strict';
// aab.js — Android App Bundle (.aab) support. A bundle is a zip of *modules* (base/, feature modules, asset packs), each laid out as
//   <module>/manifest/AndroidManifest.xml  <module>/dex/*.dex  <module>/res/**  <module>/resources.pb  <module>/assets/**
//   <module>/lib/<abi>/*.so  <module>/root/**  (root/ is merged into the APK root: META-INF, kotlin/, …)
// and the manifest, res/xml files and resources.pb are aapt2 *protobuf*, not binary AXML / resources.arsc. This file
//   • decodes proto XML into the same element tree parseAxml() returns, so every manifest / network-security-config check runs unchanged;
//   • reads string resources out of resources.pb;
//   • presents one module as an APK-shaped archive (ModuleView) so analyzeApk() can analyse it as it is;
//   • reads BUNDLE-METADATA's dependency list (exact Maven coordinates, straight from the build).
// Field numbers follow aapt2's Resources.proto (XmlNode / ResourceTable) and bundletool's app_dependencies.proto.

import { parseMessage, first, all, str, msg, msgs, PbError } from './pb.js';
import { isAxml, parseAxml } from './axml.js';

const ANDROID_NS = 'http://schemas.android.com/apk/res/android';
const hex = n => `0x${(n >>> 0).toString(16).padStart(8, '0')}`;

// ── proto Item / Primitive → the same value types AXML attributes decode to ───────────────────────
function decodeItem(buf) {
  const item = parseMessage(buf);
  const prim = msg(item, 7);
  if (prim) {
    if (prim.has(8)) return first(prim, 8) !== 0;                                   // boolean
    if (prim.has(6)) { const v = first(prim, 6); return typeof v === 'bigint' ? Number(BigInt.asIntN(32, v)) : (v | 0); }   // int_decimal
    if (prim.has(7)) return first(prim, 7) >>> 0;                                   // int_hexadecimal
    if (prim.has(3)) { const b = Buffer.alloc(4); b.writeUInt32LE(first(prim, 3) >>> 0); return b.readFloatLE(0); }
    for (const f of [9, 10, 11, 12, 13, 14]) if (prim.has(f)) return Number(first(prim, f)) >>> 0;
    return undefined;
  }
  const ref = msg(item, 1);
  if (ref) { const id = first(ref, 2), name = str(ref, 3); return id ? `@${hex(Number(id))}` : (name ? `@${name}` : undefined); }
  const s = msg(item, 2) || msg(item, 3);
  if (s) return str(s, 1) ?? '';
  const file = msg(item, 5);
  if (file) return str(file, 1);
  return undefined;
}

/** True when `buf` is plausibly an aapt2 proto XmlNode (a root element with a tag name). Never throws. */
export function isProtoXml(buf) {
  if (!Buffer.isBuffer(buf) || buf.length < 4 || buf[0] !== 0x0a) return false;
  try {
    const root = parseMessage(buf);
    const el = msg(root, 1);
    const name = el && str(el, 3);
    return !!name && /^[A-Za-z_][\w.:-]*$/.test(name);
  } catch { return false; }
}

/** Proto XML → { tag, attrs, children, text }, the shape parseAxml() returns. */
export function parseProtoXml(buf, { maxElements = 200000, maxDepth = 200 } = {}) {
  let count = 0;
  const element = (el, prefixes, depth) => {
    if (depth > maxDepth) throw new PbError('XML nested too deeply');
    if (++count > maxElements) throw new PbError('too many XML elements');
    const scope = new Map(prefixes);
    for (const d of msgs(el, 1)) { const uri = str(d, 2), prefix = str(d, 1); if (uri !== undefined) scope.set(uri, prefix || ''); }
    const attrs = {};
    let i = 0;
    for (const a of msgs(el, 4)) {
      const ns = str(a, 1) || '', name = str(a, 2) || `attr_${i}`;
      i++;
      const key = !ns || ns === ANDROID_NS ? name : `${scope.get(ns) || ns}:${name}`;
      const compiled = first(a, 6);
      let value = Buffer.isBuffer(compiled) ? decodeItem(compiled) : undefined;
      if (value === undefined) value = str(a, 3) ?? '';
      attrs[key] = value;
    }
    const node = { tag: str(el, 3) || '', attrs, children: [], text: '' };
    for (const c of msgs(el, 5)) {
      const childEl = msg(c, 1);
      if (childEl) node.children.push(element(childEl, scope, depth + 1));
      else { const t = str(c, 2); if (t) node.text += t; }
    }
    return node;
  };
  const rootEl = msg(parseMessage(buf), 1);
  if (!rootEl) throw new PbError('not a proto XML document');
  return element(rootEl, new Map(), 0);
}

/** Binary XML in either encoding (AXML or aapt2 proto). Returns the root element, or null when `buf` is neither. */
export function parseBinaryXml(buf) {
  if (isAxml(buf)) return parseAxml(buf);
  if (isProtoXml(buf)) return parseProtoXml(buf);
  return null;
}
export const isBinaryXml = buf => isAxml(buf) || isProtoXml(buf);

// ── resources.pb ────────────────────────────────────────────────────────────────────────────────
/** String resources of a proto resource table: [{ id, name, value, isDefault }] — the same shape parseArscStrings() returns. */
export function parseResourceTableStrings(buf, { maxEntries = 300000 } = {}) {
  const out = [];
  const table = parseMessage(buf);
  for (const pkg of msgs(table, 2)) {
    const pkgId = Number(first(msg(pkg, 1) || new Map(), 1) || 0);
    for (const type of msgs(pkg, 3)) {
      if (str(type, 2) !== 'string') continue;
      const typeId = Number(first(msg(type, 1) || new Map(), 1) || 0);
      for (const entry of msgs(type, 3)) {
        const name = str(entry, 2) || '';
        const entryId = Number(first(msg(entry, 1) || new Map(), 1) || 0);
        for (const cv of msgs(entry, 6)) {
          const value = msg(cv, 2), item = value && first(value, 4);
          if (!Buffer.isBuffer(item)) continue;
          const s = msg(parseMessage(item), 2);
          const text = s && str(s, 1);
          if (!text) continue;
          const cfg = first(cv, 1);
          out.push({ id: (((pkgId << 24) | (typeId << 16) | entryId) >>> 0), name, value: text, isDefault: !cfg || cfg.length === 0 });
          if (out.length >= maxEntries) return out;
        }
      }
    }
  }
  return out;
}

// ── bundle layout ───────────────────────────────────────────────────────────────────────────────
const MODULE_MANIFEST = /^([^/]+)\/manifest\/AndroidManifest\.xml$/;

/** True for an .aab: a BundleConfig.pb, or module folders holding manifest/AndroidManifest.xml, and no APK-style root manifest. */
export function isAab(zip) {
  if (zip.has('AndroidManifest.xml')) return false;
  return zip.has('BundleConfig.pb') || zip.entries.some(e => MODULE_MANIFEST.test(e.name));
}

/** Module folder names, base first. */
export function aabModules(zip) {
  const mods = [...new Set(zip.entries.map(e => MODULE_MANIFEST.exec(e.name)?.[1]).filter(Boolean))];
  return mods.sort((a, b) => (a === 'base' ? -1 : b === 'base' ? 1 : a.localeCompare(b)));
}

/** bundletool version recorded in BundleConfig.pb, or null. */
export function bundletoolVersion(zip) {
  const e = zip.entry('BundleConfig.pb');
  const buf = e && zip.tryRead(e, 4 * 1024 * 1024);
  if (!buf) return null;
  try {
    const cfg = parseMessage(buf);
    const v = str(msg(cfg, 1) || new Map(), 2);
    return v && /^\d+\.\d+(\.\d+)?([-+.\w]*)$/.test(v) ? v : null;
  } catch { return null; }
}

/**
 * One module of a bundle, shaped like an APK for analyzeApk(): the module's manifest/AndroidManifest.xml appears as AndroidManifest.xml,
 * dex/ as the root, root/ merged into the root, res/, assets/, lib/ and resources.pb under their own names. Reads delegate to the bundle.
 */
export class ModuleView {
  constructor(zip, module) {
    this.zip = zip; this.module = module;
    this.entries = []; this.byName = new Map(); this.duplicateNames = [];
    const pre = `${module}/`;
    for (const e of zip.entries) {
      if (e.isDir || !e.name.startsWith(pre)) continue;
      const rest = e.name.slice(pre.length);
      let name = null;
      if (rest === 'manifest/AndroidManifest.xml') name = 'AndroidManifest.xml';
      else if (rest.startsWith('dex/')) name = rest.slice(4);
      else if (rest.startsWith('root/')) name = rest.slice(5);
      else if (rest === 'resources.pb' || /^(res|assets|lib)\//.test(rest)) name = rest;
      if (!name) continue;
      const v = { ...e, name, _src: e };
      this.entries.push(v);
      if (this.byName.has(name)) this.duplicateNames.push(name); else this.byName.set(name, v);
    }
  }
  has(name) { return this.byName.has(name); }
  entry(name) { return this.byName.get(name) || null; }
  find(re) { return this.entries.filter(e => !e.isDir && re.test(e.name)); }
  read(entryOrName, maxBytes) {
    const e = typeof entryOrName === 'string' ? this.byName.get(entryOrName) : entryOrName;
    if (!e) throw new Error(`no such entry: ${entryOrName}`);
    return this.zip.read(e._src || e, maxBytes);
  }
  tryRead(entryOrName, maxBytes) { try { return this.read(entryOrName, maxBytes); } catch { return null; } }
  close() { /* the bundle owns the file handle */ }
}

// ── BUNDLE-METADATA: dependency list ────────────────────────────────────────────────────────────
const DEPENDENCIES_PB = 'BUNDLE-METADATA/com.android.tools.build.libraries/dependencies.pb';

/** Maven (and Unity) libraries the build resolved, with exact versions. [{ group, artifact, version, kind }] */
export function readBundleDependencies(zip) {
  const e = zip.entry(DEPENDENCIES_PB);
  const buf = e && zip.tryRead(e, 32 * 1024 * 1024);
  if (!buf) return [];
  const out = [];
  try {
    for (const lib of msgs(parseMessage(buf), 1)) {
      const mvn = msg(lib, 1);
      if (mvn) {
        const group = str(mvn, 1), artifact = str(mvn, 2), version = str(mvn, 5);
        if (group && artifact) out.push({ group, artifact, version: version || null, kind: 'maven' });
        continue;
      }
      const unity = msg(lib, 4);
      if (unity) { const name = str(unity, 1); if (name) out.push({ group: null, artifact: name, version: str(unity, 2) || null, kind: 'unity' }); }
    }
  } catch { /* a damaged list is treated as absent; the caller records the gap */ return null; }
  return out;
}
export { DEPENDENCIES_PB };
